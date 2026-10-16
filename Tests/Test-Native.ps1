# Test-Native.ps1 - Invoke-Native, Invoke-NativeText and Get-Sha256Hex (lib\Core.ps1) with REAL programs.
# The "program" is PowerShell itself, so this runs the same on Windows and Linux. Nothing here touches the system.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-native-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($tmp)
Initialize-Hp -DataDir (Join-Path $tmp 'data') -NoAcl
$ps = (Get-Process -Id $PID).Path
function Invoke-Ps { param([string]$Command, [int]$TimeoutSec = 60, [string]$WorkingDirectory = '') Invoke-Native -Path $ps -Arguments ('-NoProfile -Command "{0}"' -f $Command) -TimeoutSec $TimeoutSec -WorkingDirectory $WorkingDirectory }

Write-Host 'Invoke-Native' -ForegroundColor Cyan
$r = Invoke-Ps 'exit 3'
Assert-True ($r.ExitCode -eq 3 -and -not $r.TimedOut) 'the exit code comes back'
$r = Invoke-Ps '[Console]::Out.Write(''out-text''); [Console]::Error.Write(''err-text''); exit 0'
Assert-True ($r.StdOut -eq 'out-text' -and $r.StdErr -eq 'err-text' -and $r.ExitCode -eq 0) 'standard output and error output are kept apart'
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Ps 'Start-Sleep -Seconds 60' 2
$sw.Stop()
Assert-True ($r.TimedOut -and $r.ExitCode -eq -1) 'a program that does not finish is stopped after the time limit'
Assert-True ($sw.Elapsed.TotalSeconds -lt 20) "... and the caller does not wait for it ($([int]$sw.Elapsed.TotalSeconds) s)"
$sw.Restart()
$r = Invoke-Ps '$t = [Console]::In.ReadToEnd(); [Console]::Out.Write(''got '' + $t.Length + '' characters'')' 30
Assert-True ($r.StdOut -eq 'got 0 characters' -and $sw.Elapsed.TotalSeconds -lt 20) 'a program that waits for typing gets nothing and ends (its input is closed)'
$r = Invoke-Ps '1..150000 | ForEach-Object { ''line '' + $_ }' 120
Assert-True ($r.ExitCode -eq 0 -and ($r.StdOut -split "`n").Count -ge 150000) 'a lot of output on stdout does not block'
$r = Invoke-Ps '1..150000 | ForEach-Object { [Console]::Error.WriteLine(''err '' + $_) }; [Console]::Out.Write(''done'')' 120
Assert-True ($r.ExitCode -eq 0 -and $r.StdOut -eq 'done' -and ($r.StdErr -split "`n").Count -ge 150000) 'a lot of output on stderr does not block either'
$r = Invoke-Ps '(Get-Location).Path' 30 $tmp
Assert-Equal $r.StdOut.Trim() (Resolve-Path $tmp).Path 'the working directory can be set'

Write-Host 'An EMPTY argument really arrives' -ForegroundColor Cyan
$script1 = Join-Path $tmp 'args.ps1'
[IO.File]::WriteAllText($script1, 'Write-Output ("count=" + $args.Count)' + "`n" + 'foreach ($a in $args) { Write-Output ("[" + $a + "]") }' + "`n")
$r = Invoke-Native -Path $ps -Arguments ('-NoProfile -File "{0}" first "" third' -f $script1) -TimeoutSec 30
Assert-True ($r.StdOut -match 'count=3' -and $r.StdOut -match '\[first\]' -and $r.StdOut -match '\[\]' -and $r.StdOut -match '\[third\]') "first, empty, third = 3 arguments ($($r.StdOut -replace '\s+', ' '))"
$r = Invoke-Native -Path $ps -Arguments ('-NoProfile -File "{0}" "with space" "say ""hi"""' -f $script1) -TimeoutSec 30
Assert-True ($r.StdOut -match 'count=2' -and $r.StdOut -match '\[with space\]') 'quoted arguments with spaces stay one argument'

Write-Host 'Failures' -ForegroundColor Cyan
Assert-Throws { Invoke-Native -Path (Join-Path $tmp 'no-such-program') -Arguments '' } 'a program that does not exist throws (the caller reports it)'

Write-Host 'Invoke-NativeText' -ForegroundColor Cyan
$t = Invoke-NativeText -Path $ps -Arguments '-NoProfile -Command "[Console]::Out.Write(''hello'')"'
Assert-Equal $t 'hello' 'returns just the text'
$threw = ''
try { Invoke-NativeText -Path $ps -Arguments '-NoProfile -Command "[Console]::Error.Write(''bad thing''); exit 7"' | Out-Null } catch { $threw = $_.Exception.Message }
Assert-True ($threw -match 'exit code 7' -and $threw -match 'bad thing') "a failing program throws, with its exit code and its error text ($threw)"
$threw = ''
try { Invoke-NativeText -Path $ps -Arguments '-NoProfile -Command "Start-Sleep -Seconds 60"' -TimeoutSec 1 | Out-Null } catch { $threw = $_.Exception.Message }
Assert-True ($threw -match 'did not finish within 1 seconds') 'a program that hangs throws a time-out message'

Write-Host 'Get-Sha256Hex' -ForegroundColor Cyan
$f = Join-Path $tmp 'abc.txt'
[IO.File]::WriteAllBytes($f, [System.Text.Encoding]::ASCII.GetBytes('abc'))
Assert-Equal (Get-Sha256Hex $f) 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' 'SHA-256 of "abc" (known answer), lower-case hex'
$f0 = Join-Path $tmp 'empty.bin'
[IO.File]::WriteAllBytes($f0, [byte[]]@())
Assert-Equal (Get-Sha256Hex $f0) 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' 'SHA-256 of an empty file (known answer)'
$big = Join-Path $tmp 'big.bin'
$rnd = New-Object byte[] (5MB); (New-Object System.Random(42)).NextBytes($rnd); [IO.File]::WriteAllBytes($big, $rnd)
$sum = Microsoft.PowerShell.Core\Get-Command sha256sum -ErrorAction SilentlyContinue
if ($sum) { Assert-Equal (Get-Sha256Hex $big) ((& sha256sum $big).Split(' ')[0]) 'a 5 MB file agrees with sha256sum' }
else { Assert-Equal (Get-Sha256Hex $big) (Get-FileHash -Algorithm SHA256 -LiteralPath $big).Hash.ToLowerInvariant() 'a 5 MB file agrees with Get-FileHash' }
Assert-Throws { Get-Sha256Hex (Join-Path $tmp 'missing.bin') } 'a missing file throws'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-TestSummary
