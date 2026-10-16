# Test-LabKey.ps1 - proves the answer-key encryption works and fails safely.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\Lab\LabKey.ps1"

Write-Host "LabKey tests" -ForegroundColor Cyan
$tmp  = Join-Path ([IO.Path]::GetTempPath()) ("labkey-test-" + [guid]::NewGuid().ToString('N') + '.bin')
$text = '{"Plants":[{"Id":"P01","Kind":"User","Name":"svc_sql","Password":"Spring2026!"}]}'

Protect-LabText -Text $text -Passphrase 'correct horse' -Path $tmp
Assert-True (Test-Path $tmp) 'key file written'

$raw = [IO.File]::ReadAllBytes($tmp)
Assert-True ([Text.Encoding]::ASCII.GetString($raw, 0, 8) -eq 'HPCCKEY1') 'file starts with magic'
Assert-True (-not ([Text.Encoding]::UTF8.GetString($raw)).Contains('svc_sql')) 'plaintext is NOT visible in the file'

Assert-Equal (Unprotect-LabText -Path $tmp -Passphrase 'correct horse') $text 'round trip with right passphrase'
Assert-Throws { Unprotect-LabText -Path $tmp -Passphrase 'wrong horse' } 'wrong passphrase is rejected'

# flip one byte in the ciphertext -> MAC must catch it
$bad = $raw.Clone(); $bad[$bad.Length - 1] = $bad[$bad.Length - 1] -bxor 1
[IO.File]::WriteAllBytes($tmp, $bad)
Assert-Throws { Unprotect-LabText -Path $tmp -Passphrase 'correct horse' } 'tampered file is rejected'

# two encryptions of the same text must differ (random salt/iv)
$tmp2 = $tmp + '.2'; $tmp3 = $tmp + '.3'
Protect-LabText -Text $text -Passphrase 'x1x1' -Path $tmp2
Protect-LabText -Text $text -Passphrase 'x1x1' -Path $tmp3
Assert-True ((Get-FileHash $tmp2).Hash -ne (Get-FileHash $tmp3).Hash) 'salt/iv are random each time'

Remove-Item $tmp, $tmp2, $tmp3 -ErrorAction SilentlyContinue
Write-TestSummary
