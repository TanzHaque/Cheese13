# Test-BackupTransfer.ps1 - the REAL upload. Real ssh-keygen, ssh-keyscan and scp talk to a real sshd that this test starts on a
# high port on 127.0.0.1. The server is set up like the plan's blackbox: an upload-only user whose key has the forced command
# "scp -t <folder>" (restrict,command="scp -t ..."). No fake Windows box is loaded: only the upload code and the real programs.
#
# It proves: the key pair works, the pinned host key is enforced (a swapped key, an impostor server, an unpinned host and a wrong
# client key all FAIL and nothing arrives), the archive and its .sha256 arrive intact, the upload account can run nothing else,
# and no secret reaches the log or the journal. It needs Linux, root, sshd, a user named hpbackup; without them it skips.
# It does NOT prove the Windows OpenSSH 8.1 client behaves the same (only the OpenSSH on this machine is tested).
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"
. "$PSScriptRoot\..\lib\Collect.ps1"
. "$PSScriptRoot\..\lib\Judge.ps1"
. "$PSScriptRoot\..\lib\Act-Backup.ps1"

function Find-Program {
    param([string]$Name)
    $c = Microsoft.PowerShell.Core\Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { [string]$c.Source } else { '' }
}
$ssh = Find-Program 'ssh'; $scp = Find-Program 'scp'; $keygen = Find-Program 'ssh-keygen'; $keyscan = Find-Program 'ssh-keyscan'; $openssl = Find-Program 'openssl'
$sshd = Find-Program 'sshd'
if (-not $sshd -and $IsLinux -and (Test-Path '/usr/sbin/sshd')) { $sshd = '/usr/sbin/sshd' }
$testUser = 'hpbackup'
$why = ''
if (-not $IsLinux) { $why = 'this test needs Linux' }
elseif (-not ($ssh -and $scp -and $keygen -and $keyscan -and $sshd)) { $why = 'ssh, scp, ssh-keygen, ssh-keyscan or sshd is not installed' }
elseif ([int](& id -u) -ne 0) { $why = 'it must run as root to start sshd' }
else {
    $null = & id $testUser 2>&1
    if ($LASTEXITCODE -ne 0) { $why = "the user '$testUser' does not exist" }
}
if ($why) {
    Write-Host "  skip  Test-BackupTransfer: $why" -ForegroundColor DarkYellow
    Write-TestSummary
    return
}

# A freshly created user has a LOCKED password ("!"), and sshd without PAM then refuses even key logins ("account is locked").
# "*" means: no password works, but a key does. (RUNBOOK.md has the same line for the real backup user.)
if ((& getent shadow $testUser) -match "^${testUser}:!") { $null = & usermod -p '*' $testUser }

# ---- the sandbox: temp folders, a port, hooks
$work =Join-Path ([IO.Path]::GetTempPath()) ('hp-xfer-' + [guid]::NewGuid().ToString('N'))
$incoming = Join-Path $work 'incoming'
$evil = Join-Path $work 'incoming-evil'
foreach ($d in $work, $incoming, $evil) { [void][IO.Directory]::CreateDirectory($d) }
$null = & chown "${testUser}:${testUser}" $incoming $evil
$null = & chmod 700 $incoming $evil
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
$listener.Start(); $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop()

Initialize-Hp -DataDir (Join-Path $work 'data') -NoAcl
$script:Notices = New-Object System.Collections.ArrayList
$script:TextQueue = New-Object System.Collections.Queue
$script:Hp.Ask = { param($Title, $Text, $TypeWord) $null = $Title, $Text, $TypeWord; $true }
$script:Hp.Notify = { param($Title, $Text) [void]$script:Notices.Add("$Title : $Text") }
$script:Hp.AskText = { param($Prompt, $Default) $null = $Prompt; $v = $(if ($script:TextQueue.Count) { $script:TextQueue.Dequeue() } else { '' }); if ($v) { $v } else { $Default } }
$script:Hp.AllowChanges = $true
$script:Hp.ToolPaths = @{ 'ssh.exe' = $ssh; 'scp.exe' = $scp; 'ssh-keygen.exe' = $keygen; 'ssh-keyscan.exe' = $keyscan }
$script:Plan.BlackboxPort = $port
Set-HpSetting 'BlackboxIp' '127.0.0.1'
Set-HpSetting 'BackupUser' $testUser
$paths = Get-BackupPaths

function New-TestKey {
    param([string]$Path)
    $r = Invoke-Native -Path $keygen -Arguments ('-q -t ed25519 -N "" -C test -f "{0}"' -f $Path)
    if ($r.ExitCode -ne 0) { throw "ssh-keygen failed: $($r.StdErr)" }
}
function Get-ConsoleLine {
    # what you would read on the blackbox console:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
    param([string]$PubFile)
    (Invoke-Native -Path $keygen -Arguments ('-lf "{0}"' -f $PubFile)).StdOut.Trim()
}
function Start-TestSshd {
    param([string]$Name, [string]$HostKey, [string]$AuthKeys)
    $cfg = Join-Path $work "$Name.conf"
    $lines = @("Port $port", 'ListenAddress 127.0.0.1', "HostKey $HostKey", "PidFile $work/$Name.pid", "AuthorizedKeysFile $AuthKeys", 'StrictModes no', 'UsePAM no',
               'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'PubkeyAuthentication yes', "AllowUsers $testUser", 'LogLevel VERBOSE')
    [IO.File]::WriteAllText($cfg, ($lines -join "`n") + "`n")
    $proc = Start-Process -FilePath $sshd -ArgumentList @('-f', $cfg, '-D', '-E', (Join-Path $work "$Name.log")) -PassThru
    for ($i = 0; $i -lt 60; $i++) {
        if (Test-TcpOpen -HostName '127.0.0.1' -Port $port -TimeoutMs 200) { return $proc }
        Start-Sleep -Milliseconds 100
    }
    $proc
}
function Stop-TestSshd {
    param($Proc)
    if ($Proc -and -not $Proc.HasExited) { Stop-Process -Id $Proc.Id -Force; $null = $Proc.WaitForExit(3000) }
}
function Get-FileNames { param([string]$Dir) @(Microsoft.PowerShell.Management\Get-ChildItem -Path $Dir -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name } | Sort-Object) }
function Clear-Dir { param([string]$Dir) Microsoft.PowerShell.Management\Get-ChildItem -Path $Dir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force }
$serverA = $null; $serverB = $null
try {
    # ---- the two "blackboxes": the real one and an impostor, each with its own host key
    New-TestKey (Join-Path $work 'host_real')
    New-TestKey (Join-Path $work 'host_evil')
    $serverA = Start-TestSshd 'real' (Join-Path $work 'host_real') (Join-Path $work 'authorized_keys')
    Assert-True (Test-TcpOpen -HostName '127.0.0.1' -Port $port) "a real sshd answers on 127.0.0.1:$port"

    Write-Host 'Step 2: the SSH key pair (real ssh-keygen)' -ForegroundColor Cyan
    $r = Invoke-Change (New-BackupKeyAction) -Confirmed
    Assert-Equal $r.Status 'Applied' 'the key pair is created'
    Assert-True ((Test-Path $paths.Key) -and (Test-Path "$($paths.Key).pub")) 'private and public key files exist in the data folder'
    $pub = ([IO.File]::ReadAllText("$($paths.Key).pub")).Trim()
    Assert-True ($pub -match '^ssh-ed25519 AAAA[A-Za-z0-9+/=]+ backup@') 'the public key is ed25519, commented backup@<computer>'
    Assert-True ($r.Output -match [regex]::Escape('restrict,command="scp -t /srv/backup/incoming" ' + $pub)) 'the result shows the exact authorized_keys line (restrict + forced scp command + the public key)'
    Assert-True (-not ($r.Output -match 'PRIVATE')) 'and the private key is not in that text'
    $y = Invoke-Native -Path $keygen -Arguments ('-y -P "" -f "{0}"' -f $paths.Key)
    Assert-True ($y.ExitCode -eq 0 -and $y.StdOut.Trim().StartsWith('ssh-ed25519')) 'the private key has no passphrase (an upload can run unattended)'
    Assert-Equal ((& stat -c '%a' $paths.Key)) '600' 'the private key file is readable by its owner only'
    $r2 = Invoke-Change (New-BackupKeyAction) -Confirmed
    Assert-True ($r2.Status -eq 'Failed' -and $r2.Message -match 'already exists') 'a second run does not replace the key'
    Assert-Equal ([IO.File]::ReadAllText("$($paths.Key).pub")).Trim() $pub '... and the public key is unchanged'

    # authorized_keys of the upload-only user: forced command, restricted
    [IO.File]::WriteAllText((Join-Path $work 'authorized_keys'), "restrict,command=`"scp -t $incoming`" $pub`n")
    [IO.File]::WriteAllText((Join-Path $work 'authorized_keys_evil'), "restrict,command=`"scp -t $evil`" $pub`n")

    Write-Host 'Step 3: pinning the host key (real ssh-keyscan against the real sshd)' -ForegroundColor Cyan
    $console = Get-ConsoleLine (Join-Path $work 'host_real.pub')
    $consoleEvil = Get-ConsoleLine (Join-Path $work 'host_evil.pub')
    Assert-True ($console -match 'SHA256:') "the console line looks like: $console"
    $script:TextQueue.Enqueue($consoleEvil)
    $a = Request-PinHostKey
    Assert-True ($null -eq $a -and $script:Notices[-1] -match 'NOT PINNED') "the fingerprint of ANOTHER server's key is refused ($($script:Notices[-1].Split("`n")[0]))"
    Assert-True (-not (Test-Path $paths.KnownHosts)) '... and nothing was written to known_hosts'
    $script:TextQueue.Enqueue($console)
    $a = Request-PinHostKey
    Assert-True ($null -ne $a -and $a.Data.Type -eq 'ssh-ed25519') 'the right fingerprint (the whole console line) finds the ed25519 key'
    $r = Invoke-Change $a -Confirmed
    Assert-Equal $r.Status 'Applied' 'pinned'
    $knownText = [IO.File]::ReadAllText($paths.KnownHosts)
    $realPub = ([IO.File]::ReadAllText((Join-Path $work 'host_real.pub'))).Trim().Split(' ')
    Assert-Equal $knownText.Trim() "[127.0.0.1]:$port $($realPub[0]) $($realPub[1])" 'known_hosts holds exactly: [IP]:port, key type, the key the server really has'
    Assert-True ((Get-BackupFacts).HostKeyPinned) 'the audit sees it as pinned'
    Assert-Equal (Get-HostKeyFingerprint $realPub[1]) (($console -split '\s+')[1]) 'our fingerprint calculation equals the one ssh-keygen prints'
    Assert-Equal ((Get-SshVersion $ssh) -match '^OpenSSH') $true 'Get-SshVersion reads the real "ssh -V" text'

    Write-Host 'An archive to send (real encryption, made by the tool code)' -ForegroundColor Cyan
    $src = Join-Path $work 'archive-src'
    [void][IO.Directory]::CreateDirectory($src)
    [IO.File]::WriteAllText((Join-Path $src 'hello.txt'), 'backup test content')
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $plainZip = Join-Path $work 'plain.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $plainZip)
    $pass = 'a long test passphrase for the transfer 2026'
    $name = 'as-found-20261016-100000.zip.enc'
    $enc = Join-Path $paths.Backup $name
    Protect-File -InFile $plainZip -OutFile $enc -Passphrase $pass
    $localHash = Get-Sha256Hex $enc
    Save-Text "$enc.sha256" "$localHash  $name`n"
    Assert-Equal @((Get-BackupFacts).Archives).Count 1 'the audit sees one archive'

    Write-Host 'Step 5: every way the upload must FAIL (and nothing may arrive)' -ForegroundColor Cyan
    $act = Request-SendBackup
    Assert-True ($null -ne $act -and $act.Data.Name -eq $name) 'a send action for that archive'
    # (a) the client key is not authorized on the server
    $goodAuth = [IO.File]::ReadAllText((Join-Path $work 'authorized_keys'))
    New-TestKey (Join-Path $work 'other_client')
    [IO.File]::WriteAllText((Join-Path $work 'authorized_keys'), ("restrict,command=`"scp -t $incoming`" " + ([IO.File]::ReadAllText((Join-Path $work 'other_client.pub'))).Trim() + "`n"))
    $r = Invoke-Change $act -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Permission denied') "a key the server does not know: FAILED with the reason ($($r.Message))"
    [IO.File]::WriteAllText((Join-Path $work 'authorized_keys'), $goodAuth)
    # (b) the known_hosts entry holds ANOTHER key for this address (someone swapped the server's key)
    $knownKeep = [IO.File]::ReadAllText($paths.KnownHosts)
    $evilPub = ([IO.File]::ReadAllText((Join-Path $work 'host_evil.pub'))).Trim().Split(' ')
    Save-Text $paths.KnownHosts "[127.0.0.1]:$port $($evilPub[0]) $($evilPub[1])`n"
    $r = Invoke-Change $act -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Host key verification failed|HOST IDENTIFICATION') "the server's real key differs from the pinned one: FAILED ($(($r.Message -split "`n")[0]))"
    Save-Text $paths.KnownHosts $knownKeep
    Assert-Equal (Get-FileNames $incoming).Count 0 'so far nothing arrived on the real server'
    # (c) an impostor answers on the pinned address, even with a key the user could log in with
    Stop-TestSshd $serverA
    $serverB = Start-TestSshd 'evil' (Join-Path $work 'host_evil') (Join-Path $work 'authorized_keys_evil')
    Assert-True (Test-TcpOpen -HostName '127.0.0.1' -Port $port) 'the impostor server is up on the same address and port'
    $r = Invoke-Change $act -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Host key verification failed|HOST IDENTIFICATION') "the impostor is REFUSED ($(($r.Message -split "`n")[0]))"
    Assert-Equal (Get-FileNames $evil).Count 0 'and NOTHING reached the impostor'
    Assert-True (-not (Test-Path (Join-Path $paths.Backup 'sent.json'))) 'and nothing is recorded as sent'
    # (d) scp itself, with no pin at all, still refuses (no trust-on-first-use) even if the tool's own checks were skipped
    $emptyKnown = Join-Path $work 'known_empty'
    [IO.File]::WriteAllText($emptyKnown, '')
    $legacy = Test-ScpNeedsLegacyFlag (Get-SshVersion $ssh)
    $line = Get-ScpArguments -Key $paths.Key -KnownHosts $emptyKnown -Port $port -Legacy $legacy -Files @($name, "$name.sha256") -Target "${testUser}@127.0.0.1:"
    $res = Invoke-Native -Path $scp -Arguments $line -TimeoutSec 60 -WorkingDirectory $paths.Backup
    Assert-True ($res.ExitCode -ne 0 -and ($res.StdErr + $res.StdOut) -match 'Host key verification failed|No ED25519 host key is known|host key') "an unpinned host is refused by scp itself, never trusted on first use ($(($res.StdErr -split "`n")[0]))"
    Assert-Equal (Get-FileNames $evil).Count 0 'and nothing arrived'
    Assert-True (-not ((Get-Content -LiteralPath $emptyKnown -Raw) -match 'ssh-')) 'and scp did not add the key to the file (known_empty is still empty)'
    Stop-TestSshd $serverB; $serverB = $null
    # (e) blackbox is down
    $r = Invoke-Change $act -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'does not answer on port') 'blackbox down: the action stops before trying (and says why)'

    Write-Host 'Step 5: the real upload' -ForegroundColor Cyan
    $serverA = Start-TestSshd 'real2' (Join-Path $work 'host_real') (Join-Path $work 'authorized_keys')
    $r = Invoke-Change $act -Confirmed
    Assert-Equal $r.Status 'Applied' "the upload works ($($r.Message) $($r.Output))"
    Assert-Equal ((Get-FileNames $incoming) -join ',') "$name,$name.sha256" 'exactly the archive and its .sha256 arrived in the forced folder'
    Assert-Equal (Get-Sha256Hex (Join-Path $incoming $name)) $localHash 'the received archive has the same SHA-256 as the local one'
    Assert-Equal ([IO.File]::ReadAllText((Join-Path $incoming "$name.sha256"))) ([IO.File]::ReadAllText("$enc.sha256")) 'and the .sha256 file arrived unchanged'
    Push-Location $incoming
    $null = & sha256sum -c "$name.sha256" 2>&1
    $sumCode = $LASTEXITCODE
    Pop-Location
    Assert-Equal $sumCode 0 'sha256sum -c on the server side accepts it (this is what you run on blackbox)'
    Assert-Equal ((& stat -c '%U' (Join-Path $incoming $name))) $testUser 'the files belong to the upload user'
    if ($openssl) {
        $env:HP_TEST_PASS = $pass
        $null = & openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -pass env:HP_TEST_PASS -in (Join-Path $incoming $name) -out (Join-Path $work 'received.zip') 2>&1
        $code = $LASTEXITCODE
        Remove-Item Env:HP_TEST_PASS
        Assert-True ($code -eq 0 -and (Get-Sha256Hex (Join-Path $work 'received.zip')) -eq (Get-Sha256Hex $plainZip)) 'what arrived decrypts (real openssl) to exactly the original zip'
    }
    $sent = [IO.File]::ReadAllText((Join-Path $paths.Backup 'sent.json')) | ConvertFrom-Json
    Assert-True ($sent.Name -eq $name -and $sent.Sha256 -eq $localHash -and $sent.Ip -eq '127.0.0.1' -and $sent.User -eq $testUser) 'sent.json records name, SHA-256, address and user'
    Assert-Equal (Get-BackupFacts).Sent.Name $name 'the audit now sees "sent"'

    Write-Host 'The upload account can do nothing else' -ForegroundColor Cyan
    $base = '-i "{0}" -p {1} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="{2}" -o GlobalKnownHostsFile=/dev/null' -f $paths.Key, $port, $paths.KnownHosts
    $marker = Join-Path $work 'pwned'
    $null = Invoke-Native -Path $ssh -Arguments "$base ${testUser}@127.0.0.1 `"touch $marker`"" -TimeoutSec 30
    Assert-True (-not (Test-Path $marker)) 'asking for another command (touch) does nothing: the forced scp command runs instead'
    $null = Invoke-Native -Path $ssh -Arguments "$base ${testUser}@127.0.0.1" -TimeoutSec 30
    Assert-Equal (Get-FileNames $incoming).Count 2 'an interactive login attempt does not change the folder'

    Write-Host 'Negative control: the new scp protocol would NOT work with this account' -ForegroundColor Cyan
    if ($legacy) {
        Clear-Dir $incoming
        $noO = Get-ScpArguments -Key $paths.Key -KnownHosts $paths.KnownHosts -Port $port -Legacy $false -Files @($name) -Target "${testUser}@127.0.0.1:"
        $res = Invoke-Native -Path $scp -Arguments $noO -TimeoutSec 60 -WorkingDirectory $paths.Backup
        Assert-True ($res.ExitCode -ne 0) "without -O a 9.x scp fails against the forced 'scp -t' command (so -O is needed): exit $($res.ExitCode) $(($res.StdErr -split "`n")[0])"
        Assert-Equal (Get-FileNames $incoming).Count 0 '... and nothing arrived'
    } else { Write-Host '  skip  this ssh is older than 9.0: scp already uses the old protocol' -ForegroundColor DarkYellow }

    Write-Host 'No secret in the log, the journal or the settings' -ForegroundColor Cyan
    $privBody = @(([IO.File]::ReadAllLines($paths.Key)) | Where-Object { $_ -and $_ -notmatch '^-----' })
    $leaks = @()
    foreach ($f in @(Microsoft.PowerShell.Management\Get-ChildItem -Path $script:Hp.DataDir -Recurse -File -Force)) {
        if ($f.FullName -eq $paths.Key -or $f.Extension -eq '.enc') { continue }
        $content = [IO.File]::ReadAllText($f.FullName)
        if ($content -match 'BEGIN OPENSSH PRIVATE KEY' -or $content.Contains($pass) -or ($privBody.Count -gt 0 -and $content.Contains($privBody[0]))) { $leaks += $f.Name }
    }
    Assert-True ($leaks.Count -eq 0) "neither the private key nor the passphrase appears in any other file of the data folder ($($leaks -join ', '))"
} finally {
    Stop-TestSshd $serverA
    Stop-TestSshd $serverB
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-TestSummary
