# Test-ActBackup.ps1 - the backup ACTIONS (lib\Act-Backup.ps1) through the real gate (Invoke-Change) against the pretend Windows box.
# It proves: the archive is real AES-256 that the real OpenSSL can open, nothing readable is left behind, the passphrase never reaches a
# file, one failing item does not lose the others, no password is in the backup, and the pin / send steps refuse when something is missing.
# The real SSH upload is tested in Test-BackupTransfer.ps1. Neither test proves how real Windows behaves (that is the lab's job).
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"
. "$PSScriptRoot\..\lib\DeadMan.ps1"
. "$PSScriptRoot\..\lib\Collect.ps1"
. "$PSScriptRoot\..\lib\Judge.ps1"
. "$PSScriptRoot\..\lib\JudgeAccounts.ps1"
. "$PSScriptRoot\..\lib\JudgeFirewall.ps1"
. "$PSScriptRoot\..\lib\JudgeHunt.ps1"
. "$PSScriptRoot\..\lib\JudgeWatchdog.ps1"
. "$PSScriptRoot\..\lib\Act-Backup.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

Add-Type -AssemblyName System.IO.Compression.FileSystem
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-actbk-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl

# ---- hooks: answers are scripted, nothing waits for a human
$script:Asked = New-Object System.Collections.ArrayList
$script:Notices = New-Object System.Collections.ArrayList
$script:TextQueue = New-Object System.Collections.Queue
$script:SecretQueue = New-Object System.Collections.Queue
$script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $true }
$script:Hp.Notify = { param($Title, $Text) [void]$script:Notices.Add("$Title : $Text") }
$script:Hp.AskText = { param($Prompt, $Default) $null = $Prompt; $v = $(if ($script:TextQueue.Count) { $script:TextQueue.Dequeue() } else { '' }); if ($v) { $v } else { $Default } }   # like the console: Enter = the default
$script:Hp.AskSecret = { param($Prompt) $null = $Prompt; if ($script:SecretQueue.Count) { $script:SecretQueue.Dequeue() } else { $null } }
$script:Hp.AllowChanges = $true

# ---- helpers
$haveOpenssl = [bool](Microsoft.PowerShell.Core\Get-Command openssl -ErrorAction SilentlyContinue)
$haveSha256sum = [bool](Microsoft.PowerShell.Core\Get-Command sha256sum -ErrorAction SilentlyContinue)
$pass = 'Tr0ub4dor&3 "quoted" $HOME ' + [char]0x00E9 + '\path'      # spaces, quotes, $, a backslash and a non-ASCII letter on purpose
function Get-BackupDir { (Get-BackupPaths).Backup }
function Get-ZipNames {
    param([string]$Zip)
    $z = [System.IO.Compression.ZipFile]::OpenRead($Zip)
    try { @($z.Entries | ForEach-Object { $_.FullName }) } finally { $z.Dispose() }
}
function Read-ZipEntry {
    param([string]$Zip, [string]$Name)
    $z = [System.IO.Compression.ZipFile]::OpenRead($Zip)
    try {
        $e = $z.GetEntry($Name)
        if (-not $e) { return $null }
        $reader = New-Object System.IO.StreamReader($e.Open())
        try { $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $z.Dispose() }
}
function Expand-WithOpenssl {
    # The independent check: OpenSSL decrypts the file the way the RUNBOOK tells you to on blackbox (never on the laptop: rule 3). Returns openssl's exit code.
    param([string]$Enc, [string]$Pass, [string]$Out)
    $env:HP_TEST_PASS = $Pass
    $null = & openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -pass env:HP_TEST_PASS -in $Enc -out $Out 2>&1
    $code = $LASTEXITCODE
    Remove-Item Env:HP_TEST_PASS
    $code
}
function Get-AllFilesUnder { param([string]$Path) @(Microsoft.PowerShell.Management\Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue) }
function Test-BytesContain {
    param([byte[]]$Haystack, [byte[]]$Needle)
    $text = [System.Text.Encoding]::GetEncoding(28591).GetString($Haystack)
    $find = [System.Text.Encoding]::GetEncoding(28591).GetString($Needle)
    $text.Contains($find)
}
function Get-JournalFor { param([string]$Prefix) @(Get-JournalRecords | Where-Object { $_.ActionId -like "$Prefix*" }) }

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Small helpers' -ForegroundColor Cyan
Assert-True (Test-IpAddressText '172.16.5.5') 'a plain IPv4 address is accepted'
Assert-True (Test-IpAddressText '0.0.0.0') '... also 0.0.0.0 (shape only)'
foreach ($bad in 'blackbox', '172.16.5', '256.1.1.1', '172.16.5.5.5', ' 172.16.5.5', '172.16.5.5 ', '172.16.5.5:22', '', 'a.b.c.d', '172.16.5.-1', 'blackbox.local') {
    Assert-True (-not (Test-IpAddressText $bad)) "not an address: '$bad'"
}
Assert-Equal (Get-HostKeyFingerprint 'AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g') 'SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4' 'fingerprint = SHA256:base64(sha256(key blob)) without padding (known answer)'
$script:Plan.BlackboxPort = 22
Assert-Equal (Get-KnownHostsSpec '172.16.5.5') '172.16.5.5' 'known_hosts names the host by its IP on port 22'
$script:Plan.BlackboxPort = 2222
Assert-Equal (Get-KnownHostsSpec '172.16.5.5') '[172.16.5.5]:2222' '... and as [IP]:port on any other port'
$script:Plan.BlackboxPort = 22
Assert-True (Test-ScpNeedsLegacyFlag 'OpenSSH_9.5p1, OpenSSL 3.1') 'OpenSSH 9.x scp needs -O (the upload account has no SFTP)'
Assert-True (Test-ScpNeedsLegacyFlag 'OpenSSH_for_Windows_9.5p1, LibreSSL 3.8') '... also the Windows build 9.x'
Assert-True (Test-ScpNeedsLegacyFlag 'OpenSSH_10.0p2') '... and 10.x'
Assert-True (-not (Test-ScpNeedsLegacyFlag 'OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2')) 'the Windows Server 2022 client (8.1) does NOT get -O (it does not know the flag)'
Assert-True (-not (Test-ScpNeedsLegacyFlag 'OpenSSH_8.9p1 Ubuntu')) '8.9 does not get -O'
Assert-True (-not (Test-ScpNeedsLegacyFlag '')) 'an unreadable version does not get -O'

$line = Get-ScpArguments -Key 'C:\k\id' -KnownHosts 'C:\k\known' -Port 22 -Legacy $true -Files @('C:\b\a.enc', 'C:\b\a.enc.sha256') -Target 'backup@172.16.5.5:'
Assert-True ($line -match 'StrictHostKeyChecking=yes' -and $line -notmatch 'StrictHostKeyChecking=no') 'scp: only a pinned host key is accepted'
Assert-True ($line -match 'BatchMode=yes' -and $line -match 'PasswordAuthentication=no' -and $line -match 'IdentitiesOnly=yes') 'scp: never asks anything, no password, only our key'
Assert-True ($line -match 'UserKnownHostsFile="C:\\k\\known"' -and $line -match 'GlobalKnownHostsFile=') 'scp: our own known_hosts file, not the system-wide one'
Assert-True ($line -match '-P 22 ' -and $line -cmatch '(^| )-O( |$)') 'scp: the port, and -O for a new client'
Assert-True ($line.EndsWith('"C:\b\a.enc" "C:\b\a.enc.sha256" backup@172.16.5.5:')) 'scp: the two files, then the target'
$line2 = Get-ScpArguments -Key 'k' -KnownHosts 'h' -Port 22 -Legacy $false -Files @('f') -Target 'u@1.2.3.4:'
Assert-True ($line2 -cnotmatch '(^| )-O( |$)') 'scp: no -O for the old client (it does not know the flag)'
Assert-True ($line -notmatch '(^| )-q( |$)') 'scp: not quiet (-q would also hide the reason when an upload fails)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Step 1: blackbox IP' -ForegroundColor Cyan
$script:TextQueue.Enqueue('blackbox')
$a = Request-BlackboxIp
Assert-True ($null -eq $a -and $script:Notices[-1] -match 'not an IPv4') 'a NAME is refused (the IP is a number, never a name)'
$script:TextQueue.Enqueue('')
$a = Request-BlackboxIp
Assert-True ($null -ne $a -and $a.Data.Ip -eq '172.16.5.5') 'pressing Enter takes the default worked out from this box (172.16.5.30 -> 172.16.5.5)'
$script:TextQueue.Enqueue('172.16.9.5')
$a = Request-BlackboxIp
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-HpSetting 'BlackboxIp') -eq '172.16.9.5') 'a typed IP is saved'
Assert-True ((Get-Content -Path (Join-Path $tmp 'settings.json') -Raw) -match '172\.16\.9\.5') 'and written to settings.json'
$r = Undo-Change -Id $r.JournalId -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-HpSetting 'BlackboxIp') -eq '') 'undo puts the old (empty) value back'
Assert-Equal @($global:FW.Calls | Where-Object { $_ -notlike 'icacls*' }).Count 0 'and the box itself was not touched (no cmdlet changed anything)'
Set-HpSetting 'BlackboxIp' '172.16.5.5'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The passphrase' -ForegroundColor Cyan
$script:SecretQueue.Enqueue('Aaaaaaaaaaaaaaaaaaaa'); $script:SecretQueue.Enqueue('Bbbbbbbbbbbbbbbbbbbb')
Assert-True ($null -eq (Get-BackupPassphrase) -and $script:Notices[-1] -match 'different') 'two different entries are refused'
$script:SecretQueue.Enqueue('short'); $script:SecretQueue.Enqueue('short')
Assert-True ($null -eq (Get-BackupPassphrase) -and $script:Notices[-1] -match 'Only 5 characters') 'a short passphrase is refused'
Assert-True ($null -eq (Get-HpSecret 'backup-pass')) 'and nothing was kept'
Assert-True ($null -eq (Request-BackupNow)) 'with no passphrase there is no backup action at all'
$script:SecretQueue.Enqueue($pass); $script:SecretQueue.Enqueue($pass)
Assert-Equal (Get-BackupPassphrase) $pass 'a good passphrase (twice the same) is accepted'
Assert-Equal (Get-HpSecret 'backup-pass') $pass 'and kept in memory'
Assert-Equal (Get-BackupPassphrase) $pass 'it is not asked again in the same run'
Assert-Equal $script:SecretQueue.Count 0 '(the queue is empty: nothing else was asked)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Step 4: the as-found backup (collect, zip, encrypt)' -ForegroundColor Cyan
$act = Request-AsFoundBackup
Assert-True ($act.Id -like 'backup.take:as-found-*.zip.enc') "the action is named after the archive ($($act.Id))"
Assert-True ($act.Risk -eq 'Low' -and -not $act.UndoKind -and $act.NoUndo) 'low risk; it says up front that it has no undo (nothing on the system changes)'
$r = Invoke-Change $act
$preview = $script:Asked[-1].Text
Assert-Equal $r.Status 'Applied' 'the backup is taken'
Assert-True ($preview -match 'AES-256' -and $preview -match 'NOT saved' -and $preview -match 'LOCAL' -and $preview -match 'Nothing is sent') 'the confirm text says: AES-256, passphrase not saved, local only, nothing sent'
$enc = Join-Path (Get-BackupDir) $act.Data.Name
Assert-True (Test-Path $enc) 'the encrypted archive exists in the backup folder'
$files = @(Get-AllFilesUnder (Get-BackupDir) | ForEach-Object { $_.Name })
Assert-True ($files.Count -eq 2 -and ($files -contains $act.Data.Name) -and ($files -contains "$($act.Data.Name).sha256")) "the backup folder holds exactly the archive and its .sha256 ($($files -join ', '))"
$bytes = [IO.File]::ReadAllBytes($enc)
Assert-Equal ([System.Text.Encoding]::ASCII.GetString($bytes, 0, 8)) 'Salted__' 'the file starts with the OpenSSL header "Salted__"'
Assert-True ((($bytes.Length - 16) % 16) -eq 0 -and $bytes.Length -gt 1000) 'and the rest is whole AES blocks'
Assert-True (-not (Test-BytesContain $bytes ([System.Text.Encoding]::ASCII.GetBytes('users.txt')))) 'no file name is readable in the encrypted archive'
Assert-Equal ((Get-Content -Path "$enc.sha256" -Raw).Trim()) ("$(Get-Sha256Hex $enc)  $($act.Data.Name)") 'the .sha256 file is "hash<2 spaces>name"'
if ($haveSha256sum) {
    Push-Location (Get-BackupDir)
    $null = & sha256sum -c "$($act.Data.Name).sha256" 2>&1
    $code = $LASTEXITCODE
    Pop-Location
    Assert-Equal $code 0 'sha256sum -c accepts the .sha256 file (this is what you run on blackbox)'
} else { Write-Host '  skip  sha256sum is not installed here' -ForegroundColor DarkYellow }

$zipPath = Join-Path $tmp 'opened.zip'
if ($haveOpenssl) {
    Assert-Equal (Expand-WithOpenssl $enc $pass $zipPath) 0 'the REAL openssl opens it with the passphrase (openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256)'
    Assert-True ((Expand-WithOpenssl $enc ($pass + 'x') (Join-Path $tmp 'wrong.zip')) -ne 0) 'a wrong passphrase does not open it'
    Remove-Item -LiteralPath (Join-Path $tmp 'wrong.zip') -ErrorAction SilentlyContinue
    $names = Get-ZipNames $zipPath
    $expected = @('_manifest.txt', 'facts.json', 'users.txt', 'local-groups.txt', 'whoami.txt', 'secedit.inf', 'auditpol.txt', 'firewall.wfw', 'firewall-profiles.txt',
                  'firewall-rules.txt', 'services.csv', 'hosts.txt', 'route.txt', 'netstat.txt', 'shares.txt', 'sessions.txt', 'software.csv', 'defender-settings.txt',
                  'processes.csv', 'wmi-subscriptions.txt', 'startup-folders.txt', 'gpresult.html', 'registry/run-machine.reg', 'registry/winlogon.reg',
                  'registry/terminal-server.reg', 'registry/defender-policy.reg', 'tasks/_NightlyCopy.xml')
    $missing = @($expected | Where-Object { $names -notcontains $_ })
    Assert-True ($missing.Count -eq 0) "the zip holds every expected item ($($names.Count) entries; missing: $($missing -join ', '))"
    Assert-True (@($names | Where-Object { $_ -like 'tasks/*Defrag*' }).Count -eq 0) 'scheduled tasks under \Microsoft\ are left out (only the custom ones are saved)'
    $manifest = Read-ZipEntry $zipPath '_manifest.txt'
    Assert-True ($manifest -match 'Backup kind : as-found' -and $manifest -match 'Computer    : ASSEMBLY-5') 'the manifest names the kind and the computer'
    Assert-True ($manifest -match 'OK      users\.txt' -and $manifest -match 'OK      registry/run-machine\.reg') 'and lists each item that worked'
    Assert-True ($manifest -match 'FAILED  jenkins/ : ') 'a failure is written in the manifest (here: the pretend Jenkins home is a Windows path that does not exist)'
    Assert-True ((Read-ZipEntry $zipPath 'users.txt') -match 'plinktern') 'users.txt lists the accounts'
    Assert-True ((Read-ZipEntry $zipPath 'local-groups.txt') -match '=== Administrators') 'local-groups.txt has one block per group'
    Assert-True ((Read-ZipEntry $zipPath 'hosts.txt') -match '127\.0\.0\.1 localhost') 'hosts.txt is the hosts file'
    Assert-True ((Read-ZipEntry $zipPath 'software.csv') -match 'Jenkins 2\.440') 'software.csv lists the installed programs'
    Assert-True ((Read-ZipEntry $zipPath 'facts.json') -match '"Accounts"' -and (Read-ZipEntry $zipPath 'facts.json') -match 'jmoney') 'facts.json is the whole audit data'
    # nothing secret inside: none of the planted passwords, and not the backup passphrase
    $secretsFound = @()
    $all = Get-ZipNames $zipPath | ForEach-Object { Read-ZipEntry $zipPath $_ }
    foreach ($u in $global:FW.Users.Values) { if ($u.Password.Length -ge 5 -and @($all | Where-Object { $_ -and $_.Contains($u.Password) }).Count) { $secretsFound += $u.Name } }
    if (@($all | Where-Object { $_ -and $_.Contains($pass) }).Count) { $secretsFound += 'the backup passphrase' }
    Assert-True ($secretsFound.Count -eq 0) "no password is in the backup ($($secretsFound -join ', '))"
    Remove-Item -LiteralPath $zipPath -ErrorAction SilentlyContinue
} else { Write-Host '  skip  openssl is not installed here: the archive contents were not opened' -ForegroundColor DarkYellow }

Write-Host 'What the journal, the log and the settings hold' -ForegroundColor Cyan
$rec = Get-JournalFor 'backup.take' | Select-Object -Last 1
Assert-True ($rec.Status -eq 'applied' -and $rec.Data.Kind -eq 'as-found' -and $rec.Data.Name -eq $act.Data.Name) 'the journal records the archive name and kind'
$leaks = @()
foreach ($f in (Get-AllFilesUnder $tmp)) {
    if ($f.Extension -eq '.enc') { continue }
    if (Test-BytesContain ([IO.File]::ReadAllBytes($f.FullName)) ([System.Text.Encoding]::UTF8.GetBytes($pass))) { $leaks += $f.Name }
}
Assert-True ($leaks.Count -eq 0) "the passphrase is in no file of the data folder ($($leaks -join ', '))"
$r = Undo-Change -Id $rec.Id -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'no undo') 'a backup has no undo (and says so)'
Assert-True (Test-Path $enc) 'and the archive is still there'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'One failing item does not lose the others' -ForegroundColor Cyan
$global:FW.BrokenPrograms = @('qwinsta.exe')
$global:FW.MissingRegKeys = @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
$r = Invoke-Change (Request-BackupNow) -Confirmed
$global:FW.BrokenPrograms = @()
$global:FW.MissingRegKeys = @()
Assert-Equal $r.Status 'Applied' 'the backup still completes'
Assert-True ($r.Output -match '2 item\(s\)' -and $r.Output -match 'jenkins/' -and $r.Output -match 'sessions\.txt') "and the result names what could not be collected ($($r.Output))"
$enc2 = @(Get-AllFilesUnder (Get-BackupDir) | Where-Object { $_.Name -like 'backup-*.zip.enc' })[0].FullName
if ($haveOpenssl) {
    Assert-Equal (Expand-WithOpenssl $enc2 $pass $zipPath) 0 'the second archive opens too'
    $manifest = Read-ZipEntry $zipPath '_manifest.txt'
    Assert-True ($manifest -match 'FAILED  sessions\.txt : ') 'the broken program is marked FAILED in the manifest'
    Assert-True ($manifest -match 'OK      users\.txt' -and $manifest -match 'OK      registry/run-machine\.reg') 'while the other items are OK'
    Assert-True ($manifest -match 'OK      registry/runonce-machine\.reg' -and (Read-ZipEntry $zipPath 'registry/runonce-machine.reg') -match 'key not present') 'a registry key that does not exist is not an error: a note is saved instead'
    Assert-True ((Read-ZipEntry $zipPath '_manifest.txt') -match 'Backup kind : backup') 'the kind is "backup" for a routine backup'
    Remove-Item -LiteralPath $zipPath -ErrorAction SilentlyContinue
}

Write-Host 'Jenkins files (a real folder this time)' -ForegroundColor Cyan
$jh = Join-Path $tmp 'jenkins-home'
foreach ($rel in 'config.xml', 'credentials.xml', 'secret.key', 'hudson.model.UpdateCenter.xml', 'secrets/master.key', 'secrets/hudson.util.Secret', 'users/jmoney_1234/config.xml',
                 'nodes/n1/config.xml', 'init.groovy.d/evil.groovy', 'jobs/rocket-build/config.xml', 'jobs/rocket-build/builds/1/log', 'jobs/rocket-build/workspace/x.txt',
                 'plugins/git.jpi', 'war/jenkins.war', 'logs/jenkins.log') {
    $p = Join-Path $jh $rel
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p))
    [IO.File]::WriteAllText($p, "content of $rel")
}
[IO.File]::WriteAllBytes((Join-Path $jh 'big.bin'), (New-Object byte[] (6MB)))
$global:FW.Files[(Get-FakeKey 'C:\Program Files\Jenkins\jenkins.xml')] = "<service><env name=`"JENKINS_HOME`" value=`"$jh`"/><executable>C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe</executable></service>"
$act = New-TakeBackupAction -Kind 'jenkins'
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $r.Output -notmatch 'could not be collected') "backup with a Jenkins home: all items collected ($($r.Output))"
if ($haveOpenssl) {
    $encJ = Join-Path (Get-BackupDir) $act.Data.Name
    Assert-Equal (Expand-WithOpenssl $encJ $pass $zipPath) 0 'it opens'
    $names = Get-ZipNames $zipPath
    $want = @('config.xml', 'credentials.xml', 'secret.key', 'hudson.model.UpdateCenter.xml', 'secrets/master.key', 'secrets/hudson.util.Secret', 'users/jmoney_1234/config.xml',
              'nodes/n1/config.xml', 'init.groovy.d/evil.groovy', 'jobs/rocket-build/config.xml', '_files.txt') | ForEach-Object { "jenkins/$_" }
    $missing = @($want | Where-Object { $names -notcontains $_ })
    Assert-True ($missing.Count -eq 0) "the settings, secrets, users, nodes, init scripts and job configs are saved (missing: $($missing -join ', '))"
    $unwanted = @($names | Where-Object { $_ -like 'jenkins/*' -and ($_ -match 'builds/|workspace/|plugins/|war/|logs/|big\.bin') })
    Assert-True ($unwanted.Count -eq 0) "builds, workspaces, plugins, the war, logs and big files are NOT saved ($($unwanted -join ', '))"
    Assert-True ((Read-ZipEntry $zipPath 'jenkins/_files.txt') -match 'JENKINS_HOME = ') 'jenkins/_files.txt says where it came from'
    Assert-True ((Read-ZipEntry $zipPath 'jenkins/secret.key') -eq 'content of secret.key') 'file contents are copied unchanged'
    Remove-Item -LiteralPath $zipPath -ErrorAction SilentlyContinue
}
Assert-True ((Get-Content -Path (Join-Path $jh 'config.xml') -Raw) -eq 'content of config.xml') 'and the Jenkins folder itself was only read, never changed'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Failures never leave readable files or half an archive' -ForegroundColor Cyan
function Get-LeftOvers { @(Get-AllFilesUnder (Get-BackupDir) | Where-Object { $_.Name -notlike '*.enc' -and $_.Name -notlike '*.enc.sha256' -and $_.Name -ne 'sent.json' }) + @(Microsoft.PowerShell.Management\Get-ChildItem -Path (Get-BackupDir) -Directory -ErrorAction SilentlyContinue) }
Assert-Equal (Get-LeftOvers).Count 0 'after the successful backups: no work folder, no plain zip'
$origItems = ${function:Save-BackupItems}
function Save-BackupItems { param([string]$Dir) Save-Text (Join-Path $Dir 'secret-plain.txt') 'readable'; throw 'boom while collecting' }
$r = Invoke-Change (New-TakeBackupAction -Kind 'broken-a') -Confirmed
Set-Item -Path Function:\Save-BackupItems -Value $origItems
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'boom') 'a failure in the collection is reported as FAILED'
Assert-Equal (Get-LeftOvers).Count 0 '... and the readable working folder is gone anyway'
Assert-True (@(Get-AllFilesUnder (Get-BackupDir) | Where-Object { $_.Name -like 'broken-a*' }).Count -eq 0) '... and no archive of that name exists'
$origProtect = ${function:Protect-File}
function Protect-File { param([string]$InFile, [string]$OutFile, [string]$Passphrase) $null = $InFile, $Passphrase; [IO.File]::WriteAllText($OutFile, 'half an archive'); throw 'boom while encrypting' }
$r = Invoke-Change (New-TakeBackupAction -Kind 'broken-b') -Confirmed
Set-Item -Path Function:\Protect-File -Value $origProtect
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'boom') 'a failure in the encryption is reported as FAILED'
Assert-Equal (Get-LeftOvers).Count 0 '... the plain zip and the work folder are deleted'
Assert-True (@(Get-AllFilesUnder (Get-BackupDir) | Where-Object { $_.Name -like 'broken-b*' }).Count -eq 0) '... and the half-written archive is deleted too (it must not look like a real backup)'
Assert-True ((Get-BackupFacts).Archives.Count -eq 3) 'the audit sees exactly the 3 good archives'
Clear-HpSecret 'backup-pass'
$r = Invoke-Change (New-TakeBackupAction -Kind 'nopass') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'passphrase is no longer in memory') 'without the passphrase in memory the action fails cleanly'
Assert-Equal (Get-LeftOvers).Count 0 '... and leaves nothing'
Set-HpSecret 'backup-pass' $pass
$name = (Get-BackupFacts).Archives[0].Name
Assert-Throws { New-BackupArchive -Name $name -Passphrase $pass } 'an archive is never overwritten'
Assert-Throws { Remove-BackupTemp (Get-BackupDir) } 'Remove-BackupTemp refuses the backup folder itself'
Assert-Throws { Remove-BackupTemp $tmp } 'Remove-BackupTemp refuses anything outside the backup folder'
Assert-Throws { Remove-BackupTemp (Join-Path (Split-Path -Parent (Get-BackupDir)) 'ssh') } 'Remove-BackupTemp refuses a sibling folder'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Step 3: pinning the blackbox host key (fake ssh-keyscan answers)' -ForegroundColor Cyan
$KeyA = 'AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g'
$FpA = 'SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4'
$KeyB = 'AAAAC3NzaC1lZDI1NTE5AAAAIGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOE'
$FpB = 'SHA256:1W2ewS2tqP5kZ7+6mzLn3s+beB4JAo9hmPJAzbJwIZ8'
$KeyR = 'AAAAB3NzaC1yc2EyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SV'
$paths = Get-BackupPaths
Set-HpSetting 'BlackboxIp' ''
Assert-True ($null -eq (Request-PinHostKey) -and $script:Notices[-1] -match 'Enter the blackbox IP first') 'no IP entered: refused before anything is asked'
Set-HpSetting 'BlackboxIp' '172.16.5.5'
$global:FW.KeyscanOutput = "# 172.16.5.5:22 SSH-2.0-OpenSSH_9.6`n172.16.5.5 ssh-ed25519 $KeyA`n172.16.5.5 ssh-rsa $KeyR`n"
$script:TextQueue.Enqueue('')
Assert-True ($null -eq (Request-PinHostKey)) 'an empty answer cancels'
$script:TextQueue.Enqueue('256 MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 root@blackbox (ED25519)')
Assert-True ($null -eq (Request-PinHostKey) -and $script:Notices[-1] -match 'No SHA256 fingerprint') 'an MD5 fingerprint is refused (it is not a SHA256 one)'
$script:TextQueue.Enqueue($FpB)
$a = Request-PinHostKey
Assert-True ($null -eq $a -and $script:Notices[-1] -match 'NOT PINNED' -and $script:Notices[-1] -match [regex]::Escape($FpA)) 'a fingerprint that matches none of the offered keys: NOT pinned, and the offered ones are shown'
$global:FW.KeyscanOutput = ''
$script:TextQueue.Enqueue($FpA)
Assert-True ($null -eq (Request-PinHostKey) -and $script:Notices[-1] -match 'No host key came back') 'blackbox offers nothing: reported, not pinned'
$global:FW.KeyscanOutput = "# 172.16.5.5:22 SSH-2.0-OpenSSH_9.6`n172.16.5.5 ssh-ed25519 $KeyA`n172.16.5.5 ssh-rsa $KeyR`n"
$script:TextQueue.Enqueue($FpA.Substring(0, $FpA.Length - 1) + 'X')
Assert-True ($null -eq (Request-PinHostKey) -and $script:Notices[-1] -match 'NOT PINNED') 'one wrong character in the fingerprint: NOT pinned'
$script:TextQueue.Enqueue($FpA.ToLowerInvariant())
Assert-True ($null -eq (Request-PinHostKey)) 'the comparison is case-sensitive (a lower-cased fingerprint does not match)'
Assert-True (-not (Test-Path $paths.KnownHosts)) 'so far nothing was written to known_hosts'
$script:TextQueue.Enqueue("256 $FpA root@blackbox (ED25519)")
$a = Request-PinHostKey
Assert-True ($null -ne $a -and $a.Data.Type -eq 'ssh-ed25519' -and $a.Data.Key -eq $KeyA) 'the whole line from ssh-keygen -l works; the matching key (ed25519, not the rsa one) is chosen'
$r = Invoke-Change $a -Confirmed
Assert-Equal $r.Status 'Applied' 'pinned'
Assert-Equal ([IO.File]::ReadAllText($paths.KnownHosts)) "172.16.5.5 ssh-ed25519 $KeyA`n" 'known_hosts has one line: IP, type, key'
Assert-True ((Get-BackupFacts).HostKeyPinned) 'the audit now sees the host key as pinned'
$pinId = $r.JournalId
# a second host, and re-pinning the first one with another key
Set-HpSetting 'BlackboxIp' '172.16.7.5'
$global:FW.KeyscanOutput = "172.16.7.5 ssh-ed25519 $KeyB`n"
$script:TextQueue.Enqueue($FpB)
$r = Invoke-Change (Request-PinHostKey) -Confirmed
Assert-Equal ([IO.File]::ReadAllText($paths.KnownHosts)) "172.16.5.5 ssh-ed25519 $KeyA`n172.16.7.5 ssh-ed25519 $KeyB`n" 'a second address is added; the first line stays'
Set-HpSetting 'BlackboxIp' '172.16.5.5'
$global:FW.KeyscanOutput = "172.16.5.5 ssh-ed25519 $KeyB`n"
$script:TextQueue.Enqueue($FpB)
$r2 = Invoke-Change (Request-PinHostKey) -Confirmed
Assert-Equal ([IO.File]::ReadAllText($paths.KnownHosts)) "172.16.7.5 ssh-ed25519 $KeyB`n172.16.5.5 ssh-ed25519 $KeyB`n" 'pinning an address again REPLACES its old line (never two keys for one address)'
$null = Undo-Change -Id $r2.JournalId -Confirmed
Assert-Equal ([IO.File]::ReadAllText($paths.KnownHosts)) "172.16.5.5 ssh-ed25519 $KeyA`n172.16.7.5 ssh-ed25519 $KeyB`n" 'undo puts the previous file back'
$null = Undo-Change -Id $r.JournalId -Confirmed
$null = Undo-Change -Id $pinId -Confirmed
Assert-True (-not (Get-BackupFacts).HostKeyPinned) 'undoing everything: not pinned any more'
$script:Plan.BlackboxPort = 2222
$global:FW.KeyscanOutput = "[172.16.5.5]:2222 ssh-ed25519 $KeyA`n"
$script:TextQueue.Enqueue($FpA)
$r = Invoke-Change (Request-PinHostKey) -Confirmed
Assert-Equal ([IO.File]::ReadAllText($paths.KnownHosts).Trim()) "[172.16.5.5]:2222 ssh-ed25519 $KeyA" 'on port 2222 the line is [IP]:port'
Assert-True ((Get-BackupFacts).HostKeyPinned) 'and the audit recognises that form'
$script:Plan.BlackboxPort = 22
Assert-True (-not (Get-BackupFacts).HostKeyPinned) '... but a pin for port 2222 is not a pin for port 22'
Save-Text $paths.KnownHosts ''

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Step 2: the SSH key action' -ForegroundColor Cyan
$act = New-BackupKeyAction
Assert-True ($act.Id -eq 'backup.key' -and $act.Will -join ' ' -match 'PRIVATE key stays on this box') 'the preview says the private key stays on the box'
Assert-Equal (Get-BackupUserName) 'uploader' 'the upload account is called uploader by default (Debian, Ubuntu and Mint already have a system account called backup)'
Set-HpSetting 'BackupUser' ''
Assert-Equal (Get-BackupUserName) 'uploader' '... also when the setting is empty'
Set-HpSetting 'BackupUser' 'dropper'
Assert-Equal (Get-BackupUserName) 'dropper' '... and the BackupUser setting wins when it is set'
Set-HpSetting 'BackupUser' 'uploader'
Save-Text $paths.Key 'pretend private key'
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'already exists') 'an existing key is never overwritten'
Assert-Equal ([IO.File]::ReadAllText($paths.Key)) 'pretend private key' '... and it is untouched'
Remove-Item -LiteralPath $paths.Key

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Step 5: sending is refused until the earlier steps are done' -ForegroundColor Cyan
Set-HpSetting 'BlackboxIp' ''
Assert-True ($null -eq (Request-SendBackup) -and $script:Notices[-1] -match 'Enter the blackbox IP first') 'no IP: refused'
Set-HpSetting 'BlackboxIp' '172.16.5.5'
Assert-True ($null -eq (Request-SendBackup) -and $script:Notices[-1] -match 'Create the backup key first') 'no key: refused'
Save-Text $paths.Key 'pretend private key'
Save-Text "$($paths.Key).pub" "ssh-ed25519 AAAAFAKE backup@ASSEMBLY-5`n"
Assert-True ($null -eq (Request-SendBackup) -and $script:Notices[-1] -match 'Pin the blackbox host key first') 'no pinned host key: refused'
Save-Text $paths.KnownHosts "172.16.5.5 ssh-ed25519 $KeyA`n"
$act = Request-SendBackup
Assert-True ($null -ne $act -and $act.Id -like 'backup.send:*' -and $act.Risk -eq 'Medium') 'everything in place: a send action for the NEWEST archive'
Assert-Equal $act.Data.Name ((Get-BackupFacts).Archives[-1].Name) 'it names the newest archive'
Assert-Equal $act.Data.User 'uploader' 'and the upload goes to the uploader account'
Assert-True (($act.Will -join ' ') -match 'only place a backup may go' -and ($act.Will -join ' ') -match 'cannot read the file back' -and ($act.Will -join ' ') -match 'LAPTOP') 'the preview says: blackbox only, upload-only account, verify from the laptop'
$global:FW.Tcp['172.16.5.5:22'] = $false
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'does not answer on port 22') 'blackbox not answering: nothing is attempted, the reason is shown'
Assert-True (-not (Test-Path (Join-Path (Get-BackupDir) 'sent.json'))) 'and nothing is recorded as sent'
$global:FW.Tcp['172.16.5.5:22'] = $true
$encPath = Join-Path (Get-BackupDir) $act.Data.Name
$original = [IO.File]::ReadAllBytes($encPath)
[IO.File]::WriteAllBytes($encPath, ($original + [byte]0))
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'no longer matches its \.sha256') 'an archive that changed after it was made is NOT sent'
[IO.File]::WriteAllBytes($encPath, $original)
Move-Item -LiteralPath "$encPath.sha256" -Destination "$encPath.sha256.hidden"
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match '\.sha256 is missing') 'a missing .sha256 file stops the upload'
Move-Item -LiteralPath "$encPath.sha256.hidden" -Destination "$encPath.sha256"
Move-Item -LiteralPath $paths.Key -Destination "$($paths.Key).hidden"
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'key is missing') 'a missing private key stops the upload'
Move-Item -LiteralPath "$($paths.Key).hidden" -Destination $paths.Key
$knownKeep = [IO.File]::ReadAllText($paths.KnownHosts)
Save-Text $paths.KnownHosts "172.16.9.9 ssh-ed25519 $KeyA`n"
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'No host key is pinned for 172\.16\.5\.5') 'a pin for ANOTHER address does not count'
Save-Text $paths.KnownHosts $knownKeep
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'scp failed') 'scp failing (here: the pretend scp does not exist) is FAILED, with the program output'
Assert-True (-not (Test-Path (Join-Path (Get-BackupDir) 'sent.json'))) 'and sent.json is NOT written for a failed upload'
Assert-True (-not ($r.Message -match [regex]::Escape($pass))) 'and the error text does not contain the passphrase'
Assert-True (-not ((Get-Content -Path (Join-Path $paths.Ssh 'known_hosts') -Raw) -match 'PRIVATE')) '(the private key text is not in known_hosts)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The judge offers the backup steps in the right order' -ForegroundColor Cyan
$facts = Get-HpFacts
$set = [pscustomobject]$script:Hp.Settings
$rows = @(Get-BackupFindings $facts $set)
Assert-True (@($rows | Where-Object { $_.Subject -eq 'Take another backup' -and $_.Severity -eq 'INFO' -and $_.Fix.Do -eq 'Request-BackupNow' }).Count -eq 1) 'with archives present: an INFO row "Take another backup" -> Request-BackupNow'
$local = @($rows | Where-Object { $_.Area -eq 'Backup' -and $_.Subject -like 'Local archives*' })
Assert-True ($local.Count -eq 1 -and $local[0].Why -match 'Rule 3' -and $local[0].Why -match 'ON blackbox' -and $local[0].Why -notmatch 'on the laptop') 'the "Local archives" row says: open it ON blackbox, never copy it to the laptop (rule 3)'
Assert-True (@($rows | Where-Object { $_.Subject -eq 'Nothing sent to blackbox yet' -and $_.Fix.Do -eq 'Request-SendBackup' -and -not $_.Blocked }).Count -eq 1) 'nothing sent yet: the send row is offered, not blocked'
$archives = @((Get-BackupFacts).Archives)
Save-Text (Join-Path (Get-BackupDir) 'sent.json') (ConvertTo-Json -InputObject ([ordered]@{ Name = $archives[0].Name; Time = '2026-10-17 10:00:00'; Sha256 = 'abc'; Ip = '172.16.5.5'; User = 'backup'; Bytes = 1 }))
$rows = @(Get-BackupFindings (Get-HpFacts) $set)
Assert-True (@($rows | Where-Object { $_.Subject -eq 'Newest backup not sent to blackbox yet' }).Count -eq 1) 'an OLDER archive was sent: the newest is flagged as not sent'
Save-Text (Join-Path (Get-BackupDir) 'sent.json') (ConvertTo-Json -InputObject ([ordered]@{ Name = $archives[-1].Name; Time = '2026-10-17 10:05:00'; Sha256 = 'abc'; Ip = '172.16.5.5'; User = 'backup'; Bytes = 1 }))
$rows = @(Get-BackupFindings (Get-HpFacts) $set)
Assert-True (@($rows | Where-Object { $_.Subject -eq 'Sent to blackbox' -and $_.Severity -eq 'OK' }).Count -eq 1) 'the newest was sent: green'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-TestSummary
