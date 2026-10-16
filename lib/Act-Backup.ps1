# Act-Backup.ps1 - phase 3: take an encrypted backup of the box and send it to blackbox with scp.
#
# The steps, in the order the audit offers them:
#   1. Request-BlackboxIp     remember blackbox's IP (you only learn it at the competition)
#   2. New-BackupKeyAction    make an SSH key pair; the public half goes to the restricted upload user on blackbox (default name: uploader)
#   3. Request-PinHostKey     type the fingerprint shown on the blackbox CONSOLE; the tool then trusts only that host key
#   4. Request-AsFoundBackup  collect the box's state, zip it, encrypt it (AES-256) - all local, in the data folder
#   5. Request-SendBackup     scp the encrypted archive + its SHA-256 file to blackbox
#
# Rules of the plan that are enforced here:
#   - the IP is a number, never a name; blackbox is the ONLY place a backup may go (rule 3)
#   - the host key is pinned from the console (no "trust on first use"); scp refuses any other key
#   - the passphrase and the private key never appear in the log, the journal or any argument list shown to you
#   - the plain-text working files are deleted as soon as the encrypted archive exists
# Windows PowerShell 5.1, plain ASCII. Needs .NET Framework 4.7.2 or newer for the encryption.

# ---------------------------------------------------------------- small helpers
function Get-SshToolPath {
    # Where ssh.exe, scp.exe, ssh-keygen.exe or ssh-keyscan.exe is. (The tests can point $script:Hp.ToolPaths at other programs.)
    param([string]$Name)
    $override = $script:Hp.ToolPaths
    if ($override -and $override[$Name]) { return [string]$override[$Name] }
    $path = Join-Path (Join-Path $env:SystemRoot 'System32') ('OpenSSH\' + $Name)
    if (Test-Path $path) { return $path }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return [string]$cmd.Source }
    throw "$Name was not found. Install the OpenSSH client first (the Backup rows show how)."
}

function Get-BackupUserName {
    # The upload-only account on blackbox: the BackupUser setting, or 'uploader' when it is empty.
    $name = [string](Get-HpSetting 'BackupUser')
    if (-not $name) { $name = 'uploader' }
    $name
}

function Get-BackupPaths {
    # The folders and files of the backup step. All of them are inside the data folder, which only SYSTEM and Administrators can open.
    $ssh = Get-HpDir 'ssh'
    @{
        Backup     = Get-HpDir 'backup'
        Ssh        = $ssh
        Key        = Join-Path $ssh 'id_backup'
        KnownHosts = Join-Path $ssh 'known_hosts'
    }
}

function Test-IpAddressText {
    # True for a plain IPv4 address like 172.16.5.5 (each part 0-255). A host NAME is not accepted on purpose.
    param([string]$Text)
    [bool]($Text -match '^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$')
}

function Save-Text {
    # Writes text to a file (UTF-8 without BOM), making the folder first if needed.
    param([string]$Path, [string]$Text)
    $folder = [System.IO.Path]::GetDirectoryName($Path)
    if ($folder -and -not [System.IO.Directory]::Exists($folder)) { [void][System.IO.Directory]::CreateDirectory($folder) }
    [System.IO.File]::WriteAllText($Path, $Text)
}

function Get-KnownHostsSpec {
    # How known_hosts names the host: the IP, or [IP]:port when the port is not 22.
    param([string]$Ip)
    if ([int]$script:Plan.BlackboxPort -eq 22) { return $Ip }
    "[$Ip]:$($script:Plan.BlackboxPort)"
}

# ---------------------------------------------------------------- 1. blackbox's IP
function Request-BlackboxIp {
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
    $team = Get-TeamInfo -Ips $ips -TeamNet ([string](Get-HpSetting 'TeamNet'))
    $default = [string](Get-HpSetting 'BlackboxIp')
    if (-not $default) { $default = $team.Blackbox }
    $ip = Read-HpText 'IP address of blackbox (the NUMBERS, never a name)' $default
    if (-not $ip) { return $null }
    $ip = $ip.Trim()
    if (-not (Test-IpAddressText $ip)) {
        Show-HpNotice 'That is not an IPv4 address like 172.16.5.5. Use the number, not a name.' 'Blackbox IP'
        return $null
    }
    New-BlackboxIpAction -Ip $ip
}

function New-BlackboxIpAction {
    param([string]$Ip)
    New-Action -Id 'settings.blackbox' -Title "Remember blackbox = $Ip" -Risk 'Low' `
        -Will @("Save $Ip as blackbox's address in the tool settings",
                'The audit then tests port 22 on it and looks for the program that sends the event logs to it',
                'Nothing on the box changes') `
        -Data @{ Ip = $Ip } `
        -Capture { param($d) $null = $d; @{ Old = [string](Get-HpSetting 'BlackboxIp') } } `
        -Apply { param($d, $before) $null = $before; Set-HpSetting 'BlackboxIp' $d.Ip; "Blackbox is $($d.Ip)." } `
        -UndoKind 'settings.blackbox'
}

Register-UndoHandler 'settings.blackbox' { param($data, $before) $null = $data; Set-HpSetting 'BlackboxIp' ([string]$before.Old) }

# ---------------------------------------------------------------- 2. the SSH key pair
function New-BackupKeyAction {
    New-Action -Id 'backup.key' -Title 'Create the backup SSH key pair' -Risk 'Low' `
        -Will @('Create an ed25519 key pair in the data folder (ssh\id_backup and ssh\id_backup.pub), without a passphrase so an upload can run without you',
                'The PRIVATE key stays on this box. Only the public key goes to blackbox, into the restricted upload user (RUNBOOK.md has the exact lines)',
                'Nothing else on the box changes') `
        -Capture {
            param($d)
            $null = $d
            $p = Get-BackupPaths
            if (Test-Path $p.Key) { throw 'A backup key already exists. Delete the files in the ssh folder by hand if you really want a new one.' }
            @{ Existed = $false }
        } `
        -Apply {
            param($d, $before)
            $null = $d, $before
            $p = Get-BackupPaths
            $keygen = Get-SshToolPath 'ssh-keygen.exe'
            # -N "" = no passphrase. Invoke-Native passes the empty argument through (a plain & call would drop it).
            $arguments = '-q -t ed25519 -N "" -C "backup@{0}" -f "{1}"' -f $env:COMPUTERNAME, $p.Key
            $r = Invoke-Native -Path $keygen -Arguments $arguments -TimeoutSec 30
            if ($r.ExitCode -ne 0 -or -not (Test-Path "$($p.Key).pub")) { throw "ssh-keygen failed (exit code $($r.ExitCode)): $(($r.StdErr + ' ' + $r.StdOut).Trim())" }
            $pub = ([System.IO.File]::ReadAllText("$($p.Key).pub")).Trim()
            "Key created. Put this line in ~$(Get-BackupUserName)/.ssh/authorized_keys on blackbox (the part in front restricts the key to uploads):`n" +
                "restrict,command=`"scp -t /srv/backup/incoming`" $pub"
        } `
        -NoUndo 'creating the files (delete the ssh folder by hand to start over)'
}

# ---------------------------------------------------------------- 3. pin blackbox's host key
function Get-HostKeyFingerprint {
    # "SHA256:xxxx" for a host key given as base64 - the same text ssh-keygen -l prints on the blackbox console.
    param([string]$Base64)
    $bytes = [Convert]::FromBase64String($Base64)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($bytes) } finally { $sha.Dispose() }
    'SHA256:' + ([Convert]::ToBase64String($hash)).TrimEnd('=')
}

function Request-PinHostKey {
    $ip = [string](Get-HpSetting 'BlackboxIp')
    if (-not $ip) { Show-HpNotice 'Enter the blackbox IP first.' 'Blackbox host key'; return $null }
    $typed = Read-HpText 'Host key fingerprint as printed ON THE BLACKBOX CONSOLE by:  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub   (paste the whole line or just the SHA256:... part)'
    if (-not $typed) { return $null }
    $m = [regex]::Match($typed, '(?<![A-Za-z0-9+/])(?:SHA256:)?([A-Za-z0-9+/]{43})(?![A-Za-z0-9+/=])')
    if (-not $m.Success) {
        Show-HpNotice 'No SHA256 fingerprint found in what you typed. It looks like SHA256: followed by 43 characters. An MD5 fingerprint is not accepted.' 'Blackbox host key'
        return $null
    }
    $want = 'SHA256:' + $m.Groups[1].Value

    # ask blackbox for the keys it offers, and keep only the one whose fingerprint is the one you read on its console
    $scan = Invoke-Native -Path (Get-SshToolPath 'ssh-keyscan.exe') -Arguments ('-T 8 -p {0} {1}' -f $script:Plan.BlackboxPort, $ip) -TimeoutSec 30
    $seen = @()
    foreach ($line in ($scan.StdOut -split "`r?`n")) {
        if ($line -match '^\S+\s+((?:ssh|ecdsa)-\S+)\s+([A-Za-z0-9+/=]+)\s*$') {
            $seen += [pscustomobject]@{ Type = $Matches[1]; Base64 = $Matches[2]; Fingerprint = (Get-HostKeyFingerprint $Matches[2]) }
        }
    }
    if ($seen.Count -eq 0) {
        Show-HpNotice "No host key came back from $ip port $($script:Plan.BlackboxPort). Blackbox may be down, the IP may be wrong, or the firewall may block it. $($scan.StdErr.Trim())" 'Blackbox host key'
        return $null
    }
    $hit = @($seen | Where-Object { $_.Fingerprint -ceq $want }) | Select-Object -First 1
    if (-not $hit) {
        $list = ($seen | ForEach-Object { "$($_.Type) $($_.Fingerprint)" }) -join "`n"
        Show-HpNotice "NOT PINNED. The host at $ip offers:`n$list`n`nNone of them is the fingerprint you typed ($want). Either you typed it wrong, or something that is not the blackbox answers on that address. Do not send backups there." 'Blackbox host key'
        return $null
    }
    New-PinHostKeyAction -Ip $ip -Type $hit.Type -Base64 $hit.Base64 -Fingerprint $hit.Fingerprint
}

function New-PinHostKeyAction {
    param([string]$Ip, [string]$Type, [string]$Base64, [string]$Fingerprint)
    New-Action -Id 'backup.pin' -Title "Trust the blackbox host key $Fingerprint" -Risk 'Low' `
        -Will @("From now on the upload to $Ip accepts ONLY the $Type host key with the fingerprint $Fingerprint",
                'It is written to the tool''s own known_hosts file (data folder, ssh), not to the system-wide one',
                'Any other key makes the upload fail instead of sending your backup to a stranger') `
        -Data @{ Ip = $Ip; Spec = (Get-KnownHostsSpec $Ip); Type = $Type; Key = $Base64; Fingerprint = $Fingerprint } `
        -Capture {
            param($d)
            $null = $d
            $p = Get-BackupPaths
            @{ Previous = $(if (Test-Path $p.KnownHosts) { [System.IO.File]::ReadAllText($p.KnownHosts) } else { '' }) }
        } `
        -Apply {
            param($d, $before)
            $p = Get-BackupPaths
            # keep the other lines, drop an older line for this same host, add the new one
            $keep = @(([string]$before.Previous -split "`r?`n") | Where-Object { $_ -and -not $_.StartsWith($d.Spec + ' ') })
            $keep += ('{0} {1} {2}' -f $d.Spec, $d.Type, $d.Key)
            Save-Text $p.KnownHosts (($keep -join "`n") + "`n")
            "Pinned $($d.Fingerprint) for $($d.Ip)."
        } `
        -UndoKind 'backup.pin'
}

Register-UndoHandler 'backup.pin' {
    param($data, $before)
    $null = $data
    Save-Text (Get-BackupPaths).KnownHosts ([string]$before.Previous)
}

# ---------------------------------------------------------------- the passphrase of the archives
function Get-BackupPassphrase {
    # Asked once per run of the tool and kept in memory only. Without it an archive cannot be opened, so it belongs in Bitwarden.
    $p = Get-HpSecret 'backup-pass'
    if ($p) { return $p }
    $p1 = Read-HpSecret 'Backup passphrase (from Bitwarden, 16+ characters). You need it to open a backup later; it is NOT saved on this box.'
    if (-not $p1) { return $null }
    $p2 = Read-HpSecret 'Type the same passphrase again'
    if ($p1 -cne $p2) { Show-HpNotice 'The two entries are different.' 'Backup passphrase'; return $null }
    if ($p1.Length -lt 16) { Show-HpNotice "Only $($p1.Length) characters. Use at least 16." 'Backup passphrase'; return $null }
    Set-HpSecret 'backup-pass' $p1
    $p1
}

# ---------------------------------------------------------------- 4. collect, zip, encrypt
function Invoke-BackupItem {
    # Runs ONE piece of the backup. If it fails, the failure is written in the manifest and the backup carries on with the next piece.
    # $Code gets the working folder (and the -With values) as arguments and returns text to save as $Name, or returns nothing when it wrote its own files.
    # The values are passed in, not read from the caller's variables: a block run from here would see THIS function's $Name instead of the caller's.
    param([string]$Dir, $Log, [string]$Name, [scriptblock]$Code, [object[]]$With = @())
    try {
        $text = & $Code $Dir @With
        if ($null -ne $text) { Save-Text (Join-Path $Dir $Name) ([string]$text) }
        [void]$Log.Add("OK      $Name")
    } catch {
        [void]$Log.Add("FAILED  $Name : $($_.Exception.Message)")
        Write-HpLog "backup item $Name failed: $($_.Exception.Message)" 'WARN'
    }
}

function Export-RegKey {
    # reg.exe export for one key. A key that does not exist is not an error (not every box has every autostart key).
    param([string]$Dir, [string]$Name, [string]$Key)
    $file = Join-Path $Dir "registry/$Name.reg"
    $folder = [System.IO.Path]::GetDirectoryName($file)
    if (-not [System.IO.Directory]::Exists($folder)) { [void][System.IO.Directory]::CreateDirectory($folder) }
    $r = Invoke-Native -Path 'reg.exe' -Arguments ('export "{0}" "{1}" /y' -f $Key, $file) -TimeoutSec 30
    if ($r.ExitCode -eq 0) { return }
    if (($r.StdErr + $r.StdOut) -match 'unable to find') { Save-Text $file ";key not present: $Key"; return }
    throw "reg export failed ($($r.ExitCode)): $(($r.StdErr + ' ' + $r.StdOut).Trim())"
}

function Get-JenkinsBackupFiles {
    # What is worth keeping from JENKINS_HOME: the settings, credentials, secrets, users, nodes, init scripts and each job's config.xml.
    # Not the plugins, workspaces or build logs: they are big and can be downloaded again.
    param([string]$JenkinsHome)
    $limit = 5MB
    $list = New-Object System.Collections.ArrayList
    $root = New-Object System.IO.DirectoryInfo($JenkinsHome)
    foreach ($f in $root.GetFiles()) { if ($f.Length -le $limit) { [void]$list.Add($f) } }
    foreach ($sub in 'secrets', 'users', 'nodes', 'init.groovy.d', 'casc_configs') {
        $folder = Join-Path $JenkinsHome $sub
        if (Test-Path $folder) {
            foreach ($f in (New-Object System.IO.DirectoryInfo($folder)).GetFiles('*', [System.IO.SearchOption]::AllDirectories)) { if ($f.Length -le $limit) { [void]$list.Add($f) } }
        }
    }
    $jobs = Join-Path $JenkinsHome 'jobs'
    if (Test-Path $jobs) {
        foreach ($f in (New-Object System.IO.DirectoryInfo($jobs)).GetFiles('config.xml', [System.IO.SearchOption]::AllDirectories)) { [void]$list.Add($f) }
    }
    $list
}

function Copy-JenkinsFiles {
    param([string]$Dir)
    $j = Get-JenkinsFacts -Services @(Get-ServiceFacts) -Listeners @()
    if (-not $j.Found) { throw 'no Jenkins service was found' }
    if (-not $j.HomeFound) { throw 'the Jenkins home folder was not found' }
    $root = [string]$j.Home
    $target = Join-Path $Dir 'jenkins'
    $total = 0; $count = 0
    $names = @()
    foreach ($f in (Get-JenkinsBackupFiles -JenkinsHome $root)) {
        $relative = $f.FullName.Substring($root.Length).TrimStart('\', '/')
        if ($total + $f.Length -gt 100MB) { $names += "SKIPPED (100 MB limit): $relative"; continue }
        try {
            $dest = Join-Path $target $relative
            $folder = [System.IO.Path]::GetDirectoryName($dest)
            if (-not [System.IO.Directory]::Exists($folder)) { [void][System.IO.Directory]::CreateDirectory($folder) }
            [System.IO.File]::Copy($f.FullName, $dest, $true)
            $total += $f.Length; $count++
            $names += "$($f.Length)  $relative"
        } catch {
            $names += "NOT COPIED ($($_.Exception.Message)): $relative"      # one locked file must not lose the rest
        }
    }
    Save-Text (Join-Path $target '_files.txt') ("JENKINS_HOME = $root`r`nCopied $count files, $total bytes`r`n" + ($names -join "`r`n"))
}

function Get-SoftwareText {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $apps = @()
    foreach ($k in $keys) {
        $apps += @(Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate)
    }
    ($apps | Sort-Object DisplayName | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
}

function Get-ProcessCsv {
    # Every running process with its program file and who signed it.
    $signed = @{}
    $rows = @()
    foreach ($p in @(Get-Process)) {
        $path = ''
        try { $path = [string]$p.Path } catch { $path = '' }
        if ($path -and -not $signed.ContainsKey($path)) {
            try { $s = Get-AuthenticodeSignature -FilePath $path; $signed[$path] = "$($s.Status) $($s.SignerCertificate.Subject)".Trim() }
            catch { $signed[$path] = 'error' }
        }
        $rows += [pscustomobject]@{ Id = $p.Id; Name = $p.ProcessName; Path = $path; Signature = $(if ($path) { $signed[$path] } else { '' }) }
    }
    ($rows | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
}

function Save-BackupItems {
    # The as-found baseline: what the box looks like right now. Everything here only READS the box.
    param([string]$Dir)
    $log = New-Object System.Collections.ArrayList

    Invoke-BackupItem $Dir $log 'facts.json' { ConvertTo-Json -InputObject (Get-HpFacts) -Depth 6 }
    Invoke-BackupItem $Dir $log 'users.txt' { Invoke-NativeText 'net.exe' 'user' }
    Invoke-BackupItem $Dir $log 'local-groups.txt' {
        $text = ''
        foreach ($g in @(Get-LocalGroup)) { $text += "=== $($g.Name)`r`n" + (Invoke-NativeText 'net.exe' ('localgroup "{0}"' -f $g.Name)) + "`r`n" }
        $text
    }
    Invoke-BackupItem $Dir $log 'whoami.txt' { Invoke-NativeText 'whoami.exe' '/all' }
    Invoke-BackupItem $Dir $log 'secedit.inf' {
        param($workDir)
        $null = Invoke-NativeText 'secedit.exe' ('/export /cfg "{0}" /areas USER_RIGHTS SECURITYPOLICY' -f (Join-Path $workDir 'secedit.inf'))
    }
    Invoke-BackupItem $Dir $log 'auditpol.txt' { Invoke-NativeText 'auditpol.exe' '/get /category:*' }
    Invoke-BackupItem $Dir $log 'firewall.wfw' {
        param($workDir)
        $null = Invoke-NativeText 'netsh.exe' ('advfirewall export "{0}"' -f (Join-Path $workDir 'firewall.wfw'))
    }
    Invoke-BackupItem $Dir $log 'firewall-profiles.txt' { Invoke-NativeText 'netsh.exe' 'advfirewall show allprofiles' }
    Invoke-BackupItem $Dir $log 'firewall-rules.txt' { Invoke-NativeText 'netsh.exe' 'advfirewall firewall show rule name=all' 120 }
    Invoke-BackupItem $Dir $log 'services.csv' {
        Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName | ConvertTo-Csv -NoTypeInformation | Out-String
    }
    Invoke-BackupItem $Dir $log 'hosts.txt' { Get-Content -Path (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Raw }
    Invoke-BackupItem $Dir $log 'route.txt' { Invoke-NativeText 'route.exe' 'print' }
    Invoke-BackupItem $Dir $log 'netstat.txt' { Invoke-NativeText 'netstat.exe' '-ano' }
    Invoke-BackupItem $Dir $log 'shares.txt' { Invoke-NativeText 'net.exe' 'share' }
    Invoke-BackupItem $Dir $log 'sessions.txt' { Invoke-NativeText 'qwinsta.exe' '' }
    Invoke-BackupItem $Dir $log 'software.csv' { Get-SoftwareText }
    Invoke-BackupItem $Dir $log 'defender-settings.txt' { Get-MpPreference | Format-List * | Out-String -Width 200 }
    Invoke-BackupItem $Dir $log 'processes.csv' { Get-ProcessCsv }
    Invoke-BackupItem $Dir $log 'wmi-subscriptions.txt' {
        $text = ''
        foreach ($class in '__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding') {
            $text += "=== $class`r`n" + (Get-CimInstance -Namespace 'root/subscription' -ClassName $class -ErrorAction SilentlyContinue | Format-List * | Out-String) + "`r`n"
        }
        $text
    }
    Invoke-BackupItem $Dir $log 'startup-folders.txt' {
        $lines = @()
        foreach ($folder in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup")) {
            $lines += "== $folder"
            $lines += @(Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        }
        $lines -join "`r`n"
    }
    Invoke-BackupItem $Dir $log 'gpresult.html' {
        param($workDir)
        $null = Invoke-NativeText 'gpresult.exe' ('/scope computer /h "{0}" /f' -f (Join-Path $workDir 'gpresult.html')) 120
    }

    # scheduled tasks outside \Microsoft\, one XML file each
    foreach ($t in @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
        $safe = (($t.TaskPath + $t.TaskName) -replace '[^A-Za-z0-9._-]', '_')
        Invoke-BackupItem $Dir $log "tasks/$safe.xml" { param($workDir, $task) $null = $workDir; Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath } -With $t
    }

    # registry keys that malware and admins like to use (autostart, logon, Remote Desktop, policies)
    $keys = [ordered]@{
        'run-machine'        = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'runonce-machine'    = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'run-32bit'          = 'HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        'run-user'           = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'winlogon'           = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        'appinit'            = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
        'image-file-options' = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        'terminal-server'    = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
        'lsa'                = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        'system-policies'    = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        'firewall-policy'    = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall'
        'defender-policy'    = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
    }
    foreach ($regName in $keys.Keys) {
        Invoke-BackupItem $Dir $log "registry/$regName.reg" { param($workDir, $n, $k) Export-RegKey -Dir $workDir -Name $n -Key $k } -With $regName, $keys[$regName]
    }

    Invoke-BackupItem $Dir $log 'jenkins/' { param($workDir) Copy-JenkinsFiles -Dir $workDir }
    $log
}

function Protect-File {
    # AES-256-CBC with a key made from the passphrase by PBKDF2-HMAC-SHA256 (200000 rounds), written in the format of
    #   openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -md sha256
    # so that OpenSSL on blackbox can open it (never on the laptop: rule 3):  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -in X.zip.enc -out X.zip
    # File layout: the 8 letters Salted__, 8 bytes of salt, then the encrypted data.
    param([string]$InFile, [string]$OutFile, [string]$Passphrase)
    $salt = New-Object byte[] 8
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $random.GetBytes($salt)
    $random.Dispose()
    try {
        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 200000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch {
        throw "The archive encryption needs .NET Framework 4.7.2 or newer. $($_.Exception.Message)"
    }
    $key = $kdf.GetBytes(32)
    $iv = $kdf.GetBytes(16)
    $kdf.Dispose()
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $iv
    $in = [System.IO.File]::OpenRead($InFile)
    $out = [System.IO.File]::Create($OutFile)
    try {
        $header = [System.Text.Encoding]::ASCII.GetBytes('Salted__')
        $out.Write($header, 0, $header.Length)
        $out.Write($salt, 0, $salt.Length)
        $crypto = New-Object System.Security.Cryptography.CryptoStream($out, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
        $in.CopyTo($crypto)
        $crypto.FlushFinalBlock()
        $crypto.Dispose()
    } finally {
        $in.Dispose()
        $out.Dispose()
        $aes.Dispose()
    }
}

function Remove-BackupTemp {
    # Deletes ONE temporary thing this tool made (the plain-text working folder or the plain zip). It refuses anything outside the backup folder.
    param([string]$Path)
    $root = (Get-BackupPaths).Backup
    if (-not $Path.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) -or $Path.Length -le $root.Length) { throw "Refused: '$Path' is not inside the backup folder." }
    if (Test-Path $Path) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
}

function New-BackupArchive {
    # Collect -> zip -> encrypt -> hash. The plain-text working files are deleted at the end, also when something fails.
    param([string]$Name, [string]$Passphrase, [string]$Kind = 'backup')
    $paths = Get-BackupPaths
    $stage = Join-Path $paths.Backup ('work-' + [guid]::NewGuid().ToString('N'))
    $zip = Join-Path $paths.Backup ($Name -replace '\.enc$', '')
    $enc = Join-Path $paths.Backup $Name
    if (Test-Path $enc) { throw "The archive $Name already exists." }
    [void][System.IO.Directory]::CreateDirectory($stage)
    $done = $false
    try {
        $report = @(Save-BackupItems -Dir $stage | Where-Object { $_ -is [string] })     # only the report lines, nothing else
        $failed = @($report | Where-Object { $_ -like 'FAILED*' })
        $header = @("Backup kind : $Kind", "Computer    : $($env:COMPUTERNAME)", "Taken       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", "Items       : $($report.Count), failed: $($failed.Count)", '')
        Save-Text (Join-Path $stage '_manifest.txt') (($header + $report) -join "`r`n")
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)
        Protect-File -InFile $zip -OutFile $enc -Passphrase $Passphrase
        $done = $true
    } finally {
        Remove-BackupTemp $stage
        Remove-BackupTemp $zip
        if (-not $done -and (Test-Path $enc)) { Remove-BackupTemp $enc }       # never leave half an archive that looks like a real one
    }
    $hash = Get-Sha256Hex $enc
    $bytes = (Get-Item $enc).Length
    Save-Text "$enc.sha256" "$hash  $Name`n"
    [pscustomobject]@{ Name = $Name; Path = $enc; Bytes = [long]$bytes; Sha256 = $hash; Items = $report.Count; Failed = $failed }
}

function Request-AsFoundBackup { Request-Backup -Kind 'as-found' }
function Request-BackupNow { Request-Backup -Kind 'backup' }

function Request-Backup {
    param([string]$Kind)
    if (-not (Get-BackupPassphrase)) { return $null }
    New-TakeBackupAction -Kind $Kind
}

function New-TakeBackupAction {
    param([string]$Kind)
    $name = '{0}-{1}.zip.enc' -f $Kind, (Get-Date -Format 'yyyyMMdd-HHmmss')
    New-Action -Id "backup.take:$name" -Title "Take the $Kind backup ($name)" -Risk 'Low' `
        -Will @('Read the state of this box: users and groups, security and audit policy, firewall, scheduled tasks, services, ports, autostart registry keys, Defender settings, running programs, Jenkins files',
                "Put it all in one archive, encrypted with AES-256 and your backup passphrase (the passphrase is NOT saved: without it the archive cannot be opened)",
                'Everything stays LOCAL in the data folder (backup). Nothing is sent until you use "Send to blackbox"',
                'The plain-text working files are deleted as soon as the encrypted archive exists',
                'Nothing on the system is changed. It takes about a minute.') `
        -Data @{ Name = $name; Kind = $Kind } `
        -Capture { param($d) @{ Existed = [bool](Test-Path (Join-Path (Get-BackupPaths).Backup $d.Name)) } } `
        -Apply {
            param($d, $before)
            $null = $before
            $pass = Get-HpSecret 'backup-pass'
            if (-not $pass) { throw 'The backup passphrase is no longer in memory. Start the action again.' }
            $a = New-BackupArchive -Name $d.Name -Passphrase $pass -Kind $d.Kind
            $text = "$($a.Name): $($a.Bytes) bytes, $($a.Items) items, SHA-256 $($a.Sha256)."
            if ($a.Failed.Count -gt 0) { $text += " $($a.Failed.Count) item(s) could not be collected (see _manifest.txt inside): " + (($a.Failed | ForEach-Object { ($_ -split ' : ')[0] -replace '^FAILED\s+', '' }) -join ', ') }
            $text
        } `
        -NoUndo 'taking the backup (nothing on the system changed; delete the file by hand if you do not want it)'
}

# ---------------------------------------------------------------- 5. send it to blackbox with scp
function Get-ScpArguments {
    # The scp command line. Every option is there for a reason.
    param([string]$Key, [string]$KnownHosts, [int]$Port, [bool]$Legacy, [string[]]$Files, [string]$Target)
    $nothing = $(if ($env:OS -eq 'Windows_NT') { 'NUL' } else { '/dev/null' })
    $o = @(
        "-P $Port"
        "-i `"$Key`""
        '-o BatchMode=yes'                          # never ask anything: no password, no "trust this host?"
        '-o PasswordAuthentication=no'
        '-o IdentitiesOnly=yes'                     # use only this key, not whatever an agent offers
        '-o StrictHostKeyChecking=yes'              # refuse any host key that is not in the pinned file
        "-o UserKnownHostsFile=`"$KnownHosts`""     # only OUR pinned file ...
        "-o GlobalKnownHostsFile=$nothing"          # ... and not the system-wide one
        '-o UpdateHostKeys=no'
        '-o ConnectTimeout=10'
        '-o ServerAliveInterval=5'
        '-o ServerAliveCountMax=3'
    )
    if ($Legacy) { $o += '-O' }                     # OpenSSH 9.0+ would otherwise use SFTP, which the upload-only account does not allow
    foreach ($f in $Files) { $o += "`"$f`"" }
    $o += $Target
    $o -join ' '
}

function Test-ScpNeedsLegacyFlag {
    # scp from OpenSSH 9.0 on speaks SFTP unless told -O. The Windows 10/Server 2022 client is 8.1, which does not know -O at all.
    param([string]$VersionText)
    if ($VersionText -match 'OpenSSH(?:_for_Windows)?_(\d+)\.(\d+)') { return ([int]$Matches[1] -ge 9) }
    $false
}

function Get-PinnedKeyType {
    # The key type (for example ssh-ed25519) that was pinned for this address in the tool's own known_hosts file; '' when there is none.
    param([string]$Ip)
    $p = Get-BackupPaths
    if (-not (Test-Path $p.KnownHosts)) { return '' }
    $spec = Get-KnownHostsSpec $Ip
    $line = @([System.IO.File]::ReadAllLines($p.KnownHosts) | Where-Object { $_.StartsWith($spec + ' ') }) | Select-Object -First 1
    if (-not $line) { return '' }
    ($line -split '\s+')[1]
}

function Request-SendBackup {
    $bk = Get-BackupFacts
    $ip = [string](Get-HpSetting 'BlackboxIp')
    $problem = ''
    if (-not $ip) { $problem = 'Enter the blackbox IP first.' }
    elseif (-not $bk.KeyExists) { $problem = 'Create the backup key first.' }
    elseif (-not $bk.HostKeyPinned) { $problem = 'Pin the blackbox host key first.' }
    elseif (@($bk.Archives).Count -eq 0) { $problem = 'There is no backup to send. Take one first.' }
    if ($problem) { Show-HpNotice $problem 'Send backup'; return $null }
    $newest = @($bk.Archives)[-1]
    New-SendBackupAction -Name $newest.Name -Ip $ip -User (Get-BackupUserName)
}

function New-SendBackupAction {
    param([string]$Name, [string]$Ip, [string]$User)
    New-Action -Id "backup.send:$Name" -Title "Send $Name to blackbox ($Ip)" -Risk 'Medium' `
        -Will @("Upload $Name and its .sha256 file to ${User}@${Ip} with scp (blackbox is the only place a backup may go)",
                'The upload accepts ONLY the host key you pinned (StrictHostKeyChecking=yes, no password, no agent, no questions)',
                "It needs outbound TCP $($script:Plan.BlackboxPort) to ${Ip}: the outbound allow rule for the team network covers it",
                'This box cannot read the file back (the upload account can do nothing but upload). Check it from the LAPTOP: ssh to blackbox as your admin account and run sudo sha256sum on /srv/backup/incoming/<the archive name> (RUNBOOK.md 5.3); the result must equal the hash shown afterwards') `
        -Data @{ Name = $Name; Ip = $Ip; User = $User } `
        -Capture {
            # read-only checks: stop BEFORE anything is sent if something is wrong
            param($d)
            $p = Get-BackupPaths
            $enc = Join-Path $p.Backup $d.Name
            if (-not (Test-Path $enc)) { throw "The archive $($d.Name) is not in the backup folder." }
            if (-not (Test-Path "$enc.sha256")) { throw "The file $($d.Name).sha256 is missing. Without it the archive cannot be checked on blackbox." }
            $want = (([System.IO.File]::ReadAllText("$enc.sha256")).Trim() -split '\s+')[0]
            if ((Get-Sha256Hex $enc) -ne $want) { throw "The archive $($d.Name) no longer matches its .sha256 file: it was changed after it was made, so it is not sent." }
            if (-not (Test-Path $p.Key)) { throw 'The backup key is missing. Create it first.' }
            if (-not (Get-PinnedKeyType $d.Ip)) { throw "No host key is pinned for $($d.Ip). Pin the blackbox host key first." }
            if (-not (Test-TcpOpen -HostName $d.Ip -Port $script:Plan.BlackboxPort)) {
                throw "Blackbox $($d.Ip) does not answer on port $($script:Plan.BlackboxPort). Is it up, is the IP right, and does the outbound firewall allow the team network?"
            }
            @{ Sha256 = $want }
        } `
        -Apply {
            param($d, $before)
            $p = Get-BackupPaths
            $scp = Get-SshToolPath 'scp.exe'
            $legacy = Test-ScpNeedsLegacyFlag (Get-SshVersion (Get-SshToolPath 'ssh.exe'))
            # the two files are named without a folder (the program runs INSIDE the backup folder), so scp can never mistake C:\ for a host name
            $files = @($d.Name, "$($d.Name).sha256")
            $arguments = Get-ScpArguments -Key $p.Key -KnownHosts $p.KnownHosts -Port ([int]$script:Plan.BlackboxPort) -Legacy $legacy -Files $files -Target "$($d.User)@$($d.Ip):"
            $r = Invoke-Native -Path $scp -Arguments $arguments -TimeoutSec 300 -WorkingDirectory $p.Backup
            if ($r.TimedOut) { throw 'scp did not finish within 5 minutes and was stopped.' }
            if ($r.ExitCode -ne 0) { throw "scp failed (exit code $($r.ExitCode)): $(($r.StdErr + ' ' + $r.StdOut).Trim())" }
            $record = [ordered]@{ Name = $d.Name; Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Sha256 = [string]$before.Sha256; Ip = $d.Ip; User = $d.User; Bytes = (Get-Item (Join-Path $p.Backup $d.Name)).Length }
            Save-Text (Join-Path $p.Backup 'sent.json') (ConvertTo-Json -InputObject $record)
            "Sent $($d.Name) to $($d.Ip). SHA-256 $($before.Sha256). Verify it from the LAPTOP (RUNBOOK.md 5.3): ssh -t <your admin account>@$($d.Ip) sudo sha256sum /srv/backup/incoming/$($d.Name)"
        } `
        -NoUndo 'the upload (the file stays on blackbox)'
}
