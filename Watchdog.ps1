<#
Watchdog.ps1 - keeps the two scored services alive on assembly-t, and tells you when something changes.

The tool's Watchdog phase installs this as the SYSTEM scheduled task "NetCacheWatch", which runs this file once a minute.
Each run is ONE pass:
  CHECK   Remote Desktop, the scoring user, Jenkins, the two firewall allow rules                    (every pass)
  HEAL    a check that fails gets the matching repair from Panic.ps1 (never more than once per 2 minutes per check)
  EVENTS  new security events (accounts, groups, tasks, services, audit policy, cleared logs) and bursts of failed logons
  SLOW    every 5th pass: what changed since the baseline, the Remote Desktop logon right, Defender, the blackbox link,
          the Jenkins job files and the last build of each job (these only raise alerts, they repair nothing)
  WRITE   alerts.log (what happened, oldest first) and status.json (what is true now; the tool reads it)

It never sets or changes a password, never deletes an account, never kills a program, never uses the Internet. It switches things ON.
The repairs are the ones Panic.ps1 has, plus Restore-OurRules (below): it rebuilds the two firewall allow rules HP-Allow-TCP-3389 and
HP-Allow-TCP-8080 (those two are the only things it deletes, to make them new) and switches OFF a firewall Block rule that stops a scored
port for every address. One repair ends open Remote Desktop sessions: if Remote Desktop was moved to another port, putting 3389 back
restarts TermService. The Jenkins files are left alone; only -RestoreJob (by hand, never by itself) copies one saved job file back.

Run it by hand in an elevated PowerShell (the copy the tool installed is in C:\ProgramData\NetCacheSvc\watchdog):
    powershell -ep bypass .\Watchdog.ps1                       one pass now, shown on screen
    powershell -ep bypass .\Watchdog.ps1 -Status               the latest status and the last alerts
    powershell -ep bypass .\Watchdog.ps1 -Pause 10             stop repairing for 10 minutes (checks and alerts go on)
    powershell -ep bypass .\Watchdog.ps1 -Resume               repair again
    powershell -ep bypass .\Watchdog.ps1 -Rebaseline           take the baseline again (after hardening and the hunt)
    powershell -ep bypass .\Watchdog.ps1 -AcceptJobs           accept the Jenkins job files as they are now
    powershell -ep bypass .\Watchdog.ps1 -RestoreJob NAME      put the last good config.xml of a job back
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'the parameters are read inside the functions below')]
param(
    [string]$DataDir = 'C:\ProgramData\NetCacheSvc',
    [string]$Dir = '',
    [switch]$NoHeal,
    [int]$Pause = 0,
    [switch]$Resume,
    [switch]$Rebaseline,
    [switch]$AcceptJobs,
    [string]$RestoreJob = '',
    [switch]$Status
)
$ErrorActionPreference = 'Continue'      # each part of a pass has its own try/catch; one failing part must not stop the others
if (-not $Dir) { $Dir = Join-Path $DataDir 'watchdog' }

# ---------------------------------------------------------------- what it protects (a test checks these against $script:Plan in lib\Core.ps1)
$ScoringUser = 'jmoney'
$ScoredPorts = @(3389, 8080)
$Version = 1
$HealGapSeconds = 120                    # a check that keeps failing is repaired at most this often
$SlowEvery = 5                           # the slow checks run on every 5th pass
$BurstLimit = 20                         # this many failed logons within 5 minutes count as a password-guessing burst
$OwnTasks = @('NetCacheWatch', 'NetCacheRestore')       # this watchdog and the dead-man switch: never reported as "new tasks"
$CheckNames = @('rdp', 'jmoney', 'jenkins', 'firewall', 'rights', 'defender', 'blackbox', 'jobs', 'builds')
$BaselineNames = @('users', 'admins', 'rdpusers', 'ports', 'tasks', 'services', 'runkeys', 'startup', 'hosts', 'shares', 'routes', 'firewall')
$EventWatch = @(
    @{ Log = 'Security'; Ids = @(4720, 4722, 4724, 4728, 4732, 4738, 4740, 4719, 4698, 1102) },
    @{ Log = 'System'; Ids = @(7045, 104) }
)

# ---------------------------------------------------------------- the files (all inside $Dir)
$AlertFile  = Join-Path $Dir 'alerts.log'
$StateFile  = Join-Path $Dir 'state.json'
$StatusFile = Join-Path $Dir 'status.json'
$ConfigFile = Join-Path $Dir 'config.json'
$BaseDir    = Join-Path $Dir 'baseline'
$GoodDir    = Join-Path $Dir 'jobs-good'
$PauseFile  = Join-Path $Dir 'pause.txt'
$RebaseFlag = Join-Path $Dir 'rebaseline.flag'
$AcceptFlag = Join-Path $Dir 'acceptjobs.flag'
$LockFile   = Join-Path $Dir 'run.lock'

# The repairs come from Panic.ps1, which sits next to this file. Loading it only defines its functions (it runs nothing).
$PanicFile = Join-Path $PSScriptRoot 'Panic.ps1'
if (Test-Path $PanicFile) { . $PanicFile -DataDir $DataDir -StateDir (Join-Path $DataDir 'deadman') }

# ---------------------------------------------------------------- small helpers
function Get-Epoch { [DateTimeOffset]::Now.ToUnixTimeSeconds() }

function Get-Clock {
    param([long]$Epoch)
    [DateTimeOffset]::FromUnixTimeSeconds($Epoch).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-RegValue {
    # One registry value, or $null when the key or the value is missing.
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Get-Text {
    # A whole text file as ONE string (Get-Content gives one string per line).
    param([string]$Path)
    (@(Get-Content -Path $Path -ErrorAction Stop) -join "`n")
}

function Test-PortOpen {
    # Does a TCP connection to this address and port work within 2 seconds?
    param([string]$HostName, [int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $wait = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $wait.AsyncWaitHandle.WaitOne(2000)) { return $false }
        $client.EndConnect($wait)
        return $true
    } catch { return $false }
    finally { $client.Close() }
}

function Test-PortInList {
    # Does a firewall rule's port list ('3389', '1000-2000', 'Any') cover this port?
    param($List, [int]$Port)
    foreach ($p in $List) {
        if ($p -eq 'Any' -or $p -eq '*') { return $true }
        if ($p -match '^\d+$' -and [int]$p -eq $Port) { return $true }
        if ($p -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
    }
    $false
}

function Get-GroupMembers {
    # The names in a local group, found by the group's SID (so the language of Windows does not matter). "net localgroup" is used
    # because Get-LocalGroupMember fails on a member it cannot resolve.
    param([string]$Sid)
    $group = Get-LocalGroup -SID $Sid -ErrorAction Stop
    $lines = @(& net.exe localgroup $group.Name 2>$null)
    $dash = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^-{10,}') { $dash = $i; break } }
    if ($dash -lt 0) { return @() }
    @($lines | Select-Object -Skip ($dash + 1) | Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { $_.Trim() -replace '^.*\\', '' })
}

function Get-BlackboxIp {
    # The blackbox address the tool saved in settings.json ('' until you have entered it).
    $file = Join-Path $DataDir 'settings.json'
    if (-not (Test-Path $file)) { return '' }
    try { [string]([System.IO.File]::ReadAllText($file) | ConvertFrom-Json).BlackboxIp } catch { '' }
}

function Get-Config {
    # config.json is written by the tool when it installs the watchdog. It only holds what the tool found out: the Jenkins home folder.
    $cfg = @{ JenkinsHome = '' }
    if (Test-Path $ConfigFile) {
        try { $cfg.JenkinsHome = [string]([System.IO.File]::ReadAllText($ConfigFile) | ConvertFrom-Json).JenkinsHome } catch { $cfg.JenkinsHome = '' }
    }
    $cfg
}

# ---------------------------------------------------------------- alerts, state, status (plain files)
function Initialize-Folders {
    foreach ($d in $Dir, $BaseDir, $GoodDir) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

function Write-Alert {
    # One line at the end of alerts.log: time, a level word, the text. Levels: ALERT (something happened), DOWN (a check failed),
    # HEAL (a repair ran), UP (a check is fine again), INFO.
    param([string]$Level, [string]$Text)
    $line = '{0} {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Text
    Write-Host $line
    try {
        if ((Test-Path $AlertFile) -and (Get-Item $AlertFile).Length -gt 1MB) { Move-Item -Path $AlertFile -Destination ($AlertFile + '.old') -Force }
        [System.IO.File]::AppendAllText($AlertFile, $line + [Environment]::NewLine)
    } catch { Write-Host '(could not write alerts.log)' }
}

function Read-State {
    # state.json is a flat list of name -> value (numbers and text only), kept between passes.
    $state = @{}
    if (Test-Path $StateFile) {
        try {
            $saved = [System.IO.File]::ReadAllText($StateFile) | ConvertFrom-Json
            foreach ($p in $saved.PSObject.Properties) { $state[$p.Name] = $p.Value }
        } catch { Write-Alert 'INFO' 'state.json could not be read and was reset' }
    }
    $state
}

function Save-State {
    param($State)
    [System.IO.File]::WriteAllText($StateFile, (ConvertTo-Json -InputObject $State))
}

function Save-Status {
    # status.json: what is true now. The tool reads it (and its age tells the tool whether the watchdog is still running).
    param($State)
    $checks = @()
    foreach ($name in $CheckNames) {
        if (-not $State.ContainsKey("ok.$name")) { continue }
        $checks += [pscustomobject]@{ Name = $name; Ok = ([int]$State["ok.$name"] -eq 1); Detail = [string]$State["detail.$name"]; Since = [long]$State["since.$name"] }
    }
    $diffs = @()
    foreach ($name in $BaselineNames) {
        if ([int]$State["diffn.$name"] -gt 0) { $diffs += [pscustomobject]@{ Name = $name; Count = [int]$State["diffn.$name"]; Lines = [string]$State["difft.$name"] } }
    }
    $paused = [long]$State['paused']
    $status = [pscustomobject]@{
        Version = $Version; Time = (Get-Clock (Get-Epoch)); Epoch = (Get-Epoch); Pass = [long]$State['pass']
        HealOn = ((-not $NoHeal) -and ($paused -eq 0)); PausedUntil = $paused; Heals = [long]$State['heals']
        BaselineTaken = [long]$State['baseline.taken']; Checks = $checks; Diffs = $diffs
    }
    [System.IO.File]::WriteAllText($StatusFile, (ConvertTo-Json -InputObject $status -Depth 5))
}

function Get-PausedUntil {
    # pause.txt holds the moment (seconds since 1970) until which nothing is repaired. 0 = not paused.
    if (-not (Test-Path $PauseFile)) { return 0 }
    try { $until = [long]([System.IO.File]::ReadAllText($PauseFile).Trim()) } catch { return 0 }
    if ($until -le (Get-Epoch)) { return 0 }
    $until
}

function Use-Flag {
    # A flag file is a note left by the tool (or by you): "do this at the next pass". Reading it removes it.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    Remove-Item -Path $Path -ErrorAction SilentlyContinue
    $true
}

function Write-FlagFile {
    param([string]$Path)
    Initialize-Folders
    [System.IO.File]::WriteAllText($Path, (Get-Clock (Get-Epoch)))
}

# ---------------------------------------------------------------- the checks: each returns { Name, Ok, Detail }
function New-CheckResult {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    [pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail }
}

function Test-RdpCheck {
    $bad = @()
    $svc = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if (-not $svc) { $bad += 'the TermService service is missing' }
    elseif ([string]$svc.Status -ne 'Running') { $bad += "TermService is $($svc.Status)" }
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 1) { $bad += 'Remote Desktop is switched off (fDenyTSConnections = 1)' }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections') -eq 1) { $bad += 'a policy switches Remote Desktop off' }
    $port = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
    if ($null -ne $port -and $port -ne 3389) { $bad += "Remote Desktop listens on port $port instead of 3389" }
    if (-not (Test-PortOpen '127.0.0.1' 3389)) { $bad += 'nothing answers on port 3389' }
    New-CheckResult 'rdp' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { 'TermService runs and port 3389 answers' })
}

function Test-JmoneyCheck {
    $u = Get-LocalUser -Name $ScoringUser -ErrorAction SilentlyContinue
    if (-not $u) { return (New-CheckResult 'jmoney' $false "there is no local account called $ScoringUser") }
    $bad = @()
    if (-not $u.Enabled) { $bad += "$ScoringUser is disabled" }
    $acct = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='$ScoringUser'" -ErrorAction SilentlyContinue
    if ($acct -and $acct.Lockout) { $bad += "$ScoringUser is locked out" }
    if ($u.AccountExpires -and ([datetime]$u.AccountExpires) -lt (Get-Date)) { $bad += "the account $ScoringUser has expired" }
    if ($u.PasswordExpires -and ([datetime]$u.PasswordExpires) -lt (Get-Date)) { $bad += "the password of $ScoringUser has expired" }
    if (-not $u.PasswordLastSet) { $bad += "$ScoringUser is flagged 'must change password at next logon'" }
    $inRdp = (@(Get-GroupMembers 'S-1-5-32-555') -contains $ScoringUser) -or (@(Get-GroupMembers 'S-1-5-32-544') -contains $ScoringUser)
    if (-not $inRdp) { $bad += "$ScoringUser is not in Remote Desktop Users" }
    New-CheckResult 'jmoney' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { "$ScoringUser is enabled, not locked, allowed to use Remote Desktop" })
}

function Test-JenkinsCheck {
    $svc = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -like '*jenkins*' -or $_.PathName -like '*jenkins*' }) | Select-Object -First 1
    if (-not $svc) { return (New-CheckResult 'jenkins' $false 'no Jenkins service was found (looked at service names and program paths)') }
    if ([string]$svc.State -eq 'Start Pending') { return (New-CheckResult 'jenkins' $true "service $($svc.Name) is still starting") }
    $bad = @()
    if ([string]$svc.StartMode -eq 'Disabled') { $bad += "service $($svc.Name) is Disabled" }
    if ([string]$svc.State -ne 'Running') { $bad += "service $($svc.Name) is $($svc.State)" }
    if (-not (Test-PortOpen '127.0.0.1' 8080)) { $bad += 'nothing answers on port 8080' }
    New-CheckResult 'jenkins' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { "service $($svc.Name) runs and port 8080 answers" })
}

function Get-OwnRuleProblem {
    # '' when the tool's own allow rule for this port is as it should be, otherwise what is wrong with it.
    param([int]$Port)
    $name = "HP-Allow-TCP-$Port"
    $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if (-not $rule) { return "rule $name is missing" }
    $portFilter = $rule | Get-NetFirewallPortFilter | Select-Object -First 1
    $addrFilter = $rule | Get-NetFirewallAddressFilter | Select-Object -First 1
    if ([string]$rule.Enabled -ne 'True') { return "rule $name is switched off" }
    if ([string]$rule.Action -ne 'Allow' -or [string]$rule.Direction -ne 'Inbound') { return "rule $name is no longer an inbound Allow rule" }
    if ([string]$rule.Profile -ne 'Any') { return "rule $name does not cover every network profile ($($rule.Profile))" }
    if ([string]$portFilter.Protocol -ne 'TCP' -or (@($portFilter.LocalPort) -join ',') -ne [string]$Port) { return "rule $name no longer matches TCP port $Port" }
    if (@($addrFilter.RemoteAddress | Where-Object { $_ -ne 'Any' -and $_ -ne '*' }).Count -gt 0) { return "rule $name only lets some addresses in" }
    ''
}

function Get-BlockingRules {
    # Enabled inbound Block rules that stop a scored port for EVERY address. A Block rule always beats an Allow rule.
    # A rule that blocks only some addresses is your own list and is left alone; so is a rule for one named program on all ports.
    $found = @()
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue)) {
        $portFilter = $rule | Get-NetFirewallPortFilter | Select-Object -First 1
        $addrFilter = $rule | Get-NetFirewallAddressFilter | Select-Object -First 1
        $appFilter = $rule | Get-NetFirewallApplicationFilter | Select-Object -First 1
        if ([string]$portFilter.Protocol -ne 'TCP' -and [string]$portFilter.Protocol -ne 'Any') { continue }
        if (@($addrFilter.RemoteAddress | Where-Object { $_ -ne 'Any' -and $_ -ne '*' }).Count -gt 0) { continue }
        $anyProgram = (-not $appFilter.Program) -or ([string]$appFilter.Program -eq 'Any')
        $anyPort = (@($portFilter.LocalPort) -contains 'Any')
        foreach ($port in $ScoredPorts) {
            if ((Test-PortInList @($portFilter.LocalPort) $port) -and ($anyProgram -or -not $anyPort)) {
                $found += [pscustomobject]@{ Name = [string]$rule.Name; DisplayName = [string]$rule.DisplayName; Port = $port }
            }
        }
    }
    $found
}

function Test-FirewallCheck {
    $bad = @()
    foreach ($port in $ScoredPorts) {
        $problem = Get-OwnRuleProblem $port
        if ($problem) { $bad += $problem }
    }
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {
        if ([string]$p.AllowInboundRules -eq 'False') { $bad += "the $($p.Name) profile ignores every inbound allow rule" }
    }
    foreach ($b in (Get-BlockingRules)) { $bad += "the Block rule '$($b.DisplayName)' stops port $($b.Port)" }
    New-CheckResult 'firewall' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { 'the allow rules for 3389 and 8080 are in place and nothing blocks them' })
}

# ---------------------------------------------------------------- the slow checks (alerts only, nothing is repaired)
function Test-RightHolds {
    # Does a user-right list from secedit ('*S-1-5-32-544,*S-1-5-32-555,jmoney') name any of these SIDs or names?
    param([string]$List, [string[]]$Who)
    $items = @($List -split ',' | ForEach-Object { $_.Trim() })
    foreach ($w in $Who) { if ($items -contains "*$w" -or $items -contains $w) { return $true } }
    $false
}

function Test-RightsCheck {
    # Remote Desktop needs the right "Allow log on through Remote Desktop Services" and must not be hit by the "Deny" version.
    $tmp = Join-Path $env:TEMP ('wd-rights-' + [guid]::NewGuid().ToString('N') + '.inf')
    $lines = @()
    try {
        & secedit.exe /export /cfg $tmp /areas USER_RIGHTS | Out-Null
        $lines = @(Get-Content -Path $tmp -ErrorAction Stop)
    } finally { Remove-Item -Path $tmp -ErrorAction SilentlyContinue }
    $allow = ''; $deny = ''
    foreach ($l in $lines) {
        if ($l -match '^\s*SeRemoteInteractiveLogonRight\s*=\s*(.*)$') { $allow = $Matches[1] }
        if ($l -match '^\s*SeDenyRemoteInteractiveLogonRight\s*=\s*(.*)$') { $deny = $Matches[1] }
    }
    $u = Get-LocalUser -Name $ScoringUser -ErrorAction Stop
    $who = @($u.SID.Value, $ScoringUser, 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')        # the user itself, Everyone, Authenticated Users, Users
    if (@(Get-GroupMembers 'S-1-5-32-555') -contains $ScoringUser) { $who += 'S-1-5-32-555' }
    if (@(Get-GroupMembers 'S-1-5-32-544') -contains $ScoringUser) { $who += 'S-1-5-32-544' }
    $bad = @()
    if (-not (Test-RightHolds $allow $who)) { $bad += "$ScoringUser (or a group it is in) is not in 'Allow log on through Remote Desktop Services'" }
    if (Test-RightHolds $deny $who) { $bad += "$ScoringUser (or a group it is in) is in 'Deny log on through Remote Desktop Services'" }
    New-CheckResult 'rights' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { "$ScoringUser may log on through Remote Desktop Services" })
}

function Test-DefenderCheck {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $bad = @()
        if (-not $mp.AMServiceEnabled) { $bad += 'the Defender antivirus service is off' }
        if (-not $mp.RealTimeProtectionEnabled) { $bad += 'real-time protection is off' }
        return (New-CheckResult 'defender' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { 'Defender is on (service and real-time protection)' }))
    } catch {
        return (New-CheckResult 'defender' $false "Defender cannot be read: $($_.Exception.Message)")
    }
}

function Test-BlackboxCheck {
    $ip = Get-BlackboxIp
    if (-not $ip) { return $null }                 # no address entered yet: nothing to check
    $ok = Test-PortOpen $ip 22
    New-CheckResult 'blackbox' $ok $(if ($ok) { "$ip answers on port 22" } else { "$ip does not answer on port 22 (blackbox is down, the address is wrong, or something on the path blocks it)" })
}

function Get-JobFolders {
    # The Jenkins job folders (JENKINS_HOME\jobs\*). Empty when the tool did not find the Jenkins home folder.
    param($Cfg)
    if (-not $Cfg.JenkinsHome) { return @() }
    $jobs = Join-Path $Cfg.JenkinsHome 'jobs'
    if (-not (Test-Path $jobs)) { return @() }
    @(Get-ChildItem -Path $jobs -Directory -ErrorAction SilentlyContinue)
}

function Save-JobCopy {
    param($Job, [string]$Hash, $State)
    $copyDir = Join-Path $GoodDir $Job.Name
    if (-not (Test-Path $copyDir)) { New-Item -ItemType Directory -Path $copyDir -Force | Out-Null }
    Copy-Item -Path (Join-Path $Job.FullName 'config.xml') -Destination (Join-Path $copyDir 'config.xml') -Force
    $State['jobhash.' + $Job.Name] = $Hash
}

function Test-JobFiles {
    # Remembers the fingerprint of each job's config.xml (and keeps a copy: the "last good" one). The first look, and -AcceptJobs, only
    # record what is there now. Afterwards a job file that changed, a job that is new and a job that is gone are reported.
    param($Cfg, $State, [bool]$Accept)
    if (-not $Cfg.JenkinsHome) { return (New-CheckResult 'jobs' $true 'the Jenkins home folder is not known, so job files are not watched') }
    $record = ($Accept -or -not $State['jobs.known'])
    $problems = @()
    $present = @()
    foreach ($job in (Get-JobFolders $Cfg)) {
        $conf = Join-Path $job.FullName 'config.xml'
        if (-not (Test-Path $conf)) { continue }
        $present += $job.Name
        $hash = (Get-FileHash -Path $conf -Algorithm SHA256).Hash
        $old = [string]$State['jobhash.' + $job.Name]
        if ($record) { Save-JobCopy $job $hash $State }
        elseif (-not $old) { $problems += "$($job.Name) (new job)" }
        elseif ($old -ne $hash) { $problems += "$($job.Name) (config.xml changed)" }
    }
    foreach ($key in @($State.Keys | Where-Object { $_ -like 'jobhash.*' })) {
        $name = $key.Substring('jobhash.'.Length)
        if ($present -contains $name) { continue }
        if ($record) { $State.Remove($key) } else { $problems += "$name (job gone)" }
    }
    $State['jobs.known'] = 1
    New-CheckResult 'jobs' ($problems.Count -eq 0) $(if ($problems.Count) { "since the job files were last accepted: $($problems -join ', ')" } else { "$($present.Count) job file(s) unchanged" })
}

function Test-LastBuilds {
    # Jenkins writes jobs\NAME\builds\permalinks: "lastCompletedBuild 12", "lastSuccessfulBuild 11", ... If the last completed build
    # is not the last successful one, the newest build failed. This reads files only: no password, no Jenkins login.
    param($Cfg)
    $bad = @()
    foreach ($job in (Get-JobFolders $Cfg)) {
        $perm = Join-Path $job.FullName 'builds\permalinks'
        if (-not (Test-Path $perm)) { continue }
        $text = Get-Text $perm
        $done = -1; $good = -1
        if ($text -match '(?m)^lastCompletedBuild\s+(-?\d+)') { $done = [int]$Matches[1] }
        if ($text -match '(?m)^lastSuccessfulBuild\s+(-?\d+)') { $good = [int]$Matches[1] }
        if ($done -ge 0 -and $done -ne $good) { $bad += "$($job.Name): build #$done did not succeed (last good: #$good)" }
    }
    New-CheckResult 'builds' ($bad.Count -eq 0) $(if ($bad.Count) { $bad -join '; ' } else { 'the last build of every job succeeded' })
}

# ---------------------------------------------------------------- the repairs
function Restore-OurRules {
    # Puts the firewall right for the two scored ports: the tool's own allow rules (same names as the tool's firewall phase), the
    # "ignore inbound allow rules" switch of a profile, and any Block rule that stops a scored port for everybody (switched off, not deleted).
    $done = @()
    foreach ($port in $ScoredPorts) {
        if (-not (Get-OwnRuleProblem $port)) { continue }
        $name = "HP-Allow-TCP-$port"
        if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $name }
        New-NetFirewallRule -Name $name -DisplayName "HP Allow TCP $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any -RemoteAddress Any -Description 'HP: scored port, any source' | Out-Null
        $done += "rule $name rebuilt"
    }
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
        if ([string]$p.AllowInboundRules -ne 'False') { continue }
        Set-NetFirewallProfile -Name $p.Name -AllowInboundRules True
        $done += "profile $($p.Name) uses inbound allow rules again"
    }
    foreach ($b in (@(Get-BlockingRules) | Sort-Object -Property Name -Unique)) {
        try {
            Disable-NetFirewallRule -Name ([WildcardPattern]::Escape($b.Name)) -ErrorAction Stop
            $done += "Block rule '$($b.DisplayName)' switched off"
        } catch {
            $done += "Block rule '$($b.DisplayName)' could NOT be switched off ($($_.Exception.Message))"       # e.g. a rule that comes from a policy
        }
    }
    if ($done.Count -eq 0) { return 'nothing needed changing' }
    $done -join '; '
}

function Restore-JobConfig {
    # -RestoreJob NAME: copies the last good config.xml of one job back. Jenkins keeps its settings in memory, so it still has to
    # re-read the file (Manage Jenkins > Reload Configuration from Disk). Nothing here restarts Jenkins.
    param([string]$Name)
    $cfg = Get-Config
    if ($Name -notmatch '^[\w .()-]+$' -or $Name -match '^\.+$') { Write-Host "Refused: '$Name' is not a plain job name."; return }
    if (-not $cfg.JenkinsHome) { Write-Host 'The Jenkins home folder is not known (config.json), so nothing was restored.'; return }
    $good = Join-Path (Join-Path $GoodDir $Name) 'config.xml'
    $live = Join-Path (Join-Path (Join-Path $cfg.JenkinsHome 'jobs') $Name) 'config.xml'
    if (-not (Test-Path $good)) { Write-Host "There is no saved good copy for the job '$Name'."; return }
    if (-not (Test-Path (Split-Path -Path $live -Parent))) { Write-Host "The job folder for '$Name' does not exist in Jenkins."; return }
    Copy-Item -Path $good -Destination $live -Force
    Write-Alert 'HEAL' "job '$Name': config.xml put back from the last good copy. Jenkins still has to reload it from disk (Manage Jenkins > Reload Configuration from Disk)"
}

# ---------------------------------------------------------------- what a failing check leads to
$Healers = @{
    rdp      = { Restore-Rdp }
    jmoney   = { Restore-Jmoney }
    jenkins  = { Restore-Jenkins }
    firewall = { Restore-OurRules }
}

function Invoke-Check {
    # Runs one check. A check that itself breaks becomes a failing result marked Crashed (it is reported, but nothing is repaired).
    param([string]$Name, [scriptblock]$Code)
    try { & $Code }
    catch {
        $r = New-CheckResult $Name $false "the check itself failed: $($_.Exception.Message)"
        $r | Add-Member -NotePropertyName Crashed -NotePropertyValue $true
        $r
    }
}

function Update-Check {
    # Compares a result with what was true last time. A check that starts failing is written to alerts.log once (DOWN); while it keeps
    # failing it is repaired at most every 2 minutes and re-announced every 10th pass; when it is fine again that is written too (UP).
    param($State, $Result, [bool]$HealOn, [scriptblock]$Recheck)
    $name = $Result.Name
    $now = Get-Epoch
    if (-not $Result.Ok) {
        $streak = [long]$State["streak.$name"] + 1
        $State["streak.$name"] = $streak
        if ([long]$State["since.$name"] -eq 0) { $State["since.$name"] = $now; Write-Alert 'DOWN' "${name}: $($Result.Detail)" }
        elseif ([string]$State["detail.$name"] -ne [string]$Result.Detail) { Write-Alert 'DOWN' "${name}: the problem changed: $($Result.Detail)" }
        elseif (($streak % 10) -eq 0) { Write-Alert 'DOWN' "${name}: still failing ($streak checks in a row): $($Result.Detail)" }
        $canHeal = $HealOn -and $Healers.ContainsKey($name) -and -not $Result.Crashed -and (($now - [long]$State["healat.$name"]) -ge $HealGapSeconds)
        if ($canHeal) {
            $State["healat.$name"] = $now
            $State['heals'] = [long]$State['heals'] + 1
            $msg = ''
            try { $msg = [string](& $Healers[$name]) } catch { $msg = "the repair FAILED: $($_.Exception.Message)" }
            $Result = Invoke-Check $name $Recheck
            Write-Alert 'HEAL' ("${name}: $msg -> the check now says: " + $(if ($Result.Ok) { 'OK' } else { "still failing: $($Result.Detail)" }))
        }
    }
    if ($Result.Ok -and [long]$State["since.$name"] -gt 0) {
        Write-Alert 'UP' "${name}: back to normal after $($now - [long]$State["since.$name"]) seconds"
        $State["since.$name"] = 0
        $State["streak.$name"] = 0
    }
    $State["ok.$name"] = [int][bool]$Result.Ok
    $State["detail.$name"] = [string]$Result.Detail
}

# ---------------------------------------------------------------- security events
function Get-EventFields {
    # The named values of an event (TargetUserName, SubjectUserName, ...), read from the event's XML.
    param($Evt)
    $fields = @{}
    try {
        $xml = [xml]$Evt.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) { if ($d -and $d.Name) { $fields[[string]$d.Name] = [string]$d.'#text' } }
    } catch { $fields['xml'] = 'unreadable' }
    $fields
}

function Resolve-Sid {
    param([string]$Sid)
    try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $Sid }
}

function Format-EventText {
    param($Evt, $F)
    $who = $(if ($F['SubjectUserName']) { " (by $($F['SubjectUserName']))" } else { '' })
    switch ([int]$Evt.Id) {
        4720 { return "account CREATED: $($F['TargetUserName'])$who" }
        4722 { return "account ENABLED: $($F['TargetUserName'])$who" }
        4724 { return "password RESET for $($F['TargetUserName'])$who" }
        4728 { return "added to the group $($F['TargetUserName']): $(Resolve-Sid $F['MemberSid'])$who" }
        4732 { return "added to the group $($F['TargetUserName']): $(Resolve-Sid $F['MemberSid'])$who" }
        4738 { return "account CHANGED: $($F['TargetUserName'])$who" }
        4740 { return "account LOCKED OUT: $($F['TargetUserName'])" }
        4719 { return "the audit policy was CHANGED$who" }
        4698 { return "scheduled task CREATED: $($F['TaskName'])$who" }
        7045 { return "service INSTALLED: $($F['ServiceName']) -> $($F['ImagePath'])" }
        1102 { return 'the Security log was CLEARED' }
        104  { return 'the System log was CLEARED' }
    }
    "event $($Evt.Id): " + ([string]$Evt.Message -split "`n")[0]
}

function Watch-Events {
    # Reports each watched event once. The first look at a log only remembers where it ends: nothing from before the watchdog is reported.
    param($State)
    $since = (Get-Date).AddMinutes(-15)
    foreach ($w in $EventWatch) {
        $recKey = 'lastrec.' + $w.Log
        $timeKey = 'lasttime.' + $w.Log
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $w.Log; Id = $w.Ids; StartTime = $since } -ErrorAction SilentlyContinue | Sort-Object RecordId)
        if ([long]$State[$recKey] -eq 0) {
            $State[$recKey] = $(if ($events.Count) { [long]$events[-1].RecordId } else { 1 })
            $State[$timeKey] = $(if ($events.Count) { $events[-1].TimeCreated.Ticks } else { (Get-Date).Ticks })
            continue
        }
        $lastRec = [long]$State[$recKey]
        $lastTime = [long]$State[$timeKey]
        foreach ($e in $events) {
            # new = a later record number OR a later time (the time test catches a log that was cleared and counts from 1 again)
            if ([long]$e.RecordId -le $lastRec -and $e.TimeCreated.Ticks -le $lastTime) { continue }
            Write-Alert 'ALERT' (Format-EventText $e (Get-EventFields $e))
            $State[$recKey] = [Math]::Max([long]$State[$recKey], [long]$e.RecordId)
            $State[$timeKey] = [Math]::Max([long]$State[$timeKey], $e.TimeCreated.Ticks)
        }
    }
}

function Watch-FailedLogons {
    # Event 4625 is a failed logon. A few are normal; a burst is somebody guessing passwords. One alert per burst (then quiet for 10 minutes).
    param($State)
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddMinutes(-5) } -MaxEvents 500 -ErrorAction SilentlyContinue)
    $State['failed5'] = $events.Count
    if ($events.Count -lt $BurstLimit) { return }
    if ((Get-Epoch) -lt [long]$State['burst.until']) { return }
    $State['burst.until'] = (Get-Epoch) + 600
    $count = @{}
    foreach ($e in ($events | Select-Object -First 100)) {
        $f = Get-EventFields $e
        $from = $(if ($f['IpAddress'] -and $f['IpAddress'] -ne '-') { $f['IpAddress'] } else { $f['WorkstationName'] })
        $key = "$from as $($f['TargetUserName'])"
        $count[$key] = 1 + [int]$count[$key]
    }
    $top = ($count.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Key) x$($_.Value)" }) -join '; '
    Write-Alert 'ALERT' "$($events.Count) failed logons in the last 5 minutes (most: $top)"
}

# ---------------------------------------------------------------- the baseline: what the box looked like, compared again every 5th pass
function Get-PortLines {
    $names = @{}
    foreach ($p in @(Get-Process)) { $names[[int]$p.Id] = [string]$p.ProcessName }
    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $proc = [string]$names[[int]$c.OwningProcess]
        # Windows opens high ports for its own services; they change after every reboot and are not worth a line
        if ([int]$c.LocalPort -ge 49152 -and $proc -match '^(svchost|lsass|wininit|services|spoolsv|System)$') { continue }
        "tcp $($c.LocalPort) $proc"
    }
}

function Get-TaskLines {
    # Tasks outside \Microsoft\ with what they run; tasks inside \Microsoft\ by name only (a hidden new one still shows up).
    foreach ($t in @(Get-ScheduledTask)) {
        if ($OwnTasks -contains [string]$t.TaskName) { continue }
        if ([string]$t.TaskPath -like '\Microsoft\*') { "$($t.TaskPath)$($t.TaskName)"; continue }
        $run = @($t.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() }) -join ' ; '
        "$($t.TaskPath)$($t.TaskName) | $run"
    }
}

function Get-RunKeyLines {
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
        if (-not (Test-Path -Path $k)) { continue }
        $key = Get-Item -Path $k
        foreach ($n in $key.GetValueNames()) { "$k | $n | $($key.GetValue($n))" }
    }
}

function Get-BaselineLines {
    # What the box looks like in ONE category, as sorted text lines: { Ok; Lines }. Ok is false when it could not be read this time
    # (then nothing is compared, so a read error never looks like "everything is gone").
    param([string]$Name)
    try {
        $lines = @()
        switch ($Name) {
            'users'    { $lines = @(Get-LocalUser | ForEach-Object { "$($_.Name) enabled=$($_.Enabled)" }) }
            'admins'   { $lines = @(Get-GroupMembers 'S-1-5-32-544') }
            'rdpusers' { $lines = @(Get-GroupMembers 'S-1-5-32-555') }
            'ports'    { $lines = @(Get-PortLines) }
            'tasks'    { $lines = @(Get-TaskLines) }
            'services' { $lines = @(Get-CimInstance Win32_Service | ForEach-Object { "$($_.Name) | $($_.StartMode) | $($_.PathName)" }) }
            'runkeys'  { $lines = @(Get-RunKeyLines) }
            'startup'  { $lines = @(Get-ChildItem -Path (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
            'hosts'    { $lines = @((Get-Text (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts')) -split "`r?`n" | ForEach-Object { ($_ -replace '#.*$', '').Trim() }) }
            'shares'   { $lines = @(Get-SmbShare | ForEach-Object { "$($_.Name) | $($_.Path)" }) }
            'routes'   { $lines = @(Get-NetRoute -AddressFamily IPv4 | ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop) on interface $($_.InterfaceIndex)" }) }
            'firewall' {
                $lines = @(Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True | Where-Object { [string]$_.Action -eq 'Block' -or [string]$_.Direction -eq 'Inbound' } |
                    ForEach-Object { "$($_.Direction) $($_.Action) $($_.Name) | $($_.DisplayName)" })
            }
        }
        [pscustomobject]@{ Ok = $true; Lines = @($lines | Where-Object { $_ } | Sort-Object -Unique) }
    } catch { [pscustomobject]@{ Ok = $false; Lines = @() } }
}

function Save-Baselines {
    # Writes one file per category (baseline\NAME.txt) and forgets which differences were already reported. Returns how many were saved.
    param($State)
    $saved = 0
    foreach ($name in $BaselineNames) {
        $got = Get-BaselineLines $name
        if (-not $got.Ok) { continue }
        [System.IO.File]::WriteAllLines((Join-Path $BaseDir "$name.txt"), [string[]]$got.Lines)
        Remove-Item -Path (Join-Path $BaseDir "$name.seen") -ErrorAction SilentlyContinue
        $State["diffn.$name"] = 0
        $State["difft.$name"] = ''
        $saved++
    }
    $State['baseline.taken'] = Get-Epoch
    $saved
}

function Compare-Baseline {
    # Writes an alert for every line that is new or gone since the baseline - each one only once (baseline\NAME.seen remembers).
    # An item that comes back after it went away is reported again.
    param([string]$Name, [string[]]$Now, [string]$BlackboxIp, $State)
    $old = @([System.IO.File]::ReadAllLines((Join-Path $BaseDir "$Name.txt")))
    $seenFile = Join-Path $BaseDir "$Name.seen"
    $seen = @{}
    if (Test-Path $seenFile) { foreach ($l in [System.IO.File]::ReadAllLines($seenFile)) { $seen[$l] = $true } }
    $oldSet = @{}; foreach ($l in $old) { $oldSet[$l] = $true }
    $nowSet = @{}; foreach ($l in $Now) { $nowSet[$l] = $true }
    $diffs = @()
    foreach ($l in $Now) { if (-not $oldSet.ContainsKey($l)) { $diffs += "+$l" } }
    foreach ($l in $old) { if (-not $nowSet.ContainsKey($l)) { $diffs += "-$l" } }
    $fresh = @($diffs | Where-Object { -not $seen.ContainsKey($_) })
    foreach ($d in ($fresh | Select-Object -First 8)) {
        $what = $(if ($d.StartsWith('+')) { 'NEW' } else { 'GONE' })
        $tag = $(if ($BlackboxIp -and $d.Contains($BlackboxIp)) { ' (touches blackbox!)' } else { '' })
        Write-Alert 'ALERT' "[$Name] ${what}: $($d.Substring(1))$tag"
    }
    if ($fresh.Count -gt 8) { Write-Alert 'ALERT' "[$Name] and $($fresh.Count - 8) more differences (all of them are in baseline\$Name.seen)" }
    [System.IO.File]::WriteAllLines($seenFile, [string[]]$diffs)           # what is still different; anything that went back to normal is forgotten
    $State["diffn.$Name"] = $diffs.Count
    $State["difft.$Name"] = (($diffs | Select-Object -First 12) -join ' || ')
}

function Compare-AllBaselines {
    param($State)
    if ([long]$State['baseline.taken'] -eq 0) {
        $n = Save-Baselines $State
        Write-Alert 'INFO' "baseline taken ($n parts). Take it again with -Rebaseline after you finished hardening and the hunt."
        return
    }
    $blackbox = Get-BlackboxIp
    foreach ($name in $BaselineNames) {
        $got = Get-BaselineLines $name
        if (-not $got.Ok) { continue }
        $file = Join-Path $BaseDir "$name.txt"
        if (-not (Test-Path $file)) { [System.IO.File]::WriteAllLines($file, [string[]]$got.Lines); continue }       # this part could not be read when the baseline was taken
        Compare-Baseline $name $got.Lines $blackbox $State
    }
}

# ---------------------------------------------------------------- one pass
function Invoke-Guarded {
    # Runs one part of a pass. If it fails the other parts still run; the same error is written to alerts.log only once.
    param($State, [string]$Name, [scriptblock]$Code)
    try { & $Code; $State["err.$Name"] = '' }
    catch {
        $msg = $_.Exception.Message
        if ([string]$State["err.$Name"] -ne $msg) { Write-Alert 'INFO' "${Name}: could not run: $msg" }
        $State["err.$Name"] = $msg
    }
}

function Invoke-Pass {
    Initialize-Folders
    $state = Read-State
    $pass = [long]$state['pass'] + 1
    $state['pass'] = $pass
    if ($pass -eq 1) { Write-Alert 'INFO' "watchdog started (version $Version); slow checks every $SlowEvery passes" }
    $cfg = Get-Config

    # pausing: -Pause leaves pause.txt; the checks and alerts go on, only the repairs stop
    $until = Get-PausedUntil
    if ($until -gt 0 -and [long]$state['paused'] -eq 0) { Write-Alert 'INFO' "repairs are PAUSED until $(Get-Clock $until)" }
    if ($until -eq 0 -and [long]$state['paused'] -gt 0) { Write-Alert 'INFO' 'repairs are on again' }
    $state['paused'] = $until
    $healOn = (-not $NoHeal) -and ($until -eq 0)

    # notes left by the tool (or by you)
    $acceptJobs = Use-Flag $AcceptFlag
    if (Use-Flag $RebaseFlag) {
        $n = Save-Baselines $state
        Write-Alert 'INFO' "baseline taken again ($n parts): differences are counted from now"
    }

    $slow = (($pass % $SlowEvery) -eq 1) -or ($SlowEvery -le 1)
    $checks = [ordered]@{
        rdp      = { Test-RdpCheck }
        jmoney   = { Test-JmoneyCheck }
        jenkins  = { Test-JenkinsCheck }
        firewall = { Test-FirewallCheck }
    }
    if ($slow) {
        $checks['rights']   = { Test-RightsCheck }
        $checks['defender'] = { Test-DefenderCheck }
        $checks['blackbox'] = { Test-BlackboxCheck }
    }
    if ($slow -or $acceptJobs) { $checks['jobs'] = { Test-JobFiles $cfg $state $acceptJobs } }       # an accept note is acted on in this very pass
    if ($slow) { $checks['builds'] = { Test-LastBuilds $cfg } }
    foreach ($name in $checks.Keys) {
        $result = Invoke-Check $name $checks[$name]
        if ($result) { Update-Check $state $result $healOn $checks[$name] }
    }

    Invoke-Guarded $state 'events' { Watch-Events $state }
    Invoke-Guarded $state 'failed logons' { Watch-FailedLogons $state }
    if ($slow) { Invoke-Guarded $state 'baseline' { Compare-AllBaselines $state } }

    Save-State $state
    Save-Status $state
}

function Show-Status {
    if (-not (Test-Path $StatusFile)) { Write-Host 'No status yet: the watchdog has not finished a pass.'; return }
    $s = [System.IO.File]::ReadAllText($StatusFile) | ConvertFrom-Json
    Write-Host ("Last pass: {0} (pass {1}). Repairs are {2}; {3} done so far." -f $s.Time, $s.Pass, $(if ($s.HealOn) { 'ON' } else { 'OFF' }), $s.Heals)
    foreach ($c in @($s.Checks)) { Write-Host ("  {0,-9} {1}  {2}" -f $c.Name, $(if ($c.Ok) { 'ok  ' } else { 'DOWN' }), $c.Detail) }
    foreach ($d in @($s.Diffs)) { Write-Host ("  differs from the baseline: {0} ({1}): {2}" -f $d.Name, $d.Count, $d.Lines) }
    Write-Host 'Last alerts:'
    if (Test-Path $AlertFile) { @(Get-Content -Path $AlertFile) | Select-Object -Last 15 | ForEach-Object { Write-Host "  $_" } }
}

function Start-Watchdog {
    Initialize-Folders
    if ($Status) { Show-Status; return }
    if ($Resume) { Remove-Item -Path $PauseFile -ErrorAction SilentlyContinue; Write-Host 'Repairs are on again (from the next pass).'; return }
    if ($Pause -gt 0) {
        [System.IO.File]::WriteAllText($PauseFile, [string]((Get-Epoch) + 60 * $Pause))
        Write-Host "Repairs are paused for $Pause minutes. Checks and alerts go on. Undo: -Resume"
        return
    }
    if ($Rebaseline -or $AcceptJobs) {
        if ($Rebaseline) { Write-FlagFile $RebaseFlag }
        if ($AcceptJobs) { Write-FlagFile $AcceptFlag }
        Write-Host 'Noted. It happens at the next pass (within a minute).'
        return
    }
    if ($RestoreJob) { Restore-JobConfig $RestoreJob; return }
    # one pass at a time: if the scheduled task is running right now, this run just stops
    $lock = $null
    try { $lock = [System.IO.File]::Open($LockFile, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { Write-Host 'Another pass is running right now.'; return }
    try { Invoke-Pass } finally { $lock.Close() }
}

# Run only when started as a script (dot-sourcing it, as the tests do, just defines the functions).
if ($MyInvocation.InvocationName -ne '.') { Start-Watchdog }
