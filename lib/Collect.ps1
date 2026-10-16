# Collect.ps1 - the COLLECTORS. They READ the box and return plain objects ("facts"). They change nothing.
# The judges (Judge.ps1) turn facts into findings; nothing in this file decides what is good or bad.
# Windows only (it calls Windows cmdlets). Needs an elevated PowerShell. Windows PowerShell 5.1, plain ASCII.
#
# Get-HpFacts runs every collector inside Invoke-Collector, so one broken collector shows up as an
# entry in $facts.Errors instead of stopping the whole audit.

function Get-RegValue {
    # One registry value, or $null when the key or the value is missing.
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Get-BareName {
    # 'PC\jmoney' -> 'jmoney'
    param([string]$Name)
    $Name -replace '^.*\\', ''
}

function Get-ExePath {
    # The program file named at the start of a service command line:  "C:\x y\a.exe" -k foo   ->   C:\x y\a.exe
    param([string]$CommandLine)
    if (-not $CommandLine) { return '' }
    $c = $CommandLine.Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.*?\.exe)\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $c.Split(' ')[0]
}

function ConvertFrom-Secedit {
    # Turns the text file written by  secedit /export /cfg file.inf  into  name -> value.
    param([string[]]$Lines)
    $h = @{}
    foreach ($l in $Lines) {
        if ($l -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$') { $h[$Matches[1]] = $Matches[2] }
    }
    $h
}

function Get-LocalGroupMembers {
    # Member names of a local group, read from "net localgroup" (it still works when Get-LocalGroupMember
    # trips over a member it cannot resolve).
    param([string]$Group)
    $lines = @(& net.exe localgroup $Group 2>$null)
    $dash = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^-{10,}') { $dash = $i; break } }
    if ($dash -lt 0) { return @() }
    @($lines | Select-Object -Skip ($dash + 1) | Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { $_.Trim() })
}

function Invoke-Collector {
    param([string]$Name, [scriptblock]$Code, $Errors)
    if ($script:Hp.OnBusy) { & $script:Hp.OnBusy "Reading $Name ..." }        # the window shows this in its status bar
    try { & $Code } catch { [void]$Errors.Add("${Name}: $($_.Exception.Message)"); $null }
}

# ---------------------------------------------------------------- host, network, tools
function Get-HostFacts {
    $os  = Get-CimInstance Win32_OperatingSystem
    $ubr = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
    $hot = 'none found'
    try {
        $h = Get-CimInstance Win32_QuickFixEngineering | Sort-Object { [datetime]$_.InstalledOn } -Descending | Select-Object -First 1
        if ($h) { $hot = "$($h.HotFixID) installed $(([datetime]$h.InstalledOn).ToString('yyyy-MM-dd'))" }
    } catch { $hot = 'could not be read' }
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { [string]$_.IPAddress })
    [pscustomobject]@{
        ComputerName = [string]$env:COMPUTERNAME; Os = [string]$os.Caption; Build = "$($os.BuildNumber).$ubr"
        LastHotfix = $hot; Ips = $ips
    }
}

function Get-NetworkFacts {
    # Network profile(s), is the Internet reachable, is blackbox reachable. Outbound tests wait at most 2 seconds each.
    param([string]$BlackboxIp = '')
    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' } else { [string]$_.NetworkCategory } } | Select-Object -Unique)
    $bb = $null
    if ($BlackboxIp) { $bb = Test-TcpOpen -HostName $BlackboxIp -Port $script:Plan.BlackboxPort }
    [pscustomobject]@{ Profiles = $profiles; Internet = (Test-TcpOpen -HostName '1.1.1.1' -Port 443); BlackboxIp = $BlackboxIp; BlackboxSsh = $bb }
}

function Get-SshVersion {
    # "ssh -V" prints something like  OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2  (to the error stream)
    param([string]$Path)
    $r = Invoke-Native -Path $Path -Arguments '-V' -TimeoutSec 10
    ($r.StdErr + ' ' + $r.StdOut).Trim()
}

function Get-ToolFacts {
    # Is the OpenSSH client there (backup needs scp.exe), and is .NET new enough for the archive encryption?
    $dir = Join-Path $env:SystemRoot 'System32\OpenSSH'
    $found = @{}
    foreach ($exe in 'ssh.exe', 'scp.exe', 'ssh-keygen.exe', 'ssh-keyscan.exe') {
        $path = Join-Path $dir $exe
        if (-not (Test-Path $path)) {
            $cmd = Get-Command $exe -ErrorAction SilentlyContinue | Select-Object -First 1
            $path = $(if ($cmd) { [string]$cmd.Source } else { '' })
        }
        $found[$exe] = $path
    }
    $ver = ''
    if ($found['ssh.exe']) { $ver = Get-SshVersion $found['ssh.exe'] }
    [pscustomobject]@{
        Ssh = $found['ssh.exe']; Scp = $found['scp.exe']; SshKeygen = $found['ssh-keygen.exe']; SshKeyscan = $found['ssh-keyscan.exe']; SshVersion = $ver
        DotNetRelease = [int](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' 'Release')
        PowerShell = $PSVersionTable.PSVersion.ToString()
    }
}

# ---------------------------------------------------------------- accounts, groups, rights
function Get-AccountFacts {
    $users = @(Get-LocalUser | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name; Enabled = [bool]$_.Enabled; Sid = [string]$_.SID.Value; Description = [string]$_.Description
            LastLogon = $(if ($_.LastLogon) { ([datetime]$_.LastLogon).ToString('yyyy-MM-dd HH:mm') } else { 'never' })
        } })
    $groups = @(Get-LocalGroup | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Sid = [string]$_.SID.Value; Members = @(Get-LocalGroupMembers $_.Name | ForEach-Object { Get-BareName $_ }) } })
    [pscustomobject]@{ Users = $users; Groups = $groups }
}

function Get-SeceditFacts {
    # "secedit /export" writes the local security policy (user rights + lockout) to a text file. We read it, then delete it.
    $tmp = Join-Path $env:TEMP ('hp-secedit-' + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        & secedit.exe /export /cfg $tmp /areas USER_RIGHTS SECURITYPOLICY | Out-Null
        if (-not (Test-Path $tmp)) { return @{} }
        ConvertFrom-Secedit (Get-Content $tmp)
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- services, scheduled tasks
function Get-ServiceFacts {
    @(Get-CimInstance Win32_Service | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name; DisplayName = [string]$_.DisplayName; State = [string]$_.State; StartMode = [string]$_.StartMode
            StartName = [string]$_.StartName; PathName = [string]$_.PathName; ProcessId = [int]$_.ProcessId; Exe = (Get-ExePath $_.PathName)
        } })
}

function Get-TaskFacts {
    @(Get-ScheduledTask | ForEach-Object {
        $t = $_
        [pscustomobject]@{
            Name = [string]$t.TaskName; Path = [string]$t.TaskPath; State = [string]$t.State
            UserId = [string]$t.Principal.UserId; GroupId = [string]$t.Principal.GroupId; RunLevel = [string]$t.Principal.RunLevel
            Actions = @($t.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() })
        } })
}

# ---------------------------------------------------------------- listening ports and connections, with the program behind them
function Get-PortFacts {
    $procs = @{}
    foreach ($p in Get-Process) {
        $path = ''
        try { $path = [string]$p.Path } catch { $path = '' }
        $procs[[int]$p.Id] = @{ Name = [string]$p.ProcessName; Path = $path }
    }
    $listen = @()
    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $listen += [pscustomobject]@{ Proto = 'TCP'; Address = [string]$c.LocalAddress; Port = [int]$c.LocalPort; Pid = [int]$c.OwningProcess }
    }
    foreach ($c in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        if ([string]$c.LocalAddress -like '127.*' -or [string]$c.LocalAddress -eq '::1') { continue }
        $listen += [pscustomobject]@{ Proto = 'UDP'; Address = [string]$c.LocalAddress; Port = [int]$c.LocalPort; Pid = [int]$c.OwningProcess }
    }
    $conns = @()
    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        if ([string]$c.RemoteAddress -like '127.*' -or [string]$c.RemoteAddress -eq '::1') { continue }
        $conns += [pscustomobject]@{ LocalPort = [int]$c.LocalPort; RemoteAddress = [string]$c.RemoteAddress; RemotePort = [int]$c.RemotePort; Pid = [int]$c.OwningProcess }
    }
    # one signature lookup per distinct program file (capped, because each lookup can take a moment)
    $paths = @(@($listen) + @($conns) | ForEach-Object { if ($procs.ContainsKey($_.Pid)) { $procs[$_.Pid].Path } } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 60)
    $sig = @{}
    foreach ($path in $paths) {
        try {
            $s = Get-AuthenticodeSignature -FilePath $path
            $sig[$path] = @{ Status = [string]$s.Status; Subject = $(if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }) }
        } catch { $sig[$path] = @{ Status = 'Error'; Subject = '' } }
    }
    $fill = {
        param($Row)
        $pr = $procs[[int]$Row.Pid]
        $name = ''; $path = ''; $sg = ''; $who = ''
        if ($pr) { $name = $pr.Name; $path = $pr.Path }
        if ($path -and $sig.ContainsKey($path)) { $sg = $sig[$path].Status; $who = $sig[$path].Subject }
        $Row | Add-Member -NotePropertyName Process -NotePropertyValue $name -PassThru |
            Add-Member -NotePropertyName Path -NotePropertyValue $path -PassThru |
            Add-Member -NotePropertyName SigStatus -NotePropertyValue $sg -PassThru |
            Add-Member -NotePropertyName SigSubject -NotePropertyValue $who -PassThru
    }
    [pscustomobject]@{
        Listeners = @($listen | ForEach-Object { & $fill $_ })
        Connections = @($conns | ForEach-Object { & $fill $_ })
    }
}

# ---------------------------------------------------------------- firewall
function Get-FirewallFacts {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True')
            In = [string]$_.DefaultInboundAction; Out = [string]$_.DefaultOutboundAction
            AllowInboundRules = ([string]$_.AllowInboundRules -ne 'False')        # False = "block ALL inbound, even allowed programs"
            LogBlocked = ([string]$_.LogBlocked -eq 'True'); LogFile = [string]$_.LogFileName; LogKb = [int]$_.LogMaxSizeKilobytes
        } })
    # local rules (these can be changed here) - anything active but not in this list comes from Group Policy
    $local = @{}
    foreach ($r in @(Get-NetFirewallRule -PolicyStore PersistentStore)) { $local[[string]$r.Name] = $true }
    # the three filter kinds for ALL rules at once, joined by id (asking rule by rule takes minutes)
    $portBy = @{}; $addrBy = @{}; $appBy = @{}
    foreach ($f in @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore)) { $portBy[[string]$f.InstanceID] = $f }
    foreach ($f in @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore)) { $addrBy[[string]$f.InstanceID] = $f }
    foreach ($f in @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore)) { $appBy[[string]$f.InstanceID] = $f }
    $rules = @()
    foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True)) {
        $id = [string]$r.InstanceID
        if (-not $id) { $id = [string]$r.Name }
        $port = $portBy[$id]; $addr = $addrBy[$id]; $app = $appBy[$id]
        if (-not $port) { $port = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if (-not $addr) { $addr = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if (-not $app)  { $app  = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Select-Object -First 1 }
        $rules += [pscustomobject]@{
            Name = [string]$r.Name; DisplayName = [string]$r.DisplayName; DisplayGroup = [string]$r.DisplayGroup; Group = [string]$r.Group
            Profile = [string]$r.Profile; Action = [string]$r.Action; Local = [bool]$local[[string]$r.Name]
            Protocol = [string]$port.Protocol; LocalPort = @($port.LocalPort | ForEach-Object { [string]$_ })
            RemoteAddress = @($addr.RemoteAddress | ForEach-Object { [string]$_ }); Program = [string]$app.Program
        }
    }
    # the same profile settings as stored LOCALLY: if they differ from the effective ones, Group Policy is overriding them
    $localProfiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True'); In = [string]$_.DefaultInboundAction; Out = [string]$_.DefaultOutboundAction } })
    $svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
    $ours = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'HP *' } |
        ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; DisplayName = [string]$_.DisplayName; Direction = [string]$_.Direction; Enabled = ([string]$_.Enabled -eq 'True') } })
    [pscustomobject]@{ Profiles = $profiles; LocalProfiles = $localProfiles; Rules = $rules; ServiceState = $(if ($svc) { [string]$svc.Status } else { 'Missing' }); OurRules = $ours }
}

# ---------------------------------------------------------------- Defender
function Get-DefenderFacts {
    # Everything the Defender rows need. The two Defender cmdlets can fail (service stopped, feature removed): then Available is
    # false and Reason holds the error text, but the policy values and the Windows feature are still read, so the rows can say why.
    $available = $false; $reason = ''
    $st = $null; $pref = $null
    try {
        $st   = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $available = $true
    } catch { $reason = $_.Exception.Message }
    $paths = @(); $extensions = @(); $processes = @()
    $quick = -1                                    # days since the last quick scan; -1 = never (Windows reports 4294967295)
    if ($available) {
        $paths      = @($pref.ExclusionPath | Where-Object { $_ })
        $extensions = @($pref.ExclusionExtension | Where-Object { $_ })
        $processes  = @($pref.ExclusionProcess | Where-Object { $_ })
        if ($null -ne $st.QuickScanAge -and $st.QuickScanAge -lt 100000) { $quick = [int]$st.QuickScanAge }
    }
    $feature = 'Unknown'                           # Installed | Available (= removed, can be put back) | Removed | Unknown
    try { $feature = [string](Get-WindowsFeature -Name 'Windows-Defender' -ErrorAction Stop).InstallState } catch { $feature = 'Unknown' }
    [pscustomobject]@{
        Available = $available; Reason = $reason
        ServiceEnabled = [bool]($available -and $st.AMServiceEnabled); RealTime = [bool]($available -and $st.RealTimeProtectionEnabled)
        Behavior = [bool]($available -and $st.BehaviorMonitorEnabled); Downloads = [bool]($available -and $st.IoavProtectionEnabled)
        Tamper = [bool]($available -and $st.IsTamperProtected)
        SignatureAgeDays = $(if ($available) { [int]$st.AntivirusSignatureAge } else { 999 })
        SignatureVersion = $(if ($available) { [string]$st.AntivirusSignatureVersion } else { '' })
        ProductVersion = $(if ($available) { [string]$st.AMProductVersion } else { '' })
        RunningMode = $(if ($available) { [string]$st.AMRunningMode } else { '' })
        QuickScanAgeDays = $quick
        ExclusionPaths = $paths; ExclusionExtensions = $extensions; ExclusionProcesses = $processes
        Exclusions = @($paths + $extensions + $processes)
        Feature = $feature
        PolicyValues = @(Get-DefenderPolicyValues)
    }
}

function Get-DefenderPolicyValues {
    # Registry values that switch Defender (or parts of it) off. A policy can set them, and so can an intruder, even when the service looks fine.
    # Every value that EXISTS is returned; the judge decides which ones matter (a Disable value of 0 is harmless).
    $wanted = [ordered]@{
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' = @('DisableAntiSpyware', 'DisableAntiVirus', 'DisableRoutinelyTakingAction')
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableIOAVProtection', 'DisableScanOnRealtimeEnable', 'DisableScriptScanning')
        'HKLM:\SOFTWARE\Microsoft\Windows Defender' = @('DisableAntiSpyware', 'DisableAntiVirus')
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableIOAVProtection', 'DisableScanOnRealtimeEnable')
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' = @('ForceDefenderPassiveMode')
    }
    $out = @()
    foreach ($path in $wanted.Keys) {
        foreach ($name in $wanted[$path]) {
            $data = Get-RegValue $path $name
            if ($null -ne $data) { $out += [pscustomobject]@{ Key = $path; Name = $name; Data = $data } }
        }
    }
    $out
}

# ---------------------------------------------------------------- places a program can hide so that it starts again (phase 6, read only)
# Each reader below looks at ONE kind of hiding place and returns plain records. Get-PersistFacts runs them all through Read-Part,
# so one reader that fails (access denied, a missing cmdlet) becomes one line in Problems and the other readers still answer.
function Read-Part {
    # -One: the reader returns a single record (not a list); a reader that fails then gives $null instead of an empty list.
    param([string]$Name, [scriptblock]$Code, $Problems, [switch]$One)
    try {
        $got = @(& $Code)
        if ($One) { return $got[0] }
        return $got
    } catch {
        [void]$Problems.Add("${Name}: $($_.Exception.Message)")
        if ($One) { return $null }
        return @()
    }
}

function Get-RegistryValues {
    # All values of one registry key as name + data. A key that does not exist gives an empty list.
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) { return @() }
    $key = Get-Item -Path $Path
    $out = @()
    foreach ($n in $key.GetValueNames()) { $out += [pscustomobject]@{ Name = [string]$n; Data = $key.GetValue($n) } }
    $out
}

function Get-LoadedUserSids {
    # Users whose registry hive is loaded right now (logged on). Their own startup keys can only be read while it is loaded.
    $names = (Get-Item -Path 'Registry::HKEY_USERS').GetSubKeyNames()
    @($names | Where-Object { $_ -match '^S-1-5-21-[0-9-]+$' })
}

function Get-RunValueFacts {
    # Programs that start by themselves when somebody logs on or the box boots: the Run and RunOnce keys of the machine and of every logged-on user.
    $keys = @()
    foreach ($tail in 'Run', 'RunOnce') {
        $keys += [pscustomobject]@{ Where = "machine $tail"; Sid = ''; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\$tail" }
        $keys += [pscustomobject]@{ Where = "machine 32-bit $tail"; Sid = ''; Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\$tail" }
    }
    $keys += [pscustomobject]@{ Where = 'machine policy Run'; Sid = ''; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' }
    foreach ($sid in (Get-LoadedUserSids)) {
        foreach ($tail in 'Run', 'RunOnce') {
            $keys += [pscustomobject]@{ Where = "user $tail"; Sid = $sid; Path = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\$tail" }
        }
    }
    $out = @()
    foreach ($k in $keys) {
        foreach ($v in (Get-RegistryValues $k.Path)) {
            $out += [pscustomobject]@{ Where = $k.Where; Sid = $k.Sid; Key = $k.Path; Name = $v.Name; Data = [string]$v.Data }
        }
    }
    $out
}

function Get-StartupFileFacts {
    # Every file in a Startup folder runs at logon. Windows puts nothing there by itself (only desktop.ini).
    $folders = @([pscustomobject]@{ Where = 'all users'; Path = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') })
    foreach ($p in (Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue)) {
        $folders += [pscustomobject]@{ Where = "user $($p.Name)"; Path = (Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
    }
    $out = @()
    foreach ($f in $folders) {
        foreach ($item in @(Get-ChildItem -Path $f.Path -File -Force -ErrorAction SilentlyContinue)) {
            if ($item.Name -ieq 'desktop.ini') { continue }
            $out += [pscustomobject]@{ Where = $f.Where; Name = [string]$item.Name; Path = [string]$item.FullName; Bytes = [long]$item.Length; Time = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
        }
    }
    $out
}

function Get-WinlogonFacts {
    # What Windows starts when somebody logs on. The defaults: Shell = explorer.exe, Userinit = C:\Windows\system32\userinit.exe,
    # and no Taskman / AppSetup at all.
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    [pscustomobject]@{
        Shell = [string](Get-RegValue $path 'Shell'); Userinit = [string](Get-RegValue $path 'Userinit')
        Taskman = [string](Get-RegValue $path 'Taskman'); AppSetup = [string](Get-RegValue $path 'AppSetup')
    }
}

function Get-DebuggerFacts {
    # Image File Execution Options: a Debugger value makes Windows start THAT program whenever the named program starts (the classic
    # "sticky keys" backdoor). VerifierDlls loads a DLL into the named program. SilentProcessExit runs a program when the named one ends.
    # A normal server has none of these.
    $out = @()
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')
    foreach ($root in $roots) {
        if (-not (Test-Path -Path $root)) { continue }
        foreach ($name in (Get-Item -Path $root).GetSubKeyNames()) {
            $sub = "$root\$name"
            $debugger = [string](Get-RegValue $sub 'Debugger')
            $verifier = [string](Get-RegValue $sub 'VerifierDlls')
            if ($debugger) { $out += [pscustomobject]@{ Kind = 'Debugger'; Program = $name; Value = $debugger; Key = $sub } }
            if ($verifier) { $out += [pscustomobject]@{ Kind = 'VerifierDlls'; Program = $name; Value = $verifier; Key = $sub } }
        }
    }
    $silent = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path -Path $silent) {
        foreach ($name in (Get-Item -Path $silent).GetSubKeyNames()) {
            $monitor = [string](Get-RegValue "$silent\$name" 'MonitorProcess')
            if ($monitor) { $out += [pscustomobject]@{ Kind = 'MonitorProcess'; Program = $name; Value = $monitor; Key = "$silent\$name" } }
        }
    }
    $out
}

function Get-AppInitFacts {
    # AppInit_DLLs: DLLs that Windows loads into every program that uses a window. Empty on a normal box (and off by default).
    # The Load and Run values in the same key are an old way to start programs at logon.
    $out = @()
    foreach ($path in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $out += [pscustomobject]@{
            Key = $path; Dlls = [string](Get-RegValue $path 'AppInit_DLLs'); LoadAppInit = [int](Get-RegValue $path 'LoadAppInit_DLLs')
            LoadProgram = [string](Get-RegValue $path 'Load'); RunProgram = [string](Get-RegValue $path 'Run')
        }
    }
    $out
}

function Get-LsaFacts {
    # The packages the Local Security Authority loads: an extra DLL here sees every password typed on this box.
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    [pscustomobject]@{
        Authentication = @(Get-RegValue $path 'Authentication Packages' | Where-Object { $_ })
        Notification   = @(Get-RegValue $path 'Notification Packages' | Where-Object { $_ })
        Security       = @(Get-RegValue $path 'Security Packages' | Where-Object { $_ })
    }
}

function Get-AccessibilityFacts {
    # sethc (Sticky Keys), utilman, osk, narrator, magnify and displayswitch can be started from the RDP login screen, before anybody has
    # logged in. An attacker swaps one of them for cmd.exe to get a SYSTEM shell from the login screen. We read each file's signature and
    # SHA-256, and compare the SHA-256 with cmd.exe and powershell.exe (a swapped-in copy of cmd.exe still has Microsoft's signature).
    $system = Join-Path $env:SystemRoot 'System32'
    $shells = @()
    foreach ($rel in 'cmd.exe', 'WindowsPowerShell\v1.0\powershell.exe') {
        $shellPath = Join-Path $system $rel
        if (Test-Path -Path $shellPath) { $shells += (Get-FileHash -Algorithm SHA256 -Path $shellPath).Hash }
    }
    $out = @()
    foreach ($name in 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe') {
        $path = Join-Path $system $name
        if (-not (Test-Path -Path $path)) {
            $out += [pscustomobject]@{ Name = $name; Path = $path; Exists = $false; SigStatus = ''; SigSubject = ''; Sha256 = ''; LooksLikeShell = $false }
            continue
        }
        $sig = Get-AuthenticodeSignature -FilePath $path
        $hash = (Get-FileHash -Algorithm SHA256 -Path $path).Hash
        $out += [pscustomobject]@{
            Name = $name; Path = $path; Exists = $true; SigStatus = [string]$sig.Status
            SigSubject = $(if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { '' })
            Sha256 = $hash; LooksLikeShell = [bool]($shells -contains $hash)
        }
    }
    $out
}

function Get-WmiName {
    # A WMI reference such as  __EventFilter (Name = "x")  or  \\.\root\subscription:__EventFilter.Name="x"  -> x
    param($Reference)
    if ([string]$Reference -match 'Name\s*=\s*\\?"([^"\\]*)') { return $Matches[1] }
    [string]$Reference
}

function Get-WmiSubscriptionFacts {
    # Permanent WMI event subscriptions: "when this happens, run that". They survive reboots and show in neither Task Manager nor Task Scheduler.
    # A filter says WHEN, a consumer says WHAT to do, a binding joins the two. Windows has one of its own (the "SCM Event Log" pair).
    $ns = 'root\subscription'
    $filters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Name = [string]$_.Name; Query = [string]$_.Query } })
    $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Class = [string]$_.CimClass.CimClassName; Name = [string]$_.Name
            Command = (@($_.CommandLineTemplate, $_.ExecutablePath, $_.ScriptFileName, $_.ScriptText) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ' | '
        } })
    $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{ Filter = (Get-WmiName $_.Filter); Consumer = (Get-WmiName $_.Consumer) } })
    [pscustomobject]@{ Filters = $filters; Consumers = $consumers; Bindings = $bindings }
}

function Get-HostsFileFacts {
    # The hosts file overrides DNS. A line in it can send a name (for example the blackbox's) to the wrong address.
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $entries = @()
    if (Test-Path -Path $path) {
        $text = [string](Get-Content -Path $path -Raw)
        $entries = @($text -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
    }
    [pscustomobject]@{ Path = $path; Entries = $entries }
}

function Get-ShareFacts {
    # Network shares. ADMIN$, C$ and IPC$ are Windows' own ("special"); anything else somebody made. For those we also read who may open them.
    $out = @()
    foreach ($s in @(Get-SmbShare -ErrorAction Stop)) {
        $access = @()
        if (-not $s.Special) {
            foreach ($a in @(Get-SmbShareAccess -Name $s.Name)) { $access += "$($a.AccountName):$($a.AccessRight):$($a.AccessControlType)" }
        }
        $out += [pscustomobject]@{ Name = [string]$s.Name; Path = [string]$s.Path; Special = [bool]$s.Special; Description = [string]$s.Description; Access = $access }
    }
    $out
}

function Get-BitsFacts {
    # BITS jobs are background downloads that Windows keeps across reboots (an old trick for re-downloading a backdoor). A quiet server has none.
    $out = @()
    foreach ($j in @(Get-BitsTransfer -AllUsers -ErrorAction Stop)) {
        $out += [pscustomobject]@{ Name = [string]$j.DisplayName; State = [string]$j.JobState; Owner = [string]$j.OwnerAccount; Files = @($j.FileList | ForEach-Object { [string]$_.RemoteName }) }
    }
    $out
}

function Get-ProfileScriptFacts {
    # A PowerShell profile script runs every time somebody opens PowerShell - including you, as an administrator. A fresh server has none.
    $names = 'profile.ps1', 'Microsoft.PowerShell_profile.ps1', 'Microsoft.PowerShellISE_profile.ps1'
    $folders = @([pscustomobject]@{ Where = 'all users'; Path = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0') },
                 [pscustomobject]@{ Where = 'all users (32-bit)'; Path = (Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0') })
    foreach ($p in (Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue)) {
        $folders += [pscustomobject]@{ Where = "user $($p.Name)"; Path = (Join-Path $p.FullName 'Documents\WindowsPowerShell') }
    }
    $out = @()
    foreach ($f in $folders) {
        foreach ($n in $names) {
            $file = Join-Path $f.Path $n
            if (Test-Path -Path $file) { $out += [pscustomobject]@{ Where = $f.Where; Name = $n; Path = $file } }
        }
    }
    $out
}

function Get-PolicyScriptFacts {
    # Local group policy can run scripts at boot, shutdown, logon and logoff. A fresh server has none.
    $root = Join-Path $env:SystemRoot 'System32\GroupPolicy'
    $out = @()
    foreach ($sub in 'Machine\Scripts\Startup', 'Machine\Scripts\Shutdown', 'User\Scripts\Logon', 'User\Scripts\Logoff') {
        foreach ($item in @(Get-ChildItem -Path (Join-Path $root $sub) -File -Force -ErrorAction SilentlyContinue)) {
            $out += [pscustomobject]@{ Where = $sub; Name = [string]$item.Name; Path = [string]$item.FullName }
        }
    }
    $out
}

function Get-ProxyFacts {
    # A proxy setting sends web traffic through somebody else's server. Only settings that are switched on (or name a PAC script) are returned.
    $places = @([pscustomobject]@{ Where = 'machine'; Sid = ''; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' })
    foreach ($sid in (Get-LoadedUserSids)) {
        $places += [pscustomobject]@{ Where = 'user'; Sid = $sid; Path = "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" }
    }
    $out = @()
    foreach ($p in $places) {
        $enabled = [int](Get-RegValue $p.Path 'ProxyEnable')
        $server  = [string](Get-RegValue $p.Path 'ProxyServer')
        $pacUrl  = [string](Get-RegValue $p.Path 'AutoConfigURL')
        if ($enabled -eq 1 -or $pacUrl) { $out += [pscustomobject]@{ Where = $p.Where; Sid = $p.Sid; Enabled = ($enabled -eq 1); Server = $server; PacUrl = $pacUrl } }
    }
    $out
}

function Get-RdpDllFacts {
    # The Remote Desktop service loads this DLL; "RDP wrapper" tools and backdoors swap it. We only READ it: the service is never touched.
    $dll = [string](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters' 'ServiceDll')
    $path = [Environment]::ExpandEnvironmentVariables($dll)
    $status = ''; $who = ''
    if ($path -and (Test-Path -Path $path)) {
        $sig = Get-AuthenticodeSignature -FilePath $path
        $status = [string]$sig.Status
        if ($sig.SignerCertificate) { $who = [string]$sig.SignerCertificate.Subject }
    }
    [pscustomobject]@{ ServiceDll = $dll; Path = $path; SigStatus = $status; SigSubject = $who }
}

function Get-PersistFacts {
    $problems = New-Object System.Collections.ArrayList
    $p = [ordered]@{}
    $p.RunValues     = @(Read-Part 'Run keys' { Get-RunValueFacts } $problems)
    $p.StartupFiles  = @(Read-Part 'Startup folders' { Get-StartupFileFacts } $problems)
    $p.Winlogon      = Read-Part 'Winlogon' { Get-WinlogonFacts } $problems -One
    $p.Debuggers     = @(Read-Part 'Image File Execution Options' { Get-DebuggerFacts } $problems)
    $p.AppInit       = @(Read-Part 'AppInit' { Get-AppInitFacts } $problems)
    $p.Lsa           = Read-Part 'LSA packages' { Get-LsaFacts } $problems -One
    $p.Accessibility = @(Read-Part 'Accessibility programs' { Get-AccessibilityFacts } $problems)
    $p.Wmi           = Read-Part 'WMI subscriptions' { Get-WmiSubscriptionFacts } $problems -One
    $p.Hosts         = Read-Part 'hosts file' { Get-HostsFileFacts } $problems -One
    $p.Shares        = @(Read-Part 'Shares' { Get-ShareFacts } $problems)
    $p.Bits          = @(Read-Part 'BITS jobs' { Get-BitsFacts } $problems)
    $p.ProfileFiles  = @(Read-Part 'PowerShell profiles' { Get-ProfileScriptFacts } $problems)
    $p.PolicyScripts = @(Read-Part 'Policy scripts' { Get-PolicyScriptFacts } $problems)
    $p.Proxy         = @(Read-Part 'Proxy settings' { Get-ProxyFacts } $problems)
    $p.RdpDll        = Read-Part 'RDP service DLL' { Get-RdpDllFacts } $problems -One
    $p.Problems      = @($problems)
    [pscustomobject]$p
}

# ---------------------------------------------------------------- Jenkins and the log collector: discover, never hardcode
function Get-JenkinsFacts {
    param($Services, $Listeners)
    $svc = @($Services | Where-Object { $_.Name -like '*jenkins*' -or $_.PathName -like '*jenkins*' }) | Select-Object -First 1
    if (-not $svc) { return [pscustomobject]@{ Found = $false } }
    $exe = $svc.Exe
    $dir = $(if ($exe) { Split-Path -Parent $exe } else { '' })
    $jenkinsHome = ''; $java = ''
    # 1. the service wrapper file  jenkins.xml  (sits next to the service program)
    $xml = $(if ($dir) { Join-Path $dir 'jenkins.xml' } else { '' })
    if ($xml -and (Test-Path $xml)) {
        $raw = Get-Content $xml -Raw
        if ($raw -match '<env\s+name="JENKINS_HOME"\s+value="([^"]+)"') { $jenkinsHome = [Environment]::ExpandEnvironmentVariables($Matches[1]) }
        if ($raw -match '<executable>([^<]+)</executable>') { $java = [Environment]::ExpandEnvironmentVariables($Matches[1]) }
    }
    # 2. -DJENKINS_HOME=... on the service command line
    if (-not $jenkinsHome -and [string]$svc.PathName -match '-DJENKINS_HOME=("[^"]+"|\S+)') { $jenkinsHome = $Matches[1].Trim('"') }
    # 3. the service's own environment in the registry
    if (-not $jenkinsHome) {
        $envList = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" 'Environment'
        foreach ($e in @($envList)) { if ([string]$e -match '^JENKINS_HOME=(.+)$') { $jenkinsHome = $Matches[1] } }
    }
    # 4. the usual places (a config.xml proves it is the right folder)
    if (-not $jenkinsHome) {
        $guesses = @('C:\ProgramData\Jenkins\.jenkins', 'C:\Program Files\Jenkins', 'C:\Program Files (x86)\Jenkins',
                     'C:\Windows\System32\config\systemprofile\.jenkins', 'C:\Jenkins')
        $jenkinsHome = "$(@($guesses | Where-Object { Test-Path (Join-Path $_ 'config.xml') }) | Select-Object -First 1)"   # "$(...)" is '' when nothing matches; [string](...) would give $null
    }
    # who owns the Jenkins port, and which Java is that
    $owner = @($Listeners | Where-Object { $_.Proto -eq 'TCP' -and $_.Port -eq $script:Plan.JenkinsPort }) | Select-Object -First 1
    if (-not $java -and $owner -and $owner.Process -like 'java*') { $java = $owner.Path }
    $javaVersion = ''
    if ($java -and (Test-Path $java)) { $javaVersion = [string](Get-Item $java).VersionInfo.ProductVersion }
    $initScripts = @()
    if ($jenkinsHome) { $initScripts = @(Get-ChildItem (Join-Path $jenkinsHome 'init.groovy.d') -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
    [pscustomobject]@{
        Found = $true; Service = [string]$svc.Name; State = [string]$svc.State; StartMode = [string]$svc.StartMode; StartName = [string]$svc.StartName
        Exe = $exe; Home = $jenkinsHome; HomeFound = [bool]($jenkinsHome -and (Test-Path $jenkinsHome)); Java = $java; JavaVersion = $javaVersion
        PortOwner = $(if ($owner) { [string]$owner.Process } else { '' }); Listening = [bool]$owner
        InitGroovy = $initScripts
    }
}

function Get-CollectorFacts {
    # The log collector ships Security/System/Application logs to blackbox. We must never break it, so we look for it:
    # services whose name or program looks like a log shipper, and any program with a connection to blackbox.
    param($Services, $Connections, [string]$BlackboxIp = '')
    $words = 'otel|opentelemetry|openobserve|fluent|vector|filebeat|winlogbeat|telegraf|nxlog|splunk|promtail|alloy|cribl|logstash|collector'
    $found = @()
    foreach ($s in $Services) {
        if ($s.Name -match $words -or $s.DisplayName -match $words -or $s.Exe -match $words) {
            $found += [pscustomobject]@{ Kind = 'service'; Name = $s.Name; Path = $s.Exe; Detail = "service $($s.Name) is $($s.State), runs as $($s.StartName)" }
        }
    }
    if ($BlackboxIp) {
        foreach ($c in $Connections) {
            if ($c.RemoteAddress -eq $BlackboxIp -and $c.RemotePort -ne $script:Plan.BlackboxPort) {
                $found += [pscustomobject]@{ Kind = 'connection'; Name = $c.Process; Path = $c.Path; Detail = "$($c.Process) is connected to blackbox port $($c.RemotePort)" }
            }
        }
    }
    @($found)
}

function Get-BackupFacts {
    # What the backup step has already done (read from the data folder): archives, the SSH key, the pinned host key, the last upload.
    $dir = Join-Path $script:Hp.DataDir 'backup'
    $archives = @()
    if (Test-Path $dir) {
        $archives = @(Get-ChildItem -Path $dir -Filter '*.enc' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; Time = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); Bytes = [long]$_.Length } })
    }
    $sent = $null
    $sentFile = Join-Path $dir 'sent.json'
    if (Test-Path $sentFile) { try { $sent = [System.IO.File]::ReadAllText($sentFile) | ConvertFrom-Json } catch { $sent = $null } }
    $ssh = Join-Path $script:Hp.DataDir 'ssh'
    $key = Join-Path $ssh 'id_backup'
    $pub = ''
    if (Test-Path "$key.pub") { try { $pub = ([System.IO.File]::ReadAllText("$key.pub")).Trim() } catch { $pub = '' } }
    $pinned = $false
    $bb = [string](Get-HpSetting 'BlackboxIp')
    $known = Join-Path $ssh 'known_hosts'
    if ($bb -and (Test-Path $known)) {
        # a line starts with the IP, or with [IP]:port when the port is not 22 (a key pinned for another port does not count)
        $port = [int]$script:Plan.BlackboxPort
        $who = $(if ($port -eq 22) { [regex]::Escape($bb) } else { '\[' + [regex]::Escape($bb) + '\]:' + $port })
        try { $pinned = [bool](([System.IO.File]::ReadAllText($known)) -match ('(?m)^' + $who + '\s')) } catch { $pinned = $false }
    }
    [pscustomobject]@{ Archives = $archives; Sent = $sent; KeyPath = $key; KeyExists = [bool]$pub; PubKey = $pub; KnownHosts = $known; HostKeyPinned = $pinned }
}

# ---------------------------------------------------------------- the watchdog: installed? running? what did it find?
# Watchdog.ps1 runs as the SYSTEM task NetCacheWatch and writes small files into <data folder>\watchdog. This reads them. It changes nothing.
function Get-OwnTaskFiles {
    # The tool's two scheduled tasks and the file each one must run: lower-case task name -> full path of that script.
    # The judges use it to tell the tool's own tasks from a task that only has the same name.
    $own = @{}
    $own[([string]$script:WatchdogTaskName).ToLower()] = [string](Get-WatchdogPaths).Script
    $own[([string]$script:DeadManTaskName).ToLower()] = [string](Get-DeadManPaths).Panic
    $own
}

function Read-SharedText {
    # A whole text file, read in a way that also works while another program has it open for writing
    # (the watchdog rewrites status.json and appends to alerts.log; File.ReadAllText could fail at that moment).
    param([string]$Path)
    $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
        $reader = New-Object System.IO.StreamReader($stream)
        $reader.ReadToEnd()
    } finally { $stream.Dispose() }
}

function Format-EpochClock {
    # Seconds since 1970 -> the local time of day for a row ('' for 0).
    param([long]$Epoch)
    if ($Epoch -le 0) { return '' }
    [DateTimeOffset]::FromUnixTimeSeconds($Epoch).LocalDateTime.ToString('HH:mm:ss')
}

function Get-WatchdogAlertLines {
    # The newest lines of alerts.log as { Time; Level; Text; AgeMinutes }. A line looks like:  2026-10-17 10:15:02 ALERT text...
    param([string]$Path, [int]$Last = 200)
    $out = @()
    if (-not (Test-Path $Path)) { return $out }
    $lines = @((Read-SharedText $Path) -split "`r?`n" | Where-Object { $_ } | Select-Object -Last $Last)
    foreach ($line in $lines) {
        if ($line -match '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\S+)\s+(.*)$') {
            $when = $Matches[1]; $level = $Matches[2]; $text = $Matches[3]
            $age = 0
            try { $age = [int](((Get-Date) - [datetime]::ParseExact($when, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)).TotalMinutes) } catch { $age = 0 }
            $out += [pscustomobject]@{ Time = $when; Level = $level; Text = $text; AgeMinutes = $age }
        }
    }
    $out
}

function Get-WatchdogFacts {
    $p = Get-WatchdogPaths
    $nowEpoch = [DateTimeOffset]::Now.ToUnixTimeSeconds()

    # the scheduled task (only the one in the root folder counts: a task with the same name somewhere else is not ours)
    $task = @(Get-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -ErrorAction SilentlyContinue) | Select-Object -First 1
    $action = ''; $interval = ''
    if ($task) {
        $action = (@($task.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() })) -join ' ; '
        $trigger = @($task.Triggers) | Select-Object -First 1
        if ($trigger -and $trigger.Repetition) { $interval = [string]$trigger.Repetition.Interval }
    }

    # the two scripts: next to the tool (the originals) and in the data folder (the copies the task runs)
    $sourceFound = $false; $copyFound = $false; $copyCurrent = $false
    if ($script:HpRoot) {
        $names = @('Watchdog.ps1', 'Panic.ps1')
        $sourceFound = (@($names | Where-Object { Test-Path (Join-Path $script:HpRoot $_) }).Count -eq $names.Count)
        $copyFound = (@($names | Where-Object { Test-Path (Join-Path $p.Dir $_) }).Count -eq $names.Count)
        if ($sourceFound -and $copyFound) {
            $copyCurrent = $true
            foreach ($n in $names) {
                if ((Get-Sha256Hex (Join-Path $script:HpRoot $n)) -ne (Get-Sha256Hex (Join-Path $p.Dir $n))) { $copyCurrent = $false }
            }
        }
    }

    # what the last pass wrote
    $status = $null; $age = -1
    if (Test-Path $p.Status) {
        try {
            $status = (Read-SharedText $p.Status) | ConvertFrom-Json
            $age = [int]($nowEpoch - [long]$status.Epoch)
        } catch { $status = $null; $age = -1 }
    }
    $checks = @()
    $diffs = @()
    if ($status) {
        foreach ($c in @($status.Checks)) {
            $checks += [pscustomobject]@{ Name = [string]$c.Name; Ok = [bool]$c.Ok; Detail = [string]$c.Detail; SinceText = (Format-EpochClock ([long]$c.Since)) }
        }
        foreach ($d in @($status.Diffs)) { $diffs += [pscustomobject]@{ Name = [string]$d.Name; Count = [int]$d.Count; Lines = [string]$d.Lines } }
    }

    # notes the tool or you left for the next pass, and the Jenkins folder the watchdog was told about
    $pausedUntil = 0
    if (Test-Path $p.PauseFile) {
        try {
            $until = [long]([System.IO.File]::ReadAllText($p.PauseFile).Trim())
            if ($until -gt $nowEpoch) { $pausedUntil = $until }
        } catch { $pausedUntil = 0 }
    }
    $configHome = ''
    if (Test-Path $p.Config) {
        try { $configHome = [string]((Read-SharedText $p.Config) | ConvertFrom-Json).JenkinsHome } catch { $configHome = '' }
    }

    [pscustomobject]@{
        Dir = $p.Dir; AlertsFile = $p.Alerts
        TaskFound = [bool]$task; TaskState = $(if ($task) { [string]$task.State } else { '' }); TaskUser = $(if ($task) { [string]$task.Principal.UserId } else { '' })
        TaskAction = $action; TaskInterval = $interval
        SourceFound = $sourceFound; CopyFound = $copyFound; CopyCurrent = $copyCurrent; ConfigHome = $configHome
        StatusFound = [bool]$status; StatusAge = $age
        StatusTime = $(if ($status) { [string]$status.Time } else { '' }); Pass = $(if ($status) { [long]$status.Pass } else { 0 })
        HealOn = $(if ($status) { [bool]$status.HealOn } else { $false }); Heals = $(if ($status) { [long]$status.Heals } else { 0 })
        BaselineText = $(if ($status) { Format-EpochClock ([long]$status.BaselineTaken) } else { '' })
        Checks = $checks; Diffs = $diffs
        PausedUntil = $pausedUntil; PausedText = (Format-EpochClock $pausedUntil)
        RebaselineNote = [bool](Test-Path $p.RebaseFlag); AcceptJobsNote = [bool](Test-Path $p.AcceptFlag)
        Alerts = @(Get-WatchdogAlertLines $p.Alerts)
    }
}

# ---------------------------------------------------------------- which facts a change makes stale
function Get-SectionsForAction {
    # After a change only these parts of the audit are read again (the firewall part is the slow one).
    param([string]$ActionId)
    switch -Wildcard ($ActionId) {
        'user.*'     { return @('Accounts', 'Secedit', 'Services', 'Tasks') }
        'rights.*'   { return @('Accounts', 'Secedit') }
        'fw.*'       { return @('Firewall', 'Net') }
        'deadman.*'  { return @('DeadMan', 'Firewall', 'Tasks') }      # arming adds the task NetCacheRestore, disarming removes it (phase 6 lists the tasks)
        'backup.*'   { return @('Backup', 'Net') }
        'settings.*' { return @('Backup', 'Net', 'Collector') }
        'svc.*'      { return @('Services', 'Ports') }
        'task.*'     { return @('Tasks') }
        'def.*'      { return @('Defender', 'Services') }
        'persist.*'  { return @('Persist') }
        'watchdog.*' { return @('Watchdog', 'Tasks') }
    }
    @()
}

# ---------------------------------------------------------------- everything
function Get-HpFacts {
    # -Sections limits the work (for example after a firewall change only 'Firewall' is read again); -Previous supplies the rest.
    param([string[]]$Sections = @(), $Previous = $null)
    $errors = New-Object System.Collections.ArrayList
    $f = [ordered]@{}
    foreach ($n in 'Host', 'Net', 'Tools', 'Accounts', 'Secedit', 'Services', 'Tasks', 'Ports', 'Firewall', 'Defender', 'Persist', 'Jenkins', 'Collector', 'Backup', 'DeadMan', 'Watchdog') {
        $f[$n] = $(if ($Previous) { $Previous.$n } else { $null })
    }
    $all = ($Sections.Count -eq 0)
    $bb = [string](Get-HpSetting 'BlackboxIp')
    if ($all -or $Sections -contains 'Host')     { $f.Host     = Invoke-Collector 'Host' { Get-HostFacts } $errors }
    if ($all -or $Sections -contains 'Net')      { $f.Net      = Invoke-Collector 'Net' { Get-NetworkFacts -BlackboxIp $bb } $errors }
    if ($all -or $Sections -contains 'Tools')    { $f.Tools    = Invoke-Collector 'Tools' { Get-ToolFacts } $errors }
    if ($all -or $Sections -contains 'Accounts') { $f.Accounts = Invoke-Collector 'Accounts' { Get-AccountFacts } $errors }
    if ($all -or $Sections -contains 'Secedit')  { $f.Secedit  = Invoke-Collector 'Secedit' { Get-SeceditFacts } $errors }
    if ($all -or $Sections -contains 'Services') { $f.Services = Invoke-Collector 'Services' { Get-ServiceFacts } $errors }
    if ($all -or $Sections -contains 'Tasks')    { $f.Tasks    = Invoke-Collector 'Tasks' { Get-TaskFacts } $errors }
    if ($all -or $Sections -contains 'Ports')    { $f.Ports    = Invoke-Collector 'Ports' { Get-PortFacts } $errors }
    if ($all -or $Sections -contains 'Firewall') { $f.Firewall = Invoke-Collector 'Firewall' { Get-FirewallFacts } $errors }
    if ($all -or $Sections -contains 'Defender') { $f.Defender = Invoke-Collector 'Defender' { Get-DefenderFacts } $errors }
    if ($all -or $Sections -contains 'Persist')  { $f.Persist  = Invoke-Collector 'Persist' { Get-PersistFacts } $errors }
    $listeners = $(if ($f.Ports) { @($f.Ports.Listeners) } else { @() })
    $conns     = $(if ($f.Ports) { @($f.Ports.Connections) } else { @() })
    $svcs      = @($f.Services)
    if ($all -or $Sections -contains 'Jenkins')   { $f.Jenkins   = Invoke-Collector 'Jenkins' { Get-JenkinsFacts -Services $svcs -Listeners $listeners } $errors }
    if ($all -or $Sections -contains 'Collector') { $f.Collector = Invoke-Collector 'Collector' { Get-CollectorFacts -Services $svcs -Connections $conns -BlackboxIp $bb } $errors }
    if ($all -or $Sections -contains 'Backup')    { $f.Backup    = Invoke-Collector 'Backup' { Get-BackupFacts } $errors }
    if ($all -or $Sections -contains 'DeadMan')   { $f.DeadMan   = Invoke-Collector 'DeadMan' { Get-DeadManStatus } $errors }
    if ($all -or $Sections -contains 'Watchdog')  { $f.Watchdog  = Invoke-Collector 'Watchdog' { Get-WatchdogFacts } $errors }
    $f.OwnTasks = Get-OwnTaskFiles          # not a section: it is only paths, worked out again every time
    $f.Time = Get-Date
    # errors of sections that were NOT read again stay; errors of sections that were read again are replaced
    $oldErrors = @()
    if ($Previous -and -not $all) {
        $oldErrors = @($Previous.Errors | Where-Object { $e = $_; $_ -and -not (@($Sections | Where-Object { $e -like "${_}:*" }).Count) })
    }
    $f.Errors = @(@($errors) + $oldErrors)
    [pscustomobject]$f
}
