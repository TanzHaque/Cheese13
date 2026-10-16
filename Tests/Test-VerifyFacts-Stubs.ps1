# Test-VerifyFacts-Stubs.ps1 - runs the REAL collectors (VerifyFacts.ps1) and the judges together,
# with every Windows cmdlet replaced by a stub that returns what the real cmdlet returns for a made-up box.
# What it proves: property names line up between collectors and judges, nothing throws, and a hardened fake
# box comes out green while a sloppy fake box comes out red.
# What it does NOT prove: that Windows really returns these shapes. Test that with Verify-Hardening.ps1 in the lab.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\ScoreLib.ps1"
. "$PSScriptRoot\..\VerifyJudgeAccounts.ps1"
. "$PSScriptRoot\..\VerifyJudgeFirewall.ps1"
. "$PSScriptRoot\..\VerifyJudgeSystem.ps1"
. "$PSScriptRoot\..\VerifyFacts.ps1"

$env:TEMP = [IO.Path]::GetTempPath()
$env:SystemRoot = 'C:\Windows'
$global:Reg = @{}          # "path|name" -> value
$global:Box = $null        # the fake box (set by Set-FakeBox)

# ------------------------------------------------------------------ stubs
function Get-ItemProperty {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$Name)
    if ($Name) {
        if (-not $global:Reg.ContainsKey("$Path|$Name")) { throw 'property not found' }
        $o = New-Object psobject; $o | Add-Member -NotePropertyName $Name -NotePropertyValue $global:Reg["$Path|$Name"]; return $o
    }
    $o = New-Object psobject; $found = $false
    foreach ($k in $global:Reg.Keys) {
        if ($k.StartsWith("$Path|")) { $found = $true; $o | Add-Member -NotePropertyName $k.Substring($Path.Length + 1) -NotePropertyValue $global:Reg[$k] }
    }
    if ($found) { $o }
}
function Test-Path { param([string]$Path) ($global:Box.Files -contains $Path) -or (Microsoft.PowerShell.Management\Test-Path $Path) }
function Get-AuthenticodeSignature { param($Path) $null = $Path; [pscustomobject]@{ Status = $global:Box.SigStatus; SignerCertificate = [pscustomobject]@{ Subject = $global:Box.SigSubject } } }
function Get-Service { param($Name) $null = $Name; [pscustomobject]@{ Status = $global:Box.TermState } }
function Get-NetTCPConnection { param($LocalPort, $State) $null = $State; if ($global:Box.Listen3389 -and $LocalPort -eq 3389) { [pscustomobject]@{ LocalPort = 3389 } } }
function Get-CimInstance {
    param([Parameter(Position = 0)][string]$ClassName, [string]$Namespace)
    $null = $ClassName
    if ($Namespace) { return $global:Box.WmiConsumers | ForEach-Object { [pscustomobject]@{ Name = $_ } } }
    $global:Box.Services | ForEach-Object { [pscustomobject]$_ }
}
function Get-MpComputerStatus { if (-not $global:Box.Defender) { throw 'service not running' }; [pscustomobject]$global:Box.Defender }
function Get-MpPreference { [pscustomobject]@{ ExclusionPath = $global:Box.Exclusions; ExclusionExtension = $null; ExclusionProcess = $null } }
function Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $global:Box.Smb1 } }
function Get-SmbShare { [pscustomobject[]]($global:Box.Shares | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Special = $_.Special } }) }
function Get-ChildItem { param($Path) $null = $Path; $global:Box.IfeoKeys | ForEach-Object { [pscustomobject]@{ PSPath = "IFEO\$_"; PSChildName = $_ } } }
function Get-Content { param($Path) if ($Path -like '*\drivers\etc\hosts') { $global:Box.Hosts } else { Microsoft.PowerShell.Management\Get-Content $Path } }
function Get-LocalUser { param($Name) $null = $Name; $global:Box.Users | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; SID = [pscustomobject]@{ Value = $_.Sid } } } }
function Get-LocalGroup { $global:Box.Groups | ForEach-Object { [pscustomobject]@{ Name = $_.Name; SID = [pscustomobject]@{ Value = $_.Sid } } } }
function net.exe {
    $g = $args[1]
    'Alias name     ' + $g; 'Comment        x'; ''; 'Members'; ''; '-------------------------------------------------------------------------------'
    foreach ($m in @(($global:Box.Groups | Where-Object { $_.Name -eq $g }).Members)) { $m }
    'The command completed successfully.'
}
function secedit.exe {
    $path = $args[[array]::IndexOf($args, '/cfg') + 1]
    Set-Content -Path $path -Value $global:Box.Secedit
}
function Test-LocalCredential { param($User, $Password) $global:Box.Passwords -contains "$User|$Password" }
function Get-NetFirewallProfile { param($PolicyStore) $null = $PolicyStore; $global:Box.FwProfiles | ForEach-Object { [pscustomobject]$_ } }
function Get-NetConnectionProfile { $global:Box.NetCategories | ForEach-Object { [pscustomobject]@{ NetworkCategory = $_ } } }
function Get-NetFirewallRule {
    param($PolicyStore, $Direction, $Enabled)
    $null = $PolicyStore, $Enabled
    $global:Box.FwRules | Where-Object { $_.Direction -eq $Direction } | ForEach-Object { [pscustomobject]$_ }
}
function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { [pscustomobject]@{ Protocol = $InputObject._Proto; LocalPort = $InputObject._LPort; RemotePort = $InputObject._RPort } } }
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { [pscustomobject]@{ RemoteAddress = $InputObject._Remote } } }
function Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { [pscustomobject]@{ Program = $InputObject._Program } } }

function New-FwRule {
    param([string]$Name, [string]$Port = 'Any', [string]$Proto = 'TCP', [string]$Group = '', [string]$Dir = 'Inbound', [string]$Remote = 'Any', [string]$Program = 'Any')
    @{ DisplayName = $Name; DisplayGroup = $Group; Group = ''; Profile = 'Any'; Action = 'Allow'; Direction = $Dir
       _Proto = $Proto; _LPort = $Port; _RPort = 'Any'; _Remote = $Remote; _Program = $Program }
}

function Set-FakeBox {
    param([bool]$Hardened)
    $inf = @('[System Access]', $(if ($Hardened) { 'LockoutBadCount = 0' } else { 'LockoutBadCount = 5' }), '[Privilege Rights]',
             'SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545', 'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555',
             'SeDenyNetworkLogonRight = *S-1-5-32-546', 'SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546')
    $core = New-FwRule 'Core Networking - ICMP' 'Any' 'ICMPv4' 'Core Networking'
    $rules = @((New-FwRule 'Remote Desktop (TCP-In)' '3389'), (New-FwRule 'Jenkins 8080' '8080'), $core)
    if (-not $Hardened) { $rules += (New-FwRule 'Dev Web' '8000'); $rules += (New-FwRule 'Legacy FTP' '21') }
    $global:Reg = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections' = 0
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|PortNumber' = 3389
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication' = $(if ($Hardened) { 1 } else { 0 })
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|SecurityLayer' = $(if ($Hardened) { 2 } else { 1 })
        'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters|ServiceDll' = 'C:\Windows\System32\termsrv.dll'
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa|LmCompatibilityLevel' = 5
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|OneDriveSyncHelper' = 'cmd.exe /c echo x'
    }
    if ($Hardened) { $global:Reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient|EnableMulticast'] = 0 }
    else { $global:Reg['IFEO\sethc.exe|Debugger'] = 'cmd.exe /c echo x' }
    $users = @(@{ Name = 'Administrator'; Enabled = (-not $Hardened); Sid = 'S-1-5-21-1-2-3-500' }, @{ Name = 'Guest'; Enabled = $false; Sid = 'S-1-5-21-1-2-3-501' },
               @{ Name = 'jmoney'; Enabled = $true; Sid = 'S-1-5-21-1-2-3-1002' }, @{ Name = 'ops-9k2'; Enabled = $true; Sid = 'S-1-5-21-1-2-3-1010' },
               @{ Name = 'plinktern'; Enabled = (-not $Hardened); Sid = 'S-1-5-21-1-2-3-1001' })
    $groups = @(@{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; Members = @('Administrator', 'ops-9k2') + $(if ($Hardened) { @() } else { @('plinktern') }) },
                @{ Name = 'Remote Desktop Users'; Sid = 'S-1-5-32-555'; Members = @('jmoney', 'ops-9k2') })
    $pw = @(); if (-not $Hardened) { $pw = @('plinktern|H00ves0nTheM00n', 'jmoney|H00ves0nTheM00n') }
    $global:Box = @{
        Files = @('C:\Windows\System32\termsrv.dll'); SigStatus = 'Valid'; SigSubject = 'CN=Microsoft Windows, O=Microsoft Corporation'
        TermState = 'Running'; Listen3389 = $true
        Services = @(@{ Name = 'Jenkins'; DisplayName = 'Jenkins'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem' },
                     @{ Name = 'Spooler'; DisplayName = 'Print Spooler'; State = $(if ($Hardened) { 'Stopped' } else { 'Running' }); StartMode = 'Auto'; StartName = 'LocalSystem' },
                     @{ Name = 'TermService'; DisplayName = 'Remote Desktop Services'; State = 'Running'; StartMode = 'Manual'; StartName = 'NetworkService' })
        Defender = $(if ($Hardened) { @{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 1 } } else { @{ AMServiceEnabled = $true; RealTimeProtectionEnabled = $false; AntivirusSignatureAge = 30 } })
        Exclusions = $(if ($Hardened) { @() } else { @('C:\ProgramData\Updates') })
        Smb1 = $false; Shares = @(@{ Name = 'C$'; Special = $true }) + $(if ($Hardened) { @() } else { @(@{ Name = 'ShipData'; Special = $false }) })
        IfeoKeys = $(if ($Hardened) { @() } else { @('sethc.exe') }); WmiConsumers = @('SCM Event Log Consumer') + $(if ($Hardened) { @() } else { @('SysHealthConsumer') })
        Hosts = @('# Copyright (c) Microsoft', '127.0.0.1 localhost') + $(if ($Hardened) { @() } else { @('127.0.0.1 av-updates.example') })
        Users = $users; Groups = $groups; Secedit = $inf; Passwords = $pw
        FwProfiles = @('Domain', 'Private', 'Public' | ForEach-Object { @{ Name = $_; Enabled = 'True'; DefaultInboundAction = $(if ($Hardened) { 'Block' } else { 'Allow' }); DefaultOutboundAction = 'Allow'; LogBlocked = $(if ($Hardened) { 'True' } else { 'False' }) } })
        NetCategories = @('Public'); FwRules = $rules
    }
}

# ------------------------------------------------------------------ run collectors + judges on both boxes
function Get-AllFindings {
    $acct = Get-AccountFacts; $sec = Get-SeceditFacts
    $all = @()
    $all += Get-AccountFindings -Facts $acct -Allowed @('jmoney', 'ops-9k2') -NewAdmin 'ops-9k2'
    $all += Get-LockoutFinding $sec
    $all += Get-LogonRightFindings -Facts $acct -Secedit $sec -User jmoney -Allowed @('jmoney', 'ops-9k2')
    $all += Test-DefaultPasswords -Users $acct.Users -Passwords @('H00ves0nTheM00n') -Secedit $sec
    $all += Get-FirewallFindings -Facts (Get-FirewallFacts)
    $all += Get-RdpFindings (Get-RdpFacts)
    $all += Get-ServiceFindings (Get-ServiceFacts)
    $all += Get-DefenderFindings (Get-DefenderFacts)
    $all += Get-WindowsSettingFindings (Get-WindowsSettingFacts)
    $all += Get-ReviewFindings (Get-ReviewFacts)
    $all
}

Write-Host 'Fake HARDENED box: collectors + judges' -ForegroundColor Cyan
Set-FakeBox -Hardened $true
$good = @(Get-AllFindings)
$notGreen = @($good | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARN' })
Assert-Equal ($notGreen | ForEach-Object { "$($_.Name): $($_.Detail)" } | Out-String).Trim() '' 'hardened box: no FAIL and no WARN anywhere'
Assert-True ($good.Count -ge 35) "hardened box: $($good.Count) findings were produced"
Assert-Equal (@($good | Where-Object { $_.Name -eq 'Packet default passwords' })[0].Status) 'PASS' 'hardened box: default passwords are dead'

Write-Host 'Fake SLOPPY box: collectors + judges' -ForegroundColor Cyan
Set-FakeBox -Hardened $false
$bad = @(Get-AllFindings)
$fails = @($bad | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object { $_.Name })
foreach ($expect in 'Enabled accounts', 'Built-in Administrator', 'plinktern', 'No lockout policy', 'Inbound default', 'Other inbound allow rules', 'Defender', 'Defender exclusions') {
    Assert-True ($fails -contains $expect) "sloppy box: '$expect' is a FAIL"
}
Assert-Equal (@($bad | Where-Object { $_.Name -eq 'Packet default passwords' })[0].Status) 'SKIP' 'sloppy box: lockout is set, so passwords are NOT guessed (SKIP)'
foreach ($expect in 'hosts file', 'IFEO debuggers', 'WMI subscriptions', 'SMB shares', 'RDP NLA', 'Spooler service', 'Firewall logging') {
    Assert-True (@($bad | Where-Object { $_.Name -eq $expect -and $_.Status -eq 'WARN' }).Count -eq 1) "sloppy box: '$expect' is a WARN"
}
$global:Box.Secedit = @('[System Access]', 'LockoutBadCount = 0', '[Privilege Rights]', 'SeNetworkLogonRight = *S-1-1-0', 'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555')
$acct = Get-AccountFacts; $sec = Get-SeceditFacts
Assert-Equal (Test-DefaultPasswords -Users $acct.Users -Passwords @('H00ves0nTheM00n') -Secedit $sec).Status 'FAIL' 'sloppy box, no lockout: accounts that still accept the packet password -> FAIL'
Assert-Equal (Test-DefaultPasswords -Users $acct.Users -Passwords @('H00ves0nTheM00n') -Secedit @{}).Status 'SKIP' 'lockout policy unreadable -> passwords are NOT guessed (SKIP)'

Write-Host 'Collector output shapes' -ForegroundColor Cyan
Set-FakeBox -Hardened $true
$fw = Get-FirewallFacts
Assert-Equal (@($fw.Profiles).Count) 3 'firewall facts: three profiles'
Assert-Equal $fw.ActiveProfiles[0] 'Public' 'firewall facts: active profile'
Assert-Equal (@($fw.Rules).Count) 3 'firewall facts: three enabled inbound rules'
Assert-Equal @($fw.Rules | Where-Object { $_.DisplayName -eq 'Remote Desktop (TCP-In)' })[0].LocalPort[0] '3389' 'firewall facts: the port filter is joined to its rule'
Assert-Equal (@($fw.OutRules).Count) 0 'firewall facts: outbound rules are only read when outbound is Block'
$global:Box.NetCategories = @('DomainAuthenticated')
Assert-Equal (Get-FirewallFacts).ActiveProfiles[0] 'Domain' 'firewall facts: DomainAuthenticated is mapped to Domain'
Assert-Equal (Get-RdpFacts).ServiceDll 'C:\Windows\System32\termsrv.dll' 'rdp facts: service DLL'
$global:Reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fDisableClip'] = 1
Assert-Equal (Get-RdpFacts).DisableClip 1 'rdp facts: a clipboard POLICY overrides the normal setting'
Assert-Equal @((Get-ReviewFacts).RunEntries)[0] 'OneDriveSyncHelper' 'review facts: Run values are listed'

Write-TestSummary
