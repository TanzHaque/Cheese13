# VerifyFacts.ps1 - Verify-Hardening "collectors": they READ the box and return plain facts for the judges.
# Read-only. Windows only (they call Windows cmdlets), so they cannot run on Linux; the judges can.
# Needs an elevated PowerShell (secedit and the firewall store need administrator rights).

function Get-RegValue {
    # One registry value, or $null when the key or value is missing.
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Get-PolicyOrValue {
    # Group Policy wins over the normal setting, so look at the policy key first.
    param([string]$PolicyPath, [string]$BasePath, [string]$Name)
    $v = Get-RegValue $PolicyPath $Name
    if ($null -ne $v) { return $v }
    Get-RegValue $BasePath $Name
}

# ---------------------------------------------------------------- accounts, groups, rights
function Get-AccountFacts {
    $users = @(Get-LocalUser | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Enabled = [bool]$_.Enabled; Sid = $_.SID.Value } })
    $groups = @(Get-LocalGroup | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Sid = $_.SID.Value; Members = @(Get-LocalGroupNames $_.Name) } })
    [pscustomobject]@{ Users = $users; Groups = $groups }
}

function Get-SeceditFacts {
    # "secedit /export" writes the local security policy (user rights + lockout) to a text file. We read it, then delete it.
    $tmp = Join-Path $env:TEMP ('verify-secedit-' + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        & secedit.exe /export /cfg $tmp /areas USER_RIGHTS SECURITYPOLICY | Out-Null
        if (-not (Test-Path $tmp)) { return @{} }
        ConvertFrom-Secedit (Get-Content $tmp)
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

function Test-DefaultPasswords {
    # Does any ENABLED local account still accept a password from the packet? (Disabled accounts cannot log in anyway.)
    # Tries each password once per account. Skipped when a lockout threshold exists, so it can never lock anybody.
    param($Users, [string[]]$Passwords, $Secedit)
    if (-not $Secedit -or -not $Secedit.ContainsKey('LockoutBadCount')) {
        return New-Result 'Packet default passwords' 'SKIP' 'not tried: the lockout policy could not be read, and a wrong guess might lock an account'
    }
    $threshold = [int]$Secedit['LockoutBadCount']
    if ($threshold -ne 0) { return New-Result 'Packet default passwords' 'SKIP' "not tried: a lockout threshold of $threshold is set, wrong guesses could lock accounts" }
    $enabled = @($Users | Where-Object { $_.Enabled })
    $alive = @()
    foreach ($u in $enabled) {
        foreach ($p in $Passwords) {
            if (Test-LocalCredential -User $u.Name -Password $p) { $alive += $u.Name; break }
        }
    }
    if ($alive.Count -gt 0) { return New-Result 'Packet default passwords' 'FAIL' "still log in with a packet default password: $(Format-NameList $alive)  (the Red Team has the packet)" }
    New-Result 'Packet default passwords' 'PASS' "none of the $($enabled.Count) enabled account(s) accepts a packet default password"
}

# ---------------------------------------------------------------- firewall (ACTIVE store = local rules + GPO rules)
function Get-FirewallRuleFacts {
    param([string]$Direction)
    $rules = Get-NetFirewallRule -PolicyStore ActiveStore -Direction $Direction -Enabled True -ErrorAction SilentlyContinue
    foreach ($r in $rules) {
        $port = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Select-Object -First 1
        $addr = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | Select-Object -First 1
        $app  = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | Select-Object -First 1
        [pscustomobject]@{
            DisplayName   = [string]$r.DisplayName
            DisplayGroup  = [string]$r.DisplayGroup
            Group         = [string]$r.Group
            Profile       = [string]$r.Profile
            Action        = [string]$r.Action
            Protocol      = [string]$port.Protocol
            LocalPort     = @($port.LocalPort | ForEach-Object { [string]$_ })
            RemotePort    = @($port.RemotePort | ForEach-Object { [string]$_ })
            RemoteAddress = @($addr.RemoteAddress | ForEach-Object { [string]$_ })
            Program       = [string]$app.Program
        }
    }
}

function Get-FirewallFacts {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True')
            In = [string]$_.DefaultInboundAction; Out = [string]$_.DefaultOutboundAction
            LogBlocked = ([string]$_.LogBlocked -eq 'True')
        } })
    $active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' } else { [string]$_.NetworkCategory } } | Select-Object -Unique)
    if ($active.Count -eq 0) { $active = @('Public') }          # a network Windows cannot identify is treated as Public
    $outRules = @()
    if (@($profiles | Where-Object { $_.Out -eq 'Block' }).Count -gt 0) { $outRules = @(Get-FirewallRuleFacts 'Outbound') }
    [pscustomobject]@{ Profiles = $profiles; ActiveProfiles = $active; Rules = @(Get-FirewallRuleFacts 'Inbound'); OutRules = $outRules }
}

# ---------------------------------------------------------------- RDP, services, Defender, settings, leftovers
function Get-RdpFacts {
    $ts   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $wd   = "$ts\WinStations\RDP-Tcp"
    $pol  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $dll  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters' 'ServiceDll'
    $dllPath = ''
    if ($dll) { $dllPath = [Environment]::ExpandEnvironmentVariables([string]$dll) }
    $sig = $null
    if ($dllPath -and (Test-Path $dllPath)) { $sig = Get-AuthenticodeSignature $dllPath }
    $clip = Get-PolicyOrValue $pol $wd 'fDisableClip'
    $svc  = Get-Service TermService -ErrorAction SilentlyContinue
    [pscustomobject]@{
        DenyConnections  = Get-PolicyOrValue $pol $ts 'fDenyTSConnections'
        Port             = Get-RegValue $wd 'PortNumber'
        Nla              = Get-PolicyOrValue $pol $wd 'UserAuthentication'
        SecurityLayer    = Get-PolicyOrValue $pol $wd 'SecurityLayer'
        DisableClip      = $(if ($clip -eq 1) { 1 } else { 0 })
        ServiceDll       = $dllPath
        SigStatus        = $(if ($sig) { [string]$sig.Status } else { 'NotFound' })
        SigSubject       = $(if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' })
        TermServiceState = $(if ($svc) { [string]$svc.Status } else { 'Missing' })
        Listening        = [bool](Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue)
    }
}

function Get-ServiceFacts {
    $names = @('TermService', 'Spooler', 'RemoteRegistry')
    # Jenkins is found by its service name OR by its program path, because the lab/competition may name the service differently
    $svcs = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -like '*jenkins*' -or $_.PathName -like '*jenkins*' -or $names -contains $_.Name } | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode; StartName = $_.StartName; PathName = $_.PathName } })
    [pscustomobject]@{ Services = $svcs }
}

function Get-DefenderFacts {
    try {
        $st   = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $ex   = @(@($pref.ExclusionPath) + @($pref.ExclusionExtension) + @($pref.ExclusionProcess) | Where-Object { $_ })
        [pscustomobject]@{
            Available = $true; ServiceEnabled = [bool]$st.AMServiceEnabled; RealTime = [bool]$st.RealTimeProtectionEnabled
            SignatureAgeDays = [int]$st.AntivirusSignatureAge; Exclusions = $ex
        }
    } catch {
        [pscustomobject]@{ Available = $false; ServiceEnabled = $false; RealTime = $false; SignatureAgeDays = 999; Exclusions = @() }
    }
}

function Get-WindowsSettingFacts {
    $smb1 = $null
    try { $smb1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    [pscustomobject]@{
        Smb1               = $smb1
        WDigest            = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
        Llmnr              = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
        LmCompat           = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
        AutoLogon          = Get-RegValue $wl 'AutoAdminLogon'
        DefaultPasswordSet = [bool](Get-RegValue $wl 'DefaultPassword')
    }
}

function Get-ReviewFacts {
    # Things that should normally be empty; the judge only lists them for a human to look at.
    $hosts = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
        Where-Object { $_ -and $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$' })
    $ifeoRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $ifeo = @(Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue | Where-Object { Get-RegValue $_.PSPath 'Debugger' } | ForEach-Object { $_.PSChildName })
    $wmi = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike 'SCM Event Log*' } | ForEach-Object { $_.Name })
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special } | ForEach-Object { $_.Name })
    $run = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p) { foreach ($prop in $p.PSObject.Properties) { if ($prop.Name -notlike 'PS*') { $run += $prop.Name } } }
    }
    [pscustomobject]@{ HostsExtra = $hosts; IfeoDebuggers = $ifeo; WmiSubscriptions = $wmi; Shares = $shares; RunEntries = $run }
}
