# VerifyJudgeAccounts.ps1 - Verify-Hardening "judges" for accounts, groups and logon rights.
# PURE functions: they get plain facts (collected by VerifyFacts.ps1) and return result objects
# (Name, Status, Detail). They touch nothing on the box, so Tests\Test-VerifyJudge.ps1 can run them anywhere.
#
# Shape of the facts these functions expect:
#   $Facts.Users  = array of  @{ Name; Enabled (bool); Sid }                 one per local user
#   $Facts.Groups = array of  @{ Name; Sid; Members (array of names) }       local groups
#   $Secedit      = hashtable from ConvertFrom-Secedit  (setting name -> value text)
#
# PASS = the plan is satisfied   FAIL = a plan decision is violated or scoring is at risk
# WARN = leftover / worth a look   INFO = a fact   SKIP = could not be checked

function Get-BareName {
    # 'PC\jmoney' -> 'jmoney'
    param([string]$Name)
    $Name -replace '^.*\\', ''
}

function Get-Overlap {
    # items that appear in both lists (case-insensitive)
    param([string[]]$A, [string[]]$B)
    @(@($A) | Where-Object { @($B) -contains $_ })
}

function Get-GroupMemberNames {
    # bare member names of one local group ('Administrators'), from the facts
    param($Facts, [string]$Group)
    $g = @($Facts.Groups) | Where-Object { $_.Name -eq $Group } | Select-Object -First 1
    if (-not $g) { return @() }
    @(@($g.Members) | ForEach-Object { Get-BareName $_ } | Where-Object { $_ })
}

# ---------------------------------------------------------------- secedit (user rights + lockout)
function ConvertFrom-Secedit {
    # Turns the text file written by  secedit /export /cfg file.inf  into  name -> value.
    param([string[]]$Lines)
    $h = @{}
    foreach ($l in $Lines) {
        if ($l -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$') { $h[$Matches[1]] = $Matches[2] }
    }
    $h
}

function Get-RightEntries {
    # Who holds a user right, e.g. SeRemoteInteractiveLogonRight -> '*S-1-5-32-544', '*S-1-5-32-555'.
    param($Secedit, [string]$Right)
    if (-not $Secedit.ContainsKey($Right)) { return @() }
    @($Secedit[$Right] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } |
        ForEach-Object { if ($_ -match '^S-1-') { "*$_" } else { $_ } })
}

function Get-TokenIds {
    # Everything a logon token of this local user carries that a user-right entry could name:
    # the user's own SID + name, Everyone, Authenticated Users, Users, "Local account", and every local group
    # the user belongs to (plus "Local account and member of Administrators group" for admins).
    param($Account, $Groups)
    $ids = New-Object System.Collections.ArrayList
    foreach ($x in @("*$($Account.Sid)", $Account.Name, '*S-1-1-0', '*S-1-5-11', '*S-1-5-32-545', '*S-1-5-113')) { [void]$ids.Add($x) }
    foreach ($g in @($Groups)) {
        $members = @(@($g.Members) | ForEach-Object { Get-BareName $_ })
        if ($members -contains $Account.Name) {
            [void]$ids.Add("*$($g.Sid)"); [void]$ids.Add($g.Name)
            if ($g.Sid -eq 'S-1-5-32-544') { [void]$ids.Add('*S-1-5-114') }
        }
    }
    $ids.ToArray()
}

function Get-LogonRightFindings {
    # The Windows "user rights" that decide whether jmoney's RDP (NLA) login is accepted, and who else can RDP in.
    # A STIG/GPO import can quietly break these (for example "Deny access to this computer from the network").
    param($Facts, $Secedit, [string]$User = 'jmoney', [string[]]$Allowed)
    $out = New-Object System.Collections.ArrayList
    $allowRdp = Get-RightEntries $Secedit 'SeRemoteInteractiveLogonRight'
    $denyRdp  = Get-RightEntries $Secedit 'SeDenyRemoteInteractiveLogonRight'
    $allowNet = Get-RightEntries $Secedit 'SeNetworkLogonRight'
    $denyNet  = Get-RightEntries $Secedit 'SeDenyNetworkLogonRight'
    $users = @($Facts.Users)

    $u = $users | Where-Object { $_.Name -eq $User } | Select-Object -First 1
    if (-not $u) {
        [void]$out.Add((New-Result 'Logon rights (jmoney)' 'FAIL' "$User does not exist"))
    } else {
        $tok = Get-TokenIds $u $Facts.Groups
        $problems = @()
        if (-not (Get-Overlap $allowRdp $tok)) { $problems += "no 'Allow log on through Remote Desktop Services' right" }
        $d = Get-Overlap $denyRdp $tok;  if ($d) { $problems += "RDP logon is DENIED by: $($d -join ', ')" }
        if (-not (Get-Overlap $allowNet $tok)) { $problems += "no 'Access this computer from the network' right (NLA needs it)" }
        $d = Get-Overlap $denyNet $tok;  if ($d) { $problems += "network logon is DENIED by: $($d -join ', ') (NLA would be refused)" }
        if ($problems.Count -gt 0) { [void]$out.Add((New-Result 'Logon rights (jmoney)' 'FAIL' ($problems -join '; '))) }
        else { [void]$out.Add((New-Result 'Logon rights (jmoney)' 'PASS' "$User may log on through Remote Desktop and the network, and nothing denies it")) }
    }

    # everyone who can RDP in right now = enabled accounts that hold the allow right and are not denied
    $can = @()
    foreach ($acct in ($users | Where-Object { $_.Enabled })) {
        $t = Get-TokenIds $acct $Facts.Groups
        if ((Get-Overlap $allowRdp $t) -and -not (Get-Overlap $denyRdp $t)) { $can += $acct.Name }
    }
    $extra = @($can | Where-Object { @($Allowed) -notcontains $_ })
    if ($extra.Count -gt 0) { [void]$out.Add((New-Result 'RDP-capable accounts' 'FAIL' "can log in over RDP but are not on the allowlist: $(Format-NameList $extra)")) }
    else { [void]$out.Add((New-Result 'RDP-capable accounts' 'PASS' "only: $(Format-NameList $can)")) }
    $out.ToArray()
}

function Get-LockoutFinding {
    # Plan decision: NO account lockout (the Red Team could lock jmoney out).  secedit: LockoutBadCount = 0 means never.
    param($Secedit)
    if (-not $Secedit.ContainsKey('LockoutBadCount')) { return New-Result 'No lockout policy' 'SKIP' 'LockoutBadCount not found in the secedit export' }
    $n = [int]$Secedit['LockoutBadCount']
    if ($n -eq 0) { return New-Result 'No lockout policy' 'PASS' 'lockout threshold is 0 (accounts never lock)' }
    New-Result 'No lockout policy' 'FAIL' "lockout threshold is $n - the Red Team can lock jmoney out (plan: no lockout)"
}

# ---------------------------------------------------------------- accounts and groups
function Get-AccountFindings {
    # $Allowed = every account that may stay enabled (jmoney, the new admin, discovered service accounts).
    param($Facts, [string[]]$Allowed, [string]$NewAdmin = '')
    $out  = New-Object System.Collections.ArrayList
    $users = @($Facts.Users)
    $Allowed = @($Allowed | Where-Object { $_ })

    # 1. only allowlisted accounts are enabled
    $enabled = @($users | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
    $extra = @($enabled | Where-Object { $Allowed -notcontains $_ })
    if ($extra.Count -gt 0) { [void]$out.Add((New-Result 'Enabled accounts' 'FAIL' "enabled but not on the allowlist: $(Format-NameList $extra)  (plan: new password, remove from groups, then disable)")) }
    else { [void]$out.Add((New-Result 'Enabled accounts' 'PASS' "only: $(Format-NameList $enabled)")) }

    # 2. named accounts the plan says to disable
    $admin = $users | Where-Object { $_.Sid -match '-500$' } | Select-Object -First 1
    if ($admin) {
        if ($admin.Enabled) { [void]$out.Add((New-Result 'Built-in Administrator' 'FAIL' "$($admin.Name) is still enabled (plan: random password, then disable)")) }
        else { [void]$out.Add((New-Result 'Built-in Administrator' 'PASS' "$($admin.Name) is disabled")) }
    }
    $guest = $users | Where-Object { $_.Sid -match '-501$' } | Select-Object -First 1
    if ($guest) {
        if ($guest.Enabled) { [void]$out.Add((New-Result 'Guest account' 'FAIL' 'Guest is enabled (plan: disable)')) }
        else { [void]$out.Add((New-Result 'Guest account' 'PASS' 'Guest is disabled')) }
    }
    $pt = $users | Where-Object { $_.Name -eq 'plinktern' } | Select-Object -First 1
    if ($pt) {
        if ($pt.Enabled) { [void]$out.Add((New-Result 'plinktern' 'FAIL' 'the packet default admin is still enabled (plan: disable once the new admin works)')) }
        else { [void]$out.Add((New-Result 'plinktern' 'PASS' 'disabled')) }
    } else { [void]$out.Add((New-Result 'plinktern' 'INFO' 'no such account on this box')) }

    # 3. the new admin works
    if ($NewAdmin) {
        $na = $users | Where-Object { $_.Name -eq $NewAdmin } | Select-Object -First 1
        $problems = @()
        if (-not $na) { $problems += 'does not exist' }
        else {
            if (-not $na.Enabled) { $problems += 'is disabled' }
            if ((Get-GroupMemberNames $Facts 'Administrators') -notcontains $NewAdmin) { $problems += 'is not in Administrators' }
        }
        if ($problems.Count -gt 0) { [void]$out.Add((New-Result 'New admin account' 'FAIL' "$NewAdmin $($problems -join ', ')")) }
        else { [void]$out.Add((New-Result 'New admin account' 'PASS' "$NewAdmin exists, is enabled and is an administrator")) }
    } else { [void]$out.Add((New-Result 'New admin account' 'SKIP' 'pass -NewAdmin <name> to check it')) }

    # 4. who is in the privileged groups
    $enabledSet = $enabled
    $admMembers = Get-GroupMemberNames $Facts 'Administrators'
    $badAdmins = @($admMembers | Where-Object { $enabledSet -contains $_ -and $Allowed -notcontains $_ })
    if ($badAdmins.Count -gt 0) { [void]$out.Add((New-Result 'Administrators group' 'FAIL' "enabled members that are not on the allowlist: $(Format-NameList $badAdmins)")) }
    else { [void]$out.Add((New-Result 'Administrators group' 'PASS' "enabled members: $(Format-NameList @($admMembers | Where-Object { $enabledSet -contains $_ }))")) }

    $badOther = @()
    foreach ($gName in 'Backup Operators', 'Power Users', 'Remote Management Users', 'Network Configuration Operators') {
        foreach ($m in (Get-GroupMemberNames $Facts $gName)) {
            if ($enabledSet -contains $m -and $Allowed -notcontains $m) { $badOther += "$m ($gName)" }
        }
    }
    if ($badOther.Count -gt 0) { [void]$out.Add((New-Result 'Other privileged groups' 'FAIL' "enabled, not on the allowlist: $(Format-NameList $badOther)")) }
    else { [void]$out.Add((New-Result 'Other privileged groups' 'PASS' 'no stray members')) }

    # 5. disabled accounts that kept their group memberships (harmless until someone re-enables them)
    $left = @()
    foreach ($gName in 'Administrators', 'Remote Desktop Users', 'Backup Operators', 'Power Users', 'Remote Management Users') {
        foreach ($m in (Get-GroupMemberNames $Facts $gName)) {
            $acct = $users | Where-Object { $_.Name -eq $m } | Select-Object -First 1
            if ($acct -and -not $acct.Enabled -and $acct.Sid -notmatch '-500$') { $left += "$m ($gName)" }
        }
    }
    if ($left.Count -gt 0) { [void]$out.Add((New-Result 'Disabled but still in groups' 'WARN' "plan says remove from groups before disabling: $(Format-NameList $left)")) }
    else { [void]$out.Add((New-Result 'Disabled but still in groups' 'PASS' 'none')) }

    # 6. a fact worth knowing
    if ((Get-GroupMemberNames $Facts 'Administrators') -contains 'jmoney') {
        [void]$out.Add((New-Result 'jmoney is an administrator' 'INFO' 'jmoney is in Administrators (allowed by the plan; the Red Team treats jmoney as in scope)'))
    }
    $out.ToArray()
}
