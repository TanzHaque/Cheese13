# JudgeAccounts.ps1 - phase 2: accounts, groups, and who may log on through Remote Desktop. Reads facts, returns findings.
# The plan's decisions are written into the rules here:
#   - accounts are DISABLED, never deleted        - a new admin exists and is CONFIRMED before the old admins are touched
#   - jmoney is never disabled; its password is rotated ONCE   - no account lockout policy
# Windows PowerShell 5.1, plain ASCII.

$script:WellKnownSids = @{
    'S-1-1-0' = 'Everyone'; 'S-1-5-11' = 'Authenticated Users'; 'S-1-5-2' = 'Network'
    'S-1-5-113' = 'Local account'; 'S-1-5-114' = 'Local account and member of Administrators group'
}

function Get-AccountKind {
    # 'Administrator' (RID 500), 'Guest' (501), 'Builtin' (503 and 504) or 'Normal'. By SID, because the name can be changed.
    param($User)
    if ([string]$User.Sid -match '^S-1-5-21-[\d-]+-(\d+)$') {
        $rid = [int]$Matches[1]
        if ($rid -eq 500) { return 'Administrator' }
        if ($rid -eq 501) { return 'Guest' }
        if ($rid -eq 503 -or $rid -eq 504) { return 'Builtin' }
    }
    'Normal'
}

function Test-InGroupSid {
    # Is this account a member of the local group with this SID? (By SID, so a renamed group still works.)
    param($Groups, [string]$Name, [string]$Sid)
    $g = $Groups | Where-Object { $_.Sid -eq $Sid } | Select-Object -First 1
    [bool]($g -and ((Get-List $g.Members) -contains $Name))
}

function Get-PrivilegedGroupNames {
    # Every group the account belongs to except the harmless defaults (Users, Guests).
    param($Groups, [string]$Name)
    @($Groups | Where-Object {
        $_.Sid -ne $script:Plan.SidUsers -and $_.Sid -ne $script:Plan.SidGuests -and ((Get-List $_.Members) -contains $Name)
    } | ForEach-Object { $_.Name })
}

function Get-AccountDependents {
    # What runs as this account: services and scheduled tasks. Disabling the account stops them.
    param($Facts, [string]$Name)
    $dep = @()
    foreach ($s in (Get-List $Facts.Services)) {
        if ((Get-BareName ([string]$s.StartName)) -ieq $Name) { $dep += "service $($s.Name)" }
    }
    foreach ($t in (Get-List $Facts.Tasks)) {
        if ((Get-BareName ([string]$t.UserId)) -ieq $Name) { $dep += "task $($t.Path)$($t.Name)" }
    }
    $dep
}

function Get-AccountFindings {
    param($Facts, $Settings)
    if (-not $Facts.Accounts) { return @(New-Finding 2 'Accounts' 'WARN' 'Accounts could not be read' 'The accounts collector failed; see the Recon phase for the error.') }
    $users = Get-List $Facts.Accounts.Users
    $groups = Get-List $Facts.Accounts.Groups
    $out = @()
    $out += Get-NewAdminFindings $Settings $users $groups
    $out += Get-ScoringUserFindings $Settings $users $groups
    $out += Get-OtherAccountFindings $Facts $Settings $users $groups
    $out += Get-RightsFindings $Facts $Settings $users $groups
    $out
}

# ---------------------------------------------------------------- the new admin
function Get-NewAdminFindings {
    param($Settings, $Users, $Groups)
    $name = [string]$Settings.NewAdmin
    if (-not $name) {
        return @(New-Finding 2 'New admin' 'BAD' 'No new admin account yet' 'The packet password of plinktern is public: the Red Team has the packet. Create your own administrator with a passphrase from Bitwarden that you can TYPE on the Console. Then log in with it in a SECOND RDP session before going on.' (New-FixRef 'Request-CreateAdmin') -Batch $false)
    }
    $u = $Users | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
    if (-not $u) {
        return @(New-Finding 2 'New admin' 'BAD' "New admin '$name' does not exist" "The tool remembers the name '$name' but this box has no such account (a revert does that). Create it again." (New-FixRef 'Request-CreateAdmin' @{ Name = $name }) -Batch $false)
    }
    $problems = @()
    if (-not $u.Enabled) { $problems += 'it is disabled' }
    if (-not (Test-InGroupSid $Groups $u.Name $script:Plan.SidAdministrators)) { $problems += 'it is not an Administrator' }
    if (-not (Test-InGroupSid $Groups $u.Name $script:Plan.SidRdpUsers)) { $problems += 'it is not in Remote Desktop Users' }
    if ($problems.Count -gt 0) {
        return @(New-Finding 2 'New admin' 'BAD' "New admin '$($u.Name)' is not usable" "Problems: $($problems -join '; '). Repair enables it and puts it in Administrators and Remote Desktop Users." (New-FixRef 'New-RepairAdminAction' @{ Name = $u.Name }))
    }
    if (-not $Settings.NewAdminConfirmed) {
        return @(New-Finding 2 'New admin' 'WARN' "New admin '$($u.Name)' not confirmed yet" "Exists, enabled, administrator. Last logon: $($u.LastLogon). Open a SECOND RDP session as this account and log in. Only then press Confirm: the old admins are disabled only after that, so you cannot lock yourself out." (New-FixRef 'New-ConfirmAdminAction' @{ Name = $u.Name }) -Batch $false)
    }
    @(New-Finding 2 'New admin' 'OK' "New admin '$($u.Name)'" "Exists, enabled, administrator, confirmed. Last logon: $($u.LastLogon).")
}

# ---------------------------------------------------------------- jmoney, the scoring user
function Get-ScoringUserFindings {
    param($Settings, $Users, $Groups)
    $name = $script:Plan.ScoringUser
    $u = $Users | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
    if (-not $u) {
        return @(New-Finding 2 'jmoney' 'BAD' "Scoring user $name does not exist" 'The scoring engine logs in as this user, so the RDP and Jenkins checks fail. The tool cannot create it: ask staff or use NEIGH.')
    }
    $out = @()
    if (-not $u.Enabled) {
        $out += New-Finding 2 'jmoney' 'BAD' "$name is disabled" 'The scoring login fails while this account is disabled. Never disable it. Enabling it again is safe.' (New-FixRef 'New-EnableUserAction' @{ Name = $u.Name })
    }
    $isAdmin = Test-InGroupSid $Groups $u.Name $script:Plan.SidAdministrators
    $inRdp = Test-InGroupSid $Groups $u.Name $script:Plan.SidRdpUsers
    if (-not $isAdmin -and -not $inRdp) {
        $out += New-Finding 2 'jmoney' 'BAD' "$name may not use Remote Desktop" 'The scoring RDP login needs this account in Remote Desktop Users (or Administrators).' (New-FixRef 'New-AddToGroupAction' @{ Name = $u.Name; GroupSid = $script:Plan.SidRdpUsers })
    }
    if ($isAdmin) {
        $out += New-Finding 2 'jmoney' 'WARN' "$name is an Administrator" "Whoever gets this password owns the box. Demoting adds it to Remote Desktop Users first, then removes it from Administrators. Check NEIGH right afterwards." (New-FixRef 'New-DemoteJmoneyAction') -Batch $false
    }
    $rot = [int]$Settings.JmoneyRotations
    if ($rot -eq 0) {
        $out += New-Finding 2 'jmoney' 'BAD' "$name still has the packet password" 'The Red Team has the packet. Rotate it ONCE with a long random password from Bitwarden, then update every assembly entry in NEIGH -> Users and press Save. Wait for two green checks.' (New-FixRef 'Request-RotateJmoney') -Batch $false
    } else {
        $out += New-Finding 2 'jmoney' 'INFO' "$name password rotated $rot time(s) by this tool" 'Check that NEIGH -> Users has the new password for EVERY assembly entry and that two scoring cycles are green. A further rotation only if you must (it asks you to type a confirmation).' (New-FixRef 'Request-RotateJmoney') -Batch $false
    }
    $out
}

# ---------------------------------------------------------------- everybody else
function New-RetireFinding {
    # One row for an account that should be disabled (or, when already disabled, cleaned out of its groups).
    param($Facts, $Settings, $Groups, $User, [string]$Label)
    $name = [string]$User.Name
    $priv = Get-PrivilegedGroupNames $Groups $name
    $deps = Get-AccountDependents $Facts $name
    $isAdmin = Test-InGroupSid $Groups $name $script:Plan.SidAdministrators
    $inRdp = Test-InGroupSid $Groups $name $script:Plan.SidRdpUsers

    $what = $(if ($User.Enabled) { 'Enabled' } else { 'Disabled' })
    $text = "$what local account$Label. Groups: $(if ($priv.Count) { $priv -join ', ' } else { 'none besides Users' }). Last logon: $($User.LastLogon)."
    if ($User.Description) { $text += " Description: $($User.Description)." }
    if ($deps.Count -gt 0) { $text += " Runs as this account: $($deps -join ', ')." }
    $text += ' The plan: new password first, remove from groups, then disable. Never deleted.'

    $blocked = ''
    $svcDeps = @($deps | Where-Object { $_ -like 'service *' })
    if (($isAdmin -or (Get-AccountKind $User) -eq 'Administrator' -or $name -ieq $script:Plan.OriginalAdmin) -and -not $Settings.NewAdminConfirmed) {
        $blocked = 'Create the new admin and confirm it works (a second RDP session) first. Otherwise you could disable every admin account.'
    } elseif ($name -ieq $script:Plan.OriginalAdmin -and $svcDeps.Count -gt 0) {
        $blocked = "A service runs as this account ($($svcDeps -join ', ')). Disabling it would stop that service. Change the service account first, or add the name to ExtraKeep in settings.json."
    }
    $sev = $(if ($isAdmin -or $inRdp) { 'BAD' } else { 'WARN' })
    if (-not $User.Enabled) { $sev = 'WARN' }
    $title = $(if ($User.Enabled) { $name } else { "$name (already disabled)" })
    New-Finding 2 'Accounts' $sev $title $text (New-FixRef 'Request-RetireAccount' @{ Name = $name }) $blocked
}

function Get-OtherAccountFindings {
    param($Facts, $Settings, $Users, $Groups)
    $out = @()
    $newAdmin = [string]$Settings.NewAdmin
    $extra = @(Get-List $Settings.ExtraKeep | ForEach-Object { [string]$_ })
    $scoring = $script:Plan.ScoringUser
    $original = $script:Plan.OriginalAdmin

    # which accounts are left alone, and why
    $rows = @()
    foreach ($u in $Users) {
        $kind = Get-AccountKind $u
        if ($kind -eq 'Builtin') { continue }
        if ($u.Name -ieq $scoring) { continue }
        if ($newAdmin -and $u.Name -ieq $newAdmin) { continue }
        if ($kind -eq 'Guest') { continue }
        $rows += $u
    }
    $order = @($rows | Sort-Object { if ((Get-AccountKind $_) -eq 'Administrator') { 0 } elseif ($_.Name -ieq $original) { 1 } else { 2 } }, Name)

    $quiet = 0
    foreach ($u in $order) {
        $name = [string]$u.Name
        $kind = Get-AccountKind $u
        $svcDeps = @(Get-AccountDependents $Facts $name | Where-Object { $_ -like 'service *' })
        if ($extra -contains $name) {
            $out += New-Finding 2 'Accounts' 'INFO' "$name (kept)" 'Listed in ExtraKeep in settings.json: the tool leaves it alone.'
            continue
        }
        if ($svcDeps.Count -gt 0 -and $name -ine $original -and $kind -ne 'Administrator') {
            $out += New-Finding 2 'Accounts' 'INFO' "$name (service account)" "Kept: $($svcDeps -join ', ') runs as this account. Check that its password is not a packet default."
            continue
        }
        $priv = Get-PrivilegedGroupNames $Groups $name
        if (-not $u.Enabled -and $priv.Count -eq 0) { $quiet++; continue }
        $label = ''
        if ($kind -eq 'Administrator') { $label = ' (the built-in Administrator)' }
        if ($name -ieq $original) { $label = ' (the packet default admin)' }
        $out += New-RetireFinding $Facts $Settings $Groups $u $label
    }
    if ($quiet -gt 0) { $out += New-Finding 2 'Accounts' 'INFO' "$quiet other account(s) already disabled" 'Disabled and in no privileged group: nothing to do.' }

    $guest = $Users | Where-Object { (Get-AccountKind $_) -eq 'Guest' } | Select-Object -First 1
    if ($guest) {
        if ($guest.Enabled) { $out += New-Finding 2 'Accounts' 'BAD' "$($guest.Name) is enabled" 'The Guest account allows logins without a password on some setups. Disable it.' (New-FixRef 'New-DisableGuestAction') }
        else { $out += New-Finding 2 'Accounts' 'OK' "$($guest.Name) is disabled" 'Good.' }
    }
    $out
}

# ---------------------------------------------------------------- logon rights and the lockout policy
function Get-RightEntries {
    # "*S-1-5-32-544,*S-1-5-32-555,someone" -> list of  @{ Sid; Name }  (the name is looked up in the users and groups)
    param($Sec, [string]$Right, $Users, $Groups)
    $raw = [string]$Sec[$Right]
    $list = @()
    foreach ($item in ($raw -split ',')) {
        $e = $item.Trim().TrimStart('*')
        if (-not $e) { continue }
        $sid = ''; $name = ''
        if ($e -match '^S-1-') {
            $sid = $e
            $u = $Users | Where-Object { $_.Sid -eq $e } | Select-Object -First 1
            $g = $Groups | Where-Object { $_.Sid -eq $e } | Select-Object -First 1
            if ($u) { $name = $u.Name } elseif ($g) { $name = $g.Name } elseif ($script:WellKnownSids.ContainsKey($e)) { $name = $script:WellKnownSids[$e] } else { $name = $e }
        } else {
            $name = $e
            $u = $Users | Where-Object { $_.Name -ieq (Get-BareName $e) } | Select-Object -First 1
            $g = $Groups | Where-Object { $_.Name -ieq (Get-BareName $e) } | Select-Object -First 1
            if ($u) { $sid = $u.Sid } elseif ($g) { $sid = $g.Sid }
        }
        $list += [pscustomobject]@{ Sid = $sid; Name = $name }
    }
    $list
}

function Get-IdentitySids {
    # Every SID that a logon of this account carries: its own, its groups, and the well-known ones that apply to a local account.
    param($User, $Groups)
    $sids = @($User.Sid, 'S-1-1-0', 'S-1-5-11', 'S-1-5-113')
    foreach ($g in $Groups) { if ((Get-List $g.Members) -contains $User.Name) { $sids += $g.Sid } }
    if ($sids -contains $script:Plan.SidAdministrators) { $sids += 'S-1-5-114' }
    $sids
}

function Get-RightsFindings {
    param($Facts, $Settings, $Users, $Groups)
    $sec = $Facts.Secedit
    if (-not $sec -or $sec.Count -eq 0) {
        return @(New-Finding 2 'Rights' 'WARN' 'Local security policy could not be read' 'secedit /export gave nothing, so the logon rights and the lockout setting are unknown. Is this PowerShell elevated?')
    }
    $out = @()

    # no lockout policy: the Red Team could lock out jmoney with a few wrong passwords
    if ($sec.ContainsKey('LockoutBadCount')) {
        $threshold = [int]$sec['LockoutBadCount']
        if ($threshold -gt 0) {
            $out += New-Finding 2 'Rights' 'BAD' 'Account lockout is ON' "Accounts lock after $threshold bad passwords. That lets the Red Team lock out jmoney and fail the scoring login. The plan uses long random passwords and NO lockout." (New-FixRef 'New-LockoutOffAction')
        } else { $out += New-Finding 2 'Rights' 'OK' 'Account lockout is off' 'As the plan says.' }
    }

    $jm = $Users | Where-Object { $_.Name -ieq $script:Plan.ScoringUser } | Select-Object -First 1
    $newAdmin = [string]$Settings.NewAdmin
    $na = $Users | Where-Object { $newAdmin -and $_.Name -ieq $newAdmin } | Select-Object -First 1

    # quiet failures: jmoney (or a group he is in) is denied, or not allowed, the logons that RDP with NLA needs
    if ($jm) {
        $mine = Get-IdentitySids $jm $Groups
        foreach ($right in 'SeDenyRemoteInteractiveLogonRight', 'SeDenyNetworkLogonRight') {
            $hit = @(Get-RightEntries $sec $right $Users $Groups | Where-Object { $_.Sid -and ($mine -contains $_.Sid) })
            if ($hit.Count -gt 0) {
                $out += New-Finding 2 'Rights' 'BAD' "jmoney is DENIED: $right" "The policy denies this logon to: $(($hit | ForEach-Object { $_.Name }) -join ', '). The scoring RDP login fails while port 3389 still looks fine. Remove the entry in secpol.msc (Local Policies > User Rights Assignment) or from the GPO that sets it."
            }
        }
        $net = @(Get-RightEntries $sec 'SeNetworkLogonRight' $Users $Groups | Where-Object { $_.Sid -and ($mine -contains $_.Sid) })
        if ($sec.ContainsKey('SeNetworkLogonRight') -and $net.Count -eq 0) {
            $out += New-Finding 2 'Rights' 'BAD' 'jmoney may not log on over the network' 'NLA (the normal RDP login) needs the network logon right. jmoney and the groups he is in are missing from "Access this computer from the network".'
        }
    }

    # the plan: only the new admin and jmoney may log on through Remote Desktop Services
    $expected = @()
    if ($jm) { $expected += $jm.Sid }
    if ($na) { $expected += $na.Sid }
    foreach ($x in (Get-List $Settings.ExtraKeep)) {
        $xu = $Users | Where-Object { $_.Name -ieq [string]$x } | Select-Object -First 1
        if ($xu) { $expected += $xu.Sid }
    }
    $rdp = @(Get-RightEntries $sec 'SeRemoteInteractiveLogonRight' $Users $Groups)
    $others = @($rdp | Where-Object { $expected -notcontains $_.Sid })
    $jmOk = ($jm -and (@($rdp | Where-Object { (Get-IdentitySids $jm $Groups) -contains $_.Sid }).Count -gt 0))
    $blocked = ''
    if (-not $na -or -not $Settings.NewAdminConfirmed) { $blocked = 'Create and confirm the new admin first. Otherwise only jmoney could log on through Remote Desktop.' }
    if ($jm -and -not $jmOk) {
        $out += New-Finding 2 'Rights' 'BAD' 'jmoney is not allowed to log on through Remote Desktop' 'The right "Allow log on through Remote Desktop Services" has neither jmoney nor a group he belongs to. The scoring RDP login fails.' (New-FixRef 'Request-RestrictRdp') $blocked -Batch $false
    } elseif ($others.Count -gt 0) {
        $who = ($others | ForEach-Object { $_.Name }) -join ', '
        $out += New-Finding 2 'Rights' 'WARN' 'Remote Desktop logon is open to more than the plan allows' "Allowed now: $who. Every member of those groups can log in over RDP. The plan: only the new admin and jmoney. The old setting is saved first and Panic.ps1 can put it back." (New-FixRef 'Request-RestrictRdp') $blocked -Batch $false
    } else {
        $out += New-Finding 2 'Rights' 'OK' 'Remote Desktop logon right' 'Limited to the new admin and jmoney (and ExtraKeep).'
    }
    $out
}
