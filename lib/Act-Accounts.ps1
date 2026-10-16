# Act-Accounts.ps1 - phase 2 actions: create the new admin, retire old accounts, rotate jmoney once, limit the RDP logon right.
# Every function here only BUILDS an action (a description of one change). Invoke-Change is the only thing that runs it.
# Functions named Request-... ask you questions first (names, passwords through hidden prompts) and may return $null = cancelled.
#
# Rules of the plan that are enforced here in code, not left to the buttons:
#   - nothing is ever deleted: there is no Remove-LocalUser in this tool
#   - jmoney is never disabled and never taken out of Remote Desktop Users (Assert-NotScoringUser)
#   - passwords come from your laptop through hidden prompts; they live in memory only and never reach the log or the journal
#   - an administrator account is only retired after the new admin was confirmed (second RDP session)
# Windows PowerShell 5.1, plain ASCII.

# ---------------------------------------------------------------- small helpers
function ConvertTo-HpSecure {
    # Plain text -> SecureString, for the cmdlets that want one. The text is never logged or saved.
    param([string]$Text)
    $s = New-Object System.Security.SecureString
    foreach ($c in $Text.ToCharArray()) { $s.AppendChar($c) }
    $s.MakeReadOnly()
    $s
}

function Get-GroupNameBySid {
    # The local group's name for a well-known SID (the name differs between Windows languages).
    param([string]$Sid)
    [string](Get-LocalGroup -SID $Sid -ErrorAction Stop).Name
}

function Get-AccountGroups {
    # The local groups this account belongs to, as  @{ Name; Sid }.  net localgroup is used because Get-LocalGroupMember
    # fails when a group holds a member it cannot resolve.
    param([string]$Name)
    $mine = @()
    foreach ($g in @(Get-LocalGroup)) {
        $members = @(Get-LocalGroupMembers $g.Name | ForEach-Object { Get-BareName $_ })
        if ($members -contains $Name) { $mine += [pscustomobject]@{ Name = [string]$g.Name; Sid = [string]$g.SID.Value } }
    }
    $mine
}

function Assert-NotScoringUser {
    # The plan: jmoney is never disabled, never deleted, never taken out of Remote Desktop Users.
    param([string]$Name, [string]$What)
    if ($Name -ieq $script:Plan.ScoringUser) {
        throw "Refused: '$What' would stop the scoring user $($script:Plan.ScoringUser) from working. This tool never does that."
    }
}

function Test-HasAdminLeft {
    # Would at least one OTHER enabled administrator remain if this account were disabled? (Used as a last safety net.)
    param([string]$Name)
    $adminGroup = Get-GroupNameBySid $script:Plan.SidAdministrators
    $others = @(Get-LocalGroupMembers $adminGroup | ForEach-Object { Get-BareName $_ } | Where-Object { $_ -ine $Name })
    foreach ($o in $others) {
        $u = Get-LocalUser -Name $o -ErrorAction SilentlyContinue
        if ($u -and $u.Enabled) { return $true }
    }
    $false
}

# ---------------------------------------------------------------- the new admin
function Request-CreateAdmin {
    # Asks for a name and a passphrase (twice), then returns the action. Nothing changes until Invoke-Change runs it.
    param([string]$Default = '')
    $name = Read-HpText 'Name for the new admin account (up to 20 characters, nothing obvious)' $Default
    if (-not $name) { return $null }
    $name = $name.Trim()
    if ($name.Length -lt 1 -or $name.Length -gt 20 -or $name -notmatch '^[A-Za-z0-9._-]+$') {
        Show-HpNotice 'Use 1 to 20 characters: letters, digits and . _ - only.' 'New admin name'
        return $null
    }
    if ($name -ieq $script:Plan.ScoringUser) { Show-HpNotice 'That is the scoring user. Choose another name.' 'New admin name'; return $null }
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
        $adopt = & $script:Hp.Ask "Account '$name' exists" "An account called '$name' already exists.`n`nUse it as the new admin? It will be enabled and put in Administrators and Remote Desktop Users. Its password is NOT changed." ''
        if ($adopt) { return New-RepairAdminAction -Name $name -Adopt }
        return $null
    }
    $p1 = Read-HpSecret "Passphrase for '$name' (from Bitwarden; you must be able to TYPE it on the Console)"
    if (-not $p1) { return $null }
    $p2 = Read-HpSecret 'Type the same passphrase again'
    if ($p1 -cne $p2) { Show-HpNotice 'The two passphrases are different. Nothing was created.' 'New admin'; return $null }
    Set-HpSecret "pw:$name" $p1
    New-CreateAdminAction -Name $name -Warnings @(Test-PassphraseShape $p1)
}

function New-CreateAdminAction {
    param([string]$Name, [string[]]$Warnings = @())
    $will = @("Create the local account '$Name' with the passphrase you typed (the passphrase is not saved anywhere)",
              'The password never expires',
              'Add it to Administrators and to Remote Desktop Users',
              "Remember '$Name' in the tool settings (you still have to CONFIRM it by logging in)")
    foreach ($w in $Warnings) { $will += "WARNING about the passphrase: $w" }
    New-Action -Id "user.create:$Name" -Title "Create the new admin account '$Name'" -Risk 'Medium' -Will $will -Data @{ Name = $Name } `
        -Capture { param($d) @{ Existed = [bool](Get-LocalUser -Name $d.Name -ErrorAction SilentlyContinue); OldAdmin = [string](Get-HpSetting 'NewAdmin') } } `
        -Apply {
            param($d, $before)
            $null = $before
            $pw = Get-HpSecret "pw:$($d.Name)"
            if (-not $pw) { throw 'The passphrase is no longer in memory (the tool was restarted?). Start the action again.' }
            New-LocalUser -Name $d.Name -Password (ConvertTo-HpSecure $pw) -PasswordNeverExpires -AccountNeverExpires | Out-Null
            Add-LocalGroupMember -Group (Get-GroupNameBySid $script:Plan.SidAdministrators) -Member $d.Name
            Add-LocalGroupMember -Group (Get-GroupNameBySid $script:Plan.SidRdpUsers) -Member $d.Name
            Set-HpSetting 'NewAdmin' $d.Name
            Set-HpSetting 'NewAdminConfirmed' $false
            Clear-HpSecret "pw:$($d.Name)"
            "Created '$($d.Name)'. Now log in with it in a SECOND RDP session, then press Confirm."
        } `
        -UndoKind 'user.create' -NoUndo 'the passphrase'
}

Register-UndoHandler 'user.create' {
    # Undo = take the account out of the privileged groups and disable it. It is never deleted.
    param($data, $before)
    if ($before.Existed) { return }
    Assert-NotScoringUser $data.Name 'undoing the creation'
    foreach ($sid in $script:Plan.SidAdministrators, $script:Plan.SidRdpUsers) {
        Remove-LocalGroupMember -Group (Get-GroupNameBySid $sid) -Member $data.Name -ErrorAction SilentlyContinue
    }
    Disable-LocalUser -Name $data.Name
    Set-HpSetting 'NewAdmin' ([string]$before.OldAdmin)
    Set-HpSetting 'NewAdminConfirmed' $false
}

function New-RepairAdminAction {
    # Makes an existing account usable as the new admin: enabled, in Administrators, in Remote Desktop Users.
    param([string]$Name, [switch]$Adopt)
    $will = @("Enable '$Name' if it is disabled", 'Add it to Administrators and Remote Desktop Users (if it is not in them)')
    if ($Adopt) { $will += "Remember '$Name' as the new admin in the tool settings"; $will += 'Its password is NOT changed' }
    New-Action -Id "user.repair:$Name" -Title "Make '$Name' usable as the new admin" -Risk 'Medium' -Will $will `
        -Data @{ Name = $Name; Adopt = [bool]$Adopt } `
        -Capture {
            param($d)
            $u = Get-LocalUser -Name $d.Name -ErrorAction Stop
            @{ Enabled = [bool]$u.Enabled; Groups = @(Get-AccountGroups $d.Name | ForEach-Object { $_.Sid }); OldAdmin = [string](Get-HpSetting 'NewAdmin') }
        } `
        -Apply {
            param($d, $before)
            if (-not $before.Enabled) { Enable-LocalUser -Name $d.Name }
            foreach ($sid in $script:Plan.SidAdministrators, $script:Plan.SidRdpUsers) {
                if (@($before.Groups) -notcontains $sid) { Add-LocalGroupMember -Group (Get-GroupNameBySid $sid) -Member $d.Name }
            }
            if ($d.Adopt) { Set-HpSetting 'NewAdmin' $d.Name; Set-HpSetting 'NewAdminConfirmed' $false }
            "'$($d.Name)' is enabled, an administrator and in Remote Desktop Users."
        } `
        -UndoKind 'user.repair'
}

Register-UndoHandler 'user.repair' {
    param($data, $before)
    Assert-NotScoringUser $data.Name 'undoing the repair'
    foreach ($sid in $script:Plan.SidAdministrators, $script:Plan.SidRdpUsers) {
        if (@($before.Groups) -notcontains $sid) { Remove-LocalGroupMember -Group (Get-GroupNameBySid $sid) -Member $data.Name -ErrorAction SilentlyContinue }
    }
    if (-not $before.Enabled) { Disable-LocalUser -Name $data.Name }
    if ($data.Adopt) { Set-HpSetting 'NewAdmin' ([string]$before.OldAdmin) }
}

function New-ConfirmAdminAction {
    param([string]$Name)
    New-Action -Id "user.confirm:$Name" -Title "Confirm that '$Name' works" -Risk 'Medium' `
        -Will @("You tell the tool: I logged in as '$Name' in a SECOND RDP session and it worked",
                'From now on the tool will let you disable plinktern, the built-in Administrator and the other admins',
                'Nothing on the box changes') `
        -Data @{ Name = $Name } `
        -Capture { param($d) $null = $d; @{ Was = [bool](Get-HpSetting 'NewAdminConfirmed') } } `
        -Apply { param($d, $before) $null = $d, $before; Set-HpSetting 'NewAdminConfirmed' $true; 'Confirmed.' } `
        -UndoKind 'user.confirm'
}

Register-UndoHandler 'user.confirm' { param($data, $before) $null = $data; Set-HpSetting 'NewAdminConfirmed' ([bool]$before.Was) }

# ---------------------------------------------------------------- retire an account (new password, out of groups, disabled)
function Get-ThrowawayMaster {
    # The "throwaway master" from Bitwarden: asked once, kept in memory. Each retired account gets a password derived from it.
    $m = Get-HpSecret 'master'
    if ($m) { return $m }
    $m1 = Read-HpSecret 'Throwaway master secret (from Bitwarden, 20+ random characters). Disabled accounts get passwords derived from it, so the laptop can recompute them.'
    if (-not $m1) { return $null }
    $m2 = Read-HpSecret 'Type the same master again'
    if ($m1 -cne $m2) { Show-HpNotice 'The two entries are different.' 'Throwaway master'; return $null }
    if ($m1.Length -lt 16) { Show-HpNotice "The master is only $($m1.Length) characters. Use at least 16 random ones." 'Throwaway master'; return $null }
    Set-HpSecret 'master' $m1
    $m1
}

function Request-RetireAccount {
    param([string]$Name)
    Assert-NotScoringUser $Name 'retiring the account'
    if (-not (Get-ThrowawayMaster)) { return $null }
    New-RetireAccountAction -Name $Name
}

function New-RetireAccountAction {
    param([string]$Name)
    $groups = @(Get-AccountGroups $Name | Where-Object { $_.Sid -ne $script:Plan.SidUsers -and $_.Sid -ne $script:Plan.SidGuests } | ForEach-Object { $_.Name })
    $risk = 'Medium'; $word = ''
    $will = @("Set a new random password on '$Name' (HMAC-SHA256 of the name, keyed with your throwaway master)",
              $(if ($groups.Count) { "Remove it from: $($groups -join ', ')" } else { 'It is in no privileged group' }),
              'Disable it (it is never deleted)')
    if ($env:USERNAME -ieq $Name) {
        $risk = 'High'; $word = $Name
        $will += "YOU ARE LOGGED IN AS '$Name' right now. Make sure the new admin works in another session first."
    }
    New-Action -Id "user.retire:$Name" -Title "Retire the account '$Name'" -Risk $risk -TypeWord $word -Will $will -Data @{ Name = $Name } `
        -Capture {
            param($d)
            Assert-NotScoringUser $d.Name 'retiring the account'
            if ($d.Name -ieq [string](Get-HpSetting 'NewAdmin')) { throw 'Refused: this is the new admin account.' }
            $u = Get-LocalUser -Name $d.Name -ErrorAction Stop
            $mine = @(Get-AccountGroups $d.Name)
            $isAdmin = @($mine | Where-Object { $_.Sid -eq $script:Plan.SidAdministrators }).Count -gt 0
            if ($isAdmin -and -not (Get-HpSetting 'NewAdminConfirmed')) { throw 'Refused: confirm the new admin first (second RDP session), or you could lock yourself out.' }
            if ($isAdmin -and $u.Enabled -and -not (Test-HasAdminLeft $d.Name)) { throw 'Refused: this is the only enabled administrator.' }
            @{ Enabled = [bool]$u.Enabled; Groups = $mine }
        } `
        -Apply {
            param($d, $before)
            $master = Get-HpSecret 'master'
            if (-not $master) { throw 'The throwaway master is no longer in memory. Start the action again.' }
            Set-LocalUser -Name $d.Name -Password (ConvertTo-HpSecure (Get-DerivedPassword -Master $master -Account $d.Name))
            $notes = @('password changed')
            foreach ($g in @($before.Groups)) {
                if ($g.Sid -eq $script:Plan.SidUsers -or $g.Sid -eq $script:Plan.SidGuests) { continue }
                try { Remove-LocalGroupMember -Group $g.Name -Member $d.Name -ErrorAction Stop; $notes += "removed from $($g.Name)" }
                catch { $notes += "COULD NOT remove from $($g.Name): $($_.Exception.Message)" }
            }
            if ($before.Enabled) { Disable-LocalUser -Name $d.Name; $notes += 'disabled' }
            if ((Get-LocalUser -Name $d.Name).Enabled) { throw "The account is still enabled after Disable-LocalUser ($($notes -join '; '))." }
            "'$($d.Name)': " + ($notes -join '; ')
        } `
        -UndoKind 'user.retire' -NoUndo 'the old password (it was replaced; the new one is derived from your throwaway master)'
}

Register-UndoHandler 'user.retire' {
    # Puts the groups back and enables the account again if it was enabled. The password stays the new one.
    param($data, $before)
    Assert-NotScoringUser $data.Name 'undoing the retirement'
    foreach ($g in @($before.Groups)) {
        if ($g.Sid -eq $script:Plan.SidUsers -or $g.Sid -eq $script:Plan.SidGuests) { continue }
        Add-LocalGroupMember -Group $g.Name -Member $data.Name -ErrorAction SilentlyContinue
    }
    if ($before.Enabled) { Enable-LocalUser -Name $data.Name }
}

# ---------------------------------------------------------------- jmoney
function Request-RotateJmoney {
    # The scoring password is rotated ONCE. A second time needs a typed confirmation.
    $rot = [int](Get-HpSetting 'JmoneyRotations')
    if ($rot -ge 1) {
        $again = & $script:Hp.Ask 'Rotate jmoney AGAIN?' "This tool already changed the scoring password $rot time(s).`n`nEvery change risks a failing scoring login until NEIGH has the new password. Only continue if you must." 'ROTATE AGAIN'
        if (-not $again) { return $null }
    }
    $scoring = $script:Plan.ScoringUser
    $p1 = Read-HpSecret "New password for $scoring (long random, from Bitwarden; letters, digits and - _ . only)"
    if (-not $p1) { return $null }
    $p2 = Read-HpSecret 'Type the same password again'
    if ($p1 -cne $p2) { Show-HpNotice 'The two passwords are different. Nothing was changed.' 'jmoney'; return $null }
    Set-HpSecret "pw:$scoring" $p1
    New-RotateJmoneyAction -Warnings @(Test-ScoringPasswordShape $p1) -Count $rot
}

function New-RotateJmoneyAction {
    param([string[]]$Warnings = @(), [int]$Count = 0)
    $scoring = $script:Plan.ScoringUser
    $will = @("Set the password of $scoring to the one you just typed (it is not saved anywhere)",
              "Scoring logs in as $scoring, so RDP and Jenkins FAIL until NEIGH has the new password",
              'RIGHT AFTER: NEIGH -> Users -> every assembly entry for jmoney -> paste the password -> Save. Then wait for two green checks.',
              "Never log in as $scoring yourself (a second session can take over the scoring session)")
    foreach ($w in $Warnings) { $will += "WARNING about the password: $w" }
    New-Action -Id "user.rotate:$scoring" -Title "Change the scoring password of $scoring (change number $($Count + 1))" -Risk 'High' -TypeWord $scoring -Will $will -Data @{ Name = $scoring } `
        -Capture { param($d) $u = Get-LocalUser -Name $d.Name -ErrorAction Stop; if (-not $u.Enabled) { throw 'Refused: jmoney is disabled. Enable it first.' }; @{ Rotations = [int](Get-HpSetting 'JmoneyRotations') } } `
        -Apply {
            param($d, $before)
            $pw = Get-HpSecret "pw:$($d.Name)"
            if (-not $pw) { throw 'The password is no longer in memory. Start the action again.' }
            Set-LocalUser -Name $d.Name -Password (ConvertTo-HpSecure $pw)
            Set-HpSetting 'JmoneyRotations' ([int]$before.Rotations + 1)
            Clear-HpSecret "pw:$($d.Name)"
            "The password of $($d.Name) was changed. UPDATE NEIGH NOW (Users tab -> Save) and wait for two green checks."
        } `
        -NoUndo 'the password (the old one is not stored anywhere)'
}

function New-DemoteJmoneyAction {
    $scoring = $script:Plan.ScoringUser
    New-Action -Id 'user.demote:jmoney' -Title "Take $scoring out of Administrators" -Risk 'High' -TypeWord $scoring `
        -Will @("Add $scoring to Remote Desktop Users first (if it is not in it)", "Then remove $scoring from Administrators",
                'Check NEIGH right afterwards: the RDP login must still pass') `
        -Data @{ Name = $scoring } `
        -Capture { param($d) @{ Groups = @(Get-AccountGroups $d.Name | ForEach-Object { $_.Sid }) } } `
        -Apply {
            param($d, $before)
            if (@($before.Groups) -notcontains $script:Plan.SidRdpUsers) { Add-LocalGroupMember -Group (Get-GroupNameBySid $script:Plan.SidRdpUsers) -Member $d.Name }
            Remove-LocalGroupMember -Group (Get-GroupNameBySid $script:Plan.SidAdministrators) -Member $d.Name
            "$($d.Name) is no longer an Administrator."
        } `
        -UndoKind 'user.demote'
}

Register-UndoHandler 'user.demote' {
    # Undo puts jmoney back into Administrators. (It never removes jmoney from Remote Desktop Users.)
    param($data, $before)
    if (@($before.Groups) -contains $script:Plan.SidAdministrators) { Add-LocalGroupMember -Group (Get-GroupNameBySid $script:Plan.SidAdministrators) -Member $data.Name }
}

# ---------------------------------------------------------------- the new admin's later password changes
function Request-SetPassword {
    # Rotates the new admin's passphrase again (after the persistence hunt, then about every 2 hours).
    param([string]$Name, [string]$Kind = 'admin')
    $null = $Kind
    Assert-NotScoringUser $Name 'this password change (use the jmoney button)'
    $p1 = Read-HpSecret "New passphrase for '$Name' (from Bitwarden; you must be able to TYPE it on the Console)"
    if (-not $p1) { return $null }
    $p2 = Read-HpSecret 'Type the same passphrase again'
    if ($p1 -cne $p2) { Show-HpNotice 'The two passphrases are different. Nothing was changed.' 'New password'; return $null }
    Set-HpSecret "pw:$Name" $p1
    $will = @("Set the password of '$Name' to the passphrase you typed (not saved anywhere)",
              'Existing sessions stay open; the next login needs the new passphrase')
    foreach ($w in @(Test-PassphraseShape $p1)) { $will += "WARNING about the passphrase: $w" }
    New-Action -Id "user.setpw:$Name" -Title "Change the password of '$Name'" -Risk 'Medium' -Will $will -Data @{ Name = $Name } `
        -Capture { param($d) $null = Get-LocalUser -Name $d.Name -ErrorAction Stop; @{ Known = $true } } `
        -Apply {
            param($d, $before)
            $null = $before
            $pw = Get-HpSecret "pw:$($d.Name)"
            if (-not $pw) { throw 'The passphrase is no longer in memory. Start the action again.' }
            Set-LocalUser -Name $d.Name -Password (ConvertTo-HpSecure $pw)
            Clear-HpSecret "pw:$($d.Name)"
            "The password of '$($d.Name)' was changed."
        } `
        -NoUndo 'the password (the old one is not stored anywhere)'
}

# ---------------------------------------------------------------- small account actions
function New-EnableUserAction {
    param([string]$Name)
    $isScoring = ($Name -ieq $script:Plan.ScoringUser)
    $undo = $(if ($isScoring) { '' } else { 'user.enable' })
    New-Action -Id "user.enable:$Name" -Title "Enable the account '$Name'" -Risk 'Low' `
        -Will @("Enable '$Name' and clear a lockout (net user /active:yes)") -Data @{ Name = $Name } `
        -Capture { param($d) @{ Enabled = [bool](Get-LocalUser -Name $d.Name -ErrorAction Stop).Enabled } } `
        -Apply {
            param($d, $before)
            $null = $before
            Enable-LocalUser -Name $d.Name
            & net.exe user $d.Name /active:yes | Out-Null
            "'$($d.Name)' is enabled."
        } `
        -UndoKind $undo
}

Register-UndoHandler 'user.enable' {
    param($data, $before)
    Assert-NotScoringUser $data.Name 'disabling the account'
    if (-not $before.Enabled) { Disable-LocalUser -Name $data.Name }
}

function New-AddToGroupAction {
    param([string]$Name, [string]$GroupSid)
    $isScoringRdp = ($Name -ieq $script:Plan.ScoringUser -and $GroupSid -eq $script:Plan.SidRdpUsers)
    $undo = $(if ($isScoringRdp) { '' } else { 'user.group' })
    New-Action -Id "user.group:${Name}:$GroupSid" -Title "Add '$Name' to the group $GroupSid" -Risk 'Low' `
        -Will @("Add '$Name' to the local group with SID $GroupSid") -Data @{ Name = $Name; GroupSid = $GroupSid } `
        -Capture { param($d) @{ Was = [bool](@(Get-AccountGroups $d.Name | Where-Object { $_.Sid -eq $d.GroupSid }).Count) } } `
        -Apply {
            param($d, $before)
            if (-not $before.Was) { Add-LocalGroupMember -Group (Get-GroupNameBySid $d.GroupSid) -Member $d.Name }
            "'$($d.Name)' is in the group."
        } `
        -UndoKind $undo
}

Register-UndoHandler 'user.group' {
    param($data, $before)
    Assert-NotScoringUser $data.Name 'removing the account from a group'
    if (-not $before.Was) { Remove-LocalGroupMember -Group (Get-GroupNameBySid $data.GroupSid) -Member $data.Name -ErrorAction SilentlyContinue }
}

function New-DisableGuestAction {
    New-Action -Id 'user.guest' -Title 'Disable the Guest account' -Risk 'Low' -Will @('Disable the built-in Guest account (found by its SID ending in -501)') `
        -Capture {
            param($d)
            $null = $d
            $g = Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
            if (-not $g) { throw 'The Guest account was not found.' }
            @{ Name = [string]$g.Name; Enabled = [bool]$g.Enabled }
        } `
        -Apply { param($d, $before) $null = $d; Disable-LocalUser -Name $before.Name; "$($before.Name) is disabled." } `
        -UndoKind 'user.guest'
}

Register-UndoHandler 'user.guest' { param($data, $before) $null = $data; if ($before.Enabled) { Enable-LocalUser -Name $before.Name } }

# ---------------------------------------------------------------- local security policy: lockout, Remote Desktop logon right
function New-LockoutOffAction {
    New-Action -Id 'rights.lockout' -Title 'Turn account lockout off' -Risk 'Low' `
        -Will @('Set the lockout threshold to 0 (net accounts /lockoutthreshold:0): wrong passwords never lock an account', 'The plan uses long random passwords instead; lockout would let the Red Team lock out jmoney') `
        -Capture { param($d) $null = $d; @{ Threshold = [int](Get-SeceditFacts)['LockoutBadCount'] } } `
        -Apply {
            param($d, $before)
            $null = $d, $before
            & net.exe accounts /lockoutthreshold:0 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "net accounts failed with exit code $LASTEXITCODE" }
            'Lockout is off.'
        } `
        -UndoKind 'rights.lockout'
}

Register-UndoHandler 'rights.lockout' {
    param($data, $before)
    $null = $data
    & net.exe accounts "/lockoutthreshold:$([int]$before.Threshold)" | Out-Null
}

function Set-UserRight {
    # Sets ONE user right to exactly this list ("*S-1-5-32-544,*S-1-5-21-...") with secedit and a tiny template file.
    # The template is written in Unicode, which is what secedit writes itself. The result is read back and compared.
    param([string]$Right, [string]$Value)
    $stamp = [guid]::NewGuid().ToString('N')
    $inf = Join-Path $env:TEMP "hp-right-$stamp.inf"
    $sdb = Join-Path $env:TEMP "hp-right-$stamp.sdb"
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]', "$Right = $Value")
    try {
        [System.IO.File]::WriteAllLines($inf, $lines, [System.Text.Encoding]::Unicode)
        & secedit.exe /configure /db $sdb /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed with exit code $LASTEXITCODE" }
    } finally {
        Remove-Item $inf, $sdb -ErrorAction SilentlyContinue
    }
    $now = [string](Get-SeceditFacts)[$Right]
    $want = @($Value -split ',' | ForEach-Object { $_.Trim() } | Sort-Object)
    $got = @($now -split ',' | ForEach-Object { $_.Trim() } | Sort-Object)
    if (($want -join ',') -ne ($got -join ',')) { throw "After secedit the right $Right is '$now', not '$Value'." }
}

function Request-RestrictRdp {
    if (-not (Get-HpSetting 'NewAdmin') -or -not (Get-HpSetting 'NewAdminConfirmed')) {
        Show-HpNotice 'Create and confirm the new admin first. Otherwise only jmoney could log on through Remote Desktop.' 'Remote Desktop logon right'
        return $null
    }
    New-RestrictRdpAction
}

function New-RestrictRdpAction {
    $names = @($script:Plan.ScoringUser, [string](Get-HpSetting 'NewAdmin')) + @(Get-List (Get-HpSetting 'ExtraKeep') | ForEach-Object { [string]$_ })
    $names = @($names | Where-Object { $_ } | Select-Object -Unique)
    New-Action -Id 'rights.rdp' -Title 'Limit "Allow log on through Remote Desktop Services"' -Risk 'High' -TypeWord 'RDP' `
        -Will @("Only these accounts may log on through Remote Desktop afterwards: $($names -join ', ')",
                'Administrators and Remote Desktop Users no longer count: their other members cannot RDP in',
                'The old setting is saved in rights-before.inf; Panic.ps1 -Only Rights puts it back, and so does Undo',
                'Check NEIGH right afterwards: the RDP login as jmoney must still pass') `
        -Data @{ Names = $names } `
        -Capture {
            param($d)
            $users = @()
            foreach ($n in @($d.Names)) {
                $u = Get-LocalUser -Name $n -ErrorAction SilentlyContinue
                if (-not $u) { throw "Refused: the account '$n' does not exist, so its SID is unknown." }
                if (-not $u.Enabled) { throw "Refused: the account '$n' is disabled." }
                $users += $u
            }
            $old = [string](Get-SeceditFacts)['SeRemoteInteractiveLogonRight']
            if (-not $old) { $old = "*$($script:Plan.SidAdministrators),*$($script:Plan.SidRdpUsers)" }
            # keep the very first original for Panic.ps1 (a second run must not overwrite it with an already restricted value)
            $saved = Join-Path $script:Hp.DataDir 'rights-before.inf'
            if (-not (Test-Path $saved)) {
                $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]', "SeRemoteInteractiveLogonRight = $old")
                [System.IO.File]::WriteAllLines($saved, $lines, [System.Text.Encoding]::Unicode)
            }
            @{ Old = $old; Sids = @($users | ForEach-Object { '*' + $_.SID.Value }) }
        } `
        -Apply {
            param($d, $before)
            Set-UserRight -Right 'SeRemoteInteractiveLogonRight' -Value (@($before.Sids) -join ',')
            "Remote Desktop logon is now limited to: $(@($d.Names) -join ', ')."
        } `
        -UndoKind 'rights.rdp'
}

Register-UndoHandler 'rights.rdp' {
    param($data, $before)
    $null = $data
    Set-UserRight -Right 'SeRemoteInteractiveLogonRight' -Value ([string]$before.Old)
}
