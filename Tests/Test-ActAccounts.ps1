# Test-ActAccounts.ps1 - the account ACTIONS (lib\Act-Accounts.ps1) through the real gate, Invoke-Change, against the pretend box.
# It proves: the plan's rules are enforced in code (jmoney is never disabled, nothing is deleted, nobody is retired before the new
# admin is confirmed, passwords exist in memory only), every change that can be undone is undone exactly, and no secret reaches a file.
# It does NOT prove that real Windows accepts these passwords, group changes or secedit templates.
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
. "$PSScriptRoot\..\lib\Act-Accounts.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-actacc-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl

# ---- hooks: answers are scripted
$script:Asked = New-Object System.Collections.ArrayList
$script:Notices = New-Object System.Collections.ArrayList
$script:TextQueue = New-Object System.Collections.Queue
$script:SecretQueue = New-Object System.Collections.Queue
$script:AskAnswer = $true
$script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $script:AskAnswer }
$script:Hp.Notify = { param($Title, $Text) [void]$script:Notices.Add("$Title : $Text") }
$script:Hp.AskText = { param($Prompt, $Default) $null = $Prompt; if ($script:TextQueue.Count) { $script:TextQueue.Dequeue() } else { $Default } }
$script:Hp.AskSecret = { param($Prompt) $null = $Prompt; if ($script:SecretQueue.Count) { $script:SecretQueue.Dequeue() } else { $null } }
$script:Hp.AllowChanges = $true

function Push-Secrets { param([string[]]$Values) foreach ($v in $Values) { $script:SecretQueue.Enqueue($v) } }
function Get-FakeGroups { param([string]$Name) @($global:FW.Users[$Name].Groups) }
function Get-JournalCount { @(Get-JournalRecords).Count }
function Get-AllFilesText {
    (Microsoft.PowerShell.Management\Get-ChildItem -Path $tmp -Recurse -File | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
}

# the secrets used in this test: none of them may ever be found in a file
$PW_ADMIN   = 'Correct-Horse-Battery-Staple-9'
$PW_SHORT   = 'short1'
$PW_JMONEY  = 'Xk7-Tq9-Lm2-Rv5-Wz8-Bn4-Hd6-Pc3'
$PW_JMONEY2 = 'Zz1-Yy2-Xx3-Ww4-Vv5-Uu6-Tt7-Ss8'
$PW_ROTATE  = 'Another-Long-Passphrase-77'
$MASTER     = 'throwaway-master-0123456789abcdef'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Creating the new admin' -ForegroundColor Cyan
$script:TextQueue.Enqueue('')
Assert-True ($null -eq (Request-CreateAdmin)) 'no name -> cancelled'
foreach ($bad in 'this name is way too long for windows', 'has space', 'semi;colon', 'jmoney', 'JMoney') {
    $script:TextQueue.Enqueue($bad)
    Assert-True ($null -eq (Request-CreateAdmin)) "name '$bad' is refused"
}
Assert-True ($script:Notices.Count -eq 5 -and $script:Notices[-1] -match 'scoring user') 'each refusal is explained to you'
$script:TextQueue.Enqueue('zadmin'); Push-Secrets $PW_ADMIN, 'a different one'
Assert-True ($null -eq (Request-CreateAdmin) -and $script:Notices[-1] -match 'different') 'two different passphrases -> nothing is created'
Assert-True ($null -eq (Get-HpSecret 'pw:zadmin')) 'and the first one is not kept in memory'
$script:TextQueue.Enqueue('zadmin'); Push-Secrets ''
Assert-True ($null -eq (Request-CreateAdmin)) 'an empty passphrase cancels'

$script:TextQueue.Enqueue('zadmin'); Push-Secrets $PW_SHORT, $PW_SHORT
$a = Request-CreateAdmin
Assert-True (($a.Will -join ' ') -match 'WARNING about the passphrase: only 6 characters') 'a short passphrase gets a warning in the preview (not a refusal: you decide)'
$null = Clear-HpSecret 'pw:zadmin'
$script:TextQueue.Enqueue('zadmin'); Push-Secrets $PW_ADMIN, $PW_ADMIN
$a = Request-CreateAdmin
Assert-True ($a.Id -eq 'user.create:zadmin' -and $a.Risk -eq 'Medium' -and $a.UndoKind -eq 'user.create' -and $a.NoUndo -match 'passphrase') 'the action: medium risk, has an undo, says the passphrase cannot be undone'
Assert-True (($a.Will -join "`n") -notmatch [regex]::Escape($PW_ADMIN)) 'the preview does not contain the passphrase'
Assert-True (($a.Data | ConvertTo-Json) -notmatch [regex]::Escape($PW_ADMIN)) 'and neither does the action data (it goes into the journal)'

$script:Hp.AllowChanges = $false
Assert-Equal (Invoke-Change $a -Confirmed).Status 'Blocked' 'audit mode blocks it'
$script:Hp.AllowChanges = $true
$script:AskAnswer = $false
Assert-Equal (Invoke-Change $a).Status 'Cancelled' 'answering No cancels it'
Assert-True ($null -eq $global:FW.Users['zadmin']) 'nothing was created'
$script:AskAnswer = $true
$r = Invoke-Change $a -Confirmed
Assert-Equal $r.Status 'Applied' 'created'
$u = $global:FW.Users['zadmin']
Assert-True ($u.Enabled -and $u.Password -ceq $PW_ADMIN) 'enabled, with the passphrase that was typed'
Assert-True ((Get-FakeGroups 'zadmin') -contains 'Administrators' -and (Get-FakeGroups 'zadmin') -contains 'Remote Desktop Users') 'in Administrators and Remote Desktop Users'
Assert-True ((Get-HpSetting 'NewAdmin') -eq 'zadmin' -and -not (Get-HpSetting 'NewAdminConfirmed')) 'remembered as the new admin, NOT yet confirmed'
Assert-True ($null -eq (Get-HpSecret 'pw:zadmin')) 'the passphrase is gone from memory once used'
Assert-True ($r.Output -match 'SECOND RDP session') 'and the result tells you to log in with a second RDP session'
Assert-True ((Get-AllFilesText) -notmatch [regex]::Escape($PW_ADMIN)) 'the passphrase is in no file (log, journal, settings)'
$script:TextQueue.Enqueue('zadmin')
$null = $script:Asked.Clear()
$script:AskAnswer = $false
Assert-True ($null -eq (Request-CreateAdmin) -and $script:Asked[0].Title -match 'exists') 'asking for the same name again offers to ADOPT the existing account (and you can say no)'
$script:AskAnswer = $true

Write-Host 'Undo of the creation disables, it never deletes' -ForegroundColor Cyan
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Users.Contains('zadmin') -and -not $global:FW.Users['zadmin'].Enabled) 'the account is disabled, not deleted'
Assert-True ((Get-FakeGroups 'zadmin') -notcontains 'Administrators' -and (Get-FakeGroups 'zadmin') -notcontains 'Remote Desktop Users') 'and out of both groups'
Assert-True ([string](Get-HpSetting 'NewAdmin') -eq '') 'and the tool forgets it was the new admin'
# create it again for the rest of the test
$script:TextQueue.Enqueue('zadmin2'); Push-Secrets $PW_ADMIN, $PW_ADMIN
$a = Request-CreateAdmin
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-HpSetting 'NewAdmin') -eq 'zadmin2') 'a second new admin account can be created'

Write-Host 'Adopting an existing account / repairing the new admin' -ForegroundColor Cyan
$global:FW.Users['zadmin2'].Enabled = $false
[void]$global:FW.Users['zadmin2'].Groups.Remove('Administrators')
$a = New-RepairAdminAction -Name 'zadmin2'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Users['zadmin2'].Enabled -and (Get-FakeGroups 'zadmin2') -contains 'Administrators') 'repair: enabled again and back in Administrators'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and -not $global:FW.Users['zadmin2'].Enabled -and (Get-FakeGroups 'zadmin2') -notcontains 'Administrators') 'repair undone: disabled, out of Administrators again'
$null = Invoke-Change (New-RepairAdminAction -Name 'zadmin2') -Confirmed
$script:TextQueue.Enqueue('helpdesk')
$a = Request-CreateAdmin
Assert-True ($a.Id -eq 'user.repair:helpdesk' -and $a.Data.Adopt) 'an existing name can be adopted (its password is not changed)'
$null = $a

Write-Host 'Confirming the new admin' -ForegroundColor Cyan
Assert-True (-not (Get-HpSetting 'NewAdminConfirmed')) 'not confirmed yet'
$r = Invoke-Change (New-ConfirmAdminAction -Name 'zadmin2') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-HpSetting 'NewAdminConfirmed')) 'confirmed'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and -not (Get-HpSetting 'NewAdminConfirmed')) 'undo withdraws the confirmation'

Write-Host 'Retiring accounts: the safety rules' -ForegroundColor Cyan
Push-Secrets $MASTER, $MASTER
$a = Request-RetireAccount -Name 'plinktern'
Assert-True ($null -ne $a) 'the throwaway master is asked for once, with confirmation'
$snap = ($global:FW.Users['plinktern'].Groups -join ',') + '|' + $global:FW.Users['plinktern'].Enabled + '|' + $global:FW.Users['plinktern'].Password
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'confirm the new admin first') 'an administrator cannot be retired before the new admin is confirmed'
Assert-Equal (($global:FW.Users['plinktern'].Groups -join ',') + '|' + $global:FW.Users['plinktern'].Enabled + '|' + $global:FW.Users['plinktern'].Password) $snap 'and the account was not touched at all'
Assert-Throws { Request-RetireAccount -Name 'jmoney' } 'jmoney can never be retired (refused when asking)'
$r = Invoke-Change (New-RetireAccountAction -Name 'jmoney') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'scoring user' -and $global:FW.Users['jmoney'].Enabled) 'even a hand-built retire action for jmoney is refused in code'
$r = Invoke-Change (New-RetireAccountAction -Name 'zadmin2') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'new admin' -and $global:FW.Users['zadmin2'].Enabled) 'the new admin cannot be retired'
$r = Invoke-Change (New-RetireAccountAction -Name 'nobody') -Confirmed
Assert-Equal $r.Status 'Failed' 'an account that does not exist fails cleanly'

$null = Invoke-Change (New-ConfirmAdminAction -Name 'zadmin2') -Confirmed

Write-Host 'Retiring accounts: the normal case' -ForegroundColor Cyan
$a = Request-RetireAccount -Name 'plinktern'
Assert-Equal $script:SecretQueue.Count 0 'the master is remembered: no second prompt'
Assert-True ($a.Risk -eq 'Medium' -and $a.UndoKind -eq 'user.retire' -and (($a.Will -join ' ') -match 'Administrators') -and ($a.Will -join ' ') -match 'never deleted') 'preview: new password, groups listed, never deleted'
$r = Invoke-Change $a -Confirmed
Assert-Equal $r.Status 'Applied' 'plinktern retired'
$u = $global:FW.Users['plinktern']
Assert-True (-not $u.Enabled) 'disabled'
Assert-True ($u.Groups -notcontains 'Administrators' -and $u.Groups -notcontains 'Remote Desktop Users') 'out of Administrators and Remote Desktop Users'
$derived = Get-DerivedPassword -Master $MASTER -Account 'plinktern'
Assert-True ($u.Password -ceq $derived) 'new password = the one derived from the master (the laptop can recompute it)'
Assert-True ($derived -ne 'H00ves0nTheM00n') 'and it is not the packet password'
Assert-True ($global:FW.Users.Contains('plinktern')) 'the account still exists'
Assert-True ($r.Output -match 'password changed' -and $r.Output -match 'disabled') 'the result lists what was done'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Users['plinktern'].Enabled -and $global:FW.Users['plinktern'].Groups -contains 'Administrators' -and $global:FW.Users['plinktern'].Groups -contains 'Remote Desktop Users') 'undo: groups back, enabled again'
Assert-True ($global:FW.Users['plinktern'].Password -ceq $derived) 'the new password stays (the old one is not stored anywhere, as the preview said)'
$null = Invoke-Change (New-RetireAccountAction -Name 'plinktern') -Confirmed

$null = Invoke-Change (New-RetireAccountAction -Name 'old.employee') -Confirmed
Assert-True ((-not $global:FW.Users['old.employee'].Enabled) -and $global:FW.Users['old.employee'].Groups -notcontains 'Administrators') 'an already disabled account is cleaned out of its groups and stays disabled'
$r = Invoke-Change (New-RetireAccountAction -Name 'jbrewer') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not $global:FW.Users['jbrewer'].Enabled -and $global:FW.Users['jbrewer'].Groups -notcontains 'Remote Desktop Users') 'a plain RDP user: disabled and out of Remote Desktop Users'
Assert-True ($global:FW.Users['jmoney'].Enabled) 'jmoney is untouched through all of this'
Assert-Equal @($global:FW.Calls | Where-Object { $_ -like '*Remove-LocalUser*' }).Count 0 'no Remove-LocalUser call happened (nothing is ever deleted)'

Write-Host 'The only enabled administrator cannot be retired' -ForegroundColor Cyan
$global:FW = New-FakeBox
$script:SecretQueue.Clear()
Set-HpSetting 'NewAdmin' ''
Set-HpSetting 'NewAdminConfirmed' $true
foreach ($n in 'Administrator', 'kkiderchah', 'helpdesk', 'svc_backup', 'support$') { $global:FW.Users[$n].Enabled = $false }
$r = Invoke-Change (New-RetireAccountAction -Name 'plinktern') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'only enabled administrator' -and $global:FW.Users['plinktern'].Enabled) 'plinktern is the last enabled admin: refused'
Set-HpSetting 'NewAdmin' 'zadmin2'
Set-HpSetting 'NewAdminConfirmed' $false

Write-Host 'The master secret' -ForegroundColor Cyan
$null = Clear-HpSecret 'master'
Push-Secrets 'tooshort', 'tooshort'
Assert-True ($null -eq (Get-ThrowawayMaster) -and $script:Notices[-1] -match '16') 'a master shorter than 16 characters is refused'
Push-Secrets $MASTER, 'not the same'
Assert-True ($null -eq (Get-ThrowawayMaster) -and $script:Notices[-1] -match 'different') 'two different entries are refused'
Assert-True ($null -eq (Get-HpSecret 'master')) 'and nothing is kept'
Push-Secrets ''
Assert-True ($null -eq (Get-ThrowawayMaster)) 'an empty entry cancels'

Write-Host 'Retiring the account you are logged in as' -ForegroundColor Cyan
$oldUser = $env:USERNAME
$env:USERNAME = 'jbrewer'
$a = New-RetireAccountAction -Name 'jbrewer'
Assert-True ($a.Risk -eq 'High' -and $a.TypeWord -eq 'jbrewer' -and ($a.Will -join ' ') -match 'LOGGED IN AS') 'High risk: you must type the account name, and the preview warns you'
$env:USERNAME = $oldUser

Write-Host 'Rotating the scoring password (jmoney)' -ForegroundColor Cyan
Push-Secrets $PW_JMONEY, 'oops'
Assert-True ($null -eq (Request-RotateJmoney) -and $script:Notices[-1] -match 'different') 'mismatch -> nothing changes'
Push-Secrets ''
Assert-True ($null -eq (Request-RotateJmoney)) 'empty -> cancelled'
Push-Secrets $PW_JMONEY, $PW_JMONEY
$a = Request-RotateJmoney
Assert-True ($a.Risk -eq 'High' -and $a.TypeWord -eq 'jmoney' -and $a.UndoKind -eq '' -and ($a.Will -join ' ') -match 'NEIGH') 'high risk, you type jmoney; no undo; the preview names NEIGH'
Assert-True ($a.Title -match 'change number 1') 'it is change number 1'
Assert-True (($a.Will -join ' ') -notmatch 'WARNING') 'a clean password has no warnings'
$null = $script:Asked.Clear()
$r = Invoke-Change $a -Confirmed
Assert-True ($script:Asked.Count -eq 1 -and $script:Asked[0].Word -eq 'jmoney' -and $script:Asked[0].Text -match 'NO UNDO for: the password') 'asked once more with the typed word, and the question says there is no undo'
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Users['jmoney'].Password -ceq $PW_JMONEY -and $global:FW.Users['jmoney'].Enabled) 'jmoney has the new password and is still enabled'
Assert-True ((Get-HpSetting 'JmoneyRotations') -eq 1 -and $null -eq (Get-HpSecret 'pw:jmoney')) 'rotation counted, secret cleared'
Assert-True ($r.Output -match 'UPDATE NEIGH') 'the result says to update NEIGH now'
$rec = Get-JournalRecords | Select-Object -Last 1
Assert-True (-not $rec.UndoKind) 'the journal says: no undo'
Assert-Equal (Undo-Change -Id ([int]$rec.Id) -Confirmed).Status 'Failed' 'and Undo refuses it'

$script:AskAnswer = $false
Push-Secrets $PW_JMONEY2, $PW_JMONEY2
Assert-True ($null -eq (Request-RotateJmoney)) 'a SECOND rotation asks for a typed confirmation first; saying no stops it before any password is asked'
Assert-Equal $script:SecretQueue.Count 2 'the passwords were not even consumed'
Assert-True ($script:Asked[-1].Word -eq 'ROTATE AGAIN') 'the word is ROTATE AGAIN'
$script:AskAnswer = $true
$a = Request-RotateJmoney
Assert-True ($a.Title -match 'change number 2') 'confirmed -> change number 2'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-HpSetting 'JmoneyRotations') -eq 2) 'second rotation counted'

Push-Secrets 'has space and "quote"', 'has space and "quote"'
$a = Request-RotateJmoney
Assert-True (($a.Will -join ' ') -match 'WARNING about the password: only' -and ($a.Will -join ' ') -match 'double quote') 'a password with spaces/quotes/short length gets warnings (the scoring login can break silently)'
$global:FW.Users['jmoney'].Enabled = $false
$r = Invoke-Change (New-RotateJmoneyAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'disabled') 'a disabled jmoney is not rotated (enable him first)'
$global:FW.Users['jmoney'].Enabled = $true
$null = Clear-HpSecret 'pw:jmoney'

Write-Host 'Enabling accounts, groups, Guest, lockout' -ForegroundColor Cyan
$global:FW.Users['jmoney'].Enabled = $false
$a = New-EnableUserAction -Name 'jmoney'
Assert-True ($a.UndoKind -eq '') 'enabling jmoney has NO undo (undo would disable him)'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Users['jmoney'].Enabled -and ($global:FW.Calls -contains 'net user jmoney /active:yes')) 'jmoney enabled, and the lockout cleared with net user /active:yes'
$global:FW.Users['testuser'].Enabled = $false
$r = Invoke-Change (New-EnableUserAction -Name 'testuser') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Users['testuser'].Enabled) 'another account can be enabled'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and -not $global:FW.Users['testuser'].Enabled) 'and that is undone by disabling it again'

[void]$global:FW.Users['jmoney'].Groups.Clear()
$a = New-AddToGroupAction -Name 'jmoney' -GroupSid 'S-1-5-32-555'
Assert-True ($a.UndoKind -eq '') 'adding jmoney to Remote Desktop Users has no undo'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeGroups 'jmoney') -contains 'Remote Desktop Users') 'jmoney is in Remote Desktop Users'
$r = Invoke-Change $a -Confirmed
Assert-Equal $r.Status 'Applied' 'adding him again is harmless (already a member)'
$r = Invoke-Change (New-AddToGroupAction -Name 'testuser' -GroupSid 'S-1-5-32-555') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeGroups 'testuser') -contains 'Remote Desktop Users') 'another account can be added'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and (Get-FakeGroups 'testuser') -notcontains 'Remote Desktop Users') 'and removed again by undo'
$forged = [ordered]@{ Id = 900; Time = '2026-10-17 10:00:00'; ActionId = 'user.group:jmoney'; Title = 'forged'; Risk = 'Low'; Will = @(); UndoKind = 'user.group'; NoUndo = ''
                      NeedsDeadMan = $false; Data = @{ Name = 'jmoney'; GroupSid = 'S-1-5-32-555' }; Before = @{ Was = $false }; Status = 'applied'; Error = '' }
Save-JournalRecord $forged
$r = Undo-Change -Id 900 -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Refused' -and (Get-FakeGroups 'jmoney') -contains 'Remote Desktop Users') 'a forged journal record cannot take jmoney out of Remote Desktop Users'
$forged.Id = 901; $forged.UndoKind = 'user.enable'; $forged.Data = @{ Name = 'jmoney' }; $forged.Before = @{ Enabled = $false }
Save-JournalRecord $forged
$r = Undo-Change -Id 901 -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $global:FW.Users['jmoney'].Enabled) 'a forged record cannot disable jmoney through the enable-undo either'

$r = Invoke-Change (New-DisableGuestAction) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not $global:FW.Users['Guest'].Enabled) 'Guest disabled (found by its SID ending in -501)'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Users['Guest'].Enabled) 'and re-enabled by undo'
$global:FW.Users['Guest'].Name = 'Gast'
$global:FW.Users['Gast'] = $global:FW.Users['Guest']; $global:FW.Users.Remove('Guest')
$r = Invoke-Change (New-DisableGuestAction) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not $global:FW.Users['Gast'].Enabled) 'a renamed Guest account (other Windows language) is still found'

$global:FW.Lockout = 5
$r = Invoke-Change (New-LockoutOffAction) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Lockout -eq 0) 'lockout threshold set to 0'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Lockout -eq 5) 'undo puts the old threshold (5) back'

Write-Host 'Demoting jmoney' -ForegroundColor Cyan
[void]$global:FW.Users['jmoney'].Groups.Clear(); [void]$global:FW.Users['jmoney'].Groups.Add('Administrators')
$a = New-DemoteJmoneyAction
Assert-True ($a.Risk -eq 'High' -and $a.TypeWord -eq 'jmoney') 'high risk, typed word'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeGroups 'jmoney') -contains 'Remote Desktop Users' -and (Get-FakeGroups 'jmoney') -notcontains 'Administrators') 'Remote Desktop Users FIRST, then out of Administrators'
$order = @($global:FW.Calls | Where-Object { $_ -like 'Add-LocalGroupMember Remote Desktop Users jmoney' -or $_ -like 'Remove-LocalGroupMember Administrators jmoney' })
Assert-True ($order.Count -ge 2 -and $order[-2] -like 'Add-*' -and $order[-1] -like 'Remove-*') 'in that order (never a moment without RDP rights)'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and (Get-FakeGroups 'jmoney') -contains 'Administrators' -and (Get-FakeGroups 'jmoney') -contains 'Remote Desktop Users') 'undo: back in Administrators, still in Remote Desktop Users'

Write-Host 'Limiting the Remote Desktop logon right' -ForegroundColor Cyan
Set-HpSetting 'NewAdmin' ''
Set-HpSetting 'NewAdminConfirmed' $false
$null = $script:Notices.Clear()
Assert-True ($null -eq (Request-RestrictRdp) -and $script:Notices.Count -eq 1) 'without a confirmed new admin the button is refused with an explanation'
$script:TextQueue.Enqueue('zadmin3'); Push-Secrets $PW_ADMIN, $PW_ADMIN
$null = Invoke-Change (Request-CreateAdmin) -Confirmed
Assert-True ($null -eq (Request-RestrictRdp)) 'created but not confirmed: still refused'
$null = Invoke-Change (New-ConfirmAdminAction -Name 'zadmin3') -Confirmed
$a = Request-RestrictRdp
Assert-True ($a.Risk -eq 'High' -and $a.TypeWord -eq 'RDP' -and $a.UndoKind -eq 'rights.rdp') 'confirmed: High risk, you type RDP, has an undo'
Assert-True ((@($a.Data.Names) -join ',') -eq 'jmoney,zadmin3') 'allowed: jmoney and the new admin'
$old = [string](Get-SeceditFacts)['SeRemoteInteractiveLogonRight']
Assert-Equal $old '*S-1-5-32-544,*S-1-5-32-555' 'before: the Administrators and Remote Desktop Users groups'
$r = Invoke-Change $a -Confirmed
Assert-Equal $r.Status 'Applied' 'applied'
$now = [string](Get-SeceditFacts)['SeRemoteInteractiveLogonRight']
$want = '*' + $global:FW.Users['jmoney'].Sid + ',*' + $global:FW.Users['zadmin3'].Sid
Assert-Equal $now $want 'the right now lists exactly those two accounts by SID'
$saved = Join-Path $tmp 'rights-before.inf'
Assert-True (Test-Path $saved) 'the old setting was saved to rights-before.inf'
$savedText = [IO.File]::ReadAllText($saved, [Text.Encoding]::Unicode)
Assert-True ($savedText -match 'SeRemoteInteractiveLogonRight = \*S-1-5-32-544,\*S-1-5-32-555' -and $savedText -match '\[Privilege Rights\]' -and $savedText -match 'signature="\$CHICAGO\$"') 'in the template format Panic.ps1 feeds to secedit'
$rows = @(Get-HpFindings -Facts (Get-HpFacts) -Settings $script:Hp.Settings -Phases 2)
Assert-True (@($rows | Where-Object { $_.Subject -eq 'Remote Desktop logon right' -and $_.Severity -eq 'OK' }).Count -eq 1) 'the judge now shows the RDP right green'
# a second run must keep the very first original
$r = Invoke-Change (New-RestrictRdpAction) -Confirmed
Assert-Equal $r.Status 'Applied' 'running it a second time works'
Assert-True ([IO.File]::ReadAllText($saved, [Text.Encoding]::Unicode) -match '\*S-1-5-32-544,\*S-1-5-32-555') 'and rights-before.inf still holds the ORIGINAL value, not the restricted one'
$r = Undo-Change -Id ([int](Get-JournalRecords | Where-Object { $_.ActionId -eq 'rights.rdp' } | Select-Object -Last 1).Id) -Confirmed
Assert-True ($r.Status -eq 'Undone') 'undo of the second run works'
$r = Undo-Change -Id ([int](Get-JournalRecords | Where-Object { $_.ActionId -eq 'rights.rdp' -and $_.Status -eq 'applied' } | Select-Object -Last 1).Id) -Confirmed
Assert-Equal ([string](Get-SeceditFacts)['SeRemoteInteractiveLogonRight']) $old 'undo of the first run: the original setting is back'

# refusals and a quiet failure
$global:FW.Users['zadmin3'].Enabled = $false
$r = Invoke-Change (New-RestrictRdpAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'disabled' -and [string](Get-SeceditFacts)['SeRemoteInteractiveLogonRight'] -eq $old) 'a disabled account in the list is refused BEFORE anything changes'
$global:FW.Users['zadmin3'].Enabled = $true
$global:FW.SeceditIgnore = $true
$r = Invoke-Change (New-RestrictRdpAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'After secedit the right') 'secedit that "succeeds" without applying the right is caught by the read-back check'
$global:FW.SeceditIgnore = $false
Set-HpSetting 'ExtraKeep' @('jbrewer')
$a = Request-RestrictRdp
Assert-True ((@($a.Data.Names) -join ',') -eq 'jmoney,zadmin3,jbrewer') 'ExtraKeep accounts are allowed too'
Set-HpSetting 'ExtraKeep' @()

Write-Host 'Changing the new admin''s password later' -ForegroundColor Cyan
Assert-Throws { Request-SetPassword -Name 'jmoney' } 'jmoney''s password is not changed with this button (use the rotate button)'
Push-Secrets $PW_ROTATE, 'nope'
Assert-True ($null -eq (Request-SetPassword -Name 'zadmin3') -and $script:Notices[-1] -match 'different') 'mismatch -> nothing changes'
Push-Secrets $PW_ROTATE, $PW_ROTATE
$a = Request-SetPassword -Name 'zadmin3'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Users['zadmin3'].Password -ceq $PW_ROTATE) 'the password is changed'
Assert-True ($a.UndoKind -eq '' -and $a.NoUndo -match 'old one is not stored') 'no undo, and the preview said so'

Write-Host 'Secrets: none of them is in any file' -ForegroundColor Cyan
$allText = Get-AllFilesText
foreach ($pair in @(@('new admin passphrase', $PW_ADMIN), @('jmoney password 1', $PW_JMONEY), @('jmoney password 2', $PW_JMONEY2), @('later passphrase', $PW_ROTATE), @('throwaway master', $MASTER), @('a retired account password', $derived))) {
    Assert-True ($allText -notmatch [regex]::Escape($pair[1])) "$($pair[0]) is not in the log, the journal or the settings"
}
Assert-True ($allText -match 'user\.rotate' -or $allText -match 'Change the scoring password') 'and the journal names the rotation without its password'
Assert-True (@($global:FW.Calls | Where-Object { $_ -match 'Remove-LocalUser|Remove-LocalGroup ' }).Count -eq 0) 'no account or group was ever deleted'
Push-Secrets $MASTER, $MASTER
Assert-True ((Get-ThrowawayMaster) -ceq $MASTER -and $script:Hp.Secrets.ContainsKey('master')) 'the master lives in memory (the Secrets table) while the tool is open'
Assert-True ((Get-AllFilesText) -notmatch [regex]::Escape($MASTER)) 'and still reaches no file'

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-TestSummary
