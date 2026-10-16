# Test-Core.ps1 - tests lib\Core.ps1: the gate, confirm, journal, undo, the scoring probe and the password helpers.
# Uses a temporary data folder and made-up actions; it never touches the real box.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"

# DeadMan.ps1 is not loaded here, so this test supplies the one function Core asks it for.
$global:DeadManMsg = ''
function Get-DeadManBlocker { $global:DeadManMsg }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-core-' + [guid]::NewGuid().ToString('N'))
Initialize-Hp -DataDir $tmp -NoAcl

# ---- a fake "box" with one value, an action that changes it, and an undo handler
$global:Box = @{ Value = 'old'; ApplyCalls = 0; CaptureCalls = 0 }
Register-UndoHandler 'test.set' { param($d, $before) $null = $d; $global:Box.Value = $before.Value }
function New-TestAction {
    param([string]$Risk = 'Low', [bool]$Fail = $false, [bool]$FailCapture = $false, [switch]$NeedsDeadMan, [string]$UndoKind = 'test.set')
    New-Action -Id 'test.set' -Title 'Set the test value' -Risk $Risk -Will @('Change the value to new') `
        -Data @{ NewValue = 'new'; Fail = $Fail; FailCapture = $FailCapture } -UndoKind $UndoKind -NeedsDeadMan:$NeedsDeadMan `
        -Capture { param($d) $global:Box.CaptureCalls++; if ($d.FailCapture) { throw 'cannot read' }; @{ Value = $global:Box.Value } } `
        -Apply   { param($d, $before) $null = $before; $global:Box.ApplyCalls++; if ($d.Fail) { throw 'boom' }; $global:Box.Value = $d.NewValue; 'the output' }
}
function Reset-Box { $global:Box.Value = 'old'; $global:Box.ApplyCalls = 0; $global:Box.CaptureCalls = 0 }

# the hooks the GUI would normally replace
$global:AskLog = @(); $global:AskAnswer = $true
$script:Hp.Ask = { param($t, $text, $word) $global:AskLog += , @($t, $text, $word); $global:AskAnswer }

Write-Host 'Gate: audit mode is the default' -ForegroundColor Cyan
Assert-True (-not $script:Hp.AllowChanges) 'starts in audit mode (changes not allowed)'
$r = Invoke-Change (New-TestAction)
Assert-Equal $r.Status 'Blocked' 'a change in audit mode is Blocked'
Assert-Equal $global:Box.ApplyCalls 0 'and the change did not run'
Assert-Equal $global:Box.CaptureCalls 0 'and not even the old-state read ran'
Assert-Equal @(Get-JournalRecords).Count 0 'and no journal record was written'
Assert-Equal $global:AskLog.Count 0 'and nobody was asked'

Write-Host 'Confirm: No means nothing happens' -ForegroundColor Cyan
$script:Hp.AllowChanges = $true
$global:AskAnswer = $false
$r = Invoke-Change (New-TestAction)
Assert-Equal $r.Status 'Cancelled' 'answering No gives Cancelled'
Assert-Equal $global:Box.ApplyCalls 0 'nothing ran'
Assert-Equal @(Get-JournalRecords).Count 0 'no journal record'
Assert-True ($global:AskLog[0][1] -match 'Change the value to new') 'the confirm box showed the plain-English change'
Assert-True ($global:AskLog[0][1] -match 'Risk: Low') 'and the risk'

Write-Host 'Apply: journal, no probe, no log' -ForegroundColor Cyan
$logBefore = $script:Hp.LogLines.Count
$global:AskAnswer = $true
$r = Invoke-Change (New-TestAction)
Assert-Equal $r.Status 'Applied' 'answering Yes applies the change'
Assert-Equal $global:Box.Value 'new' 'the value changed'
Assert-Equal $r.Output 'the output' 'the output of Apply is returned'
Assert-Equal $r.JournalId 1 'first journal id is 1'
$rec = @(Get-JournalRecords)[0]
Assert-Equal $rec.Status 'applied' 'journal says applied'
Assert-Equal $rec.Before.Value 'old' 'journal kept the OLD value'
Assert-Equal $rec.Data.NewValue 'new' 'journal kept the action data'
Assert-Equal $rec.UndoKind 'test.set' 'journal knows how to undo it'
Assert-True (Test-Path (Join-Path $script:Hp.JournalDir '0001.json')) 'the journal file is 0001.json'
Assert-True ($null -eq $r.PSObject.Properties['Probe']) 'a change result carries no scoring probe (it was removed)'
Assert-True ($null -eq (Get-Command Update-ScoringProbe -ErrorAction SilentlyContinue)) 'there is no scoring probe function any more'
Assert-True (-not (Test-Path (Join-Path $tmp 'logs'))) 'there is no log folder and no log file'
Assert-Equal $script:Hp.LogLines.Count $logBefore 'a successful change adds nothing to the in-memory log (no "you did this" lines)'

Write-Host 'Undo (also after a restart: the journal is the only memory)' -ForegroundColor Cyan
Initialize-Hp -DataDir $tmp -NoAcl                      # simulate closing and reopening the tool
$script:Hp.AllowChanges = $true
$script:Hp.Ask = { param($t, $text, $word) $null = $t, $text, $word; $true }
$r = Undo-LastChange
Assert-Equal $r.Status 'Undone' 'Undo last works from the journal file'
Assert-Equal $global:Box.Value 'old' 'the old value is back'
Assert-Equal @(Get-JournalRecords)[0].Status 'undone' 'journal says undone'
Assert-Equal (Undo-LastChange).Status 'Failed' 'a second undo has nothing to do'
Assert-Equal (Undo-Change -Id 1).Status 'Failed' 'undoing the same record again is refused'
Assert-Equal (Undo-Change -Id 99).Status 'Failed' 'an unknown record number is refused'

Write-Host 'Failures' -ForegroundColor Cyan
Reset-Box
$r = Invoke-Change (New-TestAction -Fail $true) -Confirmed
Assert-Equal $r.Status 'Failed' 'an Apply that throws gives Failed'
Assert-True ($r.Message -match 'boom') 'the message says why'
$rec = @(Get-JournalRecords) | Select-Object -Last 1
Assert-Equal $rec.Status 'failed' 'journal says failed'
Assert-Equal $rec.Error 'boom' 'journal keeps the error text'
Assert-Equal $rec.Id 2 'ids keep counting after a restart'
Assert-Equal (Undo-Change -Id 2).Status 'Failed' 'a failed change cannot be undone'
$before = @(Get-JournalRecords).Count
$r = Invoke-Change (New-TestAction -FailCapture $true) -Confirmed
Assert-Equal $r.Status 'Failed' 'if the old state cannot be read, nothing is changed'
Assert-Equal $global:Box.ApplyCalls 1 'Apply was not called again (only the earlier failing one)'
Assert-Equal @(Get-JournalRecords).Count $before 'and no new journal record exists'

Write-Host 'Confirmed / High risk' -ForegroundColor Cyan
Reset-Box
$global:AskLog = @(); $script:Hp.Ask = { param($t, $text, $word) $global:AskLog += , @($t, $text, $word); $true }
$r = Invoke-Change (New-TestAction) -Confirmed
Assert-Equal $r.Status 'Applied' '-Confirmed applies a Low risk action'
Assert-Equal $global:AskLog.Count 0 'and does not ask again'
Reset-Box
$r = Invoke-Change (New-TestAction -Risk 'High') -Confirmed
Assert-Equal $r.Status 'Applied' 'a High risk action applies when you confirm'
Assert-Equal $global:AskLog.Count 1 'but High risk always asks, even with -Confirmed'
Assert-Equal $global:AskLog[0][2] 'APPLY' 'and the default word to type is APPLY'
$hi = New-Action -Id 'x' -Title 'x' -Risk 'High' -TypeWord 'kkiderchah' -Apply { 1 }
Assert-Equal $hi.TypeWord 'kkiderchah' 'an action can ask for a specific word (for example the account name)'

Write-Host 'Dead-man switch gate' -ForegroundColor Cyan
Reset-Box
$global:DeadManMsg = 'The dead-man switch is not armed.'
$r = Invoke-Change (New-TestAction -NeedsDeadMan) -Confirmed
Assert-Equal $r.Status 'Blocked' 'a firewall-type action is Blocked when the switch is not armed'
Assert-True ($r.Message -match 'not armed') 'and the message says why'
Assert-Equal $global:Box.ApplyCalls 0 'and it did not run'
$r = Invoke-Change (New-TestAction) -Confirmed
Assert-Equal $r.Status 'Applied' 'a normal action is not affected by the switch'
Reset-Box
$global:DeadManMsg = ''
$r = Invoke-Change (New-TestAction -NeedsDeadMan) -Confirmed
Assert-Equal $r.Status 'Applied' 'armed (no blocker) lets the firewall-type action run'
$global:DeadManMsg = 'expired'
Assert-Equal (Undo-LastChange).Status 'Blocked' 'undoing a firewall-type change also needs the switch'
$global:DeadManMsg = ''
Assert-Equal (Undo-LastChange).Status 'Undone' 'and works once it is armed again'

Write-Host 'Undo needs a handler' -ForegroundColor Cyan
Reset-Box
$r = Invoke-Change (New-TestAction -UndoKind '') -Confirmed
$rec = @(Get-JournalRecords) | Select-Object -Last 1
Assert-Equal (Undo-Change -Id ([int]$rec.Id)).Status 'Failed' 'a change with no undo kind cannot be undone'
$r = Invoke-Change (New-TestAction -UndoKind 'nobody.registered.this') -Confirmed
$rec = @(Get-JournalRecords) | Select-Object -Last 1
Assert-True ((Undo-Change -Id ([int]$rec.Id)).Message -match 'No undo handler') 'an unknown handler name gives a clear message'

Write-Host 'Preview text' -ForegroundColor Cyan
$act = New-Action -Id 'p' -Title 'Disable account bob' -Risk 'Medium' -Will @('line one', 'line two') -NoUndo 'the old password' -Apply { 1 } -NeedsDeadMan
$txt = Format-ActionPreview $act
Assert-True ($txt -match 'Disable account bob') 'preview has the title'
Assert-True ($txt -match 'line one' -and $txt -match 'line two') 'preview lists every line'
Assert-True ($txt -match 'Undo: NOT available') 'no undo kind -> says so'
Assert-True ($txt -match 'NO UNDO for: the old password') 'the part that cannot be undone is shown before you confirm'
Assert-True ($txt -match 'dead-man') 'the dead-man requirement is shown'
Assert-True ((Format-ActionPreview (New-TestAction)) -match 'Undo: available') 'an action with an undo says so'

Write-Host 'Log: problems only, in memory' -ForegroundColor Cyan
$countBefore = $script:Hp.LogLines.Count
Write-HpLog 'something you did' 'INFO'
Assert-Equal $script:Hp.LogLines.Count $countBefore 'an INFO line (what you just did) is thrown away'
Write-HpLog 'something went wrong' 'WARN'
Assert-Equal $script:Hp.LogLines.Count ($countBefore + 1) 'a WARN line is kept in memory'
Assert-True ($script:Hp.LogLines[$script:Hp.LogLines.Count - 1] -match '\[WARN\] something went wrong') 'with its level'
Assert-True (-not (Test-Path (Join-Path $tmp 'logs'))) 'and no log folder or file is ever made'

# real local ports: an open one and a closed one
function Get-FreePortNumber { $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); $p }
$openPort = Get-FreePortNumber; $closedPort = Get-FreePortNumber
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $openPort); $listener.Start()
try {
    Assert-True (Test-TcpOpen -Port $openPort) 'Test-TcpOpen: an open port is true'
    Assert-True (-not (Test-TcpOpen -Port $closedPort)) 'Test-TcpOpen: a closed port is false'
    Assert-True (Test-TcpOpen -HostName 'localhost' -Port $openPort) 'Test-TcpOpen: a host name works too'
} finally {
    $listener.Stop()
}

Write-Host 'Settings' -ForegroundColor Cyan
Set-HpSetting 'NewAdmin' 'rocketeer'
Set-HpSetting 'ExtraKeep' @('svc_one', 'svc_two')
Initialize-Hp -DataDir $tmp -NoAcl
Assert-Equal (Get-HpSetting 'NewAdmin') 'rocketeer' 'a setting survives a restart'
Assert-Equal @(Get-HpSetting 'ExtraKeep').Count 2 'a list setting survives a restart'
Assert-Equal (Get-HpSetting 'DeadManMinutes') 5 'untouched settings keep their defaults'
Assert-Equal (Get-HpSetting 'NewAdminConfirmed') $false 'booleans keep their defaults'

Write-Host 'Secrets and folders' -ForegroundColor Cyan
Set-HpSecret 'master' 'abc'
Assert-Equal (Get-HpSecret 'master') 'abc' 'a secret can be stored in memory'
Clear-HpSecret 'master'
Assert-True ($null -eq (Get-HpSecret 'master')) 'and cleared'
Assert-True (-not (Test-Path (Join-Path $tmp 'settings.json') -PathType Leaf) -or -not ([IO.File]::ReadAllText((Join-Path $tmp 'settings.json')) -match 'abc')) 'a secret never reaches settings.json'
$bd = Get-HpDir 'backup'
Assert-True (Test-Path $bd -PathType Container) 'Get-HpDir creates the folder'
Assert-Equal $bd (Join-Path $tmp 'backup') 'inside the data folder'

Write-Host 'Passwords' -ForegroundColor Cyan
# known answers computed independently with Python:  base64(hmac_sha256(master, lowercase name))[:24] + 'aA1!'
Assert-Equal (Get-DerivedPassword -Master 'correct horse battery staple' -Account 'kkiderchah') 'trWeATiyXfxV5o9Dt7KWZZsjaA1!' 'derived password matches the independent HMAC (1)'
Assert-Equal (Get-DerivedPassword -Master 'correct horse battery staple' -Account 'KKiderchah') 'trWeATiyXfxV5o9Dt7KWZZsjaA1!' 'upper/lower case of the account name does not matter'
Assert-Equal (Get-DerivedPassword -Master 'correct horse battery staple' -Account 'support$') 'ZL22Du/CDzB5MKvRHHvm06+XaA1!' 'derived password matches (2, symbol in the name)'
Assert-Equal (Get-DerivedPassword -Master 'another master' -Account 'kkiderchah') 'ihndxFVN76fvg1HqWX8F0wXDaA1!' 'a different master gives a different password'
$dp = Get-DerivedPassword -Master 'm' -Account 'a'
Assert-True ($dp.Length -eq 28 -and $dp -cmatch '[a-z]' -and $dp -cmatch '[A-Z]' -and $dp -match '\d' -and $dp -match '[^A-Za-z0-9]') 'derived password is 28 characters with all four character classes'
Assert-Equal @(Test-ScoringPasswordShape 'Abcdefghijklmnopqrstuvwx-12_3').Count 0 'a long letters/digits/-_. password has no warnings'
Assert-True (@(Test-ScoringPasswordShape 'Short1').Count -ge 1) 'a short scoring password is warned about'
Assert-True (@(Test-ScoringPasswordShape 'Abcdefghijklmnopqrstuvwx 12').Count -ge 1) 'a space in the scoring password is warned about'
Assert-True (@(Test-ScoringPasswordShape 'Abcdefghijklmnopqrstuvwx"12').Count -ge 2) 'a double quote is warned about twice (odd character + FreeRDP)'
Assert-True (@(Test-ScoringPasswordShape 'Abcdefghijklmnopqrstuvwx$12').Count -ge 1) 'a dollar sign is warned about'
Assert-Equal @(Test-PassphraseShape 'plain words and 1234 are typeable').Count 0 'a typeable passphrase is fine'
Assert-True (@(Test-PassphraseShape 'short one').Count -ge 1) 'a short passphrase is warned about'
Assert-True (@(Test-PassphraseShape ('long enough but with an accent ' + [char]0xE9)).Count -ge 1) 'a non-keyboard character is warned about'

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-TestSummary
