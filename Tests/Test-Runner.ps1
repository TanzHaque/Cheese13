# Test-Runner.ps1 - the flow behind every button, against the pretend lab box, with the REAL judges, actions and gate:
#   audit -> pick a row -> build the action -> Invoke-Change -> read the box again   (lib\Runner.ps1)
#   the text menu on top of it                                                        (lib\Console.ps1)
#   and the launcher's start-up                                                       (Start-Hardening.ps1 -LoadOnly / -Journal / -NoGui)
# It proves the logic of the buttons: what a batch runs and in which rounds, when it stops, what is refreshed, how undo works.
# It does NOT prove anything about the window itself (WinForms is only parse-checked here) or about real Windows.
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
. "$PSScriptRoot\..\lib\Act-Backup.ps1"
. "$PSScriptRoot\..\lib\Act-Firewall.ps1"
. "$PSScriptRoot\..\lib\Act-Hunt.ps1"
. "$PSScriptRoot\..\lib\Act-Persist.ps1"
. "$PSScriptRoot\..\lib\Act-Watchdog.ps1"
. "$PSScriptRoot\..\lib\Runner.ps1"
. "$PSScriptRoot\..\lib\Console.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$script:HpRoot = Join-Path $PSScriptRoot '..'
$script:Dirs = New-Object System.Collections.ArrayList

# ---- scripted answers instead of a person
$script:Asked = New-Object System.Collections.ArrayList
$script:Notices = New-Object System.Collections.ArrayList
$script:TextQueue = New-Object System.Collections.Queue
$script:AskAnswer = $true
$script:ProbeRed = @()                       # names of scoring checks the pretend probe reports as down
$script:TestLog = New-Object System.Collections.ArrayList

function Start-Fresh {
    # A brand-new pretend box, a new data folder, new hooks. Every test section starts here, so sections cannot affect each other.
    $global:FW = New-FakeBox
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('hp-runner-' + [guid]::NewGuid().ToString('N'))
    [void]$script:Dirs.Add($dir)
    Initialize-Hp -DataDir $dir -NoAcl
    $script:Asked.Clear(); $script:Notices.Clear(); $script:TextQueue.Clear(); $script:TestLog.Clear()
    $script:AskAnswer = $true
    $script:ProbeRed = @()
    $script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $script:AskAnswer }
    $script:Hp.Notify = { param($Title, $Text) [void]$script:Notices.Add("$Title : $Text") }
    $script:Hp.AskText = { param($Prompt, $Default) $null = $Prompt; if ($script:TextQueue.Count) { $script:TextQueue.Dequeue() } else { $Default } }
    $script:Hp.AllowChanges = $true
}
function Get-Row { param([string]$Subject) @($script:Hp.Findings | Where-Object { $_.Subject -like $Subject }) | Select-Object -First 1 }
function Get-FakeRule { param([string]$Name) @($global:FW.FwRules | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1 }
function Get-HostText {
    # Runs a script block and returns what it wrote with Write-Host (information stream) as text, plus whatever it returned.
    param([scriptblock]$Code)
    $captured = @(& $Code 6>&1)
    $text = ($captured | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { $_.MessageData.ToString() }) -join "`n"
    [pscustomobject]@{ Text = $text; Returned = @($captured | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] }) }
}
function Test-PortReachable {
    # What a scoring engine would experience, worked out from the pretend firewall (same logic as Test-ActFirewall.ps1)
    param([int]$Port)
    foreach ($prof in $global:FW.FwProfiles.Values) {
        if ($prof.Enabled -ne 'True') { continue }
        $rules = @($global:FW.FwRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' -and ($_.Profile -eq 'Any' -or $_.Profile -like "*$($prof.Name)*") })
        $covers = { param($rule, $want) ($rule.Protocol -eq 'TCP' -or $rule.Protocol -eq 'Any') -and ($rule.LocalPort -eq 'Any' -or $rule.LocalPort -eq "$want") }
        if (@($rules | Where-Object { $_.Action -eq 'Block' -and (& $covers $_ $Port) }).Count -gt 0) { return $false }
        if ($prof.DefaultInboundAction -eq 'Allow') { continue }
        if ($prof.AllowInboundRules -ne 'True') { return $false }
        if (@($rules | Where-Object { $_.Action -eq 'Allow' -and (& $covers $_ $Port) -and $_.RemoteAddress -eq 'Any' }).Count -eq 0) { return $false }
    }
    $true
}
# four little fix functions of our own, for the stop rules of the batch (a real fix is a New-* or Request-* function too)
function New-TestOkAction {
    param([string]$Tag = 'ok')
    New-Action -Id "test.ok:$Tag" -Title "Test ok $Tag" -Risk 'Low' -Will @('pretend change') -Data @{ Tag = $Tag } `
        -Apply { param($d, $before) $null = $before; [void]$script:TestLog.Add($d.Tag); "ran $($d.Tag)" }
}
function New-TestFailAction {
    New-Action -Id 'test.fail' -Title 'Test fail' -Risk 'Low' -Will @('pretend change that fails') -Apply { param($d, $before) $null = $d, $before; throw 'pretend failure' }
}
function New-TestRedAction {
    New-Action -Id 'test.red' -Title 'Test red' -Risk 'Low' -Will @('pretend change that breaks Jenkins') `
        -Apply { param($d, $before) $null = $d, $before; $script:ProbeRed = @('Jenkins'); 'Jenkins is down now' }
}
function New-TestHighAction {
    New-Action -Id 'test.high' -Title 'Test high' -Risk 'High' -TypeWord 'GO' -Will @('pretend risky change') -Apply { param($d, $before) $null = $d, $before; [void]$script:TestLog.Add('high'); 'ran high' }
}
function Request-TestNothing { $null }
function New-TestRow {
    param([string]$Subject, [string]$Do, [hashtable]$With = @{}, [string]$Blocked = '', [bool]$Batch = $true)
    $fix = $null
    if ($Do) { $fix = New-FixRef $Do $With }
    New-Finding -Phase 9 -Area 'Test' -Severity 'WARN' -Subject $Subject -Why 'a test row' -Fix $fix -Blocked $Blocked -Batch $Batch
}

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The audit' -ForegroundColor Cyan
Start-Fresh
$rows = @(Update-Audit)
Assert-True ($rows.Count -gt 40 -and @($script:Hp.Findings).Count -eq $rows.Count) "Update-Audit judges the whole pretend box and keeps the rows ($($rows.Count))"
Assert-True ($null -ne $script:Hp.Facts -and @($script:Hp.Facts.Errors).Count -eq 0) 'and keeps the facts, without collector errors'
Assert-True (@($rows | Where-Object { $script:PhaseOrder -notcontains $_.Phase }).Count -eq 0) 'every row belongs to a phase that the window and the menu list'
Assert-True ((Get-PhaseFindings 2).Count -gt 5 -and @(Get-PhaseFindings 2 | Where-Object { $_.Phase -ne 2 }).Count -eq 0) 'Get-PhaseFindings picks one phase'
Assert-Equal (Get-PhaseFindings 0).Count $rows.Count 'phase 0 means all rows'
Assert-Equal (Get-PhaseName 4) 'Firewall' 'phase 4 is called Firewall'
Assert-Equal (Get-PhaseName 9) 'Routine' 'phase 9 is called Routine'
Assert-Equal (Get-PhaseName 5) 'Phase 5' 'an unknown phase still gets a label'
$fwBefore = $script:Hp.Facts.Firewall
$accBefore = $script:Hp.Facts.Accounts
[void](Update-Audit -Sections @('Accounts'))
Assert-True ([object]::ReferenceEquals($script:Hp.Facts.Firewall, $fwBefore) -and -not [object]::ReferenceEquals($script:Hp.Facts.Accounts, $accBefore)) 'reading only "Accounts" again keeps the firewall facts and replaces the account facts'
Assert-Equal @($script:Hp.Findings).Count $rows.Count 'and the rows are judged again from the mix'
[void](Update-AfterChange @())
Assert-True ([object]::ReferenceEquals($script:Hp.Facts.Firewall, $fwBefore)) 'Update-AfterChange with no action does nothing'
[void](Update-AfterChange @('user.guest'))
Assert-True ([object]::ReferenceEquals($script:Hp.Facts.Firewall, $fwBefore)) 'a known action id reads again only its sections (the firewall is not one of them)'
[void](Update-AfterChange @('something.unknown:1'))
Assert-True (-not [object]::ReferenceEquals($script:Hp.Facts.Firewall, $fwBefore)) 'an action id the tool does not know reads EVERYTHING again'

Write-Host 'Can this row be fixed?' -ForegroundColor Cyan
$p = Get-FixProblem (Get-Row 'This box')
Assert-True ($p.Status -eq 'Skipped' -and $p.Text -match 'no automatic fix') 'an information row: Skipped, "no automatic fix"'
$p = Get-FixProblem (Get-Row 'plinktern')
Assert-True ($p.Status -eq 'Waiting' -and $p.Text) 'retiring plinktern waits for the new admin: Waiting, with the reason'
$p = Get-FixProblem (New-TestRow 'ghost' 'New-DoesNotExistAction')
Assert-True ($p.Status -eq 'Skipped' -and $p.Text -match 'not part of this version') 'a fix function that does not exist: Skipped, "not part of this version"'
Assert-True ($null -eq (Get-FixProblem (Get-Row 'Guest is enabled'))) 'the Guest row can be fixed now (no problem)'
Assert-True ((Format-FindingDetail (Get-Row 'Guest is enabled')) -match 'Fix: available') 'the detail text says a fix is available'
Assert-True ((Format-FindingDetail (Get-Row 'This box')) -match 'Fix: none') 'and for an information row: none'
Assert-True ((Format-FindingDetail (Get-Row 'plinktern')) -match 'not possible yet') 'and for a waiting row: not possible yet'
Assert-True ((Format-FindingDetail (Get-Row 'Guest is enabled')) -match 'Accounts' -and (Format-FindingDetail (Get-Row 'Guest is enabled')) -match 'phase 2') 'the detail names the phase and area'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Fix one row' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$guest = Get-Row 'Guest is enabled'
$script:Hp.AllowChanges = $false
$r = Invoke-FixFinding -Finding $guest
Assert-True ($r.Status -eq 'Blocked' -and $r.Message -match 'Audit mode' -and $global:FW.Users['Guest'].Enabled) 'audit mode: Blocked, nothing changed'
$script:Hp.AllowChanges = $true
$script:AskAnswer = $false
$r = Invoke-FixFinding -Finding $guest
Assert-True ($r.Status -eq 'Cancelled' -and $global:FW.Users['Guest'].Enabled) 'you say no: Cancelled, nothing changed'
$script:AskAnswer = $true
$script:Asked.Clear()
$r = Invoke-FixFinding -Finding $guest
Assert-True ($r.Status -eq 'Applied' -and -not $global:FW.Users['Guest'].Enabled) 'you say yes: Applied, Guest is disabled'
Assert-True ($script:Asked.Count -eq 1 -and $script:Asked[0].Text -match 'Guest') 'you were asked exactly once, with a preview that names the account'
Assert-Equal $r.ActionId 'user.guest' 'the result carries the id of the action'
Assert-True ($null -eq (Get-Row 'Guest is enabled')) 'the audit was read again: the row is gone'
$r = Invoke-FixFinding -Finding (Get-Row 'This box')
Assert-True ($r.Status -eq 'Skipped' -and $r.Message -match 'no automatic fix') 'a row with no fix: Skipped'
$r = Invoke-FixFinding -Finding (Get-Row 'plinktern')
Assert-True ($r.Status -eq 'Waiting' -and $global:FW.Users['plinktern'].Enabled) 'a waiting row: Waiting, and plinktern is untouched'
$r = Invoke-FixFinding -Finding (New-TestRow 'ghost' 'New-DoesNotExistAction')
Assert-True ($r.Status -eq 'Skipped' -and $r.Message -match 'not part of this version') 'a missing fix function: Skipped, not a crash'

Write-Host 'A fix that asks you something first' -ForegroundColor Cyan
$bb = Get-Row 'Blackbox IP not entered'
$script:TextQueue.Enqueue('')
$r = Invoke-FixFinding -Finding $bb
Assert-True ($r.Status -eq 'Cancelled' -and -not (Get-HpSetting 'BlackboxIp')) 'you type nothing: Cancelled'
$script:TextQueue.Enqueue('blackbox.local')
$r = Invoke-FixFinding -Finding $bb
Assert-True ($r.Status -eq 'Cancelled' -and $script:Notices.Count -eq 1) 'you type a name instead of an IP: Cancelled, with a message for you'
$script:TextQueue.Enqueue('172.16.5.5')
$r = Invoke-FixFinding -Finding $bb
Assert-True ($r.Status -eq 'Applied' -and (Get-HpSetting 'BlackboxIp') -eq '172.16.5.5') 'you type the IP: Applied, remembered'
Assert-True ($null -eq (Get-Row 'Blackbox IP not entered') -and $null -ne (Get-Row 'Blackbox 172.16.5.5')) 'the audit was read again: the row now says "Blackbox 172.16.5.5" and tested port 22'
Assert-True ($null -ne (Get-Row 'No backup SSH key yet')) 'and the next step (the SSH key) appeared'

Write-Host 'A fix function that throws' -ForegroundColor Cyan
function New-TestThrowsAction { throw 'cannot build this' }
$r = Invoke-FixFinding -Finding (New-TestRow 'throws' 'New-TestThrowsAction')
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'could not be prepared' -and $r.Message -match 'cannot build this') 'a fix that throws while it is built: Failed, with the reason'
function New-TestNoisyAction { 'some stray text'; 42; New-TestOkAction -Tag 'noisy' }
$r = Invoke-FixFinding -Finding (New-TestRow 'noisy' 'New-TestNoisyAction')
Assert-True ($r.Status -eq 'Applied' -and $script:TestLog -contains 'noisy') 'stray output from a fix function is ignored; the action is found'
function Remove-TestThing { [void]$script:TestLog.Add('BAD: ran Remove-TestThing') }
$r = Invoke-FixFinding -Finding (New-TestRow 'not allowed' 'Remove-TestThing')
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'may only call' -and $script:TestLog -notcontains 'BAD: ran Remove-TestThing') 'a finding cannot make the runner call any other function (only New-* and Request-*)'
$r = Invoke-FixFinding -Finding (New-TestRow 'a cmdlet' 'Remove-Item' @{ Path = 'x' })
Assert-True ($r.Status -eq 'Skipped') 'and a cmdlet name is not even a fix: Skipped'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The dead-man switch around firewall rows' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$allow = Get-Row 'Inbound TCP 3389: no HP allow rule'
$r = Invoke-FixFinding -Finding $allow -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and $r.Message -match 'not armed' -and $null -eq (Get-FakeRule 'HP-Allow-TCP-3389')) 'not armed: the gate refuses, no rule was created, nothing tried to arm it behind your back'
Assert-Equal (Get-DeadManClock) 0 'the clock reads 0 when nothing is armed'
$r = Invoke-DeadManButton -What Arm
Assert-True ($r.Status -eq 'Applied' -and (Get-DeadManClock) -gt 240) 'the Arm button arms it (about 5 minutes)'
Assert-True ($null -ne (Get-Row 'Dead-man switch is armed') -and $null -eq (Get-Row 'Dead-man switch is not armed')) 'and the Firewall phase row changed after the refresh'
Save-DeadManState -When (Get-Date).AddSeconds(90) -Minutes 5
Assert-True ((Get-DeadManClock) -le 90) 'now only 90 seconds are left (the file was rewritten by the test)'
$r = Invoke-FixFinding -Finding (Get-Row 'Inbound TCP 3389: no HP allow rule') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $null -ne (Get-FakeRule 'HP-Allow-TCP-3389')) 'with 90 seconds left a firewall row still runs'
Assert-True ((Get-DeadManClock) -gt 240) '... because the switch was extended first (less than 2 minutes left -> +5 minutes)'
Assert-True ($global:FW.Calls -contains 'Set-ScheduledTask NetCacheRestore') 'the scheduled task was moved too'
Save-DeadManState -When (Get-Date).AddSeconds(-5) -Minutes 5
$r = Invoke-FixFinding -Finding (Get-Row 'Inbound TCP 8080: no HP allow rule') -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and $null -eq (Get-FakeRule 'HP-Allow-TCP-8080')) 'if the time has already run out the switch is NOT extended silently: the row is refused'
$r = Invoke-DeadManButton -What Arm
Assert-True ($r.Status -eq 'Applied' -and (Get-DeadManClock) -gt 240) 'arming again works'
$r = Invoke-DeadManButton -What Extend
Assert-True ($r.Status -eq 'Applied') 'Extend works while armed'
$script:AskAnswer = $false
$r = Invoke-DeadManButton -What Disarm
Assert-True ($r.Status -eq 'Cancelled' -and (Get-DeadManClock) -gt 0) 'Keep changes: you say no -> still armed'
$script:AskAnswer = $true
$r = Invoke-DeadManButton -What Disarm
Assert-True ($r.Status -eq 'Applied' -and (Get-DeadManClock) -eq 0 -and -not $global:FW.Tasks2.ContainsKey('NetCacheRestore')) 'Keep changes: you say yes -> the task is gone'
$r = Invoke-DeadManButton -What Extend
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'not armed') 'Extend when nothing is armed: Failed, with the reason'
Assert-Throws { Invoke-DeadManButton -What 'Explode' } 'only Arm, Extend and Disarm are accepted'

Write-Host 'The confirm question is not enough: the switch is checked again after your answer' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$null = Invoke-DeadManButton -What Arm
$script:Hp.Ask = { param($Title, $Text, $TypeWord) $null = $Title, $Text, $TypeWord; Save-DeadManState -When (Get-Date).AddSeconds(-1) -Minutes 5; $true }   # you took so long that the switch fired
$r = Invoke-FixFinding -Finding (Get-Row 'Inbound TCP 3389: no HP allow rule')
Assert-True ($r.Status -eq 'Blocked' -and $r.Message -match 'passed|not armed' -and $null -eq (Get-FakeRule 'HP-Allow-TCP-3389')) 'you answer Yes after the time ran out: Blocked, nothing created'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Fix phase 4 in rounds (the firewall)' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$batch = @(Get-BatchPlan -Phase 4)
Assert-Equal $batch.Count 4 'round 1 offers 4 rows'
Assert-True (($batch | ForEach-Object { $_.Finding.Fix.Do }) -join ',' -eq 'New-ArmDeadManAction,New-AllowPortAction,New-AllowPortAction,New-FirewallLoggingAction') 'arm the switch, allow 3389, allow 8080, log dropped connections: in that order'
Assert-True (@($batch | Where-Object { -not $_.Tick }).Count -eq 0 -and @($batch | Where-Object { $_.Risk -eq 'High' }).Count -eq 0) 'all four are ticked (none is High risk)'
Assert-True ($batch[1].Title -match 'Allow inbound TCP 3389' -and $batch[1].Risk -eq 'Medium') 'each row shows the action title and its risk'
Assert-Equal (Get-BatchWaiting -Phase 4) 6 '6 rows (the other inbound rules) wait for the allow rules'
Assert-True (@($batch | Where-Object { $_.Finding.Subject -like 'Legacy FTP*' }).Count -eq 0) 'a waiting row is not offered yet'
$script:Asked.Clear()
$sum = Invoke-FixPhase -Findings @($batch | ForEach-Object { $_.Finding })
Assert-True ($sum.Applied -eq 4 -and $sum.Failed -eq 0 -and $sum.NotRun -eq 0 -and $sum.StoppedBecause -eq '') 'round 1: 4 applied, nothing failed, nothing left, not stopped'
Assert-Equal $script:Asked.Count 0 'no questions: you agreed in the dialog (-Confirmed), and none is High risk'
Assert-True ((Test-PortReachable 3389) -and (Test-PortReachable 8080)) 'both scored ports are reachable'
Assert-True ($null -ne (Get-FakeRule 'HP-Allow-TCP-3389') -and $null -ne (Get-FakeRule 'HP-Allow-TCP-8080')) 'the tool''s own allow rules exist'
Assert-True ((Get-DeadManClock) -gt 0) 'and the dead-man switch is armed'
Assert-True ((Format-PhaseSummary $sum) -match 'Applied: 4' -and (Format-PhaseSummary $sum) -match 'New-Arm|Arm the dead-man|Dead-man') 'the summary lists the rows'
$batch2 = @(Get-BatchPlan -Phase 4)
Assert-True ($batch2.Count -eq 6 -and @($batch2 | Where-Object { $_.Finding.Fix.Do -ne 'New-DisableRuleAction' }).Count -eq 0) 'round 2 offers the 6 "disable this inbound rule" rows that were waiting'
Assert-Equal (Get-BatchWaiting -Phase 4) 0 'nothing waits any more'
$sum2 = Invoke-FixPhase -Findings @($batch2 | ForEach-Object { $_.Finding })
Assert-True ($sum2.Applied -eq 6 -and $sum2.Failed -eq 0) 'round 2: 6 applied'
foreach ($name in 'Legacy FTP', 'Telnet Test', 'Dev Web', 'Remote Debug', 'WinRM Any', 'Temp SMB') {
    Assert-Equal (Get-FakeRule $name).Enabled 'False' "$name is disabled (not deleted)"
}
Assert-True ($global:FW.FwRules.Count -eq 12 + 2) 'no rule was deleted (12 original + 2 of ours)'
Assert-True ((Get-FakeRule 'CoreNet-DHCP-In').Enabled -eq 'True' -and (Get-FakeRule 'Jenkins 8080').Enabled -eq 'True' -and (Get-FakeRule 'RemoteDesktop-UserMode-In-TCP').Enabled -eq 'True') 'Core Networking, the Jenkins rule and the RDP rule are untouched'
Assert-True ((Test-PortReachable 3389) -and (Test-PortReachable 8080)) 'the scored ports are still reachable'
Assert-Equal @(Get-BatchPlan -Phase 4).Count 0 'round 3 has nothing left to batch'
Assert-True ($null -ne (Get-Row 'Outbound default is Allow') -and $null -eq (Get-Row 'Legacy FTP*')) 'the audit shows what is left: outbound (your decision) - the rules are gone from the list'
$journal = @(Get-JournalRecords)
Assert-True ($journal.Count -ge 10 -and @($journal | Where-Object { $_.Status -ne 'applied' }).Count -eq 0) "every change is in the journal ($($journal.Count) records, all applied)"

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Fix phase 2: what is ticked, and what asks you' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$batch = @(Get-BatchPlan -Phase 2)
$ticked = @($batch | Where-Object { $_.Tick } | ForEach-Object { $_.Finding.Fix.Do })
Assert-True ($ticked.Count -eq 2 -and $ticked -contains 'New-DisableGuestAction' -and $ticked -contains 'New-LockoutOffAction') 'ticked: disable Guest, lockout off'
$asks = @($batch | Where-Object { $_.Finding.Fix.Do -like 'Request-*' })
Assert-True ($asks.Count -ge 2 -and @($asks | Where-Object { $_.Tick }).Count -eq 0 -and $asks[0].Risk -eq 'asks you') 'retiring an account asks you for the master first, so it starts unticked'
Assert-True (@($batch | Where-Object { $_.Finding.Subject -like 'jmoney*' -or $_.Finding.Subject -like 'No new admin*' }).Count -eq 0) 'jmoney''s password and the new admin need your own judgement: never in a batch'
$sum = Invoke-FixPhase -Findings @($batch | Where-Object { $_.Tick } | ForEach-Object { $_.Finding })
Assert-True ($sum.Applied -eq 2 -and -not $global:FW.Users['Guest'].Enabled -and $global:FW.Lockout -eq 0) 'run: Guest is disabled and the lockout threshold is 0'
Assert-True ($null -eq (Get-Row 'Guest is enabled') -and $null -eq (Get-Row 'Account lockout is ON')) 'both rows are gone from the audit'
Assert-True (-not $global:FW.Users['jmoney'].Groups.Contains('Administrators') -and $global:FW.Users['jmoney'].Enabled) 'jmoney was not touched'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A batch stops when it should' -ForegroundColor Cyan
Start-Fresh
$ok1 = New-TestRow 'ok 1' 'New-TestOkAction' @{ Tag = '1' }
$ok2 = New-TestRow 'ok 2' 'New-TestOkAction' @{ Tag = '2' }
$bad = New-TestRow 'bad' 'New-TestFailAction'
$sum = Invoke-FixPhase -Findings @($ok1, $bad, $ok2)
Assert-True ($sum.Applied -eq 1 -and $sum.Failed -eq 1 -and $sum.NotRun -eq 1 -and $sum.StoppedBecause -match 'pretend failure') 'a failure stops the batch: 1 applied, 1 failed, 1 not run'
Assert-True (($script:TestLog -join ',') -eq '1') 'the row after the failure did not run'
Assert-True ((Format-PhaseSummary $sum) -match 'STOPPED' -and (Format-PhaseSummary $sum) -match 'bad') 'the summary says so'
$script:TestLog.Clear()
$nothing = New-TestRow 'cancelled' 'Request-TestNothing'
$sum = Invoke-FixPhase -Findings @($ok1, $nothing, $ok2)
Assert-True ($sum.Applied -eq 2 -and $sum.Cancelled -eq 1 -and $sum.StoppedBecause -eq '' -and ($script:TestLog -join ',') -eq '1,2') 'a cancelled question does NOT stop the batch'
$script:TestLog.Clear()
$info = New-TestRow 'info only' ''
$wait = New-TestRow 'waiting' 'New-TestOkAction' @{ Tag = 'w' } 'wait for something else'
$sum = Invoke-FixPhase -Findings @($ok1, $info, $wait, $ok2)
Assert-True ($sum.Applied -eq 2 -and $sum.Skipped -eq 2 -and $sum.StoppedBecause -eq '' -and ($script:TestLog -join ',') -eq '1,2') 'rows with no fix or still waiting are skipped, the batch goes on'
$script:TestLog.Clear()
$script:Hp.AllowChanges = $false
$sum = Invoke-FixPhase -Findings @($ok1, $ok2)
Assert-True ($sum.Applied -eq 0 -and $sum.Blocked -eq 1 -and $sum.NotRun -eq 1 -and $sum.StoppedBecause -match 'refused' -and $script:TestLog.Count -eq 0) 'audit mode: the first row is refused and the batch stops'
$script:Hp.AllowChanges = $true
$script:ProbeRed = @()
$script:TestLog.Clear()
$high = New-TestRow 'risky' 'New-TestHighAction'
$script:Asked.Clear()
$sum = Invoke-FixPhase -Findings @($ok1, $high, $ok2)
Assert-True ($sum.Applied -eq 3 -and $script:Asked.Count -eq 1 -and $script:Asked[0].Word -eq 'GO') 'a High-risk row inside a batch still asks you to type its word'
$script:TestLog.Clear()
$script:AskAnswer = $false
$sum = Invoke-FixPhase -Findings @($ok1, $high, $ok2)
Assert-True ($sum.Applied -eq 2 -and $sum.Cancelled -eq 1 -and $script:TestLog -notcontains 'high') 'and if you do not type it, that row is cancelled and the batch goes on'
$script:AskAnswer = $true

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Undo' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$null = Invoke-FixFinding -Finding (Get-Row 'Guest is enabled') -Confirmed
$null = Invoke-FixFinding -Finding (Get-Row 'Account lockout is ON') -Confirmed
$list = @(Get-UndoList)
Assert-True ($list.Count -eq 2 -and [int]$list[0].Id -gt [int]$list[1].Id -and $list[0].ActionId -eq 'rights.lockout') 'two undoable changes, newest first'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Lockout -eq 5) 'Undo (no number) undoes the newest: the lockout threshold is back to 5'
Assert-True ($null -ne (Get-Row 'Account lockout is ON') -and $null -eq (Get-Row 'Guest is enabled')) 'and the audit shows it: the lockout row is back, the Guest row is still gone'
$r = Invoke-Undo -Id ([int]$list[1].Id)
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Users['Guest'].Enabled -and $null -ne (Get-Row 'Guest is enabled')) 'Undo with a number undoes that one: Guest is enabled again'
Assert-Equal @(Get-UndoList).Count 0 'nothing is left to undo'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Nothing to undo') 'Undo with nothing in the journal: a plain message'
$r = Invoke-Undo -Id 999
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match '999') 'Undo of a number that does not exist: a plain message'
$r = Invoke-Undo -Id ([int]$list[0].Id)
Assert-Equal $r.Status 'Failed' 'a change that is already undone cannot be undone twice'
$script:Hp.AllowChanges = $false
$null = Invoke-FixFinding -Finding (Get-Row 'Guest is enabled') -Confirmed
$script:Hp.AllowChanges = $true
$null = Invoke-FixFinding -Finding (Get-Row 'Guest is enabled') -Confirmed
$script:Hp.AllowChanges = $false
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Blocked' -and -not $global:FW.Users['Guest'].Enabled) 'undo is a change too: in audit mode it is Blocked'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The text menu' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$shown = Get-HostText { Show-AuditConsole }
$list = @($shown.Returned)
Assert-True ($list.Count -eq @($script:Hp.Findings).Count) 'Show-AuditConsole returns the rows it printed, all of them'
Assert-True ($shown.Text -match '== 2 Accounts ==' -and $shown.Text -match '== 4 Firewall ==' -and $shown.Text -match '\[fix\]') 'it prints a heading per phase and marks the rows that can be fixed'
$guestNumber = 1 + [array]::IndexOf($list, (Get-Row 'Guest is enabled'))
Assert-True ($guestNumber -gt 1 -and $shown.Text -match ("(?m)^\s*$guestNumber\s+BAD\s+\[fix\]\s+Accounts: Guest is enabled")) "the printed number ($guestNumber) is the row's place in the returned list"
Assert-True ($shown.Text -match 'Changes are ALLOWED') 'it says whether changes are allowed'
$only = Get-HostText { Show-AuditConsole -Phase 4 }
Assert-True ($only.Text -notmatch '== 2 Accounts ==' -and $only.Text -match '== 4 Firewall ==' -and @($only.Returned).Count -eq (Get-PhaseFindings 4).Count) '-Phase 4 shows only the firewall'

$script:TextQueue.Enqueue([string]$guestNumber)
$script:TextQueue.Enqueue('q')
$script:Asked.Clear()
$menu = Get-HostText { Start-ConsoleMenu }
Assert-True (-not $global:FW.Users['Guest'].Enabled -and $script:Asked.Count -eq 1) 'typing the row number fixes that row (after one confirm question)'
Assert-True ($menu.Text -match 'Applied: Done\.') 'and prints the result'

Start-Fresh
[void](Update-Audit)
foreach ($c in 'd arm', 'p 4', 'p 4', 'j', 'zzz', '999', 'p', 'u', 'c', 'c', 'q') { $script:TextQueue.Enqueue($c) }
$menu = Get-HostText { Start-ConsoleMenu }
Assert-True ((Get-DeadManClock) -gt 0) 'd arm: the dead-man switch is armed'
Assert-True ((Get-FakeRule 'HP-Allow-TCP-3389') -and (Get-FakeRule 'HP-Allow-TCP-8080')) 'p 4 (first round): the allow rules exist'
Assert-True ($menu.Text -match 'Fix phase 4 Firewall' -and $menu.Text -match '6 more row\(s\) wait' -and $menu.Text -match '6 more row\(s\) can run now') 'it shows the rows, says that 6 wait, and afterwards that 6 can run now'
Assert-True ($menu.Text -match 'Applied: 3' -and $menu.Text -match 'Applied: 6') 'p 4 twice: round 1 applied 3 (the switch was armed by "d arm" already), round 2 applied 6'
Assert-True ($menu.Text -match '#\d+\s+\S+ \S+\s+applied') 'j: the journal is listed'
Assert-True ($menu.Text -match "I do not know 'zzz'" -and $menu.Text -match 'There is no row 999' -and $menu.Text -match 'Say which phase') 'unknown words, a row number that does not exist, and "p" alone get a plain answer'
Assert-Equal (Get-FakeRule 'Temp SMB').Enabled 'True' 'u: the newest change (the last disabled rule) was undone'
Assert-True ($script:Hp.AllowChanges) '... and the menu ends with changes ON'

Start-Fresh
$menu = Get-HostText { Start-ConsoleMenu }
Assert-True ($menu.Text -match 'No input: leaving the menu') 'when nobody types anything (closed input) the menu ends by itself after 5 empty answers'

Start-Fresh
[void](Update-Audit)
$script:Hp.AllowChanges = $false
$script:AskAnswer = $false
$script:TextQueue.Enqueue('c'); $script:TextQueue.Enqueue('q')
$menu = Get-HostText { Start-ConsoleMenu }
Assert-True (-not $script:Hp.AllowChanges) 'c: if you say no to "Allow changes", changes stay off'
Start-Fresh
[void](Update-Audit)
$batch = Get-HostText { Invoke-ConsolePhase -Phase 6 }
Assert-True ($batch.Text -match 'Nothing in phase 6') 'a phase with nothing to batch (the hunt rows are fixed one at a time) says so'
$script:Hp.AllowChanges = $true
[void](Invoke-FixPhase -Findings @(Get-BatchPlan -Phase 2 | Where-Object { $_.Tick } | ForEach-Object { $_.Finding }))
$batch = Get-HostText { Invoke-ConsolePhase -Phase 2 }
Assert-True ($batch.Text -match 'No row is ticked by default') 'when only "asks you" rows are left, nothing runs on its own'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 6, persistence: fix one row, the audit stops listing it, Undo brings it back' -ForegroundColor Cyan
function Test-RegValue { param([string]$Path, [string]$Name) $global:FW.Reg.ContainsKey((Get-FakeKey $Path) + '|' + $Name) }
function Get-RegValueData { param([string]$Path, [string]$Name) $global:FW.Reg[(Get-FakeKey $Path) + '|' + $Name] }
Start-Fresh
Add-FakePersistence
$script:Hp.DataDir = 'C:\ProgramData\NetCacheSvc'            # the quarantine folder is on the pretend disk; the journal keeps its own folder
[void](Update-Audit)
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Assert-Equal @(Get-BatchPlan -Phase 6).Count 0 'no phase 6 row is part of "Fix phase": every hiding place is fixed on its own'
$row = Get-Row "Startup entry 'Updater'*"
Assert-True ($row -and $null -eq (Get-FixProblem $row) -and (Format-FindingDetail $row) -match 'Fix: available') 'the Run value row can be fixed'
$j0 = @(Get-JournalRecords).Count
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not (Test-RegValue $runKey 'Updater') -and (Test-RegValue $runKey 'JenkinsHelper')) 'fixing it: that ONE value is deleted, the others stay (also the Jenkins helper)'
Assert-True ($null -eq (Get-Row "Startup entry 'Updater'*") -and $null -ne (Get-Row "Startup entry 'Beacon'*") -and $null -ne (Get-Row "Startup entry 'Sync'*")) 'the re-audit no longer lists it; the other startup rows are still there'
Assert-Equal @(Get-JournalRecords).Count ($j0 + 1) 'one journal record'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and (Test-RegValue $runKey 'Updater') -and $null -ne (Get-Row "Startup entry 'Updater'*")) 'Undo: the value is back and so is the row'

$startupDir = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
$global:FW.Hashes[(Get-FakeKey "$startupDir\evil.bat")] = 'CAFE' * 16
$row = Get-Row 'Startup file evil.bat*'
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $null -eq (Get-Row 'Startup file evil.bat*') -and $null -ne (Get-Row 'Startup file notes.lnk*')) 'a Startup file: moved to quarantine, its row is gone, the other file''s row stays'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and $null -ne (Get-Row 'Startup file evil.bat*')) 'Undo: the file is back and so is the row'

$row = Get-Row 'hosts entry: 172.16.5.5 blackbox*'
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $null -eq (Get-Row 'hosts entry: 172.16.5.5*') -and $null -ne (Get-Row 'hosts entry: 10.9.9.9*')) 'a hosts line: only that line goes, the other row stays'
$row = Get-Row 'Share Public*'
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $null -eq (Get-Row 'Share Public*') -and $null -ne (Get-Row 'Share Docs*')) 'a share: only that share stops being shared'
$row = Get-Row 'WMI CommandLineEventConsumer Updater*'
$script:Asked.Clear()
$r = Invoke-FixFinding -Finding $row
Assert-True ($r.Status -eq 'Applied' -and $script:Asked.Count -eq 1 -and $script:Asked[0].Text -match 'NO UNDO for' -and $script:Asked[0].Text -match 'does NOT recreate') 'a WMI subscription: you are asked first, and the question says there is no undo'
Assert-True ($null -eq (Get-Row 'WMI CommandLineEventConsumer Updater*') -and @(Get-UndoList | Where-Object { $_.ActionId -like 'persist.wmi:*' }).Count -eq 0) 'its row is gone, and it is not in the Undo list'
$row = Get-Row 'Winlogon Userinit*'
$script:Asked.Clear()
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($script:Asked.Count -eq 1 -and $script:Asked[0].Word -eq 'WINLOGON') 'a Winlogon value is High risk: even when the dialog already said yes, you must type WINLOGON'
Assert-True ($r.Status -eq 'Applied' -and (Get-RegValueData 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit') -eq 'C:\Windows\system32\userinit.exe,' -and $null -eq (Get-Row 'Winlogon Userinit*')) 'and it is set back to the Windows default text, not deleted'

Write-Host 'Phase 7, Defender: the policy value that blocks real-time protection goes before the switch' -ForegroundColor Cyan
$rtp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
Start-Fresh
$global:FW.Defender.RealTime = $false
Set-FakeReg $rtp 'DisableRealtimeMonitoring' 1
[void](Update-Audit)
$batch = @(Get-BatchPlan -Phase 7)
Assert-True ($batch.Count -eq 2 -and $batch[0].Finding.Fix.Do -eq 'New-RegistryValueAction' -and $batch[1].Finding.Fix.Do -eq 'New-DefenderSwitchAction') 'two rows in the batch: delete the policy value, then switch real-time protection on (in that order)'
Assert-True (@($batch | Where-Object { -not $_.Tick -or $_.Risk -eq 'High' }).Count -eq 0) 'both are ticked, neither is High risk'
$sum = Invoke-FixPhase -Findings @($batch | ForEach-Object { $_.Finding })
Assert-True ($sum.Applied -eq 2 -and $sum.Failed -eq 0 -and $sum.StoppedBecause -eq '' -and $global:FW.Defender.RealTime -and -not (Test-RegValue $rtp 'DisableRealtimeMonitoring')) 'run: both applied, real-time protection is on, the policy value is gone'
Assert-True ($null -eq (Get-Row 'Registry switches Defender off*') -and (Get-Row 'Real-time protection').Severity -eq 'OK') 'and the audit is green again'
Start-Fresh
$global:FW.Defender.RealTime = $false
Set-FakeReg $rtp 'DisableRealtimeMonitoring' 1
[void](Update-Audit)
$rows = @(Get-BatchPlan -Phase 7 | ForEach-Object { $_.Finding })
$sum = Invoke-FixPhase -Findings @($rows[1], $rows[0])
Assert-True ($sum.Applied -eq 0 -and $sum.Failed -eq 1 -and $sum.NotRun -eq 1 -and $sum.StoppedBecause -match 'policy' -and -not $global:FW.Defender.RealTime -and (Test-RegValue $rtp 'DisableRealtimeMonitoring')) 'in the wrong order the switch fails with the policy message, the batch stops, and nothing is half done'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Every fix a judge can name exists' -ForegroundColor Cyan
$names = @()
foreach ($f in Microsoft.PowerShell.Management\Get-ChildItem -Path (Join-Path $script:HpRoot 'lib') -Filter 'Judge*.ps1') {
    $names += @([regex]::Matches([IO.File]::ReadAllText($f.FullName), "New-FixRef '([A-Za-z0-9-]+)'") | ForEach-Object { $_.Groups[1].Value })
}
$names = @($names | Select-Object -Unique)
Assert-True ($names.Count -ge 20) "the judges name $($names.Count) different fix functions"
$missing = @($names | Where-Object { -not $ExecutionContext.SessionState.InvokeCommand.GetCommand($_, [System.Management.Automation.CommandTypes]::Function) })
Assert-True ($missing.Count -eq 0) ('every one of them is defined' + $(if ($missing.Count) { '  MISSING: ' + ($missing -join ', ') } else { '' }))
Assert-True (@($names | Where-Object { $_ -notmatch '^(Request|New)-' }).Count -eq 0) 'and every one is a Request-* or New-* function'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The launcher (Start-Hardening.ps1), run as a separate PowerShell' -ForegroundColor Cyan
$shell = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$launcher = Join-Path $script:HpRoot 'Start-Hardening.ps1'
$out = (& $shell -NoProfile -ExecutionPolicy Bypass -File $launcher -LoadOnly 2>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 0 -and $out.Trim() -eq '') "-LoadOnly: every library loads in order, with no output and no error ($($out.Trim()))"
$dataDir = Join-Path ([IO.Path]::GetTempPath()) ('hp-launch-' + [guid]::NewGuid().ToString('N'))
[void]$script:Dirs.Add($dataDir)
$out = (& $shell -NoProfile -ExecutionPolicy Bypass -File $launcher -Journal -DataDir $dataDir 2>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 0 -and $out -match 'journal is empty') '-Journal on a new data folder: "the journal is empty"'
$out = (& $shell -NoProfile -ExecutionPolicy Bypass -File $launcher -NoGui -Phase 1 -DataDir $dataDir 2>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 0 -and $out -match '== 1 Recon ==' -and $out -match 'Could not read') '-NoGui on a machine where every Windows command is missing: a red row per failed collector, no crash'
Assert-True ($out -notmatch 'Unhandled|at <ScriptBlock>|CommandNotFound') '... and no raw PowerShell error text'
$out = (& $shell -NoProfile -ExecutionPolicy Bypass -File $launcher -Undo 5 -DataDir $dataDir 2>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 0 -and $out -match 'Failed: Change #5 cannot be undone') '-Undo 5 with an empty journal: a plain message'

foreach ($d in $script:Dirs) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
Write-TestSummary
