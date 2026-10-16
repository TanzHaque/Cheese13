# Test-ActWatchdog.ps1 - the TOOL'S side of the watchdog (phase 8), against the pretend box:
#   - the collector (Get-WatchdogFacts) reads the task and the files the watchdog writes
#   - the judge (JudgeWatchdog.ps1) turns them into rows, including the rows that spot a tampered task or script
#   - the actions (lib\Act-Watchdog.ps1: install, remove, pause, resume, baseline, accept the job files) run through the real gate, Invoke-Change
#   - the hunt (phase 6) leaves the tool's own tasks alone, and a task that only borrows their name is flagged
# status.json and alerts.log are written here by hand, in the exact shape Watchdog.ps1 writes them (Test-Watchdog.ps1 proves, in a separate
# PowerShell, that the collector reads what the REAL watchdog writes).
# It does NOT prove that real Windows accepts these scheduled-task cmdlets the way the pretend box does (lab test, see README).
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
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$realRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:HpRoot = $realRoot
$script:Dirs = New-Object System.Collections.ArrayList
$script:Asked = New-Object System.Collections.ArrayList
$script:AskAnswer = $true

function Start-Fresh {
    # A brand-new pretend box and a new data folder; changes ON; the audit has been read once.
    $global:FW = New-FakeBox
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('hp-actwd-' + [guid]::NewGuid().ToString('N'))
    [void]$script:Dirs.Add($dir)
    Initialize-Hp -DataDir $dir -NoAcl
    $script:HpRoot = $realRoot
    $script:Asked.Clear()
    $script:AskAnswer = $true
    $script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $script:AskAnswer }
    $script:Hp.AllowChanges = $true
    [void](Update-Audit)
}
function Get-Phase8 { @($script:Hp.Findings | Where-Object { $_.Phase -eq 8 }) }
function Get-Row { param([string]$Subject) @($script:Hp.Findings | Where-Object { $_.Subject -like $Subject }) | Select-Object -First 1 }
function Get-RowCount { param([string]$Subject) @($script:Hp.Findings | Where-Object { $_.Subject -like $Subject }).Count }
function Update-Watchdog { [void](Update-Audit -Sections @('Watchdog', 'Tasks')) }
function Get-JournalCount { @(Get-JournalRecords).Count }
function Get-LastRecord { @(Get-JournalRecords)[-1] }
function Get-NowEpoch { [DateTimeOffset]::Now.ToUnixTimeSeconds() }

function Write-FakeStatus {
    # status.json exactly as Watchdog.ps1's Save-Status writes it. -Failing = the names of checks that fail.
    param([int]$AgeSeconds = 20, [string[]]$Failing = @(), [array]$Diffs = @(), [bool]$HealOn = $true, [int]$Pass = 7, [int]$Heals = 0, [string]$Detail = 'the check says so')
    $now = Get-NowEpoch
    $checks = @()
    foreach ($name in 'rdp', 'jmoney', 'jenkins', 'firewall', 'rights', 'defender', 'blackbox', 'jobs', 'builds') {
        $bad = ($Failing -contains $name)
        $checks += [pscustomobject]@{ Name = $name; Ok = (-not $bad); Detail = $(if ($bad) { $Detail } else { "$name is fine" }); Since = ($now - 300) }
    }
    $epoch = $now - $AgeSeconds
    $status = [pscustomobject]@{
        Version = 1; Time = [DateTimeOffset]::FromUnixTimeSeconds($epoch).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss'); Epoch = $epoch; Pass = $Pass
        HealOn = $HealOn; PausedUntil = 0; Heals = $Heals; BaselineTaken = ($now - 3600); Checks = $checks; Diffs = $Diffs
    }
    [System.IO.File]::WriteAllText((Get-WatchdogPaths).Status, (ConvertTo-Json -InputObject $status -Depth 5))
}
function Add-FakeAlert {
    # One line in alerts.log, in the format Watchdog.ps1's Write-Alert uses.
    param([string]$Level, [string]$Text, [double]$MinutesAgo = 1)
    $line = '{0} {1,-5} {2}' -f (Get-Date).AddMinutes(-$MinutesAgo).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Text
    [System.IO.File]::AppendAllText((Get-WatchdogPaths).Alerts, $line + [Environment]::NewLine)
}
function Install-ForTest {
    # Start fresh, install through the real gate, then pretend one watchdog pass finished a few seconds ago.
    Start-Fresh
    $r = Invoke-FixFinding -Finding (Get-Row 'Watchdog is not installed') -Confirmed
    if ($r.Status -ne 'Applied') { throw "the test setup could not install the watchdog: $($r.Message)" }
    Write-FakeStatus
    Update-Watchdog
}

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The collector on a box without a watchdog' -ForegroundColor Cyan
Start-Fresh
$w = $script:Hp.Facts.Watchdog
Assert-True ($null -ne $w) 'the audit has a Watchdog section'
Assert-True (@($script:Hp.Facts.Errors).Count -eq 0) 'and no collector failed'
Assert-True (-not $w.TaskFound -and -not $w.CopyFound -and -not $w.StatusFound -and $w.SourceFound) 'no task, no copies, no status; the two scripts are next to the tool'
Assert-Equal @($w.Alerts).Count 0 'no alerts'
Assert-Equal $script:Hp.Facts.OwnTasks['netcachewatch'] (Get-WatchdogPaths).Script 'the watchdog task must run the copy in the watchdog folder'
Assert-Equal $script:Hp.Facts.OwnTasks['netcacherestore'] (Get-DeadManPaths).Panic 'the dead-man task must run its private Panic.ps1'
Assert-True ((Get-WatchdogPaths).Dir -eq (Join-Path $script:Hp.DataDir 'watchdog')) 'the watchdog folder is <data folder>\watchdog'

Write-Host 'The judge: one row, an install button' -ForegroundColor Cyan
$rows = Get-Phase8
Assert-Equal $rows.Count 1 'phase 8 of a box without a watchdog has exactly one row'
$row = $rows[0]
Assert-True ($row.Subject -eq 'Watchdog is not installed' -and $row.Severity -eq 'WARN' -and $row.Fix.Do -eq 'New-InstallWatchdogAction' -and $row.Batch) 'a warning with an install fix that "Fix phase" may run'
Assert-True ($row.Why -match 'never sets a password' -and $row.Why -match 'SYSTEM') 'the text says what it is and what it never does'
$script:HpRoot = Join-Path ([IO.Path]::GetTempPath()) ('hp-empty-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:HpRoot | Out-Null
[void]$script:Dirs.Add($script:HpRoot)
Update-Watchdog
$row = Get-Row 'Watchdog.ps1 or Panic.ps1 not found'
Assert-True ($row -and -not $row.Fix) 'without the two scripts next to the tool there is no install fix, only the reason'
$script:HpRoot = $realRoot
Update-Watchdog
Assert-True ($null -ne (Get-Row 'Watchdog is not installed')) 'with the scripts back the install row is back'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Install: the gate, the preview and the result' -ForegroundColor Cyan
Start-Fresh
$row = Get-Row 'Watchdog is not installed'
$a = Resolve-Fix $row
Assert-True ($a.Id -eq 'watchdog.install' -and $a.Risk -eq 'Medium' -and $a.UndoKind -eq 'watchdog.task' -and -not $a.NeedsDeadMan) 'the action: id, medium risk, its undo, no dead-man switch needed (it touches no firewall rule)'
$will = $a.Will -join ' | '
Assert-True ($will -match 'SYSTEM' -and $will -match 'never sets a password' -and $will -match 'Undo puts the old task back') 'the preview says SYSTEM, "never sets a password" and what Undo does'
Assert-True ($will -match [regex]::Escape((Get-WatchdogPaths).Dir) -and $will -match 'Jenkins') 'and names the folder and the Jenkins folder'

$script:Hp.AllowChanges = $false
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch') -and -not (Test-Path (Get-WatchdogPaths).Script) -and (Get-JournalCount) -eq 0) 'audit mode: Blocked, no task, no copy, nothing journalled'
$script:Hp.AllowChanges = $true
$script:AskAnswer = $false
$r = Invoke-FixFinding -Finding $row
Assert-True ($r.Status -eq 'Cancelled' -and $script:Asked.Count -eq 1 -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'you say no: Cancelled, nothing changed'
Assert-True ($script:Asked[0].Text -match 'Undo: available' -and $script:Asked[0].Word -eq '') 'the question shows the preview and needs no typed word'
$script:AskAnswer = $true

$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Applied') 'confirmed: Applied'
$p = Get-WatchdogPaths
$t = $global:FW.Tasks2['NetCacheWatch']
Assert-True ($t.Principal.UserId -eq 'NT AUTHORITY\SYSTEM' -and $t.Principal.RunLevel -eq 'Highest') 'the task runs as SYSTEM with the highest level'
Assert-True ($t.Action.Execute -eq 'powershell.exe' -and $t.Action.Argument.Contains('-File "' + $p.Script + '"') -and $t.Action.Argument.Contains('-DataDir "' + $script:Hp.DataDir + '"')) 'it runs powershell.exe on the COPY in the data folder and says which data folder'
Assert-True ($t.Action.Argument -notmatch [regex]::Escape($realRoot)) 'and never on the original next to the tool'
Assert-True ($t.Trigger.RepetitionInterval -eq [timespan]::FromMinutes(1) -and ($null -eq $t.Trigger.RepetitionDuration -or $t.Trigger.RepetitionDuration -eq [timespan]::Zero)) 'it repeats every minute with no end time'
Assert-True ($t.Settings.ExecutionTimeLimit -eq [timespan]::FromMinutes(5) -and $t.Settings.MultipleInstances -eq 'IgnoreNew' -and $t.Settings.StartWhenAvailable) 'a pass may take 5 minutes, passes never overlap, a missed one runs when possible'
Assert-True ((Get-Sha256Hex $p.Script) -eq (Get-Sha256Hex (Join-Path $realRoot 'Watchdog.ps1'))) 'the copy of Watchdog.ps1 is identical to the original'
Assert-True ((Get-Sha256Hex $p.Panic) -eq (Get-Sha256Hex (Join-Path $realRoot 'Panic.ps1'))) 'the copy of Panic.ps1 is identical to the original'
$cfg = [System.IO.File]::ReadAllText($p.Config) | ConvertFrom-Json
Assert-Equal $cfg.JenkinsHome $script:Hp.Facts.Jenkins.Home 'config.json holds the Jenkins folder the audit found'
Assert-True ($global:FW.Calls -contains 'Start-ScheduledTask NetCacheWatch') 'the first pass was started at once'
$rec = Get-LastRecord
Assert-True ($rec.ActionId -eq 'watchdog.install' -and $rec.Status -eq 'applied' -and $rec.Before.HadTask -eq $false -and $rec.UndoKind -eq 'watchdog.task') 'the journal: applied, there was no task before, the undo is named'
Assert-True ($null -eq (Get-Row 'Watchdog is not installed') -and $null -ne (Get-Row 'Watchdog has not finished a pass yet')) 'the audit was read again: "installed, no pass yet"'
Assert-Equal (Get-RowCount 'Watchdog task is missing') 0 'and the task is no longer missing'

Write-Host 'Install: a sign-in problem and other failures leave nothing half done' -ForegroundColor Cyan
Start-Fresh
$global:FW.BreakRegister = $true
$r = Invoke-FixFinding -Finding (Get-Row 'Watchdog is not installed') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Access is denied' -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'Register-ScheduledTask refused: Failed, with the reason, and no task'
Assert-Equal (Get-LastRecord).Status 'failed' 'the journal says failed'
$global:FW.BreakRegister = $false
Start-Fresh
$empty = Join-Path ([IO.Path]::GetTempPath()) ('hp-empty-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $empty | Out-Null
[void]$script:Dirs.Add($empty)
$script:HpRoot = $empty
$r = Invoke-Change (New-InstallWatchdogAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Watchdog.ps1 was not found next to the tool' -and (Get-JournalCount) -eq 0 -and -not (Test-Path (Get-WatchdogPaths).Dir)) 'the scripts are missing: refused before anything is changed or journalled'
$script:HpRoot = $realRoot
Start-Fresh
$global:FW.BreakStartTask = $true
$r = Invoke-FixFinding -Finding (Get-Row 'Watchdog is not installed') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'the first pass cannot be started now: still Applied (the task starts by itself within a minute)'
Assert-True (@($script:Hp.LogLines | Where-Object { $_ -match 'first watchdog pass could not be started now' }).Count -eq 1) '... and the log says so'
$global:FW.BreakStartTask = $false
Start-Fresh
$global:FW.OddRepeat = $true
$r = Invoke-FixFinding -Finding (Get-Row 'Watchdog is not installed') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'PT5M' -and $r.Message -match 'schtasks' -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'Windows reports another repeat interval: Failed, the task is taken out again, the message names schtasks'
$global:FW.OddRepeat = $false

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A running watchdog: what the rows say' -ForegroundColor Cyan
Install-ForTest
$w = $script:Hp.Facts.Watchdog
Assert-True ($w.TaskFound -and $w.TaskUser -eq 'NT AUTHORITY\SYSTEM' -and $w.TaskInterval -eq 'PT1M' -and $w.CopyFound -and $w.CopyCurrent) 'the collector sees the task, SYSTEM, PT1M and two current copies'
Assert-True ($w.StatusFound -and $w.Pass -eq 7 -and $w.StatusAge -ge 15 -and $w.StatusAge -le 40 -and @($w.Checks).Count -eq 9) 'and the last pass: number 7, a few seconds old, nine checks'
Assert-True ($w.Checks[0].SinceText -match '^\d\d:\d\d:\d\d$' -and $w.BaselineText -match '^\d\d:\d\d:\d\d$') 'times are turned into a time of day for the rows'
$row = Get-Row 'Watchdog is running'
Assert-True ($row -and $row.Severity -eq 'OK' -and $row.Why -match 'Pass 7' -and $row.Why -match 'Repairs are ON') 'row: running, pass 7, repairs ON'
Assert-True ((Get-Row 'All checks pass').Severity -eq 'OK') 'row: all checks pass'
$bad = @(Get-Phase8 | Where-Object { $_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN' })
Assert-Equal $bad.Count 0 'a healthy watchdog has no BAD and no WARN row'
foreach ($c in @(
    @{ Subject = 'Pause repairs for 10 minutes'; Kind = 'Pause' }
    @{ Subject = 'Take the baseline again'; Kind = 'Rebaseline' }
    @{ Subject = 'Remove the watchdog'; Kind = '' })) {
    $r = Get-Row $c.Subject
    Assert-True ($r -and $r.Severity -eq 'INFO' -and $r.Fix -and -not $r.Batch) "control row '$($c.Subject)': a fix, and never part of 'Fix phase'"
    if ($c.Kind) { Assert-Equal $r.Fix.With.Kind $c.Kind "... it builds the '$($c.Kind)' note" }
}
Assert-Equal (Get-RowCount 'Repairs are paused') 0 'no "paused" row while not paused'

Write-Host 'Failing checks' -ForegroundColor Cyan
Write-FakeStatus -Failing @('rdp') -Detail 'TermService is Stopped'
Update-Watchdog
$row = Get-Row 'Check failing: rdp'
Assert-True ($row -and $row.Severity -eq 'BAD' -and $row.Why -match 'TermService is Stopped' -and $row.Why -match 'failing since \d\d:\d\d:\d\d' -and $row.Why -match 'repairs this by itself') 'a scoring check: BAD, the reason, since when, and that the watchdog repairs it'
Assert-True (-not $row.Fix) 'no button: the watchdog does the repair'
Assert-Equal (Get-RowCount 'All checks pass') 0 'and "all pass" is gone'
Write-FakeStatus -Failing @('rdp') -HealOn $false
Update-Watchdog
Assert-True ((Get-Row 'Check failing: rdp').Why -match 'Repairs are switched off') 'repairs off: the row says nothing is repaired'
Write-FakeStatus -Failing @('jmoney', 'jenkins', 'firewall')
Update-Watchdog
Assert-True (@('jmoney', 'jenkins', 'firewall' | Where-Object { (Get-Row "Check failing: $_").Severity -eq 'BAD' }).Count -eq 3) 'jmoney, jenkins and firewall are scoring checks too (BAD)'
Write-FakeStatus -Failing @('rights', 'defender', 'blackbox', 'builds')
Update-Watchdog
foreach ($n in 'rights', 'defender', 'blackbox', 'builds') {
    $r = Get-Row "Check failing: $n"
    Assert-True ($r -and $r.Severity -eq 'WARN' -and -not $r.Fix -and $r.Why -match 'only reports') "alert-only check '$n': WARN, no fix, says it repairs nothing"
}
Write-FakeStatus -Failing @('jobs') -Detail 'since the job files were last accepted: app (config.xml changed)'
Update-Watchdog
$row = Get-Row 'Check failing: jobs'
Assert-True ($row -and $row.Severity -eq 'WARN' -and $row.Fix.Do -eq 'New-WatchdogNoteAction' -and $row.Fix.With.Kind -eq 'AcceptJobs' -and -not $row.Batch) 'jobs: WARN with "accept the new files" as the fix, not part of Fix phase'
Assert-True ($row.Why -match 'RestoreJob' -and $row.Why -match 'Reload Configuration from Disk') 'and the text says how to put a job back'
Write-FakeStatus -Diffs @([pscustomobject]@{ Name = 'tasks'; Count = 2; Lines = '+Evil | \Evil || +Other' })
Update-Watchdog
$row = Get-Row 'Differs from the baseline: tasks (2)'
Assert-True ($row -and $row.Severity -eq 'WARN' -and -not $row.Fix -and $row.Why -match '\+Evil') 'a baseline difference: WARN with the lines, no fix'

Write-Host 'Pausing is visible, and Resume is offered' -ForegroundColor Cyan
Write-FakeStatus -Failing @('rdp')
[System.IO.File]::WriteAllText((Get-WatchdogPaths).PauseFile, [string]((Get-NowEpoch) + 600))
Update-Watchdog
$row = Get-Row 'Repairs are paused'
Assert-True ($row -and $row.Severity -eq 'WARN' -and $row.Fix.With.Kind -eq 'Resume' -and $row.Why -match '\d\d:\d\d:\d\d') 'paused: a WARN row with the end time and a Resume fix'
Assert-True ((Get-Row 'Check failing: rdp').Why -match 'PAUSED') 'a failing check says that repairs are paused'
Assert-Equal (Get-RowCount 'Pause repairs for 10 minutes') 0 'the "pause" row is replaced by the "paused" row'
Assert-True (($null -eq (Get-Row 'Watchdog is running')) -or (Get-Row 'Watchdog is running').Why -match 'PAUSED until') 'and the running row says PAUSED'
[System.IO.File]::WriteAllText((Get-WatchdogPaths).PauseFile, [string]((Get-NowEpoch) - 5))
Update-Watchdog
Assert-Equal (Get-RowCount 'Repairs are paused') 0 'a pause that has run out is no pause'
Remove-Item (Get-WatchdogPaths).PauseFile

Write-Host 'alerts.log: only fresh lines become rows' -ForegroundColor Cyan
Write-FakeStatus
Add-FakeAlert 'INFO' 'watchdog started (version 1)' 50
Add-FakeAlert 'ALERT' '[users] NEW: evil enabled=True' 4
Add-FakeAlert 'HEAL' 'rdp: repaired: TermService started' 9
Add-FakeAlert 'DOWN' 'rdp: DOWN: TermService is Stopped' 10
Add-FakeAlert 'UP' 'rdp: back up' 8
Add-FakeAlert 'ALERT' '[tasks] NEW: \Old' 180
Update-Watchdog
$fresh = @(Get-Phase8 | Where-Object { $_.Area -eq 'Alerts' -and $_.Subject -match '^\d{4}-' })
Assert-Equal $fresh.Count 3 'three fresh lines (ALERT, HEAL, DOWN) are rows; UP, INFO and the 3-hour-old ALERT are not'
Assert-True (@($fresh | Where-Object { $_.Subject -match ' ALERT: ' -and $_.Severity -eq 'WARN' }).Count -eq 1) 'an ALERT line is a WARN row'
Assert-True (@($fresh | Where-Object { $_.Subject -match ' HEAL: ' -and $_.Severity -eq 'WARN' }).Count -eq 1) 'a HEAL line (a repair happened = something broke) is a WARN row'
Assert-True (@($fresh | Where-Object { $_.Subject -match ' DOWN: ' -and $_.Severity -eq 'INFO' }).Count -eq 1) 'a DOWN line is an INFO row (the check rows show what is down NOW)'
Assert-True ($fresh[0].Subject -match ' ALERT: ' -and $fresh[2].Subject -match ' DOWN: ') 'the newest line is first'
$sum = Get-Row 'alerts.log'
Assert-True ($sum.Severity -eq 'INFO' -and $sum.Why -match '2 ALERT' -and $sum.Why -match '1 HEAL' -and $sum.Why -match '1 DOWN' -and $sum.Why -match '1 UP') 'the summary row counts every level'
for ($i = 1; $i -le 20; $i++) { Add-FakeAlert 'ALERT' "[ports] NEW: tcp $i" 2 }
Update-Watchdog
Assert-Equal @(Get-Phase8 | Where-Object { $_.Area -eq 'Alerts' -and $_.Subject -match '^\d{4}-' }).Count 12 'at most 12 alert rows'
Remove-Item (Get-WatchdogPaths).Alerts
Update-Watchdog
Assert-True ((Get-Row 'alerts.log').Why -match 'no lines yet') 'no alerts.log lines yet: the summary says so'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Tampering with the task or the scripts is noticed' -ForegroundColor Cyan
Install-ForTest
$global:FW.Tasks2['NetCacheWatch'].Action.Argument = '-NoProfile -File "C:\Users\Public\x.ps1"'
Update-Watchdog
$row = Get-Row 'Watchdog task runs something else'
Assert-True ($row -and $row.Severity -eq 'BAD' -and $row.Fix.Do -eq 'New-InstallWatchdogAction' -and -not $row.Batch -and $row.Why -match 'Public\\x\.ps1') 'another command under the same name: BAD, shows the command, the fix installs the real task, never in a batch'
Install-ForTest
$global:FW.Tasks2['NetCacheWatch'].ExtraActions = @(@{ Execute = 'C:\Users\Public\evil.exe'; Arguments = '' })
Update-Watchdog
$row = Get-Row 'Watchdog task runs something else'
Assert-True ($row -and $row.Severity -eq 'BAD' -and $row.Why -match 'evil\.exe' -and $row.Why -match 'another action was added') 'a second action added to the real task: BAD, and the row shows the added command'
Install-ForTest
$global:FW.Tasks2['NetCacheWatch'].State = 'Disabled'
Update-Watchdog
Assert-True ((Get-Row 'Watchdog task is disabled').Severity -eq 'WARN' -and (Get-Row 'Watchdog task is disabled').Fix.Do -eq 'New-InstallWatchdogAction') 'a disabled task: WARN, the fix installs again'
Assert-Equal (Get-RowCount 'Watchdog is not running') 0 'a disabled task is not also reported as "not running"'
Install-ForTest
$global:FW.Tasks2['NetCacheWatch'].Principal.UserId = 'BUILTIN\Users'
Update-Watchdog
Assert-True ($null -ne (Get-Row 'Watchdog task does not run as SYSTEM')) 'a task that runs as someone else: WARN'
Install-ForTest
$global:FW.Tasks2['NetCacheWatch'].Principal.UserId = 'SYSTEM'
Update-Watchdog
Assert-Equal (Get-RowCount 'Watchdog task does not run as SYSTEM') 0 'Windows calls the account just SYSTEM: that is fine'
$global:FW.Tasks2['NetCacheWatch'].Trigger.RepetitionInterval = [timespan]::FromMinutes(30)
Update-Watchdog
Assert-True ((Get-Row 'Watchdog task does not run every minute').Why -match 'PT30M') 'a task that repeats every 30 minutes: WARN with the value Windows reports'
Install-ForTest
[System.IO.File]::AppendAllText((Get-WatchdogPaths).Script, "`n# someone added this`n")
Update-Watchdog
Assert-True ((Get-Row "The installed watchdog differs from the tool's copy").Severity -eq 'WARN') 'a changed script copy: WARN'
Remove-Item (Get-WatchdogPaths).Panic
Update-Watchdog
Assert-True ((Get-Row 'Watchdog script is missing').Severity -eq 'BAD') 'a deleted script copy: BAD'
Install-ForTest
Write-FakeStatus -AgeSeconds 400
Update-Watchdog
$row = Get-Row 'Watchdog is not running'
Assert-True ($row -and $row.Severity -eq 'BAD' -and $row.Why -match '7 minutes ago') 'no pass finished for 400 seconds: BAD "not running", with the age (rounded to whole minutes)'
Assert-Equal (Get-RowCount 'Watchdog is running') 0 'and it is not also called running'
Write-FakeStatus -AgeSeconds 170
Update-Watchdog
Assert-Equal (Get-RowCount 'Watchdog is not running') 0 'a pass 170 seconds ago is still fine (limit 180)'
[System.IO.File]::WriteAllText((Get-WatchdogPaths).Config, '{"JenkinsHome":"D:\\Elsewhere"}')
Update-Watchdog
$row = Get-Row 'Watchdog does not know where Jenkins keeps its job files'
Assert-True ($row -and $row.Severity -eq 'WARN' -and $row.Why -match 'Elsewhere' -and -not $row.Batch) 'config.json holds another Jenkins folder than the audit found: WARN'
[System.IO.File]::WriteAllText((Get-WatchdogPaths).Config, '{"JenkinsHome":""}')
Update-Watchdog
Assert-True ((Get-Row 'Watchdog does not know where Jenkins keeps its job files').Why -match 'no Jenkins folder') 'config.json without a Jenkins folder: WARN, says so'
Remove-Item (Get-WatchdogPaths).Status
Update-Watchdog
Assert-True ($null -ne (Get-Row 'Watchdog has not finished a pass yet')) 'no status.json: "no pass yet"'
[System.IO.File]::WriteAllText((Get-WatchdogPaths).Status, '{ broken')
Update-Watchdog
Assert-True ($null -ne (Get-Row 'Watchdog has not finished a pass yet') -and @($script:Hp.Facts.Errors).Count -eq 0) 'a broken status.json is "no pass yet", not a crash'

Write-Host 'The task folder is the tool''s: the same name in another folder is not the watchdog' -ForegroundColor Cyan
Install-ForTest
$global:FW.Tasks += @{ TaskName = 'NetCacheWatch'; TaskPath = '\Microsoft\Windows\Maintenance\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'C:\Users\Public\evil.exe'; Arguments = '' }
Update-Watchdog
Assert-True ((Get-Row 'Watchdog is running') -and (Get-RowCount 'Watchdog task runs something else') -eq 0) 'the real task is judged by itself; a namesake in another folder does not confuse it'
$hunt = @(Get-HuntFindings $script:Hp.Facts $script:Hp.Settings)
$namesake = $hunt | Where-Object { $_.Subject -eq 'Task \Microsoft\Windows\Maintenance\NetCacheWatch' } | Select-Object -First 1
Assert-True ($namesake -and $namesake.Fix.Do -eq 'New-DisableTaskAction') 'the hunt flags the namesake like any other task, with the usual disable fix'
$r = Invoke-Change (New-DisableTaskAction -Name 'NetCacheWatch' -Path '\Microsoft\Windows\Maintenance\') -Confirmed
Assert-True ($r.Status -eq 'Applied') 'and that fix is allowed (the guard protects only the tool''s task in the root folder)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Install again repairs a tampered task, and Undo puts the tampered one back' -ForegroundColor Cyan
Install-ForTest
$evil = '-NoProfile -File "C:\Users\Public\x.ps1"'
$global:FW.Tasks2['NetCacheWatch'].Action.Argument = $evil
Update-Watchdog
$r = Invoke-FixFinding -Finding (Get-Row 'Watchdog task runs something else') -Confirmed
$p = Get-WatchdogPaths
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Tasks2['NetCacheWatch'].Action.Argument.Contains($p.Script)) 'installing again replaces the task with the real one'
Assert-Equal (Get-RowCount 'Watchdog task runs something else') 0 'and the BAD row is gone'
$rec = Get-LastRecord
Assert-True ($rec.Before.HadTask -eq $true -and $rec.Before.Xml -match '<Task>') 'the journal keeps the old task definition'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Tasks2['NetCacheWatch'].Action.Argument -eq $evil) 'Undo puts the old definition back exactly'
Install-ForTest
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'Undo of a first install removes the task'
Assert-True ((Test-Path (Get-WatchdogPaths).Script) -and (Test-Path (Get-WatchdogPaths).Config)) 'and leaves the watchdog folder (alerts and baseline are never thrown away)'
Update-Watchdog
Assert-True ($null -ne (Get-Row 'Watchdog task is missing')) 'the audit says: installed once, task gone'

Write-Host 'A repeat interval that Windows does not accept puts the OLD task back' -ForegroundColor Cyan
Install-ForTest
$old = $global:FW.Tasks2['NetCacheWatch'].Action.Argument
$global:FW.Tasks2['NetCacheWatch'].Action.Argument = $evil
$global:FW.OddRepeat = $true
$r = Invoke-Change (New-InstallWatchdogAction) -Confirmed
$global:FW.OddRepeat = $false
Assert-True ($r.Status -eq 'Failed' -and $global:FW.Tasks2.ContainsKey('NetCacheWatch') -and $global:FW.Tasks2['NetCacheWatch'].Action.Argument -eq $evil) 'the failed reinstall restored what was there before (not nothing)'
$global:FW.Tasks2['NetCacheWatch'].Action.Argument = $old

Write-Host 'Remove' -ForegroundColor Cyan
Install-ForTest
$row = Get-Row 'Remove the watchdog'
$a = Resolve-Fix $row
Assert-True ($a.Id -eq 'watchdog.remove' -and $a.Risk -eq 'Low' -and $a.UndoKind -eq 'watchdog.task' -and ($a.Will -join ' ') -match 'alerts.log') 'the action: low risk, undoable, says the folder stays'
$script:Hp.AllowChanges = $false
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'audit mode: the task stays'
$script:Hp.AllowChanges = $true
$r = Invoke-FixFinding -Finding $row -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch') -and (Test-Path (Get-WatchdogPaths).Script)) 'removed: the task is gone, the folder stays'
Assert-True ($null -ne (Get-Row 'Watchdog task is missing')) 'the audit says so'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and $global:FW.Tasks2.ContainsKey('NetCacheWatch') -and $global:FW.Tasks2['NetCacheWatch'].Principal.UserId -eq 'NT AUTHORITY\SYSTEM') 'Undo puts the task back'
$j0 = Get-JournalCount
$global:FW.Tasks2.Remove('NetCacheWatch')
$r = Invoke-Change (New-RemoveWatchdogAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'There is no scheduled task' -and (Get-JournalCount) -eq $j0) 'removing what is not there: refused before anything is journalled'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Notes: pause, resume, take the baseline again, accept the job files' -ForegroundColor Cyan
Install-ForTest
$p = Get-WatchdogPaths
$a = Resolve-Fix (Get-Row 'Pause repairs for 10 minutes')
Assert-True ($a.Id -eq 'watchdog.pause' -and $a.Risk -eq 'Low' -and $a.UndoKind -eq 'watchdog.note') 'pause: low risk, undoable'
$script:Hp.AllowChanges = $false
$r = Invoke-FixFinding -Finding (Get-Row 'Pause repairs for 10 minutes') -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and -not (Test-Path $p.PauseFile)) 'audit mode: no note is written'
$script:Hp.AllowChanges = $true
$r = Invoke-FixFinding -Finding (Get-Row 'Pause repairs for 10 minutes') -Confirmed
$until = [long]([System.IO.File]::ReadAllText($p.PauseFile))
Assert-True ($r.Status -eq 'Applied' -and $until -ge ((Get-NowEpoch) + 590) -and $until -le ((Get-NowEpoch) + 610)) 'pause 10: pause.txt holds the moment 10 minutes from now'
Assert-True ($null -ne (Get-Row 'Repairs are paused') -and (Get-RowCount 'Pause repairs for 10 minutes') -eq 0) 'the audit shows the pause'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and -not (Test-Path $p.PauseFile)) 'Undo takes the note away'
$r = Invoke-Change (New-WatchdogNoteAction -Kind Pause -Minutes 30) -Confirmed
$until = [long]([System.IO.File]::ReadAllText($p.PauseFile))
Assert-True ($r.Status -eq 'Applied' -and $until -ge ((Get-NowEpoch) + 1790) -and $until -le ((Get-NowEpoch) + 1810)) 'pause with another length: 30 minutes'
Update-Watchdog
$r = Invoke-FixFinding -Finding (Get-Row 'Repairs are paused') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not (Test-Path $p.PauseFile) -and $null -ne (Get-Row 'Pause repairs for 10 minutes')) 'Resume: pause.txt is gone and the "pause" row is back'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and (Test-Path $p.PauseFile) -and [long]([System.IO.File]::ReadAllText($p.PauseFile)) -eq $until) 'Undo of Resume writes the old pause back exactly'
Remove-Item $p.PauseFile

$a = Resolve-Fix (Get-Row 'Take the baseline again')
Assert-True ($a.Id -eq 'watchdog.rebaseline' -and $a.NoUndo -match 'old baseline is replaced') 'baseline: the preview warns that the old baseline is replaced'
$r = Invoke-FixFinding -Finding (Get-Row 'Take the baseline again') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Test-Path $p.RebaseFlag) -and $null -ne (Get-Row 'A new baseline is waiting') -and (Get-RowCount 'Take the baseline again') -eq 0) 'the note is written and the audit shows it is waiting'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and -not (Test-Path $p.RebaseFlag)) 'Undo takes the note away while the watchdog has not read it'

Write-FakeStatus -Failing @('jobs')
Update-Watchdog
$a = Resolve-Fix (Get-Row 'Check failing: jobs')
Assert-True ($a.Id -eq 'watchdog.acceptjobs' -and ($a.Will -join ' ') -match 'intruder changed is accepted too') 'accept jobs: the preview warns that a changed job is accepted as it is'
$r = Invoke-FixFinding -Finding (Get-Row 'Check failing: jobs') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Test-Path $p.AcceptFlag) -and $null -ne (Get-Row 'Accepting the Jenkins job files is waiting')) 'the note is written and the audit shows it is waiting'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and -not (Test-Path $p.AcceptFlag)) 'Undo takes it away'

Start-Fresh
$j0 = Get-JournalCount
$r = Invoke-Change (New-WatchdogNoteAction -Kind Pause) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'not installed' -and (Get-JournalCount) -eq $j0) 'a note without an installed watchdog is refused before anything is journalled'
Assert-Throws { New-WatchdogNoteAction -Kind 'Explode' } 'only the four known kinds of note exist'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 6, the hunt: the tool''s own tasks are left alone, a namesake is flagged' -ForegroundColor Cyan
Install-ForTest
$r = Invoke-DeadManButton -What 'Arm'
Assert-True ($r.Status -eq 'Applied') 'the dead-man switch is armed (setup)'
$hunt = @(Get-HuntFindings $script:Hp.Facts $script:Hp.Settings)
$mine = @($hunt | Where-Object { $_.Subject -like "Task \NetCache* (the tool's own)" })
Assert-Equal $mine.Count 2 'both of the tool''s tasks are listed once, as the tool''s own'
Assert-True (@($mine | Where-Object { $_.Severity -ne 'INFO' -or $_.Fix }).Count -eq 0) 'as INFO rows without a fix: there is no button that could disable them'
Assert-Equal @($hunt | Where-Object { $_.Subject -eq 'Task \NetCacheWatch' -or $_.Subject -eq 'Task \NetCacheRestore' }).Count 0 'and not also as ordinary suspicious tasks'
foreach ($n in 'NetCacheWatch', 'NetCacheRestore') {
    $j0 = Get-JournalCount
    $r = Invoke-Change (New-DisableTaskAction -Name $n -Path '\') -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Refused: this is the tool''s own' -and (Get-JournalCount) -eq $j0) "$n cannot be disabled by the Hunt fix (the guard refuses it, nothing is journalled)"
}
$global:FW.Tasks2['NetCacheRestore'].Action.Argument = '-File "C:\Users\Public\y.ps1"'
$global:FW.Tasks2['NetCacheWatch'].Action.Argument = '-File "C:\Users\Public\x.ps1"'
$script:Hp.Facts = Get-HpFacts
$hunt = @(Get-HuntFindings $script:Hp.Facts $script:Hp.Settings)
foreach ($n in 'NetCacheWatch', 'NetCacheRestore') {
    $row = $hunt | Where-Object { $_.Subject -like "Task \$n uses the name of the tool's own task" } | Select-Object -First 1
    Assert-True ($row -and $row.Severity -eq 'BAD' -and -not $row.Fix -and $row.Why -match 'intruder' -and $row.Why -match 'Disable-ScheduledTask') "$n with another command: a BAD row, no button, and the text says how to disable it by hand"
}
Install-ForTest
$r = Invoke-DeadManButton -What 'Arm'
$global:FW.Tasks2['NetCacheRestore'].ExtraActions = @(@{ Execute = 'C:\Users\Public\evil.exe'; Arguments = '' })
$script:Hp.Facts = Get-HpFacts
$hunt = @(Get-HuntFindings $script:Hp.Facts $script:Hp.Settings)
$row = $hunt | Where-Object { $_.Subject -like 'Task \NetCacheRestore uses the name of the tool''s own task' } | Select-Object -First 1
Assert-True ($r.Status -eq 'Applied' -and $row -and $row.Severity -eq 'BAD' -and $row.Why -match 'evil\.exe') 'a second action added to the dead-man task is flagged too'
Assert-True (@($hunt | Where-Object { $_.Subject -like '*NetCacheWatch*' -and $_.Severity -ne 'INFO' }).Count -eq 0) 'while the untouched watchdog task is still just the tool''s own'
$hunt = @(Get-HuntFindings ([pscustomobject]@{ Tasks = $script:Hp.Facts.Tasks; Errors = @() }) $script:Hp.Settings)
Assert-True (@($hunt | Where-Object { $_.Subject -like 'Task \NetCache*' -and $_.Subject -notlike '*uses the name*' }).Count -ge 1) 'facts without the list of own tasks: the old behaviour (an ordinary task row), no crash'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 8 in the window and the menu: names, order, batch, what is read again' -ForegroundColor Cyan
Assert-Equal $script:PhaseNames[8] 'Watchdog' 'phase 8 is called Watchdog'
Assert-True ($script:PhaseOrder -contains 8 -and [array]::IndexOf($script:PhaseOrder, 7) -lt [array]::IndexOf($script:PhaseOrder, 8) -and [array]::IndexOf($script:PhaseOrder, 8) -lt [array]::IndexOf($script:PhaseOrder, 9)) 'it comes after Defender and before Routine'
Assert-Equal (Get-PhaseName 8) 'Watchdog' 'Get-PhaseName knows it'
Assert-Equal (@(Get-SectionsForAction 'watchdog.install') -join ',') 'Watchdog,Tasks' 'installing re-reads the watchdog files and the task list'
Assert-Equal (@(Get-SectionsForAction 'watchdog.pause') -join ',') 'Watchdog,Tasks' '... and so does every note'
Assert-Equal (@(Get-SectionsForAction 'deadman.arm') -join ',') 'DeadMan,Firewall,Tasks' 'arming or disarming the dead-man switch re-reads the task list too (it adds and removes the task NetCacheRestore)'
Start-Fresh
$offered = @(Get-BatchPlan -Phase 8)
Assert-True ($offered.Count -eq 1 -and $offered[0].Tick -and $offered[0].Risk -eq 'Medium' -and $offered[0].Title -match 'Install the watchdog') 'Fix phase 8 offers the install, ticked, with its real risk'
$sum = Invoke-FixPhase -Findings @($offered | ForEach-Object { $_.Finding })
Assert-True ($sum.Applied -eq 1 -and $sum.Failed -eq 0 -and $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'and running it installs the watchdog'
Assert-Equal @(Get-BatchPlan -Phase 8).Count 0 'afterwards nothing is left to batch (the controls are never part of Fix phase)'
$r = Invoke-Undo
Assert-True ($r.Status -eq 'Undone' -and -not $global:FW.Tasks2.ContainsKey('NetCacheWatch')) 'the batch install can be undone like any other change'

Write-Host 'A judge that gets no watchdog facts says nothing and does not crash' -ForegroundColor Cyan
$none = @(Get-HpFindings -Facts ([pscustomobject]@{ Errors = @() }) -Settings $script:Hp.Settings -Phases 8)
Assert-Equal $none.Count 0 'no Watchdog facts: no rows'
$crash = @(Get-HpFindings -Facts ([pscustomobject]@{ Errors = @(); Watchdog = [pscustomobject]@{ TaskFound = $true } }) -Settings $script:Hp.Settings -Phases 8 | Where-Object { $_.Area -eq 'Judge' })
Assert-Equal $crash.Count 0 'half-empty Watchdog facts do not crash the judge'

foreach ($d in $script:Dirs) { Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue }
Write-TestSummary
