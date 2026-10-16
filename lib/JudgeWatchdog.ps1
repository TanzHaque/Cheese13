# JudgeWatchdog.ps1 - phase 8: the watchdog.
# Watchdog.ps1 is run once a minute by the SYSTEM task NetCacheWatch (installed from this phase, see Act-Watchdog.ps1). It keeps Remote Desktop,
# the scoring user, Jenkins and the two firewall allow rules alive, and writes alerts.log when the box changes.
# The rows say whether it is installed and running, what its last pass found and which alerts it raised in the last hour.
# Some rows are controls: install, remove, pause, resume, take the baseline again, accept the Jenkins job files.
# A judge only reads the facts it is given (Get-WatchdogFacts in Collect.ps1). Windows PowerShell 5.1, plain ASCII.

$script:WatchdogScoredChecks = @('rdp', 'jmoney', 'jenkins', 'firewall')       # the checks that guard scoring: when one fails the row is red

function Get-WatchdogFindings {
    param($Facts, $Settings)
    $null = $Settings
    $w = $Facts.Watchdog
    if (-not $w) { return @() }
    $out = @()
    $out += Get-WatchdogStateFindings $Facts $w
    if ($w.TaskFound) {
        $out += Get-WatchdogCheckFindings $w
        $out += Get-WatchdogAlertFindings $w
        $out += Get-WatchdogControlFindings $w
    }
    $out
}

# ---------------------------------------------------------------- is it installed, does the task look right, is it running?
function Get-WatchdogStateFindings {
    param($Facts, $W)
    $install = New-FixRef 'New-InstallWatchdogAction'
    if (-not $W.TaskFound) {
        if (-not $W.SourceFound) {
            return @(New-Finding 8 'Watchdog' 'WARN' 'Watchdog.ps1 or Panic.ps1 not found' 'The watchdog cannot be installed: Watchdog.ps1 and Panic.ps1 must be in the same folder as Start-Hardening.ps1. Copy both there and audit again.')
        }
        if ($W.CopyFound) {
            return @(New-Finding 8 'Watchdog' 'WARN' 'Watchdog task is missing' "The watchdog was installed once (the folder $($W.Dir) exists) but its scheduled task $script:WatchdogTaskName is gone: it was removed, or someone deleted it. Nothing watches the box now. Install it again." $install)
        }
        return @(New-Finding 8 'Watchdog' 'WARN' 'Watchdog is not installed' 'Nothing watches the box between your own checks. The watchdog is a task that runs once a minute as SYSTEM: it puts Remote Desktop, the scoring user, Jenkins and the two firewall allow rules back when they break, and it writes alerts.log when accounts, groups, tasks, services or the audit policy change. Install it when the Accounts and Firewall phases are done, so it guards the finished state. It never sets a password and never stops anything.' $install)
    }

    $out = @()
    $state = Get-OwnTaskState $script:WatchdogTaskName '\' $W.TaskAction $Facts.OwnTasks
    $enabled = ($W.TaskState -ne 'Disabled')
    if ($state -eq 'Fake') {
        $out += New-Finding 8 'Watchdog' 'BAD' 'Watchdog task runs something else' "The task $script:WatchdogTaskName exists, but it does not run exactly the tool's copy of Watchdog.ps1 (it runs something else, or another action was added). It runs as $($W.TaskUser) and starts: $($W.TaskAction). If you did not change it, an intruder did: a SYSTEM task that runs their file every minute is a perfect hiding place. Install again: that replaces the task with the real one (Undo puts the old definition back)." $install -Batch $false
    }
    if (-not $enabled) {
        $out += New-Finding 8 'Watchdog' 'WARN' 'Watchdog task is disabled' "The task $script:WatchdogTaskName is Disabled, so it never runs. Someone switched it off. Install again to replace it with an enabled one." $install
    }
    if ($W.TaskUser -and $W.TaskUser -notmatch '(?i)^(NT AUTHORITY\\)?SYSTEM$|^S-1-5-18$') {
        $out += New-Finding 8 'Watchdog' 'WARN' 'Watchdog task does not run as SYSTEM' "The task runs as '$($W.TaskUser)'. The repairs (services, firewall, accounts) need SYSTEM. Install again to replace the task." $install
    }
    if ($W.TaskInterval -and $W.TaskInterval -ne 'PT1M') {
        $out += New-Finding 8 'Watchdog' 'WARN' 'Watchdog task does not run every minute' "Windows reports the repeat interval of the task as '$($W.TaskInterval)' (one minute is PT1M). Install again to replace the task." $install
    }
    if (-not $W.CopyFound) {
        $out += New-Finding 8 'Watchdog' 'BAD' 'Watchdog script is missing' "The task exists, but its script (Watchdog.ps1 or Panic.ps1 in $($W.Dir)) is gone, so every run fails and nothing is watched. Install again." $install
    } elseif ($W.SourceFound -and -not $W.CopyCurrent) {
        $out += New-Finding 8 'Watchdog' 'WARN' "The installed watchdog differs from the tool's copy" "Watchdog.ps1 or Panic.ps1 in $($W.Dir) is not the same file as the one next to the tool. Either you edited the original after installing (then install again to use the new version), or someone changed the installed copy, which runs as SYSTEM every minute. Install again to put the tool's version back." $install
    }
    $configured = [string]$W.ConfigHome
    $found = $(if ($Facts.Jenkins) { [string]$Facts.Jenkins.Home } else { '' })
    if ($found -and $configured -ne $found) {
        $told = $(if ($configured) { "the folder $configured" } else { 'no Jenkins folder' })
        $out += New-Finding 8 'Watchdog' 'WARN' 'Watchdog does not know where Jenkins keeps its job files' "The watchdog was told $told, but the audit found Jenkins in $found. Until it knows, the Jenkins job files are not watched. Install again to tell it." $install -Batch $false
    }

    if ($enabled -and -not $W.StatusFound) {
        $out += New-Finding 8 'Watchdog' 'WARN' 'Watchdog has not finished a pass yet' "There is no status.json in $($W.Dir) yet. Right after installing this is normal: the first pass starts at once and takes up to a minute (the first one also takes the baseline). Audit again. If it stays like this, run Watchdog.ps1 by hand to see the error (RUNBOOK.md section 10)."
    } elseif ($enabled -and $W.StatusAge -gt 180) {
        $minutes = [int]($W.StatusAge / 60)
        $out += New-Finding 8 'Watchdog' 'BAD' 'Watchdog is not running' "The last pass finished at $($W.StatusTime), $minutes minutes ago. A pass should finish every minute. The task state is '$($W.TaskState)'. The script may be failing, or the task is not firing: run Watchdog.ps1 by hand to see the error (RUNBOOK.md section 10), or install again."
    } elseif ($enabled) {
        $repairs = $(if ($W.PausedUntil -gt 0) { "PAUSED until $($W.PausedText)" } elseif ($W.HealOn) { 'ON' } else { 'OFF' })
        $baseline = $(if ($W.BaselineText) { "The baseline was taken at $($W.BaselineText)." } else { 'No baseline yet.' })
        $out += New-Finding 8 'Watchdog' 'OK' 'Watchdog is running' "Pass $($W.Pass) finished $($W.StatusAge) seconds ago (at $($W.StatusTime)). Repairs are $repairs; $($W.Heals) repair(s) so far. $baseline"
    }
    $out
}

# ---------------------------------------------------------------- what the last pass found
function Get-WatchdogCheckFindings {
    param($W)
    $out = @()
    if (-not $W.StatusFound) { return $out }
    $failing = @($W.Checks | Where-Object { -not $_.Ok })
    foreach ($c in $failing) {
        $since = $(if ($c.SinceText) { " (failing since $($c.SinceText))" } else { '' })
        if ($script:WatchdogScoredChecks -contains $c.Name) {
            $repair = 'The watchdog repairs this by itself. If it keeps failing, something undoes the repair or the repair does not fit: read alerts.log and use Panic.ps1 (RUNBOOK.md).'
            if ($W.PausedUntil -gt 0) { $repair = "Repairs are PAUSED until $($W.PausedText), so nothing is repaired until then. Press Fix on the row 'Repairs are paused' to switch them on now." }
            elseif (-not $W.HealOn) { $repair = 'Repairs are switched off, so nothing is repaired.' }
            $out += New-Finding 8 'Watchdog checks' 'BAD' "Check failing: $($c.Name)" "$($c.Detail)$since. This guards scoring. $repair"
        } elseif ($c.Name -eq 'jobs') {
            $out += New-Finding 8 'Watchdog checks' 'WARN' 'Check failing: jobs' "$($c.Detail)$since. If YOU changed those Jenkins jobs, accept the new files (Fix). If you did not, put a job's last good config.xml back with Watchdog.ps1 -RestoreJob NAME and then use 'Reload Configuration from Disk' in Jenkins (RUNBOOK.md section 10)." (New-FixRef 'New-WatchdogNoteAction' @{ Kind = 'AcceptJobs' }) -Batch $false
        } else {
            $out += New-Finding 8 'Watchdog checks' 'WARN' "Check failing: $($c.Name)" "$($c.Detail)$since. The watchdog only reports this one; it repairs nothing here. The matching phase (accounts, Defender, backup) has the fix."
        }
    }
    $total = @($W.Checks).Count
    if ($failing.Count -eq 0 -and $total -gt 0) {
        $out += New-Finding 8 'Watchdog checks' 'OK' 'All checks pass' "$total check(s) passed in the last pass: $(@($W.Checks | ForEach-Object { $_.Name }) -join ', ')."
    }
    foreach ($d in @($W.Diffs)) {
        $out += New-Finding 8 'Baseline' 'WARN' "Differs from the baseline: $($d.Name) ($($d.Count))" "The box is different from the baseline in '$($d.Name)': $($d.Lines). A '+' is new since the baseline, a '-' is gone. Each difference is also an ALERT line in alerts.log. If you caused it, take the baseline again (row below); if not, find out who did."
    }
    $out
}

# ---------------------------------------------------------------- alerts.log, the last hour
function Get-WatchdogAlertFindings {
    param($W)
    $out = @()
    $all = @($W.Alerts)
    $count = @{ ALERT = 0; DOWN = 0; HEAL = 0; UP = 0 }
    foreach ($a in $all) { if ($count.ContainsKey([string]$a.Level)) { $count[[string]$a.Level]++ } }
    $text = $(if ($all.Count -eq 0) { "alerts.log has no lines yet ($($W.AlertsFile))." } else { "In the last $($all.Count) line(s) of alerts.log: $($count.ALERT) ALERT, $($count.HEAL) HEAL (a repair), $($count.DOWN) DOWN (a check failed), $($count.UP) UP (a check is fine again). Fresh ALERT and HEAL lines are rows below; the whole file is $($W.AlertsFile)." })
    $out += New-Finding 8 'Alerts' 'INFO' 'alerts.log' $text

    $fresh = @($all | Where-Object { @('ALERT', 'HEAL', 'DOWN') -contains [string]$_.Level -and [int]$_.AgeMinutes -le 60 } | Sort-Object -Property Time -Descending | Select-Object -First 12)
    $seen = @{}
    foreach ($a in $fresh) {
        $subject = "$($a.Time) $($a.Level): $(Get-ShortText ([string]$a.Text) 90)"
        if ($seen.ContainsKey($subject)) { continue }
        $seen[$subject] = $true
        $severity = $(if ($a.Level -eq 'DOWN') { 'INFO' } else { 'WARN' })
        $out += New-Finding 8 'Alerts' $severity $subject "The watchdog wrote at $($a.Time): $($a.Level) $($a.Text)"
    }
    $out
}

# ---------------------------------------------------------------- the controls (a row with a fix is a button)
function Get-WatchdogControlFindings {
    param($W)
    $out = @()
    if ($W.PausedUntil -gt 0) {
        $out += New-Finding 8 'Controls' 'WARN' 'Repairs are paused' "The watchdog still checks and writes alerts, but it repairs nothing until $($W.PausedText). Fix switches repairs on again now." (New-FixRef 'New-WatchdogNoteAction' @{ Kind = 'Resume' }) -Batch $false
    } else {
        $out += New-Finding 8 'Controls' 'INFO' 'Pause repairs for 10 minutes' 'Press Fix before you change Remote Desktop, the user jmoney, Jenkins or the two firewall allow rules ON PURPOSE. Otherwise the watchdog puts the old settings back within a minute. The checks and the alerts go on; repairs switch on again by themselves after 10 minutes.' (New-FixRef 'New-WatchdogNoteAction' @{ Kind = 'Pause'; Minutes = 10 }) -Batch $false
    }
    if ($W.RebaselineNote) {
        $out += New-Finding 8 'Controls' 'INFO' 'A new baseline is waiting' 'The note is written; the watchdog takes the new baseline at its next pass (within a minute).'
    } else {
        $when = $(if ($W.BaselineText) { "The current one was taken at $($W.BaselineText)." } else { 'There is none yet.' })
        $out += New-Finding 8 'Controls' 'INFO' 'Take the baseline again' "The baseline is a picture of the box (accounts, groups, ports, tasks, services, startup entries, shares, routes, firewall rules). Every 5 minutes the watchdog compares the box with it, and every difference is an alert. $when The first baseline can already contain what an intruder left, or what you were about to remove. Take it again when the Accounts, Firewall and Hunt phases are finished and you are happy with the result. It replaces the old one at the next pass." (New-FixRef 'New-WatchdogNoteAction' @{ Kind = 'Rebaseline' }) -Batch $false
    }
    if ($W.AcceptJobsNote) {
        $out += New-Finding 8 'Controls' 'INFO' 'Accepting the Jenkins job files is waiting' 'The note is written; the watchdog takes the job files as they are now at its next pass (within a minute).'
    }
    $out += New-Finding 8 'Controls' 'INFO' 'Remove the watchdog' "Press Fix to delete the task $script:WatchdogTaskName. Then nothing is checked, repaired or reported. The folder with alerts.log and the baseline stays. Undo puts the task back." (New-FixRef 'New-RemoveWatchdogAction') -Batch $false
    $out
}
