# Act-Watchdog.ps1 - phase 8 actions: install or remove the watchdog task, and leave it small notes (pause, resume, take the baseline
# again, accept the Jenkins job files). The watchdog itself is Watchdog.ps1; it repairs things later, by itself, once a minute.
# NOTHING in this file changes a password, a service, an account or a firewall rule.
# The task runs a COPY of Watchdog.ps1 from the data folder (only SYSTEM and Administrators can change files there), as SYSTEM.
# Windows PowerShell 5.1, plain ASCII.

# ---------------------------------------------------------------- install (also: install again = repair or update)
function New-InstallWatchdogAction {
    # Needs Watchdog.ps1 and Panic.ps1 next to the tool. Installing again replaces the task.
    $p = Get-WatchdogPaths
    $jenkinsHome = ''
    $facts = $script:Hp.Facts
    if ($facts -and $facts.Jenkins -and $facts.Jenkins.Home) { $jenkinsHome = [string]$facts.Jenkins.Home }
    $jenkinsLine = $(if ($jenkinsHome) { "Write the Jenkins folder into config.json: $jenkinsHome" } else { 'The audit did not find the Jenkins folder, so the Jenkins job files will not be watched' })
    New-Action -Id 'watchdog.install' -Title 'Install the watchdog (a SYSTEM task, every minute)' -Risk 'Medium' `
        -Will @("Copy Watchdog.ps1 and Panic.ps1 into $($p.Dir). The task runs these copies, so editing the originals changes nothing until you install again",
                $jenkinsLine,
                "Create the SYSTEM task '$($script:WatchdogTaskName)': one pass every minute (a pass may take 5 minutes at most), and start the first pass now",
                'Each pass checks Remote Desktop, the user jmoney, Jenkins and the two firewall allow rules, and repairs what is broken with the repairs from Panic.ps1. It never sets a password and never stops or deletes anything',
                'Every 5th pass it also compares the box with a baseline and checks Windows rights, Defender, the link to blackbox and the Jenkins job files. Those only raise alerts',
                "Alerts are written to $($p.Alerts)",
                'Installing again replaces the task. Undo puts the old task back, or removes the task when there was none (the folder with alerts.log stays)') `
        -Data @{ JenkinsHome = $jenkinsHome } `
        -Capture {
            param($d)
            $null = $d
            foreach ($name in 'Watchdog.ps1', 'Panic.ps1') {
                if (-not (Test-Path (Join-Path $script:HpRoot $name))) { throw "$name was not found next to the tool ($script:HpRoot), so the watchdog cannot be installed." }
            }
            $old = @(Get-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -ErrorAction SilentlyContinue) | Select-Object -First 1
            $xml = ''
            if ($old) { $xml = [string](Export-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\') }
            @{ HadTask = [bool]$old; Xml = $xml }
        } `
        -Apply {
            param($d, $before)
            $p = Get-WatchdogPaths
            $task = $script:WatchdogTaskName
            # 1. the folder and the two private copies
            if (-not (Test-Path $p.Dir)) { New-Item -ItemType Directory -Path $p.Dir -Force | Out-Null }
            Protect-DataDir                      # only SYSTEM and Administrators may change files that a SYSTEM task runs
            Copy-Item -Path (Join-Path $script:HpRoot 'Watchdog.ps1') -Destination $p.Script -Force
            Copy-Item -Path (Join-Path $script:HpRoot 'Panic.ps1') -Destination $p.Panic -Force
            # 2. what the tool found out: the Jenkins folder
            [System.IO.File]::WriteAllText($p.Config, (ConvertTo-Json -InputObject @{ JenkinsHome = [string]$d.JenkinsHome }))
            # 3. the task: a pass every minute, as SYSTEM
            $arg = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -DataDir "{1}"' -f $p.Script, $script:Hp.DataDir
            $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
            $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
            $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $task -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Network cache service check' -Force | Out-Null
            # 4. read it back: if Windows says the task does not repeat every minute, put the old state back and say so
            $back = @(Get-ScheduledTask -TaskName $task -TaskPath '\' -ErrorAction Stop) | Select-Object -First 1
            $trig = @($back.Triggers) | Select-Object -First 1
            $seen = ''
            if ($trig -and $trig.Repetition) { $seen = [string]$trig.Repetition.Interval }
            if ($seen -and $seen -ne 'PT1M') {
                & $script:UndoHandlers['watchdog.task'] $d $before
                throw "Windows reports the repeat interval '$seen' for the new task instead of PT1M (one minute), so the old state was put back. Create the task with schtasks instead (RUNBOOK.md section 10)."
            }
            # 5. the first pass now (a failure here is not fatal: the task starts by itself within a minute)
            try { Start-ScheduledTask -TaskName $task -TaskPath '\' } catch { Write-HpLog "the first watchdog pass could not be started now: $($_.Exception.Message)" 'WARN' }
            "The watchdog is installed. Audit again in a minute: phase 8 then shows whether it runs."
        } `
        -UndoKind 'watchdog.task'
}

# ---------------------------------------------------------------- remove
function New-RemoveWatchdogAction {
    New-Action -Id 'watchdog.remove' -Title 'Remove the watchdog task' -Risk 'Low' `
        -Will @("Delete the scheduled task '$($script:WatchdogTaskName)'. Then nothing is checked, repaired or reported (a pass that is running right now finishes)",
                'Leave the watchdog folder where it is: alerts.log, the baseline and the saved Jenkins job files stay',
                'Undo puts the task back from its saved definition') `
        -Capture {
            param($d)
            $null = $d
            $old = @(Get-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -ErrorAction SilentlyContinue) | Select-Object -First 1
            if (-not $old) { throw "There is no scheduled task '$($script:WatchdogTaskName)'." }
            @{ HadTask = $true; Xml = [string](Export-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\') }
        } `
        -Apply {
            param($d, $before)
            $null = $d, $before
            Unregister-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -Confirm:$false
            if (Get-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -ErrorAction SilentlyContinue) { throw 'The task is still there after Unregister-ScheduledTask.' }
            'The watchdog task is removed. The folder with alerts.log stays.'
        } `
        -UndoKind 'watchdog.task'
}

Register-UndoHandler 'watchdog.task' {
    # Puts the task back as it was (from the saved definition), or removes the task when there was none. Used by install and by remove.
    param($data, $before)
    $null = $data
    if ($before.HadTask) { Register-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -Xml ([string]$before.Xml) -Force | Out-Null }
    else { Unregister-ScheduledTask -TaskName $script:WatchdogTaskName -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- notes for the watchdog: it reads them at its next pass (within a minute)
function Get-WatchdogNoteFile {
    # The note file that belongs to a kind of note (read-only: it only builds a path).
    param([string]$Kind)
    $p = Get-WatchdogPaths
    switch ($Kind) {
        'Pause'      { $p.PauseFile }
        'Resume'     { $p.PauseFile }
        'Rebaseline' { $p.RebaseFlag }
        'AcceptJobs' { $p.AcceptFlag }
    }
}

function New-WatchdogNoteAction {
    # Pause: repairs stop for N minutes (checks and alerts go on). Resume: repairs on again. Rebaseline: the watchdog takes the baseline again.
    # AcceptJobs: the watchdog takes the Jenkins job files as they are now. This action only writes (or removes) one small note file.
    param([Parameter(Mandatory)][ValidateSet('Pause', 'Resume', 'Rebaseline', 'AcceptJobs')][string]$Kind, [int]$Minutes = 10)
    $title = ''; $will = @(); $noUndo = ''
    switch ($Kind) {
        'Pause' {
            $title = "Pause the watchdog's repairs for $Minutes minutes"
            $will = @("Write the note pause.txt: for $Minutes minutes the watchdog repairs nothing (it still checks and writes alerts)", 'Undo (or the Resume row) takes the note away')
        }
        'Resume' {
            $title = "Switch the watchdog's repairs on again"
            $will = @('Delete the note pause.txt, so the watchdog repairs again from its next pass', 'Undo writes the old note back')
        }
        'Rebaseline' {
            $title = 'Take the watchdog baseline again'
            $will = @('Write the note rebaseline.flag. At its next pass the watchdog saves the box as it is then (accounts, groups, ports, tasks, services, startup entries, shares, routes, firewall rules) and counts differences from that moment',
                      'Differences it already reported stay in alerts.log')
            $noUndo = 'the old baseline is replaced at the next pass. Undo only takes the note away if the watchdog has not read it yet'
        }
        'AcceptJobs' {
            $title = 'Accept the Jenkins job files as they are now'
            $will = @('Write the note acceptjobs.flag. At its next pass the watchdog saves every Jenkins job file as the good copy, so changes you made on purpose stop raising alerts',
                      'Check the changed jobs first: a job that an intruder changed is accepted too')
            $noUndo = 'the saved good copies are replaced at the next pass. Undo only takes the note away if the watchdog has not read it yet'
        }
    }
    New-Action -Id ('watchdog.' + $Kind.ToLower()) -Title $title -Risk 'Low' -Will $will -NoUndo $noUndo -Data @{ Kind = $Kind; Minutes = $Minutes } `
        -Capture {
            param($d)
            $p = Get-WatchdogPaths
            if (-not (Test-Path $p.Dir)) { throw 'The watchdog is not installed (its folder does not exist).' }
            $file = Get-WatchdogNoteFile $d.Kind
            $existed = [bool](Test-Path $file)
            $text = ''
            if ($existed) { $text = [System.IO.File]::ReadAllText($file) }
            @{ Existed = $existed; Text = $text }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            $file = Get-WatchdogNoteFile $d.Kind
            if ($d.Kind -eq 'Resume') {
                Remove-Item -Path $file -ErrorAction SilentlyContinue
                if (Test-Path $file) { throw "The note $file could not be removed." }
                return 'Repairs are on again from the next pass.'
            }
            if ($d.Kind -eq 'Pause') { [System.IO.File]::WriteAllText($file, [string]([DateTimeOffset]::Now.ToUnixTimeSeconds() + 60 * [int]$d.Minutes)) }
            else { [System.IO.File]::WriteAllText($file, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) }
            if (-not (Test-Path $file)) { throw "The note $file was not written." }
            'Noted. The watchdog reads it at its next pass (within a minute).'
        } `
        -UndoKind 'watchdog.note'
}

Register-UndoHandler 'watchdog.note' {
    # Puts the note file back as it was: the old text, or no file at all.
    param($data, $before)
    $file = Get-WatchdogNoteFile $data.Kind
    if ($before.Existed) { [System.IO.File]::WriteAllText($file, [string]$before.Text) }
    else { Remove-Item -Path $file -ErrorAction SilentlyContinue }
}
