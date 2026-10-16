# Act-Hunt.ps1 - phase 6 actions: quarantine a service or a scheduled task. DISABLE, never delete: Undo puts it back.
# The plan's never-touch list (Jenkins, Java, Remote Desktop, the log collector, Windows itself, the tool's own dead-man and watchdog tasks)
# is checked again here, when the old state is read - not only in the judge - so a wrong click cannot break scoring.
# (A service in System32 is Windows itself and stays. A TASK that starts cmd.exe or powershell.exe from System32 is not Windows:
# that is exactly what a planted task looks like, so tasks are checked against the never-touch WORDS, not the Windows folder.)
# Nothing here kills a process: a program that is already running keeps running until you stop it yourself.
# Windows PowerShell 5.1, plain ASCII.

function Assert-ServiceMayChange {
    # Guard for Capture: refuses anything on the never-touch list (Test-ProtectedProgram is in JudgeHunt.ps1), the discovered
    # Jenkins service and the discovered log collector service.
    param([string]$Name, [string]$Exe)
    if (Test-ProtectedProgram $Name $Exe) { throw "Refused: '$Name' is on the never-touch list (Jenkins, Java, Remote Desktop, the log collector, Windows itself)." }
    $facts = $script:Hp.Facts
    if (-not $facts) { return }
    if ($facts.Jenkins -and [string]$facts.Jenkins.Service -ieq $Name) { throw 'Refused: this is the Jenkins service.' }
    foreach ($c in (Get-List $facts.Collector)) {
        if ([string]$c.Kind -eq 'service' -and [string]$c.Name -ieq $Name) { throw 'Refused: this is the log collector.' }
    }
}

function Assert-TaskMayChange {
    # Guard for Capture: the tool's own tasks (dead-man switch, watchdog) and tasks that run something on the never-touch list stay. A task under \Microsoft\ may be
    # disabled only when its command shows what the judge looks for there (a shell, an odd folder: Test-SuspiciousMicrosoftTask).
    param([string]$Path, [string]$Name, [string]$ActionText)
    if ($Path -eq '\' -and $Name -ieq $script:DeadManTaskName) { throw 'Refused: this is the tool''s own dead-man task.' }
    if ($Path -eq '\' -and $Name -ieq $script:WatchdogTaskName) { throw 'Refused: this is the tool''s own watchdog task (remove it with the Watchdog phase).' }
    if (Test-NeverTouchApp $Name $ActionText) { throw "Refused: '$Name' runs something on the never-touch list (Jenkins, Java, Remote Desktop, the log collector, Defender)." }
    if ($Path -like '\Microsoft\*' -and -not (Test-SuspiciousMicrosoftTask $ActionText)) {
        throw 'Refused: this task under \Microsoft\ looks like part of Windows (it starts no shell and nothing from an odd folder).'
    }
}

# ---------------------------------------------------------------- a service
function New-DisableServiceAction {
    param([string]$Name)
    New-Action -Id "svc.disable:$Name" -Title "Disable the service '$Name'" -Risk 'Medium' `
        -Will @("Stop the service '$Name' if it is running (it fails, and nothing changes, if other services depend on it)",
                'Set its start type to Disabled, so it cannot start again after a reboot or a crash',
                'The service and its files are NOT deleted',
                'Undo sets the old start type back and starts it again if it was running') `
        -Data @{ Name = $Name } `
        -Capture {
            param($d)
            $svc = @(Get-CimInstance Win32_Service | Where-Object { [string]$_.Name -eq $d.Name }) | Select-Object -First 1
            if (-not $svc) { throw "There is no service named '$($d.Name)'." }
            Assert-ServiceMayChange $d.Name (Get-ExePath ([string]$svc.PathName))
            if (@('Auto', 'Manual', 'Disabled') -notcontains [string]$svc.StartMode) { throw "Refused: the start mode '$($svc.StartMode)' belongs to a driver, not to a normal service." }
            @{ StartMode = [string]$svc.StartMode; State = [string]$svc.State; PathName = [string]$svc.PathName }
        } `
        -Apply {
            param($d, $before)
            if ([string]$before.State -eq 'Running') { Stop-Service -Name $d.Name }          # no -Force: dependent services are not stopped for you
            Set-Service -Name $d.Name -StartupType Disabled
            $after = @(Get-CimInstance Win32_Service | Where-Object { [string]$_.Name -eq $d.Name }) | Select-Object -First 1
            if (-not $after -or [string]$after.StartMode -ne 'Disabled') { throw "The service '$($d.Name)' is not Disabled after Set-Service." }
            if ([string]$after.State -ne 'Stopped') { throw "The service '$($d.Name)' is Disabled but still $($after.State). Stop it yourself (it cannot restart)." }
            "'$($d.Name)' is stopped and disabled."
        } `
        -UndoKind 'svc.disable'
}

Register-UndoHandler 'svc.disable' {
    param($data, $before)
    $type = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[[string]$before.StartMode]
    if (-not $type) { throw "Cannot restore the start mode '$($before.StartMode)'." }
    Set-Service -Name $data.Name -StartupType $type
    if ([string]$before.State -eq 'Running') { Start-Service -Name $data.Name }
}

# ---------------------------------------------------------------- a scheduled task
function New-DisableTaskAction {
    param([string]$Name, [string]$Path)
    New-Action -Id "task.disable:$Path$Name" -Title "Disable the scheduled task '$Path$Name'" -Risk 'Medium' `
        -Will @("Disable the task '$Path$Name': it stays in Task Scheduler but never starts",
                'A copy that is running right now keeps running (the tool does not kill processes)',
                'The task is NOT deleted. Its definition (XML) is saved in the journal. Undo enables it again') `
        -Data @{ Name = $Name; Path = $Path } `
        -Capture {
            param($d)
            $t = @(Get-ScheduledTask -TaskName $d.Name -TaskPath $d.Path -ErrorAction Stop) | Select-Object -First 1
            if (-not $t) { throw "There is no task '$($d.Path)$($d.Name)'." }
            $text = (@($t.Actions | ForEach-Object { (([string]$_.Execute) + ' ' + ([string]$_.Arguments)).Trim() })) -join ' ; '
            Assert-TaskMayChange $d.Path $d.Name $text
            @{ State = [string]$t.State; Actions = $text; Xml = [string](Export-ScheduledTask -TaskName $d.Name -TaskPath $d.Path) }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            Disable-ScheduledTask -TaskName $d.Name -TaskPath $d.Path | Out-Null
            $now = @(Get-ScheduledTask -TaskName $d.Name -TaskPath $d.Path -ErrorAction Stop) | Select-Object -First 1
            if ([string]$now.State -ne 'Disabled') { throw "The task is '$($now.State)', not Disabled, after Disable-ScheduledTask." }
            "'$($d.Path)$($d.Name)' is disabled."
        } `
        -UndoKind 'task.disable'
}

Register-UndoHandler 'task.disable' {
    # Enables the task again, unless it was already disabled before the tool touched it.
    param($data, $before)
    if ([string]$before.State -ne 'Disabled') { Enable-ScheduledTask -TaskName $data.Name -TaskPath $data.Path | Out-Null }
}
