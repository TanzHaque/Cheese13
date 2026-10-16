# DeadMan.ps1 - the dead-man switch for firewall changes (and, later, network isolation).
#
# Idea: before a risky network change, save the working firewall policy and schedule a SYSTEM task for a few minutes
# from now that puts it back (it runs Panic.ps1 -FromTask). If the change cuts you off, you do nothing and the box
# repairs itself. If the change is fine, you click "Keep changes" and the task is removed.
# Firewall-type actions refuse to run unless the switch is armed and has more than 60 seconds left (see Invoke-Change).
#
# Needs $script:HpRoot (the folder that holds Panic.ps1); Start-Hardening.ps1 sets it.
# Windows PowerShell 5.1, plain ASCII.

$script:DeadManTaskName = 'NetCacheRestore'

function Get-DeadManPaths {
    # One place that knows the file names. Panic.ps1 uses the same names.
    $dir = Join-Path $script:Hp.DataDir 'deadman'
    @{
        Dir      = $dir
        Export   = Join-Path $dir 'fw-before.wfw'       # firewall policy exported just before arming
        Panic    = Join-Path $dir 'Panic.ps1'           # private copy of Panic.ps1; the task runs THIS copy
        State    = Join-Path $dir 'armed.json'          # when it was armed and when it fires
        Fired    = Join-Path $dir 'fired.json'          # written by Panic.ps1 when the task ran
        Adapters = Join-Path $dir 'adapters.txt'        # network adapters that were up when armed
    }
}

function Test-DeadManTask {
    [bool](Get-ScheduledTask -TaskName $script:DeadManTaskName -ErrorAction SilentlyContinue)
}

function Get-DeadManStatus {
    # Armed = a state file exists AND the scheduled task exists AND the fire time has not passed.
    # The fire time is stored as "seconds since 1970" because PowerShell 7 turns date-looking JSON text into dates.
    $p = Get-DeadManPaths
    $armed = $false; $left = 0; $firesAt = ''; $note = 'not armed'
    if (Test-Path $p.State) {
        try {
            $st = [System.IO.File]::ReadAllText($p.State) | ConvertFrom-Json
            $fires = [DateTimeOffset]::FromUnixTimeSeconds([long]$st.FiresEpoch)
            $left = [int][math]::Floor(($fires - [DateTimeOffset]::Now).TotalSeconds)
            $firesAt = [string]$st.FiresAt
            if (-not (Test-DeadManTask)) { $note = 'the scheduled task is MISSING (someone deleted it?) - arm again' }
            elseif ($left -le 0) { $note = 'the time has passed; the task has fired or is about to'; $left = 0 }
            else { $armed = $true; $note = "fires in $left seconds" }
        } catch { $note = 'the state file is unreadable - arm again' }
    }
    $fired = ''
    if (Test-Path $p.Fired) {
        try { $fired = [string]([System.IO.File]::ReadAllText($p.Fired) | ConvertFrom-Json).Time } catch { $fired = 'unknown time' }
    }
    [pscustomobject]@{ Armed = $armed; SecondsLeft = $left; FiresAt = $firesAt; Note = $note; FiredAt = $fired }
}

function Get-DeadManBlocker {
    # '' when firewall-type changes may go ahead, otherwise the reason they may not.
    $s = Get-DeadManStatus
    if (-not $s.Armed) { return "The dead-man switch is not armed ($($s.Note)). Arm it first: it restores the firewall if you lose access." }
    if ($s.SecondsLeft -lt 60) { return "The dead-man switch fires in $($s.SecondsLeft) seconds. Extend it first." }
    ''
}

function Get-DeadManClock {
    # Seconds until the switch fires (0 = not armed, or the time has passed). Reads only the small state file, with no
    # scheduled-task query, so the window can ask every second. Get-DeadManStatus is the full check.
    $p = Get-DeadManPaths
    if (-not (Test-Path $p.State)) { return 0 }
    try {
        $st = [System.IO.File]::ReadAllText($p.State) | ConvertFrom-Json
        $left = [int][math]::Floor(([DateTimeOffset]::FromUnixTimeSeconds([long]$st.FiresEpoch) - [DateTimeOffset]::Now).TotalSeconds)
        return [math]::Max($left, 0)
    } catch { return 0 }
}

function Save-DeadManState {
    # The little file the GUI countdown reads.
    param([datetime]$When, [int]$Minutes)
    $p = Get-DeadManPaths
    $epoch = ([DateTimeOffset]$When).ToUnixTimeSeconds()
    $state = @{ FiresEpoch = $epoch; FiresAt = $When.ToString('HH:mm:ss'); Minutes = $Minutes }
    [System.IO.File]::WriteAllText($p.State, (ConvertTo-Json -InputObject $state))
}

function Enable-DeadMan {
    # Arms the switch. If it is already armed this only EXTENDS it, so the saved known-good export is never overwritten
    # by a policy that might already be broken.
    param([int]$Minutes = 0)
    if ($Minutes -le 0) { $Minutes = [int](Get-HpSetting 'DeadManMinutes') }
    if ((Get-DeadManStatus).Armed) { Update-DeadMan -Minutes $Minutes; return }
    $p = Get-DeadManPaths
    if (-not (Test-Path $p.Dir)) { New-Item -ItemType Directory -Path $p.Dir -Force | Out-Null }
    Remove-Item $p.Fired -ErrorAction SilentlyContinue

    # 1. save the working firewall policy
    & netsh.exe advfirewall export $p.Export | Out-Null
    if (-not (Test-Path $p.Export)) { throw 'The firewall policy export failed, so the switch was NOT armed.' }
    # 2. a private copy of Panic.ps1 for the task to run
    $source = Join-Path $script:HpRoot 'Panic.ps1'
    if (-not (Test-Path $source)) { throw "Panic.ps1 was not found next to the tool ($source), so the switch was NOT armed." }
    Copy-Item $source $p.Panic -Force
    # 3. which adapters are up now (Panic turns them back on if network isolation was used)
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name })
    Set-Content -Path $p.Adapters -Value $up -Encoding ASCII
    # 4. the SYSTEM task that fires in N minutes
    $when = (Get-Date).AddMinutes($Minutes)
    $arg  = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -FromTask -StateDir "{1}"' -f $p.Panic, $p.Dir
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $trigger   = New-ScheduledTaskTrigger -Once -At $when
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $script:DeadManTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    # 5. the state file the GUI countdown reads
    Save-DeadManState -When $when -Minutes $Minutes
    Write-HpLog ('dead-man switch ARMED: the firewall is restored at ' + $when.ToString('HH:mm:ss') + ' unless you click Keep changes')
}

function Update-DeadMan {
    # Moves the fire time to N minutes from now (the export is kept).
    param([int]$Minutes = 5)
    $p = Get-DeadManPaths
    if (-not (Test-Path $p.State)) { throw 'The switch is not armed, so there is nothing to extend.' }
    $when = (Get-Date).AddMinutes($Minutes)
    Set-ScheduledTask -TaskName $script:DeadManTaskName -Trigger (New-ScheduledTaskTrigger -Once -At $when) | Out-Null
    Save-DeadManState -When $when -Minutes $Minutes
    Write-HpLog ('dead-man switch EXTENDED: now fires at ' + $when.ToString('HH:mm:ss'))
}

function Disable-DeadMan {
    # "Keep changes": removes the task. The firewall export stays on disk as a last-known-good copy.
    $p = Get-DeadManPaths
    Unregister-ScheduledTask -TaskName $script:DeadManTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $p.State -ErrorAction SilentlyContinue
    Write-HpLog 'dead-man switch DISARMED (changes kept)'
}

# ---------------------------------------------------------------- the three buttons, as actions (so they use the same gate and journal)
function New-ArmDeadManAction {
    param([int]$Minutes = 5)
    New-Action -Id 'deadman.arm' -Title "Arm the dead-man switch ($Minutes minutes)" -Risk 'Low' `
        -Will @("Save the current firewall policy to the data folder (netsh advfirewall export)",
                "Schedule a SYSTEM task that puts that policy back in $Minutes minutes unless you click Keep changes",
                'Change nothing else') `
        -Data @{ Minutes = $Minutes } `
        -Apply { param($d, $before) $null = $before; Enable-DeadMan -Minutes ([int]$d.Minutes) }
}

function New-ExtendDeadManAction {
    param([int]$Minutes = 5)
    New-Action -Id 'deadman.extend' -Title "Extend the dead-man switch (+$Minutes minutes from now)" -Risk 'Low' `
        -Will @("Move the restore time to $Minutes minutes from now") -Data @{ Minutes = $Minutes } `
        -Apply { param($d, $before) $null = $before; Update-DeadMan -Minutes ([int]$d.Minutes) }
}

function New-DisarmDeadManAction {
    New-Action -Id 'deadman.disarm' -Title 'Keep changes (disarm the dead-man switch)' -Risk 'Medium' `
        -Will @('Delete the scheduled restore task: the firewall changes become permanent',
                'Only do this after the NEIGH page shows RDP and Jenkins green') `
        -Apply { param($d, $before) $null = $d, $before; Disable-DeadMan }
}
