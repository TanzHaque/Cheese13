# LabGrade.ps1  -  LAB ONLY.  Grades the box against the decrypted answer key (used by Verify-Hardening.ps1 -Lab).
# Two steps per planted item:  Get-PlantFacts (reads the box, Windows only)  ->  Get-PlantVerdict (pure, testable anywhere).
# Verdicts:  FIXED  |  PARTIAL (mostly fixed, plan not followed to the letter)  |  MISSED  |  UNKNOWN (could not tell)
# Needs ScoreLib.ps1, VerifyJudgeAccounts.ps1 (Get-BareName) and VerifyFacts.ps1 (Get-RegValue) loaded first.

$script:StartupDirLab = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'

function New-Verdict {
    param([string]$Verdict, [string]$Note = '')
    [pscustomobject]@{ Verdict = $Verdict; Note = $Note }
}

# ---------------------------------------------------------------- 1. facts about one planted item (reads the box)
function Get-PlantFacts {
    param($p, [int]$LockoutThreshold = 0, [bool]$ProbePasswords = $true, [string]$JenkinsHome = '')
    $f = @{}
    switch ($p.Kind) {
        'User' {
            $u = Get-LocalUser -Name $p.Name -ErrorAction SilentlyContinue
            $f.Exists = [bool]$u
            $f.Enabled = $false; $f.InAdmins = $false; $f.PasswordWorks = $null
            if ($u) {
                $f.Enabled = [bool]$u.Enabled
                $f.InAdmins = (@(Get-LocalGroupNames 'Administrators' | ForEach-Object { Get-BareName $_ }) -contains $p.Name)
                if ($u.Enabled -and $p.Password -and $ProbePasswords) { $f.PasswordWorks = [bool](Test-LocalCredential -User $p.Name -Password $p.Password) }
            }
        }
        'Task' {
            $t = Get-ScheduledTask -TaskName $p.Name -TaskPath $p.Path -ErrorAction SilentlyContinue
            $f.Exists = [bool]$t
            $f.Disabled = ($t -and ([string]$t.State -eq 'Disabled'))
        }
        'RunKey'      { $f.Exists = ($null -ne (Get-RegValue $p.Key $p.Name)) }
        'StartupFile' { $f.Exists = (Test-Path (Join-Path $script:StartupDirLab $p.Name)) }
        'Service' {
            $s = Get-CimInstance Win32_Service -Filter "Name='$($p.Name)'" -ErrorAction SilentlyContinue
            $f.Exists = [bool]$s
            if ($s) { $f.StartMode = [string]$s.StartMode; $f.State = [string]$s.State }
        }
        'Wmi' {
            $n = $p.Name
            $f.Filter   = [bool](Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$n'" -ErrorAction SilentlyContinue)
            $f.Consumer = [bool](Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$n'" -ErrorAction SilentlyContinue)
            $f.Binding  = [bool](Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Filter -like "*$n*" -or $_.Consumer -like "*$n*" })
        }
        'Listener' {
            $f.Listening = [bool](Get-NetTCPConnection -LocalPort $p.Port -State Listen -ErrorAction SilentlyContinue)
            $t = Get-ScheduledTask -TaskName $p.Name -TaskPath '\' -ErrorAction SilentlyContinue
            $f.TaskExists = [bool]$t
            $f.TaskDisabled = ($t -and ([string]$t.State -eq 'Disabled'))
        }
        'Ifeo' { $f.Exists = [bool](Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($p.Name)" 'Debugger') }
        'Hosts' {
            $lines = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() })
            $f.Exists = ($lines -contains $p.Name)
        }
        'DefExclusion' { $f.Exists = (@((Get-MpPreference -ErrorAction Stop).ExclusionPath) -contains $p.Name) }
        'Share'        { $f.Exists = [bool](Get-SmbShare -Name $p.Name -ErrorAction SilentlyContinue) }
        'FwRule' {
            $r = @(Get-NetFirewallRule -DisplayName $p.Name -ErrorAction SilentlyContinue)
            $f.Exists = ($r.Count -gt 0)
            $f.AnyEnabled = (@($r | Where-Object { [string]$_.Enabled -eq 'True' }).Count -gt 0)
        }
        'Lockout' { $f.Threshold = $LockoutThreshold }
        'Guest'   { $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; $f.Enabled = [bool]($g -and $g.Enabled) }
        'JenkinsInit' {
            if (-not $JenkinsHome) { $f.Unknown = 'Jenkins home not recorded' }
            else { $f.Exists = (Test-Path (Join-Path (Join-Path $JenkinsHome 'init.groovy.d') $p.Name)) }
        }
        'JenkinsJob' {
            if (-not $JenkinsHome) { $f.Unknown = 'Jenkins home not recorded' }
            else {
                $cfg = Join-Path (Join-Path (Join-Path $JenkinsHome 'jobs') $p.Name) 'config.xml'
                $f.Exists = (Test-Path $cfg)
                $f.Disabled = ($f.Exists -and ((Get-Content $cfg -Raw) -match '<disabled>\s*true\s*</disabled>'))
            }
        }
        'JenkinsUser' {
            $r = Test-JenkinsLogin -HostName '127.0.0.1' -Port 8080 -User $p.Name -Password $p.Password
            if ($r.Status -eq 'PASS') { $f.LoginWorks = $true }
            elseif ($r.Detail -match 'refused') { $f.LoginWorks = $false }
            else { $f.Unknown = "Jenkins did not answer properly: $($r.Detail)" }
        }
        default { $f.Unknown = "no check written for kind '$($p.Kind)'" }
    }
    $f
}

# ---------------------------------------------------------------- 2. the verdict (pure)
function Get-PlantVerdict {
    param($p, $f)
    if ($f.ContainsKey('Unknown')) { return New-Verdict 'UNKNOWN' $f.Unknown }
    switch ($p.Kind) {
        'User' {
            if (-not $f.Exists) { return New-Verdict 'PARTIAL' 'account was DELETED - the plan says disable, never delete' }
            if ($f.Enabled) {
                $why = @('still enabled')
                if ($f.PasswordWorks) { $why += 'old password still works' }
                if ($f.InAdmins) { $why += 'still an administrator' }
                return New-Verdict 'MISSED' ($why -join ', ')
            }
            if ($f.InAdmins) { return New-Verdict 'PARTIAL' 'disabled, but still in Administrators (plan: remove from groups first)' }
            return New-Verdict 'FIXED' 'disabled'
        }
        'Task' {
            if (-not $f.Exists) { return New-Verdict 'FIXED' 'task is gone' }
            if ($f.Disabled)    { return New-Verdict 'FIXED' 'task is disabled' }
            return New-Verdict 'MISSED' 'task is still there and enabled'
        }
        'RunKey'      { if ($f.Exists) { return New-Verdict 'MISSED' 'Run value still present' } else { return New-Verdict 'FIXED' 'value removed' } }
        'StartupFile' { if ($f.Exists) { return New-Verdict 'MISSED' 'file still in the Startup folder' } else { return New-Verdict 'FIXED' 'file removed' } }
        'Service' {
            if (-not $f.Exists) { return New-Verdict 'FIXED' 'service is gone' }
            if ($f.StartMode -eq 'Disabled' -and $f.State -ne 'Running') { return New-Verdict 'FIXED' 'service is disabled' }
            if ($f.StartMode -eq 'Disabled') { return New-Verdict 'PARTIAL' 'start type is Disabled but it is still running' }
            return New-Verdict 'MISSED' "service still exists (start type $($f.StartMode))"
        }
        'Wmi' {
            $left = @(); if ($f.Filter) { $left += 'filter' }; if ($f.Consumer) { $left += 'consumer' }; if ($f.Binding) { $left += 'binding' }
            if ($left.Count -eq 0) { return New-Verdict 'FIXED' 'subscription removed' }
            if ($left.Count -lt 3) { return New-Verdict 'PARTIAL' "still present: $($left -join ', ')" }
            return New-Verdict 'MISSED' 'filter, consumer and binding all still there'
        }
        'Listener' {
            if ($f.Listening) { return New-Verdict 'MISSED' "port $($p.Port) is still listening" }
            if ($f.TaskExists -and -not $f.TaskDisabled) { return New-Verdict 'PARTIAL' 'port closed, but the launcher task is still enabled (comes back at boot)' }
            return New-Verdict 'FIXED' 'port closed and launcher gone or disabled'
        }
        'Ifeo'         { if ($f.Exists) { return New-Verdict 'MISSED' 'Debugger value still set' } else { return New-Verdict 'FIXED' 'Debugger removed' } }
        'Hosts'        { if ($f.Exists) { return New-Verdict 'MISSED' 'line still in the hosts file' } else { return New-Verdict 'FIXED' 'line removed' } }
        'DefExclusion' { if ($f.Exists) { return New-Verdict 'MISSED' 'exclusion still set' } else { return New-Verdict 'FIXED' 'exclusion removed' } }
        'Share'        { if ($f.Exists) { return New-Verdict 'MISSED' 'share still exists' } else { return New-Verdict 'FIXED' 'share removed' } }
        'FwRule' {
            if (-not $f.Exists) { return New-Verdict 'FIXED' 'rule removed' }
            if (-not $f.AnyEnabled) { return New-Verdict 'FIXED' 'rule disabled' }
            return New-Verdict 'MISSED' 'rule still enabled'
        }
        'Lockout' {
            if ($f.Threshold -eq 0) { return New-Verdict 'FIXED' 'lockout threshold back to 0' }
            return New-Verdict 'MISSED' "lockout threshold is still $($f.Threshold)"
        }
        'Guest' { if ($f.Enabled) { return New-Verdict 'MISSED' 'Guest is enabled' } else { return New-Verdict 'FIXED' 'Guest disabled' } }
        'JenkinsInit' { if ($f.Exists) { return New-Verdict 'MISSED' 'init.groovy.d script still in place' } else { return New-Verdict 'FIXED' 'script removed or moved' } }
        'JenkinsJob' {
            if (-not $f.Exists) { return New-Verdict 'FIXED' 'job removed' }
            if ($f.Disabled)    { return New-Verdict 'FIXED' 'job disabled' }
            return New-Verdict 'MISSED' 'job still enabled'
        }
        'JenkinsUser' { if ($f.LoginWorks) { return New-Verdict 'MISSED' 'the planted Jenkins login still works' } else { return New-Verdict 'FIXED' 'planted login refused' } }
    }
    New-Verdict 'UNKNOWN' "no verdict rule for kind '$($p.Kind)'"
}

function Get-PlantLabel {
    # A readable name for the table.
    param($p)
    switch ($p.Kind) {
        'Task'     { return "$($p.Path)$($p.Name)" }
        'Listener' { return "port $($p.Port) (task $($p.Name))" }
        'RunKey'   { return "$($p.Name) in $(Split-Path $p.Key -Leaf)" }
        'FwRule'   { return "$($p.Name) (port $($p.Port))" }
        'Lockout'  { return "lockout threshold $($p.Threshold)" }
        default    { return [string]$p.Name }
    }
}

# ---------------------------------------------------------------- 3. grade everything
function Get-LabGrade {
    param($Record, [int]$LockoutThreshold = 0, [bool]$ProbePasswords = $true)
    $rows = New-Object System.Collections.ArrayList
    foreach ($p in @($Record.Plants)) {
        $label = Get-PlantLabel $p
        if ($p.Status -ne 'planted') {
            [void]$rows.Add([pscustomobject]@{ Id = $p.Id; Kind = $p.Kind; Item = $label; Verdict = 'N/A'; Note = 'was not planted, ignored'; Expect = $p.Expect })
            continue
        }
        try {
            $facts = Get-PlantFacts $p -LockoutThreshold $LockoutThreshold -ProbePasswords $ProbePasswords -JenkinsHome ([string]$Record.JenkinsHome)
            $v = Get-PlantVerdict $p $facts
        } catch { $v = New-Verdict 'UNKNOWN' $_.Exception.Message }
        [void]$rows.Add([pscustomobject]@{ Id = $p.Id; Kind = $p.Kind; Item = $label; Verdict = $v.Verdict; Note = $v.Note; Expect = $p.Expect })
    }
    $rows.ToArray()
}

function Get-LabGradeSummary {
    # One result line for the report: how many of the planted items were dealt with.
    param($Rows)
    $graded = @($Rows | Where-Object { $_.Verdict -ne 'N/A' })
    $fixed   = @($graded | Where-Object { $_.Verdict -eq 'FIXED' }).Count
    $partial = @($graded | Where-Object { $_.Verdict -eq 'PARTIAL' }).Count
    $missed  = @($graded | Where-Object { $_.Verdict -eq 'MISSED' }).Count
    $unknown = @($graded | Where-Object { $_.Verdict -eq 'UNKNOWN' }).Count
    $text = "$fixed fixed, $partial partial, $missed missed, $unknown unknown (of $($graded.Count) planted)"
    $status = 'PASS'
    if ($partial -gt 0 -or $unknown -gt 0) { $status = 'WARN' }
    if ($missed -gt 0) { $status = 'FAIL' }
    New-Result 'Lab answer key' $status $text
}

function Get-AccountsKeptFinding {
    # Plan: disable, NEVER delete. Every account that existed when the lab was armed must still exist.
    param($Record)
    $gone = @()
    foreach ($n in @($Record.AccountsAtArm)) {
        if (-not (Get-LocalUser -Name $n -ErrorAction SilentlyContinue)) { $gone += $n }
    }
    if ($gone.Count -gt 0) { return New-Result 'Accounts kept (never delete)' 'FAIL' "deleted: $(Format-NameList $gone)  (plan: disable, never delete)" }
    New-Result 'Accounts kept (never delete)' 'PASS' "all $(@($Record.AccountsAtArm).Count) accounts that existed at arm time still exist"
}

function Watch-LabBeacon {
    # Empties the beacon log, waits, then reports which planted items wrote to it (= are still alive).
    # Only items that run on a timer can show up (scheduled tasks, WMI, Jenkins jobs); the others are judged by state.
    param($Record, [int]$Minutes, [string]$Beacon = 'C:\ProgramData\lab_beacon.log')
    Clear-Content $Beacon -ErrorAction SilentlyContinue
    for ($i = 1; $i -le $Minutes; $i++) {
        Start-Sleep -Seconds 60
        Write-Host "    waited $i of $Minutes minute(s)..." -ForegroundColor DarkGray
    }
    $lines = @(Get-Content $Beacon -ErrorAction SilentlyContinue)
    $alive = @()
    foreach ($p in @($Record.Plants | Where-Object { $_.Status -eq 'planted' -and $_.Tag })) {
        if (@($lines | Where-Object { $_ -match "^$($p.Tag)\b" }).Count -gt 0) { $alive += "$($p.Id) $($p.Kind) $(Get-PlantLabel $p)" }
    }
    if ($alive.Count -gt 0) { return New-Result 'Beacon watch' 'FAIL' "still fired in $Minutes minute(s): $(Format-NameList $alive)" }
    New-Result 'Beacon watch' 'PASS' "no planted item wrote to the beacon log in $Minutes minute(s) (only timer-based items can show up here)"
}
