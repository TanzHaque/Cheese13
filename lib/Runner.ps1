# Runner.ps1 - the glue between the audit and the changes.
#
# The window (Gui.ps1) and the console menu (Console.ps1) call ONLY these functions. That way the whole flow
#     audit  ->  pick a row  ->  build the action (it may ask you something)  ->  Invoke-Change  ->  read the box again
# is tested without a window (Tests\Test-Runner.ps1). Nothing in this file changes the box by itself: every change is an
# action, and only Invoke-Change (Core.ps1) runs an action.
# Windows PowerShell 5.1, plain ASCII.

# ---------------------------------------------------------------- the audit
function Update-Audit {
    # Reads the box and judges it. -Sections limits the reading to the parts a change made stale (see Get-SectionsForAction);
    # the rest is taken from the last audit. No sections, or no earlier audit = read everything.
    param([string[]]$Sections = @())
    $old = $script:Hp.Facts
    if ($old -and $Sections.Count -gt 0) { $facts = Get-HpFacts -Sections $Sections -Previous $old }
    else { $facts = Get-HpFacts }
    $script:Hp.Facts = $facts
    $script:Hp.Findings = @(Get-HpFindings -Facts $facts -Settings $script:Hp.Settings)
    $bad = @($script:Hp.Findings | Where-Object { $_.Severity -eq 'BAD' }).Count
    $warn = @($script:Hp.Findings | Where-Object { $_.Severity -eq 'WARN' }).Count
    Write-HpLog ('audit done: {0} rows, {1} BAD, {2} WARN' -f @($script:Hp.Findings).Count, $bad, $warn)
    $script:Hp.Findings
}

function Update-AfterChange {
    # After a change, read again only what that change could have altered. An action id the tool does not know = read everything.
    param([string[]]$ActionIds)
    $ids = @($ActionIds | Where-Object { $_ })
    if ($ids.Count -eq 0) { return }
    $sections = @()
    foreach ($id in $ids) {
        $s = @(Get-SectionsForAction $id)
        if ($s.Count -eq 0) { $sections = @(); break }
        $sections += $s
    }
    [void](Update-Audit -Sections @($sections | Select-Object -Unique))
}

function Get-PhaseFindings {
    # The rows of the last audit; -Phase 0 = all of them.
    param([int]$Phase = 0)
    if ($Phase -eq 0) { return @($script:Hp.Findings) }
    @($script:Hp.Findings | Where-Object { $_.Phase -eq $Phase })
}

function Get-PhaseName {
    param([int]$Phase)
    $n = $script:PhaseNames[$Phase]
    if ($n) { return [string]$n }
    "Phase $Phase"
}

# ---------------------------------------------------------------- can this row be fixed?
function Get-FixProblem {
    # $null when the row can be fixed now. Otherwise the reason, and a Status:
    #   'Skipped' = there is no fix (the row only informs you), or this version of the tool does not have it
    #   'Waiting' = the fix exists but must wait for another one (the judge wrote down which)
    param($Finding)
    if (-not $Finding.Fix) { return [pscustomobject]@{ Status = 'Skipped'; Text = 'This row has no automatic fix.' } }
    $name = [string]$Finding.Fix.Do
    $known = $ExecutionContext.SessionState.InvokeCommand.GetCommand($name, [System.Management.Automation.CommandTypes]::Function)
    if (-not $known) { return [pscustomobject]@{ Status = 'Skipped'; Text = "This fix ($name) is not part of this version of the tool." } }
    if ($Finding.Blocked) { return [pscustomobject]@{ Status = 'Waiting'; Text = [string]$Finding.Blocked } }
    $null
}

function Format-FindingDetail {
    # The text under the list when a row is selected: what it is, why it matters, and whether a fix exists.
    param($Finding)
    $lines = @(('[{0}]  phase {1} {2}  -  {3}' -f $Finding.Severity, $Finding.Phase, (Get-PhaseName ([int]$Finding.Phase)), $Finding.Area), [string]$Finding.Subject, '', [string]$Finding.Why, '')
    $problem = Get-FixProblem $Finding
    if (-not $Finding.Fix) { $lines += 'Fix: none. This row only tells you something.' }
    elseif ($problem) { $lines += ('Fix: not possible yet. ' + $problem.Text) }
    else { $lines += 'Fix: available. Press Fix selected: you see the exact changes first and confirm before anything happens.' }
    $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------- fix one row
function Update-DeadManIfLow {
    # A firewall change needs the dead-man switch to have more than 60 seconds left. When the switch is armed but nearly out
    # of time, this extends it (that only postpones the automatic restore). When it is NOT armed nothing happens here:
    # Invoke-Change then refuses the firewall change and tells you to arm it.
    $left = Get-DeadManClock
    if ($left -eq 0 -or $left -ge 120) { return }
    $r = Invoke-Change (New-ExtendDeadManAction -Minutes ([int](Get-HpSetting 'DeadManMinutes'))) -Confirmed
    if (-not $r.Ok) { Write-HpLog "the dead-man switch could not be extended: $($r.Message)" 'WARN' }
}

function Invoke-FixFinding {
    # One row -> its action (the fix function may ask you for input first) -> Invoke-Change -> read the box again.
    # Returns the Invoke-Change result, with ActionId added. Statuses: Applied, Failed, Cancelled, Blocked (the gate said no),
    # Skipped / Waiting (this row cannot be fixed now, see Get-FixProblem).
    # -Confirmed = you already agreed to this exact row (the Fix phase dialog); High-risk actions still ask you to type a word.
    # -NoRefresh = the caller reads the box again itself, once, after a whole batch.
    param([Parameter(Mandatory)]$Finding, [switch]$Confirmed, [switch]$NoRefresh)
    if (-not $script:Hp.AllowChanges) {
        # said BEFORE the fix function runs: it may ask for a password, and that would be wasted when the gate is going to refuse anyway
        Write-HpLog "BLOCKED (audit mode, 'Allow changes' is off): $($Finding.Subject)" 'WARN'
        return New-ChangeResult 'Blocked' 'Audit mode: tick "Allow changes" first.'
    }
    $problem = Get-FixProblem $Finding
    if ($problem) {
        Write-HpLog "not fixed: $($Finding.Subject) - $($problem.Text)"
        return New-ChangeResult $problem.Status $problem.Text
    }
    $built = @()
    try {
        # a fix function should return exactly one action (or nothing, when you cancel); anything else it printed is ignored
        $built = @(Resolve-Fix $Finding | Where-Object { $_ -and $_.PSObject.Properties['Apply'] })
    } catch {
        Write-HpLog "the fix for '$($Finding.Subject)' could not be prepared: $($_.Exception.Message)" 'ERROR'
        return New-ChangeResult 'Failed' "The fix could not be prepared: $($_.Exception.Message)"
    }
    if ($built.Count -eq 0) {
        Write-HpLog "no action for '$($Finding.Subject)': you cancelled, or the input was not accepted"
        return New-ChangeResult 'Cancelled' 'Nothing was changed (you cancelled, or what you typed was not accepted - see the log).'
    }
    $action = $built[$built.Count - 1]
    if ($action.NeedsDeadMan) { Update-DeadManIfLow }
    $result = Invoke-Change -Action $action -Confirmed:$Confirmed
    $result | Add-Member -NotePropertyName ActionId -NotePropertyValue $action.Id -Force
    if (-not $NoRefresh -and ($result.Status -eq 'Applied' -or $result.Status -eq 'Failed')) { Update-AfterChange @($action.Id) }
    $result
}

# ---------------------------------------------------------------- fix a whole phase
function Get-BatchPlan {
    # The rows the "Fix phase" dialog offers for one phase, in the order they should run. Nothing is asked or changed here.
    # Tick = on by default. A fix named New-... only BUILDS an action, so its risk is known and High risk starts unticked.
    # A fix named Request-... asks you for input first, so it starts unticked too (tick it if you want to be asked).
    param([int]$Phase)
    $rows = @()
    foreach ($f in (Get-PhaseFindings $Phase)) {
        if (-not $f.Fix -or -not $f.Batch) { continue }
        if ($f.Severity -ne 'BAD' -and $f.Severity -ne 'WARN') { continue }
        if (Get-FixProblem $f) { continue }                       # waiting for another fix, or not available: not offered
        $risk = 'asks you'; $title = [string]$f.Subject; $tick = $false
        if ([string]$f.Fix.Do -like 'New-*') {
            try {
                $a = Resolve-Fix $f
                if ($a) { $risk = [string]$a.Risk; $title = [string]$a.Title; $tick = ($risk -ne 'High') }
            } catch { $risk = 'error'; $title = "$($f.Subject)  (cannot be prepared: $($_.Exception.Message))" }
        }
        $rows += [pscustomobject]@{ Finding = $f; Risk = $risk; Title = $title; Tick = $tick }
    }
    $rows
}

function Get-BatchWaiting {
    # How many batch rows of the phase wait for another fix (they appear after the next round).
    param([int]$Phase)
    @(Get-PhaseFindings $Phase | Where-Object {
        $_.Fix -and $_.Batch -and ($_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN') -and ((Get-FixProblem $_).Status -eq 'Waiting')
    }).Count
}

function Invoke-FixPhase {
    # Runs the chosen rows one after the other. Every row goes through Invoke-Change with -Confirmed: you agreed in the dialog
    # (High-risk actions still ask you to type a word). It STOPS at the first failure or the first refusal by the gate:
    # later rows may depend on the one that went wrong.
    # The box is read again ONCE at the end, only the parts the applied actions could have changed.
    param([Parameter(Mandatory)][object[]]$Findings)
    $results = @()
    $ids = @()
    $stopped = ''
    foreach ($f in $Findings) {
        $r = Invoke-FixFinding -Finding $f -Confirmed -NoRefresh
        $results += [pscustomobject]@{ Finding = $f; Result = $r }
        if ($r.Status -eq 'Applied' -or $r.Status -eq 'Failed') { $ids += $r.ActionId }
        if ($r.Status -eq 'Failed') { $stopped = "'$($f.Subject)' failed: $($r.Message)"; break }
        if ($r.Status -eq 'Blocked') { $stopped = "'$($f.Subject)' was refused: $($r.Message)"; break }
    }
    if ($stopped) { Write-HpLog "fix phase STOPPED: $stopped" 'ERROR' }
    Update-AfterChange $ids
    [pscustomobject]@{
        Results   = $results
        Applied   = @($results | Where-Object { $_.Result.Status -eq 'Applied' }).Count
        Failed    = @($results | Where-Object { $_.Result.Status -eq 'Failed' }).Count
        Cancelled = @($results | Where-Object { $_.Result.Status -eq 'Cancelled' }).Count
        Skipped   = @($results | Where-Object { $_.Result.Status -eq 'Skipped' -or $_.Result.Status -eq 'Waiting' }).Count
        Blocked   = @($results | Where-Object { $_.Result.Status -eq 'Blocked' }).Count
        NotRun    = @($Findings).Count - @($results).Count
        StoppedBecause = $stopped
    }
}

function Format-PhaseSummary {
    param($Summary)
    $lines = @("Applied: $($Summary.Applied)   Failed: $($Summary.Failed)   Cancelled: $($Summary.Cancelled)   Skipped: $($Summary.Skipped)   Refused: $($Summary.Blocked)   Not run: $($Summary.NotRun)")
    if ($Summary.StoppedBecause) { $lines += ('STOPPED: ' + $Summary.StoppedBecause) }
    foreach ($x in $Summary.Results) { $lines += ('  {0,-9} {1}' -f $x.Result.Status, $x.Finding.Subject) }
    $lines -join [Environment]::NewLine
}

# ---------------------------------------------------------------- undo
function Get-UndoList {
    # Changes that can be undone, newest first (the "Undo..." dialog). Undo the newest first: later changes may depend on earlier ones.
    @(Get-JournalRecords | Where-Object { $_.Status -eq 'applied' -and $_.UndoKind -and $script:UndoHandlers.ContainsKey([string]$_.UndoKind) } |
        Sort-Object { [int]$_.Id } -Descending)
}

function Invoke-Undo {
    # Undoes journal record -Id, or the newest one that can be undone (no -Id). Then reads the box again.
    param([int]$Id = 0)
    $list = @(Get-UndoList)
    $rec = $null
    if ($Id -gt 0) { $rec = $list | Where-Object { [int]$_.Id -eq $Id } | Select-Object -First 1 }
    elseif ($list.Count -gt 0) { $rec = $list[0] }
    if (-not $rec) {
        if ($Id -gt 0) { return New-ChangeResult 'Failed' "Change #$Id cannot be undone (it is not in the journal, was not applied, was already undone, or has no undo)." }
        return New-ChangeResult 'Failed' 'Nothing to undo: no applied change with an undo is in the journal.'
    }
    $result = Undo-Change -Id ([int]$rec.Id)
    if ($result.Status -eq 'Undone' -or $result.Status -eq 'Failed') { Update-AfterChange @([string]$rec.ActionId) }
    $result
}

# ---------------------------------------------------------------- the journal, as text
function Get-JournalLines {
    # One line per change made so far, oldest first (the window shows them in a box, the text menu prints them).
    $out = @()
    foreach ($r in @(Get-JournalRecords)) {
        $undo = $(if ($r.UndoKind) { 'undo ok' } else { 'NO UNDO' })
        $out += ('#{0,-4} {1}  {2,-11} {3,-8} {4}' -f [int]$r.Id, $r.Time, $r.Status, $undo, $r.Title)
    }
    $out
}

# ---------------------------------------------------------------- the dead-man buttons
function Invoke-DeadManButton {
    # Arm (saves the firewall policy and schedules the restore; if already armed it only extends), Extend, or Disarm ("Keep changes").
    param([Parameter(Mandatory)][ValidateSet('Arm', 'Extend', 'Disarm')][string]$What)
    $minutes = [int](Get-HpSetting 'DeadManMinutes')
    $action = $null
    switch ($What) {
        'Arm'    { $action = New-ArmDeadManAction -Minutes $minutes }
        'Extend' { $action = New-ExtendDeadManAction -Minutes $minutes }
        'Disarm' { $action = New-DisarmDeadManAction }
    }
    $result = Invoke-Change -Action $action
    if ($result.Status -eq 'Applied' -or $result.Status -eq 'Failed') { Update-AfterChange @($action.Id) }
    $result
}
