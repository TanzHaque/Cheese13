# Console.ps1 - the tool without a window: print the audit, and a small text menu to fix rows.
# It uses exactly the same Runner.ps1 functions as the window, and every change still goes through Invoke-Change
# (preview, confirm, journal, undo). Use it when the window will not open, or on the NEIGH Console.
# Windows PowerShell 5.1, plain ASCII.

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'BAD'  { return 'Red' }
        'WARN' { return 'Yellow' }
        'OK'   { return 'Green' }
    }
    'Gray'
}

function Show-AuditConsole {
    # Prints the rows of the last audit, numbered, so the menu can fix "row 3". Returns the rows it printed, in that order
    # (callers write  @(Show-AuditConsole ...)  so that zero or one row still gives a list).
    # BAD and WARN rows show their reason; -Detail shows it for every row.
    param([int]$Phase = 0, [switch]$Detail)
    $shown = @()
    $rows = Get-PhaseFindings $Phase
    foreach ($ph in $script:PhaseOrder) {
        $mine = @($rows | Where-Object { $_.Phase -eq $ph })
        if ($mine.Count -eq 0) { continue }
        Write-Host ''
        Write-Host ('== {0} {1} ==' -f $ph, (Get-PhaseName $ph)) -ForegroundColor Cyan
        foreach ($f in $mine) {
            $shown += $f
            $problem = Get-FixProblem $f
            $mark = $(if ($problem) { '     ' } else { '[fix]' })
            Write-Host ('{0,3}  {1,-4} {2} {3}: {4}' -f $shown.Count, $f.Severity, $mark, $f.Area, $f.Subject) -ForegroundColor (Get-SeverityColor $f.Severity)
            if ($Detail -or $f.Severity -eq 'BAD' -or $f.Severity -eq 'WARN') {
                Write-Host ('       ' + $f.Why) -ForegroundColor DarkGray
                if ($problem -and $f.Fix) { Write-Host ('       (cannot be fixed yet: ' + $problem.Text + ')') -ForegroundColor DarkGray }
            }
        }
    }
    $bad = @($rows | Where-Object { $_.Severity -eq 'BAD' }).Count
    $warn = @($rows | Where-Object { $_.Severity -eq 'WARN' }).Count
    Write-Host ''
    Write-Host ("{0} rows: {1} BAD, {2} WARN.  Changes are {3}." -f @($rows).Count, $bad, $warn, $(if ($script:Hp.AllowChanges) { 'ALLOWED (each one asks first)' } else { 'OFF (read-only audit)' }))
    $shown
}

function Show-ChangeResult {
    # One line for the outcome of a change.
    param($Result)
    $color = 'Red'
    if ($Result.Ok) { $color = 'Green' }
    elseif (@('Cancelled', 'Skipped', 'Waiting') -contains $Result.Status) { $color = 'Yellow' }
    Write-Host ('{0}: {1}' -f $Result.Status, $Result.Message) -ForegroundColor $color
    $out = (@($Result.Output) | Where-Object { $null -ne $_ }) -join ' | '
    if ($out) { Write-Host ('  ' + $out) }
}

function Show-Journal {
    # The list of changes made so far (journal\NNNN.json), oldest first.
    $lines = @(Get-JournalLines)
    if ($lines.Count -eq 0) { Write-Host 'The journal is empty: nothing has been changed yet.'; return }
    foreach ($l in $lines) { Write-Host $l }
}

function Invoke-ConsolePhase {
    # "Fix phase" in text: shows the rows that would run, asks once, runs them one after the other.
    param([int]$Phase)
    $plan = @(Get-BatchPlan -Phase $Phase)
    if ($plan.Count -eq 0) { Write-Host "Nothing in phase $Phase can be fixed in one batch right now."; return }
    Write-Host ''
    Write-Host ('Fix phase {0} {1}: these rows can run, in this order' -f $Phase, (Get-PhaseName $Phase)) -ForegroundColor Cyan
    $i = 0
    foreach ($row in $plan) {
        $i++
        Write-Host ('{0,3}  [{1}] {2}   (risk: {3})' -f $i, $(if ($row.Tick) { 'x' } else { ' ' }), $row.Title, $row.Risk)
    }
    $waiting = Get-BatchWaiting -Phase $Phase
    if ($waiting -gt 0) { Write-Host "$waiting more row(s) wait for these. Run Fix phase again afterwards." }
    $take = @($plan | Where-Object { $_.Tick })
    if ($take.Count -eq 0) {
        Write-Host 'No row is ticked by default (High risk, or it asks you questions). Fix those one at a time by row number.'
        return
    }
    $text = "Run the $($take.Count) ticked row(s) [x] above, one after the other?`n`nEach change is written to the journal first. It stops at the first failure."
    if (-not (& $script:Hp.Ask "Fix phase $Phase" $text '')) { Write-Host 'Cancelled. Nothing was changed.'; return }
    $summary = Invoke-FixPhase -Findings @($take | ForEach-Object { $_.Finding })
    Write-Host (Format-PhaseSummary $summary)
    $more = @(Get-BatchPlan -Phase $Phase | Where-Object { $_.Tick }).Count
    if ($summary.Applied -gt 0 -and $more -gt 0) { Write-Host "$more more row(s) can run now. Type p $Phase again to see them." -ForegroundColor Yellow }
}

function Start-ConsoleMenu {
    # The text menu. Enter alone shows the list again.
    param([int]$Phase = 0)
    if (-not $script:Hp.Facts) { [void](Update-Audit) }
    $rows = @(Show-AuditConsole -Phase $Phase)
    $empty = 0
    while ($true) {
        Write-Host ''
        Write-Host '<row number> fix that row | p [phase] fix a whole phase | a audit again | d arm / extend / keep  the dead-man switch | u undo last | j journal | c changes on/off | q quit'
        $cmd = [string](Read-HpText 'Command' '')
        $cmd = $cmd.Trim().ToLowerInvariant()
        $redraw = $false
        if ($cmd -ne '') { $empty = 0 }
        if ($cmd -eq '') {
            $empty++
            if ($empty -ge 5) { Write-Host 'No input: leaving the menu.'; return }       # also stops a run where nobody can type (closed input)
            $redraw = $true
        }
        elseif ($cmd -eq 'q') { return }
        elseif ($cmd -eq 'a') { [void](Update-Audit); $redraw = $true }
        elseif ($cmd -match '^\d+$') {
            $n = [int]$cmd
            if ($n -lt 1 -or $n -gt $rows.Count) { Write-Host "There is no row $n." }
            else { Show-ChangeResult (Invoke-FixFinding -Finding $rows[$n - 1]); $redraw = $true }
        }
        elseif ($cmd -match '^p\s*(\d*)$') {
            $want = $(if ($Matches[1]) { [int]$Matches[1] } else { $Phase })
            if ($want -eq 0) { Write-Host 'Say which phase: for example  p 2  (phases: 1 Recon, 2 Accounts, 3 Backup, 4 Firewall, 6 Hunt, 7 Defender, 9 Routine).' }
            else { Invoke-ConsolePhase -Phase $want; $redraw = $true }
        }
        elseif ($cmd -match '^d\s+(arm|extend|keep)$') {
            $what = @{ arm = 'Arm'; extend = 'Extend'; keep = 'Disarm' }[$Matches[1]]
            Show-ChangeResult (Invoke-DeadManButton -What $what)
            $redraw = $true
        }
        elseif ($cmd -eq 'u') { Show-ChangeResult (Invoke-Undo); $redraw = $true }
        elseif ($cmd -eq 'j') { Show-Journal }
        elseif ($cmd -eq 'c') {
            if ($script:Hp.AllowChanges) { $script:Hp.AllowChanges = $false; Write-HpLog 'changes switched OFF (audit mode)' }
            elseif (& $script:Hp.Ask 'Allow changes' "Changes will be allowed. Every change still shows what it will do and asks you first.`n`nGo ahead?" '') {
                $script:Hp.AllowChanges = $true
                Write-HpLog 'changes switched ON'
            }
            $redraw = $true
        }
        else { Write-Host "I do not know '$cmd'." }
        if ($redraw) { $rows = @(Show-AuditConsole -Phase $Phase) }
    }
}
