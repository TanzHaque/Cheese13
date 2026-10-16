# Gui.ps1 - the window.
#
# This file is only glue. Every button calls a function from Runner.ps1 (the same ones the text menu in Console.ps1 uses), and every
# change still goes through Invoke-Change: preview, your confirmation, journal, undo. Nothing in this file changes the box itself.
#
# How to read it:
#   - the controls of the main window live in $script:Ui, the controls of the dialog that is open right now in $script:Dlg;
#     event handlers use only those two (and functions), never a local variable of the function that built the control
#   - every button handler goes through Invoke-GuiAction: a mistake inside it is logged and shown, and the window keeps working
#   - the file has no commands at the top level, only function definitions; the WinForms assemblies are loaded
#     when the window opens (Initialize-GuiAssemblies), so the tests can load this file on a machine without WinForms
#   - the names of every WinForms control, property, method and event used here are checked against the .NET list by
#     Tests\Test-GuiApi.ps1, because the window itself can only be tried on Windows
# Windows PowerShell 5.1, plain ASCII.

$script:Ui = @{}
$script:Dlg = @{}

# ---------------------------------------------------------------- text helpers (no controls)
function ConvertTo-GuiText {
    # A multi-line text box needs CR+LF line ends; some texts of the tool use LF only.
    param([string]$Text)
    $Text -replace "`r?`n", "`r`n"
}

function Format-GuiClock {
    # 275 seconds -> 4:35
    param([int]$Seconds)
    '{0}:{1:D2}' -f [int][math]::Floor($Seconds / 60), ($Seconds % 60)
}

function Get-GuiDeadManText {
    # The text and state of the dead-man label. $Seconds = time left (0 = not armed). $Status = the full status, or $null.
    param([int]$Seconds, $Status)
    if ($Seconds -gt 0) {
        $state = $(if ($Seconds -lt 60) { 'Low' } else { 'Armed' })
        return [pscustomobject]@{ Text = 'Dead-man switch ARMED: the firewall is restored in ' + (Format-GuiClock $Seconds) + ' unless you click Keep changes'; State = $state }
    }
    if ($Status -and $Status.FiredAt) {
        return [pscustomobject]@{ Text = 'The dead-man switch FIRED at ' + $Status.FiredAt + ': the firewall was restored'; State = 'Fired' }
    }
    [pscustomobject]@{ Text = 'Dead-man switch: not armed'; State = 'Off' }
}

function Get-GuiRowView {
    # What the list shows for one finding: the five cells, and the severity (which picks the colors).
    param($Finding)
    $problem = Get-FixProblem $Finding
    $fix = '-'
    if ($Finding.Fix) {
        if (-not $problem) { $fix = 'yes' }
        elseif ($problem.Status -eq 'Waiting') { $fix = 'waits' }
    }
    $phaseText = '{0} {1}' -f $Finding.Phase, (Get-PhaseName ([int]$Finding.Phase))
    [pscustomobject]@{ Cells = @([string]$Finding.Severity, $phaseText, [string]$Finding.Area, [string]$Finding.Subject, $fix); Severity = [string]$Finding.Severity }
}

function Get-GuiHelpText {
    @(
        'How this window works',
        '',
        '- It starts in AUDIT mode: it only reads the box. Tick "Allow changes" to let it change things.',
        '- Pick a row, read the explanation under the list, press "Fix selected". You always see exactly what will change, and you confirm.',
        '- "Fix phase..." runs several rows of one phase, in order. Run it again afterwards: some rows only appear once earlier ones are done.',
        '- "Undo last" and "Undo..." put an earlier change back. "Journal..." lists every change that was made.',
        '- Firewall changes need the dead-man switch: press Arm first. If a change cuts you off, the box restores the firewall by itself.',
        '  When the NEIGH page shows RDP and Jenkins green, press "Keep changes". This tool does not check scoring itself.',
        '- If something looks wrong: run Panic.ps1 (see RUNBOOK.md). The text menu (Start-Hardening.ps1 -NoGui -Apply) does the same as this window.'
    ) -join "`n"
}

# ---------------------------------------------------------------- small controls
function Build-GuiButton {
    param([string]$Text, [string]$Tip = '')
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.AutoSize = $true
    $b.AutoSizeMode = 'GrowAndShrink'
    $b.Margin = New-Object System.Windows.Forms.Padding(3)
    if ($Tip -and $script:Ui.Tip) { $script:Ui.Tip.SetToolTip($b, $Tip) }
    $b
}

function Build-GuiLabel {
    param([string]$Text)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.Anchor = 'Left'
    $l.Margin = New-Object System.Windows.Forms.Padding(6, 3, 3, 3)
    $l
}

function Build-GuiLight {
    # A small colored box with text (the mode, the dead-man switch).
    param([string]$Text)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.AutoSize = $true
    $l.Anchor = 'Left'
    $l.ForeColor = [System.Drawing.Color]::White
    $l.BackColor = [System.Drawing.Color]::Gray
    $l.Padding = New-Object System.Windows.Forms.Padding(6, 3, 6, 3)
    $l.Margin = New-Object System.Windows.Forms.Padding(8, 3, 3, 3)
    $l
}

function Build-GuiBar {
    # A row of controls that wraps onto a second line when the window is narrow.
    $bar = New-Object System.Windows.Forms.FlowLayoutPanel
    $bar.Dock = 'Fill'
    $bar.AutoSize = $true
    $bar.AutoSizeMode = 'GrowAndShrink'
    $bar.WrapContents = $true
    $bar.FlowDirection = 'LeftToRight'
    $bar
}

function Build-GuiTextBox {
    # A read-only box for long text (the details, the log, the journal, the preview of a change).
    $t = New-Object System.Windows.Forms.TextBox
    $t.Multiline = $true
    $t.ReadOnly = $true
    $t.ScrollBars = 'Vertical'
    $t.WordWrap = $true
    $t.Dock = 'Fill'
    $t.TabStop = $false
    $t.Font = $script:Ui.MonoFont
    $t.BackColor = [System.Drawing.SystemColors]::Window
    $t
}

function Build-GuiTable {
    # A one-column table that fills its parent; the caller adds the row styles and the controls.
    param([int]$Rows)
    $t = New-Object System.Windows.Forms.TableLayoutPanel
    $t.Dock = 'Fill'
    $t.ColumnCount = 1
    $t.RowCount = $Rows
    $t.Padding = New-Object System.Windows.Forms.Padding(8)
    [void]$t.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    $t
}

function Add-GuiRowStyle {
    param($Table, [string]$Kind, [int]$Size = 0)
    [void]$Table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle($Kind, $Size)))
}

function Build-GuiDialog {
    param([string]$Title, [int]$Width, [int]$Height)
    $d = New-Object System.Windows.Forms.Form
    $d.Text = $Title
    $d.ClientSize = New-Object System.Drawing.Size($Width, $Height)
    $d.StartPosition = 'CenterParent'
    $d.FormBorderStyle = 'FixedDialog'
    $d.MaximizeBox = $false
    $d.MinimizeBox = $false
    $d.ShowInTaskbar = $false
    $d.Font = $script:Ui.Font
    $d
}

function Build-GuiButtonRow {
    # The row of buttons at the bottom of a dialog. The first button given ends up at the right edge.
    param($Buttons)
    $row = New-Object System.Windows.Forms.FlowLayoutPanel
    $row.Dock = 'Fill'
    $row.AutoSize = $true
    $row.FlowDirection = 'RightToLeft'
    foreach ($b in $Buttons) { $row.Controls.Add($b) }
    $row
}

# ---------------------------------------------------------------- messages and questions (the hooks the tool calls)
function Show-GuiMessage {
    # A message box. Also the Notify hook: the tool uses it to tell you that something was refused.
    param([string]$Title, [string]$Text)
    $ok = [System.Windows.Forms.MessageBoxButtons]::OK
    $icon = [System.Windows.Forms.MessageBoxIcon]::Information
    if ($script:Ui.Form) { [void][System.Windows.Forms.MessageBox]::Show($script:Ui.Form, (ConvertTo-GuiText $Text), $Title, $ok, $icon) }
    else { [void][System.Windows.Forms.MessageBox]::Show((ConvertTo-GuiText $Text), $Title, $ok, $icon) }
}

function Show-GuiYesNo {
    # Yes / No question, "No" is the default button. Returns $true for Yes.
    param([string]$Title, [string]$Text)
    $buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $icon = [System.Windows.Forms.MessageBoxIcon]::Question
    $default = [System.Windows.Forms.MessageBoxDefaultButton]::Button2
    $r = [System.Windows.Forms.MessageBox]::Show($script:Ui.Form, (ConvertTo-GuiText $Text), $Title, $buttons, $icon, $default)
    $r -eq [System.Windows.Forms.DialogResult]::Yes
}

function Show-GuiNotice {
    param([string]$Title, [string]$Text)
    Show-GuiMessage $Title $Text
}

# ---------------------------------------------------------------- the dialogs
# Every dialog has two functions: Build-Gui...Dialog makes the window and its controls (the ones that a handler uses, or that are
# read after you close it, go into $script:Dlg), and Show-Gui... builds it, shows it, reads your answer and throws it away.
# Test-HardeningWindow builds all of them without showing them.

function Build-GuiConfirmDialog {
    param([string]$Title, [string]$Text, [string]$TypeWord = '')
    $dialog = Build-GuiDialog $Title 720 540
    $table = Build-GuiTable 3
    Add-GuiRowStyle $table 'Percent' 100
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'AutoSize'

    $box = Build-GuiTextBox
    $box.Text = ConvertTo-GuiText $Text
    $table.Controls.Add($box, 0, 0)

    $yes = Build-GuiButton 'Yes, do it'
    $no = Build-GuiButton 'No, cancel'
    $yes.DialogResult = 'OK'
    $no.DialogResult = 'Cancel'
    $dialog.CancelButton = $no

    $typed = $null
    if ($TypeWord) {
        $panel = New-Object System.Windows.Forms.FlowLayoutPanel
        $panel.Dock = 'Fill'
        $panel.AutoSize = $true
        $panel.Controls.Add((Build-GuiLabel "HIGH RISK. To unlock the Yes button type the word  $TypeWord  (exactly, same capital letters):"))
        $typed = New-Object System.Windows.Forms.TextBox
        $typed.Width = 160
        $panel.Controls.Add($typed)
        $table.Controls.Add($panel, 0, 1)
        $yes.Enabled = $false
        $typed.Add_TextChanged({ Invoke-GuiSafe 'type the word' { $script:Dlg.Yes.Enabled = ($script:Dlg.Typed.Text -ceq $script:Dlg.Word) } })
    }
    $table.Controls.Add((Build-GuiButtonRow @($no, $yes)), 0, 2)
    $dialog.Controls.Add($table)
    $script:Dlg = @{ Form = $dialog; Yes = $yes; Typed = $typed; Word = $TypeWord }
    $dialog
}

function Show-GuiConfirm {
    # The Ask hook: shows what is about to happen and returns $true only if you press Yes.
    # For a High-risk change the Yes button stays grey until you have typed the word, exactly (capital letters count).
    param([string]$Title, [string]$Text, [string]$TypeWord = '')
    $dialog = Build-GuiConfirmDialog $Title $Text $TypeWord
    $result = $dialog.ShowDialog($script:Ui.Form)
    $dialog.Dispose()
    $script:Dlg = @{}
    $result -eq [System.Windows.Forms.DialogResult]::OK
}

function Build-GuiInputDialog {
    param([string]$Prompt, [string]$Default = '', [switch]$Secret)
    $title = $(if ($Secret) { 'Type the secret (hidden, never saved)' } else { 'Question' })
    $lines = @($Prompt -split "`n").Count + [int]($Prompt.Length / 70)
    $dialog = Build-GuiDialog $title 600 ([math]::Min(520, 150 + 18 * $lines))
    $table = Build-GuiTable 3
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'Percent' 100

    $label = Build-GuiLabel $Prompt
    $label.MaximumSize = New-Object System.Drawing.Size(560, 0)
    $table.Controls.Add($label, 0, 0)
    $box = New-Object System.Windows.Forms.TextBox
    $box.Dock = 'Fill'
    $box.Text = $Default
    if ($Secret) { $box.UseSystemPasswordChar = $true }
    $table.Controls.Add($box, 0, 1)

    $ok = Build-GuiButton 'OK'
    $cancel = Build-GuiButton 'Cancel'
    $ok.DialogResult = 'OK'
    $cancel.DialogResult = 'Cancel'
    $dialog.AcceptButton = $ok
    $dialog.CancelButton = $cancel
    $table.Controls.Add((Build-GuiButtonRow @($cancel, $ok)), 0, 2)
    $dialog.Controls.Add($table)
    $script:Dlg = @{ Form = $dialog; Box = $box }
    $dialog
}

function Show-GuiInput {
    # One line of text. Returns the text, or $null when you cancel. -Secret hides what you type (an empty answer then counts as cancelled).
    param([string]$Prompt, [string]$Default = '', [switch]$Secret)
    $dialog = Build-GuiInputDialog -Prompt $Prompt -Default $Default -Secret:$Secret
    $result = $dialog.ShowDialog($script:Ui.Form)
    $text = $script:Dlg.Box.Text
    $dialog.Dispose()
    $script:Dlg = @{}
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ($Secret) {
        if ($text.Length -eq 0) { return $null }
        return $text
    }
    if (-not $text) { return $Default }
    $text
}

function Read-GuiSecret {
    param([string]$Prompt)
    Show-GuiInput -Prompt $Prompt -Secret
}

function Read-GuiText {
    param([string]$Prompt, [string]$Default = '')
    Show-GuiInput -Prompt $Prompt -Default $Default
}

function Build-GuiTextDialog {
    param([string]$Title, [string]$Text)
    $dialog = Build-GuiDialog $Title 820 560
    $table = Build-GuiTable 2
    Add-GuiRowStyle $table 'Percent' 100
    Add-GuiRowStyle $table 'AutoSize'
    $box = Build-GuiTextBox
    $box.Text = ConvertTo-GuiText $Text
    $table.Controls.Add($box, 0, 0)
    $close = Build-GuiButton 'Close'
    $close.DialogResult = 'OK'
    $dialog.AcceptButton = $close
    $dialog.CancelButton = $close
    $table.Controls.Add((Build-GuiButtonRow @($close)), 0, 1)
    $dialog.Controls.Add($table)
    $script:Dlg = @{ Form = $dialog }
    $dialog
}

function Show-GuiTextDialog {
    # A read-only box with a Close button (the journal, the help, the result of a whole phase).
    param([string]$Title, [string]$Text)
    $dialog = Build-GuiTextDialog $Title $Text
    [void]$dialog.ShowDialog($script:Ui.Form)
    $dialog.Dispose()
    $script:Dlg = @{}
}

function Build-GuiBatchDialog {
    param([int]$Phase, $Rows, [int]$Waiting)
    $dialog = Build-GuiDialog ("Fix phase $Phase " + (Get-PhaseName $Phase)) 860 560
    $table = Build-GuiTable 4
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'Percent' 100
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'AutoSize'

    $intro = Build-GuiLabel "These rows can run now, in this order. Untick what you do not want. Every change is written to the journal first.`nIt stops at the first failure. Rows that ask you questions start unticked."
    $intro.MaximumSize = New-Object System.Drawing.Size(820, 0)
    $table.Controls.Add($intro, 0, 0)

    $lv = New-Object System.Windows.Forms.ListView
    $lv.Dock = 'Fill'
    $lv.View = 'Details'
    $lv.CheckBoxes = $true
    $lv.FullRowSelect = $true
    $lv.HideSelection = $false
    [void]$lv.Columns.Add('Change', 690)
    [void]$lv.Columns.Add('Risk', 90)
    foreach ($r in $Rows) {
        $item = New-Object System.Windows.Forms.ListViewItem([string]$r.Title)
        [void]$item.SubItems.Add([string]$r.Risk)
        $item.Checked = [bool]$r.Tick
        $item.Tag = $r
        [void]$lv.Items.Add($item)
    }
    $table.Controls.Add($lv, 0, 1)

    $note = ''
    if ($Waiting -gt 0) { $note = "$Waiting more row(s) wait for these to finish. Run Fix phase again afterwards." }
    $table.Controls.Add((Build-GuiLabel $note), 0, 2)

    $run = Build-GuiButton 'Run the ticked rows'
    $cancel = Build-GuiButton 'Cancel'
    $all = Build-GuiButton 'Tick all'
    $none = Build-GuiButton 'Untick all'
    $run.DialogResult = 'OK'
    $cancel.DialogResult = 'Cancel'
    $dialog.CancelButton = $cancel
    $all.Add_Click({ Invoke-GuiSafe 'tick all' { foreach ($i in $script:Dlg.List.Items) { $i.Checked = $true } } })
    $none.Add_Click({ Invoke-GuiSafe 'untick all' { foreach ($i in $script:Dlg.List.Items) { $i.Checked = $false } } })
    $table.Controls.Add((Build-GuiButtonRow @($cancel, $run, $none, $all)), 0, 3)
    $dialog.Controls.Add($table)
    $script:Dlg = @{ Form = $dialog; List = $lv }
    $dialog
}

function Show-GuiBatchDialog {
    # The "Fix phase" dialog: the rows that can run now, in the order they will run, each with a tick box.
    # Returns the ticked rows (objects from Get-BatchPlan), or $null when you cancel.
    param([int]$Phase, $Rows, [int]$Waiting)
    $dialog = Build-GuiBatchDialog -Phase $Phase -Rows $Rows -Waiting $Waiting
    $result = $dialog.ShowDialog($script:Ui.Form)
    $take = @()
    foreach ($i in $script:Dlg.List.Items) { if ($i.Checked) { $take += $i.Tag } }
    $dialog.Dispose()
    $script:Dlg = @{}
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    $take
}

function Build-GuiUndoDialog {
    param($Records)
    $dialog = Build-GuiDialog 'Undo a change' 860 480
    $table = Build-GuiTable 3
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'Percent' 100
    Add-GuiRowStyle $table 'AutoSize'
    $intro = Build-GuiLabel 'Pick a change and press Undo. Undo the newest first: a later change may depend on an earlier one. You see the details and confirm next.'
    $intro.MaximumSize = New-Object System.Drawing.Size(820, 0)
    $table.Controls.Add($intro, 0, 0)

    $lv = New-Object System.Windows.Forms.ListView
    $lv.Dock = 'Fill'
    $lv.View = 'Details'
    $lv.FullRowSelect = $true
    $lv.MultiSelect = $false
    $lv.HideSelection = $false
    [void]$lv.Columns.Add('#', 50)
    [void]$lv.Columns.Add('Time', 140)
    [void]$lv.Columns.Add('Risk', 70)
    [void]$lv.Columns.Add('Change', 560)
    foreach ($r in $Records) {
        $item = New-Object System.Windows.Forms.ListViewItem([string][int]$r.Id)
        [void]$item.SubItems.Add([string]$r.Time)
        [void]$item.SubItems.Add([string]$r.Risk)
        [void]$item.SubItems.Add([string]$r.Title)
        $item.Tag = [int]$r.Id
        [void]$lv.Items.Add($item)
    }
    $table.Controls.Add($lv, 0, 1)

    $undo = Build-GuiButton 'Undo the selected change'
    $cancel = Build-GuiButton 'Close'
    $undo.DialogResult = 'OK'
    $undo.Enabled = $false
    $cancel.DialogResult = 'Cancel'
    $dialog.CancelButton = $cancel
    $lv.Add_SelectedIndexChanged({ Invoke-GuiSafe 'undo list' { $script:Dlg.Undo.Enabled = ($script:Dlg.List.SelectedItems.Count -gt 0) } })
    $table.Controls.Add((Build-GuiButtonRow @($cancel, $undo)), 0, 2)
    $dialog.Controls.Add($table)
    $script:Dlg = @{ Form = $dialog; List = $lv; Undo = $undo }
    $dialog
}

function Show-GuiUndoDialog {
    # The "Undo..." dialog: the changes that can be undone, newest first. Returns the journal number you picked, or 0.
    param($Records)
    $dialog = Build-GuiUndoDialog $Records
    $result = $dialog.ShowDialog($script:Ui.Form)
    $id = 0
    if ($script:Dlg.List.SelectedItems.Count -gt 0) { $id = [int]$script:Dlg.List.SelectedItems[0].Tag }
    $dialog.Dispose()
    $script:Dlg = @{}
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return 0 }
    $id
}

# ---------------------------------------------------------------- running a button safely
function Set-GuiBusy {
    # While a job runs the buttons and the list are greyed out and the cursor shows it. (Dialogs are separate windows and stay usable.)
    param([bool]$Busy)
    $win = $script:Ui
    $win.Busy = $Busy
    $win.BarTop.Enabled = (-not $Busy)
    $win.BarMid.Enabled = (-not $Busy)
    $win.List.Enabled = (-not $Busy)
    if ($Busy) { $win.Form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor }
    else { $win.Form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Invoke-GuiAction {
    # Runs the code of one button. A second click while a job runs does nothing. A mistake is logged and shown,
    # and the window keeps working.
    param([string]$Name, [scriptblock]$Code)
    if ($script:Ui.Busy) { return }
    Set-GuiBusy $true
    try { & $Code }
    catch {
        Write-HpLog "window button '$Name' failed: $($_.Exception.Message)" 'ERROR'
        Show-GuiMessage 'Something went wrong' ("The button '$Name' stopped with an error:`n`n$($_.Exception.Message)`n`nEvery change that was made is in the journal (button Journal...). Press Re-audit to see the real state of the box.")
    }
    finally { Set-GuiBusy $false }
}

function Invoke-GuiSafe {
    # For small handlers that must never show a message (typing, selecting): a mistake is only logged.
    param([string]$Name, [scriptblock]$Code)
    try { & $Code }
    catch { Write-HpLog "window handler '$Name' failed: $($_.Exception.Message)" 'ERROR' }
}

# ---------------------------------------------------------------- hooks the tool calls while the window is open
function Add-GuiLogLine {
    param([string]$Line)
    $box = $script:Ui.Log
    if (-not $box) { return }
    if ($box.TextLength -gt 200000) { $box.Clear() }          # only the copy on screen
    $box.AppendText($Line + [Environment]::NewLine)
}

function Set-GuiStatusText {
    param([string]$Text)
    if ($script:Ui.StatusLeft) { $script:Ui.StatusLeft.Text = $Text }
}

function Set-GuiBusyText {
    # The OnBusy hook: "Reading the firewall..." in the status bar, and a moment for the window to repaint and the clock to tick.
    param([string]$Text)
    Set-GuiStatusText $Text
    [System.Windows.Forms.Application]::DoEvents()
}

function Set-GuiHooks {
    $script:Hp.Ask = ${function:Show-GuiConfirm}
    $script:Hp.AskSecret = ${function:Read-GuiSecret}
    $script:Hp.AskText = ${function:Read-GuiText}
    $script:Hp.Notify = ${function:Show-GuiNotice}
    $script:Hp.OnLog = ${function:Add-GuiLogLine}
    $script:Hp.OnBusy = ${function:Set-GuiBusyText}
}

# ---------------------------------------------------------------- showing the state
function Get-GuiPhase {
    # The phase chosen in the box above the list; 0 = all findings.
    $i = $script:Ui.CmbPhase.SelectedIndex
    $numbers = @($script:Ui.PhaseNumbers)
    if ($i -lt 0 -or $i -ge $numbers.Count) { return 0 }
    [int]$numbers[$i]
}

function Get-GuiSelectedFinding {
    $sel = $script:Ui.List.SelectedItems
    if ($sel.Count -eq 0) { return $null }
    $sel[0].Tag
}

function Set-GuiRowColor {
    param($Item, [string]$Severity)
    switch ($Severity) {
        'BAD'   { $Item.BackColor = [System.Drawing.Color]::FromArgb(255, 215, 215) }
        'WARN'  { $Item.BackColor = [System.Drawing.Color]::FromArgb(255, 245, 200) }
        'OK'    { $Item.ForeColor = [System.Drawing.Color]::FromArgb(0, 110, 40) }
        default { $Item.ForeColor = [System.Drawing.Color]::DimGray }
    }
}

function Set-GuiColumnWidths {
    # The Subject column takes whatever room the other columns leave.
    $lv = $script:Ui.List
    $others = 0
    foreach ($i in 0, 1, 2, 4) { $others += $lv.Columns[$i].Width }
    $room = $lv.ClientSize.Width - $others - 24
    if ($room -gt 200) { $lv.Columns[3].Width = $room }
}

function Update-GuiDetail {
    $f = Get-GuiSelectedFinding
    if ($f) {
        $script:Ui.Detail.Text = ConvertTo-GuiText (Format-FindingDetail $f)
        $script:Ui.BtnFix.Enabled = (-not (Get-FixProblem $f))
    } else {
        $script:Ui.Detail.Text = 'Select a row to see why it matters and what the fix would do.'
        $script:Ui.BtnFix.Enabled = $false
    }
}

function Update-GuiRows {
    # Fills the list from the last audit (nothing is read from the box here) and keeps the selected row if it is still there.
    $win = $script:Ui
    $keep = ''
    $sel = Get-GuiSelectedFinding
    if ($sel) { $keep = [string]$sel.Key }
    $phase = Get-GuiPhase
    $problemsOnly = [bool]$win.ChkProblems.Checked
    $win.Updating = $true
    $shown = 0
    try {
        $win.List.BeginUpdate()
        $win.List.Items.Clear()
        foreach ($f in (Get-PhaseFindings $phase)) {
            if ($problemsOnly -and $f.Severity -ne 'BAD' -and $f.Severity -ne 'WARN') { continue }
            $view = Get-GuiRowView $f
            $item = New-Object System.Windows.Forms.ListViewItem([string]$view.Cells[0])
            for ($c = 1; $c -lt $view.Cells.Count; $c++) { [void]$item.SubItems.Add([string]$view.Cells[$c]) }
            $item.Tag = $f
            Set-GuiRowColor $item $view.Severity
            [void]$win.List.Items.Add($item)
            if ($keep -and [string]$f.Key -eq $keep) { $item.Selected = $true; $item.EnsureVisible() }
            $shown++
        }
    }
    finally {
        $win.List.EndUpdate()
        $win.Updating = $false
    }
    Update-GuiDetail
    $all = @($script:Hp.Findings)
    $bad = @($all | Where-Object { $_.Severity -eq 'BAD' }).Count
    $warn = @($all | Where-Object { $_.Severity -eq 'WARN' }).Count
    $win.StatusRight.Text = ('{0} rows ({1} shown) - {2} BAD - {3} WARN' -f $all.Count, $shown, $bad, $warn)
}

function Show-GuiDeadMan {
    # The dead-man label from the seconds left (and the full status, if we have one).
    param([int]$Seconds)
    $win = $script:Ui
    $d = Get-GuiDeadManText $Seconds $win.DeadStatus
    $win.LblDead.Text = $d.Text
    switch ($d.State) {
        'Armed' { $win.LblDead.BackColor = [System.Drawing.Color]::FromArgb(230, 140, 0); $win.LblDead.ForeColor = [System.Drawing.Color]::White }
        'Low'   { $win.LblDead.BackColor = [System.Drawing.Color]::FromArgb(200, 30, 30); $win.LblDead.ForeColor = [System.Drawing.Color]::White }
        'Fired' { $win.LblDead.BackColor = [System.Drawing.Color]::FromArgb(200, 30, 30); $win.LblDead.ForeColor = [System.Drawing.Color]::White }
        default { $win.LblDead.BackColor = [System.Drawing.Color]::Gainsboro; $win.LblDead.ForeColor = [System.Drawing.Color]::Black }
    }
}

function Update-GuiStatus {
    # Mode and the dead-man label. Cheap: no audit, no collectors.
    $win = $script:Ui
    if ($script:Hp.AllowChanges) {
        $win.LblMode.Text = 'CHANGES ALLOWED - every change shows what it will do and asks first'
        $win.LblMode.BackColor = [System.Drawing.Color]::FromArgb(200, 30, 30)
    } else {
        $win.LblMode.Text = 'AUDIT MODE - read only, nothing can be changed'
        $win.LblMode.BackColor = [System.Drawing.Color]::FromArgb(0, 140, 60)
    }
    $win.DeadStatus = Get-DeadManStatus
    Show-GuiDeadMan (Get-DeadManClock)
}

function Update-GuiAll {
    Update-GuiRows
    Update-GuiStatus
}

function Update-GuiAudit {
    # The whole audit: read the box, judge it, show everything.
    [void](Update-Audit)
    Update-GuiAll
    Set-GuiStatusText 'Audit done.'
}

function Update-GuiClock {
    # Once a second: the dead-man countdown. The full check (it asks Task Scheduler) runs every 20 seconds, and never during a job.
    $win = $script:Ui
    $left = Get-DeadManClock
    $win.Ticks = [int]$win.Ticks + 1
    $justEnded = ($left -eq 0 -and [int]$win.LastLeft -gt 0)
    if (-not $win.Busy -and (($win.Ticks % 20) -eq 1 -or $justEnded)) { $win.DeadStatus = Get-DeadManStatus }
    $win.LastLeft = $left
    Show-GuiDeadMan $left
}

# ---------------------------------------------------------------- what the buttons do
function Show-GuiResult {
    # One line in the status bar. A message box only when something did not work.
    param($Result, [string]$What)
    $line = '{0}: {1} - {2}' -f $Result.Status, $What, $Result.Message
    $out = (@($Result.Output) | Where-Object { $null -ne $_ }) -join ' | '
    if ($out) { $line += ('  (' + $out + ')') }
    Set-GuiStatusText $line
    if (@('Failed', 'Blocked', 'Skipped', 'Waiting') -contains $Result.Status) {
        Show-GuiMessage $Result.Status ($What + "`n`n" + $Result.Message)
    }
}

function Invoke-GuiFixSelected {
    $f = Get-GuiSelectedFinding
    if (-not $f) { Show-GuiMessage 'Fix selected' 'Select a row in the list first.'; return }
    $result = @(Invoke-FixFinding -Finding $f) | Select-Object -Last 1
    Show-GuiResult $result ([string]$f.Subject)
    Update-GuiAll
}

function Invoke-GuiFixPhase {
    $phase = Get-GuiPhase
    if ($phase -eq 0) { Show-GuiMessage 'Fix phase' 'Choose a phase in the Phase box first. A batch always belongs to one phase.'; return }
    if (-not $script:Hp.AllowChanges) { Show-GuiMessage 'Fix phase' 'Audit mode: tick "Allow changes" first.'; return }
    $rows = @(Get-BatchPlan -Phase $phase)
    if ($rows.Count -eq 0) { Show-GuiMessage "Fix phase $phase" "Nothing in phase $phase can be fixed in one batch right now."; return }
    $take = Get-List (Show-GuiBatchDialog -Phase $phase -Rows $rows -Waiting (Get-BatchWaiting -Phase $phase))
    if ($take.Count -eq 0) { Set-GuiStatusText "Fix phase ${phase}: nothing was run."; return }
    $summary = Invoke-FixPhase -Findings @($take | ForEach-Object { $_.Finding })
    $text = Format-PhaseSummary $summary
    $more = @(Get-BatchPlan -Phase $phase | Where-Object { $_.Tick }).Count
    if ($summary.Applied -gt 0 -and $more -gt 0) { $text += ([Environment]::NewLine + [Environment]::NewLine + "$more more row(s) can run now. Press Fix phase again.") }
    Set-GuiStatusText ("Fix phase ${phase}: applied $($summary.Applied), failed $($summary.Failed)")
    Update-GuiAll
    Show-GuiTextDialog "Fix phase $phase - result" $text
}

function Invoke-GuiUndoLast {
    $result = @(Invoke-Undo) | Select-Object -Last 1
    Show-GuiResult $result 'Undo last'
    Update-GuiAll
}

function Invoke-GuiUndoPick {
    $records = @(Get-UndoList)
    if ($records.Count -eq 0) { Show-GuiMessage 'Undo' 'Nothing to undo: no applied change with an undo is in the journal.'; return }
    $id = Show-GuiUndoDialog $records
    if ($id -le 0) { return }
    $result = @(Invoke-Undo -Id $id) | Select-Object -Last 1
    Show-GuiResult $result "Undo #$id"
    Update-GuiAll
}

function Show-GuiJournal {
    $lines = @(Get-JournalLines)
    if ($lines.Count -eq 0) { Show-GuiMessage 'Journal' 'The journal is empty: nothing has been changed yet.'; return }
    Show-GuiTextDialog 'Journal: every change made so far (oldest first)' ($lines -join "`n")
}

function Invoke-GuiDeadMan {
    param([string]$What)
    $result = @(Invoke-DeadManButton -What $What) | Select-Object -Last 1
    Show-GuiResult $result "Dead-man switch: $What"
    Update-GuiAll
}

function Switch-GuiAllowChanges {
    # The tick box. Switching changes ON asks you first; switching them OFF is immediate.
    $win = $script:Ui
    if ($win.Updating) { return }
    $want = [bool]$win.ChkAllow.Checked
    if ($want -and -not $script:Hp.AllowChanges) {
        $text = "Changes will be allowed. Every change still shows exactly what it will do and asks you first.`n`nGo ahead?"
        if (& $script:Hp.Ask 'Allow changes' $text '') {
            $script:Hp.AllowChanges = $true
            Write-HpLog 'changes switched ON'
        } else {
            $win.Updating = $true
            $win.ChkAllow.Checked = $false
            $win.Updating = $false
        }
    }
    elseif ((-not $want) -and $script:Hp.AllowChanges) {
        $script:Hp.AllowChanges = $false
        Write-HpLog 'changes switched OFF (audit mode)'
    }
    Update-GuiStatus
}

function Confirm-GuiClose {
    # The window's X button. Not while a job runs; and a question when the dead-man switch is still armed.
    param($CloseArgs)
    try {
        if ($script:Ui.Busy) {
            $CloseArgs.Cancel = $true
            Show-GuiMessage 'Please wait' 'A job is still running. Close the window when it has finished.'
            return
        }
        $left = Get-DeadManClock
        if ($left -gt 0) {
            $text = 'The dead-man switch is still ARMED: in ' + (Format-GuiClock $left) + " it restores the firewall to the state before you armed it.`n`nClosing this window does not disarm it. Close the window anyway?"
            if (-not (Show-GuiYesNo 'Close the window?' $text)) { $CloseArgs.Cancel = $true }
        }
    }
    catch { Write-HpLog "window handler 'close' failed: $($_.Exception.Message)" 'ERROR' }
}

function Start-GuiFirstAudit {
    $script:Ui.Timer.Start()
    Set-GuiColumnWidths
    Update-GuiAudit
}

# ---------------------------------------------------------------- the main window
function Build-GuiWindow {
    $win = $script:Ui
    $win.Busy = $false
    $win.Updating = $false
    $win.Ticks = 0
    $win.LastLeft = 0
    $win.DeadStatus = $null
    $win.PhaseNumbers = @(0) + @($script:PhaseOrder)
    $win.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $win.MonoFont = New-Object System.Drawing.Font('Consolas', 9.5)
    $win.Tip = New-Object System.Windows.Forms.ToolTip

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Hardening tool (assembly)'
    $area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $form.Size = New-Object System.Drawing.Size([math]::Min(1180, $area.Width - 40), [math]::Min(840, $area.Height - 40))
    $form.MinimumSize = New-Object System.Drawing.Size(760, 520)
    $form.StartPosition = 'CenterScreen'
    $form.Font = $win.Font
    $win.Form = $form

    # --- top bar: mode, dead-man switch
    $win.BarTop = Build-GuiBar
    $win.ChkAllow = New-Object System.Windows.Forms.CheckBox
    $win.ChkAllow.Text = 'Allow changes'
    $win.ChkAllow.AutoSize = $true
    $win.ChkAllow.Anchor = 'Left'
    $win.ChkAllow.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $win.ChkAllow.Add_CheckedChanged({ Invoke-GuiAction 'Allow changes' { Switch-GuiAllowChanges } })
    $win.LblMode = Build-GuiLight 'AUDIT MODE'
    $win.LblDead = Build-GuiLight 'Dead-man switch'
    $win.BtnArm = Build-GuiButton 'Arm' 'Save the firewall policy and schedule an automatic restore. Do this BEFORE any firewall change.'
    $win.BtnExtend = Build-GuiButton 'Extend' 'Move the automatic restore later (more time to test).'
    $win.BtnKeep = Build-GuiButton 'Keep changes' 'Cancel the automatic restore. Only after the NEIGH page shows RDP and Jenkins green.'
    $win.BtnArm.Add_Click({ Invoke-GuiAction 'Arm' { Invoke-GuiDeadMan 'Arm' } })
    $win.BtnExtend.Add_Click({ Invoke-GuiAction 'Extend' { Invoke-GuiDeadMan 'Extend' } })
    $win.BtnKeep.Add_Click({ Invoke-GuiAction 'Keep changes' { Invoke-GuiDeadMan 'Disarm' } })
    foreach ($c in @($win.ChkAllow, $win.LblMode, $win.LblDead, $win.BtnArm, $win.BtnExtend, $win.BtnKeep)) { $win.BarTop.Controls.Add($c) }

    # --- second bar: which phase, and the buttons
    $win.BarMid = Build-GuiBar
    $win.CmbPhase = New-Object System.Windows.Forms.ComboBox
    $win.CmbPhase.DropDownStyle = 'DropDownList'
    $win.CmbPhase.Width = 170
    [void]$win.CmbPhase.Items.Add('All findings')
    foreach ($p in $script:PhaseOrder) { [void]$win.CmbPhase.Items.Add(('{0} {1}' -f $p, (Get-PhaseName $p))) }
    $win.CmbPhase.SelectedIndex = 0
    $win.CmbPhase.Add_SelectedIndexChanged({ Invoke-GuiSafe 'phase box' { Update-GuiRows } })
    $win.ChkProblems = New-Object System.Windows.Forms.CheckBox
    $win.ChkProblems.Text = 'Only BAD and WARN'
    $win.ChkProblems.AutoSize = $true
    $win.ChkProblems.Checked = $true
    $win.ChkProblems.Anchor = 'Left'
    $win.ChkProblems.Add_CheckedChanged({ Invoke-GuiSafe 'problems box' { Update-GuiRows } })
    $win.BtnAudit = Build-GuiButton 'Re-audit' 'Read the whole box again (changes nothing).'
    $win.BtnFix = Build-GuiButton 'Fix selected' 'Fix the selected row. You see exactly what will change and confirm first.'
    $win.BtnPhase = Build-GuiButton 'Fix phase...' 'Fix several rows of the chosen phase, one after the other. Choose a phase in the box on the left first.'
    $win.BtnUndoLast = Build-GuiButton 'Undo last' 'Put the newest change back.'
    $win.BtnUndo = Build-GuiButton 'Undo...' 'Pick an earlier change to put back.'
    $win.BtnJournal = Build-GuiButton 'Journal...' 'List every change that was made.'
    $win.BtnHelp = Build-GuiButton 'Help'
    $win.BtnFix.Enabled = $false
    $win.BtnAudit.Add_Click({ Invoke-GuiAction 'Re-audit' { Update-GuiAudit } })
    $win.BtnFix.Add_Click({ Invoke-GuiAction 'Fix selected' { Invoke-GuiFixSelected } })
    $win.BtnPhase.Add_Click({ Invoke-GuiAction 'Fix phase' { Invoke-GuiFixPhase } })
    $win.BtnUndoLast.Add_Click({ Invoke-GuiAction 'Undo last' { Invoke-GuiUndoLast } })
    $win.BtnUndo.Add_Click({ Invoke-GuiAction 'Undo' { Invoke-GuiUndoPick } })
    $win.BtnJournal.Add_Click({ Invoke-GuiAction 'Journal' { Show-GuiJournal } })
    $win.BtnHelp.Add_Click({ Invoke-GuiAction 'Help' { Show-GuiTextDialog 'Help' (Get-GuiHelpText) } })
    $win.BarMid.Controls.Add((Build-GuiLabel 'Phase:'))
    foreach ($c in @($win.CmbPhase, $win.ChkProblems, $win.BtnAudit, $win.BtnFix, $win.BtnPhase, $win.BtnUndoLast, $win.BtnUndo, $win.BtnJournal, $win.BtnHelp)) { $win.BarMid.Controls.Add($c) }

    # --- the list, the explanation of the selected row, the log
    $lv = New-Object System.Windows.Forms.ListView
    $lv.Dock = 'Fill'
    $lv.View = 'Details'
    $lv.FullRowSelect = $true
    $lv.MultiSelect = $false
    $lv.HideSelection = $false
    $lv.GridLines = $true
    [void]$lv.Columns.Add('Sev', 55)
    [void]$lv.Columns.Add('Phase', 105)
    [void]$lv.Columns.Add('Area', 110)
    [void]$lv.Columns.Add('Subject', 600)
    [void]$lv.Columns.Add('Fix', 60)
    $lv.Add_SelectedIndexChanged({ Invoke-GuiSafe 'select a row' { if (-not $script:Ui.Updating) { Update-GuiDetail } } })
    $lv.Add_SizeChanged({ Invoke-GuiSafe 'resize the list' { Set-GuiColumnWidths } })
    $win.List = $lv
    $win.Detail = Build-GuiTextBox
    $win.Log = Build-GuiTextBox

    # --- the page: bars on top, list, explanation, log; the status bar at the bottom
    $table = New-Object System.Windows.Forms.TableLayoutPanel
    $table.Dock = 'Fill'
    $table.ColumnCount = 1
    $table.RowCount = 5
    [void]$table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle('Percent', 100)))
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'AutoSize'
    Add-GuiRowStyle $table 'Percent' 50
    Add-GuiRowStyle $table 'Percent' 22
    Add-GuiRowStyle $table 'Percent' 28
    $table.Controls.Add($win.BarTop, 0, 0)
    $table.Controls.Add($win.BarMid, 0, 1)
    $table.Controls.Add($win.List, 0, 2)
    $table.Controls.Add($win.Detail, 0, 3)
    $table.Controls.Add($win.Log, 0, 4)
    $form.Controls.Add($table)

    $strip = New-Object System.Windows.Forms.StatusStrip
    $win.StatusLeft = New-Object System.Windows.Forms.ToolStripStatusLabel
    $win.StatusLeft.Spring = $true
    $win.StatusLeft.TextAlign = 'MiddleLeft'
    $win.StatusLeft.Text = 'Starting...'
    $win.StatusRight = New-Object System.Windows.Forms.ToolStripStatusLabel
    [void]$strip.Items.Add($win.StatusLeft)
    [void]$strip.Items.Add($win.StatusRight)
    $form.Controls.Add($strip)

    # --- the clock and the window's own events
    $win.Timer = New-Object System.Windows.Forms.Timer
    $win.Timer.Interval = 1000
    $win.Timer.Add_Tick({ Invoke-GuiSafe 'clock' { Update-GuiClock } })
    $form.Add_Shown({ Invoke-GuiAction 'First audit' { Start-GuiFirstAudit } })
    $form.Add_FormClosing({ param($from, $closeArgs) $null = $from; Confirm-GuiClose $closeArgs })
    Update-GuiDetail
}

function Initialize-GuiAssemblies {
    # Loads WinForms. Done when the window opens, never when the file is loaded. (The tests replace this function.)
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
        throw 'This PowerShell is not in STA mode, which the window needs. Start it with  powershell -STA ...  or use the text menu (-NoGui -Apply).'
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
}

function Remove-GuiWindow {
    # Stops the clock and throws the window away.
    if ($script:Ui.Timer) { $script:Ui.Timer.Stop(); $script:Ui.Timer.Dispose() }
    if ($script:Ui.Form) { $script:Ui.Form.Dispose() }
    $script:Ui = @{}
}

function Show-HardeningWindow {
    # Builds the window and shows it. Returns when it is closed. A problem while BUILDING it is thrown to the launcher,
    # which then starts the text menu instead (the same tool, the same safety checks).
    Initialize-GuiAssemblies
    $saved = @{
        Ask = $script:Hp.Ask; AskSecret = $script:Hp.AskSecret; AskText = $script:Hp.AskText
        Notify = $script:Hp.Notify; OnLog = $script:Hp.OnLog; OnBusy = $script:Hp.OnBusy
    }
    try {
        $script:Ui = @{}
        Build-GuiWindow
        Set-GuiHooks
        [void]$script:Ui.Form.ShowDialog()
    }
    finally {
        $script:Hp.Ask = $saved.Ask
        $script:Hp.AskSecret = $saved.AskSecret
        $script:Hp.AskText = $saved.AskText
        $script:Hp.Notify = $saved.Notify
        $script:Hp.OnLog = $saved.OnLog
        $script:Hp.OnBusy = $saved.OnBusy
        Remove-GuiWindow
    }
}

function Test-HardeningWindow {
    # "Does the window work on THIS machine?" Builds the main window and every dialog WITHOUT showing them, fills the list from the
    # last audit, and throws the first error it meets. Start-Hardening.ps1 -GuiSelfTest runs it. Returns the number of dialogs it built.
    Initialize-GuiAssemblies
    try {
        $script:Ui = @{}
        Build-GuiWindow
        Update-GuiAll
        $rows = @(Get-BatchPlan -Phase 2)
        $dialogs = @(
            (Build-GuiConfirmDialog 'Self-test' "line one`nline two" 'APPLY'),
            (Build-GuiConfirmDialog 'Self-test' 'no word needed'),
            (Build-GuiInputDialog -Prompt 'A question?' -Default 'x'),
            (Build-GuiInputDialog -Prompt 'A secret?' -Secret),
            (Build-GuiTextDialog 'Self-test' (Get-GuiHelpText)),
            (Build-GuiBatchDialog -Phase 2 -Rows $rows -Waiting 1),
            (Build-GuiUndoDialog @([pscustomobject]@{ Id = 1; Time = 'now'; Risk = 'Low'; Title = 'a change' }))
        )
        foreach ($d in $dialogs) { $d.Dispose() }
        $dialogs.Count
    }
    finally { Remove-GuiWindow }
}
