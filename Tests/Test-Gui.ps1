# Test-Gui.ps1 - runs the window's own PowerShell code (lib\Gui.ps1) with stand-in WinForms classes (Tests\FakeWinForms.cs) on top of the
# pretend lab box, with the REAL judges, actions and gate. A scripted "person" opens the window, ticks boxes, picks rows, presses buttons,
# answers the dialogs; the test then looks at what the window shows and what happened to the pretend box.
#
# It proves the window's logic: what every button does, what the list and the lights show, what the dialogs ask, that a mistake inside a
# button does not kill the window, that the close button is careful. It does NOT prove anything about real WinForms: layout, painting, DPI,
# fonts, focus and the real message loop need Windows - run  Start-Hardening.ps1 -GuiSelfTest  there. (Tests\Test-GuiApi.ps1 checks every
# WinForms name used in Gui.ps1 against the real .NET list.) On Windows this test does nothing: the real WinForms is there.
param([string]$GuiFile = '')        # normally empty: the window code is lib\Gui.ps1. A damaged copy can be given to see that this test notices.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
if ($env:OS -eq 'Windows_NT') {
    Write-Host 'Skipped on Windows: the real WinForms is installed here. Run  Start-Hardening.ps1 -GuiSelfTest  to check the window on this machine.' -ForegroundColor Yellow
    Write-TestSummary
    exit 0
}
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
$guiLibrary = Join-Path $PSScriptRoot '..\lib\Gui.ps1'
if ($GuiFile) { $guiLibrary = $GuiFile }
. $guiLibrary
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$script:HpRoot = Join-Path $PSScriptRoot '..'
$script:Dirs = New-Object System.Collections.ArrayList

# ---- the stand-in WinForms classes, and the two small changes that let Gui.ps1 run on Linux
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'FakeWinForms.cs')))

function Initialize-GuiAssemblies { }       # the real one loads WinForms; the stand-ins are already loaded

# System.Drawing.Font cannot be made on Linux. Gui.ps1 only hands it on to a control, so a plain object will do; everything else is the real New-Object.
function New-Object {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
    param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)]$ArgumentList)
    if ($TypeName -eq 'System.Drawing.Font') { return [pscustomobject]@{ Name = $ArgumentList[0]; Size = $ArgumentList[1] } }
    Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}

# ---- the scripted person
$script:ProbeRed = @()
$script:Steps = New-Object System.Collections.Queue          # what the person does in each dialog that opens, in order (one script block each)
$script:Answers = New-Object System.Collections.Queue        # which button the person presses in each message box (default: OK, or No for a question)
$script:OpenedDialogs = New-Object System.Collections.ArrayList
$script:SurpriseDialogs = New-Object System.Collections.ArrayList
$script:Scenario = $null
$script:Seen = $null

function Initialize-Stage {
    [FakeLab.Stage]::Reset()
    $script:Steps.Clear()
    $script:Answers.Clear()
    $script:OpenedDialogs.Clear()
    $script:SurpriseDialogs.Clear()
    [FakeLab.Stage]::OnDialog = {
        param($shown)
        [void]$script:OpenedDialogs.Add($shown.Text)
        if ($script:Steps.Count -eq 0) { [void]$script:SurpriseDialogs.Add($shown.Text); return [System.Windows.Forms.DialogResult]::Cancel }
        $step = $script:Steps.Dequeue()
        $given = @(& $step $shown | Where-Object { $_ -is [System.Windows.Forms.DialogResult] }) | Select-Object -Last 1
        if ($null -eq $given) { return [System.Windows.Forms.DialogResult]::Cancel }
        $given
    }
    [FakeLab.Stage]::OnMessage = {
        param($title, $text, $buttons)
        $null = $title, $text
        if ($script:Answers.Count -gt 0) { return $script:Answers.Dequeue() }
        if ($buttons -eq [System.Windows.Forms.MessageBoxButtons]::YesNo) { return [System.Windows.Forms.DialogResult]::No }
        [System.Windows.Forms.DialogResult]::OK
    }
}

function Add-Step { param([scriptblock]$Step) $script:Steps.Enqueue($Step) }

function Start-Fresh {
    # A brand-new pretend box, a new data folder, a closed window, the person ready to be scripted. Every section starts here.
    $global:FW = New-FakeBox
    $dir = Join-Path ([IO.Path]::GetTempPath()) ('hp-gui-' + [guid]::NewGuid().ToString('N'))
    [void]$script:Dirs.Add($dir)
    Initialize-Hp -DataDir $dir -NoAcl
    $script:ProbeRed = @()
    $script:Hp.AllowChanges = $false
    $script:Ui = @{}
    $script:Dlg = @{}
    Initialize-Stage
}

function Invoke-Window {
    # Opens the window exactly like the launcher does (Show-HardeningWindow) and runs the scenario while it is open.
    param([scriptblock]$Code)
    $script:Scenario = $Code
    [FakeLab.Stage]::OnMainForm = { param($mainWindow) $null = $mainWindow; & $script:Scenario }
    Show-HardeningWindow
    [FakeLab.Stage]::OnMainForm = $null
}

function Find-Control {
    # The first control below $Root (the whole tree is searched) for which the test returns true.
    param($Root, [scriptblock]$Test)
    foreach ($c in $Root.Controls) {
        if (& $Test $c) { return $c }
        $deeper = Find-Control $c $Test
        if ($deeper) { return $deeper }
    }
    $null
}

function Find-Button {
    # The button with this text anywhere below $Root, or $null.
    param($Root, [string]$Text)
    foreach ($c in $Root.Controls) {
        if ($c -is [System.Windows.Forms.Button] -and $c.Text -eq $Text) { return $c }
        $deeper = Find-Button $c $Text
        if ($deeper) { return $deeper }
    }
    $null
}

function Invoke-Click {
    # Presses the button with this text in a window or dialog. $false when there is no such button or it is greyed out.
    param($Root, [string]$Text)
    $button = Find-Button $Root $Text
    if (-not $button -or -not $button.CanUse) { return $false }
    $button.PerformClick()
    $true
}

function Get-DialogText {
    # The long text of a dialog (the preview of a change, the journal ...).
    param($Root)
    $box = Find-Control $Root { param($x) $x -is [System.Windows.Forms.TextBox] }
    if ($box) { $box.Text } else { '' }
}

function Select-Row {
    # Clicks the row of the list whose subject matches. Returns the list item, or $null when the list has no such row.
    param([string]$Subject)
    foreach ($item in $script:Ui.List.Items) {
        if ($item.Tag.Subject -like $Subject) { $item.Selected = $true; return $item }
    }
    $null
}

function Get-ListRows {
    @($script:Ui.List.Items | ForEach-Object {
        [pscustomobject]@{ Sev = $_.Text; Phase = $_.SubItems[1].Text; Area = $_.SubItems[2].Text; Subject = $_.SubItems[3].Text; Fix = $_.SubItems[4].Text
                           Back = $_.BackColor.ToArgb(); Fore = $_.ForeColor.ToArgb(); Finding = $_.Tag }
    })
}

function Get-Argb { param([int]$A, [int]$R, [int]$G, [int]$B) [System.Drawing.Color]::FromArgb($A, $R, $G, $B).ToArgb() }
function Test-NoSurprises { @($script:SurpriseDialogs).Count -eq 0 }

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The little helpers (no controls)' -ForegroundColor Cyan
Assert-Equal (Format-GuiClock 275) '4:35' '275 seconds read 4:35'
Assert-Equal (Format-GuiClock 59) '0:59' '59 seconds read 0:59'
Assert-Equal (Format-GuiClock 0) '0:00' '0 seconds read 0:00'
Assert-Equal (ConvertTo-GuiText "a`nb") "a`r`nb" 'a text box gets CR+LF line ends'
Assert-Equal (ConvertTo-GuiText "a`r`nb") "a`r`nb" '... and a text that has them already is not doubled'
Assert-Equal (Get-GuiDeadManText 275 $null).State 'Armed' 'dead-man: 275 seconds left = Armed'
Assert-Equal (Get-GuiDeadManText 30 $null).State 'Low' 'dead-man: under a minute = Low'
Assert-True ((Get-GuiDeadManText 275 $null).Text -match '4:35' -and (Get-GuiDeadManText 275 $null).Text -match 'Keep changes') 'dead-man: the text shows the time and tells you what to press'
Assert-Equal (Get-GuiDeadManText 0 $null).State 'Off' 'dead-man: nothing armed = Off'
$fired = Get-GuiDeadManText 0 ([pscustomobject]@{ FiredAt = '2026-10-17 10:15' })
Assert-True ($fired.State -eq 'Fired' -and $fired.Text -match '10:15' -and $fired.Text -match 'restored') 'dead-man: a status with FiredAt = Fired, with the time'
Assert-Equal (Get-GuiDeadManText 90 ([pscustomobject]@{ FiredAt = 'x' })).State 'Armed' 'dead-man: still armed beats an old FiredAt'
Assert-True ((Get-GuiHelpText) -match 'AUDIT mode' -and (Get-GuiHelpText) -match 'Panic.ps1' -and (Get-GuiHelpText) -match 'Keep changes') 'the help text names the audit mode, Keep changes and Panic.ps1'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The window opens and shows the audit' -ForegroundColor Cyan
Start-Fresh
$askBefore = $script:Hp.Ask
$logHookBefore = $script:Hp.OnLog
Invoke-Window {
    $script:Seen = [pscustomobject]@{
        Title = $script:Ui.Form.Text
        Rows = @(Get-ListRows)
        Mode = $script:Ui.LblMode.Text
        Dead = $script:Ui.LblDead.Text
        Left = $script:Ui.StatusLeft.Text
        Right = $script:Ui.StatusRight.Text
        TimerOn = $script:Ui.Timer.Enabled
        TimerMs = $script:Ui.Timer.Interval
        FixEnabled = $script:Ui.BtnFix.Enabled
        PhaseItems = $script:Ui.CmbPhase.Items.Count
        LogLength = $script:Ui.Log.Text.Length
        Detail = $script:Ui.Detail.Text
        AskIsGui = [object]::ReferenceEquals($script:Hp.Ask, ${function:Show-GuiConfirm})
    }
}
$shot = $script:Seen
$problemRows = @(Get-PhaseFindings 0 | Where-Object { $_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN' })
Assert-True ([FakeLab.Stage]::Dialogs -contains 'Hardening tool (assembly)') 'the main window was shown'
Assert-True ($shot.Rows.Count -gt 10 -and $shot.Rows.Count -eq $problemRows.Count) "the list shows the BAD and WARN rows of the audit ($($shot.Rows.Count))"
Assert-True (@($shot.Rows | Where-Object { $_.Sev -ne 'BAD' -and $_.Sev -ne 'WARN' }).Count -eq 0) '... and nothing else (the "Only BAD and WARN" box starts ticked)'
$badRow = @($shot.Rows | Where-Object { $_.Sev -eq 'BAD' }) | Select-Object -First 1
$warnRow = @($shot.Rows | Where-Object { $_.Sev -eq 'WARN' }) | Select-Object -First 1
Assert-True ($badRow -and $badRow.Back -eq (Get-Argb 255 255 215 215)) 'a BAD row has the red background'
Assert-True ($warnRow -and $warnRow.Back -eq (Get-Argb 255 255 245 200)) 'a WARN row has the yellow background'
Assert-True ($badRow.Phase -match '^\d [A-Za-z]' -and $badRow.Area -and $badRow.Subject) 'each row shows phase, area and subject'
Assert-True (@($shot.Rows | Where-Object { $_.Fix -eq 'yes' }).Count -gt 3 -and @($shot.Rows | Where-Object { $_.Fix -eq 'waits' }).Count -ge 1) 'the Fix column says yes for rows that can be fixed and "waits" for rows that wait for something else'
Assert-True ($shot.Mode -match '^AUDIT MODE' -and $shot.Mode -match 'read only') 'the window starts in AUDIT mode'
Assert-Equal $shot.Dead 'Dead-man switch: not armed' 'the dead-man label says not armed'
Assert-Equal $shot.Left 'Audit done.' 'the status bar says the audit is done'
Assert-True ($shot.Right -match '^\d+ rows \(\d+ shown\) - \d+ BAD - \d+ WARN$') "the right side of the status bar counts the rows ($($shot.Right))"
Assert-True ($shot.TimerOn -and $shot.TimerMs -eq 1000) 'the clock runs once a second'
Assert-True (-not $shot.FixEnabled) 'Fix selected is grey until a row is selected'
Assert-Equal $shot.PhaseItems (1 + @($script:PhaseOrder).Count) 'the phase box lists "All findings" and every phase'
Assert-True ($shot.Detail -match 'Select a row') 'the explanation box tells you to select a row'
Assert-True ($shot.AskIsGui) 'while the window is open the questions go through the window (the Ask hook is the dialog)'
Assert-True ([object]::ReferenceEquals($script:Hp.Ask, $askBefore) -and [object]::ReferenceEquals($script:Hp.OnLog, $logHookBefore)) 'after it closes the old hooks are back (the text menu works again)'
Assert-True ($script:Ui.Count -eq 0) 'and the window''s controls are thrown away'
Assert-True ([FakeLab.Stage]::DoEventsCalls -gt 0) 'the window kept itself alive while the collectors worked (DoEvents)'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Picking a row, and the filter' -ForegroundColor Cyan
Start-Fresh
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $null = Select-Row 'Guest is enabled'
    $script:Seen | Add-Member -NotePropertyName GuestDetail -NotePropertyValue $script:Ui.Detail.Text
    $script:Seen | Add-Member -NotePropertyName GuestFixOn -NotePropertyValue $script:Ui.BtnFix.Enabled
    $script:Ui.ChkProblems.PerformClick()                       # untick "Only BAD and WARN"
    $script:Seen | Add-Member -NotePropertyName AllRows -NotePropertyValue @(Get-ListRows).Count
    $script:Seen | Add-Member -NotePropertyName KeptGuest -NotePropertyValue ($script:Ui.List.SelectedItems.Count -eq 1 -and $script:Ui.List.SelectedItems[0].Tag.Subject -like 'Guest is enabled*')
    $null = Select-Row 'This box*'
    $script:Seen | Add-Member -NotePropertyName InfoDetail -NotePropertyValue $script:Ui.Detail.Text
    $script:Seen | Add-Member -NotePropertyName InfoFixOn -NotePropertyValue $script:Ui.BtnFix.Enabled
    $null = Select-Row 'plinktern*'
    $script:Seen | Add-Member -NotePropertyName WaitDetail -NotePropertyValue $script:Ui.Detail.Text
    $script:Seen | Add-Member -NotePropertyName WaitFixOn -NotePropertyValue $script:Ui.BtnFix.Enabled
    # the phase box
    $second = [array]::IndexOf($script:Ui.PhaseNumbers, 2)
    $script:Ui.CmbPhase.SelectedIndex = $second
    $script:Seen | Add-Member -NotePropertyName PhaseRows -NotePropertyValue @(Get-ListRows)
}
$shot = $script:Seen
$everything = @(Get-PhaseFindings 0)
Assert-True ($shot.GuestDetail -match 'Guest' -and $shot.GuestDetail -match 'Fix: available' -and $shot.GuestDetail -match "`r`n") 'selecting a fixable row shows its explanation (with Windows line ends)'
Assert-True ($shot.GuestFixOn) 'and Fix selected turns on'
Assert-Equal $shot.AllRows $everything.Count 'unticking "Only BAD and WARN" shows every row of the audit, information rows too'
Assert-True ($shot.KeptGuest) 'the selected row stays selected when the list is filled again'
Assert-True ($shot.InfoDetail -match 'Fix: none' -and -not $shot.InfoFixOn) 'an information row: "Fix: none" and Fix selected stays grey'
Assert-True ($shot.WaitDetail -match 'not possible yet' -and -not $shot.WaitFixOn) 'a row that waits for another: "not possible yet" and Fix selected stays grey'
Assert-True ($shot.PhaseRows.Count -gt 3 -and @($shot.PhaseRows | Where-Object { $_.Phase -notmatch '^2 ' }).Count -eq 0) 'choosing phase 2 in the box shows only the Accounts rows'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Allow changes' -ForegroundColor Cyan
Start-Fresh
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $null = Select-Row 'Guest is enabled'
    $script:Ui.BtnFix.PerformClick()                            # audit mode: refused, nothing asked
    $script:Seen | Add-Member -NotePropertyName AuditStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName AuditMessages -NotePropertyValue @([FakeLab.Stage]::Messages)
    $script:Seen | Add-Member -NotePropertyName AuditGuest -NotePropertyValue $global:FW.Users['Guest'].Enabled
    $script:Seen | Add-Member -NotePropertyName AuditDialogs -NotePropertyValue $script:OpenedDialogs.Count
    # tick the box and say no
    Add-Step { param($d) $script:AllowTitle = $d.Text; $script:AllowText = Get-DialogText $d; [void](Invoke-Click $d 'No, cancel'); $d.DialogResult }
    $script:Ui.ChkAllow.PerformClick()
    $script:Seen | Add-Member -NotePropertyName NoChecked -NotePropertyValue $script:Ui.ChkAllow.Checked
    $script:Seen | Add-Member -NotePropertyName NoAllowed -NotePropertyValue $script:Hp.AllowChanges
    $script:Seen | Add-Member -NotePropertyName NoMode -NotePropertyValue $script:Ui.LblMode.Text
    # tick the box and say yes
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.ChkAllow.PerformClick()
    $script:Seen | Add-Member -NotePropertyName YesChecked -NotePropertyValue $script:Ui.ChkAllow.Checked
    $script:Seen | Add-Member -NotePropertyName YesAllowed -NotePropertyValue $script:Hp.AllowChanges
    $script:Seen | Add-Member -NotePropertyName YesMode -NotePropertyValue $script:Ui.LblMode.Text
    $script:Seen | Add-Member -NotePropertyName YesColor -NotePropertyValue $script:Ui.LblMode.BackColor.ToArgb()
    # untick: immediate, nothing asked
    $before = $script:OpenedDialogs.Count
    $script:Ui.ChkAllow.PerformClick()
    $script:Seen | Add-Member -NotePropertyName OffAllowed -NotePropertyValue $script:Hp.AllowChanges
    $script:Seen | Add-Member -NotePropertyName OffAsked -NotePropertyValue ($script:OpenedDialogs.Count - $before)
    $script:Seen | Add-Member -NotePropertyName OffMode -NotePropertyValue $script:Ui.LblMode.Text
}
$shot = $script:Seen
Assert-True ($shot.AuditStatus -match '^Blocked: ' -and $shot.AuditStatus -match 'Audit mode') 'audit mode: Fix selected ends with a "Blocked ... Audit mode" line'
Assert-True (@($shot.AuditMessages).Count -eq 1 -and $shot.AuditMessages[0] -match '^Blocked \|') 'and a message box tells you so'
Assert-True ($shot.AuditGuest -and $shot.AuditDialogs -eq 0) 'nothing was changed and no question was asked'
Assert-True ($script:AllowTitle -eq 'Allow changes' -and $script:AllowText -match 'asks you first') 'ticking "Allow changes" asks first, and says every change still asks'
Assert-True (-not $shot.NoChecked -and -not $shot.NoAllowed -and $shot.NoMode -match '^AUDIT MODE') 'you say No: the box un-ticks itself and the window stays in audit mode'
Assert-True ($shot.YesChecked -and $shot.YesAllowed -and $shot.YesMode -match '^CHANGES ALLOWED') 'you say Yes: changes are allowed and the label says so'
Assert-Equal $shot.YesColor (Get-Argb 255 200 30 30) 'and the label turns red'
Assert-True (-not $shot.OffAllowed -and $shot.OffAsked -eq 0 -and $shot.OffMode -match '^AUDIT MODE') 'unticking switches changes off at once, without a question'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Fix selected: you can say no, and you can say yes' -ForegroundColor Cyan
Start-Fresh
$script:Hp.AllowChanges = $true
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $null = Select-Row 'Guest is enabled'
    $script:Ui.ChkAllow.Checked = $true                         # keeps the window's own switch in step with the tool
    Add-Step { param($d) $script:FixTitle = $d.Text; $script:FixText = Get-DialogText $d; [void](Invoke-Click $d 'No, cancel'); $d.DialogResult }
    $script:Ui.BtnFix.PerformClick()
    $script:Seen | Add-Member -NotePropertyName NoStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName NoGuest -NotePropertyValue $global:FW.Users['Guest'].Enabled
    $script:Seen | Add-Member -NotePropertyName NoStillThere -NotePropertyValue ($script:Ui.List.SelectedItems.Count -eq 1)
    $script:Seen | Add-Member -NotePropertyName NoBusy -NotePropertyValue $script:Ui.Busy
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnFix.PerformClick()
    $script:Seen | Add-Member -NotePropertyName YesStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName YesGuest -NotePropertyValue $global:FW.Users['Guest'].Enabled
    $script:Seen | Add-Member -NotePropertyName YesRowGone -NotePropertyValue (@(Get-ListRows | Where-Object { $_.Subject -like 'Guest is enabled*' }).Count -eq 0)
    $script:Seen | Add-Member -NotePropertyName YesFixOn -NotePropertyValue $script:Ui.BtnFix.Enabled
    $script:Seen | Add-Member -NotePropertyName YesDetail -NotePropertyValue $script:Ui.Detail.Text
    $script:Seen | Add-Member -NotePropertyName YesBusy -NotePropertyValue $script:Ui.Busy
    $script:Seen | Add-Member -NotePropertyName Messages -NotePropertyValue @([FakeLab.Stage]::Messages)
}
$shot = $script:Seen
Assert-True ($script:FixText -match 'Guest' -and $script:FixText -match 'Risk' -and $script:FixTitle) "the question shows what will change (title: $script:FixTitle)"
Assert-True ($shot.NoStatus -match '^Cancelled: ' -and $shot.NoGuest -and $shot.NoStillThere) 'you say No: Cancelled, Guest is still enabled, the row stays selected'
Assert-True ($shot.YesStatus -match '^Applied: ' -and -not $shot.YesGuest) 'you say Yes: Applied, and Guest is disabled on the box'
Assert-True ($shot.YesRowGone -and -not $shot.YesFixOn -and $shot.YesDetail -match 'Select a row') 'the list was filled again from a fresh audit: the Guest row is gone and nothing is selected'
Assert-True (-not $shot.NoBusy -and -not $shot.YesBusy) 'the buttons are usable again afterwards (no stuck "busy")'
Assert-Equal @($shot.Messages).Count 0 'a normal outcome opens no message box (the status bar is enough)'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The confirm dialog: the word for a High-risk change, and the secret prompts' -ForegroundColor Cyan
Start-Fresh
Add-Step {
    param($d)
    $yes = Find-Button $d 'Yes, do it'
    $script:WordSeen = [System.Collections.ArrayList]@($yes.Enabled)
    foreach ($try in 'apply', 'APPLY ', ' APPLY', 'APPL', 'APPLY') { $script:Dlg.Typed.Text = $try; [void]$script:WordSeen.Add($yes.Enabled) }
    $script:WordText = Get-DialogText $d
    [void](Invoke-Click $d 'Yes, do it')
    $d.DialogResult
}
$answer = Show-GuiConfirm 'Dangerous' "This is risky.`nReally?" 'APPLY'
Assert-True ($answer -eq $true) 'the right word unlocks Yes and Yes returns true'
Assert-Equal (($script:WordSeen | ForEach-Object { [string]$_ }) -join ',') 'False,False,False,False,False,True' 'Yes is grey at first, stays grey for apply / "APPLY " / " APPLY" / APPL, and unlocks only for APPLY (capital letters count)'
Assert-True ($script:WordText -match 'This is risky' -and $script:Dlg.Count -eq 0) 'the dialog showed the text, and its controls were thrown away afterwards'
Add-Step { param($d) $script:Dlg.Typed.Text = 'nope'; $script:ClickedDisabled = Invoke-Click $d 'Yes, do it'; [void](Invoke-Click $d 'No, cancel'); $d.DialogResult }
$answer = Show-GuiConfirm 'Dangerous' 'Really?' 'APPLY'
Assert-True ($answer -eq $false -and $script:ClickedDisabled -eq $false) 'with the wrong word the Yes button cannot be pressed, and No returns false'
Add-Step { param($d) $script:PlainYes = (Find-Button $d 'Yes, do it').Enabled; $script:HasTypedBox = [bool]$script:Dlg.Typed; [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
$answer = Show-GuiConfirm 'Plain' 'Really?'
Assert-True ($answer -eq $true -and $script:PlainYes -and -not $script:HasTypedBox) 'a change without a word: Yes is usable at once and there is no typing box'
Add-Step { param($d) $null = $d; [System.Windows.Forms.DialogResult]::Cancel }
Assert-True ((Show-GuiConfirm 'Plain' 'Really?') -eq $false) 'closing the dialog with the X (Cancel) counts as No'

Add-Step { param($d) $script:Dlg.Box.Text = '172.16.5.5'; [void](Invoke-Click $d 'OK'); $d.DialogResult }
Assert-Equal (Read-GuiText 'Blackbox IP?' '10.0.0.1') '172.16.5.5' 'a text question returns what you typed'
Add-Step { param($d) $script:BoxStart = $script:Dlg.Box.Text; $script:Dlg.Box.Text = ''; [void](Invoke-Click $d 'OK'); $d.DialogResult }
Assert-True ((Read-GuiText 'Blackbox IP?' '10.0.0.1') -eq '10.0.0.1' -and $script:BoxStart -eq '10.0.0.1') 'the box starts with the default, and an empty answer gives the default back'
Add-Step { param($d) $script:Dlg.Box.Text = 'typed but cancelled'; [void](Invoke-Click $d 'Cancel'); $d.DialogResult }
Assert-True ($null -eq (Read-GuiText 'Blackbox IP?' '10.0.0.1')) 'Cancel returns nothing, whatever was typed'
Add-Step { param($d) $script:SecretHidden = $script:Dlg.Box.UseSystemPasswordChar; $script:SecretTitle = $d.Text; $script:Dlg.Box.Text = 'Tr0ub4dor&3-secret'; [void](Invoke-Click $d 'OK'); $d.DialogResult }
$secret = Read-GuiSecret 'Password?'
Assert-True ($secret -eq 'Tr0ub4dor&3-secret' -and $script:SecretHidden -and $script:SecretTitle -match 'hidden') 'a secret question hides what you type, says so, and returns the text'
Add-Step { param($d) [void](Invoke-Click $d 'OK'); $d.DialogResult }
Assert-True ($null -eq (Read-GuiSecret 'Password?')) 'an empty secret counts as cancelled'
Add-Step { param($d) $script:Dlg.Box.Text = 'another-secret'; [void](Invoke-Click $d 'Cancel'); $d.DialogResult }
Assert-True ($null -eq (Read-GuiSecret 'Password?')) 'a cancelled secret returns nothing'
Assert-True (@($script:Hp.LogLines | Where-Object { $_ -match 'Tr0ub4dor|another-secret' }).Count -eq 0 -and $script:Dlg.Count -eq 0) 'the secret is in no log line, and the dialog''s controls are gone'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Fix phase: the batch dialog' -ForegroundColor Cyan
Start-Fresh
$script:Hp.AllowChanges = $true
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $script:Ui.ChkAllow.Checked = $true
    $script:Ui.BtnPhase.PerformClick()                          # no phase chosen
    $script:Seen | Add-Member -NotePropertyName NoPhaseMessage -NotePropertyValue (@([FakeLab.Stage]::Messages) | Select-Object -Last 1)
    $script:Ui.CmbPhase.SelectedIndex = [array]::IndexOf($script:Ui.PhaseNumbers, 2)
    Add-Step {
        param($d)
        $script:BatchTitle = $d.Text
        $script:BatchRows = @($script:Dlg.List.Items | ForEach-Object { [pscustomobject]@{ Title = $_.Text; Risk = $_.SubItems[1].Text; Ticked = $_.Checked } })
        foreach ($item in $script:Dlg.List.Items) { if ($item.Text -match 'lockout') { $item.Checked = $false } }
        $script:BatchTicksAfter = @($script:Dlg.List.Items | Where-Object { $_.Checked }).Count
        [void](Invoke-Click $d 'Untick all')
        $script:BatchAfterNone = @($script:Dlg.List.Items | Where-Object { $_.Checked }).Count
        [void](Invoke-Click $d 'Tick all')
        $script:BatchAfterAll = @($script:Dlg.List.Items | Where-Object { $_.Checked }).Count
        foreach ($item in $script:Dlg.List.Items) { $item.Checked = ($item.Text -match 'Guest') }
        [void](Invoke-Click $d 'Run the ticked rows')
        $d.DialogResult
    }
    Add-Step { param($d) $script:ResultTitle = $d.Text; $script:ResultText = Get-DialogText $d; [void](Invoke-Click $d 'Close'); $d.DialogResult }
    $script:Ui.BtnPhase.PerformClick()
    $script:Seen | Add-Member -NotePropertyName Status -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName Guest -NotePropertyValue $global:FW.Users['Guest'].Enabled
    $script:Seen | Add-Member -NotePropertyName Lockout -NotePropertyValue $global:FW.Lockout
    $script:Seen | Add-Member -NotePropertyName Busy -NotePropertyValue $script:Ui.Busy
    # the phase has nothing ticked-by-default left that we unticked; choose "run" with nothing ticked
    Add-Step { param($d) foreach ($item in $script:Dlg.List.Items) { $item.Checked = $false }; [void](Invoke-Click $d 'Run the ticked rows'); $d.DialogResult }
    $script:Ui.BtnPhase.PerformClick()
    $script:Seen | Add-Member -NotePropertyName NothingStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    # cancel
    Add-Step { param($d) [void](Invoke-Click $d 'Cancel'); $d.DialogResult }
    $script:Ui.BtnPhase.PerformClick()
    $script:Seen | Add-Member -NotePropertyName CancelStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName LockoutAfterCancel -NotePropertyValue $global:FW.Lockout
}
$shot = $script:Seen
Assert-True ($shot.NoPhaseMessage -match 'Choose a phase') 'Fix phase without a phase chosen: a message, nothing else'
Assert-True ($script:BatchTitle -match '^Fix phase 2 Accounts$') "the batch dialog is called after the phase ($script:BatchTitle)"
$tickedAtStart = @($script:BatchRows | Where-Object { $_.Ticked })
Assert-True ($script:BatchRows.Count -ge 4 -and $tickedAtStart.Count -eq 2 -and @($tickedAtStart | Where-Object { $_.Title -match 'Guest' }).Count -eq 1 -and @($tickedAtStart | Where-Object { $_.Title -match 'ockout' }).Count -eq 1) 'it lists the rows in order with the safe ones ticked (Guest, lockout) and the ones that ask you questions unticked'
Assert-True (@($script:BatchRows | Where-Object { $_.Risk -match '^(Low|Medium|High|asks you)' }).Count -eq $script:BatchRows.Count) 'each row shows its risk'
Assert-True ($script:BatchTicksAfter -eq 1 -and $script:BatchAfterNone -eq 0 -and $script:BatchAfterAll -eq $script:BatchRows.Count) 'unticking one, Untick all and Tick all work on the list'
Assert-True ($shot.Status -match '^Fix phase 2: applied 1, failed 0' -and -not $shot.Guest -and $shot.Lockout -ne 0) 'only the ticked row ran: Guest is disabled, the lockout row was left alone'
Assert-True ($script:ResultTitle -match 'Fix phase 2 - result' -and $script:ResultText -match 'Applied: 1' -and $script:ResultText -match 'Guest') 'the result of the batch is shown in a window and names the row'
Assert-True (-not $shot.Busy) 'the buttons are usable again afterwards'
Assert-True ($shot.NothingStatus -match 'nothing was run') 'a batch with nothing ticked runs nothing and says so'
Assert-True ($shot.LockoutAfterCancel -eq $shot.Lockout) 'Cancel in the batch dialog changes nothing'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Fix phase in audit mode, and Undo' -ForegroundColor Cyan
Start-Fresh
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $script:Ui.CmbPhase.SelectedIndex = [array]::IndexOf($script:Ui.PhaseNumbers, 2)
    $script:Ui.BtnPhase.PerformClick()
    $script:Seen | Add-Member -NotePropertyName AuditMessage -NotePropertyValue (@([FakeLab.Stage]::Messages) | Select-Object -Last 1)
    $script:Ui.BtnUndoLast.PerformClick()                       # nothing to undo
    $script:Seen | Add-Member -NotePropertyName NothingStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Ui.BtnUndo.PerformClick()
    $script:Seen | Add-Member -NotePropertyName NothingUndoMessage -NotePropertyValue (@([FakeLab.Stage]::Messages) | Select-Object -Last 1)
    $script:Ui.BtnJournal.PerformClick()
    $script:Seen | Add-Member -NotePropertyName EmptyJournalMessage -NotePropertyValue (@([FakeLab.Stage]::Messages) | Select-Object -Last 1)
    # two real changes, then undo them: the newest with "Undo last", the other one picked from the list
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.ChkAllow.PerformClick()
    foreach ($subject in 'Guest is enabled*', 'Account lockout is ON*') {
        $null = Select-Row $subject
        Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
        $script:Ui.BtnFix.PerformClick()
    }
    $script:Seen | Add-Member -NotePropertyName ChangedGuest -NotePropertyValue $global:FW.Users['Guest'].Enabled
    $script:Seen | Add-Member -NotePropertyName ChangedLockout -NotePropertyValue $global:FW.Lockout
    Add-Step { param($d) $script:JournalTitle = $d.Text; $script:JournalText = Get-DialogText $d; [void](Invoke-Click $d 'Close'); $d.DialogResult }
    $script:Ui.BtnJournal.PerformClick()
    # Undo...: the list shows both changes, newest first; pick the OLDER one (Guest) - the newest (lockout) must stay as it is
    Add-Step {
        param($d)
        $script:UndoRows = @($script:Dlg.List.Items | ForEach-Object { $_.Text + '|' + $_.SubItems[3].Text })
        $script:UndoGreyAtStart = -not (Find-Button $d 'Undo the selected change').Enabled
        $script:Dlg.List.Items[1].Selected = $true
        $script:UndoOnAfterPick = (Find-Button $d 'Undo the selected change').Enabled
        [void](Invoke-Click $d 'Undo the selected change')
        $d.DialogResult
    }
    Add-Step { param($d) $script:UndoQuestion = Get-DialogText $d; [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnUndo.PerformClick()
    $script:Seen | Add-Member -NotePropertyName UndoPickStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName GuestBack -NotePropertyValue $global:FW.Users['Guest'].Enabled
    $script:Seen | Add-Member -NotePropertyName LockoutKept -NotePropertyValue $global:FW.Lockout
    $script:Seen | Add-Member -NotePropertyName RowsBack -NotePropertyValue (@(Get-ListRows | Where-Object { $_.Subject -like 'Guest is enabled*' }).Count -eq 1)
    # Undo last: now the newest one that is left (the lockout)
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnUndoLast.PerformClick()
    $script:Seen | Add-Member -NotePropertyName UndoLastStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Seen | Add-Member -NotePropertyName LockoutBack -NotePropertyValue $global:FW.Lockout
}
$shot = $script:Seen
Assert-True ($shot.AuditMessage -match 'Audit mode' -and $shot.AuditMessage -match 'Allow changes') 'Fix phase in audit mode: a message that says to tick "Allow changes"'
Assert-True ($shot.NothingStatus -match 'Nothing to undo' -and $shot.NothingUndoMessage -match 'Nothing to undo') 'Undo last and Undo... with an empty journal: a plain message'
Assert-True ($shot.EmptyJournalMessage -match 'journal is empty') 'Journal... with nothing changed: "the journal is empty"'
Assert-True (-not $shot.ChangedGuest -and $shot.ChangedLockout -eq 0) 'two changes were made through the window (Guest off, lockout off)'
Assert-True ($script:JournalText -match 'Guest' -and $script:JournalText -match 'ockout' -and $script:JournalTitle -match 'Journal') 'the journal window lists both changes'
Assert-True (@($script:UndoRows).Count -eq 2 -and $script:UndoRows[0] -match 'ockout' -and $script:UndoRows[1] -match 'Guest' -and $script:UndoGreyAtStart -and $script:UndoOnAfterPick) 'Undo... lists the undoable changes newest first, starts with the button grey, and enables it when a change is picked'
Assert-True ($script:UndoQuestion -match '(?i)undo') 'Undo asks before it puts anything back'
Assert-True ($shot.UndoPickStatus -match '^Undone: ' -and $shot.GuestBack -and $shot.LockoutKept -eq 0 -and $shot.RowsBack) 'Undo... put back exactly the picked (older) change: Guest is enabled again and the audit shows it; the newer lockout change was left alone'
Assert-True ($shot.UndoLastStatus -match '^Undone: ' -and $shot.LockoutBack -ne 0) 'Undo last then put back the newest change that was left (the lockout threshold)'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The dead-man switch buttons and the clock' -ForegroundColor Cyan
Start-Fresh
$script:Hp.AllowChanges = $true
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $script:Ui.ChkAllow.Checked = $true
    Add-Step { param($d) $script:ArmQuestion = Get-DialogText $d; [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnArm.PerformClick()
    $script:Seen | Add-Member -NotePropertyName ArmText -NotePropertyValue $script:Ui.LblDead.Text
    $script:Seen | Add-Member -NotePropertyName ArmColor -NotePropertyValue $script:Ui.LblDead.BackColor.ToArgb()
    $script:Seen | Add-Member -NotePropertyName ArmStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    $script:Ui.Timer.PerformTick()
    $script:Seen | Add-Member -NotePropertyName TickText -NotePropertyValue $script:Ui.LblDead.Text
    # less than a minute left: red
    Save-DeadManState -When (Get-Date).AddSeconds(30) -Minutes 5
    $script:Ui.Timer.PerformTick()
    $script:Seen | Add-Member -NotePropertyName LowColor -NotePropertyValue $script:Ui.LblDead.BackColor.ToArgb()
    $script:Seen | Add-Member -NotePropertyName LowText -NotePropertyValue $script:Ui.LblDead.Text
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnExtend.PerformClick()
    $script:Seen | Add-Member -NotePropertyName ExtendedText -NotePropertyValue $script:Ui.LblDead.Text
    $script:Seen | Add-Member -NotePropertyName ExtendedLeft -NotePropertyValue (Get-DeadManClock)
    # Keep changes: No, then Yes
    Add-Step { param($d) $script:KeepQuestion = Get-DialogText $d; [void](Invoke-Click $d 'No, cancel'); $d.DialogResult }
    $script:Ui.BtnKeep.PerformClick()
    $script:Seen | Add-Member -NotePropertyName KeepNoLeft -NotePropertyValue (Get-DeadManClock)
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnKeep.PerformClick()
    $script:Seen | Add-Member -NotePropertyName KeepYesText -NotePropertyValue $script:Ui.LblDead.Text
    $script:Seen | Add-Member -NotePropertyName KeepYesColor -NotePropertyValue $script:Ui.LblDead.BackColor.ToArgb()
    $script:Seen | Add-Member -NotePropertyName KeepYesLeft -NotePropertyValue (Get-DeadManClock)
    # the clock is cheap: it does not read the box (no new audit), and it does not ask Task Scheduler during a job
    $script:Ui.Busy = $true
    $callsBefore = @($global:FW.Calls).Count
    $script:Ui.Timer.PerformTick()
    $script:Seen | Add-Member -NotePropertyName BusyTickCalls -NotePropertyValue (@($global:FW.Calls).Count - $callsBefore)
    $script:Ui.Busy = $false
}
$shot = $script:Seen
Assert-True ($script:ArmQuestion -match '(?i)dead-man|restore') 'Arm asks first and explains what it does'
Assert-True ($shot.ArmText -match 'ARMED' -and $shot.ArmText -match '[45]:\d\d' -and $shot.ArmColor -eq (Get-Argb 255 230 140 0)) 'Arm: the label shows ARMED with the time left, in orange'
Assert-True ($shot.ArmStatus -match '^Applied: ') 'and the status bar says Applied'
Assert-True ($shot.TickText -match 'ARMED') 'the clock tick keeps the label up to date'
Assert-True ($shot.LowColor -eq (Get-Argb 255 200 30 30) -and $shot.LowText -match 'ARMED' -and $shot.LowText -match '0:[23]\d') 'under a minute left the label turns red and shows the seconds'
Assert-True ($shot.ExtendedLeft -gt 240 -and $shot.ExtendedText -match '[45]:\d\d') 'Extend moves the restore time later'
Assert-True ($script:KeepQuestion -match '(?i)green|RDP|Jenkins|scoring' -and $shot.KeepNoLeft -gt 0) 'Keep changes asks and reminds you to check the scoring first; No leaves the switch armed'
Assert-True ($shot.KeepYesLeft -eq 0 -and $shot.KeepYesText -eq 'Dead-man switch: not armed' -and $shot.KeepYesColor -eq (Get-Argb 255 220 220 220)) 'Keep changes: Yes disarms it and the label goes grey'
Assert-Equal $shot.BusyTickCalls 0 'a clock tick during a job does not ask Task Scheduler'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A button that fails' -ForegroundColor Cyan
Start-Fresh
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    # a mistake inside a button: logged and shown, the window keeps working
    $script:RealAudit = ${function:Update-Audit}
    ${function:Update-Audit} = { throw 'pretend collector crash' }
    $messagesBefore = @([FakeLab.Stage]::Messages).Count
    $script:Ui.BtnAudit.PerformClick()
    $script:Seen | Add-Member -NotePropertyName CrashMessages -NotePropertyValue @(@([FakeLab.Stage]::Messages) | Select-Object -Skip $messagesBefore)
    $script:Seen | Add-Member -NotePropertyName CrashBusy -NotePropertyValue $script:Ui.Busy
    $script:Seen | Add-Member -NotePropertyName CrashEnabled -NotePropertyValue ($script:Ui.BarMid.Enabled -and $script:Ui.BarTop.Enabled -and $script:Ui.List.Enabled)
    $script:Seen | Add-Member -NotePropertyName CrashCursor -NotePropertyValue $script:Ui.Form.Cursor.Name
    ${function:Update-Audit} = $script:RealAudit
    $script:Ui.BtnAudit.PerformClick()
    $script:Seen | Add-Member -NotePropertyName RecoverStatus -NotePropertyValue $script:Ui.StatusLeft.Text
    # a second click while a job runs does nothing
    $script:RunCount = 0
    ${function:Update-Audit} = { $script:RunCount++; $script:Ui.BtnAudit.PerformClick(); $script:Ui.BtnAudit.CanUse | Out-Null }
    $script:Ui.BtnAudit.PerformClick()
    ${function:Update-Audit} = $script:RealAudit
    $script:Seen | Add-Member -NotePropertyName ReentrantRuns -NotePropertyValue $script:RunCount
    # a handler that fails quietly: the phase box
    $script:RealRows = ${function:Update-GuiRows}
    ${function:Update-GuiRows} = { throw 'pretend list crash' }
    $before = @($script:Hp.LogLines).Count
    $script:Ui.CmbPhase.SelectedIndex = 1
    $script:Seen | Add-Member -NotePropertyName QuietLog -NotePropertyValue @(@($script:Hp.LogLines) | Select-Object -Skip $before)
    ${function:Update-GuiRows} = $script:RealRows
    $script:Ui.CmbPhase.SelectedIndex = 0
}
$shot = $script:Seen
Assert-True (@($shot.CrashMessages).Count -eq 1 -and $shot.CrashMessages[0] -match 'Something went wrong' -and $shot.CrashMessages[0] -match 'pretend collector crash') 'a mistake inside a button shows one message that names the button and the error'
Assert-True (-not $shot.CrashBusy -and $shot.CrashEnabled -and $shot.CrashCursor -eq 'Default') 'and the window is usable again (buttons enabled, normal cursor)'
Assert-True ($shot.RecoverStatus -eq 'Audit done.') 'the next press of the same button works'
Assert-Equal $shot.ReentrantRuns 1 'a second click on a button while its job runs is ignored'
Assert-True (@($shot.QuietLog | Where-Object { $_ -match 'phase box' -and $_ -match 'pretend list crash' }).Count -ge 1) 'a small handler that fails only writes to the log'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The close button' -ForegroundColor Cyan
Start-Fresh
$script:Hp.AllowChanges = $true
Invoke-Window {
    $script:Seen = [pscustomobject]@{}
    $form = $script:Ui.Form
    # a job is running
    $script:Ui.Busy = $true
    $closedBusy = $form.TryClose()
    $script:Seen | Add-Member -NotePropertyName BusyClosed -NotePropertyValue $closedBusy
    $script:Seen | Add-Member -NotePropertyName BusyMessage -NotePropertyValue (@([FakeLab.Stage]::Messages) | Select-Object -Last 1)
    $script:Ui.Busy = $false
    # armed: asks; No keeps the window open, Yes closes it
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnArm.PerformClick()
    $script:Answers.Enqueue([System.Windows.Forms.DialogResult]::No)
    $script:Seen | Add-Member -NotePropertyName ArmedNoClosed -NotePropertyValue $form.TryClose()
    $script:Seen | Add-Member -NotePropertyName ArmedQuestion -NotePropertyValue (@([FakeLab.Stage]::Messages) | Select-Object -Last 1)
    $script:Answers.Enqueue([System.Windows.Forms.DialogResult]::Yes)
    $script:Seen | Add-Member -NotePropertyName ArmedYesClosed -NotePropertyValue $form.TryClose()
    # not armed: closes without asking
    Add-Step { param($d) [void](Invoke-Click $d 'Yes, do it'); $d.DialogResult }
    $script:Ui.BtnKeep.PerformClick()
    $count = @([FakeLab.Stage]::Messages).Count
    $script:Seen | Add-Member -NotePropertyName PlainClosed -NotePropertyValue $form.TryClose()
    $script:Seen | Add-Member -NotePropertyName PlainAsked -NotePropertyValue (@([FakeLab.Stage]::Messages).Count - $count)
}
$shot = $script:Seen
Assert-True (-not $shot.BusyClosed -and $shot.BusyMessage -match 'Please wait') 'while a job runs the X button does not close the window, and says why'
Assert-True (-not $shot.ArmedNoClosed -and $shot.ArmedQuestion -match 'still ARMED' -and $shot.ArmedQuestion -match 'does not disarm') 'with the dead-man switch armed the X button asks, and says that closing does not disarm it; No keeps the window open'
Assert-True ($shot.ArmedYesClosed) '... and Yes closes it'
Assert-True ($shot.PlainClosed -and $shot.PlainAsked -eq 0) 'with nothing armed the window closes without a question'
Assert-True (Test-NoSurprises) 'no dialog opened that nobody expected'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The self-test (Start-Hardening.ps1 -GuiSelfTest)' -ForegroundColor Cyan
Start-Fresh
[void](Update-Audit)
$built = @(Test-HardeningWindow) | Select-Object -Last 1
Assert-Equal $built 7 'Test-HardeningWindow builds the main window and 7 dialogs, shows nothing'
Assert-True ($script:Ui.Count -eq 0 -and @([FakeLab.Stage]::Dialogs).Count -eq 0) 'and leaves nothing behind (no window state, no dialog was shown)'
$realBuild = ${function:Build-GuiTextDialog}
${function:Build-GuiTextDialog} = { throw 'pretend: this control does not exist on this machine' }
$caught = ''
try { [void](Test-HardeningWindow) } catch { $caught = $_.Exception.Message }
${function:Build-GuiTextDialog} = $realBuild
Assert-True ($caught -match 'pretend: this control' -and $script:Ui.Count -eq 0) 'a dialog that cannot be built makes the self-test fail with the reason, and it still cleans up'
$shell = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$launcher = Join-Path $script:HpRoot 'Start-Hardening.ps1'
$dataDir = Join-Path ([IO.Path]::GetTempPath()) ('hp-guiself-' + [guid]::NewGuid().ToString('N'))
[void]$script:Dirs.Add($dataDir)
$out = (& $shell -NoProfile -ExecutionPolicy Bypass -File $launcher -GuiSelfTest -DataDir $dataDir 2>&1 | Out-String)
Assert-True ($LASTEXITCODE -eq 1 -and $out -match 'does NOT build on this machine' -and $out -match 'NoGui -Apply') '-GuiSelfTest on a machine without WinForms: exit code 1, a plain message and the text menu as the way out'
Assert-True ($out -notmatch 'Unhandled|at <ScriptBlock>') '... and no raw PowerShell error text'

foreach ($d in $script:Dirs) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
Write-TestSummary
