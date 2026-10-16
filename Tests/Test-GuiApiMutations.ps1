# Test-GuiApiMutations.ps1 - proves that Test-GuiApi.ps1 can fail.
# A checker that always says "pass" is worse than none, so this plants ONE mistake at a time in a copy of lib\Gui.ps1
# (a misspelled property, a wrong argument count, a handler that uses a local variable ...) and expects the checker to name it.
# First the untouched copy must pass, then every damaged copy must fail with the expected words.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
$root = Split-Path -Parent $PSScriptRoot
$checker = Join-Path $PSScriptRoot 'Test-GuiApi.ps1'
$original = [System.IO.File]::ReadAllText((Join-Path $root 'lib\Gui.ps1'))
$shell = (Get-Process -Id $PID).Path
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('hp-mutation-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
Write-Host 'The window checker against planted mistakes' -ForegroundColor Cyan

function Invoke-Checker {
    # Runs the checker on a file in a fresh PowerShell and returns its text and the number it reports as failed (-1 = it did not finish).
    param([string]$File)
    $text = (& $shell -NoProfile -ExecutionPolicy Bypass -File $checker -GuiFile $File 2>&1 | Out-String)
    $m = [regex]::Match($text, '(\d+) passed, (\d+) failed')
    $failed = -1
    if ($m.Success) { $failed = [int]$m.Groups[2].Value }
    [pscustomobject]@{ Text = $text; Failed = $failed }
}

try {
    $base = Join-Path $temp 'Gui-untouched.ps1'
    [System.IO.File]::WriteAllText($base, $original)
    $baseline = Invoke-Checker $base
    Assert-True ($baseline.Failed -eq 0) 'the untouched copy of Gui.ps1 passes the checker (so a failure below comes from the planted mistake)'

    # Each mutation: the text to find (it must exist in Gui.ps1) and what to put there, and words the checker's report must contain.
    $mutations = @(
        @{ Name = 'an enum word that does not exist';        From = "`$lv.Dock = 'Fill'";                              To = "`$lv.Dock = 'Fil'";                                   Expect = "'Fil' is not a value of System.Windows.Forms.DockStyle" }
        @{ Name = 'a misspelled property on a control';      From = '$lv.CheckBoxes = $true';                          To = '$lv.CheckBox = $true';                                Expect = "has no property 'CheckBox'" }
        @{ Name = 'a misspelled property on a list item';    From = '$item.Checked = [bool]$r.Tick';                   To = '$item.Checkd = [bool]$r.Tick';                        Expect = "has no property 'Checkd'" }
        @{ Name = 'a misspelled method';                     From = '[void]$dialog.ShowDialog($script:Ui.Form)';          To = '[void]$dialog.ShowDialogue($script:Ui.Form)';            Expect = "has no method 'ShowDialogue'" }
        @{ Name = 'a method with too many arguments';        From = "[void]`$lv.Columns.Add('Change', 690)";           To = "[void]`$lv.Columns.Add('Change', 690, 1, 2, 3, 4)";   Expect = 'takes 6 argument' }
        @{ Name = 'a misspelled event';                      From = '$all.Add_Click({';                                To = '$all.Add_Clik({';                                     Expect = "has no event 'Clik'" }
        @{ Name = 'a read-only property that is assigned';   From = '$lv.FullRowSelect = $true';                       To = '$lv.Items = $null';                                   Expect = 'cannot be assigned' }
        @{ Name = 'a control type that does not exist';      From = 'New-Object System.Windows.Forms.ListView';        To = 'New-Object System.Windows.Forms.ListVue';             Expect = 'System.Windows.Forms.ListVue is not in winforms-api.txt' }
        @{ Name = 'a constructor with the wrong argument count'; From = 'New-Object System.Drawing.Size(820, 0)';     To = 'New-Object System.Drawing.Size(820, 0, 1)';           Expect = 'no constructor with 3 argument' }
        @{ Name = 'a window key that is used but never set'; From = '$script:Ui.StatusLeft.Text = $Text';               To = '$script:Ui.StatusLeftt.Text = $Text';                 Expect = 'MISSING: StatusLeftt' }
        @{ Name = 'a handler that uses a local variable';    From = 'foreach ($i in $script:Dlg.List.Items) { $i.Checked = $true }'; To = 'foreach ($i in $lv.Items) { $i.Checked = $true }'; Expect = 'uses the local variable $lv' }
        @{ Name = 'WinForms loaded in a second place';       From = 'function Add-GuiLogLine {';                       To = "function Add-GuiLogLine {`n    Add-Type -AssemblyName System.Windows.Forms"; Expect = 'WinForms is loaded in exactly one place' }
        @{ Name = 'a call to a function that does not exist'; From = '(Build-GuiLabel $note)';                        To = '(Build-GuiLabell $note)';                             Expect = 'Build-GuiLabell' }
    )

    $n = 0
    foreach ($m in $mutations) {
        $n++
        $at = $original.IndexOf($m.From)
        Assert-True ($at -ge 0) "mutation $n ($($m.Name)): the text to damage is still in Gui.ps1"
        if ($at -lt 0) { continue }
        $damaged = $original.Substring(0, $at) + $m.To + $original.Substring($at + $m.From.Length)
        $file = Join-Path $temp ("Gui-mutation-$n.ps1")
        [System.IO.File]::WriteAllText($file, $damaged)
        $res = Invoke-Checker $file
        Assert-True ($res.Failed -gt 0) "mutation $n ($($m.Name)): the checker fails"
        Assert-True ($res.Text.Contains($m.Expect)) "mutation $n ($($m.Name)): and its report says '$($m.Expect)'"
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-TestSummary
