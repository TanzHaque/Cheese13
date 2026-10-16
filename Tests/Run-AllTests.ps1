# Run-AllTests.ps1 - runs every Test-*.ps1 in this folder, each in a fresh PowerShell, and prints one line per file.
# These tests never touch the real box: Windows commands are replaced by fakes. Safe to run anywhere
# (Windows PowerShell 5.1 or PowerShell 7). Exit code = number of test files that failed.
$shell = (Get-Process -Id $PID).Path            # the same PowerShell that is running this script
$failedFiles = 0
$totalPassed = 0
foreach ($t in (Get-ChildItem -Path $PSScriptRoot -Filter 'Test-*.ps1' | Sort-Object Name)) {
    $text = (& $shell -NoProfile -ExecutionPolicy Bypass -File $t.FullName 2>&1 | Out-String)
    $m = [regex]::Match($text, '(\d+) passed, (\d+) failed')
    if (-not $m.Success -or [int]$m.Groups[2].Value -gt 0) {
        $failedFiles++
        Write-Host ('FAIL  {0,-32} {1}' -f $t.Name, $(if ($m.Success) { $m.Value } else { 'did not finish (see below)' })) -ForegroundColor Red
        $lines = $text -split "`r?`n" | Where-Object { $_ -match '^\s+FAIL\s' -or $_ -match 'rror|xception' } | Select-Object -First 8
        foreach ($l in $lines) { Write-Host "      $l" -ForegroundColor Red }
    } else {
        $totalPassed += [int]$m.Groups[1].Value
        Write-Host ('ok    {0,-32} {1}' -f $t.Name, $m.Value) -ForegroundColor Green
    }
}
Write-Host ("`n{0} checks passed, {1} test file(s) failed" -f $totalPassed, $failedFiles) -ForegroundColor Cyan
exit $failedFiles
