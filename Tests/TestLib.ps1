# TestLib.ps1 - tiny assert helpers for the logic tests (no Pester needed).
# Tests run on any PowerShell 7 (Linux/Windows). They never touch the real box.

$script:TestPass = 0
$script:TestFail = 0

function Assert-True {
    param($Condition, [string]$Name)
    if ($Condition) { $script:TestPass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:TestFail++; Write-Host "  FAIL  $Name" -ForegroundColor Red }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    $ok = ("$Actual" -eq "$Expected")
    if ($ok) { $script:TestPass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:TestFail++; Write-Host "  FAIL  $Name  (expected '$Expected', got '$Actual')" -ForegroundColor Red }
}

function Assert-Throws {
    param([scriptblock]$Code, [string]$Name)
    $threw = $false
    try { & $Code | Out-Null } catch { $threw = $true }
    if ($threw) { $script:TestPass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:TestFail++; Write-Host "  FAIL  $Name  (expected an error, got none)" -ForegroundColor Red }
}

function Register-TestError {
    # Every test file has the line   trap { Register-TestError $_; continue }   right after it loads this file.
    # Without it, an error in the middle of a check (for example a typo inside the brackets of Assert-True) prints red text, the check
    # is simply never counted, and the file still ends with "0 failed". With it the error counts as a failure and the file goes on.
    param($ErrorRecord)
    $script:TestFail++
    $where = ''
    if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.ScriptName) {
        $where = '   [' + (Split-Path -Leaf ([string]$ErrorRecord.InvocationInfo.ScriptName)) + ' line ' + $ErrorRecord.InvocationInfo.ScriptLineNumber + ']'
    }
    Write-Host ('  FAIL  an error that nothing caught: ' + $ErrorRecord.Exception.Message + $where) -ForegroundColor Red
}

function Write-TestSummary {
    Write-Host ("`n{0} passed, {1} failed" -f $script:TestPass, $script:TestFail) -ForegroundColor Cyan
    if ($script:TestFail -gt 0) { exit 1 }
}
