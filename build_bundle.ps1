$scriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptsDir

$files = @(
    'Start-Hardening.ps1',
    'Panic.ps1',
    'Watchdog.ps1',
    'ScoreLib.ps1',
    'Verify-Hardening.ps1',
    'VerifyFacts.ps1',
    'VerifyJudgeAccounts.ps1',
    'VerifyJudgeFirewall.ps1',
    'VerifyJudgeSystem.ps1',
    'lib'
)

$dest = "C:\Users\Blaze\OneDrive\Desktop\hp.zip"
if (Test-Path $dest) { Remove-Item $dest -Force }

Compress-Archive -Path $files -DestinationPath $dest -Force

$hash = (Get-FileHash $dest -Algorithm SHA256).Hash
Write-Host "Bundle created at: $dest" -ForegroundColor Green
Write-Host "Full SHA-256: $hash"
Write-Host "First 16 chars: $($hash.Substring(0,16))" -ForegroundColor Cyan
