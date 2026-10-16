<#
Start-Hardening.ps1 - the hardening tool for assembly-t. Run it in an ELEVATED Windows PowerShell:

    powershell -ep bypass C:\hp\Start-Hardening.ps1                    the window (it starts in AUDIT mode: nothing can change until you tick "Allow changes")
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -NoGui             print the audit and exit (read-only)
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -NoGui -Phase 2    only phase 2
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -NoGui -Apply      the audit, then a text menu to fix rows (every change asks first)
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -GuiSelfTest       check that the window works on this machine (shows nothing, changes nothing)
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -Journal           list the changes made so far
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -Undo 12           undo change number 12 (asks first)
    powershell -ep bypass C:\hp\Start-Hardening.ps1 -UndoLast          undo the newest change that can be undone

Phases: 1 Recon, 2 Accounts, 3 Backup, 4 Firewall, 6 Hunt, 7 Defender, 8 Watchdog, 9 Routine.
Every change is written to the journal first (C:\ProgramData\NetCacheSvc\journal) and logged (...\logs).
The files in lib\ must stay next to this script. -LoadOnly just loads them (the tests use it) and exits.
#>
param(
    [switch]$NoGui,
    [int]$Phase = 0,
    [switch]$Apply,
    [switch]$GuiSelfTest,
    [switch]$Journal,
    [int]$Undo = 0,
    [switch]$UndoLast,
    [string]$DataDir = 'C:\ProgramData\NetCacheSvc',
    [switch]$LoadOnly
)

# ---- load the tool (dot-sourcing at the top level of the script, so every function lives in this script's scope)
$script:HpRoot = $PSScriptRoot
$libDir = Join-Path $PSScriptRoot 'lib'
foreach ($file in 'Core', 'DeadMan', 'Collect', 'Judge', 'JudgeAccounts', 'JudgeFirewall', 'JudgeHunt', 'JudgeWatchdog',
                  'Act-Accounts', 'Act-Backup', 'Act-Firewall', 'Act-Hunt', 'Act-Persist', 'Act-Watchdog', 'Runner', 'Console', 'Gui') {
    . (Join-Path $libDir "$file.ps1")
}
if ($LoadOnly) { return }

# ---- administrator only (the collectors and the actions need it)
if ($env:OS -eq 'Windows_NT') {
    $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'This tool must run in an ELEVATED PowerShell (right-click PowerShell, Run as administrator).' -ForegroundColor Red
        exit 1
    }
}

Initialize-Hp -DataDir $DataDir
Write-HpLog "tool started (version of the files in $PSScriptRoot)"

if ($Journal) { Show-Journal; return }

if ($GuiSelfTest) {
    [void](Update-Audit)
    try {
        $built = @(Test-HardeningWindow) | Select-Object -Last 1
        Write-Host "OK: the window and its $built dialogs build correctly on this machine. Nothing was shown or changed." -ForegroundColor Green
    } catch {
        Write-Host ('The window does NOT build on this machine: ' + $_.Exception.Message) -ForegroundColor Red
        Write-Host 'Use the text menu instead: Start-Hardening.ps1 -NoGui -Apply' -ForegroundColor Yellow
        exit 1
    }
    return
}

if ($Undo -gt 0 -or $UndoLast) {
    $script:Hp.AllowChanges = $true                 # undoing IS a change; it still asks you first
    Show-ChangeResult (Invoke-Undo -Id $Undo)
    return
}

if ($NoGui -or $Apply) {
    [void](Update-Audit)
    if ($Apply) {
        $script:Hp.AllowChanges = $true
        Start-ConsoleMenu -Phase $Phase
    } else {
        [void](Show-AuditConsole -Phase $Phase)
    }
    return
}

try {
    Show-HardeningWindow
} catch {
    Write-Host ('The window could not open: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Starting the text menu instead (same tool, same safety checks).' -ForegroundColor Yellow
    Start-ConsoleMenu -Phase $Phase
}
