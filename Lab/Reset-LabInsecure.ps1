<#
.SYNOPSIS
  LAB ONLY. Re-arms the practice VM with a fresh, RANDOMIZED set of problems, and seals the answers.

.DESCRIPTION
  Run this on the lab VM (elevated PowerShell) before each practice run.
  Best flow:  revert the 'clean-lab' snapshot  ->  run this  ->  (optional) snapshot 'armed'  ->  harden  ->  Verify-Hardening.ps1

  What it does, in order:
    1. Safety checks (refuses to run unless this looks like the lab).
    2. Removes the previous run's plants (it can read its own old key) and the ORIGINAL Lab-Setup.ps1 plants.
    3. Puts the baseline back: plinktern + jmoney with the packet password, RDP on, Jenkins port open.
    4. Plants a new random set (users, persistence, firewall, policy, Jenkins). All harmless: they only
       append a tagged line to C:\ProgramData\lab_beacon.log or hold a port open.
    5. Writes the answer key, ENCRYPTED with a passphrase you type. Nothing printed says what was planted.
       The hardening tool does not contain code that opens the key.
  It cannot undo every hardening change (services, registry, Defender...). For a truly clean slate revert the snapshot first.

.EXAMPLE
  .\Reset-LabInsecure.ps1 -IAmInTheLab
  .\Reset-LabInsecure.ps1 -IAmInTheLab -Intensity Hard
  .\Reset-LabInsecure.ps1 -IAmInTheLab -Seed 4242        # replay an earlier scenario
#>
[CmdletBinding()]
param(
    [ValidateSet('Easy', 'Normal', 'Hard')][string]$Intensity = 'Normal',
    [int]$Seed = 0,
    [string]$DefaultPassword = 'H00ves0nTheM00n',
    [string]$KeyPath = 'C:\ProgramData\LabHarness\answer.key',
    [switch]$NoJenkins,
    [switch]$KeepLogs,
    [switch]$DiscardOldKey,
    [string[]]$KeepUsers = @(),                 # accounts to never offer for deletion (for example the one a referee logs in with)
    [switch]$IAmInTheLab
)

$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\LabKey.ps1"
. "$PSScriptRoot\LabPlan.ps1"
. "$PSScriptRoot\LabPlants.ps1"
. "$PSScriptRoot\LabCleanup.ps1"
. "$PSScriptRoot\LabJenkins.ps1"

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# ------------------------------------------------------------------ 1. safety checks
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated PowerShell.' }
if (-not $IAmInTheLab) { throw 'Add -IAmInTheLab to confirm this is the PRACTICE VM. This script weakens the box on purpose.' }
$looksLikeLab = (Test-Path 'C:\LabSetup.log') -or (Test-Path 'C:\LabAnswerKey.txt') -or (Test-Path $KeyPath)
if (-not $looksLikeLab) { throw 'No sign that Lab-Setup.ps1 ever ran here (no C:\LabSetup.log). Refusing: this might be a real box.' }
if ((Read-Host 'This weakens the box on purpose. Type LAB to continue') -ne 'LAB') { throw 'Cancelled.' }

# ------------------------------------------------------------------ 2. passphrase + old key
$oldPlan = $null
if ((Test-Path $KeyPath) -and -not $DiscardOldKey) {
    $pass = Get-LabPassphrase -Prompt 'Lab key passphrase (decrypts the previous key)'
    try { $oldPlan = (Unprotect-LabText -Path $KeyPath -Passphrase $pass) | ConvertFrom-Json }
    catch { throw "Could not open the old key: $($_.Exception.Message)  (use -DiscardOldKey to skip cleanup that needs it)" }
} else {
    $pass = Get-LabPassphrase -Prompt 'Choose a lab key passphrase' -Twice
}

# ------------------------------------------------------------------ 3. clean up
Step 'Cleaning up the previous run'
$jenkins = $null
if (-not $NoJenkins) { $jenkins = Get-JenkinsInfo }
$hasJenkins = $jenkins -and $jenkins.Service -and $jenkins.Home
if ($oldPlan) {
    foreach ($p in $oldPlan.Plants) { Remove-OnePlant $p }
    if ($hasJenkins) { Remove-OldJenkinsPlants -OldItems @($oldPlan.Plants | Where-Object Kind -like 'Jenkins*') -Info $jenkins }
}
Remove-OriginalLabPlants
$stray = @(Get-StrayUsers -Keep $KeepUsers)
if ($stray.Count -gt 0) {
    Write-Host ("  These local accounts are not part of the lab baseline: " + ($stray -join ', ')) -ForegroundColor Yellow
    if ((Read-Host '  Type DELETE to remove them (anything else keeps them)') -eq 'DELETE') {
        foreach ($n in $stray) { Remove-LocalUser -Name $n -ErrorAction SilentlyContinue }
        Write-Host '  removed.'
    } else { Write-Host '  kept (they count as accounts that existed when the lab was armed).' }
}
Clear-Content 'C:\ProgramData\lab_beacon.log' -ErrorAction SilentlyContinue

# ------------------------------------------------------------------ 4. new plan + baseline + plants
Step 'Arming'
$plan = New-PlantPlan -Intensity $Intensity -Seed $Seed
Set-LabBaseline -DefaultPassword $DefaultPassword -Scenario $plan.Scenario

$planted = @()
foreach ($item in ($plan.Plants | Where-Object { $_.Kind -notlike 'Jenkins*' })) { $planted += Add-OnePlant $item }
$jItems = @($plan.Plants | Where-Object Kind -like 'Jenkins*')
if ($jItems.Count -gt 0) {
    if ($hasJenkins) { $planted += Set-JenkinsPlants -Items $jItems -Info $jenkins }
    else { foreach ($j in $jItems) { $j | Add-Member -NotePropertyName Status -NotePropertyValue 'FAILED: Jenkins not found / skipped' -Force; $planted += $j } }
}
$plan.Plants = $planted

# ------------------------------------------------------------------ 5. seal the key
$record = [pscustomobject]@{
    Version = 1; ArmedAt = (Get-Date).ToString('s'); Seed = $plan.Seed; Intensity = $plan.Intensity
    DefaultPassword = $DefaultPassword; Scenario = $plan.Scenario; Plants = $plan.Plants
    AccountsAtArm = @((Get-LocalUser).Name); JenkinsHome = $jenkins.Home
}
Protect-LabText -Text ($record | ConvertTo-Json -Depth 6) -Passphrase $pass -Path $KeyPath

if (-not $KeepLogs) {
    foreach ($log in 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational',
                     'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-WMI-Activity/Operational') {
        wevtutil.exe cl $log 2>$null
    }
}

# ------------------------------------------------------------------ 6. summary (says nothing about WHAT was planted)
$ok   = @($planted | Where-Object { $_.Status -eq 'planted' }).Count
$fail = @($planted | Where-Object { $_.Status -ne 'planted' }).Count
Step 'ARMED'
Write-Host "  $ok item(s) planted, $fail could not be planted (those are ignored when scoring)."
Write-Host "  Answer key (encrypted): $KeyPath"

$rdp = $false
try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 3389); $rdp = $true; $c.Close() } catch { $rdp = $false }
Write-Host ("  Baseline check: RDP port 3389 listening = {0}" -f $rdp)
Write-Host '  Next: check NEIGH for green scoring, take an optional snapshot, then go hunt.'
Write-Host '  When done: Verify-Hardening.ps1 -NewAdmin <your new admin> -AskPassword -Lab   (asks for the lab passphrase and grades you).'
