<#
.SYNOPSIS
  READ-ONLY check, run ON the box (elevated): did the hardening follow the plan, and does scoring still pass?

.DESCRIPTION
  It changes nothing (the one exception: with -Lab -WatchMinutes it first empties the LAB's beacon log). It reads the box
  and prints PASS / FAIL / WARN / INFO / SKIP lines in sections:
    Scoring        RDP port + protocol + TLS, Jenkins login + last build, jmoney account, free RDP session slots
    Accounts       only allowlisted accounts enabled, Administrator/Guest/plinktern disabled, no lockout policy,
                   packet default passwords dead, logon rights not broken by a policy, who can RDP in
    Firewall       profiles on, inbound default block, 3389 + 8080 allowed from ANY source on every profile,
                   no block rule over them, no other inbound allow rules, logging, outbound path to blackbox
    RDP/services   NLA, TLS, clipboard, genuine termsrv.dll, Jenkins service running, Spooler/RemoteRegistry
    Defender       on, signatures, no exclusions;  Windows settings (SMBv1, WDigest, LLMNR, auto-logon)
    Leftovers      hosts file, IFEO debuggers, WMI subscriptions, shares, Run keys (a human reviews these)
  One thing it does that is not pure reading: it tries each packet default password ONCE on every enabled account (those
  attempts show up as failed logons in the Security log). It skips that test if a lockout policy exists or cannot be read.
  Exit code: 0 = all PASS, 1 = at least one FAIL, 2 = no FAIL but some WARN / SKIP.

  The real login test (FreeRDP) cannot run from inside the box. From your laptop run Score-Check.ps1 as well:
  it goes through the firewall like the scoring engine does, and this script cannot see that.

  -Lab also grades the box against the encrypted lab answer key (asks for the passphrase). Lab only.

.EXAMPLE
  .\Verify-Hardening.ps1 -NewAdmin ops-9k2 -AskPassword
  .\Verify-Hardening.ps1 -NewAdmin ops-9k2 -JmoneyPassword 'the-new-password' -BlackboxIp 172.16.3.5
  .\Verify-Hardening.ps1 -NewAdmin ops-9k2 -AskPassword -Lab -WatchMinutes 12
#>
[CmdletBinding()]
param(
    [string]$NewAdmin,                                  # the new admin account you created (must exist and be an administrator)
    [string[]]$AllowAccounts = @(),                     # other accounts that may stay enabled (service accounts you discovered)
    [string]$JmoneyPassword,                            # or the environment variable HPCC_JMONEY_PASSWORD, or -AskPassword
    [switch]$AskPassword,
    [string[]]$PacketPasswords = @('H00ves0nTheM00n'),  # default passwords from the packet; none may still work
    [string]$BlackboxIp,                                # if set: checks outbound rules + that port 22 is reachable
    [int[]]$Ports = @(3389, 8080),                      # the scored ports
    [string[]]$AllowedRules = @(),                      # extra inbound rules (display names) you chose to keep
    [switch]$Lab,                                       # LAB ONLY: also grade against the answer key
    [string]$KeyPath = 'C:\ProgramData\LabHarness\answer.key',
    [int]$WatchMinutes = 0                              # LAB ONLY: wait this long and see which planted items still fire
)

$ErrorActionPreference = 'Continue'
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated PowerShell (Run as administrator).' }

. "$PSScriptRoot\ScoreLib.ps1"
. "$PSScriptRoot\VerifyJudgeAccounts.ps1"
. "$PSScriptRoot\VerifyJudgeFirewall.ps1"
. "$PSScriptRoot\VerifyJudgeSystem.ps1"
. "$PSScriptRoot\VerifyFacts.ps1"

# ---- jmoney's password: parameter, then environment, then a hidden prompt
$pw = $JmoneyPassword
if (-not $pw -and $env:HPCC_JMONEY_PASSWORD) { $pw = $env:HPCC_JMONEY_PASSWORD }
if (-not $pw -and $AskPassword) { $pw = Read-Secret 'Current password of jmoney' }

# ---- lab: open the answer key first, so a wrong passphrase fails immediately
$record = $null
if ($Lab) {
    . "$PSScriptRoot\Lab\LabKey.ps1"
    . "$PSScriptRoot\Lab\LabGrade.ps1"
    if (-not (Test-Path $KeyPath)) { throw "No answer key at $KeyPath. Run Lab\Reset-LabInsecure.ps1 first." }
    $keyPass = Get-LabPassphrase -Prompt 'Lab key passphrase'
    $record = (Unprotect-LabText -Path $KeyPath -Passphrase $keyPass) | ConvertFrom-Json
}

$allowed = @('jmoney') + @($NewAdmin) + @($AllowAccounts) | Where-Object { $_ }
$script:All = New-Object System.Collections.ArrayList
$script:Accounts = $null
$script:Sec = @{}

function Start-Section {
    param([string]$Title)
    Write-Host "`n== $Title" -ForegroundColor White
}

function Add-Results {
    # prints the results and remembers them for the summary
    param($Results)
    foreach ($r in @($Results)) { Show-Result $r; [void]$script:All.Add($r) }
}

Write-Host "Verify-Hardening on $env:COMPUTERNAME at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  (read-only)" -ForegroundColor Cyan

# A crash inside one section is reported as a FAIL line and never stops the other sections.
Start-Section 'Scoring (from inside the box)'
try {
    $r = @(Invoke-ScoreChecks -Target '127.0.0.1' -RdpPort 3389 -JenkinsPort 8080 -User 'jmoney' -Password $pw -NoAuthRdp -LocalChecks Yes)
    Add-Results ($r | Where-Object { $_.Name -ne 'RDP login (NLA)' })
    Add-Results (New-Result 'RDP login (NLA)' 'INFO' 'cannot be tested from inside the box: run Score-Check.ps1 from your laptop (a real login through the firewall)')
    if ($BlackboxIp) {
        if (Test-TcpPort -HostName $BlackboxIp -Port 22) { Add-Results (New-Result 'Blackbox reachable' 'PASS' "TCP 22 to $BlackboxIp opens from this box") }
        else { Add-Results (New-Result 'Blackbox reachable' 'FAIL' "cannot reach $BlackboxIp port 22 from this box (backups need it)") }
    }
} catch { Add-Results (New-Result 'Scoring' 'FAIL' "this section crashed: $($_.Exception.Message)") }

Start-Section 'Accounts and passwords (plan Phase 2)'
try {
    $script:Accounts = Get-AccountFacts
    $script:Sec = Get-SeceditFacts
    Add-Results (Get-AccountFindings -Facts $script:Accounts -Allowed $allowed -NewAdmin $NewAdmin)
    Add-Results (Get-LockoutFinding -Secedit $script:Sec)
    Add-Results (Get-LogonRightFindings -Facts $script:Accounts -Secedit $script:Sec -User 'jmoney' -Allowed $allowed)
    Add-Results (Test-DefaultPasswords -Users $script:Accounts.Users -Passwords $PacketPasswords -Secedit $script:Sec)
} catch { Add-Results (New-Result 'Accounts' 'FAIL' "this section crashed: $($_.Exception.Message)") }

Start-Section 'Firewall (plan Phase 4) - reading the rules takes about 20 seconds'
try {
    Add-Results (Get-FirewallFindings -Facts (Get-FirewallFacts) -Ports $Ports -BlackboxIp $BlackboxIp -AllowedRules $AllowedRules)
} catch { Add-Results (New-Result 'Firewall' 'FAIL' "this section crashed: $($_.Exception.Message)") }

Start-Section 'RDP and services (plan Phase 5)'
try {
    Add-Results (Get-RdpFindings -Facts (Get-RdpFacts))
    Add-Results (Get-ServiceFindings -Facts (Get-ServiceFacts))
} catch { Add-Results (New-Result 'RDP and services' 'FAIL' "this section crashed: $($_.Exception.Message)") }

Start-Section 'Defender and Windows settings (plan Phases 5 and 7)'
try {
    Add-Results (Get-DefenderFindings -Facts (Get-DefenderFacts))
    Add-Results (Get-WindowsSettingFindings -Facts (Get-WindowsSettingFacts))
} catch { Add-Results (New-Result 'Defender' 'FAIL' "this section crashed: $($_.Exception.Message)") }

Start-Section 'Leftovers for a human to review (plan Phase 6)'
try {
    Add-Results (Get-ReviewFindings -Facts (Get-ReviewFacts))
} catch { Add-Results (New-Result 'Leftovers' 'FAIL' "this section crashed: $($_.Exception.Message)") }

if ($Lab) {
    Start-Section 'LAB answer key'
    try {
        $lock = 0
        if ($script:Sec.ContainsKey('LockoutBadCount')) { $lock = [int]$script:Sec['LockoutBadCount'] }
        $sc = $record.Scenario
        Add-Results (New-Result 'Lab scenario' 'INFO' ("seed $($record.Seed), $($record.Intensity), armed $($record.ArmedAt); at arm time: jmoney admin = $($sc.JmoneyIsAdmin), built-in Administrator on = $($sc.BuiltinAdminEnabled), Public profile = $($sc.PublicProfile)"))
        $rows = @(Get-LabGrade -Record $record -LockoutThreshold $lock -ProbePasswords ($lock -eq 0))
        $order = @{ MISSED = 0; PARTIAL = 1; UNKNOWN = 2; FIXED = 3; 'N/A' = 4 }
        foreach ($row in ($rows | Sort-Object { $order[$_.Verdict] }, Id)) {
            $color = 'Green'
            if ($row.Verdict -eq 'MISSED') { $color = 'Red' }
            elseif ($row.Verdict -eq 'PARTIAL' -or $row.Verdict -eq 'UNKNOWN') { $color = 'Yellow' }
            elseif ($row.Verdict -eq 'N/A') { $color = 'DarkGray' }
            Write-Host ('   {0,-7} {1} {2,-12} {3,-34} {4}' -f $row.Verdict, $row.Id, $row.Kind, $row.Item, $row.Note) -ForegroundColor $color
            if ($row.Verdict -eq 'MISSED') { Write-Host "           should have been: $($row.Expect)" -ForegroundColor DarkGray }
        }
        Add-Results (Get-LabGradeSummary $rows)
        Add-Results (Get-AccountsKeptFinding $record)
        if ($WatchMinutes -gt 0) {
            Write-Host "   watching the beacon log for $WatchMinutes minute(s)..." -ForegroundColor DarkGray
            Add-Results (Watch-LabBeacon -Record $record -Minutes $WatchMinutes)
        }
    } catch { Add-Results (New-Result 'Lab answer key' 'FAIL' "this section crashed: $($_.Exception.Message)") }
}

# ---- summary
$count = @{ PASS = 0; FAIL = 0; WARN = 0; INFO = 0; SKIP = 0 }
foreach ($x in $script:All) { $count[$x.Status]++ }
Write-Host "`n== Summary" -ForegroundColor White
Write-Host ('   {0} pass, {1} fail, {2} warn, {3} info, {4} skip' -f $count.PASS, $count.FAIL, $count.WARN, $count.INFO, $count.SKIP)
$failed = @($script:All | Where-Object { $_.Status -eq 'FAIL' })
if ($failed.Count -gt 0) {
    Write-Host '   To fix:' -ForegroundColor Red
    foreach ($x in $failed) { Write-Host "     - $($x.Name): $($x.Detail)" -ForegroundColor Red }
}
Write-Host '   Also run Score-Check.ps1 from your laptop: it is the only check that goes through the firewall like the scoring engine.' -ForegroundColor DarkGray
exit (Get-ScoreExitCode $script:All)
