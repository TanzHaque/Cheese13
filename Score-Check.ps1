<#
.SYNOPSIS
  Poor man's scoring engine for your lab. Run it after every hardening change.
  Extended version: it now does a REAL RDP login (needs FreeRDP), not just "is port 3389 open".

.DESCRIPTION
  Checks what the real scoring checks care about:
    RDP port, RDP service (protocol + TLS), RDP login as jmoney (NLA, through FreeRDP),
    Jenkins login as jmoney, Jenkins latest rocket-build is SUCCESS,
    and, only when run ON the box: jmoney account state and free RDP session slots.
  Best run from your LAPTOP against the VM's IP, so the firewall really applies to you.

  Password for jmoney: -JmoneyPassword, or the environment variable HPCC_JMONEY_PASSWORD, or -AskPassword
  (hidden prompt, best after you rotate it). With none of those it uses the packet's default password.

  FreeRDP is the one extra tool needed for the real RDP login test. Without it that line says SKIP and prints
  the one-line command you can run from any Linux box instead. The official FreeRDP releases are source code only,
  so on Windows use a third-party build, or run this script with PowerShell 7 from WSL / Linux (apt install freerdp3-x11).

  Result words:  PASS works.  FAIL broken (would lose points).  WARN might break.  SKIP not tested.
  Exit code:     0 = all PASS,  1 = at least one FAIL,  2 = no FAIL but some WARN / SKIP.

.EXAMPLE
  .\Score-Check.ps1 -Target 192.168.56.20 -Loop
  .\Score-Check.ps1 -Target 192.168.56.20 -AskPassword
  .\Score-Check.ps1 -Target 192.168.56.20 -FreeRdpPath C:\tools\wfreerdp.exe -CheckMariaDB
#>
[CmdletBinding()]
param(
    [string]$Target = '127.0.0.1',
    [int]$RdpPort = 3389,
    [int]$JenkinsPort = 8080,
    [string]$User = 'jmoney',
    [string]$JmoneyPassword,
    [switch]$AskPassword,
    [string]$FreeRdpPath,
    [switch]$NoAuthRdp,
    [switch]$CheckMariaDB,
    [ValidateSet('Auto', 'Yes', 'No')][string]$LocalChecks = 'Auto',   # Yes = also check jmoney + RDP slots (run it ON the box)
    [switch]$Loop,
    [int]$IntervalSeconds = 30
)

. "$PSScriptRoot\ScoreLib.ps1"

# ---- which password? parameter, then environment, then a hidden prompt, then the packet default
$pw = $JmoneyPassword
if (-not $pw -and $env:HPCC_JMONEY_PASSWORD) { $pw = $env:HPCC_JMONEY_PASSWORD }
if (-not $pw -and $AskPassword) { $pw = Read-Secret "Password for $User" }
if (-not $pw) {
    $pw = 'H00ves0nTheM00n'
    Write-Host 'No password given: using the packet default (fine until you rotate jmoney; then use -AskPassword).' -ForegroundColor DarkGray
}

$free = $null
if (-not $NoAuthRdp) {
    $free = Find-FreeRdp -ExplicitPath $FreeRdpPath
    if ($free) { Write-Host "FreeRDP client: $free" -ForegroundColor DarkGray }
}

# everything the checks need, in one place
$checkArgs = @{
    Target = $Target; RdpPort = $RdpPort; JenkinsPort = $JenkinsPort; User = $User; Password = $pw
    FreeRdp = $free; NoAuthRdp = $NoAuthRdp; CheckMariaDB = $CheckMariaDB; LocalChecks = $LocalChecks
}

do {
    Write-Host "`n--- $(Get-Date -Format HH:mm:ss)  target $Target ---"
    $results = @(Invoke-ScoreChecks @checkArgs)
    foreach ($x in $results) { Show-Result $x }
    $count = @{ PASS = 0; FAIL = 0; WARN = 0; SKIP = 0 }
    foreach ($x in $results) { $count[$x.Status]++ }
    Write-Host ('    {0} pass, {1} fail, {2} warn, {3} skip' -f $count.PASS, $count.FAIL, $count.WARN, $count.SKIP)
    $exitCode = Get-ScoreExitCode $results
    if ($Loop) { Start-Sleep -Seconds $IntervalSeconds }
} while ($Loop)

exit $exitCode
