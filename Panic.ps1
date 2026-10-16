<#
Panic.ps1 - break-glass for assembly-t.  Run it in an elevated PowerShell (typing it on the Console works):

    powershell -ep bypass C:\hp\Panic.ps1

It is ALSO the program the dead-man switch runs, with -FromTask. It needs nothing else from the tool: it stands alone.

What it does, step by step (one failing step never stops the next one):
  Firewall  put the saved firewall policy back (the one exported when the dead-man switch was armed).
            No export, or -Fallback: reset the firewall to the Windows default and allow ports 3389 and 8080.
  Adapters  switch on any network adapter that is disabled
  Rdp       Remote Desktop allowed, TermService running, Remote Desktop back on port 3389 if somebody moved it
  Jmoney    the scoring user enabled, unlocked, in Remote Desktop Users, and not expired / not forced to change its password
            (the password itself is NOT touched)
  Jenkins   the Jenkins service running
  Rights    only if the tool saved the old "log on through Remote Desktop Services" setting: put it back

-FromTask runs only Firewall and Adapters, asks nothing, then removes the dead-man task and writes fired.json.
-Only Firewall (or Adapters, Rdp, Jmoney, Jenkins, Rights) runs just that step.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'the parameters are read inside the functions below')]
param(
    [switch]$FromTask,
    [string]$DataDir  = 'C:\ProgramData\NetCacheSvc',
    [string]$StateDir = '',
    [string]$Only = '',
    [switch]$Fallback,
    [switch]$Yes
)
$ErrorActionPreference = 'Continue'      # Windows PowerShell 5.1 turns a program's error text into a script error when the caller used 'Stop'; each step has its own try/catch
if (-not $StateDir) { $StateDir = Join-Path $DataDir 'deadman' }
$LogFile = Join-Path $StateDir 'panic.log'
$TaskName = 'NetCacheRestore'

function Write-PanicLog {
    param([string]$Text, [string]$Color = 'Gray')
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text
    Write-Host $line -ForegroundColor $Color
    try {
        if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
        [System.IO.File]::AppendAllText($LogFile, $line + [Environment]::NewLine)
    } catch { Write-Host '(could not write panic.log)' -ForegroundColor DarkGray }
}

function Test-PortLocal {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $wait = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $wait.AsyncWaitHandle.WaitOne(2000)) { return $false }
        $client.EndConnect($wait)
        return $true
    } catch { return $false }
    finally { $client.Close() }
}

# ---------------------------------------------------------------- the steps (each returns a sentence, or throws)
function Restore-Firewall {
    $export = Join-Path $StateDir 'fw-before.wfw'
    if ((Test-Path $export) -and -not $Fallback) {
        $out = & netsh.exe advfirewall import $export 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { throw "netsh could not import $export : $out" }
        return "firewall policy put back from $export"
    }
    & netsh.exe advfirewall reset | Out-Null
    foreach ($port in 3389, 8080) {
        $name = "Panic allow $port"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any | Out-Null
        }
    }
    'firewall reset to the Windows default, then inbound 3389 and 8080 allowed'
}

function Restore-Adapters {
    $off = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Disabled' })
    foreach ($a in $off) { Enable-NetAdapter -Name $a.Name -Confirm:$false }
    "$($off.Count) disabled network adapter(s) switched on"
}

function Restore-Rdp {
    $ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $listener = "$ts\WinStations\RDP-Tcp"
    Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0
    if ($null -ne (Get-ItemProperty -Path $pol -Name fDenyTSConnections -ErrorAction SilentlyContinue)) {
        Set-ItemProperty -Path $pol -Name fDenyTSConnections -Value 0       # a policy value would win over the setting above
    }
    $port = (Get-ItemProperty -Path $listener -Name PortNumber -ErrorAction SilentlyContinue).PortNumber
    $portMoved = ($null -ne $port -and $port -ne 3389)
    if ($portMoved) { Set-ItemProperty -Path $listener -Name PortNumber -Value 3389 }      # somebody moved Remote Desktop to another port
    $svc = Get-Service -Name TermService
    if ($svc.StartType -eq 'Disabled') { Set-Service -Name TermService -StartupType Manual }
    if ($svc.Status -ne 'Running') { Start-Service -Name TermService }
    elseif ($portMoved) { Restart-Service -Name TermService -Force }       # the port only changes after a restart (this ends open Remote Desktop sessions)
    if ($portMoved) { return "Remote Desktop is allowed, TermService is running, and the port is back to 3389 (it was $port)" }
    'Remote Desktop is allowed and TermService is running'
}

function Restore-Jmoney {
    $name = 'jmoney'
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (-not $user) { throw "there is no local account called $name" }
    Enable-LocalUser -Name $name
    & net.exe user $name /active:yes | Out-Null                              # this also clears a lockout
    $group = Get-LocalGroup -SID 'S-1-5-32-555'                              # Remote Desktop Users (by SID, so the name does not matter)
    Add-LocalGroupMember -Group $group.Name -Member $name -ErrorAction SilentlyContinue
    # Three more things make Windows refuse a logon without any wrong password. Each is repaired only if it is set, and none of
    # them changes the password itself.
    $also = @()
    if ($user.AccountExpires -and ([datetime]$user.AccountExpires) -lt (Get-Date)) {
        & net.exe user $name /expires:never | Out-Null
        $also += 'the account expiry removed'
    }
    if ($user.PasswordExpires -and ([datetime]$user.PasswordExpires) -lt (Get-Date)) {
        Set-LocalUser -Name $name -PasswordNeverExpires $true
        $also += 'the password expiry removed'
    }
    if (-not $user.PasswordLastSet) {
        & net.exe user $name /logonpasswordchg:no | Out-Null                # a blank "password last set" means "must change it at the next logon"
        $also += "the 'must change password at next logon' flag cleared"
    }
    $text = "$name is enabled, unlocked and in $($group.Name) (password untouched)"
    if ($also.Count) { $text += '; ' + ($also -join ', ') }
    $text
}

function Restore-Jenkins {
    $svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -like '*jenkins*' -or $_.PathName -like '*jenkins*' } | Select-Object -First 1
    if (-not $svc) { throw 'no Jenkins service was found (looked at service names and program paths)' }
    if ($svc.StartMode -eq 'Disabled') { Set-Service -Name $svc.Name -StartupType Automatic }
    if ($svc.State -ne 'Running') { Start-Service -Name $svc.Name }
    "Jenkins service '$($svc.Name)' is running"
}

function Restore-Rights {
    $saved = Join-Path $DataDir 'rights-before.inf'
    if (-not (Test-Path $saved)) { return 'nothing to do: the tool never changed the Remote Desktop logon right' }
    $db = Join-Path $env:TEMP 'panic-rights.sdb'
    & secedit.exe /configure /db $db /cfg $saved /areas USER_RIGHTS /quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "secedit could not apply $saved" }
    "the old 'Allow log on through Remote Desktop Services' setting is back (from $saved)"
}

# ---------------------------------------------------------------- run the steps
function Invoke-PanicStep {
    param([string]$Name, [scriptblock]$Code)
    try {
        $msg = & $Code
        Write-PanicLog ("[ OK ] {0,-9} {1}" -f $Name, $msg) 'Green'
        return $true
    } catch {
        Write-PanicLog ("[FAIL] {0,-9} {1}" -f $Name, $_.Exception.Message) 'Red'
        return $false
    }
}

function Start-Panic {
    $steps = [ordered]@{
        Firewall = { Restore-Firewall }
        Adapters = { Restore-Adapters }
        Rdp      = { Restore-Rdp }
        Jmoney   = { Restore-Jmoney }
        Jenkins  = { Restore-Jenkins }
        Rights   = { Restore-Rights }
    }
    if ($FromTask) { $run = @('Firewall', 'Adapters') }
    elseif ($Only) { $run = @($Only) }
    else { $run = @($steps.Keys) }
    foreach ($n in $run) { if (-not $steps.Contains($n)) { Write-Host "Unknown step '$n'. Choose from: $($steps.Keys -join ', ')" -ForegroundColor Red; return } }

    Write-PanicLog ("PANIC started: steps = " + ($run -join ', ')) 'Yellow'
    if (-not $FromTask -and -not $Yes) {
        $a = Read-Host "Run these steps now? The firewall import replaces the current firewall policy. (y/N)"
        if ($a -notmatch '^(y|yes)$') { Write-PanicLog 'cancelled by you'; return }
    }
    $results = @()
    foreach ($n in $run) {
        $ok = Invoke-PanicStep $n $steps[$n]
        $results += ("{0}={1}" -f $n, $(if ($ok) { 'ok' } else { 'FAILED' }))
    }

    $rdp = Test-PortLocal 3389
    $jen = Test-PortLocal 8080
    Write-PanicLog ("check: port 3389 {0}, port 8080 {1}" -f $(if ($rdp) { 'OPEN' } else { 'CLOSED' }), $(if ($jen) { 'OPEN' } else { 'CLOSED' })) $(if ($rdp -and $jen) { 'Green' } else { 'Red' })

    if ($FromTask) {
        # the dead-man switch has done its job: remove its task and leave a note for the tool
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $StateDir 'armed.json') -ErrorAction SilentlyContinue
        $note = @{ Time = (Get-Date -Format 's'); Results = $results }
        [System.IO.File]::WriteAllText((Join-Path $StateDir 'fired.json'), (ConvertTo-Json -InputObject $note))
    }
}

# Run only when started as a script (dot-sourcing it, as the tests do, just defines the functions).
if ($MyInvocation.InvocationName -ne '.') { Start-Panic }
