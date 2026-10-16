# Test-Watchdog.ps1 - tests Watchdog.ps1 (the SYSTEM task that keeps Remote Desktop, the scoring user, Jenkins and the firewall allow
# rules alive and writes alerts) against the PRETEND Windows box of FakeWindows.ps1. The watchdog's own files (alerts.log, state.json,
# status.json, the baseline, the job copies) are REAL files in a temp folder, so the file handling is really exercised.
# What it proves: every check says "fine" on a healthy box and names the problem on a broken one; each repair is tried, never more than
# once per 2 minutes per check, and never for a check that crashed or while paused; every alert is written once; events, failed-logon
# bursts, baseline differences and Jenkins job changes are reported once; the notes (flags) and pausing work.
# What it cannot prove: that real Windows answers these cmdlets the way the pretend box does, and that the scheduled task really starts
# the script every minute (both are lab tests, see README).
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\FakeWindows.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-wd-' + [guid]::NewGuid().ToString('N'))
$dataRoot = Join-Path $tmp 'data'
$wdDir = Join-Path $dataRoot 'watchdog'
New-Item -ItemType Directory -Path $dataRoot -Force | Out-Null

$global:FW = New-FakeBox
. "$PSScriptRoot\..\Watchdog.ps1" -DataDir $dataRoot -Dir $wdDir        # dot-sourced: only defines the functions (and the Panic.ps1 repairs)

# ------------------------------------------------------------------ the REAL port test, before it is replaced by the pretend one
Write-Host "`n== Test-PortOpen against a real listener =="
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$realPort = $listener.LocalEndpoint.Port
Assert-True (Test-PortOpen '127.0.0.1' $realPort) 'a port with a listener answers'
$listener.Stop()
Assert-True (-not (Test-PortOpen '127.0.0.1' $realPort)) 'the same port after the listener stopped does not answer'

# ------------------------------------------------------------------ stand-ins for the clock and the port test
$global:WdNow = 1790000000
function Get-Epoch { [long]$global:WdNow }
function Step-Clock { param([int]$Seconds) $global:WdNow = $global:WdNow + $Seconds }
function Test-PortOpen { param([string]$HostName, [int]$Port) Test-TcpOpen -HostName $HostName -Port $Port }

function New-HealthyBox {
    # A box where all four things the watchdog guards are fine: the tool's two allow rules exist, both ports answer.
    $global:FW = New-FakeBox
    foreach ($p in 3389, 8080) {
        New-NetFirewallRule -Name "HP-Allow-TCP-$p" -DisplayName "HP Allow TCP $p" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any -RemoteAddress Any -Description 'HP: scored port, any source'
    }
    $global:FW.Tcp['127.0.0.1:3389'] = $true
    $global:FW.Tcp['127.0.0.1:8080'] = $true
    $global:FW.Calls.Clear()
}
function Reset-Watchdog {
    if (Test-Path $wdDir) { Remove-Item -Path $wdDir -Recurse -Force }
    $settings = Join-Path $dataRoot 'settings.json'
    if (Test-Path $settings) { Remove-Item -Path $settings -Force }
    New-HealthyBox
    $global:WdNow = 1790000000
    Initialize-Folders
}
function Set-FakeServiceState {
    param([string]$Name, [string]$State, [string]$StartMode = '')
    $s = @($global:FW.Services | Where-Object { $_.Name -eq $Name })[0]
    $s.State = $State
    if ($StartMode) { $s.StartMode = $StartMode }
}
function Get-FwRow { param([string]$Name) @($global:FW.FwRules | Where-Object { $_.Name -eq $Name })[0] }
function Add-BlockRule {
    param([string]$Name, [string]$Port = '3389', [string]$Protocol = 'TCP', [string]$Remote = 'Any', [string]$Program = 'Any', [bool]$Persistent = $true, [string]$Direction = 'Inbound')
    New-NetFirewallRule -Name $Name -DisplayName $Name -Direction $Direction -Protocol $Protocol -LocalPort $Port -Action Block -RemoteAddress $Remote -Program $Program
    (Get-FwRow $Name).Persistent = $Persistent
}
function Get-AlertText { if (Test-Path $AlertFile) { [System.IO.File]::ReadAllText($AlertFile) } else { '' } }
function Get-AlertsOf {
    param([string]$Level)
    $found = @()
    foreach ($line in ((Get-AlertText) -split "`r?`n")) {
        if ($line -match "^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d $Level\s+(.*)$") { $found += $Matches[1] }
    }
    $found
}
function Get-AlertCount { param([string]$Level, [string]$Pattern) @(Get-AlertsOf $Level | Where-Object { $_ -match $Pattern }).Count }
function Invoke-TestPass {
    param([int]$Seconds = 60)
    Step-Clock $Seconds
    try { Invoke-Pass 6>$null | Out-Null; $true }
    catch { Write-Host "  (the pass threw: $($_.Exception.Message))" -ForegroundColor Red; $false }
}
function Read-StatusFile { [System.IO.File]::ReadAllText($StatusFile) | ConvertFrom-Json }
function Get-CheckOf { param($StatusObject, [string]$Name) @($StatusObject.Checks | Where-Object { $_.Name -eq $Name })[0] }

Reset-Watchdog

# ------------------------------------------------------------------ the constants match the tool
Write-Host "`n== the constants match the tool (lib\Core.ps1, lib\DeadMan.ps1) =="
$probe = Join-Path $tmp 'plan.ps1'
$probeLines = @(
    ". '$PSScriptRoot\..\lib\Core.ps1'",
    ". '$PSScriptRoot\..\lib\DeadMan.ps1'",
    '$out = @{ Plan = $script:Plan; DeadMan = $script:DeadManTaskName }',
    'ConvertTo-Json -InputObject $out -Depth 4')
[System.IO.File]::WriteAllLines($probe, [string[]]$probeLines)
$pwshPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$planText = (& $pwshPath -NoProfile -File $probe) -join "`n"
$planObj = $planText | ConvertFrom-Json
Assert-Equal $ScoringUser $planObj.Plan.ScoringUser 'the scoring user is the one in the plan'
Assert-True ($ScoredPorts -contains [int]$planObj.Plan.RdpPort) 'the Remote Desktop port is guarded'
Assert-True ($ScoredPorts -contains [int]$planObj.Plan.JenkinsPort) 'the Jenkins port is guarded'
Assert-Equal $ScoredPorts.Count 2 'exactly two ports are guarded'
Assert-True ($OwnTasks -contains $planObj.DeadMan) 'the dead-man switch task is one of the watchdog''s own tasks (never reported as new)'
Assert-Equal $planObj.Plan.SidRdpUsers 'S-1-5-32-555' 'the Remote Desktop Users SID used below is the plan''s'
Assert-Equal $planObj.Plan.SidAdministrators 'S-1-5-32-544' 'the Administrators SID used below is the plan''s'
Assert-Equal $planObj.Plan.BlackboxPort 22 'the blackbox port is 22 (ssh)'

# ------------------------------------------------------------------ small helpers
Write-Host "`n== small helpers =="
Assert-True (Test-PortInList @('3389') 3389) 'port list: the exact port'
Assert-True (Test-PortInList @('Any') 3389) 'port list: Any'
Assert-True (Test-PortInList @('*') 3389) 'port list: *'
Assert-True (Test-PortInList @('1000-2000') 1500) 'port list: inside a range'
Assert-True (-not (Test-PortInList @('1000-2000') 3389)) 'port list: outside a range'
Assert-True (-not (Test-PortInList @('80', '443') 3389)) 'port list: other ports'
Assert-True (-not (Test-PortInList @() 3389)) 'port list: empty'
Assert-True (-not (Test-PortInList @('RPC') 3389)) 'port list: a name is not a number'
Assert-True (Test-RightHolds '*S-1-5-32-544,*S-1-5-32-555,jmoney' @('S-1-5-32-555')) 'right list: a SID in the list'
Assert-True (Test-RightHolds '*S-1-5-32-544,jmoney' @('jmoney')) 'right list: a plain name in the list'
Assert-True (Test-RightHolds '*S-1-5-32-544, *S-1-5-32-555' @('S-1-5-32-555')) 'right list: spaces after commas'
Assert-True (-not (Test-RightHolds '*S-1-5-32-546' @('S-1-5-32-555', 'jmoney'))) 'right list: nothing from the list'
Assert-True (-not (Test-RightHolds '' @('jmoney'))) 'right list: empty list'
Assert-True ((Get-Clock 1790000000) -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$') 'the clock text has the date and time'
Assert-Equal (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') 0 'a registry value is read'
Assert-True ($null -eq (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections')) 'a missing registry value is $null'
Assert-True ((Get-Text 'C:\Windows\System32\drivers\etc\hosts') -match 'localhost') 'a whole file comes back as one text'
$members = @(Get-GroupMembers 'S-1-5-32-555')
Assert-True ($members -contains 'jmoney') 'group members by SID: jmoney is in Remote Desktop Users'
Assert-True ($members -notcontains 'Administrator') 'group members by SID: the built-in Administrator is not'
Assert-True (@(Get-GroupMembers 'S-1-5-32-544') -contains 'plinktern') 'group members by SID: Administrators'
$global:FW.Users['LAB\bob'] = @{ Name = 'LAB\bob'; Sid = 'S-1-5-21-9-9-9-1'; Enabled = $true; Groups = (New-Object System.Collections.ArrayList); Password = ''; Description = ''; LastLogon = $null }
[void]$global:FW.Users['LAB\bob'].Groups.Add('Remote Desktop Users')
Assert-True (@(Get-GroupMembers 'S-1-5-32-555') -contains 'bob') 'group members: a DOMAIN\name is shortened to the name'
$global:FW.Users.Remove('LAB\bob')
Assert-Equal (Get-BlackboxIp) '' 'no settings.json: no blackbox address'
[System.IO.File]::WriteAllText((Join-Path $dataRoot 'settings.json'), '{"BlackboxIp":"172.16.5.5"}')
Assert-Equal (Get-BlackboxIp) '172.16.5.5' 'settings.json: the blackbox address'
[System.IO.File]::WriteAllText((Join-Path $dataRoot 'settings.json'), '{ not json')
Assert-Equal (Get-BlackboxIp) '' 'a broken settings.json gives no address (and no error)'
Remove-Item -Path (Join-Path $dataRoot 'settings.json')
Assert-Equal (Get-Config).JenkinsHome '' 'no config.json: Jenkins home unknown'
[System.IO.File]::WriteAllText($ConfigFile, (ConvertTo-Json -InputObject @{ JenkinsHome = 'C:\ProgramData\Jenkins\.jenkins' }))
Assert-Equal (Get-Config).JenkinsHome 'C:\ProgramData\Jenkins\.jenkins' 'config.json: Jenkins home'
[System.IO.File]::WriteAllText($ConfigFile, '][')
Assert-Equal (Get-Config).JenkinsHome '' 'a broken config.json gives no Jenkins home (and no error)'
Remove-Item -Path $ConfigFile

# ------------------------------------------------------------------ files: alerts, state, status, flags, pause
Write-Host "`n== alerts.log, state.json, status.json, flags, pause =="
Reset-Watchdog
Assert-True ((Test-Path $BaseDir) -and (Test-Path $GoodDir)) 'Initialize-Folders makes the baseline and jobs-good folders'
Write-Alert 'INFO' 'first line' 6>$null
Write-Alert 'ALERT' 'second line' 6>$null
$lines = @((Get-AlertText) -split "`r?`n" | Where-Object { $_ })
Assert-Equal $lines.Count 2 'two alerts are two lines'
Assert-True ($lines[0] -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d INFO  first line$') 'a line is: date time LEVEL text (level padded to 5)'
Assert-True ($lines[1] -match ' ALERT second line$') 'the second line follows the first'
[System.IO.File]::WriteAllText($AlertFile, ('x' * 1100000))
Write-Alert 'INFO' 'after rotation' 6>$null
Assert-True (Test-Path ($AlertFile + '.old')) 'an alerts.log over 1 MB is moved to alerts.log.old'
Assert-True ((Get-AlertText) -match 'after rotation' -and (Get-AlertText).Length -lt 200) 'the new alerts.log starts small'
Remove-Item -Path ($AlertFile + '.old')
$st = Read-State
Assert-Equal $st.Count 0 'no state.json: an empty state'
$st['pass'] = 7; $st['detail.rdp'] = 'some text'; $st['lasttime.Security'] = [long]638000000000000000
Save-State $st
$back = Read-State
Assert-Equal ([long]$back['pass']) 7 'state round trip: a number'
Assert-Equal $back['detail.rdp'] 'some text' 'state round trip: a text'
Assert-Equal ([long]$back['lasttime.Security']) 638000000000000000 'state round trip: a very large number (event ticks)'
[System.IO.File]::WriteAllText($StateFile, 'garbage')
$before = Get-AlertCount 'INFO' 'state.json could not be read'
$st = Read-State 6>$null
Assert-Equal $st.Count 0 'a broken state.json gives an empty state'
Assert-Equal (Get-AlertCount 'INFO' 'state.json could not be read') ($before + 1) 'a broken state.json is mentioned in alerts.log'
Remove-Item -Path $StateFile
Assert-Equal (Get-PausedUntil) 0 'no pause.txt: not paused'
[System.IO.File]::WriteAllText($PauseFile, [string]($global:WdNow + 300))
Assert-Equal (Get-PausedUntil) ($global:WdNow + 300) 'pause.txt in the future: paused until then'
[System.IO.File]::WriteAllText($PauseFile, [string]($global:WdNow - 5))
Assert-Equal (Get-PausedUntil) 0 'pause.txt in the past: not paused'
[System.IO.File]::WriteAllText($PauseFile, 'abc')
Assert-Equal (Get-PausedUntil) 0 'pause.txt with garbage: not paused'
Remove-Item -Path $PauseFile
Assert-True (-not (Use-Flag $AcceptFlag)) 'no flag file: false'
Write-FlagFile $AcceptFlag
Assert-True (Test-Path $AcceptFlag) 'Write-FlagFile leaves a note'
Assert-True (Use-Flag $AcceptFlag) 'Use-Flag: true when the note is there'
Assert-True (-not (Test-Path $AcceptFlag)) 'Use-Flag removes the note'

# ------------------------------------------------------------------ the checks on a healthy box
Write-Host "`n== every check on a healthy box =="
Reset-Watchdog
foreach ($pair in @(@('rdp', { Test-RdpCheck }), @('jmoney', { Test-JmoneyCheck }), @('jenkins', { Test-JenkinsCheck }), @('firewall', { Test-FirewallCheck }),
                    @('rights', { Test-RightsCheck }), @('defender', { Test-DefenderCheck }))) {
    $r = & $pair[1]
    Assert-True ($r.Ok -and $r.Name -eq $pair[0]) "healthy: $($pair[0]) is fine ($($r.Detail))"
}
Assert-True ($null -eq (Test-BlackboxCheck)) 'no blackbox address: the blackbox check says nothing'

# ------------------------------------------------------------------ rdp
Write-Host "`n== rdp check =="
Set-FakeServiceState 'TermService' 'Stopped'
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'TermService is Stopped') 'rdp: a stopped TermService'
Set-FakeServiceState 'TermService' 'Running'
$global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'TermService' })
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'TermService service is missing') 'rdp: no TermService at all'
Reset-Watchdog
Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'switched off') 'rdp: fDenyTSConnections = 1'
Reset-Watchdog
Set-FakeReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDenyTSConnections' 1
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'policy') 'rdp: a policy switches it off'
Reset-Watchdog
Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber' 3390
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'port 3390 instead of 3389') 'rdp: moved to another port'
Reset-Watchdog
$global:FW.Tcp['127.0.0.1:3389'] = $false
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'nothing answers on port 3389') 'rdp: the port does not answer'
Reset-Watchdog
Set-FakeServiceState 'TermService' 'Stopped'
$global:FW.Tcp['127.0.0.1:3389'] = $false
Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1
$r = Test-RdpCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'TermService is Stopped; Remote Desktop is switched off.*nothing answers') 'rdp: several problems are all named'

# ------------------------------------------------------------------ jmoney
Write-Host "`n== scoring user check =="
Reset-Watchdog
$global:FW.Users.Remove('jmoney')
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'no local account called jmoney') 'jmoney: the account is gone'
Reset-Watchdog
$global:FW.Users['jmoney'].Enabled = $false
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'jmoney is disabled') 'jmoney: disabled'
Reset-Watchdog
$global:FW.Users['jmoney'].Locked = $true
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'locked out') 'jmoney: locked out'
Reset-Watchdog
$global:FW.Users['jmoney'].AccountExpires = (Get-Date).AddDays(-1)
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'account jmoney has expired') 'jmoney: the account expired yesterday'
$global:FW.Users['jmoney'].AccountExpires = (Get-Date).AddDays(30)
Assert-True ((Test-JmoneyCheck).Ok) 'jmoney: an account that expires in 30 days is fine for now'
Reset-Watchdog
$global:FW.Users['jmoney'].PasswordExpires = (Get-Date).AddDays(-1)
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'password of jmoney has expired') 'jmoney: the password expired'
Reset-Watchdog
$global:FW.Users['jmoney'].MustChange = $true
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'must change password at next logon') 'jmoney: flagged "must change password"'
Reset-Watchdog
$global:FW.Users['jmoney'].Groups.Remove('Remote Desktop Users')
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'not in Remote Desktop Users') 'jmoney: removed from Remote Desktop Users'
[void]$global:FW.Users['jmoney'].Groups.Add('Administrators')
Assert-True ((Test-JmoneyCheck).Ok) 'jmoney: Administrators can use Remote Desktop too'
Reset-Watchdog
$global:FW.Users['jmoney'].Enabled = $false
$global:FW.Users['jmoney'].Locked = $true
$global:FW.Users['jmoney'].MustChange = $true
$r = Test-JmoneyCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'disabled; .*locked out; .*must change') 'jmoney: three problems are all named'

# ------------------------------------------------------------------ jenkins
Write-Host "`n== Jenkins check =="
Reset-Watchdog
Set-FakeServiceState 'Jenkins' 'Stopped'
$r = Test-JenkinsCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'Jenkins is Stopped') 'jenkins: stopped'
Reset-Watchdog
Set-FakeServiceState 'Jenkins' 'Stopped' 'Disabled'
$r = Test-JenkinsCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'Disabled; service Jenkins is Stopped') 'jenkins: disabled and stopped'
Reset-Watchdog
Set-FakeServiceState 'Jenkins' 'Start Pending'
$global:FW.Tcp['127.0.0.1:8080'] = $false
$r = Test-JenkinsCheck
Assert-True ($r.Ok -and $r.Detail -match 'still starting') 'jenkins: "Start Pending" is not a failure (its port is not open yet)'
Reset-Watchdog
$global:FW.Tcp['127.0.0.1:8080'] = $false
$r = Test-JenkinsCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'nothing answers on port 8080') 'jenkins: running but the port does not answer'
Reset-Watchdog
$global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'Jenkins' })
$r = Test-JenkinsCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'no Jenkins service was found') 'jenkins: no service'
Reset-Watchdog
$svc = @($global:FW.Services | Where-Object { $_.Name -eq 'Jenkins' })[0]
$svc.Name = 'BuildServer'
$svc.PathName = '"C:\Program Files\Jenkins\jenkins.exe"'
$r = Test-JenkinsCheck
Assert-True ($r.Ok -and $r.Detail -match 'BuildServer') 'jenkins: a renamed service is found by its program path'

# ------------------------------------------------------------------ firewall
Write-Host "`n== firewall check =="
Reset-Watchdog
Remove-NetFirewallRule -Name 'HP-Allow-TCP-3389'
$r = Test-FirewallCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'rule HP-Allow-TCP-3389 is missing') 'firewall: an allow rule is missing'
Reset-Watchdog
Disable-NetFirewallRule -Name 'HP-Allow-TCP-8080'
$r = Test-FirewallCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'HP-Allow-TCP-8080 is switched off') 'firewall: an allow rule is switched off'
Reset-Watchdog
(Get-FwRow 'HP-Allow-TCP-3389').Action = 'Block'
$r = Test-FirewallCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'no longer an inbound Allow rule') 'firewall: an allow rule turned into a block rule'
Reset-Watchdog
(Get-FwRow 'HP-Allow-TCP-3389').Direction = 'Outbound'
Assert-True ((-not (Test-FirewallCheck).Ok) -and (Test-FirewallCheck).Detail -match 'no longer an inbound Allow rule') 'firewall: an allow rule turned outbound'
Reset-Watchdog
(Get-FwRow 'HP-Allow-TCP-3389').Profile = 'Private'
Assert-True ((Test-FirewallCheck).Detail -match 'does not cover every network profile \(Private\)') 'firewall: an allow rule limited to one profile'
Reset-Watchdog
(Get-FwRow 'HP-Allow-TCP-3389').LocalPort = '3390'
Assert-True ((Test-FirewallCheck).Detail -match 'no longer matches TCP port 3389') 'firewall: an allow rule changed to another port'
Reset-Watchdog
(Get-FwRow 'HP-Allow-TCP-8080').Protocol = 'UDP'
Assert-True ((Test-FirewallCheck).Detail -match 'no longer matches TCP port 8080') 'firewall: an allow rule changed to UDP'
Reset-Watchdog
(Get-FwRow 'HP-Allow-TCP-8080').RemoteAddress = '10.0.0.0/8'
Assert-True ((Test-FirewallCheck).Detail -match 'only lets some addresses in') 'firewall: an allow rule limited to some addresses'
Reset-Watchdog
$global:FW.FwProfiles['Public'].AllowInboundRules = 'False'
Assert-True ((Test-FirewallCheck).Detail -match 'the Public profile ignores every inbound allow rule') 'firewall: a profile ignores inbound allow rules'
Reset-Watchdog
Add-BlockRule 'Block RDP'
$r = Test-FirewallCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match "the Block rule 'Block RDP' stops port 3389") 'firewall: a block rule for 3389'
Reset-Watchdog
Add-BlockRule 'Block range' '3000-4000'
Assert-True ((Test-FirewallCheck).Detail -match "'Block range' stops port 3389") 'firewall: a block rule for a range that holds 3389'
Reset-Watchdog
Add-BlockRule 'Block everything' 'Any'
$d = (Test-FirewallCheck).Detail
Assert-True ($d -match "'Block everything' stops port 3389" -and $d -match "'Block everything' stops port 8080") 'firewall: a block rule for every port names both scored ports'
Reset-Watchdog
Add-BlockRule 'Block some addresses' '3389' 'TCP' '203.0.113.0/24'
Assert-True ((Test-FirewallCheck).Ok) 'firewall: a block rule for only some addresses is left alone (that is a deliberate blocklist)'
Reset-Watchdog
Add-BlockRule 'Block one program' 'Any' 'TCP' 'Any' 'C:\bad\bad.exe'
Assert-True ((Test-FirewallCheck).Ok) 'firewall: a block rule for one program on every port is left alone'
Reset-Watchdog
Add-BlockRule 'Block program on 3389' '3389' 'TCP' 'Any' 'C:\bad\bad.exe'
Assert-True ((Test-FirewallCheck).Detail -match "'Block program on 3389' stops port 3389") 'firewall: a block rule for one program on port 3389 itself counts'
Reset-Watchdog
Add-BlockRule 'Block UDP 3389' '3389' 'UDP'
Assert-True ((Test-FirewallCheck).Ok) 'firewall: a UDP block rule does not stop the TCP port'
Reset-Watchdog
Add-BlockRule 'Block other port' '4444'
Assert-True ((Test-FirewallCheck).Ok) 'firewall: a block rule for another port is left alone'
Reset-Watchdog
Add-BlockRule 'Block outbound' '3389' 'TCP' 'Any' 'Any' $true 'Outbound'
Assert-True ((Test-FirewallCheck).Ok) 'firewall: an outbound block rule is left alone'
Reset-Watchdog
Add-BlockRule 'Block off' '3389'
Disable-NetFirewallRule -Name 'Block off'
Assert-True ((Test-FirewallCheck).Ok) 'firewall: a block rule that is switched off is left alone'
Reset-Watchdog
Add-BlockRule 'GPO block' '3389' 'TCP' 'Any' 'Any' $false
Assert-True ((Test-FirewallCheck).Detail -match "'GPO block' stops port 3389") 'firewall: a block rule delivered by policy (active store only) is seen'
Reset-Watchdog
$global:FW.FwProfiles['Public'].AllowInboundRules = 'False'
Remove-NetFirewallRule -Name 'HP-Allow-TCP-3389'
Add-BlockRule 'Block RDP'
$d = (Test-FirewallCheck).Detail
Assert-True ($d -match 'missing' -and $d -match 'ignores every inbound allow rule' -and $d -match 'Block rule') 'firewall: several problems are all named'

# ------------------------------------------------------------------ slow checks: rights, defender, blackbox
Write-Host "`n== rights, Defender, blackbox checks =="
Reset-Watchdog
$global:FW.Rights['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-546'
$r = Test-RightsCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match "not in 'Allow log on through Remote Desktop Services'") 'rights: nobody useful may log on through Remote Desktop'
$global:FW.Rights['SeRemoteInteractiveLogonRight'] = '*S-1-5-21-1111-2222-3333-1002'
Assert-True ((Test-RightsCheck).Ok) 'rights: the right given to jmoney''s SID alone is enough'
$global:FW.Rights['SeRemoteInteractiveLogonRight'] = 'jmoney'
Assert-True ((Test-RightsCheck).Ok) 'rights: the right given to the name jmoney is enough'
Reset-Watchdog
$global:FW.Rights['SeDenyRemoteInteractiveLogonRight'] = '*S-1-5-32-555'
$r = Test-RightsCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match "in 'Deny log on through Remote Desktop Services'") 'rights: the Deny right hits Remote Desktop Users'
$global:FW.Rights['SeDenyRemoteInteractiveLogonRight'] = '*S-1-1-0'
Assert-True (-not (Test-RightsCheck).Ok) 'rights: the Deny right given to Everyone'
Reset-Watchdog
$global:FW.Defender.Service = $false
Assert-True ((Test-DefenderCheck).Detail -match 'antivirus service is off') 'defender: the service is off'
$global:FW.Defender.Service = $true
$global:FW.Defender.RealTime = $false
Assert-True ((Test-DefenderCheck).Detail -match 'real-time protection is off') 'defender: real-time protection is off'
$global:FW.Defender = $null
$r = Test-DefenderCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match 'Defender cannot be read') 'defender: Defender cannot be read at all'
Reset-Watchdog
[System.IO.File]::WriteAllText((Join-Path $dataRoot 'settings.json'), '{"BlackboxIp":"172.16.5.5"}')
$r = Test-BlackboxCheck
Assert-True ($r.Ok -and $r.Detail -match '172.16.5.5 answers on port 22') 'blackbox: answers on 22'
[System.IO.File]::WriteAllText((Join-Path $dataRoot 'settings.json'), '{"BlackboxIp":"172.16.5.9"}')
$r = Test-BlackboxCheck
Assert-True ((-not $r.Ok) -and $r.Detail -match '172.16.5.9 does not answer') 'blackbox: a wrong address does not answer'
Remove-Item -Path (Join-Path $dataRoot 'settings.json')

# ------------------------------------------------------------------ the repairs
Write-Host "`n== Restore-OurRules =="
Reset-Watchdog
Assert-Equal (Restore-OurRules) 'nothing needed changing' 'a healthy firewall needs nothing'
Assert-Equal @($global:FW.Calls | Where-Object { $_ -match 'NetFirewall' }).Count 0 'a healthy firewall: no firewall command was run'
Remove-NetFirewallRule -Name 'HP-Allow-TCP-3389'
(Get-FwRow 'HP-Allow-TCP-8080').Action = 'Block'
(Get-FwRow 'HP-Allow-TCP-8080').Profile = 'Private'
$global:FW.FwProfiles['Private'].AllowInboundRules = 'False'
Add-BlockRule 'Block RDP'
Add-BlockRule 'Block [8080] test' '8080'
$global:FW.Calls.Clear()
$msg = Restore-OurRules
Assert-True ($msg -match 'rule HP-Allow-TCP-3389 rebuilt' -and $msg -match 'rule HP-Allow-TCP-8080 rebuilt') 'repair: both allow rules are rebuilt'
Assert-True ($msg -match 'profile Private uses inbound allow rules again') 'repair: the profile switch is put back'
Assert-True ($msg -match "Block rule 'Block RDP' switched off" -and $msg -match "Block rule 'Block \[8080\] test' switched off") 'repair: both block rules are switched off (one has [ ] in its name)'
Assert-True ((Test-FirewallCheck).Ok) 'repair: afterwards the firewall check is fine'
Assert-Equal (Get-FwRow 'Block RDP').Enabled 'False' 'repair: the block rule is switched off, not deleted'
Assert-True ($null -ne (Get-FwRow 'Block RDP')) 'repair: the block rule still exists (it can be switched on again)'
Assert-Equal @($global:FW.Calls | Where-Object { $_ -match '^Remove-NetFirewallRule Block' }).Count 0 'repair: no block rule was removed'
Assert-Equal (Get-FwRow 'HP-Allow-TCP-3389').RemoteAddress 'Any' 'repair: the rebuilt rule lets every address in'
Assert-Equal (Get-FwRow 'HP-Allow-TCP-3389').Profile 'Any' 'repair: the rebuilt rule covers every profile'
Reset-Watchdog
Add-BlockRule 'GPO block' '3389' 'TCP' 'Any' 'Any' $false
Add-BlockRule 'Block 8080' '8080'
$msg = Restore-OurRules
Assert-True ($msg -match "Block rule 'GPO block' could NOT be switched off" -and $msg -match "Block rule 'Block 8080' switched off") 'repair: a block rule that cannot be switched off does not stop the others'

Write-Host "`n== Update-Check (debounce, repair cooldown, alerts) =="
Reset-Watchdog
$origHealers = $Healers.Clone()
$global:HealCalls = 0
$global:HealWorks = $true
$Healers['rdp'] = { $global:HealCalls++; 'fixed it' }
$badR = New-CheckResult 'rdp' $false 'it is broken'
$goodR = New-CheckResult 'rdp' $true 'it is fine'
$st = @{}
Update-Check $st $badR $true { $goodR } 6>$null
Assert-Equal $global:HealCalls 1 'a failing check is repaired'
Assert-Equal (Get-AlertCount 'DOWN' '^rdp: it is broken$') 1 'the failure is written once as DOWN'
Assert-Equal (Get-AlertCount 'HEAL' '^rdp: fixed it -> the check now says: OK$') 1 'the repair is written as HEAL with the result of the new check'
Assert-Equal (Get-AlertCount 'UP' '^rdp: back to normal after 0 seconds$') 1 'a check that is fine again is written as UP'
Assert-Equal ([int]$st['ok.rdp']) 1 'state: ok'
Assert-Equal ([long]$st['since.rdp']) 0 'state: no failure running'
Assert-Equal ([long]$st['heals']) 1 'state: one repair counted'
Update-Check $st $goodR $true { $goodR } 6>$null
Assert-Equal (Get-AlertsOf 'UP').Count 1 'a check that stays fine writes nothing'

Reset-Watchdog
$global:HealCalls = 0
$st = @{}
Update-Check $st $badR $true { $badR } 6>$null
Assert-Equal (Get-AlertCount 'HEAL' 'still failing: it is broken') 1 'a repair that did not help says so'
Assert-Equal (Get-AlertsOf 'UP').Count 0 'no UP while it is still broken'
Step-Clock 60
Update-Check $st $badR $true { $badR } 6>$null
Assert-Equal $global:HealCalls 1 'a second pass 60 s later does not repair again (2 minute gap)'
Assert-Equal (Get-AlertsOf 'DOWN').Count 1 'the same failure is not written again'
Step-Clock 60
Update-Check $st $badR $true { $badR } 6>$null
Assert-Equal $global:HealCalls 2 'after 120 s the repair is tried again'
$changed = New-CheckResult 'rdp' $false 'now it is broken differently'
Update-Check $st $changed $false { $changed } 6>$null
Assert-Equal (Get-AlertCount 'DOWN' '^rdp: the problem changed: now it is broken differently$') 1 'a failing check whose problem changed is announced again'
Update-Check $st $changed $false { $changed } 6>$null
Assert-Equal (Get-AlertCount 'DOWN' 'the problem changed') 1 'the changed problem is announced once'
for ($i = 0; $i -lt 8; $i++) { Update-Check $st $changed $false { $changed } 6>$null }
Assert-Equal (Get-AlertCount 'DOWN' 'still failing \(10 checks in a row\)') 1 'every 10th failed check in a row is announced again'
Assert-Equal $global:HealCalls 2 'with repairs off nothing is repaired'
Update-Check $st $goodR $true { $goodR } 6>$null
Assert-Equal (Get-AlertCount 'UP' '^rdp: back to normal after \d+ seconds$') 1 'UP after the long failure'
Assert-Equal ([long]$st['streak.rdp']) 0 'the failure streak starts again'

Reset-Watchdog
$global:HealCalls = 0
$st = @{}
$crashed = New-CheckResult 'rdp' $false 'the check itself failed: boom'
$crashed | Add-Member -NotePropertyName Crashed -NotePropertyValue $true
Update-Check $st $crashed $true { $crashed } 6>$null
Assert-Equal $global:HealCalls 0 'a check that crashed is reported but never repaired'
Assert-Equal (Get-AlertCount 'DOWN' 'check itself failed') 1 'the crash is written as DOWN'

Reset-Watchdog
$st = @{}
$Healers['rdp'] = { throw 'boom' }
Update-Check $st $badR $true { $badR } 6>$null
Assert-Equal (Get-AlertCount 'HEAL' 'the repair FAILED: boom') 1 'a repair that throws is reported, not fatal'
$Healers['rdp'] = { 'x' }
Reset-Watchdog
$st = @{}
Update-Check $st (New-CheckResult 'builds' $false 'a build failed') $true { New-CheckResult 'builds' $false 'a build failed' } 6>$null
Assert-Equal (Get-AlertsOf 'HEAL').Count 0 'a check without a repair (builds) is only reported'
foreach ($k in @($Healers.Keys)) { $Healers[$k] = $origHealers[$k] }
Assert-Equal $Healers.Count 4 'the real repairs are back (rdp, jmoney, jenkins, firewall)'

Write-Host "`n== Invoke-Check and Invoke-Guarded =="
$r = Invoke-Check 'x' { New-CheckResult 'x' $true 'fine' }
Assert-True ($r.Ok -and -not $r.Crashed) 'Invoke-Check passes a normal result through'
$r = Invoke-Check 'x' { throw 'kaboom' }
Assert-True ((-not $r.Ok) -and $r.Crashed -and $r.Detail -match 'the check itself failed: kaboom') 'Invoke-Check turns an exception into a failing, crashed result'
$saved = ${function:Get-GroupMembers}
function Get-GroupMembers { throw 'net localgroup failed' }
$r = Invoke-Check 'jmoney' { Test-JmoneyCheck }
Assert-True ((-not $r.Ok) -and $r.Crashed) 'a real check whose helper breaks is a crashed result'
Set-Item -Path function:Get-GroupMembers -Value $saved
Assert-True (@(Get-GroupMembers 'S-1-5-32-555').Count -gt 0) 'the helper is back to normal'
Reset-Watchdog
$st = @{}
Invoke-Guarded $st 'part' { throw 'first error' } 6>$null
Invoke-Guarded $st 'part' { throw 'first error' } 6>$null
Assert-Equal (Get-AlertCount 'INFO' 'part: could not run: first error') 1 'the same error is written once'
Invoke-Guarded $st 'part' { throw 'second error' } 6>$null
Assert-Equal (Get-AlertCount 'INFO' 'part: could not run: second error') 1 'a different error is written'
Invoke-Guarded $st 'part' { 'fine' | Out-Null } 6>$null
Invoke-Guarded $st 'part' { throw 'second error' } 6>$null
Assert-Equal (Get-AlertCount 'INFO' 'part: could not run: second error') 2 'after a good run the same error counts as new again'

# ------------------------------------------------------------------ security events
Write-Host "`n== security events =="
Reset-Watchdog
$st = @{}
Watch-Events $st 6>$null
Assert-Equal ([long]$st['lastrec.Security']) 1 'an empty log: the position is "start"'
Assert-Equal (Get-AlertsOf 'ALERT').Count 0 'an empty log: no alerts'

Reset-Watchdog
Add-FakeEvent -Log Security -Id 4720 -RecordId 100 -MinutesAgo 3 -Data @{ TargetUserName = 'old1'; SubjectUserName = 'plinktern' }
Add-FakeEvent -Log Security -Id 4732 -RecordId 101 -MinutesAgo 2 -Data @{ TargetUserName = 'Administrators'; MemberSid = 'S-1-5-21-1111-2222-3333-1009'; SubjectUserName = 'plinktern' }
Add-FakeEvent -Log Security -Id 4720 -RecordId 5000 -MinutesAgo 30 -Data @{ TargetUserName = 'too-old'; SubjectUserName = 'x' }
$st = @{}
Watch-Events $st 6>$null
Assert-Equal (Get-AlertsOf 'ALERT').Count 0 'first look: events from before the watchdog are not reported'
Assert-Equal ([long]$st['lastrec.Security']) 101 'first look: the position is the newest event in the window'
Add-FakeEvent -Log Security -Id 4720 -RecordId 102 -MinutesAgo 1 -Data @{ TargetUserName = 'evil'; SubjectUserName = 'plinktern' }
Watch-Events $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^account CREATED: evil \(by plinktern\)$') 1 'a new account is reported with its name and who made it'
Watch-Events $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' 'account CREATED') 1 'the same event is not reported twice'
Add-FakeEvent -Log Security -Id 4724 -RecordId 103 -MinutesAgo 0.9 -Data @{ TargetUserName = 'jmoney'; SubjectUserName = 'kkiderchah' }
Add-FakeEvent -Log Security -Id 4732 -RecordId 104 -MinutesAgo 0.8 -Data @{ TargetUserName = 'Administrators'; MemberSid = 'S-1-5-21-1111-2222-3333-1009'; SubjectUserName = 'evil' }
Add-FakeEvent -Log Security -Id 4740 -RecordId 105 -MinutesAgo 0.7 -Data @{ TargetUserName = 'jmoney'; SubjectUserName = 'ASSEMBLY-5$' }
Add-FakeEvent -Log Security -Id 4719 -RecordId 106 -MinutesAgo 0.6 -Data @{ SubjectUserName = 'evil' }
Add-FakeEvent -Log Security -Id 4698 -RecordId 107 -MinutesAgo 0.5 -Data @{ TaskName = '\Updater'; SubjectUserName = 'evil' }
Add-FakeEvent -Log Security -Id 4722 -RecordId 108 -MinutesAgo 0.4 -Data @{ TargetUserName = 'guest2'; SubjectUserName = 'evil' }
Add-FakeEvent -Log Security -Id 4738 -RecordId 109 -MinutesAgo 0.3 -Data @{ TargetUserName = 'jmoney'; SubjectUserName = 'evil' }
Add-FakeEvent -Log Security -Id 4728 -RecordId 110 -MinutesAgo 0.2 -Data @{ TargetUserName = 'Domain Admins'; MemberSid = 'S-1-5-21-1111-2222-3333-1010' }
Watch-Events $st 6>$null
$texts = @(Get-AlertsOf 'ALERT')
Assert-Equal $texts.Count 9 'eight more events: eight more alerts (nine in all)'
Assert-Equal $texts[1] 'password RESET for jmoney (by kkiderchah)' 'event 4724 text'
Assert-Equal $texts[2] 'added to the group Administrators: S-1-5-21-1111-2222-3333-1009 (by evil)' 'event 4732 text (an unknown SID is shown as the SID)'
Assert-Equal $texts[3] 'account LOCKED OUT: jmoney' 'event 4740 text'
Assert-Equal $texts[4] 'the audit policy was CHANGED (by evil)' 'event 4719 text'
Assert-Equal $texts[5] 'scheduled task CREATED: \Updater (by evil)' 'event 4698 text'
Assert-Equal $texts[6] 'account ENABLED: guest2 (by evil)' 'event 4722 text'
Assert-Equal $texts[7] 'account CHANGED: jmoney (by evil)' 'event 4738 text'
Assert-Equal $texts[8] 'added to the group Domain Admins: S-1-5-21-1111-2222-3333-1010' 'event 4728 text (no "by" when the event has no subject)'
Assert-True (-not (Get-AlertText).Contains('too-old')) 'an event outside the 15 minute window is never reported'
Add-FakeEvent -Log Security -Id 1102 -RecordId 1 -MinutesAgo 0.05 -UserData $true
Watch-Events $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^the Security log was CLEARED$') 1 'a cleared log (record numbers start at 1 again) is still reported: the time test catches it'
Watch-Events $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' 'CLEARED') 1 'the cleared log is reported once'
Add-FakeEvent -Log System -Id 7045 -RecordId 300 -MinutesAgo 0.04 -Data @{ ServiceName = 'evilsvc'; ImagePath = 'C:\x\e.exe' }
Add-FakeEvent -Log System -Id 104 -RecordId 301 -MinutesAgo 0.03 -UserData $true
Watch-Events $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^service INSTALLED: evilsvc -> C:\\x\\e.exe$') 1 'System log: a new service'
Assert-Equal (Get-AlertCount 'ALERT' '^the System log was CLEARED$') 1 'System log: cleared'
Add-FakeEvent -Log Security -Id 4624 -RecordId 400 -MinutesAgo 0.02 -Data @{ TargetUserName = 'jmoney' }
Watch-Events $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' 'jmoney') 3 'an event that is not on the watch list (4624, a logon) is ignored (the three jmoney alerts above are all there is)'
$fakeEvent = [pscustomobject]@{ Id = 9999; Message = "first line`nsecond line" }
Assert-Equal (Format-EventText $fakeEvent @{}) 'event 9999: first line' 'an unknown event id falls back to the first line of its message'

Write-Host "`n== failed logon bursts =="
Reset-Watchdog
for ($i = 1; $i -le 19; $i++) { Add-FakeEvent -Log Security -Id 4625 -RecordId (1000 + $i) -MinutesAgo 1 -Data @{ TargetUserName = 'jmoney'; IpAddress = '203.0.113.9' } }
$st = @{}
Watch-FailedLogons $st 6>$null
Assert-Equal ([int]$st['failed5']) 19 '19 failed logons are counted'
Assert-Equal (Get-AlertsOf 'ALERT').Count 0 '19 failed logons (below 20) raise no alert'
for ($i = 20; $i -le 25; $i++) { Add-FakeEvent -Log Security -Id 4625 -RecordId (1000 + $i) -MinutesAgo 1 -Data @{ TargetUserName = 'administrator'; IpAddress = '-'; WorkstationName = 'KALI' } }
Watch-FailedLogons $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^25 failed logons in the last 5 minutes \(most: 203.0.113.9 as jmoney x19; KALI as administrator x6\)$') 1 '25 failed logons: one alert naming the sources (an address, or the workstation name when the address is "-")'
Watch-FailedLogons $st 6>$null
Assert-Equal (Get-AlertsOf 'ALERT').Count 1 'the same burst is not reported again at once'
Step-Clock 500
Watch-FailedLogons $st 6>$null
Assert-Equal (Get-AlertsOf 'ALERT').Count 1 '500 seconds later: still quiet (10 minute quiet time)'
Step-Clock 101
Watch-FailedLogons $st 6>$null
Assert-Equal (Get-AlertsOf 'ALERT').Count 2 'after the quiet time a continuing burst is reported again'
Reset-Watchdog
for ($i = 1; $i -le 30; $i++) { Add-FakeEvent -Log Security -Id 4625 -RecordId (2000 + $i) -MinutesAgo 10 -Data @{ TargetUserName = 'jmoney'; IpAddress = '203.0.113.9' } }
$st = @{}
Watch-FailedLogons $st 6>$null
Assert-Equal ([int]$st['failed5']) 0 'failed logons older than 5 minutes are not counted'

# ------------------------------------------------------------------ the baseline
Write-Host "`n== baseline =="
Reset-Watchdog
[System.IO.File]::WriteAllText((Join-Path $dataRoot 'settings.json'), '{"BlackboxIp":"172.16.5.5"}')
$st = @{}
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'INFO' '^baseline taken \(12 parts\)') 1 'the first time the baseline is taken (12 parts)'
Assert-Equal @(Get-ChildItem -Path $BaseDir -File | Where-Object { $_.Name -like '*.txt' }).Count 12 'twelve baseline files'
Assert-True ($st['baseline.taken'] -gt 0) 'state: the baseline time is remembered'
$baseText = @{}
foreach ($n in $BaselineNames) { $baseText[$n] = [System.IO.File]::ReadAllText((Join-Path $BaseDir "$n.txt")) }
Assert-True ($baseText['users'] -match 'jmoney enabled=True') 'baseline users: jmoney and whether it is enabled'
Assert-True ($baseText['admins'] -match 'plinktern') 'baseline admins'
Assert-True ($baseText['rdpusers'] -match 'jmoney') 'baseline Remote Desktop users'
Assert-True ($baseText['ports'] -match 'tcp 3389 svchost' -and $baseText['ports'] -match 'tcp 8080 java') 'baseline ports: port and process'
Assert-True ($baseText['tasks'] -match '\\NightlyCopy \| C:\\Tools\\copy.bat') 'baseline tasks: name and what they run'
Assert-True ($baseText['tasks'] -match '\\Microsoft\\Windows\\Defrag\\Defrag(\r?\n|$)' -and $baseText['tasks'] -notmatch 'Defrag \|') 'baseline tasks: tasks under \Microsoft\ by name only'
Assert-True ($baseText['services'] -match 'Jenkins \| Auto \| "C:\\Program Files\\Jenkins\\jenkins.exe"') 'baseline services: name, start mode, program'
Assert-True ($baseText['runkeys'] -match 'CurrentVersion\\Run \| SecurityHealth') 'baseline run keys'
Assert-True ($baseText['hosts'] -match '127.0.0.1 localhost') 'baseline hosts file (comments are dropped)'
Assert-True ($baseText['shares'] -match 'ADMIN\$ \| C:\\Windows') 'baseline shares'
Assert-True ($baseText['routes'] -match '0.0.0.0/0 via 172.16.5.1 on interface 6') 'baseline routes'
Assert-True ($baseText['firewall'] -match 'Inbound Allow HP-Allow-TCP-3389 \| HP Allow TCP 3389') 'baseline firewall rules'
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertsOf 'ALERT').Count 0 'an unchanged box: no differences'
foreach ($n in $BaselineNames) { if ([int]$st["diffn.$n"] -ne 0) { Assert-True $false "no difference counted for $n" } }

New-LocalUser -Name evil -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -Description 'x'
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^\[users\] NEW: evil enabled=True$') 1 'a new account is a NEW difference'
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '\[users\] NEW: evil') 1 'the same difference is reported once'
Assert-Equal ([int]$st['diffn.users']) 1 'state: one difference in users'
Add-LocalGroupMember -Group Administrators -Member evil
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^\[admins\] NEW: evil$') 1 'a new administrator is a NEW difference'
$global:FW.Users.Remove('evil')
Compare-AllBaselines $st 6>$null
Assert-Equal ([int]$st['diffn.users']) 0 'when the new account is gone the difference is gone'
New-LocalUser -Name evil -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -Description 'x'
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '\[users\] NEW: evil') 2 'an item that comes back after it went away is reported again'
$global:FW.Users.Remove('testuser')
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^\[users\] GONE: testuser enabled=True$') 1 'an account that was there at the baseline and is gone is a GONE difference'
$global:FW.Tasks = @($global:FW.Tasks) + @(@{ TaskName = 'Updater'; TaskPath = '\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'cmd.exe'; Arguments = '/c scp x u@172.16.5.5:/t' })
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^\[tasks\] NEW: \\Updater \| cmd.exe /c scp x u@172.16.5.5:/t \(touches blackbox!\)$') 1 'a new task that mentions the blackbox address is tagged'
$global:FW.Tasks2['NetCacheWatch'] = @{ Action = @{ Execute = 'powershell.exe'; Argument = '-File x' }; Principal = @{ UserId = 'SYSTEM' } }
$global:FW.Tasks2['NetCacheRestore'] = @{ Action = @{ Execute = 'powershell.exe'; Argument = '-File y' }; Principal = @{ UserId = 'SYSTEM' } }
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' 'NetCache') 0 'the watchdog''s own tasks are never reported as new'
$global:FW.Listen += @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 50000; Pid = 1200 }
$global:FW.Listen += @{ Proto = 'TCP'; Addr = '0.0.0.0'; Port = 50001; Pid = 3100 }
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '\[ports\] NEW: tcp 50000') 0 'a high port opened by svchost (Windows does this after every reboot) is not a difference'
Assert-Equal (Get-AlertCount 'ALERT' '^\[ports\] NEW: tcp 50001 ftpd$') 1 'a high port opened by anything else is'
Reset-Watchdog
$st = @{}
Compare-AllBaselines $st 6>$null
for ($i = 1; $i -le 10; $i++) { New-LocalUser -Name "bad$i" -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -Description 'x' }
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^\[users\] NEW: bad') 8 'ten new accounts: eight single alerts'
Assert-Equal (Get-AlertCount 'ALERT' '^\[users\] and 2 more differences \(all of them are in baseline\\users.seen\)$') 1 'ten new accounts: and one line for the rest'
Assert-Equal @([System.IO.File]::ReadAllLines((Join-Path $BaseDir 'users.seen'))).Count 10 'the .seen file lists all ten'
Assert-Equal ([int]$st['diffn.users']) 10 'state: ten differences'
$n = Save-Baselines $st
Assert-Equal $n 12 'Save-Baselines reports 12 parts'
Assert-Equal ([int]$st['diffn.users']) 0 'a new baseline: no differences'
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '^\[users\] NEW: bad') 8 'a new baseline: nothing more is reported'
$global:FW.BreakShares = $true
$sharesBefore = [System.IO.File]::ReadAllText((Join-Path $BaseDir 'shares.txt'))
Compare-AllBaselines $st 6>$null
Assert-Equal (Get-AlertCount 'ALERT' '\[shares\]') 0 'a part that cannot be read is skipped (an error never looks like "everything is gone")'
Assert-Equal ([System.IO.File]::ReadAllText((Join-Path $BaseDir 'shares.txt'))) $sharesBefore 'a part that cannot be read leaves its baseline untouched'
Reset-Watchdog
$global:FW.BreakShares = $true
$st = @{}
Compare-AllBaselines $st 6>$null
Assert-Equal @(Get-ChildItem -Path $BaseDir -File | Where-Object { $_.Name -like '*.txt' }).Count 11 'a part that cannot be read at the start is left out of the baseline'
$global:FW.BreakShares = $false
Compare-AllBaselines $st 6>$null
Assert-True (Test-Path (Join-Path $BaseDir 'shares.txt')) 'it is added to the baseline as soon as it can be read'
Assert-Equal (Get-AlertCount 'ALERT' '\[shares\]') 0 'and that is not reported as a difference'

# ------------------------------------------------------------------ Jenkins job files and builds
Write-Host "`n== Jenkins job files and builds =="
Reset-Watchdog
$jh = Join-Path $tmp 'jenkins_home'
foreach ($j in 'build-app', 'deploy', 'empty-folder') { New-Item -ItemType Directory -Path (Join-Path (Join-Path $jh 'jobs') $j) -Force | Out-Null }
foreach ($j in 'build-app', 'deploy') {
    [System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path $jh 'jobs') $j) 'config.xml'), "<project>$j v1</project>")
    New-Item -ItemType Directory -Path (Join-Path (Join-Path (Join-Path $jh 'jobs') $j) 'builds') -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path (Join-Path $jh 'jobs') $j) 'builds') 'permalinks'), "lastCompletedBuild 5`r`nlastFailedBuild -1`r`nlastSuccessfulBuild 5`r`n")
}
$cfg = @{ JenkinsHome = '' }
$st = @{}
$r = Test-JobFiles $cfg $st $false
Assert-True ($r.Ok -and $r.Detail -match 'not known') 'jobs: Jenkins home unknown: nothing to watch, no complaint'
$r = Test-LastBuilds $cfg
Assert-True ($r.Ok) 'builds: Jenkins home unknown: nothing to watch, no complaint'
$cfg = @{ JenkinsHome = $jh }
$r = Test-JobFiles $cfg $st $false
Assert-True ($r.Ok -and $r.Detail -match '^2 job file\(s\) unchanged$') 'jobs: first look records the two job files (the folder without config.xml is skipped)'
Assert-Equal ([System.IO.File]::ReadAllText((Join-Path (Join-Path $GoodDir 'build-app') 'config.xml'))) '<project>build-app v1</project>' 'jobs: a good copy is kept'
Assert-True ($st['jobhash.build-app'] -match '^[0-9A-F]{64}$') 'jobs: the fingerprint is a SHA-256'
Assert-True ((Test-JobFiles $cfg $st $false).Ok) 'jobs: a second look: unchanged'
[System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path $jh 'jobs') 'build-app') 'config.xml'), '<project>build-app EVIL</project>')
$r = Test-JobFiles $cfg $st $false
Assert-True ((-not $r.Ok) -and $r.Detail -match 'build-app \(config.xml changed\)' -and $r.Detail -notmatch 'deploy') 'jobs: a changed job file is named, the other one is not'
Assert-Equal ([System.IO.File]::ReadAllText((Join-Path (Join-Path $GoodDir 'build-app') 'config.xml'))) '<project>build-app v1</project>' 'jobs: the good copy is NOT overwritten by a changed file'
New-Item -ItemType Directory -Path (Join-Path (Join-Path $jh 'jobs') 'backdoor') -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path $jh 'jobs') 'backdoor') 'config.xml'), '<project>x</project>')
Remove-Item -Path (Join-Path (Join-Path $jh 'jobs') 'deploy') -Recurse -Force
$r = Test-JobFiles $cfg $st $false
Assert-True ($r.Detail -match 'backdoor \(new job\)' -and $r.Detail -match 'deploy \(job gone\)' -and $r.Detail -match 'build-app \(config.xml changed\)') 'jobs: a new job, a gone job and a changed job are all named'
$r = Test-JobFiles $cfg $st $true
Assert-True ($r.Ok -and $r.Detail -match '^2 job file\(s\) unchanged$') 'jobs: accepting makes the present files the good ones'
Assert-True ($null -eq $st['jobhash.deploy']) 'jobs: accepting forgets a job that is gone'
Assert-Equal ([System.IO.File]::ReadAllText((Join-Path (Join-Path $GoodDir 'build-app') 'config.xml'))) '<project>build-app EVIL</project>' 'jobs: accepting stores the new content as the good copy'
[System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path $jh 'jobs') 'build-app') 'config.xml'), '<project>build-app v3</project>')
Assert-True (-not (Test-JobFiles $cfg $st $false).Ok) 'jobs: changed again'
[System.IO.File]::WriteAllText($ConfigFile, (ConvertTo-Json -InputObject @{ JenkinsHome = $jh }))
$out = (Restore-JobConfig 'build-app' 6>&1 | Out-String)
Assert-Equal ([System.IO.File]::ReadAllText((Join-Path (Join-Path (Join-Path $jh 'jobs') 'build-app') 'config.xml'))) '<project>build-app EVIL</project>' 'restore: the last good config.xml is copied back'
Assert-Equal (Get-AlertCount 'HEAL' "job 'build-app': config.xml put back.*Reload Configuration from Disk") 1 'restore: written as HEAL, with the reload hint'
Assert-True ((Test-JobFiles $cfg $st $false).Ok) 'restore: afterwards the job file matches the good one again'
foreach ($bad in '..', '...', '..\evil', '../evil', 'a/b', 'a;b', 'x*') {
    $out = (Restore-JobConfig $bad 6>&1 | Out-String)
    Assert-True ($out -match 'Refused') "restore: the name '$bad' is refused"
}
$out = (Restore-JobConfig 'nosuchjob' 6>&1 | Out-String)
Assert-True ($out -match 'no saved good copy') 'restore: no saved copy for an unknown job'
New-Item -ItemType Directory -Path (Join-Path $GoodDir 'ghost') -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path (Join-Path $GoodDir 'ghost') 'config.xml'), 'x')
$out = (Restore-JobConfig 'ghost' 6>&1 | Out-String)
Assert-True ($out -match 'job folder for .ghost. does not exist') 'restore: the job folder is gone from Jenkins: nothing is created'
Assert-True (-not (Test-Path (Join-Path (Join-Path $jh 'jobs') 'ghost'))) 'restore: no job folder was made'
Remove-Item -Path $ConfigFile
$out = (Restore-JobConfig 'build-app' 6>&1 | Out-String)
Assert-True ($out -match 'Jenkins home folder is not known') 'restore: without config.json nothing is restored'

$r = Test-LastBuilds $cfg
Assert-True ($r.Ok -and $r.Detail -match 'succeeded') 'builds: last completed = last successful: fine (the file has Windows line ends)'
$permalinks = Join-Path (Join-Path (Join-Path (Join-Path $jh 'jobs') 'build-app') 'builds') 'permalinks'
[System.IO.File]::WriteAllText($permalinks, "lastCompletedBuild 6`nlastFailedBuild 6`nlastSuccessfulBuild 5`n")
$r = Test-LastBuilds $cfg
Assert-True ((-not $r.Ok) -and $r.Detail -match 'build-app: build #6 did not succeed \(last good: #5\)') 'builds: a failed newest build is named'
[System.IO.File]::WriteAllText($permalinks, "lastCompletedBuild 1`nlastFailedBuild 1`nlastSuccessfulBuild -1`n")
Assert-True ((Test-LastBuilds $cfg).Detail -match 'build #1 did not succeed \(last good: #-1\)') 'builds: a job that never succeeded'
[System.IO.File]::WriteAllText($permalinks, "lastCompletedBuild -1`nlastSuccessfulBuild -1`n")
Assert-True ((Test-LastBuilds $cfg).Ok) 'builds: a job that never ran is fine'
Remove-Item -Path $permalinks
Assert-True ((Test-LastBuilds $cfg).Ok) 'builds: a job without a permalinks file is skipped'

# ------------------------------------------------------------------ one pass at a time, end to end
Write-Host "`n== Invoke-Pass: the first pass on a healthy box =="
Reset-Watchdog
Assert-True (Invoke-TestPass) 'the first pass finishes'
Assert-Equal (Get-AlertCount 'INFO' '^watchdog started \(version 1\); slow checks every 5 passes$') 1 'the first pass says the watchdog started'
Assert-Equal (Get-AlertCount 'INFO' '^baseline taken \(12 parts\)') 1 'the first pass takes the baseline'
foreach ($lv in 'DOWN', 'HEAL', 'UP', 'ALERT') { Assert-Equal (Get-AlertsOf $lv).Count 0 "a healthy box: no $lv alert" }
$s = Read-StatusFile
Assert-Equal $s.Version 1 'status.json: version'
Assert-Equal $s.Pass 1 'status.json: pass 1'
Assert-Equal $s.Epoch $global:WdNow 'status.json: the time of the pass (seconds)'
Assert-True ($s.HealOn -eq $true) 'status.json: repairs are on'
Assert-Equal $s.Heals 0 'status.json: no repairs so far'
Assert-True ($s.BaselineTaken -gt 0) 'status.json: the baseline time'
Assert-Equal @($s.Checks).Count 8 'status.json: eight checks (the blackbox is left out until an address is entered)'
Assert-True (@($s.Checks | Where-Object { -not $_.Ok }).Count -eq 0) 'status.json: all checks are fine'
Assert-Equal @($s.Diffs).Count 0 'status.json: no differences from the baseline'
$text = Show-Status 6>&1 | Out-String
Assert-True ($text -match 'Last pass:.*pass 1.*Repairs are ON; 0 done so far' -and $text -match 'rdp\s+ok' -and $text -match 'Last alerts:') '-Status: prints the last pass, every check and the last alerts'

Write-Host "`n== Invoke-Pass: break, repair, recover =="
Reset-Watchdog
[void](Invoke-TestPass)
Set-FakeServiceState 'TermService' 'Stopped'
Set-FakeServiceState 'Jenkins' 'Stopped'
$global:FW.Users['jmoney'].Enabled = $false
Remove-NetFirewallRule -Name 'HP-Allow-TCP-8080'
[void](Invoke-TestPass)
Assert-Equal (Get-AlertsOf 'DOWN').Count 4 'four broken things: four DOWN alerts'
Assert-Equal (Get-AlertsOf 'HEAL').Count 4 'four broken things: four repairs'
Assert-Equal (Get-AlertsOf 'UP').Count 4 'four broken things: all four are fine again afterwards'
Assert-Equal @($global:FW.Services | Where-Object { $_.Name -eq 'TermService' })[0].State 'Running' 'TermService is running again'
Assert-Equal @($global:FW.Services | Where-Object { $_.Name -eq 'Jenkins' })[0].State 'Running' 'Jenkins is running again'
Assert-True $global:FW.Users['jmoney'].Enabled 'jmoney is enabled again'
Assert-True ($null -ne (Get-FwRow 'HP-Allow-TCP-8080')) 'the 8080 allow rule is back'
Assert-True (@($global:FW.Calls | Where-Object { $_ -match 'Set-LocalUser jmoney -Password' }).Count -eq 0) 'no password was set'
$s = Read-StatusFile
Assert-Equal $s.Heals 4 'status.json: four repairs counted'
Assert-True (@($s.Checks | Where-Object { -not $_.Ok }).Count -eq 0) 'status.json: all fine again'
$global:FW.Calls.Clear()
[void](Invoke-TestPass)
Assert-Equal (Get-AlertsOf 'DOWN').Count 4 'a quiet pass writes nothing new'
Assert-Equal $global:FW.Calls.Count 0 'a quiet pass changes nothing on the box'

Write-Host "`n== Invoke-Pass: a failure the repair cannot fix =="
Reset-Watchdog
[void](Invoke-TestPass)
$global:FW.Tcp['127.0.0.1:3389'] = $false
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'DOWN' '^rdp: nothing answers on port 3389$') 1 'rdp: DOWN'
Assert-Equal (Get-AlertCount 'HEAL' '^rdp: .* still failing: nothing answers') 1 'rdp: a repair was tried and did not help'
$global:FW.Calls.Clear()
[void](Invoke-TestPass)
Assert-Equal @($global:FW.Calls | Where-Object { $_ -match 'Set-ItemProperty' }).Count 0 'the next pass (60 s later) does not repair again'
[void](Invoke-TestPass)
Assert-True (@($global:FW.Calls | Where-Object { $_ -match 'Set-ItemProperty' }).Count -gt 0) 'the pass 120 s after the repair tries again'
Assert-Equal (Get-AlertsOf 'DOWN').Count 1 'still one DOWN alert only'
Assert-True ((Get-CheckOf (Read-StatusFile) 'rdp').Ok -eq $false) 'status.json: rdp is down'
Assert-True ((Get-CheckOf (Read-StatusFile) 'rdp').Since -gt 0) 'status.json: since when'
$global:FW.Tcp['127.0.0.1:3389'] = $true
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'UP' '^rdp: back to normal') 1 'when the port answers again the watchdog says so'

Write-Host "`n== Invoke-Pass: the slow checks run on every 5th pass =="
Reset-Watchdog
[void](Invoke-TestPass)
$global:FW.Defender.RealTime = $false
foreach ($i in 2..5) { [void](Invoke-TestPass) }
Assert-Equal (Get-AlertCount 'DOWN' '^defender:') 0 'passes 2 to 5 do not look at Defender'
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'DOWN' '^defender: real-time protection is off$') 1 'pass 6 does'
Assert-Equal (Get-AlertsOf 'HEAL').Count 0 'Defender is only reported, never repaired by the watchdog'

Write-Host "`n== Invoke-Pass: events and bursts inside a pass =="
Reset-Watchdog
Add-FakeEvent -Log Security -Id 4720 -RecordId 10 -MinutesAgo 5 -Data @{ TargetUserName = 'before'; SubjectUserName = 'x' }
[void](Invoke-TestPass)
Add-FakeEvent -Log Security -Id 4720 -RecordId 11 -MinutesAgo 0.1 -Data @{ TargetUserName = 'after'; SubjectUserName = 'plinktern' }
for ($i = 1; $i -le 21; $i++) { Add-FakeEvent -Log Security -Id 4625 -RecordId (100 + $i) -MinutesAgo 0.2 -Data @{ TargetUserName = 'jmoney'; IpAddress = '203.0.113.9' } }
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'ALERT' 'account CREATED: before') 0 'an account created before the watchdog started is not reported'
Assert-Equal (Get-AlertCount 'ALERT' 'account CREATED: after \(by plinktern\)') 1 'an account created after it is'
Assert-Equal (Get-AlertCount 'ALERT' '^21 failed logons') 1 'the burst is reported in the same pass'
$global:FW.BreakEvents = $true
[void](Invoke-TestPass)
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'INFO' '^events: could not run') 1 'an unreadable event log is mentioned once, and the pass still finishes'
$global:FW.BreakEvents = $false

Write-Host "`n== Invoke-Pass: a check that crashes =="
Reset-Watchdog
$saved = ${function:Get-GroupMembers}
function Get-GroupMembers { throw 'net localgroup failed' }
Set-FakeServiceState 'TermService' 'Stopped'
Assert-True (Invoke-TestPass) 'a pass with a broken helper still finishes'
Assert-Equal (Get-AlertCount 'DOWN' '^jmoney: the check itself failed: net localgroup failed$') 1 'the crashed check is reported'
Assert-Equal (Get-AlertCount 'HEAL' '^jmoney') 0 'a crashed check is not "repaired"'
Assert-Equal (Get-AlertCount 'HEAL' '^rdp') 1 'the other checks of the same pass run and repair normally'
$s = Read-StatusFile
Assert-True ((Get-CheckOf $s 'jmoney').Ok -eq $false -and (Get-CheckOf $s 'rdp').Ok -eq $true) 'status.json: jmoney down (crashed), rdp fine again'
Assert-True (@($s.Diffs).Count -eq 0) 'the baseline parts that use the broken helper are skipped, not reported as everything gone'
Set-Item -Path function:Get-GroupMembers -Value $saved

Write-Host "`n== Invoke-Pass: pausing the repairs and the notes =="
Reset-Watchdog
[void](Invoke-TestPass)
[System.IO.File]::WriteAllText($PauseFile, [string]($global:WdNow + 300))
Set-FakeServiceState 'TermService' 'Stopped'
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'INFO' '^repairs are PAUSED until') 1 'pause: written once'
Assert-Equal (Get-AlertCount 'DOWN' '^rdp:') 1 'pause: the failure is still reported'
Assert-Equal (Get-AlertsOf 'HEAL').Count 0 'pause: nothing is repaired'
Assert-Equal @($global:FW.Services | Where-Object { $_.Name -eq 'TermService' })[0].State 'Stopped' 'pause: TermService stays stopped'
$s = Read-StatusFile
Assert-True ($s.HealOn -eq $false -and $s.PausedUntil -eq ($global:WdNow + 240)) 'pause: status.json says repairs are off, until when'
[void](Invoke-TestPass 400)
Assert-Equal (Get-AlertCount 'INFO' '^repairs are on again$') 1 'pause over: written once'
Assert-Equal (Get-AlertsOf 'HEAL').Count 1 'pause over: the repair happens in that very pass'
Assert-Equal @($global:FW.Services | Where-Object { $_.Name -eq 'TermService' })[0].State 'Running' 'pause over: TermService is running again'
$NoHeal = $true
Set-FakeServiceState 'TermService' 'Stopped'
[void](Invoke-TestPass 400)
Assert-Equal @($global:FW.Services | Where-Object { $_.Name -eq 'TermService' })[0].State 'Stopped' '-NoHeal: nothing is repaired'
Assert-True ((Read-StatusFile).HealOn -eq $false) '-NoHeal: status.json says repairs are off'
$NoHeal = $false
[void](Invoke-TestPass 400)
Assert-Equal @($global:FW.Services | Where-Object { $_.Name -eq 'TermService' })[0].State 'Running' 'without -NoHeal the repair happens'

Reset-Watchdog
[void](Invoke-TestPass)
New-LocalUser -Name drift -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -Description 'x'
foreach ($i in 2..6) { [void](Invoke-TestPass) }
Assert-Equal (Get-AlertCount 'ALERT' '^\[users\] NEW: drift') 1 'baseline differences are looked for on the slow pass'
Write-FlagFile $RebaseFlag
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'INFO' '^baseline taken again \(12 parts\)') 1 'the rebaseline note is acted on at the next pass'
Assert-True (-not (Test-Path $RebaseFlag)) 'the rebaseline note is used up'
Assert-Equal @((Read-StatusFile).Diffs).Count 0 'status.json: no differences after the new baseline'

Write-Host "`n== Invoke-Pass: Jenkins job files =="
Reset-Watchdog
$jh2 = Join-Path $tmp 'jenkins_home2'
New-Item -ItemType Directory -Path (Join-Path (Join-Path $jh2 'jobs') 'app') -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path $jh2 'jobs') 'app') 'config.xml'), '<project>v1</project>')
[System.IO.File]::WriteAllText($ConfigFile, (ConvertTo-Json -InputObject @{ JenkinsHome = $jh2 }))
[void](Invoke-TestPass)
Assert-True ((Get-CheckOf (Read-StatusFile) 'jobs').Ok) 'pass 1: job files recorded'
[System.IO.File]::WriteAllText((Join-Path (Join-Path (Join-Path $jh2 'jobs') 'app') 'config.xml'), '<project>CHANGED</project>')
foreach ($i in 2..5) { [void](Invoke-TestPass) }
Assert-Equal (Get-AlertCount 'DOWN' '^jobs:') 0 'passes 2 to 5 do not look at job files'
[void](Invoke-TestPass)
Assert-Equal (Get-AlertCount 'DOWN' '^jobs: since the job files were last accepted: app \(config.xml changed\)$') 1 'pass 6 reports the changed job file'
Assert-Equal (Get-AlertsOf 'HEAL').Count 0 'a changed job file is reported, not repaired'
Write-FlagFile $AcceptFlag
[void](Invoke-TestPass)
Assert-True (-not (Test-Path $AcceptFlag)) 'the accept note is used up'
Assert-Equal (Get-AlertCount 'UP' '^jobs: back to normal') 1 'the accept note is acted on at once, even on a pass that is not a slow one'

Write-Host "`n== Start-Watchdog: the command line switches =="
Reset-Watchdog
$Status = $true
$text = Start-Watchdog 6>&1 | Out-String
$Status = $false
Assert-True ($text -match 'No status yet') '-Status before any pass'
$Pause = 10
$text = Start-Watchdog 6>&1 | Out-String
$Pause = 0
Assert-True ($text -match 'paused for 10 minutes') '-Pause prints what it did'
Assert-Equal ([System.IO.File]::ReadAllText($PauseFile)) ($global:WdNow + 600) '-Pause 10: pause.txt holds now + 600 seconds'
$Resume = $true
$text = Start-Watchdog 6>&1 | Out-String
$Resume = $false
Assert-True (($text -match 'on again') -and -not (Test-Path $PauseFile)) '-Resume removes pause.txt'
$Rebaseline = $true; $AcceptJobs = $true
$text = Start-Watchdog 6>&1 | Out-String
$Rebaseline = $false; $AcceptJobs = $false
Assert-True ((Test-Path $RebaseFlag) -and (Test-Path $AcceptFlag) -and $text -match 'Noted') '-Rebaseline and -AcceptJobs leave their notes'
Remove-Item -Path $RebaseFlag, $AcceptFlag
$lock = [System.IO.File]::Open($LockFile, 'OpenOrCreate', 'ReadWrite', 'None')
$text = Start-Watchdog 6>&1 | Out-String
$lock.Close()
Assert-True (($text -match 'Another pass is running right now') -and -not (Test-Path $StatusFile)) 'while a pass is running a second one stops at once'
$text = Start-Watchdog 6>&1 | Out-String
Assert-True ((Test-Path $StatusFile) -and (Read-StatusFile).Pass -eq 1) 'with no pass running, Start-Watchdog does one pass'

Write-Host "`n== the real script on the command line (only the switches that touch no Windows setting) =="
$cliRoot = Join-Path $tmp 'cli'
$cliDir = Join-Path $cliRoot 'watchdog'
$script = (Resolve-Path (Join-Path $PSScriptRoot '..\Watchdog.ps1')).Path
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot -Dir $cliDir -Status 2>&1) -join "`n"
Assert-True ($text -match 'No status yet') 'cli -Status: runs and says there is no status yet'
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot -Dir $cliDir -Pause 10 2>&1) -join "`n"
$until = [long]([System.IO.File]::ReadAllText((Join-Path $cliDir 'pause.txt')))
$nowReal = [DateTimeOffset]::Now.ToUnixTimeSeconds()
Assert-True (($text -match 'paused for 10 minutes') -and $until -ge ($nowReal + 590) -and $until -le ($nowReal + 610)) 'cli -Pause 10: pause.txt holds the time 10 minutes from now'
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot -Dir $cliDir -Resume 2>&1) -join "`n"
Assert-True (($text -match 'on again') -and -not (Test-Path (Join-Path $cliDir 'pause.txt'))) 'cli -Resume: pause.txt is removed'
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot -Dir $cliDir -Rebaseline -AcceptJobs 2>&1) -join "`n"
Assert-True ((Test-Path (Join-Path $cliDir 'rebaseline.flag')) -and (Test-Path (Join-Path $cliDir 'acceptjobs.flag'))) 'cli -Rebaseline -AcceptJobs: both notes are left'
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot -Dir $cliDir -RestoreJob '..' 2>&1) -join "`n"
Assert-True ($text -match 'Refused') 'cli -RestoreJob ..: refused'
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot -Dir $cliDir -RestoreJob 'app' 2>&1) -join "`n"
Assert-True ($text -match 'Jenkins home folder is not known') 'cli -RestoreJob app without config.json: nothing is done'
$made = @(Get-ChildItem -Path $cliRoot -Force | ForEach-Object { $_.Name })
Assert-True (($made.Count -eq 1) -and $made[0] -eq 'watchdog') 'the command line switches wrote nothing outside the watchdog folder'

Write-Host "`n== the tool's side agrees with this script: names, and what it reads back from a real pass =="
# The tool (lib\Core.ps1, lib\Collect.ps1) and this script never load each other. They meet only in file names and in the task name,
# so this part runs the tool's own reader, in a separate PowerShell, on the files that passes of THIS script wrote.
Reset-Watchdog
$global:WdNow = [DateTimeOffset]::Now.ToUnixTimeSeconds() - 600        # so the "age" of status.json is small in the tool's eyes
[void](Invoke-TestPass)                                                 # pass 1: healthy; the baseline is taken
New-LocalUser -Name drift -Password (ConvertTo-SecureString 'x' -AsPlainText -Force) -Description 'x'
Set-FakeServiceState 'TermService' 'Stopped'
foreach ($i in 2..6) { [void](Invoke-TestPass) }                        # pass 2 repairs Remote Desktop (DOWN, HEAL, UP); pass 6 sees the new user (ALERT)
$NoHeal = $true
Set-FakeServiceState 'TermService' 'Stopped'
[void](Invoke-TestPass)                                                 # pass 7: Remote Desktop is down and nobody repairs it (-NoHeal)
$NoHeal = $false
$st = Read-StatusFile

$toolProbe = Join-Path $tmp 'tool-side.ps1'
$toolRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolLines = @(
    ". '$toolRoot\lib\Core.ps1'",
    ". '$toolRoot\lib\Collect.ps1'",
    "`$script:Hp = @{ DataDir = '$dataRoot'; Settings = @{ } }",
    "`$script:HpRoot = '$toolRoot'",
    'function Get-ScheduledTask { }',          # stand-in: only the files are of interest here, there is no task on this machine
    '$out = @{ TaskName = $script:WatchdogTaskName; Paths = (Get-WatchdogPaths); Facts = (Get-WatchdogFacts) }',
    'ConvertTo-Json -InputObject $out -Depth 6')
[System.IO.File]::WriteAllLines($toolProbe, [string[]]$toolLines)
$tool = ((& $pwshPath -NoProfile -File $toolProbe 2>&1) -join "`n") | ConvertFrom-Json

Assert-True ($OwnTasks -contains $tool.TaskName) "the tool's task name ($($tool.TaskName)) is one of this script's own tasks"
Assert-Equal (Split-Path -Leaf $tool.Paths.Dir) (Split-Path -Leaf $wdDir) 'the tool looks in the folder this script uses (watchdog)'
Assert-Equal (Split-Path -Leaf $tool.Paths.Alerts) (Split-Path -Leaf $AlertFile) 'alerts.log has the same name on both sides'
Assert-Equal (Split-Path -Leaf $tool.Paths.Status) (Split-Path -Leaf $StatusFile) 'status.json has the same name on both sides'
Assert-Equal (Split-Path -Leaf $tool.Paths.Config) (Split-Path -Leaf $ConfigFile) 'config.json has the same name on both sides'
Assert-Equal (Split-Path -Leaf $tool.Paths.PauseFile) (Split-Path -Leaf $PauseFile) 'pause.txt has the same name on both sides'
Assert-Equal (Split-Path -Leaf $tool.Paths.RebaseFlag) (Split-Path -Leaf $RebaseFlag) 'rebaseline.flag has the same name on both sides'
Assert-Equal (Split-Path -Leaf $tool.Paths.AcceptFlag) (Split-Path -Leaf $AcceptFlag) 'acceptjobs.flag has the same name on both sides'
Assert-Equal (Split-Path -Leaf $tool.Paths.Script) 'Watchdog.ps1' 'the copy the task runs is called Watchdog.ps1'
Assert-Equal (Split-Path -Leaf $tool.Paths.Panic) 'Panic.ps1' 'and it finds Panic.ps1 next to itself under that name'

$cliRoot2 = Join-Path $tmp 'cli2'
$text = (& $pwshPath -NoProfile -File $script -DataDir $cliRoot2 -Status 2>&1) -join "`n"
Assert-True (($text -match 'No status yet') -and (Test-Path (Join-Path $cliRoot2 'watchdog'))) 'without -Dir the script works in <data folder>\watchdog (where the tool looks)'

$f = $tool.Facts
Assert-True ($f.StatusFound -and $f.Pass -eq 7 -and $f.Pass -eq $st.Pass) 'the tool reads the pass number the script wrote (7)'
Assert-True ($f.StatusAge -ge 0 -and $f.StatusAge -le 1000) "and a sensible age for status.json ($($f.StatusAge) seconds)"
Assert-Equal (@($f.Checks | ForEach-Object { $_.Name }) -join ',') (@($st.Checks | ForEach-Object { $_.Name }) -join ',') 'the tool sees the same checks, in the same order'
$rdp = @($f.Checks | Where-Object { $_.Name -eq 'rdp' })[0]
Assert-True ($rdp -and -not $rdp.Ok -and $rdp.Detail -match 'TermService is Stopped' -and $rdp.SinceText -match '^\d\d:\d\d:\d\d$') 'the failing rdp check comes through with its reason and a time of day'
Assert-True (@($f.Checks | Where-Object { $_.Name -ne 'rdp' -and -not $_.Ok }).Count -eq 0) 'and every other check is fine'
Assert-True ($f.HealOn -eq $false -and $f.Heals -eq 1) 'repairs are off (-NoHeal) and one repair was done so far'
Assert-True ($f.BaselineText -match '^\d\d:\d\d:\d\d$') 'the baseline time comes through as a time of day'
Assert-True (@($f.Diffs | Where-Object { $_.Name -eq 'users' -and $_.Count -eq 1 -and $_.Lines -match 'drift' }).Count -eq 1) 'the baseline difference (the new user) comes through'
$levels = @($f.Alerts | ForEach-Object { $_.Level } | Select-Object -Unique)
Assert-True (($levels -contains 'DOWN') -and ($levels -contains 'HEAL') -and ($levels -contains 'UP') -and ($levels -contains 'ALERT') -and ($levels -contains 'INFO')) "the tool parses every level the script writes ($($levels -join ', '))"
$fileLines = @((Get-AlertText) -split "`r?`n" | Where-Object { $_ })
Assert-Equal @($f.Alerts).Count $fileLines.Count 'and every line of alerts.log, none dropped'
Assert-Equal @($f.Alerts)[-1].Text ($fileLines[-1] -replace '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+\s+', '') 'the newest alert text is the last line of the file'
Assert-True (@($f.Alerts | Where-Object { $_.AgeMinutes -gt 5 }).Count -eq 0) 'the age of a fresh alert is a few minutes at most'
Assert-True ($f.Alerts[0].Time -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$') 'the time of an alert is kept as written'

Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-TestSummary
