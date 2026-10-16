# Test-DeadManPanic.ps1 - tests lib\DeadMan.ps1 and Panic.ps1 with made-up Windows commands
# (the scheduled-task cmdlets, netsh, adapters, services, accounts). Nothing here touches a real box.
# What it proves: the arm / extend / disarm logic, the 60-second rule, what Panic does step by step and that a failing
# step never stops the next one. What it cannot prove: that Windows really accepts these cmdlet calls (lab test).
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"
. "$PSScriptRoot\..\lib\DeadMan.ps1"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-dm-' + [guid]::NewGuid().ToString('N'))
Initialize-Hp -DataDir $tmp -NoAcl
$script:HpRoot = Join-Path $tmp 'tool'
New-Item -ItemType Directory -Path $script:HpRoot -Force | Out-Null
Copy-Item "$PSScriptRoot\..\Panic.ps1" (Join-Path $script:HpRoot 'Panic.ps1')
$script:Hp.Ask = { $true }
$script:Hp.AllowChanges = $true

# ------------------------------------------------------------------ fake Windows commands
$global:Calls = New-Object System.Collections.ArrayList
$global:Tasks = @{}
$global:NetshMakesFile = $true
$global:NetshExit = 0
$global:Adapters = @()
$global:Users = @{}
$global:Svc = @{}
$global:FwRules = @{}

function netsh.exe {
    [void]$global:Calls.Add('netsh ' + ($args -join ' '))
    if ($args[1] -eq 'export' -and $global:NetshMakesFile) { Set-Content -Path $args[2] -Value 'FAKE-FIREWALL-EXPORT' }
    $global:LASTEXITCODE = $global:NetshExit
}
function net.exe { [void]$global:Calls.Add('net ' + ($args -join ' ')) }
function secedit.exe { [void]$global:Calls.Add('secedit ' + ($args -join ' ')); $global:LASTEXITCODE = 0 }
function Get-ScheduledTask { param($TaskName) if ($global:Tasks.ContainsKey($TaskName)) { [pscustomobject]$global:Tasks[$TaskName] } }
function New-ScheduledTaskAction { param($Execute, $Argument) @{ Execute = $Execute; Argument = $Argument } }
function New-ScheduledTaskTrigger { param([switch]$Once, $At) $null = $Once; @{ At = $At } }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) @{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel } }
function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable, [switch]$AllowStartIfOnBatteries, $ExecutionTimeLimit) $null = $StartWhenAvailable, $AllowStartIfOnBatteries, $ExecutionTimeLimit; @{} }
function New-TimeSpan { param($Minutes) [timespan]::FromMinutes($Minutes) }
function Register-ScheduledTask {
    param($TaskName, $Action, $Trigger, $Principal, $Settings, [switch]$Force)
    $null = $Settings, $Force
    $global:Tasks[$TaskName] = @{ TaskName = $TaskName; Action = $Action; Trigger = $Trigger; Principal = $Principal }
}
function Set-ScheduledTask { param($TaskName, $Trigger) $global:Tasks[$TaskName].Trigger = $Trigger }
function Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction) $null = $Confirm, $ErrorAction; $global:Tasks.Remove($TaskName) }
function Get-NetAdapter { param($ErrorAction) $null = $ErrorAction; $global:Adapters | ForEach-Object { [pscustomobject]$_ } }
function Enable-NetAdapter { param($Name, $Confirm) $null = $Confirm; [void]$global:Calls.Add("Enable-NetAdapter $Name"); foreach ($a in $global:Adapters) { if ($a.Name -eq $Name) { $a.Status = 'Up' } } }
function Get-NetFirewallRule { param($DisplayName, $ErrorAction) $null = $ErrorAction; if ($global:FwRules.ContainsKey($DisplayName)) { [pscustomobject]@{ DisplayName = $DisplayName } } }
function New-NetFirewallRule { param($DisplayName, $Direction, $Protocol, $LocalPort, $Action, $Profile) $global:FwRules[$DisplayName] = "$Direction $Protocol $LocalPort $Action $Profile" }
function Get-ItemProperty {
    param($Path, $Name, $ErrorAction)
    $null = $ErrorAction, $Name
    if ($global:RegPolicy -and $Path -like '*Policies*') { [pscustomobject]@{ fDenyTSConnections = 1 } }
    elseif ($global:RdpPort -and $Path -like '*RDP-Tcp') { [pscustomobject]@{ PortNumber = $global:RdpPort } }
}
function Set-ItemProperty { param($Path, $Name, $Value) [void]$global:Calls.Add("Set-ItemProperty $Path $Name=$Value") }
function Get-Service { param($Name) $global:Svc[$Name] }
function Set-Service { param($Name, $StartupType) [void]$global:Calls.Add("Set-Service $Name $StartupType") }
function Start-Service { param($Name) [void]$global:Calls.Add("Start-Service $Name") }
function Restart-Service { param($Name, [switch]$Force) $null = $Force; [void]$global:Calls.Add("Restart-Service $Name") }
function Get-CimInstance { param($ClassName) $null = $ClassName; $global:CimServices | ForEach-Object { [pscustomobject]$_ } }
function Get-LocalUser { param($Name, $ErrorAction) $null = $ErrorAction; if ($global:Users.ContainsKey($Name)) { [pscustomobject]$global:Users[$Name] } }
function Enable-LocalUser { param($Name) [void]$global:Calls.Add("Enable-LocalUser $Name") }
function Set-LocalUser { param($Name, $PasswordNeverExpires) [void]$global:Calls.Add("Set-LocalUser $Name PasswordNeverExpires=$PasswordNeverExpires") }
function Get-LocalGroup { param($SID) [pscustomobject]@{ Name = "group-$SID" } }
function Add-LocalGroupMember { param($Group, $Member, $ErrorAction) $null = $ErrorAction; [void]$global:Calls.Add("Add-LocalGroupMember $Group $Member") }
$global:RegPolicy = $false
$global:RdpPort = 0
$global:CimServices = @()

# ------------------------------------------------------------------ DeadMan: arm, extend, disarm
Write-Host 'Dead-man switch: before arming' -ForegroundColor Cyan
$st = Get-DeadManStatus
Assert-True (-not $st.Armed) 'not armed at the start'
Assert-True ((Get-DeadManBlocker) -match 'not armed') 'the blocker says it is not armed'

Write-Host 'Dead-man switch: arm' -ForegroundColor Cyan
$global:Adapters = @(@{ Name = 'Ethernet0'; Status = 'Up' }, @{ Name = 'Ethernet1'; Status = 'Disabled' })
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-Equal $r.Status 'Applied' 'the arm action applies'
$p = Get-DeadManPaths
Assert-True (Test-Path $p.Export) 'the firewall export exists'
Assert-True (Test-Path $p.Panic) 'a private copy of Panic.ps1 exists'
Assert-True (Test-Path $p.State) 'the state file exists'
Assert-Equal ((Get-Content $p.Adapters) -join ',') 'Ethernet0' 'only the adapters that were UP are noted'
Assert-True (@($global:Calls | Where-Object { $_ -eq "netsh advfirewall export $($p.Export)" }).Count -eq 1) 'netsh was asked to export the policy to that file'
$t = $global:Tasks['NetCacheRestore']
Assert-True ($null -ne $t) 'the scheduled task NetCacheRestore exists'
Assert-Equal $t.Principal.UserId 'NT AUTHORITY\SYSTEM' 'it runs as SYSTEM'
Assert-Equal $t.Principal.RunLevel 'Highest' 'with the highest run level'
Assert-Equal $t.Action.Execute 'powershell.exe' 'it starts powershell.exe'
Assert-True ($t.Action.Argument -match '-FromTask' -and $t.Action.Argument -match [regex]::Escape($p.Dir)) 'with -FromTask and the state folder'
Assert-True ($t.Action.Argument -match [regex]::Escape($p.Panic)) 'and runs the private copy'
$minsAway = ($t.Trigger.At - (Get-Date)).TotalMinutes
Assert-True ($minsAway -gt 4.5 -and $minsAway -le 5.01) 'the trigger is about 5 minutes from now'
$st = Get-DeadManStatus
Assert-True $st.Armed 'status says armed'
Assert-True ($st.SecondsLeft -gt 280 -and $st.SecondsLeft -le 300) 'about 300 seconds left'
Assert-Equal (Get-DeadManBlocker) '' 'no blocker while armed with time left'

Write-Host 'Dead-man switch: the 60-second rule and a deleted task' -ForegroundColor Cyan
$state = @{ FiresEpoch = ([DateTimeOffset](Get-Date).AddSeconds(30)).ToUnixTimeSeconds(); FiresAt = 'x'; Minutes = 5 }
[IO.File]::WriteAllText($p.State, (ConvertTo-Json -InputObject $state))
Assert-True ((Get-DeadManBlocker) -match 'fires in') 'under 60 seconds left: a firewall-type change is blocked'
$fw = New-Action -Id 'x' -Title 'firewall thing' -NeedsDeadMan -Apply { 1 }
Assert-Equal (Invoke-Change $fw -Confirmed).Status 'Blocked' 'and Invoke-Change really refuses it'
$saved = $global:Tasks['NetCacheRestore']; $global:Tasks.Remove('NetCacheRestore')
$st = Get-DeadManStatus
Assert-True (-not $st.Armed -and $st.Note -match 'MISSING') 'a deleted task is noticed (the Red Team could do that)'
$global:Tasks['NetCacheRestore'] = $saved

Write-Host 'Dead-man switch: arming again only extends' -ForegroundColor Cyan
$exportsBefore = @($global:Calls | Where-Object { $_ -like 'netsh advfirewall export*' }).Count
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-Equal $r.Status 'Applied' 'arming again works'
$exportsAfter = @($global:Calls | Where-Object { $_ -like 'netsh advfirewall export*' }).Count
Assert-Equal $exportsAfter $exportsBefore 'but did NOT export again (the known-good export is not overwritten)'
Assert-True ((Get-DeadManStatus).SecondsLeft -gt 280) 'and the time is back to about 5 minutes'
$r = Invoke-Change (New-ExtendDeadManAction -Minutes 8) -Confirmed
Assert-True ((Get-DeadManStatus).SecondsLeft -gt 470) 'extend moves the time to 8 minutes from now'

Write-Host 'Dead-man switch: Keep changes' -ForegroundColor Cyan
$r = Invoke-Change (New-DisarmDeadManAction) -Confirmed
Assert-Equal $r.Status 'Applied' 'disarm applies'
Assert-True (-not $global:Tasks.ContainsKey('NetCacheRestore')) 'the task is gone'
Assert-True (-not (Test-Path $p.State)) 'the state file is gone'
Assert-True (Test-Path $p.Export) 'the firewall export is kept as a last-known-good copy'
Assert-True (-not (Get-DeadManStatus).Armed) 'status says not armed'

Write-Host 'Dead-man switch: things that go wrong while arming' -ForegroundColor Cyan
$global:NetshMakesFile = $false; Remove-Item $p.Export -ErrorAction SilentlyContinue
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-Equal $r.Status 'Failed' 'if the export fails the switch is NOT armed'
Assert-True ($r.Message -match 'export failed') 'and the message says so'
Assert-True (-not $global:Tasks.ContainsKey('NetCacheRestore')) 'and no task was created'
$global:NetshMakesFile = $true
Rename-Item (Join-Path $script:HpRoot 'Panic.ps1') 'Panic.moved'
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Panic.ps1 was not found') 'if Panic.ps1 is missing the switch is NOT armed'
Rename-Item (Join-Path $script:HpRoot 'Panic.moved') 'Panic.ps1'

# ------------------------------------------------------------------ Panic.ps1
$env:TEMP = [IO.Path]::GetTempPath()
$stateDir = $p.Dir                                   # in real life the task passes this same folder to Panic.ps1
Write-Host 'Panic: the steps' -ForegroundColor Cyan
. "$PSScriptRoot\..\Panic.ps1" -DataDir $tmp -StateDir $stateDir -Yes        # dot-sourced: defines the functions, runs nothing
$global:Calls.Clear()

Set-Content -Path (Join-Path $stateDir 'fw-before.wfw') -Value 'FAKE'
$msg = Restore-Firewall
Assert-True ($msg -match 'put back from') 'with an export: the firewall policy is imported'
Assert-True (@($global:Calls | Where-Object { $_ -eq "netsh advfirewall import $(Join-Path $stateDir 'fw-before.wfw')" }).Count -eq 1) 'with the right netsh command'
$global:NetshExit = 1
Assert-Throws { Restore-Firewall } 'a failing import is reported as an error'
$global:NetshExit = 0
$global:Calls.Clear()
Remove-Item (Join-Path $stateDir 'fw-before.wfw')
$msg = Restore-Firewall
Assert-True ($global:Calls -contains 'netsh advfirewall reset') 'no export: the firewall is reset'
Assert-True ($global:FwRules.ContainsKey('Panic allow 3389') -and $global:FwRules.ContainsKey('Panic allow 8080')) 'and 3389 and 8080 are allowed'
Assert-True ($global:FwRules['Panic allow 3389'] -match 'Inbound TCP 3389 Allow Any') 'as inbound TCP allow rules on every profile'

$global:Adapters = @(@{ Name = 'Ethernet0'; Status = 'Up' }, @{ Name = 'Ethernet1'; Status = 'Disabled' })
$global:Calls.Clear()
$msg = Restore-Adapters
Assert-True ($msg -match '^1 disabled') 'one disabled adapter found'
Assert-True ($global:Calls -contains 'Enable-NetAdapter Ethernet1') 'and switched on'
Assert-True ($global:Calls -notcontains 'Enable-NetAdapter Ethernet0') 'the adapter that was already up is left alone'

$global:Svc['TermService'] = [pscustomobject]@{ Status = 'Stopped'; StartType = 'Disabled' }
$global:Calls.Clear()
$null = Restore-Rdp
Assert-True ($global:Calls -contains 'Set-Service TermService Manual') 'a disabled TermService is set to Manual'
Assert-True ($global:Calls -contains 'Start-Service TermService') 'and started'
Assert-True (@($global:Calls | Where-Object { $_ -like '*Terminal Server fDenyTSConnections=0' }).Count -eq 1) 'RDP is allowed in the normal setting'
Assert-True (@($global:Calls | Where-Object { $_ -like '*Policies*fDenyTSConnections=0' }).Count -eq 0) 'the policy value is left alone when there is none'
$global:RegPolicy = $true; $global:Calls.Clear()
$null = Restore-Rdp
Assert-True (@($global:Calls | Where-Object { $_ -like '*Policies*fDenyTSConnections=0' }).Count -eq 1) 'a policy that denies RDP is switched to allow as well'
$global:RegPolicy = $false
$global:Svc['TermService'] = [pscustomobject]@{ Status = 'Running'; StartType = 'Manual' }
$global:RdpPort = 3389; $global:Calls.Clear()
$msg = Restore-Rdp
Assert-True (@($global:Calls | Where-Object { $_ -like '*RDP-Tcp PortNumber=*' -or $_ -like 'Restart-Service*' }).Count -eq 0) 'Remote Desktop on 3389 and running: no port change, no restart'
$global:RdpPort = 3390; $global:Calls.Clear()
$msg = Restore-Rdp
Assert-True (@($global:Calls | Where-Object { $_ -like '*RDP-Tcp PortNumber=3389' }).Count -eq 1) 'a Remote Desktop port that was moved is set back to 3389'
Assert-True ($global:Calls -contains 'Restart-Service TermService') 'and the service is restarted so that the port counts'
Assert-True ($msg -match '3390') 'and the sentence says what the port was'
$global:RdpPort = 0

$global:Users['jmoney'] = @{ Name = 'jmoney'; Enabled = $false; PasswordLastSet = (Get-Date).AddDays(-1); AccountExpires = $null; PasswordExpires = $null }
$global:Calls.Clear()
$msg = Restore-Jmoney
Assert-True ($global:Calls -contains 'Enable-LocalUser jmoney') 'jmoney is enabled'
Assert-True ($global:Calls -contains 'net user jmoney /active:yes') 'and unlocked'
Assert-True (@($global:Calls | Where-Object { $_ -like 'Add-LocalGroupMember group-S-1-5-32-555 jmoney' }).Count -eq 1) 'and put in Remote Desktop Users (found by SID)'
Assert-True (@($global:Calls | Where-Object { $_ -match 'password' -or $_ -match 'Set-LocalUser' }).Count -eq 0) 'the password is never touched'
Assert-True (@($global:Calls | Where-Object { $_ -match 'expires' -or $_ -match 'logonpasswordchg' }).Count -eq 0) 'an account with nothing wrong gets nothing extra'
Write-Host 'Panic: things that stop jmoney logging on without a wrong password' -ForegroundColor Cyan
$global:Users['jmoney'] = @{ Name = 'jmoney'; Enabled = $true; PasswordLastSet = $null; AccountExpires = (Get-Date).AddDays(-1); PasswordExpires = (Get-Date).AddHours(-2) }
$global:Calls.Clear()
$msg = Restore-Jmoney
Assert-True ($global:Calls -contains 'net user jmoney /expires:never') 'an expired account is set to never expire'
Assert-True ($global:Calls -contains 'Set-LocalUser jmoney PasswordNeverExpires=True') 'an expired password is set to never expire'
Assert-True ($global:Calls -contains 'net user jmoney /logonpasswordchg:no') 'a blank "password last set" (= must change it at the next logon) is cleared'
Assert-True ($msg -match 'account expiry' -and $msg -match 'password expiry' -and $msg -match 'must change') 'and the sentence says what was repaired'
Assert-True (@($global:Calls | Where-Object { $_ -match 'Set-LocalUser' -and $_ -notmatch 'PasswordNeverExpires' }).Count -eq 0) 'the password itself is never set'
$global:Users['jmoney'] = @{ Name = 'jmoney'; Enabled = $true; PasswordLastSet = (Get-Date).AddDays(-1); AccountExpires = (Get-Date).AddDays(30); PasswordExpires = (Get-Date).AddDays(30) }
$global:Calls.Clear()
$msg = Restore-Jmoney
Assert-True (@($global:Calls | Where-Object { $_ -match 'expires' -or $_ -match 'Set-LocalUser' -or $_ -match 'logonpasswordchg' }).Count -eq 0) 'an expiry date in the FUTURE is left alone'
$global:Users.Remove('jmoney')
Assert-Throws { Restore-Jmoney } 'no jmoney account -> an error, not a crash'

$global:CimServices = @(@{ Name = 'Spooler'; PathName = 'C:\Windows\spoolsv.exe'; StartMode = 'Auto'; State = 'Running' },
                        @{ Name = 'Jenkins'; PathName = '"C:\Program Files\Jenkins\jenkins.exe"'; StartMode = 'Disabled'; State = 'Stopped' })
$global:Calls.Clear()
$msg = Restore-Jenkins
Assert-True ($global:Calls -contains 'Set-Service Jenkins Automatic' -and $global:Calls -contains 'Start-Service Jenkins') 'a disabled, stopped Jenkins is set to Automatic and started'
$global:CimServices = @(@{ Name = 'WeirdName'; PathName = '"D:\ci\jenkins\jenkins.exe" -x'; StartMode = 'Auto'; State = 'Running' })
$global:Calls.Clear()
$msg = Restore-Jenkins
Assert-True ($msg -match 'WeirdName') 'Jenkins is found by its program path when the service name is different'
Assert-True ($global:Calls.Count -eq 0) 'a running Jenkins is left alone'
$global:CimServices = @()
Assert-Throws { Restore-Jenkins } 'no Jenkins service -> an error'

$global:Calls.Clear()
Assert-True ((Restore-Rights) -match 'nothing to do') 'no saved rights file -> nothing to do'
Set-Content -Path (Join-Path $tmp 'rights-before.inf') -Value 'x'
$null = Restore-Rights
Assert-True (@($global:Calls | Where-Object { $_ -like 'secedit /configure*rights-before.inf*/areas USER_RIGHTS*' }).Count -eq 1) 'a saved rights file is applied with secedit /configure'

Write-Host 'Panic: Start-Panic' -ForegroundColor Cyan
$global:Tasks['NetCacheRestore'] = @{ TaskName = 'NetCacheRestore' }
Set-Content -Path (Join-Path $stateDir 'armed.json') -Value '{}'
Set-Content -Path (Join-Path $stateDir 'fw-before.wfw') -Value 'FAKE'
$global:Calls.Clear()
$FromTask = $true
Start-Panic
$FromTask = $false
Assert-True (@($global:Calls | Where-Object { $_ -like 'netsh advfirewall import*' }).Count -eq 1) '-FromTask restores the firewall'
Assert-True ($global:Calls -contains 'Enable-NetAdapter Ethernet1' -or $global:Adapters[1].Status -eq 'Up') 'and the adapters'
Assert-True (@($global:Calls | Where-Object { $_ -like '*TermService*' -or $_ -like '*jmoney*' -or $_ -like 'Start-Service*' }).Count -eq 0) '-FromTask does nothing else (no accounts, no services)'
Assert-True (-not $global:Tasks.ContainsKey('NetCacheRestore')) 'it removes its own task'
Assert-True (-not (Test-Path (Join-Path $stateDir 'armed.json'))) 'and the armed state'
$fired = [IO.File]::ReadAllText((Join-Path $stateDir 'fired.json')) | ConvertFrom-Json
Assert-True ($fired.Results -contains 'Firewall=ok') 'fired.json records what happened'
Assert-True ((Get-Content (Join-Path $stateDir 'panic.log') -Raw) -match 'PANIC started') 'panic.log has the story'
Assert-True ([bool](Get-DeadManStatus).FiredAt) 'the tool can see that the switch fired'

Write-Host 'Panic: one failing step does not stop the others' -ForegroundColor Cyan
$global:CimServices = @()                                   # Jenkins step will throw
$global:Users.Remove('jmoney')                              # jmoney step will throw
$global:Calls.Clear()
$global:Adapters = @(@{ Name = 'Ethernet1'; Status = 'Disabled' })
Set-Content -Path (Join-Path $stateDir 'fw-before.wfw') -Value 'FAKE'
$out = Start-Panic *>&1 | Out-String
Assert-True ($out -match '\[FAIL\] Jmoney') 'jmoney failed and was reported'
Assert-True ($out -match '\[FAIL\] Jenkins') 'Jenkins failed and was reported'
Assert-True ($out -match '\[ OK \] Firewall' -and $out -match '\[ OK \] Adapters' -and $out -match '\[ OK \] Rdp') 'but Firewall, Adapters and Rdp still ran'
Assert-True ($out -match 'check: port 3389') 'the final port check is printed'

Write-Host 'Panic: -Only and unknown step' -ForegroundColor Cyan
$Only = 'Adapters'; $global:Calls.Clear()
$out = Start-Panic *>&1 | Out-String
Assert-True ($out -match 'steps = Adapters' -and $out -notmatch 'Firewall') '-Only Adapters runs just that step'
$Only = 'Nonsense'
$out = Start-Panic *>&1 | Out-String
Assert-True ($out -match 'Unknown step') 'an unknown step name is refused'
$Only = ''

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-TestSummary
