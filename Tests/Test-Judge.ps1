# Test-Judge.ps1 - the JUDGES (lib\Judge*.ps1) against facts from the pretend lab box and against hand-made edge cases.
# A judge only reads facts and settings, so these tests change the pretend box, collect facts again, and look at the rows.
# It proves the rules fire (and stay quiet) when they should. It does NOT prove that the real Windows facts look like the fake ones.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"
. "$PSScriptRoot\..\lib\DeadMan.ps1"
. "$PSScriptRoot\..\lib\Collect.ps1"
. "$PSScriptRoot\..\lib\Judge.ps1"
. "$PSScriptRoot\..\lib\JudgeAccounts.ps1"
. "$PSScriptRoot\..\lib\JudgeFirewall.ps1"
. "$PSScriptRoot\..\lib\JudgeHunt.ps1"
. "$PSScriptRoot\..\lib\JudgeWatchdog.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-judge-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl

function New-TestSettings {
    param([hashtable]$Over = @{})
    $h = @{}
    foreach ($k in $script:SettingDefaults.Keys) { $h[$k] = $script:SettingDefaults[$k] }
    foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }
    $h
}

function Get-Scenario {
    # A fresh pretend box, optionally changed by $Tweak, then facts, then findings.
    param([scriptblock]$Tweak = $null, [hashtable]$Settings = @{}, [int[]]$Phases = @())
    $global:FW = New-FakeBox
    if ($Tweak) { & $Tweak }
    $script:Hp.Settings['BlackboxIp'] = $(if ($Settings.ContainsKey('BlackboxIp')) { $Settings['BlackboxIp'] } else { '' })   # the collectors read this one
    $f = Get-HpFacts
    $rows = @(Get-HpFindings -Facts $f -Settings (New-TestSettings $Settings) -Phases $Phases)
    [pscustomobject]@{ Facts = $f; Rows = $rows }
}

function Find-Row {
    param($Rows, [string]$Area, [string]$Like)
    @($Rows | Where-Object { $_.Area -eq $Area -and $_.Subject -like $Like }) | Select-Object -First 1
}
function Get-RowCount { param($Rows, [string]$Area, [string]$Like = '*') @($Rows | Where-Object { $_.Area -eq $Area -and $_.Subject -like $Like }).Count }

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Row type and helpers' -ForegroundColor Cyan
$r = New-Finding 2 'Accounts' 'BAD' 'x' 'why'
Assert-True ($r.Phase -eq 2 -and $r.Batch -eq $true -and $r.Key -eq '2|Accounts|x' -and $r.Blocked -eq '' -and $null -eq $r.Fix) 'a finding has a key, is batchable and has no fix by default'
Assert-Throws { New-Finding 2 'A' 'WRONG' 's' 'w' } 'a severity outside BAD/WARN/INFO/OK is refused'
function New-TestFixTarget { param([string]$A, [int]$B) "target:${A}:$B" }
$fx = New-Finding 2 'A' 'WARN' 's' 'w' (New-FixRef 'New-TestFixTarget' @{ A = 'x'; B = 7 })
Assert-Equal (Resolve-Fix $fx) 'target:x:7' 'Resolve-Fix calls the named function with its arguments'
foreach ($evil in 'Remove-Item', 'Set-HpSetting', 'Invoke-Change', 'Invoke-Expression', 'net.exe', 'New-Action; calc', 'Request-X Y', '') {
    $bad = New-Finding 2 'A' 'WARN' 's' 'w' (New-FixRef $evil @{})
    Assert-Throws { Resolve-Fix $bad } "Resolve-Fix refuses to call '$evil' (a fix can only be a Request-* or New-* function)"
}
Assert-True ($null -eq (Resolve-Fix (New-Finding 2 'A' 'OK' 's' 'w'))) 'Resolve-Fix of a finding without a fix is $null'
function Get-CrashingJudge { param($Facts, $Settings) $null = $Facts, $Settings; throw 'boom' }
$crash = @(Invoke-Judge 9 'crashy' 'Get-CrashingJudge' $null $null)
Assert-True ($crash.Count -eq 1 -and $crash[0].Severity -eq 'BAD' -and $crash[0].Why -match 'boom') 'a judge that crashes becomes ONE red row, it does not stop the audit'
$ti = Get-TeamInfo -Ips @('10.0.0.4', '172.16.7.30')
Assert-True ($ti.Team -eq '7' -and $ti.Net -eq '172.16.7.0/24' -and $ti.Blackbox -eq '172.16.7.5') 'team number, network and blackbox come from the 172.16.t.x address'
$ti = Get-TeamInfo -Ips @('10.0.0.4') -TeamNet '172.16.9.0/24'
Assert-True ($ti.Team -eq '' -and $ti.Net -eq '172.16.9.0/24' -and $ti.Blackbox -eq '') 'no team address: the TeamNet setting is used, blackbox stays unknown'
Assert-Equal (Get-TeamInfo -Ips @()).Net '' 'no address, no setting: nothing is guessed'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The whole fake lab box through all judges' -ForegroundColor Cyan
$base = Get-Scenario
Assert-True (@($base.Facts.Errors).Count -eq 0) 'no collector error'
$rows = $base.Rows
Assert-True ($rows.Count -ge 40) "plenty of rows ($($rows.Count))"
Assert-True (@($rows | Where-Object { $_.Area -eq 'Judge' }).Count -eq 0) 'no judge crashed'
$sorted = @($rows | ForEach-Object { $_.Phase })
Assert-True (($sorted | Sort-Object) -join ',' -eq ($sorted -join ',')) 'rows come out in phase order'
$keys = @($rows | ForEach-Object { $_.Key })
Assert-Equal ($keys | Select-Object -Unique).Count $keys.Count 'every row has its own key'
Assert-Equal @(Get-HpFindings -Facts $base.Facts -Settings (New-TestSettings) -Phases @(2, 4) | Where-Object { $_.Phase -notin 2, 4 }).Count 0 '-Phases limits the result'

Write-Host 'Phase 1: recon' -ForegroundColor Cyan
Assert-True ((Find-Row $rows 'Host' 'Team network').Why -match '172\.16\.5\.0/24.*172\.16\.5\.5') 'team network and blackbox IP are worked out from this box'
Assert-True ((Find-Row $rows 'Jenkins' 'Jenkins service').Severity -eq 'INFO') 'Jenkins running -> informational'
Assert-True ((Find-Row $rows 'Jenkins' 'Scripts in init.groovy.d').Severity -eq 'WARN') 'a script in init.groovy.d is flagged'
Assert-True ((Find-Row $rows 'Log collector' 'Log collector found').Why -match 'NEVER stop') 'the log collector is found and protected'
Assert-True ((Find-Row $rows 'Safety net' 'Dead-man switch').Severity -eq 'WARN') 'dead-man switch not armed -> a warning in recon'
Assert-True ((Find-Row $rows 'Inventory' '*').Why -match '8 services, 2 scheduled tasks') 'inventory counts services and non-Microsoft tasks'

$s = Get-Scenario { $global:FW.NetCategory = 'Public' } -Phases 1
Assert-True ((Find-Row $s.Rows 'Network' 'Network profile is Public').Severity -eq 'WARN') 'Public network profile is flagged'
$s = Get-Scenario { $global:FW.Ips = @('10.0.0.9') } -Phases 1
Assert-True ((Find-Row $s.Rows 'Host' 'Team network').Severity -eq 'WARN') 'no 172.16.t.x address -> the team is unknown (warning)'
$s = Get-Scenario { $global:FW.Tcp.Remove('1.1.1.1:443') } -Phases 1
Assert-True ((Find-Row $s.Rows 'Network' 'Internet').Why -match 'NOT reachable') 'no Internet is reported'
$s = Get-Scenario { $global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'Jenkins' }) } -Phases 1
Assert-True ((Find-Row $s.Rows 'Jenkins' 'Jenkins service not found').Severity -eq 'WARN') 'no Jenkins service -> warning'
$s = Get-Scenario { ($global:FW.Services | Where-Object { $_.Name -eq 'Jenkins' }).State = 'Stopped'; $global:FW.Listen = @($global:FW.Listen | Where-Object { $_.Port -ne 8080 }) } -Phases 1
Assert-True ((Find-Row $s.Rows 'Jenkins' 'Jenkins service').Severity -eq 'BAD') 'Jenkins stopped -> red'
Assert-True ((Find-Row $s.Rows 'Jenkins' 'Nothing listens on port 8080').Severity -eq 'BAD') 'nothing on 8080 -> red'
$s = Get-Scenario { $global:FW.Files.Remove((Get-FakeKey 'C:\Program Files\Jenkins\jenkins.xml')); $global:FW.Reg.Remove('hklm:\system\currentcontrolset\services\jenkins|Environment') } -Phases 1
Assert-True ((Find-Row $s.Rows 'Jenkins' 'Jenkins home not found').Severity -eq 'WARN') 'Jenkins home not found -> warning'
$s = Get-Scenario { $global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'otelcol' }) } -Phases 1
Assert-True ((Find-Row $s.Rows 'Log collector' 'Log collector').Severity -eq 'INFO') 'no collector found and no blackbox IP -> informational only'
$s = Get-Scenario { $global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'otelcol' }) } -Settings @{ BlackboxIp = '172.16.5.5' } -Phases 1
Assert-True ((Find-Row $s.Rows 'Log collector' 'Log collector found').Why -match 'connected to blackbox port 4317') 'no collector service, but a program is connected to blackbox -> found by its connection'
$s = Get-Scenario { $global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'otelcol' }); $global:FW.Conns = @($global:FW.Conns | Where-Object { $_.RemoteAddress -ne '172.16.5.5' }) } -Settings @{ BlackboxIp = '172.16.5.5' } -Phases 1
Assert-True ((Find-Row $s.Rows 'Log collector' 'Log collector not found').Severity -eq 'WARN') 'no collector service, no connection, blackbox known -> warning'
$s = Get-Scenario { $global:FW.BreakTasks = $true } -Phases 1
Assert-True ((Find-Row $s.Rows 'Recon' 'Could not read: Tasks').Severity -eq 'BAD') 'a collector error becomes a red row'
$empty = @(Get-HpFindings -Facts ([pscustomobject]@{ Errors = @() }) -Settings (New-TestSettings))
Assert-True (@($empty | Where-Object { $_.Area -eq 'Judge' }).Count -eq 0) 'facts with every section missing: no judge crashes'

Write-Host 'Phase 2: accounts' -ForegroundColor Cyan
$a = $base.Rows | Where-Object { $_.Phase -eq 2 }
$na = Find-Row $a 'New admin' 'No new admin*'
Assert-True ($na.Severity -eq 'BAD' -and $na.Fix.Do -eq 'Request-CreateAdmin' -and -not $na.Batch) 'no new admin -> red, create one (never in a batch)'
foreach ($n in 'Administrator', 'plinktern', 'helpdesk', 'kkiderchah', 'support$') {
    $x = Find-Row $a 'Accounts' "$n*"
    Assert-True ($x.Blocked -match 'confirm it works' -and $x.Fix.Do -eq 'Request-RetireAccount') "$n : retiring is BLOCKED until the new admin is confirmed"
}
$x = Find-Row $a 'Accounts' 'jbrewer*'
Assert-True ($x.Blocked -eq '' -and $x.Severity -eq 'BAD') 'jbrewer (RDP user only) is not blocked'
$x = Find-Row $a 'Accounts' 'testuser*'
Assert-True ($x.Severity -eq 'WARN' -and $x.Blocked -eq '') 'testuser (no privileged group) is a warning, not blocked'
Assert-True ((Find-Row $a 'Accounts' 'svc_backup*').Severity -eq 'INFO' -and $null -eq (Find-Row $a 'Accounts' 'svc_backup*').Fix) 'a service account is kept (no fix offered)'
Assert-True ((Find-Row $a 'Accounts' 'old.employee*').Subject -match 'already disabled') 'a disabled account that is still in groups is listed'
Assert-True (@($a | Where-Object { $_.Subject -like 'jmoney*' -and $_.Fix -and $_.Fix.Do -eq 'Request-RetireAccount' }).Count -eq 0) 'jmoney is never offered for retirement'
Assert-True (@($a | Where-Object { $_.Subject -like 'DefaultAccount*' -or $_.Subject -like 'WDAGUtility*' }).Count -eq 0) 'the two Windows built-ins are not listed'
$j = Find-Row $a 'jmoney' 'jmoney still has*'
Assert-True ($j.Severity -eq 'BAD' -and $j.Fix.Do -eq 'Request-RotateJmoney' -and -not $j.Batch) 'jmoney with the packet password -> rotate, never in a batch'
Assert-True ((Find-Row $a 'Accounts' 'Guest is enabled').Fix.Do -eq 'New-DisableGuestAction') 'Guest enabled -> disable it'
Assert-True ((Find-Row $a 'Rights' 'Account lockout is ON').Fix.Do -eq 'New-LockoutOffAction') 'lockout on -> turn it off'
$rd = Find-Row $a 'Rights' 'Remote Desktop logon is open*'
Assert-True ($rd.Severity -eq 'WARN' -and $rd.Blocked -match 'new admin' -and $rd.Fix.Do -eq 'Request-RestrictRdp') 'RDP right is open to the groups: blocked until the new admin is confirmed'

$conf = @{ NewAdmin = 'zadmin'; NewAdminConfirmed = $true }
$s = Get-Scenario {
    $u = @{ Name = 'zadmin'; Sid = (ConvertTo-FakeSid 2100); Enabled = $true; Groups = (New-Object System.Collections.ArrayList); Password = 'x'; Description = ''; LastLogon = [datetime]'2026-10-17 09:00' }
    [void]$u.Groups.Add('Administrators'); [void]$u.Groups.Add('Remote Desktop Users'); $global:FW.Users['zadmin'] = $u
} -Settings $conf -Phases 2
$a = $s.Rows
Assert-True ((Find-Row $a 'New admin' "New admin 'zadmin'").Severity -eq 'OK') 'confirmed new admin -> green'
Assert-True ((Find-Row $a 'Accounts' 'plinktern*').Blocked -eq '') 'plinktern is free to retire after the new admin is confirmed'
Assert-True ((Find-Row $a 'Accounts' 'Administrator*').Blocked -eq '') 'the built-in Administrator is free to retire too'
Assert-True ($null -eq (Find-Row $a 'Accounts' 'zadmin*')) 'the new admin itself is never offered for retirement'
Assert-True ((Find-Row $a 'Rights' 'Remote Desktop logon is open*').Blocked -eq '') 'restricting RDP is free once the new admin is confirmed'

$s = Get-Scenario {
    $u = @{ Name = 'zadmin'; Sid = (ConvertTo-FakeSid 2100); Enabled = $true; Groups = (New-Object System.Collections.ArrayList); Password = 'x'; Description = ''; LastLogon = $null }
    [void]$u.Groups.Add('Administrators'); [void]$u.Groups.Add('Remote Desktop Users'); $global:FW.Users['zadmin'] = $u
} -Settings @{ NewAdmin = 'zadmin' } -Phases 2
$x = Find-Row $s.Rows 'New admin' "*not confirmed yet"
Assert-True ($x.Severity -eq 'WARN' -and $x.Fix.Do -eq 'New-ConfirmAdminAction' -and -not $x.Batch) 'new admin exists but is not confirmed -> confirm button, never in a batch'
Assert-True ((Find-Row $s.Rows 'Accounts' 'plinktern*').Blocked -match 'confirm') 'and until then plinktern stays blocked'

$s = Get-Scenario $null -Settings @{ NewAdmin = 'ghost' } -Phases 2
$x = Find-Row $s.Rows 'New admin' "New admin 'ghost' does not exist"
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.With.Name -eq 'ghost') 'a remembered new admin that no longer exists (a revert) -> create it again'

$s = Get-Scenario {
    $u = @{ Name = 'zadmin'; Sid = (ConvertTo-FakeSid 2100); Enabled = $false; Groups = (New-Object System.Collections.ArrayList); Password = 'x'; Description = ''; LastLogon = $null }
    $global:FW.Users['zadmin'] = $u
} -Settings $conf -Phases 2
$x = Find-Row $s.Rows 'New admin' "*is not usable"
Assert-True ($x.Fix.Do -eq 'New-RepairAdminAction' -and $x.Why -match 'disabled' -and $x.Why -match 'not an Administrator' -and $x.Why -match 'Remote Desktop Users') 'a disabled, ungrouped new admin -> repair, with every problem listed'

# jmoney edge cases
$s = Get-Scenario { $global:FW.Users['jmoney'].Enabled = $false } -Phases 2
$x = Find-Row $s.Rows 'jmoney' 'jmoney is disabled'
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-EnableUserAction') 'jmoney disabled -> red, the fix ENABLES it'
$s = Get-Scenario { $global:FW.Users['jmoney'].Groups.Clear() } -Phases 2
$x = Find-Row $s.Rows 'jmoney' 'jmoney may not use Remote Desktop'
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-AddToGroupAction' -and $x.Fix.With.GroupSid -eq 'S-1-5-32-555') 'jmoney not in Remote Desktop Users -> add him'
$s = Get-Scenario { [void]$global:FW.Users['jmoney'].Groups.Add('Administrators') } -Phases 2
$x = Find-Row $s.Rows 'jmoney' 'jmoney is an Administrator'
Assert-True ($x.Severity -eq 'WARN' -and $x.Fix.Do -eq 'New-DemoteJmoneyAction' -and -not $x.Batch) 'jmoney is an admin -> demote offered, never in a batch'
$s = Get-Scenario { $global:FW.Users.Remove('jmoney') } -Phases 2
Assert-True ((Find-Row $s.Rows 'jmoney' 'Scoring user jmoney does not exist').Severity -eq 'BAD') 'jmoney missing -> red (the tool cannot create it)'
$s = Get-Scenario $null -Settings @{ JmoneyRotations = 1 } -Phases 2
$x = Find-Row $s.Rows 'jmoney' 'jmoney password rotated*'
Assert-True ($x.Severity -eq 'INFO' -and $x.Why -match 'NEIGH') 'after one rotation: informational, with the NEIGH reminder'

# other accounts
$s = Get-Scenario $null -Settings @{ ExtraKeep = @('jbrewer') } -Phases 2
Assert-True ((Find-Row $s.Rows 'Accounts' 'jbrewer (kept)').Severity -eq 'INFO') 'ExtraKeep: the account is left alone'
$s = Get-Scenario { $global:FW.Users['Guest'].Enabled = $false } -Phases 2
Assert-True ((Find-Row $s.Rows 'Accounts' 'Guest is disabled').Severity -eq 'OK') 'Guest disabled -> green'
$s = Get-Scenario { $global:FW.Services += @{ Name = 'InternRun'; DisplayName = 'Intern thing'; State = 'Running'; StartMode = 'Auto'; StartName = '.\plinktern'; PathName = '"C:\Program Files\x\x.exe"'; ProcessId = 99 } } -Settings $conf -Phases 2
$x = Find-Row $s.Rows 'Accounts' 'plinktern*'
Assert-True ($x.Blocked -match 'service InternRun' -and $x.Why -match 'Runs as this account') 'a service that runs as plinktern blocks its retirement and says which service'
$s = Get-Scenario { $global:FW.Tasks += @{ TaskName = 'Mine'; TaskPath = '\'; State = 'Ready'; UserId = 'ASSEMBLY-5\jbrewer'; GroupId = ''; RunLevel = 'Limited'; Execute = 'C:\Program Files\x\y.exe'; Arguments = '' } } -Phases 2
Assert-True ((Find-Row $s.Rows 'Accounts' 'jbrewer*').Why -match 'task \\Mine') 'a scheduled task that runs as the account is mentioned (retiring is still allowed)'
$s = Get-Scenario { $global:FW.Users['Administrator'].Groups.Clear(); $global:FW.Users['Administrator'].Enabled = $false } -Phases 2
Assert-True ($null -eq (Find-Row $s.Rows 'Accounts' 'Administrator*')) 'a disabled account in no group is just counted, not listed'
Assert-True ((Find-Row $s.Rows 'Accounts' '* other account(s) already disabled').Severity -eq 'INFO') 'and the count row says so'
$s = Get-Scenario { $global:FW.Users.Remove('plinktern'); $global:FW.Users['intern2'] = @{ Name = 'intern2'; Sid = (ConvertTo-FakeSid 1001); Enabled = $true; Groups = (New-Object System.Collections.ArrayList); Password = 'x'; Description = ''; LastLogon = $null } ; [void]$global:FW.Users['intern2'].Groups.Add('Administrators') } -Phases 2
Assert-True ((Find-Row $s.Rows 'Accounts' 'intern2*').Blocked -match 'confirm') 'an unknown admin account is also blocked until the new admin works'

# logon rights
$s = Get-Scenario { $global:FW.Lockout = 0 } -Phases 2
Assert-True ((Find-Row $s.Rows 'Rights' 'Account lockout is off').Severity -eq 'OK') 'lockout 0 -> green'
$s = Get-Scenario { $global:FW.Rights['SeDenyRemoteInteractiveLogonRight'] = '*S-1-5-32-555' } -Phases 2
Assert-True ((Find-Row $s.Rows 'Rights' 'jmoney is DENIED: SeDenyRemoteInteractiveLogonRight').Severity -eq 'BAD') 'a deny entry for a group jmoney is in -> red (the quiet failure)'
$s = Get-Scenario { $global:FW.Rights['SeDenyNetworkLogonRight'] = '*' + (ConvertTo-FakeSid 1002) } -Phases 2
Assert-True ((Find-Row $s.Rows 'Rights' 'jmoney is DENIED: SeDenyNetworkLogonRight').Why -match 'jmoney') 'a deny entry for jmoney himself -> red'
$s = Get-Scenario { $global:FW.Rights['SeNetworkLogonRight'] = '*S-1-5-32-544' } -Phases 2
Assert-True ((Find-Row $s.Rows 'Rights' 'jmoney may not log on over the network').Severity -eq 'BAD') 'jmoney missing from "access this computer from the network" -> red'
$s = Get-Scenario { $global:FW.Rights['SeRemoteInteractiveLogonRight'] = '*S-1-5-32-544' } -Phases 2
Assert-True ((Find-Row $s.Rows 'Rights' 'jmoney is not allowed to log on through Remote Desktop').Severity -eq 'BAD') 'RDP right without jmoney or his groups -> red'
$s = Get-Scenario { $global:FW.Rights['SeRemoteInteractiveLogonRight'] = '*' + (ConvertTo-FakeSid 1002) + ',*' + (ConvertTo-FakeSid 2100)
    $u = @{ Name = 'zadmin'; Sid = (ConvertTo-FakeSid 2100); Enabled = $true; Groups = (New-Object System.Collections.ArrayList); Password = 'x'; Description = ''; LastLogon = $null }
    [void]$u.Groups.Add('Administrators'); [void]$u.Groups.Add('Remote Desktop Users'); $global:FW.Users['zadmin'] = $u } -Settings $conf -Phases 2
Assert-True ((Find-Row $s.Rows 'Rights' 'Remote Desktop logon right').Severity -eq 'OK') 'RDP right limited to the new admin and jmoney -> green'
$s = Get-Scenario $null -Phases 2
$s.Facts.Secedit = @{}
$rows = @(Get-HpFindings -Facts $s.Facts -Settings (New-TestSettings) -Phases 2)
Assert-True ((Find-Row $rows 'Rights' 'Local security policy could not be read').Severity -eq 'WARN') 'no secedit data -> a warning, not a crash'
$s = Get-Scenario { $global:FW.Users.Clear() } -Phases 2
Assert-True (@($s.Rows | Where-Object { $_.Area -eq 'Judge' }).Count -eq 0) 'no users at all: no judge crashes'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 4: firewall' -ForegroundColor Cyan
$fwRows = $base.Rows | Where-Object { $_.Phase -eq 4 }
$x = Find-Row $fwRows 'Safety net' 'Dead-man switch is not armed'
Assert-True ($x.Severity -eq 'WARN' -and $x.Fix.Do -eq 'New-ArmDeadManAction' -and $x.Fix.With.Minutes -eq 5) 'dead-man not armed -> arm it (5 minutes from the settings)'
foreach ($p in 3389, 8080) {
    $x = Find-Row $fwRows 'Allow rules' "Inbound TCP ${p}: no HP allow rule"
    Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-AllowPortAction' -and $x.Fix.With.Port -eq $p) "TCP $p : no HP rule -> create it"
}
Assert-True ((Find-Row $fwRows 'Allow rules' 'Inbound TCP 3389*').Why -match 'RemoteDesktop-UserMode-In-TCP') 'and the text names the other rule that lets the port in today'
$legacy = Find-Row $fwRows 'Other inbound rules' 'Legacy FTP*'
Assert-True ($legacy.Fix.Do -eq 'New-DisableRuleAction' -and $legacy.Blocked -match 'allow rules for ports 3389 and 8080 first') 'disabling other rules is blocked until the HP allow rules exist'
$gpo = Find-Row $fwRows 'Other inbound rules' 'GpoDeliveredRule*'
Assert-True ($null -eq $gpo.Fix -and $gpo.Why -match 'Group Policy') 'a rule delivered by Group Policy has no fix, and says why'
Assert-True ($null -eq (Find-Row $fwRows 'Other inbound rules' 'Core*') -and $null -eq (Find-Row $fwRows 'Other inbound rules' 'CoreNet*')) 'Core Networking rules are never listed'
Assert-True ($null -eq (Find-Row $fwRows 'Other inbound rules' 'RemoteDesktop*') -and $null -eq (Find-Row $fwRows 'Other inbound rules' 'Jenkins 8080*')) 'rules that only open 3389 or 8080 are not listed as "to disable"'
Assert-True ((Find-Row $fwRows 'Profiles' 'Firewall profiles').Severity -eq 'OK') 'profiles already on with inbound Block -> green'
$x = Find-Row $fwRows 'Outbound' 'Outbound default is Allow'
Assert-True ($x.Fix.Do -eq 'Request-OutboundDeny' -and -not $x.Batch -and $x.Blocked -match 'allow rules for ports') 'outbound deny: never in a batch, and blocked until the HP allow rules exist'

# the same box once the tool's own rules exist
$ours = {
    foreach ($p in 3389, 8080) { New-NetFirewallRule -Name "HP-Allow-TCP-$p" -DisplayName "HP Allow TCP $p" -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any | Out-Null }
}
$s = Get-Scenario $ours -Phases 4
$fwRows2 = $s.Rows
Assert-True ((Find-Row $fwRows2 'Allow rules' 'Inbound TCP 3389 is allowed').Severity -eq 'OK') 'HP rule for 3389 present -> green'
Assert-True ((Find-Row $fwRows2 'Allow rules' 'Inbound TCP 8080 is allowed').Severity -eq 'OK') 'HP rule for 8080 present -> green'
Assert-True ((Find-Row $fwRows2 'Other inbound rules' 'Legacy FTP*').Blocked -eq '') 'now disabling the other rules is no longer blocked'
Assert-True ($null -eq (Find-Row $fwRows2 'Other inbound rules' 'HP Allow*')) 'the HP rules are not offered for disabling'
Assert-True ((Find-Row $fwRows2 'Outbound' 'Outbound default is Allow').Blocked -eq '') 'outbound deny is no longer blocked'

$s = Get-Scenario { & $ours; ($global:FW.FwRules | Where-Object { $_.Name -eq 'HP-Allow-TCP-3389' }).RemoteAddress = '203.0.113.7' } -Phases 4
$x = Find-Row $s.Rows 'Allow rules' 'Inbound TCP 3389: no HP allow rule'
Assert-True ($x.Severity -eq 'BAD' -and $x.Why -match 'limited to some source addresses') 'an HP rule limited to one source address does NOT count (the scoring engine uses many)'
$s = Get-Scenario { & $ours; ($global:FW.FwRules | Where-Object { $_.Name -eq 'HP-Allow-TCP-8080' }).Profile = 'Private' } -Phases 4
$x = Find-Row $s.Rows 'Allow rules' 'Inbound TCP 8080: no HP allow rule'
Assert-True ($x.Severity -eq 'BAD' -and $x.Why -match 'Profiles without it: Domain, Public') 'an HP rule on one profile only -> the missing profiles are named'
$s = Get-Scenario { & $ours; ($global:FW.FwRules | Where-Object { $_.Name -eq 'HP-Allow-TCP-3389' }).LocalPort = '3380-3399' } -Phases 4
Assert-True ((Find-Row $s.Rows 'Allow rules' 'Inbound TCP 3389 is allowed').Severity -eq 'OK') 'a port RANGE that contains 3389 counts'
$s = Get-Scenario { & $ours; ($global:FW.FwRules | Where-Object { $_.Name -eq 'HP-Allow-TCP-3389' }).Enabled = 'False' } -Phases 4
Assert-True ((Find-Row $s.Rows 'Allow rules' 'Inbound TCP 3389: no HP allow rule').Severity -eq 'BAD') 'a disabled HP rule does not count'
$s = Get-Scenario { & $ours
    New-NetFirewallRule -Name 'BlockRdp' -DisplayName 'Block RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block | Out-Null } -Phases 4
$x = Find-Row $s.Rows 'Allow rules' "Block rule 'Block RDP'*"
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-DisableRuleAction' -and $x.Fix.With.Name -eq 'BlockRdp') 'a local BLOCK rule on 3389 beats every allow rule -> red, with a fix'
$s = Get-Scenario { & $ours
    New-NetFirewallRule -Name 'GpoBlock' -DisplayName 'Policy block' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Block | Out-Null
    ($global:FW.FwRules | Where-Object { $_.Name -eq 'GpoBlock' }).Persistent = $false } -Phases 4
$x = Find-Row $s.Rows 'Allow rules' "Block rule 'Policy block'*"
Assert-True ($null -eq $x.Fix -and $x.Blocked -match 'Group Policy') 'a BLOCK rule from Group Policy cannot be fixed here and says so'

$s = Get-Scenario { & $ours; $global:FW.FwProfiles['Public'].DefaultInboundAction = 'Allow'; $global:FW.FwProfiles['Domain'].Enabled = 'False'; $global:FW.FwProfiles['Private'].AllowInboundRules = 'False' } -Phases 4
$x = Find-Row $s.Rows 'Profiles' 'Firewall profiles are not set as planned'
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-FirewallBaselineAction' -and $x.Blocked -eq '' -and $x.Why -match 'Domain profile is OFF' -and $x.Why -match 'Public: inbound default is Allow' -and $x.Why -match 'Private: all inbound is blocked') 'a profile off / inbound Allow / "block all inbound": all three problems are named'
$s = Get-Scenario { $global:FW.FwProfiles['Public'].DefaultInboundAction = 'Allow' } -Phases 4
Assert-True ((Find-Row $s.Rows 'Profiles' 'Firewall profiles are not set as planned').Blocked -match 'allow rules for ports 3389 and 8080 first') 'the profile baseline is blocked until the HP allow rules exist'
$s = Get-Scenario { & $ours; foreach ($p in $global:FW.FwProfiles.Values) { $p.LogBlocked = 'True' } } -Phases 4
Assert-True ($null -eq (Find-Row $s.Rows 'Profiles' 'Dropped connections are not logged')) 'logging already on -> no logging row'
$s = Get-Scenario { $global:FW.FwServiceStopped = $true } -Phases 4
$x = Find-Row $s.Rows 'Firewall' 'Firewall service is not running'
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-StartFirewallServiceAction') 'firewall service stopped -> red, start it'
$s = Get-Scenario { $global:FW.Services = @($global:FW.Services); $global:FW.FwServiceMissing = $true } -Phases 4
$s = Get-Scenario { & $ours; foreach ($p in $global:FW.FwProfiles.Values) { $p.DefaultOutboundAction = 'Block' } } -Phases 4
Assert-True ((Find-Row $s.Rows 'Outbound' 'Outbound default is Block').Severity -eq 'OK') 'outbound already Block -> green'
$s = Get-Scenario { $global:FW.FwProfiles['Public'].DefaultInboundAction = 'Allow' } -Phases 4
Assert-True ((Find-Row $s.Rows 'Outbound' 'Outbound default is Allow').Blocked -ne '') 'outbound deny is blocked while the inbound baseline is not done'
$s = Get-Scenario { & $ours; $global:FW.Ips = @('10.0.0.9') } -Phases 4
Assert-True ((Find-Row $s.Rows 'Outbound' 'Outbound default is Allow').Blocked -match 'TeamNet') 'outbound deny is blocked while the team network is unknown'

# group policy overriding a profile: the facts must differ between the local store and the active store
$s = Get-Scenario $ours -Phases 4
$f = $s.Facts
$f.Firewall.LocalProfiles[0].In = 'Allow'
$rows = @(Get-HpFindings -Facts $f -Settings (New-TestSettings) -Phases 4)
Assert-True ((Find-Row $rows 'Profiles' 'Group Policy overrides the *').Severity -eq 'WARN') 'local profile setting different from the one in force -> Group Policy override is reported'

# dead-man states
$dmFacts = {
    param($armed, $fired)
    $f2 = Get-HpFacts -Sections 'Firewall' -Previous $base.Facts
    $f2.DeadMan = [pscustomobject]@{ Armed = $armed; SecondsLeft = 200; FiresAt = '10:00:00'; Note = 'fires in 200 seconds'; FiredAt = $fired }
    $f2
}
$rows = @(Get-HpFindings -Facts (& $dmFacts $true '') -Settings (New-TestSettings) -Phases 4)
$x = Find-Row $rows 'Safety net' 'Dead-man switch is armed'
Assert-True ($x.Fix.Do -eq 'New-ExtendDeadManAction' -and -not $x.Batch) 'armed -> extend is offered (not in a batch)'
Assert-True ($null -eq (Find-Row $rows 'Safety net' 'Everything is in place*')) 'armed but rows still red -> no "Keep changes" row yet'
$rows = @(Get-HpFindings -Facts (& $dmFacts $false '10:03:00') -Settings (New-TestSettings) -Phases 4)
Assert-True ((Find-Row $rows 'Safety net' 'Dead-man switch FIRED at 10:03:00').Severity -eq 'WARN') 'the switch fired -> a warning that says when'

# "Keep changes" appears only when everything is green and the switch is armed
$s = Get-Scenario {
    & $ours
    foreach ($p in $global:FW.FwProfiles.Values) { $p.LogBlocked = 'True'; $p.DefaultOutboundAction = 'Block' }
    foreach ($n in 'Legacy FTP', 'Telnet Test', 'Dev Web', 'Remote Debug', 'WinRM Any', 'Temp SMB') { ($global:FW.FwRules | Where-Object { $_.Name -eq $n }).Enabled = 'False' }
    ($global:FW.FwRules | Where-Object { $_.Name -eq 'GpoDeliveredRule' }).Enabled = 'False' } -Phases 4
$f = $s.Facts
$f.DeadMan = [pscustomobject]@{ Armed = $true; SecondsLeft = 200; FiresAt = '10:00:00'; Note = 'fires in 200 seconds'; FiredAt = '' }
$rows = @(Get-HpFindings -Facts $f -Settings (New-TestSettings) -Phases 4)
Assert-True (@($rows | Where-Object { $_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN' }).Count -eq 0) 'a fully hardened fake box has no red or yellow firewall rows'
$x = Find-Row $rows 'Safety net' 'Everything is in place*'
Assert-True ($x.Fix.Do -eq 'New-DisarmDeadManAction' -and -not $x.Batch) 'then, and only then: "Keep changes" is offered (not in a batch)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 3: backup' -ForegroundColor Cyan
$bk = $base.Rows | Where-Object { $_.Phase -eq 3 }
$x = Find-Row $bk 'Blackbox' 'Blackbox IP not entered'
Assert-True ($x.Severity -eq 'WARN' -and $x.Fix.Do -eq 'Request-BlackboxIp' -and $x.Why -match '172\.16\.5\.5') 'no blackbox IP -> enter it (the likely address is suggested)'
Assert-True ((Find-Row $bk 'Backup' 'No as-found backup yet').Fix.Do -eq 'Request-AsFoundBackup') 'no backup yet -> take the as-found backup'
Assert-True ((Find-Row $bk 'Tools' 'OpenSSH client').Severity -eq 'OK') 'scp.exe present -> green'
$s = Get-Scenario { $global:FW.Files.Remove((Get-FakeKey 'C:\Windows\System32\OpenSSH\scp.exe')); $global:FW.Files.Remove((Get-FakeKey 'C:\Windows\System32\OpenSSH\ssh-keyscan.exe')) } -Phases 3
Assert-True ((Find-Row $s.Rows 'Tools' 'OpenSSH client is missing: scp.exe, ssh-keyscan.exe').Why -match 'Add-WindowsCapability') 'scp.exe or ssh-keyscan.exe missing -> red, names the missing files, with the install command'
$s = Get-Scenario { $global:FW.Reg['hklm:\software\microsoft\net framework setup\ndp\v4\full|Release'] = 394802 } -Phases 3
Assert-True ((Find-Row $s.Rows 'Tools' '.NET is too old*').Severity -eq 'BAD') '.NET older than 4.7.2 -> red'

$bb = @{ BlackboxIp = '172.16.5.5' }
$s = Get-Scenario $null -Settings $bb -Phases 3
$bk = $s.Rows
Assert-True ((Find-Row $bk 'Blackbox' 'Blackbox 172.16.5.5').Severity -eq 'OK') 'blackbox IP set and port 22 answers -> green'
$x = Find-Row $bk 'Blackbox' 'No backup SSH key yet'
Assert-True ($x.Fix.Do -eq 'New-BackupKeyAction' -and -not $x.Batch) 'no key yet -> create it'
$s = Get-Scenario { $global:FW.Tcp.Remove('172.16.5.5:22') } -Settings $bb -Phases 3
Assert-True ((Find-Row $s.Rows 'Blackbox' 'Blackbox 172.16.5.5 port 22 does not answer').Severity -eq 'WARN') 'blackbox port 22 closed -> warning'

# key, host key, archives and the upload record live in the data folder
$ssh = Join-Path $tmp 'ssh'
New-Item -ItemType Directory -Path $ssh -Force | Out-Null
Set-HpSetting 'BlackboxIp' '172.16.5.5'
[IO.File]::WriteAllText((Join-Path $ssh 'id_backup'), 'PRIVATE')
[IO.File]::WriteAllText((Join-Path $ssh 'id_backup.pub'), 'ssh-ed25519 AAAATEST backup@assembly')
$s = Get-Scenario $null -Settings $bb -Phases 3
$x = Find-Row $s.Rows 'Blackbox' 'Blackbox host key not pinned'
Assert-True ($x.Fix.Do -eq 'Request-PinHostKey') 'key exists, host key not pinned -> pin it'
[IO.File]::WriteAllText((Join-Path $ssh 'known_hosts'), '172.16.5.5 ssh-ed25519 AAAAHOSTKEY')
$s = Get-Scenario $null -Settings $bb -Phases 3
Assert-True ((Find-Row $s.Rows 'Blackbox' 'Blackbox host key pinned').Severity -eq 'OK') 'host key pinned -> green'
$bdir = Get-HpDir 'backup'
[IO.File]::WriteAllText((Join-Path $bdir 'as-found-20261017-0930.zip.enc'), 'x')
$s = Get-Scenario $null -Settings $bb -Phases 3
Assert-True ((Find-Row $s.Rows 'Backup' 'Local archives: 1').Severity -eq 'OK') 'one local archive -> green'
$x = Find-Row $s.Rows 'Backup' 'Nothing sent to blackbox yet'
Assert-True ($x.Fix.Do -eq 'Request-SendBackup' -and $x.Blocked -eq '' -and -not $x.Batch) 'archive but nothing sent, everything ready -> send it (not in a batch)'
Remove-Item (Join-Path $ssh 'known_hosts')
$s = Get-Scenario $null -Settings $bb -Phases 3
Assert-True ((Find-Row $s.Rows 'Backup' 'Nothing sent to blackbox yet').Blocked -match 'Pin the blackbox host key') 'sending is blocked until the host key is pinned'
Remove-Item (Join-Path $ssh 'id_backup.pub')
$s = Get-Scenario $null -Settings $bb -Phases 3
Assert-True ((Find-Row $s.Rows 'Backup' 'Nothing sent to blackbox yet').Blocked -match 'backup key') 'sending is blocked until the key exists'
$s = Get-Scenario $null -Phases 3
Assert-True ((Find-Row $s.Rows 'Backup' 'Nothing sent to blackbox yet').Blocked -match 'blackbox IP') 'sending is blocked until the blackbox IP is entered'
[IO.File]::WriteAllText((Join-Path $bdir 'sent.json'), '{"Name":"as-found-20261017-0930.zip.enc","Time":"2026-10-17 09:40","Sha256":"ABC123","Ip":"172.16.5.5"}')
$s = Get-Scenario $null -Settings $bb -Phases 3
$x = Find-Row $s.Rows 'Backup' 'Sent to blackbox'
Assert-True ($x.Severity -eq 'OK' -and $x.Why -match 'ABC123' -and $x.Why -match 'LAPTOP') 'sent -> green, with the hash to verify from the laptop'
[IO.File]::WriteAllText((Join-Path $bdir 'as-found-20261017-1000.zip.enc'), 'newer')
(Get-Item (Join-Path $bdir 'as-found-20261017-1000.zip.enc')).LastWriteTime = (Get-Date).AddMinutes(5)
$s = Get-Scenario $null -Settings $bb -Phases 3
$x = Find-Row $s.Rows 'Backup' 'Newest backup not sent to blackbox yet'
Assert-True ($x.Fix.Do -eq 'Request-SendBackup') 'a NEWER archive than the one sent -> send again'
Remove-Item (Join-Path $bdir 'as-found-20261017-1000.zip.enc')
Set-HpSetting 'BlackboxIp' ''
Remove-Item (Join-Path $bdir 'sent.json'), (Join-Path $bdir 'as-found-20261017-0930.zip.enc'), (Join-Path $ssh 'id_backup') -ErrorAction SilentlyContinue

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 7: Defender, phase 9: routine' -ForegroundColor Cyan
$d = $base.Rows | Where-Object { $_.Phase -eq 7 }
Assert-True ((Find-Row $d 'Defender' 'Antivirus service').Severity -eq 'OK' -and (Find-Row $d 'Defender' 'Real-time protection').Severity -eq 'OK') 'Defender healthy -> green'
$s = Get-Scenario { $global:FW.Defender = $null } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender cannot be read').Severity -eq 'WARN') 'Defender cannot be read -> one warning'
$s = Get-Scenario { $global:FW.Defender.Service = $false; $global:FW.Defender.RealTime = $false; $global:FW.Defender.SigAge = 9; $global:FW.Defender.Exclusions = @('C:\Tools', 'C:\Users\Public'); $global:FW.Defender.Tamper = $false } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Antivirus service').Severity -eq 'BAD' -and (Find-Row $s.Rows 'Defender' 'Real-time protection').Severity -eq 'BAD') 'service and real-time off -> red'
Assert-True ((Find-Row $s.Rows 'Defender' 'Signatures').Severity -eq 'WARN') 'old signatures -> warning'
Assert-Equal (Get-RowCount $s.Rows 'Defender' 'Exclusion: *') 2 'each Defender exclusion gets its own row'
Assert-True ((Find-Row $s.Rows 'Defender' 'Tamper protection').Severity -eq 'INFO') 'tamper protection off -> informational'
$rt = $base.Rows | Where-Object { $_.Phase -eq 9 }
Assert-True ($null -eq (Find-Row $rt 'Routine' 'Rotate the new admin password')) 'no rotate-password reminder before a new admin exists'
$s = Get-Scenario $null -Settings $conf -Phases 9
$x = Find-Row $s.Rows 'Routine' 'Rotate the new admin password'
Assert-True ($x.Fix.Do -eq 'Request-SetPassword' -and $x.Fix.With.Name -eq 'zadmin' -and -not $x.Batch) 'with a confirmed new admin: rotate its passphrase later (not in a batch)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Phase 6: hunt (report only, nothing in a batch)' -ForegroundColor Cyan
$h = $base.Rows | Where-Object { $_.Phase -eq 6 }
$x = Find-Row $h 'Services' 'Service WinSvcHelper'
Assert-True ($x.Severity -eq 'BAD' -and $x.Fix.Do -eq 'New-DisableServiceAction' -and -not $x.Batch) 'a service whose program sits in C:\Windows\Temp -> red, fix is one item at a time'
Assert-True ($null -eq (Find-Row $h 'Services' 'Service Jenkins') -and $null -eq (Find-Row $h 'Services' 'Service otelcol')) 'Jenkins and the log collector are never offered'
Assert-True ($null -eq (Find-Row $h 'Services' 'Service TermService') -and $null -eq (Find-Row $h 'Services' 'Service Spooler')) 'Windows services in system32 are not listed'
$x = Find-Row $h 'Scheduled tasks' 'Task \MicrosoftEdgeUpdateTaskCore2'
Assert-True ($x.Fix.Do -eq 'New-DisableTaskAction' -and $x.Fix.With.Path -eq '\' -and -not $x.Batch) 'a task that runs cmd.exe /c is listed with a disable fix'
Assert-True ($null -eq (Find-Row $h 'Scheduled tasks' '*Defrag*')) 'tasks under \Microsoft\ are skipped'
$x = Find-Row $h 'Ports' 'TCP 21 listening (ftpd)'
Assert-True ($x.Severity -eq 'BAD' -and $null -eq $x.Fix -and $x.Why -match 'never kills') 'an unsigned program on port 21: a red row, and NO fix (the tool never kills a process)'
Assert-True ((Find-Row $h 'Ports' 'TCP 8080 Jenkins (java)').Severity -eq 'INFO') 'java on 8080 is expected'
$x = Find-Row $h 'Connections' 'ftpd talks to 203.0.113.9:443'
Assert-True ($x.Severity -eq 'BAD' -and $null -eq $x.Fix) 'a connection to an outside address is reported, with no fix'
Assert-True ($null -eq (Find-Row $h 'Connections' '*172.16.5.5*')) 'connections to the lab network are not reported'
Assert-True (Test-OddPath 'C:\Users\Public\x.exe') 'Test-OddPath: Public folder'
Assert-True (-not (Test-OddPath 'C:\Program Files\x\y.exe')) 'Test-OddPath: Program Files is normal'
Assert-True (Test-OddPath 'D:\tools\x.exe') 'Test-OddPath: an unusual drive'
Assert-True (Test-ProtectedProgram 'Jenkins' 'x') 'Test-ProtectedProgram: Jenkins'
Assert-True (Test-ProtectedProgram 'x' 'C:\Program Files\Java\bin\javaw.exe') 'Test-ProtectedProgram: Java'
Assert-True (-not (Test-ProtectedProgram 'evil' 'C:\Windows\Temp\evil.exe')) 'Test-ProtectedProgram: Temp is not protected'
Assert-Equal (Get-ActionProgram '"C:\a b\c.exe" /x') 'C:\a b\c.exe' 'Get-ActionProgram: quoted path'
Assert-Equal (Get-ActionProgram 'cmd.exe /c echo') '' 'Get-ActionProgram: no folder -> empty'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The plan''s rules hold in EVERY row of EVERY scenario' -ForegroundColor Cyan
$scenarios = @($base)
$scenarios += Get-Scenario $ours -Settings $conf
$scenarios += Get-Scenario { $global:FW.Users['jmoney'].Enabled = $false; $global:FW.Users['jmoney'].Groups.Clear() } -Settings $conf
$scenarios += Get-Scenario { $global:FW.Rights['SeDenyRemoteInteractiveLogonRight'] = '*S-1-5-32-555'; $global:FW.FwServiceStopped = $true }
$all = @($scenarios | ForEach-Object { $_.Rows })
Assert-True ($all.Count -gt 150) "checked $($all.Count) rows"
$retireJm = @($all | Where-Object { $_.Fix -and $_.Fix.Do -eq 'Request-RetireAccount' -and $_.Fix.With.Name -ieq 'jmoney' })
Assert-Equal $retireJm.Count 0 'no row ever offers to retire jmoney'
$disableJm = @($all | Where-Object { $_.Fix -and $_.Fix.Do -match 'Disable' -and ($_.Fix.With.Name -ieq 'jmoney') -and $_.Fix.Do -notmatch 'Rule|Task|Service' })
Assert-Equal $disableJm.Count 0 'no row offers any "disable" action for jmoney'
$core = @($all | Where-Object { $_.Fix -and $_.Fix.Do -eq 'New-DisableRuleAction' -and $_.Fix.With.Name -like 'CoreNet-*' })
Assert-Equal $core.Count 0 'no row offers to disable a Core Networking rule'
$prot = @($all | Where-Object { $_.Fix -and ($_.Fix.Do -eq 'New-DisableServiceAction') -and ($_.Fix.With.Name -match 'Jenkins|otel|TermService') })
Assert-Equal $prot.Count 0 'no row offers to disable Jenkins, the log collector or the Remote Desktop service'
$batchBad = @($all | Where-Object { $_.Batch -and $_.Fix -and $_.Fix.Do -match '^(Request-|New-ConfirmAdmin|New-DemoteJmoney|New-ExtendDeadMan|New-DisarmDeadMan|New-DisableServiceAction|New-DisableTaskAction)' -and $_.Fix.Do -ne 'Request-RetireAccount' -and $_.Fix.Do -ne 'Request-RestrictRdp' })
Assert-Equal $batchBad.Count 0 'rows that need your own judgement (passwords, names, Keep changes, hunt items) are never in a batch'
$retireNoBlock = @($all | Where-Object { $_.Fix -and $_.Fix.Do -eq 'Request-RetireAccount' -and $_.Fix.With.Name -ieq 'plinktern' -and $_.Blocked -eq '' })
$unconfirmed = @($scenarios[0].Rows | Where-Object { $_.Fix -and $_.Fix.Do -eq 'Request-RetireAccount' -and $_.Fix.With.Name -ieq 'plinktern' -and $_.Blocked -eq '' })
Assert-Equal $unconfirmed.Count 0 'plinktern is never unblocked while the new admin is unconfirmed'
Assert-True ($retireNoBlock.Count -ge 1) 'but it is unblocked once the new admin is confirmed'
$text = ($all | ForEach-Object { $_.Why + ' ' + $_.Subject }) -join "`n"
Assert-True ($text -notmatch 'H00ves0nTheM00n|Sauce4Life|Helpdesk1!|Password1|Backup2026|AdminPw1') 'no known lab password appears in any row text'

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-TestSummary
