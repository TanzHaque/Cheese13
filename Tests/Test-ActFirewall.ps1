# Test-ActFirewall.ps1 - the firewall ACTIONS (lib\Act-Firewall.ps1 and lib\DeadMan.ps1) through the real gate, Invoke-Change,
# against the pretend Windows box. It proves: nothing runs without the dead-man switch, nothing cuts the scored ports,
# other rules are disabled (never deleted), every change can be undone, and the Core Networking / HP-only guards hold.
# It does NOT prove that real Windows enforces the rules the way the fake's Test-PortReachable does.
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
. "$PSScriptRoot\..\lib\Act-Firewall.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-actfw-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl

# ---- hooks: answers are scripted, nothing waits for a human
$script:Asked = New-Object System.Collections.ArrayList
$script:Notices = New-Object System.Collections.ArrayList
$script:TextQueue = New-Object System.Collections.Queue
$script:AskAnswer = $true
$script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $script:AskAnswer }
$script:Hp.Notify = { param($Title, $Text) [void]$script:Notices.Add("$Title : $Text") }
$script:Hp.AskText = { param($Prompt, $Default) $null = $Prompt; if ($script:TextQueue.Count) { $script:TextQueue.Dequeue() } else { $Default } }
$script:Hp.AllowChanges = $true

# ---- what a scoring engine would experience, worked out from the pretend firewall
function Test-PortReachable {
    param([int]$Port)
    foreach ($p in $global:FW.FwProfiles.Values) {
        if ($p.Enabled -ne 'True') { continue }
        $rules = @($global:FW.FwRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' -and ($_.Profile -eq 'Any' -or $_.Profile -like "*$($p.Name)*") })
        $covers = { param($r, $want) ($r.Protocol -eq 'TCP' -or $r.Protocol -eq 'Any') -and ($r.LocalPort -eq 'Any' -or $r.LocalPort -eq "$want") }
        if (@($rules | Where-Object { $_.Action -eq 'Block' -and (& $covers $_ $Port) }).Count -gt 0) { return $false }
        if ($p.DefaultInboundAction -eq 'Allow') { continue }
        if ($p.AllowInboundRules -ne 'True') { return $false }
        if (@($rules | Where-Object { $_.Action -eq 'Allow' -and (& $covers $_ $Port) -and $_.RemoteAddress -eq 'Any' }).Count -eq 0) { return $false }
    }
    $true
}
function Get-FwRule { param([string]$Name) @($global:FW.FwRules | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1 }
function Get-FwSnapshot {
    # the firewall state the undo handlers must bring back (the tool's own HP-* rules are left out: Undo disables them, never deletes them)
    $rules = @($global:FW.FwRules | Where-Object { $_.Name -notlike 'HP-*' } | ForEach-Object { "$($_.Name)=$($_.Enabled)" } | Sort-Object)
    $profiles = @($global:FW.FwProfiles.Keys | ForEach-Object { $p = $global:FW.FwProfiles[$_]; "$_=$($p.Enabled),$($p.DefaultInboundAction),$($p.DefaultOutboundAction),$($p.AllowInboundRules),$($p.LogBlocked)" })
    ($rules + $profiles) -join '|'
}
function Get-JournalCount { @(Get-JournalRecords).Count }

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The gate: audit mode and the dead-man switch' -ForegroundColor Cyan
Assert-True ((Test-PortReachable 3389) -and (Test-PortReachable 8080)) 'to start with, both scored ports are reachable (the built-in rules)'
$script:Hp.AllowChanges = $false
$r = Invoke-Change (New-AllowPortAction -Port 3389) -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and $r.Message -match 'Audit mode') 'audit mode: "Allow changes" is off -> blocked'
$script:Hp.AllowChanges = $true
$r = Invoke-Change (New-AllowPortAction -Port 3389) -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and $r.Message -match 'not armed') 'dead-man switch not armed -> a firewall change is blocked'
Assert-True ($null -eq (Get-FwRule 'HP-Allow-TCP-3389') -and (Get-JournalCount) -eq 0) 'and nothing was created, nothing was journalled'
Assert-Equal $script:Asked.Count 0 'and you were not even asked (the gate comes before the question)'

Write-Host 'Arming the dead-man switch' -ForegroundColor Cyan
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-Equal $r.Status 'Applied' 'arming works'
$st = Get-DeadManStatus
Assert-True ($st.Armed -and $st.SecondsLeft -gt 240 -and $st.SecondsLeft -le 300) "armed, about 5 minutes left ($($st.SecondsLeft) s)"
Assert-True ($global:FW.Tasks2.ContainsKey('NetCacheRestore')) 'the SYSTEM restore task is registered'
Assert-True ($global:FW.Tasks2['NetCacheRestore'].Principal.UserId -eq 'NT AUTHORITY\SYSTEM' -and $global:FW.Tasks2['NetCacheRestore'].Action.Argument -match 'Panic\.ps1.* -FromTask') 'it runs as SYSTEM and calls Panic.ps1 -FromTask'
Assert-True (Test-Path (Get-DeadManPaths).Export) 'the known-good firewall export was saved'
Assert-True (Test-Path (Get-DeadManPaths).Panic) 'a private copy of Panic.ps1 sits next to it'
$exportBefore = [IO.File]::ReadAllText((Get-DeadManPaths).Export)
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and ((Get-DeadManStatus).Armed)) 'arming twice only extends it'
Assert-Equal ($global:FW.Calls | Where-Object { $_ -like 'netsh advfirewall export*' }).Count 1 'and the known-good export is NOT taken again (it could already be broken)'
Assert-Equal ([IO.File]::ReadAllText((Get-DeadManPaths).Export)) $exportBefore 'the saved export is unchanged'

Write-Host 'Nothing may touch the firewall before the HP allow rules exist' -ForegroundColor Cyan
$snap0 = Get-FwSnapshot
$before = Get-JournalCount
$r = Invoke-Change (New-DisableRuleAction -Name 'Legacy FTP') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'own allow rule for TCP 3389') 'disabling another rule is refused'
$r = Invoke-Change (New-FirewallBaselineAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'own allow rule') 'the profile baseline is refused'
$r = Invoke-Change (New-OutboundDenyAction -Net '172.16.5.0/24') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'own allow rule') 'outbound deny is refused'
Assert-Equal (Get-FwSnapshot) $snap0 'the firewall is exactly as it was'
Assert-Equal (Get-JournalCount) $before 'and a refused change leaves no journal record (it was refused while reading the old state)'

Write-Host 'The allow rules for 3389 and 8080' -ForegroundColor Cyan
$a = New-AllowPortAction -Port 3389
Assert-True ($a.NeedsDeadMan -and $a.Risk -eq 'Medium' -and $a.UndoKind -eq 'fw.allow') 'the action is flagged: needs the dead-man switch, has an undo'
Assert-True (($a.Will -join ' ') -match 'ALL source addresses') 'and the preview says there is no source restriction'
$r = Invoke-Change $a -Confirmed
Assert-Equal $r.Status 'Applied' 'rule for 3389 created'
$rule = Get-FwRule 'HP-Allow-TCP-3389'
Assert-True ($rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow' -and $rule.Protocol -eq 'TCP' -and $rule.LocalPort -eq '3389' -and $rule.RemoteAddress -eq 'Any' -and $rule.Profile -eq 'Any') 'inbound, allow, TCP, port 3389, ANY source, ANY profile'
Assert-True ($rule.DisplayName -eq 'HP Allow TCP 3389' -and $rule.Enabled -eq 'True') 'display name and enabled'
$r = Invoke-Change (New-AllowPortAction -Port 8080) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FwRule 'HP-Allow-TCP-8080').LocalPort -eq '8080') 'rule for 8080 created'
$count = @($global:FW.FwRules).Count
$r = Invoke-Change (New-AllowPortAction -Port 3389) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and @($global:FW.FwRules).Count -eq $count) 'running it again rebuilds the rule instead of adding a second one'
$f = Get-HpFacts
$rows = @(Get-HpFindings -Facts $f -Phases 4)
Assert-True ((@($rows | Where-Object { $_.Area -eq 'Allow rules' -and $_.Severity -eq 'OK' }).Count) -eq 2) 'the judge now shows both allow rules green'
$rec = Get-JournalRecords | Select-Object -Last 1
Assert-True ($rec.ActionId -eq 'fw.allow:3389' -and $rec.Status -eq 'applied' -and $rec.NeedsDeadMan -eq $true -and $rec.Before.Existed -eq $true) 'the journal remembers: rule existed before the rebuild'

Write-Host 'Undo of an allow rule disables it, never deletes it' -ForegroundColor Cyan
$id = [int]$rec.Id
$r = Undo-Change -Id $id -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-FwRule 'HP-Allow-TCP-3389').Enabled -eq 'False') 'undo: the HP rule is disabled'
Assert-True ($null -ne (Get-FwRule 'HP-Allow-TCP-3389')) 'and still exists'
Assert-True ((Test-PortReachable 3389)) 'port 3389 is still reachable (the older built-in rule is still on)'
$rows = @(Get-HpFindings -Facts (Get-HpFacts -Sections 'Firewall' -Previous $f) -Phases 4)
Assert-True ((@($rows | Where-Object { $_.Subject -eq 'Inbound TCP 3389: no HP allow rule' }).Count) -eq 1) 'and the judge shows 3389 as missing again (a disabled HP rule does not count)'
$r = Invoke-Change (New-AllowPortAction -Port 3389) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FwRule 'HP-Allow-TCP-3389').Enabled -eq 'True') 'applying again re-creates it, enabled'
$r = Undo-Change -Id $id
Assert-Equal $r.Status 'Failed' 'undoing the same change twice is refused ("only an applied change can be undone")'

Write-Host 'Disabling other inbound rules' -ForegroundColor Cyan
$snap1 = Get-FwSnapshot
$a = New-DisableRuleAction -Name 'Legacy FTP'
Assert-True ($a.NeedsDeadMan -and $a.UndoKind -eq 'fw.disable' -and $a.Risk -eq 'Low') 'flagged for the dead-man switch, with an undo'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FwRule 'Legacy FTP').Enabled -eq 'False') 'Legacy FTP is disabled'
Assert-True ($null -ne (Get-FwRule 'Legacy FTP')) 'and NOT deleted'
Assert-True (@($global:FW.Calls | Where-Object { $_ -like 'Remove-NetFirewallRule*Legacy*' }).Count -eq 0) 'no Remove-NetFirewallRule call for it'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and (Get-FwRule 'Legacy FTP').Enabled -eq 'True') 'Undo last: enabled again'
Assert-Equal (Get-FwSnapshot) $snap1 'the firewall is exactly as before'

$r = Invoke-Change (New-DisableRuleAction -Name 'CoreNet-DHCP-In') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Core Networking' -and (Get-FwRule 'CoreNet-DHCP-In').Enabled -eq 'True') 'a Core Networking rule is refused'
$r = Invoke-Change (New-DisableRuleAction -Name 'CoreNet-IPHTTPS-In') -Confirmed
Assert-True ($r.Status -eq 'Failed') 'also by its group, not just by its name'
$r = Invoke-Change (New-DisableRuleAction -Name 'HP-Allow-TCP-3389') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'tool''s own rules' -and (Get-FwRule 'HP-Allow-TCP-3389').Enabled -eq 'True') 'the tool''s own HP rules cannot be disabled by this action'
$r = Invoke-Change (New-DisableRuleAction -Name 'No Such Rule') -Confirmed
Assert-Equal $r.Status 'Failed' 'a rule that does not exist fails cleanly'
$r = Invoke-Change (New-DisableRuleAction -Name 'GpoDeliveredRule') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and (Get-FwRule 'GpoDeliveredRule').Enabled -eq 'True') 'a rule that comes from Group Policy cannot be changed here'

# wildcard characters in a rule name: only the rule with exactly that name may be touched
New-NetFirewallRule -Name 'Odd [rule]' -DisplayName 'Odd [rule]' -Direction Inbound -Protocol TCP -LocalPort 7777 -Action Allow | Out-Null
New-NetFirewallRule -Name 'Odd r' -DisplayName 'Odd r' -Direction Inbound -Protocol TCP -LocalPort 7778 -Action Allow | Out-Null
$r = Invoke-Change (New-DisableRuleAction -Name 'Odd [rule]') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FwRule 'Odd [rule]').Enabled -eq 'False' -and (Get-FwRule 'Odd r').Enabled -eq 'True') 'a name with [ ] disables only that rule, not the ones the pattern would match'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and (Get-FwRule 'Odd [rule]').Enabled -eq 'True') 'and undo re-enables exactly it'

# cancel at the question
$script:AskAnswer = $false
$n = Get-JournalCount
$r = Invoke-Change (New-DisableRuleAction -Name 'Telnet Test')
Assert-True ($r.Status -eq 'Cancelled' -and (Get-FwRule 'Telnet Test').Enabled -eq 'True' -and (Get-JournalCount) -eq $n) 'answering No: nothing changes, nothing is journalled'
Assert-True ($script:Asked[-1].Text -match 'NOT deleted' -and $script:Asked[-1].Text -match 'Undo: available') 'and the question said what would happen and that undo exists'
$script:AskAnswer = $true

Write-Host 'The three profiles' -ForegroundColor Cyan
$global:FW.FwProfiles['Public'].DefaultInboundAction = 'Allow'
$global:FW.FwProfiles['Domain'].Enabled = 'False'
$global:FW.FwProfiles['Private'].AllowInboundRules = 'False'
$snap2 = Get-FwSnapshot
Assert-True ((Test-PortReachable 3389) -eq $false) 'before: the "block all inbound" switch on Private cuts the port'
$r = Invoke-Change (New-FirewallBaselineAction) -Confirmed
Assert-Equal $r.Status 'Applied' 'baseline applied'
Assert-True ($r.Output -match 'All three profiles are on') 'and verified in the active store'
$p = $global:FW.FwProfiles
Assert-True ($p['Domain'].Enabled -eq 'True' -and $p['Public'].DefaultInboundAction -eq 'Block' -and $p['Private'].AllowInboundRules -eq 'True') 'Domain on, Public inbound Block, Private honours allow rules'
Assert-True ((Test-PortReachable 3389) -and (Test-PortReachable 8080)) 'both scored ports are still reachable with inbound default Block (the HP rules do it)'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and (Get-FwSnapshot) -eq $snap2) 'undo restores each profile exactly as it was'
$global:FW.GpoProfile = @{ Public = @{ DefaultInboundAction = 'Allow' } }
$r = Invoke-Change (New-FirewallBaselineAction) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $r.Output -match 'Group Policy overrides' -and $r.Output -match 'Public') 'when Group Policy overrides a profile the result says so instead of claiming success'
$rows = @(Get-HpFindings -Facts (Get-HpFacts -Sections 'Firewall' -Previous $f) -Phases 4)
Assert-True ((@($rows | Where-Object { $_.Subject -like 'Group Policy overrides the Public*' }).Count) -eq 1) 'and the judge shows the override as a warning row'
$global:FW.GpoProfile = $null

Write-Host 'Dropped-connection logging' -ForegroundColor Cyan
$snap3 = Get-FwSnapshot
$r = Invoke-Change (New-FirewallLoggingAction) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.FwProfiles['Public'].LogBlocked -eq 'True' -and $global:FW.FwProfiles['Domain'].LogAllowed -eq 'False' -and $global:FW.FwProfiles['Private'].LogMaxSizeKilobytes -eq 16384) 'blocked connections are logged, allowed ones are not, 16 MB'
Assert-True ((New-FirewallLoggingAction).NeedsDeadMan -eq $false) 'logging does not need the dead-man switch (it cannot cut a connection)'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone' -and (Get-FwSnapshot) -eq $snap3 -and $global:FW.FwProfiles['Private'].LogMaxSizeKilobytes -eq 4096) 'undo puts the old logging settings back'

Write-Host 'The firewall service' -ForegroundColor Cyan
$global:FW.FwServiceStopped = $true
$rows = @(Get-HpFindings -Facts (Get-HpFacts -Sections 'Firewall' -Previous $f) -Phases 4)
Assert-True ((@($rows | Where-Object { $_.Subject -eq 'Firewall service is not running' }).Count) -eq 1) 'the judge notices a stopped firewall service'
$r = Invoke-Change (New-StartFirewallServiceAction) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-Service -Name mpssvc).Status -eq 'Running' -and (Get-Service -Name mpssvc).StartType -eq 'Automatic') 'service set to Automatic and started'
$global:FW.FwServiceMissing = $true
$r = Invoke-Change (New-StartFirewallServiceAction) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'old state') 'a missing service fails cleanly before anything is changed'
$global:FW.FwServiceMissing = $false

Write-Host 'Outbound default-deny' -ForegroundColor Cyan
$script:TextQueue.Enqueue('banana')
$a = Request-OutboundDeny
Assert-True ($null -eq $a -and $script:Notices[-1] -match '172\.16\.5\.0/24') 'a network that is not written like 172.16.5.0/24 is refused with a hint'
$script:TextQueue.Enqueue('')
Assert-True ($null -eq (Request-OutboundDeny)) 'an empty answer cancels'
$a = Request-OutboundDeny
Assert-True ($a.Data.Net -eq '172.16.5.0/24') 'the default is the team network worked out from this box''s address'
Assert-True ($a.Risk -eq 'High' -and $a.TypeWord -eq 'OUTBOUND' -and $a.NeedsDeadMan) 'high risk: you must type OUTBOUND, and the dead-man switch is required'
$snap4 = Get-FwSnapshot
$script:Asked.Clear()
$r = Invoke-Change $a -Confirmed
Assert-True ($script:Asked.Count -eq 1 -and $script:Asked[0].Word -eq 'OUTBOUND') 'even when the batch dialog already asked, a High-risk change asks again with the typed word'
Assert-Equal $r.Status 'Applied' 'outbound deny applied'
foreach ($n in 'Domain', 'Private', 'Public') { Assert-Equal $global:FW.FwProfiles[$n].DefaultOutboundAction 'Block' "$n : outbound default is Block" }
$t = Get-FwRule 'HP-Out-TeamNet'
Assert-True ($t.Direction -eq 'Outbound' -and $t.Action -eq 'Allow' -and $t.RemoteAddress -eq '172.16.5.0/24') 'allow rule: everything to the team network (blackbox port 22 and the log collector are in it)'
Assert-True ((Get-FwRule 'HP-Out-DNS-UDP').Protocol -eq 'UDP' -and (Get-FwRule 'HP-Out-DNS-UDP').RemotePort -eq '53' -and (Get-FwRule 'HP-Out-DNS-TCP').Protocol -eq 'TCP' -and (Get-FwRule 'HP-Out-NTP').RemotePort -eq '123') 'allow rules for DNS (UDP+TCP 53) and NTP (UDP 123)'
Assert-True ((Test-PortReachable 3389) -and (Test-PortReachable 8080)) 'inbound scoring is unaffected'
$rows = @(Get-HpFindings -Facts (Get-HpFacts -Sections 'Firewall' -Previous $f) -Phases 4)
Assert-True ((@($rows | Where-Object { $_.Subject -eq 'Outbound default is Block' -and $_.Severity -eq 'OK' }).Count) -eq 1) 'the judge shows outbound green'
$r = Undo-LastChange
Assert-True ($r.Status -eq 'Undone') 'undo outbound deny'
foreach ($n in 'Domain', 'Private', 'Public') { Assert-Equal $global:FW.FwProfiles[$n].DefaultOutboundAction 'Allow' "$n : outbound default is Allow again" }
Assert-True ((Get-FwRule 'HP-Out-TeamNet').Enabled -eq 'False' -and (Get-FwRule 'HP-Out-NTP').Enabled -eq 'False') 'and the outbound allow rules are disabled, not deleted'
Assert-Equal (Get-FwSnapshot) $snap4 'the firewall state matches the snapshot from before'

Write-Host 'Dead-man timing' -ForegroundColor Cyan
$r = Invoke-Change (New-ExtendDeadManAction -Minutes 5) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-DeadManStatus).SecondsLeft -gt 240) 'extend: five minutes from now again'
Save-DeadManState -When (Get-Date).AddSeconds(30) -Minutes 1
$r = Invoke-Change (New-DisableRuleAction -Name 'Telnet Test') -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and $r.Message -match 'fires in' -and (Get-FwRule 'Telnet Test').Enabled -eq 'True') 'with less than a minute left a firewall change is blocked ("Extend it first")'
Save-DeadManState -When (Get-Date).AddMinutes(5) -Minutes 5
$global:FW.Tasks2.Remove('NetCacheRestore')
$r = Invoke-Change (New-DisableRuleAction -Name 'Telnet Test') -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and (Get-DeadManStatus).Note -match 'MISSING') 'if somebody deletes the restore task the switch counts as NOT armed'
$r = Invoke-Change (New-ArmDeadManAction -Minutes 5) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-DeadManStatus).Armed -and $global:FW.Tasks2.ContainsKey('NetCacheRestore')) 'arming again re-creates the task'

Write-Host 'A forged journal record cannot make undo touch a rule that is not ours' -ForegroundColor Cyan
$forged = [ordered]@{ Id = 900; Time = '2026-10-17 10:00:00'; ActionId = 'fw.allow:forged'; Title = 'forged'; Risk = 'Low'; Will = @(); UndoKind = 'fw.allow'; NoUndo = ''
                      NeedsDeadMan = $false; Data = @{ Name = 'CoreNet-DHCP-In'; Port = 68 }; Before = @{ Existed = $true }; Status = 'applied'; Error = '' }
Save-JournalRecord $forged
$r = Undo-Change -Id 900 -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'not one of the tool''s own rules' -and (Get-FwRule 'CoreNet-DHCP-In').Enabled -eq 'True') 'undo of a forged record that names a Core Networking rule is refused'
$forged.Id = 901; $forged.UndoKind = 'fw.outbound'; $forged.Before = @{ Profiles = @() }
Save-JournalRecord $forged
$r = Undo-Change -Id 901 -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-FwRule 'CoreNet-DHCP-In').Enabled -eq 'True') 'the outbound undo only ever touches HP-Out-* names'

Write-Host 'Keep changes (disarm)' -ForegroundColor Cyan
$a = New-DisarmDeadManAction
Assert-True ($a.UndoKind -eq '' -and -not $a.NeedsDeadMan) 'disarming has no undo and does not need the switch itself'
$r = Invoke-Change $a -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not (Get-DeadManStatus).Armed -and -not $global:FW.Tasks2.ContainsKey('NetCacheRestore')) 'the restore task is gone and the switch is off'
Assert-True (Test-Path (Get-DeadManPaths).Export) 'the known-good export stays on disk'
$r = Invoke-Change (New-DisableRuleAction -Name 'Telnet Test') -Confirmed
Assert-Equal $r.Status 'Blocked' 'and firewall changes are blocked again until it is re-armed'

Write-Host 'No secret, no password anywhere in the log or the journal' -ForegroundColor Cyan
$all = (Microsoft.PowerShell.Management\Get-ChildItem -Path $tmp -Recurse -File | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
Assert-True ($all -notmatch 'H00ves0nTheM00n|Sauce4Life') 'and no lab password'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'End to end: walk the Fix list of phase 4 on a fresh box, then undo everything' -ForegroundColor Cyan
$global:FW = New-FakeBox
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Initialize-Hp -DataDir $tmp -NoAcl
$script:Hp.Ask = { param($Title, $Text, $TypeWord) $null = $Title, $Text, $TypeWord; $true }
$script:Hp.AllowChanges = $true
$start = Get-FwSnapshot
$facts = Get-HpFacts
$tried = @{}
$steps = 0
$cut = @()
while ($steps -lt 40) {
    $rows = @(Get-HpFindings -Facts $facts -Phases 4)
    $next = @($rows | Where-Object { $_.Fix -and $_.Blocked -eq '' -and $_.Batch -and ($_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN') -and -not $tried[$_.Key] }) | Select-Object -First 1
    if (-not $next) { break }
    $tried[$next.Key] = $true
    $act = Resolve-Fix $next
    $res = Invoke-Change $act -Confirmed
    $steps++
    if ($res.Status -ne 'Applied') { Write-Host "    step $steps '$($next.Subject)' gave $($res.Status): $($res.Message)" -ForegroundColor Yellow }
    if (-not ((Test-PortReachable 3389) -and (Test-PortReachable 8080))) { $cut += $next.Subject }
    $facts = Get-HpFacts -Sections (Get-SectionsForAction $act.Id) -Previous $facts
}
Assert-True ($steps -ge 9) "the walk made $steps changes in the order the judge offered them"
Assert-Equal $cut.Count 0 "after EVERY step both scored ports stayed reachable $(if ($cut.Count) { '(cut by: ' + ($cut -join '; ') + ')' })"
$rows = @(Get-HpFindings -Facts $facts -Phases 4)
Assert-True ($rows[0].Subject -match 'Dead-man' -or (@($rows | Where-Object { $_.Subject -like 'Dead-man switch is armed' }).Count) -eq 1) 'the dead-man switch got armed first (nothing else could run before it)'
Assert-Equal @($rows | Where-Object { $_.Area -eq 'Allow rules' -and $_.Severity -eq 'OK' }).Count 2 'both allow rules are green'
Assert-Equal @($rows | Where-Object { $_.Area -eq 'Other inbound rules' -and $_.Fix }).Count 0 'every other inbound rule that could be disabled was disabled'
Assert-True (@($rows | Where-Object { $_.Area -eq 'Profiles' -and $_.Severity -ne 'OK' }).Count -eq 0) 'profiles are green and logging is on'
$left = @($rows | Where-Object { ($_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN') })
Assert-True ($left.Count -eq 2 -and (@($left | Where-Object { $_.Area -eq 'Outbound' }).Count -eq 1) -and (@($left | Where-Object { $_.Subject -like 'GpoDeliveredRule*' }).Count -eq 1)) 'what is left: outbound (your own decision) and the rule Group Policy delivers (cannot be changed here)'
Assert-True (@($global:FW.FwRules | Where-Object { $_.Name -eq 'Legacy FTP' }).Count -eq 1) 'nothing was deleted: the old rules are still in the list'
Assert-True ((@($global:FW.FwRules | Where-Object { $_.Name -like 'CoreNet-*' -and $_.Enabled -ne 'True' }).Count) -eq 0) 'Core Networking rules are all still enabled'
Assert-True (@($global:FW.Calls | Where-Object { $_ -like 'Remove-NetFirewallRule*' }).Count -eq 0) 'no firewall rule was removed at all in this walk'

# now everything back
$undone = 0
while ($undone -lt 60) {
    $r = Undo-LastChange
    if ($r.Status -ne 'Undone') { break }
    $undone++
}
Assert-True ($undone -ge 8) "Undo last, repeated, undid $undone changes"
Assert-Equal (Get-FwSnapshot) $start 'and the firewall is exactly as it was found (rules and all three profiles)'
Assert-True ((Test-PortReachable 3389) -and (Test-PortReachable 8080)) 'scored ports are reachable'

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-TestSummary
