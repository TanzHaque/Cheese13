# JudgeFirewall.ps1 - phase 4: the Windows firewall. Reads facts, returns findings, in the order you should fix them:
#   1. the firewall service   2. the dead-man switch   3. allow rules for 3389 and 8080   4. the three profiles
#   5. every other inbound allow rule   6. outbound   7. "Keep changes"
# The plan's rules: inbound default BLOCK; allow 3389 and 8080 with NO source restrictions (the scoring engine comes from
# many addresses); DISABLE (never delete) the other inbound allow rules; keep Core Networking; outbound deny comes last.
# Windows PowerShell 5.1, plain ASCII.

$script:AllProfiles = @('Domain', 'Private', 'Public')

function Test-RuleCoversPort {
    # Does this rule apply to TCP traffic coming in to this local port?
    param($Rule, [int]$Port)
    if ($Rule.Protocol -ne 'TCP' -and $Rule.Protocol -ne 'Any' -and $Rule.Protocol -ne '6') { return $false }
    foreach ($p in (Get-List $Rule.LocalPort)) {
        if ($p -eq 'Any' -or $p -eq '*') { return $true }
        if ($p -match '^\d+$' -and [int]$p -eq $Port) { return $true }
        if ($p -match '^(\d+)-(\d+)$' -and $Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }
    }
    $false
}

function Test-AddressAny {
    # True when the rule lets in traffic from ANY address (no source restriction).
    param($Rule)
    $addr = Get-List $Rule.RemoteAddress
    if ($addr.Count -eq 0) { return $true }
    @($addr | Where-Object { $_ -ne 'Any' -and $_ -ne '*' }).Count -eq 0
}

function Get-RuleProfiles {
    # The profiles a rule is active on: 'Any' means all three.
    param($Rule)
    $p = [string]$Rule.Profile
    if ($p -eq '' -or $p -eq 'Any' -or $p -eq 'All') { return $script:AllProfiles }
    @($p -split '[,\s]+' | Where-Object { $_ })
}

function Test-CoreNetworkingRule {
    # Core Networking (DHCP, DNS, IPv6 neighbour discovery...) must stay. The group id works in every language.
    param($Rule)
    ([string]$Rule.DisplayGroup -eq 'Core Networking') -or ([string]$Rule.Group -like '*FirewallAPI.dll,-25000*') -or ([string]$Rule.Name -like 'CoreNet-*')
}

function Get-PortCoverage {
    # For one scored port: the allow rules that let everyone in, the ones that exist but are limited to some addresses,
    # and the profiles that are covered.
    param($Rules, [int]$Port)
    $good = @(); $limited = @(); $covered = @{}
    foreach ($r in $Rules) {
        if ($r.Action -ne 'Allow' -or -not (Test-RuleCoversPort $r $Port)) { continue }
        if (-not (Test-AddressAny $r)) { $limited += $r; continue }
        $good += $r
        foreach ($p in (Get-RuleProfiles $r)) { $covered[$p] = $true }
    }
    [pscustomobject]@{ Port = $Port; Good = $good; Limited = $limited; Covered = @($covered.Keys); All = (@($script:AllProfiles | Where-Object { -not $covered[$_] }).Count -eq 0) }
}

function Get-FirewallFindings {
    param($Facts, $Settings)
    $fw = $Facts.Firewall
    if (-not $fw) { return @(New-Finding 4 'Firewall' 'WARN' 'The firewall could not be read' 'The firewall collector failed; see the Recon phase for the error.') }
    $rules = Get-List $fw.Rules
    # The tool relies on its OWN allow rules ("HP Allow TCP 3389" and "HP Allow TCP 8080"): nobody else's rule can be
    # trusted to stay. Other rules that also cover the ports are only mentioned.
    $ours = @($rules | Where-Object { [string]$_.DisplayName -like 'HP *' })
    $theirs = @($rules | Where-Object { [string]$_.DisplayName -notlike 'HP *' })
    $cover = @{}
    foreach ($port in $script:Plan.RdpPort, $script:Plan.JenkinsPort) {
        $c = Get-PortCoverage $ours $port
        $c | Add-Member -NotePropertyName Others -NotePropertyValue (Get-PortCoverage $theirs $port) -PassThru | Out-Null
        $cover[$port] = $c
    }
    $allowOk = ($cover[$script:Plan.RdpPort].All -and $cover[$script:Plan.JenkinsPort].All)

    $out = @()
    $out += Get-FirewallServiceFindings $fw
    $out += Get-DeadManFindings $Facts $Settings
    $out += Get-AllowRuleFindings $rules $cover
    $out += Get-ProfileFindings $fw $allowOk
    $out += Get-OtherRuleFindings $rules $allowOk
    $out += Get-OutboundFindings $Facts $fw $Settings $allowOk
    $bad = @($out | Where-Object { $_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN' }).Count
    if ($Facts.DeadMan -and $Facts.DeadMan.Armed -and $bad -eq 0) {
        $out += New-Finding 4 'Safety net' 'INFO' 'Everything is in place: Keep changes?' 'All firewall rows are green. Check that NEIGH shows RDP and Jenkins green for two cycles, and trigger rocket-build once and see SUCCESS. Only then press Keep changes: it removes the dead-man task.' (New-FixRef 'New-DisarmDeadManAction') -Batch $false
    }
    $out
}

function Get-FirewallServiceFindings {
    param($Fw)
    if ($Fw.ServiceState -eq 'Running') { return @() }
    if ($Fw.ServiceState -eq 'Missing') { return @(New-Finding 4 'Firewall' 'BAD' 'Firewall service not found' 'The Windows Defender Firewall service (mpssvc) does not exist on this box. Something removed it.') }
    @(New-Finding 4 'Firewall' 'BAD' 'Firewall service is not running' "The Windows Defender Firewall service (mpssvc) is $($Fw.ServiceState): no firewall rule is enforced. Start it and set it to Automatic." (New-FixRef 'New-StartFirewallServiceAction'))
}

function Get-DeadManFindings {
    param($Facts, $Settings)
    $dm = $Facts.DeadMan
    if (-not $dm) { return @() }
    $minutes = [int]$Settings.DeadManMinutes
    if ($dm.Armed) {
        return @(New-Finding 4 'Safety net' 'INFO' 'Dead-man switch is armed' "$($dm.Note). If you are still working, extend it; if the firewall breaks something, do nothing: it restores the saved policy." (New-FixRef 'New-ExtendDeadManAction' @{ Minutes = $minutes }) -Batch $false)
    }
    if ($dm.FiredAt) {
        return @(New-Finding 4 'Safety net' 'WARN' "Dead-man switch FIRED at $($dm.FiredAt)" 'It put the saved firewall policy back because it was not disarmed in time. Find out what the last change broke before you change the firewall again. Arm it to continue.' (New-FixRef 'New-ArmDeadManAction' @{ Minutes = $minutes }))
    }
    @(New-Finding 4 'Safety net' 'WARN' 'Dead-man switch is not armed' "The tool refuses every firewall change until it is armed. Arming saves the current policy and schedules a restore in $minutes minutes unless you press Keep changes." (New-FixRef 'New-ArmDeadManAction' @{ Minutes = $minutes }))
}

function Get-AllowRuleFindings {
    param($Rules, $Cover)
    $out = @()
    foreach ($port in $script:Plan.RdpPort, $script:Plan.JenkinsPort) {
        $c = $Cover[$port]
        if ($c.Good.Count -gt 0 -and $c.All) {
            $out += New-Finding 4 'Allow rules' 'OK' "Inbound TCP $port is allowed" "The tool's own rule: $(($c.Good | ForEach-Object { $_.DisplayName }) -join ', '). Any source address, all three profiles."
            continue
        }
        $why = "The tool's own allow rule for TCP $port (any source, all profiles) is missing or not complete."
        $missing = @($script:AllProfiles | Where-Object { $c.Covered -notcontains $_ })
        if ($c.Good.Count -gt 0 -and $missing.Count -gt 0) { $why += " Profiles without it: $($missing -join ', ')." }
        if ($c.Limited.Count -gt 0) { $why += " Its own rule is limited to some source addresses: $(($c.Limited | ForEach-Object { $_.DisplayName }) -join ', ') (the scoring engine uses many addresses)." }
        if ($c.Others.Good.Count -gt 0) { $why += " Other rules currently let the port in: $(($c.Others.Good | ForEach-Object { $_.DisplayName }) -join ', '). Someone else's rule can be removed or changed, so the tool adds its own." }
        $out += New-Finding 4 'Allow rules' 'BAD' "Inbound TCP ${port}: no HP allow rule" $why (New-FixRef 'New-AllowPortAction' @{ Port = $port })
    }
    # a BLOCK rule beats every allow rule
    $seen = @{}
    foreach ($r in $Rules) {
        if ($r.Action -ne 'Block' -or -not (Test-AddressAny $r)) { continue }
        $ports = @($script:Plan.RdpPort, $script:Plan.JenkinsPort | Where-Object { Test-RuleCoversPort $r $_ })
        if ($ports.Count -eq 0 -or $seen.ContainsKey($r.Name)) { continue }
        $seen[$r.Name] = $true
        $fix = $null; $blocked = ''
        if ($r.Local) { $fix = New-FixRef 'New-DisableRuleAction' @{ Name = $r.Name; Label = $r.DisplayName } }
        else { $blocked = 'This rule comes from Group Policy, so it cannot be changed here. Find the GPO (gpresult /h) or the local policy (gpedit.msc).' }
        $out += New-Finding 4 'Allow rules' 'BAD' "Block rule '$($r.DisplayName)' stops port $($ports -join ', ')" 'A block rule always wins over an allow rule. Scoring cannot get through while it is active.' $fix $blocked
    }
    $out
}

function Get-ProfileFindings {
    param($Fw, [bool]$AllowOk)
    $out = @()
    $issues = @()
    foreach ($p in (Get-List $Fw.Profiles)) {
        if (-not $p.Enabled) { $issues += "$($p.Name) profile is OFF" }
        if ($p.In -ne 'Block') { $issues += "$($p.Name): inbound default is $($p.In), not Block" }
        if (-not $p.AllowInboundRules) { $issues += "$($p.Name): all inbound is blocked, even allowed ports" }
    }
    if ($issues.Count -gt 0) {
        $blocked = $(if ($AllowOk) { '' } else { 'Add the allow rules for ports 3389 and 8080 first, or the default block would cut scoring.' })
        $out += New-Finding 4 'Profiles' 'BAD' 'Firewall profiles are not set as planned' "$($issues -join '; '). Planned: all three profiles ON, inbound default Block, inbound allow rules honoured." (New-FixRef 'New-FirewallBaselineAction') $blocked
    } else {
        $out += New-Finding 4 'Profiles' 'OK' 'Firewall profiles' 'All three profiles are on with inbound default Block.'
    }
    foreach ($p in (Get-List $Fw.LocalProfiles)) {
        $eff = (Get-List $Fw.Profiles) | Where-Object { $_.Name -eq $p.Name } | Select-Object -First 1
        if ($eff -and ($eff.Enabled -ne $p.Enabled -or $eff.In -ne $p.In -or $eff.Out -ne $p.Out)) {
            $out += New-Finding 4 'Profiles' 'WARN' "Group Policy overrides the $($p.Name) profile" "The local setting (on=$($p.Enabled), in=$($p.In), out=$($p.Out)) is not what is in force (on=$($eff.Enabled), in=$($eff.In), out=$($eff.Out)). Changes made here will not take effect for those settings. Look at gpresult /h and gpedit.msc."
        }
    }
    $noLog = @((Get-List $Fw.Profiles) | Where-Object { -not $_.LogBlocked })
    if ($noLog.Count -gt 0) {
        $out += New-Finding 4 'Profiles' 'WARN' 'Dropped connections are not logged' "Profiles without dropped-connection logging: $(($noLog | ForEach-Object { $_.Name }) -join ', '). The log shows who knocks on closed ports." (New-FixRef 'New-FirewallLoggingAction')
    }
    $out
}

function Get-OtherRuleFindings {
    param($Rules, [bool]$AllowOk)
    $out = @()
    $scored = @($script:Plan.RdpPort, $script:Plan.JenkinsPort)
    foreach ($r in $Rules) {
        if ($r.Action -ne 'Allow') { continue }
        if (Test-CoreNetworkingRule $r) { continue }
        if ([string]$r.DisplayName -like 'HP *') { continue }
        $ports = Get-List $r.LocalPort
        $onlyScored = ($ports.Count -gt 0) -and (@($ports | Where-Object { $_ -notmatch '^\d+$' -or ($scored -notcontains [int]$_) }).Count -eq 0)
        if ($onlyScored) { continue }                          # a rule for 3389 or 8080 only: that is what we want open
        $portText = $(if ($ports.Count) { $ports -join ',' } else { 'Any' })
        $wide = ($portText -eq 'Any' -and [string]$r.Program -eq 'Any')
        $text = "$($r.DisplayName)  [$($r.Protocol) port $portText, from $((Get-List $r.RemoteAddress) -join ',')]"
        $sev = $(if ($wide) { 'BAD' } else { 'WARN' })
        if ($r.Local) {
            $blocked = $(if ($AllowOk) { '' } else { 'Add the allow rules for ports 3389 and 8080 first.' })
            $out += New-Finding 4 'Other inbound rules' $sev $text 'An inbound allow rule the plan does not need. Disable it (never delete): Undo turns it back on.' (New-FixRef 'New-DisableRuleAction' @{ Name = $r.Name; Label = $r.DisplayName }) $blocked
        } else {
            $out += New-Finding 4 'Other inbound rules' $sev $text 'This allow rule is delivered by Group Policy, so it cannot be disabled here. Change the GPO, or add a block rule if it really must go.'
        }
    }
    $out
}

function Get-OutboundFindings {
    param($Facts, $Fw, $Settings, [bool]$AllowOk)
    $profiles = Get-List $Fw.Profiles
    $open = @($profiles | Where-Object { $_.Out -ne 'Block' })
    if ($profiles.Count -gt 0 -and $open.Count -eq 0) {
        return @(New-Finding 4 'Outbound' 'OK' 'Outbound default is Block' 'Only the allow rules (team network, DNS, NTP) leave this box.')
    }
    $team = Get-TeamInfo -Ips (Get-List $Facts.Host.Ips) -TeamNet ([string]$Settings.TeamNet)
    $now = @(Get-List $Facts.Ports.Connections | Select-Object -First 8 | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) ($($_.Process))" })
    $why = "Outbound is Allow. The plan: log first, watch about 10 minutes, then default-deny with allow rules for the team network $($team.Net) (blackbox port 22 and the log collector), DNS (53) and NTP (123). Connections open right now: $(if ($now.Count) { $now -join '; ' } else { 'none' })."
    $blocked = ''
    $inboundDone = (@($profiles | Where-Object { $_.In -ne 'Block' -or -not $_.Enabled }).Count -eq 0)
    if (-not $AllowOk) { $blocked = 'Add the allow rules for ports 3389 and 8080 first.' }
    elseif (-not $inboundDone) { $blocked = 'Do the inbound baseline first.' }
    elseif (-not $team.Net) { $blocked = 'The team network is unknown: set TeamNet in settings.json.' }
    @(New-Finding 4 'Outbound' 'WARN' 'Outbound default is Allow' $why (New-FixRef 'Request-OutboundDeny') $blocked -Batch $false)
}
