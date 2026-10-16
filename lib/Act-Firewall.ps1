# Act-Firewall.ps1 - phase 4 actions: allow rules for 3389 and 8080, disable other inbound rules, profile baseline, logging,
# outbound default-deny. Every change that could cut a connection is marked NeedsDeadMan, so Invoke-Change refuses it
# unless the dead-man switch is armed (DeadMan.ps1) - the saved firewall policy comes back by itself if you lose access.
#
# The plan's rules, as code:
#   - inbound allow rules for the scored ports have NO source restriction (the scoring engine comes from many addresses)
#   - other inbound allow rules are DISABLED, never deleted (Undo turns them back on); Core Networking is never touched
#   - nothing here may run before the tool's own allow rules for 3389 and 8080 exist (Assert-ScoredPortsAllowed)
#   - the only rules this tool ever removes are its own  HP-*  rules, when it rebuilds them
# Windows PowerShell 5.1, plain ASCII.

function Get-HpRuleName {
    # The fixed internal name of the tool's allow rule for a port:  HP-Allow-TCP-3389
    param([int]$Port)
    "HP-Allow-TCP-$Port"
}

function Assert-OurRule {
    # Guard: this tool only ever removes or rebuilds rules whose name starts with HP-
    param([string]$Name)
    if ($Name -notlike 'HP-*') { throw "Refused: '$Name' is not one of the tool's own rules (HP-...)." }
}

function Assert-ScoredPortsAllowed {
    # A firewall change must never cut scoring: the tool's own allow rules for both ports must exist and be enabled.
    foreach ($port in $script:Plan.RdpPort, $script:Plan.JenkinsPort) {
        $r = Get-NetFirewallRule -Name (Get-HpRuleName $port) -ErrorAction SilentlyContinue
        if (-not $r -or [string]$r.Enabled -ne 'True') {
            throw "Refused: the tool's own allow rule for TCP $port is missing or disabled. Add it first, or this change could cut scoring."
        }
    }
}

function New-OurRule {
    # Creates one of the tool's own allow rules. If a rule with that name exists (someone changed it?) it is rebuilt from scratch.
    param([string]$Name, [string]$DisplayName, [string]$Direction, [string]$Protocol, [string]$LocalPort = '', [string]$RemotePort = '', [string]$RemoteAddress = 'Any', [string]$Description = '')
    Assert-OurRule $Name
    if (Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $Name }
    $ruleArgs = @{
        Name = $Name; DisplayName = $DisplayName; Direction = $Direction; Action = 'Allow'; Profile = 'Any'
        Protocol = $Protocol; RemoteAddress = $RemoteAddress; Description = $Description
    }
    if ($LocalPort) { $ruleArgs['LocalPort'] = $LocalPort }
    if ($RemotePort) { $ruleArgs['RemotePort'] = $RemotePort }
    New-NetFirewallRule @ruleArgs | Out-Null
}

# ---------------------------------------------------------------- the firewall service
function New-StartFirewallServiceAction {
    New-Action -Id 'fw.service' -Title 'Start the Windows Defender Firewall service' -Risk 'Medium' `
        -Will @('Set the service mpssvc to Automatic and start it',
                'The existing rules start to be enforced. If they do not allow 3389 and 8080, scoring fails until you add the HP allow rules (next row)') `
        -Capture { param($d) $null = $d; $s = Get-Service -Name mpssvc -ErrorAction Stop; @{ StartType = [string]$s.StartType; Status = [string]$s.Status } } `
        -Apply {
            param($d, $before)
            $null = $d, $before
            Set-Service -Name mpssvc -StartupType Automatic
            Start-Service -Name mpssvc
            'The firewall service is running.'
        }
}

# ---------------------------------------------------------------- allow 3389 and 8080 (the tool's own rules)
function New-AllowPortAction {
    param([int]$Port)
    $name = Get-HpRuleName $Port
    New-Action -Id "fw.allow:$Port" -Title "Allow inbound TCP $Port from anywhere" -Risk 'Medium' -NeedsDeadMan `
        -Will @("Create the rule 'HP Allow TCP $Port': inbound, TCP, local port $Port, ALL source addresses, all three profiles",
                'No source restriction on purpose: the scoring engine connects from many addresses',
                'An older rule with the same internal name is rebuilt; no other rule is touched') `
        -Data @{ Port = $Port; Name = $name } `
        -Capture { param($d) @{ Existed = [bool](Get-NetFirewallRule -Name $d.Name -ErrorAction SilentlyContinue) } } `
        -Apply {
            param($d, $before)
            $null = $before
            New-OurRule -Name $d.Name -DisplayName "HP Allow TCP $($d.Port)" -Direction 'Inbound' -Protocol 'TCP' -LocalPort ([string]$d.Port) -Description 'HP: scored port, any source'
            $r = Get-NetFirewallRule -Name $d.Name -ErrorAction Stop
            if ([string]$r.Enabled -ne 'True') { throw "The rule $($d.Name) was created but is not enabled." }
            "Inbound TCP $($d.Port) is allowed."
        } `
        -UndoKind 'fw.allow'
}

Register-UndoHandler 'fw.allow' {
    # Undo disables the tool's own rule (it is not deleted).
    param($data, $before)
    $null = $before
    Assert-OurRule $data.Name
    Disable-NetFirewallRule -Name $data.Name
}

# ---------------------------------------------------------------- disable one other inbound rule
function New-DisableRuleAction {
    param([string]$Name, [string]$Label = '')
    $text = $(if ($Label) { $Label } else { $Name })
    New-Action -Id "fw.disable:$Name" -Title "Disable the inbound rule '$text'" -Risk 'Low' -NeedsDeadMan `
        -Will @("Disable the firewall rule '$text' (internal name: $Name). It is NOT deleted; Undo enables it again") `
        -Data @{ Name = $Name; Label = $text } `
        -Capture {
            param($d)
            Assert-ScoredPortsAllowed
            $r = Get-NetFirewallRule -Name ([WildcardPattern]::Escape($d.Name)) -ErrorAction Stop
            if ([string]$r.DisplayName -like 'HP *') { throw 'Refused: this is one of the tool''s own rules.' }
            if (([string]$r.DisplayGroup -eq 'Core Networking') -or ([string]$r.Group -like '*FirewallAPI.dll,-25000*') -or ([string]$r.Name -like 'CoreNet-*')) {
                throw 'Refused: Core Networking rules (DHCP, DNS, IPv6) must stay.'
            }
            @{ Enabled = [string]$r.Enabled }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            $key = [WildcardPattern]::Escape($d.Name)
            Disable-NetFirewallRule -Name $key
            if ([string](Get-NetFirewallRule -Name $key -ErrorAction Stop).Enabled -eq 'True') { throw "The rule '$($d.Name)' is still enabled after Disable-NetFirewallRule." }
            "Disabled '$($d.Label)'."
        } `
        -UndoKind 'fw.disable'
}

Register-UndoHandler 'fw.disable' {
    param($data, $before)
    if ([string]$before.Enabled -eq 'True') { Enable-NetFirewallRule -Name ([WildcardPattern]::Escape($data.Name)) }
}

# ---------------------------------------------------------------- the three profiles
function New-FirewallBaselineAction {
    New-Action -Id 'fw.baseline' -Title 'Firewall baseline: all profiles on, inbound default Block' -Risk 'Medium' -NeedsDeadMan `
        -Will @('Turn the Domain, Private and Public profiles ON',
                'Inbound default action = Block on all three (only allow rules let traffic in)',
                'Honour inbound allow rules on all three (the "block all inbound" switch off)',
                'Outbound stays as it is for now') `
        -Capture {
            param($d)
            $null = $d
            Assert-ScoredPortsAllowed
            @{ Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
                @{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; In = [string]$_.DefaultInboundAction; AllowInboundRules = [string]$_.AllowInboundRules } }) }
        } `
        -Apply {
            param($d, $before)
            $null = $d, $before
            Set-NetFirewallProfile -Name Domain, Private, Public -Enabled True -DefaultInboundAction Block -AllowInboundRules True
            $bad = @(Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block' })
            if ($bad.Count -gt 0) { return "Set, but still not in force on: $(($bad | ForEach-Object { $_.Name }) -join ', ') (Group Policy overrides it?). Check gpresult /h." }
            'All three profiles are on with inbound Block.'
        } `
        -UndoKind 'fw.baseline'
}

Register-UndoHandler 'fw.baseline' {
    param($data, $before)
    $null = $data
    foreach ($p in @($before.Profiles)) {
        Set-NetFirewallProfile -Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.In -AllowInboundRules $p.AllowInboundRules
    }
}

function New-FirewallLoggingAction {
    New-Action -Id 'fw.logging' -Title 'Log dropped connections (all profiles)' -Risk 'Low' `
        -Will @('Write blocked connections to %systemroot%\system32\LogFiles\Firewall\pfirewall.log',
                'Log size 16 MB. Allowed connections are not logged',
                'The log shows who knocks on closed ports') `
        -Capture {
            param($d)
            $null = $d
            @{ Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
                @{ Name = [string]$_.Name; LogBlocked = [string]$_.LogBlocked; LogFileName = [string]$_.LogFileName; LogMaxSizeKilobytes = [uint64]$_.LogMaxSizeKilobytes } }) }
        } `
        -Apply {
            param($d, $before)
            $null = $d, $before
            Set-NetFirewallProfile -Name Domain, Private, Public -LogBlocked True -LogAllowed False -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384
            'Dropped connections are logged.'
        } `
        -UndoKind 'fw.logging'
}

Register-UndoHandler 'fw.logging' {
    param($data, $before)
    $null = $data
    foreach ($p in @($before.Profiles)) {
        Set-NetFirewallProfile -Name $p.Name -LogBlocked $p.LogBlocked -LogFileName $p.LogFileName -LogMaxSizeKilobytes ([uint64]$p.LogMaxSizeKilobytes)
    }
}

# ---------------------------------------------------------------- outbound default-deny (last, after watching)
function Request-OutboundDeny {
    # Asks which network must stay reachable (the team network, worked out from this box's address), then returns the action.
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.IPAddress })
    $team = Get-TeamInfo -Ips $ips -TeamNet ([string](Get-HpSetting 'TeamNet'))
    $net = Read-HpText 'Network that must stay reachable from this box (team network, for example 172.16.5.0/24)' $team.Net
    if (-not $net) { return $null }
    $net = $net.Trim()
    if ($net -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { Show-HpNotice 'Use the form 172.16.5.0/24.' 'Outbound deny'; return $null }
    New-OutboundDenyAction -Net $net
}

function New-OutboundDenyAction {
    param([string]$Net)
    New-Action -Id 'fw.outbound' -Title 'Outbound default-deny' -Risk 'High' -TypeWord 'OUTBOUND' -NeedsDeadMan `
        -Will @("First create these allow rules: all traffic to $Net (blackbox port 22 and the log collector are in it), DNS (TCP+UDP 53), NTP (UDP 123)",
                'Then set the outbound default action to Block on all three profiles',
                'Everything else that leaves this box is dropped: Windows Update, Defender updates, downloads, and a backdoor calling home',
                'Jenkins builds that fetch from the Internet will fail: trigger rocket-build and see SUCCESS before you press Keep changes',
                'If scoring or the log collector breaks, do nothing: the dead-man switch restores the old policy') `
        -Data @{ Net = $Net } `
        -Capture {
            param($d)
            $null = $d
            Assert-ScoredPortsAllowed
            @{ Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { @{ Name = [string]$_.Name; Out = [string]$_.DefaultOutboundAction } }) }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            New-OurRule -Name 'HP-Out-TeamNet' -DisplayName 'HP Out Team Net' -Direction 'Outbound' -Protocol 'Any' -RemoteAddress $d.Net -Description 'HP: team network'
            New-OurRule -Name 'HP-Out-DNS-UDP' -DisplayName 'HP Out DNS UDP' -Direction 'Outbound' -Protocol 'UDP' -RemotePort '53' -Description 'HP: DNS'
            New-OurRule -Name 'HP-Out-DNS-TCP' -DisplayName 'HP Out DNS TCP' -Direction 'Outbound' -Protocol 'TCP' -RemotePort '53' -Description 'HP: DNS'
            New-OurRule -Name 'HP-Out-NTP' -DisplayName 'HP Out NTP' -Direction 'Outbound' -Protocol 'UDP' -RemotePort '123' -Description 'HP: NTP'
            Set-NetFirewallProfile -Name Domain, Private, Public -DefaultOutboundAction Block
            'Outbound is Block. Allowed out: the team network, DNS, NTP.'
        } `
        -UndoKind 'fw.outbound'
}

Register-UndoHandler 'fw.outbound' {
    # Undo sets the outbound default back and disables the tool's allow rules (they are not deleted).
    param($data, $before)
    $null = $data
    foreach ($p in @($before.Profiles)) { Set-NetFirewallProfile -Name $p.Name -DefaultOutboundAction $p.Out }
    foreach ($n in 'HP-Out-TeamNet', 'HP-Out-DNS-UDP', 'HP-Out-DNS-TCP', 'HP-Out-NTP') {
        Assert-OurRule $n
        Disable-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
    }
}
