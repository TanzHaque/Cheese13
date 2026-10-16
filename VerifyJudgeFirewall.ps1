# VerifyJudgeFirewall.ps1 - Verify-Hardening "judges" for the Windows firewall (plan Phase 4).
# PURE functions: plain facts in, result objects out. They touch nothing, so they can be tested anywhere.
#
# Facts expected (collected by VerifyFacts.ps1, from the ACTIVE store = local rules + any GPO rules):
#   $Facts.Profiles       = Name (Domain/Private/Public), Enabled (bool), In, Out ('Block'/'Allow'), LogBlocked (bool)
#   $Facts.ActiveProfiles = names of the profile(s) the network adapters are using right now
#   $Facts.Rules          = ENABLED INBOUND rules:  DisplayName, DisplayGroup, Group, Profile ('Any' or 'Domain, Private'),
#                           Action (Allow/Block), Protocol (TCP/UDP/Any), LocalPort (array), RemoteAddress (array), Program
#   $Facts.OutRules       = ENABLED OUTBOUND rules, same fields plus RemotePort (only collected when an outbound default is Block)

$script:AllProfiles = @('Domain', 'Private', 'Public')

function Get-RuleProfiles {
    # 'Any' -> all three;  'Domain, Private' -> those two
    param([string]$Spec)
    if (-not $Spec -or $Spec -match 'Any|All|NotConfigured') { return $script:AllProfiles }
    $p = @($script:AllProfiles | Where-Object { $Spec -match $_ })
    if ($p.Count -eq 0) { return $script:AllProfiles }      # a number we do not understand: assume all
    $p
}

function Test-PortInSpec {
    # Does a rule's LocalPort list ('Any', '3389', '8000-8100') cover this port? Names like RPC never match.
    param([string[]]$Spec, [int]$Port)
    $items = @($Spec | Where-Object { $_ })
    if ($items.Count -eq 0) { return $true }                 # no port filter = any port
    foreach ($item in $items) {
        if ($item -match '^(Any|\*)$') { return $true }
        if ($item -match '^(\d+)$') { if ([int]$Matches[1] -eq $Port) { return $true } }
        elseif ($item -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true } }
    }
    $false
}

function Test-ProtocolMatch {
    # TCP traffic is covered by a rule whose protocol is TCP or Any.
    param([string]$Protocol)
    $Protocol -in @('', 'Any', 'TCP', '6')
}

function Test-RemoteAny {
    # True when the rule has no source restriction.
    param([string[]]$Spec)
    $items = @($Spec | Where-Object { $_ })
    if ($items.Count -eq 0) { return $true }
    foreach ($i in $items) { if ($i -notmatch '^(Any|\*)$') { return $false } }
    $true
}

function ConvertTo-IpNumber {
    param([string]$Ip)
    $b = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    ([long]$b[0] * 16777216) + ([long]$b[1] * 65536) + ([long]$b[2] * 256) + [long]$b[3]
}

function Test-IpInSpec {
    # Does a RemoteAddress list ('Any', '172.16.1.5', '172.16.1.0/24', '172.16.1.0/255.255.255.0', 'a-b') include this IPv4?
    param([string[]]$Spec, [string]$Ip)
    $n = ConvertTo-IpNumber $Ip
    foreach ($item in @($Spec)) {
        if (-not $item -or $item -match '^(Any|\*)$') { return $true }
        if ($item -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
            $size = [long][Math]::Pow(2, 32 - [int]$Matches[2])
            $base = ConvertTo-IpNumber $Matches[1]
            $start = $base - ($base % $size)
            if ($n -ge $start -and $n -lt ($start + $size)) { return $true }
        }
        elseif ($item -match '^(\d+\.\d+\.\d+\.\d+)/(\d+\.\d+\.\d+\.\d+)$') {
            $size = 4294967296 - (ConvertTo-IpNumber $Matches[2])
            $base = ConvertTo-IpNumber $Matches[1]
            $start = $base - ($base % $size)
            if ($n -ge $start -and $n -lt ($start + $size)) { return $true }
        }
        elseif ($item -match '^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$') {
            if ($n -ge (ConvertTo-IpNumber $Matches[1]) -and $n -le (ConvertTo-IpNumber $Matches[2])) { return $true }
        }
        elseif ($item -match '^\d+\.\d+\.\d+\.\d+$') {
            if ($n -eq (ConvertTo-IpNumber $item)) { return $true }
        }
    }
    $false
}

function Test-ProgramAny {
    # A rule limited to one program does not "open the port" for everything, so we treat it separately.
    param([string]$Program)
    (-not $Program) -or $Program -eq 'Any'
}

function Get-FirewallFindings {
    param($Facts, [int[]]$Ports = @(3389, 8080), [string]$BlackboxIp = '', [string[]]$AllowedRules = @())
    $out = New-Object System.Collections.ArrayList
    $profiles = @($Facts.Profiles)
    $rules = @($Facts.Rules)
    $active = @($Facts.ActiveProfiles)

    # 1. all three profiles on
    $off = @()
    foreach ($n in $script:AllProfiles) {
        $p = $profiles | Where-Object { $_.Name -eq $n } | Select-Object -First 1
        if (-not $p -or -not $p.Enabled) { $off += $n }
    }
    if ($off.Count -gt 0) { [void]$out.Add((New-Result 'Firewall profiles' 'FAIL' "firewall is OFF for: $($off -join ', ')")) }
    else { [void]$out.Add((New-Result 'Firewall profiles' 'PASS' 'Domain, Private and Public are all on')) }

    # 2. inbound default = block
    $loose = @($profiles | Where-Object { $_.In -ne 'Block' } | ForEach-Object { "$($_.Name)=$($_.In)" })
    if ($loose.Count -gt 0) { [void]$out.Add((New-Result 'Inbound default' 'FAIL' "default inbound action is not Block: $($loose -join ', ')")) }
    else { [void]$out.Add((New-Result 'Inbound default' 'PASS' 'default inbound action is Block on every profile')) }

    # 3. the scored ports have an allow rule with no source restriction, on every profile
    #    (Windows' own "Remote Desktop - User Mode (TCP-In)" rule is tied to svchost.exe: it works, but the plan wants a plain port rule)
    foreach ($port in $Ports) {
        $allow = @($rules | Where-Object { $_.Action -eq 'Allow' -and (Test-ProtocolMatch $_.Protocol) -and (Test-PortInSpec $_.LocalPort $port) })
        $open = @($allow | Where-Object { Test-RemoteAny $_.RemoteAddress })
        $name = "Allow TCP $port"
        if ($allow.Count -eq 0) { [void]$out.Add((New-Result $name 'FAIL' "no enabled inbound allow rule for TCP $port (scoring cannot connect)")); continue }
        if ($open.Count -eq 0) { [void]$out.Add((New-Result $name 'FAIL' "the allow rule(s) only accept certain source addresses ($(Format-NameList @($allow | ForEach-Object { $_.DisplayName }))); scoring IPs vary, so allow any source")); continue }
        $plain = @($open | Where-Object { Test-ProgramAny $_.Program })          # rules that are not tied to one program
        $coverAll = @(); foreach ($r in $open) { $coverAll += Get-RuleProfiles $r.Profile }
        $coverPlain = @(); foreach ($r in $plain) { $coverPlain += Get-RuleProfiles $r.Profile }
        $missing = @($script:AllProfiles | Where-Object { $coverAll -notcontains $_ })
        $missingActive = @($active | Where-Object { $missing -contains $_ })
        $notPlain = @($script:AllProfiles | Where-Object { $coverPlain -notcontains $_ })
        if ($missingActive.Count -gt 0) { [void]$out.Add((New-Result $name 'FAIL' "no allow rule applies to the ACTIVE network profile ($($missingActive -join ', ')): the port is blocked right now")) }
        elseif ($missing.Count -gt 0) { [void]$out.Add((New-Result $name 'WARN' "allowed now, but not on profile(s) $($missing -join ', ') - if the network profile changes the port gets blocked")) }
        elseif ($notPlain.Count -gt 0) { [void]$out.Add((New-Result $name 'WARN' "on profile(s) $($notPlain -join ', ') the port is allowed only by rule(s) tied to one program ($(Format-NameList @($open | ForEach-Object { $_.DisplayName }))): fine while that program owns the port, but the plan uses a plain port rule")) }
        else { [void]$out.Add((New-Result $name 'PASS' "allowed from any source on every profile ($(Format-NameList @($plain | ForEach-Object { $_.DisplayName })))")) }
    }

    # 4. no block rule over the scored ports (this includes a blanket block on the Public profile)
    $hardBlocks = @(); $softBlocks = @()
    foreach ($b in ($rules | Where-Object { $_.Action -eq 'Block' -and (Test-ProtocolMatch $_.Protocol) })) {
        $hitsPort = $false
        foreach ($port in $Ports) { if (Test-PortInSpec $b.LocalPort $port) { $hitsPort = $true } }
        if (-not $hitsPort) { continue }
        $blanket = (@($b.LocalPort | Where-Object { $_ -and $_ -ne 'Any' }).Count -eq 0)
        $label = "$($b.DisplayName) [$($b.Profile)]"
        if ($blanket) { $label = "$label BLANKET" }
        if (-not (Test-ProgramAny $b.Program)) { $softBlocks += "$label (only for $($b.Program))" }      # blocks one program: breaks scoring only if that program owns the port
        elseif (Test-RemoteAny $b.RemoteAddress) { $hardBlocks += $label }
        else { $softBlocks += $label }
    }
    if ($hardBlocks.Count -gt 0) { [void]$out.Add((New-Result 'Inbound block rules' 'FAIL' "enabled block rule(s) override the allow rules: $(Format-NameList $hardBlocks)")) }
    elseif ($softBlocks.Count -gt 0) { [void]$out.Add((New-Result 'Inbound block rules' 'WARN' "block rule(s) on the scored ports limited to certain sources or one program: $(Format-NameList $softBlocks). Scoring IPs vary - do not block broad ranges.")) }
    else { [void]$out.Add((New-Result 'Inbound block rules' 'PASS' 'no block rule touches the scored ports')) }

    # 5. leftover allow rules (the plan: disable them, keep the Core Networking group)
    $leftover = @()
    foreach ($r in ($rules | Where-Object { $_.Action -eq 'Allow' })) {
        if ($r.DisplayGroup -eq 'Core Networking' -or $r.Group -like '*FirewallAPI.dll,-25000*') { continue }
        if ($AllowedRules -contains $r.DisplayName) { continue }
        $ruleLocalPorts = @($r.LocalPort | Where-Object { $_ })        # (not named $ports: PowerShell names are not case-sensitive, it would clash with $Ports)
        $onlyScoredPorts = ($ruleLocalPorts.Count -gt 0)
        foreach ($lp in $ruleLocalPorts) { if ($lp -notmatch '^\d+$' -or ($Ports -notcontains [int]$lp)) { $onlyScoredPorts = $false } }
        if ($onlyScoredPorts -and (Test-ProgramAny $r.Program)) { continue }      # e.g. the TCP and UDP rules for 3389
        $leftover += $r.DisplayName
    }
    if ($leftover.Count -gt 0) { [void]$out.Add((New-Result 'Other inbound allow rules' 'FAIL' "$($leftover.Count) other inbound allow rule(s) still enabled (plan: disable, do not delete; keep Core Networking): $(Format-NameList $leftover)")) }
    else { [void]$out.Add((New-Result 'Other inbound allow rules' 'PASS' 'only the scored ports and Core Networking are allowed in')) }

    # 6. dropped-connection logging
    $noLog = @($profiles | Where-Object { -not $_.LogBlocked } | ForEach-Object { $_.Name })
    if ($noLog.Count -gt 0) { [void]$out.Add((New-Result 'Firewall logging' 'WARN' "dropped-connection logging is off on: $($noLog -join ', ') (plan: turn it on)")) }
    else { [void]$out.Add((New-Result 'Firewall logging' 'PASS' 'dropped connections are logged')) }

    # 7. outbound
    $outTxt = ($profiles | ForEach-Object { "$($_.Name)=$($_.Out)" }) -join ', '
    $outBlock = @($profiles | Where-Object { $_.Out -eq 'Block' })
    if ($outBlock.Count -eq 0) { [void]$out.Add((New-Result 'Outbound default' 'INFO' "outbound is open ($outTxt). The plan locks it down only after a logging period.")) }
    elseif (-not $BlackboxIp) { [void]$out.Add((New-Result 'Outbound default' 'INFO' "outbound default is Block ($outTxt). Pass -BlackboxIp to check the path to blackbox.")) }
    else {
        # an enabled outbound allow rule that reaches blackbox on TCP 22 (backups go over scp)
        $okRule = @(@($Facts.OutRules) | Where-Object {
            $_.Action -eq 'Allow' -and (Test-ProtocolMatch $_.Protocol) -and (Test-PortInSpec $_.RemotePort 22) -and (Test-IpInSpec $_.RemoteAddress $BlackboxIp)
        })
        $who = Format-NameList @($okRule | ForEach-Object { $_.DisplayName })
        if ($okRule.Count -gt 0) { [void]$out.Add((New-Result 'Outbound default' 'PASS' "outbound default is Block ($outTxt) and an allow rule reaches blackbox $BlackboxIp port 22: $who")) }
        else { [void]$out.Add((New-Result 'Outbound default' 'FAIL' "outbound default is Block ($outTxt) but no enabled outbound allow rule reaches blackbox $BlackboxIp port 22 - backups would fail")) }
    }
    $out.ToArray()
}
