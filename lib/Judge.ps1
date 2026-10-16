# Judge.ps1 - the JUDGES. A judge reads FACTS (what Collect.ps1 found) and SETTINGS and returns FINDINGS (the rows in the grid).
# A judge never calls Windows. It only looks at the facts, which is how it is tested on a laptop with made-up facts.
#
#   Judge.ps1          this file: the row type, recon (phase 1), backup (phase 3), Defender (phase 7), routine (phase 9)
#   JudgeAccounts.ps1  phase 2        JudgeFirewall.ps1  phase 4        JudgeHunt.ps1  phase 6        JudgeWatchdog.ps1  phase 8
#
# A finding says WHAT is wrong, WHY it matters, and (maybe) which function builds the fix. The fix itself is an Action
# (see Core.ps1) and only Invoke-Change may run it. Uses Get-BareName from Collect.ps1. Windows PowerShell 5.1, plain ASCII.

# a plain hashtable: $script:PhaseNames[4] looks up the KEY 4. (An [ordered] one would treat the 4 as a position.)
$script:PhaseNames = @{ 1 = 'Recon'; 2 = 'Accounts'; 3 = 'Backup'; 4 = 'Firewall'; 6 = 'Hunt'; 7 = 'Defender'; 8 = 'Watchdog'; 9 = 'Routine' }
$script:PhaseOrder = @(1, 2, 3, 4, 6, 7, 8, 9)        # the order the phases are worked through (5 is a manual step in the plan)
$script:SeverityRank = @{ BAD = 0; WARN = 1; INFO = 2; OK = 3 }

function New-FixRef {
    # "Call THIS function with THESE arguments to get the action for the finding". The function may ask you questions
    # (a name, a password) and returns an action, or $null when you cancel.
    param([string]$Do, [hashtable]$With = @{})
    @{ Do = $Do; With = $With }
}

function New-Finding {
    # Batch = $false means "Fix phase" skips it: it needs your own judgement (Keep changes, outbound deny, password changes).
    param(
        [Parameter(Mandatory)][int]$Phase,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][ValidateSet('BAD', 'WARN', 'INFO', 'OK')][string]$Severity,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Why,
        $Fix = $null,
        [string]$Blocked = '',
        [bool]$Batch = $true
    )
    [pscustomobject]@{
        Phase = $Phase; Area = $Area; Severity = $Severity; Subject = $Subject; Why = $Why
        Fix = $Fix; Blocked = $Blocked; Batch = $Batch; Key = "$Phase|$Area|$Subject"
    }
}

function Resolve-Fix {
    # Turns a finding's fix reference into an action by calling the named function. $null = no fix, or you cancelled.
    param($Finding)
    if (-not $Finding.Fix) { return $null }
    $do = [string]$Finding.Fix.Do
    # a fix may only BUILD an action (New-*) or ask you for what an action needs (Request-*); it can never call anything else by name
    if ($do -notmatch '^(Request|New)-[A-Za-z0-9]+$') { throw "A fix may only call a Request-* or New-* function, not '$do'." }
    $with = $Finding.Fix.With
    if ($with -and $with.Count -gt 0) { return (& $do @with) }
    & $do
}

function Invoke-Judge {
    # Runs one judge function by name; if the judge itself has a bug it becomes ONE red row instead of stopping the whole audit.
    param([int]$Phase, [string]$Name, [string]$Judge, $Facts, $Settings)
    try { @(& $Judge $Facts $Settings) }
    catch { @(New-Finding -Phase $Phase -Area 'Judge' -Severity 'BAD' -Subject "$Name crashed" -Why "The judge '$Name' failed: $($_.Exception.Message)") }
}

function Get-HpFindings {
    # All findings, in the order you should work through them. -Phases limits the result (for example 2,4).
    param($Facts, $Settings = $null, [int[]]$Phases = @())
    if (-not $Settings) { $Settings = $script:Hp.Settings }
    $all = @()
    $all += Invoke-Judge 1 'recon' 'Get-ReconFindings' $Facts $Settings
    $all += Invoke-Judge 2 'accounts' 'Get-AccountFindings' $Facts $Settings
    $all += Invoke-Judge 3 'backup' 'Get-BackupFindings' $Facts $Settings
    $all += Invoke-Judge 4 'firewall' 'Get-FirewallFindings' $Facts $Settings
    $all += Invoke-Judge 6 'hunt' 'Get-HuntFindings' $Facts $Settings
    $all += Invoke-Judge 7 'defender' 'Get-DefenderFindings' $Facts $Settings
    $all += Invoke-Judge 8 'watchdog' 'Get-WatchdogFindings' $Facts $Settings
    $all += Invoke-Judge 9 'routine' 'Get-RoutineFindings' $Facts $Settings
    if ($Phases.Count -gt 0) { $all = @($all | Where-Object { $Phases -contains $_.Phase }) }
    @($all)
}

function Get-TeamInfo {
    # The team number is in this box's address: 172.16.<team>.30. From it: the team network and blackbox's address.
    param([string[]]$Ips = @(), [string]$TeamNet = '')
    $team = ''
    foreach ($ip in $Ips) {
        if ($ip -match '^172\.16\.(\d{1,3})\.\d{1,3}$') { $team = $Matches[1]; break }
    }
    $net = $TeamNet
    if (-not $net -and $team) { $net = "172.16.$team.0/24" }
    $blackbox = $(if ($team) { "172.16.$team.5" } else { '' })
    [pscustomobject]@{ Team = $team; Net = $net; Blackbox = $blackbox }
}

# ---------------------------------------------------------------- phase 1: recon
function Get-ReconFindings {
    param($Facts, $Settings)
    $out = @()
    foreach ($e in (Get-List $Facts.Errors)) {
        if ($e) { $out += New-Finding 1 'Recon' 'BAD' "Could not read: $(($e -split ':')[0])" "A collector failed, so the audit is incomplete here: $e" }
    }
    if ($Facts.Host) {
        $h = $Facts.Host
        $out += New-Finding 1 'Host' 'INFO' 'This box' "$($h.ComputerName): $($h.Os), build $($h.Build). Last update: $($h.LastHotfix). Addresses: $((Get-List $h.Ips) -join ', ')."
        $team = Get-TeamInfo -Ips (Get-List $h.Ips) -TeamNet ([string]$Settings.TeamNet)
        if ($team.Team) { $out += New-Finding 1 'Host' 'INFO' 'Team network' "Team $($team.Team): network $($team.Net), blackbox should be $($team.Blackbox) (use the IP, never a name)." }
        else { $out += New-Finding 1 'Host' 'WARN' 'Team network' 'This box has no 172.16.<team>.x address, so the team number is unknown. Set TeamNet in settings.json (for example 172.16.5.0/24).' }
    }
    if ($Facts.Net) {
        $n = $Facts.Net
        if ((Get-List $n.Profiles) -contains 'Public') {
            $out += New-Finding 1 'Network' 'WARN' 'Network profile is Public' 'Windows treats this network as Public (strictest, and different rules apply). The firewall steps turn on all three profiles, but find out why: a GPO or the network setup may have set it.'
        } else { $out += New-Finding 1 'Network' 'INFO' 'Network profile' "Active profile: $((Get-List $n.Profiles) -join ', ')." }
        $out += New-Finding 1 'Network' 'INFO' 'Internet' $(if ($n.Internet) { 'The Internet is reachable (1.1.1.1:443): download tools now, before the outbound lockdown.' } else { 'The Internet is NOT reachable from here: tools must come from your laptop or from blackbox.' })
    }
    if ($Facts.Tools) {
        $t = $Facts.Tools
        $out += New-Finding 1 'Tools' 'INFO' 'PowerShell and .NET' "Windows PowerShell $($t.PowerShell), .NET Framework release $($t.DotNetRelease) (461808 or higher is needed for the backup encryption)."
    }
    $out += Get-JenkinsReconFindings $Facts
    $out += Get-CollectorReconFindings $Facts $Settings
    $dm = $Facts.DeadMan
    if ($dm) {
        $sev = $(if ($dm.Armed) { 'INFO' } else { 'WARN' })
        $out += New-Finding 1 'Safety net' $sev 'Dead-man switch' $(if ($dm.Armed) { "Armed: $($dm.Note)." } else { "Not armed. Arm it in the Firewall phase BEFORE any firewall change; the tool refuses firewall changes until it is armed. ($($dm.Note))" })
    }
    $svcCount = (Get-List $Facts.Services).Count
    $taskCount = @(Get-List $Facts.Tasks | Where-Object { $_.Path -notlike '\Microsoft\*' }).Count
    $portCount = (Get-List $Facts.Ports.Listeners).Count
    $out += New-Finding 1 'Inventory' 'INFO' 'Services, tasks, ports' "$svcCount services, $taskCount scheduled tasks outside \Microsoft\, $portCount listening ports. The Hunt phase lists what looks wrong."
    $out
}

function Get-JenkinsReconFindings {
    param($Facts)
    $j = $Facts.Jenkins
    if (-not $j) { return @() }
    if (-not $j.Found) { return @(New-Finding 1 'Jenkins' 'WARN' 'Jenkins service not found' 'No service with "jenkins" in its name or program path. Scoring needs Jenkins on port 8080: find out where it runs before changing anything.') }
    $out = @()
    $state = "service '$($j.Service)' is $($j.State), starts $($j.StartMode), runs as $($j.StartName). Program: $($j.Exe)."
    $out += New-Finding 1 'Jenkins' $(if ($j.State -eq 'Running') { 'INFO' } else { 'BAD' }) 'Jenkins service' "$state Leave the service account and the home folder as they are."
    if (-not $j.HomeFound) {
        $out += New-Finding 1 'Jenkins' 'WARN' 'Jenkins home not found' 'The JENKINS_HOME folder could not be located, so Jenkins files cannot be backed up. Look for config.xml and a jobs folder.'
    } else {
        $out += New-Finding 1 'Jenkins' 'INFO' 'Jenkins home' "JENKINS_HOME = $($j.Home). Java: $($j.Java) $($j.JavaVersion)."
    }
    if ((Get-List $j.InitGroovy).Count -gt 0) {
        $out += New-Finding 1 'Jenkins' 'WARN' 'Scripts in init.groovy.d' "These run every time Jenkins starts, so a planted one is a classic backdoor: $(@($j.InitGroovy) -join ', '). Read each one before deciding."
    }
    if (-not $j.Listening) { $out += New-Finding 1 'Jenkins' 'BAD' 'Nothing listens on port 8080' 'Scoring needs Jenkins on 8080. The service may be stopped or on another port.' }
    $out
}

function Get-CollectorReconFindings {
    param($Facts, $Settings)
    $c = Get-List $Facts.Collector
    if ($c.Count -gt 0) {
        $lines = @($c | ForEach-Object { $_.Detail })
        return @(New-Finding 1 'Log collector' 'INFO' 'Log collector found' "NEVER stop or block it (it ships the event logs to blackbox): $($lines -join '; ').")
    }
    if ([string]$Settings.BlackboxIp) {
        return @(New-Finding 1 'Log collector' 'WARN' 'Log collector not found' 'No log shipper service and no program connected to blackbox. Find the program that sends the event logs before the firewall step, so its traffic is not cut.')
    }
    @(New-Finding 1 'Log collector' 'INFO' 'Log collector' 'Not identified yet: enter the blackbox IP in the Backup phase and audit again, then the program connected to blackbox is shown here.')
}

# ---------------------------------------------------------------- phase 3: backup
function Get-BackupFindings {
    param($Facts, $Settings)
    $out = @()
    $tools = $Facts.Tools
    $bk = $Facts.Backup
    $bb = [string]$Settings.BlackboxIp
    $suggest = (Get-TeamInfo -Ips (Get-List $Facts.Host.Ips) -TeamNet ([string]$Settings.TeamNet)).Blackbox

    if ($tools) {
        $missing = @()
        if (-not $tools.Ssh) { $missing += 'ssh.exe' }
        if (-not $tools.Scp) { $missing += 'scp.exe' }
        if (-not $tools.SshKeygen) { $missing += 'ssh-keygen.exe' }
        if (-not $tools.SshKeyscan) { $missing += 'ssh-keyscan.exe' }
        if ($missing.Count -gt 0) {
            $out += New-Finding 3 'Tools' 'BAD' "OpenSSH client is missing: $($missing -join ', ')" 'Sending backups needs the OpenSSH client. Install it (needs the Internet / Windows Update): Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0   Or copy the missing files from the laptop folder C:\Windows\System32\OpenSSH.'
        } else {
            $out += New-Finding 3 'Tools' 'OK' 'OpenSSH client' "ssh, scp, ssh-keygen and ssh-keyscan found. $($tools.SshVersion)"
        }
    }
    if ($tools -and $tools.DotNetRelease -lt 461808) {
        $out += New-Finding 3 'Tools' 'BAD' '.NET is too old for the archive encryption' ".NET Framework release $($tools.DotNetRelease) is older than 4.7.2 (461808). The encrypted archive step will fail."
    }

    if (-not $bb) {
        $why = 'Blackbox is where backups go. You get its IP at the competition (it should be ' + $(if ($suggest) { $suggest } else { '172.16.<team>.5' }) + '). Until it is entered, the tool builds local backups only.'
        $out += New-Finding 3 'Blackbox' 'WARN' 'Blackbox IP not entered' $why (New-FixRef 'Request-BlackboxIp') -Batch $false
    } else {
        $reach = $Facts.Net.BlackboxSsh
        if ($reach -eq $true) { $out += New-Finding 3 'Blackbox' 'OK' "Blackbox $bb" 'SSH port 22 answers.' }
        else { $out += New-Finding 3 'Blackbox' 'WARN' "Blackbox $bb port 22 does not answer" 'Blackbox may be down, the IP may be wrong, or something on the path (firewall, route) blocks it. The network path to blackbox is in the Red Team scope: check it.' }
    }

    $keyOk = ($bk -and $bk.KeyExists)
    if ($bb -and -not $keyOk) {
        $out += New-Finding 3 'Blackbox' 'WARN' 'No backup SSH key yet' 'Create the key pair here, then put the PUBLIC key into the restricted upload user on blackbox (RUNBOOK.md has the exact commands). The private key stays on this box, so that user must be able to do nothing but upload.' (New-FixRef 'New-BackupKeyAction') -Batch $false
    } elseif ($bb -and $keyOk -and -not $bk.HostKeyPinned) {
        $out += New-Finding 3 'Blackbox' 'WARN' 'Blackbox host key not pinned' 'Read the SSH host key fingerprint on the blackbox CONSOLE (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub) and type it here. The tool then accepts only a key with that fingerprint (this is not trust-on-first-use).' (New-FixRef 'Request-PinHostKey') -Batch $false
    } elseif ($bb -and $keyOk) {
        $out += New-Finding 3 'Blackbox' 'OK' 'Blackbox host key pinned' 'Uploads only go to a server that proves it is the blackbox you pinned.'
    }

    $count = $(if ($bk) { (Get-List $bk.Archives).Count } else { 0 })
    if ($count -eq 0) {
        $out += New-Finding 3 'Backup' 'WARN' 'No as-found backup yet' 'The as-found backup records what the box looked like before you changed it (users, groups, policy, firewall, tasks, services, registry keys, Jenkins files). It is a LOCAL encrypted archive first. Take it early.' (New-FixRef 'Request-AsFoundBackup') -Batch $false
    } else {
        $last = (Get-List $bk.Archives)[-1]
        $out += New-Finding 3 'Backup' 'OK' "Local archives: $count" "Newest: $($last.Name), $($last.Time), $($last.Bytes) bytes. Rule 3: do not copy it to the laptop. To open one, do it ON blackbox: see RUNBOOK.md."
        $out += New-Finding 3 'Backup' 'INFO' 'Take another backup' 'Take a fresh encrypted backup after each big change (accounts, firewall), so there is a recent copy to send to blackbox and to restore from.' (New-FixRef 'Request-BackupNow') -Batch $false
        $sentName = $(if ($bk.Sent) { [string]$bk.Sent.Name } else { '' })
        if ($sentName -ne [string]$last.Name) {
            $blocked = ''
            if (-not $bb) { $blocked = 'Enter the blackbox IP first.' } elseif (-not $keyOk) { $blocked = 'Create the backup key first.' } elseif (-not $bk.HostKeyPinned) { $blocked = 'Pin the blackbox host key first.' }
            $subject = $(if ($bk.Sent) { 'Newest backup not sent to blackbox yet' } else { 'Nothing sent to blackbox yet' })
            $out += New-Finding 3 'Backup' 'WARN' $subject 'A backup that only exists on this box is lost if the box is reverted or wiped. Send it with scp to blackbox (the only place data may go: rule 3).' (New-FixRef 'Request-SendBackup') $blocked -Batch $false
        } else {
            $s = $bk.Sent
            $out += New-Finding 3 'Backup' 'OK' 'Sent to blackbox' "$($s.Name) at $($s.Time), SHA-256 $($s.Sha256). Verify it from the LAPTOP (RUNBOOK.md 5.3): sudo sha256sum on blackbox must show the same hash."
        }
    }
    $out
}

# ---------------------------------------------------------------- phase 7: Defender (diagnosis first; fixes for policy values, exclusions and the scanning switches)
# The rows follow the plan's order for a repair: the services, the registry values that switch it off, the exclusions, passive mode,
# the Windows feature, the signatures, then real-time protection and the rest.
$script:DefenderValueMeaning = @{
    DisableAntiSpyware = 'the whole antivirus'; DisableAntiVirus = 'the whole antivirus'; DisableRoutinelyTakingAction = 'automatic cleaning of threats'
    DisableRealtimeMonitoring = 'real-time protection'; DisableBehaviorMonitoring = 'behavior monitoring'; DisableOnAccessProtection = 'scanning of files as they are opened'
    DisableIOAVProtection = 'scanning of downloads and attachments'; DisableScanOnRealtimeEnable = 'the scan that runs when real-time protection starts'
    DisableScriptScanning = 'script scanning'; ForceDefenderPassiveMode = 'Defender itself (it is forced into passive mode)'
}
$script:OtherAntivirus = 'malwarebytes|mbamservice|360 total|360safe|qhsafemain|kaspersky|avp\b|avast|avgsvc|avg antivirus|ekrn|eset service|sophos|symantec|norton|mcafee|mfemms|trend micro|ds_agent|crowdstrike|csagent|sentinelagent|cylance|bitdefender|vsserv|webroot|clamd|clamav'

function Get-DefenderFindings {
    param($Facts, $Settings)
    $null = $Settings
    $d = $Facts.Defender
    if (-not $d) { return @() }
    $out = @()
    $out += Get-DefenderServiceFindings $Facts
    $out += Get-DefenderPolicyFindings $d
    if (-not $d.Available) {
        $out += New-Finding 7 'Defender' 'WARN' 'Defender cannot be read' "Get-MpComputerStatus failed: $($d.Reason) Defender may be removed, stopped, switched off by policy, or replaced by another antivirus. The other Defender rows say which. Diagnose before repairing (plan phase 7)."
        $out += Get-DefenderFeatureFindings $d
        return $out
    }
    $out += New-Finding 7 'Defender' $(if ($d.ServiceEnabled) { 'OK' } else { 'BAD' }) 'Antivirus service' $(if ($d.ServiceEnabled) { 'The Defender antivirus service is on.' } else { 'The Defender antivirus service is OFF.' })
    $fixRealTime = $null; if (-not $d.RealTime) { $fixRealTime = New-FixRef 'New-DefenderSwitchAction' @{ Setting = 'Realtime' } }
    $fixBehavior = $null; if (-not $d.Behavior) { $fixBehavior = New-FixRef 'New-DefenderSwitchAction' @{ Setting = 'Behavior' } }
    $fixDownloads = $null; if (-not $d.Downloads) { $fixDownloads = New-FixRef 'New-DefenderSwitchAction' @{ Setting = 'Downloads' } }
    $out += New-Finding 7 'Defender' $(if ($d.RealTime) { 'OK' } else { 'BAD' }) 'Real-time protection' $(if ($d.RealTime) { 'On.' } else { 'OFF: nothing is scanned as it runs. The fix switches it on; if a policy value (rows above) holds it off, remove that first.' }) $fixRealTime
    $out += New-Finding 7 'Defender' $(if ($d.Behavior) { 'OK' } else { 'BAD' }) 'Behavior monitoring' $(if ($d.Behavior) { 'On.' } else { 'OFF: programs that misbehave (but look harmless on disk) are not caught. The fix switches it on.' }) $fixBehavior
    $out += New-Finding 7 'Defender' $(if ($d.Downloads) { 'OK' } else { 'WARN' }) 'Scanning of downloads' $(if ($d.Downloads) { 'On.' } else { 'OFF: files that are downloaded or attached are not scanned. The fix switches it on.' }) $fixDownloads
    foreach ($x in (Get-List $d.ExclusionPaths)) {
        $out += New-Finding 7 'Defender' 'WARN' "Exclusion: $x" 'Defender skips this path. Attackers add exclusions to hide tools. The plan removes all of them and adds none. The fix removes it (Undo adds it back).' (New-FixRef 'New-RemoveDefenderExclusionAction' @{ Kind = 'Path'; Value = [string]$x })
    }
    foreach ($x in (Get-List $d.ExclusionExtensions)) {
        $out += New-Finding 7 'Defender' 'WARN' "Exclusion (extension): $x" 'Defender skips every file with this extension. Attackers add exclusions to hide tools. The plan removes all of them and adds none. The fix removes it (Undo adds it back).' (New-FixRef 'New-RemoveDefenderExclusionAction' @{ Kind = 'Extension'; Value = [string]$x })
    }
    foreach ($x in (Get-List $d.ExclusionProcesses)) {
        $out += New-Finding 7 'Defender' 'WARN' "Exclusion (process): $x" 'Defender skips files opened by this program. Attackers add exclusions to hide tools. The plan removes all of them and adds none. The fix removes it (Undo adds it back).' (New-FixRef 'New-RemoveDefenderExclusionAction' @{ Kind = 'Process'; Value = [string]$x })
    }
    $out += Get-DefenderModeFindings $Facts $d
    $out += Get-DefenderFeatureFindings $d
    $age = [int]$d.SignatureAgeDays
    $out += New-Finding 7 'Defender' $(if ($age -le 3) { 'OK' } else { 'WARN' }) 'Signatures' "Signatures are $age day(s) old (version $($d.SignatureVersion), Defender $($d.ProductVersion)). An old set means a missed update: apply the offline package (mpam-fe.exe) if the box has no Internet."
    if (-not $d.Tamper) { $out += New-Finding 7 'Defender' 'INFO' 'Tamper protection' 'Off (or not reported). With it on, exclusions and settings are harder to change.' }
    $quick = [int]$d.QuickScanAgeDays
    $out += New-Finding 7 'Defender' 'INFO' 'Last quick scan' $(if ($quick -lt 0) { 'No quick scan has run yet. The plan ends the Defender repair with one (watch for Jenkins false positives).' } else { "The last quick scan was $quick day(s) ago." })
    $out
}

function Get-DefenderServiceFindings {
    # WinDefend is the antivirus itself; WdNisSvc is its network inspection part (less important).
    param($Facts)
    if (-not $Facts.Services) { return @() }
    $bad = @(); $warn = @(); $fine = @()
    foreach ($name in 'WinDefend', 'WdNisSvc') {
        $s = @(Get-List $Facts.Services | Where-Object { $_.Name -eq $name }) | Select-Object -First 1
        $problem = ''
        if (-not $s) { $problem = 'is missing' }
        elseif ($s.StartMode -eq 'Disabled') { $problem = 'is Disabled' }
        elseif ($s.State -ne 'Running') { $problem = "is $($s.State)" }
        if ($problem -and $name -eq 'WinDefend') { $bad += "$name $problem" }
        elseif ($problem) { $warn += "$name $problem" }
        else { $fine += "$name is running ($($s.StartMode))" }
    }
    if ($bad.Count -gt 0) {
        return @(New-Finding 7 'Defender' 'BAD' 'Defender services' "$((@($bad) + @($warn)) -join '; '). Without WinDefend there is no antivirus. A stopped service can be started; a missing one means the Windows feature is gone (see the Windows feature row). Tamper protection often blocks changing the start type: then it must be done as SYSTEM.")
    }
    if ($warn.Count -gt 0) { return @(New-Finding 7 'Defender' 'WARN' 'Defender services' "$($warn -join '; '). WinDefend itself is fine: $($fine -join '; ').") }
    @(New-Finding 7 'Defender' 'OK' 'Defender services' "$($fine -join '; ').")
}

function Get-DefenderPolicyFindings {
    # A registry value that switches Defender (or a part of it) off. A value of 0 is harmless and not listed.
    param($D)
    $out = @()
    foreach ($v in (Get-List $D.PolicyValues)) {
        if ([string]$v.Name -notmatch '^(Disable|Force)') { continue }
        if ([int]$v.Data -eq 0) { continue }
        $means = $script:DefenderValueMeaning[[string]$v.Name]
        $short = ([string]$v.Key) -replace '^HKLM:\\SOFTWARE\\', ''
        $fix = New-FixRef 'New-RegistryValueAction' @{ Key = [string]$v.Key; Name = [string]$v.Name; Area = 'def'; Label = "the Defender switch $($v.Name)"; Shown = "$($v.Name) = $($v.Data)" }
        $out += New-Finding 7 'Defender' 'BAD' "Registry switches Defender off: $($v.Name) ($short)" "$($v.Key) has $($v.Name) = $($v.Data), which turns off $means. A policy or an intruder sets this even when the service looks fine. Removing the value is how it is repaired (the old value stays in the journal)." $fix
    }
    $out
}

function Get-DefenderModeFindings {
    # Passive mode and other antivirus products.
    param($Facts, $D)
    $out = @()
    if ($D.RunningMode) {
        $normal = ([string]$D.RunningMode -eq 'Normal')
        $out += New-Finding 7 'Defender' $(if ($normal) { 'OK' } else { 'WARN' }) 'Running mode' $(if ($normal) { 'Normal: Defender is the active antivirus.' } else { "Defender runs in '$($D.RunningMode)' mode: another antivirus (or a setting) has taken over, so Defender does not scan by itself. Find out which one." })
    }
    $found = @()
    foreach ($s in (Get-List $Facts.Services)) {
        if ([string]$s.Name -match $script:OtherAntivirus -or [string]$s.DisplayName -match $script:OtherAntivirus) { $found += "$($s.Name) ($($s.State))" }
    }
    if ($found.Count -gt 0) {
        $out += New-Finding 7 'Defender' 'INFO' 'Another antivirus' "Services that look like another antivirus: $($found -join ', '). Defender goes passive when another antivirus registers with Windows."
    }
    $out
}

function Get-DefenderFeatureFindings {
    # On Windows Server, Defender is a Windows feature. Putting it back needs a reboot, so it is decided by a person (RUNBOOK.md).
    param($D)
    $state = [string]$D.Feature
    if ($state -eq 'Installed') { return @(New-Finding 7 'Defender' 'OK' 'Windows feature' 'The Windows feature Windows-Defender is installed.') }
    if ($state -eq 'Removed' -or $state -eq 'Available') {
        return @(New-Finding 7 'Defender' 'BAD' 'Windows feature' "The Windows feature Windows-Defender is '$state': Defender is not installed on this server. Putting it back (Install-WindowsFeature Windows-Defender) needs a REBOOT, so decide early when a reboot is acceptable. The tool does not do this itself (RUNBOOK.md section 9).")
    }
    @(New-Finding 7 'Defender' 'INFO' 'Windows feature' 'Windows could not be asked whether the Windows-Defender feature is installed (Get-WindowsFeature failed).')
}

# ---------------------------------------------------------------- phase 9: routine reminders
function Get-RoutineFindings {
    param($Facts, $Settings)
    $null = $Facts
    $out = @()
    $admin = [string]$Settings.NewAdmin
    if ($admin -and $Settings.NewAdminConfirmed) {
        $out += New-Finding 9 'Routine' 'INFO' 'Rotate the new admin password' "Change the password of '$admin' again after the persistence hunt, then about every 2 hours. Use a new Bitwarden passphrase; you must be able to type it on the Console." (New-FixRef 'Request-SetPassword' @{ Name = $admin; Kind = 'admin' }) -Batch $false
    }
    $out += New-Finding 9 'Routine' 'INFO' 'Every 30 minutes' 'NEIGH Details page, this audit, and confirm a new backup arrived on blackbox.'
    $out += New-Finding 9 'Routine' 'INFO' 'After any revert or the lunch break' 'Everything planted is back after a revert. Run the audit first, then the phases again. Scoring is paused 12:00-1:30 and NEIGH rejects password changes during that time.'
    $out
}
