# VerifyJudgeSystem.ps1 - Verify-Hardening "judges" for RDP settings, services, Defender, Windows settings
# and leftover-persistence review. PURE functions: plain facts in, result objects out (testable anywhere).
# A missing fact ($null) means "could not read it"; judges say SKIP/WARN instead of guessing.

function Get-RdpFindings {
    # $Facts: DenyConnections, Port, Nla, SecurityLayer, DisableClip (numbers or $null), ServiceDll (text),
    #         SigStatus, SigSubject (text), TermServiceState, Listening (bool)
    param($Facts)
    $out = New-Object System.Collections.ArrayList
    if ($Facts.DenyConnections -eq 0) { [void]$out.Add((New-Result 'RDP enabled' 'PASS' 'Remote Desktop connections are allowed')) }
    else { [void]$out.Add((New-Result 'RDP enabled' 'FAIL' "Remote Desktop is turned OFF (fDenyTSConnections = $($Facts.DenyConnections))")) }

    if ($Facts.Port -eq 3389) { [void]$out.Add((New-Result 'RDP port' 'PASS' 'port is 3389')) }
    else { [void]$out.Add((New-Result 'RDP port' 'FAIL' "RDP port is '$($Facts.Port)' - never change it, scoring uses 3389")) }

    if ($Facts.TermServiceState -eq 'Running' -and $Facts.Listening) { [void]$out.Add((New-Result 'TermService' 'PASS' 'running and listening on 3389')) }
    else { [void]$out.Add((New-Result 'TermService' 'FAIL' "service state '$($Facts.TermServiceState)', listening on 3389: $($Facts.Listening)")) }

    if ($Facts.Nla -eq 1) { [void]$out.Add((New-Result 'RDP NLA' 'PASS' 'Network Level Authentication is required')) }
    else { [void]$out.Add((New-Result 'RDP NLA' 'WARN' "NLA is not required (UserAuthentication = $($Facts.Nla)); plan Phase 5: NLA on")) }

    if ($Facts.SecurityLayer -eq 2) { [void]$out.Add((New-Result 'RDP security layer' 'PASS' 'TLS')) }
    else { [void]$out.Add((New-Result 'RDP security layer' 'WARN' "SecurityLayer = $($Facts.SecurityLayer) (2 = TLS is the plan)")) }

    if ($Facts.DisableClip -eq 1) { [void]$out.Add((New-Result 'RDP clipboard' 'FAIL' 'clipboard redirection is disabled (plan: keep it, you paste passwords with it)')) }
    else { [void]$out.Add((New-Result 'RDP clipboard' 'PASS' 'clipboard redirection is not disabled')) }

    $dllOk = ($Facts.ServiceDll -like '*\system32\termsrv.dll') -and ($Facts.SigStatus -eq 'Valid') -and ($Facts.SigSubject -match 'Microsoft')
    if ($dllOk) { [void]$out.Add((New-Result 'TermService DLL' 'PASS' 'termsrv.dll in System32, validly signed by Microsoft')) }
    else { [void]$out.Add((New-Result 'TermService DLL' 'FAIL' "ServiceDll '$($Facts.ServiceDll)', signature '$($Facts.SigStatus)' - could be a hijacked RDP service")) }
    $out.ToArray()
}

function Get-ServiceFindings {
    # $Facts.Services = array of Name, DisplayName, State, StartMode, StartName, PathName
    param($Facts)
    $out = New-Object System.Collections.ArrayList
    $svc = @($Facts.Services)
    # Jenkins: a service whose NAME says jenkins, else one whose program PATH says jenkins (the service may be named differently)
    $jenkins = $svc | Where-Object { $_.Name -like '*jenkins*' } | Select-Object -First 1
    if (-not $jenkins) { $jenkins = $svc | Where-Object { $_.PathName -like '*jenkins*' } | Select-Object -First 1 }
    if (-not $jenkins) { [void]$out.Add((New-Result 'Jenkins service' 'FAIL' 'no Jenkins service found (looked at service names and program paths)')) }
    elseif ($jenkins.State -ne 'Running') { [void]$out.Add((New-Result 'Jenkins service' 'FAIL' "$($jenkins.Name) is $($jenkins.State) (scoring needs Jenkins up)")) }
    elseif ($jenkins.StartMode -ne 'Auto') { [void]$out.Add((New-Result 'Jenkins service' 'WARN' "$($jenkins.Name) runs but its start type is $($jenkins.StartMode) (will not come back after a reboot)")) }
    else { [void]$out.Add((New-Result 'Jenkins service' 'PASS' "$($jenkins.Name) running, automatic, account $($jenkins.StartName)")) }

    foreach ($name in 'Spooler', 'RemoteRegistry') {
        $s = $svc | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($s -and $s.State -eq 'Running') { [void]$out.Add((New-Result "$name service" 'WARN' "$name is running (plan: disable it if nothing needs it)")) }
        else { [void]$out.Add((New-Result "$name service" 'PASS' 'not running')) }
    }
    $out.ToArray()
}

function Get-DefenderFindings {
    # $Facts: Available (bool), RealTime (bool), ServiceEnabled (bool), SignatureAgeDays (int), Exclusions (array of text)
    param($Facts)
    $out = New-Object System.Collections.ArrayList
    if (-not $Facts.Available) {
        [void]$out.Add((New-Result 'Defender' 'FAIL' 'Defender status could not be read (service stopped or feature removed?) - plan Phase 7'))
        return $out.ToArray()
    }
    if ($Facts.ServiceEnabled -and $Facts.RealTime) { [void]$out.Add((New-Result 'Defender' 'PASS' 'service on, real-time protection on')) }
    else { [void]$out.Add((New-Result 'Defender' 'FAIL' "Defender service enabled: $($Facts.ServiceEnabled), real-time protection: $($Facts.RealTime)")) }
    if ($Facts.SignatureAgeDays -gt 7) { [void]$out.Add((New-Result 'Defender signatures' 'WARN' "signatures are $($Facts.SignatureAgeDays) days old (plan: apply the offline package)")) }
    else { [void]$out.Add((New-Result 'Defender signatures' 'PASS' "signatures are $($Facts.SignatureAgeDays) day(s) old")) }
    $ex = @($Facts.Exclusions | Where-Object { $_ })
    if ($ex.Count -gt 0) { [void]$out.Add((New-Result 'Defender exclusions' 'FAIL' "exclusions exist (plan: remove all, add none): $(Format-NameList $ex)")) }
    else { [void]$out.Add((New-Result 'Defender exclusions' 'PASS' 'none')) }
    $out.ToArray()
}

function Get-WindowsSettingFindings {
    # $Facts: Smb1 (bool or $null), WDigest (0/1/$null), Llmnr (EnableMulticast 0/1/$null), LmCompat (number/$null),
    #         AutoLogon (text/$null), DefaultPasswordSet (bool)
    param($Facts)
    $out = New-Object System.Collections.ArrayList
    if ($Facts.Smb1 -eq $true) { [void]$out.Add((New-Result 'SMBv1' 'WARN' 'SMBv1 is enabled (plan Phase 5: off)')) }
    else { [void]$out.Add((New-Result 'SMBv1' 'PASS' 'off')) }
    if ($Facts.WDigest -eq 1) { [void]$out.Add((New-Result 'WDigest' 'FAIL' 'UseLogonCredential = 1: passwords are kept in memory in clear text')) }
    else { [void]$out.Add((New-Result 'WDigest' 'PASS' 'clear-text credential caching is off')) }
    if ($Facts.Llmnr -eq 0) { [void]$out.Add((New-Result 'LLMNR' 'PASS' 'off')) }
    else { [void]$out.Add((New-Result 'LLMNR' 'WARN' 'LLMNR is not disabled (plan Phase 5)')) }
    [void]$out.Add((New-Result 'NTLM level' 'INFO' "LmCompatibilityLevel = $(if ($null -eq $Facts.LmCompat) { 'not set (default)' } else { $Facts.LmCompat }). NTLMv2-only (5) is a lab-test item in the plan."))
    if ($Facts.AutoLogon -eq '1' -or $Facts.DefaultPasswordSet) { [void]$out.Add((New-Result 'Auto-logon' 'FAIL' 'auto-logon is configured or a DefaultPassword is stored in the registry')) }
    else { [void]$out.Add((New-Result 'Auto-logon' 'PASS' 'no stored logon password')) }
    $out.ToArray()
}

function Get-ReviewFindings {
    # Things that should normally be empty. Not proof of a problem - a human decides. All arrays of text.
    # $Facts: HostsExtra, IfeoDebuggers, WmiSubscriptions, Shares, RunEntries
    param($Facts)
    $out = New-Object System.Collections.ArrayList
    $pairs = @(
        @('hosts file', @($Facts.HostsExtra), 'lines besides the default localhost entries'),
        @('IFEO debuggers', @($Facts.IfeoDebuggers), 'Image File Execution Options with a Debugger value (a classic backdoor)'),
        @('WMI subscriptions', @($Facts.WmiSubscriptions), 'permanent WMI event consumers'),
        @('SMB shares', @($Facts.Shares), 'shares other than the built-in admin shares')
    )
    foreach ($p in $pairs) {
        $items = @($p[1] | Where-Object { $_ })
        if ($items.Count -gt 0) { [void]$out.Add((New-Result $p[0] 'WARN' "$($p[2]): $(Format-NameList $items)")) }
        else { [void]$out.Add((New-Result $p[0] 'PASS' 'nothing unusual')) }
    }
    $run = @($Facts.RunEntries | Where-Object { $_ })
    [void]$out.Add((New-Result 'Auto-start entries' 'INFO' "$($run.Count) Run/RunOnce value(s): $(Format-NameList $run 6)"))
    $out.ToArray()
}
