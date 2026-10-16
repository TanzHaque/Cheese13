# Test-VerifyJudge.ps1 - tests the PURE judges of Verify-Hardening with made-up facts (no Windows needed).
# Each judge gets a "hardened" box (must PASS) and several broken boxes (must FAIL / WARN with the right reason).
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\ScoreLib.ps1"
. "$PSScriptRoot\..\VerifyJudgeAccounts.ps1"
. "$PSScriptRoot\..\VerifyJudgeFirewall.ps1"
. "$PSScriptRoot\..\VerifyJudgeSystem.ps1"

function Find-R { param($Results, [string]$Name) @($Results | Where-Object { $_.Name -eq $Name })[0] }
function New-U { param([string]$Name, [bool]$Enabled, [string]$Rid) [pscustomobject]@{ Name = $Name; Enabled = $Enabled; Sid = "S-1-5-21-111-222-333-$Rid" } }
function New-G { param([string]$Name, [string]$Sid, [string[]]$Members = @()) [pscustomobject]@{ Name = $Name; Sid = $Sid; Members = $Members } }

# ================================================================== secedit + logon rights + lockout
Write-Host 'secedit parsing, logon rights, lockout' -ForegroundColor Cyan
$inf = @(
    '[Unicode]', 'Unicode=yes', '[System Access]', 'MinimumPasswordAge = 0', 'LockoutBadCount = 0', 'EnableGuestAccount = 0',
    '[Privilege Rights]',
    'SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551',
    'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555',
    'SeDenyNetworkLogonRight = *S-1-5-32-546',
    'SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546'
)
$sec = ConvertFrom-Secedit $inf
Assert-Equal $sec['LockoutBadCount'] '0' 'secedit: reads LockoutBadCount'
Assert-Equal ((Get-RightEntries $sec 'SeRemoteInteractiveLogonRight') -join ',') '*S-1-5-32-544,*S-1-5-32-555' 'secedit: reads a user right as SIDs'
Assert-Equal @(Get-RightEntries $sec 'SeNoSuchRight').Count 0 'secedit: unknown right is an empty list'
Assert-Equal ((Get-RightEntries (ConvertFrom-Secedit @('SeX = S-1-5-32-544,jmoney')) 'SeX') -join ',') '*S-1-5-32-544,jmoney' 'secedit: SID without star gets a star, names stay'

$facts = [pscustomobject]@{
    Users  = @((New-U 'Administrator' $false '500'), (New-U 'Guest' $false '501'), (New-U 'jmoney' $true '1002'), (New-U 'ops-9k2' $true '1010'), (New-U 'plinktern' $false '1001'))
    Groups = @((New-G 'Administrators' 'S-1-5-32-544' @('Administrator', 'ops-9k2')), (New-G 'Remote Desktop Users' 'S-1-5-32-555' @('jmoney', 'ops-9k2')),
               (New-G 'Users' 'S-1-5-32-545' @()), (New-G 'Backup Operators' 'S-1-5-32-551' @()))
}
$allowed = @('jmoney', 'ops-9k2')
$r = Get-LogonRightFindings -Facts $facts -Secedit $sec -User jmoney -Allowed $allowed
Assert-Equal (Find-R $r 'Logon rights (jmoney)').Status 'PASS' 'default rights: jmoney may log on by RDP and network'
Assert-Equal (Find-R $r 'RDP-capable accounts').Status 'PASS' 'default rights: only allowlisted accounts can RDP'

$stig = ConvertFrom-Secedit ($inf + 'SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113')
$stig = ConvertFrom-Secedit (($inf | Where-Object { $_ -notlike 'SeDenyNetworkLogonRight*' }) + 'SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113')
$r = Get-LogonRightFindings -Facts $facts -Secedit $stig -User jmoney -Allowed $allowed
Assert-Equal (Find-R $r 'Logon rights (jmoney)').Status 'FAIL' 'STIG-style "deny network logon to Local account" breaks jmoney'
Assert-True ((Find-R $r 'Logon rights (jmoney)').Detail -match 'NLA') 'the FAIL explains that NLA would be refused'

$denyRdp = ConvertFrom-Secedit (($inf | Where-Object { $_ -notlike 'SeDenyRemoteInteractiveLogonRight*' }) + 'SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546,*S-1-5-114')
$facts2 = [pscustomobject]@{ Users = $facts.Users; Groups = @((New-G 'Administrators' 'S-1-5-32-544' @('Administrator', 'ops-9k2', 'jmoney')), $facts.Groups[1]) }
$r = Get-LogonRightFindings -Facts $facts2 -Secedit $denyRdp -User jmoney -Allowed $allowed
Assert-Equal (Find-R $r 'Logon rights (jmoney)').Status 'FAIL' 'deny RDP to "local account and member of Administrators" breaks an admin jmoney'

$noAllow = ConvertFrom-Secedit (($inf | Where-Object { $_ -notlike 'SeRemoteInteractiveLogonRight*' }) + 'SeRemoteInteractiveLogonRight = *S-1-5-32-544')
$r = Get-LogonRightFindings -Facts $facts -Secedit $noAllow -User jmoney -Allowed $allowed
Assert-Equal (Find-R $r 'Logon rights (jmoney)').Status 'FAIL' 'RDP right limited to Administrators: jmoney (not an admin) is locked out'

$extraUser = [pscustomobject]@{ Users = $facts.Users + (New-U 'helpdesk' $true '1020'); Groups = @($facts.Groups[0], (New-G 'Remote Desktop Users' 'S-1-5-32-555' @('jmoney', 'ops-9k2', 'helpdesk')), $facts.Groups[2], $facts.Groups[3]) }
$r = Get-LogonRightFindings -Facts $extraUser -Secedit $sec -User jmoney -Allowed $allowed
Assert-Equal (Find-R $r 'RDP-capable accounts').Status 'FAIL' 'a stray user in Remote Desktop Users can RDP -> FAIL'
Assert-True ((Find-R $r 'RDP-capable accounts').Detail -match 'helpdesk') 'the FAIL names the stray user'

Assert-Equal (Get-LockoutFinding $sec).Status 'PASS' 'lockout 0 -> PASS'
Assert-Equal (Get-LockoutFinding (ConvertFrom-Secedit @('LockoutBadCount = 5'))).Status 'FAIL' 'lockout 5 -> FAIL'
Assert-Equal (Get-LockoutFinding @{}).Status 'SKIP' 'no value -> SKIP'

# ================================================================== accounts
Write-Host 'accounts and groups' -ForegroundColor Cyan
$hard = Get-AccountFindings -Facts $facts -Allowed $allowed -NewAdmin 'ops-9k2'
Assert-Equal (@($hard | Where-Object { $_.Status -eq 'FAIL' }).Count) 0 'hardened box: no FAIL'
Assert-Equal (Find-R $hard 'Enabled accounts').Status 'PASS' 'hardened box: only allowlisted accounts enabled'
Assert-Equal (Find-R $hard 'New admin account').Status 'PASS' 'hardened box: new admin is fine'

$lab = [pscustomobject]@{
    Users  = @((New-U 'Administrator' $true '500'), (New-U 'Guest' $true '501'), (New-U 'jmoney' $true '1002'), (New-U 'plinktern' $true '1001'),
               (New-U 'svc_sql' $true '1040'), (New-U 'tfox' $true '1041'), (New-U 'old.employee' $false '1042'))
    Groups = @((New-G 'Administrators' 'S-1-5-32-544' @('Administrator', 'plinktern', 'PC\svc_sql', 'old.employee')),
               (New-G 'Remote Desktop Users' 'S-1-5-32-555' @('jmoney', 'tfox')), (New-G 'Power Users' 'S-1-5-32-547' @('tfox')))
}
$bad = Get-AccountFindings -Facts $lab -Allowed @('jmoney') -NewAdmin 'ops-9k2'
Assert-Equal (Find-R $bad 'Enabled accounts').Status 'FAIL' 'lab box: extra enabled accounts -> FAIL'
Assert-True ((Find-R $bad 'Enabled accounts').Detail -match 'svc_sql' -and (Find-R $bad 'Enabled accounts').Detail -match 'tfox') 'lab box: names the extra accounts'
Assert-Equal (Find-R $bad 'Built-in Administrator').Status 'FAIL' 'lab box: built-in Administrator enabled -> FAIL'
Assert-Equal (Find-R $bad 'Guest account').Status 'FAIL' 'lab box: Guest enabled -> FAIL'
Assert-Equal (Find-R $bad 'plinktern').Status 'FAIL' 'lab box: plinktern enabled -> FAIL'
Assert-Equal (Find-R $bad 'New admin account').Status 'FAIL' 'lab box: new admin does not exist -> FAIL'
Assert-Equal (Find-R $bad 'Administrators group').Status 'FAIL' 'lab box: enabled stray admins -> FAIL'
Assert-True ((Find-R $bad 'Administrators group').Detail -match 'svc_sql') 'lab box: "PC\svc_sql" is matched to svc_sql'
Assert-Equal (Find-R $bad 'Other privileged groups').Status 'FAIL' 'lab box: tfox in Power Users -> FAIL'
Assert-Equal (Find-R $bad 'Disabled but still in groups').Status 'WARN' 'lab box: old.employee disabled but still an admin -> WARN'
Assert-Equal (Find-R (Get-AccountFindings -Facts $lab -Allowed @('jmoney')) 'New admin account').Status 'SKIP' 'no -NewAdmin given -> SKIP'

$jAdmin = [pscustomobject]@{ Users = $facts.Users; Groups = @((New-G 'Administrators' 'S-1-5-32-544' @('Administrator', 'ops-9k2', 'jmoney'))) }
Assert-Equal (Find-R (Get-AccountFindings -Facts $jAdmin -Allowed $allowed -NewAdmin 'ops-9k2') 'jmoney is an administrator').Status 'INFO' 'jmoney as admin is an INFO, not a failure'

# ================================================================== firewall helpers
Write-Host 'firewall helpers' -ForegroundColor Cyan
Assert-True (Test-PortInSpec @('3389') 3389) 'port: exact match'
Assert-True (-not (Test-PortInSpec @('3389') 8080)) 'port: no match'
Assert-True (Test-PortInSpec @('8000-8100') 8080) 'port: inside a range'
Assert-True (Test-PortInSpec @('Any') 22) 'port: Any'
Assert-True (Test-PortInSpec @() 22) 'port: empty = any'
Assert-True (-not (Test-PortInSpec @('RPC', 'IPHTTPSIn') 3389)) 'port: names like RPC never match'
Assert-True (Test-IpInSpec @('172.16.3.0/24') '172.16.3.5') 'ip: inside a /24'
Assert-True (-not (Test-IpInSpec @('172.16.3.0/24') '172.16.4.5')) 'ip: outside a /24'
Assert-True (Test-IpInSpec @('172.16.3.0/255.255.255.0') '172.16.3.5') 'ip: inside a netmask-style subnet (how Windows prints it)'
Assert-True (Test-IpInSpec @('172.16.3.1-172.16.3.9') '172.16.3.5') 'ip: inside a range'
Assert-True (Test-IpInSpec @('172.16.3.5') '172.16.3.5') 'ip: single address'
Assert-True (Test-IpInSpec @('Any') '10.1.1.1') 'ip: Any'
Assert-True (-not (Test-IpInSpec @('LocalSubnet') '172.16.3.5')) 'ip: LocalSubnet is not guessed'
Assert-Equal ((Get-RuleProfiles 'Any') -join ',') 'Domain,Private,Public' 'profiles: Any = all three'
Assert-Equal ((Get-RuleProfiles 'Domain, Private') -join ',') 'Domain,Private' 'profiles: a list'
Assert-True (Test-RemoteAny @('Any')) 'remote: Any is unrestricted'
Assert-True (-not (Test-RemoteAny @('10.0.0.0/8'))) 'remote: a subnet is a restriction'

# ================================================================== firewall findings
Write-Host 'firewall findings' -ForegroundColor Cyan
function New-Rule {
    param([string]$Name, [string]$Port = '', [string]$Proto = 'TCP', [string]$Action = 'Allow', [string]$Prof = 'Any', [string]$Group = '', [string]$Remote = 'Any', [string]$Program = 'Any', [string]$RPort = '')
    [pscustomobject]@{ DisplayName = $Name; DisplayGroup = $Group; Group = ''; Profile = $Prof; Action = $Action; Protocol = $Proto
                       LocalPort = @($(if ($Port) { $Port } else { 'Any' })); RemotePort = @($(if ($RPort) { $RPort } else { 'Any' })); RemoteAddress = @($Remote); Program = $Program }
}
function New-Prof { param([string]$Name, [string]$In = 'Block', [string]$Out = 'Allow', [bool]$Log = $true, [bool]$On = $true) [pscustomobject]@{ Name = $Name; Enabled = $On; In = $In; Out = $Out; LogBlocked = $Log } }
$goodProfiles = @((New-Prof Domain), (New-Prof Private), (New-Prof Public))
$goodRules = @((New-Rule 'Remote Desktop (TCP-In)' 3389), (New-Rule 'Remote Desktop (UDP-In)' 3389 UDP), (New-Rule 'Jenkins 8080' 8080),
               (New-Rule 'Core Networking - DHCP' 68 UDP Allow Any 'Core Networking'), (New-Rule 'Core Networking - ICMP' '' ICMPv4 Allow Any 'Core Networking'))
$fw = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = $goodRules; OutRules = @() }
$r = Get-FirewallFindings -Facts $fw
Assert-Equal (@($r | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARN' }).Count) 0 'hardened firewall: no FAIL or WARN'
Assert-Equal (Find-R $r 'Allow TCP 3389').Status 'PASS' 'hardened firewall: 3389 allowed'
Assert-Equal (Find-R $r 'Allow TCP 8080').Status 'PASS' 'hardened firewall: 8080 allowed'

$sloppy = [pscustomobject]@{ Profiles = @((New-Prof Domain), (New-Prof Private 'Allow'), (New-Prof Public 'Block' 'Allow' $false $false)); ActiveProfiles = @('Public')
    Rules = $goodRules + (New-Rule 'Dev Web' 8000) + (New-Rule 'Legacy FTP' 21) + (New-Rule 'Remote Desktop - Shadow (TCP-In)' '' TCP Allow Any 'Remote Desktop' Any 'C:\Windows\system32\RdpSa.exe'); OutRules = @() }
$r = Get-FirewallFindings -Facts $sloppy
Assert-Equal (Find-R $r 'Firewall profiles').Status 'FAIL' 'sloppy: Public profile off -> FAIL'
Assert-Equal (Find-R $r 'Inbound default').Status 'FAIL' 'sloppy: Private inbound default Allow -> FAIL'
Assert-Equal (Find-R $r 'Other inbound allow rules').Status 'FAIL' 'sloppy: leftover allow rules -> FAIL'
Assert-True ((Find-R $r 'Other inbound allow rules').Detail -match 'Dev Web' -and (Find-R $r 'Other inbound allow rules').Detail -match 'Shadow') 'sloppy: leftover rules are named (incl. the program-limited Shadow rule)'
Assert-Equal (Find-R $r 'Firewall logging').Status 'WARN' 'sloppy: logging off -> WARN'
Assert-Equal (Find-R (Get-FirewallFindings -Facts $sloppy -AllowedRules @('Dev Web', 'Legacy FTP', 'Remote Desktop - Shadow (TCP-In)')) 'Other inbound allow rules').Status 'PASS' '-AllowedRules lets you keep chosen rules'

$noRule = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Private'); Rules = @($goodRules[2]); OutRules = @() }
Assert-Equal (Find-R (Get-FirewallFindings -Facts $noRule) 'Allow TCP 3389').Status 'FAIL' 'no 3389 rule at all -> FAIL'

$limited = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Private'); Rules = @((New-Rule 'RDP office only' 3389 TCP Allow Any '' '10.0.0.0/8'), $goodRules[2]); OutRules = @() }
$x = Find-R (Get-FirewallFindings -Facts $limited) 'Allow TCP 3389'
Assert-Equal $x.Status 'FAIL' 'a source-restricted RDP rule -> FAIL (scoring IPs vary)'

$profLimited = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = @((New-Rule 'RDP' 3389 TCP Allow 'Domain, Private'), $goodRules[2]); OutRules = @() }
Assert-Equal (Find-R (Get-FirewallFindings -Facts $profLimited) 'Allow TCP 3389').Status 'FAIL' 'rule not applying to the ACTIVE (Public) profile -> FAIL'
$profLimited.ActiveProfiles = @('Private')
Assert-Equal (Find-R (Get-FirewallFindings -Facts $profLimited) 'Allow TCP 3389').Status 'WARN' 'rule missing only on an inactive profile -> WARN'

# Windows' own "Remote Desktop - User Mode (TCP-In)" rule is tied to svchost.exe: it works, so it must not be reported as "no rule"
$svcRule = New-Rule 'Remote Desktop - User Mode (TCP-In)' 3389 TCP Allow Any 'Remote Desktop' Any 'C:\Windows\system32\svchost.exe'
$svchostOnly = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = @($svcRule, $goodRules[2]); OutRules = @() }
$x = Find-R (Get-FirewallFindings -Facts $svchostOnly) 'Allow TCP 3389'
Assert-Equal $x.Status 'WARN' 'only the program-bound RDP rule -> WARN, not a false FAIL'
Assert-True ($x.Detail -match 'one program') 'the WARN says the rule is tied to one program'
$mixed = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = @((New-Rule 'RDP plain' 3389 TCP Allow 'Domain, Private'), $svcRule, $goodRules[2]); OutRules = @() }
$x = Find-R (Get-FirewallFindings -Facts $mixed) 'Allow TCP 3389'
Assert-Equal $x.Status 'WARN' 'plain rule on two profiles + program-bound rule everywhere -> WARN (works, but not plain everywhere)'
Assert-True ($x.Detail -match 'Public') 'the WARN names the profile that only has the program-bound rule'

$blanket = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = $goodRules + (New-Rule 'Block all Public' '' Any Block Public); OutRules = @() }
$x = Find-R (Get-FirewallFindings -Facts $blanket) 'Inbound block rules'
Assert-Equal $x.Status 'FAIL' 'last year''s hazard: a blanket inbound block on Public -> FAIL'
Assert-True ($x.Detail -match 'BLANKET') 'the FAIL says it is a blanket block'
$blockSome = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = $goodRules + (New-Rule 'Block redteam' 3389 TCP Block Any '' '203.0.113.0/24'); OutRules = @() }
Assert-Equal (Find-R (Get-FirewallFindings -Facts $blockSome) 'Inbound block rules').Status 'WARN' 'a block on 3389 for one subnet -> WARN (do not block broad ranges)'
$blockProg = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = $goodRules + (New-Rule 'Block java' 8080 TCP Block Any '' Any 'C:\Program Files\Java\bin\java.exe'); OutRules = @() }
$x = Find-R (Get-FirewallFindings -Facts $blockProg) 'Inbound block rules'
Assert-Equal $x.Status 'WARN' 'a block rule tied to one program on a scored port -> WARN'
Assert-True ($x.Detail -match 'java.exe') 'the WARN names the program'
$blockOther = [pscustomobject]@{ Profiles = $goodProfiles; ActiveProfiles = @('Public'); Rules = $goodRules + (New-Rule 'Block telnet' 23 TCP Block); OutRules = @() }
Assert-Equal (Find-R (Get-FirewallFindings -Facts $blockOther) 'Inbound block rules').Status 'PASS' 'a block on an unrelated port is fine'

$outBlock = [pscustomobject]@{ Profiles = @((New-Prof Domain 'Block' 'Block'), (New-Prof Private 'Block' 'Block'), (New-Prof Public 'Block' 'Block')); ActiveProfiles = @('Public'); Rules = $goodRules
    OutRules = @((New-Rule 'Allow lab net' '' TCP Allow Any '' '172.16.3.0/255.255.255.0' Any 22)) }
Assert-Equal (Find-R (Get-FirewallFindings -Facts $outBlock -BlackboxIp 172.16.3.5) 'Outbound default').Status 'PASS' 'outbound Block + allow rule to blackbox:22 -> PASS'
Assert-Equal (Find-R (Get-FirewallFindings -Facts $outBlock -BlackboxIp 172.16.9.5) 'Outbound default').Status 'FAIL' 'outbound Block + no rule for the blackbox IP -> FAIL'
Assert-Equal (Find-R (Get-FirewallFindings -Facts $outBlock) 'Outbound default').Status 'INFO' 'outbound Block, no -BlackboxIp -> INFO'
Assert-Equal (Find-R (Get-FirewallFindings -Facts $fw) 'Outbound default').Status 'INFO' 'outbound open -> INFO'

# ================================================================== RDP, services, Defender, settings, leftovers
Write-Host 'RDP, services, Defender, settings, leftovers' -ForegroundColor Cyan
$rdpGood = [pscustomobject]@{ DenyConnections = 0; Port = 3389; Nla = 1; SecurityLayer = 2; DisableClip = 0; ServiceDll = 'C:\Windows\System32\termsrv.dll'
                              SigStatus = 'Valid'; SigSubject = 'CN=Microsoft Windows, O=Microsoft Corporation'; TermServiceState = 'Running'; Listening = $true }
$r = Get-RdpFindings $rdpGood
Assert-Equal (@($r | Where-Object { $_.Status -ne 'PASS' }).Count) 0 'RDP: good config -> all PASS'
$rdpBad = [pscustomobject]@{ DenyConnections = 1; Port = 3390; Nla = 0; SecurityLayer = 0; DisableClip = 1; ServiceDll = 'C:\Users\Public\termsrv.dll'
                             SigStatus = 'NotSigned'; SigSubject = ''; TermServiceState = 'Stopped'; Listening = $false }
$r = Get-RdpFindings $rdpBad
Assert-Equal (Find-R $r 'RDP enabled').Status 'FAIL' 'RDP: turned off -> FAIL'
Assert-Equal (Find-R $r 'RDP port').Status 'FAIL' 'RDP: port changed -> FAIL'
Assert-Equal (Find-R $r 'TermService').Status 'FAIL' 'RDP: service stopped -> FAIL'
Assert-Equal (Find-R $r 'RDP NLA').Status 'WARN' 'RDP: NLA off -> WARN'
Assert-Equal (Find-R $r 'RDP clipboard').Status 'FAIL' 'RDP: clipboard disabled -> FAIL'
Assert-Equal (Find-R $r 'TermService DLL').Status 'FAIL' 'RDP: hijacked ServiceDll -> FAIL'

$svcGood = [pscustomobject]@{ Services = @([pscustomobject]@{ Name = 'Jenkins'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem' }) }
$r = Get-ServiceFindings $svcGood
Assert-Equal (Find-R $r 'Jenkins service').Status 'PASS' 'services: Jenkins running -> PASS'
Assert-Equal (Find-R $r 'Spooler service').Status 'PASS' 'services: Spooler absent/stopped -> PASS'
$svcBad = [pscustomobject]@{ Services = @([pscustomobject]@{ Name = 'Jenkins'; State = 'Stopped'; StartMode = 'Auto'; StartName = 'x' }, [pscustomobject]@{ Name = 'Spooler'; State = 'Running'; StartMode = 'Auto'; StartName = 'x' }) }
$r = Get-ServiceFindings $svcBad
Assert-Equal (Find-R $r 'Jenkins service').Status 'FAIL' 'services: Jenkins stopped -> FAIL'
Assert-Equal (Find-R $r 'Spooler service').Status 'WARN' 'services: Spooler running -> WARN'
Assert-Equal (Find-R (Get-ServiceFindings ([pscustomobject]@{ Services = @() })) 'Jenkins service').Status 'FAIL' 'services: no Jenkins service -> FAIL'
$svcOdd = [pscustomobject]@{ Services = @([pscustomobject]@{ Name = 'RocketCI'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\Program Files\Jenkins\jenkins.exe"' }) }
Assert-Equal (Find-R (Get-ServiceFindings $svcOdd) 'Jenkins service').Status 'PASS' 'services: Jenkins found by program path when the service has another name'

$defGood = [pscustomobject]@{ Available = $true; ServiceEnabled = $true; RealTime = $true; SignatureAgeDays = 1; Exclusions = @() }
$r = Get-DefenderFindings $defGood
Assert-Equal (@($r | Where-Object { $_.Status -ne 'PASS' }).Count) 0 'Defender: healthy -> all PASS'
$r = Get-DefenderFindings ([pscustomobject]@{ Available = $true; ServiceEnabled = $true; RealTime = $false; SignatureAgeDays = 30; Exclusions = @('C:\Windows\Temp\cache') })
Assert-Equal (Find-R $r 'Defender').Status 'FAIL' 'Defender: real-time off -> FAIL'
Assert-Equal (Find-R $r 'Defender signatures').Status 'WARN' 'Defender: old signatures -> WARN'
Assert-Equal (Find-R $r 'Defender exclusions').Status 'FAIL' 'Defender: exclusions -> FAIL'
Assert-Equal @(Get-DefenderFindings ([pscustomobject]@{ Available = $false }))[0].Status 'FAIL' 'Defender: status unreadable -> FAIL'

$setGood = [pscustomobject]@{ Smb1 = $false; WDigest = 0; Llmnr = 0; LmCompat = 5; AutoLogon = '0'; DefaultPasswordSet = $false }
Assert-Equal (@(Get-WindowsSettingFindings $setGood | Where-Object { $_.Status -eq 'FAIL' -or $_.Status -eq 'WARN' }).Count) 0 'settings: hardened -> no FAIL/WARN'
$setBad = [pscustomobject]@{ Smb1 = $true; WDigest = 1; Llmnr = $null; LmCompat = $null; AutoLogon = '1'; DefaultPasswordSet = $true }
$r = Get-WindowsSettingFindings $setBad
Assert-Equal (Find-R $r 'SMBv1').Status 'WARN' 'settings: SMBv1 on -> WARN'
Assert-Equal (Find-R $r 'WDigest').Status 'FAIL' 'settings: WDigest clear-text on -> FAIL'
Assert-Equal (Find-R $r 'Auto-logon').Status 'FAIL' 'settings: auto-logon password -> FAIL'

$revClean = [pscustomobject]@{ HostsExtra = @(); IfeoDebuggers = @(); WmiSubscriptions = @(); Shares = @(); RunEntries = @('SecurityHealth') }
Assert-Equal (@(Get-ReviewFindings $revClean | Where-Object { $_.Status -eq 'WARN' }).Count) 0 'leftovers: clean box -> no WARN'
$revDirty = [pscustomobject]@{ HostsExtra = @('127.0.0.1 av-updates.example'); IfeoDebuggers = @('sethc.exe'); WmiSubscriptions = @('SysHealthConsumer'); Shares = @('ShipData'); RunEntries = @('A', 'B') }
Assert-Equal (@(Get-ReviewFindings $revDirty | Where-Object { $_.Status -eq 'WARN' }).Count) 4 'leftovers: four kinds of leftovers -> four WARN'

Write-TestSummary
