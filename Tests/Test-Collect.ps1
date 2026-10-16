# Test-Collect.ps1 - runs the REAL collectors (lib\Collect.ps1) against the pretend Windows box (FakeWindows.ps1).
# It proves the collectors run end to end, read the right properties and survive a broken section.
# It does NOT prove that real Windows returns these shapes: that is the first thing to check in the lab.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\lib\Core.ps1"
. "$PSScriptRoot\..\lib\DeadMan.ps1"
. "$PSScriptRoot\..\lib\Collect.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-collect-' + [guid]::NewGuid().ToString('N'))
$global:FW = New-FakeBox
$script:HpRoot = Join-Path $PSScriptRoot '..'
Initialize-Hp -DataDir $tmp -NoAcl

Write-Host 'Small helpers' -ForegroundColor Cyan
Assert-Equal (Get-ExePath '"C:\Program Files\Jenkins\jenkins.exe" -arg x') 'C:\Program Files\Jenkins\jenkins.exe' 'quoted path with arguments'
Assert-Equal (Get-ExePath 'C:\Windows\System32\svchost.exe -k NetworkService -p') 'C:\Windows\System32\svchost.exe' 'unquoted path with arguments'
Assert-Equal (Get-ExePath 'C:\Program Files\Some App\app.exe') 'C:\Program Files\Some App\app.exe' 'unquoted path with spaces'
Assert-Equal (Get-ExePath '') '' 'empty command line'
Assert-Equal (Get-BareName 'ASSEMBLY-5\jmoney') 'jmoney' 'bare name strips the machine'
$sec = ConvertFrom-Secedit @('[Unicode]', 'Unicode=yes', '[System Access]', 'LockoutBadCount = 5', '[Privilege Rights]', 'SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544')
Assert-Equal $sec['LockoutBadCount'] '5' 'secedit: a plain setting'
Assert-Equal $sec['SeNetworkLogonRight'] '*S-1-1-0,*S-1-5-32-544' 'secedit: a user right'

Write-Host 'All collectors against the fake lab box' -ForegroundColor Cyan
$f = Get-HpFacts
Assert-True (@($f.Errors).Count -eq 0) ('no collector failed' + $(if (@($f.Errors).Count) { ': ' + (@($f.Errors) -join ' | ') } else { '' }))

Write-Host 'Host, network, tools' -ForegroundColor Cyan
Assert-Equal $f.Host.ComputerName 'ASSEMBLY-5' 'computer name'
Assert-True ($f.Host.Os -match 'Server 2022') 'OS caption'
Assert-Equal $f.Host.Build '20348.4000' 'build number with the update revision'
Assert-True ($f.Host.LastHotfix -match 'KB5031364 installed 2026-09-14') 'last hotfix'
Assert-True ($f.Host.Ips -contains '172.16.5.30' -and $f.Host.Ips -notcontains '127.0.0.1') 'IP addresses without loopback'
Assert-True ($f.Net.Profiles -contains 'Private') 'network profile'
Assert-True $f.Net.Internet 'Internet reachable'
Assert-True ($null -eq $f.Net.BlackboxSsh) 'blackbox not tested while its IP is not set'
Assert-True (-not [string]::IsNullOrEmpty($f.Tools.Scp)) 'scp.exe found'
Assert-Equal (Get-FakeKey $f.Tools.Ssh) 'c:\windows\system32\openssh\ssh.exe' 'ssh.exe path'
Assert-True ($f.Tools.SshVersion -match 'OpenSSH_for_Windows_8.1') 'ssh version text'
Assert-Equal $f.Tools.DotNetRelease 528040 '.NET release number'

Write-Host 'Accounts and rights' -ForegroundColor Cyan
Assert-Equal @($f.Accounts.Users).Count 13 'thirteen local users'
$jm = $f.Accounts.Users | Where-Object { $_.Name -eq 'jmoney' }
Assert-True ($jm.Enabled -and $jm.Sid -match '-1002$') 'jmoney: enabled, with its SID'
$admins = @($f.Accounts.Groups | Where-Object { $_.Name -eq 'Administrators' }).Members
Assert-True (($admins -contains 'plinktern') -and ($admins -contains 'support$') -and ($admins -contains 'old.employee')) 'Administrators members read through net localgroup'
Assert-True (-not ($admins -contains 'jmoney')) 'jmoney is not an administrator'
Assert-Equal $f.Secedit['LockoutBadCount'] '5' 'lockout threshold from secedit'
Assert-Equal $f.Secedit['SeRemoteInteractiveLogonRight'] '*S-1-5-32-544,*S-1-5-32-555' 'RDP logon right from secedit'

Write-Host 'Services and tasks' -ForegroundColor Cyan
Assert-Equal @($f.Services).Count 8 'eight services (the two Defender services included)'
$jsvc = $f.Services | Where-Object { $_.Name -eq 'Jenkins' }
Assert-Equal $jsvc.Exe 'C:\Program Files\Jenkins\jenkins.exe' 'service program path is cut out of the command line'
Assert-Equal ($f.Services | Where-Object { $_.Name -eq 'BackupSvc' }).StartName '.\svc_backup' 'service account is kept'
Assert-Equal @($f.Tasks).Count 3 'three tasks'
$nc = $f.Tasks | Where-Object { $_.Name -eq 'NightlyCopy' }
Assert-Equal $nc.UserId 'ASSEMBLY-5\plinktern' 'task principal'
Assert-Equal $nc.Actions[0] 'C:\Tools\copy.bat' 'task action text'

Write-Host 'Ports' -ForegroundColor Cyan
Assert-Equal @($f.Ports.Listeners).Count 6 'six listeners (5 TCP, 1 UDP)'
$l8080 = $f.Ports.Listeners | Where-Object { $_.Port -eq 8080 }
Assert-True ($l8080.Process -eq 'java' -and $l8080.SigStatus -eq 'Valid') '8080 belongs to java, signed'
$l21 = $f.Ports.Listeners | Where-Object { $_.Port -eq 21 }
Assert-True ($l21.Process -eq 'ftpd' -and $l21.SigStatus -eq 'NotSigned' -and $l21.Path -match 'Public') 'port 21 belongs to an unsigned program in a public folder'
$l445 = $f.Ports.Listeners | Where-Object { $_.Port -eq 445 }
Assert-True ($l445.Process -eq 'System' -and $l445.Path -eq '') 'System has no path'
Assert-Equal @($f.Ports.Connections).Count 2 'two established connections'
Assert-True (@($f.Ports.Connections | Where-Object { $_.RemoteAddress -eq '203.0.113.9' -and $_.Process -eq 'ftpd' }).Count -eq 1) 'a connection to an outside address names its program'

Write-Host 'Firewall' -ForegroundColor Cyan
Assert-Equal @($f.Firewall.Profiles).Count 3 'three profiles'
Assert-True ($f.Firewall.Profiles[0].Enabled -and $f.Firewall.Profiles[0].AllowInboundRules) 'profile flags are real booleans'
Assert-Equal @($f.Firewall.Rules).Count 12 'twelve enabled inbound rules (one of them from Group Policy)'
$ghost = $f.Firewall.Rules | Where-Object { $_.Name -eq 'GpoDeliveredRule' }
Assert-True (-not $ghost.Local) 'a rule that is not in the local store is marked as coming from policy'
$jr = $f.Firewall.Rules | Where-Object { $_.Name -eq 'Jenkins 8080' }
Assert-True ($jr.Local -and $jr.LocalPort -contains '8080' -and $jr.Protocol -eq 'TCP' -and $jr.Action -eq 'Allow') 'rule details: local, port, protocol, action'
$rd = $f.Firewall.Rules | Where-Object { $_.Name -eq 'RemoteDesktop-UserMode-In-TCP' }
Assert-Equal $rd.Program 'C:\Windows\System32\svchost.exe' 'the built-in RDP rule is tied to a program'
Assert-Equal $f.Firewall.ServiceState 'Running' 'firewall service state'
Assert-Equal @($f.Firewall.OurRules).Count 0 'none of our own rules yet'

Write-Host 'Defender, Jenkins, collector, backup' -ForegroundColor Cyan
Assert-True ($f.Defender.Available -and $f.Defender.RealTime -and $f.Defender.Exclusions.Count -eq 0) 'Defender facts'
$j = $f.Jenkins
Assert-True $j.Found 'Jenkins found'
Assert-True ($j.Service -eq 'Jenkins' -and $j.StartName -eq 'LocalSystem' -and $j.State -eq 'Running') 'service, account and state'
Assert-Equal $j.Home 'C:\ProgramData\Jenkins\.jenkins' 'JENKINS_HOME read from jenkins.xml'
Assert-True $j.HomeFound 'and that folder exists'
Assert-True ($j.Java -match 'java.exe' -and $j.JavaVersion -eq '17.0.9.9') 'Java path and version'
Assert-True ($j.Listening -and $j.PortOwner -eq 'java') 'port 8080 is owned by java'
Assert-True ($j.InitGroovy -contains 'lab-init.groovy') 'init.groovy.d listing'
Assert-True (@($f.Collector | Where-Object { $_.Kind -eq 'service' -and $_.Name -eq 'otelcol' }).Count -eq 1) 'the log collector service is recognised by its name'
Assert-True (@($f.Collector | Where-Object { $_.Kind -eq 'connection' }).Count -eq 0) 'no connection match while blackbox IP is unknown'
Assert-Equal @($f.Backup.Archives).Count 0 'no backup archives yet'

Write-Host 'Blackbox known' -ForegroundColor Cyan
Set-HpSetting 'BlackboxIp' '172.16.5.5'
$f2 = Get-HpFacts
Assert-True ($f2.Net.BlackboxSsh -eq $true) 'blackbox port 22 reachable'
$conn = @($f2.Collector | Where-Object { $_.Kind -eq 'connection' })
Assert-True ($conn.Count -eq 1 -and $conn[0].Name -eq 'otelcol-contrib' -and $conn[0].Detail -match '4317') 'the program connected to blackbox is found'
$global:FW.Tcp.Remove('172.16.5.5:22')
Assert-True ((Get-HpFacts -Sections 'Net' -Previous $f2).Net.BlackboxSsh -eq $false) 'blackbox down is noticed'

Write-Host 'Jenkins discovery fallbacks' -ForegroundColor Cyan
$saveXml = $global:FW.Files[(Get-FakeKey 'C:\Program Files\Jenkins\jenkins.xml')]
$global:FW.Files.Remove((Get-FakeKey 'C:\Program Files\Jenkins\jenkins.xml'))
$j = (Get-HpFacts -Sections 'Jenkins' -Previous $f).Jenkins
Assert-Equal $j.Home 'C:\ProgramData\Jenkins\.jenkins' 'without jenkins.xml: JENKINS_HOME comes from the service environment'
Assert-True ($j.Java -match 'java.exe') 'and Java comes from the process that owns port 8080'
$global:FW.Reg.Remove('hklm:\system\currentcontrolset\services\jenkins|Environment')
$global:FW.Files[(Get-FakeKey 'C:\ProgramData\Jenkins\.jenkins\config.xml')] = '<x/>'
$j = (Get-HpFacts -Sections 'Jenkins' -Previous $f).Jenkins
Assert-Equal $j.Home 'C:\ProgramData\Jenkins\.jenkins' 'without both: the usual places are tried (config.xml proves it)'
$global:FW.Files.Remove((Get-FakeKey 'C:\ProgramData\Jenkins\.jenkins\config.xml'))
$j = (Get-HpFacts -Sections 'Jenkins' -Previous $f).Jenkins
Assert-True ($j.Found -and $j.Home -eq '' -and -not $j.HomeFound) 'if nothing is found the home is empty (not a crash)'
$global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'Jenkins' })
$j = (Get-HpFacts -Sections 'Services', 'Jenkins' -Previous $f).Jenkins
Assert-True (-not $j.Found) 'no Jenkins service -> Found is false'
$global:FW.Services += @{ Name = 'CI'; DisplayName = 'CI'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"D:\jenkins\run.exe"'; ProcessId = 1 }
$j = (Get-HpFacts -Sections 'Services', 'Jenkins' -Previous $f).Jenkins
Assert-True ($j.Found -and $j.Service -eq 'CI') 'Jenkins is found by its program path when the service name is different'
$global:FW.Files[(Get-FakeKey 'C:\Program Files\Jenkins\jenkins.xml')] = $saveXml

Write-Host 'Backup facts' -ForegroundColor Cyan
$bdir = Get-HpDir 'backup'
Set-Content -Path (Join-Path $bdir 'as-found-20261017-0930.zip.enc') -Value 'x'
[IO.File]::WriteAllText((Join-Path $bdir 'sent.json'), '{"Name":"as-found-20261017-0930.zip.enc","Sha256":"abc","Ip":"172.16.5.5"}')
$b = (Get-HpFacts -Sections 'Backup' -Previous $f).Backup
Assert-Equal @($b.Archives).Count 1 'one archive listed'
Assert-Equal $b.Sent.Ip '172.16.5.5' 'the last upload record is read'

Write-Host 'A broken collector does not stop the others' -ForegroundColor Cyan
$global:FW.BreakTasks = $true
$f3 = Get-HpFacts
Assert-True (@($f3.Errors) -match '^Tasks: Access is denied') 'the failure is listed with its section name'
Assert-True ($null -eq $f3.Tasks) 'the broken section is empty'
Assert-Equal @($f3.Accounts.Users).Count 13 'but the other sections are fine'
$global:FW.BreakTasks = $false
$f4 = Get-HpFacts -Sections 'Tasks' -Previous $f3
Assert-Equal @($f4.Tasks).Count 3 'a partial refresh fixes just that section'
Assert-Equal @($f4.Errors | Where-Object { $_ -like 'Tasks:*' }).Count 0 'and its old error is gone'
Assert-Equal @($f4.Errors | Where-Object { $_ -like 'Watchdog:*' }).Count 1 'the watchdog section reads the task list too: its error stays until that section is read again'
Assert-Equal @((Get-HpFacts -Sections 'Tasks', 'Watchdog' -Previous $f3).Errors).Count 0 'and reading both clears every error'
Assert-Equal @($f4.Accounts.Users).Count 13 'while the other sections are carried over'

Write-Host 'Partial refresh sees new facts' -ForegroundColor Cyan
$null = New-NetFirewallRule -DisplayName 'HP Allow TCP 9' -Direction Inbound -Protocol TCP -LocalPort 9 -Action Allow
$f5 = Get-HpFacts -Sections 'Firewall' -Previous $f
Assert-Equal @($f5.Firewall.Rules).Count 13 'a new rule shows up after refreshing only the firewall'
Assert-Equal @($f5.Firewall.OurRules).Count 1 'and it is listed as one of ours'
Assert-Equal @($f.Firewall.Rules).Count 12 'the old facts object is not modified'

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-TestSummary
