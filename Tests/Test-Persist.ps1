# Test-Persist.ps1 - the PERSISTENCE audit (phase 6, second part) and the Defender diagnosis (phase 7): the new collectors in lib\Collect.ps1
# and the new judges in lib\JudgeHunt.ps1 / lib\Judge.ps1, against the pretend box. The audit itself is READ-ONLY; this file also checks WHICH rows
# offer a fix and that each fix builds an action (building changes nothing). Running the fixes is Test-ActPersist.ps1's job.
# It proves: a clean box gives no complaints, every planted item gives a row with the right severity, the never-touch list is respected,
# one reader that fails does not hide the others, and Defender's own services are not mistaken for a planted service.
# It does NOT prove that real Windows returns these shapes (registry value types, CIM subscription objects, Get-SmbShare, Get-WindowsFeature).
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
. "$PSScriptRoot\..\lib\Act-Hunt.ps1"
. "$PSScriptRoot\..\lib\Act-Persist.ps1"
. "$PSScriptRoot\..\lib\Act-Watchdog.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-persist-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl

function Get-Scenario {
    # A fresh pretend box, optionally changed by $Tweak, then the facts and the rows of the chosen phases.
    param([scriptblock]$Tweak = $null, [int[]]$Phases = @())
    $global:FW = New-FakeBox
    if ($Tweak) { & $Tweak }
    $f = Get-HpFacts
    $s = @{}
    foreach ($k in $script:SettingDefaults.Keys) { $s[$k] = $script:SettingDefaults[$k] }
    [pscustomobject]@{ Facts = $f; Rows = @(Get-HpFindings -Facts $f -Settings $s -Phases $Phases) }
}
function Find-Row {
    param($Rows, [string]$Area, [string]$Like)
    @($Rows | Where-Object { $_.Area -eq $Area -and $_.Subject -like $Like }) | Select-Object -First 1
}
function Get-RowCount { param($Rows, [string]$Area, [string]$Like = '*') @($Rows | Where-Object { $_.Area -eq $Area -and $_.Subject -like $Like }).Count }
function Get-Worry { param($Rows, [string]$Area) @($Rows | Where-Object { $_.Area -eq $Area -and ($_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN') }) }

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Small helpers' -ForegroundColor Cyan
Assert-Equal (Get-WmiName '__EventFilter (Name = "SCM Event Log Filter")') 'SCM Event Log Filter' 'WMI reference in the CIM form'
Assert-Equal (Get-WmiName '\\.\root\subscription:__EventFilter.Name="Updater Filter"') 'Updater Filter' 'WMI reference in the old string form'
Assert-Equal (Get-ShortText ('a' * 300) 20) ('a' * 20 + '...') 'long text is cut'
Assert-Equal (Get-ShortText "two   words`r`n here") 'two words here' 'white space is squeezed'
Assert-Equal (Get-StartSeverity 'C:\Windows\system32\SecurityHealthSystray.exe') 'INFO' 'a Windows program is normal'
Assert-Equal (Get-StartSeverity '"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr') 'INFO' 'a Program Files program is normal'
Assert-Equal (Get-StartSeverity 'C:\Users\Public\up.exe /silent') 'BAD' 'a program in the Public folder is red'
Assert-Equal (Get-StartSeverity 'D:\tools\x.exe') 'WARN' 'a program on another drive is a warning'
Assert-Equal (Get-StartSeverity 'cmd.exe /c start x') 'WARN' 'a script interpreter is a warning'
Assert-Equal (Get-StartSeverity 'rundll32.exe x.dll,Run') 'WARN' 'rundll32 is a warning'
Assert-True (Test-StandardFolder 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe') 'Defender''s own folder under ProgramData is a standard folder'
Assert-True (-not (Test-StandardFolder 'C:\ProgramData\Evil\x.exe')) 'but other ProgramData folders are not'
Assert-True (Test-NeverTouchApp 'x' 'C:\Users\Public\jenkins-agent.exe') 'never-touch: Jenkins in a Run entry'
Assert-True (-not (Test-NeverTouchApp 'x' 'C:\Windows\System32\cmd.exe /c x')) 'a Run entry in System32 is NOT protected (that is what the audit must flag)'
Assert-True (Test-ProtectedProgram 'WinDefend' 'C:\ProgramData\Microsoft\Windows Defender\Platform\1\MsMpEng.exe') 'Defender is on the never-touch list for services'
Assert-True (Test-ProtectedProgram 'x' 'C:\Windows\System32\cmd.exe') 'and Windows folders still are, for services'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A clean box: the facts' -ForegroundColor Cyan
$clean = Get-Scenario
$p = $clean.Facts.Persist
Assert-Equal @($clean.Facts.Errors).Count 0 'no collector error'
Assert-Equal @($p.Problems).Count 0 'no reader failed'
Assert-True (@($p.RunValues).Count -eq 1 -and $p.RunValues[0].Name -eq 'SecurityHealth' -and $p.RunValues[0].Where -eq 'machine Run') 'one Run value: the Windows Security icon'
Assert-Equal @($p.StartupFiles).Count 0 'no startup files'
Assert-True ($p.Winlogon.Shell -eq 'explorer.exe' -and $p.Winlogon.Userinit -match 'userinit\.exe,$' -and $p.Winlogon.Taskman -eq '') 'Winlogon values'
Assert-Equal @($p.Debuggers).Count 0 'no debugger hooks'
Assert-True (@($p.AppInit).Count -eq 2 -and $p.AppInit[0].Dlls -eq '' -and $p.AppInit[0].LoadAppInit -eq 0) 'AppInit: 64-bit and 32-bit keys, both empty'
Assert-True (($p.Lsa.Authentication -contains 'msv1_0') -and ($p.Lsa.Notification -contains 'scecli')) 'LSA packages'
Assert-True (@($p.Accessibility).Count -eq 6 -and @($p.Accessibility | Where-Object { $_.Exists -and $_.SigStatus -eq 'Valid' -and -not $_.LooksLikeShell }).Count -eq 6) 'six sticky-keys programs, all signed and not a copy of a shell'
Assert-True (@($p.Wmi.Consumers).Count -eq 1 -and $p.Wmi.Consumers[0].Name -eq 'SCM Event Log Consumer' -and $p.Wmi.Bindings[0].Filter -eq 'SCM Event Log Filter') 'WMI: only Windows'' own subscription'
Assert-True (@($p.Hosts.Entries).Count -eq 1 -and $p.Hosts.Entries[0] -eq '127.0.0.1 localhost') 'hosts: comments are dropped'
Assert-True (@($p.Shares).Count -eq 3 -and @($p.Shares | Where-Object { $_.Special }).Count -eq 3) 'three special shares'
Assert-True (@($p.Bits).Count -eq 0 -and @($p.ProfileFiles).Count -eq 0 -and @($p.PolicyScripts).Count -eq 0 -and @($p.Proxy).Count -eq 0) 'no BITS jobs, profiles, policy scripts or proxies'
Assert-True ($p.RdpDll.Path -eq 'C:\Windows\System32\termsrv.dll' -and $p.RdpDll.SigStatus -eq 'Valid') 'TermService''s DLL: the variable is expanded and the signature read'

Write-Host 'A clean box: the rows' -ForegroundColor Cyan
$rows = $clean.Rows
$worry = @($rows | Where-Object { $_.Phase -in 6, 7 -and ($_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN') } | Where-Object { $_.Area -notin 'Services', 'Scheduled tasks', 'Ports', 'Connections' })
Assert-Equal $worry.Count 0 ('no BAD or WARN in the persistence and Defender rows' + $(if ($worry.Count) { ': ' + (($worry | ForEach-Object { $_.Subject }) -join ' | ') } else { '' }))
$sum = Find-Row $rows 'Persistence' 'Persistence audit'
Assert-True ($sum.Severity -eq 'INFO' -and $sum.Why -match 'Nothing found in: Run keys, Startup folders, Winlogon' -and $sum.Why -notmatch 'Rows above for') 'the summary row says everything was checked and clean'
Assert-True ($sum.Why -match 'Not covered: Run keys of users who are not logged on') 'and it says what is NOT covered'
Assert-True ((Find-Row $rows 'Startup entries' '1 startup entries look normal').Why -match 'SecurityHealth') 'normal startup entries are summed up in one INFO row'
Assert-True ($null -eq (Find-Row $rows 'Services' 'Service WinDefend') -and $null -eq (Find-Row $rows 'Services' 'Service WdNisSvc')) 'the hunt does NOT offer to disable Defender''s services (their program sits under ProgramData)'
$keys = @($rows | ForEach-Object { $_.Key })
Assert-Equal ($keys | Select-Object -Unique).Count $keys.Count 'every row has its own key'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A box with persistence planted: the facts' -ForegroundColor Cyan
$bad = Get-Scenario { Add-FakePersistence }
$p = $bad.Facts.Persist
Assert-Equal @($bad.Facts.Errors).Count 0 'no collector error'
Assert-Equal @($p.Problems).Count 0 'no reader failed'
$run = @($p.RunValues)
Assert-Equal $run.Count 5 'five Run values (three in the machine keys, one 32-bit RunOnce, one of jmoney)'
$u = $run | Where-Object { $_.Name -eq 'Sync' }
Assert-True ($u.Where -eq 'user Run' -and $u.Sid -eq 'S-1-5-21-1111-2222-3333-1002' -and $u.Data -match 'cmd\.exe') 'a user''s Run value is found through the loaded hive and carries the SID'
Assert-True (@($run | Where-Object { $_.Name -eq 'Beacon' -and $_.Where -eq 'machine 32-bit RunOnce' }).Count -eq 1) 'the 32-bit RunOnce key is read'
Assert-True (-not (@($p.RunValues | Where-Object { $_.Sid -match '_Classes|S-1-5-18' }).Count)) 'the _Classes and SYSTEM hives are not read as users'
$sf = @($p.StartupFiles)
Assert-True ($sf.Count -eq 2 -and @($sf | Where-Object { $_.Name -eq 'evil.bat' -and $_.Where -eq 'all users' }).Count -eq 1 -and @($sf | Where-Object { $_.Name -eq 'notes.lnk' -and $_.Where -eq 'user jmoney' }).Count -eq 1) 'startup files: desktop.ini is ignored, the others are listed with their owner'
Assert-True ($p.Winlogon.Userinit -match 'u\.exe$' -and $p.Winlogon.Taskman -match 'tm\.exe') 'Winlogon: changed Userinit and a Taskman value'
$dbg = @($p.Debuggers)
Assert-Equal $dbg.Count 3 'three hooks: Debugger, VerifierDlls (32-bit), MonitorProcess; GlobalFlag alone is not one'
Assert-True (@($dbg | Where-Object { $_.Kind -eq 'Debugger' -and $_.Program -eq 'sethc.exe' }).Count -eq 1) 'the sethc Debugger'
Assert-True ($p.AppInit[0].Dlls -match 'hook\.dll' -and $p.AppInit[0].LoadAppInit -eq 1) 'AppInit_DLLs and its switch'
Assert-True ($p.Lsa.Notification -contains 'evilpkg') 'LSA: the extra package'
$acc = @($p.Accessibility)
Assert-True (($acc | Where-Object { $_.Name -eq 'sethc.exe' }).LooksLikeShell) 'sethc has the same fingerprint as cmd.exe'
Assert-True (($acc | Where-Object { $_.Name -eq 'utilman.exe' }).SigStatus -eq 'NotSigned') 'utilman is unsigned'
Assert-True (-not ($acc | Where-Object { $_.Name -eq 'magnify.exe' }).Exists) 'a missing file is reported as missing'
Assert-True (@($p.Wmi.Consumers).Count -eq 2 -and @($p.Wmi.Bindings | Where-Object { $_.Consumer -eq 'Updater' -and $_.Filter -eq 'Updater Filter' }).Count -eq 1) 'WMI: the planted consumer and its binding'
Assert-True (@($p.Hosts.Entries).Count -eq 4 -and $p.Hosts.Entries -contains '172.16.5.5 blackbox') 'hosts: the entries without comments'
Assert-True (@($p.Shares | Where-Object { -not $_.Special }).Count -eq 2 -and (($p.Shares | Where-Object { $_.Name -eq 'Public' }).Access -contains 'Everyone:Full:Allow')) 'shares: the two new ones, with their access'
Assert-True (@($p.Bits).Count -eq 1 -and $p.Bits[0].Files -contains 'http://203.0.113.9/p.exe') 'a BITS job with its download address'
Assert-Equal @($p.ProfileFiles).Count 2 'two PowerShell profiles'
Assert-True (@($p.PolicyScripts).Count -eq 1 -and $p.PolicyScripts[0].Name -eq 'boot.bat') 'a policy startup script'
Assert-True (@($p.Proxy).Count -eq 2 -and (($p.Proxy | Where-Object { $_.Where -eq 'machine' }).Server -eq '203.0.113.9:8080') -and (($p.Proxy | Where-Object { $_.Where -eq 'user' }).PacUrl -match 'proxy\.pac')) 'proxy settings: machine and a user'
Assert-True ($p.RdpDll.ServiceDll -match 'rdpwrap' -and $p.RdpDll.SigStatus -eq '') 'TermService''s DLL is another file'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A box with persistence planted: the rows' -ForegroundColor Cyan
$rows = $bad.Rows
$x = Find-Row $rows 'Startup entries' "Startup entry 'Updater' (machine Run)"
Assert-True ($x.Severity -eq 'BAD' -and $x.Why -match 'up\.exe' -and $x.Phase -eq 6) 'a Run value in the Public folder: red, names the command'
$x = Find-Row $rows 'Startup entries' "Startup entry 'Beacon' (machine 32-bit RunOnce)"
Assert-True ($x.Severity -eq 'WARN' -and $x.Why -match 'iwr') 'a hidden PowerShell in RunOnce: warning'
$x = Find-Row $rows 'Startup entries' "Startup entry 'Sync' (user Run of jmoney)"
Assert-True ($x.Severity -eq 'BAD') 'a user''s Run value: the SID is shown as the account name'
$x = Find-Row $rows 'Startup entries' "Startup entry 'JenkinsHelper' (machine Run) (protected)"
Assert-True ($x.Severity -eq 'INFO' -and $null -eq $x.Fix) 'an odd entry that matches the never-touch list is only INFO'
Assert-True ((Find-Row $rows 'Startup entries' '1 startup entries look normal').Why -match 'SecurityHealth') 'the normal one is still only summed up'
Assert-True ((Find-Row $rows 'Startup folders' 'Startup file evil.bat (all users)').Severity -eq 'BAD') 'a .bat in the all-users Startup folder: red'
Assert-True ((Find-Row $rows 'Startup folders' 'Startup file notes.lnk (user jmoney)').Severity -eq 'WARN') 'a shortcut: warning'
Assert-Equal (Get-RowCount $rows 'Startup folders') 2 'desktop.ini does not get a row'
Assert-True ((Find-Row $rows 'Winlogon' 'Winlogon Userinit has extra programs').Severity -eq 'BAD') 'a program added after userinit.exe, is red'
Assert-True ((Find-Row $rows 'Winlogon' 'Winlogon Taskman is set').Severity -eq 'BAD') 'Taskman is red'
Assert-True ($null -eq (Find-Row $rows 'Winlogon' 'Winlogon Shell*')) 'the unchanged Shell gets no row'
Assert-True ((Find-Row $rows 'Debuggers' 'Debugger on sethc.exe').Why -match 'sticky-keys backdoor') 'the sethc Debugger is explained'
Assert-True ((Find-Row $rows 'Debuggers' 'VerifierDlls on calc.exe (32-bit)').Severity -eq 'BAD') 'VerifierDlls in the 32-bit key is red'
Assert-True ((Find-Row $rows 'Debuggers' 'MonitorProcess on taskmgr.exe').Severity -eq 'BAD') 'SilentProcessExit MonitorProcess is red'
Assert-Equal (Get-RowCount $rows 'Debuggers') 3 'GlobalFlag alone is quiet'
Assert-True ((Find-Row $rows 'AppInit' 'AppInit_DLLs is set').Why -match 'hook\.dll.*ON') 'AppInit_DLLs: red, and says the switch is on'
Assert-True ((Find-Row $rows 'LSA' 'LSA Notification package evilpkg').Severity -eq 'WARN') 'an unknown LSA package: warning'
Assert-Equal (Get-RowCount $rows 'LSA') 1 'the usual LSA packages are quiet'
Assert-True ((Find-Row $rows 'Accessibility' 'sethc.exe was replaced').Why -match 'same file as cmd\.exe') 'sethc = cmd.exe: red'
Assert-True ((Find-Row $rows 'Accessibility' 'utilman.exe was replaced').Why -match 'NotSigned') 'unsigned utilman: red'
Assert-True ((Find-Row $rows 'Accessibility' 'osk.exe was replaced').Why -match 'Totally Legit') 'osk signed by someone else: red'
Assert-True ((Find-Row $rows 'Accessibility' 'Accessibility programs not found').Why -match 'magnify\.exe') 'a missing program is INFO'
Assert-Equal (Get-RowCount $rows 'Accessibility') 4 'narrator and displayswitch are quiet'
$x = Find-Row $rows 'WMI' 'WMI CommandLineEventConsumer Updater'
Assert-True ($x.Severity -eq 'BAD' -and $x.Why -match 'powershell\.exe -enc' -and $x.Why -match 'Updater Filter' -and $x.Why -match 'WITHIN 60') 'the WMI consumer: red, with its command and the filter that triggers it'
Assert-Equal (Get-RowCount $rows 'WMI') 1 'Windows'' own SCM Event Log subscription is not listed'
Assert-True ((Find-Row $rows 'hosts file' 'hosts entry: 172.16.5.5 blackbox').Severity -eq 'BAD') 'a hosts line pointing into the lab network is red'
Assert-True ((Find-Row $rows 'hosts file' 'hosts entry: 10.9.9.9 update.microsoft.com').Severity -eq 'WARN') 'another hosts line is a warning'
Assert-Equal (Get-RowCount $rows 'hosts file') 2 'localhost lines (with or without a comment) are quiet'
Assert-True ((Find-Row $rows 'Shares' 'Share Public').Severity -eq 'BAD') 'a share that Everyone may change: red'
Assert-True ((Find-Row $rows 'Shares' 'Share Docs').Severity -eq 'WARN') 'another share: warning'
Assert-Equal (Get-RowCount $rows 'Shares') 2 'ADMIN$, C$ and IPC$ are quiet'
Assert-True ((Find-Row $rows 'BITS jobs' 'BITS job Update*').Why -match '203\.0\.113\.9') 'the BITS job shows where it downloads from'
Assert-Equal (Get-RowCount $rows 'PowerShell profiles') 2 'both profiles'
Assert-True ((Find-Row $rows 'Policy scripts' 'Policy script boot.bat*').Severity -eq 'BAD') 'a policy startup script is red'
Assert-Equal (Get-RowCount $rows 'Proxy') 2 'both proxy settings'
Assert-True ((Find-Row $rows 'Proxy' 'Proxy setting (machine)').Why -match '203\.0\.113\.9:8080') 'the proxy server is named'
Assert-True ((Find-Row $rows 'Proxy' 'Proxy setting (user jmoney)').Why -match 'proxy\.pac') 'a user''s proxy script is named, with the account name'
$x = Find-Row $rows 'RDP service' 'RDP service uses another DLL'
Assert-True ($x.Severity -eq 'BAD' -and $null -eq $x.Fix -and $x.Why -match 'never touches the Remote Desktop service') 'the RDP service DLL: red, and NO fix (the service is never touched)'
$sum = Find-Row $rows 'Persistence' 'Persistence audit'
Assert-True ($sum.Why -match 'Rows above for: .*Run keys \(\d+\)' -and $sum.Why -match 'sticky-keys programs \(3\)') 'the summary counts the rows per area'
Assert-True ($sum.Why -notmatch 'Nothing found in: [^.]*Run keys') 'and no longer calls the Run keys clean'
$fixes = @($rows | Where-Object { $_.Phase -eq 6 -and $_.Area -notin 'Services', 'Scheduled tasks', 'Ports', 'Connections' -and $_.Fix })
Assert-Equal $fixes.Count 19 'nineteen persistence rows name a fix: 3 Run values, 2 startup files, 2 Winlogon, 3 hooks, AppInit, WMI, 2 hosts lines, 2 shares, 2 profiles, 1 policy script'
Assert-Equal @($fixes | Where-Object { $_.Batch }).Count 0 'none of them is part of a batch: each is one decision of yours'
$noFix = @($rows | Where-Object { $_.Phase -eq 6 -and $_.Area -in 'LSA', 'Accessibility', 'BITS jobs', 'Proxy', 'RDP service', 'Persistence' -and $_.Fix })
Assert-Equal $noFix.Count 0 'LSA, accessibility programs, BITS, proxy and the RDP DLL offer no fix (RUNBOOK.md has the commands)'
$built = @($fixes | ForEach-Object { Resolve-Fix $_ })
Assert-True ($built.Count -eq 19 -and @($built | Where-Object { $_.Id -and $_.Apply -and $_.Capture }).Count -eq 19) 'every one of the nineteen fixes builds a complete action (and building changes nothing)'
$x = Find-Row $rows 'Winlogon' 'Winlogon Userinit has extra programs'
$a = Resolve-Fix $x
Assert-True ($a.Risk -eq 'High' -and $a.TypeWord -eq 'WINLOGON' -and $a.Data.Reset -and $a.Data.NewValue -eq 'C:\Windows\system32\userinit.exe,') 'a Winlogon change is High risk and needs the word WINLOGON'
$x = Find-Row $rows 'Startup entries' "Startup entry 'Updater' (machine Run)"
$a = Resolve-Fix $x
Assert-True ($a.Id -eq 'persist.reg:HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Updater' -and $a.Risk -eq 'Medium' -and $a.UndoKind -eq 'persist.reg' -and -not $a.Data.Reset) 'a Run value: delete it, Medium risk, own undo'
Assert-True (($a.Will -join ' ') -match 'up\.exe' -and ($a.Will -join ' ') -match 'Undo writes them back') 'the preview shows what the value holds now and says Undo restores it'
$x = Find-Row $rows 'WMI' 'WMI CommandLineEventConsumer Updater'
$a = Resolve-Fix $x
Assert-True ($a.UndoKind -eq '' -and $a.NoUndo -match 'does NOT recreate') 'the WMI fix has no Undo, and the preview says so'
$keys = @($rows | ForEach-Object { $_.Key })
Assert-Equal ($keys | Select-Object -Unique).Count $keys.Count 'every row has its own key, planted or not'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Single changes' -ForegroundColor Cyan
$s = Get-Scenario { Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'explorer.exe,evil.exe' }
Assert-True ((Find-Row $s.Rows 'Winlogon' 'Winlogon Shell is not explorer.exe').Severity -eq 'BAD') 'a different Winlogon Shell is red'
$s = Get-Scenario { Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Userinit' 'c:\WINDOWS\SYSTEM32\USERINIT.EXE' }
Assert-Equal (Get-RowCount $s.Rows 'Winlogon') 0 'userinit.exe in other letter case, without the comma, is still the default'
$s = Get-Scenario { Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AppSetup' 'C:\x.exe' }
Assert-True ((Find-Row $s.Rows 'Winlogon' 'Winlogon AppSetup is set').Severity -eq 'WARN') 'AppSetup is a warning'
$s = Get-Scenario { Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'Load' 'C:\x.exe'; Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'Run' 'C:\y.exe' }
Assert-True ((Find-Row $s.Rows 'AppInit' 'Windows key Load value is set').Severity -eq 'BAD' -and (Find-Row $s.Rows 'AppInit' 'Windows key Run value is set').Severity -eq 'BAD') 'the old Load and Run values are red'
$s = Get-Scenario { Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Security Packages' 'kerberos,msv1_0,schannel,wdigest,tspkg,pku2u' }
Assert-Equal (Get-RowCount $s.Rows 'LSA') 0 'Security Packages as one comma list of the usual names is quiet'
$s = Get-Scenario { Set-FakeReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'Authentication Packages' @('msv1_0', 'evilauth.dll') }
Assert-True ((Find-Row $s.Rows 'LSA' 'LSA Authentication package evilauth').Severity -eq 'WARN') 'an extra authentication package (".dll" is ignored)'
$s = Get-Scenario { $global:FW.Sigs['C:\Windows\System32\termsrv.dll'] = @{ Status = 'HashMismatch'; Subject = '' } }
Assert-True ((Find-Row $s.Rows 'RDP service' 'termsrv.dll is not signed by Microsoft').Severity -eq 'BAD') 'termsrv.dll with a broken signature: red'
$s = Get-Scenario { $global:FW.Reg.Remove('hklm:\system\currentcontrolset\services\termservice\parameters|ServiceDll') }
Assert-True ((Find-Row $s.Rows 'RDP service' 'RDP service DLL could not be read').Severity -eq 'WARN') 'no ServiceDll value: a warning, not a crash'
$s = Get-Scenario { $global:FW.Dirs[(Get-FakeKey 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp')] = @('readme.txt') }
Assert-True ((Find-Row $s.Rows 'Startup folders' 'Startup file readme.txt*').Severity -eq 'WARN') 'a text file in Startup is a warning, not red'
$s = Get-Scenario { $global:FW.Wmi.Consumers += @{ Class = 'LogFileEventConsumer'; Name = 'Logger'; CommandLineTemplate = $null; ExecutablePath = $null; ScriptText = $null; ScriptFileName = 'C:\x.log' } }
$x = Find-Row $s.Rows 'WMI' 'WMI LogFileEventConsumer Logger'
Assert-True ($x.Severity -eq 'WARN' -and $x.Why -match 'no filter is bound') 'another consumer kind is a warning; an unbound one says so'
$s = Get-Scenario { $global:FW.Hives = @('S-1-5-21-1111-2222-3333-1002'); Set-FakeReg 'Registry::HKEY_USERS\S-1-5-21-1111-2222-3333-9999\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 'Ghost' 'C:\Users\Public\g.exe' }
Assert-Equal (Get-RowCount $s.Rows 'Startup entries' "*Ghost*") 0 'a hive that is not loaded cannot be read (and the summary says so)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'One reader fails, the others still answer' -ForegroundColor Cyan
$s = Get-Scenario { Add-FakePersistence; $global:FW.BreakWmi = $true; $global:FW.BreakShares = $true }
$p = $s.Facts.Persist
Assert-Equal @($p.Problems).Count 2 'two problems are noted'
Assert-True (($p.Problems -join '|') -match 'WMI subscriptions: Access denied' -and ($p.Problems -join '|') -match 'Shares: The Server service') 'each names its reader and the error'
Assert-True ($null -eq $p.Wmi -and @($p.Shares).Count -eq 0) 'the failed parts are empty'
Assert-Equal @($s.Facts.Errors).Count 0 'the Persist section itself did not fail'
Assert-True (@($p.RunValues).Count -eq 5 -and @($p.Debuggers).Count -eq 3) 'the other readers still found their items'
Assert-True ((Find-Row $s.Rows 'Persistence' 'Could not check: WMI subscriptions').Severity -eq 'WARN') 'a warning row for the reader that failed'
Assert-True ((Find-Row $s.Rows 'Persistence' 'Persistence audit').Why -match 'Could not check: WMI subscriptions, Shares') 'and the summary lists them'
Assert-Equal (Get-RowCount $s.Rows 'WMI') 0 'no WMI rows (nothing was read)'
$s = Get-Scenario { $global:FW.Hives = $null }
Assert-True (@($s.Facts.Persist.Problems).Count -ge 1 -or @($s.Facts.Persist.RunValues).Count -eq 1) 'a box with no hive list does not crash the audit'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Defender: the facts' -ForegroundColor Cyan
$d = $clean.Facts.Defender
Assert-True ($d.Available -and $d.ServiceEnabled -and $d.RealTime -and $d.Behavior -and $d.Downloads -and $d.Tamper) 'all protections are reported'
Assert-True ($d.RunningMode -eq 'Normal' -and $d.QuickScanAgeDays -eq 1 -and $d.SignatureVersion -eq '1.421.100.0' -and $d.ProductVersion -match '^4\.18') 'running mode, quick scan age, versions'
Assert-True ($d.Feature -eq 'Installed' -and @($d.PolicyValues).Count -eq 0 -and @($d.Exclusions).Count -eq 0) 'the Windows feature, no policy values, no exclusions'
$s = Get-Scenario {
    $global:FW.Defender.Exclusions = @('C:\Tools'); $global:FW.Defender.ExclusionExtensions = @('ps1'); $global:FW.Defender.ExclusionProcesses = @('evil.exe')
    $global:FW.Defender.QuickScanAge = 4294967295
    Set-FakeReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1
    Set-FakeReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0
}
$d = $s.Facts.Defender
Assert-True (@($d.ExclusionPaths) -contains 'C:\Tools' -and @($d.ExclusionExtensions) -contains 'ps1' -and @($d.ExclusionProcesses) -contains 'evil.exe' -and @($d.Exclusions).Count -eq 3) 'exclusions by kind, and all together'
Assert-Equal $d.QuickScanAgeDays -1 'a quick scan that never ran (4294967295) becomes -1'
Assert-Equal @($d.PolicyValues).Count 2 'both policy values that exist are listed (also the harmless 0)'
$s = Get-Scenario { $global:FW.Defender = $null; $global:FW.Feature = 'Removed' }
$d = $s.Facts.Defender
Assert-True (-not $d.Available -and $d.Reason -match 'not available' -and $d.Feature -eq 'Removed' -and $d.SignatureAgeDays -eq 999) 'when the Defender cmdlets fail: the reason is kept and the feature is still read'
$s = Get-Scenario { $global:FW.BreakFeature = $true }
Assert-Equal $s.Facts.Defender.Feature 'Unknown' 'if the feature cannot be asked, it is Unknown (not an error)'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Defender: the rows' -ForegroundColor Cyan
$rows = $clean.Rows | Where-Object { $_.Phase -eq 7 }
foreach ($name in 'Defender services', 'Antivirus service', 'Real-time protection', 'Behavior monitoring', 'Scanning of downloads', 'Running mode', 'Windows feature') {
    Assert-True ((Find-Row $rows 'Defender' $name).Severity -eq 'OK') "healthy: '$name' is green"
}
Assert-True ((Find-Row $rows 'Defender' 'Signatures').Severity -eq 'OK' -and (Find-Row $rows 'Defender' 'Last quick scan').Severity -eq 'INFO') 'fresh signatures are green; the last quick scan is information'
Assert-True ((Find-Row $rows 'Defender' 'Defender services').Why -match 'WinDefend is running \(Auto\)') 'the services row names the start types'
$s = Get-Scenario { ($global:FW.Services | Where-Object { $_.Name -eq 'WinDefend' }).State = 'Stopped' } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender services').Severity -eq 'BAD' -and (Find-Row $s.Rows 'Defender' 'Defender services').Why -match 'WinDefend is Stopped') 'WinDefend stopped: red'
$s = Get-Scenario { ($global:FW.Services | Where-Object { $_.Name -eq 'WinDefend' }).StartMode = 'Disabled' } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender services').Why -match 'WinDefend is Disabled') 'WinDefend disabled: named'
$s = Get-Scenario { $global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -ne 'WinDefend' }) } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender services').Why -match 'WinDefend is missing') 'WinDefend missing: named'
$s = Get-Scenario { ($global:FW.Services | Where-Object { $_.Name -eq 'WdNisSvc' }).State = 'Stopped' } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender services').Severity -eq 'WARN' -and (Find-Row $s.Rows 'Defender' 'Defender services').Why -match 'WinDefend itself is fine') 'only the network inspection service stopped: a warning'
$s = Get-Scenario {
    Set-FakeReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1
    Set-FakeReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 0
    Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' 'DisableBehaviorMonitoring' 1
} -Phases 7
Assert-Equal (Get-RowCount $s.Rows 'Defender' 'Registry switches Defender off:*') 2 'two values switch things off; the harmless 0 gets no row'
$x = Find-Row $s.Rows 'Defender' 'Registry switches Defender off: DisableAntiSpyware (Policies\Microsoft\Windows Defender)'
Assert-True ($x.Severity -eq 'BAD' -and $x.Why -match 'the whole antivirus' -and $x.Fix.Do -eq 'New-RegistryValueAction' -and $x.Fix.With.Area -eq 'def') 'the policy value: red, what it turns off, and a fix that deletes the value'
$a = Resolve-Fix $x
Assert-True ($a.Id -eq 'def.reg:HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender|DisableAntiSpyware' -and $a.Title -match 'Delete the Defender switch DisableAntiSpyware') 'its action is named after the Defender switch'
Assert-True ((Find-Row $s.Rows 'Defender' 'Registry switches Defender off: DisableBehaviorMonitoring*').Why -match 'behavior monitoring') 'and the other value says what it turns off'
$s = Get-Scenario { $global:FW.Defender.Behavior = $false; $global:FW.Defender.Downloads = $false; $global:FW.Defender.Mode = 'Passive mode'; $global:FW.Defender.QuickScanAge = 4294967295 } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Behavior monitoring').Severity -eq 'BAD' -and (Find-Row $s.Rows 'Defender' 'Scanning of downloads').Severity -eq 'WARN') 'behavior monitoring off is red; scanning of downloads off is a warning'
Assert-True ((Find-Row $s.Rows 'Defender' 'Behavior monitoring').Fix.With.Setting -eq 'Behavior' -and (Find-Row $s.Rows 'Defender' 'Scanning of downloads').Fix.With.Setting -eq 'Downloads') 'each switch that is off has its own fix'
Assert-True ($null -eq (Find-Row $s.Rows 'Defender' 'Running mode').Fix -and $null -eq (Find-Row $s.Rows 'Defender' 'Last quick scan').Fix) 'passive mode and the quick scan age have no fix here (RUNBOOK.md)'
Assert-True ((Resolve-Fix (Find-Row $s.Rows 'Defender' 'Behavior monitoring')).Id -eq 'def.switch:Behavior') 'the fix builds the Defender switch action'
Assert-True ((Find-Row $s.Rows 'Defender' 'Running mode').Severity -eq 'WARN' -and (Find-Row $s.Rows 'Defender' 'Running mode').Why -match 'Passive mode') 'passive mode: a warning that names the mode'
Assert-True ((Find-Row $s.Rows 'Defender' 'Last quick scan').Why -match 'No quick scan has run') 'no quick scan yet is said plainly'
$s = Get-Scenario { $global:FW.Defender.RealTime = $false } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Real-time protection').Severity -eq 'BAD' -and (Find-Row $s.Rows 'Defender' 'Real-time protection').Fix.With.Setting -eq 'Realtime') 'real-time protection off: red, with a fix'
$s = Get-Scenario { $global:FW.Defender.Mode = '' } -Phases 7
Assert-True ($null -eq (Find-Row $s.Rows 'Defender' 'Running mode')) 'an older Defender that does not report a mode: no row'
$s = Get-Scenario { $global:FW.Services += @{ Name = 'MBAMService'; DisplayName = 'Malwarebytes Service'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe"'; ProcessId = 77 } } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Another antivirus').Why -match 'MBAMService \(Running\)') 'another antivirus is noticed by its service'
$s = Get-Scenario { $global:FW.Feature = 'Removed' } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Windows feature').Severity -eq 'BAD' -and (Find-Row $s.Rows 'Defender' 'Windows feature').Why -match 'REBOOT') 'the feature removed: red, and it warns about the reboot'
$s = Get-Scenario { $global:FW.Feature = 'Removed'; $global:FW.Defender = $null; $global:FW.Services = @($global:FW.Services | Where-Object { $_.Name -notin 'WinDefend', 'WdNisSvc' }) } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender cannot be read').Why -match 'not available') 'cannot be read: the real error text is in the row'
Assert-True ((Find-Row $s.Rows 'Defender' 'Defender services').Severity -eq 'BAD' -and (Find-Row $s.Rows 'Defender' 'Windows feature').Severity -eq 'BAD') 'and the services and the feature rows still explain why'
Assert-Equal (Get-RowCount $s.Rows 'Defender' 'Antivirus service') 0 'but no "service is on" row when the status cannot be read'
$s = Get-Scenario { $global:FW.Defender.Exclusions = @('C:\Tools'); $global:FW.Defender.ExclusionExtensions = @('ps1'); $global:FW.Defender.ExclusionProcesses = @('evil.exe') } -Phases 7
Assert-True ((Find-Row $s.Rows 'Defender' 'Exclusion: C:\Tools').Severity -eq 'WARN' -and (Find-Row $s.Rows 'Defender' 'Exclusion (extension): ps1').Severity -eq 'WARN' -and (Find-Row $s.Rows 'Defender' 'Exclusion (process): evil.exe').Severity -eq 'WARN') 'each kind of exclusion gets its own row'
$ex = @('Exclusion: C:\Tools', 'Exclusion (extension): ps1', 'Exclusion (process): evil.exe') | ForEach-Object { Resolve-Fix (Find-Row $s.Rows 'Defender' $_) }
Assert-True (($ex | ForEach-Object { $_.Id }) -join ' ' -eq 'def.exclusion:Path|C:\Tools def.exclusion:Extension|ps1 def.exclusion:Process|evil.exe') 'each exclusion row builds the remove action for its own kind'

Write-Host 'Sections that a change makes stale' -ForegroundColor Cyan
Assert-Equal ((Get-SectionsForAction 'persist.run:x') -join ',') 'Persist' 'a persistence change re-reads the Persist section'
Assert-Equal ((Get-SectionsForAction 'def.exclusion:x') -join ',') 'Defender,Services' 'a Defender change re-reads Defender and the services'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-TestSummary
