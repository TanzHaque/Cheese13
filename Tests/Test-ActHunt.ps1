# Test-ActHunt.ps1 - the phase 6 ACTIONS (lib\Act-Hunt.ps1: disable a service, disable a scheduled task) through the real gate,
# Invoke-Change, against the pretend box. It proves: the judge's fixes build these actions, disabling never deletes, a running
# service is stopped first (and nothing changes when it cannot be), every change is undone exactly, and the never-touch list
# (Jenkins, Java, Remote Desktop, the log collector, Windows, the tool's own dead-man task) is refused in code.
# It does NOT prove that real Windows behaves like these stand-ins (Set-Service on a service with dependents, task states).
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
. "$PSScriptRoot\..\lib\Act-Watchdog.ps1"
. "$PSScriptRoot\FakeWindows.ps1"          # last, so its stand-ins win

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-acthunt-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl

$script:Asked = New-Object System.Collections.ArrayList
$script:AskAnswer = $true
$script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $script:AskAnswer }
$script:Hp.AllowChanges = $true

function Get-FakeService { param([string]$Name) @($global:FW.Services | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1 }
function Get-FakeTask { param([string]$Name) @($global:FW.Tasks | Where-Object { $_.TaskName -eq $Name }) | Select-Object -First 1 }
function Get-JournalCount { @(Get-JournalRecords).Count }
function Get-LastRecordId { (@(Get-JournalRecords)[-1]).Id }

# two more things on the pretend box: a log shipper under a name the never-touch regex does not know, and a Jenkins helper task
$global:FW.Services += @{ Name = 'LogShip'; DisplayName = 'Log shipper'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = '"C:\Tools\fluent-bit.exe"'; ProcessId = 3000 }
$global:FW.Tasks += @{ TaskName = 'JenkinsNightly'; TaskPath = '\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'C:\Program Files\Jenkins\nightly.bat'; Arguments = '' }
# tasks hidden under \Microsoft\ (where a red team and the lab plant them), and a shell task from System32 outside it
$global:FW.Tasks += @{ TaskName = 'WinMaintSync'; TaskPath = '\Microsoft\Windows\Maintenance\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'cmd.exe'; Arguments = '/c echo beacon >> C:\ProgramData\lab_beacon.log' }
$global:FW.Tasks += @{ TaskName = 'WinMaintPublic'; TaskPath = '\Microsoft\Windows\Maintenance\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'C:\Users\Public\up.exe'; Arguments = '/silent' }
$global:FW.Tasks += @{ TaskName = 'PsReport'; TaskPath = '\'; State = 'Ready'; UserId = 'SYSTEM'; GroupId = ''; RunLevel = 'Highest'; Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Arguments = '-NoProfile -File C:\Tools\report.ps1' }
$script:Hp.Facts = Get-HpFacts
Assert-True (@($script:Hp.Facts.Errors).Count -eq 0) 'the audit of the pretend box ran without collector errors'
Assert-True (@($script:Hp.Facts.Collector | Where-Object { $_.Name -eq 'LogShip' }).Count -eq 1) 'the audit found the log shipper by itself'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The judge offers these fixes, and they build the expected actions' -ForegroundColor Cyan
$hunt = @(Get-HuntFindings $script:Hp.Facts $script:Hp.Settings)
$svcRow = $hunt | Where-Object { $_.Subject -eq 'Service WinSvcHelper' } | Select-Object -First 1
Assert-True ($svcRow -and $svcRow.Fix.Do -eq 'New-DisableServiceAction' -and -not $svcRow.Batch) 'a service in C:\Windows\Temp -> a fix that is NOT part of a batch'
$a = Resolve-Fix $svcRow
Assert-True ($a.Id -eq 'svc.disable:WinSvcHelper' -and $a.UndoKind -eq 'svc.disable' -and $a.Risk -eq 'Medium') 'the action: id, undo kind, risk'
Assert-True (($a.Will -join ' ') -match 'NOT deleted') 'the preview says nothing is deleted'
$taskRow = $hunt | Where-Object { $_.Subject -eq 'Task \NightlyCopy' } | Select-Object -First 1
Assert-True ($taskRow -and $taskRow.Fix.Do -eq 'New-DisableTaskAction') 'a task that runs a .bat file -> a fix'
$a = Resolve-Fix $taskRow
Assert-True ($a.Id -eq 'task.disable:\NightlyCopy' -and $a.UndoKind -eq 'task.disable') 'the task action: id and undo kind'
Assert-True (@($hunt | Where-Object { $_.Subject -eq 'Service Jenkins' -or $_.Subject -eq 'Service otelcol' }).Count -eq 0) 'Jenkins and the collector get no fix row at all (the judge hides them)'
$msRow = $hunt | Where-Object { $_.Subject -eq 'Task \Microsoft\Windows\Maintenance\WinMaintSync' } | Select-Object -First 1
Assert-True ($msRow -and $msRow.Severity -eq 'WARN' -and $msRow.Fix.Do -eq 'New-DisableTaskAction' -and -not $msRow.Batch) 'a shell task hidden under \Microsoft\ -> a WARN row with a fix that is not part of a batch'
Assert-True ($msRow.Why -match 'where Windows keeps its own tasks') 'and its text says why a task there is worth reading'
$msRow2 = $hunt | Where-Object { $_.Subject -eq 'Task \Microsoft\Windows\Maintenance\WinMaintPublic' } | Select-Object -First 1
Assert-True ($msRow2 -and $msRow2.Severity -eq 'BAD') 'a program from the Public folder under \Microsoft\ is BAD'
Assert-True (@($hunt | Where-Object { $_.Subject -like '*Defrag*' }).Count -eq 0) 'the stock task under \Microsoft\ (Defrag) gets no row'
$psRow = $hunt | Where-Object { $_.Subject -eq 'Task \PsReport' } | Select-Object -First 1
Assert-True ($psRow -and $psRow.Fix.Do -eq 'New-DisableTaskAction') 'a PowerShell task outside \Microsoft\ gets a fix row even though the program is in System32'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Disable a service that is already stopped, then undo' -ForegroundColor Cyan
$j0 = Get-JournalCount
$r = Invoke-Change (New-DisableServiceAction -Name 'WinSvcHelper') -Confirmed
Assert-Equal $r.Status 'Applied' 'applied'
$s = Get-FakeService 'WinSvcHelper'
Assert-True ($s.StartMode -eq 'Disabled' -and $s.State -eq 'Stopped') 'start mode Disabled, still stopped'
Assert-True ($null -ne $s) 'the service still exists (disable, never delete)'
Assert-True ((Get-JournalCount) -eq $j0 + 1) 'one journal record'
$rec = @(Get-JournalRecords)[-1]
Assert-True ($rec.Before.StartMode -eq 'Auto' -and $rec.Before.State -eq 'Stopped') 'the old state was written before the change'
Assert-True (@($global:FW.Calls | Where-Object { $_ -eq 'Stop-Service WinSvcHelper' }).Count -eq 0) 'a stopped service is not stopped again'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-Equal $r.Status 'Undone' 'undone'
$s = Get-FakeService 'WinSvcHelper'
Assert-True ($s.StartMode -eq 'Auto' -and $s.State -eq 'Stopped') 'start mode Auto again, and NOT started (it was not running before)'

Write-Host 'Disable a running service, then undo' -ForegroundColor Cyan
$r = Invoke-Change (New-DisableServiceAction -Name 'BackupSvc') -Confirmed
Assert-Equal $r.Status 'Applied' 'applied'
$s = Get-FakeService 'BackupSvc'
Assert-True ($s.StartMode -eq 'Disabled' -and $s.State -eq 'Stopped') 'stopped and disabled'
$calls = @($global:FW.Calls | Where-Object { $_ -match 'BackupSvc' })
Assert-True ($calls.Count -eq 2 -and $calls[0] -eq 'Stop-Service BackupSvc' -and $calls[1] -eq 'Set-Service BackupSvc Disabled') 'it is stopped first, then disabled'
$rec = @(Get-JournalRecords)[-1]
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
$s = Get-FakeService 'BackupSvc'
Assert-True ($r.Status -eq 'Undone' -and $s.StartMode -eq 'Auto' -and $s.State -eq 'Running') 'undo: start mode Auto and running again'

Write-Host 'A service that cannot be stopped is left exactly as it was' -ForegroundColor Cyan
$global:FW.StopFails = @('BackupSvc')
$r = Invoke-Change (New-DisableServiceAction -Name 'BackupSvc') -Confirmed
$s = Get-FakeService 'BackupSvc'
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'dependent') "the failure is reported ($($r.Message))"
Assert-True ($s.StartMode -eq 'Auto' -and $s.State -eq 'Running') 'start mode and state unchanged (it was stopped BEFORE disabling, so nothing half-happened)'
$global:FW.StopFails = @()

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The never-touch list is enforced when the old state is read' -ForegroundColor Cyan
foreach ($name in 'Jenkins', 'otelcol', 'TermService', 'Spooler', 'LogShip', 'WinDefend', 'WdNisSvc') {
    $j0 = Get-JournalCount
    $snap = (Get-FakeService $name | ForEach-Object { "$($_.StartMode)/$($_.State)" })
    $r = Invoke-Change (New-DisableServiceAction -Name $name) -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Refused') "$name is refused ($($r.Message -replace '^.*Refused: ', ''))"
    Assert-True ((Get-FakeService $name | ForEach-Object { "$($_.StartMode)/$($_.State)" }) -eq $snap -and (Get-JournalCount) -eq $j0) "$name is unchanged and nothing was journalled"
}
$r = Invoke-Change (New-DisableServiceAction -Name 'NoSuchService') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'no service named') 'an unknown name is reported'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Disable a scheduled task, then undo' -ForegroundColor Cyan
$r = Invoke-Change (New-DisableTaskAction -Name 'NightlyCopy' -Path '\') -Confirmed
Assert-Equal $r.Status 'Applied' 'applied'
Assert-Equal (Get-FakeTask 'NightlyCopy').State 'Disabled' 'the task is Disabled'
Assert-True ($null -ne (Get-FakeTask 'NightlyCopy')) 'the task still exists (disable, never delete)'
$rec = @(Get-JournalRecords)[-1]
Assert-True ($rec.Before.State -eq 'Ready' -and $rec.Before.Xml -match '<Task>' -and $rec.Before.Actions -match 'copy\.bat') 'the journal keeps the old state, the task XML and what it ran'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-FakeTask 'NightlyCopy').State -eq 'Ready') 'undo enables it again'

Write-Host 'A task that was already disabled stays disabled after Undo' -ForegroundColor Cyan
(Get-FakeTask 'MicrosoftEdgeUpdateTaskCore2').State = 'Disabled'
$r = Invoke-Change (New-DisableTaskAction -Name 'MicrosoftEdgeUpdateTaskCore2' -Path '\') -Confirmed
$rec = @(Get-JournalRecords)[-1]
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeTask 'MicrosoftEdgeUpdateTaskCore2').State -eq 'Disabled') 'it was disabled before; undoing does not enable it'

Write-Host 'A task hidden under \Microsoft\: disabled only because its command is suspicious, then undone' -ForegroundColor Cyan
$r = Invoke-Change (Resolve-Fix $msRow) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeTask 'WinMaintSync').State -eq 'Disabled') 'the shell task under \Microsoft\ is disabled'
$rec = @(Get-JournalRecords)[-1]
Assert-True ($rec.Before.Actions -match 'lab_beacon' -and $rec.Data.Path -eq '\Microsoft\Windows\Maintenance\') 'the journal keeps its command and its folder'
$r = Invoke-Change (New-DisableTaskAction -Name 'WinMaintPublic' -Path '\Microsoft\Windows\Maintenance\') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeTask 'WinMaintPublic').State -eq 'Disabled') 'a program from the Public folder under \Microsoft\ can be disabled too'
$null = Undo-Change -Id ([int](Get-LastRecordId)) -Confirmed
Assert-Equal (Get-FakeTask 'WinMaintPublic').State 'Ready' 'its undo enables it again'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-FakeTask 'WinMaintSync').State -eq 'Ready') 'and the first one is undone as well'

Write-Host 'A shell task from System32 outside \Microsoft\ is NOT treated as part of Windows' -ForegroundColor Cyan
$r = Invoke-Change (Resolve-Fix $psRow) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-FakeTask 'PsReport').State -eq 'Disabled') 'powershell.exe from System32 does not make the task untouchable (only the never-touch list does)'
$null = Undo-Change -Id ([int](Get-LastRecordId)) -Confirmed
Assert-Equal (Get-FakeTask 'PsReport').State 'Ready' 'and undo enables it again'

Write-Host 'Tasks that must stay' -ForegroundColor Cyan
$global:FW.Tasks2['NetCacheRestore'] = @{ Action = @{ Execute = 'powershell.exe'; Argument = '-File Panic.ps1 -FromTask' }; Trigger = @{}; Principal = @{ UserId = 'NT AUTHORITY\SYSTEM'; LogonType = 'ServiceAccount'; RunLevel = 'Highest'; GroupId = '' } }
$cases = @(
    @{ Name = 'Defrag'; Path = '\Microsoft\Windows\Defrag\'; Match = 'part of Windows' }
    @{ Name = 'NetCacheRestore'; Path = '\'; Match = 'dead-man' }
    @{ Name = 'JenkinsNightly'; Path = '\'; Match = 'never-touch' }
)
foreach ($c in $cases) {
    $j0 = Get-JournalCount
    $r = Invoke-Change (New-DisableTaskAction -Name $c.Name -Path $c.Path) -Confirmed
    Assert-True ($r.Status -eq 'Failed' -and $r.Message -match $c.Match) "$($c.Path)$($c.Name) is refused ($($r.Message -replace '^.*Refused: ', ''))"
    Assert-True ((Get-JournalCount) -eq $j0) '... and nothing was journalled'
}
Assert-True ((Get-FakeTask 'Defrag').State -eq 'Ready' -and (Get-FakeTask 'JenkinsNightly').State -eq 'Ready') 'their state is unchanged'
$r = Invoke-Change (New-DisableTaskAction -Name 'NoSuchTask' -Path '\') -Confirmed
Assert-Equal $r.Status 'Failed' 'an unknown task is reported'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The text rules behind those decisions: which commands under \Microsoft\ are worth a row' -ForegroundColor Cyan
$wordCases = @(
    @{ Text = '';                                                                            Want = $false; Why = 'no command at all' }
    @{ Text = '%windir%\system32\defrag.exe -c';                                             Want = $false; Why = 'a stock Windows program' }
    @{ Text = 'C:\Windows\System32\svchost.exe -k netsvcs';                                  Want = $false; Why = 'svchost' }
    @{ Text = '"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1';         Want = $false; Why = 'a program in Program Files' }
    @{ Text = '%ProgramFiles(x86)%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /ua';        Want = $false; Why = '%ProgramFiles(x86)% is expanded, not mistaken for an odd folder' }
    @{ Text = '%systemdrive%\Windows\System32\compattelrunner.exe -m';                       Want = $false; Why = '%systemdrive% is expanded' }
    @{ Text = 'C:\Windows\System32\cmdkey.exe /list';                                        Want = $false; Why = 'cmdkey is not cmd' }
    @{ Text = 'C:\Windows\System32\curling.exe';                                             Want = $false; Why = 'a name that only starts like a shell word' }
    @{ Text = 'cmd.exe /c echo beacon >> C:\ProgramData\lab_beacon.log';                     Want = $true;  Why = 'a shell with no folder' }
    @{ Text = 'C:\Windows\System32\cmd.exe /c whoami';                                       Want = $true;  Why = 'cmd.exe from System32' }
    @{ Text = 'powershell.exe -NoProfile -File C:\ProgramData\x.ps1';                        Want = $true;  Why = 'PowerShell' }
    @{ Text = 'C:\Windows\System32\wscript.exe //B C:\Windows\x.vbs';                        Want = $true;  Why = 'a script host' }
    @{ Text = 'C:\Windows\System32\certutil.exe -urlcache -f http://x/y z';                  Want = $true;  Why = 'certutil downloading' }
    @{ Text = 'C:\Users\Public\evil.exe';                                                    Want = $true;  Why = 'a program in the Public folder' }
    @{ Text = 'C:\Tools\run.exe';                                                            Want = $true;  Why = 'a program outside Windows and Program Files' }
    @{ Text = '%windir%\system32\defrag.exe -c ; cmd.exe /c x';                              Want = $true;  Why = 'the second of two actions is a shell' }
)
foreach ($c in $wordCases) { Assert-Equal (Test-SuspiciousMicrosoftTask $c.Text) $c.Want "Test-SuspiciousMicrosoftTask: $($c.Why)" }

$pathCases = @(
    @{ Given = '%windir%\system32\defrag.exe';               Want = 'C:\Windows\system32\defrag.exe' }
    @{ Given = '%SystemRoot%\x.exe';                         Want = 'C:\Windows\x.exe' }
    @{ Given = '%ProgramFiles(x86)%\a\b.exe';                Want = 'C:\Program Files (x86)\a\b.exe' }
    @{ Given = '%ProgramFiles%\a\b.exe';                     Want = 'C:\Program Files\a\b.exe' }
    @{ Given = '%programdata%\a\b.exe';                      Want = 'C:\ProgramData\a\b.exe' }
    @{ Given = '%systemdrive%\x\y.exe';                      Want = 'C:\x\y.exe' }
    @{ Given = '"C:\a b\c.exe"';                             Want = 'C:\a b\c.exe' }
)
foreach ($c in $pathCases) { Assert-Equal (Expand-CommonPath $c.Given) $c.Want "Expand-CommonPath $($c.Given)" }

$progCases = @(
    @{ Given = '"C:\x y\a.exe" /c';                                       Want = 'C:\x y\a.exe' }
    @{ Given = 'C:\Tools\copy.bat ';                                      Want = 'C:\Tools\copy.bat' }
    @{ Given = '%windir%\system32\defrag.exe -c';                         Want = '%windir%\system32\defrag.exe' }
    @{ Given = '%ProgramFiles(x86)%\Google\Update\GoogleUpdate.exe /c';   Want = '%ProgramFiles(x86)%\Google\Update\GoogleUpdate.exe' }
    @{ Given = 'cmd.exe /c echo x';                                       Want = '' }
    @{ Given = '';                                                        Want = '' }
)
foreach ($c in $progCases) { Assert-Equal (Get-ActionProgram $c.Given) $c.Want "Get-ActionProgram '$($c.Given)'" }

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The gate in front of both' -ForegroundColor Cyan
$script:Hp.AllowChanges = $false
$r = Invoke-Change (New-DisableServiceAction -Name 'BackupSvc') -Confirmed
Assert-True ($r.Status -eq 'Blocked' -and (Get-FakeService 'BackupSvc').StartMode -eq 'Auto') 'audit mode: blocked, nothing changed'
$script:Hp.AllowChanges = $true
$script:AskAnswer = $false
$r = Invoke-Change (New-DisableServiceAction -Name 'BackupSvc')
Assert-True ($r.Status -eq 'Cancelled' -and (Get-FakeService 'BackupSvc').StartMode -eq 'Auto') 'you say no: cancelled, nothing changed'
$script:AskAnswer = $true
$script:Asked.Clear()
$r = Invoke-Change (New-DisableTaskAction -Name 'NightlyCopy' -Path '\')
Assert-True ($script:Asked.Count -eq 1 -and $script:Asked[0].Text -match 'NightlyCopy' -and $script:Asked[0].Text -match 'running right now') 'without -Confirmed you are asked, and the preview mentions that a running copy keeps running'
Assert-Equal $r.Status 'Applied' 'and then it is applied'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-TestSummary
