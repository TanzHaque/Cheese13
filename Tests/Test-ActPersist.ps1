# Test-ActPersist.ps1 - the persistence and Defender FIXES (lib\Act-Persist.ps1) through the real gate, Invoke-Change, against the pretend box.
# It proves, for every kind of fix: the old state is written to the journal BEFORE the change, the change does what the preview says (and
# nothing else), Undo puts the old state back exactly (registry type included), a change that did not take is reported as a failure,
# and the lists of what may be touched (and the never-touch list) are enforced when the old state is read, not only by the judge.
# It does NOT prove that real Windows behaves like these stand-ins (registry value types, WMI objects, SMB shares, Set-MpPreference
# with Tamper Protection, Move-Item on a running program). Those are checked in the lab (README.md).
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

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hp-actpersist-' + [guid]::NewGuid().ToString('N'))
$script:HpRoot = Join-Path $PSScriptRoot '..'
$global:FW = New-FakeBox
Initialize-Hp -DataDir $tmp -NoAcl
Add-FakePersistence

$script:Asked = New-Object System.Collections.ArrayList
$script:AskAnswer = $true
$script:Hp.Ask = { param($Title, $Text, $TypeWord) [void]$script:Asked.Add([pscustomobject]@{ Title = $Title; Text = $Text; Word = $TypeWord }); $script:AskAnswer }
$script:Hp.AllowChanges = $true

function Get-JournalCount { @(Get-JournalRecords).Count }
function Get-LastRecord { @(Get-JournalRecords)[-1] }
function Get-RegData { param([string]$Key, [string]$Name) $global:FW.Reg[(Get-FakeKey $Key) + '|' + $Name] }
function Test-RegHas { param([string]$Key, [string]$Name) $global:FW.Reg.ContainsKey((Get-FakeKey $Key) + '|' + $Name) }
function Get-RegKind { param([string]$Key, [string]$Name) $global:FW.RegKinds[(Get-FakeKey $Key) + '|' + $Name] }
function Get-FakeShare { param([string]$Name) @($global:FW.Shares | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1 }
function Test-InFolder { param([string]$Folder, [string]$Name) @(@($global:FW.Dirs[(Get-FakeKey $Folder)]) | Where-Object { (Get-FakeEntryName $_) -ieq $Name }).Count -gt 0 }
function Get-HostsText { [string]$global:FW.Files[(Get-FakeKey 'C:\Windows\System32\drivers\etc\hosts')] }
function Set-HostsText { param([string]$Text) $global:FW.Files[(Get-FakeKey 'C:\Windows\System32\drivers\etc\hosts')] = $Text }
function Assert-Refused {
    # The change must fail when the old state is read: nothing is changed and nothing is journalled.
    param($Action, [string]$Match, [string]$What)
    $count = Get-JournalCount
    $result = Invoke-Change $Action -Confirmed
    Assert-True ($result.Status -eq 'Failed' -and $result.Message -match 'nothing was changed' -and $result.Message -match $Match) "$What is refused ($($result.Message -replace '^.*nothing was changed: ', ''))"
    Assert-Equal (Get-JournalCount) $count "$What : nothing was journalled"
}

$run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A Run value: delete it, then undo' -ForegroundColor Cyan
$act = New-RegistryValueAction -Key $run -Name 'Updater' -Label "the startup entry 'Updater'" -Shown '"C:\Users\Public\up.exe" /silent'
Assert-True ($act.Id -eq "persist.reg:$run|Updater" -and $act.Title -eq "Delete the startup entry 'Updater'" -and $act.Risk -eq 'Medium' -and $act.UndoKind -eq 'persist.reg') 'the action: id, title, risk, undo kind'
Assert-True (($act.Will -join ' ') -match 'up\.exe' -and ($act.Will -join ' ') -match 'Undo writes them back exactly') 'the preview shows what the value holds now and promises an exact Undo'
$before = $global:FW.Calls.Count
$null = New-RegistryValueAction -Key $run -Name 'Updater'
Assert-Equal $global:FW.Calls.Count $before 'building an action changes nothing'
$j0 = Get-JournalCount
$script:Asked.Clear()
$r = Invoke-Change $act
Assert-Equal $r.Status 'Applied' 'applied (you were asked first)'
Assert-True ($script:Asked.Count -eq 1 -and $script:Asked[0].Text -match 'Delete the startup entry') 'the question shows the same preview'
Assert-True (-not (Test-RegHas $run 'Updater')) 'the value is gone'
Assert-True ((Test-RegHas $run 'SecurityHealth') -and (Test-RegHas $run 'JenkinsHelper')) 'its neighbours in the same key are untouched'
Assert-True ((Get-JournalCount) -eq $j0 + 1) 'one journal record'
$rec = Get-LastRecord
Assert-True ($rec.Status -eq 'applied' -and $rec.UndoKind -eq 'persist.reg' -and $rec.Before.Kind -eq 'String' -and $rec.Before.Value -eq '"C:\Users\Public\up.exe" /silent') 'the journal has the old value and its type'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-RegData $run 'Updater') -eq '"C:\Users\Public\up.exe" /silent' -and (Get-RegKind $run 'Updater') -eq 'String') 'undo writes the same text back, as a String'

Write-Host 'A value that expands %variables% (REG_EXPAND_SZ) keeps its text and its type' -ForegroundColor Cyan
Set-FakeReg $run 'Expander' '%SystemRoot%\system32\odd.exe -x'
$global:FW.RegKinds[(Get-FakeKey $run) + '|Expander'] = 'ExpandString'
$r = Invoke-Change (New-RegistryValueAction -Key $run -Name 'Expander') -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and $rec.Before.Kind -eq 'ExpandString' -and $rec.Before.Value -eq '%SystemRoot%\system32\odd.exe -x') 'the journal keeps %SystemRoot% as text (it is not filled in) and the type ExpandString'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ((Get-RegData $run 'Expander') -eq '%SystemRoot%\system32\odd.exe -x' -and (Get-RegKind $run 'Expander') -eq 'ExpandString') 'undo: the same text with %SystemRoot% in it, still an ExpandString'

Write-Host 'The only value of a key: the key stays; if the key is gone at undo time, undo makes it again' -ForegroundColor Cyan
$spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\taskmgr.exe'
$r = Invoke-Change (New-RegistryValueAction -Key $spe -Name 'MonitorProcess' -Label 'the MonitorProcess hook on taskmgr.exe') -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and -not (Test-RegHas $spe 'MonitorProcess') -and (Test-Path -LiteralPath $spe)) 'the value is deleted, the (now empty) key stays like on real Windows'
[void]$global:FW.RegKeys.Remove((Get-FakeKey $spe))
Assert-True (-not (Test-Path -LiteralPath $spe)) '(somebody removes the empty key)'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Test-Path -LiteralPath $spe) -and (Get-RegData $spe 'MonitorProcess') -eq 'C:\Temp\m.exe') 'undo made the key again and wrote the value'

Write-Host 'A Defender policy value (a number): deleted, and undone as a number' -ForegroundColor Cyan
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Set-FakeReg $pol 'DisableAntiSpyware' 1
$act = New-RegistryValueAction -Key $pol -Name 'DisableAntiSpyware' -Area 'def' -Label 'the Defender switch DisableAntiSpyware' -Shown 'DisableAntiSpyware = 1'
$r = Invoke-Change $act -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and $rec.ActionId -like 'def.reg:*' -and $rec.Before.Kind -eq 'DWord' -and [int]$rec.Before.Value -eq 1 -and -not (Test-RegHas $pol 'DisableAntiSpyware')) 'deleted; the journal has the number 1 and the type DWord'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ((Get-RegData $pol 'DisableAntiSpyware') -eq 1 -and (Get-RegKind $pol 'DisableAntiSpyware') -eq 'DWord') 'undo: the number 1 again, as a DWord'

Write-Host 'A user''s Run key (found through the loaded hive)' -ForegroundColor Cyan
$jm = 'Registry::HKEY_USERS\S-1-5-21-1111-2222-3333-1002\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$r = Invoke-Change (New-RegistryValueAction -Key $jm -Name 'Sync') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not (Test-RegHas $jm 'Sync')) 'jmoney''s Run value is deleted'
$null = Undo-Change -Id ([int](Get-LastRecord).Id) -Confirmed
Assert-True (Test-RegHas $jm 'Sync') 'and comes back'

Write-Host 'A value that must keep existing is SET back to its default, not deleted (Winlogon)' -ForegroundColor Cyan
$act = New-RegistryValueAction -Key $wl -Name 'Userinit' -Reset -NewValue 'C:\Windows\system32\userinit.exe,' -Risk 'High' -TypeWord 'WINLOGON' -Label 'the Winlogon Userinit' -Shown 'C:\Windows\system32\userinit.exe,C:\Windows\Temp\u.exe'
Assert-True ($act.Risk -eq 'High' -and $act.TypeWord -eq 'WINLOGON' -and $act.Title -match 'back to its default') 'High risk, you type WINLOGON'
$script:AskAnswer = $false
$script:Asked.Clear()
$r = Invoke-Change $act -Confirmed
Assert-True ($r.Status -eq 'Cancelled' -and $script:Asked.Count -eq 1 -and $script:Asked[0].Word -eq 'WINLOGON' -and (Get-RegData $wl 'Userinit') -match 'u\.exe$') 'High risk asks for the word even in a batch; "no" changes nothing'
$script:AskAnswer = $true
$r = Invoke-Change $act -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and (Get-RegData $wl 'Userinit') -eq 'C:\Windows\system32\userinit.exe,' -and (Test-RegHas $wl 'Userinit')) 'Userinit is the Windows default again (the value was not deleted)'
Assert-True ($rec.Before.Value -eq 'C:\Windows\system32\userinit.exe,C:\Windows\Temp\u.exe') 'the journal keeps the bad value'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ((Get-RegData $wl 'Userinit') -eq 'C:\Windows\system32\userinit.exe,C:\Windows\Temp\u.exe') 'undo puts the bad value back (so you can look at it)'
Set-FakeReg $wl 'Userinit' 'C:\Windows\system32\userinit.exe,'
Set-FakeReg $wl 'Shell' 'explorer.exe,evil.exe'
$r = Invoke-Change (New-RegistryValueAction -Key $wl -Name 'Shell' -Reset -NewValue 'explorer.exe' -Risk 'High' -TypeWord 'WINLOGON') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-RegData $wl 'Shell') -eq 'explorer.exe') 'Shell is explorer.exe again'
$aip = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$r = Invoke-Change (New-RegistryValueAction -Key $aip -Name 'AppInit_DLLs' -Reset -NewValue '' -Label 'AppInit_DLLs') -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and (Test-RegHas $aip 'AppInit_DLLs') -and (Get-RegData $aip 'AppInit_DLLs') -eq '') 'AppInit_DLLs is emptied; the value itself stays'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-Equal (Get-RegData $aip 'AppInit_DLLs') 'C:\Windows\Temp\hook.dll' 'undo: the DLL path is back'
$r = Invoke-Change (New-RegistryValueAction -Key $aip -Name 'AppInit_DLLs' -Reset -NewValue '' -Label 'AppInit_DLLs') -Confirmed

Write-Host 'The list of registry values is enforced when the old state is read' -ForegroundColor Cyan
Set-FakeReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1
Set-FakeReg $run 'AgentLauncher' 'C:\Program Files\Eclipse Adoptium\jdk-17\bin\javaw.exe -jar agent.jar'
Set-FakeReg $run 'BinThing' 'x'
$global:FW.RegKinds[(Get-FakeKey $run) + '|BinThing'] = 'Binary'
$calls = $global:FW.Calls.Count
Assert-Refused (New-RegistryValueAction -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA') 'not on the list' 'a key that is not on the list'
Assert-Refused (New-RegistryValueAction -Key "$ifeo\notepad.exe" -Name 'GlobalFlag') 'not on the list' 'GlobalFlag (an IFEO value that is not a hook)'
Assert-Refused (New-RegistryValueAction -Key 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'x') 'not on the list' 'the current user''s own Run key (the audit never reads it)'
Assert-Refused (New-RegistryValueAction -Key 'Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'x') 'not on the list' 'a hive that is not a normal account'
Assert-Refused (New-RegistryValueAction -Key $run -Name '*') 'wildcard' 'a wildcard in the value name'
Assert-Refused (New-RegistryValueAction -Key $run -Name '') 'unnamed' 'the unnamed (Default) value'
Assert-Refused (New-RegistryValueAction -Key $wl -Name 'Shell') 'must be set back' 'deleting the Winlogon Shell'
Assert-Refused (New-RegistryValueAction -Key $wl -Name 'Userinit') 'must be set back' 'deleting the Winlogon Userinit'
Assert-Refused (New-RegistryValueAction -Key $run -Name 'Updater' -Reset -NewValue 'x') 'never set to a new text' 'setting a Run value to a text'
Assert-Refused (New-RegistryValueAction -Key $wl -Name 'Shell' -Reset -NewValue 'cmd.exe') 'may only be set back' 'a Shell that is not explorer.exe'
Assert-Refused (New-RegistryValueAction -Key $wl -Name 'Userinit' -Reset -NewValue 'C:\x.exe') 'may only be set back' 'a Userinit that is not the Windows default'
Assert-Refused (New-RegistryValueAction -Key $run -Name 'JenkinsHelper') 'never-touch' 'a Run entry with Jenkins in its name'
Assert-Refused (New-RegistryValueAction -Key $run -Name 'AgentLauncher') 'never-touch' 'a Run entry that starts Java (the name is harmless, the program is not)'
Assert-Refused (New-RegistryValueAction -Key $run -Name 'BinThing') 'type Binary' 'a binary value'
Assert-Refused (New-RegistryValueAction -Key $run -Name 'Ghost') 'not in .* any more' 'a value that is not there'
Assert-Refused (New-RegistryValueAction -Key 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'x') 'Cannot find path' 'a key that is not there'
Assert-Equal @($global:FW.Calls | Select-Object -Skip $calls | Where-Object { $_ -match '^(New|Remove)-ItemProperty' }).Count 0 'none of them wrote to the registry'
Assert-True ((Test-RegHas $run 'Updater') -and (Test-RegHas $run 'JenkinsHelper') -and (Test-RegHas $run 'AgentLauncher') -and (Get-RegData $wl 'Shell') -eq 'explorer.exe' -and (Test-RegHas 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')) 'and everything is still where it was'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Quarantine: a Startup file is moved (never deleted), then undone' -ForegroundColor Cyan
$script:Hp.DataDir = 'C:\ProgramData\NetCacheSvc'            # the quarantine folder is on the pretend disk (the journal stays in the real temp folder)
$startup = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
$qdir = 'C:\ProgramData\NetCacheSvc\quarantine'
$evil = "$startup\evil.bat"
$print = 'BEEF' * 16
$global:FW.Hashes[(Get-FakeKey $evil)] = $print
$act = New-QuarantineFileAction -Path $evil
Assert-True ($act.Id -eq "persist.quarantine:$evil" -and $act.Title -eq "Move 'evil.bat' to the quarantine folder" -and $act.UndoKind -eq 'persist.quarantine') 'the action: id, title, undo kind'
Assert-True (($act.Will -join ' ') -match 'NOT deleted' -and ($act.Will -join ' ') -match 'SHA-256') 'the preview says it is not deleted and that a fingerprint is kept'
$r = Invoke-Change $act -Confirmed
$rec = Get-LastRecord
$landed = @(@($global:FW.Dirs[(Get-FakeKey $qdir)]) | ForEach-Object { Get-FakeEntryName $_ })
Assert-Equal $r.Status 'Applied' 'applied'
Assert-True (-not (Test-Path -LiteralPath $evil) -and -not (Test-InFolder $startup 'evil.bat') -and (Test-InFolder $startup 'desktop.ini')) 'the file is gone from the Startup folder; its neighbour stays'
Assert-True ($landed.Count -eq 1 -and $landed[0] -match '^\d{8}-\d{6}-evil\.bat$') 'it sits in the quarantine folder with a time stamp in front of its name'
Assert-True ($rec.Before.Sha256 -eq $print -and $rec.Before.Dest -eq "$qdir\$($landed[0])" -and $rec.Before.Time -eq '2026-10-14 09:30:00' -and [long]$rec.Before.Bytes -eq 10) 'the journal has the fingerprint, size, date and the new place'
Assert-Equal (Get-FileHash -LiteralPath $rec.Before.Dest).Hash $print 'the quarantined file has the same fingerprint'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Test-InFolder $startup 'evil.bat') -and -not (Test-InFolder $qdir $landed[0]) -and (Get-FileHash -LiteralPath $evil).Hash -eq $print) 'undo: the file is back, with the same fingerprint, and the quarantine folder is empty again'

Write-Host 'Undo does not overwrite something that took the place of the file' -ForegroundColor Cyan
$r = Invoke-Change (New-QuarantineFileAction -Path $evil) -Confirmed
$rec = Get-LastRecord
$global:FW.Dirs[(Get-FakeKey $startup)] = @($global:FW.Dirs[(Get-FakeKey $startup)]) + 'evil.bat'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Something is at' -and (Test-Path -LiteralPath $rec.Before.Dest)) 'undo refuses, and the quarantined copy stays where it is'
Assert-Equal (Get-LastRecord).Status 'undo-failed' 'the journal says the undo failed'
$global:FW.Dirs[(Get-FakeKey $startup)] = @(@($global:FW.Dirs[(Get-FakeKey $startup)]) | Where-Object { (Get-FakeEntryName $_) -ine 'evil.bat' })

Write-Host 'A moved file that does not match its fingerprint is reported at once' -ForegroundColor Cyan
$global:FW.Dirs[(Get-FakeKey $startup)] = @($global:FW.Dirs[(Get-FakeKey $startup)]) + 'second.vbs'
$global:FW.CorruptMoves = $true
$r = Invoke-Change (New-QuarantineFileAction -Path "$startup\second.vbs") -Confirmed
$global:FW.CorruptMoves = $false
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'another fingerprint' -and $r.Message -match 'quarantine') 'the failure names the problem and where the file is'
Assert-Equal (Get-LastRecord).Status 'failed' 'the journal says failed'

Write-Host 'PowerShell profiles and policy scripts' -ForegroundColor Cyan
$prof = 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'
$global:FW.Dirs[(Get-FakeKey 'C:\Windows\System32\WindowsPowerShell\v1.0')] = @()                  # the folder exists on a real box
$r = Invoke-Change (New-QuarantineFileAction -Path $prof) -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and -not (Test-Path -LiteralPath $prof)) 'the all-users profile is moved'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True (Test-Path -LiteralPath $prof) 'and comes back'
$userProf = 'C:\Users\jmoney\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
$r = Invoke-Change (New-QuarantineFileAction -Path $userProf) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not (Test-Path -LiteralPath $userProf)) 'a user''s profile is moved'
$boot = 'C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup\boot.bat'
$r = Invoke-Change (New-QuarantineFileAction -Path $boot) -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and -not (Test-Path -LiteralPath $boot)) 'a local policy script is moved'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True (Test-Path -LiteralPath $boot) 'and comes back'

Write-Host 'Only those files can be moved' -ForegroundColor Cyan
$global:FW.Dirs[(Get-FakeKey $startup)] = @($global:FW.Dirs[(Get-FakeKey $startup)]) + 'jenkins-agent.lnk' + @{ Name = 'sub'; IsDir = $true }
$calls = $global:FW.Calls.Count
Assert-Refused (New-QuarantineFileAction -Path 'C:\Windows\System32\cmd.exe') 'only moves files from a Startup folder' 'cmd.exe in System32'
Assert-Refused (New-QuarantineFileAction -Path 'C:\Users\Public\up.exe') 'only moves files from a Startup folder' 'a file in the Public folder'
Assert-Refused (New-QuarantineFileAction -Path 'C:\Program Files\Jenkins\jenkins.xml') 'only moves files from a Startup folder' 'a Jenkins file'
Assert-Refused (New-QuarantineFileAction -Path "$startup\..\..\..\..\..\Windows\System32\cmd.exe") 'only moves files from a Startup folder' 'a path that climbs out of the Startup folder'
Assert-Refused (New-QuarantineFileAction -Path "$startup\sub\x.bat") 'only moves files from a Startup folder' 'a file in a sub-folder of Startup'
Assert-Refused (New-QuarantineFileAction -Path "$startup\jenkins-agent.lnk") 'never-touch' 'a Startup file with Jenkins in its name'
Assert-Refused (New-QuarantineFileAction -Path "$startup\sub") 'folder' 'a folder inside Startup'
Assert-Refused (New-QuarantineFileAction -Path "$startup\nothere.bat") 'Cannot find path' 'a file that is not there'
Assert-Equal @($global:FW.Calls | Select-Object -Skip $calls | Where-Object { $_ -match '^Move-Item' }).Count 0 'nothing was moved'
$script:Hp.DataDir = $tmp

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The hosts file: one line removed, the rest untouched, undo writes the whole old file back' -ForegroundColor Cyan
$old = Get-HostsText
$act = New-HostsLineAction -Entry '172.16.5.5 blackbox'
Assert-True ($act.Id -eq 'persist.hosts:172.16.5.5 blackbox' -and $act.UndoKind -eq 'persist.hosts' -and ($act.Will -join ' ') -match 'comments included') 'the action: id, undo kind, preview'
$r = Invoke-Change $act -Confirmed
$rec = Get-LastRecord
Assert-Equal $r.Status 'Applied' 'applied'
Assert-Equal (Get-HostsText) "# hosts file`r`n127.0.0.1 localhost`r`n::1 localhost # loopback`r`n10.9.9.9 update.microsoft.com`r`n" 'exactly that line is gone: comments, the localhost lines and the line ends are as before'
Assert-Equal $global:FW.LastEncoding 'Ascii' 'the file is written as plain ASCII (no BOM)'
Assert-True ($rec.Before.Text -eq $old -and [int]$rec.Before.Lines -eq 1) 'the journal has the whole old file'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and (Get-HostsText) -eq $old) 'undo: the file is byte for byte the old one'

Write-Host 'A line with a comment, and a line that is there twice' -ForegroundColor Cyan
Set-HostsText "127.0.0.1 localhost`r`n10.9.9.9 update.microsoft.com # added by admin`r`n10.9.9.9 UPDATE.microsoft.com`r`n10.9.9.90 update.microsoft.com`r`n"
$r = Invoke-Change (New-HostsLineAction -Entry '10.9.9.9 update.microsoft.com') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-HostsText) -eq "127.0.0.1 localhost`r`n10.9.9.90 update.microsoft.com`r`n" -and [int](Get-LastRecord).Before.Lines -eq 2) 'both copies go (also the one with a comment, and in another case); the line with another address stays'

Write-Host 'The hosts file: refusals' -ForegroundColor Cyan
Set-HostsText $old
Assert-Refused (New-HostsLineAction -Entry '10.1.1.1 nothere') 'No line with' 'a line that is not in the file'
Assert-Refused (New-HostsLineAction -Entry '') 'empty or a comment' 'an empty entry'
Assert-Refused (New-HostsLineAction -Entry '# hosts file') 'empty or a comment' 'a comment as the entry'
Set-HostsText "127.0.0.1 localhost`r`n# caf$([char]0xE9)`r`n10.9.9.9 x`r`n"
Assert-Refused (New-HostsLineAction -Entry '10.9.9.9 x') 'not plain ASCII' 'a file with non-ASCII characters'
$global:FW.Files.Remove((Get-FakeKey 'C:\Windows\System32\drivers\etc\hosts'))
$r = Invoke-Change (New-HostsLineAction -Entry '10.9.9.9 x') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'nothing was changed') 'a missing hosts file is reported'
Set-HostsText $old

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A network share: stop sharing, then share again with the same people' -ForegroundColor Cyan
$act = New-RemoveShareAction -Name 'Public'
Assert-True ($act.Id -eq 'persist.share:Public' -and $act.UndoKind -eq 'persist.share' -and ($act.Will -join ' ') -match 'NOT deleted') 'the action: id, undo kind, preview'
$r = Invoke-Change $act -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and $null -eq (Get-FakeShare 'Public') -and $null -ne (Get-FakeShare 'Docs')) 'Public is not shared any more; Docs is'
Assert-True ($rec.Before.Path -eq 'C:\Users\Public' -and $rec.Before.Description -eq 'public files' -and @($rec.Before.Access).Count -eq 1 -and $rec.Before.Access[0].Account -eq 'Everyone' -and $rec.Before.Access[0].Right -eq 'Full') 'the journal has the folder, the description and who could open it'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
$s = Get-FakeShare 'Public'
Assert-True ($r.Status -eq 'Undone' -and $s.Path -eq 'C:\Users\Public' -and $s.Description -eq 'public files' -and ($s.Access -join ',') -eq 'Everyone:Full:Allow') 'undo: shared again, same folder, same description, Everyone: Full'
$global:FW.Shares += @{ Name = 'Mixed'; Path = 'E:\mixed'; Special = $false; Description = ''; Access = @('Everyone:Change:Allow', 'CONTOSO\Bad:Full:Deny', 'BUILTIN\Administrators:Full:Allow', 'BUILTIN\Users:Read:Allow') }
$r = Invoke-Change (New-RemoveShareAction -Name 'Mixed') -Confirmed
$rec = Get-LastRecord
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
$s = Get-FakeShare 'Mixed'
Assert-Equal (($s.Access | Sort-Object) -join ',') 'BUILTIN\Administrators:Full:Allow,BUILTIN\Users:Read:Allow,CONTOSO\Bad:Full:Deny,Everyone:Change:Allow' 'undo: Full, Change, Read and a Deny entry all come back'

Write-Host 'Shares that must stay' -ForegroundColor Cyan
$global:FW.Shares += @{ Name = 'D$'; Path = 'D:\'; Special = $false; Description = 'Default share'; Access = @() }
Assert-Refused (New-RemoveShareAction -Name 'ADMIN$') 'administrative' 'ADMIN$'
Assert-Refused (New-RemoveShareAction -Name 'C$') 'administrative' 'C$'
Assert-Refused (New-RemoveShareAction -Name 'IPC$') 'administrative' 'IPC$'
Assert-Refused (New-RemoveShareAction -Name 'D$') 'administrative' 'a drive share that Windows did not flag as special'
Assert-Refused (New-RemoveShareAction -Name 'NoSuchShare') 'No MSFT_SmbShare|no share named' 'a share that does not exist'
Assert-True ($null -ne (Get-FakeShare 'ADMIN$') -and $null -ne (Get-FakeShare 'C$') -and $null -ne (Get-FakeShare 'IPC$')) 'all three are still shared'
$global:FW.BreakShareChange = $true
$r = Invoke-Change (New-RemoveShareAction -Name 'Docs') -Confirmed
$global:FW.BreakShareChange = $false
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Server service' -and $null -ne (Get-FakeShare 'Docs')) 'when Windows refuses, the failure is reported and the share is still there'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'A WMI subscription: removed with its binding and its own filter; there is NO undo, and the preview says so' -ForegroundColor Cyan
$global:FW.Wmi.Consumers += @{ Class = 'CommandLineEventConsumer'; Name = 'Second'; CommandLineTemplate = 'cmd.exe /c echo x'; ExecutablePath = $null; ScriptText = $null; ScriptFileName = $null }
$global:FW.Wmi.Bindings += @{ Filter = '__EventFilter (Name = "Updater Filter")'; Consumer = 'CommandLineEventConsumer (Name = "Second")' }
$act = New-RemoveWmiAction -Name 'Updater' -Class 'CommandLineEventConsumer'
Assert-True ($act.Id -eq 'persist.wmi:CommandLineEventConsumer/Updater' -and $act.UndoKind -eq '' -and $act.NoUndo -match 'does NOT recreate') 'the action has no undo kind and says why'
$script:Asked.Clear()
$r = Invoke-Change $act
$rec = Get-LastRecord
Assert-True ($script:Asked[0].Text -match 'Undo: NOT available' -and $script:Asked[0].Text -match 'NO UNDO for: the subscription itself') 'the question says BEFORE you confirm that there is no undo'
$names = @($global:FW.Wmi.Consumers | ForEach-Object { $_.Name })
Assert-True ($r.Status -eq 'Applied' -and $names -notcontains 'Updater' -and $names -contains 'Second' -and $names -contains 'SCM Event Log Consumer') 'the consumer is gone; the other one and Windows'' own stay'
Assert-True (@($global:FW.Wmi.Bindings | Where-Object { $_.Consumer -match '"Updater"' }).Count -eq 0 -and @($global:FW.Wmi.Bindings | Where-Object { $_.Consumer -match '"Second"' }).Count -eq 1) 'its binding is gone, the other binding stays'
Assert-True (@($global:FW.Wmi.Filters | Where-Object { $_.Name -eq 'Updater Filter' }).Count -eq 1) 'the filter stays: another consumer still uses it'
Assert-True ($rec.Before.Command -eq 'powershell.exe -enc AAAA' -and @($rec.Before.Filters).Count -eq 1 -and $rec.Before.Filters[0].Name -eq 'Updater Filter' -and $rec.Before.Filters[0].Query -match 'WITHIN 60') 'the journal has the command and the filter query'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'has no undo') 'Undo-Change says plainly that there is none'
$r = Invoke-Change (New-RemoveWmiAction -Name 'Second' -Class 'CommandLineEventConsumer') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and @($global:FW.Wmi.Filters | Where-Object { $_.Name -eq 'Updater Filter' }).Count -eq 0 -and @($global:FW.Wmi.Filters).Count -eq 1) 'the last consumer of the filter goes: now the filter goes too (Windows'' own filter stays)'
$global:FW.Wmi.Filters += @{ Name = 'Script Filter'; Query = 'SELECT * FROM __TimerEvent' }
$global:FW.Wmi.Consumers += @{ Class = 'ActiveScriptEventConsumer'; Name = 'ScriptBackdoor'; CommandLineTemplate = $null; ExecutablePath = $null; ScriptText = 'WScript.Echo 1'; ScriptFileName = $null }
$global:FW.Wmi.Bindings += @{ Filter = '__EventFilter (Name = "Script Filter")'; Consumer = 'ActiveScriptEventConsumer (Name = "ScriptBackdoor")' }
$r = Invoke-Change (New-RemoveWmiAction -Name 'ScriptBackdoor' -Class 'ActiveScriptEventConsumer') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and (Get-LastRecord).Before.Command -eq 'WScript.Echo 1') 'a script consumer works the same way, and its script is in the journal'

Write-Host 'WMI: refusals and failures' -ForegroundColor Cyan
Assert-Refused (New-RemoveWmiAction -Name 'SCM Event Log Consumer' -Class 'NTEventLogEventConsumer') 'Windows installs itself' 'Windows'' own subscription'
Assert-Refused (New-RemoveWmiAction -Name 'NoSuch' -Class 'CommandLineEventConsumer') 'There is no WMI consumer' 'a consumer that does not exist'
Assert-Refused (New-RemoveWmiAction -Name 'Updater' -Class 'ActiveScriptEventConsumer') 'There is no WMI consumer' 'the right name in the wrong class'
$global:FW.Wmi.Filters += @{ Name = 'F3'; Query = 'SELECT * FROM __TimerEvent' }
$global:FW.Wmi.Consumers += @{ Class = 'CommandLineEventConsumer'; Name = 'Third'; CommandLineTemplate = 'cmd.exe /c echo 3'; ExecutablePath = $null; ScriptText = $null; ScriptFileName = $null }
$global:FW.Wmi.Bindings += @{ Filter = '__EventFilter (Name = "F3")'; Consumer = 'CommandLineEventConsumer (Name = "Third")' }
$global:FW.BreakWmiRemove = $true
$r = Invoke-Change (New-RemoveWmiAction -Name 'Third' -Class 'CommandLineEventConsumer') -Confirmed
$global:FW.BreakWmiRemove = $false
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'Access denied' -and @($global:FW.Wmi.Consumers | Where-Object { $_.Name -eq 'Third' }).Count -eq 1 -and @($global:FW.Wmi.Bindings | Where-Object { $_.Consumer -match '"Third"' }).Count -eq 1) 'when Windows refuses, the failure is reported and nothing is half removed'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'Defender exclusions: one removed, the others stay, undo adds it back' -ForegroundColor Cyan
$global:FW.Defender.Exclusions = @('C:\Tools', 'D:\keep')
$global:FW.Defender.ExclusionExtensions = @('ps1')
$global:FW.Defender.ExclusionProcesses = @('evil.exe')
$act = New-RemoveDefenderExclusionAction -Kind 'Path' -Value 'C:\Tools'
Assert-True ($act.Id -eq 'def.exclusion:Path|C:\Tools' -and $act.UndoKind -eq 'def.exclusion' -and $act.Risk -eq 'Low') 'the action: id, undo kind, risk'
$r = Invoke-Change $act -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and (@($global:FW.Defender.Exclusions) -join ',') -eq 'D:\keep' -and @($global:FW.Calls | Where-Object { $_ -eq 'Remove-MpPreference ExclusionPath=C:\Tools' }).Count -eq 1) 'only C:\Tools is removed'
$r = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Undone' -and @($global:FW.Defender.Exclusions) -contains 'C:\Tools' -and @($global:FW.Defender.Exclusions) -contains 'D:\keep') 'undo: the exclusion is back'
$r = Invoke-Change (New-RemoveDefenderExclusionAction -Kind 'Extension' -Value 'ps1') -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and @($global:FW.Defender.ExclusionExtensions).Count -eq 0 -and @($global:FW.Defender.ExclusionProcesses).Count -eq 1) 'an extension exclusion is removed; the process exclusion is not touched'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True (@($global:FW.Defender.ExclusionExtensions) -contains 'ps1') 'undo adds the extension back'
$r = Invoke-Change (New-RemoveDefenderExclusionAction -Kind 'Process' -Value 'EVIL.EXE') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and @($global:FW.Defender.ExclusionProcesses).Count -eq 0) 'a process exclusion is removed (the case of the name does not matter)'
$null = Undo-Change -Id ([int](Get-LastRecord).Id) -Confirmed
Assert-Refused (New-RemoveDefenderExclusionAction -Kind 'Path' -Value 'C:\NotThere') 'no Path exclusion' 'an exclusion that is not there'
$global:FW.DefenderRefuses = $true
$r = Invoke-Change (New-RemoveDefenderExclusionAction -Kind 'Path' -Value 'C:\Tools') -Confirmed
$global:FW.DefenderRefuses = $false
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match '0x800106ba' -and @($global:FW.Defender.Exclusions) -contains 'C:\Tools') 'when Defender refuses, the failure shows its message and the exclusion is still there'
Assert-Throws { New-RemoveDefenderExclusionAction -Kind 'Everything' -Value 'x' } 'only Path, Extension and Process are valid kinds'

Write-Host 'Defender scanning switches: back on, and undo puts the old setting back' -ForegroundColor Cyan
$global:FW.Defender.RealTime = $false; $global:FW.Defender.Behavior = $false; $global:FW.Defender.Downloads = $false
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Realtime') -Confirmed
$rec = Get-LastRecord
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Defender.RealTime -and -not $global:FW.Defender.Behavior -and -not $global:FW.Defender.Downloads) 'real-time protection is on; the other two are not touched'
Assert-True ($rec.Before.Name -eq 'DisableRealtimeMonitoring' -and $rec.Before.WasOff -eq $true -and @($global:FW.Calls | Where-Object { $_ -eq 'Set-MpPreference DisableRealtimeMonitoring=False' }).Count -eq 1) 'the journal says what it was; Set-MpPreference was called with False'
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True (-not $global:FW.Defender.RealTime) 'undo: real-time protection is off again, as it was'
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Behavior') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Defender.Behavior) 'behavior monitoring is on'
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Downloads') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Defender.Downloads -and (Get-LastRecord).Before.Name -eq 'DisableIOAVProtection') 'scanning of downloads is on'
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Downloads') -Confirmed
$rec = Get-LastRecord
$null = Undo-Change -Id ([int]$rec.Id) -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $rec.Before.WasOff -eq $false -and $global:FW.Defender.Downloads) 'a switch that was already on: nothing breaks, and undo leaves it on'
Assert-Throws { New-DefenderSwitchAction -Setting 'Everything' } 'only Realtime, Behavior and Downloads are valid'

Write-Host 'A policy value holds a switch off: the fix says so, and the value is removed first' -ForegroundColor Cyan
$global:FW.Defender.RealTime = $false
$rtp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
Set-FakeReg $rtp 'DisableRealtimeMonitoring' 1
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Realtime') -Confirmed
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match 'still reports DisableRealtimeMonitoring = True' -and $r.Message -match 'policy' -and -not $global:FW.Defender.RealTime) 'the switch fails with a clear message when a policy overrides it'
$r = Invoke-Change (New-RegistryValueAction -Key $rtp -Name 'DisableRealtimeMonitoring' -Area 'def' -Label 'the Defender switch DisableRealtimeMonitoring') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and -not (Test-RegHas $rtp 'DisableRealtimeMonitoring')) 'the policy value is deleted'
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Realtime') -Confirmed
Assert-True ($r.Status -eq 'Applied' -and $global:FW.Defender.RealTime) 'and now the switch works'
$global:FW.DefenderRefuses = $true
$global:FW.Defender.Behavior = $false
$r = Invoke-Change (New-DefenderSwitchAction -Setting 'Behavior') -Confirmed
$global:FW.DefenderRefuses = $false
Assert-True ($r.Status -eq 'Failed' -and $r.Message -match '0x800106ba') 'when Defender itself refuses, its message is shown'
$global:FW.Defender = $null
Assert-Refused (New-DefenderSwitchAction -Setting 'Realtime') 'Defender is not available' 'a box where Defender cannot be read'

# ----------------------------------------------------------------------------------------------------------------
Write-Host 'The gate in front of all of it' -ForegroundColor Cyan
$global:FW.Defender = @{ Service = $true; RealTime = $false; SigAge = 1; Tamper = $true; Exclusions = @(); ExclusionExtensions = @(); ExclusionProcesses = @(); Mode = 'Normal'; Behavior = $true; Downloads = $true; QuickScanAge = 1; SigVersion = '1.421.100.0'; Version = '4.18.24090.11' }
$script:Hp.AllowChanges = $false
$count = Get-JournalCount
$r1 = Invoke-Change (New-RegistryValueAction -Key $run -Name 'Updater') -Confirmed
$r2 = Invoke-Change (New-HostsLineAction -Entry '172.16.5.5 blackbox') -Confirmed
$r3 = Invoke-Change (New-DefenderSwitchAction -Setting 'Realtime') -Confirmed
$r4 = Invoke-Change (New-RemoveShareAction -Name 'Docs') -Confirmed
Assert-True (@($r1, $r2, $r3, $r4 | Where-Object { $_.Status -eq 'Blocked' }).Count -eq 4 -and (Test-RegHas $run 'Updater') -and $null -ne (Get-FakeShare 'Docs') -and -not $global:FW.Defender.RealTime -and (Get-JournalCount) -eq $count) 'audit mode: all four are blocked, nothing changed, nothing journalled'
$script:Hp.AllowChanges = $true
$script:AskAnswer = $false
$r = Invoke-Change (New-RemoveShareAction -Name 'Docs')
Assert-True ($r.Status -eq 'Cancelled' -and $null -ne (Get-FakeShare 'Docs')) 'you say no: cancelled, nothing changed'
$script:AskAnswer = $true

Write-Host 'After a change, the right part of the box is read again' -ForegroundColor Cyan
foreach ($id in 'persist.reg:HKLM:\x|y', 'persist.quarantine:C:\x', 'persist.hosts:1.2.3.4 x', 'persist.share:Docs', 'persist.wmi:CommandLineEventConsumer/x') {
    Assert-Equal ((Get-SectionsForAction $id) -join ',') 'Persist' "$id re-reads the Persist section"
}
foreach ($id in 'def.reg:HKLM:\x|y', 'def.exclusion:Path|C:\x', 'def.switch:Realtime') {
    Assert-Equal ((Get-SectionsForAction $id) -join ',') 'Defender,Services' "$id re-reads Defender and the services"
}

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-TestSummary
