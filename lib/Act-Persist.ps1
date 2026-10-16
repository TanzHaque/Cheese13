# Act-Persist.ps1 - the fixes for the persistence audit (phase 6) and the Defender diagnosis (phase 7). One item per action:
#   - delete ONE registry value from a short list of hiding places (Run keys, debugger hooks, Winlogon, AppInit, Defender policy)
#   - move ONE startup file, PowerShell profile or policy script to the quarantine folder (moved, never deleted)
#   - remove ONE line of the hosts file, ONE network share, ONE WMI subscription
#   - Defender: remove ONE exclusion, switch ONE kind of scanning back on
# Building an action changes nothing; only Invoke-Change runs it (preview, confirm, journal, apply). Undo puts the
# old state back - except for a WMI subscription: its details are written to the journal, but Undo does not recreate it.
# The rules about what may be touched are checked AGAIN when the old state is read (Capture), not only in the judge, so a wrong
# click cannot change anything outside the lists below. Nothing here kills a process.
# Windows PowerShell 5.1, plain ASCII.

# ---------------------------------------------------------------- registry values
# The only registry values these actions may change. A key is compared after its root has been shortened (see Get-RegistryShortKey).
# Set = $null means "delete the value"; any other text means "set the value to exactly this text" (Windows needs a value there).
$script:RegistryFixRules = @(
    @{ Key = '^(HKLM|HKU)\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce)$'; Name = '.'; Set = $null }
    @{ Key = '^(HKLM|HKU)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run$'; Name = '.'; Set = $null }
    @{ Key = '^HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\[^\\]+$'; Name = '^(Debugger|VerifierDlls)$'; Set = $null }
    @{ Key = '^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\[^\\]+$'; Name = '^MonitorProcess$'; Set = $null }
    @{ Key = '^HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Windows$'; Name = '^AppInit_DLLs$'; Set = '' }
    @{ Key = '^HKLM\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Windows$'; Name = '^(Load|Run)$'; Set = $null }
    @{ Key = '^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$'; Name = '^Shell$'; Set = 'explorer.exe' }
    @{ Key = '^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$'; Name = '^Userinit$'; Set = 'C:\Windows\system32\userinit.exe,' }
    @{ Key = '^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon$'; Name = '^(Taskman|AppSetup)$'; Set = $null }
    @{ Key = '^HKLM\\SOFTWARE\\(Policies\\)?Microsoft\\Windows Defender(\\Real-Time Protection)?$'
       Name = '^(DisableAntiSpyware|DisableAntiVirus|DisableRoutinelyTakingAction|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableOnAccessProtection|DisableIOAVProtection|DisableScanOnRealtimeEnable|DisableScriptScanning)$'; Set = $null }
    @{ Key = '^HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection$'; Name = '^ForceDefenderPassiveMode$'; Set = $null }
)

function Get-RegistryShortKey {
    # HKLM:\SOFTWARE\x  or  Registry::HKEY_LOCAL_MACHINE\SOFTWARE\x  ->  HKLM\SOFTWARE\x
    # Registry::HKEY_USERS\S-1-5-21-...\SOFTWARE\x (a logged-on user)  ->  HKU\SOFTWARE\x.   Anything else -> '' (not allowed).
    param([string]$Key)
    $k = $Key.TrimEnd('\')
    if ($k -match '(?i)^(HKLM:|Registry::HKEY_LOCAL_MACHINE)\\(.+)$') { return 'HKLM\' + $Matches[2] }
    if ($k -match '(?i)^Registry::HKEY_USERS\\S-1-5-21-[0-9-]+\\(.+)$') { return 'HKU\' + $Matches[1] }
    ''
}

function Find-RegistryFixRule {
    # The rule that allows changing this value, or $null when no rule does.
    param([string]$Key, [string]$Name)
    $short = Get-RegistryShortKey $Key
    if (-not $short) { return $null }
    foreach ($rule in $script:RegistryFixRules) {
        if ($short -match $rule.Key -and $Name -match $rule.Name) { return $rule }
    }
    $null
}

function Assert-RegistryValueMayChange {
    # Guard for Capture: the value must be on the list, removed or reset the way the list says, and not belong to a never-touch program.
    param([string]$Key, [string]$Name, [bool]$Reset, [string]$NewValue, $OldValue)
    if (-not $Name) { throw 'Refused: the unnamed (Default) value is not handled here. Use reg.exe by hand (RUNBOOK.md).' }
    if ($Name -match '[*?\[\]]') { throw "Refused: the value name '$Name' has wildcard characters. Remove it by hand (RUNBOOK.md)." }
    $rule = Find-RegistryFixRule $Key $Name
    if (-not $rule) { throw "Refused: '$Name' in $Key is not on the list of places this tool may change (Run keys, debugger hooks, AppInit, Winlogon, Defender policy)." }
    if ($Reset) {
        if ($null -eq $rule.Set) { throw "Refused: '$Name' is deleted, never set to a new text." }
        if ($NewValue -ne [string]$rule.Set) { throw "Refused: '$Name' may only be set back to its Windows default ($($rule.Set))." }
    } elseif ($null -ne $rule.Set) {
        throw "Refused: '$Name' must be set back to its Windows default ($($rule.Set)), not deleted: Windows needs a value there."
    }
    if ((Get-RegistryShortKey $Key) -match '\\Run(Once)?$' -and (Test-NeverTouchApp $Name ([string]$OldValue))) {
        throw "Refused: '$Name' is on the never-touch list (Jenkins, Java, Remote Desktop, the log collector, Defender)."
    }
}

function New-RegistryValueAction {
    # Deletes ONE registry value, or (with -Reset) sets it back to its Windows default text. -Shown is only for the preview.
    param([string]$Key, [string]$Name, [string]$Area = 'persist', [string]$Label = '', [string]$Shown = '',
          [switch]$Reset, [string]$NewValue = '', [string]$Risk = 'Medium', [string]$TypeWord = '')
    $what = $(if ($Label) { $Label } else { "the registry value '$Name'" })
    $title = $(if ($Reset) { "Set $what back to its default" } else { "Delete $what" })
    $will = @()
    if ($Reset) { $will += "Set the value '$Name' in $Key back to '$NewValue'" }
    else { $will += "Delete the value '$Name' from $Key" }
    if ($Shown) { $will += "It holds now: $(Get-ShortText $Shown 200)" }
    $will += 'The old value and its type are saved in the journal; Undo writes them back exactly'
    $will += 'A program that is running right now keeps running (the tool does not kill processes)'
    New-Action -Id "$Area.reg:$Key|$Name" -Title $title -Risk $Risk -Will $will -TypeWord $TypeWord `
        -Data @{ Key = $Key; Name = $Name; Reset = [bool]$Reset; NewValue = $NewValue } `
        -Capture {
            param($d)
            Assert-RegistryValueMayChange $d.Key $d.Name $d.Reset $d.NewValue ''                # the list first: nothing off the list is even read
            $item = Get-Item -LiteralPath $d.Key -ErrorAction Stop
            if ($item.GetValueNames() -notcontains $d.Name) { throw "The value '$($d.Name)' is not in $($d.Key) any more." }
            $old = $item.GetValue($d.Name, $null, 'DoNotExpandEnvironmentNames')           # as stored: %variables% are not filled in
            $kind = [string]$item.GetValueKind($d.Name)
            if (@('String', 'ExpandString', 'DWord') -notcontains $kind) { throw "Refused: the value is of type $kind, which this tool does not handle. Use reg.exe by hand (RUNBOOK.md)." }
            Assert-RegistryValueMayChange $d.Key $d.Name $d.Reset $d.NewValue $old              # and again with the value itself (a Run entry that starts Jenkins stays)
            @{ Kind = $kind; Value = $old }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            if ($d.Reset) { New-ItemProperty -LiteralPath $d.Key -Name $d.Name -Value $d.NewValue -PropertyType String -Force | Out-Null }
            else { Remove-ItemProperty -LiteralPath $d.Key -Name $d.Name }
            $now = Get-ItemProperty -LiteralPath $d.Key -Name $d.Name -ErrorAction SilentlyContinue
            if ($d.Reset) {
                if (-not $now -or [string]$now.($d.Name) -ne $d.NewValue) { throw "'$($d.Name)' was not set to '$($d.NewValue)'." }
                return "'$($d.Name)' is back to '$($d.NewValue)'."
            }
            if ($now) { throw "The value '$($d.Name)' is still in $($d.Key) after the delete." }
            "'$($d.Name)' is gone from $($d.Key)."
        } `
        -UndoKind 'persist.reg'
}

Register-UndoHandler 'persist.reg' {
    # Writes the old value back with its old type (and makes the key again if it has disappeared).
    param($data, $before)
    if (-not (Test-Path -LiteralPath $data.Key)) { New-Item -Path $data.Key -Force | Out-Null }
    New-ItemProperty -LiteralPath $data.Key -Name $data.Name -Value $before.Value -PropertyType ([string]$before.Kind) -Force | Out-Null
}

# ---------------------------------------------------------------- files: quarantine, never delete
function Assert-FileMayBeQuarantined {
    # Only the files the audit lists: Startup folders, PowerShell profiles, local policy scripts. Never a Jenkins or Java file.
    param([string]$Path)
    $ok = ($Path -match '(?i)\\Start Menu\\Programs\\Startup\\[^\\]+$') -or
          ($Path -match '(?i)\\WindowsPowerShell\\(v1\.0\\)?(profile|Microsoft\.PowerShell_profile|Microsoft\.PowerShellISE_profile)\.ps1$') -or
          ($Path -match '(?i)\\System32\\GroupPolicy\\(Machine|User)\\Scripts\\(Startup|Shutdown|Logon|Logoff)\\[^\\]+$')
    if (-not $ok) { throw 'Refused: this tool only moves files from a Startup folder, PowerShell profiles and local policy scripts.' }
    if (Test-NeverTouchApp (Split-Path -Path $Path -Leaf) $Path) { throw 'Refused: this file matches the never-touch list (Jenkins, Java, Remote Desktop, the log collector, Defender).' }
}

function New-QuarantineFileAction {
    param([string]$Path)
    $leaf = Split-Path -Path $Path -Leaf
    New-Action -Id "persist.quarantine:$Path" -Title "Move '$leaf' to the quarantine folder" -Risk 'Medium' `
        -Will @("Move the file $Path into the quarantine folder inside the tool's data folder (it is NOT deleted)",
                'Its SHA-256 fingerprint, size and date are written to the journal before it moves',
                'If the file is running right now, it keeps running (the tool does not kill processes)',
                'Undo moves it back to where it was (it refuses if something else has taken its place)') `
        -Data @{ Path = $Path } `
        -Capture {
            param($d)
            Assert-FileMayBeQuarantined $d.Path
            $file = Get-Item -LiteralPath $d.Path -ErrorAction Stop
            if ($file.PSIsContainer) { throw 'Refused: this is a folder, not a file.' }
            $hash = (Get-FileHash -LiteralPath $d.Path -Algorithm SHA256).Hash
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $dest = Join-Path (Join-Path $script:Hp.DataDir 'quarantine') ($stamp + '-' + $file.Name)
            @{ Sha256 = $hash; Bytes = [long]$file.Length; Time = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'); Dest = $dest }
        } `
        -Apply {
            param($d, $before)
            New-Item -ItemType Directory -Path (Split-Path -Path $before.Dest -Parent) -Force | Out-Null
            Move-Item -LiteralPath $d.Path -Destination $before.Dest
            if (Test-Path -LiteralPath $d.Path) { throw "The file is still at $($d.Path) after the move." }
            $moved = (Get-FileHash -LiteralPath $before.Dest -Algorithm SHA256).Hash
            if ($moved -ne $before.Sha256) { throw "The moved file has another fingerprint ($moved). It is in $($before.Dest): look at it before you do anything else." }
            "Moved to $($before.Dest)."
        } `
        -UndoKind 'persist.quarantine'
}

Register-UndoHandler 'persist.quarantine' {
    param($data, $before)
    if (Test-Path -LiteralPath $data.Path) { throw "Something is at $($data.Path) already, so the file was not moved back. It stays in $($before.Dest)." }
    Move-Item -LiteralPath $before.Dest -Destination $data.Path
}

# ---------------------------------------------------------------- the hosts file
function New-HostsLineAction {
    param([string]$Entry)
    New-Action -Id "persist.hosts:$Entry" -Title "Remove the hosts line '$Entry'" -Risk 'Medium' `
        -Will @("Remove every line of the hosts file whose content (before any #) is exactly: $Entry",
                'All other lines, comments included, stay as they are',
                'The whole old file is saved in the journal. Undo writes it back as it was, so undo in order (Undo last)') `
        -Data @{ Entry = $Entry } `
        -Capture {
            param($d)
            if (-not $d.Entry -or $d.Entry.StartsWith('#')) { throw 'Refused: the entry is empty or a comment.' }
            $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            $text = [string](Get-Content -Path $path -Raw)
            if ($text -cmatch '[^\x00-\x7F]') { throw 'Refused: the hosts file has characters that are not plain ASCII. Edit it by hand (RUNBOOK.md).' }
            $hits = @(($text -split "\r?\n") | Where-Object { (($_ -split '#')[0]).Trim() -ieq $d.Entry })
            if ($hits.Count -eq 0) { throw "No line with '$($d.Entry)' is in the hosts file any more." }
            @{ Path = $path; Text = $text; Lines = $hits.Count }
        } `
        -Apply {
            param($d, $before)
            $keep = @(($before.Text -split "\r?\n") | Where-Object { (($_ -split '#')[0]).Trim() -ine $d.Entry })
            Set-Content -Path $before.Path -Value ($keep -join "`r`n") -Encoding Ascii -NoNewline
            $check = [string](Get-Content -Path $before.Path -Raw)
            if (@(($check -split "\r?\n") | Where-Object { (($_ -split '#')[0]).Trim() -ieq $d.Entry }).Count -gt 0) { throw 'The line is still in the hosts file after the rewrite.' }
            "Removed $($before.Lines) line(s) from the hosts file."
        } `
        -UndoKind 'persist.hosts'
}

Register-UndoHandler 'persist.hosts' {
    param($data, $before)
    $null = $data
    Set-Content -Path $before.Path -Value ([string]$before.Text) -Encoding Ascii -NoNewline
}

# ---------------------------------------------------------------- a network share
function New-RemoveShareAction {
    param([string]$Name)
    New-Action -Id "persist.share:$Name" -Title "Stop sharing '$Name'" -Risk 'Medium' `
        -Will @("Stop sharing '$Name' over the network (the folder and its files are NOT deleted)",
                'Who could open it is saved in the journal; Undo shares the folder again with the same people') `
        -Data @{ Name = $Name } `
        -Capture {
            param($d)
            $s = @(Get-SmbShare -Name $d.Name -ErrorAction Stop) | Select-Object -First 1
            if (-not $s) { throw "There is no share named '$($d.Name)'." }
            if ($s.Special -or $d.Name -match '^(ADMIN|IPC)\$$|^[A-Za-z]\$$') { throw "Refused: '$($d.Name)' is one of Windows' own administrative shares." }
            $access = @()
            foreach ($a in @(Get-SmbShareAccess -Name $d.Name)) { $access += @{ Account = [string]$a.AccountName; Right = [string]$a.AccessRight; Type = [string]$a.AccessControlType } }
            @{ Path = [string]$s.Path; Description = [string]$s.Description; Access = $access }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            Remove-SmbShare -Name $d.Name -Force
            if (@(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $d.Name }).Count -gt 0) { throw "The share '$($d.Name)' is still there." }
            "'$($d.Name)' is no longer shared."
        } `
        -UndoKind 'persist.share'
}

Register-UndoHandler 'persist.share' {
    # Shares the folder again, with the people it had before (an Allow entry per access level, a Deny entry as "no access").
    param($data, $before)
    $full = @(); $change = @(); $read = @(); $none = @()
    foreach ($a in @($before.Access)) {
        if ([string]$a.Type -eq 'Deny') { $none += [string]$a.Account }
        elseif ([string]$a.Right -eq 'Full') { $full += [string]$a.Account }
        elseif ([string]$a.Right -eq 'Change') { $change += [string]$a.Account }
        else { $read += [string]$a.Account }
    }
    $with = @{ Name = [string]$data.Name; Path = [string]$before.Path }
    if ($before.Description) { $with.Description = [string]$before.Description }
    if ($full.Count -gt 0) { $with.FullAccess = $full }
    if ($change.Count -gt 0) { $with.ChangeAccess = $change }
    if ($read.Count -gt 0) { $with.ReadAccess = $read }
    if ($none.Count -gt 0) { $with.NoAccess = $none }
    New-SmbShare @with | Out-Null
}

# ---------------------------------------------------------------- a WMI event subscription
function New-RemoveWmiAction {
    param([string]$Name, [string]$Class)
    New-Action -Id "persist.wmi:$Class/$Name" -Title "Remove the WMI subscription '$Name'" -Risk 'Medium' `
        -Will @("Remove the WMI event consumer '$Name' ($Class) and the bindings that join it to a filter",
                'Remove each filter that no other consumer uses any more',
                'Nothing else on the box is touched; a program that is running right now keeps running') `
        -NoUndo 'the subscription itself: Undo does NOT recreate it. Its filter query and command are written to the journal first, so you can read them' `
        -Data @{ Name = $Name; Class = $Class } `
        -Capture {
            param($d)
            $ns = 'root\subscription'
            if ($d.Class -eq 'NTEventLogEventConsumer' -and $d.Name -eq 'SCM Event Log Consumer') { throw 'Refused: this is the subscription Windows installs itself.' }
            $consumer = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop | Where-Object { [string]$_.Name -eq $d.Name -and [string]$_.CimClass.CimClassName -eq $d.Class }) | Select-Object -First 1
            if (-not $consumer) { throw "There is no WMI consumer '$($d.Name)' of class $($d.Class)." }
            $command = (@($consumer.CommandLineTemplate, $consumer.ExecutablePath, $consumer.ScriptFileName, $consumer.ScriptText) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ' | '
            $filters = @()
            foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)) {
                if ((Get-WmiName $b.Consumer) -ne $d.Name) { continue }
                $filterName = Get-WmiName $b.Filter
                $filter = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop | Where-Object { [string]$_.Name -eq $filterName }) | Select-Object -First 1
                $filters += @{ Name = $filterName; Query = $(if ($filter) { [string]$filter.Query } else { '' }) }
            }
            @{ Command = $command; Filters = $filters }
        } `
        -Apply {
            param($d, $before)
            $ns = 'root\subscription'
            foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding)) {
                if ((Get-WmiName $b.Consumer) -eq $d.Name) { $b | Remove-CimInstance }
            }
            foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer)) {
                if ([string]$c.Name -eq $d.Name -and [string]$c.CimClass.CimClassName -eq $d.Class) { $c | Remove-CimInstance }
            }
            foreach ($f in @($before.Filters)) {
                $stillUsed = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { (Get-WmiName $_.Filter) -eq $f.Name }).Count
                if ($stillUsed -gt 0) { continue }
                foreach ($e in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter)) {
                    if ([string]$e.Name -eq $f.Name) { $e | Remove-CimInstance }
                }
            }
            $left = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer | Where-Object { [string]$_.Name -eq $d.Name -and [string]$_.CimClass.CimClassName -eq $d.Class })
            if ($left.Count -gt 0) { throw "The consumer '$($d.Name)' is still there after Remove-CimInstance." }
            "The subscription '$($d.Name)' is removed."
        }
}

# ---------------------------------------------------------------- Defender
function New-RemoveDefenderExclusionAction {
    param([ValidateSet('Path', 'Extension', 'Process')][string]$Kind, [string]$Value)
    New-Action -Id "def.exclusion:$Kind|$Value" -Title "Remove the Defender $Kind exclusion '$Value'" -Risk 'Low' `
        -Will @("Tell Defender to scan again what the $Kind exclusion '$Value' made it skip",
                'Nothing is deleted. Undo adds the exclusion back') `
        -Data @{ Kind = $Kind; Value = $Value } `
        -Capture {
            param($d)
            $pref = Get-MpPreference -ErrorAction Stop
            $listName = 'Exclusion' + $d.Kind                       # ExclusionPath, ExclusionExtension or ExclusionProcess
            $list = @($pref.$listName)
            if (@($list | Where-Object { [string]$_ -ieq $d.Value }).Count -eq 0) { throw "Defender has no $($d.Kind) exclusion '$($d.Value)' any more." }
            @{ Kind = $d.Kind; Value = $d.Value }
        } `
        -Apply {
            param($d, $before)
            $null = $before
            $listName = 'Exclusion' + $d.Kind
            $change = @{}
            $change[$listName] = $d.Value
            Remove-MpPreference @change
            $pref = Get-MpPreference -ErrorAction Stop
            if (@(@($pref.$listName) | Where-Object { [string]$_ -ieq $d.Value }).Count -gt 0) { throw "The exclusion '$($d.Value)' is still there. Tamper Protection or a policy may be holding it." }
            "The exclusion '$($d.Value)' is gone."
        } `
        -UndoKind 'def.exclusion'
}

Register-UndoHandler 'def.exclusion' {
    param($data, $before)
    $null = $before
    $listName = 'Exclusion' + $data.Kind
    $change = @{}
    $change[$listName] = [string]$data.Value
    Add-MpPreference @change
}

function Get-DefenderSwitchName {
    # The Set-MpPreference setting behind each kind of scanning. The setting says Disable..., so $false means "on".
    param([string]$Setting)
    if ($Setting -eq 'Realtime') { return 'DisableRealtimeMonitoring' }
    if ($Setting -eq 'Behavior') { return 'DisableBehaviorMonitoring' }
    if ($Setting -eq 'Downloads') { return 'DisableIOAVProtection' }
    ''
}

function New-DefenderSwitchAction {
    param([ValidateSet('Realtime', 'Behavior', 'Downloads')][string]$Setting)
    $label = @{ Realtime = 'real-time protection'; Behavior = 'behavior monitoring'; Downloads = 'scanning of downloads and attachments' }[$Setting]
    New-Action -Id "def.switch:$Setting" -Title "Switch Defender's $label back on" -Risk 'Low' `
        -Will @("Tell Defender to use $label again (Set-MpPreference)",
                'Defender may now block files it did not look at before - watch NEIGH, especially Jenkins',
                'If a policy value or Tamper Protection overrides the setting, the change fails and says so',
                'Undo puts the old setting back') `
        -Data @{ Setting = $Setting } `
        -Capture {
            param($d)
            $name = Get-DefenderSwitchName $d.Setting
            $pref = Get-MpPreference -ErrorAction Stop
            @{ Name = $name; WasOff = [bool]$pref.$name }
        } `
        -Apply {
            param($d, $before)
            $null = $d
            $change = @{}
            $change[[string]$before.Name] = $false
            Set-MpPreference @change
            $pref = Get-MpPreference -ErrorAction Stop
            if ([bool]$pref.($before.Name)) { throw "Defender still reports $($before.Name) = True after Set-MpPreference. A policy value or Tamper Protection is probably overriding it: see the rows above." }
            "$($before.Name) is False now."
        } `
        -UndoKind 'def.switch'
}

Register-UndoHandler 'def.switch' {
    param($data, $before)
    $null = $data
    $change = @{}
    $change[[string]$before.Name] = [bool]$before.WasOff
    Set-MpPreference @change
}
