# JudgeHunt.ps1 - phase 6: things that look like persistence or a backdoor. REPORT FIRST: nothing here is fixed in a batch.
# Each fix is one item, with its own confirmation. The plan's rules: quarantine (disable), never delete; never touch Jenkins,
# Java, TermService, the log collector or Windows components; never kill a process just because it is unsigned.
# Windows PowerShell 5.1, plain ASCII.

$script:OddFolders = '\\temp\\|\\users\\public\\|\\appdata\\|\\downloads\\|\\perflogs\\|\\windows\\tasks\\|\\recycle'
$script:ScriptyPrograms = 'cmd\.exe|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl|wget|\.bat|\.vbs|\.ps1|\.js\b'

function Expand-CommonPath {
    # Turns %windir% and friends into real folders (just text work, no Windows call).
    param([string]$Path)
    $p = $Path
    $p = $p -replace '(?i)%(systemroot|windir)%', 'C:\Windows'
    $p = $p -replace '(?i)%programfiles\(x86\)%', 'C:\Program Files (x86)'
    $p = $p -replace '(?i)%programfiles%', 'C:\Program Files'
    $p = $p -replace '(?i)%programdata%', 'C:\ProgramData'
    $p = $p -replace '(?i)%systemdrive%', 'C:'
    $p.Trim('"')
}

function Test-StandardFolder {
    # Windows itself and installed programs live in these folders. Defender's own program folder is under ProgramData
    # (the WinDefend service runs from there on a real server), so it counts as standard too.
    param([string]$Path)
    $p = Expand-CommonPath $Path
    ($p -match '(?i)^c:\\windows\\') -or ($p -match '(?i)^c:\\program files( \(x86\))?\\') -or ($p -match '(?i)^c:\\programdata\\microsoft\\windows defender( advanced threat protection)?\\')
}

function Test-OddPath {
    # True when a program sits somewhere programs normally do not live.
    param([string]$Path)
    $p = Expand-CommonPath $Path
    if (-not $p) { return $false }
    ($p -match "(?i)$($script:OddFolders)") -or (-not (Test-StandardFolder $p))
}

$script:NeverTouchWords = 'jenkins|\\java|javaw?\.exe|termservice|termsrv|otel|collector|windows defender|msmpeng|nissrv|windefend|wdnissvc'

function Test-ProtectedProgram {
    # The plan's never-touch list: Jenkins, Java, the Remote Desktop service, the log collector, Defender, Windows itself.
    # (Defender is repaired in phase 7; it is never disabled here.)
    param([string]$Name, [string]$Path)
    $text = "$Name $Path"
    ($text -match "(?i)$($script:NeverTouchWords)|\\windows\\system32\\|\\windows\\syswow64\\")
}

function Test-NeverTouchApp {
    # The same list WITHOUT the Windows folders: for startup entries, which are not Windows components (a Run entry that starts
    # cmd.exe or powershell.exe from System32 is exactly what the audit must be able to flag).
    param([string]$Name, [string]$Path)
    ("$Name $Path" -match "(?i)$($script:NeverTouchWords)")
}

function Get-ActionProgram {
    # The program named at the start of a task action:  "C:\x y\a.exe" /c  ->  C:\x y\a.exe  ('' when it names no folder)
    param([string]$Action)
    $m = [regex]::Match($Action, '(?i)^"?((?:[A-Za-z]:|%[A-Za-z0-9()]+%)\\[^"]*?\.(?:exe|bat|cmd|ps1|vbs|js|com|scr|dll))')
    if ($m.Success) { return $m.Groups[1].Value }
    ''
}

$script:ShellWords = '(?i)(^|[\\"\s;])(cmd|powershell|pwsh|wscript|cscript|mshta|regsvr32|certutil|bitsadmin|curl|wget)(\.exe)?($|[\s";])'

function Test-SuspiciousMicrosoftTask {
    # Windows keeps hundreds of its own tasks under \Microsoft\, so those are NOT listed one by one. A task there gets a row only when its
    # command shows one of three signs: it runs from a folder where programs do not live (Temp, Public, AppData ...), its program sits
    # outside Windows and Program Files, or it starts a shell or script host (cmd, powershell, wscript ...). The fix uses this same test.
    param([string]$ActionText)
    if (-not $ActionText) { return $false }
    if ($ActionText -match "(?i)$($script:OddFolders)") { return $true }
    foreach ($a in ($ActionText -split ' ; ')) {
        $exe = Get-ActionProgram $a
        if ($exe -and (Test-OddPath $exe)) { return $true }
    }
    [bool]($ActionText -match $script:ShellWords)
}

function Get-HuntFindings {
    param($Facts, $Settings)
    $null = $Settings
    $out = @()
    $out += Get-ServiceHuntFindings $Facts
    $out += Get-TaskHuntFindings $Facts
    $out += Get-PortHuntFindings $Facts
    $out += Get-PersistHuntFindings $Facts
    $out
}

function Get-ServiceHuntFindings {
    param($Facts)
    $out = @()
    foreach ($s in (Get-List $Facts.Services)) {
        if (-not $s.Exe) { continue }
        if (-not (Test-OddPath $s.Exe)) { continue }
        $sev = $(if ((Expand-CommonPath $s.Exe) -match "(?i)$($script:OddFolders)") { 'BAD' } else { 'WARN' })
        $why = "Service '$($s.Name)' ($($s.DisplayName)) is $($s.State), starts $($s.StartMode), runs as $($s.StartName), and its program is $($s.Exe): not in Windows or Program Files."
        if (Test-ProtectedProgram $s.Name $s.Exe) {
            $out += New-Finding 6 'Services' 'INFO' "$($s.Name) (protected)" "$why It matches the never-touch list, so no fix is offered."
        } else {
            $out += New-Finding 6 'Services' $sev "Service $($s.Name)" "$why Disabling stops it and prevents a restart; Undo restores both." (New-FixRef 'New-DisableServiceAction' @{ Name = $s.Name }) -Batch $false
        }
    }
    $out
}

function Get-OwnTaskState {
    # 'Own'  = a task the tool created: its name is the tool's, it has exactly ONE action, and that action runs the tool's script.
    # 'Fake' = it has the name of one of them but runs something else, or something more (an intruder hiding behind the name, or a
    #          second action added to the real task).
    # ''     = any other task.   $OwnFiles: lower-case task name -> the script it must run (Get-OwnTaskFiles in Collect.ps1).
    param([string]$Name, [string]$Path, [string]$ActionText, $OwnFiles)
    if (-not $OwnFiles -or $Path -ne '\') { return '' }
    $file = $OwnFiles[$Name.ToLower()]
    if (-not $file) { return '' }
    if (@($ActionText -split ' ; ').Count -ne 1) { return 'Fake' }          # the actions of a task are joined with ' ; ': a second one was added
    if ($ActionText -match [regex]::Escape([string]$file)) { return 'Own' }
    'Fake'
}

function Get-TaskHuntFindings {
    param($Facts)
    $out = @()
    foreach ($t in (Get-List $Facts.Tasks)) {
        $action = (Get-List $t.Actions) -join ' ; '
        $own = Get-OwnTaskState $t.Name $t.Path $action $Facts.OwnTasks
        if ($own -eq 'Own') {
            $out += New-Finding 6 'Scheduled tasks' 'INFO' "Task $($t.Path)$($t.Name) (the tool's own)" "This task was created by this tool and runs the tool's own script as $($t.UserId): $action. Leave it alone (the Watchdog phase and the dead-man switch manage it)."
            continue
        }
        if ($own -eq 'Fake') {
            $out += New-Finding 6 'Scheduled tasks' 'BAD' "Task $($t.Path)$($t.Name) uses the name of the tool's own task" "The tool has a task with this name, but this one is not the tool's task: it does not run exactly the tool's script (it runs something else, or another action was added). It runs as $($t.UserId) and starts: $action. If you did not change it, an intruder did. No button disables it (the tool refuses to touch tasks with its own names): disable it by hand (Disable-ScheduledTask -TaskName $($t.Name) -TaskPath '\'), then put the real one back (Watchdog phase: install; dead-man: arm again)."
            continue
        }
        $odd = [bool]($action -and ($action -match "(?i)$($script:OddFolders)"))
        $ofWindows = ($t.Path -like '\Microsoft\*')
        if ($ofWindows) {
            if (-not (Test-SuspiciousMicrosoftTask $action)) { continue }
        } else {
            $scripty = [bool]($action -match "(?i)$($script:ScriptyPrograms)")
            $strange = $false
            foreach ($a in (Get-List $t.Actions)) {
                $exe = Get-ActionProgram $a
                if ($exe -and (Test-OddPath $exe)) { $strange = $true }
            }
            if (-not ($scripty -or $odd -or $strange)) { continue }
        }
        $sev = $(if ($odd) { 'BAD' } else { 'WARN' })
        $why = "Task $($t.Path)$($t.Name) is $($t.State), runs as $($t.UserId) ($($t.RunLevel)) and starts: $action"
        if ($ofWindows) { $why += ' It sits under \Microsoft\, where Windows keeps its own tasks (and where a planted one hides), but Windows rarely starts a shell or a program from a place like this: read the command.' }
        $out += New-Finding 6 'Scheduled tasks' $sev "Task $($t.Path)$($t.Name)" "$why Disabling it keeps the task but stops it from running; Undo enables it again." (New-FixRef 'New-DisableTaskAction' @{ Name = $t.Name; Path = $t.Path }) -Batch $false
    }
    $out
}

function Get-PortHuntFindings {
    param($Facts)
    $ports = $Facts.Ports
    if (-not $ports) { return @() }
    $out = @()
    $standard = @()
    $seen = @{}
    foreach ($l in (Get-List $ports.Listeners)) {
        $key = "$($l.Proto)|$($l.Port)|$($l.Process)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $microsoft = ($l.SigStatus -eq 'Valid' -and [string]$l.SigSubject -match 'Microsoft')
        $loopback = ($l.Address -like '127.*' -or $l.Address -eq '::1')
        $isStandard = $microsoft -or $l.Process -eq 'System' -or $l.Process -eq 'lsass'
        if ($isStandard -or ($loopback -and $l.SigStatus -eq 'Valid')) { $standard += "$($l.Proto) $($l.Port)"; continue }
        if ($l.Port -eq $script:Plan.JenkinsPort -and $l.Process -like 'java*') {
            $out += New-Finding 6 'Ports' 'INFO' "TCP $($l.Port) Jenkins (java)" "Expected: the scored Jenkins port, owned by $($l.Path)."
            continue
        }
        $unsigned = ($l.SigStatus -ne 'Valid')
        $odd = [bool]($l.Path -and (Test-OddPath $l.Path))
        $sev = $(if ($unsigned -or $odd) { 'BAD' } else { 'WARN' })
        $who = $(if ($l.Process) { "$($l.Process) ($($l.Path))" } else { 'a program that could not be identified' })
        $sig = $(if ($l.SigStatus) { "signature: $($l.SigStatus) $($l.SigSubject)" } else { 'no signature information' })
        $out += New-Finding 6 'Ports' $sev "$($l.Proto) $($l.Port) listening ($($l.Process))" "Listening on $($l.Address):$($l.Port), owned by $who; $sig. Look at the program before deciding. The tool never kills a process by itself."
    }
    if ($standard.Count -gt 0) { $out += New-Finding 6 'Ports' 'INFO' "$($standard.Count) standard Windows listeners" "Microsoft-signed or system: $(($standard | Select-Object -Unique) -join ', ')." }

    foreach ($c in (Get-List $ports.Connections)) {
        if ($c.RemoteAddress -like '172.16.*' -or $c.RemoteAddress -like '10.*' -or $c.RemoteAddress -like '192.168.*') { continue }
        $microsoft = ($c.SigStatus -eq 'Valid' -and [string]$c.SigSubject -match 'Microsoft')
        if ($microsoft) { continue }
        $unsigned = ($c.SigStatus -ne 'Valid')
        $sev = $(if ($unsigned) { 'BAD' } else { 'WARN' })
        $out += New-Finding 6 'Connections' $sev "$($c.Process) talks to $($c.RemoteAddress):$($c.RemotePort)" "An established connection to an address outside the lab, from $($c.Path) (signature: $($c.SigStatus) $($c.SigSubject)). This is how a backdoor calls home. Blocking one C2 address is allowed; attacking it is not."
    }
    $out
}

# ---------------------------------------------------------------- phase 6, part 2: places a program can hide so that it starts again
# The facts come from Get-PersistFacts (Collect.ps1). Like the rest of this phase: REPORT FIRST. A row names the place, the exact value and
# why it matters. Things that look normal are not listed one by one; Get-PersistSummary says what was checked and found clean.
$script:ScriptFileTypes = '\.(bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|scr|exe|dll|com|pif|jar)$'
$script:KnownLsa = @{
    Authentication = @('msv1_0')
    Notification   = @('scecli', 'rassfm')
    Security       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp')
}

function Get-ShortText {
    # A long value (a script, a command line) cut to a length that fits in a row.
    param([string]$Text, [int]$Max = 160)
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + '...' }
    $t
}

function Get-OwnerName {
    # The account name that belongs to a SID (for the "user ..." part of a startup key). Falls back to the SID itself.
    param($Facts, [string]$Sid)
    $u = @(Get-List $Facts.Accounts.Users | Where-Object { [string]$_.Sid -eq $Sid }) | Select-Object -First 1
    if ($u) { return [string]$u.Name }
    $Sid
}

function Get-StartSeverity {
    # BAD when the command names a folder where programs do not live (Temp, Public, AppData ...); WARN when it runs a script interpreter
    # or a program outside Windows and Program Files; INFO when it looks normal.
    param([string]$Command)
    if ($Command -match "(?i)$($script:OddFolders)") { return 'BAD' }
    $exe = Get-ActionProgram $Command
    if ($exe -and (Test-OddPath $exe)) { return 'WARN' }
    if ($Command -match "(?i)$($script:ScriptyPrograms)") { return 'WARN' }
    'INFO'
}

function Get-PersistHuntFindings {
    param($Facts)
    $p = $Facts.Persist
    if (-not $p) { return @() }
    $out = @()
    $out += Get-RunValueFindings $p $Facts
    $out += Get-StartupFileFindings $p
    $out += Get-WinlogonFindings $p
    $out += Get-DebuggerFindings $p
    $out += Get-AppInitFindings $p
    $out += Get-LsaFindings $p
    $out += Get-AccessibilityFindings $p
    $out += Get-WmiFindings $p
    $out += Get-HostsFindings $p
    $out += Get-ShareFindings $p
    $out += Get-BitsFindings $p
    $out += Get-ProfileFileFindings $p
    $out += Get-PolicyScriptFindings $p
    $out += Get-ProxyFindings $p $Facts
    $out += Get-RdpDllFindings $p
    foreach ($m in (Get-List $p.Problems)) {
        $out += New-Finding 6 'Persistence' 'WARN' "Could not check: $(($m -split ':')[0])" "This part of the persistence audit failed, so it shows nothing: $m"
    }
    $out += Get-PersistSummary $p $out
    $out
}

function Get-RunValueFindings {
    param($P, $Facts)
    $out = @()
    $normal = @()
    foreach ($r in (Get-List $P.RunValues)) {
        $place = [string]$r.Where
        if ($r.Sid) { $place = "$($r.Where) of $(Get-OwnerName $Facts $r.Sid)" }
        $sev = Get-StartSeverity $r.Data
        if ($sev -eq 'INFO') { $normal += [string]$r.Name; continue }
        $why = "In the $place key: $($r.Name) = $($r.Data). Whatever is in a Run key starts by itself at logon or boot, so this is where an intruder's program comes back after a reboot."
        if (Test-NeverTouchApp $r.Name $r.Data) {
            $out += New-Finding 6 'Startup entries' 'INFO' "Startup entry '$($r.Name)' ($place) (protected)" "$why It matches the never-touch list (Jenkins, Java, Remote Desktop, the log collector, Defender), so no fix is offered."
        } else {
            $fix = New-FixRef 'New-RegistryValueAction' @{ Key = [string]$r.Key; Name = [string]$r.Name; Area = 'persist'; Label = "the startup entry '$($r.Name)'"; Shown = [string]$r.Data }
            $out += New-Finding 6 'Startup entries' $sev "Startup entry '$($r.Name)' ($place)" "$why Check the file. If it is not yours, delete the entry; the old value stays in the journal and Undo writes it back." $fix -Batch $false
        }
    }
    if ($normal.Count -gt 0) {
        $out += New-Finding 6 'Startup entries' 'INFO' "$($normal.Count) startup entries look normal" "Programs from Windows or Program Files that start at logon: $(($normal | Select-Object -Unique) -join ', ')."
    }
    $out
}

function Get-StartupFileFindings {
    param($P)
    $out = @()
    foreach ($f in (Get-List $P.StartupFiles)) {
        $sev = $(if ($f.Name -match "(?i)$($script:ScriptFileTypes)") { 'BAD' } else { 'WARN' })
        $out += New-Finding 6 'Startup folders' $sev "Startup file $($f.Name) ($($f.Where))" "$($f.Path), $($f.Bytes) bytes, changed $($f.Time). Everything in a Startup folder runs at logon, and Windows puts nothing there by itself. The fix moves it to the quarantine folder (a copy is kept; Undo moves it back)." (New-FixRef 'New-QuarantineFileAction' @{ Path = [string]$f.Path }) -Batch $false
    }
    $out
}

function Get-WinlogonFindings {
    param($P)
    $w = $P.Winlogon
    if (-not $w) { return @() }
    $out = @()
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($w.Shell -and $w.Shell -ne 'explorer.exe') {
        $fix = New-FixRef 'New-RegistryValueAction' @{ Key = $key; Name = 'Shell'; Reset = $true; NewValue = 'explorer.exe'; Shown = [string]$w.Shell; Label = 'the Winlogon Shell'; Risk = 'High'; TypeWord = 'WINLOGON' }
        $out += New-Finding 6 'Winlogon' 'BAD' 'Winlogon Shell is not explorer.exe' "Shell = $($w.Shell). Windows starts this program as the desktop of every user who logs on; the default is explorer.exe. The fix sets it back to explorer.exe (you type WINLOGON to confirm: a wrong value here breaks every logon)." $fix -Batch $false
    }
    if ($w.Userinit -and $w.Userinit -notmatch '(?i)^\s*c:\\windows\\system32\\userinit\.exe,?\s*$') {
        $fix = New-FixRef 'New-RegistryValueAction' @{ Key = $key; Name = 'Userinit'; Reset = $true; NewValue = 'C:\Windows\system32\userinit.exe,'; Shown = [string]$w.Userinit; Label = 'the Winlogon Userinit'; Risk = 'High'; TypeWord = 'WINLOGON' }
        $out += New-Finding 6 'Winlogon' 'BAD' 'Winlogon Userinit has extra programs' "Userinit = $($w.Userinit). The default is C:\Windows\system32\userinit.exe, and every program added after the comma runs at every logon. The fix sets the default back (you type WINLOGON to confirm)." $fix -Batch $false
    }
    if ($w.Taskman) {
        $fix = New-FixRef 'New-RegistryValueAction' @{ Key = $key; Name = 'Taskman'; Area = 'persist'; Shown = [string]$w.Taskman; Label = 'the Winlogon Taskman value' }
        $out += New-Finding 6 'Winlogon' 'BAD' 'Winlogon Taskman is set' "Taskman = $($w.Taskman). This value does not exist on a normal box; Windows starts the program when Ctrl+Alt+Del is pressed." $fix -Batch $false
    }
    if ($w.AppSetup) {
        $fix = New-FixRef 'New-RegistryValueAction' @{ Key = $key; Name = 'AppSetup'; Area = 'persist'; Shown = [string]$w.AppSetup; Label = 'the Winlogon AppSetup value' }
        $out += New-Finding 6 'Winlogon' 'WARN' 'Winlogon AppSetup is set' "AppSetup = $($w.AppSetup). This value does not exist on a normal box; Windows starts the program at logon." $fix -Batch $false
    }
    $out
}

function Get-DebuggerFindings {
    param($P)
    $out = @()
    foreach ($d in (Get-List $P.Debuggers)) {
        $bits = $(if ([string]$d.Key -match 'WOW6432Node') { ' (32-bit)' } else { '' })
        $what = switch ([string]$d.Kind) {
            'Debugger'       { "When $($d.Program) starts, Windows runs $($d.Value) instead. This is the sticky-keys backdoor: Shift pressed five times on the RDP login screen gives a SYSTEM shell." }
            'VerifierDlls'   { "A DLL named $($d.Value) is loaded into every copy of $($d.Program)." }
            default          { "When $($d.Program) ends, Windows runs $($d.Value)." }
        }
        $fix = New-FixRef 'New-RegistryValueAction' @{ Key = [string]$d.Key; Name = [string]$d.Kind; Area = 'persist'; Shown = [string]$d.Value; Label = "the $($d.Kind) hook on $($d.Program)" }
        $out += New-Finding 6 'Debuggers' 'BAD' "$($d.Kind) on $($d.Program)$bits" "Image File Execution Options, key $($d.Key). $what Nothing on this server needs it." $fix -Batch $false
    }
    $out
}

function Get-AppInitFindings {
    param($P)
    $out = @()
    foreach ($a in (Get-List $P.AppInit)) {
        $bits = $(if ([string]$a.Key -match 'WOW6432Node') { ' (32-bit)' } else { '' })
        if ($a.Dlls) {
            $fix = New-FixRef 'New-RegistryValueAction' @{ Key = [string]$a.Key; Name = 'AppInit_DLLs'; Reset = $true; NewValue = ''; Shown = [string]$a.Dlls; Label = "AppInit_DLLs$bits" }
            $out += New-Finding 6 'AppInit' 'BAD' "AppInit_DLLs is set$bits" "AppInit_DLLs = $($a.Dlls) (loading is switched $(if ($a.LoadAppInit -eq 1) { 'ON' } else { 'off' })). Windows loads these DLLs into every program that has a window. Normal boxes leave it empty. The fix empties the value (the value itself stays)." $fix -Batch $false
        }
        if ($a.LoadProgram) {
            $fix = New-FixRef 'New-RegistryValueAction' @{ Key = [string]$a.Key; Name = 'Load'; Area = 'persist'; Shown = [string]$a.LoadProgram; Label = "the Windows key Load value$bits" }
            $out += New-Finding 6 'AppInit' 'BAD' "Windows key Load value is set$bits" "Load = $($a.LoadProgram) in $($a.Key). An old way to start a program at every logon; normal boxes do not have it." $fix -Batch $false
        }
        if ($a.RunProgram) {
            $fix = New-FixRef 'New-RegistryValueAction' @{ Key = [string]$a.Key; Name = 'Run'; Area = 'persist'; Shown = [string]$a.RunProgram; Label = "the Windows key Run value$bits" }
            $out += New-Finding 6 'AppInit' 'BAD' "Windows key Run value is set$bits" "Run = $($a.RunProgram) in $($a.Key). An old way to start a program at every logon; normal boxes do not have it." $fix -Batch $false
        }
    }
    $out
}

function Get-LsaFindings {
    param($P)
    $l = $P.Lsa
    if (-not $l) { return @() }
    $out = @()
    foreach ($kind in 'Authentication', 'Notification', 'Security') {
        foreach ($entry in (Get-List $l.$kind)) {
            foreach ($piece in ([string]$entry -split '[,\s]+')) {
                $pkg = ($piece -replace '\.dll$', '').Trim('"').Trim()
                if (-not $pkg) { continue }
                if ($script:KnownLsa[$kind] -contains $pkg) { continue }
                $out += New-Finding 6 'LSA' 'WARN' "LSA $kind package $pkg" "The Local Security Authority loads $pkg as a $kind package. It is not one of the usual Windows names (the usual ones: $($script:KnownLsa[$kind] -join ', ')). A password-stealing DLL looks like this; check the file in System32 and its signature."
            }
        }
    }
    $out
}

function Get-AccessibilityFindings {
    param($P)
    $out = @()
    $missing = @()
    foreach ($a in (Get-List $P.Accessibility)) {
        if (-not $a.Exists) { $missing += [string]$a.Name; continue }
        $problem = ''
        if ($a.LooksLikeShell) { $problem = 'it is byte for byte the same file as cmd.exe or powershell.exe' }
        elseif ($a.SigStatus -ne 'Valid') { $problem = "its signature is '$($a.SigStatus)'" }
        elseif ([string]$a.SigSubject -notmatch 'Microsoft') { $problem = "it is signed by '$($a.SigSubject)', not by Microsoft" }
        if ($problem) {
            $out += New-Finding 6 'Accessibility' 'BAD' "$($a.Name) was replaced" "$($a.Path): $problem. This program can be started from the RDP login screen with no password, so a swapped copy is a SYSTEM shell for anybody who can reach port 3389. Compare it with a good copy (sfc /verifyfile=$($a.Path))."
        }
    }
    if ($missing.Count -gt 0) {
        $out += New-Finding 6 'Accessibility' 'INFO' 'Accessibility programs not found' "Not in System32: $($missing -join ', '). Some editions of Windows do not have them; on a full server a missing one can also mean it was removed on purpose."
    }
    $out
}

function Get-WmiFindings {
    param($P)
    $w = $P.Wmi
    if (-not $w) { return @() }
    $out = @()
    foreach ($c in (Get-List $w.Consumers)) {
        if ([string]$c.Class -eq 'NTEventLogEventConsumer' -and [string]$c.Name -eq 'SCM Event Log Consumer') { continue }      # Windows' own
        $when = @()
        foreach ($b in (Get-List $w.Bindings)) {
            if ([string]$b.Consumer -ne [string]$c.Name) { continue }
            $q = @(Get-List $w.Filters | Where-Object { [string]$_.Name -eq [string]$b.Filter }) | Select-Object -First 1
            $when += $(if ($q) { "$($b.Filter): $(Get-ShortText $q.Query 100)" } else { [string]$b.Filter })
        }
        $sev = $(if ($c.Class -match 'CommandLine|ActiveScript') { 'BAD' } else { 'WARN' })
        $whenText = $(if ($when.Count -gt 0) { $when -join '; ' } else { 'no filter is bound to it' })
        $out += New-Finding 6 'WMI' $sev "WMI $($c.Class) $($c.Name)" "A permanent WMI subscription: it runs '$(Get-ShortText $c.Command)' when this happens: $whenText. It survives reboots and shows in neither Task Manager nor Task Scheduler. The fix removes it (no Undo: its query and command are kept in the journal)." (New-FixRef 'New-RemoveWmiAction' @{ Name = [string]$c.Name; Class = [string]$c.Class }) -Batch $false
    }
    $out
}

function Get-HostsFindings {
    param($P)
    $h = $P.Hosts
    if (-not $h) { return @() }
    $out = @()
    foreach ($line in (Get-List $h.Entries)) {
        $text = (([string]$line -split '#')[0]).Trim()
        if (-not $text) { continue }
        $parts = @($text -split '\s+' | Where-Object { $_ })
        $address = $parts[0]
        $names = @($parts | Select-Object -Skip 1)
        $onlyLocalhost = (@($names | Where-Object { $_ -ne 'localhost' }).Count -eq 0)
        if (($address -eq '127.0.0.1' -or $address -eq '::1') -and $onlyLocalhost) { continue }
        $sev = $(if ($address -like '172.16.*') { 'BAD' } else { 'WARN' })
        $out += New-Finding 6 'hosts file' $sev "hosts entry: $text" "$($h.Path) sends $($names -join ', ') to $address, whatever DNS says. An entry that points a lab name (like the blackbox) at another address breaks backups and logging; one that points at an outside address redirects traffic." (New-FixRef 'New-HostsLineAction' @{ Entry = $text }) -Batch $false
    }
    $out
}

function Get-ShareFindings {
    param($P)
    $out = @()
    foreach ($s in (Get-List $P.Shares)) {
        if ($s.Special) { continue }
        $open = [bool](@(Get-List $s.Access | Where-Object { [string]$_ -match '^Everyone:(Full|Change)' }).Count)
        $sev = $(if ($open) { 'BAD' } else { 'WARN' })
        $out += New-Finding 6 'Shares' $sev "Share $($s.Name)" "$($s.Path) is shared as $($s.Name) ($($s.Description)). Who may open it: $((Get-List $s.Access) -join ', '). ADMIN`$, C`$ and IPC`$ are Windows' own; any other share is somebody's addition. The fix stops sharing it (the folder stays; Undo shares it again)." (New-FixRef 'New-RemoveShareAction' @{ Name = [string]$s.Name }) -Batch $false
    }
    $out
}

function Get-BitsFindings {
    param($P)
    $out = @()
    foreach ($j in (Get-List $P.Bits)) {
        $out += New-Finding 6 'BITS jobs' 'WARN' "BITS job $($j.Name) ($($j.Owner))" "State $($j.State), files: $((Get-List $j.Files) -join ', '). BITS keeps background downloads across reboots, an old way to fetch a backdoor again. A quiet server has no jobs."
    }
    $out
}

function Get-ProfileFileFindings {
    param($P)
    $out = @()
    foreach ($f in (Get-List $P.ProfileFiles)) {
        $out += New-Finding 6 'PowerShell profiles' 'WARN' "PowerShell profile $($f.Name) ($($f.Where))" "$($f.Path) runs every time somebody opens PowerShell (including you, as an administrator). A fresh server has none; read it before you open PowerShell as that user. The fix moves it to the quarantine folder." (New-FixRef 'New-QuarantineFileAction' @{ Path = [string]$f.Path }) -Batch $false
    }
    $out
}

function Get-PolicyScriptFindings {
    param($P)
    $out = @()
    foreach ($f in (Get-List $P.PolicyScripts)) {
        $out += New-Finding 6 'Policy scripts' 'BAD' "Policy script $($f.Name) ($($f.Where))" "$($f.Path). Local group policy runs scripts from this folder ($($f.Where)). A fresh server has none. The fix moves it to the quarantine folder." (New-FixRef 'New-QuarantineFileAction' @{ Path = [string]$f.Path }) -Batch $false
    }
    $out
}

function Get-ProxyFindings {
    param($P, $Facts)
    $out = @()
    foreach ($x in (Get-List $P.Proxy)) {
        $place = [string]$x.Where
        if ($x.Sid) { $place = "$($x.Where) $(Get-OwnerName $Facts $x.Sid)" }
        $what = @()
        if ($x.Enabled) { $what += "proxy server $($x.Server)" }
        if ($x.PacUrl) { $what += "proxy script $($x.PacUrl)" }
        $out += New-Finding 6 'Proxy' 'WARN' "Proxy setting ($place)" "Web traffic of this account goes through: $($what -join ' and '). A proxy that nobody set up lets someone else read or change that traffic."
    }
    $out
}

function Get-RdpDllFindings {
    param($P)
    $r = $P.RdpDll
    if (-not $r) { return @() }
    if (-not $r.ServiceDll) {
        return @(New-Finding 6 'RDP service' 'WARN' 'RDP service DLL could not be read' 'TermService has no ServiceDll value that could be read. Check HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters by hand.')
    }
    $path = Expand-CommonPath $r.Path
    if ($path -notmatch '(?i)^c:\\windows\\system32\\termsrv\.dll$') {
        return @(New-Finding 6 'RDP service' 'BAD' 'RDP service uses another DLL' "TermService loads $($r.ServiceDll) instead of C:\Windows\System32\termsrv.dll. RDP wrapper tools and backdoors do this. The tool never touches the Remote Desktop service: look at the file and fix the registry value by hand (RUNBOOK.md).")
    }
    if ($r.SigStatus -ne 'Valid' -or [string]$r.SigSubject -notmatch 'Microsoft') {
        return @(New-Finding 6 'RDP service' 'BAD' 'termsrv.dll is not signed by Microsoft' "$($r.Path): signature '$($r.SigStatus)' $($r.SigSubject). The tool never touches the Remote Desktop service: compare the file with a good copy by hand (RUNBOOK.md).")
    }
    @()
}

function Get-PersistSummary {
    # One row that says what was looked at, so "no row" can be told apart from "not checked".
    param($P, $Rows)
    $areas = [ordered]@{
        'Startup entries' = 'Run keys'; 'Startup folders' = 'Startup folders'; 'Winlogon' = 'Winlogon'; 'Debuggers' = 'debugger hooks'; 'AppInit' = 'AppInit'
        'LSA' = 'LSA packages'; 'Accessibility' = 'sticky-keys programs'; 'WMI' = 'WMI subscriptions'; 'hosts file' = 'hosts file'; 'Shares' = 'shares'
        'BITS jobs' = 'BITS jobs'; 'PowerShell profiles' = 'PowerShell profiles'; 'Policy scripts' = 'policy scripts'; 'Proxy' = 'proxy settings'; 'RDP service' = 'RDP service DLL'
    }
    $failed = @(Get-List $P.Problems | ForEach-Object { ($_ -split ':')[0] })
    $clean = @()
    $found = @()
    foreach ($area in $areas.Keys) {
        $hits = @($Rows | Where-Object { $_.Area -eq $area -and ($_.Severity -eq 'BAD' -or $_.Severity -eq 'WARN') })
        if ($hits.Count -gt 0) { $found += "$($areas[$area]) ($($hits.Count))" } else { $clean += $areas[$area] }
    }
    $text = "Looked at: $($areas.Values -join ', '). "
    if ($found.Count -gt 0) { $text += "Rows above for: $($found -join ', '). " }
    if ($clean.Count -gt 0) { $text += "Nothing found in: $($clean -join ', '). " }
    $text += 'Not covered: Run keys of users who are not logged on (their NTUSER.DAT is not loaded), COM hijacks, DLL planting, and unsigned files in System32 (RUNBOOK.md section 8 has the commands).'
    if ($failed.Count -gt 0) { $text += " Could not check: $($failed -join ', ')." }
    New-Finding 6 'Persistence' 'INFO' 'Persistence audit' $text
}
