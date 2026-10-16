# Core.ps1 - the foundation of the hardening tool.
#   1. the plan's decisions as constants (not options)
#   2. settings and an undo journal (plain text on disk); warnings and errors live in memory only, there is no log file
#   3. Invoke-Change: the ONLY function that is allowed to change the box
# Every button ends up in Invoke-Change, so the safety rules live in exactly one place.
# Windows PowerShell 5.1, plain ASCII.

# ---------------------------------------------------------------- the plan, as constants
$script:Plan = @{
    ScoringUser   = 'jmoney'        # scored for RDP and Jenkins: never disabled, never deleted, password rotated ONCE
    OriginalAdmin = 'plinktern'     # packet default admin: disabled (not deleted) after the new admin is confirmed
    RdpPort       = 3389
    JenkinsPort   = 8080
    BlackboxPort  = 22
    WindowsBuiltIns = @('DefaultAccount', 'WDAGUtilityAccount')      # disabled by Windows already; the tool never touches them
    SidAdministrators = 'S-1-5-32-544'
    SidRdpUsers       = 'S-1-5-32-555'
    SidUsers          = 'S-1-5-32-545'
    SidGuests         = 'S-1-5-32-546'
}

# Settings that are remembered between runs (settings.json in the data folder).
$script:SettingDefaults = @{
    NewAdmin          = ''          # name of the admin account this tool created (or that you told it about)
    NewAdminConfirmed = $false      # you ticked "I logged in with it in a second RDP session"
    ExtraKeep         = @()         # more account names the tool must leave alone
    TeamNet           = ''          # team network like 172.16.5.0/24 (blank = work it out from this box's IP)
    BlackboxIp        = ''          # filled in at the competition
    BackupUser        = 'uploader'  # the restricted account on blackbox that may only upload (RUNBOOK.md sets it up). Not 'backup': Debian, Ubuntu and Mint already have a system account with that name
    DeadManMinutes    = 5
    JmoneyRotations   = 0           # how many times the scoring password was changed by this tool
}

$script:UndoHandlers = @{}          # kind -> scriptblock; filled by Register-UndoHandler in the Act-*.ps1 files

# The tool creates two scheduled tasks, both run as SYSTEM from a script in the data folder:
#   the dead-man switch  (DeadMan.ps1, task name in $script:DeadManTaskName)   and   the watchdog  (Act-Watchdog.ps1, Watchdog.ps1)
$script:WatchdogTaskName = 'NetCacheWatch'

function Get-WatchdogPaths {
    # One place that knows the watchdog's file names. Watchdog.ps1 uses the same names (a test compares them).
    $dir = Join-Path $script:Hp.DataDir 'watchdog'
    @{
        Dir        = $dir
        Script     = Join-Path $dir 'Watchdog.ps1'          # private copy; the task runs THIS file, so editing the original changes nothing
        Panic      = Join-Path $dir 'Panic.ps1'             # private copy; Watchdog.ps1 loads its repair functions
        Config     = Join-Path $dir 'config.json'           # what the tool found out (the Jenkins home folder)
        Status     = Join-Path $dir 'status.json'           # written by every pass; the tool reads it
        Alerts     = Join-Path $dir 'alerts.log'
        PauseFile  = Join-Path $dir 'pause.txt'
        RebaseFlag = Join-Path $dir 'rebaseline.flag'
        AcceptFlag = Join-Path $dir 'acceptjobs.flag'
    }
}

# ---------------------------------------------------------------- start-up
function Initialize-Hp {
    # Creates the state object, the data folders and loads the settings.
    param([string]$DataDir = 'C:\ProgramData\NetCacheSvc', [switch]$NoAcl)
    $script:Hp = @{
        DataDir      = $DataDir
        JournalDir   = Join-Path $DataDir 'journal'
        AllowChanges = $false                       # AUDIT (read-only) until the GUI tick box says otherwise
        LogLines     = New-Object System.Collections.ArrayList     # warnings and errors only, in memory (nothing is written to a log file)
        OnLog        = $null                        # the GUI puts a scriptblock here to show new warning/error lines
        Notify       = ${function:Write-ConsoleNotice}   # (title, text) -> shows a message; the GUI swaps in a message box
        Ask          = ${function:Read-ConsoleAnswer}    # (title, text, typeWord) -> $true / $false
        AskSecret    = ${function:Read-ConsoleSecret}    # (prompt) -> text, or $null when cancelled
        AskText      = ${function:Read-ConsoleText}      # (prompt, default) -> text, or $null when cancelled
        Secrets      = @{}                               # secrets live ONLY here, in memory: never in a file, never in the journal
        Settings     = @{}
        Facts        = $null                             # the last audit: what Collect.ps1 found (Runner.ps1 keeps it up to date)
        Findings     = @()                               # the last audit: the rows the judges made from it
        OnBusy       = $null                             # the GUI puts a scriptblock here: (text) -> shows "Reading the firewall..." and keeps the window alive
    }
    foreach ($d in @($DataDir, $script:Hp.JournalDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    if (-not $NoAcl) { Protect-DataDir }            # the tests pass -NoAcl so they never change permissions
    Import-HpSettings
}

function Protect-DataDir {
    # Only SYSTEM and Administrators may open the data folder (journal, backups, keys). Windows only.
    if ($env:OS -ne 'Windows_NT') { return }
    $d = $script:Hp.DataDir
    & icacls.exe $d /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
}

# ---------------------------------------------------------------- settings
function Import-HpSettings {
    $s = @{}
    foreach ($k in $script:SettingDefaults.Keys) { $s[$k] = $script:SettingDefaults[$k] }
    $file = Join-Path $script:Hp.DataDir 'settings.json'
    if (Test-Path $file) {
        try {
            $saved = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json
            foreach ($p in $saved.PSObject.Properties) { $s[$p.Name] = $p.Value }
        } catch { Write-HpLog "settings.json could not be read, using defaults: $($_.Exception.Message)" 'WARN' }
    }
    $script:Hp.Settings = $s
}

function Get-HpSetting {
    param([string]$Name)
    $script:Hp.Settings[$Name]
}

function Set-HpSetting {
    param([string]$Name, $Value)
    $script:Hp.Settings[$Name] = $Value
    $file = Join-Path $script:Hp.DataDir 'settings.json'
    [System.IO.File]::WriteAllText($file, (ConvertTo-Json -InputObject $script:Hp.Settings -Depth 4))
}

# ---------------------------------------------------------------- messages about problems (there is NO log of what you did)
function Write-HpLog {
    # Only warnings and errors are kept: in a short in-memory list that the GUI shows, and nowhere else (no file).
    # Level INFO (what you just did: "change ok", "undo ok", "cancelled") is thrown away on purpose: the journal is the record of changes.
    param([string]$Text, [string]$Level = 'INFO')
    if ($Level -eq 'INFO') { return }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Text
    [void]$script:Hp.LogLines.Add($line)
    if ($script:Hp.LogLines.Count -gt 500) { $script:Hp.LogLines.RemoveAt(0) }
    if ($script:Hp.OnLog) { & $script:Hp.OnLog $line }
}

# ---------------------------------------------------------------- one tiny helper used everywhere
function Get-List {
    # A real list: nothing (or $null) gives an EMPTY list. (@($null) is a list holding one $null, which would be counted.)
    param($Items)
    @($Items | Where-Object { $null -ne $_ })
}

# ---------------------------------------------------------------- actions
function New-Action {
    # An action is a plain description of ONE change: what it does, how to read the old state, how to apply it.
    # Nothing happens when you create one. Only Invoke-Change runs it.
    param(
        [Parameter(Mandatory)][string]$Id,           # unique key, for example 'user.disable:kkiderchah'
        [Parameter(Mandatory)][string]$Title,
        [string]$Risk = 'Low',                       # Low | Medium | High  (High = you must type a word)
        [string[]]$Will = @(),                       # plain-English lines: what will change
        [hashtable]$Data = @{},                      # the values Capture and Apply need (account name, port, ...)
        [scriptblock]$Capture = $null,               # READ-ONLY: returns the old state; it is saved in the journal first
        [Parameter(Mandatory)][scriptblock]$Apply,   # the change itself:  { param($d, $before) ... }
        [string]$UndoKind = '',                      # name of the undo handler ('' = nothing can be undone)
        [string]$NoUndo = '',                        # the part that cannot be undone, shown BEFORE you confirm
        [string]$TypeWord = '',                      # High risk: the word you must type
        [switch]$NeedsDeadMan                        # firewall-type change: refuses unless the dead-man switch is armed
    )
    if ($Risk -eq 'High' -and -not $TypeWord) { $TypeWord = 'APPLY' }
    [pscustomobject]@{
        Id = $Id; Title = $Title; Risk = $Risk; Will = $Will; Data = $Data; Capture = $Capture; Apply = $Apply
        UndoKind = $UndoKind; NoUndo = $NoUndo; TypeWord = $TypeWord; NeedsDeadMan = [bool]$NeedsDeadMan
    }
}

function Register-UndoHandler {
    # An undo handler is the code that puts the OLD state back.  { param($data, $before) ... }
    # It is looked up by name, so a journal file from an earlier run can still be undone.
    param([string]$Kind, [scriptblock]$Code)
    $script:UndoHandlers[$Kind] = $Code
}

function Format-ActionPreview {
    # The text shown in the confirm box. Built from the action itself, not from the button.
    param($Action)
    $lines = @($Action.Title, ('Risk: ' + $Action.Risk), '', 'This will:')
    foreach ($w in $Action.Will) { $lines += ('  - ' + $w) }
    $lines += ''
    if ($Action.UndoKind) { $lines += 'Undo: available (button "Undo last", or from the journal).' }
    else { $lines += 'Undo: NOT available for this change.' }
    if ($Action.NoUndo) { $lines += ('NO UNDO for: ' + $Action.NoUndo) }
    if ($Action.NeedsDeadMan) { $lines += 'The dead-man switch must be armed (it restores the firewall if you lose access).' }
    $lines -join [Environment]::NewLine
}

function New-ChangeResult {
    param([string]$Status, [string]$Message, [int]$JournalId = 0, $Output = $null)
    [pscustomobject]@{ Ok = ($Status -eq 'Applied' -or $Status -eq 'Undone'); Status = $Status; Message = $Message
                       JournalId = $JournalId; Output = $Output }
}

# ---------------------------------------------------------------- journal (one JSON file per change)
function Get-JournalRecords {
    # All journal records, oldest first.
    $out = @()
    $files = @(Get-ChildItem -Path $script:Hp.JournalDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name)
    foreach ($f in $files) {
        try { $out += ([System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json) }
        catch { Write-HpLog "journal file $($f.Name) is unreadable: $($_.Exception.Message)" 'WARN' }
    }
    $out
}

function Save-JournalRecord {
    param($Record)
    $path = Join-Path $script:Hp.JournalDir ('{0:D4}.json' -f [int]$Record.Id)
    [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Record -Depth 8))
}

function Get-NextJournalId {
    $ids = @(Get-JournalRecords | ForEach-Object { [int]$_.Id })
    if ($ids.Count -eq 0) { return 1 }
    ($ids | Measure-Object -Maximum).Maximum + 1
}

# ---------------------------------------------------------------- Invoke-Change: the one door
function Invoke-Change {
    # gate -> (dead-man check) -> preview + confirm -> read old state -> journal -> apply
    # -Confirmed means the caller already asked you about exactly this action (the batch dialog). High risk still asks.
    param([Parameter(Mandatory)]$Action, [switch]$Confirmed)
    $ErrorActionPreference = 'Stop'          # a cmdlet that fails halfway must fail the whole change (reported as FAILED), never "succeed" quietly
    $title = $Action.Title

    if (-not $script:Hp.AllowChanges) {
        Write-HpLog "BLOCKED (audit mode, 'Allow changes' is off): $title" 'WARN'
        return New-ChangeResult 'Blocked' 'Audit mode: tick "Allow changes" first.'
    }
    if ($Action.NeedsDeadMan) {
        $why = Get-DeadManBlocker
        if ($why) {
            Write-HpLog "BLOCKED (dead-man switch): $title - $why" 'WARN'
            return New-ChangeResult 'Blocked' $why
        }
    }

    $needAsk = (-not $Confirmed) -or ($Action.Risk -eq 'High')
    if ($needAsk) {
        $yes = & $script:Hp.Ask $title (Format-ActionPreview $Action) $Action.TypeWord
        if (-not $yes) {
            Write-HpLog "CANCELLED by you: $title"
            return New-ChangeResult 'Cancelled' 'Not applied (you did not confirm).'
        }
        if ($Action.NeedsDeadMan) {
            # reading the preview can take minutes, so the switch is checked AGAIN right before the change
            $why = Get-DeadManBlocker
            if ($why) {
                Write-HpLog "BLOCKED (dead-man switch, checked again after your answer): $title - $why" 'WARN'
                return New-ChangeResult 'Blocked' $why
            }
        }
    }

    # old state first, then the journal, then the change
    $before = @{}
    try {
        if ($Action.Capture) { $before = & $Action.Capture $Action.Data }
    } catch {
        Write-HpLog "NOT APPLIED (could not read the old state): $title - $($_.Exception.Message)" 'ERROR'
        return New-ChangeResult 'Failed' "Could not read the old state, so nothing was changed: $($_.Exception.Message)"
    }
    $rec = [ordered]@{
        Id = (Get-NextJournalId); Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); ActionId = $Action.Id; Title = $title
        Risk = $Action.Risk; Will = @($Action.Will); UndoKind = $Action.UndoKind; NoUndo = $Action.NoUndo
        NeedsDeadMan = $Action.NeedsDeadMan; Data = $Action.Data; Before = $before; Status = 'started'; Error = ''
    }
    Save-JournalRecord $rec
    Write-HpLog "CHANGE #$($rec.Id) start: $title"

    $output = $null
    try {
        $output = & $Action.Apply $Action.Data $before
        $rec.Status = 'applied'
        Write-HpLog "CHANGE #$($rec.Id) ok: $title"
    } catch {
        $rec.Status = 'failed'
        $rec.Error = $_.Exception.Message
        Write-HpLog "CHANGE #$($rec.Id) FAILED: $title - $($_.Exception.Message)" 'ERROR'
    }
    Save-JournalRecord $rec

    if ($rec.Status -eq 'applied') { return New-ChangeResult 'Applied' 'Done.' $rec.Id $output }
    New-ChangeResult 'Failed' $rec.Error $rec.Id $output
}

function Undo-Change {
    # Puts one journal record back. Same gate and confirm as a normal change.
    param([int]$Id, [switch]$Confirmed)
    $ErrorActionPreference = 'Stop'
    if (-not $script:Hp.AllowChanges) { return New-ChangeResult 'Blocked' 'Audit mode: tick "Allow changes" first.' }
    $rec = Get-JournalRecords | Where-Object { [int]$_.Id -eq $Id } | Select-Object -First 1
    if (-not $rec) { return New-ChangeResult 'Failed' "There is no journal record #$Id." }
    if ($rec.Status -ne 'applied') { return New-ChangeResult 'Failed' "Change #$Id is '$($rec.Status)', only an applied change can be undone." }
    if (-not $rec.UndoKind) { return New-ChangeResult 'Failed' "Change #$Id has no undo ($($rec.Title))." }
    $handler = $script:UndoHandlers[[string]$rec.UndoKind]
    if (-not $handler) { return New-ChangeResult 'Failed' "No undo handler named '$($rec.UndoKind)' is loaded." }
    if ($rec.NeedsDeadMan) {
        $why = Get-DeadManBlocker
        if ($why) { return New-ChangeResult 'Blocked' $why }
    }
    if (-not $Confirmed) {
        $text = "Undo change #$Id : $($rec.Title)`n`nThis puts the old state back (journal $('{0:D4}' -f [int]$Id).json)."
        if (-not (& $script:Hp.Ask "Undo #$Id" $text '')) { return New-ChangeResult 'Cancelled' 'Not undone (you did not confirm).' }
        if ($rec.NeedsDeadMan) {
            $why = Get-DeadManBlocker            # checked again after your answer, like in Invoke-Change
            if ($why) { return New-ChangeResult 'Blocked' $why }
        }
    }
    try {
        & $handler $rec.Data $rec.Before
        $rec.Status = 'undone'
        Write-HpLog "UNDO #$Id ok: $($rec.Title)"
    } catch {
        $rec.Status = 'undo-failed'
        $rec.Error = $_.Exception.Message
        Write-HpLog "UNDO #$Id FAILED: $($rec.Title) - $($_.Exception.Message)" 'ERROR'
    }
    Save-JournalRecord $rec
    if ($rec.Status -eq 'undone') { return New-ChangeResult 'Undone' 'Undone.' $Id $null }
    New-ChangeResult 'Failed' $rec.Error $Id $null
}

function Undo-LastChange {
    $last = Get-JournalRecords | Where-Object { $_.Status -eq 'applied' -and $_.UndoKind } | Select-Object -Last 1
    if (-not $last) { return New-ChangeResult 'Failed' 'Nothing to undo: no applied change with an undo is in the journal.' }
    Undo-Change -Id ([int]$last.Id)
}

# ---------------------------------------------------------------- a TCP connection test (blackbox, Internet)
function Test-TcpOpen {
    # Can we open a TCP connection to this host and port within the time limit?
    param([string]$HostName = '127.0.0.1', [int]$Port, [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $wait = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $wait.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $client.EndConnect($wait)
        return $true
    } catch { return $false }
    finally { $client.Close() }
}


# ---------------------------------------------------------------- running other programs
function Invoke-Native {
    # Runs a program and returns what it printed. Used instead of  & program args  because
    #   - an EMPTY argument ("") really arrives (Windows PowerShell 5.1 silently drops it when you call a program with &)
    #   - the program's error text cannot turn into a PowerShell error
    #   - it has a time limit, and it can never wait for you to type something (its input is closed)
    param([Parameter(Mandatory)][string]$Path, [string]$Arguments = '', [int]$TimeoutSec = 60, [string]$WorkingDirectory = '')
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = $Arguments
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $p.StandardInput.Close()
    $out = $p.StandardOutput.ReadToEndAsync()
    $err = $p.StandardError.ReadToEndAsync()
    $finished = $p.WaitForExit($TimeoutSec * 1000)
    if ($finished) { $p.WaitForExit() } else { try { $p.Kill() } catch { Write-HpLog "could not stop $Path : $($_.Exception.Message)" 'WARN' } }
    $code = $(if ($finished) { $p.ExitCode } else { -1 })
    $result = [pscustomobject]@{ ExitCode = $code; StdOut = $out.Result; StdErr = $err.Result; TimedOut = (-not $finished) }
    $p.Dispose()
    $result
}

function Invoke-NativeText {
    # Like Invoke-Native, but returns just the text, and throws when the program failed (so a backup item is marked FAILED).
    param([Parameter(Mandatory)][string]$Path, [string]$Arguments = '', [int]$TimeoutSec = 60)
    $r = Invoke-Native -Path $Path -Arguments $Arguments -TimeoutSec $TimeoutSec
    if ($r.TimedOut) { throw "$Path did not finish within $TimeoutSec seconds" }
    if ($r.ExitCode -ne 0) { throw "$Path failed with exit code $($r.ExitCode): $(($r.StdErr + ' ' + $r.StdOut).Trim())" }
    $r.StdOut
}

function Get-Sha256Hex {
    # SHA-256 of a file as lower-case hex (the form sha256sum prints).
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try { $bytes = $sha.ComputeHash($stream) } finally { $stream.Dispose(); $sha.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

# ---------------------------------------------------------------- questions (console versions; the GUI swaps in dialogs)
function Read-ConsoleAnswer {
    param([string]$Title, [string]$Text, [string]$TypeWord = '')
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Yellow
    Write-Host $Text
    if ($TypeWord) {
        $a = Read-Host "Type $TypeWord (exactly) to go ahead, anything else cancels"
        return ($a -ceq $TypeWord)
    }
    $a = Read-Host 'Go ahead? (y/N)'
    return ($a -match '^(y|yes)$')
}

function Write-ConsoleNotice {
    param([string]$Title, [string]$Text)
    Write-Host ''
    Write-Host "--- $Title ---" -ForegroundColor Yellow
    Write-Host $Text
}

function Show-HpNotice {
    # A message for you (something was refused or needs your attention). Also written to the log.
    param([string]$Text, [string]$Title = 'Note')
    Write-HpLog "$Title : $Text" 'WARN'
    & $script:Hp.Notify $Title $Text
}

function Convert-SecureToText {
    param([securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Read-ConsoleSecret {
    param([string]$Prompt)
    $s = Read-Host -AsSecureString $Prompt
    if (-not $s -or $s.Length -eq 0) { return $null }
    Convert-SecureToText $s
}

function Read-HpSecret {
    # What the rest of the tool calls when it needs a typed or pasted secret. Never logged, never saved.
    param([string]$Prompt)
    & $script:Hp.AskSecret $Prompt
}

function Read-ConsoleText {
    param([string]$Prompt, [string]$Default = '')
    $a = Read-Host $(if ($Default) { "$Prompt [$Default]" } else { $Prompt })
    if (-not $a) { return $Default }
    $a
}

function Read-HpText {
    # An ordinary (visible) question, for example the name of the new admin account.
    param([string]$Prompt, [string]$Default = '')
    & $script:Hp.AskText $Prompt $Default
}

# Secrets (passwords) are kept in memory only, under a short name, so that actions never carry them in their data.
function Set-HpSecret { param([string]$Name, [string]$Value) $script:Hp.Secrets[$Name] = $Value }
function Get-HpSecret { param([string]$Name) $script:Hp.Secrets[$Name] }
function Clear-HpSecret { param([string]$Name) $script:Hp.Secrets.Remove($Name) }

function Get-HpDir {
    # Sub-folders of the data folder (created on demand): 'backup', 'work', ...
    param([string]$Name)
    $d = Join-Path $script:Hp.DataDir $Name
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $d
}

# ---------------------------------------------------------------- passwords (they come from your laptop, see RUNBOOK.md)
function Get-DerivedPassword {
    # A throwaway password for one disabled account: HMAC-SHA256 keyed with your master secret, over the lowercase
    # account name, as base64. The laptop can recompute any of them with the one-liner in RUNBOOK.md.
    # The fixed ending 'aA1!' guarantees a lowercase, an uppercase, a digit and a symbol.
    param([string]$Master, [string]$Account)
    $key  = [System.Text.Encoding]::UTF8.GetBytes($Master)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $key)
    $mac  = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Account.ToLowerInvariant()))
    ([Convert]::ToBase64String($mac)).Substring(0, 24) + 'aA1!'
}

function Test-ScoringPasswordShape {
    # The scoring engine pastes this password into RDP and Jenkins logins. Odd characters can break that silently.
    # Returns a list of warnings (empty list = fine).
    param([string]$Password)
    $w = @()
    if ($Password.Length -lt 24) { $w += "only $($Password.Length) characters; 24 or more is recommended" }
    if ($Password -notmatch '^[A-Za-z0-9_.-]+$') { $w += 'contains characters other than letters, digits and - _ . (quotes, spaces, $ or backslash can break the scoring login)' }
    if ($Password.Contains('"')) { $w += 'contains a double quote, which FreeRDP-based checkers cannot take' }
    $w
}

function Test-PassphraseShape {
    # For the new admin: you must be able to TYPE it on the Console, so it should be plain keyboard characters.
    param([string]$Password)
    $w = @()
    if ($Password.Length -lt 16) { $w += "only $($Password.Length) characters; 16 or more is recommended" }
    if ($Password -cmatch '[^\x20-\x7E]') { $w += 'contains characters that are not plain keyboard characters (the Console may not type them)' }
    $w
}
