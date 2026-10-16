# Test-CodeRules.ps1 - reads every script in this folder tree (it runs none of them) and checks the house rules:
#   1. each file parses, is plain ASCII and has LF line endings (Windows PowerShell 5.1 can garble anything else)
#   2. inside one function (or the script body) a variable is always spelled the same way
#      (PowerShell ignores case: $ports and $Ports are the SAME variable - that bug happened once)
#   3. the check scripts (Score-Check / Verify-Hardening and the files they load) only READ the box
#   4. only Lab\, Tests\ and Verify-Hardening.ps1 may mention the lab answer key
#   5. only actions change the box: in lib\Act-*.ps1 and lib\DeadMan.ps1 a command that changes something may appear only inside the
#      scriptblocks given to New-Action / Register-UndoHandler, or in a helper on a short, named list (each is called only from such a block)
#   6. the collectors (lib\Collect.ps1) only read
#   7. the judges (lib\Judge*.ps1) are pure: they work on the facts they are given and call nothing that touches the box
#   8. only Core.ps1 runs an action's Capture / Apply (Invoke-Change is the one door)
#   9. a launcher or test that loads lib\ must not reuse a library's script-level variable name (PowerShell ignores case: a test's
#      $plan would silently replace the tool's $script:Plan - that really happened while the runner test was written)
#  10. the glue files (Runner, Console, Gui) contain no command that changes the box: they only call Invoke-Change and friends
#  11. a New-* function only BUILDS an action: it never asks you anything (the "Fix phase" dialog builds many of them to show their risk)
#  12. Watchdog.ps1 and Panic.ps1 run as SYSTEM with nobody watching: the watchdog may change things only in the functions listed below,
#      neither file ever sets a password, stops a service or a process, deletes or disables an account, or reaches the Internet, and the
#      watchdog calls only the three Panic repairs that are safe to repeat every minute (never the firewall import, the adapters, the rights)
#  13. every test file turns an error that nothing caught into a failure (a check that crashes must not simply disappear)
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
$root  = Split-Path -Parent $PSScriptRoot
$files = @(Get-ChildItem -Path $root -Recurse -Filter *.ps1)

function Get-Relative { param($File) $File.FullName.Substring($root.Length + 1) }

Write-Host "Code rules ($($files.Count) files)" -ForegroundColor Cyan

# ---- 1. parse / ASCII / LF
foreach ($f in $files) {
    $rel = Get-Relative $f
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errors)
    Assert-True (@($errors).Count -eq 0) "$rel parses"
    $text = [IO.File]::ReadAllText($f.FullName)
    Assert-True (-not ($text -cmatch '[^\x00-\x7F]')) "$rel is plain ASCII"
    Assert-True (-not $text.Contains("`r")) "$rel uses LF line endings"
}

# ---- 2. one spelling per variable per function
$skipNames = @('_', 'true', 'false', 'null')
foreach ($f in $files) {
    $rel = Get-Relative $f
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $uses = $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
    $seen = @{}                                         # "scope|lowercase name" -> list of spellings
    foreach ($u in $uses) {
        $name = $u.VariablePath.UserPath -replace '^(script|global|local|private|using):', ''
        if ($name.Contains(':') -or $skipNames -contains $name) { continue }   # env:Path and friends
        $scope = '<script>'
        $p = $u.Parent
        while ($p) {
            if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $scope = $p.Name; break }
            $p = $p.Parent
        }
        $key = $scope + '|' + $name.ToLower()
        if (-not $seen.ContainsKey($key)) { $seen[$key] = New-Object System.Collections.ArrayList }
        if ($seen[$key] -cnotcontains $name) { [void]$seen[$key].Add($name) }
    }
    $clash = @($seen.Keys | Where-Object { $seen[$_].Count -gt 1 } | ForEach-Object { "$_ => " + ($seen[$_] -join ' / ') })
    Assert-True ($clash.Count -eq 0) ("${rel}: one spelling per variable" + $(if ($clash.Count) { '  ' + ($clash -join '; ') } else { '' }))
}

# ---- 3. the check scripts only read
$checkFiles = @('Score-Check.ps1', 'ScoreLib.ps1', 'Verify-Hardening.ps1', 'VerifyFacts.ps1',
                'VerifyJudgeAccounts.ps1', 'VerifyJudgeFirewall.ps1', 'VerifyJudgeSystem.ps1')
$okPrefix = '^(Get|Test|Select|Where|ForEach|Sort|Measure|Format|ConvertTo|ConvertFrom|Compare|Join|Split|Resolve|Group)(-|$)'
$okExact  = @('Write-Host', 'Out-Null', 'Out-String', 'New-Object', 'New-Result', 'Add-Results', 'Add-Type', 'Show-Result',
              'Start-Section', 'Start-Sleep', 'Read-Host', 'Read-Secret', 'Invoke-ScoreChecks', 'Invoke-RestMethod',
              'Find-FreeRdp', 'Send-Http', 'Remove-Item', 'net.exe', 'quser.exe', 'secedit.exe')
$badMembers = '^(Delete|Kill|WriteAllText|WriteAllBytes|AppendAllText|SetValue|CreateSubKey|CreateText|CreateDirectory|DeleteSubKey|DeleteValue|MoveTo|CopyTo|Stop|Start)$'
# these two are lab-only: allowed in Verify-Hardening.ps1, and only inside "if ($Lab) { ... }"
# (Unprotect-LabText opens the answer key; Watch-LabBeacon empties the lab beacon log before it waits)
$labOnly = @('Unprotect-LabText', 'Watch-LabBeacon')
foreach ($name in $checkFiles) {
    $path = Join-Path $root $name
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    $cmds = $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)
    $odd = @()
    foreach ($c in $cmds) {
        $n = $c.GetCommandName()
        if (-not $n) {
            # a dot-source of our own file, or a call through a variable ("& $FreeRdp ..."); anything else is odd
            $first = $c.Extent.Text.TrimStart()
            if ($first -match '^\.\s+"\$PSScriptRoot\\' -or $first -match '^& \$(FreeRdp|mysql)\b') { continue }
            $odd += $first.Split("`n")[0]; continue
        }
        if ($labOnly -contains $n) {
            $inLab = $false
            $p = $c.Parent
            while ($p) {
                if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -eq '$Lab') { $inLab = $true; break }
                $p = $p.Parent
            }
            if ($name -ne 'Verify-Hardening.ps1' -or -not $inLab) { $odd += "$n outside if (`$Lab)" }
            continue
        }
        if ($n -match $okPrefix -or $okExact -contains $n) {
            if ($n -eq 'secedit.exe' -and $c.Extent.Text -notmatch '/export') { $odd += $c.Extent.Text }
            if ($n -eq 'Remove-Item' -and $c.Extent.Text -notmatch '^Remove-Item \$tmp\b') { $odd += $c.Extent.Text }
            if ($n -eq 'Invoke-RestMethod' -and $c.Extent.Text -match '-Method') { $odd += $c.Extent.Text }
            continue
        }
        $odd += $n
    }
    $members = $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
    foreach ($m in $members) { if ($m.Member.Value -match $badMembers) { $odd += ('.' + $m.Member.Value + '()') } }
    Assert-True ($odd.Count -eq 0) ("$name only reads the box" + $(if ($odd.Count) { '  odd: ' + (($odd | Select-Object -Unique) -join ' | ') } else { '' }))
}

# ---- 4. answer-key isolation
$keyWords = 'answer\.key|LabHarness|LabKey|LabGrade|lab_beacon|Unprotect-LabText'
foreach ($f in $files) {
    $rel = Get-Relative $f
    if ($rel -like 'Lab\*' -or $rel -like 'Lab/*' -or $rel -like 'Tests\*' -or $rel -like 'Tests/*' -or $rel -eq 'Verify-Hardening.ps1') { continue }
    $hit = @(Select-String -Path $f.FullName -Pattern $keyWords)
    Assert-True ($hit.Count -eq 0) "$rel does not mention the lab answer key"
}

# ---- 5. only actions change the box
function Get-LibFile { param([string]$Name) Join-Path (Join-Path $root 'lib') $Name }
function Test-InsideActionBlock {
    param($Ast)
    $p = $Ast.Parent
    while ($p) {
        if ($p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            $q = $p.Parent
            while ($q -and $q -isnot [System.Management.Automation.Language.CommandAst]) { $q = $q.Parent }
            if ($q -and (@('New-Action', 'Register-UndoHandler') -contains $q.GetCommandName())) { return $true }
        }
        $p = $p.Parent
    }
    $false
}
function Get-EnclosingFunction {
    param($Ast)
    $p = $Ast.Parent
    while ($p) { if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $p.Name }; $p = $p.Parent }
    '<script>'
}
$changingName = '^(New|Set|Remove|Disable|Enable|Add|Register|Unregister|Start|Stop|Restart|Rename|Move|Copy|Clear|Reset|Import|Install|Uninstall)-|\.exe$|^(Invoke-Native|Invoke-NativeText|Invoke-Expression|Invoke-WebRequest|Invoke-RestMethod|Invoke-Command|Out-File)$'
$notChanging = @('New-Object', 'New-Finding', 'New-FixRef', 'New-Action', 'New-ChangeResult', 'Register-UndoHandler', 'Set-HpSetting', 'Set-HpSecret', 'Clear-HpSecret',
                 'Add-Member', 'Add-Type', 'New-TimeSpan', 'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet')
# helpers that change something outside an action block. Each one is only ever called from inside an Apply / undo block.
$helpers = @(
    'DeadMan.ps1::Enable-DeadMan', 'DeadMan.ps1::Disable-DeadMan', 'DeadMan.ps1::Update-DeadMan',      # the dead-man task and its files
    'Act-Firewall.ps1::New-OurRule',                                                                  # creates / replaces the tool's own HP-* rule
    'Act-Accounts.ps1::Set-UserRight',                                                                # secedit /configure for one user right
    'Act-Backup.ps1::Remove-BackupTemp', 'Act-Backup.ps1::New-BackupArchive',                         # delete only inside the backup folder (Remove-BackupTemp refuses anything else)
    'Act-Backup.ps1::Export-RegKey', 'Act-Backup.ps1::Save-BackupItems',                              # read-only collection into the plain work folder
    'Act-Backup.ps1::Request-PinHostKey'                                                              # ssh-keyscan: only asks the server which keys it offers
)
$actFiles = @(Get-ChildItem -Path (Join-Path $root 'lib') -Filter 'Act-*.ps1') + @(Get-Item (Get-LibFile 'DeadMan.ps1'))
foreach ($f in $actFiles) {
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $bad = @()
    foreach ($c in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $n = $c.GetCommandName()
        if (-not $n -or $n -notmatch $changingName -or $notChanging -contains $n) { continue }
        if ($n -match '^New-\w+Action$') { continue }                  # builds an action object (nothing runs until Invoke-Change)
        if (Test-InsideActionBlock $c) { continue }
        $fn = Get-EnclosingFunction $c
        if ($helpers -contains ($f.Name + '::' + $fn)) { continue }
        $bad += "$n in $fn"
    }
    Assert-True ($bad.Count -eq 0) ("$($f.Name): every command that changes something is inside an action block or a listed helper" + $(if ($bad.Count) { '  BAD: ' + (($bad | Select-Object -Unique) -join ' | ') } else { '' }))
}
foreach ($h in $helpers) {
    $file, $fn = $h -split '::'
    $tree = [System.Management.Automation.Language.Parser]::ParseFile((Get-LibFile $file), [ref]$null, [ref]$null)
    $found = @($tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $fn }, $true))
    Assert-True ($found.Count -eq 1) "the listed helper $h exists (an unused entry would hide a future mistake)"
}

# ---- 6. the collectors only read
$collect = Get-LibFile 'Collect.ps1'
$tree = [System.Management.Automation.Language.Parser]::ParseFile($collect, [ref]$null, [ref]$null)
$bad = @()
foreach ($c in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if (-not $n -or $n -notmatch $changingName -or $notChanging -contains $n) { continue }
    $text = $c.Extent.Text
    if ($n -eq 'net.exe' -and $text -match '^& net\.exe localgroup ') { continue }              # lists a group's members
    if ($n -eq 'secedit.exe' -and $text -match '/export ') { continue }                         # writes a temp file, never changes policy
    if ($n -eq 'Remove-Item' -and $text -match '^Remove-Item \$tmp\b') { continue }             # deletes that temp file
    if ($n -eq 'Invoke-Native' -and $text -match "-Arguments '-V'") { continue }                # ssh -V
    $bad += $text.Split("`n")[0]
}
Assert-True ($bad.Count -eq 0) ('Collect.ps1 only reads the box' + $(if ($bad.Count) { '  BAD: ' + ($bad -join ' | ') } else { '' }))
$members = $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)
$badMembers2 = @($members | Where-Object { $_.Member.Value -match $badMembers } | ForEach-Object { '.' + $_.Member.Value + '()' })
Assert-True ($badMembers2.Count -eq 0) ('Collect.ps1 calls no writing .NET method' + $(if ($badMembers2.Count) { '  BAD: ' + ($badMembers2 -join ' | ') } else { '' }))

# ---- 7. the judges are pure
$judgeFiles = @(Get-ChildItem -Path (Join-Path $root 'lib') -Filter 'Judge*.ps1' | Where-Object { $_.Name -ne 'JudgeHunt.ps1' -or $true })
$definedInJudges = @()
foreach ($f in $judgeFiles) {
    $t = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $definedInJudges += @($t.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
}
$pureCommands = @('ForEach-Object', 'Where-Object', 'Select-Object', 'Sort-Object', 'Measure-Object', 'Group-Object', 'Out-Null', 'Add-Member',
                  'Get-List', 'Get-BareName', 'Get-TeamInfo', 'New-Finding', 'New-FixRef') + $definedInJudges
foreach ($f in $judgeFiles) {
    $t = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $bad = @()
    foreach ($c in $t.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $n = $c.GetCommandName()
        if (-not $n) {
            # the only two places that call a function by name: Resolve-Fix (guarded: Request-* / New-* only) and Invoke-Judge (a judge function)
            if (@('Resolve-Fix', 'Invoke-Judge') -contains (Get-EnclosingFunction $c)) { continue }
            $bad += $c.Extent.Text.Split("`n")[0]; continue
        }
        if ($pureCommands -notcontains $n) { $bad += $n }
    }
    foreach ($m in $t.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $a.Static }, $true)) {
        if ($m.Expression.TypeName.Name -notin @('regex', 'string', 'int', 'math')) { $bad += $m.Extent.Text.Split("`n")[0] }
    }
    Assert-True ($bad.Count -eq 0) ("$($f.Name) is pure (works on the facts only)" + $(if ($bad.Count) { '  BAD: ' + (($bad | Select-Object -Unique) -join ' | ') } else { '' }))
}

# ---- 8. only Core.ps1 runs an action
foreach ($f in $files) {
    $rel = Get-Relative $f
    if ($rel -like 'Tests*' -or $rel -like 'Lab*' -or $f.Name -eq 'Core.ps1') { continue }
    $t = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $hits = @($t.FindAll({ param($a) $a -is [System.Management.Automation.Language.MemberExpressionAst] -and $a.Member.Value -in @('Apply', 'Capture') }, $true) | ForEach-Object { $_.Extent.Text })
    Assert-True ($hits.Count -eq 0) ("$rel does not run an action's Apply or Capture itself (only Invoke-Change does)" + $(if ($hits.Count) { '  BAD: ' + ($hits -join ' | ') } else { '' }))
}

# ---- 9. no name clash between a library's script-level variables and the script that loads the libraries
$libScriptVars = @{}                                    # lowercase name -> the spelling the libraries use
foreach ($f in @(Get-ChildItem -Path (Join-Path $root 'lib') -Filter *.ps1)) {
    $t = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    foreach ($u in $t.FindAll({ param($a) $a -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        if ($u.VariablePath.IsScript) {
            $plain = $u.VariablePath.UserPath -replace '^script:', ''
            if (-not $libScriptVars.ContainsKey($plain.ToLower())) { $libScriptVars[$plain.ToLower()] = $plain }
        }
    }
}
Assert-True ($libScriptVars.Count -ge 8 -and $libScriptVars.ContainsKey('plan') -and $libScriptVars.ContainsKey('hp')) "the libraries use $($libScriptVars.Count) script-level variables (Plan, Hp, ...)"
$loaders = 0
foreach ($f in $files) {
    $rel = Get-Relative $f
    if ($rel -like 'lib*' -or $rel -like 'Lab*') { continue }
    $t = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    # only a file that dot-sources something from lib\ shares its variable scope with the libraries
    $dots = @($t.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.InvocationOperator -eq 'Dot' -and $a.Extent.Text -match '(?i)[\\/]lib[\\/]|\$libDir' }, $true))
    if ($dots.Count -eq 0) { continue }
    $loaders++
    $clash = @()
    foreach ($u in $t.FindAll({ param($a) $a -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        if ((Get-EnclosingFunction $u) -ne '<script>') { continue }
        $vp = $u.VariablePath
        if (-not ($vp.IsScript -or $vp.IsUnscopedVariable)) { continue }
        $plain = $vp.UserPath -replace '^script:', ''
        if (-not $libScriptVars.ContainsKey($plain.ToLower())) { continue }
        # `$script:Plan` spelled exactly as the library spells it is the intended variable; anything else is a clash
        if ($vp.IsScript -and $plain -ceq $libScriptVars[$plain.ToLower()]) { continue }
        $clash += $u.Extent.Text
    }
    Assert-True ($clash.Count -eq 0) ("${rel}: no variable shares a name with a library's script-level variable" + $(if ($clash.Count) { '  CLASH: ' + (($clash | Select-Object -Unique) -join ' ') } else { '' }))
}
Assert-True ($loaders -ge 10) "rule 9 looked at $loaders files that load the libraries (it must not silently check nothing)"

# ---- 10. the glue files do not change the box themselves
$glueNames = @('Runner.ps1', 'Console.ps1', 'Gui.ps1')
$guiBadMembers = '^(Delete|Kill|WriteAllText|WriteAllBytes|AppendAllText|SetValue|CreateSubKey|CreateText|CreateDirectory|DeleteSubKey|DeleteValue|MoveTo|CopyTo)$'
foreach ($name in $glueNames) {
    $tree = [System.Management.Automation.Language.Parser]::ParseFile((Get-LibFile $name), [ref]$null, [ref]$null)
    # a call to a function that is defined in this same file is fine: that function's own body is checked by this same loop
    $definedHere = @($tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
    $bad = @()
    foreach ($c in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $n = $c.GetCommandName()
        if (-not $n -or $n -notmatch $changingName -or $notChanging -contains $n -or $definedHere -contains $n) { continue }
        if ($n -match '^New-\w+Action$') { continue }                  # builds an action object; only Invoke-Change runs it
        $bad += $n
    }
    foreach ($m in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        if ($m.Member.Value -match $guiBadMembers) { $bad += ('.' + $m.Member.Value + '()') }
    }
    Assert-True ($bad.Count -eq 0) ("$name changes nothing itself (it only calls Invoke-Change, Invoke-Undo and the audit)" + $(if ($bad.Count) { '  BAD: ' + (($bad | Select-Object -Unique) -join ' | ') } else { '' }))
}

# ---- 11. New-* functions never ask you anything (outside the action blocks they hand to Invoke-Change)
$asks = '^(Read-HpText|Read-HpSecret|Show-HpNotice|Read-Host|Get-ThrowawayMaster|Get-BackupPassphrase)$'
foreach ($f in $actFiles) {
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    $bad = @()
    foreach ($fn in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -like 'New-*' }, $true)) {
        foreach ($c in $fn.Body.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $n = $c.GetCommandName()
            $isAsk = $false
            if ($n -and $n -match $asks) { $isAsk = $true }
            if (-not $n -and $c.Extent.Text -match '^&\s*\$script:Hp\.(Ask|AskText|AskSecret|Notify)\b') { $isAsk = $true }
            if ($isAsk -and -not (Test-InsideActionBlock $c)) { $bad += "$($fn.Name) calls $(if ($n) { $n } else { 'a prompt hook' })" }
        }
    }
    Assert-True ($bad.Count -eq 0) ("$($f.Name): no New-* function asks you anything" + $(if ($bad.Count) { '  BAD: ' + ($bad -join ' | ') } else { '' }))
}

# ---- 12. the watchdog and the repairs it borrows
$wdPath = Join-Path $root 'Watchdog.ps1'
$pnPath = Join-Path $root 'Panic.ps1'
$wdTree = [System.Management.Automation.Language.Parser]::ParseFile($wdPath, [ref]$null, [ref]$null)
$pnTree = [System.Management.Automation.Language.Parser]::ParseFile($pnPath, [ref]$null, [ref]$null)
$wdLocal = @($wdTree.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
$pnLocal = @($pnTree.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })

# 12a. the watchdog changes only what is listed here, only in the function listed for it (everything else in the file only reads)
$wdMayChange = @{
    'New-Item'                = @('Initialize-Folders', 'Save-JobCopy')                        # its own folders
    'Move-Item'               = @('Write-Alert')                                               # alerts.log -> alerts.log.old once it is over 1 MB
    'Copy-Item'               = @('Save-JobCopy', 'Restore-JobConfig')                         # job files into its own folder; -RestoreJob (by hand) back
    'Remove-Item'             = @('Use-Flag', 'Test-RightsCheck', 'Save-Baselines', 'Start-Watchdog')   # its own notes and baseline notes, one temp file
    'New-NetFirewallRule'     = @('Restore-OurRules')                                          # the tool's own HP-Allow-TCP-<port> rules
    'Remove-NetFirewallRule'  = @('Restore-OurRules')                                          # ... only to rebuild one of those (by name)
    'Set-NetFirewallProfile'  = @('Restore-OurRules')                                          # -AllowInboundRules True, nothing else
    'Disable-NetFirewallRule' = @('Restore-OurRules')                                          # a Block rule that stops a scored port for everybody
    'secedit.exe'             = @('Test-RightsCheck')                                          # /export only: it reads the rights
    'net.exe'                 = @('Get-GroupMembers')                                          # localgroup NAME only: it lists the members
}
$wdUsed = @{}
$wdBad = @()
foreach ($c in $wdTree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if (-not $n -or $n -notmatch $changingName -or $notChanging -contains $n -or $wdLocal -contains $n) { continue }
    $fn = Get-EnclosingFunction $c
    if (-not $wdMayChange.ContainsKey($n) -or $wdMayChange[$n] -notcontains $fn) { $wdBad += "$n in $fn"; continue }
    $wdUsed["$n::$fn"] = $true
    $text = $c.Extent.Text
    if ($n -eq 'secedit.exe' -and ($text -notmatch '/export ' -or $text -match '/configure')) { $wdBad += "secedit.exe is only for /export: $text" }
    if ($n -eq 'net.exe' -and $text -notmatch '^& net\.exe localgroup \$group\.Name') { $wdBad += "net.exe is only for localgroup: $text" }
    if ($n -eq 'Remove-Item' -and $text -match '(?i)-Recurse') { $wdBad += "Remove-Item -Recurse: $text" }
    if ($n -eq 'Remove-NetFirewallRule' -and $text -notmatch '^Remove-NetFirewallRule -Name \$name$') { $wdBad += "Remove-NetFirewallRule must name one rule: $text" }
    if ($n -eq 'Set-NetFirewallProfile' -and $text -notmatch '^Set-NetFirewallProfile -Name \$p\.Name -AllowInboundRules True$') { $wdBad += "Set-NetFirewallProfile: $text" }
}
Assert-True ($wdBad.Count -eq 0) ('Watchdog.ps1 changes only what the list allows, only in the listed functions' + $(if ($wdBad.Count) { '  BAD: ' + (($wdBad | Select-Object -Unique) -join ' | ') } else { '' }))
$wdUnused = @()
foreach ($n in $wdMayChange.Keys) { foreach ($fn in $wdMayChange[$n]) { if (-not $wdUsed.ContainsKey("$n::$fn")) { $wdUnused += "$n::$fn" } } }
Assert-True ($wdUnused.Count -eq 0) ('every entry of the watchdog list is really used (an unused entry would hide a future mistake)' + $(if ($wdUnused.Count) { '  UNUSED: ' + ($wdUnused -join ' | ') } else { '' }))

# 12b. what neither file may ever contain
$never = @('Stop-Service', 'Stop-Process', 'Remove-Service', 'Restart-Computer', 'Stop-Computer', 'Remove-LocalUser', 'Disable-LocalUser', 'New-LocalUser', 'Rename-LocalUser',
           'Remove-LocalGroupMember', 'Disable-ScheduledTask', 'Set-MpPreference', 'Add-MpPreference', 'Remove-MpPreference', 'ConvertTo-SecureString', 'Get-Credential',
           'Invoke-Expression', 'iex', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'Start-Process', 'Set-ExecutionPolicy', 'sc.exe', 'taskkill.exe', 'reg.exe',
           'ssh.exe', 'scp.exe', 'curl.exe', 'wget')
foreach ($one in @(@{ Name = 'Watchdog.ps1'; Tree = $wdTree; Path = $wdPath }, @{ Name = 'Panic.ps1'; Tree = $pnTree; Path = $pnPath })) {
    $bad = @()
    foreach ($c in $one.Tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $n = $c.GetCommandName()
        if ($n -and ($never -contains $n)) { $bad += $n }
        if ($n -eq 'Read-Host' -and $one.Name -eq 'Watchdog.ps1') { $bad += 'Read-Host (a prompt would hang a task nobody watches)' }
    }
    foreach ($p in $one.Tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandParameterAst] }, $true)) {
        if ($p.ParameterName -match '^(Password|AccountPassword|NewPassword|OldPassword|Credential)$') { $bad += ('-' + $p.ParameterName) }
    }
    foreach ($t in $one.Tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.TypeExpressionAst] -or $a -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
        if ($t.TypeName.Name -match '(?i)SecureString|PSCredential|WebClient|HttpClient|WebRequest') { $bad += ('[' + $t.TypeName.Name + ']') }
    }
    foreach ($c in $one.Tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'New-Object' }, $true)) {
        if ($c.Extent.Text -match '(?i)SecureString|PSCredential|WebClient|HttpClient|WebRequest') { $bad += $c.Extent.Text.Split("`n")[0] }
    }
    Assert-True ($bad.Count -eq 0) ("$($one.Name) never sets a password, stops or deletes anything of the box's, or uses the Internet" + $(if ($bad.Count) { '  BAD: ' + (($bad | Select-Object -Unique) -join ' | ') } else { '' }))
}

# 12c. the three account repairs in Panic.ps1 (the watchdog runs them every minute): the password itself is never set
$bad = @()
foreach ($c in $pnTree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if ($n -eq 'Set-LocalUser') {
        $names = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
        if (@($names | Where-Object { $_ -notin @('Name', 'PasswordNeverExpires') }).Count -gt 0) { $bad += "Set-LocalUser with $($names -join ',')" }
    }
    if ($n -eq 'net.exe' -and $c.Extent.Text -match '^& net\.exe user') {
        if ($c.Extent.Text -notmatch '^& net\.exe user \$name /(active:yes|expires:never|logonpasswordchg:no)$') { $bad += $c.Extent.Text.Split("`n")[0] }
    }
    if ($n -eq 'Restart-Service' -and (Get-EnclosingFunction $c) -ne 'Restore-Rdp') { $bad += "Restart-Service in $(Get-EnclosingFunction $c)" }
}
Assert-True ($bad.Count -eq 0) ('Panic.ps1: Set-LocalUser only for PasswordNeverExpires, "net user" only with its three switches, Restart-Service only for a moved Remote Desktop port' + $(if ($bad.Count) { '  BAD: ' + ($bad -join ' | ') } else { '' }))

# 12d. the watchdog borrows only three repairs from Panic.ps1 (never the firewall import, the adapters or the rights), and writes a job file
#      back into Jenkins only when you start it with -RestoreJob
$borrowed = @()
foreach ($c in $wdTree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if ($n -and $n -like 'Restore-*' -and $wdLocal -notcontains $n) { $borrowed += $n }
}
$wantBorrowed = @('Restore-Rdp', 'Restore-Jmoney', 'Restore-Jenkins')
Assert-True ((@($borrowed | Select-Object -Unique | Sort-Object) -join ',') -eq (($wantBorrowed | Sort-Object) -join ',')) ("the watchdog calls exactly the repairs $($wantBorrowed -join ', ') from Panic.ps1" + $(if ($borrowed.Count) { "  (it calls: $((@($borrowed | Select-Object -Unique)) -join ', '))" } else { '' }))
Assert-True (@($wantBorrowed | Where-Object { $pnLocal -notcontains $_ }).Count -eq 0) 'and Panic.ps1 really defines them'
$restoreCalls = @($wdTree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Restore-JobConfig' }, $true))
$guarded = $false
if ($restoreCalls.Count -eq 1) {
    $p = $restoreCalls[0].Parent
    while ($p) {
        if ($p -is [System.Management.Automation.Language.IfStatementAst] -and $p.Clauses[0].Item1.Extent.Text -eq '$RestoreJob') { $guarded = $true; break }
        $p = $p.Parent
    }
}
Assert-True ($restoreCalls.Count -eq 1 -and (Get-EnclosingFunction $restoreCalls[0]) -eq 'Start-Watchdog' -and $guarded) 'Restore-JobConfig (it writes into Jenkins'' folder) is called once, only under "if ($RestoreJob)"'

# ---- 13. every test file counts an error that nothing caught as a failure
foreach ($t in @(Get-ChildItem -Path $PSScriptRoot -Filter 'Test-*.ps1')) {
    $lines = @(Get-Content -Path $t.FullName)
    $lib = [array]::IndexOf(@($lines | ForEach-Object { $_.Trim() }), '. "$PSScriptRoot\TestLib.ps1"')
    $trapOk = ($lib -ge 0 -and ($lib + 1) -lt $lines.Count -and $lines[$lib + 1] -match '^trap \{ Register-TestError \$_; continue \}')
    Assert-True $trapOk "$($t.Name) turns an error that nothing caught into a failure (the trap line right after TestLib.ps1)"
}

Write-TestSummary
