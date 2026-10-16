# Test-GuiApi.ps1 - checks lib\Gui.ps1 against the real WinForms / Drawing names, because the window itself can only be tried on Windows.
# It reads winforms-api.txt (made from the .NET assemblies by WinFormsApiDump.cs) and the PowerShell syntax tree of Gui.ps1, and checks:
#   - every control the file creates exists, and its constructor takes that many arguments
#   - every property, method, event and static member that is used on a control exists, and a property that is assigned is writable
#   - a word assigned to an enum property ('Fill', 'Top, Left') is a value of that enum
#   - every $script:Ui.Key that is used is assigned somewhere, and the same for $script:Dlg.Key
#   - event handlers stay tiny: they only call Invoke-GuiAction / Invoke-GuiSafe / Confirm-GuiClose, and use no local variable of the function
#   - every command the file calls exists, and the file has no commands at the top level
# Where the type of an expression cannot be worked out, that one step is skipped (the checker never guesses).
param([string]$GuiFile = '')        # normally empty: the checker reads lib\Gui.ps1. Test-GuiApiMutations.ps1 hands it a copy with a planted mistake.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
$root = Split-Path -Parent $PSScriptRoot
$guiPath = Join-Path $root 'lib\Gui.ps1'
if ($GuiFile) { $guiPath = $GuiFile }
$apiPath = Join-Path $PSScriptRoot 'winforms-api.txt'
Write-Host 'The window code against the .NET WinForms names' -ForegroundColor Cyan

# ---------------------------------------------------------------- the list of real names
function Add-Entry {
    param($Table, [string]$Name, $Entry)
    if (-not $Table.ContainsKey($Name)) { $Table[$Name] = New-Object System.Collections.ArrayList }
    [void]$Table[$Name].Add($Entry)
}

$api = @{}
$current = $null
foreach ($line in [System.IO.File]::ReadAllLines($apiPath)) {
    if ($line.Length -eq 0 -or $line.StartsWith('#')) { continue }
    $f = $line.Split("`t")
    switch ($f[0]) {
        'TYPE' { $current = @{ Base = $f[2]; Kind = $f[3]; Props = @{}; Indexers = @{}; Methods = @{}; Events = @{}; Fields = @{}; Ctors = @(); Values = @(); Flags = $false }; $api[$f[1]] = $current }
        'ENUM' { $current.Flags = ($f[1] -eq 'flags') }
        'V'    { $current.Values += $f[1] }
        'C'    { $current.Ctors += $f[1] }
        'P'    { Add-Entry $current.Props $f[1] @{ Type = $f[2]; Rw = $f[3]; Decl = $f[4] } }
        'I'    { Add-Entry $current.Indexers $f[1] @{ Type = $f[2]; Params = $f[3]; Decl = $f[4] } }
        'M'    { Add-Entry $current.Methods $f[1] @{ Ret = $f[2]; Params = $f[3]; Static = ($f[4] -eq 'S'); Decl = $f[5] } }
        'E'    { Add-Entry $current.Events $f[1] @{ Handler = $f[2]; Decl = $f[3] } }
        'F'    { Add-Entry $current.Fields $f[1] @{ Type = $f[2]; Static = ($f[3] -eq 'S'); Decl = $f[4] } }
    }
}
Assert-True ($api.Count -ge 100 -and $api.ContainsKey('System.Windows.Forms.Form') -and $api.ContainsKey('System.Drawing.Color')) "the list holds $($api.Count) WinForms / Drawing types"
Assert-True ($api['System.Windows.Forms.DockStyle'].Values -contains 'Fill' -and $api['System.Windows.Forms.AnchorStyles'].Flags) 'enum values and the Flags marker are in the list'

function Get-TypeChain {
    param([string]$Type)
    $chain = @()
    $t = $Type
    while ($t -and $api.ContainsKey($t)) { $chain += $t; $t = $api[$t].Base }
    $chain
}

function Select-Nearest {
    # A derived class can hide a base member of the same name; take the one declared nearest to the receiver's own type.
    param($Entries, [string]$Type)
    $chain = @(Get-TypeChain $Type)
    $best = $null
    $bestRank = 9999
    foreach ($e in $Entries) {
        $rank = [array]::IndexOf($chain, $e.Decl)
        if ($rank -lt 0) { $rank = 500 }
        if ($rank -lt $bestRank) { $best = $e; $bestRank = $rank }
    }
    $best
}

function Get-ParamCount {
    param([string]$Params)
    if ($Params.Length -eq 0) { return 0 }
    $Params.Split(',').Count
}

function Test-WinFormsName {
    param([string]$Type)
    $Type -like 'System.Windows.Forms.*' -or $Type -like 'System.Drawing.*'
}

# ---------------------------------------------------------------- the syntax tree of Gui.ps1
$tree = [System.Management.Automation.Language.Parser]::ParseFile($guiPath, [ref]$null, [ref]$null)
$allFunctions = @($tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
Assert-True ($allFunctions.Count -ge 60) "Gui.ps1 defines $($allFunctions.Count) functions"

function Get-NodeKind { param($Ast) if ($null -eq $Ast) { '' } else { $Ast.GetType().Name } }

function Get-Inner {
    # The innermost expression of (a pipeline of) one expression: strips Pipeline, CommandExpression and Paren wrappers.
    param($Ast)
    $x = $Ast
    while ($true) {
        $k = Get-NodeKind $x
        if ($k -eq 'PipelineAst' -and $x.PipelineElements.Count -eq 1) { $x = $x.PipelineElements[0]; continue }
        if ($k -eq 'CommandExpressionAst') { $x = $x.Expression; continue }
        if ($k -eq 'ParenExpressionAst') { $x = $x.Pipeline; continue }
        break
    }
    $x
}

function Get-ArgCount {
    # How many arguments a method call has. A call without arguments has Arguments = $null, and @($null).Count is 1, so ask this way.
    param($Call)
    if ($null -eq $Call.Arguments) { return 0 }
    @($Call.Arguments).Count
}

function Get-EnclosingFunctionName {
    param($Ast)
    $p = $Ast.Parent
    while ($p) {
        if ((Get-NodeKind $p) -eq 'FunctionDefinitionAst') { return $p.Name }
        $p = $p.Parent
    }
    ''
}

# what the tool knows that the syntax tree cannot tell: the types of a few function parameters, and what a collection hands out
$paramTypes = @{
    'Add-GuiRowStyle:Table'      = 'System.Windows.Forms.TableLayoutPanel'
    'Set-GuiRowColor:Item'       = 'System.Windows.Forms.ListViewItem'
    'Confirm-GuiClose:CloseArgs' = 'System.Windows.Forms.FormClosingEventArgs'
}
$elementTypes = @{
    'System.Windows.Forms.ListView+ListViewItemCollection'         = 'System.Windows.Forms.ListViewItem'
    'System.Windows.Forms.ListView+SelectedListViewItemCollection' = 'System.Windows.Forms.ListViewItem'
    'System.Windows.Forms.ListView+ColumnHeaderCollection'         = 'System.Windows.Forms.ColumnHeader'
    'System.Windows.Forms.ListViewItem+ListViewSubItemCollection'  = 'System.Windows.Forms.ListViewItem+ListViewSubItem'
}
# a string given to one of OUR helper functions that must be a value of an enum:  command -> position of the argument (0 = first after the name) -> enum
$helperEnumArgs = @{ 'Add-GuiRowStyle' = @{ 1 = 'System.Windows.Forms.SizeType' } }

$fnTypes = @{}          # function name -> the WinForms type it returns
$fnVars = @{}           # function name -> (variable name in lower case -> type, or '?' when it is assigned two different types)
$uiTypes = @{}          # $script:Ui key -> type
$dlgTypes = @{}         # $script:Dlg key -> type

function Get-NewObjectInfo {
    # For a New-Object command: the type name and the list of constructor argument expressions.
    param($Cmd)
    $positional = @()
    $elems = @($Cmd.CommandElements | Select-Object -Skip 1)
    for ($i = 0; $i -lt $elems.Count; $i++) {
        $e = $elems[$i]
        if ((Get-NodeKind $e) -eq 'CommandParameterAst') {
            if ($e.ParameterName -like 't*' -and $i + 1 -lt $elems.Count) { $positional = @($elems[$i + 1]) + $positional; $i++ }
            elseif ($e.ParameterName -like 'a*' -and $i + 1 -lt $elems.Count) { $positional += $elems[$i + 1]; $i++ }
            continue
        }
        $positional += $e
    }
    $typeName = ''
    if ($positional.Count -gt 0) { $typeName = [string]$positional[0].Extent.Text }
    $args2 = @()
    if ($positional.Count -gt 1) {
        $inner = Get-Inner $positional[1]
        if ((Get-NodeKind $inner) -eq 'ArrayLiteralAst') { $args2 = @($inner.Elements) } else { $args2 = @($inner) }
    }
    [pscustomobject]@{ Type = $typeName; Args = $args2 }
}

function Get-ExprType {
    # The WinForms type of an expression, or $null when it cannot be told.
    param($Ast, [string]$Fn)
    $Ast = Get-Inner $Ast
    $kind = Get-NodeKind $Ast
    switch ($kind) {
        'CommandAst' {
            $n = $Ast.GetCommandName()
            if ($n -eq 'New-Object') { return (Get-NewObjectInfo $Ast).Type }
            if ($n -and $fnTypes.ContainsKey($n)) { return $fnTypes[$n] }
            return $null
        }
        'VariableExpressionAst' {
            $vars = $fnVars[$Fn]
            $name = $Ast.VariablePath.UserPath.ToLower()
            if ($vars -and $vars.ContainsKey($name) -and $vars[$name] -ne '?') { return $vars[$name] }
            $key = $Fn + ':' + $Ast.VariablePath.UserPath
            if ($paramTypes.ContainsKey($key)) { return $paramTypes[$key] }
            return $null
        }
        'IndexExpressionAst' {
            $ct = Get-ExprType $Ast.Target $Fn
            if ($ct -and $elementTypes.ContainsKey($ct)) { return $elementTypes[$ct] }
            return $null
        }
        'InvokeMemberExpressionAst' {
            $rt = Get-ReceiverType $Ast $Fn
            if (-not $rt -or -not $api.ContainsKey($rt) -or (Get-NodeKind $Ast.Member) -ne 'StringConstantExpressionAst') { return $null }
            $m = $api[$rt].Methods[[string]$Ast.Member.Value]
            if (-not $m) { return $null }
            $want = Get-ArgCount $Ast
            $returns = @($m | Where-Object { (Get-ParamCount $_.Params) -eq $want } | ForEach-Object { $_.Ret } | Select-Object -Unique)
            if ($returns.Count -eq 1 -and $api.ContainsKey($returns[0])) { return $returns[0] }
            return $null
        }
        'MemberExpressionAst' {
            if ((Get-NodeKind $Ast.Member) -ne 'StringConstantExpressionAst') { return $null }
            $holder = Get-UiHolder $Ast.Expression
            if ($holder -eq 'Ui') { return $uiTypes[[string]$Ast.Member.Value] }
            if ($holder -eq 'Dlg') { return $dlgTypes[[string]$Ast.Member.Value] }
            $rt = Get-ReceiverType $Ast $Fn
            if (-not $rt -or -not $api.ContainsKey($rt)) { return $null }
            $name = [string]$Ast.Member.Value
            if ($api[$rt].Props.ContainsKey($name)) {
                $p = Select-Nearest $api[$rt].Props[$name] $rt
                if ($api.ContainsKey($p.Type)) { return $p.Type }
            }
            return $null
        }
    }
    $null
}

function Get-UiHolder {
    # 'Ui' for  $script:Ui  or its short name  $win;  'Dlg' for  $script:Dlg;  otherwise ''.
    param($Ast)
    if ((Get-NodeKind $Ast) -ne 'VariableExpressionAst') { return '' }
    $p = $Ast.VariablePath.UserPath.ToLower()
    if ($p -eq 'script:ui' -or $p -eq 'win') { return 'Ui' }
    if ($p -eq 'script:dlg') { return 'Dlg' }
    ''
}

function Get-ReceiverType {
    # The type a member is looked up on:  [Type]::Member  -> Type;  expr.Member -> type of expr.
    param($Member, [string]$Fn)
    $e = $Member.Expression
    if ((Get-NodeKind $e) -eq 'TypeExpressionAst') {
        $name = $e.TypeName.FullName
        if ($name -eq 'math') { return $null }
        return $name
    }
    Get-ExprType $e $Fn
}

# ---- pass 1: the type each function returns (its last line is a variable that holds a New-Object / helper result)
function Update-VarTypes {
    foreach ($fn in $allFunctions) {
        $vars = $fnVars[$fn.Name]
        if (-not $vars) { $vars = @{}; $fnVars[$fn.Name] = $vars }
        foreach ($a in $fn.Body.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
            $t = Get-ExprType $a.Right $fn.Name
            if (-not $t) { continue }
            $name = $a.Left.VariablePath.UserPath.ToLower()
            if ($vars.ContainsKey($name) -and $vars[$name] -ne $t) { $vars[$name] = '?' } else { $vars[$name] = $t }
        }
        foreach ($loop in $fn.Body.FindAll({ param($x) $x -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
            $ct = Get-ExprType $loop.Condition $fn.Name
            if ($ct -and $elementTypes.ContainsKey($ct)) { $vars[$loop.Variable.VariablePath.UserPath.ToLower()] = $elementTypes[$ct] }
        }
        # the function's result: its last statement, when that is a plain variable
        $last = @($fn.Body.EndBlock.Statements) | Select-Object -Last 1
        if ($last) {
            $inner = Get-Inner $last
            if ((Get-NodeKind $inner) -eq 'VariableExpressionAst') {
                $t = Get-ExprType $inner $fn.Name
                if ($t) { $fnTypes[$fn.Name] = $t }
            }
        }
    }
}

# ---- pass 2: the types of the $script:Ui keys and the $script:Dlg keys
function Update-HolderTypes {
    foreach ($fn in $allFunctions) {
        foreach ($a in $fn.Body.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
            $left = $a.Left
            if ((Get-NodeKind $left) -eq 'MemberExpressionAst' -and (Get-UiHolder $left.Expression) -eq 'Ui' -and (Get-NodeKind $left.Member) -eq 'StringConstantExpressionAst') {
                $t = Get-ExprType $a.Right $fn.Name
                if ($t) { $uiTypes[[string]$left.Member.Value] = $t }
            }
            if ((Get-NodeKind $left) -eq 'VariableExpressionAst' -and (Get-UiHolder $left) -eq 'Dlg') {
                $table = Get-Inner $a.Right
                if ((Get-NodeKind $table) -eq 'HashtableAst') {
                    foreach ($pair in $table.KeyValuePairs) {
                        $t = Get-ExprType $pair.Item2 $fn.Name
                        if ($t) { $dlgTypes[[string]$pair.Item1.Extent.Text] = $t }
                    }
                }
            }
        }
    }
}
# the two passes feed each other (a local variable holds a $script:Ui control, a Ui key holds a helper's result), so go round a few times
foreach ($round in 1..4) { Update-VarTypes; Update-HolderTypes }
Assert-True ($uiTypes.Count -ge 25) "the types of $($uiTypes.Count) window controls (`$script:Ui keys) could be worked out"
Assert-True ($uiTypes['List'] -eq 'System.Windows.Forms.ListView' -and $uiTypes['BarTop'] -eq 'System.Windows.Forms.FlowLayoutPanel' -and $uiTypes['Form'] -eq 'System.Windows.Forms.Form') 'spot check: List is a ListView, BarTop a FlowLayoutPanel, Form a Form'
Assert-True ($dlgTypes['Yes'] -eq 'System.Windows.Forms.Button' -and $dlgTypes['List'] -eq 'System.Windows.Forms.ListView' -and $dlgTypes['Box'] -eq 'System.Windows.Forms.TextBox') 'spot check: the dialog keys Yes, List and Box have their types'
Assert-True ($fnTypes['Build-GuiButton'] -eq 'System.Windows.Forms.Button' -and $fnTypes['Build-GuiConfirmDialog'] -eq 'System.Windows.Forms.Form') 'spot check: Build-GuiButton returns a Button, Build-GuiConfirmDialog a Form'

# ---------------------------------------------------------------- the checks
$problems = New-Object System.Collections.ArrayList
$counts = @{ Members = 0; Methods = 0; Events = 0; Assign = 0; Enum = 0; Ctor = 0; Skipped = 0 }
$skippedList = New-Object System.Collections.ArrayList        # shown when the environment variable HP_SHOW_SKIPPED is 1

function Test-ArgsAgainstEnums {
    # A string constant given for a parameter that every matching overload declares as the same enum must be a value of it.
    param($Overloads, $ArgAsts, [string]$Where)
    for ($i = 0; $i -lt @($ArgAsts).Count; $i++) {
        $inner = Get-Inner $ArgAsts[$i]
        if ((Get-NodeKind $inner) -ne 'StringConstantExpressionAst') { continue }
        $types = @($Overloads | ForEach-Object { @($_.Split(','))[$i] } | Select-Object -Unique)
        if ($types.Count -eq 1 -and $api.ContainsKey($types[0]) -and $api[$types[0]].Kind -eq 'enum') {
            $counts.Enum++
            if (-not (Test-EnumWord $types[0] ([string]$inner.Value))) { [void]$problems.Add("$Where : '$($inner.Value)' is not a value of $($types[0])") }
        }
    }
}

function Test-EnumWord {
    param([string]$EnumType, [string]$Text)
    $e = $api[$EnumType]
    $words = @($Text.Split(',') | ForEach-Object { $_.Trim() })
    if ($words.Count -gt 1 -and -not $e.Flags) { return $false }
    foreach ($w in $words) { if ($e.Values -notcontains $w) { return $false } }
    $true
}

# ---- members: properties, methods, events, static members
foreach ($node in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
    if ((Get-NodeKind $node.Member) -ne 'StringConstantExpressionAst') { continue }
    $fnName = Get-EnclosingFunctionName $node
    $name = [string]$node.Member.Value
    $where = "$fnName : " + $node.Extent.Text.Split("`n")[0]
    if ((Get-UiHolder $node.Expression) -ne '') { continue }                       # a key of $script:Ui / $script:Dlg: checked below
    $rt = Get-ReceiverType $node $fnName
    if (-not $rt) { $counts.Skipped++; [void]$skippedList.Add($where); continue }
    if (-not $api.ContainsKey($rt)) {
        if (Test-WinFormsName $rt) { [void]$problems.Add("$where : the type $rt is not in winforms-api.txt (add it to winforms-types.txt and run WinFormsApiDump)") }
        else { $counts.Skipped++; [void]$skippedList.Add($where) }
        continue
    }
    $t = $api[$rt]
    if ((Get-NodeKind $node) -eq 'InvokeMemberExpressionAst') {
        if ($name -like 'Add_*') {
            $counts.Events++
            if (-not $t.Events.ContainsKey($name.Substring(4))) { [void]$problems.Add("$where : $rt has no event '$($name.Substring(4))'") }
            continue
        }
        $counts.Methods++
        if (-not $t.Methods.ContainsKey($name)) { [void]$problems.Add("$where : $rt has no method '$name'"); continue }
        $want = Get-ArgCount $node
        $fits = @($t.Methods[$name] | Where-Object { (Get-ParamCount $_.Params) -eq $want -or $_.Params -like '*[[][]]' })
        if ($fits.Count -eq 0) { [void]$problems.Add("$where : no overload of $rt.$name takes $want argument(s)"); continue }
        if ($want -gt 0) { Test-ArgsAgainstEnums @($fits | ForEach-Object { $_.Params }) @($node.Arguments) $where }
        continue
    }
    $counts.Members++
    if ($t.Kind -eq 'enum') {
        if ($t.Values -notcontains $name) { [void]$problems.Add("$where : $rt has no value '$name'") }
        continue
    }
    if (-not ($t.Props.ContainsKey($name) -or $t.Fields.ContainsKey($name) -or $t.Methods.ContainsKey($name))) { [void]$problems.Add("$where : $rt has no member '$name'") }
}

# ---- assignments:  control.Property = value
foreach ($a in $tree.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    $left = $a.Left
    if ((Get-NodeKind $left) -ne 'MemberExpressionAst' -or (Get-NodeKind $left.Member) -ne 'StringConstantExpressionAst') { continue }
    if ((Get-UiHolder $left.Expression) -ne '') { continue }
    $fnName = Get-EnclosingFunctionName $a
    $rt = Get-ReceiverType $left $fnName
    if (-not $rt -or -not $api.ContainsKey($rt)) { continue }
    $name = [string]$left.Member.Value
    $where = "$fnName : " + $a.Extent.Text.Split("`n")[0]
    $entries = $api[$rt].Props[$name]
    if (-not $entries) { if (-not $api[$rt].Fields.ContainsKey($name)) { [void]$problems.Add("$where : $rt has no property '$name' to assign") }; continue }
    $counts.Assign++
    $p = Select-Nearest $entries $rt
    if ($p.Rw -notlike '*W*') { [void]$problems.Add("$where : $rt.$name cannot be assigned (read-only)"); continue }
    $value = Get-Inner $a.Right
    if ((Get-NodeKind $value) -eq 'StringConstantExpressionAst' -and $api.ContainsKey($p.Type) -and $api[$p.Type].Kind -eq 'enum') {
        $counts.Enum++
        if (-not (Test-EnumWord $p.Type ([string]$value.Value))) { [void]$problems.Add("$where : '$($value.Value)' is not a value of $($p.Type)") }
    }
}

# ---- New-Object: the type exists and has a constructor with that many arguments; helper calls with enum words
foreach ($c in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if ($n -eq 'New-Object') {
        $info = Get-NewObjectInfo $c
        if (-not (Test-WinFormsName $info.Type)) { continue }
        $counts.Ctor++
        $where = (Get-EnclosingFunctionName $c) + ' : ' + $c.Extent.Text.Split("`n")[0]
        if (-not $api.ContainsKey($info.Type)) { [void]$problems.Add("$where : the type $($info.Type) is not in winforms-api.txt"); continue }
        $t = $api[$info.Type]
        $want = @($info.Args).Count
        $fits = @($t.Ctors | Where-Object { (Get-ParamCount $_) -eq $want })
        if ($fits.Count -eq 0 -and -not ($want -eq 0 -and $t.Kind -eq 'struct')) { [void]$problems.Add("$where : $($info.Type) has no constructor with $want argument(s)"); continue }
        Test-ArgsAgainstEnums $fits @($info.Args) $where
    }
    elseif ($n -and $helperEnumArgs.ContainsKey($n)) {
        $positional = @($c.CommandElements | Select-Object -Skip 1 | Where-Object { (Get-NodeKind $_) -ne 'CommandParameterAst' })
        foreach ($pos in $helperEnumArgs[$n].Keys) {
            if ($pos -ge $positional.Count) { continue }
            $inner = Get-Inner $positional[$pos]
            if ((Get-NodeKind $inner) -ne 'StringConstantExpressionAst') { continue }
            $counts.Enum++
            if (-not (Test-EnumWord $helperEnumArgs[$n][$pos] ([string]$inner.Value))) { [void]$problems.Add("$n : '$($inner.Value)' is not a value of $($helperEnumArgs[$n][$pos])") }
        }
    }
}

Assert-True ($problems.Count -eq 0) ("every WinForms name, argument count and enum word in Gui.ps1 exists in the .NET list" + $(if ($problems.Count) { "`n    " + (($problems | Select-Object -Unique) -join "`n    ") } else { '' }))
Write-Host ("  checked: {0} property/field/static reads, {1} method calls, {2} event subscriptions, {3} assignments, {4} enum words, {5} constructors ({6} steps skipped: type unknown)" -f $counts.Members, $counts.Methods, $counts.Events, $counts.Assign, $counts.Enum, $counts.Ctor, $counts.Skipped)
if ($env:HP_SHOW_SKIPPED -eq '1') { $skippedList | ForEach-Object { Write-Host ('  skipped: ' + $_) -ForegroundColor DarkGray } }
Assert-True ($counts.Members -ge 60 -and $counts.Methods -ge 60 -and $counts.Events -ge 15 -and $counts.Assign -ge 80 -and $counts.Enum -ge 25 -and $counts.Ctor -ge 25) 'the checker really looked at the code (it did not silently check nothing)'

# ---- $script:Ui and $script:Dlg keys: used ones are assigned somewhere
$uiAssigned = @{}
$uiUsed = @{}
$dlgAssigned = @{}
$dlgUsed = @{}
foreach ($node in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
    if ((Get-NodeKind $node) -eq 'InvokeMemberExpressionAst') { continue }
    $holder = Get-UiHolder $node.Expression
    if ($holder -eq '' -or (Get-NodeKind $node.Member) -ne 'StringConstantExpressionAst') { continue }
    if ($holder -eq 'Ui') { $uiUsed[[string]$node.Member.Value] = $true } else { $dlgUsed[[string]$node.Member.Value] = $true }
}
foreach ($a in $tree.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    $left = $a.Left
    if ((Get-NodeKind $left) -eq 'MemberExpressionAst' -and (Get-UiHolder $left.Expression) -eq 'Ui') { $uiAssigned[[string]$left.Member.Value] = $true }
    if ((Get-NodeKind $left) -eq 'VariableExpressionAst' -and (Get-UiHolder $left) -eq 'Dlg') {
        $table = Get-Inner $a.Right
        if ((Get-NodeKind $table) -eq 'HashtableAst') { foreach ($pair in $table.KeyValuePairs) { $dlgAssigned[[string]$pair.Item1.Extent.Text] = $true } }
    }
}
$uiMissing = @($uiUsed.Keys | Where-Object { -not $uiAssigned.ContainsKey($_) })
$dlgMissing = @($dlgUsed.Keys | Where-Object { -not $dlgAssigned.ContainsKey($_) })
Assert-True ($uiMissing.Count -eq 0) ("every `$script:Ui key that is used is assigned somewhere ($($uiUsed.Count) keys)" + $(if ($uiMissing.Count) { '  MISSING: ' + ($uiMissing -join ', ') } else { '' }))
Assert-True ($dlgMissing.Count -eq 0) ("every `$script:Dlg key that is used is set when a dialog is built ($($dlgUsed.Count) keys)" + $(if ($dlgMissing.Count) { '  MISSING: ' + ($dlgMissing -join ', ') } else { '' }))
Assert-True ($uiUsed.Count -ge 30) 'the checker saw the window keys'

# ---- event handlers are tiny and use no local variable
$allowedFirst = @('Invoke-GuiAction', 'Invoke-GuiSafe', 'Confirm-GuiClose')
$automatic = @('_', 'psitem', 'true', 'false', 'null', 'args', 'input', 'this')
$badHandlers = @()
$handlerCount = 0
foreach ($h in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $a.Member.Value -like 'Add_*' }, $true)) {
    $handlerCount++
    $where = (Get-EnclosingFunctionName $h) + ' : ' + $h.Extent.Text.Split("`n")[0]
    $sb = $h.Arguments[0]
    if ((Get-NodeKind $sb) -ne 'ScriptBlockExpressionAst') { $badHandlers += "$where : the handler is not a script block written in place"; continue }
    foreach ($s in @($sb.ScriptBlock.EndBlock.Statements)) {
        $ok = $false
        if ((Get-NodeKind $s) -eq 'PipelineAst') {
            $first = $s.PipelineElements[0]
            if ((Get-NodeKind $first) -eq 'CommandAst' -and $allowedFirst -contains $first.GetCommandName()) { $ok = $true }
        }
        if ((Get-NodeKind $s) -eq 'AssignmentStatementAst' -and $s.Left.Extent.Text -eq '$null') { $ok = $true }
        if (-not $ok) { $badHandlers += "$where : a handler may only call Invoke-GuiAction / Invoke-GuiSafe / Confirm-GuiClose, not: " + $s.Extent.Text.Split("`n")[0] }
    }
    # variables: only parameters, things assigned inside, and script-scope variables
    $defined = @()
    foreach ($pb in $sb.ScriptBlock.FindAll({ param($x) $x -is [System.Management.Automation.Language.ParameterAst] }, $true)) { $defined += $pb.Name.VariablePath.UserPath.ToLower() }
    foreach ($as in $sb.ScriptBlock.FindAll({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) { $defined += $as.Left.VariablePath.UserPath.ToLower() }
    foreach ($fe in $sb.ScriptBlock.FindAll({ param($x) $x -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) { $defined += $fe.Variable.VariablePath.UserPath.ToLower() }
    foreach ($v in $sb.ScriptBlock.FindAll({ param($x) $x -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        $vp = $v.VariablePath
        if ($vp.IsScript -or $vp.IsGlobal -or $vp.UserPath.Contains(':')) { continue }
        $vn = $vp.UserPath.ToLower()
        if ($automatic -contains $vn -or $defined -contains $vn) { continue }
        $badHandlers += "$where : uses the local variable `$$($vp.UserPath), which the handler will not see when it runs"
    }
}
Assert-True ($badHandlers.Count -eq 0) ("$handlerCount event handlers are tiny and use only `$script: variables, their own parameters and what they assign" + $(if ($badHandlers.Count) { "`n    " + (($badHandlers | Select-Object -Unique) -join "`n    ") } else { '' }))
Assert-True ($handlerCount -ge 20) 'the checker found the event handlers'

# ---- every command the file calls exists
$known = @{}
foreach ($f in Get-ChildItem -Path (Join-Path $root 'lib') -Filter *.ps1) {
    $t = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
    foreach ($fd in $t.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $known[$fd.Name] = $true }
}
$unknown = @()
$called = @{}
foreach ($c in $tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $n = $c.GetCommandName()
    if (-not $n) { continue }
    $called[$n] = $true
    if ($known.ContainsKey($n)) { continue }
    if (Get-Command $n -ErrorAction SilentlyContinue) { continue }
    $unknown += $n
}
Assert-True ($unknown.Count -eq 0) ("all $($called.Count) commands called in Gui.ps1 exist (lib functions or PowerShell commands)" + $(if ($unknown.Count) { '  UNKNOWN: ' + (($unknown | Select-Object -Unique) -join ', ') } else { '' }))

# ---- the file has nothing at the top level except function definitions (and the two state tables)
$topBad = @()
foreach ($s in $tree.EndBlock.Statements) {
    $k = Get-NodeKind $s
    if ($k -eq 'FunctionDefinitionAst') { continue }
    if ($k -eq 'AssignmentStatementAst' -and ($s.Left.Extent.Text -eq '$script:Ui' -or $s.Left.Extent.Text -eq '$script:Dlg')) { continue }
    $topBad += $s.Extent.Text.Split("`n")[0]
}
Assert-True ($topBad.Count -eq 0) ('Gui.ps1 has no commands at the top level, only functions' + $(if ($topBad.Count) { '  BAD: ' + ($topBad -join ' | ') } else { '' }))
$addType = @($tree.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Add-Type' }, $true) | ForEach-Object { Get-EnclosingFunctionName $_ } | Select-Object -Unique)
Assert-True ($addType.Count -eq 1 -and $addType[0] -eq 'Initialize-GuiAssemblies') 'WinForms is loaded in exactly one place: Initialize-GuiAssemblies'

# ---- the table of parameter types above still points at real functions and parameters
$stale = @()
foreach ($key in $paramTypes.Keys) {
    $fnPart, $paramPart = $key -split ':'
    $fd = $allFunctions | Where-Object { $_.Name -eq $fnPart } | Select-Object -First 1
    $hasParam = $false
    if ($fd) {
        $plist = @()
        if ($fd.Body.ParamBlock) { $plist = @($fd.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) }
        $hasParam = ($plist -contains $paramPart)
    }
    if (-not $hasParam) { $stale += $key }
}
Assert-True ($stale.Count -eq 0) ('the checker''s table of parameter types matches Gui.ps1' + $(if ($stale.Count) { '  STALE: ' + ($stale -join ', ') } else { '' }))

Write-TestSummary
