# Test-LabGrade.ps1 - tests the lab grader (Lab\LabGrade.ps1):
#   1. the verdict rules (pure) for every plant kind, fixed / partial / missed,
#   2. the fact collection with Windows stubs (property names line up, nothing throws),
#   3. a round trip: plan -> encrypted key -> decrypt -> grade, with a fake "box" that is fixed or untouched.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\ScoreLib.ps1"
. "$PSScriptRoot\..\VerifyJudgeAccounts.ps1"
. "$PSScriptRoot\..\VerifyFacts.ps1"
. "$PSScriptRoot\..\Lab\LabKey.ps1"
. "$PSScriptRoot\..\Lab\LabPlan.ps1"
. "$PSScriptRoot\..\Lab\LabGrade.ps1"

function V { param($Kind, $Facts, $Plant = $null)
    if (-not $Plant) { $Plant = [pscustomobject]@{ Kind = $Kind; Name = 'x'; Port = 4444 } }
    (Get-PlantVerdict $Plant $Facts).Verdict
}

Write-Host 'Verdict rules' -ForegroundColor Cyan
Assert-Equal (V User @{ Exists = $true; Enabled = $true; InAdmins = $true; PasswordWorks = $true }) 'MISSED' 'user: enabled -> MISSED'
Assert-Equal (V User @{ Exists = $true; Enabled = $false; InAdmins = $true; PasswordWorks = $null }) 'PARTIAL' 'user: disabled but still admin -> PARTIAL'
Assert-Equal (V User @{ Exists = $true; Enabled = $false; InAdmins = $false; PasswordWorks = $null }) 'FIXED' 'user: disabled and not admin -> FIXED'
Assert-Equal (V User @{ Exists = $false }) 'PARTIAL' 'user: DELETED -> PARTIAL (plan: never delete)'
Assert-True ((Get-PlantVerdict ([pscustomobject]@{ Kind = 'User'; Name = 'x' }) @{ Exists = $true; Enabled = $true; InAdmins = $true; PasswordWorks = $true }).Note -match 'old password still works') 'user: the note says the old password still works'
Assert-Equal (V Task @{ Exists = $true; Disabled = $false }) 'MISSED' 'task: still enabled -> MISSED'
Assert-Equal (V Task @{ Exists = $true; Disabled = $true }) 'FIXED' 'task: disabled -> FIXED'
Assert-Equal (V Task @{ Exists = $false; Disabled = $false }) 'FIXED' 'task: gone -> FIXED'
Assert-Equal (V RunKey @{ Exists = $true }) 'MISSED' 'run key present -> MISSED'
Assert-Equal (V RunKey @{ Exists = $false }) 'FIXED' 'run key gone -> FIXED'
Assert-Equal (V StartupFile @{ Exists = $true }) 'MISSED' 'startup file present -> MISSED'
Assert-Equal (V StartupFile @{ Exists = $false }) 'FIXED' 'startup file gone -> FIXED'
Assert-Equal (V Service @{ Exists = $true; StartMode = 'Auto'; State = 'Running' }) 'MISSED' 'service auto-start -> MISSED'
Assert-Equal (V Service @{ Exists = $true; StartMode = 'Disabled'; State = 'Stopped' }) 'FIXED' 'service disabled+stopped -> FIXED'
Assert-Equal (V Service @{ Exists = $true; StartMode = 'Disabled'; State = 'Running' }) 'PARTIAL' 'service disabled but running -> PARTIAL'
Assert-Equal (V Service @{ Exists = $false }) 'FIXED' 'service deleted -> FIXED'
Assert-Equal (V Wmi @{ Filter = $true; Consumer = $true; Binding = $true }) 'MISSED' 'wmi: all three left -> MISSED'
Assert-Equal (V Wmi @{ Filter = $false; Consumer = $true; Binding = $false }) 'PARTIAL' 'wmi: consumer left -> PARTIAL'
Assert-Equal (V Wmi @{ Filter = $false; Consumer = $false; Binding = $false }) 'FIXED' 'wmi: none left -> FIXED'
Assert-Equal (V Listener @{ Listening = $true; TaskExists = $true; TaskDisabled = $false }) 'MISSED' 'listener: still listening -> MISSED'
Assert-Equal (V Listener @{ Listening = $false; TaskExists = $true; TaskDisabled = $false }) 'PARTIAL' 'listener: killed but launcher task remains -> PARTIAL'
Assert-Equal (V Listener @{ Listening = $false; TaskExists = $false; TaskDisabled = $false }) 'FIXED' 'listener: closed and launcher gone -> FIXED'
Assert-Equal (V Ifeo @{ Exists = $true }) 'MISSED' 'ifeo present -> MISSED'
Assert-Equal (V Hosts @{ Exists = $false }) 'FIXED' 'hosts line gone -> FIXED'
Assert-Equal (V DefExclusion @{ Exists = $true }) 'MISSED' 'defender exclusion present -> MISSED'
Assert-Equal (V Share @{ Exists = $false }) 'FIXED' 'share gone -> FIXED'
Assert-Equal (V FwRule @{ Exists = $true; AnyEnabled = $true }) 'MISSED' 'firewall rule enabled -> MISSED'
Assert-Equal (V FwRule @{ Exists = $true; AnyEnabled = $false }) 'FIXED' 'firewall rule disabled -> FIXED'
Assert-Equal (V FwRule @{ Exists = $false; AnyEnabled = $false }) 'FIXED' 'firewall rule deleted -> FIXED'
Assert-Equal (V Lockout @{ Threshold = 5 }) 'MISSED' 'lockout 5 -> MISSED'
Assert-Equal (V Lockout @{ Threshold = 0 }) 'FIXED' 'lockout 0 -> FIXED'
Assert-Equal (V Guest @{ Enabled = $true }) 'MISSED' 'Guest enabled -> MISSED'
Assert-Equal (V Guest @{ Enabled = $false }) 'FIXED' 'Guest disabled -> FIXED'
Assert-Equal (V JenkinsInit @{ Exists = $true }) 'MISSED' 'jenkins init script present -> MISSED'
Assert-Equal (V JenkinsJob @{ Exists = $true; Disabled = $true }) 'FIXED' 'jenkins job disabled -> FIXED'
Assert-Equal (V JenkinsJob @{ Exists = $true; Disabled = $false }) 'MISSED' 'jenkins job enabled -> MISSED'
Assert-Equal (V JenkinsUser @{ LoginWorks = $true }) 'MISSED' 'planted jenkins login works -> MISSED'
Assert-Equal (V JenkinsUser @{ LoginWorks = $false }) 'FIXED' 'planted jenkins login refused -> FIXED'
Assert-Equal (V Task @{ Unknown = 'x' }) 'UNKNOWN' 'a fact that could not be read -> UNKNOWN'
Assert-Equal (V Mystery @{ Exists = $true }) 'UNKNOWN' 'a kind with no rule -> UNKNOWN'

# every kind the planner can produce must have a verdict rule
$kinds = @{}
foreach ($lvl in 'Easy', 'Normal', 'Hard') { for ($seed = 1; $seed -le 80; $seed++) { foreach ($p in (New-PlantPlan -Intensity $lvl -Seed $seed).Plants) { $kinds[$p.Kind] = $p } } }
$noRule = @()
foreach ($k in $kinds.Keys) { if ((Get-PlantVerdict $kinds[$k] @{ Exists = $true; Enabled = $true; Filter = $true; Listening = $true; Threshold = 3; LoginWorks = $true; AnyEnabled = $true; InAdmins = $true; StartMode = 'Auto'; State = 'Running' }).Verdict -eq 'UNKNOWN') { $noRule += $k } }
Assert-Equal ($noRule -join ',') '' "every planner kind has a verdict rule ($($kinds.Count) kinds: $(($kinds.Keys | Sort-Object) -join ', '))"

Write-Host 'Summary line' -ForegroundColor Cyan
$rows = @([pscustomobject]@{ Verdict = 'FIXED' }, [pscustomobject]@{ Verdict = 'FIXED' }, [pscustomobject]@{ Verdict = 'PARTIAL' }, [pscustomobject]@{ Verdict = 'N/A' })
Assert-Equal (Get-LabGradeSummary $rows).Status 'WARN' 'summary: a PARTIAL -> WARN'
Assert-True ((Get-LabGradeSummary $rows).Detail -match '2 fixed, 1 partial, 0 missed') 'summary: counts ignore N/A'
Assert-Equal (Get-LabGradeSummary ($rows + [pscustomobject]@{ Verdict = 'MISSED' })).Status 'FAIL' 'summary: a MISSED -> FAIL'
Assert-Equal (Get-LabGradeSummary @([pscustomobject]@{ Verdict = 'FIXED' })).Status 'PASS' 'summary: all fixed -> PASS'

# ------------------------------------------------------------------ fact collection with stubs
Write-Host 'Fact collection with stubs' -ForegroundColor Cyan
$global:Fake = @{ Fixed = $false }
function Join-Path { param($Path, $ChildPath) "$Path\$ChildPath" }       # Linux cannot join 'C:\...' paths
function Get-LocalUser { param($Name) $null = $Name; if ($global:Fake.Fixed) { [pscustomobject]@{ Name = $Name; Enabled = $false } } else { [pscustomobject]@{ Name = $Name; Enabled = $true } } }
function Get-LocalGroupNames { param($g) $null = $g; if ($global:Fake.Fixed) { @('Administrator') } else { @('Administrator', 'PC\svc_sql', 'tfox') } }
function Test-LocalCredential { param($User, $Password) $null = $User, $Password; -not $global:Fake.Fixed }
function Get-ScheduledTask { param($TaskName, $TaskPath) $null = $TaskName, $TaskPath; if (-not $global:Fake.Fixed) { [pscustomobject]@{ State = 'Ready' } } }
function Get-RegValue { param($Path, $Name) $null = $Path, $Name; if ($global:Fake.Fixed) { $null } else { 'cmd.exe /c echo' } }
function Test-Path { param($Path) $null = $Path; -not $global:Fake.Fixed }
function Get-CimInstance { param($ClassName, $Filter) $null = $ClassName, $Filter; if (-not $global:Fake.Fixed) { [pscustomobject]@{ StartMode = 'Auto'; State = 'Running' } } }
function Get-WmiObject { param($Namespace, $Class, $Filter) $null = $Namespace, $Class, $Filter; if (-not $global:Fake.Fixed) { [pscustomobject]@{ Filter = 'DiskHealthFilter'; Consumer = 'DiskHealthFilter' } } }
function Get-NetTCPConnection { param($LocalPort, $State) $null = $LocalPort, $State; if (-not $global:Fake.Fixed) { [pscustomobject]@{ LocalPort = 4444 } } }
function Get-Content { param($Path, [switch]$Raw) $null = $Path, $Raw; if ($global:Fake.Fixed) { @('127.0.0.1 localhost') } else { @('127.0.0.1 localhost', '127.0.0.1 definitionupdates.hlf-cdn.example') } }
function Get-MpPreference { [pscustomobject]@{ ExclusionPath = $(if ($global:Fake.Fixed) { @() } else { @('C:\ProgramData\Updates') }) } }
function Get-SmbShare { param($Name) $null = $Name; if (-not $global:Fake.Fixed) { [pscustomobject]@{ Name = 'Public' } } }
function Get-NetFirewallRule { param($DisplayName) $null = $DisplayName; if (-not $global:Fake.Fixed) { [pscustomobject]@{ Enabled = 'True' } } }
function Test-JenkinsLogin { param($HostName, $Port, $User, $Password) $null = $HostName, $Port, $User, $Password; if ($global:Fake.Fixed) { New-Result 'Jenkins login' 'FAIL' 'login as x refused (HTTP 302)' } else { New-Result 'Jenkins login' 'PASS' 'logged in' } }

$plants = @(
    [pscustomobject]@{ Kind = 'User'; Name = 'svc_sql'; Password = 'Spring2026!' },
    [pscustomobject]@{ Kind = 'Task'; Name = 'DiskCleanupHelper'; Path = '\' },
    [pscustomobject]@{ Kind = 'RunKey'; Name = 'AdobeUpdater'; Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
    [pscustomobject]@{ Kind = 'StartupFile'; Name = 'printfix.bat' },
    [pscustomobject]@{ Kind = 'Service'; Name = 'NetProfileSvc' },
    [pscustomobject]@{ Kind = 'Wmi'; Name = 'DiskHealthFilter' },
    [pscustomobject]@{ Kind = 'Listener'; Name = 'WinSATCache'; Port = 4444 },
    [pscustomobject]@{ Kind = 'Ifeo'; Name = 'sethc.exe' },
    [pscustomobject]@{ Kind = 'Hosts'; Name = '127.0.0.1 definitionupdates.hlf-cdn.example' },
    [pscustomobject]@{ Kind = 'DefExclusion'; Name = 'C:\ProgramData\Updates' },
    [pscustomobject]@{ Kind = 'Share'; Name = 'Public' },
    [pscustomobject]@{ Kind = 'FwRule'; Name = 'Dev Web'; Port = 8000 },
    [pscustomobject]@{ Kind = 'Lockout'; Name = 'AccountLockout'; Threshold = 5 },
    [pscustomobject]@{ Kind = 'Guest'; Name = 'Guest' },
    [pscustomobject]@{ Kind = 'JenkinsInit'; Name = 'cleanup.groovy' },
    [pscustomobject]@{ Kind = 'JenkinsJob'; Name = 'artifact-sync' },
    [pscustomobject]@{ Kind = 'JenkinsUser'; Name = 'svc-ci'; Password = 'Rocket123!' }
)
$global:Fake.Fixed = $false
$bad = @(foreach ($p in $plants) { $f = Get-PlantFacts $p -LockoutThreshold 5 -ProbePasswords $true -JenkinsHome 'C:\J'; (Get-PlantVerdict $p $f).Verdict })
Assert-Equal (($bad | Select-Object -Unique) -join ',') 'MISSED' "untouched fake box: all $($plants.Count) kinds come out MISSED"
$global:Fake.Fixed = $true
$good = @(foreach ($p in $plants) { $f = Get-PlantFacts $p -LockoutThreshold 0 -ProbePasswords $true -JenkinsHome 'C:\J'; (Get-PlantVerdict $p $f).Verdict })
Assert-Equal (($good | Select-Object -Unique) -join ',') 'FIXED' 'fixed fake box: all kinds come out FIXED'
$f = Get-PlantFacts $plants[14] -JenkinsHome ''
Assert-Equal (Get-PlantVerdict $plants[14] $f).Verdict 'UNKNOWN' 'jenkins item with no recorded Jenkins home -> UNKNOWN'
$global:Fake.Fixed = $false
$f = Get-PlantFacts $plants[0] -LockoutThreshold 5 -ProbePasswords $false
Assert-True ($null -eq $f.PasswordWorks) 'password probing can be switched off (lockout set)'

# ------------------------------------------------------------------ round trip with the encrypted key
Write-Host 'Round trip: plan -> encrypted key -> decrypt -> grade' -ForegroundColor Cyan
$plan = New-PlantPlan -Intensity Normal -Seed 777
$planted = @(foreach ($p in $plan.Plants) { $p | Add-Member -NotePropertyName Status -NotePropertyValue 'planted' -Force -PassThru })
$planted[0].Status = 'FAILED: test'
$record = [pscustomobject]@{ Version = 1; ArmedAt = '2026-10-15T10:00:00'; Seed = 777; Intensity = 'Normal'; DefaultPassword = 'x'; Scenario = $plan.Scenario; Plants = $planted
                             AccountsAtArm = @('Administrator', 'jmoney'); JenkinsHome = 'C:\J' }
$tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'grade-key-' + [guid]::NewGuid().ToString('N') + '.bin')
Protect-LabText -Text ($record | ConvertTo-Json -Depth 6) -Passphrase 'pass phrase 1' -Path $tmp
$back = (Unprotect-LabText -Path $tmp -Passphrase 'pass phrase 1') | ConvertFrom-Json
$global:Fake.Fixed = $false
$rows = @(Get-LabGrade -Record $back -LockoutThreshold 5 -ProbePasswords $false)
Assert-Equal $rows.Count $planted.Count 'one grade row per plant'
Assert-Equal @($rows | Where-Object { $_.Verdict -eq 'N/A' }).Count 1 'the plant that failed to plant is ignored (N/A)'
$notNa = @($rows | Where-Object { $_.Verdict -ne 'N/A' })
Assert-True (@($notNa | Where-Object { $_.Verdict -eq 'MISSED' -or $_.Verdict -eq 'PARTIAL' }).Count -ge ($notNa.Count - 2)) 'untouched fake box: nearly everything MISSED or PARTIAL after the JSON round trip'
Assert-Equal (Get-LabGradeSummary $rows).Status 'FAIL' 'untouched box -> FAIL'
$global:Fake.Fixed = $true
$rows = @(Get-LabGrade -Record $back -LockoutThreshold 0 -ProbePasswords $false)
Assert-Equal @($rows | Where-Object { $_.Verdict -eq 'MISSED' }).Count 0 'fixed fake box: nothing MISSED'
Assert-True (@($rows | Where-Object { $_.Item -eq '' }).Count -eq 0) 'every row has a readable item label'
Assert-Equal (Get-AccountsKeptFinding $back).Status 'PASS' 'accounts kept: all still exist'
function Get-LocalUser { param($Name) if ($Name -eq 'jmoney') { $null } else { [pscustomobject]@{ Name = $Name; Enabled = $false } } }
$kept = Get-AccountsKeptFinding $back
Assert-Equal $kept.Status 'FAIL' 'accounts kept: a deleted account -> FAIL'
Assert-True ($kept.Detail -match 'jmoney') 'accounts kept: names the deleted account'
Remove-Item $tmp -ErrorAction SilentlyContinue

Write-TestSummary
