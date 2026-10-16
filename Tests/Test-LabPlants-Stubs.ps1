# Test-LabPlants-Stubs.ps1 - checks the GLUE between the planner and the planting/cleanup code.
# Windows commands are replaced by "recorders", so this runs on Linux. It proves property names line up,
# every plant kind is dispatched, and nothing throws. It does NOT prove Windows accepts the commands.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\Lab\LabPlan.ps1"
. "$PSScriptRoot\..\Lab\LabPlants.ps1"
. "$PSScriptRoot\..\Lab\LabCleanup.ps1"
. "$PSScriptRoot\..\Lab\LabJenkins.ps1"

$global:Calls = New-Object System.Collections.ArrayList
function Rec { param($n, $a) [void]$global:Calls.Add("$n " + ($a -join ' ')) }

# --- recorders for every Windows-only command the plant/cleanup code calls
function New-LocalUser { Rec 'New-LocalUser' $args }
function Remove-LocalUser { Rec 'Remove-LocalUser' $args }
function Add-LocalGroupMember { Rec 'Add-LocalGroupMember' $args }
function Enable-LocalUser { Rec 'Enable-LocalUser' $args }
function New-ScheduledTaskAction { Rec 'New-ScheduledTaskAction' $args; 'action' }
function New-ScheduledTaskTrigger { Rec 'New-ScheduledTaskTrigger' $args; 'trigger' }
function Register-ScheduledTask { Rec 'Register-ScheduledTask' $args }
function Start-ScheduledTask { Rec 'Start-ScheduledTask' $args }
function Unregister-ScheduledTask { Rec 'Unregister-ScheduledTask' $args }
function Set-WmiInstance { Rec 'Set-WmiInstance' $args; 'wmi-obj' }
function Get-WmiObject { Rec 'Get-WmiObject' $args }
function Remove-WmiObject { Rec 'Remove-WmiObject' $args }
function Add-MpPreference { Rec 'Add-MpPreference' $args }
function Remove-MpPreference { Rec 'Remove-MpPreference' $args }
function Get-MpPreference {
    # pretend Defender accepted every exclusion we added (path = the word after -ExclusionPath)
    [pscustomobject]@{ ExclusionPath = @($global:Calls | ForEach-Object {
        if ($_ -like 'Add-MpPreference*') { $w = $_ -split ' '; $w[[array]::IndexOf($w, '-ExclusionPath') + 1] } }) }
}
function Join-Path { param($Path, $ChildPath) "$Path\$ChildPath" }   # Linux cannot join 'C:\...' paths
function New-SmbShare { Rec 'New-SmbShare' $args }
function Remove-SmbShare { Rec 'Remove-SmbShare' $args }
function New-NetFirewallRule { Rec 'New-NetFirewallRule' $args }
function Remove-NetFirewallRule { Rec 'Remove-NetFirewallRule' $args }
function Get-NetTCPConnection { Rec 'Get-NetTCPConnection' $args }
function sc.exe { Rec 'sc.exe' $args; $global:LASTEXITCODE = 0 }
function net.exe { Rec 'net.exe' $args; $global:LASTEXITCODE = 0 }
function Out-File { Rec 'Out-File' $args }
function Add-Content { Rec 'Add-Content' $args }
function Set-Content { Rec 'Set-Content' $args }
function New-Item { Rec 'New-Item' $args }
function Remove-Item { Rec 'Remove-Item' $args }
function New-ItemProperty { Rec 'New-ItemProperty' $args }
function Remove-ItemProperty { Rec 'Remove-ItemProperty' $args }
function Stop-Process { Rec 'Stop-Process' $args }
function Get-Content { @('127.0.0.1 localhost') }

Write-Host "LabPlants glue tests (stubbed Windows)" -ForegroundColor Cyan

$allKinds = @{}
$failures = @()
foreach ($lvl in 'Easy', 'Normal', 'Hard') {
    for ($seed = 1; $seed -le 60; $seed++) {
        $plan = New-PlantPlan -Intensity $lvl -Seed $seed
        $global:Calls.Clear()
        foreach ($item in ($plan.Plants | Where-Object { $_.Kind -notlike 'Jenkins*' })) {
            $r = Add-OnePlant $item
            $allKinds[$r.Kind] = 1
            if ($r.Status -ne 'planted') { $failures += "$lvl seed ${seed}: $($r.Kind) $($r.Name) -> $($r.Status)" }
            if (-not $r.Tag) { $failures += "$lvl seed ${seed}: $($r.Kind) has no Tag" }
            Remove-OnePlant $r      # cleanup must also run without throwing
        }
    }
}
Assert-Equal ($failures -join "`n") '' 'every non-Jenkins plant kind plants and cleans up without error (540 plans)'
Assert-True ($allKinds.Count -ge 12) "kinds exercised: $($allKinds.Count) ($(($allKinds.Keys | Sort-Object) -join ', '))"

# a few specific expectations on what gets sent to Windows
$global:Calls.Clear()
$u = [pscustomobject]@{ Kind='User'; Name='tfox'; Password='Password1'; Admin=$true; Rdp=$true; NeverExpires=$false }
[void](Add-OnePlant $u)
Assert-True ($global:Calls -match 'New-LocalUser .*tfox') 'User: New-LocalUser called with the name'
Assert-True ($global:Calls -match 'Add-LocalGroupMember .*Administrators') 'User: admin item joins Administrators'
$global:Calls.Clear()
$svc = [pscustomobject]@{ Kind='Service'; Name='NetProfileSvc'; Where='C:\ProgramData' }
[void](Add-OnePlant $svc)
Assert-True (($global:Calls -match '^sc.exe create NetProfileSvc').Count -eq 1) 'Service: sc.exe create called once'
$global:Calls.Clear()
$fw = [pscustomobject]@{ Kind='FwRule'; Name='Dev Web'; Port=8000 }
[void](Add-OnePlant $fw)
Assert-True ($global:Calls -match 'New-NetFirewallRule .*Dev Web.*8000') 'FwRule: rule created with name and port'

# Jenkins script text
$items = @(
    [pscustomobject]@{ Kind='JenkinsInit'; Name='cleanup.groovy'; Tag='b1a2' },
    [pscustomobject]@{ Kind='JenkinsJob'; Name='artifact-sync'; Tag='b3c4'; Cron='H/10 * * * *' },
    [pscustomobject]@{ Kind='JenkinsUser'; Name='svc-ci'; Tag='b5d6'; Password='Rocket123!' }
)
$g = New-JenkinsPlantScript -Items $items
Assert-True ($g.Contains("createProject(FreeStyleProject, 'artifact-sync')")) 'Groovy: creates the planted job'
Assert-True ($g.Contains("createAccount('svc-ci', 'Rocket123!')")) 'Groovy: creates the planted user'
Assert-True ($g.Contains('b1a2 jenkins-init')) 'Groovy: init beacon carries its tag'
Assert-True ($g.Contains('C:\\ProgramData\\lab_beacon.log')) 'Groovy: batch step path has doubled backslashes'
Assert-True (-not ($g -match '[^\x00-\x7F]')) 'Groovy: ASCII only'
$open = ([regex]::Matches($g, '\{')).Count; $close = ([regex]::Matches($g, '\}')).Count
Assert-Equal $open $close 'Groovy: braces balance'
$clean = New-JenkinsCleanupScript -OldItems $items
Assert-True ($clean.Contains("getItem('artifact-sync')?.delete()")) 'Cleanup groovy removes the old job'
Assert-True ($clean.Contains("getById('svc-ci', false)?.delete()")) 'Cleanup groovy removes the old user'

# Get-StrayUsers only LISTS accounts. It must skip baseline accounts, service accounts, the running account and -Keep names.
function Get-LocalUser { 'Administrator', 'Guest', 'jmoney', 'plinktern', 'ops-9k2', 'refbot', 'svcacct', 'me' | ForEach-Object { [pscustomobject]@{ Name = $_ } } }
function Get-CimInstance { [pscustomobject]@{ StartName = 'LocalSystem' }; [pscustomobject]@{ StartName = '.\svcacct' }; [pscustomobject]@{ StartName = $null } }
$env:USERNAME = 'me'
Assert-Equal ((Get-StrayUsers -Keep @('refbot')) -join ',') 'ops-9k2' 'stray users: only the leftover admin is offered (not baseline, service, running or -Keep accounts)'
Assert-Equal ((Get-StrayUsers) -join ',') 'ops-9k2,refbot' 'stray users: without -Keep the referee account would be offered (and Reset asks before deleting)'
Write-TestSummary
