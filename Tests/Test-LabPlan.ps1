# Test-LabPlan.ps1 - checks the randomizer: repeatable, varied, no name clashes, sane counts.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\Lab\LabPlan.ps1"

Write-Host "LabPlan tests" -ForegroundColor Cyan

# same seed -> same plan; different seed -> different plan
$a = New-PlantPlan -Intensity Normal -Seed 1234
$b = New-PlantPlan -Intensity Normal -Seed 1234
$c = New-PlantPlan -Intensity Normal -Seed 9999
Assert-Equal ($a | ConvertTo-Json -Depth 6 -Compress) ($b | ConvertTo-Json -Depth 6 -Compress) 'same seed gives the same plan'
Assert-True (($a | ConvertTo-Json -Depth 6 -Compress) -ne ($c | ConvertTo-Json -Depth 6 -Compress)) 'different seed gives a different plan'

# run many seeds at every level and check the rules
foreach ($lvl in 'Easy', 'Normal', 'Hard') {
    $bad = @()
    for ($seed = 1; $seed -le 200; $seed++) {
        $p = New-PlantPlan -Intensity $lvl -Seed $seed
        $users = @($p.Plants | Where-Object Kind -eq 'User')
        $ids   = @($p.Plants.Id)
        if ($users.Count -ne $script:Levels[$lvl].Users)           { $bad += "seed $seed users count" }
        if (@($users | Where-Object Admin).Count -lt 1)            { $bad += "seed $seed no admin user" }
        if (($ids | Select-Object -Unique).Count -ne $ids.Count)   { $bad += "seed $seed duplicate ids" }
        $uNames = @($users.Name)
        if (($uNames | Select-Object -Unique).Count -ne $uNames.Count) { $bad += "seed $seed duplicate user names" }
        if ($uNames -contains 'plinktern' -or $uNames -contains 'jmoney') { $bad += "seed $seed touches a protected account" }
        if (@($p.Plants | Where-Object Kind -eq 'FwRule').Count -ne $script:Levels[$lvl].Fw) { $bad += "seed $seed fw count" }
        $ports = @($p.Plants | Where-Object Kind -eq 'FwRule' | ForEach-Object Port)
        if ($ports -contains 3389 -or $ports -contains 8080) { $bad += "seed $seed plants a rule on a scored port" }
        $mech = @($p.Plants | Where-Object { $_.Kind -notin 'User','FwRule','Lockout','Guest','JenkinsInit','JenkinsJob','JenkinsUser' })
        if ($mech.Count -ne $script:Levels[$lvl].Mech) { $bad += "seed $seed mechanism count $($mech.Count)" }
        if (($mech.Kind | Select-Object -Unique).Count -ne $mech.Count) { $bad += "seed $seed repeated mechanism kind" }
        if ($lvl -eq 'Easy' -and (@($p.Plants | Where-Object Kind -eq 'Lockout').Count -gt 0)) { $bad += "seed $seed easy has lockout" }
        if ($lvl -eq 'Easy' -and (@($p.Plants | Where-Object Kind -like 'Jenkins*').Count -gt 0)) { $bad += "seed $seed easy has jenkins" }
    }
    Assert-Equal ($bad -join '; ') '' "$lvl : 200 seeds follow the rules"
}

# variety: over 200 Normal seeds, many different kinds and several different user names appear
$kindsSeen = @{}; $namesSeen = @{}
for ($seed = 1; $seed -le 200; $seed++) {
    foreach ($s in (New-PlantPlan -Intensity Normal -Seed $seed).Plants) { $kindsSeen[$s.Kind] = 1; if ($s.Kind -eq 'User') { $namesSeen[$s.Name] = 1 } }
}
Assert-True ($kindsSeen.Count -ge 12) "variety of plant kinds ($($kindsSeen.Count) seen)"
Assert-True ($namesSeen.Count -ge 25) "variety of user names ($($namesSeen.Count) seen)"

# Scenario flags exist and the plan serializes to JSON (that is how the key is stored)
$j = $a | ConvertTo-Json -Depth 6
$back = $j | ConvertFrom-Json
Assert-Equal $back.Plants.Count $a.Plants.Count 'plan survives JSON round trip'
Assert-True ($null -ne $back.Scenario.JmoneyIsAdmin) 'scenario flags present'
Write-TestSummary
