# LabJenkins.ps1  -  LAB ONLY.  Plants / removes the Jenkins items (an init.groovy.d script,
# an extra job, an extra user). Jenkins only reads init.groovy.d at startup, so we restart it.
# New-JenkinsPlantScript is plain text-building (testable anywhere); the rest needs the real box.

function Get-JenkinsInfo {
    # Finds the Jenkins service and JENKINS_HOME (same method as Lab-Setup.ps1). Never hard-coded.
    $svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -like '*jenkins*' -or $_.PathName -like '*jenkins*' } | Select-Object -First 1
    $jHome = $null
    $wrapperXml = 'C:\Program Files\Jenkins\jenkins.xml'
    if (Test-Path $wrapperXml) {
        $raw = Get-Content $wrapperXml -Raw
        if ($raw -match '<env name="JENKINS_HOME" value="([^"]+)"') {
            $jHome = [Environment]::ExpandEnvironmentVariables($matches[1])
        }
    }
    if (-not $jHome) {
        $jHome = @('C:\ProgramData\Jenkins\.jenkins', 'C:\Program Files\Jenkins', 'C:\Program Files (x86)\Jenkins') |
            Where-Object { Test-Path (Join-Path $_ 'config.xml') } | Select-Object -First 1
    }
    [pscustomobject]@{ Service = $svc.Name; Home = $jHome }
}

function New-JenkinsPlantScript {
    # Builds the Groovy text. $Items = the Jenkins plan items (each has Kind, Name, Tag, ...).
    param($Items, [string]$Beacon = 'C:\ProgramData\lab_beacon.log')
    $initItem = $Items | Where-Object Kind -eq 'JenkinsInit' | Select-Object -First 1
    $tag = $initItem.Tag
    $g = New-Object System.Text.StringBuilder
    [void]$g.AppendLine('import jenkins.model.*')
    [void]$g.AppendLine('import hudson.security.*')
    [void]$g.AppendLine('import hudson.model.*')
    [void]$g.AppendLine('import hudson.tasks.BatchFile')
    [void]$g.AppendLine('import hudson.triggers.TimerTrigger')
    [void]$g.AppendLine('def j = Jenkins.get()')
    $beaconGroovy = $Beacon.Replace('\', '/')
    [void]$g.AppendLine("new File('$beaconGroovy').append('$tag jenkins-init ' + new Date() + '\n')")
    foreach ($it in ($Items | Where-Object Kind -eq 'JenkinsJob')) {
        $bat = ("echo $($it.Tag) jenkins-job >> $Beacon").Replace('\', '\\')
        [void]$g.AppendLine("if (j.getItem('$($it.Name)') == null) {")
        [void]$g.AppendLine("  def p = j.createProject(FreeStyleProject, '$($it.Name)')")
        [void]$g.AppendLine("  p.buildersList.add(new BatchFile('$bat'))")
        [void]$g.AppendLine("  p.addTrigger(new TimerTrigger('$($it.Cron)'))")
        [void]$g.AppendLine('  p.save()')
        [void]$g.AppendLine('}')
    }
    foreach ($it in ($Items | Where-Object Kind -eq 'JenkinsUser')) {
        [void]$g.AppendLine('def realm = j.getSecurityRealm()')
        [void]$g.AppendLine("if (realm instanceof HudsonPrivateSecurityRealm && User.getById('$($it.Name)', false) == null) {")
        [void]$g.AppendLine("  realm.createAccount('$($it.Name)', '$($it.Password)')")
        [void]$g.AppendLine('}')
    }
    $g.ToString()
}

function New-JenkinsCleanupScript {
    # Groovy that deletes the jobs/users named in an OLD plan (used when re-arming).
    param($OldItems)
    $g = New-Object System.Text.StringBuilder
    [void]$g.AppendLine('import jenkins.model.*')
    [void]$g.AppendLine('import hudson.model.*')
    [void]$g.AppendLine('def j = Jenkins.get()')
    foreach ($it in ($OldItems | Where-Object Kind -eq 'JenkinsJob')) {
        [void]$g.AppendLine("j.getItem('$($it.Name)')?.delete()")
    }
    foreach ($it in ($OldItems | Where-Object Kind -eq 'JenkinsUser')) {
        [void]$g.AppendLine("User.getById('$($it.Name)', false)?.delete()")
    }
    $g.ToString()
}

function Wait-JenkinsUp {
    # True when Jenkins answers with anything other than 503 ("getting ready").
    param([int]$Seconds = 240)
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        try { Invoke-WebRequest 'http://localhost:8080/login' -UseBasicParsing -TimeoutSec 5 | Out-Null; return $true }
        catch {
            if ($_.Exception.Response -and ([int]$_.Exception.Response.StatusCode) -ne 503) { return $true }
            Start-Sleep 5
        }
    }
    $false
}

function Set-JenkinsPlants {
    # Writes the plant script into init.groovy.d, restarts Jenkins, marks each item planted or failed.
    param($Items, $Info)
    foreach ($it in $Items) {
        $it | Add-Member -NotePropertyName Tag -NotePropertyValue ('b' + (-join ((1..4) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }))) -Force
    }
    $initItem = $Items | Where-Object Kind -eq 'JenkinsInit' | Select-Object -First 1
    $dir = Join-Path $Info.Home 'init.groovy.d'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    New-JenkinsPlantScript -Items $Items | Out-File (Join-Path $dir $initItem.Name) -Encoding ascii
    Restart-Service $Info.Service -ErrorAction Stop
    $up = Wait-JenkinsUp
    foreach ($it in $Items) {
        $it | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($up) { 'planted' } else { 'FAILED: Jenkins did not come back' }) -Force
    }
    $Items
}

function Remove-OldJenkinsPlants {
    # Runs a one-off cleanup script for the previous run's jobs/users, then removes old init files.
    param($OldItems, $Info)
    if (-not $OldItems) { return }
    $dir = Join-Path $Info.Home 'init.groovy.d'
    foreach ($it in ($OldItems | Where-Object Kind -eq 'JenkinsInit')) { Remove-Item (Join-Path $dir $it.Name) -ErrorAction SilentlyContinue }
    $tmp = Join-Path $dir 'zz-lab-cleanup.groovy'
    New-JenkinsCleanupScript -OldItems $OldItems | Out-File $tmp -Encoding ascii
    Restart-Service $Info.Service -ErrorAction SilentlyContinue
    [void](Wait-JenkinsUp)
    Remove-Item $tmp -ErrorAction SilentlyContinue
}
