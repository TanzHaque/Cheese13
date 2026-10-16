# LabPlan.ps1  -  LAB ONLY.  Decides WHAT to plant. It changes nothing on the box (pure logic),
# so it can be tested anywhere. LabPlants.ps1 does the actual planting from this plan.
#
# Everything planted is harmless: it only appends a line to the beacon log or opens a port.

$script:Pools = @{
    UserNames = @('kkiderchah','jbrewer','schef','rocket.eng','intern01','helpdesk','svc_backup','old.employee',
                  'dmiller','tfox','svc_sql','svc_deploy','mlopez','launchops','telemetry','horseshoe','stablehand',
                  'qa.tester','contractor1','jenkins.svc','backupadmin','vendor.support','labtech','plinkbot',
                  'nwilson','agarcia','rpatel','sauce.qa','padlock','moonbase')
    WeakPasswords = @('Password1','Welcome1!','Summer2026!','Rocket123!','Qwerty123','Letmein1!','Plinko2026!',
                      'Horse123!','Changeme1','P@ssw0rd','Fall2026!','Sauce4Life!','Spring2026!','Winter2026!')
    TaskNames = @('GoogleUpdateTaskMachineQC','AdobeFlashPlayerUpdate','WindowsDefenderCacheMaintenance','NvTmRepOnLogon',
                  'IntelDriverUpdate','SystemTelemetryCollect','MicrosoftEdgeUpdateBrowserReplacement','DiskCleanupHelper',
                  'JavaUpdateSched','OneDriveStandaloneUpdateTask','WinSATCache','LogRotateHelper')
    TaskPaths = @('\','\Microsoft\Windows\Maintenance\','\Microsoft\Windows\WindowsUpdate\','\Microsoft\Office\')
    ServiceNames = @('WindowsTimeSyncHelper','SysMonHelperSvc','NetProfileSvc','DiagTrackHelper','UpdateOrchestratorSvc2',
                     'PrintSpoolerHelper','ClipSvcExt','AudioEndpointHelper')
    RunNames = @('SecurityHealthTray','WindowsUpdateAssistant','AdobeUpdater','RealtekAudioHD','IntelGfxTray','DiscordUpdate',
                 'JavaSchedulerX','OfficeClickToRunHelper')
    StartupFiles = @('sysmon-helper.cmd','printfix.bat','telemetry.cmd','onedrive-sync.bat','chkdsk-run.bat','netcheck.cmd')
    WmiNames = @('ProcessMonFilter','NetCheckFilter','BatteryEventFilter','DiskHealthFilter','TimeSyncFilter')
    IfeoExes = @('sethc.exe','utilman.exe','magnify.exe','narrator.exe','osk.exe')
    Ports = @(4444,1337,31337,9001,8888,5555,6667,7777)
    FwNames = @('Dev Web','Allow Debug','Test Port','Remote Support','Windows Update Delivery','Media Share','App Telemetry','Remote Assist TCP-In')
    FwPorts = @(21,23,69,445,3306,4444,5985,8000,8888,9001,1337,31337,5900,2222)
    ShareNames = @('Backup$','Public','Data','ShipLogs','Dropbox','Temp')
    HostsLines = @('127.0.0.1 definitionupdates.hlf-cdn.example','0.0.0.0 av-updates.hlf-cdn.example',
                   '10.66.6.6 telemetry.hlf-cdn.example','127.0.0.1 patches.hlf-cdn.example')
    ExclusionDirs = @('C:\ProgramData\Updates','C:\Windows\Temp\cache','C:\Users\Public\Libraries','C:\PerfLogs\sys')
    JenkinsJobs = @('nightly-cleanup','artifact-sync','telemetry-upload','env-check','log-archive')
    JenkinsUsers = @('svc-ci','deploy','build.bot','ops','release.mgr')
    JenkinsInits = @('startup-check.groovy','cleanup.groovy','plugins-fix.groovy','env-init.groovy')
}

# How many of each thing per difficulty.
$script:Levels = @{
    Easy   = @{ Users = 3; Mech = 3; Fw = 2; Jenkins = 0; MechKinds = 4 }
    Normal = @{ Users = 5; Mech = 5; Fw = 3; Jenkins = 2; MechKinds = 8 }
    Hard   = @{ Users = 8; Mech = 8; Fw = 4; Jenkins = 3; MechKinds = 10 }
}

function Select-Names {
    # Pick $Count different items from a pool, in random order.
    param([string[]]$Pool, [int]$Count)
    @(Get-Random -InputObject $Pool -Count ([Math]::Min($Count, $Pool.Count)))
}

function New-PlantPlan {
    param(
        [ValidateSet('Easy', 'Normal', 'Hard')][string]$Intensity = 'Normal',
        [int]$Seed = 0
    )
    if ($Seed -eq 0) { $Seed = [int]((Get-Date).Ticks % 2000000000) + 1 }
    Get-Random -SetSeed $Seed | Out-Null          # same seed = same plan (so a run can be replayed)

    $lv    = $script:Levels[$Intensity]
    $specs = New-Object System.Collections.ArrayList

    # ---- users: always at least one extra admin; the rest are a random mix
    $userNames = Select-Names $script:Pools.UserNames $lv.Users
    $typePool  = @('Admin','Admin','Weak','Weak','Weak','Blank','Dollar','SvcAdmin')
    $types     = @('Admin') + @(Get-Random -InputObject $typePool -Count ($lv.Users - 1))
    for ($i = 0; $i -lt $lv.Users; $i++) {
        $t = $types[$i % $types.Count]
        $name = $userNames[$i]
        if ($t -eq 'Dollar') { $name = ($name -replace '[^a-z0-9]', '') + '$' }
        if ($t -eq 'SvcAdmin' -and $name -notlike 'svc*') { $name = 'svc_' + ($name -replace '[^a-z0-9]', '') }
        $pw = if ($t -eq 'Blank') { '' } else { Get-Random -InputObject $script:Pools.WeakPasswords }
        $isAdmin = $t -in @('Admin', 'Dollar', 'SvcAdmin')
        [void]$specs.Add([pscustomobject]@{
            Kind = 'User'; Name = $name; Password = $pw; Admin = $isAdmin
            Rdp = (($t -ne 'SvcAdmin') -and ((Get-Random -Maximum 100) -lt 70))
            NeverExpires = ($t -eq 'SvcAdmin')
            Expect = 'disable (never delete); remove from Administrators; old password must stop working'
        })
    }

    # ---- persistence / backdoor mechanisms (distinct kinds, random names)
    $kinds = @('Task','RunKey','StartupFile','Service','Wmi','Listener','Ifeo','Hosts','DefExclusion','Share')
    $kinds = $kinds[0..($lv.MechKinds - 1)]
    foreach ($k in (Get-Random -InputObject $kinds -Count ([Math]::Min($lv.Mech, $kinds.Count)))) {
        switch ($k) {
            'Task' { [void]$specs.Add([pscustomobject]@{ Kind='Task'; Name=(Get-Random -InputObject $script:Pools.TaskNames)
                        Path=(Get-Random -InputObject $script:Pools.TaskPaths); Minutes=(Get-Random -InputObject @(2,3,5,10)); Expect='task removed or disabled' }) }
            'RunKey' { [void]$specs.Add([pscustomobject]@{ Kind='RunKey'; Name=(Get-Random -InputObject $script:Pools.RunNames)
                        Key=(Get-Random -InputObject @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'))
                        Expect='Run value removed' }) }
            'StartupFile' { [void]$specs.Add([pscustomobject]@{ Kind='StartupFile'; Name=(Get-Random -InputObject $script:Pools.StartupFiles); Expect='file removed/moved' }) }
            'Service' { [void]$specs.Add([pscustomobject]@{ Kind='Service'; Name=(Get-Random -InputObject $script:Pools.ServiceNames)
                        Where=(Get-Random -InputObject @('C:\Windows\Temp','C:\ProgramData','C:\Users\Public')); Expect='service removed or disabled (not auto-start)' }) }
            'Wmi' { [void]$specs.Add([pscustomobject]@{ Kind='Wmi'; Name=(Get-Random -InputObject $script:Pools.WmiNames)
                        Minute=(Get-Random -Minimum 0 -Maximum 60); Expect='WMI filter + consumer + binding removed' }) }
            'Listener' { [void]$specs.Add([pscustomobject]@{ Kind='Listener'; Port=(Get-Random -InputObject $script:Pools.Ports)
                        Name=(Get-Random -InputObject $script:Pools.TaskNames); Expect='nothing listening on the port; launcher task gone' }) }
            'Ifeo' { [void]$specs.Add([pscustomobject]@{ Kind='Ifeo'; Name=(Get-Random -InputObject $script:Pools.IfeoExes); Expect='IFEO Debugger value removed' }) }
            'Hosts' { [void]$specs.Add([pscustomobject]@{ Kind='Hosts'; Name=(Get-Random -InputObject $script:Pools.HostsLines); Expect='hosts line removed' }) }
            'DefExclusion' { [void]$specs.Add([pscustomobject]@{ Kind='DefExclusion'; Name=(Get-Random -InputObject $script:Pools.ExclusionDirs); Expect='Defender exclusion removed' }) }
            'Share' { [void]$specs.Add([pscustomobject]@{ Kind='Share'; Name=(Get-Random -InputObject $script:Pools.ShareNames); Expect='share removed' }) }
        }
    }

    # ---- sloppy inbound firewall rules
    $fwNames = Select-Names $script:Pools.FwNames $lv.Fw
    $fwPorts = @(Get-Random -InputObject $script:Pools.FwPorts -Count $lv.Fw)
    for ($i = 0; $i -lt $lv.Fw; $i++) {
        [void]$specs.Add([pscustomobject]@{ Kind='FwRule'; Name=$fwNames[$i]; Port=$fwPorts[$i]; Expect='rule disabled or removed (3389 and 8080 stay open)' })
    }

    # ---- Jenkins plants (need a Jenkins restart; Reset-LabInsecure does that once)
    if ($lv.Jenkins -ge 1) { [void]$specs.Add([pscustomobject]@{ Kind='JenkinsInit'; Name=(Get-Random -InputObject $script:Pools.JenkinsInits); Expect='init.groovy.d script removed/quarantined' }) }
    if ($lv.Jenkins -ge 2) { [void]$specs.Add([pscustomobject]@{ Kind='JenkinsJob'; Name=(Get-Random -InputObject $script:Pools.JenkinsJobs); Cron='H/10 * * * *'; Expect='job disabled or removed' }) }
    if ($lv.Jenkins -ge 3) { [void]$specs.Add([pscustomobject]@{ Kind='JenkinsUser'; Name=(Get-Random -InputObject $script:Pools.JenkinsUsers)
                        Password=(Get-Random -InputObject $script:Pools.WeakPasswords); Expect='Jenkins user removed or password changed' }) }

    # ---- policy / account switches that make the box worse
    $lock = 0
    if ($Intensity -ne 'Easy') { $lock = Get-Random -InputObject @(0, 3, 5, 10) }
    if ($lock -gt 0) { [void]$specs.Add([pscustomobject]@{ Kind='Lockout'; Name='AccountLockout'; Threshold=$lock; Expect='lockout threshold back to 0 (never lock)' }) }
    if ((Get-Random -Maximum 100) -lt 60) { [void]$specs.Add([pscustomobject]@{ Kind='Guest'; Name='Guest'; Expect='Guest account disabled' }) }

    # ---- shuffle so the order gives nothing away, then number them
    $shuffled = @(Get-Random -InputObject @($specs) -Count $specs.Count)
    $n = 0
    foreach ($s in $shuffled) { $n++; $s | Add-Member -NotePropertyName Id -NotePropertyValue ('P{0:D2}' -f $n) }

    [pscustomobject]@{
        Seed      = $Seed
        Intensity = $Intensity
        Scenario  = [pscustomobject]@{
            # facts about the box that change what the right answer is (not graded, but shown to Verify)
            JmoneyIsAdmin       = ((Get-Random -Maximum 100) -lt $(if ($Intensity -eq 'Easy') { 25 } else { 50 }))
            BuiltinAdminEnabled = ((Get-Random -Maximum 100) -lt 50)
            PublicProfile       = ($Intensity -ne 'Easy' -and (Get-Random -Maximum 100) -lt 30)
        }
        Plants    = $shuffled
    }
}
