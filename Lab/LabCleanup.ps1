# LabCleanup.ps1  -  LAB ONLY.  Removes the plants from the previous run, the ORIGINAL Lab-Setup.ps1
# plants (so nothing stays memorized), and sets the baseline accounts. Everything here is tolerant:
# a missing item is not an error. (The real hardening tool never deletes accounts; this lab reset does, but only after asking.)

$script:OriginalLab = @{
    Users       = @('kkiderchah','jbrewer','schef','rocket.eng','intern01','helpdesk','svc_backup','old.employee','support$','testuser')
    Task        = 'MicrosoftEdgeUpdateTaskCore2'
    RunValue    = 'OneDriveSyncHelper'
    StartupFile = 'update.bat'
    Service     = 'WinSvcHelper'
    Wmi         = @('SysHealthFilter', 'SysHealthConsumer')
    Share       = 'ShipData'
    FwRules     = @('Legacy FTP','Telnet Test','Dev Web','Remote Debug','WinRM Any','Temp SMB')
}
$script:StartupDir = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'

function Remove-WmiPlant {
    param([string]$Name)
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Where-Object { $_.Filter -like "*$Name*" -or $_.Consumer -like "*$Name*" } | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$Name'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$Name'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
}

function Remove-OnePlant {
    param($s)
    switch ($s.Kind) {
        'User'         { Remove-LocalUser -Name $s.Name -ErrorAction SilentlyContinue }
        'Task'         { Unregister-ScheduledTask -TaskName $s.Name -TaskPath $s.Path -Confirm:$false -ErrorAction SilentlyContinue }
        'RunKey'       { Remove-ItemProperty -Path $s.Key -Name $s.Name -ErrorAction SilentlyContinue }
        'StartupFile'  { Remove-Item (Join-Path $script:StartupDir $s.Name) -ErrorAction SilentlyContinue }
        'Service'      {
            sc.exe stop $s.Name 2>&1 | Out-Null
            sc.exe delete $s.Name 2>&1 | Out-Null
            Remove-Item (Join-Path $s.Where ($s.Name + '.bat')) -ErrorAction SilentlyContinue
        }
        'Wmi'          { Remove-WmiPlant -Name $s.Name }
        'Listener'     {
            Get-NetTCPConnection -LocalPort $s.Port -State Listen -ErrorAction SilentlyContinue |
                ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
            Unregister-ScheduledTask -TaskName $s.Name -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue
        }
        'Ifeo'         { Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($s.Name)" -ErrorAction SilentlyContinue }
        'Hosts'        {
            $h = "$env:SystemRoot\System32\drivers\etc\hosts"
            $keep = @(Get-Content $h | Where-Object { $_ -ne $s.Name })
            Set-Content -Path $h -Value $keep -Encoding ascii
        }
        'DefExclusion' { Remove-MpPreference -ExclusionPath $s.Name -ErrorAction SilentlyContinue }
        'Share'        { Remove-SmbShare -Name $s.Name -Force -ErrorAction SilentlyContinue }
        'FwRule'       { Remove-NetFirewallRule -DisplayName $s.Name -ErrorAction SilentlyContinue }
        default        { }   # Lockout, Guest: reset by Set-LabBaseline. Jenkins: Remove-OldJenkinsPlants.
    }
}

function Remove-OriginalLabPlants {
    # The items Lab-Setup.ps1 planted. Keeps RDP, jmoney, plinktern, Jenkins and the 'Jenkins 8080' rule.
    $o = $script:OriginalLab
    foreach ($u in $o.Users) { Remove-LocalUser -Name $u -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $o.Task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $o.RunValue -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $script:StartupDir $o.StartupFile) -ErrorAction SilentlyContinue
    sc.exe delete $o.Service 2>&1 | Out-Null
    foreach ($w in $o.Wmi) { Remove-WmiPlant -Name $w }
    Remove-SmbShare -Name $o.Share -Force -ErrorAction SilentlyContinue
    foreach ($r in $o.FwRules) { Remove-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue }
    # the old plain-text answer key from Lab-Setup.ps1 lists the OLD plants, so it is stale and misleading
    Remove-Item 'C:\LabAnswerKey.txt' -ErrorAction SilentlyContinue
}

function Get-StrayUsers {
    # Local accounts that are not part of the lab baseline (for example the new admin the hardening tool made last time).
    # It only LISTS them; Reset-LabInsecure.ps1 asks before deleting. It never lists: the account you are running as,
    # accounts that run a service, and the names you pass in -Keep (for example the account a referee logs in with).
    param([string[]]$Keep)
    $serviceAccounts = @(Get-CimInstance Win32_Service | ForEach-Object { $_.StartName } | Where-Object { $_ } | ForEach-Object { $_ -replace '^.*\\', '' })
    $baseline = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'plinktern', 'jmoney') + @($Keep) + $serviceAccounts + @($env:USERNAME)
    @((Get-LocalUser).Name | Where-Object { $baseline -notcontains $_ })
}

function Set-LabBaseline {
    # Puts the always-true parts back: plinktern + jmoney with the packet password, RDP on, Jenkins port open.
    # $Scenario comes from the plan (is jmoney an admin? is the built-in Administrator on? Public profile?).
    param([string]$DefaultPassword, $Scenario)
    $sec = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
    foreach ($n in 'plinktern', 'jmoney') {
        if (Get-LocalUser -Name $n -ErrorAction SilentlyContinue) { Set-LocalUser -Name $n -Password $sec; Enable-LocalUser -Name $n }
        else { New-LocalUser -Name $n -Password $sec -PasswordNeverExpires -AccountNeverExpires | Out-Null }
        Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $n -ErrorAction SilentlyContinue
    }
    Add-LocalGroupMember -Group 'Administrators' -Member 'plinktern' -ErrorAction SilentlyContinue
    if ($Scenario.JmoneyIsAdmin) { Add-LocalGroupMember -Group 'Administrators' -Member 'jmoney' -ErrorAction SilentlyContinue }
    else { Remove-LocalGroupMember -Group 'Administrators' -Member 'jmoney' -ErrorAction SilentlyContinue }

    if ($env:USERNAME -ne 'Administrator') {
        if ($Scenario.BuiltinAdminEnabled) { Set-LocalUser -Name 'Administrator' -Password $sec; Enable-LocalUser -Name 'Administrator' }
        else { Disable-LocalUser -Name 'Administrator' }
    }
    Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    net.exe accounts /lockoutthreshold:0 | Out-Null

    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
    Set-Service TermService -StartupType Automatic
    Start-Service TermService -ErrorAction SilentlyContinue
    if (-not (Get-NetFirewallRule -DisplayName 'Jenkins 8080' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'Jenkins 8080' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow -Profile Any | Out-Null
    }
    $cat = if ($Scenario.PublicProfile) { 'Public' } else { 'Private' }
    Get-NetConnectionProfile -ErrorAction SilentlyContinue | Set-NetConnectionProfile -NetworkCategory $cat -ErrorAction SilentlyContinue
}
