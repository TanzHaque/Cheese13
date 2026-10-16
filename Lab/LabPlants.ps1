# LabPlants.ps1  -  LAB ONLY.  Plants ONE item from the plan on this box.
# Every planted item is harmless: it only appends a tagged line to the beacon log or opens a port.
# Each function takes one plan item ($s) and throws if it fails (the caller records the failure).
# NOT testable on Linux: these call Windows cmdlets. Test them in the lab (see Reset-LabInsecure.ps1).

$script:Beacon = 'C:\ProgramData\lab_beacon.log'

function Get-BeaconCommand {
    # The one-line command every planted item runs. Tag = random label so the log shows WHICH item fired.
    param([string]$Tag)
    "cmd.exe /c echo $Tag %date% %time% >> $script:Beacon"
}

function Add-PlantUser {
    param($s)
    if ($s.Password -eq '') {
        New-LocalUser -Name $s.Name -NoPassword -Description 'temp account' | Out-Null
    } else {
        $sec = ConvertTo-SecureString $s.Password -AsPlainText -Force
        New-LocalUser -Name $s.Name -Password $sec -Description 'imported account' `
            -PasswordNeverExpires:([bool]$s.NeverExpires) | Out-Null
    }
    if ($s.Admin) { Add-LocalGroupMember -Group 'Administrators' -Member $s.Name }
    if ($s.Rdp)   { Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $s.Name }
}

function Add-PlantTask {
    param($s)
    $act = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c echo $($s.Tag) %date% %time% >> $script:Beacon"
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes $s.Minutes) -RepetitionDuration (New-TimeSpan -Days 3650)
    Register-ScheduledTask -TaskName $s.Name -TaskPath $s.Path -Action $act -Trigger $trg `
        -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
}

function Add-PlantRunKey {
    param($s)
    New-ItemProperty -Path $s.Key -Name $s.Name -Value (Get-BeaconCommand $s.Tag) -Force | Out-Null
}

function Add-PlantStartupFile {
    param($s)
    $dir = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
    "@echo $($s.Tag) %date% %time% >> $script:Beacon" | Out-File (Join-Path $dir $s.Name) -Encoding ascii
}

function Add-PlantService {
    # A service that runs a small .bat at boot. (The bat just appends to the beacon log.)
    param($s)
    $bat = Join-Path $s.Where ($s.Name + '.bat')
    "@echo $($s.Tag) %date% %time% >> $script:Beacon" | Out-File $bat -Encoding ascii
    sc.exe create $s.Name binPath= "cmd.exe /c $bat" start= auto DisplayName= "Windows $($s.Name)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed ($LASTEXITCODE)" }
}

function Add-PlantWmi {
    # Same pattern as Lab-Setup.ps1: filter + consumer + binding, fires once an hour.
    param($s)
    $q = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Minute=$($s.Minute) AND TargetInstance.Second=0"
    $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name = $s.Name; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'; Query = $q }
    $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
        Name = $s.Name; CommandLineTemplate = (Get-BeaconCommand $s.Tag) }
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c } | Out-Null
}

function Add-PlantListener {
    # A hidden PowerShell that only holds a TCP port open (a stand-in for a C2 listener).
    param($s)
    $code = '$l=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any,__PORT__);$l.Start();while($true){Start-Sleep 60}'
    $code = $code.Replace('__PORT__', [string]$s.Port)
    $enc  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    $act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $enc"
    $trg  = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName $s.Name -TaskPath '\' -Action $act -Trigger $trg -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $s.Name
}

function Add-PlantIfeo {
    param($s)
    $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($s.Name)"
    New-Item -Path $k -Force | Out-Null
    New-ItemProperty -Path $k -Name Debugger -Value (Get-BeaconCommand $s.Tag) -Force | Out-Null
}

function Add-PlantHosts {
    param($s)
    # a newline first: if the hosts file does not end with one, our line would be glued to the last line
    Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value ([Environment]::NewLine + $s.Name) -Encoding ascii
}

function Add-PlantDefExclusion {
    param($s)
    New-Item -ItemType Directory -Path $s.Name -Force | Out-Null
    Add-MpPreference -ExclusionPath $s.Name -ErrorAction Stop
    if ((Get-MpPreference).ExclusionPath -notcontains $s.Name) { throw 'Defender did not accept the exclusion (Tamper Protection?)' }
}

function Add-PlantShare {
    param($s)
    $dir = 'C:\Shares\' + ($s.Name -replace '[^A-Za-z0-9]', '')
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    New-SmbShare -Name $s.Name -Path $dir -FullAccess Everyone | Out-Null
}

function Add-PlantFwRule {
    param($s)
    New-NetFirewallRule -DisplayName $s.Name -Direction Inbound -Protocol TCP -LocalPort $s.Port `
        -Action Allow -Profile Any | Out-Null
}

function Add-PlantLockout {
    param($s)
    net.exe accounts /lockoutthreshold:$($s.Threshold) /lockoutduration:30 /lockoutwindow:30 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "net accounts failed ($LASTEXITCODE)" }
}

function Add-PlantGuest {
    param($s)
    $null = $s          # nothing to read from the item; the Guest account is fixed
    Enable-LocalUser -Name 'Guest'
}

function Add-OnePlant {
    # Dispatcher: gives the item a random tag, plants it, returns the item with a Status field.
    param($s)
    $tag = 'b' + (-join ((1..4) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }))
    $s | Add-Member -NotePropertyName Tag -NotePropertyValue $tag -Force
    try {
        switch ($s.Kind) {
            'User'         { Add-PlantUser $s }
            'Task'         { Add-PlantTask $s }
            'RunKey'       { Add-PlantRunKey $s }
            'StartupFile'  { Add-PlantStartupFile $s }
            'Service'      { Add-PlantService $s }
            'Wmi'          { Add-PlantWmi $s }
            'Listener'     { Add-PlantListener $s }
            'Ifeo'         { Add-PlantIfeo $s }
            'Hosts'        { Add-PlantHosts $s }
            'DefExclusion' { Add-PlantDefExclusion $s }
            'Share'        { Add-PlantShare $s }
            'FwRule'       { Add-PlantFwRule $s }
            'Lockout'      { Add-PlantLockout $s }
            'Guest'        { Add-PlantGuest $s }
            default        { }     # Jenkins items are planted together by LabJenkins.ps1
        }
        $s | Add-Member -NotePropertyName Status -NotePropertyValue 'planted' -Force
    } catch {
        $s | Add-Member -NotePropertyName Status -NotePropertyValue ("FAILED: " + $_.Exception.Message) -Force
    }
    $s
}
