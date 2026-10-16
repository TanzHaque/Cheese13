# ScoreLib.ps1 - the individual "does the scoring engine still pass?" checks.
# Used by Score-Check.ps1 (run from your laptop) and by Verify-Hardening.ps1.
# Every Test-* function returns ONE result object:  Name, Status (PASS / FAIL / WARN / INFO / SKIP), Detail.
# Plain Windows PowerShell 5.1 (also runs on PowerShell 7). Nothing here changes the target.
#   PASS = works   FAIL = broken (would lose points)   WARN = might break / review   INFO = just a fact   SKIP = not tested

function New-Result {
    param([string]$Name, [string]$Status, [string]$Detail = '')
    [pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }
}

function Format-NameList {
    # 'a, b, c'  - or  'a, b, c, d (+4 more)'  when the list is long.
    param([string[]]$Names, [int]$Max = 8)
    $n = @($Names | Where-Object { $_ })
    if ($n.Count -le $Max) { return ($n -join ', ') }
    ($n[0..($Max - 1)] -join ', ') + " (+$($n.Count - $Max) more)"
}

function Read-Secret {
    # Hidden prompt (nothing is shown while you type). Returns the text.
    param([string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Test-TcpPort {
    # True if a TCP connection opens within the timeout.
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 3000)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($iar)
        return $true
    } catch { return $false }
    finally { $c.Close() }
}

# ---------------------------------------------------------------- RDP: protocol + TLS (no password needed)
function Test-RdpNegotiation {
    # Sends the first RDP packet (X.224 Connection Request asking for TLS or NLA), reads the answer,
    # then tries the TLS handshake. Proves the RDP service answers and which security it picked.
    param([string]$HostName, [int]$Port = 3389, [int]$TimeoutMs = 4000)
    $out = [ordered]@{ Reachable = $false; Protocol = ''; Failure = ''; TlsOk = $false; TlsVersion = ''; CertSubject = ''; CertExpires = ''; Error = '' }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "no TCP connection to ${HostName}:$Port within $TimeoutMs ms" }
        $client.EndConnect($iar)
        $out.Reachable = $true
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMs

        # TPKT(4) + X.224 CR(7) + RDP_NEG_REQ(8): ask for TLS (0x1) and NLA/CredSSP (0x2)
        $req = [byte[]](0x03,0x00,0x00,0x13, 0x0E,0xE0,0x00,0x00,0x00,0x00,0x00, 0x01,0x00,0x08,0x00, 0x03,0x00,0x00,0x00)
        $stream.Write($req, 0, $req.Length)
        $buf = New-Object byte[] 64
        $n = $stream.Read($buf, 0, $buf.Length)

        # answer = TPKT(4) + X.224 CC(7) [byte 5 = 0xD0] + RDP_NEG_RSP/FAILURE(8) [byte 11 = type, bytes 15-18 = value]
        if ($n -lt 11 -or $buf[0] -ne 0x03 -or $buf[5] -ne 0xD0) { throw 'the port answered, but not like an RDP server' }
        if ($n -lt 19) { $out.Protocol = 'RDP standard security (no negotiation data)'; return [pscustomobject]$out }

        $kind = $buf[11]
        $val  = [BitConverter]::ToUInt32($buf, 15)
        if ($kind -eq 0x03) {
            $names = @{ 1 = 'SSL_REQUIRED_BY_SERVER'; 2 = 'SSL_NOT_ALLOWED_BY_SERVER'; 3 = 'SSL_CERT_NOT_ON_SERVER'; 4 = 'INCONSISTENT_FLAGS'; 5 = 'HYBRID_REQUIRED_BY_SERVER'; 6 = 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER' }
            $out.Failure = if ($names.ContainsKey([int]$val)) { $names[[int]$val] } else { "code $val" }
            throw "server refused the negotiation: $($out.Failure)"
        }
        $protoNames = @{ 0 = 'RDP standard security'; 1 = 'TLS'; 2 = 'NLA (CredSSP)'; 4 = 'RDSTLS'; 8 = 'NLA with early auth' }
        $out.Protocol = if ($protoNames.ContainsKey([int]$val)) { $protoNames[[int]$val] } else { "protocol $val" }

        # TLS handshake (any certificate is accepted: the question is only "does TLS work?")
        if ($val -ne 0) {
            $accept = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
            $ssl = New-Object System.Net.Security.SslStream($stream, $false, $accept)
            $ssl.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
            $out.TlsOk = $true
            $out.TlsVersion = [string]$ssl.SslProtocol
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $out.CertSubject = $cert.Subject
            $out.CertExpires = $cert.NotAfter.ToString('yyyy-MM-dd')
        }
    } catch { $out.Error = $_.Exception.Message }
    finally { $client.Close() }
    [pscustomobject]$out
}

function Test-RdpService {
    # Turns the raw probe above into one PASS/WARN/FAIL line.
    param([string]$HostName, [int]$Port = 3389)
    $n = Test-RdpNegotiation -HostName $HostName -Port $Port
    if (-not $n.Reachable) { return New-Result 'RDP service' 'FAIL' "no connection: $($n.Error)" }
    if ($n.Failure)        { return New-Result 'RDP service' 'FAIL' "server refused the RDP negotiation: $($n.Failure)" }
    if (-not $n.Protocol)  { return New-Result 'RDP service' 'FAIL' $n.Error }
    if ($n.Protocol -like 'RDP standard*') { return New-Result 'RDP service' 'WARN' 'answers, but only with old standard RDP security (no TLS / NLA)' }
    if (-not $n.TlsOk)     { return New-Result 'RDP service' 'WARN' "answers with $($n.Protocol) but the TLS handshake failed: $($n.Error)" }
    New-Result 'RDP service' 'PASS' "$($n.Protocol), $($n.TlsVersion), certificate $($n.CertSubject) (expires $($n.CertExpires))"
}

# ---------------------------------------------------------------- RDP: real login (needs a FreeRDP client)
function Find-FreeRdp {
    # Path of a FreeRDP client, or $null. Order: the path you gave, then common names on PATH.
    param([string]$ExplicitPath)
    if ($ExplicitPath) { if (Test-Path $ExplicitPath) { return (Resolve-Path $ExplicitPath).Path } else { return $null } }
    foreach ($n in 'xfreerdp3', 'xfreerdp', 'wfreerdp', 'wfreerdp3', 'sdl-freerdp3', 'sdl-freerdp') {
        $c = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return $c.Source }
    }
    $null
}

function Test-RdpLogin {
    # Real authenticated RDP login with FreeRDP in "authentication only" mode (no desktop is opened).
    # Exit code 0 = the server accepted the username and password (NLA / CredSSP done).
    # Do not use a password that contains a double quote.
    param([string]$HostName, [int]$Port = 3389, [string]$User, [string]$Password, [string]$FreeRdp)
    $ErrorActionPreference = 'Continue'      # PS 5.1 would throw on the first line FreeRDP writes to stderr if the caller used 'Stop'
    if (-not $FreeRdp) {
        $hand = "xfreerdp3 /v:${HostName}:$Port /u:$User /p:<password> /cert:ignore /auth-only ; echo exit code `$?"
        return New-Result 'RDP login (NLA)' 'SKIP' "FreeRDP not found, so this is NOT a real login test. From any Linux box run:  $hand   (0 = login works)"
    }
    $isV2 = ((& $FreeRdp /version 2>&1 | Out-String) -match 'version 2\.')
    $certArg = if ($isV2) { '/cert-ignore' } else { '/cert:ignore' }     # FreeRDP 2 and 3 spell these differently
    $authArg = if ($isV2) { '+auth-only' } else { '/auth-only' }
    $text = & $FreeRdp "/v:${HostName}:$Port" "/u:$User" "/p:$Password" $certArg $authArg 2>&1 | Out-String
    $code = $LASTEXITCODE
    if ($code -eq 0) { return New-Result 'RDP login (NLA)' 'PASS' "FreeRDP logged in as $User on ${HostName}:$Port" }
    # the most specific reason FreeRDP printed
    $why = [regex]::Match($text, 'ERRCONNECT_[A-Z_]+|STATUS_[A-Z_]+|failed to open display').Value
    if (-not $why -and $code -eq 134) { $why = 'logon failure (wrong user or password)' }
    if (-not $why) { $why = "exit code $code" }
    if ($why -eq 'failed to open display') { $why = 'this FreeRDP build needs a display (use xfreerdp3, or run it under xvfb-run)' }
    New-Result 'RDP login (NLA)' 'FAIL' "FreeRDP could not log in as ${User}: $why"
}

# ---------------------------------------------------------------- Jenkins (what the scoring engine does)
function Send-Http {
    # One HTTP request that NEVER follows redirects (we want to read the redirect). Same behaviour on PS 5.1 and 7.
    # Returns Code (0 = no answer), Location (redirect target), Body and Error.
    param([string]$Url, [string]$Method = 'GET', [string]$Body = '', [int]$TimeoutMs = 10000, [System.Net.CookieContainer]$Cookies = $null)
    $req = [System.Net.WebRequest]::Create($Url) -as [System.Net.HttpWebRequest]
    $req.Method = $Method
    $req.AllowAutoRedirect = $false
    $req.Timeout = $TimeoutMs
    if ($Cookies) { $req.CookieContainer = $Cookies }
    try {
        if ($Method -eq 'POST') {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentType = 'application/x-www-form-urlencoded'
            $req.ContentLength = $bytes.Length
            $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
        }
        $resp = $req.GetResponse()
    } catch [System.Net.WebException] {
        $resp = $_.Exception.Response            # 4xx / 5xx still give us a response to read
        if (-not $resp) { return [pscustomobject]@{ Code = 0; Location = ''; Body = ''; Error = $_.Exception.Message } }
    } catch { return [pscustomobject]@{ Code = 0; Location = ''; Body = ''; Error = $_.Exception.Message } }
    $code = [int]$resp.StatusCode
    $loc  = [string]$resp.Headers['Location']
    $respBody = ''
    try {
        $stream = $resp.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream)
            $respBody = $reader.ReadToEnd()
            $reader.Close()
        }
    } catch { }
    $resp.Close()
    [pscustomobject]@{ Code = $code; Location = $loc; Body = $respBody; Error = '' }
}

function Test-JenkinsLogin {
    # Logs in the way a browser does: POST the login form, then look at where Jenkins redirects us.
    # Back to the page we asked for = good login.  To /loginError = bad login.
    param([string]$HostName, [int]$Port = 8080, [string]$User, [string]$Password)
    $base = "http://${HostName}:$Port"
    $cookies = New-Object System.Net.CookieContainer
    $page = Send-Http "$base/login" -Cookies $cookies
    if ($page.Code -eq 0)   { return New-Result 'Jenkins login' 'FAIL' "no answer from $base ($($page.Error))" }
    if ($page.Code -ge 500) { return New-Result 'Jenkins login' 'FAIL' "GET /login gave HTTP $($page.Code) (is Jenkins still starting?)" }
    $crumb = ''
    if ($page.Body -match 'name="Jenkins-Crumb"\s+type="hidden"\s+value="([^"]+)"') { $crumb = $matches[1] }
    elseif ($page.Body -match 'value="([^"]+)"\s+name="Jenkins-Crumb"') { $crumb = $matches[1] }
    $form = 'j_username=' + [uri]::EscapeDataString($User) + '&j_password=' + [uri]::EscapeDataString($Password) + '&from=%2F&Submit=Sign+in'
    if ($crumb) { $form += '&Jenkins-Crumb=' + [uri]::EscapeDataString($crumb) }
    $r = Send-Http "$base/j_spring_security_check" -Method POST -Body $form -Cookies $cookies
    if ($r.Code -eq 0) { return New-Result 'Jenkins login' 'FAIL' "login request failed: $($r.Error)" }
    if ($r.Code -in 301, 302, 303 -and $r.Location -notmatch 'loginError') { return New-Result 'Jenkins login' 'PASS' "$User logged in (redirected to $($r.Location))" }
    New-Result 'Jenkins login' 'FAIL' "login as $User refused (HTTP $($r.Code), redirect '$($r.Location)')"
}

function Get-JenkinsBuild {
    # Reads the latest build of rocket-build with HTTP Basic auth (user:password), like an API client.
    param([string]$HostName, [int]$Port = 8080, [string]$User, [string]$Password, [string]$Job = 'rocket-build', [int]$StaleMinutes = 30)
    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${User}:$Password"))
    $url = "http://${HostName}:$Port/job/$Job/lastBuild/api/json?tree=number,result,building,timestamp,duration"
    try { $b = Invoke-RestMethod $url -Headers @{ Authorization = "Basic $b64" } -TimeoutSec 10 -ErrorAction Stop }
    catch { return New-Result 'Jenkins last build' 'FAIL' $_.Exception.Message }
    $ageMin = [int](([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - [int64]$b.timestamp) / 60000)
    if ($b.building) { return New-Result 'Jenkins last build' 'WARN' "build #$($b.number) is still running (result not final yet)" }
    if ($b.result -ne 'SUCCESS') { return New-Result 'Jenkins last build' 'FAIL' "build #$($b.number) result=$($b.result)" }
    if ($ageMin -gt $StaleMinutes) { return New-Result 'Jenkins last build' 'WARN' "build #$($b.number) SUCCESS but $ageMin min old (are builds still being triggered?)" }
    New-Result 'Jenkins last build' 'PASS' "build #$($b.number) SUCCESS, $ageMin min ago"
}

# ---------------------------------------------------------------- jmoney, on the box itself (Windows only)
function Get-LocalGroupNames {
    # Member names of a local group, read from "net localgroup" (it still works when Get-LocalGroupMember
    # trips over an orphaned SID). Names come back as 'jmoney' or 'DOMAIN\name'.
    param([string]$Group)
    $lines = @(net.exe localgroup $Group 2>$null)
    $dash = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^-{10,}') { $dash = $i; break } }
    if ($dash -lt 0) { return @() }
    @($lines | Select-Object -Skip ($dash + 1) | Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { $_.Trim() })
}

function Test-LocalCredential {
    # Asks Windows: is this username + password valid on THIS machine? (local accounts)
    param([string]$User, [string]$Password)
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $env:COMPUTERNAME)
    try { $ctx.ValidateCredentials($User, $Password) }
    catch { $false }          # e.g. an account that must change its password: not a valid login
    finally { $ctx.Dispose() }
}

function Test-LocalScoringUser {
    # Everything that can stop jmoney from logging in over RDP, checked from the inside.
    param([string]$User = 'jmoney', [string]$Password)
    $u = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    if (-not $u) { return New-Result 'jmoney account' 'FAIL' "$User does not exist" }
    $adsi    = [ADSI]"WinNT://./$User,user"
    $locked  = [bool]$adsi.IsAccountLocked
    $expired = ($adsi.PasswordExpired -eq 1)
    $groups  = @()
    foreach ($g in 'Administrators', 'Remote Desktop Users') {
        $names = Get-LocalGroupNames $g
        if (@($names | Where-Object { $_ -eq $User -or $_ -like "*\$User" }).Count -gt 0) { $groups += $g }
    }
    $problems = @()
    if (-not $u.Enabled)    { $problems += 'disabled' }
    if ($locked)            { $problems += 'locked out' }
    if ($expired)           { $problems += 'password expired / must change at next logon' }
    if ($groups.Count -eq 0) { $problems += 'not in Administrators or Remote Desktop Users (RDP not allowed)' }
    if ($Password -and -not (Test-LocalCredential -User $User -Password $Password)) { $problems += 'password rejected' }
    if ($problems.Count -gt 0) { return New-Result 'jmoney account' 'FAIL' ($problems -join '; ') }
    New-Result 'jmoney account' 'PASS' ('enabled, unlocked, member of: ' + ($groups -join ', '))
}

function Test-RdpSessionSlots {
    # Server 2022 without RDS licensing allows 2 remote sessions, and DISCONNECTED sessions still use a slot.
    # If two OTHER users hold both slots, the scoring login for jmoney is refused.
    param([string]$User = 'jmoney')
    $lines = @(quser.exe 2>$null | Select-Object -Skip 1)
    $mine = 0; $others = 0
    foreach ($l in $lines) {
        if ($l -notmatch 'rdp-tcp#|\sDisc\s') { continue }            # remote sessions only (active or disconnected)
        $name = ($l.TrimStart('>', ' ') -split '\s+')[0]
        if ($name -eq $User) { $mine++ } else { $others++ }
    }
    if ($others -ge 2) { return New-Result 'RDP session slots' 'WARN' "$others other RDP sessions hold both slots (limit 2): a scoring login may be refused. Log them off." }
    New-Result 'RDP session slots' 'PASS' "$others other session(s), $mine for $User (limit 2 in total)"
}

# ---------------------------------------------------------------- optional: MariaDB (from the old Score-Check)
function Test-MariaDb {
    param([string]$HostName, [string]$User = 'jmoney', [string]$Password)
    $ErrorActionPreference = 'Continue'
    if (-not (Test-TcpPort -HostName $HostName -Port 3306)) { return New-Result 'MariaDB plinkcom' 'FAIL' 'port 3306 not reachable' }
    $mysql = (Get-Command mysql -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $mysql) {
        $mysql = Get-ChildItem 'C:\Program Files\MariaDB*\bin\mysql.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $mysql) { return New-Result 'MariaDB plinkcom' 'SKIP' 'mysql client not found' }
    $out = & $mysql -h $HostName -u $User "--password=$Password" -N -e 'SELECT COUNT(*) FROM plinkcom.rockets' 2>&1
    if ($LASTEXITCODE -eq 0 -and "$out" -match '^\d+$') { return New-Result 'MariaDB plinkcom' 'PASS' "rockets rows: $out" }
    New-Result 'MariaDB plinkcom' 'FAIL' "query failed: $out"
}

# ---------------------------------------------------------------- all checks together
function Invoke-ScoreChecks {
    # Runs every check once and returns the list of result objects.
    param(
        [string]$Target = '127.0.0.1', [int]$RdpPort = 3389, [int]$JenkinsPort = 8080,
        [string]$User = 'jmoney', [string]$Password, [string]$FreeRdp,
        [switch]$NoAuthRdp, [switch]$CheckMariaDB,
        [ValidateSet('Auto', 'Yes', 'No')][string]$LocalChecks = 'Auto'    # Auto = only when Target is this machine
    )
    $r = New-Object System.Collections.ArrayList
    $isLocal = ($LocalChecks -eq 'Yes') -or ($LocalChecks -eq 'Auto' -and $Target -in @('127.0.0.1', 'localhost', '::1', $env:COMPUTERNAME))

    # RDP: port, then protocol/TLS, then a real login
    $open = Test-TcpPort -HostName $Target -Port $RdpPort
    if ($open) { [void]$r.Add((New-Result "RDP port $RdpPort" 'PASS' 'reachable')) }
    else       { [void]$r.Add((New-Result "RDP port $RdpPort" 'FAIL' 'no TCP connection (firewall? TermService stopped?)')) }
    $needPw = 'needs the jmoney password (pass it, or use -AskPassword)'
    if ($open) {
        [void]$r.Add((Test-RdpService -HostName $Target -Port $RdpPort))
        if ($NoAuthRdp) { [void]$r.Add((New-Result 'RDP login (NLA)' 'SKIP' 'skipped on request (-NoAuthRdp)')) }
        elseif (-not $Password) { [void]$r.Add((New-Result 'RDP login (NLA)' 'SKIP' $needPw)) }
        else { [void]$r.Add((Test-RdpLogin -HostName $Target -Port $RdpPort -User $User -Password $Password -FreeRdp $FreeRdp)) }
    }

    # Jenkins
    if ($Password) {
        [void]$r.Add((Test-JenkinsLogin -HostName $Target -Port $JenkinsPort -User $User -Password $Password))
        [void]$r.Add((Get-JenkinsBuild -HostName $Target -Port $JenkinsPort -User $User -Password $Password))
    } else {
        [void]$r.Add((New-Result 'Jenkins login' 'SKIP' $needPw))
        [void]$r.Add((New-Result 'Jenkins last build' 'SKIP' $needPw))
    }

    # things only visible from inside the box
    if ($isLocal) {
        if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
            try { [void]$r.Add((Test-LocalScoringUser -User $User -Password $Password)) }
            catch { [void]$r.Add((New-Result 'jmoney account' 'FAIL' $_.Exception.Message)) }
            try { [void]$r.Add((Test-RdpSessionSlots -User $User)) }
            catch { [void]$r.Add((New-Result 'RDP session slots' 'SKIP' $_.Exception.Message)) }
        } else {
            [void]$r.Add((New-Result 'jmoney account' 'SKIP' 'needs Windows (Get-LocalUser not available)'))
        }
    }

    if ($CheckMariaDB) { [void]$r.Add((Test-MariaDb -HostName $Target -User $User -Password $Password)) }
    $r.ToArray()
}

function Show-Result {
    param($Result)
    $color = switch ($Result.Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } 'INFO' { 'Cyan' } default { 'DarkGray' } }
    Write-Host ('[{0}] {1,-28} {2}' -f $Result.Status, $Result.Name, $Result.Detail) -ForegroundColor $color
}

function Get-ScoreExitCode {
    # 0 = everything PASS.   1 = at least one FAIL.   2 = no FAIL, but some WARN or SKIP (not fully proven).
    param($Results)
    if (@($Results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { return 1 }
    if (@($Results | Where-Object { $_.Status -eq 'WARN' -or $_.Status -eq 'SKIP' }).Count -gt 0) { return 2 }
    0
}
