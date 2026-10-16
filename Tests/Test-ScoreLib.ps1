# Test-ScoreLib.ps1 - tests the scoring checks against FAKE servers that this script starts itself:
#   a fake Jenkins (HTTP) and a fake RDP server (X.224 answer + a real TLS handshake).
# Needs nothing installed. Runs on Windows PowerShell 5.1 AND PowerShell 7, on Windows or Linux.
# It never touches a real box. Windows-only calls (net.exe, quser.exe, Get-LocalUser) are replaced by stubs.
. "$PSScriptRoot\TestLib.ps1"
trap { Register-TestError $_; continue }       # an error nobody caught is a failure, not a silently missing check (see TestLib.ps1)
. "$PSScriptRoot\..\ScoreLib.ps1"

$script:UsedPorts = @()
function Get-FreePort {
    # asks the OS for an unused port (and never hands out the same one twice)
    do {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop()
    } while ($script:UsedPorts -contains $p)
    $script:UsedPorts += $p
    $p
}

# ------------------------------------------------------------------ fake Jenkins (runs in a background runspace)
$jenkinsServer = {
    param($port, $st)
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add("http://127.0.0.1:$port/")
    $l.Start()
    while (-not $st.Stop) {
        $task = $l.GetContextAsync()
        while (-not $task.Wait(200)) { if ($st.Stop) { break } }
        if ($st.Stop) { break }
        $ctx = $task.Result; $req = $ctx.Request; $res = $ctx.Response
        $code = 404; $body = ''
        if ($req.Url.AbsolutePath -eq '/login') {
            if ($st.Ready) { $code = 200; $body = '<html>login</html>' } else { $code = 503; $body = 'Please wait while Jenkins is getting ready' }
        } elseif ($req.Url.AbsolutePath -eq '/j_spring_security_check' -and $req.HttpMethod -eq 'POST') {
            $form = (New-Object System.IO.StreamReader($req.InputStream)).ReadToEnd()
            $f = @{}
            foreach ($pair in ($form -split '&')) {
                $kv = $pair -split '=', 2
                if ($kv.Count -eq 2) { $f[[uri]::UnescapeDataString($kv[0].Replace('+', ' '))] = [uri]::UnescapeDataString($kv[1].Replace('+', ' ')) }
            }
            $code = 302
            if ($f['j_username'] -eq $st.User -and $f['j_password'] -eq $st.Pass) { $res.RedirectLocation = '/' } else { $res.RedirectLocation = '/loginError' }
        } elseif ($req.Url.AbsolutePath -eq '/job/rocket-build/lastBuild/api/json') {
            $want = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($st.User + ':' + $st.Pass))
            if ($req.Headers['Authorization'] -ne $want) { $code = 401; $body = 'no' }
            else {
                $code = 200
                $ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - ([int64]$st.AgeMin * 60000)
                $result = 'null'; if ($st.Result) { $result = '"' + $st.Result + '"' }
                $building = 'false'; if ($st.Building) { $building = 'true' }
                $body = '{"number":7,"result":' + $result + ',"building":' + $building + ',"timestamp":' + $ts + ',"duration":1000}'
            }
        }
        $res.StatusCode = $code
        if ($body) { $b = [Text.Encoding]::UTF8.GetBytes($body); $res.ContentLength64 = $b.Length; $res.OutputStream.Write($b, 0, $b.Length) }
        $res.Close()
    }
    $l.Stop()
}

# ------------------------------------------------------------------ fake RDP server (runs in a background runspace)
$rdpServer = {
    param($port, $st, $cert)
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
    $l.Start()
    while (-not $st.Stop) {
        if (-not $l.Pending()) { Start-Sleep -Milliseconds 40; continue }
        $c = $l.AcceptTcpClient()
        try {
            $s = $c.GetStream()
            $buf = New-Object byte[] 64
            [void]$s.Read($buf, 0, 64)                              # the client's connection request
            if ($st.Hold) { Start-Sleep -Milliseconds 2500 }        # a server that accepts but never answers
            if ($st.Reply.Length -gt 0) { $s.Write($st.Reply, 0, $st.Reply.Length); $s.Flush() }
            if ($st.Tls -and $cert) {
                $ssl = New-Object System.Net.Security.SslStream($s, $false)
                $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
                Start-Sleep -Milliseconds 200
            }
        } catch { $null = $_ } finally { $c.Close() }
    }
    $l.Stop()
}

# RDP_NEG_RSP / FAILURE answers (TPKT + X.224 CC + 8 bytes)
function New-RdpAnswer { param([byte]$Type, [byte]$Value)
    [byte[]](0x03,0x00,0x00,0x13, 0x0E,0xD0,0x00,0x00,0x12,0x34,0x00, $Type,0x00,0x08,0x00, $Value,0x00,0x00,0x00) }

$jState = [hashtable]::Synchronized(@{ Stop = $false; Ready = $true; User = 'jmoney'; Pass = 'Pw!x y&z'; Result = 'SUCCESS'; Building = $false; AgeMin = 2 })
$rState = [hashtable]::Synchronized(@{ Stop = $false; Reply = [byte[]]@(); Tls = $false; Hold = $false })
$jPort = Get-FreePort; $rPort = Get-FreePort; $deadPort = Get-FreePort

# a throw-away self-signed certificate for the fake RDP server (skipped if this PowerShell cannot make one)
$cert = $null
try {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $csr = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=fake-rdp', $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $tmpCert = $csr.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmpCert.Export('Pfx', 'x'), 'x')
} catch { $cert = $null }

$jPs = [powershell]::Create(); [void]$jPs.AddScript($jenkinsServer).AddArgument($jPort).AddArgument($jState); $null = $jPs.BeginInvoke()
$rPs = [powershell]::Create(); [void]$rPs.AddScript($rdpServer).AddArgument($rPort).AddArgument($rState).AddArgument($cert); $null = $rPs.BeginInvoke()
Start-Sleep -Milliseconds 700

try {
    Write-Host 'Fake Jenkins: login and last build' -ForegroundColor Cyan
    $r = Test-JenkinsLogin -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'Pw!x y&z'
    Assert-Equal $r.Status 'PASS' 'good login (password with a space and & in it)'
    $r = Test-JenkinsLogin -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'wrong'
    Assert-Equal $r.Status 'FAIL' 'wrong password is a FAIL'
    Assert-True ($r.Detail -match 'loginError') 'the FAIL says Jenkins redirected to loginError'
    $jState.Ready = $false
    $r = Test-JenkinsLogin -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'Pw!x y&z'
    Assert-Equal $r.Status 'FAIL' 'Jenkins still starting (HTTP 503) is a FAIL'
    $jState.Ready = $true
    $r = Test-JenkinsLogin -HostName 127.0.0.1 -Port $deadPort -User jmoney -Password 'x'
    Assert-Equal $r.Status 'FAIL' 'nothing listening is a FAIL'

    $b = Get-JenkinsBuild -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'Pw!x y&z'
    Assert-Equal $b.Status 'PASS' 'recent SUCCESS build is PASS'
    $jState.Result = 'FAILURE'
    Assert-Equal (Get-JenkinsBuild -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'Pw!x y&z').Status 'FAIL' 'FAILURE build is FAIL'
    $jState.Result = 'SUCCESS'; $jState.AgeMin = 90
    Assert-Equal (Get-JenkinsBuild -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'Pw!x y&z').Status 'WARN' 'SUCCESS but 90 minutes old is WARN'
    $jState.AgeMin = 2; $jState.Building = $true; $jState.Result = ''
    Assert-Equal (Get-JenkinsBuild -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'Pw!x y&z').Status 'WARN' 'build still running is WARN'
    $jState.Building = $false; $jState.Result = 'SUCCESS'
    Assert-Equal (Get-JenkinsBuild -HostName 127.0.0.1 -Port $jPort -User jmoney -Password 'bad').Status 'FAIL' 'wrong Basic-auth password is FAIL (HTTP 401)'

    Write-Host 'Fake RDP server: the first packet exchange' -ForegroundColor Cyan
    $rState.Reply = New-RdpAnswer 0x02 0x02          # NLA
    $n = Test-RdpNegotiation -HostName 127.0.0.1 -Port $rPort
    Assert-Equal $n.Protocol 'NLA (CredSSP)' 'reads "NLA" from the answer'
    Assert-True ($n.Reachable -and -not $n.TlsOk) 'no TLS follows -> TlsOk is false'
    Assert-Equal (Test-RdpService -HostName 127.0.0.1 -Port $rPort).Status 'WARN' 'answers but TLS fails -> WARN'

    $rState.Reply = New-RdpAnswer 0x03 0x05          # failure: HYBRID_REQUIRED_BY_SERVER
    $r = Test-RdpService -HostName 127.0.0.1 -Port $rPort
    Assert-Equal $r.Status 'FAIL' 'negotiation failure is FAIL'
    Assert-True ($r.Detail -match 'HYBRID_REQUIRED_BY_SERVER') 'the FAIL names the reason'

    $rState.Reply = [byte[]](0x03,0x00,0x00,0x0B, 0x06,0xD0,0x00,0x00,0x12,0x34,0x00)   # old style: no negotiation data
    $r = Test-RdpService -HostName 127.0.0.1 -Port $rPort
    Assert-Equal $r.Status 'WARN' 'old "standard RDP security" is WARN'

    $rState.Reply = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 400 Bad Request`r`n`r`n")
    $r = Test-RdpService -HostName 127.0.0.1 -Port $rPort
    Assert-Equal $r.Status 'FAIL' 'something that is not RDP is FAIL'
    Assert-True ($r.Detail -match 'not like an RDP server') 'the FAIL says it is not RDP'

    $rState.Reply = [byte[]]@(); $rState.Hold = $true
    $n = Test-RdpNegotiation -HostName 127.0.0.1 -Port $rPort -TimeoutMs 700
    Assert-True ($n.Reachable -and -not $n.Protocol -and $n.Error) 'a server that never answers: reachable, no protocol, an error'
    $rState.Hold = $false
    Start-Sleep -Milliseconds 2200          # let the fake server finish its pause

    if ($cert) {
        $rState.Reply = New-RdpAnswer 0x02 0x02; $rState.Tls = $true     # NLA + a real TLS handshake
        $r = Test-RdpService -HostName 127.0.0.1 -Port $rPort
        Assert-Equal $r.Status 'PASS' 'NLA + successful TLS handshake is PASS'
        Assert-True ($r.Detail -match 'fake-rdp') 'the PASS shows the certificate subject'
        $rState.Reply = New-RdpAnswer 0x02 0x01                          # plain TLS
        Assert-Equal (Test-RdpService -HostName 127.0.0.1 -Port $rPort).Status 'PASS' 'TLS-only server is PASS'
        $rState.Tls = $false
    } else {
        Write-Host '  SKIP  TLS handshake tests (this PowerShell could not create a self-signed certificate)' -ForegroundColor DarkGray
    }

    Write-Host 'The whole set together (Invoke-ScoreChecks)' -ForegroundColor Cyan
    if ($cert) { $rState.Reply = New-RdpAnswer 0x02 0x02; $rState.Tls = $true }
    $all = @(Invoke-ScoreChecks -Target 127.0.0.1 -RdpPort $rPort -JenkinsPort $jPort -User jmoney -Password 'Pw!x y&z' -NoAuthRdp -LocalChecks No)
    Assert-Equal $all.Count 5 'five checks: port, service, login(skipped), Jenkins login, Jenkins build'
    Assert-Equal (@($all | Where-Object Name -eq 'RDP login (NLA)')[0].Status) 'SKIP' '-NoAuthRdp gives a SKIP line'
    Assert-Equal (Get-ScoreExitCode $all) 2 'exit code 2 when there are only SKIP / no FAIL'
    $jState.Result = 'FAILURE'
    $all = @(Invoke-ScoreChecks -Target 127.0.0.1 -RdpPort $rPort -JenkinsPort $jPort -User jmoney -Password 'Pw!x y&z' -NoAuthRdp -LocalChecks No)
    Assert-Equal (Get-ScoreExitCode $all) 1 'exit code 1 when a check FAILs'
    $jState.Result = 'SUCCESS'
    $all = @(Invoke-ScoreChecks -Target 127.0.0.1 -RdpPort $deadPort -JenkinsPort $jPort -User jmoney -Password 'Pw!x y&z' -LocalChecks No)
    Assert-Equal $all.Count 3 'closed RDP port: the service and login lines are not attempted'
    Assert-Equal $all[0].Status 'FAIL' 'closed RDP port is a FAIL'
    Assert-Equal (Get-ScoreExitCode @([pscustomobject]@{ Status = 'PASS' })) 0 'all PASS gives exit code 0'
}
finally {
    $jState.Stop = $true; $rState.Stop = $true
    Start-Sleep -Milliseconds 500
    try { $jPs.Stop() } catch { $null = $_ }
    try { $rPs.Stop() } catch { $null = $_ }
    $jPs.Dispose(); $rPs.Dispose()
}

# ------------------------------------------------------------------ Windows-only helpers, with stubs
Write-Host 'Local helpers with stubbed Windows commands' -ForegroundColor Cyan
function net.exe {
    'Alias name     Administrators'
    'Comment        Administrators have complete and unrestricted access'
    ''
    'Members'
    ''
    '-------------------------------------------------------------------------------'
    'Administrator'
    'jmoney'
    'CONTOSO\Domain Admins'
    'The command completed successfully.'
}
$names = @(Get-LocalGroupNames 'Administrators')
Assert-Equal ($names -join '|') 'Administrator|jmoney|CONTOSO\Domain Admins' 'net localgroup output is parsed to member names'

function quser.exe {
    ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME'
    '>blaze                 rdp-tcp#8           1  Active          .  10/15/2026 2:00 PM'
    ' tfox                                      2  Disc         1:23  10/15/2026 2:10 PM'
    ' console-user          console             3  Active          .  10/15/2026 2:12 PM'
}
Assert-Equal (Test-RdpSessionSlots -User jmoney).Status 'WARN' 'two other users hold both RDP slots -> WARN'
function quser.exe {
    ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME'
    '>blaze                 rdp-tcp#8           1  Active          .  10/15/2026 2:00 PM'
    ' jmoney                                    2  Disc         1:23  10/15/2026 2:10 PM'
}
$r = Test-RdpSessionSlots -User jmoney
Assert-Equal $r.Status 'PASS' 'one other user + jmoney own session -> PASS'
Assert-True ($r.Detail -match '1 other') 'detail counts the other sessions'
function quser.exe { }
Assert-Equal (Test-RdpSessionSlots -User jmoney).Status 'PASS' 'nobody logged on -> PASS'

# the aggregator with stubbed local checks
function Get-LocalUser { }
function Test-LocalScoringUser { param($User, $Password) $null = $User, $Password; New-Result 'jmoney account' 'PASS' 'stub' }
function Test-RdpSessionSlots { param($User) $null = $User; New-Result 'RDP session slots' 'PASS' 'stub' }
$dead = Get-FreePort
$all = @(Invoke-ScoreChecks -Target 127.0.0.1 -RdpPort $dead -JenkinsPort $dead -User jmoney -Password x -LocalChecks Yes)
Assert-True (($all | Where-Object Name -eq 'jmoney account').Status -eq 'PASS') '-LocalChecks Yes adds the jmoney account line'
Assert-True (($all | Where-Object Name -eq 'RDP session slots').Status -eq 'PASS') '-LocalChecks Yes adds the session slots line'
$all = @(Invoke-ScoreChecks -Target 127.0.0.2 -RdpPort $dead -JenkinsPort $dead -User jmoney -Password x -LocalChecks Auto -NoAuthRdp)
Assert-True (@($all | Where-Object Name -eq 'jmoney account').Count -eq 0) 'Auto: a remote target gets no local checks'

Write-TestSummary
