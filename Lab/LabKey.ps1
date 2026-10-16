# LabKey.ps1  -  LAB ONLY.  Encrypts / decrypts the answer key for the practice box.
#
# Why this exists: Reset-LabInsecure.ps1 writes down everything it planted (the "answer key").
# The hardening tool must NOT be able to read it, so the key is encrypted with a passphrase
# that only you type. The hardening tool never loads this file and never opens the key file.
#
# File layout:  "HPCCKEY1" (8 bytes) | salt (16) | iv (16) | mac (32) | cipher (rest)
#   - Rfc2898DeriveBytes turns your passphrase into 64 bytes: 32 for AES, 32 for the MAC.
#   - AES-CBC encrypts the text.   - HMAC-SHA256 lets us say "wrong passphrase" cleanly.

$script:LabKeyMagic = [System.Text.Encoding]::ASCII.GetBytes('HPCCKEY1')

function ConvertTo-PlainText {
    # SecureString -> normal string (needed to feed the key derivation).
    param([Parameter(Mandatory)][securestring]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-LabKeyBytes {
    # Passphrase + salt -> 64 key bytes (first 32 = AES key, last 32 = MAC key).
    param([string]$Passphrase, [byte[]]$Salt)
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $Salt, 100000)
    $kdf.GetBytes(64)
}

function Get-LabMac {
    param([byte[]]$MacKey, [byte[]]$Data)
    $h = New-Object System.Security.Cryptography.HMACSHA256(, $MacKey)
    $h.ComputeHash($Data)
}

function Protect-LabText {
    # Encrypt $Text with $Passphrase and write the result to $Path.
    param([string]$Text, [string]$Passphrase, [string]$Path)
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16;  $rng.GetBytes($salt)
    $iv   = New-Object byte[] 16;  $rng.GetBytes($iv)
    $keys = Get-LabKeyBytes -Passphrase $Passphrase -Salt $salt
    $aes  = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keys[0..31]
    $aes.IV  = $iv
    $plain  = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $cipher = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
    $mac    = Get-LabMac -MacKey ([byte[]]$keys[32..63]) -Data ([byte[]]($iv + $cipher))
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllBytes($Path, [byte[]]($script:LabKeyMagic + $salt + $iv + $mac + $cipher))
}

function Unprotect-LabText {
    # Read $Path, check the MAC, decrypt, return the text. Throws on wrong passphrase.
    param([string]$Path, [string]$Passphrase)
    $all = [System.IO.File]::ReadAllBytes($Path)
    if ($all.Length -lt 72 -or [System.Text.Encoding]::ASCII.GetString($all, 0, 8) -ne 'HPCCKEY1') {
        throw "Not a lab key file: $Path"
    }
    $salt   = [byte[]]$all[8..23]
    $iv     = [byte[]]$all[24..39]
    $mac    = [byte[]]$all[40..71]
    $cipher = [byte[]]$all[72..($all.Length - 1)]
    $keys   = Get-LabKeyBytes -Passphrase $Passphrase -Salt $salt
    $check  = Get-LabMac -MacKey ([byte[]]$keys[32..63]) -Data ([byte[]]($iv + $cipher))
    # compare every byte (no early exit)
    $diff = 0
    for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($check[$i] -bxor $mac[$i]) }
    if ($diff -ne 0) { throw 'Wrong passphrase, or the key file was changed.' }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = [byte[]]$keys[0..31]
    $aes.IV  = $iv
    $plain = $aes.CreateDecryptor().TransformFinalBlock($cipher, 0, $cipher.Length)
    [System.Text.Encoding]::UTF8.GetString($plain)
}

function Get-LabPassphrase {
    # Passphrase from the HPCC_LAB_KEY environment variable if set, otherwise a hidden prompt.
    param([string]$Prompt = 'Lab key passphrase', [switch]$Twice)
    if ($env:HPCC_LAB_KEY) { return $env:HPCC_LAB_KEY }
    $a = ConvertTo-PlainText (Read-Host -AsSecureString $Prompt)
    if ($Twice) {
        $b = ConvertTo-PlainText (Read-Host -AsSecureString "$Prompt (again)")
        if ($a -ne $b) { throw 'The two passphrases do not match.' }
    }
    if ($a.Length -lt 4) { throw 'Passphrase too short (min 4).' }
    $a
}
