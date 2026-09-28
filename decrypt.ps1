# Decrypt a Zone Nova master data blob using .NET's own PasswordDeriveBytes.
# Works in Windows PowerShell 5.1+ (no Python needed).
# Usage: powershell -File decrypt.ps1 -In <encrypted file> -Out <output bin>
param(
    [Parameter(Mandatory = $true)][string]$In,
    [string]$Out = "$In.dec.bin"
)

$password = 'zVGyaQ6h9tLzqiD5HJQF'
$salt = [byte[]](0x93, 0x83, 0x33, 0x72)

$cipher = [IO.File]::ReadAllBytes((Resolve-Path $In))
if ($cipher.Length -lt 16) { throw "input too short" }
$magic = [byte[]](0xb5, 0x61, 0x2a, 0x39, 0x2a, 0x41, 0xb8, 0x09)
$ok = -not (Compare-Object $cipher[0..7] $magic -SyncWindow 0)
if (-not $ok) { Write-Warning "file does not start with the expected magic b5 61 2a 39 2a 41 b8 09" }

$pdb = New-Object System.Security.Cryptography.PasswordDeriveBytes($password, $salt)
$aes = New-Object System.Security.Cryptography.AesManaged
$aes.Key = $pdb.GetBytes(32)
$aes.IV = $pdb.GetBytes(16)
$dec = $aes.CreateDecryptor()
$ms = New-Object System.IO.MemoryStream
$cs = New-Object System.Security.Cryptography.CryptoStream($ms, $dec, [System.Security.Cryptography.CryptoStreamMode]::Write)
$cs.Write($cipher, 0, $cipher.Length)
$cs.FlushFinalBlock()
$plain = $ms.ToArray()
"decrypted {0} bytes -> {1}" -f $plain.Length, $Out
[IO.File]::WriteAllBytes($Out, $plain)
