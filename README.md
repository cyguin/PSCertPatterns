# PSCertPatterns

Production cryptographic patterns in PowerShell 7

## Overview

PSCertPatterns provides production-grade cryptographic implementations for PowerShell 7, covering AES-GCM symmetric encryption, RSA and ECDSA asymmetric operations, key rotation strategies, algorithm agility patterns, and comprehensive certificate chain validation.

## Prerequisites

- PowerShell 7.4+
- .NET 8
- Pester 5.x

## Installation

```powershell
Import-Module ./PSCertPatterns.psm1
```

## Usage

```powershell
using module ./PSCertPatterns.psm1

# AES-GCM encrypt / decrypt
$key = [byte[]]::new(32)
$aesGcm = [AesGcmService]::new($key)
$encrypted = $aesGcm.Encrypt([System.Text.Encoding]::UTF8.GetBytes("Hello, world!"))
$decrypted = $aesGcm.Decrypt($encrypted)
$aesGcm.Dispose()

# PBKDF2 key derivation
$salt = [SaltGenerator]::Generate(32)
$derivedKey = [Pbkdf2KeyDerivation]::DeriveKey("password", $salt, 32)

# AES-CBC + HMAC Encrypt-then-MAC
$encKey = [byte[]]::new(32)
$macKey = [byte[]]::new(32)
$aesCbc = [AesCbcService]::new($encKey, $macKey)
$package = $aesCbc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("Hello, world!"))
$decrypted = $aesCbc.Decrypt($package)
$aesCbc.Dispose()

# RSA encrypt / decrypt (OAEP SHA-256)
$rsaEnc = [RsaEncryptionService]::new(2048)
$encrypted = $rsaEnc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("Hello, world!"))
$decrypted = $rsaEnc.Decrypt($encrypted)
$rsaEnc.Dispose()

# RSA sign / verify (PSS SHA-256)
$rsaSign = [RsaSigningService]::new(2048)
$data = [System.Text.Encoding]::UTF8.GetBytes("message to sign")
$signature = $rsaSign.Sign($data)
$valid = $rsaSign.Verify($data, $signature)
$rsaSign.Dispose()
```

## Test Suite

```powershell
Invoke-Pester -Path './tests/*.Tests.ps1' -Output Detailed
```

103 Pester tests covering all completed slices.

| Slice | File | Classes | Tests |
|-------|------|---------|-------|
| 1 | src/01_AesGcm.ps1 | AesGcmService | 15 |
| 2 | src/02_KeyDerivation.ps1 | Pbkdf2KeyDerivation, SaltGenerator | 14 |
| 3 | src/03_NonceManagement.ps1 | RandomNonceGenerator, CounterNonceGenerator | 17 |
| 4 | src/04_HmacCbc.ps1 | AesCbcService, HmacService | 27 |
| 5 | src/05_Rsa.ps1 | RsaEncryptionService, RsaSigningService | 30 |

## License

MIT License — see [LICENSE](LICENSE) for details.

---

```
██████╗██╗   ██╗ ██████╗ ██╗   ██╗██╗███╗   ██╗
██╔════╝╚██╗ ██╔╝██╔════╝ ██║   ██║██║████╗  ██║
██║      ╚████╔╝ ██║  ███╗██║   ██║██║██╔██╗ ██║
██║       ╚██╔╝  ██║   ██║██║   ██║██║██║╚██╗██║
╚██████╗   ██║   ╚██████╔╝╚██████╔╝██║██║ ╚████║
╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝
drop-in tools for developers · cyguin.com
```
