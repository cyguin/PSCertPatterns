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
# AES-GCM encryption
$encrypted = Protect-CertData -Plaintext "Hello, world!" -Certificate $cert

# RSA sign and verify
$signature = Sign-CertData -Data $data -Certificate $signingCert
$valid = Verify-CertSignature -Data $data -Signature $signature -Certificate $cert

# Certificate chain validation
$chain = Test-CertificateChain -Certificate $serverCert
```

## Test Suite

```powershell
Invoke-Pester -Path './tests/*.Tests.ps1' -Output Detailed
```

73 Pester tests covering all completed slices.

| Slice | File | Classes | Tests |
|-------|------|---------|-------|
| 1 | src/01_AesGcm.ps1 | AesGcmService | 15 |
| 2 | src/02_KeyDerivation.ps1 | Pbkdf2KeyDerivation, SaltGenerator | 14 |
| 3 | src/03_NonceManagement.ps1 | RandomNonceGenerator, CounterNonceGenerator | 17 |
| 4 | src/04_HmacCbc.ps1 | AesCbcService, HmacService | 27 |

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
