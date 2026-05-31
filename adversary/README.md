# PSCertPatterns Adversary

## What This Is

This tool runs cryptographic attacks against PowerShell class implementations. It flips bits in ciphertext, replays nonces, truncates packages, probes boundaries, and attempts cross-key decryption. The purpose is to verify that your implementation detects and rejects these attacks correctly. Run it against code you wrote. 

## What This Is Not

---
DISCLAIMER

This tool exists to validate the behavioral correctness of the cryptographic patterns implemented in PSCertPatterns. It is:

- NOT suitable for use against production systems, third-party code, or any target you do not own and fully understand

Do not run this against code you did not write. Do not interpret a passing score as a security guarantee. Do not use this to evaluate your bank, your employer's systems, your neighbor's NAS, or your mom's dog.

---

## Supported Contracts

| Contract | Required Methods | Description |
|----------|-----------------|-------------|
| EncryptDecrypt | Encrypt([byte[]]), Decrypt([byte[]]) | Symmetric encryption round-trip |
| SignVerify | Sign([byte[]]), Verify([byte[]], [byte[]]) | Asymmetric signing |
| DeriveKey | DeriveKey([string], [byte[]], [int]) | Key derivation |
| ReplayGuard | CheckAndRecord([byte[]]), HasSeen([byte[]]) | Nonce replay prevention |
| KeyRotation | Encrypt([byte[]]), Decrypt([string],[byte[]]), Rotate(), CurrentKeyId() | Rotating key management |

## Usage

```powershell
# Import the module
Import-Module ./PSCertPatterns.psm1

# Run battery against AesGcmService
$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$svc = [AesGcmService]::new($key)

. ./adversary/Invoke-AdversaryBattery.ps1
Invoke-AdversaryBattery -Target $svc -Contract EncryptDecrypt

# With output path
Invoke-AdversaryBattery -Target $svc -Contract EncryptDecrypt -OutputPath ./report.json -ReportFormat Both
```

## Output

The JSON report contains the full evaluation hashtable with per-test results, thresholds comparison, and a score. The markdown summary provides a human-readable report with pass/fail counts, threshold violations, and a findings table.

## Thresholds

See [thresholds.json](thresholds.json). Thresholds represent the acceptable operational floor for each pattern based on findings from the PSCertPatterns adversarial test suite.

## Discover Mode

```powershell
Invoke-AdversaryBattery -Target $svc -Discover
```

Inspects the target object's methods and suggests which contracts it may satisfy. Does not run the battery. Caller must explicitly pass -Contract to run tests.

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
