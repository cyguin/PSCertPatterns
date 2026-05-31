# PSCertPatterns Decisions

## 2026-05-30 — AesGcmService Slice 1

### `-bxor` is a binary infix operator in PowerShell
`-bxor` cannot be used in prefix form (`-bxor $a $b`). It is a binary infix operator and must be written as `$a -bxor $b`.

### `-bnot` returns signed integer, overflows byte assignment
`-bnot [byte]` returns a negative `[int]`, which cannot be assigned back to a `[byte[]]` element. Use `$a -bxor 255` to flip all bits within byte range.

### PowerShell wraps .NET exceptions in MethodInvocationException
When a .NET method called via PowerShell throws an exception (e.g. `AuthenticationTagMismatchException` from `AesGcm.Decrypt`), PowerShell wraps it in `MethodInvocationException`. Tests should either:
- Use bare `Should -Throw` (any exception), or
- Use `Should -Throw -PassThru` then inspect `$exception.Exception.InnerException` with `Should -BeOfType`

## 2026-05-30 — Key Derivation Slice 2

### Rfc2898DeriveBytes try/finally disposal
`Rfc2898DeriveBytes` implements `IDisposable`. The `DeriveKey` methods wrap the constructor and `GetBytes` call in a try/finally block, initializing `$deriveBytes` to `$null` before the try so the finally can safely dispose only on non-null.

### 3-parameter overload delegates to 4-parameter overload
`DeriveKey(password, salt, keySize)` calls `DeriveKey(password, salt, keySize, 600000)` to avoid duplicating validation logic and the try/finally disposal pattern. This keeps iteration count default (600000) in a single location.

### Static class pattern in PowerShell
`SaltGenerator` and `Pbkdf2KeyDerivation` use the PowerShell `class` keyword with `static` methods only. No constructor is defined. This matches the intended usage pattern (no instance needed) and avoids the need for a private constructor (PowerShell classes do not support private constructors meaningfully).

### No behavioral surprises
Implementation matched expectations. All 14 tests passed on first run with no PowerShell or .NET interop quirks. The `Should -Throw -ExceptionType` pattern established in slice 1 works correctly for ArgumentException thrown directly from PowerShell code.

## 2026-05-30 — Nonce Management Slice 3

### `[System.Threading.Interlocked]::Increment` incompatible with `[ref]` on class fields
`[ref]` in PowerShell creates a `PSReference` wrapper object, not a true managed by-ref pointer (`T&`). .NET methods like `Interlocked::Increment(Increment&)` require the latter and silently fail (no exception, no modification) when given a `PSReference`. Replaced with `$this._counter++`. For true concurrent scenarios, a `[System.Threading.Monitor]` / lock pattern would be needed.

### PowerShell array slice returns object[], not byte[]
`$nonce[0..7]` produces `System.Object[]`, not `System.Byte[]`. This causes `Enumerable::SequenceEqual` to fail ("Cannot find an overload"). The fix is to explicitly cast: `[byte[]]$nonce[0..7]`. This is a general PowerShell quirk — range-indexed slices lose the source array's type.

### Direct bit-shift for big-endian test verification
The incrementing nonce test reads the big-endian counter from the last 4 nonce bytes. Using `BitConverter::ToUInt32` followed by `IPAddress::NetworkToHostOrder` introduced complexity. Simplified to direct bit-shift reconstruction: `($b[0] -shl 24) -bor ($b[1] -shl 16) -bor ($b[2] -shl 8) -bor $b[3]`. This is unambiguous and avoids platform endianness concerns.

## 2026-05-30 — Encrypt-then-MAC / AES-CBC Slice 4

### No behavioral surprises
Implementation matched expectations. All 27 slice 4 tests passed on first run with no PowerShell or .NET interop quirks.

### Key disposal via `Array::Clear` is by-reference
`AesCbcService.Dispose()` calls `[System.Array]::Clear()` on the stored `$_encryptionKey` and `$_macKey` references. Since .NET arrays are reference types, this zeroes out the caller's original arrays too. This is intentional — cryptographic key material should not persist in memory after disposal. Callers must copy keys if they need them after the service is disposed.

### Encrypt-then-MAC order is enforced structurally
The `Decrypt` method verifies the MAC (via `CryptographicOperations::FixedTimeEquals`) and throws `CryptographicException` before any AES decryption call. This prevents padding-oracle attacks by never exposing decryption failure types to the caller when the MAC is invalid.

### AesCbcService verifies MAC before touching AES
The MAC input is `iv + ciphertext` (not plaintext). The `Decrypt` method splits the package, reconstructs `iv + ciphertext`, computes HMAC-SHA256, and compares with `FixedTimeEquals`. Only on success does it proceed to AES-CBC decryption. This ensures tampering is detected before any padding or plaintext data is exposed.

## 2026-05-30 — RSA Encryption and Signing Slice 5

### No behavioral surprises
Implementation matched expectations. All 30 slice 5 tests passed on first run. RSA key generation via `RSA::Create(keySizeInBits)` works as expected with OAEP SHA-256 padding and PSS signatures.

### Public-key-only instance pattern via `_hasPrivateKey` flag
Both `RsaEncryptionService` and `RsaSigningService` use a `$_hasPrivateKey` field to distinguish full-key-pair instances from public-key-only instances created via `FromPublicKey`. `Decrypt` (encryption service) and `Sign` (signing service) check this flag and throw `InvalidOperationException` when the instance lacks a private key. `Encrypt` and `Verify` work on public-key-only instances without restriction.

### FromPublicKey wastes a key generation
`FromPublicKey` calls the public constructor (which generates a new RSA key pair) then immediately replaces `_rsa` and disposes the generated key. PowerShell classes do not support private constructors or parameterless constructors in a way that would allow skipping this. The overhead is ~100ms for 2048-bit and acceptable for a static factory.

### FromPublicKey uses ImportSubjectPublicKeyInfo with [ref] out parameter
`RSA.ImportSubjectPublicKeyInfo(byte[], out int bytesRead)` requires a by-ref out parameter in .NET. PowerShell's `[ref]$bytesRead` works correctly here, unlike the `Interlocked::Increment` case from slice 3, because `ImportSubjectPublicKeyInfo` is designed to accept a `ref` parameter (passed as `T&` by the runtime), not a `PSReference`.

## 2026-05-30 — ECDSA Signing Slice 6

### `ECCurve.CreateFromFriendlyName` fails on macOS
`ECCurve.CreateFromFriendlyName("P-256")` throws `PlatformNotSupportedException` on macOS (Darwin). The friendly name "P-256" is not recognized by the Apple Security framework that backs .NET's ECDsa implementation on macOS.

- **What was tried**: `CreateFromFriendlyName` with "P-256", "P-384", "P-521" — all failed
- **What fixed it**: Used `ECCurve.CreateFromOid(Oid)` with explicit OID values:
  - P-256 → `1.2.840.10045.3.1.7`
  - P-384 → `1.3.132.0.34`
  - P-521 → `1.3.132.0.35`
- **Why it matters**: OID-based curve specification is platform-independent and guarantees cross-platform compatibility. Any future ECC work should prefer `CreateFromOid` over `CreateFromFriendlyName`.

## 2026-05-30 — Certificate Chain Validation and InMemoryPki Slice 7

### UntrustedRoot chain status persists with AllowUnknownCertificateAuthority on macOS
`X509Chain.Build()` returns `true` for a self-signed cert with `AllowUnknownCertificateAuthority` set, but the `ChainStatus` still contains an `UntrustedRoot` entry. The chain IS built successfully — the flag prevents build failure but doesn't suppress the status report.

- **What was tried**: Initially filtered chain errors naively; `AllowUntrustedRoot` tests failed
- **What fixed it**: Added a filter in the error collection loop: `if ($AllowUntrustedRoot -and $status.Status -eq UntrustedRoot) { continue }`
- **Why it matters**: The X509Chain API distinguishes "chain built successfully" from "chain is trusted." On macOS, trusting an untrusted root requires explicit status filtering. This pattern should be used whenever `AllowUnknownCertificateAuthority` is set.

### CertificateRequest.Create() notBefore must be >= issuer's NotBefore
`CertificateRequest.Create(issuer, notBefore, notAfter, serial)` validates that the issued cert's `notBefore` is not earlier than the issuer's `NotBefore`. The spec's "-1min" offset for clock skew caused a failure when the leaf was issued within seconds of root creation.

- **What was fixed**: Clamped `notBefore` to `max(now - 1min, root.NotBefore)` before calling `Create()`
- **Why it matters**: Certificate validity windows must always fall within the issuer's validity. Any future cert issuance logic must clamp notBefore/notAfter against the issuer's bounds.

### CopyWithPrivateKey overload resolution fails on macOS for RSA
`$cert.CopyWithPrivateKey($rsaKey)` fails on macOS because PowerShell resolves the call to the `ECDiffieHellman` overload instead of `RSA`. The macOS RSA implementation (`RSASecurityTransforms`) apparently implements interfaces that create overload ambiguity.

- **What was tried**: Explicit cast `[System.Security.Cryptography.RSA]$leafKey` — still failed
- **What fixed it**: Calling the extension method directly as a static method on the declaring class: `[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($signed, $leafKey)`
- **Why it matters**: Extension method calls on platform-specific types can produce ambiguous overload resolution in PowerShell. Calling extension methods as static methods on their declaring class bypasses this ambiguity entirely.

## 2026-05-30 — RotatingKeyManager Slice 8

### No behavioral surprises
Implementation matched expectations. All 21 slice 8 tests passed on first run with no PowerShell or .NET interop quirks.

### Inline AES-GCM recurrence
`RotatingKeyManager` duplicates the AES-GCM encrypt/decrypt logic from slice 1 internally rather than depending on `AesGcmService`. This preserves the one-file-per-pattern design. The inlined code uses the same `System.Security.Cryptography.AesGcm` API with 12-byte nonce, 16-byte tag, and `nonce+tag+ciphertext` package format.

### Queue + Dictionary eviction pattern
`RotatingKeyManager` uses a `Queue<string>` to track key insertion order and a `Dictionary<string, byte[]>` for key lookup by ID. Eviction dequeues the oldest key ID, clears the associated byte array via `Array::Clear`, and removes the dictionary entry. This ensures forward secrecy: once a key is evicted, its material is zeroed and unrecoverable.

### Array::Clear on evicted keys
When a key is evicted (retention window exceeded), `Array::Clear` zeroes the key bytes before removing the dictionary entry. The Dispose method does the same for all remaining keys. This ensures key material does not persist in process memory after it is no longer needed.

## 2026-05-30 — Algorithm Agility Slice 9

### No behavioral surprises
Implementation matched expectations. All 22 slice 9 tests passed on first run with no PowerShell or .NET interop quirks.

### Static constructor pattern for registry initialization
`AlgorithmRegistry` uses a PowerShell `static` constructor (`static AlgorithmRegistry()`) to initialize the built-in `$_profiles` dictionary with the four default `CipherProfile` entries. This ensures the registry is populated on first access without requiring explicit initialization.

### Mutating registry state in tests
The `Register` and `Deprecate` tests modify the static registry state. Tests that register/deprecate profiles clean up after themselves (e.g. resetting deprecated profiles back). However, the "Register replaces an existing profile" test permanently changes the `KdfIterations` for `AES-256-GCM` from 600000 to 999999 — this is acceptable since the registry is mutable by design and later tests check for structural properties (name, algorithm) rather than exact iteration values.

## Adversarial Test Suite — Threshold Findings (2026-05-30)

### AES-GCM
- Zero-length plaintext: allowed, package size = 28 bytes (12 nonce + 16 tag + 0 ciphertext)
- Single-byte plaintext: package size = 29 bytes
- All nonce, tag, and ciphertext positions cause authentication failure when bit-flipped (GCM authenticates the entire ciphertext + nonce + AAD)
- All-zero key (32 bytes): AesGcmService accepts and encrypts without error (AES-GCM does not reject weak keys)
- All-zero plaintext: round-trips correctly

### HMAC-CBC
- Zero-length plaintext: allowed, package size = 64 bytes (16 IV + 16 ciphertext (PKCS7 full block) + 32 HMAC)
- IV byte-flip detection confirmed: both IV byte 0 and IV byte 15 cause Decrypt to throw
- Ciphertext tamper detection confirmed: MAC covers IV + ciphertext
- MAC truncation (strip last byte): correctly caught
- IV swap between two packages: both throw (MAC covers IV)
- Wrong MAC key: correctly caught

### PBKDF2
- Minimum iteration count: none enforced by .NET — 1 iteration succeeds (caller responsibility to set sane minimum)
- Key size minimum: 16 bytes (enforced by our validation)
- Key size maximum: no upper limit (tested up to 64 bytes, succeeds)
- Password length: no practical limit (tested 10000 characters, succeeds; theoretical limit is CLR object size)
- Salt uniqueness: caller responsibility — deterministic by design for same password + salt
- Salt minimum: 16 bytes (enforced by our validation)

### Nonce Uniqueness
- CounterNonceGenerator (10000 samples): 10000/10000 unique, confirmed monotonically increasing
- RandomNonceGenerator (10000 samples): 10000/10000 unique with random 12-byte nonces
- Theoretical collision probability for RandomNonceGenerator at 10000 samples: negligible (birthday bound for 96-bit random space is ~2^48)
- Two CounterNonceGenerator instances with identical keyId produce identical first nonce (expected — both start with counter=1)

### RSA
- OAEP-SHA256 max plaintext for 2048-bit key: 190 bytes (256 - 2 - 2*32 = 190)
- 191 bytes throws CryptographicException
- Zero-length plaintext: allowed, round-trips correctly (encrypts to 256-byte ciphertext)
- Zero-length data signature: allowed, verifies correctly
- Cross-key verification: returns false (not throws)
- Tampered signature (1-bit flip): returns false (not throws)

### Key Rotation
- Window=1: Rotate() evicts original key; Decrypt with original KeyId throws
- Window=3: KeyCount never exceeds 3 after any number of rotations
- Encrypt-before-Rotate pattern: with 10 rotation cycles and window=3, only 2 packages remain decryptable (because the 10th rotation's key never encrypts a package)
- After Dispose(): `_keys` dictionary is empty (verified via direct access to hidden field)

### Certificate Chain
- Cross-PKI rejection confirmed: leaf from PKI A validated with PKI B's root returns IsValid=false
- Expired cert with 1ms validity window: correctly detected (requires `Start-Sleep -Milliseconds 100` after creation to ensure expiry)
- Thumbprint pinning with multiple pins: cert matching any pinned thumbprint passes
- Empty subject "CN=": CertificateRequest accepts without error; subject is confirmed as containing "CN="

### Acceptable Thresholds Summary

| Pattern | Threshold | Acceptable Floor | Notes |
|---------|-----------|-----------------|-------|
| AES-GCM nonce | Random 12 bytes | Never reuse per key | Birthday bound ~2^48 |
| AES-GCM key size | 256 bits | 128 bits minimum | Zero-key is accepted by API |
| PBKDF2 iterations | 600000 | 310000 minimum (OWASP 2024) | Increase yearly |
| PBKDF2 salt size | 32 bytes | 16 bytes minimum | Caller must ensure uniqueness |
| RSA key size | 2048 bits | 2048 minimum | 3072 for post-2030 |
| RSA OAEP max plaintext | 190 bytes (2048-bit) | KeySize/8 - 66 | 66 = 2 + 2*32 (SHA-256) |
| Retention window | configurable | >= 2 recommended | Window=1 = no overlap |
| ECDSA curve | P-256 | P-256 minimum | P-384 for high-security |
| Random nonce uniqueness | 10000/10000 at 12 bytes | ~2^48 birthday bound | CSPRNG behavior confirmed |
| Counter nonce uniqueness | 10000/10000 at 12 bytes | Deterministic | Monotonically increasing |

## 2026-05-30 — Nonce Replay Protection Slice 10

### No behavioral surprises
Implementation matched expectations. All 20 slice 10 tests passed on first run with no PowerShell or .NET interop quirks.

### HashSet + Queue eviction pattern
`NonceReplayGuard` mirrors the `RotatingKeyManager` eviction pattern from slice 8: a `HashSet<string>` for O(1) lookup and a `Queue<string>` for FIFO eviction tracking. When the set exceeds `windowSize`, the oldest entry (from queue front) is removed from both structures.

### Base64 encoding for nonce storage
Nonces are converted to Base64 strings (`Convert::ToBase64String`) before being stored in the HashSet. This avoids storing raw byte arrays as dictionary keys (which would require a custom comparer) and makes debugging/verification straightforward.

### Null validation via NonceToKey helper
`CheckAndRecord` and `HasSeen` delegate null validation to a shared `NonceToKey` helper method that throws `ArgumentNullException` for null nonces. This deduplicates validation logic while ensuring consistent error behavior.
