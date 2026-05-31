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
