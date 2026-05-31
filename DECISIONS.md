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
