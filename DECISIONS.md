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
