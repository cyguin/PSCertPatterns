BeforeAll {
    . "$PSScriptRoot/../src/01_AesGcm.ps1"
}

Describe "AesGcmService" {

    Context "Construction" {
        It "Accepts a valid 32-byte key" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Throws ArgumentException for 15-byte key" {
            { [AesGcmService]::new([byte[]]::new(15)) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Throws ArgumentException for 17-byte key" {
            { [AesGcmService]::new([byte[]]::new(17)) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Throws ArgumentException for 31-byte key" {
            { [AesGcmService]::new([byte[]]::new(31)) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Throws ArgumentException for 33-byte key" {
            { [AesGcmService]::new([byte[]]::new(33)) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Encrypt" {
        It "Returns byte array of length plaintext + 28" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("Hello, world!")
            $result = $svc.Encrypt($plaintext)
            $result.Length | Should -Be ($plaintext.Length + 28)
            $svc.Dispose()
        }

        It "Produces different output for two encryptions of identical plaintext" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("data")
            $a = $svc.Encrypt($plaintext)
            $b = $svc.Encrypt($plaintext)
            $result = [System.Linq.Enumerable]::SequenceEqual($a, $b)
            $result | Should -Be $false
            $svc.Dispose()
        }
    }

    Context "Round trip" {
        It "Decrypt returns original plaintext" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("Round-trip test payload")
            $encrypted = $svc.Encrypt($plaintext)
            $decrypted = $svc.Decrypt($encrypted)
            $decrypted | Should -Be $plaintext
            $svc.Dispose()
        }
    }

    Context "Tamper detection" {
        It "Throws CryptographicException on tampered ciphertext" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $encrypted = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $encrypted[30] = $encrypted[30] -bxor 255
            { $svc.Decrypt($encrypted) } | Should -Throw
            $svc.Dispose()
        }

        It "Throws CryptographicException on tampered tag" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $encrypted = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $encrypted[13] = $encrypted[13] -bxor 255
            { $svc.Decrypt($encrypted) } | Should -Throw
            $svc.Dispose()
        }

        It "Throws CryptographicException on tampered nonce" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $encrypted = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $encrypted[5] = $encrypted[5] -bxor 255
            { $svc.Decrypt($encrypted) } | Should -Throw
            $svc.Dispose()
        }
    }

    Context "Associated data" {
        It "Round-trips with valid AAD" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("with AAD")
            $aad = [System.Text.Encoding]::UTF8.GetBytes("header")
            $encrypted = $svc.Encrypt($plaintext, $aad)
            $decrypted = $svc.Decrypt($encrypted, $aad)
            $decrypted | Should -Be $plaintext
            $svc.Dispose()
        }

        It "Throws CryptographicException on mismatched AAD" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $encrypted = $svc.Encrypt(
                [System.Text.Encoding]::UTF8.GetBytes("with AAD"),
                [System.Text.Encoding]::UTF8.GetBytes("correct-aad")
            )
            $exception = { $svc.Decrypt($encrypted, [System.Text.Encoding]::UTF8.GetBytes("wrong-aad")) } | Should -Throw -PassThru
            $exception.Exception.InnerException | Should -BeOfType ([System.Security.Cryptography.CryptographicException])
            $svc.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on Encrypt after Dispose" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $svc.Dispose()
            { $svc.Encrypt([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on Decrypt after Dispose" {
            $key = [byte[]]::new(32)
            $svc = [AesGcmService]::new($key)
            $encrypted = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
            $svc.Dispose()
            { $svc.Decrypt($encrypted) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}
