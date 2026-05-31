BeforeAll {
    . "$PSScriptRoot/../src/04_HmacCbc.ps1"
}

Describe "HmacService" {
    Context "Sign" {
        It "Returns 32-byte HMAC" {
            $key = [byte[]]::new(32)
            $data = [System.Text.Encoding]::UTF8.GetBytes("test data")
            $mac = [HmacService]::Sign($data, $key)
            $mac.Length | Should -Be 32
        }

        It "Same inputs produce same HMAC" {
            $key = [byte[]]::new(32)
            $data = [System.Text.Encoding]::UTF8.GetBytes("consistent")
            $a = [HmacService]::Sign($data, $key)
            $b = [HmacService]::Sign($data, $key)
            [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($a, $b) | Should -Be $true
        }

        It "Different data produces different HMAC" {
            $key = [byte[]]::new(32)
            $a = [HmacService]::Sign([System.Text.Encoding]::UTF8.GetBytes("data-a"), $key)
            $b = [HmacService]::Sign([System.Text.Encoding]::UTF8.GetBytes("data-b"), $key)
            [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($a, $b) | Should -Be $false
        }

        It "Different keys produce different HMAC" {
            $key1 = [byte[]]::new(32)
            $key2 = [byte[]]::new(32); $key2[0] = 1
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $a = [HmacService]::Sign($data, $key1)
            $b = [HmacService]::Sign($data, $key2)
            [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($a, $b) | Should -Be $false
        }
    }

    Context "Verify" {
        It "Returns true for valid MAC" {
            $key = [byte[]]::new(32)
            $data = [System.Text.Encoding]::UTF8.GetBytes("verify me")
            $mac = [HmacService]::Sign($data, $key)
            [HmacService]::Verify($data, $key, $mac) | Should -Be $true
        }

        It "Returns false for tampered data" {
            $key = [byte[]]::new(32)
            $data = [System.Text.Encoding]::UTF8.GetBytes("original")
            $mac = [HmacService]::Sign($data, $key)
            $tampered = [System.Text.Encoding]::UTF8.GetBytes("tampered")
            [HmacService]::Verify($tampered, $key, $mac) | Should -Be $false
        }

        It "Returns false for tampered MAC" {
            $key = [byte[]]::new(32)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $mac = [HmacService]::Sign($data, $key)
            $mac[0] = ($mac[0] -bxor 255)
            [HmacService]::Verify($data, $key, $mac) | Should -Be $false
        }

        It "Returns false for wrong key" {
            $key1 = [byte[]]::new(32)
            $key2 = [byte[]]::new(32); $key2[0] = 1
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $mac = [HmacService]::Sign($data, $key1)
            [HmacService]::Verify($data, $key2, $mac) | Should -Be $false
        }
    }

    Context "Validation" {
        It "Null data throws" {
            $key = [byte[]]::new(32)
            { [HmacService]::Sign($null, $key) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Null key throws" {
            $data = [byte[]]::new(1)
            { [HmacService]::Sign($data, $null) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Null expectedMac throws" {
            $key = [byte[]]::new(32)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            { [HmacService]::Verify($data, $key, $null) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Key under 32 bytes throws" {
            $shortKey = [byte[]]::new(31)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            { [HmacService]::Sign($data, $shortKey) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }
}

Describe "AesCbcService" {
    Context "Construction" {
        It "Accepts 16-byte encryption key" {
            $encKey = [byte[]]::new(16)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts 24-byte encryption key" {
            $encKey = [byte[]]::new(24)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts 32-byte encryption key" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Invalid encryption key size throws ArgumentException" {
            $badKey = [byte[]]::new(15)
            $macKey = [byte[]]::new(32)
            { [AesCbcService]::new($badKey, $macKey) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "macKey under 32 bytes throws ArgumentException" {
            $encKey = [byte[]]::new(16)
            $shortMacKey = [byte[]]::new(31)
            { [AesCbcService]::new($encKey, $shortMacKey) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Encrypt" {
        It "Returns package of length >= IV + HMAC (48)" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("Hello")
            $result = $svc.Encrypt($plaintext)
            $result.Length | Should -BeGreaterOrEqual 48
            $svc.Dispose()
        }

        It "Two encryptions of identical plaintext produce different output" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("unique")
            $a = $svc.Encrypt($plaintext)
            $b = $svc.Encrypt($plaintext)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
            $svc.Dispose()
        }

        It "Decrypt round-trips correctly" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("Round-trip AES-CBC payload")
            $encrypted = $svc.Encrypt($plaintext)
            $decrypted = $svc.Decrypt($encrypted)
            $decrypted | Should -Be $plaintext
            $svc.Dispose()
        }
    }

    Context "Tamper detection" {
        It "Tampered ciphertext throws CryptographicException" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $package = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $package[20] = $package[20] -bxor 255
            { $svc.Decrypt($package) } | Should -Throw
            $svc.Dispose()
        }

        It "Tampered IV throws CryptographicException" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $package = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $package[5] = $package[5] -bxor 255
            { $svc.Decrypt($package) } | Should -Throw
            $svc.Dispose()
        }

        It "Tampered HMAC throws CryptographicException" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $package = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $package[-1] = $package[-1] -bxor 255
            { $svc.Decrypt($package) } | Should -Throw
            $svc.Dispose()
        }

        It "MAC verification happens before decryption" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $package = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
            $package[-1] = $package[-1] -bxor 255
            { $svc.Decrypt($package) } | Should -Throw -ExceptionType ([System.Security.Cryptography.CryptographicException])
            $svc.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on Encrypt after Dispose" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $svc.Dispose()
            { $svc.Encrypt([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on Decrypt after Dispose" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $svc.Dispose()
            { $svc.Decrypt([byte[]]::new(48)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Dispose clears key material" {
            $encKey = [byte[]]::new(32)
            $macKey = [byte[]]::new(32)
            $svc = [AesCbcService]::new($encKey, $macKey)
            $svc.Dispose()
            $encCleared = $true
            foreach ($b in $svc._encryptionKey) {
                if ($b -ne 0) { $encCleared = $false; break }
            }
            $macCleared = $true
            foreach ($b in $svc._macKey) {
                if ($b -ne 0) { $macCleared = $false; break }
            }
            $encCleared | Should -Be $true
            $macCleared | Should -Be $true
        }
    }
}
