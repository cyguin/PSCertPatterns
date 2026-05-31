# Slice 5 tests — all RSA operations use 2048-bit keys to keep the suite fast

BeforeAll {
    . "$PSScriptRoot/../src/05_Rsa.ps1"
}

Describe "RsaEncryptionService" {
    Context "Construction" {
        It "Accepts 2048-bit key" {
            $svc = [RsaEncryptionService]::new(2048)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts 3072-bit key" {
            $svc = [RsaEncryptionService]::new(3072)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts 4096-bit key" {
            $svc = [RsaEncryptionService]::new(4096)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Invalid key size 1024 throws ArgumentException" {
            { [RsaEncryptionService]::new(1024) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Invalid key size 1023 throws ArgumentException" {
            { [RsaEncryptionService]::new(1023) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Encrypt" {
        It "Returns ciphertext of length equal to key size in bytes" {
            $svc = [RsaEncryptionService]::new(2048)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("Hello RSA")
            $ciphertext = $svc.Encrypt($plaintext)
            $ciphertext.Length | Should -Be 256
            $svc.Dispose()
        }

        It "Two encryptions of identical plaintext produce different output" {
            $svc = [RsaEncryptionService]::new(2048)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("random")
            $a = $svc.Encrypt($plaintext)
            $b = $svc.Encrypt($plaintext)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
            $svc.Dispose()
        }
    }

    Context "Round trip" {
        It "Decrypt round-trips correctly" {
            $svc = [RsaEncryptionService]::new(2048)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("RSA round-trip payload")
            $ciphertext = $svc.Encrypt($plaintext)
            $decrypted = $svc.Decrypt($ciphertext)
            $decrypted | Should -Be $plaintext
            $svc.Dispose()
        }

        It "Tampered ciphertext throws CryptographicException" {
            $svc = [RsaEncryptionService]::new(2048)
            $ciphertext = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $ciphertext[10] = $ciphertext[10] -bxor 255
            { $svc.Decrypt($ciphertext) } | Should -Throw
            $svc.Dispose()
        }
    }

    Context "Key export" {
        It "ExportPublicKey returns non-empty byte array" {
            $svc = [RsaEncryptionService]::new(2048)
            $pubKey = $svc.ExportPublicKey()
            $pubKey.Length | Should -BeGreaterThan 0
            $svc.Dispose()
        }

        It "ExportPrivateKey returns non-empty byte array" {
            $svc = [RsaEncryptionService]::new(2048)
            $privKey = $svc.ExportPrivateKey()
            $privKey.Length | Should -BeGreaterThan 0
            $svc.Dispose()
        }
    }

    Context "FromPublicKey" {
        It "Constructs without error" {
            $signer = [RsaEncryptionService]::new(2048)
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [RsaEncryptionService]::FromPublicKey($pubKey)
            $fromPub | Should -Not -BeNullOrEmpty
            $signer.Dispose()
            $fromPub.Dispose()
        }

        It "Decrypt on public-key-only instance throws InvalidOperationException" {
            $signer = [RsaEncryptionService]::new(2048)
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [RsaEncryptionService]::FromPublicKey($pubKey)
            { $fromPub.Decrypt([byte[]]::new(256)) } | Should -Throw -ExceptionType ([System.InvalidOperationException])
            $signer.Dispose()
            $fromPub.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on Encrypt after Dispose" {
            $svc = [RsaEncryptionService]::new(2048)
            $svc.Dispose()
            { $svc.Encrypt([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on Decrypt after Dispose" {
            $svc = [RsaEncryptionService]::new(2048)
            $svc.Dispose()
            { $svc.Decrypt([byte[]]::new(256)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}

Describe "RsaSigningService" {
    Context "Construction" {
        It "Accepts 2048-bit key" {
            $svc = [RsaSigningService]::new(2048)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts 3072-bit key" {
            $svc = [RsaSigningService]::new(3072)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts 4096-bit key" {
            $svc = [RsaSigningService]::new(4096)
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Invalid key size throws ArgumentException" {
            { [RsaSigningService]::new(1024) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Sign and Verify" {
        It "Sign returns byte array of length equal to key size in bytes" {
            $svc = [RsaSigningService]::new(2048)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data to sign")
            $sig = $svc.Sign($data)
            $sig.Length | Should -Be 256
            $svc.Dispose()
        }

        It "Verify returns true for valid signature" {
            $svc = [RsaSigningService]::new(2048)
            $data = [System.Text.Encoding]::UTF8.GetBytes("verify me")
            $sig = $svc.Sign($data)
            $svc.Verify($data, $sig) | Should -Be $true
            $svc.Dispose()
        }

        It "Verify returns false for tampered data" {
            $svc = [RsaSigningService]::new(2048)
            $data = [System.Text.Encoding]::UTF8.GetBytes("original")
            $sig = $svc.Sign($data)
            $tampered = [System.Text.Encoding]::UTF8.GetBytes("tampered")
            $svc.Verify($tampered, $sig) | Should -Be $false
            $svc.Dispose()
        }

        It "Verify returns false for tampered signature" {
            $svc = [RsaSigningService]::new(2048)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $sig = $svc.Sign($data)
            $sig[10] = $sig[10] -bxor 255
            $svc.Verify($data, $sig) | Should -Be $false
            $svc.Dispose()
        }

        It "Verify returns false for wrong key" {
            $signer = [RsaSigningService]::new(2048)
            $other = [RsaSigningService]::new(2048)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $sig = $signer.Sign($data)
            $pubKeyOther = $other.ExportPublicKey()
            $verifier = [RsaSigningService]::FromPublicKey($pubKeyOther)
            $verifier.Verify($data, $sig) | Should -Be $false
            $signer.Dispose()
            $other.Dispose()
            $verifier.Dispose()
        }

        It "Verify never throws on invalid signature — must return false only" {
            $svc = [RsaSigningService]::new(2048)
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $sig = $svc.Sign($data)
            $tampered = [System.Text.Encoding]::UTF8.GetBytes("tampered")
            $result = $false
            { $result = $svc.Verify($tampered, $sig) } | Should -Not -Throw
            $result | Should -Be $false
            $svc.Dispose()
        }
    }

    Context "Key export" {
        It "ExportPublicKey returns non-empty byte array" {
            $svc = [RsaSigningService]::new(2048)
            $pubKey = $svc.ExportPublicKey()
            $pubKey.Length | Should -BeGreaterThan 0
            $svc.Dispose()
        }
    }

    Context "FromPublicKey" {
        It "Constructs without error" {
            $signer = [RsaSigningService]::new(2048)
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [RsaSigningService]::FromPublicKey($pubKey)
            $fromPub | Should -Not -BeNullOrEmpty
            $signer.Dispose()
            $fromPub.Dispose()
        }

        It "Sign on public-key-only instance throws InvalidOperationException" {
            $signer = [RsaSigningService]::new(2048)
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [RsaSigningService]::FromPublicKey($pubKey)
            { $fromPub.Sign([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.InvalidOperationException])
            $signer.Dispose()
            $fromPub.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on Sign after Dispose" {
            $svc = [RsaSigningService]::new(2048)
            $svc.Dispose()
            { $svc.Sign([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on Verify after Dispose" {
            $svc = [RsaSigningService]::new(2048)
            $svc.Dispose()
            { $svc.Verify([byte[]]::new(1), [byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}
