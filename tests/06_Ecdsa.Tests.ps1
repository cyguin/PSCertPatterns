BeforeAll {
    . "$PSScriptRoot/../src/06_Ecdsa.ps1"
}

Describe "EcdsaSigningService" {
    Context "Construction" {
        It "Accepts curve P-256" {
            $svc = [EcdsaSigningService]::new("P-256")
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts curve P-384" {
            $svc = [EcdsaSigningService]::new("P-384")
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Accepts curve P-521" {
            $svc = [EcdsaSigningService]::new("P-521")
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "Invalid curve P-128 throws ArgumentException" {
            { [EcdsaSigningService]::new("P-128") } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Invalid curve secp256k1 throws ArgumentException" {
            { [EcdsaSigningService]::new("secp256k1") } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Sign" {
        It "Returns non-empty byte array" {
            $svc = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $sig = $svc.Sign($data)
            $sig.Length | Should -BeGreaterThan 0
            $svc.Dispose()
        }

        It "Two signs of identical data produce different signatures" {
            $svc = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("same data")
            $a = $svc.Sign($data)
            $b = $svc.Sign($data)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
            $svc.Dispose()
        }
    }

    Context "Verify" {
        It "Returns true for valid signature" {
            $svc = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("verify me")
            $sig = $svc.Sign($data)
            $svc.Verify($data, $sig) | Should -Be $true
            $svc.Dispose()
        }

        It "Returns false for tampered data" {
            $svc = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("original")
            $sig = $svc.Sign($data)
            $tampered = [System.Text.Encoding]::UTF8.GetBytes("tampered")
            $svc.Verify($tampered, $sig) | Should -Be $false
            $svc.Dispose()
        }

        It "Returns false for tampered signature" {
            $svc = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $sig = $svc.Sign($data)
            $sig[5] = $sig[5] -bxor 255
            $svc.Verify($data, $sig) | Should -Be $false
            $svc.Dispose()
        }

        It "Returns false for wrong key instance" {
            $a = [EcdsaSigningService]::new("P-256")
            $b = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("data")
            $sig = $a.Sign($data)
            $b.Verify($data, $sig) | Should -Be $false
            $a.Dispose()
            $b.Dispose()
        }

        It "Verify never throws on invalid signature — must return false only" {
            $svc = [EcdsaSigningService]::new("P-256")
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
            $svc = [EcdsaSigningService]::new("P-256")
            $pubKey = $svc.ExportPublicKey()
            $pubKey.Length | Should -BeGreaterThan 0
            $svc.Dispose()
        }

        It "ExportPrivateKey returns non-empty byte array on full-key instance" {
            $svc = [EcdsaSigningService]::new("P-256")
            $privKey = $svc.ExportPrivateKey()
            $privKey.Length | Should -BeGreaterThan 0
            $svc.Dispose()
        }
    }

    Context "FromPublicKey" {
        It "Constructs without error" {
            $signer = [EcdsaSigningService]::new("P-256")
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [EcdsaSigningService]::FromPublicKey($pubKey)
            $fromPub | Should -Not -BeNullOrEmpty
            $signer.Dispose()
            $fromPub.Dispose()
        }

        It "Sign on public-key-only instance throws InvalidOperationException" {
            $signer = [EcdsaSigningService]::new("P-256")
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [EcdsaSigningService]::FromPublicKey($pubKey)
            { $fromPub.Sign([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.InvalidOperationException])
            $signer.Dispose()
            $fromPub.Dispose()
        }

        It "ExportPrivateKey on public-key-only instance throws InvalidOperationException" {
            $signer = [EcdsaSigningService]::new("P-256")
            $pubKey = $signer.ExportPublicKey()
            $fromPub = [EcdsaSigningService]::FromPublicKey($pubKey)
            { $fromPub.ExportPrivateKey() } | Should -Throw -ExceptionType ([System.InvalidOperationException])
            $signer.Dispose()
            $fromPub.Dispose()
        }

        It "FromPublicKey + Verify round-trips correctly" {
            $signer = [EcdsaSigningService]::new("P-256")
            $data = [System.Text.Encoding]::UTF8.GetBytes("round-trip")
            $sig = $signer.Sign($data)
            $pubKey = $signer.ExportPublicKey()
            $verifier = [EcdsaSigningService]::FromPublicKey($pubKey)
            $verifier.Verify($data, $sig) | Should -Be $true
            $signer.Dispose()
            $verifier.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on Sign after Dispose" {
            $svc = [EcdsaSigningService]::new("P-256")
            $svc.Dispose()
            { $svc.Sign([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on Verify after Dispose" {
            $svc = [EcdsaSigningService]::new("P-256")
            $svc.Dispose()
            { $svc.Verify([byte[]]::new(1), [byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}
