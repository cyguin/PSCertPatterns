BeforeAll {
    . "$PSScriptRoot/../src/08_KeyRotation.ps1"
}

Describe "EncryptedPackage" {
    It "Constructs with KeyId and Ciphertext" {
        $pkg = [EncryptedPackage]::new("key-1", [byte[]]::new(3))
        $pkg | Should -Not -BeNullOrEmpty
    }

    It "KeyId and Ciphertext properties return expected values" {
        $data = [byte[]]::new(3)
        $pkg = [EncryptedPackage]::new("test-key", $data)
        $pkg.KeyId | Should -Be "test-key"
        $pkg.Ciphertext | Should -Be $data
    }
}

Describe "RotatingKeyManager" {
    Context "Construction" {
        It "retentionWindow < 1 throws ArgumentException" {
            { [RotatingKeyManager]::new(0) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "retentionWindow = 1 constructs without error" {
            $mgr = [RotatingKeyManager]::new(1)
            $mgr | Should -Not -BeNullOrEmpty
            $mgr.Dispose()
        }

        It "retentionWindow = 3 constructs without error" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr | Should -Not -BeNullOrEmpty
            $mgr.Dispose()
        }

        It "After construction KeyCount() == 1" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr.KeyCount() | Should -Be 1
            $mgr.Dispose()
        }

        It "CurrentKeyId() is non-null and non-empty after construction" {
            $mgr = [RotatingKeyManager]::new(3)
            $id = $mgr.CurrentKeyId()
            $id | Should -Not -BeNullOrEmpty
            $mgr.Dispose()
        }
    }

    Context "Encrypt/Decrypt" {
        It "Encrypt returns EncryptedPackage with non-null KeyId and non-empty Ciphertext" {
            $mgr = [RotatingKeyManager]::new(3)
            $pkg = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
            $pkg.KeyId | Should -Not -BeNullOrEmpty
            $pkg.Ciphertext.Length | Should -BeGreaterThan 0
            $mgr.Dispose()
        }

        It "Encrypt KeyId matches CurrentKeyId()" {
            $mgr = [RotatingKeyManager]::new(3)
            $pkg = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
            $pkg.KeyId | Should -Be $mgr.CurrentKeyId()
            $mgr.Dispose()
        }

        It "Decrypt round-trips correctly" {
            $mgr = [RotatingKeyManager]::new(3)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes("round-trip test")
            $pkg = $mgr.Encrypt($plaintext)
            $decrypted = $mgr.Decrypt($pkg.KeyId, $pkg.Ciphertext)
            $decrypted | Should -Be $plaintext
            $mgr.Dispose()
        }

        It "Two encryptions of identical plaintext produce different ciphertext" {
            $mgr = [RotatingKeyManager]::new(3)
            $data = [System.Text.Encoding]::UTF8.GetBytes("same data")
            $a = $mgr.Encrypt($data)
            $b = $mgr.Encrypt($data)
            [System.Linq.Enumerable]::SequenceEqual($a.Ciphertext, $b.Ciphertext) | Should -Be $false
            $mgr.Dispose()
        }
    }

    Context "Rotation" {
        It "Rotate() changes CurrentKeyId()" {
            $mgr = [RotatingKeyManager]::new(3)
            $original = $mgr.CurrentKeyId()
            $mgr.Rotate()
            $mgr.CurrentKeyId() | Should -Not -Be $original
            $mgr.Dispose()
        }

        It "Rotate() increments KeyCount() up to retentionWindow" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr.KeyCount() | Should -Be 1
            $mgr.Rotate()
            $mgr.KeyCount() | Should -Be 2
            $mgr.Rotate()
            $mgr.KeyCount() | Should -Be 3
            $mgr.Dispose()
        }

        It "Rotate() beyond retentionWindow keeps KeyCount() == retentionWindow" {
            $mgr = [RotatingKeyManager]::new(2)
            $mgr.KeyCount() | Should -Be 1
            $mgr.Rotate()
            $mgr.KeyCount() | Should -Be 2
            $mgr.Rotate()
            $mgr.KeyCount() | Should -Be 2
            $mgr.Rotate()
            $mgr.KeyCount() | Should -Be 2
            $mgr.Dispose()
        }

        It "Decrypt still works for keys within retention window after rotation" {
            $mgr = [RotatingKeyManager]::new(3)
            $a = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("first"))
            $mgr.Rotate()
            $b = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("second"))
            $mgr.Rotate()
            $c = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("third"))

            $mgr.Decrypt($a.KeyId, $a.Ciphertext) | Should -Be ([System.Text.Encoding]::UTF8.GetBytes("first"))
            $mgr.Decrypt($b.KeyId, $b.Ciphertext) | Should -Be ([System.Text.Encoding]::UTF8.GetBytes("second"))
            $mgr.Decrypt($c.KeyId, $c.Ciphertext) | Should -Be ([System.Text.Encoding]::UTF8.GetBytes("third"))
            $mgr.Dispose()
        }

        It "Decrypt throws after key is evicted (window=1, rotate once)" {
            $mgr = [RotatingKeyManager]::new(1)
            $pkg = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("sensitive"))
            $originalKeyId = $pkg.KeyId
            $mgr.Rotate()
            { $mgr.Decrypt($originalKeyId, $pkg.Ciphertext) } | Should -Throw
            $mgr.Dispose()
        }

        It "Decrypt throws KeyNotFoundException for unknown KeyId" {
            $mgr = [RotatingKeyManager]::new(3)
            $pkg = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
            { $mgr.Decrypt("nonexistent-key-id", $pkg.Ciphertext) } | Should -Throw
            $mgr.Dispose()
        }
    }

    Context "Disposal" {
        It "Dispose clears all keys" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("a"))
            $mgr.Rotate()
            $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("b"))
            $mgr.Dispose()
            { $mgr.KeyCount() } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Disposed instance throws ObjectDisposedException on Encrypt" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr.Dispose()
            { $mgr.Encrypt([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Disposed instance throws ObjectDisposedException on Decrypt" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr.Dispose()
            { $mgr.Decrypt("k", [byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Disposed instance throws ObjectDisposedException on Rotate" {
            $mgr = [RotatingKeyManager]::new(3)
            $mgr.Dispose()
            { $mgr.Rotate() } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}
