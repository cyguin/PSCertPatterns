BeforeAll {
    . "$PSScriptRoot/../src/02_KeyDerivation.ps1"
}

Describe "SaltGenerator" {
    Context "Generate" {
        It "Returns byte array of requested size" {
            $salt = [SaltGenerator]::Generate(64)
            $salt.Length | Should -Be 64
        }

        It "With size 16 returns 16 bytes" {
            $salt = [SaltGenerator]::Generate(16)
            $salt.Length | Should -Be 16
        }

        It "Two calls produce different output" {
            $a = [SaltGenerator]::Generate(32)
            $b = [SaltGenerator]::Generate(32)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
        }

        It "With size < 16 throws ArgumentException" {
            { [SaltGenerator]::Generate(8) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }
}

Describe "Pbkdf2KeyDerivation" {
    Context "DeriveKey (3-parameter)" {
        It "Returns byte array of requested keySize" {
            $salt = [SaltGenerator]::Generate(32)
            $key = [Pbkdf2KeyDerivation]::DeriveKey("password", $salt, 32)
            $key.Length | Should -Be 32
        }

        It "Same inputs produce same output" {
            $salt = [SaltGenerator]::Generate(32)
            $a = [Pbkdf2KeyDerivation]::DeriveKey("test-password", $salt, 32)
            $b = [Pbkdf2KeyDerivation]::DeriveKey("test-password", $salt, 32)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $true
        }

        It "Different salts produce different output" {
            $salt1 = [SaltGenerator]::Generate(32)
            $salt2 = [SaltGenerator]::Generate(32)
            $a = [Pbkdf2KeyDerivation]::DeriveKey("password", $salt1, 32)
            $b = [Pbkdf2KeyDerivation]::DeriveKey("password", $salt2, 32)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
        }

        It "Different passwords produce different output" {
            $salt = [SaltGenerator]::Generate(32)
            $a = [Pbkdf2KeyDerivation]::DeriveKey("password-a", $salt, 32)
            $b = [Pbkdf2KeyDerivation]::DeriveKey("password-b", $salt, 32)
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
        }

        It "Null password throws" {
            $salt = [SaltGenerator]::Generate(32)
            { [Pbkdf2KeyDerivation]::DeriveKey($null, $salt, 32) } | Should -Throw
        }

        It "Empty string password throws" {
            $salt = [SaltGenerator]::Generate(32)
            { [Pbkdf2KeyDerivation]::DeriveKey("", $salt, 32) } | Should -Throw
        }

        It "Salt under 16 bytes throws" {
            $shortSalt = [byte[]]::new(8)
            { [Pbkdf2KeyDerivation]::DeriveKey("password", $shortSalt, 32) } | Should -Throw
        }

        It "KeySize under 16 throws" {
            $salt = [SaltGenerator]::Generate(32)
            { [Pbkdf2KeyDerivation]::DeriveKey("password", $salt, 8) } | Should -Throw
        }
    }

    Context "DeriveKey (4-parameter)" {
        It "Caller-supplied iterations overload works" {
            $salt = [SaltGenerator]::Generate(32)
            $key = [Pbkdf2KeyDerivation]::DeriveKey("password", $salt, 32, 1000)
            $key.Length | Should -Be 32
        }

        It "Iterations < 1 throws" {
            $salt = [SaltGenerator]::Generate(32)
            { [Pbkdf2KeyDerivation]::DeriveKey("password", $salt, 32, 0) } | Should -Throw
        }
    }
}
