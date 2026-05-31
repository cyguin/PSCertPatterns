BeforeAll {
    . "$PSScriptRoot/../src/09_AlgorithmAgility.ps1"
}

Describe "CipherProfile" {
    It "Constructs with all properties set correctly" {
        $p = [CipherProfile]::new("AES-256-GCM", "AES-GCM", 256, 12, 16, "PBKDF2-SHA256", 600000, $false)
        $p.Name | Should -Be "AES-256-GCM"
        $p.Algorithm | Should -Be "AES-GCM"
        $p.KeySize | Should -Be 256
        $p.NonceSizeBytes | Should -Be 12
        $p.TagSizeBytes | Should -Be 16
        $p.KdfAlgorithm | Should -Be "PBKDF2-SHA256"
        $p.KdfIterations | Should -Be 600000
        $p.Deprecated | Should -Be $false
    }

    It "ToString() returns expected format" {
        $p = [CipherProfile]::new("AES-256-GCM", "AES-GCM", 256, 12, 16, "PBKDF2-SHA256", 600000, $false)
        $p.ToString() | Should -Be "AES-256-GCM (KeySize=256, Deprecated=False)"
    }

    It "Deprecated defaults to false" {
        $p = [CipherProfile]::new("T", "A", 128, 12, 16, "K", 1000, $false)
        $p.Deprecated | Should -Be $false
    }
}

Describe "AlgorithmRegistry" {
    Context "Get" {
        It "Get('AES-256-GCM') returns correct profile" {
            $p = [AlgorithmRegistry]::Get("AES-256-GCM")
            $p.Name | Should -Be "AES-256-GCM"
            $p.Algorithm | Should -Be "AES-GCM"
            $p.KeySize | Should -Be 256
            $p.Deprecated | Should -Be $false
        }

        It "Get('AES-128-CBC-HMAC') returns deprecated profile" {
            $p = [AlgorithmRegistry]::Get("AES-128-CBC-HMAC")
            $p.Name | Should -Be "AES-128-CBC-HMAC"
            $p.Deprecated | Should -Be $true
        }

        It "Get('nonexistent') throws KeyNotFoundException" {
            { [AlgorithmRegistry]::Get("nonexistent") } | Should -Throw
        }
    }

    Context "GetActive" {
        It "GetActive('AES-256-GCM') returns profile" {
            $p = [AlgorithmRegistry]::GetActive("AES-256-GCM")
            $p.Name | Should -Be "AES-256-GCM"
        }

        It "GetActive('AES-128-CBC-HMAC') throws InvalidOperationException" {
            { [AlgorithmRegistry]::GetActive("AES-128-CBC-HMAC") } | Should -Throw -ExceptionType ([System.InvalidOperationException])
        }

        It "GetActive('nonexistent') throws KeyNotFoundException" {
            { [AlgorithmRegistry]::GetActive("nonexistent") } | Should -Throw
        }
    }

    Context "Register" {
        It "Register adds a new custom profile" {
            $p = [CipherProfile]::new("CUSTOM-AES", "AES-GCM", 256, 12, 16, "PBKDF2-SHA256", 600000, $false)
            [AlgorithmRegistry]::Register($p)
            $retrieved = [AlgorithmRegistry]::Get("CUSTOM-AES")
            $retrieved.Name | Should -Be "CUSTOM-AES"
        }

        It "Register replaces an existing profile" {
            $p = [CipherProfile]::new("AES-256-GCM", "AES-GCM", 256, 12, 16, "PBKDF2-SHA256", 999999, $false)
            [AlgorithmRegistry]::Register($p)
            $retrieved = [AlgorithmRegistry]::Get("AES-256-GCM")
            $retrieved.KdfIterations | Should -Be 999999
        }

        It "Register with null throws ArgumentException" {
            { [AlgorithmRegistry]::Register($null) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Deprecate" {
        It "Deprecate marks profile as deprecated" {
            [AlgorithmRegistry]::Deprecate("AES-128-GCM")
            $p = [AlgorithmRegistry]::Get("AES-128-GCM")
            $p.Deprecated | Should -Be $true
            # Reset for other tests
            $reset = [CipherProfile]::new("AES-128-GCM", "AES-GCM", 128, 12, 16, "PBKDF2-SHA256", 600000, $false)
            [AlgorithmRegistry]::Register($reset)
        }

        It "Deprecate on nonexistent name throws KeyNotFoundException" {
            { [AlgorithmRegistry]::Deprecate("does-not-exist") } | Should -Throw
        }

        It "After Deprecate, GetActive throws InvalidOperationException" {
            $p = [CipherProfile]::new("TO-DEPRECATE", "AES-GCM", 128, 12, 16, "PBKDF2-SHA256", 600000, $false)
            [AlgorithmRegistry]::Register($p)
            [AlgorithmRegistry]::Deprecate("TO-DEPRECATE")
            { [AlgorithmRegistry]::GetActive("TO-DEPRECATE") } | Should -Throw -ExceptionType ([System.InvalidOperationException])
        }

        It "After Deprecate, Get still returns the profile" {
            $p = [AlgorithmRegistry]::Get("TO-DEPRECATE")
            $p | Should -Not -BeNullOrEmpty
            $p.Deprecated | Should -Be $true
        }
    }

    Context "List" {
        It "ListActive returns only non-deprecated profiles" {
            $active = [AlgorithmRegistry]::ListActive()
            foreach ($p in $active) {
                $p.Deprecated | Should -Be $false
            }
        }

        It "ListAll returns all profiles including deprecated" {
            $all = [AlgorithmRegistry]::ListAll()
            $deprecatedCount = 0
            foreach ($p in $all) {
                if ($p.Deprecated) { $deprecatedCount++ }
            }
            $deprecatedCount | Should -BeGreaterThan 0
        }
    }

    Context "IsRegistered" {
        It "IsRegistered returns true for known profile" {
            [AlgorithmRegistry]::IsRegistered("AES-256-GCM") | Should -Be $true
        }

        It "IsRegistered returns false for unknown profile" {
            [AlgorithmRegistry]::IsRegistered("NONEXISTENT") | Should -Be $false
        }
    }

    Context "Built-in profiles" {
        It "ListAll returns at least 4 profiles" {
            $all = [AlgorithmRegistry]::ListAll()
            $all.Count | Should -BeGreaterOrEqual 4
        }

        It "At least 1 deprecated profile in ListAll" {
            $all = [AlgorithmRegistry]::ListAll()
            $deprecatedCount = 0
            foreach ($p in $all) {
                if ($p.Deprecated) { $deprecatedCount++ }
            }
            $deprecatedCount | Should -BeGreaterOrEqual 1
        }
    }
}
