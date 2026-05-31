BeforeAll {
    . "$PSScriptRoot/../src/03_NonceManagement.ps1"
}

Describe "RandomNonceGenerator" {
    Context "Generate()" {
        It "Returns exactly 12 bytes" {
            $nonce = [RandomNonceGenerator]::Generate()
            $nonce.Length | Should -Be 12
        }

        It "Two calls produce different output" {
            $a = [RandomNonceGenerator]::Generate()
            $b = [RandomNonceGenerator]::Generate()
            [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $false
        }
    }

    Context "Generate([int])" {
        It "Returns requested size" {
            $nonce = [RandomNonceGenerator]::Generate(32)
            $nonce.Length | Should -Be 32
        }

        It "Size 1 returns 1 byte" {
            $nonce = [RandomNonceGenerator]::Generate(1)
            $nonce.Length | Should -Be 1
        }

        It "Size 0 throws ArgumentException" {
            { [RandomNonceGenerator]::Generate(0) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "Size -1 throws ArgumentException" {
            { [RandomNonceGenerator]::Generate(-1) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }
}

Describe "CounterNonceGenerator" {
    Context "Construction" {
        It "Accepts valid 8-byte keyId" {
            $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
            $svc | Should -Not -BeNullOrEmpty
            $svc.Dispose()
        }

        It "7-byte keyId throws ArgumentException" {
            { [CounterNonceGenerator]::new([byte[]]::new(7)) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "9-byte keyId throws ArgumentException" {
            { [CounterNonceGenerator]::new([byte[]]::new(9)) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }
    }

    Context "Next()" {
        It "Returns exactly 12 bytes" {
            $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
            $nonce = $svc.Next()
            $nonce.Length | Should -Be 12
            $svc.Dispose()
        }

        It "First 8 bytes of nonce match keyId" {
            $keyId = [System.Text.Encoding]::UTF8.GetBytes("KEYID123")
            $svc = [CounterNonceGenerator]::new($keyId)
            $nonce = $svc.Next()
            $prefix = [byte[]]$nonce[0..7]
            [System.Linq.Enumerable]::SequenceEqual($prefix, $keyId) | Should -Be $true
            $svc.Dispose()
        }

        It "Sequential calls produce strictly incrementing nonces" {
            $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
            $n1 = $svc.Next()
            $n2 = $svc.Next()

            $c1 = [byte[]]$n1[8..11]
            $c2 = [byte[]]$n2[8..11]
            $v1 = ($c1[0] -shl 24) -bor ($c1[1] -shl 16) -bor ($c1[2] -shl 8) -bor $c1[3]
            $v2 = ($c2[0] -shl 24) -bor ($c2[1] -shl 16) -bor ($c2[2] -shl 8) -bor $c2[3]

            $v2 | Should -BeGreaterThan $v1
            $svc.Dispose()
        }

        It "Two instances with same keyId produce independent counters" {
            $keyId = [byte[]]::new(8)
            $a = [CounterNonceGenerator]::new($keyId)
            $b = [CounterNonceGenerator]::new($keyId)
            $nonceA1 = $a.Next()
            $nonceB1 = $b.Next()
            # Both first calls should have counter value 1, producing same nonce
            [System.Linq.Enumerable]::SequenceEqual($nonceA1, $nonceB1) | Should -Be $true
            $a.Dispose()
            $b.Dispose()
        }
    }

    Context "CurrentCount()" {
        It "Reflects number of Next() calls made" {
            $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
            $svc.CurrentCount() | Should -Be 0
            $svc.Next()
            $svc.CurrentCount() | Should -Be 1
            $svc.Next()
            $svc.Next()
            $svc.CurrentCount() | Should -Be 3
            $svc.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on Next() after Dispose" {
            $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
            $svc.Dispose()
            { $svc.Next() } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on CurrentCount() after Dispose" {
            $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
            $svc.Dispose()
            { $svc.CurrentCount() } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Dispose clears keyId bytes" {
            $keyId = [System.Text.Encoding]::UTF8.GetBytes("KEYID123")
            $svc = [CounterNonceGenerator]::new($keyId)
            $svc.Dispose()
            $cleared = $true
            foreach ($b in $svc._keyId) {
                if ($b -ne 0) {
                    $cleared = $false
                    break
                }
            }
            $cleared | Should -Be $true
        }
    }
}
