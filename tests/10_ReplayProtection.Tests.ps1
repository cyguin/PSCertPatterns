BeforeAll {
    . "$PSScriptRoot/../src/10_ReplayProtection.ps1"
}

Describe "NonceReplayGuard" {
    Context "Construction" {
        It "windowSize < 1 throws ArgumentException" {
            { [NonceReplayGuard]::new(0) } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It "windowSize = 1 constructs without error" {
            $g = [NonceReplayGuard]::new(1)
            $g | Should -Not -BeNullOrEmpty
            $g.Dispose()
        }

        It "windowSize = 100 constructs without error" {
            $g = [NonceReplayGuard]::new(100)
            $g | Should -Not -BeNullOrEmpty
            $g.Dispose()
        }
    }

    Context "CheckAndRecord" {
        It "Returns true on first use of a nonce" {
            $g = [NonceReplayGuard]::new(10)
            $g.CheckAndRecord([System.Text.Encoding]::UTF8.GetBytes("nonce-1")) | Should -Be $true
            $g.Dispose()
        }

        It "Returns false on second use of same nonce" {
            $g = [NonceReplayGuard]::new(10)
            $nonce = [System.Text.Encoding]::UTF8.GetBytes("replay-me")
            $g.CheckAndRecord($nonce) | Should -Be $true
            $g.CheckAndRecord($nonce) | Should -Be $false
            $g.Dispose()
        }

        It "Returns false on third use of same nonce" {
            $g = [NonceReplayGuard]::new(10)
            $nonce = [System.Text.Encoding]::UTF8.GetBytes("triple")
            $g.CheckAndRecord($nonce) | Should -Be $true
            $g.CheckAndRecord($nonce) | Should -Be $false
            $g.CheckAndRecord($nonce) | Should -Be $false
            $g.Dispose()
        }

        It "Null nonce throws ArgumentNullException" {
            $g = [NonceReplayGuard]::new(10)
            { $g.CheckAndRecord($null) } | Should -Throw -ExceptionType ([System.ArgumentNullException])
            $g.Dispose()
        }
    }

    Context "HasSeen" {
        It "Returns false before nonce is recorded" {
            $g = [NonceReplayGuard]::new(10)
            $g.HasSeen([System.Text.Encoding]::UTF8.GetBytes("not-seen")) | Should -Be $false
            $g.Dispose()
        }

        It "Returns true after nonce is recorded via CheckAndRecord" {
            $g = [NonceReplayGuard]::new(10)
            $nonce = [System.Text.Encoding]::UTF8.GetBytes("now-seen")
            $g.CheckAndRecord($nonce)
            $g.HasSeen($nonce) | Should -Be $true
            $g.Dispose()
        }

        It "Does not record the nonce (SeenCount unchanged after HasSeen)" {
            $g = [NonceReplayGuard]::new(10)
            $nonce = [System.Text.Encoding]::UTF8.GetBytes("no-record")
            $g.HasSeen($nonce) | Out-Null
            $g.SeenCount() | Should -Be 0
            $g.Dispose()
        }

        It "Null nonce throws ArgumentNullException" {
            $g = [NonceReplayGuard]::new(10)
            { $g.HasSeen($null) } | Should -Throw -ExceptionType ([System.ArgumentNullException])
            $g.Dispose()
        }
    }

    Context "SeenCount" {
        It "Increments correctly up to windowSize" {
            $g = [NonceReplayGuard]::new(5)
            1..5 | ForEach-Object {
                $g.CheckAndRecord([byte[]]::new($_)) | Should -Be $true
            }
            $g.SeenCount() | Should -Be 5
            $g.Dispose()
        }

        It "Does not exceed windowSize after eviction" {
            $g = [NonceReplayGuard]::new(5)
            1..10 | ForEach-Object {
                $g.CheckAndRecord([byte[]]::new($_)) | Out-Null
            }
            $g.SeenCount() | Should -Be 5
            $g.Dispose()
        }
    }

    Context "Eviction" {
        It "WindowSize=3, record 4, SeenCount=3 and first nonce evicted" {
            $g = [NonceReplayGuard]::new(3)
            $n1 = [System.Text.Encoding]::UTF8.GetBytes("first")
            $n2 = [System.Text.Encoding]::UTF8.GetBytes("second")
            $n3 = [System.Text.Encoding]::UTF8.GetBytes("third")
            $n4 = [System.Text.Encoding]::UTF8.GetBytes("fourth")

            $g.CheckAndRecord($n1)
            $g.CheckAndRecord($n2)
            $g.CheckAndRecord($n3)
            $g.SeenCount() | Should -Be 3

            $g.CheckAndRecord($n4)
            $g.SeenCount() | Should -Be 3

            $g.HasSeen($n1) | Should -Be $false
            $g.HasSeen($n2) | Should -Be $true
            $g.HasSeen($n3) | Should -Be $true
            $g.HasSeen($n4) | Should -Be $true
            $g.Dispose()
        }

        It "Evicted nonce can be re-recorded" {
            $g = [NonceReplayGuard]::new(2)
            $n1 = [System.Text.Encoding]::UTF8.GetBytes("a")
            $n2 = [System.Text.Encoding]::UTF8.GetBytes("b")
            $n3 = [System.Text.Encoding]::UTF8.GetBytes("c")

            $g.CheckAndRecord($n1)
            $g.CheckAndRecord($n2)
            $g.CheckAndRecord($n3)  # n1 evicted

            $g.CheckAndRecord($n1) | Should -Be $true
            $g.Dispose()
        }
    }

    Context "Reset" {
        It "Clears all seen nonces (SeenCount=0)" {
            $g = [NonceReplayGuard]::new(10)
            $g.CheckAndRecord([System.Text.Encoding]::UTF8.GetBytes("x"))
            $g.CheckAndRecord([System.Text.Encoding]::UTF8.GetBytes("y"))
            $g.SeenCount() | Should -BeGreaterThan 0
            $g.Reset()
            $g.SeenCount() | Should -Be 0
            $g.Dispose()
        }

        It "Allows re-recording after Reset" {
            $g = [NonceReplayGuard]::new(10)
            $nonce = [System.Text.Encoding]::UTF8.GetBytes("reset-me")
            $g.CheckAndRecord($nonce) | Should -Be $true
            $g.Reset()
            $g.CheckAndRecord($nonce) | Should -Be $true
            $g.Dispose()
        }
    }

    Context "Disposal" {
        It "Throws ObjectDisposedException on CheckAndRecord after Dispose" {
            $g = [NonceReplayGuard]::new(10)
            $g.Dispose()
            { $g.CheckAndRecord([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on HasSeen after Dispose" {
            $g = [NonceReplayGuard]::new(10)
            $g.Dispose()
            { $g.HasSeen([byte[]]::new(1)) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Throws ObjectDisposedException on Reset after Dispose" {
            $g = [NonceReplayGuard]::new(10)
            $g.Dispose()
            { $g.Reset() } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}
