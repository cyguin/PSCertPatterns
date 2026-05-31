BeforeAll {
    . "$PSScriptRoot/../src/07_CertChain.ps1"
}

Describe "CertificateValidator" {
    Context "Factories" {
        It "Strict() sets CheckRevocation=true and AllowUntrustedRoot=false" {
            $v = [CertificateValidator]::Strict()
            $v.CheckRevocation | Should -Be $true
            $v.AllowUntrustedRoot | Should -Be $false
            $v.Dispose()
        }

        It "Development() sets CheckRevocation=false and AllowUntrustedRoot=true" {
            $v = [CertificateValidator]::Development()
            $v.CheckRevocation | Should -Be $false
            $v.AllowUntrustedRoot | Should -Be $true
            $v.Dispose()
        }
    }

    Context "Validation" {
        It "Development() validates self-signed cert as IsValid=true" {
            $pki = [InMemoryPki]::new("CN=TestDevRoot")
            $root = $pki.RootCertificate()
            $v = [CertificateValidator]::Development()
            $v.ExtraStore.Add($root)
            $result = $v.Validate($root)
            $result.IsValid | Should -Be $true
            $v.Dispose()
            $pki.Dispose()
        }

        It "Strict() with self-signed cert returns IsValid=false (untrusted root)" {
            $pki = [InMemoryPki]::new("CN=TestStrictRoot")
            $root = $pki.RootCertificate()
            $v = [CertificateValidator]::Strict()
            $v.CheckRevocation = $false
            $v.ExtraStore.Add($root)
            $result = $v.Validate($root)
            $result.IsValid | Should -Be $false
            $v.Dispose()
            $pki.Dispose()
        }
    }

    Context "Thumbprint pinning" {
        It "Pinned thumbprint matching cert returns IsValid=true" {
            $pki = [InMemoryPki]::new("CN=TestPinRoot")
            $root = $pki.RootCertificate()
            $v = [CertificateValidator]::Development()
            $v.ExtraStore.Add($root)
            $v.TrustedThumbprints.Add($root.Thumbprint)
            $result = $v.Validate($root)
            $result.IsValid | Should -Be $true
            $v.Dispose()
            $pki.Dispose()
        }

        It "Pinned thumbprint NOT matching cert returns IsValid=false with error" {
            $pki = [InMemoryPki]::new("CN=TestPinRoot")
            $root = $pki.RootCertificate()
            $v = [CertificateValidator]::Development()
            $v.ExtraStore.Add($root)
            $v.TrustedThumbprints.Add("0000000000000000000000000000000000000000")
            $result = $v.Validate($root)
            $result.IsValid | Should -Be $false
            $result.Errors -contains "Thumbprint not in pinned set" | Should -Be $true
            $v.Dispose()
            $pki.Dispose()
        }

        It "Empty thumbprints list skips thumbprint check entirely" {
            $pki = [InMemoryPki]::new("CN=TestSkipRoot")
            $root = $pki.RootCertificate()
            $v = [CertificateValidator]::Development()
            $v.ExtraStore.Add($root)
            $v.TrustedThumbprints.Count | Should -Be 0
            $result = $v.Validate($root)
            $result.IsValid | Should -Be $true
            $v.Dispose()
            $pki.Dispose()
        }
    }

    Context "Disposal" {
        It "Disposed instance throws ObjectDisposedException on Validate" {
            $v = [CertificateValidator]::new()
            $v.Dispose()
            { $v.Validate([System.Security.Cryptography.X509Certificates.X509Certificate2]::new()) } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}

Describe "InMemoryPki" {
    Context "Construction" {
        It "Constructs without error" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $pki | Should -Not -BeNullOrEmpty
            $pki.Dispose()
        }
    }

    Context "Root certificate" {
        It "RootCertificate() returns non-null X509Certificate2" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $root = $pki.RootCertificate()
            $root | Should -Not -BeNullOrEmpty
            $pki.Dispose()
        }

        It "RootCertificate() subject matches constructor argument" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $root = $pki.RootCertificate()
            $root.Subject | Should -Be "CN=TestRoot"
            $pki.Dispose()
        }
    }

    Context "Issued certificate" {
        It "IssueCertificate() returns non-null X509Certificate2" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $leaf = $pki.IssueCertificate("CN=Leaf")
            $leaf | Should -Not -BeNullOrEmpty
            $leaf.Dispose()
            $pki.Dispose()
        }

        It "Issued cert subject matches requested subject" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $leaf = $pki.IssueCertificate("CN=Leaf")
            $leaf.Subject | Should -Be "CN=Leaf"
            $leaf.Dispose()
            $pki.Dispose()
        }

        It "Issued cert has private key" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $leaf = $pki.IssueCertificate("CN=Leaf")
            $leaf.HasPrivateKey | Should -Be $true
            $leaf.Dispose()
            $pki.Dispose()
        }
    }

    Context "Chain validation" {
        It "Issued cert is signed by root" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $leaf = $pki.IssueCertificate("CN=Leaf")
            $v = [CertificateValidator]::Development()
            $v.ExtraStore.Add($pki.RootCertificate())
            $result = $v.Validate($leaf)
            $result.IsValid | Should -Be $true
            $v.Dispose()
            $leaf.Dispose()
            $pki.Dispose()
        }

        It "Development() without root in ExtraStore fails validation" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $leaf = $pki.IssueCertificate("CN=Leaf")
            $v = [CertificateValidator]::Development()
            $result = $v.Validate($leaf)
            $result.IsValid | Should -Be $false
            $v.Dispose()
            $leaf.Dispose()
            $pki.Dispose()
        }
    }

    Context "Disposal" {
        It "Disposed instance throws ObjectDisposedException on IssueCertificate" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $pki.Dispose()
            { $pki.IssueCertificate("CN=Dead") } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }

        It "Disposed instance throws ObjectDisposedException on RootCertificate" {
            $pki = [InMemoryPki]::new("CN=TestRoot")
            $pki.Dispose()
            { $pki.RootCertificate() } | Should -Throw -ExceptionType ([System.ObjectDisposedException])
        }
    }
}
