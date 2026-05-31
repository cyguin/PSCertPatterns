class CertificateValidator : System.IDisposable {
    [bool]$AllowUntrustedRoot = $false
    [bool]$CheckRevocation = $true
    [System.Collections.Generic.List[string]]$TrustedThumbprints
    [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$ExtraStore
    hidden [bool]$_disposed = $false

    CertificateValidator() {
        $this.TrustedThumbprints = [System.Collections.Generic.List[string]]::new()
        $this.ExtraStore = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [hashtable] Validate([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
        $this.CheckDisposed()
        $chain = $null
        try {
            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            if ($this.CheckRevocation) {
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            } else {
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            }
            if ($this.AllowUntrustedRoot) {
                $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
            }
            foreach ($extra in $this.ExtraStore) {
                $chain.ChainPolicy.ExtraStore.Add($extra)
            }
            $chainBuilt = $chain.Build($cert)
            $errors = [System.Collections.Generic.List[string]]::new()
            foreach ($status in $chain.ChainStatus) {
                if ($this.AllowUntrustedRoot -and $status.Status -eq [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) {
                    continue
                }
                $msg = $status.StatusInformation.Trim()
                if ($msg -ne "") {
                    $errors.Add($msg)
                }
            }
            if ($this.TrustedThumbprints.Count -gt 0 -and -not $this.TrustedThumbprints.Contains($cert.Thumbprint)) {
                $errors.Add("Thumbprint not in pinned set")
            }
            $isValid = $chainBuilt -and ($errors.Count -eq 0)
            return @{ IsValid = $isValid; Errors = $errors }
        }
        finally {
            if ($chain -ne $null) {
                $chain.Dispose()
            }
        }
    }

    static [CertificateValidator] Strict() {
        $v = [CertificateValidator]::new()
        $v.CheckRevocation = $true
        $v.AllowUntrustedRoot = $false
        return $v
    }

    static [CertificateValidator] Development() {
        $v = [CertificateValidator]::new()
        $v.CheckRevocation = $false
        $v.AllowUntrustedRoot = $true
        return $v
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this.ExtraStore -ne $null) {
                foreach ($cert in $this.ExtraStore) {
                    $cert.Dispose()
                }
            }
        }
    }
}

class InMemoryPki : System.IDisposable {
    hidden [System.Security.Cryptography.X509Certificates.X509Certificate2]$_root
    hidden [System.Security.Cryptography.RSA]$_rootKey
    hidden [bool]$_disposed = $false

    InMemoryPki([string]$rootSubject) {
        $this._rootKey = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $rootSubject,
            $this._rootKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
            $true, $false, 0, $true)
        $request.CertificateExtensions.Add($basicConstraints)
        $spki = $this._rootKey.ExportSubjectPublicKeyInfo()
        $bytesRead = 0
        $pubKey = [System.Security.Cryptography.X509Certificates.PublicKey]::CreateFromSubjectPublicKeyInfo($spki, [ref]$bytesRead)
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($pubKey, $false))
        $now = [System.DateTimeOffset]::Now
        $this._root = $request.CreateSelfSigned($now, $now.AddYears(10))
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [System.Security.Cryptography.X509Certificates.X509Certificate2] IssueCertificate([string]$subject) {
        $this.CheckDisposed()
        $leafKey = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject,
            $leafKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $serial = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
        $serial[0] = $serial[0] -band 0x7F
        $now = [System.DateTimeOffset]::Now
        $notBefore = $now.AddMinutes(-1)
        if ($notBefore -lt $this._root.NotBefore) {
            $notBefore = $this._root.NotBefore
        }
        $signed = $request.Create($this._root, $notBefore, $now.AddYears(1), $serial)
        $cert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($signed, $leafKey)
        $signed.Dispose()
        $leafKey.Dispose()
        return $cert
    }

    [System.Security.Cryptography.X509Certificates.X509Certificate2] RootCertificate() {
        $this.CheckDisposed()
        return $this._root
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._root -ne $null) {
                $this._root.Dispose()
            }
            if ($this._rootKey -ne $null) {
                $this._rootKey.Dispose()
            }
        }
    }
}
