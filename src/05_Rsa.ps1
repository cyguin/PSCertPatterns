class RsaEncryptionService : System.IDisposable {
    hidden [System.Security.Cryptography.RSA]$_rsa
    hidden [bool]$_disposed = $false
    hidden [bool]$_hasPrivateKey

    RsaEncryptionService([int]$keySizeInBits) {
        $valid = ($keySizeInBits -eq 2048) -or ($keySizeInBits -eq 3072) -or ($keySizeInBits -eq 4096)
        if (-not $valid) {
            throw [System.ArgumentException]::new("keySizeInBits must be 2048, 3072, or 4096.", "keySizeInBits")
        }
        $this._rsa = [System.Security.Cryptography.RSA]::Create($keySizeInBits)
        $this._hasPrivateKey = $true
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [byte[]] Encrypt([byte[]]$plaintext) {
        $this.CheckDisposed()
        return $this._rsa.Encrypt($plaintext, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }

    [byte[]] Decrypt([byte[]]$ciphertext) {
        $this.CheckDisposed()
        if (-not $this._hasPrivateKey) {
            throw [System.InvalidOperationException]::new("Instance does not contain a private key.")
        }
        return $this._rsa.Decrypt($ciphertext, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }

    [byte[]] ExportPublicKey() {
        $this.CheckDisposed()
        return $this._rsa.ExportSubjectPublicKeyInfo()
    }

    [byte[]] ExportPrivateKey() {
        $this.CheckDisposed()
        return $this._rsa.ExportPkcs8PrivateKey()
    }

    static [RsaEncryptionService] FromPublicKey([byte[]]$der) {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $bytesRead = 0
        $rsa.ImportSubjectPublicKeyInfo($der, [ref]$bytesRead)
        $instance = [RsaEncryptionService]::new($rsa.KeySize)
        $instance._rsa.Dispose()
        $instance._rsa = $rsa
        $instance._hasPrivateKey = $false
        return $instance
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._rsa -ne $null) {
                $this._rsa.Dispose()
            }
        }
    }
}

class RsaSigningService : System.IDisposable {
    hidden [System.Security.Cryptography.RSA]$_rsa
    hidden [bool]$_disposed = $false
    hidden [bool]$_hasPrivateKey

    RsaSigningService([int]$keySizeInBits) {
        $valid = ($keySizeInBits -eq 2048) -or ($keySizeInBits -eq 3072) -or ($keySizeInBits -eq 4096)
        if (-not $valid) {
            throw [System.ArgumentException]::new("keySizeInBits must be 2048, 3072, or 4096.", "keySizeInBits")
        }
        $this._rsa = [System.Security.Cryptography.RSA]::Create($keySizeInBits)
        $this._hasPrivateKey = $true
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [byte[]] Sign([byte[]]$data) {
        $this.CheckDisposed()
        if (-not $this._hasPrivateKey) {
            throw [System.InvalidOperationException]::new("Instance does not contain a private key.")
        }
        return $this._rsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pss)
    }

    [bool] Verify([byte[]]$data, [byte[]]$signature) {
        $this.CheckDisposed()
        return $this._rsa.VerifyData($data, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pss)
    }

    [byte[]] ExportPublicKey() {
        $this.CheckDisposed()
        return $this._rsa.ExportSubjectPublicKeyInfo()
    }

    static [RsaSigningService] FromPublicKey([byte[]]$der) {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $bytesRead = 0
        $rsa.ImportSubjectPublicKeyInfo($der, [ref]$bytesRead)
        $instance = [RsaSigningService]::new($rsa.KeySize)
        $instance._rsa.Dispose()
        $instance._rsa = $rsa
        $instance._hasPrivateKey = $false
        return $instance
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._rsa -ne $null) {
                $this._rsa.Dispose()
            }
        }
    }
}
