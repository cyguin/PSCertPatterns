class EcdsaSigningService : System.IDisposable {
    hidden [System.Security.Cryptography.ECDsa]$_ecdsa
    hidden [bool]$_disposed = $false
    hidden [bool]$_hasPrivateKey

    EcdsaSigningService([string]$curveName) {
        $valid = ($curveName -eq "P-256") -or ($curveName -eq "P-384") -or ($curveName -eq "P-521")
        if (-not $valid) {
            throw [System.ArgumentException]::new("curveName must be P-256, P-384, or P-521.", "curveName")
        }
        $oidString = switch ($curveName) {
            "P-256" { "1.2.840.10045.3.1.7" }
            "P-384" { "1.3.132.0.34" }
            "P-521" { "1.3.132.0.35" }
        }
        $this._ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $this._ecdsa.GenerateKey([System.Security.Cryptography.ECCurve]::CreateFromOid([System.Security.Cryptography.Oid]::new($oidString)))
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
        return $this._ecdsa.SignData($data, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }

    [bool] Verify([byte[]]$data, [byte[]]$signature) {
        $this.CheckDisposed()
        return $this._ecdsa.VerifyData($data, $signature, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }

    [byte[]] ExportPublicKey() {
        $this.CheckDisposed()
        return $this._ecdsa.ExportSubjectPublicKeyInfo()
    }

    [byte[]] ExportPrivateKey() {
        $this.CheckDisposed()
        if (-not $this._hasPrivateKey) {
            throw [System.InvalidOperationException]::new("Instance does not contain a private key.")
        }
        return $this._ecdsa.ExportPkcs8PrivateKey()
    }

    static [EcdsaSigningService] FromPublicKey([byte[]]$der) {
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $bytesRead = 0
        $ecdsa.ImportSubjectPublicKeyInfo($der, [ref]$bytesRead)
        $instance = [EcdsaSigningService]::new("P-256")
        $instance._ecdsa.Dispose()
        $instance._ecdsa = $ecdsa
        $instance._hasPrivateKey = $false
        return $instance
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._ecdsa -ne $null) {
                $this._ecdsa.Dispose()
            }
        }
    }
}
