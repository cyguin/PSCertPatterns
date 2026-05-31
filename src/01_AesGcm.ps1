class AesGcmService : System.IDisposable {
    hidden [System.Security.Cryptography.AesGcm]$_gcm
    hidden [bool]$_disposed = $false

    AesGcmService([byte[]]$key) {
        $valid = ($key.Length -eq 16) -or ($key.Length -eq 24) -or ($key.Length -eq 32)
        if (-not $valid) {
            throw [System.ArgumentException]::new("Key must be 16, 24, or 32 bytes.", "key")
        }
        $this._gcm = [System.Security.Cryptography.AesGcm]::new($key)
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [byte[]] Encrypt([byte[]]$plaintext) {
        $this.CheckDisposed()
        $nonce = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $ciphertext = [byte[]]::new($plaintext.Length)
        $tag = [byte[]]::new(16)
        $this._gcm.Encrypt($nonce, $plaintext, $ciphertext, $tag)
        $package = [byte[]]::new($nonce.Length + $tag.Length + $ciphertext.Length)
        [System.Buffer]::BlockCopy($nonce, 0, $package, 0, $nonce.Length)
        [System.Buffer]::BlockCopy($tag, 0, $package, $nonce.Length, $tag.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $package, $nonce.Length + $tag.Length, $ciphertext.Length)
        return $package
    }

    [byte[]] Encrypt([byte[]]$plaintext, [byte[]]$associatedData) {
        $this.CheckDisposed()
        $nonce = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $ciphertext = [byte[]]::new($plaintext.Length)
        $tag = [byte[]]::new(16)
        $this._gcm.Encrypt($nonce, $plaintext, $ciphertext, $tag, $associatedData)
        $package = [byte[]]::new($nonce.Length + $tag.Length + $ciphertext.Length)
        [System.Buffer]::BlockCopy($nonce, 0, $package, 0, $nonce.Length)
        [System.Buffer]::BlockCopy($tag, 0, $package, $nonce.Length, $tag.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $package, $nonce.Length + $tag.Length, $ciphertext.Length)
        return $package
    }

    [byte[]] Decrypt([byte[]]$package) {
        $this.CheckDisposed()
        $nonce = $package[0..11]
        $tag = $package[12..27]
        $ciphertext = $package[28..($package.Length - 1)]
        $plaintext = [byte[]]::new($ciphertext.Length)
        $this._gcm.Decrypt($nonce, $ciphertext, $tag, $plaintext)
        return $plaintext
    }

    [byte[]] Decrypt([byte[]]$package, [byte[]]$associatedData) {
        $this.CheckDisposed()
        $nonce = $package[0..11]
        $tag = $package[12..27]
        $ciphertext = $package[28..($package.Length - 1)]
        $plaintext = [byte[]]::new($ciphertext.Length)
        $this._gcm.Decrypt($nonce, $ciphertext, $tag, $plaintext, $associatedData)
        return $plaintext
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._gcm.Dispose()
            $this._disposed = $true
        }
    }
}
