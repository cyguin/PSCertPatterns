class EncryptedPackage {
    [string]$KeyId
    [byte[]]$Ciphertext

    EncryptedPackage([string]$keyId, [byte[]]$ciphertext) {
        $this.KeyId = $keyId
        $this.Ciphertext = $ciphertext
    }
}

class RotatingKeyManager : System.IDisposable {
    hidden [int]$_retentionWindow
    hidden [System.Collections.Generic.Queue[string]]$_keyOrder
    hidden [System.Collections.Generic.Dictionary[string, byte[]]]$_keys
    hidden [string]$_currentKeyId
    hidden [bool]$_disposed = $false

    RotatingKeyManager([int]$retentionWindow) {
        if ($retentionWindow -lt 1) {
            throw [System.ArgumentException]::new("retentionWindow must be at least 1.", "retentionWindow")
        }
        $this._retentionWindow = $retentionWindow
        $this._keyOrder = [System.Collections.Generic.Queue[string]]::new()
        $this._keys = [System.Collections.Generic.Dictionary[string, byte[]]]::new()
        $this._GenerateKey()
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    hidden [void] _GenerateKey() {
        $key = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
        $keyId = [System.Guid]::NewGuid().ToString()
        $this._keys[$keyId] = $key
        $this._keyOrder.Enqueue($keyId)
        $this._currentKeyId = $keyId
        if ($this._keyOrder.Count -gt $this._retentionWindow) {
            $evictedId = $this._keyOrder.Dequeue()
            $evictedKey = $this._keys[$evictedId]
            [System.Array]::Clear($evictedKey, 0, $evictedKey.Length)
            $this._keys.Remove($evictedId)
        }
    }

    [EncryptedPackage] Encrypt([byte[]]$plaintext) {
        $this.CheckDisposed()
        $nonce = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $key = $this._keys[$this._currentKeyId]
        $gcm = $null
        try {
            $gcm = [System.Security.Cryptography.AesGcm]::new($key)
            $ciphertext = [byte[]]::new($plaintext.Length)
            $tag = [byte[]]::new(16)
            $gcm.Encrypt($nonce, $plaintext, $ciphertext, $tag)
            $package = [byte[]]::new($nonce.Length + $tag.Length + $ciphertext.Length)
            [System.Buffer]::BlockCopy($nonce, 0, $package, 0, $nonce.Length)
            [System.Buffer]::BlockCopy($tag, 0, $package, $nonce.Length, $tag.Length)
            [System.Buffer]::BlockCopy($ciphertext, 0, $package, $nonce.Length + $tag.Length, $ciphertext.Length)
            return [EncryptedPackage]::new($this._currentKeyId, $package)
        }
        finally {
            if ($gcm -ne $null) {
                $gcm.Dispose()
            }
        }
    }

    [byte[]] Decrypt([string]$keyId, [byte[]]$ciphertext) {
        $this.CheckDisposed()
        if (-not $this._keys.ContainsKey($keyId)) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("Key not found: $keyId")
        }
        $key = $this._keys[$keyId]
        $nonce = [byte[]]$ciphertext[0..11]
        $tag = [byte[]]$ciphertext[12..27]
        $ct = [byte[]]$ciphertext[28..($ciphertext.Length - 1)]
        $gcm = $null
        try {
            $gcm = [System.Security.Cryptography.AesGcm]::new($key)
            $plaintext = [byte[]]::new($ct.Length)
            $gcm.Decrypt($nonce, $ct, $tag, $plaintext)
            return $plaintext
        }
        finally {
            if ($gcm -ne $null) {
                $gcm.Dispose()
            }
        }
    }

    [void] Rotate() {
        $this.CheckDisposed()
        $this._GenerateKey()
    }

    [string] CurrentKeyId() {
        $this.CheckDisposed()
        return $this._currentKeyId
    }

    [int] KeyCount() {
        $this.CheckDisposed()
        return $this._keys.Count
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._keys -ne $null) {
                foreach ($kvp in $this._keys.GetEnumerator()) {
                    [System.Array]::Clear($kvp.Value, 0, $kvp.Value.Length)
                }
                $this._keys.Clear()
            }
        }
    }
}
