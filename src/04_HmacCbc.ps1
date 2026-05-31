class HmacService {
    static [byte[]] Sign([byte[]]$data, [byte[]]$key) {
        if ($null -eq $data) {
            throw [System.ArgumentException]::new("Data cannot be null.", "data")
        }
        if ($null -eq $key) {
            throw [System.ArgumentException]::new("Key cannot be null.", "key")
        }
        if ($key.Length -lt 32) {
            throw [System.ArgumentException]::new("Key must be at least 32 bytes.", "key")
        }
        $hmac = $null
        try {
            $hmac = [System.Security.Cryptography.HMACSHA256]::new($key)
            return $hmac.ComputeHash($data)
        }
        finally {
            if ($hmac -ne $null) {
                $hmac.Dispose()
            }
        }
    }

    static [bool] Verify([byte[]]$data, [byte[]]$key, [byte[]]$expectedMac) {
        if ($null -eq $data) {
            throw [System.ArgumentException]::new("Data cannot be null.", "data")
        }
        if ($null -eq $key) {
            throw [System.ArgumentException]::new("Key cannot be null.", "key")
        }
        if ($null -eq $expectedMac) {
            throw [System.ArgumentException]::new("Expected MAC cannot be null.", "expectedMac")
        }
        if ($key.Length -lt 32) {
            throw [System.ArgumentException]::new("Key must be at least 32 bytes.", "key")
        }
        $computed = [HmacService]::Sign($data, $key)
        return [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($computed, $expectedMac)
    }
}

class AesCbcService : System.IDisposable {
    hidden [byte[]]$_encryptionKey
    hidden [byte[]]$_macKey
    hidden [bool]$_disposed = $false

    AesCbcService([byte[]]$encryptionKey, [byte[]]$macKey) {
        $validEncSize = ($encryptionKey.Length -eq 16) -or ($encryptionKey.Length -eq 24) -or ($encryptionKey.Length -eq 32)
        if (-not $validEncSize) {
            throw [System.ArgumentException]::new("encryptionKey must be 16, 24, or 32 bytes.", "encryptionKey")
        }
        if ($macKey.Length -lt 32) {
            throw [System.ArgumentException]::new("macKey must be at least 32 bytes.", "macKey")
        }
        $this._encryptionKey = $encryptionKey
        $this._macKey = $macKey
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [byte[]] Encrypt([byte[]]$plaintext) {
        $this.CheckDisposed()
        $iv = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)

        $aes = $null
        $ciphertext = $null
        try {
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $this._encryptionKey
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $encryptor = $aes.CreateEncryptor()
            $ciphertext = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
            $encryptor.Dispose()
        }
        finally {
            if ($aes -ne $null) {
                $aes.Dispose()
            }
        }

        $macInput = [byte[]]::new($iv.Length + $ciphertext.Length)
        [System.Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $macInput, $iv.Length, $ciphertext.Length)

        $hmac = [HmacService]::Sign($macInput, $this._macKey)

        $package = [byte[]]::new($iv.Length + $ciphertext.Length + $hmac.Length)
        [System.Buffer]::BlockCopy($iv, 0, $package, 0, $iv.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $package, $iv.Length, $ciphertext.Length)
        [System.Buffer]::BlockCopy($hmac, 0, $package, $iv.Length + $ciphertext.Length, $hmac.Length)
        return $package
    }

    [byte[]] Decrypt([byte[]]$package) {
        $this.CheckDisposed()
        $ivLength = 16
        $hmacLength = 32

        $iv = [byte[]]$package[0..($ivLength - 1)]
        $hmac = [byte[]]$package[($package.Length - $hmacLength)..($package.Length - 1)]
        $cipherLength = $package.Length - $ivLength - $hmacLength
        $ciphertext = [byte[]]$package[$ivLength..($ivLength + $cipherLength - 1)]

        $macInput = [byte[]]::new($iv.Length + $ciphertext.Length)
        [System.Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $macInput, $iv.Length, $ciphertext.Length)

        $computed = [HmacService]::Sign($macInput, $this._macKey)
        $macValid = [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals($computed, $hmac)
        if (-not $macValid) {
            throw [System.Security.Cryptography.CryptographicException]::new("MAC verification failed.")
        }

        $aes = $null
        try {
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key = $this._encryptionKey
            $aes.IV = $iv
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $decryptor = $aes.CreateDecryptor()
            return $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        }
        finally {
            if ($aes -ne $null) {
                $aes.Dispose()
            }
        }
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._encryptionKey -ne $null) {
                [System.Array]::Clear($this._encryptionKey, 0, $this._encryptionKey.Length)
            }
            if ($this._macKey -ne $null) {
                [System.Array]::Clear($this._macKey, 0, $this._macKey.Length)
            }
        }
    }
}
