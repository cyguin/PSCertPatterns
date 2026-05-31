class RandomNonceGenerator {
    static [byte[]] Generate() {
        return [RandomNonceGenerator]::Generate(12)
    }

    static [byte[]] Generate([int]$size) {
        if ($size -lt 1) {
            throw [System.ArgumentException]::new("Size must be at least 1.", "size")
        }
        $nonce = [byte[]]::new($size)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        return $nonce
    }
}

class CounterNonceGenerator : System.IDisposable {
    hidden [int64]$_counter = 0
    hidden [byte[]]$_keyId
    hidden [bool]$_disposed = $false

    CounterNonceGenerator([byte[]]$keyId) {
        if ($keyId.Length -ne 8) {
            throw [System.ArgumentException]::new("keyId must be exactly 8 bytes.", "keyId")
        }
        $this._keyId = $keyId
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    [byte[]] Next() {
        $this.CheckDisposed()
        $this._counter++
        $counterBytes = [System.BitConverter]::GetBytes([uint32]$this._counter)
        if ([System.BitConverter]::IsLittleEndian) {
            [System.Array]::Reverse($counterBytes)
        }
        $nonce = [byte[]]::new(12)
        [System.Buffer]::BlockCopy($this._keyId, 0, $nonce, 0, 8)
        [System.Buffer]::BlockCopy($counterBytes, 0, $nonce, 8, 4)
        return $nonce
    }

    [int64] CurrentCount() {
        $this.CheckDisposed()
        return $this._counter
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._keyId -ne $null) {
                [System.Array]::Clear($this._keyId, 0, $this._keyId.Length)
            }
        }
    }
}
