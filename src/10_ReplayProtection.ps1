class NonceReplayGuard : System.IDisposable {
    hidden [System.Collections.Generic.HashSet[string]]$_seen
    hidden [System.Collections.Generic.Queue[string]]$_order
    hidden [int]$_windowSize
    hidden [bool]$_disposed = $false

    NonceReplayGuard([int]$windowSize) {
        if ($windowSize -lt 1) {
            throw [System.ArgumentException]::new("windowSize must be at least 1.", "windowSize")
        }
        $this._windowSize = $windowSize
        $this._seen = [System.Collections.Generic.HashSet[string]]::new()
        $this._order = [System.Collections.Generic.Queue[string]]::new()
    }

    hidden [void] CheckDisposed() {
        if ($this._disposed) {
            throw [System.ObjectDisposedException]::new($this.GetType().FullName)
        }
    }

    hidden [string] NonceToKey([byte[]]$nonce) {
        if ($null -eq $nonce) {
            throw [System.ArgumentNullException]::new("nonce")
        }
        return [System.Convert]::ToBase64String($nonce)
    }

    [bool] CheckAndRecord([byte[]]$nonce) {
        $this.CheckDisposed()
        $key = $this.NonceToKey($nonce)
        if ($this._seen.Contains($key)) {
            return $false
        }
        $this._seen.Add($key) | Out-Null
        $this._order.Enqueue($key)
        if ($this._order.Count -gt $this._windowSize) {
            $oldest = $this._order.Dequeue()
            $this._seen.Remove($oldest) | Out-Null
        }
        return $true
    }

    [bool] HasSeen([byte[]]$nonce) {
        $this.CheckDisposed()
        return $this._seen.Contains($this.NonceToKey($nonce))
    }

    [int] SeenCount() {
        $this.CheckDisposed()
        return $this._seen.Count
    }

    [void] Reset() {
        $this.CheckDisposed()
        $this._seen.Clear()
        $this._order.Clear()
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            $this._disposed = $true
            if ($this._seen -ne $null) {
                $this._seen.Clear()
            }
            if ($this._order -ne $null) {
                $this._order.Clear()
            }
        }
    }
}
