class CipherProfile {
    [string]$Name
    [string]$Algorithm
    [int]$KeySize
    [int]$NonceSizeBytes
    [int]$TagSizeBytes
    [string]$KdfAlgorithm
    [int]$KdfIterations
    [bool]$Deprecated = $false

    CipherProfile(
        [string]$name,
        [string]$algorithm,
        [int]$keySize,
        [int]$nonceSizeBytes,
        [int]$tagSizeBytes,
        [string]$kdfAlgorithm,
        [int]$kdfIterations,
        [bool]$deprecated
    ) {
        $this.Name = $name
        $this.Algorithm = $algorithm
        $this.KeySize = $keySize
        $this.NonceSizeBytes = $nonceSizeBytes
        $this.TagSizeBytes = $tagSizeBytes
        $this.KdfAlgorithm = $kdfAlgorithm
        $this.KdfIterations = $kdfIterations
        $this.Deprecated = $deprecated
    }

    [string] ToString() {
        return "$($this.Name) (KeySize=$($this.KeySize), Deprecated=$($this.Deprecated))"
    }
}

class AlgorithmRegistry {
    hidden static [System.Collections.Generic.Dictionary[string, CipherProfile]]$_profiles

    static AlgorithmRegistry() {
        [AlgorithmRegistry]::_profiles = [System.Collections.Generic.Dictionary[string, CipherProfile]]::new()
        [AlgorithmRegistry]::_profiles.Add("AES-256-GCM", [CipherProfile]::new("AES-256-GCM", "AES-GCM", 256, 12, 16, "PBKDF2-SHA256", 600000, $false))
        [AlgorithmRegistry]::_profiles.Add("AES-128-GCM", [CipherProfile]::new("AES-128-GCM", "AES-GCM", 128, 12, 16, "PBKDF2-SHA256", 600000, $false))
        [AlgorithmRegistry]::_profiles.Add("AES-256-CBC-HMAC", [CipherProfile]::new("AES-256-CBC-HMAC", "AES-CBC", 256, 16, 32, "PBKDF2-SHA256", 600000, $false))
        [AlgorithmRegistry]::_profiles.Add("AES-128-CBC-HMAC", [CipherProfile]::new("AES-128-CBC-HMAC", "AES-CBC", 128, 16, 32, "PBKDF2-SHA256", 600000, $true))
    }

    static [CipherProfile] Get([string]$name) {
        if (-not [AlgorithmRegistry]::_profiles.ContainsKey($name)) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("Profile not found: $name")
        }
        return [AlgorithmRegistry]::_profiles[$name]
    }

    static [CipherProfile] GetActive([string]$name) {
        $profile = [AlgorithmRegistry]::Get($name)
        if ($profile.Deprecated) {
            throw [System.InvalidOperationException]::new("Profile '$name' is deprecated.")
        }
        return $profile
    }

    static [void] Register([CipherProfile]$profile) {
        if ($null -eq $profile) {
            throw [System.ArgumentException]::new("Profile cannot be null.", "profile")
        }
        [AlgorithmRegistry]::_profiles[$profile.Name] = $profile
    }

    static [void] Deprecate([string]$name) {
        if (-not [AlgorithmRegistry]::_profiles.ContainsKey($name)) {
            throw [System.Collections.Generic.KeyNotFoundException]::new("Profile not found: $name")
        }
        [AlgorithmRegistry]::_profiles[$name].Deprecated = $true
    }

    static [System.Collections.Generic.List[CipherProfile]] ListActive() {
        $result = [System.Collections.Generic.List[CipherProfile]]::new()
        foreach ($kvp in [AlgorithmRegistry]::_profiles.GetEnumerator()) {
            if (-not $kvp.Value.Deprecated) {
                $result.Add($kvp.Value)
            }
        }
        return $result
    }

    static [System.Collections.Generic.List[CipherProfile]] ListAll() {
        $result = [System.Collections.Generic.List[CipherProfile]]::new()
        foreach ($kvp in [AlgorithmRegistry]::_profiles.GetEnumerator()) {
            $result.Add($kvp.Value)
        }
        return $result
    }

    static [bool] IsRegistered([string]$name) {
        return [AlgorithmRegistry]::_profiles.ContainsKey($name)
    }
}
