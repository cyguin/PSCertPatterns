class SaltGenerator {
    static [byte[]] Generate([int]$size) {
        if ($size -lt 16) {
            throw [System.ArgumentException]::new("Size must be at least 16.", "size")
        }
        $buffer = [byte[]]::new($size)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
        return $buffer
    }
}

class Pbkdf2KeyDerivation {
    static [byte[]] DeriveKey([string]$password, [byte[]]$salt, [int]$keySize) {
        return [Pbkdf2KeyDerivation]::DeriveKey($password, $salt, $keySize, 600000)
    }

    static [byte[]] DeriveKey([string]$password, [byte[]]$salt, [int]$keySize, [int]$iterations) {
        if ($iterations -lt 1) {
            throw [System.ArgumentException]::new("Iterations must be at least 1.", "iterations")
        }
        if ([string]::IsNullOrEmpty($password)) {
            throw [System.ArgumentException]::new("Password cannot be null or empty.", "password")
        }
        if ($null -eq $salt -or $salt.Length -lt 16) {
            throw [System.ArgumentException]::new("Salt must be at least 16 bytes.", "salt")
        }
        if ($keySize -lt 16) {
            throw [System.ArgumentException]::new("KeySize must be at least 16.", "keySize")
        }
        $deriveBytes = $null
        try {
            $deriveBytes = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
                $password, $salt, $iterations,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256)
            return $deriveBytes.GetBytes($keySize)
        }
        finally {
            if ($deriveBytes -ne $null) {
                $deriveBytes.Dispose()
            }
        }
    }
}
