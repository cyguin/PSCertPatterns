BeforeAll {
    . "$PSScriptRoot/../src/01_AesGcm.ps1"
    . "$PSScriptRoot/../src/02_KeyDerivation.ps1"
    . "$PSScriptRoot/../src/03_NonceManagement.ps1"
    . "$PSScriptRoot/../src/04_HmacCbc.ps1"
    . "$PSScriptRoot/../src/05_Rsa.ps1"
    . "$PSScriptRoot/../src/06_Ecdsa.ps1"
    . "$PSScriptRoot/../src/07_CertChain.ps1"
    . "$PSScriptRoot/../src/08_KeyRotation.ps1"
    . "$PSScriptRoot/../src/09_AlgorithmAgility.ps1"
}

Describe "Adversarial — AES-GCM Package Format" {
    BeforeAll {
        $script:gcmKey = [byte[]]::new(32)
    }

    It "Zero-length plaintext encrypts, package length = 28" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([byte[]]::new(0))
        $pkg.Length | Should -Be 28
        $svc.Dispose()
    }

    It "Single-byte plaintext, package length = 29" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([byte[]]::new(1))
        $pkg.Length | Should -Be 29
        $svc.Dispose()
    }

    It "Bit-flip at nonce byte 0 throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $pkg[0] = $pkg[0] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip at nonce byte 11 throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $pkg[11] = $pkg[11] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip at tag byte 0 (package[12]) throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $pkg[12] = $pkg[12] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip at tag byte 15 (package[27]) throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $pkg[27] = $pkg[27] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip at first ciphertext byte throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pt = [System.Text.Encoding]::UTF8.GetBytes("payload-data")
        $pkg = $svc.Encrypt($pt)
        $pkg[28] = $pkg[28] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip at last ciphertext byte throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pt = [System.Text.Encoding]::UTF8.GetBytes("payload-data")
        $pkg = $svc.Encrypt($pt)
        $pkg[-1] = $pkg[-1] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Truncated package (remove last byte) throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $truncated = [byte[]]$pkg[0..($pkg.Length - 2)]
        { $svc.Decrypt($truncated) } | Should -Throw
        $svc.Dispose()
    }

    It "Extended package (append 0x00) throws" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $extended = [byte[]]::new($pkg.Length + 1)
        [System.Buffer]::BlockCopy($pkg, 0, $extended, 0, $pkg.Length)
        { $svc.Decrypt($extended) } | Should -Throw
        $svc.Dispose()
    }

    It "All-zero key constructs and encrypts without error" {
        $zeroKey = [byte[]]::new(32)
        $svc = [AesGcmService]::new($zeroKey)
        $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("test")) | Should -Not -BeNullOrEmpty
        $svc.Dispose()
    }

    It "All-zero plaintext (32 bytes) encrypts and round-trips" {
        $svc = [AesGcmService]::new($script:gcmKey)
        $plaintext = [byte[]]::new(32)
        $pkg = $svc.Encrypt($plaintext)
        $decrypted = $svc.Decrypt($pkg)
        [System.Linq.Enumerable]::SequenceEqual($decrypted, $plaintext) | Should -Be $true
        $svc.Dispose()
    }
}

Describe "Adversarial — HMAC-CBC Attack Surface" {
    BeforeAll {
        $script:cbcEncKey = [byte[]]::new(32)
        $script:cbcMacKey = [byte[]]::new(32)
    }

    It "Bit-flip at IV byte 0 throws" {
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $pkg[0] = $pkg[0] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip at IV byte 15 throws" {
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $pkg[15] = $pkg[15] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "Bit-flip in ciphertext body throws" {
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("payload-data-here"))
        $pkg[20] = $pkg[20] -bxor 1
        { $svc.Decrypt($pkg) } | Should -Throw
        $svc.Dispose()
    }

    It "HMAC truncation (strip last byte) throws" {
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $truncated = [byte[]]$pkg[0..($pkg.Length - 2)]
        { $svc.Decrypt($truncated) } | Should -Throw
        $svc.Dispose()
    }

    It "Swap IV between two packages — both throw" {
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkgA = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("aaaa"))
        $pkgB = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("bbbb"))
        $ivA = [byte[]]$pkgA[0..15]
        $ivB = [byte[]]$pkgB[0..15]
        [System.Buffer]::BlockCopy($ivB, 0, $pkgA, 0, 16)
        [System.Buffer]::BlockCopy($ivA, 0, $pkgB, 0, 16)
        { $svc.Decrypt($pkgA) } | Should -Throw
        { $svc.Decrypt($pkgB) } | Should -Throw
        $svc.Dispose()
    }

    It "Zero-length plaintext encrypts, documents PKCS7 padding size" {
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkg = $svc.Encrypt([byte[]]::new(0))
        $pkg.Length | Should -Be 64
        $svc.Dispose()
    }

    It "Wrong MAC key throws" {
        $wrongMacKey = [byte[]]::new(32)
        $wrongMacKey[0] = 1
        $svc = [AesCbcService]::new($script:cbcEncKey, $script:cbcMacKey)
        $pkg = $svc.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $svc.Dispose()
        $attackerSvc = [AesCbcService]::new($script:cbcEncKey, $wrongMacKey)
        { $attackerSvc.Decrypt($pkg) } | Should -Throw
        $attackerSvc.Dispose()
    }
}

Describe "Adversarial — PBKDF2 Thresholds" {
    BeforeAll {
        $script:pbkdfSalt = [SaltGenerator]::Generate(32)
    }

    It "1 iteration completes without error" {
        $key = [Pbkdf2KeyDerivation]::DeriveKey("password", $script:pbkdfSalt, 32, 1)
        $key.Length | Should -Be 32
    }

    It "600000 iterations completes and is deterministic" {
        $a = [Pbkdf2KeyDerivation]::DeriveKey("test", $script:pbkdfSalt, 32)
        $b = [Pbkdf2KeyDerivation]::DeriveKey("test", $script:pbkdfSalt, 32)
        [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $true
    }

    It "Same password + same salt produces identical key" {
        $s = [SaltGenerator]::Generate(32)
        $a = [Pbkdf2KeyDerivation]::DeriveKey("pwd", $s, 16)
        $b = [Pbkdf2KeyDerivation]::DeriveKey("pwd", $s, 16)
        [System.Linq.Enumerable]::SequenceEqual($a, $b) | Should -Be $true
    }

    It "Key size 1 throws ArgumentException" {
        { [Pbkdf2KeyDerivation]::DeriveKey("pwd", $script:pbkdfSalt, 1) } | Should -Throw -ExceptionType ([System.ArgumentException])
    }

    It "Key size 16 succeeds" {
        $key = [Pbkdf2KeyDerivation]::DeriveKey("pwd", $script:pbkdfSalt, 16)
        $key.Length | Should -Be 16
    }

    It "Key size 64 succeeds" {
        $key = [Pbkdf2KeyDerivation]::DeriveKey("pwd", $script:pbkdfSalt, 64)
        $key.Length | Should -Be 64
    }

    It "Password of 10000 characters completes without error" {
        $longPwd = [string]::new('x', 10000)
        $key = [Pbkdf2KeyDerivation]::DeriveKey($longPwd, $script:pbkdfSalt, 32)
        $key.Length | Should -Be 32
    }

    It "Salt of exactly 16 bytes succeeds" {
        $s16 = [SaltGenerator]::Generate(16)
        $key = [Pbkdf2KeyDerivation]::DeriveKey("pwd", $s16, 32)
        $key.Length | Should -Be 32
    }

    It "Salt of 15 bytes throws ArgumentException" {
        $s15 = [byte[]]::new(15)
        { [Pbkdf2KeyDerivation]::DeriveKey("pwd", $s15, 32) } | Should -Throw -ExceptionType ([System.ArgumentException])
    }
}

Describe "Adversarial — Nonce Uniqueness" {
    It "CounterNonceGenerator: 10000 sequential nonces are all unique" {
        $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
        $set = [System.Collections.Generic.HashSet[string]]::new()
        for ($i = 0; $i -lt 10000; $i++) {
            $set.Add([System.Convert]::ToBase64String($svc.Next())) | Out-Null
        }
        $set.Count | Should -Be 10000
        $svc.Dispose()
    }

    It "CounterNonceGenerator: nonces are strictly monotonically increasing" {
        $svc = [CounterNonceGenerator]::new([byte[]]::new(8))
        $firstNonce = $svc.Next()
        $lastNonce = $svc.Next()
        for ($i = 2; $i -lt 10000; $i++) { $lastNonce = $svc.Next() }
        $firstCounter = [byte[]]$firstNonce[8..11]; $v1 = ($firstCounter[0] -shl 24) -bor ($firstCounter[1] -shl 16) -bor ($firstCounter[2] -shl 8) -bor $firstCounter[3]
        $lastCounter = [byte[]]$lastNonce[8..11]; $v2 = ($lastCounter[0] -shl 24) -bor ($lastCounter[1] -shl 16) -bor ($lastCounter[2] -shl 8) -bor $lastCounter[3]
        $v1 | Should -BeGreaterThan 0
        $v2 | Should -BeGreaterThan $v1
        $svc.Dispose()
    }

    It "RandomNonceGenerator: 10000 nonces are all unique" {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        for ($i = 0; $i -lt 10000; $i++) {
            $set.Add([System.Convert]::ToBase64String([RandomNonceGenerator]::Generate())) | Out-Null
        }
        $set.Count | Should -Be 10000
    }

    It "Two CounterNonceGenerator instances with same keyId produce same first nonce" {
        $keyId = [byte[]]::new(8)
        $a = [CounterNonceGenerator]::new($keyId)
        $b = [CounterNonceGenerator]::new($keyId)
        $na = $a.Next()
        $nb = $b.Next()
        [System.Linq.Enumerable]::SequenceEqual($na, $nb) | Should -Be $true
        $a.Dispose()
        $b.Dispose()
    }
}

Describe "Adversarial — RSA Attack Surface" {
    It "OAEP-SHA256 max plaintext: 190 bytes succeeds" {
        $svc = [RsaEncryptionService]::new(2048)
        $max190 = [byte[]]::new(190)
        $ct = $svc.Encrypt($max190)
        $ct.Length | Should -Be 256
        $svc.Dispose()
    }

    It "OAEP-SHA256 max plaintext: 191 bytes throws" {
        $svc = [RsaEncryptionService]::new(2048)
        $max191 = [byte[]]::new(191)
        { $svc.Encrypt($max191) } | Should -Throw
        $svc.Dispose()
    }

    It "Empty plaintext round-trips" {
        $svc = [RsaEncryptionService]::new(2048)
        $empty = [byte[]]::new(0)
        $ct = $svc.Encrypt($empty)
        $decrypted = $svc.Decrypt($ct)
        $decrypted.Length | Should -Be 0
        $svc.Dispose()
    }

    It "Signature of zero-length data round-trips" {
        $signer = [RsaSigningService]::new(2048)
        $sig = $signer.Sign([byte[]]::new(0))
        $signer.Verify([byte[]]::new(0), $sig) | Should -Be $true
        $signer.Dispose()
    }

    It "Cross-key verification returns false (not throws)" {
        $a = [RsaSigningService]::new(2048)
        $b = [RsaSigningService]::new(2048)
        $data = [System.Text.Encoding]::UTF8.GetBytes("data")
        $sig = $a.Sign($data)
        $result = $false
        { $result = $b.Verify($data, $sig) } | Should -Not -Throw
        $result | Should -Be $false
        $a.Dispose()
        $b.Dispose()
    }

    It "Tampered signature (flip one bit) returns false" {
        $signer = [RsaSigningService]::new(2048)
        $data = [System.Text.Encoding]::UTF8.GetBytes("data")
        $sig = $signer.Sign($data)
        $sig[10] = $sig[10] -bxor 1
        $result = $false
        { $result = $signer.Verify($data, $sig) } | Should -Not -Throw
        $result | Should -Be $false
        $signer.Dispose()
    }
}

Describe "Adversarial — Key Rotation Eviction" {
    It "Window=1: after Rotate(), original KeyId throws KeyNotFoundException" {
        $mgr = [RotatingKeyManager]::new(1)
        $pkg = $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $originalKId = $pkg.KeyId
        $mgr.Rotate()
        { $mgr.Decrypt($originalKId, $pkg.Ciphertext) } | Should -Throw
        $mgr.Dispose()
    }

    It "Window=3: rotate 10 times, KeyCount never exceeds 3" {
        $mgr = [RotatingKeyManager]::new(3)
        for ($i = 0; $i -lt 10; $i++) {
            $mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
            $mgr.Rotate()
            $mgr.KeyCount() | Should -BeLessOrEqual 3
        }
        $mgr.Dispose()
    }

    It "Window=3: Encrypt-before-Rotate pattern leaves 2 valid packages after 10 cycles" {
        $mgr = [RotatingKeyManager]::new(3)
        $packages = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt 10; $i++) {
            $packages.Add($mgr.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data$i")))
            $mgr.Rotate()
        }
        $validCount = 0
        for ($i = 0; $i -lt $packages.Count; $i++) {
            try {
                $r = $mgr.Decrypt($packages[$i].KeyId, $packages[$i].Ciphertext)
                $validCount++
            } catch {
                # expected for evicted keys
            }
        }
        $validCount | Should -Be 2
        $mgr.Dispose()
    }

    It "After Dispose(), internal _keys dictionary is empty" {
        $mgr = [RotatingKeyManager]::new(3)
        $mgr.Encrypt([byte[]]::new(1))
        $mgr.Rotate()
        $mgr.Dispose()
        $mgr._keys.Count | Should -Be 0
    }
}

Describe "Adversarial — Certificate Chain" {
    It "Cross-PKI rejection: leaf from PKI A validated with PKI B's root fails" {
        $pkiA = [InMemoryPki]::new("CN=RootA")
        $pkiB = [InMemoryPki]::new("CN=RootB")
        $leaf = $pkiA.IssueCertificate("CN=LeafA")
        $v = [CertificateValidator]::Development()
        $v.ExtraStore.Add($pkiB.RootCertificate())
        $result = $v.Validate($leaf)
        $result.IsValid | Should -Be $false
        $v.Dispose()
        $leaf.Dispose()
        $pkiA.Dispose()
        $pkiB.Dispose()
    }

    It "Expired cert validation returns IsValid=false with time-related error" {
        $pki = [InMemoryPki]::new("CN=RootExpired")
        $root = $pki.RootCertificate()
        $leafKey = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=ExpiredLeaf",
            $leafKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $serial = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
        $serial[0] = $serial[0] -band 0x7F
        $notBefore = $root.NotBefore
        $notAfter = $notBefore.AddMilliseconds(1)
        $signed = $req.Create($root, $notBefore, $notAfter, $serial)
        $cert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($signed, $leafKey)
        $signed.Dispose()
        $leafKey.Dispose()
        $v = [CertificateValidator]::Development()
        $v.ExtraStore.Add($root)
        Start-Sleep -Milliseconds 100
        $result = $v.Validate($cert)
        $result.IsValid | Should -Be $false
        $hasTimeError = $false
        foreach ($e in $result.Errors) {
            if ($e -match "Time|time|valid|expir|NotTime") {
                $hasTimeError = $true
                break
            }
        }
        $hasTimeError | Should -Be $true
        $v.Dispose()
        $cert.Dispose()
        $pki.Dispose()
    }

    It "Thumbprint pin with multiple pins: matching any one passes" {
        $pki = [InMemoryPki]::new("CN=RootMultiPin")
        $root = $pki.RootCertificate()
        $v = [CertificateValidator]::Development()
        $v.ExtraStore.Add($root)
        $v.TrustedThumbprints.Add("0000000000000000000000000000000000000000")
        $v.TrustedThumbprints.Add($root.Thumbprint)
        $v.TrustedThumbprints.Add("ffffffffffffffffffffffffffffffffffffffff")
        $result = $v.Validate($root)
        $result.IsValid | Should -Be $true
        $v.Dispose()
        $pki.Dispose()
    }

    It "Empty subject cert (CN=) is accepted by CertificateRequest" {
        $pki = [InMemoryPki]::new("CN=RootEmptySubj")
        $root = $pki.RootCertificate()
        $leafKey = [System.Security.Cryptography.RSA]::Create(2048)
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=",
            $leafKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $serial = [byte[]]::new(8)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
        $serial[0] = $serial[0] -band 0x7F
        $now = [System.DateTimeOffset]::Now
        $notBefore = $now.AddMinutes(-1)
        if ($notBefore -lt $root.NotBefore) { $notBefore = $root.NotBefore }
        $signed = $req.Create($root, $notBefore, $now.AddYears(1), $serial)
        $cert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($signed, $leafKey)
        $cert.Subject.Contains("CN=") | Should -Be $true
        $cert.Dispose()
        $signed.Dispose()
        $leafKey.Dispose()
        $pki.Dispose()
    }
}

Describe "Adversarial — Cross-Slice Integration" {
    It "Derive key -> AES-GCM encrypt/decrypt round-trips" {
        $salt = [SaltGenerator]::Generate(32)
        $key = [Pbkdf2KeyDerivation]::DeriveKey("integration-test", $salt, 32)
        $svc = [AesGcmService]::new($key)
        $plaintext = [System.Text.Encoding]::UTF8.GetBytes("cross-slice integration")
        $pkg = $svc.Encrypt($plaintext)
        $decrypted = $svc.Decrypt($pkg)
        [System.Linq.Enumerable]::SequenceEqual($decrypted, $plaintext) | Should -Be $true
        $svc.Dispose()
    }

    It "Salt -> derive -> AES-GCM -> key rotation -> old decrypt works" {
        $salt = [SaltGenerator]::Generate(32)
        $key = [Pbkdf2KeyDerivation]::DeriveKey("password", $salt, 32)
        $svc = [AesGcmService]::new($key)
        $originalPlaintext = [System.Text.Encoding]::UTF8.GetBytes("rotate me")
        $encrypted = $svc.Encrypt($originalPlaintext)
        $svc.Dispose()
        $mgr = [RotatingKeyManager]::new(3)
        $mgr.Encrypt([byte[]]::new(1))
        $mgr.Rotate()
        $mgr.Dispose()
        $svc2 = [AesGcmService]::new($key)
        $decrypted = $svc2.Decrypt($encrypted)
        [System.Linq.Enumerable]::SequenceEqual($decrypted, $originalPlaintext) | Should -Be $true
        $svc2.Dispose()
    }

    It "ECDSA sign -> export -> FromPublicKey -> verify" {
        $signer = [EcdsaSigningService]::new("P-256")
        $data = [System.Text.Encoding]::UTF8.GetBytes("ecdsa cross-slice")
        $sig = $signer.Sign($data)
        $pubKeyDer = $signer.ExportPublicKey()
        $verifier = [EcdsaSigningService]::FromPublicKey($pubKeyDer)
        $verifier.Verify($data, $sig) | Should -Be $true
        $signer.Dispose()
        $verifier.Dispose()
    }

    It "InMemoryPki: issue 3 certs, validate all with same validator" {
        $pki = [InMemoryPki]::new("CN=RootMultiIssue")
        $root = $pki.RootCertificate()
        $leaves = @()
        1..3 | ForEach-Object { $leaves += $pki.IssueCertificate("CN=Leaf$_") }
        $v = [CertificateValidator]::Development()
        $v.ExtraStore.Add($root)
        foreach ($leaf in $leaves) {
            $result = $v.Validate($leaf)
            $result.IsValid | Should -Be $true
        }
        $v.Dispose()
        foreach ($leaf in $leaves) { $leaf.Dispose() }
        $pki.Dispose()
    }
}
