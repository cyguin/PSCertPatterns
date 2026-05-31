function Invoke-EncryptDecryptBattery {
    param([object]$Target, [hashtable]$Thresholds)

    $results = [System.Collections.Generic.List[hashtable]]::new()

    function AddResult($name, $passed, $observed, $expected, $thresholdKey, $notes) {
        $results.Add(@{ TestName = $name; Passed = $passed; Observed = $observed; Expected = $expected; ThresholdKey = $thresholdKey; Notes = $notes })
    }

    # Zero-length plaintext
    try {
        $ct = $Target.Encrypt([byte[]]::new(0))
        AddResult "Zero-length plaintext" $true "Encrypted to $($ct.Length) bytes" "Package >= 28" "zeroLengthPlaintext" $null
    } catch {
        AddResult "Zero-length plaintext" $false $_.Exception.Message "Encrypt succeeds" "zeroLengthPlaintext" $null
    }

    # Single-byte plaintext
    try {
        $ct = $Target.Encrypt([byte[]]::new(1))
        AddResult "Single-byte plaintext" $true "Encrypted to $($ct.Length) bytes" "Package >= 29" $null $null
    } catch {
        AddResult "Single-byte plaintext" $false $_.Exception.Message "Encrypt succeeds" $null $null
    }

    # Round-trip
    try {
        $pt = [System.Text.Encoding]::UTF8.GetBytes("Adversary round-trip")
        $encrypted = $Target.Encrypt($pt)
        $decrypted = $Target.Decrypt($encrypted)
        if ([System.Linq.Enumerable]::SequenceEqual($pt, $decrypted)) {
            AddResult "Round-trip" $true "Plaintext recovered correctly" "Decrypt(Encrypt(pt)) == pt" $null $null
        } else {
            AddResult "Round-trip" $false "Decrypted data does not match" "Decrypt(Encrypt(pt)) == pt" $null $null
        }
    } catch {
        AddResult "Round-trip" $false $_.Exception.Message "Round-trip succeeds" $null $null
    }

    # Bit-flip at every byte position
    try {
        $pt32 = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($pt32)
        $ct32 = $Target.Encrypt($pt32)
        $allPassed = $true
        $failCount = 0
        for ($i = 0; $i -lt $ct32.Length; $i++) {
            $flipped = [byte[]]$ct32.Clone()
            $flipped[$i] = $flipped[$i] -bxor 1
            try {
                $Target.Decrypt($flipped)
                $allPassed = $false
                $failCount++
            } catch {
                # expected
            }
        }
        if ($allPassed) {
            AddResult "Bit-flip at every position" $true "All $($ct32.Length) positions rejected" "Every bit flip causes Decrypt to throw" "bitFlipDetection" $null
        } else {
            AddResult "Bit-flip at every position" $false "$failCount positions did not throw" "Every bit flip causes Decrypt to throw" "bitFlipDetection" $null
        }
    } catch {
        AddResult "Bit-flip at every position" $false $_.Exception.Message "Bit-flip test runs" "bitFlipDetection" $null
    }

    # Truncation
    try {
        $ct = $Target.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $trunc = [byte[]]$ct[0..($ct.Length - 2)]
        $Target.Decrypt($trunc)
        AddResult "Truncation attack" $false "Decrypt succeeded on truncated package" "Truncated package throws" $null $null
    } catch {
        AddResult "Truncation attack" $true "Truncated package rejected" "Truncated package throws" $null $null
    }

    # Extension
    try {
        $ct = $Target.Encrypt([System.Text.Encoding]::UTF8.GetBytes("data"))
        $ext = [byte[]]::new($ct.Length + 1)
        [System.Buffer]::BlockCopy($ct, 0, $ext, 0, $ct.Length)
        $Target.Decrypt($ext)
        AddResult "Extension attack" $false "Decrypt succeeded on extended package" "Extended package throws" $null $null
    } catch {
        AddResult "Extension attack" $true "Extended package rejected" "Extended package throws" $null $null
    }

    # Uniqueness: 1000 encryptions of same 16-byte plaintext
    try {
        $pt16 = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($pt16)
        $set = [System.Collections.Generic.HashSet[string]]::new()
        for ($i = 0; $i -lt 1000; $i++) {
            $set.Add([System.Convert]::ToBase64String($Target.Encrypt($pt16))) | Out-Null
        }
        if ($set.Count -eq 1000) {
            AddResult "Encryption uniqueness (1000 samples)" $true "All 1000 outputs unique" "No collisions" "nonceUniqueness" $null
        } else {
            AddResult "Encryption uniqueness (1000 samples)" $false "Only $($set.Count) unique out of 1000" "No collisions" "nonceUniqueness" $null
        }
    } catch {
        AddResult "Encryption uniqueness (1000 samples)" $false $_.Exception.Message "Uniqueness test runs" "nonceUniqueness" $null
    }

    return $results
}

function Invoke-SignVerifyBattery {
    param([object]$Target, [hashtable]$Thresholds)

    $results = [System.Collections.Generic.List[hashtable]]::new()

    function AddResult($name, $passed, $observed, $expected, $thresholdKey, $notes) {
        $results.Add(@{ TestName = $name; Passed = $passed; Observed = $observed; Expected = $expected; ThresholdKey = $thresholdKey; Notes = $notes })
    }

    $data = [System.Text.Encoding]::UTF8.GetBytes("Adversary signature test")

    # Round-trip
    try {
        $sig = $Target.Sign($data)
        if ($Target.Verify($data, $sig)) {
            AddResult "Sign and verify round-trip" $true "Signature verified correctly" "Verify(Sign(data), data) == true" $null $null
        } else {
            AddResult "Sign and verify round-trip" $false "Verify returned false" "Verify returns true" $null $null
        }
    } catch {
        AddResult "Sign and verify round-trip" $false $_.Exception.Message "Round-trip succeeds" $null $null
    }

    # Tampered data
    try {
        $sig = $Target.Sign($data)
        $tampered = [System.Text.Encoding]::UTF8.GetBytes("TAMPERED DATA")
        if (-not $Target.Verify($tampered, $sig)) {
            AddResult "Tampered data rejection" $true "Verify returned false for tampered data" "Verify returns false" "tamperedSignatureRejection" $null
        } else {
            AddResult "Tampered data rejection" $false "Verify returned true for tampered data" "Verify returns false" "tamperedSignatureRejection" $null
        }
    } catch {
        AddResult "Tampered data rejection" $false $_.Exception.Message "Verify does not throw" "tamperedSignatureRejection" $null
    }

    # Tampered signature
    try {
        $sig = $Target.Sign($data)
        $tamperedSig = [byte[]]$sig.Clone()
        if ($tamperedSig.Length -gt 0) {
            $tamperedSig[0] = $tamperedSig[0] -bxor 1
        }
        if (-not $Target.Verify($data, $tamperedSig)) {
            AddResult "Tampered signature rejection" $true "Verify returned false for tampered signature" "Verify returns false" "tamperedSignatureRejection" $null
        } else {
            AddResult "Tampered signature rejection" $false "Verify returned true for tampered signature" "Verify returns false" "tamperedSignatureRejection" $null
        }
    } catch {
        AddResult "Tampered signature rejection" $false $_.Exception.Message "Verify does not throw" "tamperedSignatureRejection" $null
    }

    # Zero-length data
    try {
        $sig = $Target.Sign([byte[]]::new(0))
        if ($Target.Verify([byte[]]::new(0), $sig)) {
            AddResult "Zero-length data sign/verify" $true "Zero-length data round-trips" "Sign and verify succeed" $null $null
        } else {
            AddResult "Zero-length data sign/verify" $false "Verify returned false" "Round-trip succeeds" $null $null
        }
    } catch {
        AddResult "Zero-length data sign/verify" $false $_.Exception.Message "Sign succeeds" $null $null
    }

    return $results
}

function Invoke-DeriveKeyBattery {
    param([object]$Target, [hashtable]$Thresholds)

    $results = [System.Collections.Generic.List[hashtable]]::new()
    $salt = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)

    function AddResult($name, $passed, $observed, $expected, $thresholdKey, $notes) {
        $results.Add(@{ TestName = $name; Passed = $passed; Observed = $observed; Expected = $expected; ThresholdKey = $thresholdKey; Notes = $notes })
    }

    # Standard derivation
    try {
        $key = $Target.DeriveKey("test-password", $salt, 32)
        AddResult "Standard derivation" $true "Derived $($key.Length)-byte key" "Key derived without error" $null $null
    } catch {
        AddResult "Standard derivation" $false $_.Exception.Message "Derivation succeeds" $null $null
    }

    # Determinism
    try {
        $a = $Target.DeriveKey("consistent", $salt, 32)
        $b = $Target.DeriveKey("consistent", $salt, 32)
        if ([System.Linq.Enumerable]::SequenceEqual($a, $b)) {
            AddResult "Deterministic output" $true "Same inputs produce same key" "Deterministic for same salt+password" $null $null
        } else {
            AddResult "Deterministic output" $false "Different keys for same inputs" "Same inputs produce same key" $null $null
        }
    } catch {
        AddResult "Deterministic output" $false $_.Exception.Message "Derivation succeeds" $null $null
    }

    # Salt uniqueness
    try {
        $salt2 = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt2)
        $a = $Target.DeriveKey("password", $salt, 32)
        $b = $Target.DeriveKey("password", $salt2, 32)
        if (-not [System.Linq.Enumerable]::SequenceEqual($a, $b)) {
            AddResult "Salt uniqueness" $true "Different salts produce different keys" "Different salts yield different keys" $null $null
        } else {
            AddResult "Salt uniqueness" $false "Same key for different salts" "Different salts yield different keys" $null $null
        }
    } catch {
        AddResult "Salt uniqueness" $false $_.Exception.Message "Derivation succeeds" $null $null
    }

    # Boundary: salt at exactly 16 bytes
    try {
        $s16 = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($s16)
        $key = $Target.DeriveKey("boundary", $s16, 32)
        AddResult "Salt boundary (16 bytes)" $true "16-byte salt accepted, derived $($key.Length)-byte key" "16-byte salt succeeds" "minimumSaltBytes" $null
    } catch {
        AddResult "Salt boundary (16 bytes)" $false $_.Exception.Message "16-byte salt succeeds" "minimumSaltBytes" $null
    }

    # Boundary: salt at 15 bytes
    try {
        $s15 = [byte[]]::new(15)
        $Target.DeriveKey("boundary", $s15, 32)
        AddResult "Salt boundary (15 bytes)" $false "15-byte salt accepted" "15-byte salt should throw" "minimumSaltBytes" $null
    } catch {
        AddResult "Salt boundary (15 bytes)" $true "15-byte salt rejected" "15-byte salt throws" "minimumSaltBytes" $null
    }

    return $results
}

function Invoke-ReplayGuardBattery {
    param([object]$Target, [hashtable]$Thresholds)

    $results = [System.Collections.Generic.List[hashtable]]::new()

    function AddResult($name, $passed, $observed, $expected, $thresholdKey, $notes) {
        $results.Add(@{ TestName = $name; Passed = $passed; Observed = $observed; Expected = $expected; ThresholdKey = $thresholdKey; Notes = $notes })
    }

    $nonce = [byte[]]::new(12)
    try {
        $result = $Target.CheckAndRecord($nonce)
        if ($result) {
            AddResult "First use returns true" $true "CheckAndRecord returned true" "true" $null $null
        } else {
            AddResult "First use returns true" $false "CheckAndRecord returned false" "true" $null $null
        }
    } catch {
        AddResult "First use returns true" $false $_.Exception.Message "CheckAndRecord succeeds" $null $null
    }

    # Second use returns false
    try {
        $nonce = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $Target.CheckAndRecord($nonce) | Out-Null
        $result = $Target.CheckAndRecord($nonce)
        if (-not $result) {
            AddResult "Second use returns false" $true "Replay detected" "false" $null $null
        } else {
            AddResult "Second use returns false" $false "Replay not detected" "false" $null $null
        }
    } catch {
        AddResult "Second use returns false" $false $_.Exception.Message "CheckAndRecord succeeds" $null $null
    }

    # HasSeen does not record
    try {
        $nonce = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $before = $Target.SeenCount()
        $Target.HasSeen($nonce) | Out-Null
        $after = $Target.SeenCount()
        if ($after -eq $before) {
            AddResult "HasSeen does not record" $true "SeenCount unchanged" "SeenCount unchanged after HasSeen" $null $null
        } else {
            AddResult "HasSeen does not record" $false "SeenCount changed from $before to $after" "SeenCount unchanged after HasSeen" $null $null
        }
    } catch {
        AddResult "HasSeen does not record" $false $_.Exception.Message "HasSeen succeeds" $null $null
    }

    # Uniqueness: 1000 random nonces
    try {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        $allOk = $true
        for ($i = 0; $i -lt 1000; $i++) {
            $n = [byte[]]::new(12)
            [System.Security.Cryptography.RandomNumberGenerator]::Fill($n)
            if (-not $Target.CheckAndRecord($n)) {
                $allOk = $false
                break
            }
        }
        if ($allOk) {
            AddResult "1000 unique nonces" $true "All 1000 accepted" "No false positives" "uniquenessAt1000" $null
        } else {
            AddResult "1000 unique nonces" $false "False positive detected" "No false positives" "uniquenessAt1000" $null
        }
    } catch {
        AddResult "1000 unique nonces" $false $_.Exception.Message "CheckAndRecord succeeds" "uniquenessAt1000" $null
    }

    return $results
}

function Invoke-KeyRotationBattery {
    param([object]$Target, [hashtable]$Thresholds)

    $results = [System.Collections.Generic.List[hashtable]]::new()

    function AddResult($name, $passed, $observed, $expected, $thresholdKey, $notes) {
        $results.Add(@{ TestName = $name; Passed = $passed; Observed = $observed; Expected = $expected; ThresholdKey = $thresholdKey; Notes = $notes })
    }

    # Encrypt and decrypt round-trip
    try {
        $pt = [System.Text.Encoding]::UTF8.GetBytes("rotation test")
        $pkg = $Target.Encrypt($pt)
        $decrypted = $Target.Decrypt($pkg.KeyId, $pkg.Ciphertext)
        if ([System.Linq.Enumerable]::SequenceEqual($pt, $decrypted)) {
            AddResult "Round-trip" $true "Plaintext recovered" "Decrypt(Encrypt(pt)) == pt" $null $null
        } else {
            AddResult "Round-trip" $false "Decrypted data mismatch" "Plaintext recovered" $null $null
        }
    } catch {
        AddResult "Round-trip" $false $_.Exception.Message "Round-trip succeeds" $null $null
    }

    # Rotate changes CurrentKeyId
    try {
        $original = $Target.CurrentKeyId()
        $Target.Rotate()
        $after = $Target.CurrentKeyId()
        if ($after -ne $original) {
            AddResult "Rotate changes key" $true "CurrentKeyId changed from $original to $after" "Key ID changes after rotation" $null $null
        } else {
            AddResult "Rotate changes key" $false "CurrentKeyId unchanged after Rotate" "Key ID changes after rotation" $null $null
        }
    } catch {
        AddResult "Rotate changes key" $false $_.Exception.Message "Rotate succeeds" $null $null
    }

    # Post-rotate decrypt still works for in-window keys
    try {
        $pkg = $Target.Encrypt([System.Text.Encoding]::UTF8.GetBytes("pre-rotate"))
        $Target.Rotate()
        $decrypted = $Target.Decrypt($pkg.KeyId, $pkg.Ciphertext)
        if ([System.Linq.Enumerable]::SequenceEqual([System.Text.Encoding]::UTF8.GetBytes("pre-rotate"), $decrypted)) {
            AddResult "Post-rotate decrypt" $true "Pre-rotate package still decrypts" "In-window key works after rotation" $null $null
        } else {
            AddResult "Post-rotate decrypt" $false "Decrypted data mismatch" "Plaintext recovered" $null $null
        }
    } catch {
        AddResult "Post-rotate decrypt" $false $_.Exception.Message "Decrypt succeeds" $null $null
    }

    # Evicted key decrypt throws
    try {
        # Window must be >= 2 for this test to be meaningful
        $earlyPkg = $Target.Encrypt([System.Text.Encoding]::UTF8.GetBytes("pre-rotation"))
        $earlyKeyId = $earlyPkg.KeyId
        $Target.Rotate()
        $Target.Rotate()
        $Target.Rotate()
        $Target.Rotate()
        $Target.Decrypt($earlyKeyId, $earlyPkg.Ciphertext) | Out-Null
        AddResult "Evicted key rejection" $false "Decrypt succeeded on evicted key" "Evicted key throws" $null $null
    } catch {
        AddResult "Evicted key rejection" $true "Evicted key rejected" "Evicted key throws" $null $null
    }

    return $results
}
