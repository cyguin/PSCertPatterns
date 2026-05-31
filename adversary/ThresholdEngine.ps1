function Compare-Thresholds {
    param([hashtable[]]$Results, [hashtable]$Thresholds)

    $passed = 0
    $failed = 0
    $skipped = 0
    $violations = [System.Collections.Generic.List[string]]::new()
    $findings = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($result in $Results) {
        $finding = @{
            TestName = $result.TestName
            Passed = $result.Passed
            Observed = $result.Observed
            Expected = $result.Expected
            ThresholdKey = $result.ThresholdKey
            Notes = $result.Notes
            ThresholdViolation = $false
        }

        if ($result.Passed) {
            $passed++
        } else {
            $failed++
            if (-not [string]::IsNullOrEmpty($result.ThresholdKey)) {
                $finding.ThresholdViolation = $true
                $violations.Add("$($result.TestName): $($result.Observed)")
            }
        }

        $findings.Add($finding)
    }

    $total = $passed + $failed + $skipped
    $score = if ($total -gt 0) { [math]::Round(($passed / $total) * 100) } else { 0 }

    return @{
        Score = $score
        Passed = $passed
        Failed = $failed
        Skipped = $skipped
        ThresholdViolations = [string[]]$violations
        Findings = [hashtable[]]$findings
    }
}
