function Write-AdversaryReport {
    param(
        [hashtable]$Evaluation,
        [string]$OutputPath,
        [string]$Format = "Markdown"
    )

    if ($Format -eq "JSON" -or $Format -eq "Both") {
        $json = $Evaluation | ConvertTo-Json -Depth 10
        if ($OutputPath) {
            $jsonPath = if ($Format -eq "Both") { $OutputPath -replace '\.json$', '' + ".json" } else { $OutputPath }
            $json | Out-File -FilePath $jsonPath -Encoding utf8
        }
        if ($Format -eq "JSON") {
            return $json
        }
    }

    $markdown = @"
# PSCertPatterns Adversary Report

**Date:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Contract:** $($Evaluation.Contract)
**Target Type:** $($Evaluation.TargetType)

## Score Summary

**$($Evaluation.Passed)/$($Evaluation.Passed + $Evaluation.Failed + $Evaluation.Skipped) tests passed ($($Evaluation.Score)%)**

| Metric | Count |
|--------|-------|
| Passed | $($Evaluation.Passed) |
| Failed | $($Evaluation.Failed) |
| Skipped | $($Evaluation.Skipped) |
| Score | $($Evaluation.Score)% |

"@

    if ($Evaluation.ThresholdViolations.Count -gt 0) {
        $markdown += @"

## Threshold Violations

| Test | Observation |
|------|-------------|
"@
        foreach ($v in $Evaluation.ThresholdViolations) {
            $markdown += "`n| $v |"
        }
    } else {
        $markdown += "`n**No threshold violations.**"
    }

    $markdown += @"

## Findings

| TestName | Passed | Observed | Notes |
|----------|--------|----------|-------|
"@

    foreach ($f in $Evaluation.Findings) {
        $status = if ($f.Passed) { "PASS" } else { "FAIL" }
        $obs = ($f.Observed -replace '\|', '/') -replace "`n", " "
        $notes = if ($f.Notes) { ($f.Notes -replace '\|', '/') -replace "`n", " " } else { "" }
        $markdown += "`n| $($f.TestName) | $status | $obs | $notes |"
    }

    $markdown += @"

---

*This report is observational data about behavioral thresholds. It does not prove cryptographic correctness. See adversary/README.md for the full disclaimer.*
"@

    if ($OutputPath -and ($Format -eq "Markdown" -or $Format -eq "Both")) {
        $mdPath = if ($Format -eq "Both") { $OutputPath -replace '\.md$', '' + ".md" } else { $OutputPath }
        $markdown | Out-File -FilePath $mdPath -Encoding utf8
    }

    return $markdown
}
