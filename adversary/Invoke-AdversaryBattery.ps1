. "$PSScriptRoot/Contracts.ps1"
. "$PSScriptRoot/Battery.ps1"
. "$PSScriptRoot/ThresholdEngine.ps1"
. "$PSScriptRoot/Reporter.ps1"

$script:isAdversaryLoaded = $true

function Invoke-AdversaryBattery {
    param(
        [object]$Target,
        [string]$Contract,
        [switch]$Discover,
        [string]$OutputPath,
        [string]$ReportFormat = "Markdown",
        [switch]$PassThru
    )

    $thresholdsPath = Join-Path $PSScriptRoot "thresholds.json"
    $thresholds = Get-Content $thresholdsPath -Raw | ConvertFrom-Json -AsHashtable

    if ($Discover) {
        $suggested = Get-SuggestedContracts -Target $Target
        Write-Host "Discovered contract matches for $($Target.GetType().Name):"
        if ($suggested.Length -eq 0) {
            Write-Host "  (none)"
        } else {
            foreach ($c in $suggested) {
                Write-Host "  - $c"
            }
        }
        Write-Host ""
        Write-Host "Run with: Invoke-AdversaryBattery -Target `$target -Contract <name>"
        return
    }

    if ([string]::IsNullOrEmpty($Contract)) {
        throw "Contract is required when -Discover is not specified."
    }

    $validContracts = $script:Contracts.Keys
    if ($Contract -notin $validContracts) {
        throw "Unknown contract '$Contract'. Valid contracts: $($validContracts -join ', ')"
    }

    $validation = Test-Contract -Target $Target -ContractName $Contract
    if (-not $validation.Satisfied) {
        Write-Host "Contract '$Contract' validation failed. Missing methods:" -ForegroundColor Red
        foreach ($m in $validation.Missing) {
            Write-Host "  - $m" -ForegroundColor Red
        }
        throw "Target does not satisfy contract '$Contract'."
    }

    $results = $null
    switch ($Contract) {
        "EncryptDecrypt" { $results = Invoke-EncryptDecryptBattery -Target $Target -Thresholds $thresholds }
        "SignVerify"     { $results = Invoke-SignVerifyBattery -Target $Target -Thresholds $thresholds }
        "DeriveKey"      { $results = Invoke-DeriveKeyBattery -Target $Target -Thresholds $thresholds }
        "ReplayGuard"    { $results = Invoke-ReplayGuardBattery -Target $Target -Thresholds $thresholds }
        "KeyRotation"    { $results = Invoke-KeyRotationBattery -Target $Target -Thresholds $thresholds }
    }

    $evaluation = Compare-Thresholds -Results $results -Thresholds $thresholds
    $evaluation.Contract = $Contract
    $evaluation.TargetType = $Target.GetType().FullName

    Write-Host ""
    Write-Host "=== Adversary Battery: $Contract ===" -ForegroundColor Cyan
    Write-Host "Target: $($Target.GetType().Name)"
    Write-Host "Score: $($evaluation.Score)% ($($evaluation.Passed)/$($evaluation.Passed + $evaluation.Failed + $evaluation.Skipped))" -ForegroundColor $(if ($evaluation.Failed -eq 0) { "Green" } else { "Red" })
    Write-Host "Threshold violations: $($evaluation.ThresholdViolations.Count)" -ForegroundColor $(if ($evaluation.ThresholdViolations.Count -eq 0) { "Green" } else { "Red" })
    Write-Host ""

    if ($OutputPath) {
        Write-Host "Writing report to: $OutputPath"
        Write-AdversaryReport -Evaluation $evaluation -OutputPath $OutputPath -Format $ReportFormat | Out-Null
    }

    $markdown = Write-AdversaryReport -Evaluation $evaluation -Format Markdown
    Write-Host $markdown

    if ($PassThru) {
        return $evaluation
    }

    if ($evaluation.ThresholdViolations.Count -gt 0) {
        exit 1
    }
}
