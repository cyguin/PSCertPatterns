$script:Contracts = @{
    EncryptDecrypt = @(
        @{ Name = 'Encrypt'; ParamTypes = @([byte[]]) }
        @{ Name = 'Decrypt'; ParamTypes = @([byte[]]) }
    )
    SignVerify = @(
        @{ Name = 'Sign';   ParamTypes = @([byte[]]) }
        @{ Name = 'Verify'; ParamTypes = @([byte[]], [byte[]]) }
    )
    DeriveKey = @(
        @{ Name = 'DeriveKey'; ParamTypes = @([string], [byte[]], [int]) }
    )
    ReplayGuard = @(
        @{ Name = 'CheckAndRecord'; ParamTypes = @([byte[]]) }
        @{ Name = 'HasSeen';        ParamTypes = @([byte[]]) }
    )
    KeyRotation = @(
        @{ Name = 'Encrypt';      ParamTypes = @([byte[]]) }
        @{ Name = 'Decrypt';      ParamTypes = @([string], [byte[]]) }
        @{ Name = 'Rotate';       ParamTypes = @() }
        @{ Name = 'CurrentKeyId'; ParamTypes = @() }
    )
}

function Test-Contract {
    param([object]$Target, [string]$ContractName)

    $missing = [System.Collections.Generic.List[string]]::new()
    $requirements = $script:Contracts[$ContractName]
    if ($null -eq $requirements) {
        return @{ Satisfied = $false; Missing = @("Unknown contract: $ContractName") }
    }

    $targetMethods = $Target | Get-Member -MemberType Method | ForEach-Object { $_.Name }
    foreach ($req in $requirements) {
        if ($targetMethods -notcontains $req.Name) {
            $paramDesc = ($req.ParamTypes | ForEach-Object { $_.Name }) -join ', '
            $missing.Add("$($req.Name)($paramDesc)")
        }
    }

    return @{
        Satisfied = ($missing.Count -eq 0)
        Missing = [string[]]$missing
    }
}

function Get-SuggestedContracts {
    param([object]$Target)

    $suggested = [System.Collections.Generic.List[string]]::new()
    foreach ($contractName in $script:Contracts.Keys) {
        $result = Test-Contract -Target $Target -ContractName $contractName
        if ($result.Satisfied) {
            $suggested.Add($contractName)
        }
    }
    return [string[]]$suggested
}
