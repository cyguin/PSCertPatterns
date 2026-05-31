$sourceFiles = @(
    "$PSScriptRoot/src/01_AesGcm.ps1"
    "$PSScriptRoot/src/02_KeyDerivation.ps1"
    "$PSScriptRoot/src/03_NonceManagement.ps1"
)
foreach ($f in $sourceFiles) {
    . $f
}
