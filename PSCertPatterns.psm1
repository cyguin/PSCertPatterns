$sourceFiles = @(
    "$PSScriptRoot/src/01_AesGcm.ps1"
    "$PSScriptRoot/src/02_KeyDerivation.ps1"
    "$PSScriptRoot/src/03_NonceManagement.ps1"
    "$PSScriptRoot/src/04_HmacCbc.ps1"
    "$PSScriptRoot/src/05_Rsa.ps1"
    "$PSScriptRoot/src/06_Ecdsa.ps1"
)
foreach ($f in $sourceFiles) {
    . $f
}
