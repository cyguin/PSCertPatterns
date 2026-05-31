$sourceFiles = @(
    "$PSScriptRoot/src/01_AesGcm.ps1"
)
foreach ($f in $sourceFiles) {
    . $f
}
