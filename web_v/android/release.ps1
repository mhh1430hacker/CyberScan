param(
    [int]$VersionCode = 0,
    [string]$VersionName = "",
    [string]$Keystore = ""
)

$script = Join-Path $PSScriptRoot "..\..\..\Mobile\android\release.ps1"
if (-not (Test-Path -LiteralPath $script)) {
    throw "Mobile release script not found: $script"
}

$forward = @()
if ($VersionCode -gt 0) { $forward += @("-VersionCode", $VersionCode) }
if ($VersionName) { $forward += @("-VersionName", $VersionName) }
if ($Keystore) { $forward += @("-Keystore", $Keystore) }
& $script @forward
exit $LASTEXITCODE
