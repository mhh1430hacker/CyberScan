param(
    [string]$ManifestPath = "data\datasets\manifest.csv",
    [string]$ModelPath
)

$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$resolvedManifest = $ManifestPath
if (-not [System.IO.Path]::IsPathRooted($resolvedManifest)) {
    $resolvedManifest = Join-Path $projectRoot $resolvedManifest
}

if (-not (Test-Path -LiteralPath $resolvedManifest -PathType Leaf)) {
    Write-Host "Training manifest not found: $resolvedManifest. Create a reviewed CSV with path,label,source columns, clean/suspicious/malware labels, and an optional family column for group-disjoint validation, then run this command again." -ForegroundColor Red
    exit 2
}

$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) {
        Write-Host "Python was not found. Install Python or create the project .venv first." -ForegroundColor Red
        exit 2
    }
    $pythonPath = $pythonCommand.Source
}

$arguments = @(
    "-m",
    "ml.training.train",
    "--manifest",
    (Resolve-Path -LiteralPath $resolvedManifest).Path
)
if ($ModelPath) {
    $arguments += @("--model", $ModelPath)
}

Push-Location $projectRoot
try {
    & $pythonPath @arguments
    $trainingExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

exit $trainingExitCode
