# Run Phase 1 until it finishes, restarting it whenever it stops early.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File repair_engine\data\resume.ps1 [step ...]
#
# Every step skips finished work and resumes .part files, so restarting is safe.
# Each run's output goes to C:\CyberScanData\logs\resume_<date>.txt. Started on
# its own (Start-Process), it does not depend on any editor or chat session.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Steps)
if (-not $Steps) { $Steps = @('sorel', 'tools', 'benign', 'ember_big') }

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python = Join-Path $repo '.venv\Scripts\python.exe'
Set-Location $repo

for ($attempt = 1; $attempt -le 200; $attempt++) {
    $log = "C:\CyberScanData\logs\resume_$(Get-Date -Format yyyy-MM-dd).txt"
    Add-Content -Encoding utf8 $log "[resume] $(Get-Date -Format s) attempt ${attempt}: $($Steps -join ' ')"
    cmd /c "`"$python`" -u -m repair_engine.data.phase1 $($Steps -join ' ') >> `"$log`" 2>&1"
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Add-Content -Encoding utf8 $log "[resume] $(Get-Date -Format s) finished"
        break
    }
    Add-Content -Encoding utf8 $log "[resume] $(Get-Date -Format s) stopped with exit code $code; restarting in 60 s"
    Start-Sleep -Seconds 60
}
