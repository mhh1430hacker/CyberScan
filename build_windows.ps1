<#
  Builds the CyberScan Windows app and installer.

      powershell -ExecutionPolicy Bypass -File build_windows.ps1

  1. PyInstaller (build.spec)            -> dist\CyberScan\CyberScan.exe
  2. self-test of the frozen app         -> CyberScan.exe --self-test (every engine loads, two real scans)
  3. code signing of CyberScan.exe       -> only when a certificate is configured (see below)
  4. Inno Setup (installer.iss)          -> dist\CyberScan-Setup.exe
  5. code signing of the installer       -> same condition
  6. copy to web_v\static\downloads\CyberScan-Setup-<version>.exe and write downloads\windows.json
     (size + SHA-256). Nothing is uploaded: publishing stays a separate, deliberate step.

  Code signing (docs/SIGNING.md). Set ONE of these before running; with none, signing is skipped:
    a) a .pfx file:            CYBERSCAN_SIGN_PFX = path to the .pfx, CYBERSCAN_SIGN_PASSWORD = its password
    b) a certificate in the Windows store / on a hardware token:
                               CYBERSCAN_SIGN_THUMBPRINT = SHA-1 thumbprint of the certificate
    c) Azure Trusted Signing:  CYBERSCAN_SIGN_DLIB = path to Azure.CodeSigning.Dlib.dll,
                               CYBERSCAN_SIGN_METADATA = path to metadata.json (endpoint, account, profile)
  Optional: CYBERSCAN_SIGN_TIMESTAMP (default http://timestamp.digicert.com), CYBERSCAN_SIGNTOOL (signtool.exe path).
  Switches: -SkipPyInstaller (reuse dist\CyberScan), -NoPublishCopy (don't touch web_v\static\downloads).
#>
param([switch]$SkipPyInstaller, [switch]$NoPublishCopy)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

$Version = ([regex]::Match((Get-Content installer.iss -Raw), '#define AppVersion "([\d.]+)"')).Groups[1].Value
$AppVer  = ([regex]::Match((Get-Content ui\updater.py -Raw), 'APP_VERSION = "([\d.]+)"')).Groups[1].Value
if ($Version -ne $AppVer) { throw "installer.iss AppVersion ($Version) and ui/updater.py APP_VERSION ($AppVer) differ." }
Write-Host "CyberScan $Version" -ForegroundColor Cyan

function Find-SignTool {
    if ($env:CYBERSCAN_SIGNTOOL -and (Test-Path $env:CYBERSCAN_SIGNTOOL)) { return $env:CYBERSCAN_SIGNTOOL }
    $c = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if ($c) { return $c.FullName }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-Sign([string]$File) {
    $ts = if ($env:CYBERSCAN_SIGN_TIMESTAMP) { $env:CYBERSCAN_SIGN_TIMESTAMP } else { "http://timestamp.digicert.com" }
    $common = @("sign", "/fd", "SHA256", "/tr", $ts, "/td", "SHA256", "/d", "CyberScan", "/du", "https://ainex-ai.xyz/")
    if ($env:CYBERSCAN_SIGN_DLIB -and $env:CYBERSCAN_SIGN_METADATA) {
        $signArgs = @("sign", "/v", "/fd", "SHA256", "/tr", "http://timestamp.acs.microsoft.com", "/td", "SHA256",
                      "/dlib", $env:CYBERSCAN_SIGN_DLIB, "/dmdf", $env:CYBERSCAN_SIGN_METADATA)
    } elseif ($env:CYBERSCAN_SIGN_PFX) {
        if (-not (Test-Path $env:CYBERSCAN_SIGN_PFX)) { throw "CYBERSCAN_SIGN_PFX does not exist: $env:CYBERSCAN_SIGN_PFX" }
        $signArgs = $common + @("/f", $env:CYBERSCAN_SIGN_PFX)
        if ($env:CYBERSCAN_SIGN_PASSWORD) { $signArgs += @("/p", $env:CYBERSCAN_SIGN_PASSWORD) }
    } elseif ($env:CYBERSCAN_SIGN_THUMBPRINT) {
        $signArgs = $common + @("/sha1", $env:CYBERSCAN_SIGN_THUMBPRINT)
    } else {
        Write-Host "  signing skipped (no certificate configured): $([IO.Path]::GetFileName($File))" -ForegroundColor Yellow
        return
    }
    $tool = Find-SignTool
    if (-not $tool) { throw "A certificate is configured but signtool.exe was not found (install the Windows SDK or set CYBERSCAN_SIGNTOOL)." }
    & $tool @signArgs $File
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $File" }
    & $tool verify /pa $File
    if ($LASTEXITCODE -ne 0) { throw "The signature on $File did not verify." }
    Write-Host "  signed: $([IO.Path]::GetFileName($File))" -ForegroundColor Green
}

# ---------------------------------------------------------------- 1. PyInstaller
if (-not $SkipPyInstaller) {
    $py = Join-Path $Root ".venv\Scripts\pyinstaller.exe"
    if (-not (Test-Path $py)) { $py = "pyinstaller" }
    & $py build.spec --noconfirm
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
}
$exe = Join-Path $Root "dist\CyberScan\CyberScan.exe"

# ---------------------------------------------------------------- 2. self-test
$report = Join-Path $env:TEMP "cyberscan-selftest.json"
Remove-Item $report -ErrorAction SilentlyContinue
$p = Start-Process $exe -ArgumentList "--self-test", "`"$report`"" -Wait -PassThru
if ($p.ExitCode -ne 0 -or -not (Test-Path $report)) {
    if (Test-Path $report) { Get-Content $report }
    throw "The frozen app's self-test failed (exit $($p.ExitCode))."
}
Write-Host "  self-test passed" -ForegroundColor Green

# ---------------------------------------------------------------- 3-5. sign, installer, sign
Invoke-Sign $exe
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 (ISCC.exe) was not found." }
& $iscc installer.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed." }
$setup = Join-Path $Root "dist\CyberScan-Setup.exe"
Invoke-Sign $setup
$mb = [math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host "Installer: $setup ($mb MB)" -ForegroundColor Cyan

# ---------------------------------------------------------------- 6. website copy (not uploaded)
if (-not $NoPublishCopy) {
    $site = Join-Path $Root "web_v\static\downloads"
    $file = "CyberScan-Setup-$Version.exe"
    Copy-Item $setup (Join-Path $site $file) -Force
    $info = [ordered]@{
        file = $file; version = $Version; size = (Get-Item $setup).Length
        sha256 = (Get-FileHash -Algorithm SHA256 $setup).Hash.ToLower(); os = "Windows 10/11 (64-bit)"
    }
    [IO.File]::WriteAllText((Join-Path $site "windows.json"), ($info | ConvertTo-Json))
    Write-Host "Copied to web_v\static\downloads\$file and updated windows.json (not uploaded)." -ForegroundColor Cyan
}
