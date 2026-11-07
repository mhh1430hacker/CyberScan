<#
  CyberScan for Android: signed release build (Google Play .aab + installable .apk)

  Run from the project root in PowerShell:
      powershell -ExecutionPolicy Bypass -File web_v\android\release.ps1
      powershell -ExecutionPolicy Bypass -File web_v\android\release.ps1 -VersionCode 2 -VersionName 1.0.1

  The first run creates the upload key (cyberscan-upload.jks, publisher "CyberScan", SA).
  The password is typed here, kept only in this process's memory, and never written to disk.
  Back up cyberscan-upload.jks and its password: every future update must be signed with it.
#>
param(
    [int]$VersionCode = 0,
    [string]$VersionName = "",
    [string]$Keystore = ""   # another key file (for tests); default: android\cyberscan-upload.jks
)
# native tools print notes on stderr; failures are caught through $LASTEXITCODE instead
$ErrorActionPreference = "Continue"

$Root    = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Project = Join-Path $PSScriptRoot "android"
$Tools   = "C:\Users\mahdi\Android"
$Jks     = if ($Keystore) { $Keystore } else { Join-Path $Project "cyberscan-upload.jks" }
$Props   = Join-Path $Project "keystore.properties"
$Out     = Join-Path $PSScriptRoot "release"
$Alias   = "cyberscan"
$DName   = "CN=CyberScan, OU=CyberScan, O=CyberScan, C=SA"

$env:JAVA_HOME = Join-Path $Tools "jdk21"
$env:ANDROID_HOME = Join-Path $Tools "sdk"
$Keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"
$Gradle  = Join-Path $Tools "gradle-8.14.3\bin\gradle.bat"
$BuildTools = Get-ChildItem (Join-Path $env:ANDROID_HOME "build-tools") | Sort-Object Name | Select-Object -Last 1
$Apksigner = Join-Path $BuildTools.FullName "apksigner.bat"
$Jarsigner = Join-Path $env:JAVA_HOME "bin\jarsigner.exe"

function Read-Secret([string]$Prompt) {
    $secure = Read-Host -AsSecureString $Prompt
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

try {
    # ---------------------------------------------------------------- the upload key
    if (-not (Test-Path $Jks)) {
        Write-Host "`nNo upload key yet: creating one for publisher 'CyberScan' (SA)." -ForegroundColor Cyan
        Write-Host "Choose a strong password (at least 8 characters). You will need it for every update.`n"
        # a password already in the environment (CI) is used as is
        $p1 = if ($env:CYBERSCAN_KEYSTORE_PASSWORD) { $env:CYBERSCAN_KEYSTORE_PASSWORD } else { Read-Secret "New keystore password" }
        $p2 = if ($env:CYBERSCAN_KEYSTORE_PASSWORD) { $p1 } else { Read-Secret "Type it again" }
        if ($p1 -ne $p2) { throw "The passwords don't match." }
        if ($p1.Length -lt 8) { throw "The password must be at least 8 characters." }
        $env:CYBERSCAN_KEYSTORE_PASSWORD = $p1
        & $Keytool -genkeypair -v -keystore $Jks -storetype PKCS12 -alias $Alias `
            -keyalg RSA -keysize 4096 -validity 10000 -dname $DName `
            -storepass:env CYBERSCAN_KEYSTORE_PASSWORD -keypass:env CYBERSCAN_KEYSTORE_PASSWORD
        if ($LASTEXITCODE -ne 0) { throw "keytool failed." }
        Write-Host "`nCreated $Jks" -ForegroundColor Green
        Write-Host "BACK IT UP NOW (USB drive / password manager), together with the password." -ForegroundColor Yellow
    } elseif (-not $env:CYBERSCAN_KEYSTORE_PASSWORD) {
        $env:CYBERSCAN_KEYSTORE_PASSWORD = Read-Secret "Keystore password"
    }
    if (-not (Test-Path $Props)) {
        $store = if ($Keystore) { $Jks -replace "\\", "/" } else { "cyberscan-upload.jks" }
        "storeFile=$store`nkeyAlias=$Alias`n" | Set-Content -Encoding ascii $Props
    }

    # check the password before a long build
    & $Keytool -list -keystore $Jks -alias $Alias -storepass:env CYBERSCAN_KEYSTORE_PASSWORD *> $null
    if ($LASTEXITCODE -ne 0) { throw "Wrong keystore password." }

    # ---------------------------------------------------------------- version
    $gradleFile = Join-Path $Project "app\build.gradle"
    $g = Get-Content $gradleFile -Raw
    if ($VersionCode -gt 0) { $g = $g -replace 'versionCode \d+', "versionCode $VersionCode" }
    if ($VersionName) { $g = $g -replace 'versionName "[^"]*"', "versionName `"$VersionName`"" }
    if ($VersionCode -gt 0 -or $VersionName) { Set-Content -Encoding utf8 -NoNewline $gradleFile $g }
    $code = [regex]::Match($g, 'versionCode (\d+)').Groups[1].Value
    $name = [regex]::Match($g, 'versionName "([^"]*)"').Groups[1].Value
    Write-Host "`nBuilding CyberScan $name (versionCode $code)..." -ForegroundColor Cyan

    # ---------------------------------------------------------------- build
    Push-Location $Root
    & .\.venv\Scripts\python.exe web_v\build_android_www.py
    if ($LASTEXITCODE -ne 0) { throw "build_android_www.py failed." }
    Pop-Location
    Push-Location $PSScriptRoot
    & npx cap sync android
    if ($LASTEXITCODE -ne 0) { throw "cap sync failed." }
    Pop-Location
    Push-Location $Project
    $env:JAVA_TOOL_OPTIONS = "-Djavax.net.ssl.trustStoreType=Windows-ROOT"   # Avast scans HTTPS on this PC
    & $Gradle bundleRelease assembleRelease --no-daemon -q "-Pkotlin.compiler.execution.strategy=in-process"
    $ok = $LASTEXITCODE
    Remove-Item Env:JAVA_TOOL_OPTIONS -ErrorAction SilentlyContinue
    Pop-Location
    if ($ok -ne 0) { throw "Gradle build failed." }

    $aab = Join-Path $Project "app\build\outputs\bundle\release\app-release.aab"
    $apk = Join-Path $Project "app\build\outputs\apk\release\app-release.apk"

    # ---------------------------------------------------------------- verify the signatures
    Write-Host "`nVerifying signatures..." -ForegroundColor Cyan
    & $Apksigner verify --verbose --print-certs $apk | Select-String "Verified using|Signer #1 certificate (DN|SHA-256)"
    if ($LASTEXITCODE -ne 0) { throw "The APK signature did not verify." }
    & $Jarsigner -verify $aab | Select-String "jar verified"
    if ($LASTEXITCODE -ne 0) { throw "The AAB signature did not verify." }

    # ---------------------------------------------------------------- copy out
    New-Item -ItemType Directory -Force $Out | Out-Null
    $aabOut = Join-Path $Out "CyberScan-$name-$code.aab"
    $apkOut = Join-Path $Out "CyberScan-$name-$code.apk"
    Copy-Item $aab $aabOut -Force
    Copy-Item $apk $apkOut -Force
    $fp = (& $Keytool -list -v -keystore $Jks -alias $Alias -storepass:env CYBERSCAN_KEYSTORE_PASSWORD | Select-String "SHA256:").ToString().Trim()

    # ---------------------------------------------------------------- publish on the website
    # the "Get the app" menu reads downloads/android.json (skipped for test keys)
    if (-not $Keystore) {
        $site = Join-Path $Root "web_v\static\downloads"
        New-Item -ItemType Directory -Force $site | Out-Null
        Get-ChildItem $site -Filter "CyberScan-*.apk" | Remove-Item -Force
        $siteApk = Join-Path $site "CyberScan-$name.apk"
        Copy-Item $apk $siteApk -Force
        $info = [ordered]@{
            file = "CyberScan-$name.apk"; version = $name; versionCode = [int]$code; size = (Get-Item $siteApk).Length
            sha256 = (Get-FileHash -Algorithm SHA256 $siteApk).Hash.ToLower()
            cert_sha256 = ($fp -replace "^SHA256:\s*", ""); publisher = $DName; min_android = "7.0"
        }
        $info | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $site "android.json")
    }

    Write-Host "`nDone." -ForegroundColor Green
    Write-Host "  Google Play upload : $aabOut"
    Write-Host "  Signed APK (phones): $apkOut"
    if (-not $Keystore) { Write-Host "  On the website     : web_v\static\downloads\CyberScan-$name.apk" }
    Write-Host "  Upload-key $fp"
    Write-Host "`nKeep cyberscan-upload.jks and its password safe; every update must use them." -ForegroundColor Yellow
}
finally {
    Remove-Item Env:CYBERSCAN_KEYSTORE_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:JAVA_TOOL_OPTIONS -ErrorAction SilentlyContinue
}
