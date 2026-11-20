<#
  Builds the CyberScan phone app (Flutter) for release and puts it on the website.

      powershell -ExecutionPolicy Bypass -File phone\release.ps1

  1. asks for the publisher key's password (the key in web_v\android\android\cyberscan-upload.jks,
     the same key as the APK the website offered before, so the new app installs as an update);
  2. builds one APK for every phone (flutter build apk --release) and checks its signature;
  3. copies it to web_v\static\downloads\, writes downloads\android.json (version, size, SHA-256,
     certificate) and uploads the APK to S3 (assets/downloads/, where the site sends downloads);
  4. runs tools\deploy\deploy_aws.py so the website shows the new version.
  The version comes from phone\pubspec.yaml ("version: 1.1.0+2" = name 1.1.0, versionCode 2);
  raise it before every release.
#>
$ErrorActionPreference = "Stop"
$Root    = Split-Path $PSScriptRoot -Parent
$Phone   = $PSScriptRoot
$Jks     = Join-Path $Root "web_v\android\android\cyberscan-upload.jks"
$Alias   = "cyberscan"
$DName   = "CN=CyberScan, OU=CyberScan, O=CyberScan, C=SA"
$Tools   = if ($env:CYBERSCAN_ANDROID_TOOLS) { $env:CYBERSCAN_ANDROID_TOOLS } else { Join-Path $env:USERPROFILE "Android" }
$Keytool = Join-Path $Tools "jdk21\bin\keytool.exe"
if (-not (Test-Path $Keytool)) { $Keytool = "keytool" }
$Sdk     = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { Join-Path $Tools "sdk" }
# flutter and gradle find the Android SDK and Java 21 through these (the old app's tools in %USERPROFILE%\Android)
$env:ANDROID_HOME = $Sdk; $env:ANDROID_SDK_ROOT = $Sdk
if (Test-Path (Join-Path $Tools "jdk21")) { $env:JAVA_HOME = Join-Path $Tools "jdk21"; $env:Path = "$(Join-Path $env:JAVA_HOME 'bin');$env:Path" }
$BuildTools = Get-ChildItem (Join-Path $Sdk "build-tools") -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
$Apksigner  = if ($BuildTools) { Join-Path $BuildTools.FullName "apksigner.bat" } else { $null }

if (-not (Test-Path $Jks)) { throw "The publisher key is missing: $Jks" }

try {
    # ------------------------------------------------------------ the key
    if (-not $env:CYBERSCAN_KEYSTORE_PASSWORD) {
        $secure = Read-Host -AsSecureString "Publisher key password"
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $env:CYBERSCAN_KEYSTORE_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    }
    & $Keytool -list -keystore $Jks -alias $Alias -storepass:env CYBERSCAN_KEYSTORE_PASSWORD *> $null
    if ($LASTEXITCODE -ne 0) { throw "Wrong password for the publisher key." }
    # android\key.properties (git-ignored): where the key is; the password stays in the environment
    $props = Join-Path $Phone "android\key.properties"
    "storeFile=$($Jks -replace '\\', '/')`nkeyAlias=$Alias`n" | Set-Content -Encoding ascii $props

    # ------------------------------------------------------------ version
    $m = [regex]::Match((Get-Content (Join-Path $Phone "pubspec.yaml") -Raw), '(?m)^version:\s*([\d.]+)\+(\d+)')
    $name = $m.Groups[1].Value; $code = [int]$m.Groups[2].Value
    Write-Host "Building CyberScan $name (versionCode $code)..." -ForegroundColor Cyan

    # ------------------------------------------------------------ build + verify
    Push-Location $Phone
    try { & flutter build apk --release; if ($LASTEXITCODE -ne 0) { throw "flutter build failed." } }
    finally { Pop-Location }
    $apk = Join-Path $Phone "build\app\outputs\flutter-apk\app-release.apk"
    if ($Apksigner -and (Test-Path $Apksigner)) {
        $certs = & $Apksigner verify --print-certs $apk
        if ($LASTEXITCODE -ne 0) { throw "The APK signature did not verify." }
        if (-not ($certs -match "CN=CyberScan")) { throw "The APK is not signed with the CyberScan key (debug key?)." }
    }
    $fp = (& $Keytool -list -v -keystore $Jks -alias $Alias -storepass:env CYBERSCAN_KEYSTORE_PASSWORD | Select-String "SHA256:").ToString().Trim()

    # ------------------------------------------------------------ the website
    $site = Join-Path $Root "web_v\static\downloads"
    New-Item -ItemType Directory -Force $site | Out-Null
    Get-ChildItem $site -Filter "CyberScan-*.apk" | Remove-Item -Force
    $file = "CyberScan-$name.apk"
    $siteApk = Join-Path $site $file
    Copy-Item $apk $siteApk -Force
    $info = [ordered]@{
        file = $file; version = $name; versionCode = $code; size = (Get-Item $siteApk).Length
        sha256 = (Get-FileHash -Algorithm SHA256 $siteApk).Hash.ToLower()
        cert_sha256 = ($fp -replace "^SHA256:\s*", ""); publisher = $DName; min_android = "7.0"
    }
    [IO.File]::WriteAllText((Join-Path $site "android.json"), ($info | ConvertTo-Json))
    Write-Host "Uploading $file to S3..." -ForegroundColor Cyan
    # a Python that has boto3 (the project's .venv may not): the active one, else the system one
    $Py = $null
    & python -c "import boto3" 2>$null; if ($LASTEXITCODE -eq 0) { $Py = "python" }
    if (-not $Py) {
        $venv = $env:VIRTUAL_ENV; $env:VIRTUAL_ENV = $null
        foreach ($c in (Get-Command python.exe -All -ErrorAction SilentlyContinue).Source + (Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\*\python.exe", "C:\Python3*\python.exe" -ErrorAction SilentlyContinue).FullName) {
            if ($c -and $c -notlike "*\.venv\*") { & $c -c "import boto3" 2>$null; if ($LASTEXITCODE -eq 0) { $Py = $c; break } }
        }
        $env:VIRTUAL_ENV = $venv
    }
    if (-not $Py) { throw "No Python with boto3 found: run  pip install boto3  and try again." }
    & $Py -c "import boto3,sys; boto3.client('s3',region_name='eu-north-1').upload_file(sys.argv[1],'cyberscan-assets','assets/downloads/'+sys.argv[2],ExtraArgs={'ContentType':'application/vnd.android.package-archive','ContentDisposition':'attachment; filename='+sys.argv[2]})" $siteApk $file
    if ($LASTEXITCODE -ne 0) { throw "Upload to S3 failed." }
    & $Py (Join-Path $Root "tools\deploy\deploy_aws.py")
    if ($LASTEXITCODE -ne 0) { throw "Website deploy failed." }
    Write-Host "`nDone: $file is live." -ForegroundColor Green
}
finally {
    Remove-Item Env:\CYBERSCAN_KEYSTORE_PASSWORD -ErrorAction SilentlyContinue
}
