# CyberScan for Android

The Android application packages the Mobile web app, Pyodide and its on-device
engine with Capacitor. Editable source and the Android project live under
`Mobile/`. `Web/web_v/static/m/` remains the compatibility copy served by the
website.

| Property | Value |
|---|---|
| Application ID | `io.github.mhh1430hacker.cyberscan` |
| Minimum Android | 7.0 (API 24) |
| Target Android | API 36 |

## Features

- Scan files, links and text locally; scan several selected files sequentially.
- Explain findings, inspect file structure and fingerprints, export reports, and
  repair a copy.
- Keep scan history and settings on-device; support English and Arabic.
- Share files, links and text to CyberScan; support Android file-manager
  "Open with", launcher shortcuts, a Quick Settings tile and biometric app lock.
- Optional online lookups are off by default. When enabled with the user's own
  keys, only a file hash or link is sent, never the file or pasted text.

## Source layout

```text
Mobile/
  static/m/                    canonical mobile UI and engine bundle
  static/pyodide/              Pyodide and NumPy assets
  mobile_bridge.py             Python bridge executed in the worker
  build_mobile.py              builds static/m/engine.zip
  build_android_www.py         prepares android/www for Capacitor
  android/
    android/                   Android Studio / Gradle project
    store/                     Play listing assets and text
    make_android_assets.py     launcher, splash and store graphics
    make_android_drawables.py  shortcut, tile and themed icons
```

`Web/web_v/build_mobile.py` and `Web/web_v/build_android_www.py` remain as
compatibility entry points. Use the `Mobile/` scripts for new work.
`--sync-web-compat` refreshes the website's `/m/` asset copy.

## Local debug build

The Web virtual environment supplies Python dependencies used by the engine
builder. From the repository root:

```powershell
Web\.venv\Scripts\python.exe Mobile\build_mobile.py --sync-web-compat
Web\.venv\Scripts\python.exe Mobile\build_android_www.py --sync-web-compat
Push-Location Mobile\android
npx cap sync android
Push-Location android
$env:JAVA_HOME = "$HOME\Android\jdk21"
$env:JAVA_TOOL_OPTIONS = "-Djavax.net.ssl.trustStoreType=Windows-ROOT"
& "$HOME\Android\gradle-8.14.3\bin\gradle.bat" assembleDebug
Pop-Location
Pop-Location
```

The debug APK is written under
`Mobile/android/android/app/build/outputs/apk/debug/`. Do not run a signed
release as part of structural validation.

Expected local tool locations are `%USERPROFILE%\Android\jdk21`,
`%USERPROFILE%\Android\sdk` (platform 36 and build tools), and
`%USERPROFILE%\Android\gradle-8.14.3`. Set `CYBERSCAN_ANDROID_TOOLS` to use a
different tools directory.

## Signed release workflow

`Mobile/android/release.ps1` retains the existing signed-release workflow. It
uses the local upload key and password, signs and verifies APK/AAB outputs, and
copies APK metadata into `Web/web_v/static/downloads/`. The legacy entry point
`Web/web_v/android/release.ps1` forwards to it. This migration does not run
that workflow, create keys, change versions, or publish anything.

The first release creates `Mobile/android/cyberscan-upload.jks` and
`Mobile/android/keystore.properties`. Protect and back up the key and password;
never commit or expose them.

## Hosting and Play Console

The website's `/m/` compatibility assets remain at
`Web/web_v/static/m/`; `Web/web_v/run.py` serves them locally. Static hosts must
serve `.wasm` as `application/wasm` and `.mjs` as `text/javascript`, over HTTPS.
The Play privacy-policy URL can point to `/m/privacy.html`.

The existing Play listing, data-safety answers and store graphics remain under
`Mobile/android/store/`. Follow Google Play's current testing and release
requirements when preparing a release.
