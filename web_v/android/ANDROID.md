# CyberScan for Android (Google Play)

The phone app (`web_v/static/m/`) packaged as a real Android app with [Capacitor](https://capacitorjs.com).
Everything is inside the app: the interface, Pyodide and the CyberScan engine (about 17 MB), so it
works offline and needs no server.

| | |
|---|---|
| Package name | `io.github.mhh1430hacker.cyberscan` (permanent once published) |
| Android | 7.0 and newer (minSdk 24), targets Android 16 (API 36) as Play requires |
| Size | about 15 MB to download |

## What the app does

**Same engine as the desktop and web apps**, running on the phone:
file type vs. name, randomness, warning signs, **YARA rules** (a pure-Python reader,
`web_v/yara_lite.py`, because the YARA library is C), program anatomy (PE), archives, MITRE ATT&CK,
one score with plain-language explanations in English and Arabic, and **repair a copy**.

**Screens**
- *Scan*: file / link / text; pick **several files** to check them one after another; paste the copied link
- *Result*: verdict, findings, **map of the file** (randomness of every part, flagged parts ringed),
  YARA matches, program details (sections, unusual imports), **fingerprints** (SHA-256/SHA-1/MD5, tap
  to copy), checks, engines, MITRE; **export** as HTML page / text / JSON; share; repair a copy
- *History*: overview (donut + 14-day bars), search by name or fingerprint, filters, delete one,
  export all as JSON
- *Settings*: language, vibration, start the engine early, keep history, **online lookups**,
  **app lock**, **hide in recent apps**, privacy policy, erase all data, device and engine details,
  open-source licences

**Android features** (`android/app/src/main/java/.../`)
- *Share → CyberScan* for one file, **several files** (`SEND_MULTIPLE`), a link or text
- *Open with → CyberScan* from file managers (`VIEW` on `content:` files)
- **Launcher shortcuts** (long-press the icon): Check a file · Check copied link · History
- **Quick Settings tile**: "Check copied link"
- **App lock** with fingerprint, face or screen lock (AndroidX Biometric), asked again after 30 s away
- **Hide in recent apps**: `FLAG_SECURE` + no recents screenshot
- **Secrets** (lookup API keys) encrypted with an AES-256-GCM key in the Android Keystore
- Back button/gesture closes sheets, then goes back, then leaves the app
- Edge-to-edge with safe areas, themed (monochrome) icon on Android 13+, per-app language list,
  no cloud backup of history or keys (`data_extraction_rules.xml`)

**Optional online lookups** (off by default, Android app only): with the person's own free
abuse.ch key (MalwareBazaar, URLhaus, ThreatFox) and/or AlienVault OTX key. Only a file's SHA-256 or
the link is sent, never the file or pasted text. Native HTTP (`CapacitorHttp`), because these
services don't accept browser requests.

## Files

```
web_v/static/m/                 the app (shared with the web version at /m/)
  index.html m.css m.js           screens and logic
  viz.js report.js lookup.js      file map & charts · exports · online lookups
  native.js                       Android bridge (window.CSNative), inert in a browser
  privacy.html licenses.html      shown in the app; host privacy.html for Play
web_v/yara_lite.py              YARA reader packed into engine.zip as `yara`
web_v/build_mobile.py           builds m/engine.zip
web_v/build_android_www.py      copies the app into web_v/android/www
web_v/android/
  android/                        the Android Studio / Gradle project
  make_android_assets.py          launcher icons, splash, store icon + feature graphic
  make_android_drawables.py       shortcut and tile icons, themed icon
  store/                          Play listing text (EN/AR), Data safety answers, graphics
```

## Tools (in your user folder, nothing system-wide)

```
%USERPROFILE%\Android\jdk21          Temurin JDK 21 (Gradle needs 17–21; JDK 25 is too new)
%USERPROFILE%\Android\sdk            Android SDK: platform 36, build-tools 36, platform-tools
%USERPROFILE%\Android\gradle-8.14.3  Gradle
```

`release.ps1` looks there (or in `$env:CYBERSCAN_ANDROID_TOOLS`). If an antivirus scans HTTPS
(Avast does), Java must trust the Windows certificate store:
`JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStoreType=Windows-ROOT` (only for the build command).

## Build

```powershell
.venv\Scripts\python.exe web_v\build_mobile.py               # engine.zip (after engine changes)
.venv\Scripts\python.exe web_v\build_android_www.py          # copy the app + engine into www/
cd web_v\android; npx cap sync android; cd android
$env:JAVA_HOME = "$HOME\Android\jdk21"
$env:JAVA_TOOL_OPTIONS = "-Djavax.net.ssl.trustStoreType=Windows-ROOT"
& "$HOME\Android\gradle-8.14.3\bin\gradle.bat" assembleDebug    # test APK
& "$HOME\Android\gradle-8.14.3\bin\gradle.bat" bundleRelease    # signed .aab for Play
```

Outputs:
- `app/build/outputs/apk/debug/app-debug.apk`: install it on a phone to test
- `app/build/outputs/bundle/release/app-release.aab`: upload this to Google Play

Each Play upload needs a higher `versionCode` (and usually a new `versionName`) in
`android/app/build.gradle`.

## Signed release (one command)

```powershell
powershell -ExecutionPolicy Bypass -File web_vndroidelease.ps1                               # first release
powershell -ExecutionPolicy Bypass -File web_vndroidelease.ps1 -VersionCode 2 -VersionName 1.0.1   # updates
```

- **First run:** creates the upload key `android/cyberscan-upload.jks` (RSA 4096, valid ~27 years,
  publisher `CN=CyberScan, O=CyberScan, C=SA`) and `android/keystore.properties`. You type the
  password; it stays in that PowerShell process only and is never written to disk.
- Every run builds the app, signs the **.aab** (for Play) and an **.apk** (APK Signature Scheme v2 + v3),
  verifies both signatures, and copies them to `web_v/android/release/` (git ignores it, the `.jks`
  and `keystore.properties`).
- For CI, set `CYBERSCAN_KEYSTORE_PASSWORD` beforehand and the script won't prompt.

**Back up `cyberscan-upload.jks` and its password** (USB drive, password manager). Every update must
be signed with it. With Play App Signing (the default) Google keeps the final app-signing key; if
the upload key is lost, Play support can reset it, which takes a few days.

**Who users see as the publisher:** Google Play shows your **developer account name** and verified
details, not the certificate. Use the same name ("CyberScan") as the developer name in Play Console;
Google verifies your identity during account setup. Once installed from Play, the app is signed by
Google's app-signing key and Play Protect treats it as a known app.

## Publishing checklist (Play Console)

1. A Google Play developer account (one-time US$25) at play.google.com/console.
2. Create the app → upload `app-release.aab` to *Internal testing* first.
3. Store listing (EN + AR text in `store/LISTING.md`): `store/icon-512.png`,
   `store/feature-graphic-1024x500.png`, and at least 2 phone screenshots.
4. **Privacy policy URL**: host `web_v/static/m/privacy.html` (e.g. on your AWS site as
   `https://<domain>/m/privacy.html`) and paste the URL.
5. Data safety form, content rating and target audience: answers in `store/LISTING.md`.
6. New personal developer accounts must run a closed test with at least 12 testers for 14 days
   before production access.

## Download from the website

`release.ps1` also copies the signed APK to `web_v/static/downloads/CyberScan-<version>.apk` and writes
`downloads/android.json` (version, size, SHA-256 of the file, signing-certificate fingerprint). The
landing page's **Get the app** menu reads that file, so a new release updates the site by itself.
The menu also shows Google Play and App Store badges, greyed out with "Coming soon".

When hosting on AWS (S3/CloudFront), serve `.apk` files with
`Content-Type: application/vnd.android.package-archive` and `Content-Disposition: attachment`
(the local `web_v/run.py` server already does). Browsers then download the file instead of showing it.
