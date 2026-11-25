# Publishing CyberScan: step by step for the owner

Everything below is ready in the repository except what needs your accounts, keys and money.
Nothing has been uploaded or published.

## 0. Before anything

- [ ] Commit the work (phone 1.2.0, desktop 2.1.0, extension 1.0.0, docs).
- [ ] Make sure the privacy page (`https://ainex-ai.xyz/privacy`) mentions the phone app (on-device,
      no network in release), the desktop update check (it reads `downloads/windows.json`) and the
      extension (local checks; the full check opens the scan page). Stores link to it.

## 1. Android phone app (1.2.0, versionCode 3)

1. Build and sign: `powershell -ExecutionPolicy Bypass -File phone\release.ps1` (asks for the
   publisher key password). Note: that script also uploads to S3 and deploys the site. To only
   build, run `flutter build apk --release` / `flutter build appbundle --release` in `phone\` with
   `CYBERSCAN_KEYSTORE_PASSWORD` set.
2. Google Play needs an **App Bundle**: `flutter build appbundle --release` ->
   `phone\build\app\outputs\bundle\release\app-release.aab`.
3. Play Console (`https://play.google.com/console`, one-time USD 25, identity verification):
   1. Create app > name "CyberScan", default language English (add Arabic), App, Free.
   2. **Play App Signing:** choose "Use my own key" / upload the existing upload key so the Play
      build and the website APK share a signature (`web_v\android\android\cyberscan-upload.jks`).
      Otherwise Play re-signs and users can't update between the website APK and Play.
   3. Fill **Store listing** from `docs/stores/google-play.md` (EN and AR), upload
      `assets/icon-512.png`, `assets/feature-graphic-1024x500.png`, and the screenshots in
      `google-play/screenshots/` (en_* for English, ar_* for Arabic).
   4. **App content:** privacy policy URL, Ads = No, App access = no login, Content rating
      questionnaire, Target audience 13+, Data safety (answers in `google-play.md`).
   5. New personal developer accounts must run a **closed test with at least 12 testers for 14
      days** before production. Create a closed testing track, upload the .aab, invite testers.
   6. Then Production > Create release > upload the .aab > release notes > roll out.
4. Website APK: `phone\release.ps1` writes `CyberScan-1.2.0.apk` + `android.json`.

Test on a real phone before release (things that could not be tested here, without a device):
- Share a PDF from Files, a link from Chrome, text from WhatsApp, and several photos at once.
- Add the widget (long-press home screen > Widgets > CyberScan), run a check, see it update; tap
  Quick scan.
- Settings > New files > Choose a folder (pick e.g. Download/WhatsApp or a browser folder; Android
  11+ does not allow picking the top Download folder), add a file, reopen the app.
- QR scanning still works with the release build (it has no internet permission now).

## 2. Windows desktop app (2.1.0)

1. (Optional, recommended) Get a code-signing certificate: `docs/SIGNING.md`.
2. Build: `powershell -ExecutionPolicy Bypass -File build_windows.ps1` (PyInstaller, self-test,
   signing if configured, Inno Setup, copy to `web_v\static\downloads\` + `windows.json`).
   Already built once, unsigned: `web_v\static\downloads\CyberScan-Setup-2.1.0.exe` (88.9 MB).
3. Upload the installer to S3 `assets/downloads/CyberScan-Setup-2.1.0.exe` (like `release.ps1`
   does for the APK) and deploy `web_v/static/downloads/windows.json`. **Upload the exe before the
   json**: installed 2.0.0 apps don't check, but 2.1.0+ apps read the json and download the file
   it names; its SHA-256 must match or the update is refused.
4. `web_v/static/index.html` still links `downloads/CyberScan-Setup-2.0.0.exe` directly in the
   "win-card" (the menu reads windows.json); update that link when publishing.
5. Microsoft Store and Uptodown: `docs/stores/microsoft-store.md`.

## 3. Browser extension (1.0.0)

1. The scan page must support the prefill (`#/scan?url=...`, added to `web_v/static/app.js`):
   deploy the site first, then publish the extension.
2. Chrome Web Store and Edge Add-ons: `extension/README.md` and `docs/stores/extension-listing.md`;
   upload `dist\CyberScan-extension-1.0.0.zip`.

## 4. iOS (not built)

Share-extension code and steps: `phone/ios/ShareExtension/README.md` (needs a Mac with Xcode and
an Apple Developer account, USD 99/year). App Store listing texts can reuse `google-play.md`.
