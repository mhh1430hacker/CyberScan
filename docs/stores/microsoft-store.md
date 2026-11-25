# Microsoft Store and Uptodown: CyberScan for Windows

Installer: `dist\CyberScan-Setup.exe` (Inno Setup, per-user, no admin prompt), version 2.1.0,
88.9 MB, also copied to `web_v\static\downloads\CyberScan-Setup-2.1.0.exe` (SHA-256 in
`web_v\static\downloads\windows.json`). Built by `build_windows.ps1`.

## Microsoft Store (Win32 app, "EXE or MSI" submission)

The Store lists classic installers without repackaging. Requirements and how CyberScan meets them:

| requirement | status |
|---|---|
| Partner Center developer account (individual: free since 2024; company: one-time fee) | **Owner to do** |
| Installer at a stable, versioned HTTPS URL that never changes content | Upload `CyberScan-Setup-2.1.0.exe` to `https://ainex-ai.xyz/downloads/CyberScan-Setup-2.1.0.exe` and never overwrite it; new versions get new names |
| Installer signed with a certificate chaining to a Microsoft-trusted root | **Missing**: needs a code-signing certificate (`docs/SIGNING.md`); the build signs automatically once configured |
| Silent install switch | Inno Setup: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` (enter in "Installer parameters") |
| Installs without user interaction / no bundled offers | Yes |
| Appears in Apps & features with an uninstaller | Yes (Inno Setup uninstaller) |
| 64-bit Windows 10/11 | Yes (x64) |
| Privacy policy URL | `https://ainex-ai.xyz/privacy` |
| Age rating (IARC questionnaire) | Same answers as Google Play (`google-play.md`): no objectionable content, no user interaction, no purchases; expected 3+ |
| Screenshots 1366x768 or larger (1-10) | **Owner to capture** from the desktop app (Win+Shift+S on a 1920x1080 window): home (lens), a scan running, a result, history, settings |
| Store logo | `docs/stores/assets/icon-512.png` / `logo-300.png` |

Restricted capability notes: the app reads files the user picks and, when the user enables it,
watches the Downloads folder; it makes network requests only for the update check
(`https://ainex-ai.xyz/downloads/windows.json`) and the optional online lookups the user turns on.
Declare "Internet access" in the submission notes.

The in-app updater: for the Store build, Store policy prefers Store-managed updates. Either keep
the website build separate or start the Store build with `CYBERSCAN_NO_UPDATE_CHECK=1` set by a
shortcut; simplest is to mention in the certification notes that the app only *offers* a download
from the publisher's site and never installs silently.

### Listing text (English)

**Name:** CyberScan

**Short description:** Check files, links and messages on your PC before you open them. Static analysis only, nothing is run.

**Description:**
```
CyberScan checks files, links and messages before you open them, and explains what it finds in plain words.

• Files: Windows programs, documents, PDFs, Office files with macros, archives and pictures are taken apart without being run. CyberScan reads the program structure, imports, packed or encrypted sections, YARA rules, hidden data after the end of a file, double extensions and disguised names.
• Links and messages: look-alike sites, letters from other alphabets, shortened links, phishing bait and scam wording.
• Downloads watch: optionally, every new file in your Downloads folder is checked as it arrives.
• Repair: for supported files, see what is broken and get a repaired copy, never touching the original.
• Clear results: a 0-100 score, a verdict and the evidence behind it, with a short, detailed and expert view.
• Private: the analysis runs on your PC. Online lookups are off until you turn them on.
• English and Arabic.

CyberScan is a defensive tool that helps you decide; it does not replace antivirus software.
```
**Features (up to 20):** On-device static analysis · Program anatomy (PE) · YARA rules · Archive and document inspection · Link and phishing checks · Downloads monitoring · File repair · Explainable scores · English and Arabic · Automatic update check

### Listing text (Arabic)

**الوصف المختصر:** افحص الملفات والروابط والرسائل على حاسوبك قبل أن تفتحها. تحليل ثابت فقط، لا يُشغَّل أي شيء.

**الوصف:**
```
يفحص CyberScan الملفات والروابط والرسائل قبل أن تفتحها، ويشرح ما يجده بكلمات واضحة.

• الملفات: تُفكَّك برامج ويندوز والمستندات وملفات PDF وملفات Office ذات وحدات الماكرو والأرشيفات والصور دون تشغيلها. يقرأ CyberScan بنية البرنامج ومكتباته والأقسام المضغوطة أو المشفّرة وقواعد YARA والبيانات المخبّأة بعد نهاية الملف والامتدادات المزدوجة والأسماء المموّهة.
• الروابط والرسائل: المواقع المقلّدة، والحروف من أبجديات أخرى، والروابط المختصرة، وطُعم التصيّد، وصياغة الاحتيال.
• مراقبة التنزيلات: عند تفعيلها يُفحص كل ملف جديد في مجلد التنزيلات فور وصوله.
• الإصلاح: للملفات المدعومة، اعرف ما التالف واحصل على نسخة مُصلحة دون المساس بالأصل.
• نتائج واضحة: درجة من 0 إلى 100 وحكم والأدلة التي بُني عليها، بعرض مختصر ومفصّل وللخبراء.
• خصوصية: التحليل يعمل على حاسوبك، والبحث عبر الإنترنت معطّل حتى تفعّله.
• بالعربية والإنجليزية.

CyberScan أداة دفاعية تساعدك على القرار، ولا تغني عن برامج الحماية.
```

## Uptodown

Uptodown lists Windows and Android apps from developers (free developer account at
`https://developers.uptodown.com`).

Checklist:

- [ ] Create the developer account and claim the app name "CyberScan".
- [ ] Windows: upload `CyberScan-Setup-2.1.0.exe` (or give the stable download URL). Uptodown
      scans every file with its antivirus partners: an unsigned installer is accepted but a signed
      one avoids "unknown publisher" questions.
- [ ] Android: upload the signed release APK from `phone\release.ps1` (`CyberScan-1.2.0.apk`).
      It must be signed with the same key as earlier versions so updates install over each other.
- [ ] Category: Security / Antivirus (Windows), Tools (Android).
- [ ] Texts: reuse the descriptions above and in `google-play.md` (EN + AR); Uptodown translates
      to other languages itself, so give them complete English and Arabic texts.
- [ ] Images: `assets/icon-512.png`, the phone screenshots in `google-play/screenshots/`, desktop
      screenshots (1280x720 or larger).
- [ ] License: Free. Requirements: Windows 10/11 64-bit; Android 7.0+.
- [ ] Changelog: "Automatic update check, installer almost half the size (163 MB -> 89 MB)" for
      Windows 2.1.0; the 1.2.0 "What's new" text for Android.
