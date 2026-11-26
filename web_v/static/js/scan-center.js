/* The scan experience: workspace, live analysis, and the security results center.
 *
 * Builds on app.js without replacing its engine plumbing: it listens to the events app.js emits
 * ("cs:scan-start", "cs:upload", "cs:stages", "cs:result", "cs:scan-error") and presents them.
 * Everything shown is what the backend actually produced:
 *   - classifications are the engine's own labels (NO_INDICATORS_OBSERVED, REVIEW, SUSPICIOUS,
 *     UNKNOWN); no MALWARE label is invented (only an approved ML model could produce one);
 *   - progress is the server's real stages and the real elapsed time; no percentage is made up
 *     (the only measured progress is the upload's bytes);
 *   - the score is labelled for what it is (an explainable indicator, not a probability), and model
 *     confidence is shown only when an approved model produced it, marked as uncalibrated.
 * Existing actions (export, quarantine, AI, repair) are app.js's own buttons, moved into place. */
(function () {
  "use strict";
  const CS = window.CS;
  if (!CS || !document.getElementById("form")) return;
  const { $, el, t } = CS;
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");

  /* ================================================================ text */
  const STR = {
    en: {
      hDate: "Date", hAll: "Any time", hDay: "Last 24 hours", hWeek: "Last 7 days", hMonth: "Last 30 days", hSort: "Sort", hNew: "Newest first", hOld: "Oldest first", hRisk: "Highest score first", reportMissing: "Report missing",
      fmtTitle: "What CyberScan reads", fmtBody: "Any file can be checked. Dedicated analyzers: PDF, Word/Excel/PowerPoint (new and old formats), Outlook messages, RTF, ZIP, Android APK, browser extensions, Windows programs (PE), Linux programs (ELF), images, emails and text.",
      dropEg: "For example: an email attachment, an invoice, a download you didn't expect, or an app (APK, EXE). Up to {n} MB.",
      fmtLimit: "Largest file here: {n} MB", fmtNever: "Files are read as data and never opened or run.",
      fiName: "Name", fiExt: "Extension", fiSize: "Size", fiType: "Detected type", fiHash: "SHA-256", fiCheck: "Validation", fiHashing: "computing…", fiNoExt: "none",
      fiOk: "Ready to scan", fiTooBig: "Larger than the {n} MB limit", fiEmpty: "The file is empty", fiMismatch: "Extension says {a}, content looks like {b}: worth checking",
      fiRemove: "Remove", fiReplace: "Replace", fiUnknownType: "not recognised from its first bytes",
      optTitle: "Scan options", optHint: "These are the settings this scan will use. Change them in Settings.", optPublic: "On the website these are fixed.", optOpen: "Open Settings",
      oEntropy: "Entropy and structure", oRules: "Heuristic rules", oModel: "Machine-learning model", oOsint: "Online threat lookups", oTimeout: "Time limit", on: "On", off: "Off", sec: "{n} s",
      oModelNote: "runs only if an approved model is installed",
      whatHappens: "Starting a scan reads the file once, measures its structure, compares it with rules and known patterns, and explains what it finds. Nothing is executed.",
      tlTitle: "Analysis", tlElapsed: "Elapsed", tlUpload: "Uploading", tlUploadDone: "Uploaded", tlContent: "Content inspection (format analyzers, privacy, secrets)",
      tlContentDone: "Content inspected", tlReport: "Building the report", tlReportDone: "Report ready", tlWaiting: "waiting", tlFailed: "Stopped: {m}",
      tlPublic: "The online version runs the whole analysis in one request and reports its stages when it finishes.", tlObserved: "observed",
      stage: ["Reading the target and collecting static evidence", "Measuring entropy and structure", "Building the structural representation", "Optional online lookups"],
      cls: { NO_INDICATORS_OBSERVED: ["No warning signs observed", "None of CyberScan's checks found an indicator in this file. That is not a guarantee of safety."],
        REVIEW: ["Needs review", "Something in this file is worth a closer look. Read the findings below before you trust it."],
        KNOWN_MALWARE: ["Known malware", "This exact file is listed as malware by a threat-intelligence source. Delete it; do not open or run it."],
        SUSPICIOUS: ["Suspicious", "CyberScan found strong warning signs. Don't open or run this unless you are sure where it came from."],
        UNKNOWN: ["Inconclusive", "The analysis could not complete, so CyberScan can't give a verdict. Treat the file with care."],
        EMPTY: ["Empty file", "This file has no content, so there is nothing to check. If you expected content, the copy may be incomplete."] },
      sumTitle: "Security summary", score: "Score", scoreNote: "Weighted evidence from all of CyberScan's checks, from 0 to 100: each finding adds its weight, and the strongest piece of evidence sets the minimum. It is not a probability of malware.",
      bands: ["0: no indicators", "1–49: review", "50+: suspicious"],
      conf: "Model confidence", confNone: "Not available for this result: the result rests on static evidence.", confMl: "Resembles malware (EMBER2024)", confMlNote: "A model trained on millions of Windows programs and PDFs. It is one piece of evidence among many, not a probability, and never decides a verdict alone.", confMlNa: "The machine-learning model (EMBER2024) reads complete Windows programs and PDF files only; this file isn't one it can read, so it was not used.",
      confNote: "Model scores are uncalibrated: they rank classes, they are not probabilities.", confAbst: "The model abstained (more than one class fits).",
      ident: "File identity", target: "Target", type: "Type", size: "Size", sha: "SHA-256", when: "Scanned", status: "Status", stComplete: "Complete", stPartial: "Partial (content inspection incomplete)",
      sevCount: "Findings by severity", sev: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
      why: "Why CyberScan reached this result", whyNote: "Each finding adds its weight to the score, and the strongest one sets its floor. All of them are listed so you can judge them yourself.",
      gObserved: "Observed in the file", gObservedNote: "measured by rules and structural analysis", gModel: "Model interpretation", gModelNote: "a statistical model's view, not a confirmed fact",
      gExternal: "External reports", gExternalNote: "public threat-intelligence services", noFind: "No warning signs were observed.", showAll: "Show all {n}", showLess: "Show fewer",
      entropy: "Entropy along the file", eMean: "mean", ePeak: "peak", eJumps: "sudden jumps", eNote: "How random the bytes are (0–8 bits per byte). Encrypted or compressed data is near 8; a sudden jump can mark where something hidden starts.",
      reco: "What to do", limits: "Limits of this result",
      recos: { NO_INDICATORS_OBSERVED: ["No suspicious indicators were found by these checks.", "That is not a guarantee: static analysis cannot see what a program does only when it runs.", "Still prefer files from sources you trust."],
        REVIEW: ["Read the findings before you open the file.", "Check where the file came from; ask the sender through another channel if it was unexpected.", "If it is a program you didn't expect, don't run it."],
        KNOWN_MALWARE: ["Delete the file; don't open, run or forward it.", "If it was already opened, disconnect the computer from the network and run a full antivirus scan.", "If it came by email or chat, report the sender to your security team.", "Change passwords used on this computer from another, clean device."],
        SUSPICIOUS: ["Don't open or run this file.", "If it came by email or chat, report it and delete it; don't forward it.", "If it was already opened, disconnect the computer from the network and run a full scan with your antivirus.", "Keep a copy only if your security team asks for it."],
        UNKNOWN: ["The analysis was incomplete: treat the file as unverified.", "Try the scan again; if it keeps failing, check the file with another tool before opening it."],
        EMPTY: ["There is nothing to open in an empty file.", "If you expected content, get the file again from where it came from."] },
      techTitle: "Technical analysis", techNote: "For advanced users and analysts: structure, details, checks, ATT&CK mapping and engine output.",
      report: "Open the full report", reportHint: "A printable report you can save as PDF.",
      riskScore: "Risk score", again: "Scan another", more: "More", keyTitle: "Key findings", seeAll: "See all {n} findings and why", detailsTitle: "Details",
      noFindKey: "No warning signs were found in this file.", noFindKeyUrl: "No warning signs were found in this link.", noFindKeyText: "No warning signs were found in this text.",
      sevLow: { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" }, sevItem: "{n} {k}", comma: ", ",
      whyShort: "Why this result", whyLine: "{n} findings: {s}", whyLine1: "1 finding: {s}", layTitle: "Layered analysis", layLine: "{n} checks: {s} suspicious, {c} clean, {x} n/a",
      extTitle: "External intelligence", extOff: "Not asked for this scan", extBad: "{b} of {n} services flagged it", extNone: "{a} of {n} services answered; none flagged it", extNoAnswer: "No service could answer", extLocal: "Known-malware lists and rule matches",
      modelTitle: "Machine-learning model", modelUsed: "An approved model gave its view (an input, not the verdict)", modelLine: "Resembles malware: {p}% · an input, not the verdict", modelNa: "Not used: it doesn't read this kind of file", modelNone: "Not used for this result",
      modelInput: "This is one input the verdict weighs, not a second score: the risk score at the top is the only verdict score.", techLine: "Structure, checks, ATT&CK mapping and engine output", show: "Show details", hide: "Hide details",
      identUrl: "Link details", identText: "Text details", gObservedUrl: "Observed in the link", gObservedText: "Observed in the text",
      gObservedNoteUrl: "measured by link rules and threat lists", gObservedNoteText: "measured by rules and pattern checks", chars: "{n} characters",
      clsUrl: { NO_INDICATORS_OBSERVED: ["No warning signs observed", "None of CyberScan's checks found a warning sign in this link. That is not a guarantee it is safe."],
        REVIEW: ["Needs review", "Something about this link is worth a closer look. Read the findings below before you open it."],
        KNOWN_MALWARE: ["Known malicious link", "This address is on a list of malicious links. Don't open it."],
        SUSPICIOUS: ["Suspicious", "CyberScan found strong warning signs in this link. Don't open it, and never enter details on the page it leads to."],
        UNKNOWN: ["Inconclusive", "The analysis could not complete, so CyberScan can't give a verdict. Treat the link with care."] },
      clsText: { NO_INDICATORS_OBSERVED: ["No warning signs observed", "None of CyberScan's checks found a warning sign in this text. That is not a guarantee it is harmless."],
        REVIEW: ["Needs review", "Something in this text is worth a closer look. Read the findings below before you act on it."],
        KNOWN_MALWARE: ["Known malicious content", "This text contains an address or item listed as malicious. Don't follow it."],
        SUSPICIOUS: ["Suspicious", "CyberScan found strong warning signs in this text. Don't follow its links or instructions."],
        UNKNOWN: ["Inconclusive", "The analysis could not complete, so CyberScan can't give a verdict. Treat the text with care."] },
      recosUrl: { NO_INDICATORS_OBSERVED: ["No warning signs were found in this link.", "That is not a guarantee: the page it leads to can change at any time.", "For accounts and payments, type addresses you know yourself instead of following links."],
        REVIEW: ["Read the findings before you open the link.", "If it came in a message, check with the sender through another channel.", "Never enter a password or card number on a page reached through a link like this."],
        KNOWN_MALWARE: ["Don't open this link: it is on a list of malicious addresses.", "Delete the message it came in and report it.", "If you already opened it, run a full antivirus scan and change any password you entered there."],
        SUSPICIOUS: ["Don't open this link.", "Don't enter passwords, codes or card details on the page it leads to.", "If it came by email or chat, report it and delete the message.", "If you already entered a password there, change it now from a page you open yourself."],
        UNKNOWN: ["The analysis was incomplete: treat the link as unverified.", "Try again; if it keeps failing, don't open the link."] },
      recosText: { NO_INDICATORS_OBSERVED: ["No warning signs were found in this text.", "That is not a guarantee: be careful with unexpected requests for money, codes or personal details."],
        REVIEW: ["Read the findings before acting on this text.", "Check any request with the sender through another channel.", "Don't follow its links unless you are sure where they lead."],
        KNOWN_MALWARE: ["Don't follow the links or instructions in this text.", "Delete the message and report it.", "If you already opened a link from it, run a full antivirus scan."],
        SUSPICIOUS: ["Don't follow the links or instructions in this text.", "Don't reply with passwords, codes or card details.", "If it came by email or chat, report it and delete it."],
        UNKNOWN: ["The analysis was incomplete: treat the text as unverified.", "Try again before acting on it."] },
      sigs: { pdf: "PDF document", zip: "ZIP / Office / APK", ole: "OLE (old Office, MSG)", pe: "Windows program (PE)", elf: "Linux program (ELF)", png: "PNG image", jpeg: "JPEG image", gif: "GIF image", rtf: "RTF document", rar: "RAR archive", "7z": "7-Zip archive", gz: "GZIP archive", crx: "Chrome extension (CRX)", text: "Text" },
    },
    ar: {
      hDate: "التاريخ", hAll: "أي وقت", hDay: "آخر 24 ساعة", hWeek: "آخر 7 أيام", hMonth: "آخر 30 يومًا", hSort: "الترتيب", hNew: "الأحدث أولًا", hOld: "الأقدم أولًا", hRisk: "الأعلى درجة أولًا", reportMissing: "التقرير مفقود",
      fmtTitle: "ما الذي يقرؤه CyberScan", fmtBody: "يمكن فحص أي ملف. محلّلات مخصّصة لـ: PDF، وWord/Excel/PowerPoint (الصيغ الحديثة والقديمة)، ورسائل Outlook، وRTF، وZIP، وتطبيقات Android ‏(APK)، وإضافات المتصفح، وبرامج Windows ‏(PE)، وبرامج Linux ‏(ELF)، والصور، والبريد، والنصوص.",
      dropEg: "مثلًا: مرفق بريد، أو فاتورة، أو ملف نزّلته ولم تتوقعه، أو تطبيق (APK أو EXE). حتى {n} ميغابايت.",
      fmtLimit: "أكبر ملف هنا: {n} ميغابايت", fmtNever: "تُقرأ الملفات كبيانات، ولا تُفتح أو تُشغَّل أبدًا.",
      fiName: "الاسم", fiExt: "الامتداد", fiSize: "الحجم", fiType: "النوع المكتشف", fiHash: "SHA-256", fiCheck: "التحقق", fiHashing: "جارٍ الحساب…", fiNoExt: "بلا امتداد",
      fiOk: "جاهز للفحص", fiTooBig: "أكبر من الحد ({n} ميغابايت)", fiEmpty: "الملف فارغ", fiMismatch: "الامتداد يقول {a} والمحتوى يبدو {b}: يستحق التحقق",
      fiRemove: "إزالة", fiReplace: "استبدال", fiUnknownType: "لم يُتعرَّف عليه من أول بايتاته",
      optTitle: "خيارات الفحص", optHint: "هذه هي الإعدادات التي سيستخدمها الفحص. غيّرها من الإعدادات.", optPublic: "في الموقع هذه الإعدادات ثابتة.", optOpen: "افتح الإعدادات",
      oEntropy: "الإنتروبيا والبنية", oRules: "القواعد الاستدلالية", oModel: "نموذج التعلّم الآلي", oOsint: "البحث في مصادر التهديدات عبر الإنترنت", oTimeout: "المهلة", on: "مفعّل", off: "متوقف", sec: "{n} ث",
      oModelNote: "يعمل فقط إن ثُبّت نموذج معتمد",
      whatHappens: "بدء الفحص يقرأ الملف مرة واحدة، ويقيس بنيته، ويقارنه بالقواعد والأنماط المعروفة، ويشرح ما يجده. لا يُشغَّل أي شيء.",
      tlTitle: "التحليل", tlElapsed: "الوقت المنقضي", tlUpload: "جارٍ الرفع", tlUploadDone: "اكتمل الرفع", tlContent: "فحص المحتوى (محلّلات الصيغ، والخصوصية، والأسرار)",
      tlContentDone: "اكتمل فحص المحتوى", tlReport: "إعداد التقرير", tlReportDone: "التقرير جاهز", tlWaiting: "بالانتظار", tlFailed: "توقف: {m}",
      tlPublic: "النسخة الإلكترونية تُجري التحليل كاملًا في طلب واحد وتعرض مراحله عند انتهائه.", tlObserved: "مُلاحَظ",
      stage: ["قراءة الهدف وجمع الأدلة الساكنة", "قياس الإنتروبيا والبنية", "بناء التمثيل البنيوي", "البحث الاختياري عبر الإنترنت"],
      cls: { NO_INDICATORS_OBSERVED: ["لم تُرصد علامات تحذير", "لم يجد أي من فحوص CyberScan مؤشرًا في هذا الملف. هذا ليس ضمانًا للأمان."],
        REVIEW: ["يحتاج مراجعة", "في هذا الملف ما يستحق نظرة أقرب. اقرأ ما وُجد أدناه قبل أن تثق به."],
        KNOWN_MALWARE: ["برنامج ضار معروف", "هذا الملف بعينه مُدرج كبرنامج ضار لدى مصدر استخبارات تهديدات. احذفه ولا تفتحه أو تشغّله."],
        SUSPICIOUS: ["مشبوه", "وجد CyberScan علامات تحذير قوية. لا تفتحه ولا تشغّله ما لم تكن متأكدًا من مصدره."],
        UNKNOWN: ["غير حاسم", "لم يكتمل التحليل، فلا يستطيع CyberScan إصدار حكم. تعامل مع الملف بحذر."],
        EMPTY: ["ملف فارغ", "لا يحتوي هذا الملف على أي محتوى، فلا يوجد ما يُفحص. إن توقعت محتوى فقد تكون النسخة ناقصة."] },
      sumTitle: "الملخص الأمني", score: "الدرجة", scoreNote: "أدلة موزونة من كل فحوص CyberScan، من 0 إلى 100: كل نتيجة تضيف وزنها، وأقوى دليل يحدد الحد الأدنى. ليست احتمالًا لوجود برمجية خبيثة.",
      bands: ["0: لا مؤشرات", "1–49: مراجعة", "50+: مشبوه"],
      conf: "ثقة النموذج", confNone: "غير متاحة لهذه النتيجة: تعتمد النتيجة على الأدلة الساكنة.", confMl: "تشابه مع البرمجيات الخبيثة (EMBER2024)", confMlNote: "نموذج مدرَّب على ملايين برامج Windows وملفات PDF. هو دليل واحد بين أدلة كثيرة، وليس احتمالًا، ولا يقرّر الحكم وحده.", confMlNa: "نموذج التعلّم الآلي (EMBER2024) يقرأ برامج Windows الكاملة وملفات PDF فقط؛ وهذا الملف ليس مما يستطيع قراءته، فلم يُستخدم.",
      confNote: "درجات النموذج غير معايَرة: ترتّب الفئات، وليست احتمالات.", confAbst: "امتنع النموذج عن الحكم (أكثر من فئة محتملة).",
      ident: "هوية الملف", target: "الهدف", type: "النوع", size: "الحجم", sha: "SHA-256", when: "وقت الفحص", status: "الحالة", stComplete: "مكتمل", stPartial: "جزئي (فحص المحتوى لم يكتمل)",
      sevCount: "ما وُجد حسب الخطورة", sev: { critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة" },
      why: "لماذا وصل CyberScan إلى هذه النتيجة", whyNote: "كل نتيجة تضيف وزنها إلى الدرجة، وأقواها يحدد حدها الأدنى. كلها معروضة لتحكم عليها بنفسك.",
      gObserved: "ما رُصد في الملف", gObservedNote: "قيس بالقواعد والتحليل البنيوي", gModel: "تفسير النموذج", gModelNote: "رأي نموذج إحصائي، وليس حقيقة مؤكدة",
      gExternal: "تقارير خارجية", gExternalNote: "خدمات استخبارات التهديدات العامة", noFind: "لم تُرصد علامات تحذير.", showAll: "اعرض الكل ({n})", showLess: "اعرض أقل",
      entropy: "الإنتروبيا على امتداد الملف", eMean: "المتوسط", ePeak: "الذروة", eJumps: "قفزات مفاجئة", eNote: "مدى عشوائية البايتات (0–8 بت لكل بايت). البيانات المشفّرة أو المضغوطة قريبة من 8، والقفزة المفاجئة قد تدل على بداية جزء مخفي.",
      reco: "ماذا تفعل", limits: "حدود هذه النتيجة",
      recos: { NO_INDICATORS_OBSERVED: ["لم تجد هذه الفحوص مؤشرات مشبوهة.", "هذا ليس ضمانًا: التحليل الساكن لا يرى ما يفعله البرنامج عند تشغيله فقط.", "فضّل دائمًا الملفات من مصادر تثق بها."],
        REVIEW: ["اقرأ ما وُجد قبل فتح الملف.", "تحقق من مصدر الملف، واسأل المرسل عبر وسيلة أخرى إن لم تكن تتوقعه.", "إن كان برنامجًا لم تتوقعه، فلا تشغّله."],
        KNOWN_MALWARE: ["احذف الملف، ولا تفتحه أو تشغّله أو تعِد إرساله.", "إن فُتح من قبل، فافصل الجهاز عن الشبكة وشغّل فحصًا كاملًا ببرنامج الحماية.", "إن وصلك بالبريد أو المحادثة فأبلغ فريق الأمن عن المرسل.", "غيّر كلمات المرور المستخدمة على هذا الجهاز من جهاز آخر سليم."],
        SUSPICIOUS: ["لا تفتح هذا الملف ولا تشغّله.", "إن وصلك بالبريد أو المحادثة فأبلغ عنه واحذفه، ولا تعِد إرساله.", "إن فُتح من قبل، فافصل الجهاز عن الشبكة وشغّل فحصًا كاملًا ببرنامج الحماية.", "احتفظ بنسخة فقط إن طلب فريق الأمن ذلك."],
        UNKNOWN: ["لم يكتمل التحليل: عامل الملف على أنه غير متحقق منه.", "أعد الفحص، وإن تكرر الفشل فافحص الملف بأداة أخرى قبل فتحه."],
        EMPTY: ["لا يوجد ما يُفتح في ملف فارغ.", "إن توقعت محتوى، فاحصل على الملف مجددًا من مصدره."] },
      techTitle: "التحليل التقني", techNote: "للمستخدمين المتقدمين والمحللين: البنية، والتفاصيل، والفحوص، وربط ATT&CK، ومخرجات المحركات.",
      report: "افتح التقرير الكامل", reportHint: "تقرير قابل للطباعة يمكنك حفظه بصيغة PDF.",
      riskScore: "درجة الخطر", again: "افحص شيئًا آخر", more: "المزيد", keyTitle: "أبرز ما وُجد", seeAll: "اعرض كل النتائج ({n}) وسببها", detailsTitle: "التفاصيل",
      noFindKey: "لم تُرصد علامات تحذير في هذا الملف.", noFindKeyUrl: "لم تُرصد علامات تحذير في هذا الرابط.", noFindKeyText: "لم تُرصد علامات تحذير في هذا النص.",
      sevLow: { critical: "حرجة", high: "مرتفعة", medium: "متوسطة", low: "منخفضة", info: "معلومة" }, sevItem: "{k}: {n}", comma: "، ",
      whyShort: "لماذا هذه النتيجة", whyLine: "{n} نتائج — {s}", whyLine1: "نتيجة واحدة — {s}", layTitle: "التحليل الطبقي", layLine: "{n} فحصًا: {s} مشبوهة، {c} سليمة، {x} لا تنطبق",
      extTitle: "الاستخبارات الخارجية", extOff: "لم تُسأل في هذا الفحص", extBad: "أشارت إليه {b} من {n} خدمات", extNone: "أجابت {a} من {n} خدمات، ولم تُشر إليه أي منها", extNoAnswer: "لم تستطع أي خدمة الإجابة", extLocal: "قوائم البرامج الضارة المعروفة ومطابقات القواعد",
      modelTitle: "نموذج التعلّم الآلي", modelUsed: "أبدى نموذج معتمد رأيه (مُدخل، وليس الحكم)", modelLine: "التشابه مع البرمجيات الخبيثة: {p}% · مُدخل، وليس الحكم", modelNa: "لم يُستخدم: لا يقرأ هذا النوع من الملفات", modelNone: "لم يُستخدم لهذه النتيجة",
      modelInput: "هذا مُدخل واحد يزنه الحكم، وليس درجة ثانية: درجة الخطر في الأعلى هي درجة الحكم الوحيدة.", techLine: "البنية والفحوص وربط ATT&CK ومخرجات المحركات", show: "اعرض التفاصيل", hide: "أخفِ التفاصيل",
      identUrl: "تفاصيل الرابط", identText: "تفاصيل النص", gObservedUrl: "ما رُصد في الرابط", gObservedText: "ما رُصد في النص",
      gObservedNoteUrl: "قيس بقواعد الروابط وقوائم التهديدات", gObservedNoteText: "قيس بالقواعد وفحص الأنماط", chars: "{n} حرفًا",
      clsUrl: { NO_INDICATORS_OBSERVED: ["لم تُرصد علامات تحذير", "لم يجد أي من فحوص CyberScan علامة تحذير في هذا الرابط. هذا ليس ضمانًا لأمانه."],
        REVIEW: ["يحتاج مراجعة", "في هذا الرابط ما يستحق نظرة أقرب. اقرأ ما وُجد أدناه قبل أن تفتحه."],
        KNOWN_MALWARE: ["رابط ضار معروف", "هذا العنوان مُدرج في قائمة للروابط الضارة. لا تفتحه."],
        SUSPICIOUS: ["مشبوه", "وجد CyberScan علامات تحذير قوية في هذا الرابط. لا تفتحه، ولا تُدخل أي بيانات في الصفحة التي يقود إليها."],
        UNKNOWN: ["غير حاسم", "لم يكتمل التحليل، فلا يستطيع CyberScan إصدار حكم. تعامل مع الرابط بحذر."] },
      clsText: { NO_INDICATORS_OBSERVED: ["لم تُرصد علامات تحذير", "لم يجد أي من فحوص CyberScan علامة تحذير في هذا النص. هذا ليس ضمانًا لسلامته."],
        REVIEW: ["يحتاج مراجعة", "في هذا النص ما يستحق نظرة أقرب. اقرأ ما وُجد أدناه قبل أن تتصرف بناءً عليه."],
        KNOWN_MALWARE: ["محتوى ضار معروف", "يحتوي هذا النص على عنوان أو عنصر مُدرج كضار. لا تتبعه."],
        SUSPICIOUS: ["مشبوه", "وجد CyberScan علامات تحذير قوية في هذا النص. لا تتبع روابطه ولا تعليماته."],
        UNKNOWN: ["غير حاسم", "لم يكتمل التحليل، فلا يستطيع CyberScan إصدار حكم. تعامل مع النص بحذر."] },
      recosUrl: { NO_INDICATORS_OBSERVED: ["لم تُرصد علامات تحذير في هذا الرابط.", "هذا ليس ضمانًا: قد تتغير الصفحة التي يقود إليها في أي وقت.", "للحسابات والمدفوعات، اكتب العناوين التي تعرفها بنفسك بدل اتباع الروابط."],
        REVIEW: ["اقرأ ما وُجد قبل أن تفتح الرابط.", "إن وصلك في رسالة، فتحقق من المرسل عبر وسيلة أخرى.", "لا تُدخل كلمة مرور أو رقم بطاقة في صفحة وصلت إليها عبر رابط كهذا."],
        KNOWN_MALWARE: ["لا تفتح هذا الرابط: إنه مُدرج في قائمة للعناوين الضارة.", "احذف الرسالة التي وصل فيها وأبلغ عنها.", "إن فتحته من قبل، فشغّل فحصًا كاملًا ببرنامج الحماية وغيّر أي كلمة مرور أدخلتها هناك."],
        SUSPICIOUS: ["لا تفتح هذا الرابط.", "لا تُدخل كلمات مرور أو رموزًا أو بيانات بطاقة في الصفحة التي يقود إليها.", "إن وصلك بالبريد أو المحادثة فأبلغ عنه واحذف الرسالة.", "إن أدخلت كلمة مرور هناك، فغيّرها الآن من صفحة تفتحها بنفسك."],
        UNKNOWN: ["لم يكتمل التحليل: عامل الرابط على أنه غير متحقق منه.", "أعد المحاولة، وإن تكرر الفشل فلا تفتح الرابط."] },
      recosText: { NO_INDICATORS_OBSERVED: ["لم تُرصد علامات تحذير في هذا النص.", "هذا ليس ضمانًا: احذر من الطلبات غير المتوقعة للمال أو الرموز أو البيانات الشخصية."],
        REVIEW: ["اقرأ ما وُجد قبل أن تتصرف بناءً على هذا النص.", "تحقق من أي طلب مع المرسل عبر وسيلة أخرى.", "لا تتبع روابطه ما لم تكن متأكدًا إلى أين تقود."],
        KNOWN_MALWARE: ["لا تتبع الروابط أو التعليمات في هذا النص.", "احذف الرسالة وأبلغ عنها.", "إن فتحت رابطًا منه من قبل، فشغّل فحصًا كاملًا ببرنامج الحماية."],
        SUSPICIOUS: ["لا تتبع الروابط أو التعليمات في هذا النص.", "لا ترد بكلمات مرور أو رموز أو بيانات بطاقة.", "إن وصلك بالبريد أو المحادثة فأبلغ عنه واحذفه."],
        UNKNOWN: ["لم يكتمل التحليل: عامل النص على أنه غير متحقق منه.", "أعد المحاولة قبل أن تتصرف بناءً عليه."] },
      sigs: { pdf: "مستند PDF", zip: "ZIP / Office / APK", ole: "OLE (Office القديم، MSG)", pe: "برنامج Windows ‏(PE)", elf: "برنامج Linux ‏(ELF)", png: "صورة PNG", jpeg: "صورة JPEG", gif: "صورة GIF", rtf: "مستند RTF", rar: "أرشيف RAR", "7z": "أرشيف 7-Zip", gz: "أرشيف GZIP", crx: "إضافة Chrome ‏(CRX)", text: "نص" },
    },
  };
  const I = window.I18N;
  if (I && I.en && I.ar) {
    ["hDate", "hAll", "hDay", "hWeek", "hMonth", "hSort", "hNew", "hOld", "hRisk", "reportMissing"].forEach((k) => { I.en[k] = STR.en[k]; I.ar[k] = STR.ar[k]; });
  }
  const L = () => STR[CS.lang === "ar" ? "ar" : "en"];
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] ?? ""));
  const fmtBytes = (n) => (CS.formatBytes ? CS.formatBytes(n) : `${n} B`);
  const settings = () => CS.settings || {};
  const isPublic = () => !!settings().public;
  const limitBytes = () => Math.min(settings().maximum_file_size || Infinity, isPublic() ? 4 * 1048576 : 50 * 1048576); // the same cap the server applies

  /* ================================================================ 1. the workspace */
  const composer = document.querySelector(".composer");
  const drop = $("drop");
  const info = el("div", "sc-fileinfo"); info.hidden = true; info.setAttribute("aria-live", "polite");
  const formats = el("details", "sc-formats");
  const opts = el("details", "sc-opts");
  const what = el("p", "sc-what");
  drop.after(info);
  const formPanel = drop.closest("[data-panel]") || drop.parentElement;
  formPanel.append(formats);
  const go = $("go");
  go.before(opts); go.after(what);
  // the drop zone says what people usually check here
  const dropEg = el("small", "sc-drop-eg"); dropEg.id = "drop-eg";
  drop.append(dropEg);
  const dropHint = drop.querySelector("small[data-i18n]");
  if (dropHint) { dropHint.id = "drop-hint"; drop.setAttribute("aria-describedby", "drop-hint drop-eg"); } else drop.setAttribute("aria-describedby", "drop-eg");
  // Start sits right under what is being checked; the options and notes follow it
  const afterGo = el("div", "sc-after-go");
  go.after(afterGo);
  const settle = () => {
    afterGo.append(...[document.querySelector("#form .ext-toggle"), formats, opts, what].filter(Boolean));
    formats.hidden = !!formPanel.hidden;
    if (CS.updateReady) CS.updateReady();
  };
  // the outside-services switch (js/external-intel.js) is made after this file runs: settle again once everything has
  settle(); document.addEventListener("DOMContentLoaded", settle); window.addEventListener("load", settle); setTimeout(settle, 0);
  new MutationObserver(() => { formats.hidden = !!formPanel.hidden; }).observe(formPanel, { attributes: true, attributeFilter: ["hidden"] });

  function paintFormats() {
    const l = L();
    formats.replaceChildren();
    const sm = el("summary"); sm.append(el("b", "", l.fmtTitle), el("span", "sc-limit", fill(l.fmtLimit, { n: Math.round(limitBytes() / 1048576) })));
    formats.append(sm, el("p", "", l.fmtBody), el("p", "sc-never", l.fmtNever));
    what.textContent = l.whatHappens;
    dropEg.textContent = fill(l.dropEg, { n: Math.round(limitBytes() / 1048576) });
  }
  function paintOpts() {
    const l = L(), s = settings();
    opts.replaceChildren();
    const sm = el("summary", "", l.optTitle);
    const list = el("dl", "sc-opt-list");
    const row = (k, v, note) => { const dt = el("dt", "", k); const dd = el("dd", "", v); if (note) dd.append(el("small", "", ` · ${note}`)); list.append(dt, dd); };
    const onoff = (v) => (v === false ? l.off : l.on);
    row(l.oEntropy, onoff(s.entropy_analysis));
    row(l.oRules, onoff(s.heuristic_rules));
    row(l.oModel, onoff(s.ml_analysis), l.oModelNote);
    row(l.oOsint, onoff(!!s.osint_enabled));
    row(l.oTimeout, fill(l.sec, { n: s.analysis_timeout || (isPublic() ? 50 : 15) }));
    const foot = el("p", "sc-opt-foot", isPublic() ? l.optPublic : l.optHint);
    opts.append(sm, list, foot);
    if (!isPublic()) { const a = el("a", "ghost small", l.optOpen); a.href = "#/settings"; opts.append(a); }
  }

  // the chosen file: its identity, its real type (from its first bytes), its fingerprint, a validation
  const SIGS = [
    [[0x25, 0x50, 0x44, 0x46], "pdf"], [[0x50, 0x4b, 0x03, 0x04], "zip"], [[0xd0, 0xcf, 0x11, 0xe0], "ole"],
    [[0x4d, 0x5a], "pe"], [[0x7f, 0x45, 0x4c, 0x46], "elf"], [[0x89, 0x50, 0x4e, 0x47], "png"],
    [[0xff, 0xd8, 0xff], "jpeg"], [[0x47, 0x49, 0x46, 0x38], "gif"], [[0x7b, 0x5c, 0x72, 0x74, 0x66], "rtf"],
    [[0x52, 0x61, 0x72, 0x21], "rar"], [[0x37, 0x7a, 0xbc, 0xaf], "7z"], [[0x1f, 0x8b], "gz"], [[0x43, 0x72, 0x32, 0x34], "crx"],
  ];
  const EXT_KIND = { pdf: "pdf", zip: "zip", docx: "zip", xlsx: "zip", pptx: "zip", apk: "zip", jar: "zip",
    doc: "ole", xls: "ole", ppt: "ole", msg: "ole", exe: "pe", dll: "pe", scr: "pe",
    png: "png", jpg: "jpeg", jpeg: "jpeg", gif: "gif", rtf: "rtf", rar: "rar", "7z": "7z", gz: "gz", crx: "crx" };
  let infoFor = null;
  async function showFile(file) {
    infoFor = file;
    const l = L();
    if (!file) { info.hidden = true; return; }
    const dot = file.name.lastIndexOf("."), ext = dot > 0 ? file.name.slice(dot + 1).toLowerCase() : "";
    const head = new Uint8Array(await file.slice(0, 16).arrayBuffer());
    if (infoFor !== file) return;
    const sig = SIGS.find(([b]) => b.every((x, i) => head[i] === x));
    const type = sig ? sig[1] : (head.length && [...head].every((b) => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) ? "text" : null);
    const issues = [];
    let tone = "ok", check = l.fiOk;
    if (!file.size) { tone = "bad"; check = l.fiEmpty; }
    else if (file.size > limitBytes()) { tone = "bad"; check = fill(l.fiTooBig, { n: Math.round(limitBytes() / 1048576) }); }
    else if (ext && EXT_KIND[ext] && type && EXT_KIND[ext] !== type && type !== "text") { tone = "warn"; issues.push(fill(l.fiMismatch, { a: `.${ext}`, b: l.sigs[type] || type })); }
    info.replaceChildren();
    const top = el("div", "sc-fi-top");
    const name = el("b", "sc-fi-name", file.name); name.dir = "auto"; name.title = file.name;
    const btns = el("div", "sc-fi-btns");
    const rep = el("button", "ghost small", l.fiReplace); rep.type = "button"; rep.addEventListener("click", () => $("file").click());
    const rem = el("button", "ghost small", l.fiRemove); rem.type = "button"; rem.addEventListener("click", () => { CS.resetChoice && CS.resetChoice(); infoFor = null; info.hidden = true; if (CS.updateReady) CS.updateReady(); });
    btns.append(rep, rem);
    top.append(name, btns);
    const dl = el("dl", "sc-fi-grid");
    const add = (k, v, cls) => { const d = el("dd", cls || "", v); if (cls === "mono") d.dir = "ltr"; dl.append(el("dt", "", k), d); return d; };
    add(l.fiExt, ext ? `.${ext}` : l.fiNoExt, "mono");
    add(l.fiSize, file.size < 1024 ? `${file.size} B` : `${fmtBytes(file.size)} (${file.size.toLocaleString()} B)`);
    add(l.fiType, type ? (l.sigs[type] || type) : l.fiUnknownType);
    const hashCell = add(l.fiHash, l.fiHashing, "mono hash");
    const chk = add(l.fiCheck, check, `check t-${tone}`);
    issues.forEach((x) => chk.append(el("small", "", x)));
    info.append(top, dl);
    info.hidden = false;
    if (!reduced()) info.animate([{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "none" }], { duration: 360, easing: "cubic-bezier(.22,1,.36,1)" });
    // the fingerprint, computed in the browser (the file is not sent for this)
    // the fingerprint of an empty file is real too (e3b0c442…), and the "seen before" panel uses it
    if (file.size <= 256 * 1048576 && crypto.subtle) {
      try {
        const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
        if (infoFor === file) hashCell.textContent = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
      } catch { hashCell.textContent = "–"; }
    } else hashCell.textContent = "–";
  }
  const syncFile = () => setTimeout(() => showFile(CS.state && CS.state.file), 0);
  $("file").addEventListener("change", syncFile);
  drop.addEventListener("drop", syncFile);
  // the composer comes back for a new scan: forget the old file card
  new MutationObserver(() => { if (!composer.hidden && !(CS.state && CS.state.file)) { info.hidden = true; infoFor = null; } }).observe(composer, { attributes: true, attributeFilter: ["hidden"] });

  /* ================================================================ 2. live analysis */
  const progress = $("progress");
  const tl = el("div", "sc-tl");
  const tlHead = el("div", "sc-tl-head");
  const tlTitle = el("h3", "sc-tl-title"), tlClock = el("span", "sc-tl-clock");
  tlHead.append(tlTitle, tlClock);
  const tlList = el("ol", "sc-tl-list");
  const tlNote = el("p", "sc-tl-note"); tlNote.hidden = true;
  tl.append(tlHead, tlList, tlNote);
  progress.append(tl);
  let steps = [], t0 = 0, clockRaf = 0, isFileScan = false, finished = false, active = false;
  // steps: upload (files) · content inspection · the 4 server stages · report
  function makeSteps() {
    const l = L();
    steps = [];
    if (isFileScan) steps.push({ key: "up", label: l.tlUpload, done: l.tlUploadDone, state: "running", t: performance.now() });
    steps.push({ key: "content", label: l.tlContent, done: l.tlContentDone, state: isFileScan ? "pending" : "running", t: isFileScan ? 0 : performance.now() });
    l.stage.forEach((s, i) => steps.push({ key: `s${i}`, label: s, state: "pending", detail: "" }));
    steps.push({ key: "rep", label: l.tlReport, done: l.tlReportDone, state: "pending" });
  }
  const step = (k) => steps.find((s) => s.key === k);
  function setState(s, state) {
    if (!s || s.state === state) return;
    const now = performance.now();
    if (state === "running") s.t = now;
    if (state === "complete" || state === "failed") s.ms = s.t ? now - s.t : null;
    s.state = state;
  }
  function paintTl() {
    const l = L();
    tlTitle.textContent = l.tlTitle;
    tlList.replaceChildren(...steps.map((s, i) => {
      const li = el("li", `sc-st st-${s.state}`);
      li.style.setProperty("--i", i);
      const dot = el("span", "sc-st-dot"); dot.setAttribute("aria-hidden", "true");
      const body = el("div", "sc-st-body");
      const name = el("b", "", s.state === "complete" && s.done ? s.done : s.label);
      body.append(name);
      if (s.key === "up" && s.total && s.state === "running") {
        const pct = Math.round((s.loaded / s.total) * 100);                   // real: bytes the browser has sent
        const bar = el("span", "sc-st-bar"); const f = el("i"); f.style.width = `${pct}%`; bar.append(f);
        body.append(bar, el("small", "", `${fmtBytes(s.loaded)} / ${fmtBytes(s.total)} · ${pct}%`));
      } else if (s.detail) { const d = el("small", "", s.detail); d.dir = "auto"; body.append(d); }
      if (s.state === "failed") body.append(el("small", "sc-st-err", CS.ax("errTitle")));
      const time = el("span", "sc-st-time", s.ms != null ? `${(s.ms / 1000).toFixed(2)} s` : s.state === "pending" ? l.tlWaiting : "");
      if (s.ms != null) time.title = l.tlObserved;
      li.append(dot, body, time);
      li.setAttribute("aria-current", s.state === "running" ? "step" : "false");
      return li;
    }));
  }
  function tick() {
    clockRaf = 0;
    if (finished || progress.hidden) return;
    tlClock.textContent = `${L().tlElapsed} ⁦${((performance.now() - t0) / 1000).toFixed(1)} s⁩`;
    clockRaf = requestAnimationFrame(tick);
  }
  window.addEventListener("cs:scan-start", () => {
    isFileScan = !!(CS.state && CS.state.mode === "file" && CS.state.file);
    finished = false; active = true; t0 = performance.now();
    makeSteps();
    tlNote.hidden = !isPublic(); tlNote.textContent = L().tlPublic;
    progress.classList.add("sc-on");
    paintTl();
    if (!clockRaf) clockRaf = requestAnimationFrame(tick);
  });
  window.addEventListener("cs:upload", (e) => {
    const s = step("up"); if (!s) return;
    s.loaded = e.detail.loaded; s.total = e.detail.total;
    if (e.detail.done) { setState(s, "complete"); setState(step("content"), "running"); }
    paintTl();
  });
  window.addEventListener("cs:stages", (e) => {
    const st = e.detail || [];
    if (!steps.length) return;
    const up = step("up"); if (up && up.state !== "complete") { setState(up, "complete"); }
    const any = st.some((x) => x && x.state !== "pending");
    // the server inspects the content first, without reporting it; it's over once its own stages begin
    if (any) setState(step("content"), "complete");
    else setState(step("content"), "running");
    st.forEach((x, i) => {
      const s = step(`s${i}`); if (!s || !x) return;
      setState(s, x.state === "complete" ? "complete" : x.state === "running" ? "running" : "pending");
      if (x.detail) s.detail = x.detail;
    });
    if (st.length && st.every((x) => x && x.state === "complete")) setState(step("rep"), "running");
    paintTl();
  });
  window.addEventListener("cs:result", (e) => {
    if (!e.detail.animate || !steps.length || !active) return;   // a reopened record is not this scan
    active = false;
    steps.forEach((s) => { if (s.state !== "complete") setState(s, "complete"); });
    finished = true;
    const server = CS.elapsedOf(e.detail.result);
    const secs = Math.max((performance.now() - t0) / 1000, server || 0);
    tlClock.textContent = `${L().tlElapsed} ⁦${secs.toFixed(2)} s⁩`;
    paintTl();
  });
  window.addEventListener("cs:scan-error", (e) => {
    const s = steps.find((x) => x.state === "running") || steps.find((x) => x.state === "pending") || steps[steps.length - 1];
    if (s) { setState(s, "failed"); s.error = String(e.detail || ""); }
    // the steps after it never ran
    finished = true; active = false;
    tlClock.textContent = `${L().tlElapsed} ⁦${((performance.now() - t0) / 1000).toFixed(2)} s⁩`;
    paintTl();
  });

  /* ================================================================ 3. the results center */
  const resultSec = $("result");
  const rc = el("div", "rc"); rc.setAttribute("aria-live", "polite");
  resultSec.prepend(rc);
  resultSec.classList.add("has-rc");
  const actions = $("actions");
  const techCard = resultSec.querySelector(".result-tabs");
  const techHead = el("div", "rc-tech-head");
  const limitsP = $("limits");   // the engine's own limits line, shown with the technical tabs
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sevOf = (f) => String(f.severity || "info").toLowerCase();

  // every finding once, in the user's language: the same list the Findings tab, the report and the exports use
  const collect = (r) => CS.findingsOf(r);
  // texts that depend on what was checked: a file, a link or a text
  const byMode = (l, mode, key) => (mode === "url" ? l[`${key}Url`] : mode === "text" ? l[`${key}Text`] : null) || l[key];

  function render(r, animate) {
    const l = L();
    const mode = CS.modeOf(r);
    const shown = CS.verdictOf(r);            // the one score, and the badge that follows its band
    const cls = shown.cls;
    const [word, sentence] = byMode(l, mode, "cls")[cls] || l.cls.UNKNOWN;
    const tone = cls === "SUSPICIOUS" || cls === "KNOWN_MALWARE" ? "bad" : cls === "REVIEW" ? "warn" : cls === "NO_INDICATORS_OBSERVED" ? "ok" : "neutral";
    const score = shown.score;
    const finds = collect(r);
    rc.replaceChildren();
    rc.className = `rc t-${tone}`;

    /* The result reads top to bottom in the order a person needs it:
     *   1. one verdict card: the verdict word and colour, the one score, one plain sentence, the summary
     *      written for the reader (js/layers.js) and Bit's line (js/result-plus.js);
     *   2. one primary action, "Scan another", and a "More" menu with everything else;
     *   3. the top findings in plain words;
     *   4. the details, folded, each with a one-line summary in its header (open state remembered). */
    const sum = el("section", "card rc-sum rx-verdict");
    const head = el("div", "rc-sum-head");
    const badge = el("span", "rc-badge", word);
    const title = el("h2", "rc-title", word);
    title.id = "rx-verdict-title";
    sum.setAttribute("aria-labelledby", "rx-verdict-title");
    const lede = el("p", "rc-lede", sentence);
    // what was checked, in one line
    const ftype = r.content_analysis && r.content_analysis.file_type;
    const typeName = CS.typeLabel(mode === "file" ? (ftype || "file") : mode);
    const sizeTxt = mode === "file" && r.size ? fmtBytes(r.size) : mode === "text" && r.size ? fill(l.chars, { n: Number(r.size).toLocaleString(CS.lang) }) : "";
    const tline = el("p", "rx-target");
    const tname = el("bdi", "", CS.targetLabel(r, false)); tname.dir = mode === "url" ? "ltr" : "auto"; tname.title = String(r.target || "");
    tline.append(tname, document.createTextNode(` · ${[typeName, sizeTxt].filter(Boolean).join(" · ")}`));
    head.append(badge, title, lede, tline);
    // the one score, with what its bands mean
    const meter = el("div", "rc-meter rx-score");
    const num = el("b", "rc-score", "0"); const of = el("span", "rc-of", "/100");
    const scale = el("div", "rc-scale"); scale.setAttribute("role", "img"); scale.setAttribute("aria-label", `${l.score} ${score}/100`);
    scale.append(el("i", "z0"), el("i", "z1"), el("i", "z2"));
    const mark = el("span", "rc-mark"); scale.append(mark);
    const bands = el("div", "rc-bands"); l.bands.forEach((b) => bands.append(el("span", "", b)));
    meter.append(el("small", "", l.riskScore), (() => { const d = el("div", "rc-score-line"); d.append(num, of); return d; })(), scale, bands);
    const top = el("div", "rx-v-top"); top.append(head, meter);
    sum.append(top);
    rc.append(sum);

    /* --- the actions: one primary, "Scan another", and More --- */
    const actRow = el("div", "rc-actions rx-actions");
    const repBtn = el("button", "primary rc-report", l.report); repBtn.type = "button"; repBtn.title = l.reportHint;
    repBtn.addEventListener("click", () => openReport(r));
    const again = el("button", "ghost rx-again", l.again); again.type = "button";
    again.addEventListener("click", () => { CS.newScan(); const c = document.querySelector(".composer"); if (c) { c.scrollIntoView({ block: "start", behavior: reduced() ? "auto" : "smooth" }); const d = $("drop"); if (d && !d.closest("[hidden]")) d.focus({ preventScroll: true }); } });
    const moreWrap = el("div", "rx-more");
    const moreBtn = el("button", "ghost rx-more-btn"); moreBtn.type = "button";
    moreBtn.append(el("span", "", l.more));
    moreBtn.insertAdjacentHTML("beforeend", '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>');
    const menu = el("div", "rx-menu"); menu.id = "rx-menu"; menu.hidden = true;
    menu.setAttribute("role", "group"); menu.setAttribute("aria-label", l.more);
    moreBtn.setAttribute("aria-expanded", "false"); moreBtn.setAttribute("aria-controls", "rx-menu");
    menu.append(actions);
    moreWrap.append(moreBtn, menu);
    wireMenu(moreBtn, menu);
    actRow.append(repBtn, again, moreWrap);
    rc.append(actRow);

    /* --- the key findings: the three that matter most, in plain words --- */
    const key = el("section", "card rx-key");
    key.setAttribute("aria-labelledby", "rx-key-title");
    const kh = el("h3", "", l.keyTitle); kh.id = "rx-key-title";
    key.append(kh);
    const ranked = finds.slice().sort((a, b) => (SEV_RANK[a.sev] ?? 5) - (SEV_RANK[b.sev] ?? 5) || (b.contrib || 0) - (a.contrib || 0));
    const topFinds = ranked.filter((f) => f.sev !== "info" || ranked.length <= 3).slice(0, 3);
    if (!topFinds.length) key.append(el("p", "rc-none", byMode(l, mode, "noFindKey")));
    else {
      const ul = el("ul", "rx-key-list");
      topFinds.forEach((f) => {
        const li = el("li", `rx-kf s-${f.sev}`);
        li.append(el("span", "rc-sev", l.sev[f.sev] || f.sev));
        const box = el("div", "rx-kf-body");
        const tt = el("b", "", f.title + (f.count > 1 ? ` ×${f.count}` : "")); tt.dir = "auto";
        box.append(tt);
        if (f.text && f.text.trim().toLowerCase() !== String(f.title).trim().toLowerCase()) { const p = el("p", "", f.text); p.dir = "auto"; box.append(p); }
        li.append(box);
        ul.append(li);
      });
      key.append(ul);
    }
    if (finds.length > topFinds.length) {
      const all = el("button", "link-btn rx-see-all", fill(l.seeAll, { n: finds.length })); all.type = "button";
      all.addEventListener("click", () => openSection("why", true));
      key.append(all);
    }
    rc.append(key);

    /* --- the details, folded --- */
    const secs = el("section", "rx-secs");
    secs.setAttribute("aria-labelledby", "rx-secs-title");
    const sh = el("div", "rx-secs-head");
    const st = el("h3", "", l.detailsTitle); st.id = "rx-secs-title";
    sh.append(st);
    secs.append(sh);
    const bodies = {};
    const counts = {}; finds.forEach((f) => { counts[f.sev] = (counts[f.sev] || 0) + 1; });
    const sevLine = ["critical", "high", "medium", "low", "info"].filter((k) => counts[k]).map((k) => fill(l.sevItem, { n: counts[k], k: l.sevLow[k] })).join(l.comma);
    const lay = r.layers && r.layers.summary;
    const layLine = lay ? fill(l.layLine, { n: lay.total ?? (r.layers.layers || []).length, s: lay.suspicious ?? 0, c: lay.clean ?? 0, x: (lay.not_applicable ?? 0) + (lay.unavailable ?? 0) }) : "";
    const ext = r.external;
    let extLine = "";
    if (ext && Array.isArray(ext.rows) && ext.rows.length) {
      const bad = ext.rows.filter((x) => x.chip === "bad").length;
      const answered = ext.rows.filter((x) => ["bad", "warn", "ok", "neutral"].includes(x.chip)).length;
      extLine = !ext.ran ? l.extOff : bad ? fill(l.extBad, { b: bad, n: ext.rows.length }) : answered ? fill(l.extNone, { a: answered, n: ext.rows.length }) : l.extNoAnswer;
    } else extLine = l.extLocal;
    const recos = byMode(l, mode, "recos");
    const recoList = recos[cls] || recos.UNKNOWN;
    const pred = r.prediction || {}, cs = pred.class_scores || {};
    const hasModel = pred.status && !/untrained|unavailable|unapproved|missing|disabled/i.test(String(pred.status)) && Object.keys(cs).length;
    const mm = r.ml_model || {};
    const modelLine = hasModel ? l.modelUsed : mm.status === "scored" ? fill(l.modelLine, { p: Math.round(Number(mm.score) * 100) }) : mm.status === "not_applicable" ? l.modelNa : l.modelNone;
    [
      ["todo", l.reco, recoList[0]],
      ["file", byMode(l, mode, "ident"), [CS.targetLabel(r, false), typeName, sizeTxt].filter(Boolean).join(" · ")],
      ["why", l.whyShort, finds.length ? fill(finds.length === 1 ? l.whyLine1 : l.whyLine, { n: finds.length, s: sevLine }) : byMode(l, mode, "noFindKey")],
      ["layers", l.layTitle, layLine],
      ["ext", l.extTitle, extLine],
      ["model", l.modelTitle, modelLine],
      ["tech", l.techTitle, l.techLine],
    ].forEach(([k, name, line]) => {
      if (k === "layers" && !lay) return;
      const d = el("details", `rx-sec rx-${k}`); d.dataset.sec = k;
      const s = el("summary");
      const tx = el("span", "rx-sec-text");
      tx.append(el("b", "rx-sec-name", name));
      if (line) { const ln = el("span", "rx-sec-line", line); ln.dir = "auto"; tx.append(ln); }
      s.append(tx, el("span", "rx-sec-hint", l.show));
      const body = el("div", "rx-sec-body");
      d.append(s, body);
      d.open = !!openState()[k];
      d.addEventListener("toggle", () => {
        const o = openState(); o[k] = d.open; saveOpen(o);
        s.querySelector(".rx-sec-hint").textContent = d.open ? L().hide : L().show;
        if (d.open) requestAnimationFrame(() => window.dispatchEvent(new Event("resize")));   // curves and grids measure themselves
      });
      if (d.open) s.querySelector(".rx-sec-hint").textContent = l.hide;
      bodies[k] = body;
      secs.append(d);
    });
    rc.append(secs);

    // file details: identity, the severity counts and the entropy curve
    const idc = el("dl", "rc-id");
    // values keep their own direction (a hash, a link) without leaving the column's alignment
    const addId = (k, v, mono) => { if (v == null || v === "") return; const d = el("dd", mono ? "mono" : ""); const b = el("bdi", "", String(v)); b.dir = mono ? "ltr" : "auto"; d.append(b); idc.append(el("dt", "", k), d); return d; };
    const tgt = addId(l.target, CS.targetLabel(r, false), mode === "url");
    if (tgt) tgt.title = String(r.target || "");
    addId(l.type, typeName);
    if (sizeTxt) addId(l.size, sizeTxt);
    if (mode === "file") addId(l.sha, r.sha256, true);
    const when = CS.scanTime(r);
    if (when) addId(l.when, new Intl.DateTimeFormat(CS.lang, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(when)));
    addId(l.status, (r.detection_status && r.detection_status !== "complete") ? l.stPartial : l.stComplete);
    const secs2 = CS.elapsedOf(r);
    if (secs2 != null) addId(l.tlElapsed, `⁦${secs2.toFixed(2)} s⁩`);
    const sevs = el("div", "rc-sevs");
    sevs.append(el("small", "", l.sevCount));
    const strip = el("div", "rc-sev-strip");
    ["critical", "high", "medium", "low", "info"].forEach((k2) => { const c = el("span", `s-${k2}${counts[k2] ? "" : " zero"}`); c.append(el("b", "", String(counts[k2] || 0)), el("span", "", l.sev[k2])); strip.append(c); });
    sevs.append(strip);
    bodies.file.append(idc, sevs);
    // entropy, when the scan measured it (a file; a link or a short text has no meaningful curve)
    const en = r.entropy || {};
    if (mode === "file" && Array.isArray(en.trajectory) && en.trajectory.length > 1) {
      const box = el("div", "rc-entropy");
      box.append(el("h4", "", l.entropy));
      const svgNS = "http://www.w3.org/2000/svg", W = 600, H = 120;
      const svg = document.createElementNS(svgNS, "svg"); svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("aria-hidden", "true");
      const pts = en.trajectory.map((v, i) => [(i / (en.trajectory.length - 1)) * W, H - 6 - (Math.min(8, Number(v)) / 8) * (H - 12)]);
      const d = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
      const area = document.createElementNS(svgNS, "path"); area.setAttribute("d", `${d}L${W},${H}L0,${H}Z`); area.setAttribute("class", "area");
      const line = document.createElementNS(svgNS, "path"); line.setAttribute("d", d); line.setAttribute("class", "line");
      const seven = document.createElementNS(svgNS, "line"); seven.setAttribute("x1", 0); seven.setAttribute("x2", W); const y7 = H - 6 - (7 / 8) * (H - 12); seven.setAttribute("y1", y7); seven.setAttribute("y2", y7); seven.setAttribute("class", "ref");
      svg.append(area, seven, line);
      const stats = el("div", "rc-e-stats");
      [[l.eMean, en.mean], [l.ePeak, en.peak], [l.eJumps, en.anomalies]].forEach(([k2, v]) => { const s = el("span"); s.append(el("b", "", v == null ? "–" : (typeof v === "number" && !Number.isInteger(v) ? v.toFixed(2) : String(v))), el("small", "", k2)); stats.append(s); });
      box.append(svg, stats, el("p", "rc-note", l.eNote));
      bodies.file.append(box);
    }

    // why: every finding, grouped by where it comes from (js/result-plus.js adds the evidence graph before it
    // and the sources after it)
    const why = el("div", "rc-why");
    why.append(el("h4", "rx-sub", l.why), el("p", "rc-note", `${l.whyNote} ${l.scoreNote}`));
    const groups = [["observed", byMode(l, mode, "gObserved"), byMode(l, mode, "gObservedNote")], ["model", l.gModel, l.gModelNote], ["external", l.gExternal, l.gExternalNote]];
    let anyFind = false;
    groups.forEach(([src, gt, gn]) => {
      const list = finds.filter((f) => f.src === src);
      if (!list.length) return;
      anyFind = true;
      const g = el("div", `rc-group g-${src}`);
      g.append((() => { const h = el("h4", "", gt); h.append(el("small", "", ` · ${gn}`)); return h; })());
      const ul = el("ul", "rc-finds");
      const LIMIT = 6;
      list.forEach((f, i) => {
        const li = el("li", `rc-f s-${f.sev}`); if (i >= LIMIT) li.hidden = true;
        const ftop = el("div", "rc-f-top");
        const tt = el("b", "", f.title + (f.count > 1 ? ` ×${f.count}` : "")); tt.dir = "auto";
        ftop.append(el("span", "rc-sev", l.sev[f.sev] || f.sev), tt);
        if (f.contrib) ftop.append(el("span", "rc-contrib x-only", `+${f.contrib}`));
        li.append(ftop);
        if (f.text && f.text.trim().toLowerCase() !== String(f.title).trim().toLowerCase()) { const p = el("p", "", f.text); p.dir = "auto"; li.append(p); }   // skip an explanation that only repeats the title
        if (f.where) { const c = el("span", "rc-cat", f.where); c.dir = "auto"; li.append(c); }
        ul.append(li);
      });
      g.append(ul);
      if (list.length > LIMIT) {
        const more = el("button", "ghost small rc-more", fill(l.showAll, { n: list.length })); more.type = "button";
        more.addEventListener("click", () => { const open = more.dataset.open === "1"; ul.querySelectorAll("li").forEach((x, i) => { if (i >= LIMIT) x.hidden = open; }); more.dataset.open = open ? "" : "1"; more.textContent = open ? fill(l.showAll, { n: list.length }) : l.showLess; });
        g.append(more);
      }
      why.append(g);
    });
    if (!anyFind) why.append(el("p", "rc-none", l.noFind));
    bodies.why.append(why);

    // what to do, and the limits (js/scan-pro.js adds the repair card after it)
    const reco = el("div", "rc-reco");
    const ol = el("ol"); recoList.forEach((x) => ol.append(el("li", "", x)));
    reco.append(ol);
    const limits = CS.limitsLabel(r);
    if (limits) { const lim = el("details", "rc-limits"); lim.append(el("summary", "", l.limits)); const p = el("p", "", limits); p.dir = "auto"; lim.append(p); reco.append(lim); }
    bodies.todo.append(reco);

    // the machine-learning model: an input to the verdict, never a second score
    const conf = el("div", "rc-conf");
    conf.append(el("p", "rx-input-note", l.modelInput));
    if (hasModel) {
      const bars = el("div", "rc-conf-bars");
      Object.entries(cs).forEach(([k2, v]) => { const row = el("div", "rc-cb"); const b = el("span", "rc-cb-bar"); const f = el("i"); f.style.width = `${Math.min(100, Number(v))}%`; b.append(f); row.append(el("span", "", k2), b, el("span", "", `${Number(v).toFixed(1)}%`)); bars.append(row); });
      conf.append(bars, el("p", "rc-note", l.confNote));
      if (pred.abstained) conf.append(el("p", "rc-note", l.confAbst));
    } else if (mm.status === "scored") {
      // the EMBER2024 model (trained on millions of Windows programs and PDFs): its view of this file
      const pct = Math.round(Number(mm.score) * 100);
      const bars = el("div", "rc-conf-bars"), row = el("div", "rc-cb"), b = el("span", "rc-cb-bar"), f = el("i");
      f.style.width = `${Math.min(100, pct)}%`; b.append(f);
      row.append(el("span", "", l.confMl), b, el("span", "", `${pct}%`)); bars.append(row);
      conf.append(bars, el("p", "rc-note", l.confMlNote));
    } else if (mm.status === "not_applicable") conf.append(el("p", "rc-conf-none", l.confMlNa));
    else conf.append(el("p", "rc-conf-none", l.confNone));
    bodies.model.append(conf);

    // the technical analysis (the existing tabs)
    techHead.replaceChildren(el("p", "rc-note", l.techNote));
    bodies.tech.append(techHead);
    if (techCard) bodies.tech.append(techCard);
    if (limitsP) bodies.tech.append(limitsP);

    // other modules (js/scan-pro.js, external-intel.js, result-plus.js, layers.js, journey-hook.js) add theirs now
    window.dispatchEvent(new CustomEvent("cs:rc-built", { detail: { rc, result: r, cls, findings: finds } }));
    arrange();

    // motion: the score counts and its marker travels; sections arrive in turn
    if (animate && !reduced()) {
      const tStart = performance.now();
      const run = (now) => { const k = Math.min(1, (now - tStart) / 1200), e = 1 - Math.pow(1 - k, 3); num.textContent = Math.round(score * e); mark.style.insetInlineStart = `${score * e}%`; if (k < 1) requestAnimationFrame(run); };
      requestAnimationFrame(run);
      [...rc.children].forEach((c, i) => c.animate([{ opacity: 0, transform: "translateY(16px)" }, { opacity: 1, transform: "none" }], { duration: 560, delay: i * 90, easing: "cubic-bezier(.22,1,.36,1)", fill: "backwards" }));
    } else { num.textContent = score; mark.style.insetInlineStart = `${score}%`; }
  }

  /* where the other modules' pieces belong in the new layout (they insert themselves next to the
   * classic anchors; this moves each into its place, now and whenever one re-renders) */
  function sec(k) { return rc.querySelector(`.rx-sec[data-sec="${k}"] > .rx-sec-body`); }
  function arrange() {
    if (arranging) return;
    arranging = true;
    try {
      const sum = rc.querySelector(".rx-verdict");
      if (!sum) return;
      // the summary written for the reader joins the verdict card
      const ai = rc.querySelector(":scope > .lz-ai");
      if (ai) { ai.classList.add("rx-embed"); ai.classList.remove("card"); sum.append(ai); }
      // ask, share and the journey go in the More menu
      const menu = rc.querySelector("#rx-menu");
      if (menu) {
        const extra = rc.querySelector(".rx-actions ~ .rp-actions, :scope > .rp-actions");
        if (extra) { menu.prepend(...extra.children); extra.remove(); }
        const jr = rc.querySelector(".rc-journey");
        if (jr && jr.parentElement !== menu) menu.append(jr);
        if (jr) { const hint = jr.querySelector("small"); if (hint) hint.hidden = true; }
        // "Check something else" has its own button now
        const againTxt = CS.t("again");
        actions.querySelectorAll("button").forEach((b) => { if (b.textContent.trim() === againTxt) b.hidden = true; });
        menu.querySelectorAll("button, a").forEach((b) => { b.classList.add("rx-mi"); });
      }
      const put = (k, sel) => { const body = sec(k); if (!body) return; rc.querySelectorAll(sel).forEach((n) => { if (!body.contains(n)) body.append(n); }); };
      put("layers", ":scope > .lz-card, .rx-verdict ~ .lz-card");
      const extBody = sec("ext");
      if (extBody) {
        rc.querySelectorAll(".sp-intel").forEach((n) => { if (n.parentElement !== extBody) extBody.prepend(n); });
        rc.querySelectorAll(".ext-card").forEach((n) => { if (n.parentElement !== extBody) extBody.append(n); });
      }
      // the explanation level (js/result-plus.js) is one switch for all the details
      const seg = rc.querySelector(".rp-why .rp-seg");
      const sh = rc.querySelector(".rx-secs-head");
      if (seg && sh) sh.append(seg);
      // the pieces from other modules are sections inside a section now: no card inside a card
      rc.querySelectorAll(".rx-sec-body .card").forEach((c) => c.classList.add("rx-inner"));
      // a section with nothing in it is not shown
      rc.querySelectorAll(".rx-sec").forEach((d) => { d.hidden = !d.querySelector(".rx-sec-body").childElementCount; });
    } finally { arranging = false; }
  }
  let arranging = false, arrangeRaf = 0;
  new MutationObserver(() => { if (arranging || arrangeRaf) return; arrangeRaf = requestAnimationFrame(() => { arrangeRaf = 0; arrange(); }); }).observe(rc, { childList: true, subtree: false });

  // the More menu: a disclosure button and a list of buttons (arrows move, Escape closes)
  function wireMenu(btn, menu) {
    const visible = () => [...menu.querySelectorAll("button, a[href]")].filter((b) => b.offsetParent !== null);
    const close = (focus) => { if (menu.hidden) return; menu.hidden = true; btn.setAttribute("aria-expanded", "false"); if (focus) btn.focus(); };
    const open = (first) => { menu.hidden = false; btn.setAttribute("aria-expanded", "true"); const v = visible(); if (first && v.length) v[0].focus(); };
    btn.addEventListener("click", () => (menu.hidden ? open(false) : close(false)));
    btn.addEventListener("keydown", (e) => { if (e.key === "ArrowDown") { e.preventDefault(); open(true); } });
    menu.addEventListener("keydown", (e) => {
      const v = visible(), i = v.indexOf(document.activeElement);
      if (e.key === "Escape") { e.preventDefault(); close(true); }
      else if (e.key === "ArrowDown") { e.preventDefault(); (v[i + 1] || v[0]).focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); (v[i - 1] || v[v.length - 1]).focus(); }
      else if (e.key === "Home") { e.preventDefault(); v[0] && v[0].focus(); }
      else if (e.key === "End") { e.preventDefault(); v[v.length - 1] && v[v.length - 1].focus(); }
    });
    // a choice closes the menu (dialogs it opens take the focus themselves)
    menu.addEventListener("click", (e) => { if (e.target.closest("button, a")) setTimeout(() => close(false), 0); });
    document.addEventListener("click", (e) => { if (!menu.hidden && !menu.parentElement.contains(e.target)) close(false); });
    menu.parentElement.addEventListener("focusout", (e) => { if (!menu.hidden && e.relatedTarget && !menu.parentElement.contains(e.relatedTarget)) close(false); });
  }
  // which detail sections are open, remembered in this browser
  const OPEN_KEY = "cs-result-open";
  function openState() { try { return JSON.parse(localStorage.getItem(OPEN_KEY) || "{}") || {}; } catch { return {}; } }
  function saveOpen(o) { try { localStorage.setItem(OPEN_KEY, JSON.stringify(o)); } catch { /* storage off */ } }
  function openSection(k, scroll) {
    const d = rc.querySelector(`.rx-sec[data-sec="${k}"]`);
    if (!d) return;
    d.open = true;
    if (scroll) { d.scrollIntoView({ block: "start", behavior: reduced() ? "auto" : "smooth" }); d.querySelector("summary").focus({ preventScroll: true }); }
  }

  window.addEventListener("cs:result", (e) => { const { result, animate } = e.detail || {}; if (result) render(result, animate); });
  CS.onLang(() => { paintFormats(); paintOpts(); if (CS.state && CS.state.lastResult && !resultSec.hidden) render(CS.state.lastResult, false); if (infoFor) showFile(infoFor); });

  /* ================================================================ 4. the report */
  /* The report page gets the result and everything already worked out here, in the user's
   * language: the one score and verdict, the findings, the engines' states, the scan's time. */
  function openReport(r) {
    const key = `cs-report-${Date.now()}`;
    const v = CS.verdictOf(r);
    const checks = CS.checksByEngine(r);
    const view = {
      score: v.score, cls: v.cls, mode: CS.modeOf(r),
      target: CS.targetLabel(r, true), type: CS.typeLabel(CS.modeOf(r) === "file" ? ((r.content_analysis && r.content_analysis.file_type) || "file") : CS.modeOf(r)),
      scanned: CS.scanTime(r), elapsed: CS.elapsedOf(r), limits: CS.limitsLabel(r),
      engines: Object.entries(r.engines || {}).map(([name, status]) => [checks.has(name) ? checks.get(name).name : CS.engineName(name), CS.engineText(r, name, status, checks)]),
      mitre: CS.mitreOf(r).map((m) => [m.id, m.name || ""]),
      host: location.hostname && !/^(127\.|localhost$|\[?::1)/.test(location.hostname) ? location.host : "",
    };
    try {
      // keep only the latest few reports in this browser
      Object.keys(localStorage).filter((k) => k.startsWith("cs-report-")).sort().slice(0, -4).forEach((k) => localStorage.removeItem(k));
      // only what the report prints: the 3D structure, the plain texts and raw outputs can be megabytes
      const slim = { ...r, structure: undefined, plain: undefined, report_text: undefined, intel: undefined,
        entropy: r.entropy ? { mean: r.entropy.mean, peak: r.entropy.peak, anomalies: r.entropy.anomalies } : undefined,
        content_analysis: r.content_analysis ? { file_type: r.content_analysis.file_type, score: r.content_analysis.score } : undefined };
      localStorage.setItem(key, JSON.stringify({ result: slim, lang: CS.lang, generated: new Date().toISOString(), findings: collect(r), view }));
    } catch { CS.toast && CS.toast(CS.lang === "ar" ? "مساحة التخزين ممتلئة أو معطّلة: تعذّر إعداد التقرير." : "Storage is full or disabled: the report can't be prepared."); return; }
    window.open(`report.html#${key}`, "_blank", "noopener");
  }

  /* ================================================================ 5. phones: four views and "More"
   * Six views don't fit a phone's width with readable labels: Scan, Protection, Toolbox and History stay,
   * with short labels; Repair and Settings move into a "More" menu. Wider screens keep the full sidebar. */
  (function phoneNav() {
    const nav = document.querySelector("#app .nav");
    if (!nav || nav.querySelector(".nav-more-wrap")) return;
    const SHORT = { en: { scan: "Scan", tools: "Protection", toolbox: "Toolbox", history: "History", more: "More" },
      ar: { scan: "فحص", tools: "الحماية", toolbox: "الأدوات", history: "السجل", more: "المزيد" } };
    const sh = () => SHORT[CS.lang === "ar" ? "ar" : "en"];
    const views = [...nav.querySelectorAll(".nav-btn[data-view]")];
    views.forEach((b) => {
      const long = b.querySelector("span[data-i18n]");
      if (long) long.classList.add("nav-long");
      if (SHORT.en[b.dataset.view]) { const s2 = el("span", "nav-short"); s2.dataset.k = b.dataset.view; b.append(s2); }
    });
    const moved = views.filter((b) => b.dataset.view === "repair" || b.dataset.view === "settings");
    const wrap = el("div", "nav-more-wrap");
    const btn = el("button", "nav-btn nav-more"); btn.type = "button";
    btn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5.5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18.5" cy="12" r="1.6"/></svg>';
    const bl = el("span", "nav-short"); bl.dataset.k = "more"; btn.append(bl);
    const menu = el("div", "nav-more-menu"); menu.id = "nav-more-menu"; menu.hidden = true;
    btn.setAttribute("aria-expanded", "false"); btn.setAttribute("aria-controls", "nav-more-menu");
    const links = moved.map((b) => {
      const a = el("a"); a.href = b.getAttribute("href"); a.dataset.view = b.dataset.view;
      const ic = b.querySelector("svg"); if (ic) a.append(ic.cloneNode(true));
      a.append(el("span", "nav-more-label"));
      menu.append(a);
      return a;
    });
    wrap.append(btn, menu);
    const ink = nav.querySelector(".nav-ink");
    if (ink) ink.before(wrap); else nav.append(wrap);
    const paint = () => {
      const t2 = sh();
      nav.querySelectorAll(".nav-short").forEach((x) => { x.textContent = t2[x.dataset.k] || ""; });
      links.forEach((a, i) => { const long = moved[i].querySelector(".nav-long"); a.querySelector(".nav-more-label").textContent = long ? long.textContent : a.dataset.view; });
      btn.setAttribute("aria-label", t2.more);
    };
    const mark = () => {
      const v = (location.hash.match(/^#\/(\w+)/) || [])[1] || "";
      btn.classList.toggle("active-in", v === "repair" || v === "settings");
      links.forEach((a) => { if (a.dataset.view === v) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    };
    const close = (focus) => { if (menu.hidden) return; menu.hidden = true; btn.setAttribute("aria-expanded", "false"); if (focus) btn.focus(); };
    btn.addEventListener("click", () => { if (menu.hidden) { menu.hidden = false; btn.setAttribute("aria-expanded", "true"); } else close(false); });
    btn.addEventListener("keydown", (e) => { if (e.key === "ArrowDown") { e.preventDefault(); menu.hidden = false; btn.setAttribute("aria-expanded", "true"); links[0].focus(); } });
    menu.addEventListener("keydown", (e) => {
      const i = links.indexOf(document.activeElement);
      if (e.key === "Escape") { e.preventDefault(); close(true); }
      else if (e.key === "ArrowDown") { e.preventDefault(); (links[i + 1] || links[0]).focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); (links[i - 1] || links[links.length - 1]).focus(); }
    });
    menu.addEventListener("click", (e) => { if (e.target.closest("a")) close(false); });
    document.addEventListener("click", (e) => { if (!wrap.contains(e.target)) close(false); });
    wrap.addEventListener("focusout", (e) => { if (e.relatedTarget && !wrap.contains(e.relatedTarget)) close(false); });
    window.addEventListener("hashchange", mark);
    CS.onLang(() => requestAnimationFrame(paint));
    paint(); mark();
  })();

  /* settings arrive after start-up: repaint what depends on them */
  let lastSettings = null;
  const watchSettings = () => { if (CS.settings && CS.settings !== lastSettings) { lastSettings = CS.settings; paintFormats(); paintOpts(); } };
  setInterval(watchSettings, 1000);
  paintFormats(); paintOpts();
})();
