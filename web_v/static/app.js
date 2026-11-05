"use strict";

const TOKEN = document.querySelector('meta[name="cyberscan-token"]').content;
const $ = (id) => document.getElementById(id);

/* ---------------- translations ---------------- */
const I18N = {
  en: {
    switchLang: "العربية",
    title: "Check a file, link or text",
    lede: "Static analysis only. Nothing you check is ever run.",
    tabFile: "File", tabUrl: "Link", tabText: "Text",
    dropTitle: "Drop a file here or click to choose",
    dropHint: "Up to 50 MB · read locally, deleted after the check",
    urlPh: "https://example.com/download",
    textPh: "Paste a script, an email or a command…",
    scan: "Start check", working: "Checking…",
    s0: "Reading the target", s1: "Measuring structure",
    s2: "Comparing with known patterns", s3: "Public threat lookups",
    again: "Check something else", copy: "Copy report", copied: "Copied ✓",
    evidence: "What we found", entropy: "Byte randomness across the file",
    mean: "Average", peak: "Peak", jumps: "Sudden jumps", engines: "Engines",
    noEvidence: "No warning signs", noEvidenceBody: "None of the checks raised anything.",
    noEntropy: "Not measured for this input.",
    verdicts: {
      NO_INDICATORS_OBSERVED: ["CLEAR", "No warning signs found",
        "The checks we ran found nothing concerning. This is not a guarantee, only that nothing stood out."],
      REVIEW: ["REVIEW", "Worth a closer look",
        "A few things stood out. They are often harmless, but read the findings before you trust it."],
      SUSPICIOUS: ["SUSPICIOUS", "This looks suspicious",
        "Several strong warning signs. Don't open or run it unless you know exactly where it came from."],
    },
    sev: { high: "High", medium: "Medium", low: "Low", info: "Info" },
    failed: "The check could not finish: ",
    network: "Lost contact with the local scanner.",
    navScan: "Scan", navHistory: "History", navSettings: "Settings",
    historyTitle: "Your scans", searchPh: "Search by name or link",
    fAll: "All", fBad: "Suspicious", fReview: "Review", fClear: "Clear",
    count: (n) => `${n} saved`,
    groups: { today: "Today", yesterday: "Yesterday", week: "This week", earlier: "Earlier" },
    emptyHistory: "Nothing here yet. Scans you run will appear here.",
    noMatch: "No scans match.",
    delTitle: "Remove this scan?", delBody: (name) => `“${name}” and its saved report will be removed. The scanned file itself is not touched.`,
    cancel: "Cancel", remove: "Remove", removed: "Scan removed", delete: "Remove",
    scannedAt: (d) => `Checked ${d}`, reportGone: "That saved report can no longer be opened.",
    settingsTitle: "Settings",
    settingsLede: "Changes save on their own and apply to your next check. The desktop app uses the same settings.",
    grpChecks: "What to check", grpOnline: "Online", grpDisplay: "Display", grpLimits: "Limits",
    setEntropy: "Check how scrambled the content is", setEntropyHint: "Packed or encrypted parts look random.",
    setHeur: "Look for common warning signs", setHeurHint: "Known tricks used by harmful files and links.",
    setMl: "Use the learning model, if one is installed", setMlHint: "Its scores are not calibrated yet.",
    setOsint: "Look the result up in public threat lists", setOsintHint: "Sends only a fingerprint or the link, never the file itself.",
    setLarge: "Larger text", setAnim: "Moving background",
    setSize: "Largest file to check", setTime: "Give up after",
    mb: (n) => `${n} MB`, sec: (n) => `${n} seconds`,
    saving: "Saving…", saved: "Saved", saveFailed: "Couldn't save: ",
    tooBig: (n) => `This file is larger than the ${n} MB limit set in Settings.`,
  },
  ar: {
    switchLang: "English",
    title: "افحص ملفًا أو رابطًا أو نصًا",
    lede: "تحليل ثابت فقط. لا يتم تشغيل أي شيء تفحصه.",
    tabFile: "ملف", tabUrl: "رابط", tabText: "نص",
    dropTitle: "اسحب ملفًا هنا أو انقر للاختيار",
    dropHint: "حتى 50 ميغابايت · يُقرأ محليًا ويُحذف بعد الفحص",
    urlPh: "https://example.com/download",
    textPh: "الصق سكربتًا أو رسالة بريد أو أمرًا…",
    scan: "ابدأ الفحص", working: "جارٍ الفحص…",
    s0: "قراءة الهدف", s1: "قياس البنية",
    s2: "المقارنة بالأنماط المعروفة", s3: "البحث في مصادر التهديد العامة",
    again: "افحص شيئًا آخر", copy: "نسخ التقرير", copied: "تم النسخ ✓",
    evidence: "ما وجدناه", entropy: "عشوائية البايتات عبر الملف",
    mean: "المتوسط", peak: "الذروة", jumps: "قفزات مفاجئة", engines: "المحركات",
    noEvidence: "لا توجد علامات تحذير", noEvidenceBody: "لم يُظهر أي فحص شيئًا مقلقًا.",
    noEntropy: "لم يُقَس لهذا النوع من المدخلات.",
    verdicts: {
      NO_INDICATORS_OBSERVED: ["سليم", "لم نجد علامات تحذير",
        "لم تُظهر الفحوصات شيئًا مقلقًا. هذا ليس ضمانًا، لكن لم يبرز أي شيء."],
      REVIEW: ["للمراجعة", "يستحق نظرة أدق",
        "برزت بعض الأمور. غالبًا ما تكون غير ضارة، لكن اقرأ النتائج قبل أن تثق به."],
      SUSPICIOUS: ["مشبوه", "يبدو هذا مشبوهًا",
        "عدة علامات تحذير قوية. لا تفتحه أو تشغّله إلا إذا كنت تعرف مصدره بالضبط."],
    },
    sev: { high: "عالية", medium: "متوسطة", low: "منخفضة", info: "معلومة" },
    failed: "تعذّر إكمال الفحص: ",
    network: "انقطع الاتصال بالماسح المحلي.",
    navScan: "فحص", navHistory: "السجل", navSettings: "الإعدادات",
    historyTitle: "فحوصاتك", searchPh: "ابحث بالاسم أو الرابط",
    fAll: "الكل", fBad: "مشبوه", fReview: "للمراجعة", fClear: "سليم",
    count: (n) => `${n} محفوظ`,
    groups: { today: "اليوم", yesterday: "أمس", week: "هذا الأسبوع", earlier: "أقدم" },
    emptyHistory: "لا يوجد شيء بعد. ستظهر هنا الفحوصات التي تجريها.",
    noMatch: "لا توجد فحوصات مطابقة.",
    delTitle: "حذف هذا الفحص؟", delBody: (name) => `سيُحذف «${name}» وتقريره المحفوظ. الملف المفحوص نفسه لن يُمس.`,
    cancel: "إلغاء", remove: "حذف", removed: "تم حذف الفحص", delete: "حذف",
    scannedAt: (d) => `فُحص ${d}`, reportGone: "لم يعد بالإمكان فتح هذا التقرير المحفوظ.",
    settingsTitle: "الإعدادات",
    settingsLede: "تُحفظ التغييرات تلقائيًا وتُطبَّق على الفحص التالي. تطبيق سطح المكتب يستخدم الإعدادات نفسها.",
    grpChecks: "ما الذي نفحصه", grpOnline: "عبر الإنترنت", grpDisplay: "العرض", grpLimits: "الحدود",
    setEntropy: "فحص مدى عشوائية المحتوى", setEntropyHint: "الأجزاء المضغوطة أو المشفّرة تبدو عشوائية.",
    setHeur: "البحث عن علامات التحذير الشائعة", setHeurHint: "حيل معروفة تستخدمها الملفات والروابط الضارة.",
    setMl: "استخدام نموذج التعلّم إن كان مثبتًا", setMlHint: "درجاته غير معايَرة بعد.",
    setOsint: "البحث عن النتيجة في قوائم التهديد العامة", setOsintHint: "يُرسل البصمة أو الرابط فقط، وليس الملف نفسه أبدًا.",
    setLarge: "نص أكبر", setAnim: "خلفية متحركة",
    setSize: "أكبر حجم ملف للفحص", setTime: "التوقف بعد",
    mb: (n) => `${n} ميغابايت`, sec: (n) => `${n} ثانية`,
    saving: "جارٍ الحفظ…", saved: "تم الحفظ", saveFailed: "تعذّر الحفظ: ",
    tooBig: (n) => `هذا الملف أكبر من حد ${n} ميغابايت المحدد في الإعدادات.`,
  },
};

let lang = "en";
try { lang = localStorage.getItem("cyberscan-lang") === "ar" ? "ar" : "en"; } catch { /* storage off */ }
const t = (key) => I18N[lang][key];

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    if (el.id === "drop-label" && state.file) return;
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  requestAnimationFrame(() => { moveInk(); moveNavInk(); });
  if (state.lastResult && !$("result").hidden) renderResult(state.lastResult, false);
  if (state.view === "history" && state.history) renderHistory(false);
  if (state.settings) renderSettings();
}

/* ---------------- state ---------------- */
const state = {
  mode: "file", file: null, lastResult: null, polling: null,
  view: "scan", history: null, filter: "all", settings: null,
};

/* ---------------- tabs ---------------- */
const tabs = [...document.querySelectorAll(".tab")];
const ink = document.querySelector(".tab-ink");
function moveInk() {
  const active = document.querySelector(".tab.active");
  const box = active.parentElement.getBoundingClientRect();
  const r = active.getBoundingClientRect();
  ink.style.width = `${r.width}px`;
  ink.style.transform = `translateX(${r.left - box.left}px)`;
}
tabs.forEach((tab) => tab.addEventListener("click", () => {
  state.mode = tab.dataset.mode;
  tabs.forEach((x) => { x.classList.toggle("active", x === tab); x.setAttribute("aria-selected", x === tab); });
  document.querySelectorAll("[data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== state.mode; });
  moveInk();
  updateReady();
  const field = document.querySelector(`[data-panel="${state.mode}"]`);
  if (field.matches("input, textarea")) field.focus();
}));
window.addEventListener("resize", moveInk);

/* ---------------- inputs ---------------- */
const drop = $("drop");
function chooseFile(file) {
  if (!file) return;
  state.file = file;
  drop.classList.add("chosen");
  $("drop-label").textContent = `${file.name} · ${formatBytes(file.size)}`;
  updateReady();
}
$("file").addEventListener("change", (e) => chooseFile(e.target.files[0]));
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => chooseFile(e.dataTransfer.files[0]));
$("url").addEventListener("input", updateReady);
$("text").addEventListener("input", updateReady);

function updateReady() {
  const ready = state.mode === "file" ? !!state.file
    : state.mode === "url" ? $("url").value.trim().length > 3
    : $("text").value.trim().length > 0;
  $("go").disabled = !ready;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

/* ---------------- API ---------------- */
async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "X-CyberScan-Token": TOKEN, ...(options.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if ($("go").disabled) return;
  const limit = state.settings?.maximum_file_size;
  if (state.mode === "file" && limit && state.file.size > limit) {
    showError(t("tooBig")(Math.round(limit / 1048576)));
    return;
  }
  showProgress();
  try {
    let job;
    if (state.mode === "file") {
      job = await api("/api/scan/file", {
        method: "POST",
        headers: { "X-Filename": encodeURIComponent(state.file.name), "Content-Type": "application/octet-stream" },
        body: state.file,
      });
    } else {
      const value = $(state.mode).value;
      job = await api("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: state.mode, value }),
      });
    }
    poll(job.id);
  } catch (err) {
    showError(err.message);
  }
});

function poll(id) {
  clearTimeout(state.polling);
  api(`/api/scan/${id}`).then((job) => {
    renderStages(job.stages);
    if (job.status === "running") { state.polling = setTimeout(() => poll(id), 250); return; }
    if (job.status === "failed") { showError(job.error); return; }
    renderStages(job.stages.map((s) => ({ ...s, state: "complete" })));
    state.history = null; // a new scan was saved; reload the list next time
    setTimeout(() => { state.lastResult = job.result; renderResult(job.result, true); }, 450);
  }).catch(() => showError(t("network")));
}

/* ---------------- views ---------------- */
function showProgress() {
  $("error").hidden = true;
  $("result").hidden = true;
  $("progress").hidden = false;
  restartAnim($("progress"));
  renderStages([]);
  $("stage-detail").textContent = "";
  $("go").disabled = true;
}

function showError(message) {
  $("progress").hidden = true;
  $("error").hidden = false;
  $("error").textContent = t("failed") + message;
  restartAnim($("error"));
  updateReady();
}

function renderStages(stages) {
  const items = [...document.querySelectorAll(".stages li")];
  items.forEach((li, i) => {
    li.classList.remove("running", "complete");
    const s = stages[i];
    if (s && s.state !== "pending") li.classList.add(s.state);
  });
  const current = [...stages].reverse().find((s) => s.detail);
  if (current) $("stage-detail").textContent = current.detail;
}

const RISK_COLOR = { NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad" };
const SEV_COLOR = { high: "--bad", critical: "--bad", medium: "--warn", low: "--accent", info: "--muted" };

function renderResult(r, animate) {
  document.querySelector(".composer").hidden = true;
  $("progress").hidden = true;
  $("error").hidden = true;
  const view = $("result");
  view.hidden = false;
  if (animate) view.querySelectorAll(".card").forEach(restartAnim);

  const [badge, title, body] = t("verdicts")[r.classification] || [r.classification, r.classification, r.summary];
  document.documentElement.style.setProperty("--risk", `var(${RISK_COLOR[r.classification] || "--accent"})`);
  $("badge").textContent = badge;
  $("verdict-title").textContent = title;
  $("verdict-body").textContent = body;
  $("target").textContent = r.target;
  $("when").hidden = !r.timestamp;
  if (r.timestamp) $("when").textContent = t("scannedAt")(formatWhen(r.timestamp, true));
  $("gauge").setAttribute("aria-label", `${r.combined_score} / 100`);
  $("limits").textContent = r.limitations;

  const meter = $("meter");
  const circumference = 326.73;
  const offset = circumference * (1 - r.combined_score / 100);
  if (animate) {
    meter.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => requestAnimationFrame(() => { meter.style.strokeDashoffset = offset; }));
    countUp($("score"), r.combined_score, 1600);
  } else {
    meter.style.strokeDashoffset = offset;
    $("score").textContent = r.combined_score;
  }

  const list = $("evidence");
  list.replaceChildren();
  const items = [...r.evidence].sort((a, b) => b.contribution - a.contribution);
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.append(strong(t("noEvidence")), span(t("noEvidenceBody")));
    list.append(li);
  }
  items.forEach((f, i) => {
    const li = document.createElement("li");
    const sev = String(f.severity).toLowerCase();
    li.style.setProperty("--sev", `var(${SEV_COLOR[sev] || "--muted"})`);
    li.style.setProperty("--d", animate ? `${0.25 + i * 0.07}s` : "0s");
    li.title = `${t("sev")[sev] || sev} · +${f.contribution}`;
    li.append(strong(f.evidence));
    if (f.explanation && f.explanation.trim() !== String(f.evidence).trim()) li.append(span(f.explanation));
    list.append(li);
  });

  drawSpark(r.entropy, animate);

  const engines = $("engines");
  engines.replaceChildren();
  Object.entries(r.engines || {}).forEach(([name, status]) => {
    const li = document.createElement("li");
    const b = document.createElement("b");
    b.textContent = name;
    li.append(b, ` ${status}`);
    engines.append(li);
  });
}

function drawSpark(entropy, animate) {
  const line = $("spark-line"), fill = $("spark-fill");
  const pts = entropy.trajectory || [];
  $("e-mean").textContent = pts.length ? entropy.mean.toFixed(2) : "–";
  $("e-peak").textContent = pts.length ? entropy.peak.toFixed(2) : "–";
  $("e-jumps").textContent = pts.length ? entropy.anomalies : "–";
  if (pts.length < 2) { line.setAttribute("d", ""); fill.setAttribute("d", ""); $("spark").setAttribute("aria-label", t("noEntropy")); return; }
  const W = 300, H = 90;
  const coords = pts.map((v, i) => [(i / (pts.length - 1)) * W, H - 4 - (Math.min(v, 8) / 8) * (H - 8)]);
  const d = coords.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  line.setAttribute("d", d);
  fill.setAttribute("d", `${d}L${W},${H}L0,${H}Z`);
  // pathLength=1 keeps the dash maths right despite non-scaling-stroke.
  line.setAttribute("pathLength", "1");
  line.style.strokeDasharray = 1;
  line.style.strokeDashoffset = animate ? 1 : 0;
  line.classList.remove("drawing");
  fill.classList.remove("on");
  if (animate) { void line.getBoundingClientRect(); line.classList.add("drawing"); }
  requestAnimationFrame(() => fill.classList.add("on"));
}

function countUp(el, target, ms) {
  const start = performance.now();
  const step = (now) => {
    const p = Math.min((now - start) / ms, 1);
    el.textContent = Math.round(target * (1 - Math.pow(1 - p, 4)));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function restartAnim(el) { el.style.animation = "none"; void el.offsetWidth; el.style.animation = ""; }
function strong(text) { const s = document.createElement("strong"); s.textContent = text; return s; }
function span(text) { const s = document.createElement("span"); s.textContent = text; return s; }

/* ---------------- actions ---------------- */
$("again").addEventListener("click", () => {
  state.lastResult = null;
  $("result").hidden = true;
  const composer = document.querySelector(".composer");
  composer.hidden = false;
  restartAnim(composer);
  requestAnimationFrame(moveInk);
  updateReady();
});

$("copy").addEventListener("click", async () => {
  if (!state.lastResult) return;
  try {
    await navigator.clipboard.writeText(state.lastResult.report_text);
    $("copy").textContent = t("copied");
    setTimeout(() => { $("copy").textContent = t("copy"); }, 1600);
  } catch { /* clipboard blocked */ }
});

$("lang").addEventListener("click", () => {
  lang = lang === "en" ? "ar" : "en";
  try { localStorage.setItem("cyberscan-lang", lang); } catch { /* storage off */ }
  applyLang();
});

/* ---------------- navigation ---------------- */
const navButtons = [...document.querySelectorAll(".nav-btn")];
const navInk = document.querySelector(".nav-ink");
function moveNavInk() {
  const active = document.querySelector(".nav-btn.active");
  const box = active.parentElement.getBoundingClientRect();
  const r = active.getBoundingClientRect();
  navInk.style.width = `${r.width}px`;
  navInk.style.transform = `translateX(${r.left - box.left}px)`;
}
window.addEventListener("resize", moveNavInk);

function go(view) {
  state.view = view;
  navButtons.forEach((b) => {
    const on = b.dataset.view === view;
    b.classList.toggle("active", on);
    if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach((v) => {
    const on = v.id === `view-${view}`;
    v.hidden = !on;
    if (on) { v.classList.remove("entering"); void v.offsetWidth; v.classList.add("entering"); }
  });
  moveNavInk();
  if (view === "scan") requestAnimationFrame(moveInk);
  if (view === "history") loadHistory();
  if (view === "settings") loadSettings();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
navButtons.forEach((b) => b.addEventListener("click", () => go(b.dataset.view)));

/* ---------------- history ---------------- */
const TRASH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>';

function formatWhen(iso, full) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const locale = lang === "ar" ? "ar" : "en";
  return new Intl.DateTimeFormat(locale, full
    ? { dateStyle: "medium", timeStyle: "short" }
    : { hour: "2-digit", minute: "2-digit" }).format(d);
}

function groupOf(iso) {
  const d = new Date(iso);
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const days = Math.floor((today - new Date(d.getFullYear(), d.getMonth(), d.getDate())) / 86400000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 7) return "week";
  return "earlier";
}

async function loadHistory() {
  if (state.history) { renderHistory(true); return; }
  const list = $("history-list");
  list.replaceChildren(...Array.from({ length: 5 }, () => Object.assign(document.createElement("div"), { className: "skeleton" })));
  try {
    state.history = await api("/api/history");
    renderHistory(true);
  } catch (err) {
    list.replaceChildren(Object.assign(document.createElement("p"), { className: "empty-state", textContent: t("network") }));
  }
}

function renderHistory(animate) {
  const list = $("history-list");
  const query = $("history-search").value.trim().toLowerCase();
  const all = state.history || [];
  const rows = all.filter((r) =>
    (state.filter === "all" || r.classification === state.filter) &&
    (!query || r.target.toLowerCase().includes(query)));
  $("history-count").textContent = all.length ? t("count")(all.length) : "";
  list.replaceChildren();
  if (!rows.length) {
    list.append(Object.assign(document.createElement("p"), { className: "empty-state", textContent: all.length ? t("noMatch") : t("emptyHistory") }));
    return;
  }
  let lastGroup = null;
  rows.forEach((r, i) => {
    const g = groupOf(r.timestamp);
    if (g !== lastGroup) {
      lastGroup = g;
      list.append(Object.assign(document.createElement("div"), { className: "group-label", textContent: t("groups")[g] }));
    }
    list.append(historyRow(r, animate ? Math.min(i, 14) * 0.035 : 0));
  });
}

function historyRow(r, delay) {
  const row = document.createElement("div");
  row.className = "row";
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.style.setProperty("--c", `var(${RISK_COLOR[r.classification] || "--muted"})`);
  row.style.setProperty("--d", `${delay}s`);

  const mini = document.createElement("div");
  mini.className = "mini";
  mini.style.setProperty("--p", Math.max(3, r.score));
  mini.append(span(String(r.score)));

  const main = document.createElement("div");
  main.className = "row-main";
  const name = r.target.split(/[\\/]/).filter(Boolean).pop() || r.target;
  const title = strong(r.target.startsWith("http") ? r.target : name);
  title.title = r.target;
  const when = document.createElement("small");
  when.textContent = formatWhen(r.timestamp, groupOf(r.timestamp) !== "today");
  main.append(title, when);

  const tag = document.createElement("span");
  tag.className = "row-tag";
  tag.textContent = (t("verdicts")[r.classification] || [r.classification])[0];

  const del = document.createElement("button");
  del.type = "button";
  del.className = "row-del";
  del.setAttribute("aria-label", t("delete"));
  del.innerHTML = TRASH;
  del.addEventListener("click", (e) => { e.stopPropagation(); confirmDelete(r, row, name); });

  row.append(mini, main, tag, del);
  row.addEventListener("click", () => openRecord(r.id));
  row.addEventListener("keydown", (e) => {
    if (e.target !== row) return;
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openRecord(r.id); }
    if (e.key === "Delete") confirmDelete(r, row, name);
  });
  return row;
}

async function openRecord(id) {
  try {
    const result = await api(`/api/history/${id}`);
    state.lastResult = result;
    go("scan");
    renderResult(result, true);
  } catch {
    toast(t("reportGone"));
  }
}

function confirmDelete(record, row, name) {
  const dialog = $("confirm");
  $("confirm-body").textContent = t("delBody")(name);
  dialog.returnValue = "";
  dialog.showModal();
  dialog.addEventListener("close", async () => {
    if (dialog.returnValue !== "ok") { row.focus(); return; }
    try {
      await api(`/api/history/${record.id}`, { method: "DELETE" });
    } catch (err) {
      toast(err.message);
      return;
    }
    state.history = state.history.filter((r) => r.id !== record.id);
    row.classList.add("leaving");
    row.addEventListener("animationend", () => renderHistory(false), { once: true });
    toast(t("removed"));
  }, { once: true });
}

$("history-search").addEventListener("input", () => renderHistory(false));
document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => {
  state.filter = chip.dataset.filter;
  document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
  renderHistory(true);
}));

/* ---------------- settings ---------------- */
const settingInputs = [...document.querySelectorAll("[data-key]")];

async function loadSettings() {
  try {
    state.settings = await api("/api/settings");
    renderSettings();
    applyPrefs();
  } catch { /* keep defaults */ }
}

function renderSettings() {
  const s = state.settings;
  if (!s) return;
  settingInputs.forEach((input) => {
    const value = s[input.dataset.key];
    if (input.type === "checkbox") input.checked = !!value;
    else input.value = Math.round(value / (Number(input.dataset.scale) || 1));
  });
  updateOutputs();
}

function updateOutputs() {
  const size = settingInputs.find((i) => i.dataset.key === "maximum_file_size");
  const time = settingInputs.find((i) => i.dataset.key === "analysis_timeout");
  $("size-out").textContent = t("mb")(size.value);
  $("time-out").textContent = t("sec")(time.value);
}

function applyPrefs() {
  const s = state.settings || {};
  document.documentElement.classList.toggle("large", !!s.large_text);
  document.documentElement.classList.toggle("still", s.animated_background === false);
  requestAnimationFrame(() => { moveNavInk(); moveInk(); });
}

let saveTimer = null;
const pending = {};
function setSaveState(cls, text) {
  const el = $("save-state");
  el.className = `save-state ${cls}`;
  el.textContent = text;
}

settingInputs.forEach((input) => {
  const handler = () => {
    const scale = Number(input.dataset.scale) || 1;
    pending[input.dataset.key] = input.type === "checkbox" ? input.checked : Number(input.value) * scale;
    state.settings = { ...state.settings, ...pending };
    applyPrefs();
    updateOutputs();
    setSaveState("saving", t("saving"));
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveSettings, input.type === "range" ? 450 : 150);
  };
  input.addEventListener(input.type === "range" ? "input" : "change", handler);
});

async function saveSettings() {
  const changes = { ...pending };
  Object.keys(pending).forEach((k) => delete pending[k]);
  try {
    state.settings = await api("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(changes),
    });
    setSaveState("saved", `✓ ${t("saved")}`);
  } catch (err) {
    setSaveState("error", t("saveFailed") + err.message);
    loadSettings();
  }
}

/* ---------------- toast ---------------- */
let toastTimer = null;
function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.hidden = false;
  restartAnim(el);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
}

applyLang();
loadSettings();
