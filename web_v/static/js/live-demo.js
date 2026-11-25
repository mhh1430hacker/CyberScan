/* The landing's live parts (strings: js/landing-i18n.js; styles: landing-plus.css).
 *
 * 1. The hero's live demo: a file dropped on the scan card (or picked, or one of three harmless
 *    samples built here in the browser) is scanned for real by the same API the scan page uses
 *    (POST /api/scan/file with the page's token, then GET /api/scan/<id> until it is done; the
 *    public server answers with the finished scan at once). The card then shows the verdict, the
 *    score, the top three findings and the plain-language line, with a link to the full scanner.
 *    The samples are NOT malware: a tiny text PDF, an "invoice.pdf.exe" made of an MZ header and
 *    readable text with no code at all, and a phishing-looking page whose form points at a
 *    documentation-only address (192.0.2.0/24, RFC 5737). They are never written to the server's
 *    files: they exist only as bytes in this page until they are sent to be scanned.
 * 2. Live figures: threat-rule count, known-malware fingerprints and the rules' date, from
 *    GET /api/protection, in the hero and the stats section. */
(function () {
  "use strict";
  if (!window.CS) return;
  const { $, el } = window.CS;
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");
  const lang = () => (CS.lang === "ar" ? "ar" : CS.lang || "en");
  const tx = (key, vars) => {
    let s = CS.t(key);
    if (typeof s !== "string") s = key;
    return vars ? s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined ? vars[k] : m)) : s;
  };
  const meta = (name, fallback) => { const v = (document.querySelector(`meta[name="${name}"]`) || {}).content || ""; return v && !v.startsWith("__") ? v : fallback; };
  const TOKEN = meta("cyberscan-token", "");
  const SCAN_URL = meta("cyberscan-scan-url", "app.html");
  const fmtN = (n) => Number(n).toLocaleString(lang() === "ar" ? "ar-SA-u-nu-latn" : lang());
  const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

  /* ================================================================ live figures */
  let prot = null;
  function paintFigures() {
    const strip = $("live-strip"), stats = $("stats-live");
    if (!prot) return;
    const parts = [];
    const rules = Number(prot.forge_rules) || 0, hashes = Number(prot.malware_hashes) || 0;
    if (rules) parts.push(["rules", tx("lsRules", { n: fmtN(rules) })]);
    if (hashes) parts.push(["hashes", tx("lsHashes", { n: fmtN(hashes) })]);
    const day = prot.forge_version || prot.updated;
    if (day && /^\d{4}-\d{2}-\d{2}/.test(day)) {
      let d = day;
      try { d = new Intl.DateTimeFormat(lang() === "ar" ? "ar-SA-u-ca-gregory-nu-latn" : lang(), { day: "numeric", month: "short", year: "numeric" }).format(new Date(`${day.slice(0, 10)}T12:00:00Z`)); } catch { /* keep ISO */ }
      parts.push(["date", tx("lsUpdated", { d })]);
    }
    if (!parts.length) return;
    const build = (box) => {
      box.replaceChildren();
      parts.forEach(([k, s], i) => {
        if (i) box.append(el("span", "ls-sep", "·"));
        box.append(el("span", `ls-${k}`, s));
      });
    };
    if (strip) { build($("ls-items")); strip.title = tx("lsLive"); strip.hidden = false; }
    if (stats) { stats.replaceChildren(el("b", "", tx("lsLive"))); const box = el("span"); build(box); stats.append(" ", box); stats.hidden = false; }
  }
  function loadFigures() {
    CS.api("/api/protection").then((p) => { prot = p; paintFigures(); }).catch(() => { /* the figures simply stay hidden */ });
  }

  /* ================================================================ the live demo */
  const card = $("ld-card"), status = $("ld-status"), fileInput = $("ld-file"), hero = document.querySelector(".hero");
  if (!card || !status) { loadFigures(); CS.onLang(paintFigures); return; }

  /* --- the three harmless samples, built from text (no network, no stored file) --- */
  const enc = (s) => new TextEncoder().encode(s);
  const SAMPLES = {
    clean: () => new File([enc([
      "%PDF-1.4",
      "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj",
      "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj",
      "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj",
      "4 0 obj<</Length 60>>stream",
      "BT /F1 18 Tf 72 720 Td (Quarterly report: all figures in order.) Tj ET",
      "endstream endobj",
      "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj",
      "trailer<</Root 1 0 R>>",
      "%%EOF", ""].join("\n"))], "quarterly-report.pdf", { type: "application/pdf" }),
    // an "MZ" header and readable text only: no PE structure, no machine code, nothing that can run
    disguised: () => {
      const head = new Uint8Array(1024);
      head[0] = 0x4d; head[1] = 0x5a; head[0x3c] = 0x80;
      head.set(enc("CyberScan harmless demo sample. Not a program: no code, nothing runs."), 0x40);
      const tail = enc("powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==");   // the encoded text is just the word "Invoke-WebRequest"
      return new File([head, tail], "invoice_2026.pdf.exe", { type: "application/octet-stream" });
    },
    // looks like a saved phishing email; its form and link point at 192.0.2.44 (RFC 5737: reserved for documentation, reaches nothing)
    phish: () => new File([enc([
      "<!doctype html>",
      '<html><head><meta charset="utf-8"><title>Mailbox storage full</title></head><body>',
      "<pre>",
      "From: Mail Support Team <no-reply@secure-mailbox-support.example.top>",
      "Reply-To: helpdesk.verify@freemail.example",
      "Subject: URGENT: your mailbox will be suspended in 24 hours",
      "</pre>",
      "<h2>Your mailbox will be suspended in 24 hours</h2>",
      "<p>Dear user, we detected unusual activity. Verify your account immediately or it will be permanently closed.</p>",
      "<p>Enter your password below to confirm your identity.</p>",
      '<form action="http://192.0.2.44/mail/login.php" method="post">Email <input name="email"> Password <input type="password" name="pass"><button>Verify now</button></form>',
      '<p><a href="http://192.0.2.44/mail/login.php">https://mail.example.com/verify</a></p>',
      "<p>CyberScan demo sample: a harmless imitation built to show how phishing is recognised.</p>",
      "</body></html>", ""].join("\n"))], "mailbox-verify.html", { type: "text/html" }),
  };

  /* --- the server's limit (4 MB on the public site; the local server's own setting otherwise) --- */
  let limit = 0;
  async function maxBytes() {
    if (limit) return limit;
    try { const s = await CS.api("/api/settings"); limit = Number(s.maximum_file_size) || 0; } catch { /* use the public limit */ }
    if (!limit) limit = 4 * 1024 * 1024;
    return limit;
  }

  /* --- one scan: upload (with progress), then follow the job --- */
  let busy = false, run = 0, last = null;
  function upload(file, onProgress) {
    return new Promise((resolve, reject) => {
      const x = new XMLHttpRequest();
      x.open("POST", "/api/scan/file");
      x.setRequestHeader("X-CyberScan-Token", TOKEN);
      x.setRequestHeader("X-CyberScan-Lang", lang() === "ar" ? "ar" : "en");
      x.setRequestHeader("X-Filename", encodeURIComponent(file.name));
      x.setRequestHeader("Content-Type", "application/octet-stream");
      x.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
      x.onload = () => {
        let body = {};
        try { body = JSON.parse(x.responseText || "{}"); } catch { /* not JSON */ }
        if (x.status >= 200 && x.status < 300) resolve(body);
        else { const err = new Error(errText(body.error) || `HTTP ${x.status}`); err.status = x.status; err.body = body; reject(err); }
      };
      x.onerror = () => { const err = new Error("network"); err.kind = "network"; reject(err); };
      x.timeout = 70000;
      x.ontimeout = x.onerror;
      x.send(file);
    });
  }
  function errText(e) {
    if (!e) return "";
    if (typeof e === "string") return e;
    return e[lang() === "ar" ? "ar" : "en"] || e.message || e.code || "";
  }
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  async function follow(job, mine) {
    let tries = 0;
    while (job && job.status === "running" || (job && !job.status && job.id)) {
      if (mine !== run) return null;
      if (++tries > 400) throw new Error("timeout");
      await wait(tries < 10 ? 200 : 400);
      job = await CS.api(`/api/scan/${job.id}`);
    }
    return job;
  }

  /* --- the verdict, the same bands as the scan page (0 none, 1-49 review, 50+ suspicious) --- */
  function verdictOf(r) {
    const ds = (r && r.detection_summary) || {};
    const fin = [ds.final_score, r && r.final_score].find((v) => v !== undefined && v !== null && Number.isFinite(Number(v)));
    const raw = fin !== undefined ? Number(fin) : Math.max(Number(r && r.combined_score) || 0, Number(ds.content_score) || 0);
    const score = Math.max(0, Math.min(100, Math.round(raw)));
    let cls = ds.classification || (r && r.classification) || "UNKNOWN";
    if (cls !== "KNOWN_MALWARE" && cls !== "UNKNOWN" && cls !== "EMPTY") cls = score >= 50 ? "SUSPICIOUS" : score > 0 ? "REVIEW" : "NO_INDICATORS_OBSERVED";
    return { score, cls };
  }
  const VERDICT = { NO_INDICATORS_OBSERVED: ["vNone", "ok", "✓"], REVIEW: ["vReview", "warn", "?"], SUSPICIOUS: ["vSusp", "bad", "!"], KNOWN_MALWARE: ["vKnown", "bad", "!"], UNKNOWN: ["vUnknown", "warn", "?"], EMPTY: ["vEmptyFile", "warn", "–"] };
  const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  /* --- the card --- */
  const icon = card.querySelector(".sc-icon"), nameB = card.querySelector(".sc-head b"), sizeS = card.querySelector(".sc-head small");
  const meter = card.querySelector(".sc-meter"), num = card.querySelector(".sc-num");
  const badge = card.querySelector(".sc-verdict .badge"), vText = card.querySelector(".sc-verdict b"), list = card.querySelector(".sc-list");
  const original = { icon: icon.textContent, size: sizeS.textContent, list: [...list.children].map((li) => li.cloneNode(true)), badge: badge.className, badgeText: badge.textContent };
  let extra = null;
  const keep = (on) => [nameB, vText].forEach((n) => { if (on) n.dataset.keep = "1"; else delete n.dataset.keep; });
  function setShape(shape) { if (!hero) return; hero.dataset.shape = shape; window.dispatchEvent(new Event("cs:shape-refresh")); }
  function gauge(score) {
    const C = 326.73;
    if (reduced()) { meter.style.strokeDashoffset = C * (1 - score / 100); num.textContent = String(score); return; }
    meter.style.strokeDashoffset = C * (1 - score / 100);
    const start = performance.now(), from = Number(num.textContent) || 0;
    const step = (now) => { const p = Math.min((now - start) / 1200, 1), e = 1 - Math.pow(1 - p, 3); num.textContent = String(Math.round(from + (score - from) * e)); if (p < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  function extOf(name) { const m = /\.([a-z0-9]{1,5})$/i.exec(name || ""); return m ? m[1].toUpperCase() : "FILE"; }

  function showScanning(file) {
    card.classList.add("ld-live", "ld-busy", "lit");
    card.classList.remove("ld-done");
    keep(true);
    icon.textContent = extOf(file.name);
    nameB.textContent = file.name; nameB.dir = "auto";
    sizeS.textContent = fmtSize(file.size);
    meter.style.transition = "none"; meter.style.strokeDashoffset = 326.73; void meter.getBoundingClientRect(); meter.style.transition = "";
    num.textContent = "0";
    badge.className = "badge"; badge.textContent = "…";
    vText.textContent = tx("ldScanning", { name: "" }).replace(/\s*…$/, "…").trim();
    list.replaceChildren();
    if (extra) extra.remove();
    extra = null;
    setShape("file");
  }

  function render(result) {
    last = result;
    const v = verdictOf(result), [vk, tone, mark] = VERDICT[v.cls] || VERDICT.UNKNOWN;
    const plain = (result.plain && (result.plain[lang()] || result.plain.en)) || null;
    card.classList.remove("ld-busy");
    card.classList.add("ld-done");
    card.dataset.tone = tone;
    badge.className = `badge ${tone}`; badge.textContent = mark;
    vText.textContent = tx(vk);
    gauge(v.score);
    const finds = ((plain && plain.details && plain.details.findings) || []).slice().sort((a, b) => (SEV[a.severity] ?? 5) - (SEV[b.severity] ?? 5));
    const top = finds.filter((f) => f.severity !== "info").slice(0, 3);
    const shown = top.length ? top : finds.slice(0, Math.min(3, finds.length));
    list.replaceChildren(...(shown.length ? shown.map((f) => { const li = el("li", `ld-f ld-${f.tone || "neutral"}`); li.append(el("bdi", "", f.title)); if (f.body) li.title = f.body; return li; }) : [el("li", "ld-f ld-ok", tx("ldNoFindings"))]));
    extra = el("div", "ld-extra");
    if (plain && plain.summary) {
      const p = el("p", "ld-plain");
      p.dir = "auto";
      p.append(el("b", "", plain.summary.headline || ""), document.createTextNode(" " + [plain.summary.sentence, plain.summary.notice].filter(Boolean).join(" ")));
      extra.append(p);
    }
    const row = el("div", "ld-actions");
    const report = el("a", "ld-report", tx("ldReport"));
    report.href = `${SCAN_URL}#/scan`;
    const again = el("button", "ld-again", tx("ldAgain"));
    again.type = "button";
    again.addEventListener("click", () => { reset(); $("ld-pick").focus(); });
    row.append(report, again);
    extra.append(row, el("p", "ld-priv", tx("ldPrivacy")));
    card.append(extra);
    status.textContent = tx("ldDone", { verdict: tx(vk), score: v.score });
    if (window.CSAudio) CSAudio.play(v.cls === "NO_INDICATORS_OBSERVED" ? "clean" : v.cls === "REVIEW" || v.cls === "UNKNOWN" ? "review" : "threat");
  }

  function fail(message) {
    card.classList.remove("ld-busy");
    card.classList.add("ld-done");
    card.dataset.tone = "warn";
    badge.className = "badge warn"; badge.textContent = "!";
    vText.textContent = message;
    num.textContent = "–";
    list.replaceChildren();
    extra = el("div", "ld-extra");
    const row = el("div", "ld-actions");
    const report = el("a", "ld-report", tx("ldReport")); report.href = `${SCAN_URL}#/scan`;
    const again = el("button", "ld-again", tx("ldAgain")); again.type = "button";
    again.addEventListener("click", () => { reset(); $("ld-pick").focus(); });
    row.append(report, again); extra.append(row); card.append(extra);
    status.textContent = message;
    if (window.CSAudio) CSAudio.play("error");
  }

  function reset() {
    run++; busy = false; last = null;
    card.classList.remove("ld-live", "ld-busy", "ld-done");
    delete card.dataset.tone;
    keep(false);
    icon.textContent = original.icon; sizeS.textContent = original.size;
    nameB.textContent = tx("lCardFile"); vText.textContent = tx("lCardVerdict");
    badge.className = original.badge; badge.textContent = original.badgeText;
    list.replaceChildren(...original.list.map((li) => { const n = li.cloneNode(true); n.textContent = tx(n.dataset.i18n); return n; }));
    if (extra) extra.remove();
    extra = null;
    status.textContent = "";
    setShape("shield");
  }

  async function scan(file, sample) {
    if (busy) return;
    if (!file) return;
    if (!file.size) { showScanning(file); fail(tx("ldEmpty")); return; }
    const max = await maxBytes();
    if (file.size > max) { showScanning(file); fail(tx("ldTooBig", { n: Math.round(max / 1048576) })); return; }
    busy = true;
    const mine = ++run;
    showScanning(file);
    status.textContent = tx("ldScanning", { name: file.name }) + (sample ? ` ${tx("ldSampleNote")}` : "");
    if (window.CSAudio) CSAudio.play("scanStart");
    const started = performance.now();
    try {
      let job = await upload(file, (p) => { if (mine === run && file.size > 200000) status.textContent = tx("ldUploading", { name: file.name, p: Math.round(p * 100) }); });
      if (job && (job.status === "busy" || (job.error && job.error.code === "busy"))) throw Object.assign(new Error("busy"), { kind: "busy" });
      job = await follow(job, mine);
      if (mine !== run || !job) return;
      if (job.status === "busy") throw Object.assign(new Error("busy"), { kind: "busy" });
      if (job.status === "failed" || !job.result) throw new Error(errText(job.error) || "failed");
      // the scan theatre stays at least a moment, so the result reads as a result
      const left = 900 - (performance.now() - started);
      if (left > 0 && !reduced()) await wait(left);
      if (mine !== run) return;
      render(job.result);
    } catch (err) {
      if (mine !== run) return;
      const body = err.body || {};
      if (err.kind === "busy" || err.status === 503 || err.status === 429 || (body.error && body.error.code === "busy")) fail(tx("ldBusy"));
      else if (err.status === 413) fail(tx("ldTooBig", { n: Math.round((limit || 4194304) / 1048576) }));
      else if (err.kind === "network") fail(tx("ldOffline"));
      else fail(tx("ldFail", { msg: String(err.message || "error").slice(0, 120) }));
    } finally {
      if (mine === run) busy = false;
    }
  }

  /* --- wiring: samples, picker, drag and drop on the card --- */
  document.querySelectorAll(".ld-chip[data-sample]").forEach((b) => b.addEventListener("click", () => { const make = SAMPLES[b.dataset.sample]; if (make) scan(make(), true); }));
  $("ld-pick").addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => { const f = fileInput.files && fileInput.files[0]; fileInput.value = ""; if (f) scan(f, false); });
  const zone = card.closest(".hero-visual") || card;
  let depth = 0;
  const hasFiles = (e) => e.dataTransfer && [...(e.dataTransfer.types || [])].includes("Files");
  zone.addEventListener("dragenter", (e) => { if (!hasFiles(e)) return; e.preventDefault(); if (++depth === 1) { card.classList.add("ld-dropping"); if (window.CSAudio) CSAudio.play("dragIn"); } });
  zone.addEventListener("dragover", (e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = "copy"; });
  zone.addEventListener("dragleave", (e) => { if (!hasFiles(e)) return; if (--depth <= 0) { depth = 0; card.classList.remove("ld-dropping"); } });
  zone.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); depth = 0; card.classList.remove("ld-dropping");
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) { if (window.CSAudio) CSAudio.play("drop"); scan(f, false); }
  });
  // a file dropped elsewhere on the page would make the browser open it: keep it here
  window.addEventListener("dragover", (e) => { if (hasFiles(e) && !document.body.classList.contains("page-scan")) e.preventDefault(); });
  window.addEventListener("drop", (e) => { if (hasFiles(e) && !document.body.classList.contains("page-scan") && !zone.contains(e.target)) e.preventDefault(); });

  CS.onLang(() => {
    paintFigures();
    if (last) { if (extra) extra.remove(); extra = null; render(last); }
    else if (card.classList.contains("ld-busy")) vText.textContent = tx("ldScanning", { name: "" }).replace(/\s*…$/, "…").trim();
  });
  loadFigures();

  // test hook (not used by the page): window.CSLiveDemo.scanSample("phish")
  window.CSLiveDemo = { scanSample: (k) => SAMPLES[k] && scan(SAMPLES[k](), true), reset };
})();
