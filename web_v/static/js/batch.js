/* Instant fingerprints and batch scanning.
 *
 * CSHash.fingerprint(file) → SHA-256 from a Web Worker (WebCrypto).
 * CSHash.seen(hex)         → earlier scans of the exact same bytes.
 * CSBatch.start(files)     → a queue that scans several files, two at a time,
 *                            with a live card per file.
 */
(function () {
  "use strict";
  const { $, el, t, api, toast, formatBytes } = window.CS;
  const MAX_HASH = 512 * 1024 * 1024;
  const CONCURRENCY = 2;
  const RISK = { KNOWN_MALWARE: "--bad", NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad" };

  /* ---------------- fingerprints ---------------- */
  let worker = null, nextId = 0;
  const waiting = new Map();
  function fingerprint(file) {
    if (!window.Worker || !crypto.subtle || file.size > MAX_HASH) return Promise.resolve(null);
    if (!worker) {
      worker = new Worker("js/hash-worker.js");
      worker.onmessage = (e) => { const done = waiting.get(e.data.id); waiting.delete(e.data.id); if (done) done(e.data.hex ? e.data : null); };
    }
    const id = ++nextId;
    return new Promise((resolve) => { waiting.set(id, resolve); worker.postMessage({ id, file }); });
  }
  async function seen(hex) {
    if (!hex) return [];
    try { return (await api(`/api/history/lookup?sha256=${hex}`)).matches; } catch { return []; }
  }

  /* the banner under the drop zone for a single file */
  let token = 0;
  async function check(file) {
    const box = $("seen");
    const mine = ++token;
    box.hidden = false;
    box.className = "seen hashing";
    box.replaceChildren(el("i", "spin"), el("span", "", t("hashing")));
    const result = await fingerprint(file);
    if (mine !== token) return;
    if (!result) { box.hidden = true; return; }
    const matches = await seen(result.hex);
    if (mine !== token) return;
    box.className = matches.length ? "seen match" : "seen fresh";
    const line = el("div", "seen-line");
    const hash = el("code", "mono", `${result.hex.slice(0, 16)}…${result.hex.slice(-8)}`);
    hash.title = result.hex;
    if (matches.length) {
      const m = matches[0];
      const v = t("verdicts")[m.classification], verdict = v ? v[1] || v[0] : m.classification;   // the plain-language name, not the short code
      line.append(el("b", "", t("seenBefore")(matches.length)), el("span", "", ` ${verdict} · ${m.score}/100 · ${new Date(m.timestamp).toLocaleString(window.CS.lang)}`));
      const open = el("button", "link-btn", t("openEarlier"));
      open.type = "button";
      open.addEventListener("click", () => window.CS.openRecord(m.id));
      box.replaceChildren(line, el("div", "seen-sub", ""), open);
      box.querySelector(".seen-sub").append(document.createTextNode(`${t("fingerprint")}: `), hash);
    } else {
      line.append(el("b", "", t("seenNew")), el("span", "", ` · ${t("hashedIn")(result.ms)}`));
      const sub = el("div", "seen-sub");
      sub.append(document.createTextNode(`${t("fingerprint")}: `), hash);
      box.replaceChildren(line, sub);
    }
  }
  function clear() { token++; $("seen").hidden = true; }

  /* ---------------- batch ---------------- */
  let queue = [], running = 0, items = [];
  function start(files) {
    const list = [...files].filter((f) => f && f.size >= 0);
    if (!list.length) return;
    const limit = window.CS.settings && window.CS.settings.maximum_file_size;
    $("batch").hidden = false;
    document.querySelector(".composer").hidden = true;
    $("result").hidden = true;
    $("error").hidden = true;
    const grid = $("batch-list");
    list.forEach((file) => {
      const card = el("div", "bcard");
      card.style.setProperty("--d", `${(items.length % 12) * 0.04}s`);
      const ring = el("div", "bring");
      ring.append(el("span", "", "…"));
      const meta = el("div", "bmeta");
      meta.append(el("b", "", file.name), el("small", "", formatBytes(file.size)));
      const status = el("div", "bstatus", t("bQueued"));
      const bar = el("div", "bbar"); bar.append(el("i"));
      card.append(ring, meta, status, bar);
      grid.append(card);
      const item = { file, card, status, ring, state: "queued", hex: null, result: null };
      items.push(item);
      if (limit && file.size > limit) { finish(item, null, t("tooBig")(Math.round(limit / 1048576))); return; }
      fingerprint(file).then(async (fp) => {
        if (!fp) return;
        item.hex = fp.hex;
        const matches = await seen(fp.hex);
        if (matches.length) card.append(el("span", "bseen", t("seenBefore")(matches.length)));
      });
      queue.push(item);
    });
    summary();
    pump();
  }

  function pump() {
    while (running < CONCURRENCY && queue.length) {
      const item = queue.shift();
      running++;
      scan(item).finally(() => { running--; summary(); pump(); });
    }
  }

  async function scan(item) {
    item.state = "scanning";
    item.card.classList.add("scanning");
    item.status.textContent = t("bScanning");
    try {
      const job = await api("/api/scan/file", {
        method: "POST",
        headers: { "X-Filename": encodeURIComponent(item.file.name), "Content-Type": "application/octet-stream" },
        body: item.file,
      });
      let first = job.status ? job : null;   // the online version answers with the finished scan
      for (;;) {
        if (!first) await new Promise((r) => setTimeout(r, 300));
        const s = first || await api(`/api/scan/${job.id}`);
        first = null;
        const done = s.stages.filter((x) => x.state === "complete").length;
        item.card.style.setProperty("--p", `${(done / 4) * 100}%`);
        if (s.status === "done" || s.status === "partial") { finish(item, s.result, null); return; }
        if (s.status === "failed") { finish(item, null, s.error); return; }
      }
    } catch (err) {
      finish(item, null, err.message);
    }
  }

  function finish(item, result, error) {
    item.card.classList.remove("scanning");
    item.card.style.setProperty("--p", "100%");
    if (error) {
      item.state = "failed";
      item.card.classList.add("failed");
      item.status.textContent = error;
      item.ring.firstChild.textContent = "!";
      queue = queue.filter((q) => q !== item);
      summary();
      return;
    }
    item.state = "done";
    item.result = result;
    const plain = result.plain && (result.plain[window.CS.lang] || result.plain.en);
    const TONE = { ok: "--ok", warn: "--warn", danger: "--bad", neutral: "--muted", info: "--accent" };
    const tone = plain ? TONE[plain.summary.tone] || "--muted" : RISK[result.classification] || "--muted";
    item.card.style.setProperty("--c", `var(${tone})`);
    item.card.style.setProperty("--s", String(Math.max(3, result.combined_score)));
    item.card.classList.add("done");
    item.ring.firstChild.textContent = String(result.combined_score);
    item.status.textContent = plain ? plain.summary.headline : (t("verdicts")[result.classification] || [result.classification])[1];
    item.card.tabIndex = 0;
    item.card.setAttribute("role", "button");
    const open = () => { window.CS.showResult(result); };
    item.card.addEventListener("click", open);
    item.card.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    window.CS.notify && window.CS.notify(item.file.name, item.status.textContent);
  }

  function summary() {
    const counts = { done: 0, scanning: 0, queued: 0, failed: 0, SUSPICIOUS: 0, REVIEW: 0, NO_INDICATORS_OBSERVED: 0 };
    items.forEach((i) => { counts[i.state]++; if (i.result) counts[i.result.classification]++; });
    const total = items.length;
    $("batch-title").textContent = t("bTitle")(total);
    $("batch-progress").style.transform = `scaleX(${total ? (counts.done + counts.failed) / total : 0})`;
    const pills = $("batch-summary");
    pills.replaceChildren(
      pill(t("bDone")(counts.done, total), "--accent"),
      pill(`${counts.SUSPICIOUS} ${t("verdicts").SUSPICIOUS[0]}`, "--bad"),
      pill(`${counts.REVIEW} ${t("verdicts").REVIEW[0]}`, "--warn"),
      pill(`${counts.NO_INDICATORS_OBSERVED} ${t("verdicts").NO_INDICATORS_OBSERVED[0]}`, "--ok"),
    );
    if (counts.failed) pills.append(pill(`${counts.failed} ✕`, "--muted"));
    if (total && counts.done + counts.failed === total && !queue.length && running === 0) {
      window.CS.state.history = null;
      toast(t("bFinished")(total));
    }
  }
  function pill(text, color) { const p = el("span", "bpill", text); p.style.setProperty("--c", `var(${color})`); return p; }

  function reset() {
    queue = []; items = [];
    $("batch-list").replaceChildren();
    $("batch").hidden = true;
    document.querySelector(".composer").hidden = false;
  }
  $("batch-new").addEventListener("click", reset);
  $("batch-add").addEventListener("click", () => $("batch-file").click());
  $("batch-file").addEventListener("change", (e) => { start(e.target.files); e.target.value = ""; });

  window.CSHash = { fingerprint, seen, check, clear };
  window.CSBatch = { start, reset };
})();
