/* Command palette (Ctrl/⌘+K), keyboard shortcuts, and paste or drop
 * anywhere to scan. */
(function () {
  "use strict";
  const { $, el, t, api, toast } = window.CS;
  const CS = window.CS;
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
  const MOD = isMac ? "⌘" : "Ctrl";

  /* ---------------- palette ---------------- */
  const root = $("palette");
  const input = $("pal-input");
  const list = $("pal-list");
  let items = [], index = 0, recent = null, lastFocus = null;

  const go = (hash) => () => { location.hash = hash; };
  function actions() {
    const a = [
      { icon: "⬆", label: t("pScanFile"), hint: "", run: () => { go("#/scan")(); CS.newScan(); CS.setMode("file"); setTimeout(() => $("file").click(), 50); } },
      { icon: "⧉", label: t("pBatch"), hint: "", run: () => { go("#/scan")(); setTimeout(() => $("batch-file").click(), 50); } },
      { icon: "🔗", label: t("pScanLink"), hint: "", run: () => { go("#/scan")(); CS.newScan(); CS.setMode("url"); } },
      { icon: "¶", label: t("pScanText"), hint: "", run: () => { go("#/scan")(); CS.newScan(); CS.setMode("text"); } },
      { icon: "◷", label: t("navHistory"), hint: "Alt+2", run: go("#/history") },
      { icon: "✚", label: t("navRepair"), hint: "Alt+3", run: go("#/repair") },
      { icon: "⚙", label: t("navSettings"), hint: "Alt+4", run: go("#/settings") },
      { icon: "◎", label: t("navScan"), hint: "Alt+1", run: go("#/scan") },
      { icon: "⌂", label: t("home"), hint: "", run: go("#/") },
      { icon: "文", label: t("pLang"), hint: "Alt+L", run: () => CS.toggleLang() },
      { icon: "⌨", label: t("pShortcuts"), hint: "?", run: () => showShortcuts() },
    ];
    if (window.CSPwa && CSPwa.canInstall()) a.splice(8, 0, { icon: "⤓", label: t("pInstall"), hint: "", run: () => CSPwa.install() });
    if (CS.state.lastResult) a.unshift({ icon: "⎙", label: t("pPrint"), hint: `${MOD}+P`, run: () => { go("#/scan")(); setTimeout(() => window.print(), 150); } });
    return a;
  }

  function smart(q) {
    const out = [];
    const v = q.trim();
    if (/^https?:\/\/\S+$/i.test(v)) out.push({ icon: "🔗", label: t("pScanThisLink"), sub: v, run: () => scanValue("url", v) });
    else if (/^[a-z]:\\|^\\\\/i.test(v)) out.push({ icon: "⬆", label: t("pScanThisPath"), sub: v, run: () => CS.scanPath(v) });
    else if (/^[0-9a-f]{64}$/i.test(v)) out.push({ icon: "#", label: t("pLookup"), sub: v.slice(0, 24) + "…", run: () => lookup(v) });
    else if (v.length > 24) out.push({ icon: "¶", label: t("pScanThisText"), sub: v.slice(0, 60) + "…", run: () => scanValue("text", v) });
    return out;
  }

  function scanValue(mode, value) {
    location.hash = "#/scan";
    CS.newScan();
    CS.setMode(mode);
    $(mode).value = value;
    $(mode).dispatchEvent(new Event("input"));
    $("form").requestSubmit();
  }

  async function lookup(hex) {
    try {
      const { matches } = await api(`/api/history/lookup?sha256=${hex.toLowerCase()}`);
      if (matches.length) CS.openRecord(matches[0].id); else toast(t("pNoMatch"));
    } catch (err) { toast(err.message); }
  }

  /* How well a label answers what was typed: the label starting with it first, then a word starting
   * with it, then anywhere inside it; a scattered-letters match ranks below all of those. */
  function score(text, q) {
    if (!q) return 1;
    const s = String(text || "").toLowerCase(), qq = q.toLowerCase();
    if (s.startsWith(qq)) return 300 - Math.min(s.length, 99);
    const words = s.split(/[\s/\\._-]+/);
    if (words.some((w) => w.startsWith(qq))) return 200 - Math.min(s.length, 99);
    const at = s.indexOf(qq);
    if (at >= 0) return 100 - Math.min(at, 60);
    let i = 0, gaps = 0, last = -1;
    [...s].forEach((ch, k) => { if (i < qq.length && ch === qq[i]) { if (last >= 0) gaps += k - last - 1; last = k; i++; } });
    return i === qq.length ? Math.max(1, 30 - gaps) : 0;
  }

  async function loadRecent() {
    try { recent = await api("/api/history"); } catch { recent = []; }
    if (!root.hidden) render();
  }

  function render() {
    const q = input.value.trim();
    const groups = [];
    const s = smart(q);
    if (s.length) groups.push([t("pSuggested"), s]);
    const acts = actions().map((a) => ({ ...a, s: score(a.label, q) })).filter((a) => a.s > 0).sort((a, b) => b.s - a.s);
    if (acts.length) groups.push([t("pActions"), acts]);
    const scansGroupAt = groups.length;
    if (recent) {
      const RISK = { NO_INDICATORS_OBSERVED: "--ok", REVIEW: "--warn", SUSPICIOUS: "--bad", KNOWN_MALWARE: "--bad" };
      const latest = new Map();
      recent.forEach((r) => { if (!latest.has(r.target)) latest.set(r.target, r); });
      const scans = [...latest.values()]
        .map((r) => {
          const name = r.target.split(/[\\/]/).filter(Boolean).pop() || r.target;
          const label = /^https?:\/\//i.test(r.target) ? r.target : name;
          return { icon: String(r.score), color: RISK[r.classification], label, sub: r.target === label ? "" : r.target, s: Math.max(score(label, q), score(r.target, q) - 50), run: () => CS.openRecord(r.id) };
        })
        .filter((r) => r.s > 0)
        .sort((a, b) => (q ? b.s - a.s : 0))
        .slice(0, q ? 12 : 6);
      if (scans.length) groups.push([t("pRecent"), scans]);
      // a recent scan that answers the query better than every command is listed first
      if (q && scans.length && acts.length && scans[0].s > acts[0].s) groups.splice(scansGroupAt - 1, 0, groups.splice(scansGroupAt, 1)[0]);
    }
    items = groups.flatMap(([, g]) => g);
    index = Math.min(index, Math.max(0, items.length - 1));
    list.replaceChildren();
    if (!items.length) { list.append(el("div", "pal-empty", t("pNothing"))); return; }
    let n = 0;
    groups.forEach(([title, group]) => {
      list.append(el("div", "pal-group", title));
      group.forEach((item) => {
        const k = n++;
        const row = el("div", "pal-item");
        row.setAttribute("role", "option");
        row.id = `pal-${k}`;
        const icon = el("span", "pal-icon", item.icon);
        if (item.color) { icon.classList.add("score"); icon.style.setProperty("--c", `var(${item.color})`); }
        const text = el("span", "pal-text");
        text.append(el("b", "", item.label));
        if (item.sub) text.append(el("small", "", item.sub));
        row.append(icon, text);
        if (item.hint) row.append(el("kbd", "", item.hint));
        row.addEventListener("mousemove", () => { if (index !== k) { index = k; mark(); } });
        row.addEventListener("click", () => choose(k));
        list.append(row);
      });
    });
    mark();
  }

  function mark() {
    list.querySelectorAll(".pal-item").forEach((r, k) => r.classList.toggle("on", k === index));
    const on = $(`pal-${index}`);
    if (on) { on.scrollIntoView({ block: "nearest" }); input.setAttribute("aria-activedescendant", on.id); }
  }

  function choose(k) {
    const item = items[k];
    close();
    if (item) setTimeout(item.run, 60);
  }

  const narrow = () => matchMedia("(max-width: 760px), (hover: none)").matches;
  function open() {
    if (!root.hidden) return;
    lastFocus = document.activeElement;
    input.placeholder = narrow() ? CS.ax("palShort") : t("pPlaceholder");
    root.classList.toggle("touch", narrow());
    root.hidden = false;
    root.classList.remove("out"); void root.offsetWidth; root.classList.add("in");
    input.value = "";
    index = 0;
    render();
    loadRecent();
    input.focus();
  }
  function close() {
    if (root.hidden) return;
    root.classList.remove("in");
    root.classList.add("out");
    setTimeout(() => { root.hidden = true; root.classList.remove("out"); }, 180);
    if (lastFocus && lastFocus.focus && document.contains(lastFocus)) lastFocus.focus();
    lastFocus = null;
  }
  // while it is open, the palette keeps the keyboard: Tab stays in the search field (arrows move in the
  // list), Escape closes it from anywhere, and a click outside the box closes it
  document.addEventListener("keydown", (e) => {
    if (root.hidden || root.classList.contains("out")) return;
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(); return; }
    if (e.key === "Tab") { e.preventDefault(); input.focus(); }
  }, true);
  document.addEventListener("focusin", (e) => { if (!root.hidden && !root.classList.contains("out") && !root.contains(e.target)) input.focus(); });
  document.addEventListener("pointerdown", (e) => { if (!root.hidden && !root.classList.contains("out") && !root.querySelector(".pal-box").contains(e.target)) { e.preventDefault(); close(); } }, true);

  input.addEventListener("input", () => { index = 0; render(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); index = (index + 1) % Math.max(1, items.length); mark(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); index = (index - 1 + items.length) % Math.max(1, items.length); mark(); }
    else if (e.key === "Enter") { e.preventDefault(); choose(index); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
  });

  document.querySelectorAll(".pal-open").forEach((b) => b.addEventListener("click", open));

  /* ---------------- shortcuts ---------------- */
  const sheet = $("shortcuts");
  function showShortcuts() {
    const rows = [
      [`${MOD} K`, t("kPalette")], ["Alt 1–4", t("kViews")], ["N", t("kNew")], ["/", t("kSearch")],
      ["Alt L", t("pLang")], [`${MOD} V`, t("kPaste")], [`${MOD} P`, t("pPrint")], ["?", t("pShortcuts")], ["Esc", t("kClose")],
    ];
    $("sc-list").replaceChildren(...rows.map(([k, label]) => {
      const r = el("div", "sc-row");
      r.append(el("span", "", label), el("span", "sc-keys", ""));
      k.split(" ").forEach((part) => r.lastChild.append(el("kbd", "", part)));
      return r;
    }));
    sheet.showModal();
  }
  const typing = (e) => e.target.closest && e.target.closest("input, textarea, select, [contenteditable]");
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); root.hidden ? open() : close(); return; }
    if (!root.hidden || sheet.open) return;
    if (e.altKey && /^[1-4]$/.test(e.key)) { e.preventDefault(); location.hash = ["#/scan", "#/history", "#/repair", "#/settings"][Number(e.key) - 1]; return; }
    if (e.altKey && e.key.toLowerCase() === "l") { e.preventDefault(); CS.toggleLang(); return; }
    if (typing(e) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === "?") { e.preventDefault(); showShortcuts(); }
    else if (e.key === "/" && CS.state.view === "history") { e.preventDefault(); $("history-search").focus(); }
    else if (e.key.toLowerCase() === "n" && CS.state.view) { e.preventDefault(); location.hash = "#/scan"; CS.newScan(); }
  });

  /* ---------------- paste anywhere ---------------- */
  document.addEventListener("paste", (e) => {
    if (!CS.state.view || typing(e)) return;
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); location.hash = "#/scan"; CS.newScan(); CS.setMode("file"); CS.chooseFiles(files); toast(t("pastedFile")); return; }
    const text = (e.clipboardData?.getData("text") || "").trim();
    if (!text) return;
    e.preventDefault();
    location.hash = "#/scan";
    CS.newScan();
    if (/^[a-z]:\\|^\\\\/i.test(text) && !text.includes("\n")) { CS.scanPath(text); return; }
    const mode = /^https?:\/\/\S+$/i.test(text) ? "url" : "text";
    CS.setMode(mode);
    $(mode).value = text;
    $(mode).dispatchEvent(new Event("input"));
    toast(mode === "url" ? t("pastedLink") : t("pastedText"), { label: t("scan"), run: () => $("form").requestSubmit() });
  });

  /* ---------------- drop anywhere ---------------- */
  const veil = $("drop-veil");
  let depth = 0;
  const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes("Files");
  window.addEventListener("dragenter", (e) => { if (!CS.state.view || !hasFiles(e)) return; depth++; veil.hidden = false; veil.classList.add("on"); });
  window.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; veil.classList.remove("on"); setTimeout(() => { if (!depth) veil.hidden = true; }, 200); } });
  window.addEventListener("dragover", (e) => { if (CS.state.view && hasFiles(e)) e.preventDefault(); });
  window.addEventListener("drop", (e) => {
    if (!CS.state.view || !hasFiles(e)) return;
    e.preventDefault();
    depth = 0; veil.classList.remove("on"); veil.hidden = true;
    if (CS.state.view === "repair") return; // the repair drop zone handles its own files
    location.hash = "#/scan";
    CS.newScan();
    CS.setMode("file");
    CS.chooseFiles(e.dataTransfer.files);
  });

  window.CSPalette = { open, close, showShortcuts };
})();
