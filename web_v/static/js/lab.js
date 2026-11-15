/* The CyberScan Lab (#lab): an interactive workspace with nine modules over one real, harmless
 * sample file (data/lab.json, produced by web_v/make_lab_data.py) and the real Tool Registry
 * metadata (data/lab-tools.json, loaded only when a module needs it).
 *
 * - Real values come from CyberScan's code at build time or from the browser right now (Web
 *   Crypto, CompressionStream, the entropy formula). Simulations are labelled as such.
 * - Three levels (Discover / Explore / Deep tech) are progressive disclosure on the same view:
 *   [data-lv="2"] and [data-lv="3"] blocks appear as the level rises; nothing moves or reloads.
 * - Only the open module exists in the layout; loops run only while the lab is on screen (.live).
 * - All text goes through textContent; the CSP forbids inline styles, so geometry is set via CSSOM. */
(function () {
  "use strict";
  const root = document.getElementById("lab");
  if (!root) return;
  const CS = window.CS || {};
  const html = document.documentElement;
  const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion") || html.classList.contains("perf-low");
  const lang = () => (CS.lang || html.lang || "en");
  const LAB = () => (window.I18N[lang()] && window.I18N[lang()].lab) || {};
  // L("ex.regions.dos") with per-key English fallback
  function L(path) {
    const get = (o) => path.split(".").reduce((a, k) => (a == null ? a : a[k]), o);
    const v = get(LAB());
    return v === undefined ? get(window.I18N.en.lab) : v;
  }
  // keys such as ".text" contain a dot, so region text is looked up by object, not by dotted path
  const RG = (group, key) => { const o = L(`ex.${group}`) || {}; const v = o[key]; return v === undefined ? (window.I18N.en.lab.ex[group] || {})[key] : v; };
  const NS = "http://www.w3.org/2000/svg";
  function h(tag, props, ...kids) {
    const svg = props && props.svg;
    const n = svg ? document.createElementNS(NS, tag) : document.createElement(tag);
    if (props) for (const k in props) {
      const v = props[k];
      if (v == null || v === false || k === "svg") continue;
      if (k === "class") n.setAttribute("class", v);
      else if (k === "text") n.textContent = v;
      else if (k === "on") for (const e in v) n.addEventListener(e, v[e]);
      else if (k === "lv") n.dataset.lv = v;
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c)));
    return n;
  }
  const s = (tag, props, ...kids) => h(tag, { ...(props || {}), svg: true }, ...kids);
  // replaceChildren() would print "null" for optional pieces that are absent
  const put = (n, ...kids) => n.replaceChildren(...kids.flat().filter((c) => c != null && c !== false));
  const hex = (n, w = 2) => n.toString(16).toUpperCase().padStart(w, "0");
  const fmt = (n) => Number(n).toLocaleString(lang() === "ar" ? "ar-EG" : "en-US");
  const fmtEn = (n) => Number(n).toLocaleString("en-US");   // inside technical (left-to-right) strings
  const tagEl = (kind) => kind === "info" ? null : h("span", { class: `lab-tag ${kind}`, text: L(`tag.${kind}`), title: L(`tagTip.${kind}`) || null });
  const ltr = (n) => { n.dir = "ltr"; n.lang = "en"; return n; };

  let D = null, TOOLS = null, bytes = null, live = false;
  const state = (() => {
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem("cs-lab") || "{}"); } catch { /* storage off */ }
    return {
      mod: saved.mod || "explorer", level: [1, 2, 3].includes(saved.level) ? saved.level : 1,
      ex: { region: "dos", top: "headers" }, en: { a: "text", b: "aes", mix: 0, custom: "Hello! Type anything here." },
      hs: { text: "CyberScan sample text: hello!", algo: "SHA-256", prev: null },
      pl: { i: 0, playing: false }, ev: { off: new Set(), honest: false, sel: 1 },
      nw: { node: "url", url: 1 }, dm: { i: 4 }, rg: { all: true, tool: "cyberscan.cloud.kubernetes", sim: "", q: "", cat: "" },
      ai: { text: "", mode: 0, ran: false, stage: 0, confirm: new Set() },
    };
  })();
  const save = () => { try { localStorage.setItem("cs-lab", JSON.stringify({ mod: state.mod, level: state.level })); } catch { /* storage off */ } };

  /* ================================================================ shell */
  const MODS = ["explorer", "entropy", "hash", "pipeline", "evidence", "network", "domains", "registry", "ai"];
  const ICONS = {
    explorer: "M7 3h7l5 5v13H7zM14 3v5h5M10 12h6m-6 4h6", entropy: "M3 18c3 0 3-10 6-10s3 6 6 6 3-9 6-9",
    hash: "M9 3 7 21M17 3l-2 18M4 9h17M3 15h17", pipeline: "M3 12h4m4 0h2m4 0h4M7 9h4v6H7zm6 0h4v6h-4z",
    evidence: "M5 6a2 2 0 1 0 0 .01M19 6a2 2 0 1 0 0 .01M12 18a2 2 0 1 0 0 .01M6.5 7.5l4 8.5m7-8.5-4 8.5M7 6h10",
    network: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.8 3 2.8 15 0 18M12 3c-2.8 3-2.8 15 0 18",
    domains: "M12 2l8.5 5v10L12 22l-8.5-5V7zM12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", registry: "M4 5h16v4H4zm0 6h16v4H4zm0 6h10v3H4zM17 18l2 2 3-4",
    ai: "M12 3a6 6 0 0 0-6 6c0 2.2 1.2 3.6 2 4.6V17h8v-3.4c.8-1 2-2.4 2-4.6a6 6 0 0 0-6-6zM9 21h6",
  };
  const icon = (d, cls = "lab-ic") => s("svg", { class: cls, viewBox: "0 0 24 24", "aria-hidden": "true" }, s("path", { d }));
  const built = {};
  let mainEl = null, navBtns = [];

  function shell() {
    built.panels = {};
    put(root);
    root.classList.add("lab-js");
    root.dataset.level = state.level;
    const levelBtns = L("lv").map((name, i) => h("button", {
      type: "button", role: "radio", "aria-checked": String(state.level === i + 1), class: "lab-lvbtn",
      on: { click: () => setLevel(i + 1) },
    }, h("b", { text: String(i + 1) }), name));
    const lvGroup = h("div", { class: "lab-level", role: "radiogroup", "aria-label": L("level") }, levelBtns);
    lvGroup.addEventListener("keydown", (e) => {
      if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(e.key)) return;
      e.preventDefault();
      const rtl = html.dir === "rtl";
      const fwd = e.key === "ArrowDown" || (e.key === "ArrowRight" && !rtl) || (e.key === "ArrowLeft" && rtl);
      setLevel(((state.level - 1 + (fwd ? 1 : 2)) % 3) + 1);
      levelBtns[state.level - 1].focus();
    });
    navBtns = MODS.map((m) => h("button", {
      type: "button", role: "tab", id: `lab-tab-${m}`, "aria-controls": `lab-p-${m}`, "aria-selected": String(state.mod === m),
      tabindex: state.mod === m ? "0" : "-1", class: "lab-tab", on: { click: () => open(m) },
    }, icon(ICONS[m]), h("span", { text: L(`mods.${m}`)[0] })));
    const nav = h("nav", { class: "lab-nav", role: "tablist", "aria-label": L("title"), "aria-orientation": "vertical" }, navBtns);
    nav.addEventListener("keydown", (e) => {
      const i = navBtns.indexOf(document.activeElement);
      if (i < 0) return;
      const rtl = html.dir === "rtl";
      const back = e.key === "ArrowUp" || (e.key === "ArrowLeft" && !rtl) || (e.key === "ArrowRight" && rtl);
      if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(e.key)) {
        e.preventDefault();
        const j = (i + (back ? -1 : 1) + MODS.length) % MODS.length;
        navBtns[j].focus(); open(MODS[j]);
      } else if (e.key === "Home" || e.key === "End") { e.preventDefault(); const j = e.key === "Home" ? 0 : MODS.length - 1; navBtns[j].focus(); open(MODS[j]); }
    });
    mainEl = h("div", { class: "lab-main" });
    const sample = D ? h("p", { class: "lab-sample" }, h("span", { class: "lab-chip", text: L("sampleBadge") }), ltr(h("code", { text: D.sample.name })),
      h("span", { text: ` · ${fmt(D.sample.size)} ${L("ex.bytes")} · ` }), h("span", { class: "lab-sample-note", text: L("sampleNote") })) : null;
    root.append(h("div", { class: "lab-shell" },
      h("header", { class: "lab-top" },
        h("div", { class: "lab-titles" }, h("h3", { class: "lab-title", text: L("title") }), h("p", { class: "lab-sub", text: L("sub") }), sample),
        h("div", { class: "lab-levelwrap" }, h("span", { class: "lab-level-label", text: L("level") }), lvGroup, h("p", { class: "lab-lvhint", "aria-live": "polite", text: L("lvHint")[state.level - 1] }))),
      h("div", { class: "lab-body" }, nav, mainEl)));
    open(state.mod, true);
  }

  function setLevel(n) {
    state.level = n; save();
    root.dataset.level = n;
    root.querySelectorAll(".lab-lvbtn").forEach((b, i) => b.setAttribute("aria-checked", String(i + 1 === n)));
    const hint = root.querySelector(".lab-lvhint"); if (hint) hint.textContent = L("lvHint")[n - 1];
    Object.values(built.panels).forEach((p) => p.onLevel && p.onLevel());
  }

  function open(m, first) {
    if (!MODS.includes(m)) m = "explorer";
    if (state.mod !== m || first) { state.mod = m; save(); }
    navBtns.forEach((b) => { const on = b.id === `lab-tab-${m}`; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
    for (const id in built.panels) { built.panels[id].el.hidden = id !== m; if (id !== m && built.panels[id].onHide) built.panels[id].onHide(); }
    if (!built.panels[m]) {
      const el = h("section", { class: `lab-panel lab-${m}`, id: `lab-p-${m}`, role: "tabpanel", "aria-labelledby": `lab-tab-${m}`, tabindex: "-1" });
      el.append(h("header", { class: "lab-phead" }, h("h4", { text: L(`mods.${m}`)[0] }), h("p", { class: "lab-l1", text: L(`mods.${m}`)[1] })));
      mainEl.append(el);
      let api = {};
      try { api = BUILD[m](el) || {}; } catch (err) { console.error("lab module", m, err); el.append(h("p", { class: "lab-warn lab-err", text: L("fail") })); }
      built.panels[m] = { el, ...api };
    }
    const p = built.panels[m];
    p.el.hidden = false;
    if (p.onShow) p.onShow();
  }
  const go = (m, then) => { open(m); if (then) then(built.panels[m]); built.panels[m].el.focus({ preventScroll: true }); };

  /* ================================================================ 1 · file explorer */
  const TECH_NAMES = { dos: "DOS header", stub: "DOS stub", sig: "PE signature", coff: "COFF file header", opt: "Optional header", dirs: "Data directories",
    table: "Section table", pad: "Header padding", ".text": "Code section (.text)", ".rdata": "Read-only data (.rdata)", ".data": "Data section (.data)", overlay: "Overlay" };
  const REGION_HUE = { header: "#6b9bff", padding: "#3a4766", section: "#4fe0ff", overlay: "#fb7185" };
  const regColor = (r) => (r.key === ".rdata" ? "#2dd4bf" : r.key === ".data" ? "#a78bfa" : REGION_HUE[r.kind]);

  function buildExplorer(el) {
    const S = D.sample, R = S.regions;
    const byKey = Object.fromEntries(R.map((r) => [r.key, r]));
    const headerKeys = R.filter((r) => r.end <= 0x200).map((r) => r.key);
    let hlField = null;

    // name vs content
    const compare = h("div", { class: "ex-compare" },
      h("div", { class: "ex-says" }, h("small", { text: L("ex.nameSays") }), ltr(h("b", { text: S.name })), h("span", { text: L("ex.doc") })),
      h("div", { class: "ex-vs", "aria-hidden": "true", text: "≠" }),
      h("div", { class: "ex-says bad" }, h("small", { text: L("ex.bytesSay") }), ltr(h("b", { text: "4D 5A  ·  “MZ”" })), h("span", { text: L("ex.prog") })),
      h("p", { class: "ex-mismatch" }, L("ex.mismatch"), " ", h("button", { type: "button", class: "lab-link", text: L("ex.openEvidence"), on: { click: () => go("evidence") } })));

    // two-level byte map: whole file, and the 512 header bytes zoomed in
    const seg = (r, total) => {
      const b = h("button", { type: "button", class: `ex-seg k-${r.kind}`, "data-key": r.key, title: `${TECH_NAMES[r.key]} · 0x${hex(r.start, 3)}–0x${hex(r.end, 3)}`, on: { click: () => select(r.key) } },
        h("span", { text: RG("regions", r.key)[0] }));
      b.style.flexGrow = String((r.end - r.start) / total);
      b.style.setProperty("--c", regColor(r));
      return b;
    };
    const top = [{ key: "headers", kind: "header", start: 0, end: 0x200 }, ...R.filter((r) => r.start >= 0x200)];
    const topRow = h("div", { class: "ex-map-row" }, top.map((r) => {
      if (r.key !== "headers") return seg(r, S.size);
      const b = h("button", { type: "button", class: "ex-seg k-header group", "data-key": "headers", on: { click: () => select("dos") } }, h("span", { text: "Headers" }));
      b.style.flexGrow = String(0x200 / S.size); b.style.setProperty("--c", "#6b9bff");
      return b;
    }));
    const zoomRow = h("div", { class: "ex-map-row zoom" }, headerKeys.map((k) => seg(byKey[k], 0x200)));
    const scale = h("div", { class: "ex-scale", "aria-hidden": "true" }, ["0x000", "0x200", "0x400", "0x600", "0x800", "0xA00", "0xC00", "0xE00", "0x1000"].map((t) => h("span", { text: t })));
    const map = h("div", { class: "ex-map" }, h("p", { class: "lab-cap", text: L("ex.map") }), topRow, scale,
      h("p", { class: "lab-cap zoomcap", lv: "2", text: "0x000–0x200 ×8" }), h("div", { lv: "2" }, zoomRow));

    // byte picture: all 4096 bytes, 64 per row
    const pic = h("canvas", { class: "ex-pic", width: "256", height: "256", role: "img", "aria-label": "All 4096 bytes of the sample, 64 per row. Dark is zero; noise is the overlay." });
    const picInfo = h("p", { class: "ex-picinfo", "aria-live": "polite", text: L("ex.hover") });
    pic.addEventListener("mousemove", (e) => { const o = picOffset(e); if (o != null) picInfo.textContent = byteInfo(o); });
    pic.addEventListener("click", (e) => { const o = picOffset(e); if (o == null) return; const r = R.find((x) => o >= x.start && o < x.end); if (r) select(r.key); picInfo.textContent = byteInfo(o); });
    function picOffset(e) {
      const b = pic.getBoundingClientRect(); const x = Math.floor((e.clientX - b.left) / b.width * 64), y = Math.floor((e.clientY - b.top) / b.height * 64);
      return x >= 0 && x < 64 && y >= 0 && y < 64 ? y * 64 + x : null;
    }
    function byteInfo(o) {
      const r = R.find((x) => o >= x.start && o < x.end); const v = bytes[o];
      const f = r && r.fields ? r.fields.find((q) => o >= q[2] && o < q[2] + q[3]) : null;
      return `0x${hex(o, 4)} · 0x${hex(v)} (${v >= 32 && v < 127 ? `'${String.fromCharCode(v)}'` : "·"}) · ${r ? TECH_NAMES[r.key] : ""}${f ? " · " + f[0] : ""}`;
    }
    function drawPic(sel) {
      const ctx = pic.getContext("2d"); const img = ctx.createImageData(64, 64);
      const tint = R.map((r) => [r, hexRgb(regColor(r))]);
      for (let o = 0; o < 4096; o++) {
        const [r, c] = tint.find(([x]) => o >= x.start && o < x.end) || [null, [120, 130, 160]];
        const v = bytes[o] / 255, on = !sel || (r && r.key === sel);
        const k = (0.12 + 0.88 * v) * (on ? 1 : 0.28);
        img.data.set([c[0] * k, c[1] * k, c[2] * k, 255], o * 4);
      }
      const tmp = document.createElement("canvas"); tmp.width = 64; tmp.height = 64; tmp.getContext("2d").putImageData(img, 0, 0);
      ctx.imageSmoothingEnabled = false; ctx.clearRect(0, 0, 256, 256); ctx.drawImage(tmp, 0, 0, 256, 256);
    }

    // hex view of the selected region (Explore and up)
    const hexBox = h("div", { class: "ex-hex", lv: "2", role: "group", "aria-label": L("ex.hex") });
    const hexWrap = h("div", { lv: "2" }, h("p", { class: "lab-cap", text: L("ex.hex") }), hexBox);
    function drawHex(r) {
      const start = r.start - (r.start % 16), end = Math.min(r.end, start + 16 * 24);
      const rows = [];
      for (let o = start; o < end; o += 16) {
        const cells = [], chars = [];
        for (let k = 0; k < 16; k++) {
          const at = o + k, v = bytes[at], inR = at >= r.start && at < r.end;
          const f = inR && r.fields ? r.fields.find((q) => at >= q[2] && at < q[2] + q[3]) : null;
          const c = h("span", { class: `hx${inR ? " in" : ""}${f && hlField === f[0] ? " hl" : ""}`, "data-o": at, text: hex(v) });
          if (f) c.dataset.f = f[0];
          cells.push(c);
          chars.push(h("span", { class: `ch${inR ? " in" : ""}`, text: v >= 32 && v < 127 ? String.fromCharCode(v) : "·" }));
        }
        rows.push(h("div", { class: "hxrow" }, h("span", { class: "off", text: hex(o, 4) }), h("span", { class: "hxs" }, cells), h("span", { class: "chs" }, chars)));
      }
      if (r.end > end) rows.push(h("div", { class: "hxmore", text: `… ${fmt(r.end - end)} ${L("ex.bytes")}` }));
      put(hexBox, ...rows);
      hexBox.style.setProperty("--c", regColor(r));
    }
    hexBox.addEventListener("mouseover", (e) => { const o = e.target.dataset && e.target.dataset.o; if (o) picInfo.textContent = byteInfo(Number(o)); });

    // inspector
    const insp = h("div", { class: "lab-insp", "aria-live": "polite" });
    function inspector(r) {
      const [simple, l1] = RG("regions", r.key);
      const flags = r.flags ? h("p", { class: "ex-perms", lv: "2" }, h("small", { text: L("ex.perms") + ": " }),
        ["r", "w", "x"].map((k) => h("span", { class: `perm ${r.flags[{ r: "read", w: "write", x: "execute" }[k]] ? "on" : ""}`, text: L(`ex.${k}`) }))) : null;
      const ent = h("div", { class: "ex-ent", lv: "2" }, h("small", { text: `${L("ex.entropy")}: ${r.entropy.toFixed(3)} / 8` }), meter(r.entropy / 8, r.entropy > 7 ? "hot" : ""));
      const fieldsTbl = r.fields && r.fields.length ? ltr(h("table", { class: "lab-tbl ex-fields", lv: "3" },
        h("caption", { text: L("ex.fields") }),
        h("thead", {}, h("tr", {}, ["field", "value", "offset", "size"].map((x) => h("th", { text: x })))),
        h("tbody", {}, r.fields.map((f) => {
          const tr = h("tr", { tabindex: "0", "data-f": f[0] }, h("td", { text: f[0] }), h("td", { text: typeof f[1] === "number" ? `0x${hex(f[1])} (${f[1]})` : String(f[1]) }), h("td", { text: "0x" + hex(f[2], 3) }), h("td", { text: f[3] }));
          const on = () => { hlField = f[0]; drawHex(r); tr.classList.add("on"); };
          const off = () => { hlField = null; drawHex(r); tr.classList.remove("on"); };
          tr.addEventListener("mouseenter", on); tr.addEventListener("focus", on); tr.addEventListener("mouseleave", off); tr.addEventListener("blur", off);
          return tr;
        })))) : null;
      const extra = [];
      if (r.key === ".text") extra.push(ltr(h("pre", { class: "lab-code", lv: "3", text: `0x1000  6A 00              push 0\n0x1002  FF 15 00 20 40 00  call dword ptr [0x402000]   ; ExitProcess\n0x1008  C3                 ret` })));
      if (r.key === ".rdata") extra.push(ltr(h("p", { class: "lab-mono", lv: "2", text: S.imports.map((i) => `${i.dll} → ${i.names.join(", ")}`).join("\n") })));
      if (r.key === "stub") extra.push(ltr(h("p", { class: "lab-mono", lv: "2", text: `“${r.text}”` })));
      put(insp, 
        h("p", { class: "lab-kicker" }, h("span", { class: "sw" }), ltr(h("span", { lv: "2", text: TECH_NAMES[r.key] })), ltr(h("span", { class: "lab-mono", text: ` 0x${hex(r.start, 3)}–0x${hex(r.end, 3)} · ${fmt(r.end - r.start)} ${L("ex.bytes")}` }))),
        h("h5", { text: simple }), h("p", { text: l1 }), flags, ent,
        ltr(h("p", { class: "lab-tech", lv: "3", text: RG("tech", r.key) })), fieldsTbl, ...extra);
      insp.querySelector(".sw").style.setProperty("--c", regColor(r));
    }
    const hashes = ltr(h("dl", { class: "lab-kv ex-hashes", lv: "3" },
      h("dt", { text: "MD5" }), h("dd", { text: S.md5 }), h("dt", { text: "SHA-1" }), h("dd", { text: S.sha1 }), h("dt", { text: "SHA-256" }), h("dd", { text: S.sha256 }),
      h("dt", { text: "type" }), h("dd", { text: `${S.sniffed_type} (detection.engine.sniff_type)` }), h("dt", { text: "entry" }), h("dd", { text: `RVA 0x${hex(S.entry_rva, 4)} → file 0x${hex(S.entry_offset, 3)}` })));

    function select(key) {
      state.ex.region = key;
      const r = byKey[key];
      el.querySelectorAll(".ex-seg").forEach((b) => b.classList.toggle("on", b.dataset.key === key || (b.dataset.key === "headers" && r.end <= 0x200)));
      drawPic(key); drawHex(r); inspector(r);
    }
    el.append(compare, h("div", { class: "ex-grid" },
      h("div", { class: "ex-left" }, map, h("div", { class: "ex-picwrap" }, pic, picInfo), hexWrap),
      h("div", { class: "ex-right" }, insp, h("p", { class: "lab-cap", lv: "3", text: L("ex.hashes") }), hashes, foot())));
    select(state.ex.region in byKey ? state.ex.region : "dos");
    return { select, field: (name) => { const r = R.find((x) => x.fields && x.fields.some((f) => f[0] === name)); if (r) { if (state.level < 3) setLevel(3); select(r.key); hlField = name; drawHex(r); } } };
  }
  function hexRgb(c) { const n = parseInt(c.slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255]; }
  function meter(k, cls = "") { const m = h("span", { class: `lab-meter ${cls}` }, h("i")); m.firstChild.style.transform = `scaleX(${Math.max(0, Math.min(1, k))})`; return m; }
  const foot = () => h("p", { class: "lab-foot", lv: "2" }, tagEl("real"), " ", h("span", { text: `${L("builtOn")} ${D.generated_on}` }));

  /* ================================================================ 2 · entropy */
  const TEXT = "CyberScan reads a file the way a careful detective reads a suspicious letter. It studies the envelope, the handwriting and what the letter asks for, without ever doing what it says. Ordinary writing repeats letters and words, so the next byte is fairly easy to guess. ";
  function entropyOf(buf) {
    const c = new Uint32Array(256); for (const b of buf) c[b]++;
    let H = 0, distinct = 0; const n = buf.length;
    for (let i = 0; i < 256; i++) if (c[i]) { const p = c[i] / n; H -= p * Math.log2(p); distinct++; }
    return { H, counts: c, n, distinct };
  }
  async function preset(name) {
    const enc = new TextEncoder();
    if (name === "text") return enc.encode(TEXT.repeat(2));
    if (name === "repeat") return enc.encode("ABCD".repeat(160));
    if (name === "random") { const b = new Uint8Array(640); crypto.getRandomValues(b); return b; }
    if (name === "overlay") return bytes.slice(0x800, 0x1000);
    if (name === "custom") return enc.encode(state.en.custom || " ");
    if (name === "gzip") {
      if (!("CompressionStream" in window)) return enc.encode(TEXT);
      const out = await new Response(new Blob([TEXT.repeat(8)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer();
      return new Uint8Array(out);
    }
    if (name === "aes") {
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(TEXT.repeat(2))));
    }
    return enc.encode(TEXT);
  }
  function mixIn(buf, frac) {
    if (!frac) return buf;
    const out = buf.slice(); let x = 2463534242;
    for (let i = 0; i < out.length; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; if (((x >>> 0) % 1000) / 1000 < frac) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; out[i] = (x >>> 0) & 255; } }
    return out;
  }
  function buildEntropy(el) {
    const PRESETS = ["text", "repeat", "random", "gzip", "aes", "overlay", "custom"];
    const panel = (which) => {
      const sel = h("select", { class: "lab-select", "aria-label": L(`en.${which}`) }, PRESETS.map((p) => h("option", { value: p, text: L(`en.presets.${p}`) })));
      sel.value = state.en[which];
      const canvas = h("canvas", { class: "en-hist", width: "512", height: "120", role: "img", "aria-label": "Byte histogram, 0x00 to 0xFF" });
      const big = h("b", { class: "en-big" }), verdict = h("span", { class: "en-verdict" }), facts = h("small", { class: "en-facts" }), note = h("small", { class: "en-note" });
      const custom = h("input", { type: "text", class: "lab-input", value: state.en.custom, maxlength: "300", "aria-label": L("en.edit"), spellcheck: "false" });
      custom.hidden = sel.value !== "custom";
      const mix = which === "a" ? h("label", { class: "en-mix" }, h("span", { text: L("en.mix") }),
        h("input", { type: "range", min: "0", max: "100", value: String(state.en.mix), "aria-describedby": "en-mixhint" }), h("output", { text: state.en.mix + "%" })) : null;
      const gauge = h("div", { class: "en-gauge" }, h("i"), h("span", { class: "en-gauge-scale", "aria-hidden": "true" }, ["0", "2", "4", "6", "8"].map((t) => h("span", { text: t }))));
      const table = h("div", { class: "en-calc", lv: "3" });
      const box = h("section", { class: `en-panel ${which}` },
        h("header", {}, h("h5", { text: L(`en.${which}`) }), sel), custom,
        h("div", { class: "en-read" }, big, h("span", { class: "en-unit", text: `${L("en.bits")} · ${L("en.of8")}` }), verdict), gauge, canvas, facts, note, mix, table);
      let base = null;
      async function load() { base = await preset(sel.value); draw(); }
      function draw() {
        const buf = which === "a" ? mixIn(base, state.en.mix / 100) : base;
        const r = entropyOf(buf);
        big.textContent = r.H.toFixed(3);
        verdict.textContent = L("en.verdict")[r.H < 2.5 ? 0 : r.H < 5 ? 1 : r.H < 7 ? 2 : 3];
        box.dataset.band = r.H < 2.5 ? "0" : r.H < 5 ? "1" : r.H < 7 ? "2" : "3";
        facts.textContent = `${fmt(r.n)} ${L("en.n")} · ${r.distinct} ${L("en.distinct")}`;
        note.textContent = L(`en.presetNote.${sel.value}`) || "";
        gauge.firstChild.style.transform = `scaleX(${r.H / 8})`;
        hist(canvas, r.counts, r.n);
        calc(table, r);
      }
      sel.addEventListener("change", () => { state.en[which] = sel.value; custom.hidden = sel.value !== "custom"; load(); });
      custom.addEventListener("input", () => { state.en.custom = custom.value; if (sel.value === "custom") load(); });
      if (mix) mix.querySelector("input").addEventListener("input", (e) => { state.en.mix = Number(e.target.value); mix.querySelector("output").textContent = state.en.mix + "%"; draw(); });
      load();
      return box;
    };
    function hist(canvas, counts, n) {
      const ctx = canvas.getContext("2d"); ctx.clearRect(0, 0, 512, 120);
      let max = 0; for (const c of counts) max = Math.max(max, c);
      const grad = ctx.createLinearGradient(0, 120, 0, 0); grad.addColorStop(0, "#2a6cff"); grad.addColorStop(1, "#4fe0ff");
      ctx.fillStyle = "rgba(130,170,255,.08)"; ctx.fillRect(0, 119, 512, 1);
      ctx.fillStyle = grad;
      for (let i = 0; i < 256; i++) if (counts[i]) { const hgt = Math.max(1.5, (counts[i] / max) * 112); ctx.fillRect(i * 2, 120 - hgt, 1.6, hgt); }
      ctx.fillStyle = "rgba(180,108,255,.6)"; ctx.fillRect(0, 120 - (n / 256 / max) * 112, 512, 1);   // the uniform line
    }
    function calc(box, r) {
      const rows = [];
      for (let i = 0; i < 256; i++) if (r.counts[i]) rows.push([i, r.counts[i]]);
      rows.sort((a, b) => b[1] - a[1]);
      const top = rows.slice(0, 6);
      put(box, ltr(h("div", {},
        h("p", { class: "lab-formula", text: "H = −Σ p(x) · log₂ p(x)" }),
        h("table", { class: "lab-tbl" }, h("thead", {}, h("tr", {}, ["byte", "count", "p(x)", "−p·log₂p"].map((x) => h("th", { text: x })))),
          h("tbody", {}, top.map(([b, c]) => { const p = c / r.n; return h("tr", {}, h("td", { text: `0x${hex(b)}${b >= 32 && b < 127 ? ` '${String.fromCharCode(b)}'` : ""}` }), h("td", { text: c }), h("td", { text: p.toFixed(4) }), h("td", { text: (-p * Math.log2(p)).toFixed(4) })); }),
            rows.length > 6 ? h("tr", { class: "more" }, h("td", { text: `+${rows.length - 6} more` }), h("td"), h("td"), h("td")) : null)),
        h("p", { class: "lab-mono", text: `Σ = ${r.H.toFixed(4)} bits/byte · n = ${r.n} · max for n: log₂(min(n, 256)) = ${Math.log2(Math.min(r.n, 256)).toFixed(3)}` }))));
    }
    // entropy along the real sample
    const T = D.sample.trajectory, R = D.sample.regions;
    const W = 640, Hh = 150, xs = (o) => (o / D.sample.size) * W, ys = (v) => Hh - (v / 8) * (Hh - 12);
    const bands = R.filter((r) => r.start >= 0x200).map((r) => s("rect", { x: xs(r.start), y: 0, width: xs(r.end) - xs(r.start), height: Hh, class: `en-band k-${r.kind}` }));
    const pts = T.offsets.map((o, i) => `${xs(o + T.window / 2).toFixed(1)},${ys(T.values[i]).toFixed(1)}`).join(" ");
    const cursor = s("line", { class: "en-cur", x1: 0, x2: 0, y1: 0, y2: Hh });
    const along = s("svg", { class: "en-along", viewBox: `0 0 ${W} ${Hh + 18}`, role: "img", "aria-label": L("en.along") },
      ...bands, s("polyline", { points: pts, class: "en-line" }), s("line", { x1: 0, x2: W, y1: ys(7), y2: ys(7), class: "en-ref" }), cursor,
      ...["header", ".text", ".rdata", ".data", "overlay"].map((k, i) => s("text", { x: xs([0, 0x200, 0x400, 0x600, 0x800][i]) + 4, y: Hh + 14, class: "en-lbl", text: k === "header" ? "headers" : k })));
    const alongRead = h("p", { class: "lab-mono en-alread", "aria-live": "polite" });
    along.addEventListener("mousemove", (e) => {
      const b = along.getBoundingClientRect(); const o = ((e.clientX - b.left) / b.width) * D.sample.size;
      let i = 0; while (i < T.offsets.length - 1 && T.offsets[i] + T.window / 2 < o) i++;
      cursor.setAttribute("x1", xs(T.offsets[i] + T.window / 2)); cursor.setAttribute("x2", xs(T.offsets[i] + T.window / 2));
      alongRead.textContent = `0x${hex(T.offsets[i], 4)}–0x${hex(T.offsets[i] + T.window, 4)} · H = ${T.values[i].toFixed(3)}`;
    });
    el.append(
      h("div", { class: "lab-story" }, h("p", { text: L("en.l1") }), h("p", { lv: "2", text: L("en.l2") })),
      h("div", { class: "en-pair" }, panel("a"), panel("b")),
      h("p", { class: "lab-cap", id: "en-mixhint", text: L("en.mixHint") }),
      h("p", { class: "lab-warn", text: L("en.warn") }),
      h("figure", { class: "en-alongfig", lv: "2" }, h("figcaption", {}, tagEl("real"), " ", L("en.along")), along, alongRead, h("p", { class: "lab-cap", text: L("en.alongNote") })));
  }

  /* ================================================================ 3 · fingerprint */
  function buildHash(el) {
    const ta = h("textarea", { class: "lab-input hs-in", rows: "3", maxlength: "2000", spellcheck: "false", "aria-label": L("hs.input") });
    ta.value = state.hs.text;
    const algo = h("select", { class: "lab-select", "aria-label": L("hs.algo") }, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((a) => h("option", { value: a, text: a })));
    algo.value = state.hs.algo;
    const flip = h("button", { type: "button", class: "lab-btn", text: L("hs.flip") });
    const inBytes = ltr(h("p", { class: "lab-mono hs-bytes" })), digest = ltr(h("p", { class: "hs-digest" }));
    const grid = h("div", { class: "hs-grid", role: "img", "aria-label": L("hs.grid") });
    const changed = h("p", { class: "hs-changed", "aria-live": "polite" });
    const flow = h("div", { class: "hs-flow", "aria-hidden": "true" });
    const padBox = h("div", { class: "hs-pad", lv: "3" });
    const verify = h("p", { class: "hs-verify", lv: "2" });
    let prevBits = null, prevAlgo = null;
    async function run() {
      const data = new TextEncoder().encode(ta.value);
      const buf = new Uint8Array(await crypto.subtle.digest(algo.value, data));
      const hexStr = [...buf].map((b) => hex(b).toLowerCase()).join("");
      const bits = []; for (const b of buf) for (let k = 7; k >= 0; k--) bits.push((b >> k) & 1);
      digest.textContent = hexStr;
      inBytes.textContent = [...data.slice(0, 40)].map((b) => hex(b)).join(" ") + (data.length > 40 ? ` … (${data.length} bytes)` : ` (${data.length} bytes)`);
      let diff = 0;
      put(grid, ...bits.map((b, i) => { const ch = prevBits && prevAlgo === algo.value && prevBits[i] !== b; if (ch) diff++; return h("i", { class: `${b ? "one" : ""}${ch ? " ch" : ""}` }); }));
      grid.dataset.n = bits.length;
      changed.textContent = prevBits && prevAlgo === algo.value ? L("hs.changed")(diff, bits.length) : L("hs.first");
      prevBits = bits; prevAlgo = algo.value;
      // blocks and padding (SHA-1/256: 512-bit blocks, 64-bit length; SHA-384/512: 1024-bit blocks, 128-bit length)
      const blockBits = algo.value === "SHA-1" || algo.value === "SHA-256" ? 512 : 1024, lenBits = blockBits / 8;
      const L0 = data.length * 8, blocks = Math.ceil((L0 + 1 + lenBits) / blockBits);
      put(flow, h("span", { class: "hs-node", text: `${data.length} B` }), h("span", { class: "hs-arrow" }),
        h("span", { class: "hs-node blocks" }, Array.from({ length: Math.min(blocks, 8) }, () => h("i")), blocks > 8 ? h("small", { text: `+${blocks - 8}` }) : null),
        h("span", { class: "hs-arrow" }), h("span", { class: "hs-node", text: algo.value }), h("span", { class: "hs-arrow" }), h("span", { class: "hs-node out", text: `${buf.length * 8} bit` }));
      flow.classList.remove("go"); void flow.offsetWidth; if (!still()) flow.classList.add("go");
      const zeros = blocks * blockBits - L0 - 1 - lenBits;
      const segs = [[L0, L("hs.pad")[0]], [1, L("hs.pad")[1]], [zeros, L("hs.pad")[2]], [lenBits, L("hs.pad")[3]]];
      put(padBox, h("p", { class: "lab-mono", text: L("hs.blocks")(blocks, L0) }),
        h("div", { class: "hs-padbar" }, segs.map(([n, name], i) => { const b = h("span", { class: `p${i}`, title: `${name}: ${n} bits` }, h("small", { text: name })); b.style.flexGrow = String(Math.max(n, blocks * blockBits * 0.04)); return b; })),
        h("p", { class: "lab-cap", text: "FIPS 180-4. MD5 and SHA-1 are broken for collisions; CyberScan identifies files by SHA-256." }));
      state.hs.text = ta.value; state.hs.algo = algo.value;
    }
    ta.addEventListener("input", run); algo.addEventListener("change", () => { prevBits = null; run(); });
    flip.addEventListener("click", () => {
      const v = ta.value; if (!v) return;
      const i = [...v].findIndex((c) => /[a-z]/i.test(c)); if (i < 0) { ta.value = v + "!"; } else { const c = v[i]; ta.value = v.slice(0, i) + (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()) + v.slice(i + 1); }
      run();
    });
    (async () => {
      const dg = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      const got = [...dg].map((b) => hex(b).toLowerCase()).join(""), ok = got === D.sample.sha256;
      put(verify, tagEl("real"), " ", h("span", { text: `${L("hs.verify")}: ` }), ltr(h("code", { text: got.slice(0, 24) + "…" })), h("b", { class: ok ? "ok" : "bad", text: ` ${ok ? "✓" : "✗"} ${ok ? L("hs.match") : L("hs.nomatch")}` }));
    })();
    el.append(
      h("div", { class: "lab-story" }, h("p", { text: L("hs.l1") }), h("p", { lv: "2", text: L("hs.l2") })),
      h("div", { class: "hs-grid2" },
        h("div", { class: "hs-left" }, h("label", { class: "lab-cap", text: L("hs.input") }), ta, h("div", { class: "hs-row" }, flip, h("label", { class: "hs-algo" }, h("span", { text: L("hs.algo") }), algo)),
          h("div", { lv: "2" }, h("p", { class: "lab-cap", text: L("hs.inBytes") }), inBytes), flow, padBox),
        h("div", { class: "hs-right" }, h("p", { class: "lab-cap" }, tagEl("real"), " ", L("hs.digest")), digest, grid, h("p", { class: "lab-cap", text: L("hs.grid") }), changed, verify)));
    run();
  }

  /* ================================================================ 4 · pipeline */
  function pipelineStages() {
    const sc = D.scan, f = sc.features, es = sc.engine_status || {}, ev = sc.evidence;
    const evs = (cats) => ev.filter((e) => cats.includes(e.category)).map((e) => `${e.evidence} (+${e.contribution})`).join(" · ") || "—";
    return [
      { id: "intake", st: "live", res: `${fmtEn(D.sample.size)} B · type “${D.sample.sniffed_type}” · SHA-256 ${D.sample.sha256.slice(0, 16)}…`, src: "detection/engine.py · sniff_type; hashlib" },
      { id: "name", st: "live", res: `double extension: ${f.double_extension ? "yes" : "no"} · magic mismatch: ${f.magic_mismatch ? "yes" : "no"} → ${evs(["structural", "heuristic"])}`, src: "core/file_analyzer.py · core/heuristic_engine.py" },
      { id: "pe", st: "live", res: `${sc.pe.section_count} sections · imports: ${(sc.pe.import_names || []).join(", ")} · ${(sc.pe.findings || [])[0] || ""} · ${evs(["signature"])}`, src: "core/pe_decompiler.py (pefile) · core/authenticode.py" },
      { id: "cfg", st: "live", res: `${sc.cfg.basic_block_count} blocks · ${sc.cfg.edge_count} edge(s) · M = ${sc.cfg.cyclomatic_complexity} · descriptive pattern: ${(sc.cfg.detected_patterns || []).join(", ") || "none"} (never warns) · evidence patterns: ${(sc.cfg.evidence_patterns || []).length || "none"}`, src: "core/nextgen_engine.py · extract_cfg_topology (Capstone, linear sweep)" },
      { id: "sig", st: "live", res: `YARA: ${es.YARA || "?"} · matches: ${sc.yara_matches || 0}`, src: "core/yara_engine.py (YARA-X); production loads YARA-Forge when installed" },
      { id: "stats", st: "live", res: `entropy ${f.entropy} bits/byte (4 KiB window) · dissonance: ${es.Dissonance || "?"} · surprise map: ${es["Surprise map"] || "?"}`, src: "core/entropy.py · core/dissonance.py · core/surprise_map.py" },
      { id: "content", st: "live", res: `file type ${sc.content.file_type} · score ${sc.content.score} · ${sc.content.classification} · ${(sc.content.findings || []).length} finding(s)`, src: "detection/engine.py · inspect_content → detection/executables.py" },
      { id: "ml", st: "none", res: sc.model_status, src: "ml/structural_classifier.py · runs only with an operator-approved model hash" },
      { id: "osint", st: "off", res: "Off by default. When switched on, only the SHA-256 is sent (ThreatFox, URLhaus, OTX in parallel, 450 ms budget).", src: "core/global_intelligence.py" },
      { id: "fusion", st: "live", res: `combined score ${sc.combined_score}/100 → ${sc.classification} (max of evidence contributions)`, src: "core/risk_engine.py · finalize_result, classify_risk" },
    ];
  }
  let plTimer = null;
  function buildPipeline(el) {
    const ST = pipelineStages();
    const nodes = ST.map((x, i) => h("button", { type: "button", class: `pl-node st-${x.st}`, "data-i": i, "aria-pressed": "false", on: { click: () => { pause(); go_(i); } } },
      h("span", { class: "pl-dot" }, h("b", { text: String(i + 1) })), h("span", { class: "pl-name", text: L(`pl.stages.${x.id}`)[0] })));
    const token = h("span", { class: "pl-token", "aria-hidden": "true" }, icon("M7 3h7l5 5v13H7zM14 3v5h5"));
    const track = h("div", { class: "pl-track" }, h("span", { class: "pl-rail", "aria-hidden": "true" }, h("i")), nodes, token);
    const btn = (k, fn, d) => h("button", { type: "button", class: "lab-btn icon", "aria-label": L(`ctl.${k}`), title: L(`ctl.${k}`), on: { click: fn } }, icon(d));
    const playBtn = btn("play", () => (state.pl.playing ? pause() : play()), "M8 5v14l11-7z");
    const ctl = h("div", { class: "pl-ctl" }, btn("prev", () => { pause(); go_(Math.max(0, state.pl.i - 1)); }, "M15 6l-6 6 6 6"), playBtn,
      btn("next", () => { pause(); go_(Math.min(ST.length - 1, state.pl.i + 1)); }, "M9 6l6 6-6 6"), btn("replay", () => { go_(0); play(); }, "M4 12a8 8 0 1 0 2.4-5.7M4 4v4.5h4.5"),
      h("span", { class: "pl-sealed" }, icon("M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5z", "lab-ic sm"), L("pl.sealed")));
    const insp = h("div", { class: "lab-insp pl-insp", "aria-live": "polite" });
    function go_(i) {
      state.pl.i = i;
      nodes.forEach((n, k) => { n.classList.toggle("done", k < i); n.classList.toggle("on", k === i); n.setAttribute("aria-pressed", String(k === i)); });
      const r = nodes[i];
      token.style.transform = `translate(${r.offsetLeft + r.offsetWidth / 2}px, ${r.offsetTop}px)`;
      track.querySelector(".pl-rail i").style.transform = `scaleX(${i / (ST.length - 1)})`;
      const x = ST[i], t = L(`pl.stages.${x.id}`);
      put(insp, 
        h("p", { class: "lab-kicker" }, h("span", { class: "lab-mono", text: `${i + 1}/${ST.length}` }), tagEl(x.st)),
        h("h5", { text: t[0] }), h("p", { text: t[1] }),
        h("dl", { class: "lab-kv pl-io", lv: "2" }, h("dt", { text: L("pl.receives") }), h("dd", { text: t[2] }), h("dt", { text: L("pl.examines") }), h("dd", { text: t[3] }), h("dt", { text: L("pl.produces") }), h("dd", { text: t[4] })),
        h("div", { class: "pl-res" }, h("p", { class: "lab-cap" }, tagEl("real"), " ", L("pl.result")), ltr(h("p", { class: "lab-mono", text: x.res }))),
        ltr(h("p", { class: "lab-tech", lv: "3", text: x.src })),
        x.id === "name" || x.id === "fusion" ? h("button", { type: "button", class: "lab-link", text: L("mods.evidence")[0] + " →", on: { click: () => go("evidence") } }) : null,
        x.id === "pe" || x.id === "intake" ? h("button", { type: "button", class: "lab-link", text: L("mods.explorer")[0] + " →", on: { click: () => go("explorer") } }) : null);
    }
    function play() {
      if (still()) { go_(ST.length - 1); return; }
      state.pl.playing = true; playBtn.setAttribute("aria-label", L("ctl.pause")); playBtn.title = L("ctl.pause"); playBtn.querySelector("path").setAttribute("d", "M7 5h4v14H7zm6 0h4v14h-4z");
      clearInterval(plTimer);
      if (state.pl.i >= ST.length - 1) go_(0);
      plTimer = setInterval(() => { if (!live) return; if (state.pl.i >= ST.length - 1) { pause(); return; } go_(state.pl.i + 1); }, 1700);
    }
    function pause() {
      state.pl.playing = false; clearInterval(plTimer); plTimer = null;
      playBtn.setAttribute("aria-label", L("ctl.play")); playBtn.title = L("ctl.play"); playBtn.querySelector("path").setAttribute("d", "M8 5v14l11-7z");
    }
    el.append(h("div", { class: "pl-wrap" }, track), ctl, insp, foot());
    requestAnimationFrame(() => go_(state.pl.i));
    addEventListener("resize", () => { if (!el.hidden) go_(state.pl.i); }, { passive: true });
    return { onShow: () => requestAnimationFrame(() => go_(state.pl.i)), onHide: pause };
  }

  /* ================================================================ 5 · evidence */
  function buildEvidence(el) {
    const view = h("div", { class: "ev-view" }), insp = h("div", { class: "lab-insp ev-insp", "aria-live": "polite" });
    const rename = h("div", { class: "ev-rename", role: "radiogroup", "aria-label": L("ev.rename") },
      h("span", { class: "lab-cap", text: L("ev.rename") + ":" }),
      ...[[false, D.scan.name, L("ev.tricky")], [true, D.scan_honest.name, L("ev.honest")]].map(([honest, name, label]) =>
        h("button", { type: "button", role: "radio", class: "lab-btn", "aria-checked": String(state.ev.honest === honest), on: { click: () => { state.ev.honest = honest; state.ev.off.clear(); state.ev.sel = 0; draw(); rename.querySelectorAll("button").forEach((b, k) => b.setAttribute("aria-checked", String(k === (honest ? 1 : 0)))); } } },
          ltr(h("code", { text: name })), h("small", { text: label }))));
    const tiers = h("ol", { class: "ev-tiers" }, L("ev.tiers").map(([n, d], i) => h("li", { class: `t${i}` }, h("b", { text: n }), h("span", { text: d }))));
    const group = (label) => D.correlated[label] || ("label:" + label);
    function compute(list) {
      const on = list.filter((e, i) => !state.ev.off.has(i));
      const host = on.reduce((m, e) => Math.max(m, e.contribution), 0);
      const strongest = {}; for (const e of on) { const g = group(e.evidence); strongest[g] = Math.max(strongest[g] || 0, e.contribution); }
      let rem = 1; for (const g in strongest) rem *= 1 - Math.min(100, Math.max(0, strongest[g])) / 100;
      return { host, noisy: Math.round(100 * (1 - rem)), strongest };
    }
    const cls = (sc) => (sc >= 50 ? "SUSPICIOUS" : sc > 0 ? "REVIEW" : "NO_INDICATORS_OBSERVED");
    function draw() {
      const sc = state.ev.honest ? D.scan_honest : D.scan, list = sc.evidence;
      const counts = {}; list.forEach((e) => { const g = group(e.evidence); counts[g] = (counts[g] || 0) + 1; });
      const tier = (e) => (counts[group(e.evidence)] > 1 && e.contribution > 0 ? 2 : e.contribution > 0 ? 1 : 0);
      const r = compute(list);
      const W = 700, rowH = 56, Hh = Math.max(300, list.length * rowH + 80), y0 = (Hh - list.length * rowH) / 2 + rowH / 2;
      const gIds = [...new Set(list.filter((e) => counts[group(e.evidence)] > 1).map((e) => group(e.evidence)))];
      const svg = s("svg", { class: "ev-graph", viewBox: `0 0 ${W} ${Hh}`, role: "img", "aria-label": `${list.length} findings → score ${r.host}` });
      const fileY = Hh / 2, scoreX = 612;
      svg.append(s("g", { class: "ev-file" }, s("rect", { x: 14, y: fileY - 34, width: 150, height: 68, rx: 12 }),
        s("text", { x: 89, y: fileY - 6, class: "ev-t1", text: L("ev.file") }), s("text", { x: 89, y: fileY + 16, class: "ev-t2", text: sc.name })));
      const gy = {};
      gIds.forEach((g) => { const ys = list.map((e, i) => [e, i]).filter(([e]) => group(e.evidence) === g).map(([, i]) => y0 + i * rowH); gy[g] = ys.reduce((a, b) => a + b, 0) / ys.length; });
      const order = [...gIds].sort((a, b) => gy[a] - gy[b]);
      order.forEach((g, k) => { if (k && gy[g] - gy[order[k - 1]] < 58) gy[g] = gy[order[k - 1]] + 58; });
      if (order.length > 1) { const shift = (gy[order[0]] + gy[order[order.length - 1]]) / 2 - Hh / 2; order.forEach((g) => { gy[g] -= shift; }); }
      list.forEach((e, i) => {
        const y = y0 + i * rowH, off = state.ev.off.has(i), t = tier(e), g = group(e.evidence);
        svg.append(s("path", { class: `ev-edge${off ? " off" : ""}`, d: `M164 ${fileY} C210 ${fileY} 210 ${y} 250 ${y}` }));
        const to = gIds.includes(g) ? [478, gy[g]] : [scoreX - 58, Hh / 2];
        svg.append(s("path", { class: `ev-edge out t${t}${off ? " off" : ""}${e.contribution === 0 ? " zero" : ""}`, d: `M450 ${y} C${(450 + to[0]) / 2} ${y} ${(450 + to[0]) / 2} ${to[1]} ${to[0]} ${to[1]}` }));
        const node = s("g", { class: `ev-node t${t}${off ? " off" : ""}${state.ev.sel === i ? " sel" : ""}`, tabindex: "0", role: "button", "aria-pressed": String(state.ev.sel === i), "aria-label": `${e.evidence}, +${e.contribution}` },
          s("rect", { x: 250, y: y - 21, width: 200, height: 42, rx: 9 }), s("text", { x: 262, y: y + 5, class: "ev-t3", text: e.evidence.length > 21 ? e.evidence.slice(0, 20) + "…" : e.evidence }),
          s("text", { x: 440, y: y + 5, class: "ev-pts", text: `+${e.contribution}` }));
        const pick = () => { state.ev.sel = i; draw(); };
        node.addEventListener("click", pick); node.addEventListener("keydown", (k) => { if (k.key === "Enter" || k.key === " ") { k.preventDefault(); pick(); } });
        svg.append(node);
      });
      gIds.forEach((g) => {
        svg.append(s("path", { class: "ev-edge out t2", d: `M558 ${gy[g]} C580 ${gy[g]} 580 ${Hh / 2} ${scoreX - 58} ${Hh / 2}` }));
        svg.append(s("g", { class: "ev-group" }, s("rect", { x: 478, y: gy[g] - 24, width: 80, height: 48, rx: 24 }), s("text", { x: 518, y: gy[g] - 3, class: "ev-t3c", text: "group" }), s("text", { x: 518, y: gy[g] + 14, class: "ev-t4", text: `max ${r.strongest[g] || 0}` })));
      });
      const verdict = cls(r.host);
      svg.append(s("g", { class: `ev-score v-${verdict}` }, s("circle", { cx: scoreX + 30, cy: Hh / 2, r: 58 }),
        s("text", { x: scoreX + 30, y: Hh / 2 + 4, class: "ev-big", text: String(r.host) }), s("text", { x: scoreX + 30, y: Hh / 2 + 26, class: "ev-t4", text: "/100" })));
      const checks = h("ul", { class: "ev-checks" }, list.map((e, i) => h("li", {}, h("label", {},
        h("input", { type: "checkbox", checked: !state.ev.off.has(i), on: { change: (x) => { if (x.target.checked) state.ev.off.delete(i); else state.ev.off.add(i); state.ev.sel = i; draw(); } } }),
        ltr(h("span", { text: e.evidence })), h("b", { text: `+${e.contribution}` })))));
      const result = h("div", { class: `ev-result v-${verdict}` },
        h("p", { class: "ev-verdict" }, h("small", { text: L("ev.score") }), h("b", { text: `${r.host}/100` }), h("strong", { text: L(`ev.verdicts.${verdict}`) })),
        ltr(h("p", { class: "lab-mono", lv: "3", text: `${L("ev.host")}: max(${list.filter((e, i) => !state.ev.off.has(i)).map((e) => e.contribution).join(", ") || "∅"}) = ${r.host}` })),
        ltr(h("p", { class: "lab-mono", lv: "3", text: `${L("ev.noisy")}: 1 − Π(1 − cᵍ/100) = ${r.noisy}` })),
        gIds.length ? h("p", { class: "lab-cap ev-gnote", text: L("ev.groupNote") }) : null);
      put(view, h("div", { class: "ev-gwrap" }, svg), h("div", { class: "ev-side" }, h("p", { class: "lab-cap", lv: "2", text: L("ev.include") }), h("div", { lv: "2" }, checks), result));
      // inspector for the selected finding
      const e = list[state.ev.sel] || list[0];
      if (e) {
        const t = tier(e);
        put(insp, h("p", { class: "lab-kicker" }, tagEl("real"), h("span", { class: `ev-tierchip t${t}`, text: L("ev.tiers")[t][0] })),
          ltr(h("h5", { text: e.evidence })), ltr(h("p", { text: e.explanation })),
          h("dl", { class: "lab-kv", lv: "2" }, h("dt", { text: "category" }), ltr(h("dd", { text: e.category })), h("dt", { text: "severity" }), ltr(h("dd", { text: e.severity })), h("dt", { text: "contribution" }), h("dd", { text: `+${e.contribution}` })),
          ltr(h("p", { class: "lab-tech", lv: "3", text: `correlation group: ${group(e.evidence)}${counts[group(e.evidence)] > 1 ? ` (${counts[group(e.evidence)]} findings, strongest counted)` : ""}` })));
      }
      const note = (sc.pe.findings || [])[0];
      if (note) insp.append(h("div", { class: "ev-note", lv: "2" }, h("p", { class: "lab-cap", text: L("ev.noteFrom") }), ltr(h("p", { text: note })),
        h("button", { type: "button", class: "lab-link", text: L("ev.jump") + " → Subsystem", on: { click: () => go("explorer", (p) => p.field("Subsystem")) } })));
    }
    el.append(h("div", { class: "lab-story" }, h("p", { text: L("ev.l1") }), h("p", { lv: "2", text: L("ev.l2") })), rename, view, h("div", { class: "ev-bottom" }, insp, tiers), foot());
    draw();
  }

  /* ================================================================ 6 · network */
  const NW = [
    { id: "user", st: ["info"] }, { id: "url", st: ["live", "live", "dev"] }, { id: "dns", st: ["dev"] }, { id: "ip", st: ["live", "dev"] },
    { id: "tls", st: ["dev"] }, { id: "server", st: ["dev"] }, { id: "page", st: ["live", "dev"] }, { id: "download", st: ["live"] },
  ];
  function buildNetwork(el) {
    const nodes = NW.map((n, i) => h("button", { type: "button", class: `nw-node${n.st.includes("live") ? " has-live" : ""}`, "data-i": i, "aria-pressed": "false", on: { click: () => pick(i) } },
      icon(NW_ICONS[n.id]), h("span", { text: L(`nw.nodes.${n.id}`)[0] })));
    const chain = h("div", { class: "nw-chain" }, nodes.flatMap((n, i) => (i ? [h("span", { class: "nw-link", "aria-hidden": "true" }, h("i")), n] : [n])));
    const insp = h("div", { class: "lab-insp nw-insp", "aria-live": "polite" });
    function pick(i) {
      state.nw.node = NW[i].id;
      nodes.forEach((n, k) => { n.classList.toggle("on", k === i); n.classList.toggle("path", k < i); n.setAttribute("aria-pressed", String(k === i)); });
      chain.querySelectorAll(".nw-link").forEach((l, k) => { l.classList.toggle("lit", k < i); l.style.setProperty("--d", `${k * 90}ms`); });
      const n = NW[i];
      put(insp, h("h5", { text: L(`nw.nodes.${n.id}`)[0] }), h("p", { text: L(`nw.nodes.${n.id}`)[1] }),
        h("p", { class: "lab-cap", lv: "2", text: L("nw.inspect") }),
        h("ul", { class: "nw-caps", lv: "2" }, (L(`nw.caps.${n.id}`) || []).map((txt, k) => h("li", {}, tagEl(n.st[k]), h("span", { text: txt })))));
    }
    // real URL analysis on reserved documentation domains
    const list = h("div", { class: "nw-urls", role: "radiogroup", "aria-label": L("nw.pick") }, D.urls.map((u, i) => h("button", {
      type: "button", role: "radio", class: "nw-url", "aria-checked": String(state.nw.url === i), on: { click: () => { state.nw.url = i; showUrl(); } },
    }, ltr(h("code", { text: u.url })), h("b", { class: `nw-score v-${u.classification}`, text: String(u.score) }))));
    const own = h("input", { type: "url", class: "lab-input", placeholder: "https://…", "aria-label": L("nw.parsed"), dir: "ltr", spellcheck: "false" });
    const anat = h("div", { class: "nw-anat" }), finds = h("div", { class: "nw-finds" });
    function anatomy(urlStr, real) {
      let u; try { u = new URL(urlStr); } catch { put(anat, h("p", { class: "lab-cap", text: "—" })); return; }
      const host = real ? real.unicode_host || u.hostname : u.hostname;
      const hostSpans = [...host].map((c) => h("span", { class: /[^\x00-\x7f]/.test(c) ? "odd" : "", title: /[^\x00-\x7f]/.test(c) ? `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}` : null, text: c }));
      const rows = [["scheme", u.protocol.replace(":", "")], ["host", u.hostname], ["unicode", null], ["domain", real ? real.registrable_domain : "—"], ["path", u.pathname], ["query", u.search || "—"]];
      put(anat, ltr(h("dl", { class: "lab-kv" }, rows.flatMap(([k, v]) => (k === "unicode" ? [h("dt", { text: L(`nw.parts.${k}`) }), h("dd", { class: "nw-host" }, hostSpans)] : [h("dt", { text: L(`nw.parts.${k}`) }), h("dd", { text: v })])))));
    }
    function showUrl() {
      const u = D.urls[state.nw.url];
      list.querySelectorAll(".nw-url").forEach((b, k) => b.setAttribute("aria-checked", String(k === state.nw.url)));
      anatomy(u.url, u);
      put(finds, h("p", { class: "lab-cap" }, tagEl("real"), ` ${L("nw.findings")} · ${u.score}/100 · ${u.classification}${u.impersonated_brand ? ` · brand: ${u.impersonated_brand}` : ""}`),
        ltr(h("ul", { class: "nw-flist" }, (u.findings || []).length ? u.findings.map((f) => h("li", {}, h("b", { text: `+${f.contribution}` }), h("span", { text: f.label || f.evidence }), h("small", { lv: "3", text: f.explanation }))) : [h("li", { text: "No red flags (not a guarantee)." })])));
    }
    own.addEventListener("input", () => { if (own.value.trim()) { anatomy(own.value.trim(), null); put(finds, h("p", { class: "lab-cap", text: L("nw.scanIt") })); } else showUrl(); });
    el.append(h("p", { class: "lab-cap nw-sim" }, tagEl("sim"), " ", L("nw.sim")), h("div", { class: "nw-wrap" }, chain), insp,
      h("section", { class: "nw-try" }, h("h5", { text: L("nw.try") }), h("p", { class: "lab-cap", text: L("nw.pick") }), list,
        h("div", { class: "nw-tgrid" }, h("div", {}, h("p", { class: "lab-cap", text: L("nw.anatomy") }), anat, h("label", { class: "lab-cap", lv: "2" }, L("nw.parsed"), own)), finds)), foot());
    pick(Math.max(0, NW.findIndex((n) => n.id === state.nw.node))); showUrl();
  }
  const NW_ICONS = { user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0", url: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
    dns: "M4 4h16v6H4zm0 10h16v6H4zM8 7h.01M8 17h.01", ip: "M5 12h14M12 5v14M7 7l10 10M17 7 7 17", tls: "M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5zM12 15v2",
    server: "M4 4h16v7H4zm0 9h16v7H4zM8 7.5h.01M8 16.5h.01", page: "M4 4h16v16H4zM4 9h16M9 9v11", download: "M12 4v12m-5-5 5 5 5-5M5 20h14" };

  /* ================================================================ 7 · domains */
  const DOM_DIR = ["file_security", "malware_analysis", "url_domain_security", "website_security", "email_security", "network_security", "system_security", "privacy_data_protection", "code_dependency_security", "cloud_infrastructure"];
  const DOM_ICON = ["M7 3h7l5 5v13H7zM14 3v5h5", "M12 3a5 5 0 0 0-5 5v3l-2 3h14l-2-3V8a5 5 0 0 0-5-5zM9 18a3 3 0 0 0 6 0", ICONS.network, "M4 4h16v16H4zM4 9h16",
    "M3 6h18v12H3zM3 7l9 6 9-6", "M5 15h14v5H5zM12 15V9m-4-2a5.5 5.5 0 0 1 8 0", "M4 5h16v11H4zM2 20h20", "M12 3 5 6v5c0 4.5 3 8.2 7 9.5 4-1.3 7-5 7-9.5V6z",
    "M8 8 4 12l4 4m8-8 4 4-4 4M14 5l-4 14", "M7 18h10a4 4 0 0 0 .6-8A6 6 0 0 0 6.2 9.5 4.3 4.3 0 0 0 7 18z"];
  const REL = [[4, 2, "links in messages", "الروابط داخل الرسائل"], [4, 0, "attachments", "المرفقات"], [0, 1, "programs inside files", "البرامج داخل الملفات"], [2, 0, "downloads", "التنزيلات"],
    [2, 3, "the site behind a link", "الموقع خلف الرابط"], [3, 5, "TLS and DNS", "TLS وDNS"], [5, 6, "open services on a computer", "الخدمات المفتوحة على الحاسوب"],
    [6, 1, "startup items and processes", "عناصر بدء التشغيل والعمليات"], [7, 0, "secrets inside files", "الأسرار داخل الملفات"], [8, 7, "keys and passwords in code", "المفاتيح وكلمات المرور في الشيفرة"],
    [9, 8, "infrastructure written as code", "البنية التحتية المكتوبة كشيفرة"], [9, 5, "exposed services", "الخدمات المكشوفة"]];
  function buildDomains(el) {
    const W = 600, Hh = 520, cx = 300, cy = 260, R = 205;
    const P = DOM_DIR.map((_, i) => { const a = (-90 + i * 36) * Math.PI / 180; return [cx + R * Math.cos(a), cy + R * Math.sin(a)]; });
    const edges = REL.map(([a, b]) => s("path", { class: "dm-edge", d: `M${P[a][0].toFixed(1)} ${P[a][1].toFixed(1)} Q${cx} ${cy} ${P[b][0].toFixed(1)} ${P[b][1].toFixed(1)}` }));
    const svg = s("svg", { class: "dm-graph", viewBox: `0 0 ${W} ${Hh}`, "aria-hidden": "true" }, s("circle", { class: "dm-orbit", cx, cy, r: R }), ...edges,
      s("circle", { class: "dm-core", cx, cy, r: 44 }), s("text", { class: "dm-coret", x: cx, y: cy + 5, text: "CyberScan" }));
    const doms = L("domains");
    const btns = doms.map((d, i) => {
      const b = h("button", { type: "button", class: `dm-node ${d.s}`, "aria-pressed": "false", on: { click: () => pick(i) } }, icon(DOM_ICON[i]), h("span", { text: d.n }));
      b.style.left = `${(P[i][0] / W) * 100}%`; b.style.top = `${(P[i][1] / Hh) * 100}%`;
      return b;
    });
    const stage = h("div", { class: "dm-stage" }, svg, h("div", { class: "dm-nodes", role: "group", "aria-label": L("mods.domains")[0] }, btns));
    stage.addEventListener("keydown", (e) => {
      const i = btns.indexOf(document.activeElement); if (i < 0 || !["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp"].includes(e.key)) return;
      e.preventDefault(); const j = (i + (e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : -1) + 10) % 10; btns[j].focus(); pick(j);
    });
    const insp = h("div", { class: "lab-insp dm-insp", "aria-live": "polite" });
    async function pick(i) {
      state.dm.i = i;
      btns.forEach((b, k) => { b.setAttribute("aria-pressed", String(k === i)); b.classList.toggle("rel", REL.some(([a, c]) => (a === i && c === k) || (c === i && a === k))); });
      edges.forEach((e, k) => e.classList.toggle("on", REL[k][0] === i || REL[k][1] === i));
      const d = doms[i], ar = lang() === "ar";
      const rels = REL.filter(([a, b]) => a === i || b === i).map(([a, b, en, arT]) => h("li", {}, h("button", { type: "button", class: "lab-link", text: doms[a === i ? b : a].n, on: { click: () => pick(a === i ? b : a) } }), h("span", { text: ` · ${ar ? arT : en}` })));
      const toolsBox = h("div", { class: "dm-tools", lv: "2" }, h("p", { class: "lab-cap", text: L("loading") }));
      put(insp, h("p", { class: "lab-kicker" }, h("span", { class: "dm-ic" }, icon(DOM_ICON[i])), tagEl(d.s)), h("h5", { text: d.n }), h("p", { text: d.l1 }), h("p", { class: "lab-l2", lv: "2", text: d.l2 }),
        h("p", { class: "lab-cap", text: L("dm.relations") }), h("ul", { class: "dm-rels" }, rels), toolsBox);
      const T = await tools();
      if (state.dm.i !== i) return;
      if (!T) { put(toolsBox); return; }
      const mine = T.discovery_all_categories.filter((r) => r.relative_path.startsWith(DOM_DIR[i] + "/"));
      put(toolsBox, h("p", { class: "lab-cap" }, tagEl("real"), " ", L("dm.catalogNote")(mine.length)),
        h("ul", { class: "dm-tlist" }, mine.map((r) => h("li", {}, h("button", { type: "button", class: "lab-link", on: { click: () => go("registry", (p) => p.show(r.tool_id)) } }, ltr(h("span", { text: r.name }))), h("small", { lv: "3", class: "lab-mono", text: r.tool_id })))));
    }
    el.append(h("div", { class: "dm-grid" }, stage, insp));
    pick(state.dm.i);
  }

  /* ================================================================ 8 · registry */
  async function tools() {
    if (TOOLS !== null) return TOOLS;
    try { const r = await fetch("data/lab-tools.json", { credentials: "same-origin" }); TOOLS = r.ok ? await r.json() : false; } catch { TOOLS = false; }
    return TOOLS;
  }
  function schemaTree(schema, name, required) {
    if (!schema || typeof schema !== "object") return h("li", { text: String(schema) });
    const facets = [schema.type, schema.enum ? `enum(${schema.enum.join(" | ")})` : null, schema.maxLength != null ? `≤${schema.maxLength} chars` : null,
      schema.maxItems != null ? `≤${schema.maxItems} items` : null, schema.minimum != null ? `≥${schema.minimum}` : null, schema.maximum != null ? `≤${schema.maximum}` : null].filter(Boolean).join(" · ");
    const kids = [];
    if (schema.properties) for (const k in schema.properties) kids.push(schemaTree(schema.properties[k], k, (schema.required || []).includes(k)));
    if (schema.items) kids.push(schemaTree(schema.items, "[ ]", false));
    return h("li", {}, h("span", { class: "sk" }, name ? h("b", { text: name + (required ? " *" : "") }) : null, h("code", { text: facets || "any" })), kids.length ? h("ul", {}, kids) : null);
  }
  function buildRegistry(el) {
    const steps = h("ol", { class: "rg-steps" }, L("rg.steps").map(([n, d], i) => h("li", { "data-i": i }, h("span", { class: "rg-n", text: String(i + 1) }), h("b", { text: n }), h("small", { text: d }))));
    const toggle = h("div", { class: "rg-config", role: "radiogroup" }, [L("rg.configReal"), L("rg.configAll")].map((t, k) =>
      h("button", { type: "button", role: "radio", class: "lab-btn", "aria-checked": String(state.rg.all === (k === 1)), on: { click: () => { state.rg.all = k === 1; render(); } } }, t)));
    const search = h("input", { type: "search", class: "lab-input", placeholder: L("rg.search"), "aria-label": L("rg.search"), value: state.rg.q });
    const cats = h("div", { class: "rg-cats" }), list = h("ul", { class: "rg-list", role: "listbox", "aria-label": L("mods.registry")[0] }), card = h("div", { class: "lab-insp rg-card", "aria-live": "polite" });
    const counts = h("p", { class: "rg-count" });
    search.addEventListener("input", () => { state.rg.q = search.value; render(); });
    let T = null;
    function records() { return T ? (state.rg.all ? T.discovery_all_categories : T.discovery_real) : []; }
    function render() {
      toggle.querySelectorAll("button").forEach((b, k) => b.setAttribute("aria-checked", String(state.rg.all === (k === 1))));
      const recs = records(), q = state.rg.q.trim().toLowerCase();
      const byCat = {}; recs.forEach((r) => { const c = r.relative_path.split("/")[0]; byCat[c] = (byCat[c] || 0) + 1; });
      const max = Math.max(1, ...Object.values(byCat));
      put(cats, ...Object.entries(byCat).map(([c, n]) => {
        const b = h("button", { type: "button", class: `rg-cat${state.rg.cat === c ? " on" : ""}`, "aria-pressed": String(state.rg.cat === c), on: { click: () => { state.rg.cat = state.rg.cat === c ? "" : c; render(); } } },
          ltr(h("span", { text: c })), h("b", { text: String(n) }), h("i")); b.lastChild.style.transform = `scaleX(${n / max})`; return b;
      }));
      put(counts, tagEl("real"), " ", ltr(h("code", { text: `registry.json → approved_directories: ${JSON.stringify(state.rg.all ? T.categories : T.registry_json.approved_directories)}, trusted_tools: ${T.registry_json.trusted_tools}` })),
        h("br"), h("span", { text: `${L("rg.found")(recs.length)}. ${L("rg.allDisabled")}` }));
      const shown = recs.filter((r) => (!state.rg.cat || r.relative_path.startsWith(state.rg.cat + "/")) && (!q || `${r.name} ${r.tool_id} ${r.description}`.toLowerCase().includes(q)));
      put(list, ...shown.slice(0, 200).map((r) => h("li", {}, h("button", { type: "button", role: "option", class: `rg-item${state.rg.tool === r.tool_id ? " on" : ""}`, "aria-selected": String(state.rg.tool === r.tool_id), on: { click: () => show(r.tool_id) } },
        ltr(h("span", { text: r.name })), h("small", { class: `rg-st ${r.status}`, text: r.status })))));
      if (!recs.some((r) => r.tool_id === state.rg.tool) && recs[0]) state.rg.tool = (recs.find((r) => r.relative_path.includes("kubernetes")) || recs[0]).tool_id;
      showCard();
    }
    function show(id) { state.rg.tool = id; state.rg.sim = ""; const r = records().find((x) => x.tool_id === id); if (!r) { state.rg.all = true; } render(); const b = list.querySelector(".rg-item.on"); if (b) b.scrollIntoView({ block: "nearest" }); }
    async function showCard() {
      const r = records().find((x) => x.tool_id === state.rg.tool); if (!r) { put(card); return; }
      let status = r.status, reason = r.error, sha = r.sha256;
      if (state.rg.sim === "approve") { status = "available"; reason = null; }
      if (state.rg.sim === "edit") { status = "disabled"; reason = "approval_hash_mismatch"; sha = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(r.sha256 + "\n# edited")))].map((b) => hex(b).toLowerCase()).join(""); }
      const stepAt = state.rg.sim === "approve" ? 5 : 4;
      steps.querySelectorAll("li").forEach((li, k) => { li.classList.toggle("done", k < stepAt); li.classList.toggle("on", k === stepAt); li.classList.toggle("bad", state.rg.sim === "edit" && k === 4); });
      const proc = r.processing || {}, blocked = ["network", "filesystem", "executes_files"].filter((k) => proc[k] === true);
      const out = T.output_schemas[r.output_schema_ref];
      put(card, 
        h("p", { class: "lab-kicker" }, tagEl("real"), h("span", { class: `rg-st ${status}`, text: status }), reason ? ltr(h("code", { class: "rg-reason", text: reason })) : null, state.rg.sim ? tagEl("sim") : null),
        ltr(h("h5", { text: r.name })), ltr(h("p", { text: r.description })),
        h("div", { class: "rg-simbar" }, h("button", { type: "button", class: "lab-btn", text: L("rg.simApprove"), on: { click: () => { state.rg.sim = "approve"; showCard(); } } }),
          h("button", { type: "button", class: "lab-btn", text: L("rg.simEdit"), on: { click: () => { state.rg.sim = "edit"; showCard(); } } }),
          h("button", { type: "button", class: "lab-btn ghosty", text: L("rg.simReset"), on: { click: () => { state.rg.sim = ""; showCard(); } } }), h("small", { text: L("rg.simNote") })),
        ltr(h("dl", { class: "lab-kv", lv: "2" }, h("dt", { text: "tool_id" }), h("dd", { text: r.tool_id }), h("dt", { text: "category" }), h("dd", { text: r.category }), h("dt", { text: "version" }), h("dd", { text: r.version }),
          h("dt", { text: "path" }), h("dd", { text: "Tools/" + r.relative_path }), h("dt", { text: L("rg.privacy") }), h("dd", { text: `${r.privacy.data_handling} ${r.privacy.external_services || ""}` }),
          h("dt", { text: L("rg.processing") }), h("dd", { text: Object.entries(proc).map(([k, v]) => `${k}: ${v}`).join(" · ") }), h("dt", { text: "sha256" }), h("dd", { class: "rg-sha", text: sha }))),
        h("p", { class: `rg-elig ${blocked.length ? "no" : "yes"}`, lv: "2", text: blocked.length ? `${L("rg.notEligible")} ${blocked.join(", ")}.` : L("rg.eligible") }),
        h("div", { class: "rg-schemas", lv: "3" },
          h("div", {}, h("p", { class: "lab-cap", text: L("rg.input") }), ltr(h("ul", { class: "rg-tree" }, schemaTree(r.input_schema, "input", false)))),
          h("div", {}, h("p", { class: "lab-cap", text: L("rg.output") }), ltr(h("ul", { class: "rg-tree" }, schemaTree(out, "output", false))))));
    }
    el.append(h("div", { class: "lab-story" }, h("p", { text: L("rg.l1") }), h("p", { lv: "2", text: L("rg.l2") })), steps, toggle,
      h("div", { class: "rg-grid" }, h("div", { class: "rg-left" }, counts, cats, search, list), card));
    put(list, h("li", { class: "lab-cap", text: L("loading") }));
    tools().then((t) => { if (!t) { put(list, h("li", { class: "lab-cap", text: L("fail") })); return; } T = t; render(); });
    return { show: (id) => { const wait = () => (T ? show(id) : setTimeout(wait, 120)); wait(); } };
  }

  /* ================================================================ 9 · local AI */
  const AI_ST = [["request", "planned", "No user interface exists yet."], ["intent", "tested", "AI/language.py: langdetect identifies the language; the planner passes the request and response language to the model."],
    ["discover", "tested", "RegistryCatalog.discover(available_only=True): only approved tools; metadata comes from the AST-based registry, never a hard-coded list."],
    ["select", "tested", "ToolPlanner.prepare(): the model receives planner_view() of each tool (id, name, description, category, input_schema) as untrusted data and returns JSON tool_ids; unknown ids are rejected."],
    ["permit", "tested", "Tools that declare network, filesystem or executes_files are excluded; inputs are validated against each input_schema; execute() requires confirmation of exactly the displayed tool IDs."],
    ["execute", "tested", "LocalAIAgent.execute(): validates the caller, consumes the plan once, honours cancellation, re-checks Registry availability and source hashes, then ToolRegistry.execute()."],
    ["collect", "tested", "Each result is validated against the tool's OUTPUT_SCHEMA: tool_id, status, classification, risk_score, findings, evidence, metadata."],
    ["correlate", "planned", "Not built: combining several tool results into one assessment."], ["explain", "planned", "LocalAIAgent.chat() generates text but has no tool access; a combined explanation step is not built."]];
  const AR_HINTS = { "بريد": "email", "تصيد": "phishing", "التصيّد": "phishing", "ملف": "file", "كلمات مرور": "password", "سجل": "log", "شبكة": "network", "شهادة": "certificate", "كوبرنيتس": "kubernetes", "Kubernetes": "kubernetes", "رابط": "url", "موقع": "website", "سحابة": "cloud" };
  const STOP = new Set(["this", "that", "the", "and", "for", "with", "check", "analyze", "look", "safe", "file", "files", "into", "from", "are", "you", "can", "what", "does", "my", "is"]);
  function buildAI(el) {
    const ta = h("textarea", { class: "lab-input", rows: "2", maxlength: "300", "aria-label": L("ai.ask") }); ta.value = state.ai.text || L("ai.examples")[0];
    const chips = h("div", { class: "ai-chips" }, L("ai.examples").map((x) => h("button", { type: "button", class: "lab-chipbtn", text: x, on: { click: () => { ta.value = x; run(); } } })));
    const mode = h("div", { class: "ai-mode", role: "radiogroup" }, L("ai.mode").map((t, k) => h("button", { type: "button", role: "radio", class: "lab-btn", "aria-checked": String(state.ai.mode === k), on: { click: () => { state.ai.mode = k; mode.querySelectorAll("button").forEach((b, j) => b.setAttribute("aria-checked", String(j === k))); run(); } } }, t)));
    const runBtn = h("button", { type: "button", class: "lab-btn primary", text: L("ai.run"), on: { click: run } });
    const flow = h("ol", { class: "ai-flow" }), insp = h("div", { class: "lab-insp ai-insp", "aria-live": "polite" });
    let out = {}, timer = null;
    function stageTag(st, short) { const t = tagEl(st === "tested" ? "tested" : "planned"); if (short && st === "tested") t.textContent = L("tag.testedShort"); return t; }
    function renderFlow(upto) {
      put(flow, ...AI_ST.map(([id, st], i) => h("li", { class: `ai-st ${st}${i <= upto ? " lit" : ""}${state.ai.stage === i ? " on" : ""}` },
        h("button", { type: "button", "aria-pressed": String(state.ai.stage === i), on: { click: () => { state.ai.stage = i; renderFlow(upto); stageInsp(); } } },
          h("span", { class: "ai-n", text: String(i + 1) }), h("span", { class: "ai-t" }, h("b", { text: L(`ai.stages.${id}`)[0] }), h("small", { text: L(`ai.stages.${id}`)[1] })), stageTag(st, true)))));
    }
    function stageInsp() {
      const [id, st, tech] = AI_ST[state.ai.stage], o = out[id];
      put(insp, h("p", { class: "lab-kicker" }, stageTag(st), o && o.sim ? tagEl("sim") : null), h("h5", { text: L(`ai.stages.${id}`)[0] }), h("p", { text: L(`ai.stages.${id}`)[1] }),
        o ? h("div", { class: "ai-out", lv: "1" }, o.node) : null, ltr(h("p", { class: "lab-tech", lv: "3", text: tech })));
    }
    async function run() {
      state.ai.text = ta.value.trim() || L("ai.examples")[0];
      const T = await tools();
      const req = state.ai.text, isAr = /[؀-ۿ]/.test(req);
      let words = req.toLowerCase().match(/[a-z0-9]{3,}/g) || [];
      for (const k in AR_HINTS) if (req.includes(k)) words.push(AR_HINTS[k]);
      words = [...new Set(words.filter((w) => !STOP.has(w)))];
      const all = T ? T.discovery_all_categories : [];
      const approved = T ? T.discovery_real.filter((r) => r.status === "available") : [];
      const pool = state.ai.mode === 1 ? all : approved;
      const eligible = pool.filter((r) => !["network", "filesystem", "executes_files"].some((k) => (r.processing || {})[k] === true));
      const scored = eligible.map((r) => {
        const name = r.name.toLowerCase(), desc = r.description.toLowerCase(), cat = r.category.toLowerCase();
        const hits = words.filter((w) => name.includes(w) || desc.includes(w) || cat.includes(w));
        return { r, hits, score: words.reduce((a, w) => a + (name.includes(w) ? 3 : 0) + (cat.includes(w) ? 2 : 0) + (desc.includes(w) ? 1 : 0), 0) };
      }).filter((x) => x.score > 0).sort((a, b) => b.score - a.score).slice(0, 3);
      const envelope = T ? Object.keys((Object.values(T.output_schemas)[0] || {}).properties || {}) : [];
      out = {
        request: { node: h("p", { class: "ai-q", text: `“${req}”` }) },
        intent: { sim: true, node: h("p", { text: `language: ${isAr ? "ar" : "en"} · keywords: ${words.join(", ") || "—"}` }) },
        discover: { node: ltr(h("p", { class: "lab-mono", text: state.ai.mode === 1 ? `${all.length} tools discovered from metadata · approvals simulated · ${eligible.length} eligible` : `${T ? T.discovery_real.length : 0} tool(s) discovered · ${approved.length} approved · ${eligible.length} eligible` })) },
        select: { sim: state.ai.mode === 1, node: state.ai.mode === 0 || !scored.length ? h("p", { class: "ai-none", text: state.ai.mode === 0 ? L("ai.none") : "—" })
          : h("div", {}, h("p", { class: "lab-cap", text: L("ai.picked") }), h("ul", { class: "ai-picks" }, scored.map((x) => h("li", {}, ltr(h("b", { text: x.r.name })), ltr(h("small", { text: `${x.r.tool_id} · score ${x.score} · ${x.hits.join(", ")}` })))))) },
        permit: { sim: true, node: scored.length && state.ai.mode === 1 ? h("ul", { class: "ai-confirm" }, scored.map((x) => h("li", {}, h("label", {}, h("input", { type: "checkbox", checked: state.ai.confirm.has(x.r.tool_id), on: { change: (e) => { if (e.target.checked) state.ai.confirm.add(x.r.tool_id); else state.ai.confirm.delete(x.r.tool_id); } } }), ltr(h("code", { text: x.r.tool_id })))))) : h("p", { text: "—" }) },
        execute: { sim: true, node: ltr(h("p", { class: "lab-mono", text: scored.length && state.ai.mode === 1 ? scored.map((x) => `re-check sha256 ${x.r.sha256.slice(0, 12)}… → ${state.ai.confirm.has(x.r.tool_id) ? "run" : "waiting for your confirmation"}`).join("\n") : "nothing to run" })) },
        collect: { node: ltr(h("p", { class: "lab-mono", text: `{ ${envelope.join(", ")} }` })) },
        correlate: { node: h("p", { text: L("tag.planned") }) }, explain: { node: h("p", { text: L("tag.planned") }) },
      };
      clearInterval(timer);
      if (still()) { renderFlow(AI_ST.length - 1); stageInsp(); return; }
      let k = -1; renderFlow(k);
      timer = setInterval(() => { k++; renderFlow(k); if (k >= AI_ST.length - 1) clearInterval(timer); }, 260);
      state.ai.stage = 3; stageInsp();
    }
    el.append(h("p", { class: "lab-warn ai-banner" }, tagEl("planned"), " ", L("ai.banner")),
      h("div", { class: "ai-ask" }, h("label", { class: "lab-cap", text: L("ai.ask") }), ta, chips, h("div", { class: "ai-row" }, mode, runBtn)),
      h("div", { class: "ai-grid" }, flow, insp));
    renderFlow(-1); stageInsp(); run();
    return { onHide: () => clearInterval(timer) };
  }

  const BUILD = { explorer: buildExplorer, entropy: buildEntropy, hash: buildHash, pipeline: buildPipeline, evidence: buildEvidence, network: buildNetwork, domains: buildDomains, registry: buildRegistry, ai: buildAI };

  /* ================================================================ boot: load when near the viewport */
  const status = root.querySelector(".lab-fallback");
  let booted = false;
  async function boot() {
    if (booted) return; booted = true;
    if (status) status.textContent = L("loading");
    try {
      const r = await fetch("data/lab.json", { credentials: "same-origin" });
      if (!r.ok) throw new Error(r.status);
      D = await r.json();
      bytes = Uint8Array.from(atob(D.sample.b64), (c) => c.charCodeAt(0));
      shell();
    } catch (err) { console.error("lab:", err); if (status && status.isConnected) status.textContent = L("fail"); booted = false; }
  }
  const io = new IntersectionObserver((es) => { if (es[0].isIntersecting) { boot(); } }, { rootMargin: "800px 0px" });
  io.observe(root);
  new IntersectionObserver((es) => { live = es[0].isIntersecting; root.classList.toggle("live", live && !still()); }, { threshold: 0 }).observe(root);
  if (CS.onLang) CS.onLang(() => { if (D) shell(); });
})();
