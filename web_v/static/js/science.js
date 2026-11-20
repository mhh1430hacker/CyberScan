/* The science behind CyberScan (#science).
 *
 * Progressive enhancement over the section's static HTML (which reads fully without JS):
 *   - data/science.json (engine output from web_v/make_science_data.py) is fetched only
 *     when the section comes within ~1 screen of the viewport;
 *   - IntersectionObserver drives every reveal, the stage rail and the "on screen" flag;
 *     CSS animations run only while .sci has .on, so nothing moves off screen;
 *   - no requestAnimationFrame loop: the only rAF use is a short count-up that ends;
 *   - reduced motion / light mode: final states are set directly. */
(function () {
  "use strict";
  const root = document.getElementById("science");
  if (!root || !("IntersectionObserver" in window)) return;
  const $ = (id) => document.getElementById(id);
  const NS = "http://www.w3.org/2000/svg";
  const html = document.documentElement;
  const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches
    || html.classList.contains("reduce-motion") || html.classList.contains("fx-scenes-static");
  const svgEl = (tag, attrs, parent) => {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.append(n);
    return n;
  };
  const node = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const hex = (n, w = 4) => "0x" + n.toString(16).toUpperCase().padStart(w, "0");
  const observers = [];
  const watch = (cb, opts) => { const o = new IntersectionObserver(cb, opts); observers.push(o); return o; };

  root.classList.add("sci-js");

  /* ---------- on-screen flag: CSS animations only run while the section is visible ---------- */
  watch((es) => { root.classList.toggle("on", es[0].isIntersecting); }, { threshold: 0 }).observe(root);

  /* ---------- reveals ---------- */
  const revealer = watch((es) => es.forEach((e) => {
    if (!e.isIntersecting) return;
    e.target.classList.add("in");
    revealer.unobserve(e.target);
    e.target.dispatchEvent(new CustomEvent("sci:in"));
  }), { threshold: 0.18, rootMargin: "0px 0px -8% 0px" });
  root.querySelectorAll(".sci-rv, .sci-link").forEach((n) => (still() ? n.classList.add("in") : revealer.observe(n)));

  /* ---------- stage rail follows the chapter crossing the middle of the screen ---------- */
  const links = [...root.querySelectorAll(".sci-rail a")];
  const fill = root.querySelector(".sci-rail-fill");
  const chapters = links.map((a) => $(a.dataset.ch));
  function setStage(i) {
    links.forEach((a, k) => { a.classList.toggle("on", k === i); a.classList.toggle("done", k < i); a.toggleAttribute("aria-current", k === i); });
    fill.style.setProperty("--p", ((i + 1) / links.length).toFixed(3));
    const a = links[i];
    if (a && matchMedia("(max-width: 860px)").matches) {
      const ol = a.closest("ol");
      ol.scrollTo({ left: a.offsetLeft - 16, behavior: still() ? "auto" : "smooth" });
    }
  }
  const railObs = watch((es) => es.forEach((e) => { if (e.isIntersecting) setStage(chapters.indexOf(e.target)); }),
    { rootMargin: "-45% 0px -50% 0px", threshold: 0 });
  chapters.forEach((c) => c && railObs.observe(c));

  /* ---------- intro: a row of bytes, one pulse travelling to "measurements" ---------- */
  (function intro() {
    const g = root.querySelector(".sci-intro-bytes");
    if (!g) return;
    const heights = [4, 4, 22, 18, 20, 16, 12, 14, 11, 30, 31, 29, 30, 2, 2, 2];   // header · code · text · random · padding
    heights.forEach((h, i) => svgEl("rect", { x: 8 + i * 8.5, y: 46 - h, width: 6, height: h + 2, rx: 1, opacity: 0.35 + h / 50 }, g));
    svgEl("circle", { cx: 150, cy: 32, r: 3.5, class: "sci-intro-pulse" }, root.querySelector(".sci-intro-svg"));
  })();

  /* ---------- count-up: a short, finite rAF tween ---------- */
  function countUp(el, to, digits = 0, ms = 700) {
    if (still()) { el.textContent = to.toFixed(digits); return; }
    const t0 = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - k, 3);
      el.textContent = (to * e).toFixed(digits);
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /* ---------- the in-browser entropy calculator (needs no data) ---------- */
  (function tryEntropy() {
    const input = $("sci-try-in"), out = $("sci-try-out");
    if (!input) return;
    const enc = new TextEncoder();
    function run() {
      const bytes = enc.encode(input.value);
      const n = bytes.length;
      out.replaceChildren();
      if (!n) { out.textContent = "n = 0 bytes · H = 0 (an empty window carries no information)"; return; }
      const counts = new Uint32Array(256);
      for (const b of bytes) counts[b]++;
      let sum = 0, distinct = 0;
      for (const c of counts) if (c) { distinct++; if (c > 1) sum += c * Math.log2(c); }
      const h = Math.max(0, Math.min(8, Math.log2(n) - sum / n));          // the engine's form of the formula
      const cap = Math.log2(Math.min(n, 256));
      out.append("n = " + n + " bytes · " + distinct + " distinct · H = ", node("b", null, h.toFixed(3)),
        " bits/byte (most possible for n = " + n + ": " + cap.toFixed(3) + ")");
      const m = node("div", "sci-meter"), i = node("i");
      i.style.setProperty("--v", (h / 8).toFixed(3));
      m.append(i); out.append(m);
    }
    input.addEventListener("input", run);
    run();
  })();

  /* ================= data-driven figures ================= */
  let started = false;
  const loader = watch((es) => {
    if (!es[0].isIntersecting || started) return;
    started = true;
    loader.disconnect();
    fetch("data/science.json", { credentials: "same-origin" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))))
      .then(build)
      .catch(() => {
        $("sci-ent-read").textContent = "The measurements could not be loaded. The explanations above still apply.";
        root.classList.add("sci-nodata");
      });
  }, { rootMargin: "100% 0px 100% 0px" });
  loader.observe(root);

  function build(d) {
    entropyFigure(d.entropy, d.scan_topography);
    cfgFigure(d.cfg);
    latentFigure(d.embedding);
    intelFigure();
    explainFigure(d.assessment, d.scan_topography);
  }

  /* ---------------------------------------------------------------- entropy */
  function entropyFigure(fine, scan) {
    const svg = $("sci-ent-svg"), range = $("sci-ent-range"), read = $("sci-ent-read");
    const hist = $("sci-ent-hist"), histCap = $("sci-ent-hist-cap");
    const regions = fine.regions, total = fine.file_bytes;
    const COLORS = { header: "#94a3b8", code: "#38d6f5", text: "#4ade80", random: "#e879f9", padding: "#64748b" };
    const L = 34, R = 632, T = 16, B = 232;
    const xOf = (off) => L + (off / total) * (R - L);
    const yOf = (h) => T + (1 - h / 8) * (B - T);
    let series = fine, idx = 0, cursor = null, bands = [], drawnOnce = false;

    function draw() {
      svg.querySelectorAll(":scope > g, :scope > path").forEach((n) => n.remove());
      const grid = svgEl("g", { class: "grid axis" }, svg);
      for (let h = 0; h <= 8; h += 2) {
        svgEl("line", { x1: L, x2: R, y1: yOf(h), y2: yOf(h) }, grid);
        svgEl("text", { x: L - 6, y: yOf(h) + 3, "text-anchor": "end" }, grid).textContent = h;
      }
      for (let k = 0; k <= total; k += 4096) svgEl("text", { x: xOf(k), y: B + 16, "text-anchor": "middle" }, grid).textContent = k / 1024 + " KiB";
      svgEl("text", { x: 4, y: T + 2 }, grid).textContent = "bits";

      const bandG = svgEl("g", {}, svg);
      bands = regions.map((r) => {
        const g = svgEl("g", { class: "band" }, bandG);
        svgEl("rect", { x: xOf(r.start), y: T, width: xOf(r.end) - xOf(r.start), height: B - T, fill: COLORS[r.key] }, g);
        const label = svgEl("text", { x: (xOf(r.start) + xOf(r.end)) / 2, y: B - 6, "text-anchor": "middle" }, g);
        label.textContent = r.label;
        return g;
      });

      const refs = svgEl("g", {}, svg);
      const ref = (h, cls, text) => {
        svgEl("line", { x1: L, x2: R, y1: yOf(h), y2: yOf(h), class: "ref " + cls }, refs);
        const t = svgEl("text", { x: R - 2, y: yOf(h) - 3, "text-anchor": "end", class: "ref-t", fill: cls === "hi" ? "#fbbf24" : cls === "lo" ? "#4ade80" : "#e879f9" }, refs);
        t.textContent = text;
      };
      ref(7.2, "hi", "7.2 high band");
      ref(3.5, "lo", "3.5 low band");
      if (series.window <= 256) ref(Math.log2(series.window), "cap", "log₂" + series.window + " = " + Math.log2(series.window) + " (window ceiling)");

      const pts = series.trajectory.map((h, i) => [xOf(series.offsets[i] + Math.min(series.window, total) / 2), yOf(h)]);
      const dLine = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + "," + p[1].toFixed(1)).join("");
      const curveG = svgEl("g", { class: "sci-draw" + (drawnOnce || still() ? " in" : "") }, svg);
      svgEl("path", { d: dLine + "L" + pts[pts.length - 1][0].toFixed(1) + "," + B + "L" + pts[0][0].toFixed(1) + "," + B + "Z", class: "area" }, curveG);
      const curve = svgEl("path", { d: dLine, class: "curve" }, curveG);
      curveG.style.setProperty("--len", Math.ceil(curve.getTotalLength()));
      if (!drawnOnce && !still()) {
        const fig = $("sci-ent-fig").closest(".sci-rv");
        const go = () => requestAnimationFrame(() => curveG.classList.add("in"));
        if (fig.classList.contains("in")) go(); else fig.addEventListener("sci:in", go, { once: true });
      }
      drawnOnce = true;

      const an = svgEl("g", {}, svg);
      series.anomalies.forEach((a) => {
        const x = xOf((a.start + a.end) / 2);
        svgEl("line", { x1: x, x2: x, y1: T, y2: B, class: "anom-l" }, an);
        const c = svgEl("path", { d: `M${x - 5},${T - 2}L${x + 5},${T - 2}L${x},${T + 6}Z`, class: "anom" }, an);
        svgEl("title", {}, c).textContent = `Discontinuity ΔH ${a.delta > 0 ? "+" : ""}${a.delta} (${a.severity}) at ${hex(a.start)}–${hex(a.end)}`;
      });

      cursor = svgEl("g", {}, svg);
      cursor.win = svgEl("rect", { y: T, height: B - T, class: "cursor-win" }, cursor);
      cursor.line = svgEl("line", { y1: T, y2: B, class: "cursor" }, cursor);
      cursor.dot = svgEl("circle", { r: 4, class: "dot" }, cursor);
      range.max = series.trajectory.length - 1;
      update(Math.min(idx, series.trajectory.length - 1));
    }

    function regionAt(off) { return regions.find((r) => off >= r.start && off < r.end) || regions[regions.length - 1]; }

    function update(i) {
      idx = i;
      range.value = i;
      const off = series.offsets[i], w = Math.min(series.window, total), h = series.trajectory[i];
      const mid = off + w / 2, x = xOf(mid);
      cursor.win.setAttribute("x", xOf(off)); cursor.win.setAttribute("width", xOf(off + w) - xOf(off));
      cursor.line.setAttribute("x1", x); cursor.line.setAttribute("x2", x);
      cursor.dot.setAttribute("cx", x); cursor.dot.setAttribute("cy", yOf(h));
      const reg = regionAt(mid);
      bands.forEach((g, k) => g.classList.toggle("sel", regions[k] === reg));
      const delta = i ? h - series.trajectory[i - 1] : 0;
      const hit = series.anomalies.find((a) => a.start === series.offsets[i - 1]);
      read.replaceChildren(
        `Window ${i + 1}/${series.trajectory.length} · ${hex(off)}–${hex(off + w)} · H = `, node("em", null, h.toFixed(3)),
        ` bits/byte · ${reg.label}`, document.createElement("br"),
        i ? `ΔH from previous window: ${delta >= 0 ? "+" : ""}${delta.toFixed(3)}` : "First window",
        hit ? ` → discontinuity (${hit.severity}): |ΔH| ≥ 1.5` : "");
      drawHist(reg);
    }

    let lastHist = null;
    function drawHist(reg) {
      if (lastHist === reg) return;
      lastHist = reg;
      const ctx = hist.getContext("2d"), W = hist.width, H = hist.height;
      ctx.clearRect(0, 0, W, H);
      const max = Math.max(...reg.histogram);
      ctx.fillStyle = COLORS[reg.key];
      reg.histogram.forEach((c, b) => {
        if (!c) return;
        const h = Math.max(1, Math.sqrt(c / max) * (H - 2));
        ctx.fillRect(b * 2, H - h, 1.6, h);
      });
      histCap.textContent = `Byte histogram of "${reg.label}" (0x00 → 0xFF, √ scale) · ${reg.desc} · whole-region H = ${reg.entropy_whole.toFixed(3)}`;
    }

    range.addEventListener("input", () => update(Number(range.value)));
    const pick = (e) => {
      const r = svg.getBoundingClientRect();
      const off = ((e.clientX - r.left) / r.width * 640 - L) / (R - L) * total;
      let best = 0, bd = Infinity;
      series.offsets.forEach((o, k) => { const dd = Math.abs(o + Math.min(series.window, total) / 2 - off); if (dd < bd) { bd = dd; best = k; } });
      update(best);
    };
    svg.addEventListener("pointermove", (e) => { if (e.pointerType === "mouse") pick(e); });
    svg.addEventListener("pointerdown", pick);

    $("sci-ent-fig").querySelectorAll("[data-res]").forEach((b) => b.addEventListener("click", () => {
      const next = b.dataset.res === "scan" ? scan : fine;
      if (next === series) return;
      const frac = idx / Math.max(1, series.trajectory.length - 1);
      series = next;
      idx = Math.round(frac * (series.trajectory.length - 1));
      $("sci-ent-fig").querySelectorAll("[data-res]").forEach((o) => { o.classList.toggle("on", o === b); o.setAttribute("aria-pressed", o === b); });
      $("sci-ent-note").textContent = series === scan
        ? `The file scan uses 4096-byte windows every 1024 bytes: ${scan.trajectory.length} windows here, peak ${scan.peak} bits/byte. The random region now reads close to 8, but the boundaries are blurred across a whole window.`
        : "A 128-byte window can never exceed log₂128 = 7 bits, which is why the pseudo-random region peaks near 6.7 even though its whole-region entropy is 7.95. Larger windows see more of the distribution but blur where a boundary falls.";
      draw();
    }));
    idx = 290;
    draw();
  }

  /* ---------------------------------------------------------------- control flow */
  function cfgFigure(samples) {
    const svg = $("sci-cfg-svg"), asm = $("sci-cfg-asm"), metrics = $("sci-cfg-metrics"), pat = $("sci-cfg-patterns");
    const W = 250, NX = 40, NW = 160, NH = 38;
    let s = null, nodes = [], edges = [], sel = -1;

    function render(k) {
      s = samples[k];
      svg.replaceChildren();
      const defs = svgEl("defs", {}, svg);
      [["fall", "#7dd3fc"], ["jump", "#4ade80"], ["back", "#fbbf24"]].forEach(([id, c]) => {
        const m = svgEl("marker", { id: "sci-ar-" + id, viewBox: "0 0 8 8", refX: 7, refY: 4, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
        svgEl("path", { d: "M0,0L8,4L0,8Z", fill: c }, m);
      });
      const n = s.blocks.length;
      const gap = Math.min(84, (420 - 24 - NH) / Math.max(1, n - 1));
      const H = 24 + NH + gap * (n - 1) + 12;
      svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
      const y = (i) => 12 + i * gap;
      const edgeG = svgEl("g", {}, svg);
      let right = 0, left = 0;
      edges = s.edges.map((e) => {
        const ys = y(e.from), yt = y(e.to);
        let d;
        if (e.kind === "fall" && e.to === e.from + 1) d = `M${NX + NW / 2},${ys + NH}L${NX + NW / 2},${yt - 2}`;
        else if (e.kind === "back" && e.to === e.from) d = `M${NX},${ys + NH - 8}C${NX - 34},${ys + NH + 6} ${NX - 34},${ys - 6} ${NX - 2},${ys + 8}`;
        else if (e.kind === "back") { const b = NX - 26 - 14 * left++; d = `M${NX},${ys + NH / 2}C${b},${ys + NH / 2} ${b},${yt + NH / 2} ${NX - 2},${yt + NH / 2}`; }
        else { const b = NX + NW + 26 + 14 * right++; d = `M${NX + NW},${ys + NH / 2}C${b},${ys + NH / 2} ${b},${yt + NH / 2} ${NX + NW + 2},${yt + NH / 2}`; }
        const p = svgEl("path", { d, class: "edge " + e.kind, "marker-end": `url(#sci-ar-${e.kind})` }, edgeG);
        return { ...e, el: p };
      });
      const loopInstr = new Set();
      if (s.evidence_patterns.length) s.blocks.forEach((b) => b.forEach((ins) => { if (/^xor \w+ ptr \[/.test(ins.asm)) loopInstr.add(ins.addr); }));
      nodes = s.blocks.map((b, i) => {
        const g = svgEl("g", { class: "node", tabindex: "0", role: "button", transform: `translate(${NX},${y(i)})` }, svg);
        const succ = s.edges.filter((e) => e.from === i).map((e) => "B" + e.to);
        g.setAttribute("aria-label", `Basic block B${i} at ${b[0].addr}, ${b.length} instruction${b.length > 1 ? "s" : ""}, ending in ${b[b.length - 1].asm}. Successors: ${succ.join(", ") || "none (returns)"}.`);
        svgEl("rect", { width: NW, height: NH, rx: 7 }, g);
        svgEl("text", { x: 10, y: 15, class: "id" }, g).textContent = `B${i} · ${b[0].addr}`;
        const last = b[b.length - 1].asm;
        svgEl("text", { x: 10, y: 30 }, g).textContent = (b.length > 1 ? "… " : "") + (last.length > 21 ? last.slice(0, 20) + "…" : last);
        if (b.some((ins) => loopInstr.has(ins.addr))) g.classList.add("hit");
        g.addEventListener("click", () => select(i));
        g.addEventListener("focus", () => select(i));
        g.addEventListener("keydown", (e) => {
          if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); nodes[(i + (e.key === "ArrowDown" ? 1 : n - 1)) % n].focus(); }
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(i); }
        });
        return g;
      });

      const m = s.metrics;
      metrics.replaceChildren();
      const dl = (k, v, cls) => { const d = node("div", cls); d.append(node("dt", null, k), node("dd", null, v)); metrics.append(d); return d; };
      dl("Instructions", String(m.instructions));
      dl("Blocks N", String(m.blocks));
      dl("Edges E", String(m.edges));
      dl("Back edges", String(m.back_edges));
      dl("Density", m.density.toFixed(2));
      const mBox = dl("M", "0");
      dl("Cyclomatic complexity", `M = E − N + 2P = ${m.edges} − ${m.blocks} + 2·${m.components} = ${m.cyclomatic}`, "wide");
      countUp(mBox.querySelector("dd"), m.cyclomatic);

      pat.className = "sci-verdictline " + (s.evidence_patterns.length ? "warn" : "ok");
      pat.textContent = s.evidence_patterns.length
        ? `Evidence pattern: ${s.evidence_patterns.join(", ")}. The loop body XORs into memory (byte ptr [esi + ecx]) and steps a counter. Descriptive pattern also recorded: ${s.descriptive_patterns.join(", ") || "none"}. Inside a program this warns only if there is somewhere to decrypt into.`
        : "No pattern. The loop compares and counts; the one XOR (xor eax, eax) zeroes a register outside the loop, which is what compilers do, and is not evidence.";

      const firstLoop = s.edges.find((e) => e.kind === "back");
      sel = -1;
      select(firstLoop ? firstLoop.to : 0, true);
    }

    function select(i, quiet) {
      if (i === sel && !quiet) return;
      sel = i;
      nodes.forEach((g, k) => g.classList.toggle("sel", k === i));
      edges.forEach((e) => {
        const on = e.from === i || e.to === i;
        e.el.classList.toggle("lit", on);
        e.el.classList.toggle("dim", !on);
      });
      const b = s.blocks[i];
      asm.replaceChildren(node("h5", null, `Block B${i} · ${b.length} instruction${b.length > 1 ? "s" : ""}`));
      b.forEach((ins) => {
        const ln = node("div", "ln" + (/^xor \w+ ptr \[/.test(ins.asm) ? " mark" : ""));
        ln.append(node("span", null, ins.addr), node("span", null, ins.asm));
        ln.title = ins.bytes;
        asm.append(ln);
      });
      const name = { fall: "fall-through", jump: "branch taken", back: "back edge" };
      const out = s.edges.filter((e) => e.from === i).map((e) => `B${e.to} (${name[e.kind]})`);
      const inn = s.edges.filter((e) => e.to === i).map((e) => `B${e.from} (${name[e.kind]})`);
      asm.append(node("div", "succ", `→ ${out.join(", ") || "none: returns"}\n← ${inn.join(", ") || "entry point"}`));
    }

    const seg = $("sci-cfg-fig").querySelectorAll("[data-cfg]");
    seg.forEach((b) => b.addEventListener("click", () => {
      seg.forEach((o) => { o.classList.toggle("on", o === b); o.setAttribute("aria-pressed", o === b); });
      render(Number(b.dataset.cfg));
    }));
    render(0);
  }

  /* ---------------------------------------------------------------- 4096-D vector */
  function latentFigure(emb) {
    const canvas = $("sci-lat-canvas"), ctx = canvas.getContext("2d");
    const samples = emb.samples;
    const vec = samples.map((s) => { const raw = atob(s.q), a = new Int8Array(raw.length); for (let i = 0; i < raw.length; i++) a[i] = (raw.charCodeAt(i) << 24) >> 24; return a; });
    let a = 0, b = 1, shown = 0;
    const img = ctx.createImageData(64, 64);
    const BG = [5, 10, 20], POS = [56, 214, 245], NEG = [232, 121, 249];

    function paint(k) {
      shown = k;
      const v = vec[k];
      for (let i = 0; i < 4096; i++) {
        const t = Math.sqrt(Math.abs(v[i]) / 127), c = v[i] >= 0 ? POS : NEG, o = i * 4;
        img.data[o] = BG[0] + (c[0] - BG[0]) * t; img.data[o + 1] = BG[1] + (c[1] - BG[1]) * t; img.data[o + 2] = BG[2] + (c[2] - BG[2]) * t; img.data[o + 3] = 255;
      }
      ctx.putImageData(img, 0, 0);
      canvas.setAttribute("aria-label", `All 4096 coordinates of "${samples[k].label}", 64 per row; the four horizontal bands are the four channels`);
      const nz = samples[k].nonzero;
      $("sci-lat-nz").textContent = `Showing "${samples[k].label}". Non-zero coordinates per channel: ${nz.join(" · ")} of 1024. `
        + (nz[3] === 0 ? "Channel 3 is empty: no PE header. " : "")
        + (samples[k].id.startsWith("text") ? "The graph channel is filled even for text, because the embedder disassembles whatever bytes it is given." : "");
    }
    function compare() {
      const c = emb.similarity[a][b];
      $("sci-lat-cos").textContent = c.toFixed(3);
      $("sci-lat-cos-bar").style.setProperty("--v", Math.max(0, c).toFixed(3));
    }
    function radios(box, getter, setter) {
      const btns = samples.map((s, k) => {
        const x = node("button", null, s.label);
        x.type = "button"; x.setAttribute("role", "radio");
        x.addEventListener("click", () => { setter(k); sync(); paint(k); compare(); });
        x.addEventListener("keydown", (e) => {
          const d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
          if (!d) return;
          e.preventDefault();
          const nk = (getter() + d + samples.length) % samples.length;
          setter(nk); sync(); paint(nk); compare(); btns[nk].focus();
        });
        box.append(x);
        return x;
      });
      const sync = () => btns.forEach((x, k) => { x.setAttribute("aria-checked", k === getter()); x.tabIndex = k === getter() ? 0 : -1; });
      sync();
    }
    radios($("sci-lat-a"), () => a, (k) => { a = k; });
    radios($("sci-lat-b"), () => b, (k) => { b = k; });
    paint(shown);
    compare();
  }

  /* ---------------------------------------------------------------- intelligence (illustrative timings) */
  function intelFigure() {
    const lanesBox = $("sci-lanes"), fig = $("sci-intel-fig");
    const FEEDS = ["ThreatFox", "URLhaus", "AlienVault OTX"];
    const SPAN = 450 / 0.82;          // the budget line sits at 82% of the track
    const SLOW = 3;                    // shown three times slower than the illustrative timings
    const SCN = {
      nokeys: [{ ms: 210, st: "no_match" }, { ms: 0, st: "authentication_required" }, { ms: 0, st: "authentication_required" }],
      slow: [{ ms: 180, st: "no_match" }, { ms: 260, st: "no_match" }, { ms: 450, st: "timeout" }],
      match: [{ ms: 230, st: "matched" }, { ms: 300, st: "no_match" }, { ms: 380, st: "no_match" }],
    };
    // mirrors GlobalIntelligenceEngine._build_result
    const merge = (sts) => sts.includes("matched") ? "matched"
      : sts.every((x) => ["authentication_required", "unsupported_indicator", "dependency_missing"].includes(x)) ? "unavailable"
      : sts.includes("timeout") ? "partial_timeout" : "no_match";
    const lanes = FEEDS.map((name) => {
      const row = node("div", "sci-lane"), track = node("div", "sci-track"), bar = node("i"), label = node("em");
      row.append(node("span", null, name), track);
      track.append(bar, label);
      lanesBox.append(row);
      return { bar, label };
    });
    let scn = "nokeys", timers = [];
    function play() {
      timers.forEach(clearTimeout); timers = [];
      const plan = SCN[scn], instant = still();
      $("sci-intel-status").textContent = "…";
      $("sci-intel-effect").textContent = "";
      lanes.forEach((l, k) => {
        const p = plan[k];
        l.bar.className = ""; l.label.className = ""; l.label.textContent = "";
        l.bar.style.setProperty("--w", "0");
        void l.bar.offsetWidth;                                    // restart the transition
        const cls = p.st === "timeout" ? "timeout" : p.st === "matched" ? "matched" : p.ms === 0 ? "instant" : "";
        l.bar.className = "go " + cls;
        l.bar.style.setProperty("--t", instant ? "0s" : (Math.max(p.ms, 60) * SLOW) / 1000 + "s");
        l.bar.style.setProperty("--w", (Math.max(p.ms, 12) / SPAN).toFixed(3));
        const done = () => {
          l.label.textContent = p.st === "timeout" ? "timeout · cancelled at the deadline" : p.ms === 0 ? p.st + " · no request sent" : `${p.st} · ${p.ms} ms`;
          l.label.classList.add("show");
        };
        if (instant) done(); else timers.push(setTimeout(done, Math.max(p.ms, 60) * SLOW));
      });
      const finish = () => {
        const st = merge(plan.map((p) => p.st));
        $("sci-intel-status").textContent = st;
        $("sci-intel-effect").textContent = st === "matched"
          ? "→ finding \"External threat-intelligence match\" (+70). A report, not proof."
          : "→ no finding added. No match is not proof of safety.";
      };
      if (instant) finish(); else timers.push(setTimeout(finish, Math.max(...plan.map((p) => Math.max(p.ms, 60))) * SLOW + 150));
    }
    fig.querySelectorAll("[data-scn]").forEach((b) => b.addEventListener("click", () => {
      scn = b.dataset.scn;
      fig.querySelectorAll("[data-scn]").forEach((o) => { o.classList.toggle("on", o === b); o.setAttribute("aria-pressed", o === b); });
      play();
    }));
    $("sci-intel-replay").addEventListener("click", play);
    // play when the figure is actually in view; never off screen
    const once = watch((es) => { if (es[0].isIntersecting) { once.disconnect(); play(); } }, { threshold: 0.5 });
    once.observe(fig);
  }

  /* ---------------------------------------------------------------- explanation chain */
  function explainFigure(a, topo) {
    const fmt = (x) => (x > 0 ? "+" : "") + x.toFixed(3);
    const ev = $("sci-x-evidence"), fx = $("sci-x-findings"), corr = $("sci-x-corr"), as = $("sci-x-assess"), ex = $("sci-x-explain");
    const hl = (key, text) => { const s = node("span", "sci-hl", text); s.dataset.k = key; return s; };
    const line = (...parts) => { const p = node("div"); p.append(...parts); return p; };

    ev.append(
      line("Peak 4096-byte window: ", hl("peak", `${topo.peak} bits/byte`), " (threshold 7.0)"),
      ...topo.anomalies.map((x, i) => line(`Adjacent windows ${hex(x.start)}–${hex(x.end)}: `, hl("a" + i, "ΔH " + fmt(x.delta)), " (|ΔH| ≥ 1.5)")),
      line(node("small", null, `${topo.trajectory.length} windows of ${topo.window} bytes, step ${topo.step}. Mean ${topo.mean} bits/byte.`)));

    const box = node("div", "sci-fx");
    let k = 0;
    a.findings.forEach((f) => {
      const keys = f.evidence === "High entropy" ? ["peak", "mitre"] : f.evidence === "Entropy discontinuity" ? ["a" + k++] : [];
      const btn = node("button");
      btn.type = "button"; btn.setAttribute("aria-pressed", "false");
      btn.append(node("span", null, f.evidence), node("b", null, "+" + f.contribution), node("small", null, f.explanation));
      btn.addEventListener("click", () => {
        const on = btn.getAttribute("aria-pressed") !== "true";
        box.querySelectorAll("button").forEach((o) => o.setAttribute("aria-pressed", "false"));
        btn.setAttribute("aria-pressed", String(on));
        root.querySelectorAll("#sci-exp-fig .sci-hl").forEach((s) => s.classList.toggle("on", on && keys.includes(s.dataset.k)));
      });
      box.append(btn);
    });
    fx.append(box, node("small", null, "Select a finding to trace it back to its evidence."));

    a.mitre.forEach((m) => corr.append(line("ATT&CK ", hl("mitre", `${m.id} ${m.name}`), ` ← keyword rule on "${m.evidence.join(", ")}"`)));
    corr.append(
      line(`Online intelligence: ${a.osint} (opt-in)`),
      line(`Structural classifier: ${a.engines.ML}`),
      line(`Code graph, dissonance, surprise map: ${a.engines.Dissonance} (no MZ/ELF header)`));

    const max = Math.max(...a.findings.map((f) => f.contribution));
    const score = node("div", "sci-score");
    const num = node("strong", null, "0");
    score.append(num, node("span", null, "/ 100"), node("span", "band", a.classification));
    const scale = node("div", "sci-scale"), mark = node("i");
    mark.style.setProperty("--x", a.combined_score + "%");
    scale.append(mark);
    const lbl = node("div", "sci-scale-l");
    lbl.append(node("span", null, "0 none"), node("span", null, "1–49 review"), node("span", null, "≥ 50 suspicious"));
    as.append(score, line(`score = max(${a.findings.map((f) => f.contribution).join(", ")}) = ${max}; heuristic and model weights 1 / 0`), scale, lbl);
    const link = as.closest(".sci-link");
    const count = () => countUp(num, a.combined_score);
    if (link.classList.contains("in")) count(); else link.addEventListener("sci:in", count, { once: true });

    const story = node("ol", "sci-story");
    a.storyline.forEach((s) => {
      story.append(node("li", null, s.replace(/^Phase \d+: /, "")));
    });
    ex.append(line("The report shows each finding's sentence (above), plus the engine's storyline:"), story);

    const c = a.components;
    $("sci-x-note").textContent = `The storyline's composite indicator (${a.composite}/100 = entropy level ${c.entropy_level} + discontinuities ${c.discontinuities} + gradient spread ${c.gradient_spread} + graph ${c.cfg_complexity} + patterns ${c.structural_patterns}) is descriptive context in the report. It is not the verdict, which stays at ${a.combined_score} because only the findings count. This file is harmless by construction: "review" means "a person may want to look", which is the honest reading of encrypted-looking bytes in an unknown file.`;
  }

  /* ---------- tidy up if the landing is ever torn down (single-page navigation) ---------- */
  window.addEventListener("pagehide", () => observers.forEach((o) => o.disconnect()), { once: true });
})();
