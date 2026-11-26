/* The engine pipeline: your file flows through nine engines into one
 * verdict. Packets of data travel along the wires; hovering (or tapping) a
 * node explains what that engine does, and the packets favour its wire.
 * With nothing hovered, the explanation walks through the nodes on its own. */
(function () {
  "use strict";
  const { $, el, t } = window.CS;
  const box = $("pipe");
  const svg = $("pipe-svg");
  const nodesBox = $("pipe-nodes");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const NS = "http://www.w3.org/2000/svg";
  const HUES = ["#38bdf8", "#a78bfa", "#f472b6", "#fbbf24", "#34d399", "#22d3ee", "#818cf8", "#fb7185", "#2dd4bf"];
  const GLYPHS = ["01", "≈", "!", "{}", "PE", "ZIP", "✓", "ML", "◎"];

  let nodes = [], wires = [], packets = [], active = 0, hovered = false, vertical = false, raf = 0, last = 0, spawnT = 0, cycleT = 0, visible = false;

  function model() {
    const e = t("pipeEngines");
    return [
      { id: "in", kind: "io", label: t("pipeIn")[0], body: t("pipeIn")[1], ex: t("pipeIn")[2], glyph: "⬆", hue: "#e2e8f0" },
      ...e.map(([label, body, ex], i) => ({ id: `e${i}`, kind: "engine", label, body, ex, glyph: GLYPHS[i], hue: HUES[i] })),
      { id: "fuse", kind: "io", label: t("pipeFuse")[0], body: t("pipeFuse")[1], ex: t("pipeFuse")[2], glyph: "∑", hue: "#c4b5fd" },
      { id: "out", kind: "io", label: t("pipeOut")[0], body: t("pipeOut")[1], ex: t("pipeOut")[2], glyph: "✓", hue: "#34d399" },
    ];
  }

  function positions() {
    // fractions of the diagram; engines in two staggered columns
    const pos = { in: [0, 0.5], fuse: [0.77, 0.5], out: [1, 0.5] };
    for (let i = 0; i < 9; i++) {
      const colA = i < 5;
      const k = colA ? i : i - 5;
      pos[`e${i}`] = colA ? [0.29, 0.08 + k * 0.21] : [0.52, 0.185 + k * 0.21];
    }
    return pos;
  }

  function build(width) {
    const data = model();
    nodesBox.replaceChildren();
    nodes = data.map((d, i) => {
      const n = el("button", `pipe-node ${d.kind}`);
      n.type = "button";
      n.style.setProperty("--hue", d.hue);
      n.style.setProperty("--d", `${i * 0.05}s`);
      n.append(el("span", "pn-glyph", d.glyph), el("span", "pn-label", d.label));
      n.addEventListener("pointerenter", () => { hovered = true; select(i); });
      n.addEventListener("focus", () => { hovered = true; select(i); });
      n.addEventListener("pointerleave", () => { hovered = false; });
      n.addEventListener("blur", () => { hovered = false; });
      n.addEventListener("click", () => { hovered = true; select(i); setTimeout(() => { hovered = false; }, 6000); });
      nodesBox.append(n);
      return { ...d, el: n, x: 0, y: 0, flash: 0 };
    });
    layout(width);
    select(active, true);
  }

  function layout(width) {
    const diagram = $("pipe-diagram");
    const w = width || diagram.clientWidth;
    vertical = w < 760;
    const h = vertical ? 760 : 470;
    diagram.style.height = `${h}px`;
    const padX = vertical ? 30 : 95, padY = vertical ? 30 : 28;
    const pos = positions();
    const rtl = document.documentElement.dir === "rtl";
    // phones: the engines sit in a 3 × 3 grid, so each one has room for its name under the icon
    if (vertical) for (let i = 0; i < 9; i++) pos[`e${i}`] = [0.5 + (((i % 3) - 1) * 0.36) * (rtl ? -1 : 1), 0.22 + Math.floor(i / 3) * 0.2];
    nodes.forEach((n) => {
      let [fx, fy] = pos[n.id];
      if (vertical && n.kind !== "engine") [fx, fy] = [fy, fx];
      if (rtl && !vertical) fx = 1 - fx;
      n.x = padX + fx * (w - padX * 2);
      n.y = padY + fy * (h - padY * 2);
      n.el.style.left = `${n.x}px`;
      n.el.style.top = `${n.y}px`;
    });
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    box.classList.toggle("vertical", vertical);
    drawWires();
  }

  function curve(a, b) {
    if (vertical) { const my = (a.y + b.y) / 2; return `M${a.x},${a.y} C${a.x},${my} ${b.x},${my} ${b.x},${b.y}`; }
    const mx = (a.x + b.x) / 2;
    return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`;
  }

  function drawWires() {
    svg.replaceChildren();
    const defs = document.createElementNS(NS, "defs");
    defs.innerHTML = '<filter id="pglow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';
    svg.append(defs);
    wires = [];
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const add = (a, b, engine) => {
      const p = document.createElementNS(NS, "path");
      p.setAttribute("d", curve(byId[a], byId[b]));
      p.setAttribute("class", "wire");
      p.style.setProperty("--hue", byId[engine] ? byId[engine].hue : "#94a3b8");
      svg.append(p);
      // the wire's length and 49 sample points are read when a packet first travels it (they
      // need layout: ~900 reads, too many to do while the page starts)
      const wire = { a, b, engine, el: p, len: 1, pts: null };
      wires.push(wire);
      return wire;
    };
    for (let i = 0; i < 9; i++) { add("in", `e${i}`, `e${i}`); add(`e${i}`, "fuse", `e${i}`); }
    add("fuse", "out", "fuse");
    packets.forEach((p) => p.el.remove());
    packets = [];
  }

  function select(i, silent) {
    active = i;
    const n = nodes[i];
    if (!n) return;
    nodes.forEach((m, k) => m.el.classList.toggle("on", k === i));
    wires.forEach((w) => w.el.classList.toggle("lit", w.engine === n.id || (n.id === "in" && w.a === "in") || (n.id === "fuse" && w.b === "fuse") || (n.id === "out" && w.b === "out")));
    const panel = $("pipe-panel");
    const idx = n.kind === "engine" ? Number(n.id.slice(1)) + 1 : 0;
    $("pp-kicker").textContent = n.kind === "engine" ? t("ppEngine")(idx) : n.id === "in" ? t("ppInput") : n.id === "fuse" ? t("ppFusion") : t("ppVerdict");
    $("pp-title").textContent = n.label;
    $("pp-body").textContent = n.body;
    $("pp-example").textContent = n.ex;
    panel.style.setProperty("--hue", n.hue);
    if (!silent) { panel.classList.remove("swap"); void panel.offsetWidth; panel.classList.add("swap"); }
  }

  function sample(w) {
    if (!w || w.pts) return;
    w.len = w.el.getTotalLength() || 1;
    w.pts = [];
    for (let k = 0; k <= 48; k++) { const q = w.el.getPointAtLength((k / 48) * w.len); w.pts.push(q.x, q.y); }
  }

  function spawn() {
    const prefer = nodes[active] && nodes[active].kind === "engine" && Math.random() < 0.55 ? Number(nodes[active].id.slice(1)) : (Math.random() * 9) | 0;
    const legs = [wires.find((w) => w.a === "in" && w.b === `e${prefer}`), wires.find((w) => w.a === `e${prefer}` && w.b === "fuse"), wires.find((w) => w.a === "fuse")];
    legs.forEach(sample);
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("r", "3.6");
    c.setAttribute("class", "packet");
    c.setAttribute("stroke-width", "4");
    c.style.stroke = "color-mix(in srgb, currentColor 35%, transparent)";
    c.style.fill = nodes[prefer + 1].hue;
    c.style.color = nodes[prefer + 1].hue;
    svg.append(c);
    packets.push({ el: c, legs, leg: 0, s: 0, speed: 0.45 + Math.random() * 0.25, engine: prefer });
  }

  // the loop exists only while the diagram is on screen and the tab is visible
  function frame(now) {
    raf = 0;
    if (!visible || document.hidden) return;
    raf = requestAnimationFrame(frame);
    const dt = Math.min(0.05, (now - last) / 1000 || 0); last = now;
    spawnT += dt; cycleT += dt;
    if (spawnT > 0.16 && packets.length < 26) { spawnT = 0; spawn(); }
    if (!hovered && cycleT > 3.4) { cycleT = 0; select((active + 1) % nodes.length); }
    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i];
      const w = p.legs[p.leg];
      p.s += (p.speed * dt * 420) / w.len;
      if (p.s >= 1) {
        p.s = 0; p.leg++;
        const hit = p.leg === 1 ? nodes[p.engine + 1] : p.leg === 2 ? nodes[10] : nodes[11];
        if (hit) hit.flash = 1;
        if (p.leg === 2) p.el.style.fill = "#c4b5fd";
        if (p.leg >= 3) { p.el.remove(); packets.splice(i, 1); continue; }
      }
      const pts = p.legs[p.leg].pts, f = p.s * 48, k = Math.min(47, f | 0), u = f - k;
      p.el.setAttribute("cx", (pts[2 * k] + (pts[2 * k + 2] - pts[2 * k]) * u).toFixed(1));
      p.el.setAttribute("cy", (pts[2 * k + 1] + (pts[2 * k + 3] - pts[2 * k + 1]) * u).toFixed(1));
    }
    nodes.forEach((n) => {
      if (n.flash > 0.01) { n.flash *= 0.9; n.el.style.setProperty("--flash", n.flash.toFixed(2)); }
    });
  }

  const run = () => { if (!reduced && visible && wires.length && !document.hidden && !raf) { last = performance.now(); raf = requestAnimationFrame(frame); } };
  new IntersectionObserver((entries) => { visible = entries[0].isIntersecting; run(); }, { threshold: 0.05 }).observe(box);
  document.addEventListener("visibilitychange", run);
  // Built from the ResizeObserver's first report (it comes with the diagram's width, after the
  // browser's own layout and before the frame is painted), so start-up forces no layout here.
  let lastW = 0;
  new ResizeObserver((es) => {
    const w = Math.round(es[0].contentRect.width);
    if (!w || w === lastW) return;
    const first = !lastW; lastW = w;
    if (first) { build(w); run(); } else layout(w);
  }).observe($("pipe-diagram"));
  window.CS.onLang(() => { if (lastW) build(); });
})();
