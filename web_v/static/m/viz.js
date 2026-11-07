/* Drawings for CyberScan Mobile: the map of a file, the history donut and the
 * 14-day activity bars. Plain canvas/SVG, no libraries. */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const STOPS = [[0, [40, 60, 160]], [3.5, [34, 140, 255]], [5.2, [34, 232, 255]], [6.6, [180, 108, 255]], [8, [255, 79, 216]]];

  function color(e) {
    for (let i = 1; i < STOPS.length; i++) if (e <= STOPS[i][0]) {
      const [e0, c0] = STOPS[i - 1], [e1, c1] = STOPS[i], k = (e - e0) / (e1 - e0);
      return c0.map((v, j) => Math.round(v + (c1[j] - v) * k));
    }
    return STOPS[STOPS.length - 1][1];
  }

  /* The file as a grid of cells: each cell is one slice of the file, coloured by
   * how random its bytes are; cells the engine flagged get a red ring. */
  function map(canvas, r, animate) {
    const s = r.structure && r.structure.entropy && r.structure.entropy.length ? r.structure : null;
    const values = s ? s.entropy : ((r.entropy && r.entropy.trajectory) || []);
    if (!values.length) return false;
    const flags = s ? s.flags || [] : [];
    const dpr = Math.min(window.devicePixelRatio || 1, 3);
    const w = canvas.clientWidth || 320;
    const n = values.length;
    const cols = Math.max(8, Math.min(48, Math.round(Math.sqrt(n * (w / 120)))));
    const rows = Math.ceil(n / cols);
    const cell = w / cols;
    const h = Math.max(48, Math.min(260, rows * cell));
    canvas.style.height = `${h}px`;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const ch = h / rows;
    const start = performance.now(), dur = animate ? 900 : 0;
    const draw = (now) => {
      const k = dur ? Math.min(1, (now - start) / dur) : 1;
      ctx.clearRect(0, 0, w, h);
      const shown = Math.ceil(n * k);
      for (let i = 0; i < shown; i++) {
        const x = (i % cols) * cell, y = Math.floor(i / cols) * ch;
        const [cr, cg, cb] = color(values[i]);
        ctx.fillStyle = `rgb(${cr},${cg},${cb})`;
        ctx.globalAlpha = 0.35 + 0.65 * Math.min(1, values[i] / 8);
        ctx.fillRect(x + 1, y + 1, cell - 2, ch - 2);
        ctx.globalAlpha = 1;
        if (flags[i]) {
          ctx.strokeStyle = "#ff4f6d"; ctx.lineWidth = 1.6;
          ctx.strokeRect(x + 1.5, y + 1.5, cell - 3, ch - 3);
        }
      }
      if (k < 1) requestAnimationFrame(draw);
    };
    requestAnimationFrame(draw);
    return { cells: n, flagged: flags.filter(Boolean).length, regions: s && s.regions ? s.regions.length : 0 };
  }

  function donut(svg, counts, colors) {
    svg.replaceChildren();
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    const C = 2 * Math.PI * 46;
    const ring = (stroke, len, off) => {
      const c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", 60); c.setAttribute("cy", 60); c.setAttribute("r", 46);
      c.setAttribute("fill", "none"); c.setAttribute("stroke-width", 14);
      c.setAttribute("stroke", stroke); c.setAttribute("stroke-dasharray", `${len} ${C}`); c.setAttribute("stroke-dashoffset", String(-off));
      c.setAttribute("transform", "rotate(-90 60 60)");
      svg.append(c); return c;
    };
    ring("rgba(127,139,179,.18)", C, 0);
    let off = 0;
    Object.keys(colors).forEach((key, i) => {
      if (!total || !counts[key]) return;
      const len = Math.max(0, (counts[key] / total) * C - 2);
      const arc = ring(colors[key], 0, off);
      arc.style.transition = "stroke-dasharray .9s cubic-bezier(.22,1,.36,1)";
      setTimeout(() => arc.setAttribute("stroke-dasharray", `${len} ${C}`), 80 + i * 160);
      off += (counts[key] / total) * C;
    });
  }

  /* checks per day for the last 14 days (bars), worst verdict sets the colour */
  function days(box, list, colors, locale) {
    const DAY = 864e5, today = new Date(); today.setHours(0, 0, 0, 0);
    const buckets = Array.from({ length: 14 }, (_, i) => ({ day: new Date(today - (13 - i) * DAY), n: 0, worst: null }));
    const rank = { NO_INDICATORS_OBSERVED: 0, REVIEW: 1, SUSPICIOUS: 2 };
    list.forEach((r) => {
      const d = new Date(r.when); d.setHours(0, 0, 0, 0);
      const i = 13 - Math.round((today - d) / DAY);
      if (i < 0 || i > 13) return;
      const b = buckets[i]; b.n++;
      if (b.worst == null || rank[r.classification] > rank[b.worst]) b.worst = r.classification;
    });
    const max = Math.max(1, ...buckets.map((b) => b.n));
    box.replaceChildren(...buckets.map((b, i) => {
      const bar = document.createElement("i");
      bar.style.setProperty("--h", `${Math.max(b.n ? 10 : 3, (b.n / max) * 100)}%`);
      bar.style.setProperty("--c", b.worst ? colors[b.worst] : "rgba(127,139,179,.3)");
      bar.style.transitionDelay = `${i * 30}ms`;
      bar.title = `${b.day.toLocaleDateString(locale, { month: "short", day: "numeric" })}: ${b.n}`;
      return bar;
    }));
    requestAnimationFrame(() => requestAnimationFrame(() => box.classList.add("grown")));
  }

  window.CSViz = { map, donut, days, color };
})();
