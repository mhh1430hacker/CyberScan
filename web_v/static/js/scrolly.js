/* The CyberScan story (#sci-story): one continuous scroll film in six chapters.
 *
 * - One canvas (.sy-bg, sticky, full screen) draws every visual from a single number P, the story
 *   position (scene i holds while P runs i .. i+0.7 and hands over to scene i+1 while P runs
 *   i+0.7 .. i+1). Objects travel between scenes: the suspicious file of the network (1) is the file
 *   that opens in layers (2); its bytes stream into the four instruments (3); the verdict gauge
 *   becomes the core of the ecosystem (4, 5); the ecosystem folds into the core and the core into
 *   the shield (6). Every scroll position shows a composed frame: no empty stretches.
 * - The words are real HTML: each scene's copy is a sticky block; the next scene's copy pushes it up.
 *   Kicker, title (word by word, out of masks) and beats are scrubbed from the same position.
 * - The scroll is native (no hijacking). The position is damped (critically, ~90 ms) so motion has
 *   weight; the loop runs only while that damped position is still moving: zero work when idle,
 *   none at all while the story is off screen.
 * - Reduced motion, html.reduce-motion and the "static scenes" level (phones) show each scene as an
 *   ordinary section with one finished frame drawn once into its own canvas. */
(function () {
  "use strict";
  const root = document.getElementById("sci-story");
  if (!root) return;
  const html = document.documentElement;
  const CS = window.CS || {};
  // The performance engine's "static scenes" level is honoured when the page loads; reached later,
  // mid-visit, the scenes keep their layout (un-pinning them would remove thousands of pixels above
  // the reader at once).
  const staticAtStart = html.classList.contains("fx-scenes-static");
  const isStill = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion") || staticAtStart;

  /* ---------------- maths ---------------- */
  const clamp = (x, a = 0, b = 1) => (x < a ? a : x > b ? b : x);
  const lerp = (a, b, t) => a + (b - a) * t;
  const seg = (t, a, b) => clamp((t - a) / (b - a));
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const expo = (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t));
  const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const back = (t) => { const c = 1.45, d = t - 1; return 1 + (c + 1) * d * d * d + c * d * d; };
  const frac = (x) => x - Math.floor(x);
  const bump = (t) => Math.sin(Math.PI * clamp(t));
  const rtl = () => html.dir === "rtl";
  const tr = (k, fb) => { const v = CS.t ? CS.t(k) : null; return typeof v === "string" && v ? v : fb; };
  const stepName = (i) => { const st = CS.t && CS.t("steps"); return Array.isArray(st) && st[i] && st[i][0] ? st[i][0] : ["Read", "Measure", "Compare", "Explain"][i]; };
  function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

  /* ---------------- identity ---------------- */
  const C = { cyan: "34,232,255", violet: "201,162,255", mag: "255,79,216", blue: "110,140,255", amber: "251,191,36", rose: "255,92,138", green: "74,222,128", text: "241,236,255", muted: "169,159,201", ink: "4,3,12" };
  const rgba = (c, a) => `rgba(${c},${a < 0 ? 0 : a > 1 ? 1 : a.toFixed(3)})`;
  const MONO = 'Consolas, "Cascadia Mono", ui-monospace, monospace';
  let SANS = '"Segoe UI Variable", "Segoe UI", system-ui, sans-serif';
  const font = (px, w, mono) => `${w || 400} ${px.toFixed(1)}px ${mono ? MONO : SANS}`;

  const ICONS = {
    you: "M4 6h16v10H4zM2 19h20M9 16v3m6-3v3", file: "M7 3h7l5 5v13H7zM14 3v5h5", apps: "M4 4h7v7H4zm9 0h7v7h-7zM4 13h7v7H4zm9 0h7v7h-7z",
    web: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.8 3 2.8 15 0 18M12 3c-2.8 3-2.8 15 0 18", devices: "M8 3h8v18H8zM11 18h2",
    cloud: "M7 18h10a4 4 0 0 0 .6-8A6 6 0 0 0 6.2 9.5 4.3 4.3 0 0 0 7 18z", net: "M5 15h14v5H5zM12 15V9m-4-2a5.5 5.5 0 0 1 8 0M5.5 4.5a9 9 0 0 1 13 0",
    bug: "M12 4a5 5 0 0 0-5 5v3l-2 3h14l-2-3V9a5 5 0 0 0-5-5zM9 18a3 3 0 0 0 6 0", link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
    site: "M3 5h18v14H3zM3 9h18M7 7h.01", mail: "M3 6h18v12H3zM3 7l9 6 9-6", lan: "M5 15h14v5H5zM12 15V9m-4-2a5.5 5.5 0 0 1 8 0", sys: "M4 5h16v11H4zM2 20h20",
    lock: "M12 3 5 6v5c0 4.5 3 8.2 7 9.5 4-1.3 7-5 7-9.5V6zM9.5 11h5v4h-5zm1-2a1.5 1.5 0 0 1 3 0v2h-3z", code: "M8 8 4 12l4 4m8-8 4 4-4 4M14 5l-4 14",
    check: "M5 12.5l4.5 4.5L19 7.5",
  };
  const PATHS = {};
  const path = (k) => PATHS[k] || (PATHS[k] = new Path2D(ICONS[k]));
  function icon(ctx, k, x, y, size, color, lw) {
    ctx.save(); ctx.translate(x - size / 2, y - size / 2); ctx.scale(size / 24, size / 24);
    ctx.lineWidth = lw || 1.7; ctx.strokeStyle = color; ctx.lineCap = "round"; ctx.lineJoin = "round"; ctx.stroke(path(k)); ctx.restore();
  }
  const SPRITES = {};
  function sprite(c) {
    if (SPRITES[c]) return SPRITES[c];
    const cv = document.createElement("canvas"); cv.width = cv.height = 128;
    const g = cv.getContext("2d"), gr = g.createRadialGradient(64, 64, 0, 64, 64, 64);
    gr.addColorStop(0, `rgba(${c},1)`); gr.addColorStop(0.22, `rgba(${c},.5)`); gr.addColorStop(0.55, `rgba(${c},.12)`); gr.addColorStop(1, `rgba(${c},0)`);
    g.fillStyle = gr; g.fillRect(0, 0, 128, 128); return (SPRITES[c] = cv);
  }
  function bloom(ctx, c, x, y, r, a) {
    if (a <= 0.004 || r <= 0.5) return;
    const op = ctx.globalCompositeOperation, ga = ctx.globalAlpha;
    ctx.globalCompositeOperation = "lighter"; ctx.globalAlpha = ga * clamp(a);
    ctx.drawImage(sprite(c), x - r, y - r, r * 2, r * 2);
    ctx.globalCompositeOperation = op; ctx.globalAlpha = ga;
  }
  function rr(ctx, x, y, w, h, r) {
    r = Math.max(0, Math.min(r, w / 2, h / 2));
    ctx.beginPath(); ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r); ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h); ctx.lineTo(x + r, y + h); ctx.quadraticCurveTo(x, y + h, x, y + h - r); ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y); ctx.closePath();
  }
  function txt(ctx, s, x, y, px, color, o = {}) {
    ctx.font = font(px, o.w, o.mono); ctx.fillStyle = color;
    ctx.textAlign = o.align || "left"; ctx.textBaseline = o.base || "middle";
    ctx.direction = o.mono || o.ltr ? "ltr" : rtl() ? "rtl" : "ltr";
    ctx.fillText(s, x, y);
  }
  const MEASURE = new Map();
  function tw(ctx, s, px, w, mono) { const k = `${px.toFixed(1)}|${w || 4}|${mono ? 1 : 0}|${s}`; let v = MEASURE.get(k); if (v == null) { ctx.font = font(px, w, mono); v = ctx.measureText(s).width; if (MEASURE.size > 600) MEASURE.clear(); MEASURE.set(k, v); } return v; }
  function wrap(ctx, s, px, w, maxW) {
    const words = s.split(/\s+/), lines = []; let line = "";
    for (const wd of words) { const tryL = line ? `${line} ${wd}` : wd; if (line && tw(ctx, tryL, px, w) > maxW) { lines.push(line); line = wd; } else line = tryL; }
    if (line) lines.push(line); return lines;
  }
  // a partial quadratic curve from its start to t (de Casteljau)
  function qPart(ctx, x0, y0, cx, cy, x1, y1, t) {
    const ax = lerp(x0, cx, t), ay = lerp(y0, cy, t), bx = lerp(cx, x1, t), by = lerp(cy, y1, t);
    ctx.moveTo(x0, y0); ctx.quadraticCurveTo(ax, ay, lerp(ax, bx, t), lerp(ay, by, t));
  }
  const qPt = (x0, y0, cx, cy, x1, y1, t) => { const u = 1 - t; return [u * u * x0 + 2 * u * t * cx + t * t * x1, u * u * y0 + 2 * u * t * cy + t * t * y1]; };
  const fz = (r, px, min = 10.5) => clamp(px * r.s / 0.8, min, px * 1.55);

  /* ---------------- data shared by the scenes ---------------- */
  const HUBS = [
    { x: 0, y: 0, ic: "you", k: "syYou", fb: "You" }, { x: -330, y: -220, ic: "file", k: "syFiles", fb: "Files" },
    { x: 330, y: -220, ic: "apps", k: "syApps", fb: "Apps" }, { x: 420, y: 40, ic: "web", k: "syWeb", fb: "Websites" },
    { x: 190, y: 292, ic: "devices", k: "syDevices", fb: "Devices" }, { x: -190, y: 292, ic: "cloud", k: "syCloud", fb: "Cloud" },
    { x: -420, y: 40, ic: "net", k: "syNet", fb: "Networks" },
  ];
  const SATS = (() => {
    const r = rng(11), out = [];
    for (let j = 1; j < HUBS.length; j++) {
      const h = HUBS[j], base = Math.atan2(h.y, h.x);
      for (let n = 0; n < 8; n++) {
        const ang = base + (r() - 0.5) * 2.6, dist = 78 + r() * 110;
        out.push({ h: j, x: clamp(h.x + Math.cos(ang) * dist, -485, 485), y: clamp(h.y + Math.sin(ang) * dist * 0.8, -395, 395), r: 1.3 + r() * 2.2, o: r() });
      }
    }
    return out;
  })();
  const SPOKES = HUBS.slice(1).map((h, i) => { const mx = h.x / 2, my = h.y / 2, len = Math.hypot(h.x, h.y), sg = i % 2 ? 1 : -1; return { cx: mx - (h.y / len) * len * 0.14 * sg, cy: my + (h.x / len) * len * 0.14 * sg }; });

  const BYTES = (() => {
    const b = new Array(128).fill(0);
    [0x4D, 0x5A, 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xB8].forEach((v, i) => { b[i] = v; });
    b[0x18] = 0x40; b[0x3C] = 0x80;
    [0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21].forEach((v, i) => { b[0x40 + i] = v; });
    const s = "This program cannot be run in DOS mode.\r\r\n$";
    for (let i = 0; i < s.length; i++) b[0x4E + i] = s.charCodeAt(i);
    return b;
  })();
  const HEX = BYTES.map((v) => v.toString(16).toUpperCase().padStart(2, "0"));
  const ASC = BYTES.map((v) => (v >= 32 && v < 127 ? String.fromCharCode(v) : "."));
  const STR0 = 0x4E, STR1 = 0x4E + 39;
  const ENT = (() => {
    const r = rng(5), e = [];
    for (let i = 0; i < 48; i++) {
      let v;
      if (i < 3) v = 1.6 + r() * 1.4; else if (i < 21) v = 5.5 + r() * 0.9; else if (i < 28) v = 3.9 + r() * 1.1; else if (i < 42) v = 7.62 + r() * 0.32; else v = 3.2 + r() * 1.3;
      e.push(v);
    }
    return e;
  })();
  const SECTS = [["hdr", 3, C.blue], [".text", 18, C.cyan], [".data", 7, C.violet], ["UPX1", 14, C.mag], [".rsrc", 6, C.blue]];
  const RULES = [
    { k: "syC1", fb: "Double extension (.pdf.exe)", tag: "NAME", w: 0.86, m: true },
    { k: "syC2", fb: "A program dressed as a document", tag: "MAGIC", w: 0.72, m: true },
    { k: "syC3", fb: "Scrambled section", tag: "ENTROPY", w: 0.5, m: true },
    { k: "syC4", fb: "Known threat fingerprint", tag: "SHA-256", w: 0, m: false },
  ];
  const DOMS = [
    { ic: "file", k: "syD1", fb: "File security", st: "live" }, { ic: "bug", k: "syD2", fb: "Malware analysis", st: "live" },
    { ic: "link", k: "syD3", fb: "URL & domain", st: "live" }, { ic: "site", k: "syD4", fb: "Website security", st: "dev" },
    { ic: "mail", k: "syD5", fb: "Email security", st: "live" }, { ic: "lan", k: "syD6", fb: "Network security", st: "dev" },
    { ic: "sys", k: "syD7", fb: "System security", st: "dev" }, { ic: "lock", k: "syD8", fb: "Privacy", st: "part" },
    { ic: "code", k: "syD9", fb: "Code & dependencies", st: "dev" }, { ic: "cloud", k: "syD10", fb: "Cloud & infrastructure", st: "dev" },
  ];
  const RELS = [[4, 2], [4, 0], [0, 1], [2, 0], [2, 3], [3, 5], [5, 6], [6, 1], [7, 0], [8, 7], [9, 8], [9, 5]];
  const DUST = (() => { const r = rng(3), d = []; for (let i = 0; i < 150; i++) d.push({ x: r(), y: r(), z: 0.15 + r() * 0.85, w: r() * 6.28 }); return d; })();
  // the shield outline as 96 points (the same path as the logo), and a circle with the same count, for the morph
  const SHIELD = (() => {
    const pts = [], push = (x, y) => pts.push([x, y]);
    const half = [];
    for (let i = 0; i <= 20; i++) { const t = i / 20; half.push([lerp(0, 0.8, t), lerp(-1, -0.73, t)]); }
    for (let i = 1; i <= 20; i++) { const t = i / 20; half.push([0.8, lerp(-0.73, -0.02, t)]); }
    for (let i = 1; i <= 30; i++) { const t = i / 30, [x, y] = qPt(0.8, -0.02, 0.76, 0.62, 0, 1, t); half.push([x, y]); }
    half.forEach(([x, y]) => push(x, y));
    for (let i = half.length - 2; i > 0; i--) push(-half[i][0], half[i][1]);
    // resample to 96 points evenly along the outline
    const L = [0]; for (let i = 1; i <= pts.length; i++) { const a = pts[i - 1], b = pts[i % pts.length]; L.push(L[i - 1] + Math.hypot(b[0] - a[0], b[1] - a[1])); }
    const total = L[L.length - 1], out = [];
    for (let k = 0, j = 0; k < 96; k++) {
      const want = (k / 96) * total; while (L[j + 1] < want) j++;
      const a = pts[j], b = pts[(j + 1) % pts.length], f = (want - L[j]) / Math.max(1e-6, L[j + 1] - L[j]);
      out.push([lerp(a[0], b[0], f), lerp(a[1], b[1], f) + 0.03]);
    }
    return out;
  })();
  function morphPath(ctx, x, y, rad, m) {
    ctx.beginPath();
    for (let k = 0; k < 96; k++) {
      const ang = -Math.PI / 2 + (k / 96) * Math.PI * 2, cx = Math.cos(ang), cy = Math.sin(ang);
      const px = x + lerp(cx, SHIELD[k][0] * 1.06, m) * rad, py = y + lerp(cy, SHIELD[k][1] * 1.06, m) * rad;
      if (k) ctx.lineTo(px, py); else ctx.moveTo(px, py);
    }
    ctx.closePath();
  }

  /* ---------------- geometry of the stage ---------------- */
  function mkReg(x0, y0, x1, y1) { const w = Math.max(1, x1 - x0), h = Math.max(1, y1 - y0); return { x0, y0, x1, y1, w, h, cx: x0 + w / 2, cy: y0 + h / 2, s: Math.min(w / 1000, h / 820) }; }
  // scene 1: camera that dives into the suspicious file
  function s1cam(V, P) {
    const r = V.reg[0], t = clamp(P / 0.7), d = clamp((P - 0.7) / 0.3), f = HUBS[1];
    const zoom = 1 + 0.09 * inOut(seg(t, 0.62, 1)) + 1.7 * inOut(d);
    const fx = r.cx + f.x * r.s, fy = r.cy + f.y * r.s;
    return { r, zoom, fx, fy, X: (x) => fx + (r.cx + x * r.s - fx) * zoom, Y: (y) => fy + (r.cy + y * r.s - fy) * zoom, S: (v) => v * r.s * zoom };
  }
  function s2geo(V) {
    const r = V.reg[1], compact = r.w < 640, ss = Math.min(r.w / (compact ? 640 : 900), r.h / 700), side = rtl() ? -1 : 1;
    return { r, ss, compact, side, cx: r.cx - side * (compact ? 120 : 150) * ss, cy: r.cy + 10 * ss };
  }
  function s3geo(V) {
    const r = V.reg[2], w = Math.min(r.w, r.h * 1.6), h = Math.min(r.h, w * 0.98), gap = clamp(w * 0.028, 10, 26);
    const x0 = r.cx - w / 2, y0 = r.cy - h / 2, pw = (w - gap) / 2, ph = (h - gap) / 2, R = rtl();
    return [[0, 0], [1, 0], [1, 1], [0, 1]].map(([c, rw]) => { const cc = R ? 1 - c : c; return { x: x0 + cc * (pw + gap), y: y0 + rw * (ph + gap), w: pw, h: ph, ps: clamp(Math.min(pw / 420, ph / 360), 0.55, 1.7) }; });
  }
  function gaugeGeo(p) { const R = Math.min(p.w * 0.27, p.h * 0.27); return { x: p.x + p.w / 2, y: p.y + 54 * p.ps + R, R }; }

  /* ---------------- the frame ---------------- */
  function draw(V, P) {
    const ctx = V.ctx;
    ctx.setTransform(V.dpr, 0, 0, V.dpr, 0, 0);
    ctx.clearRect(0, 0, V.W, V.H);
    drawBg(V, P);
    if (P < 1) scene1(V, P);
    if (P > 0.7 && P < 2) scene2(V, P);
    if (P > 1.72 && P < 3) scene3(V, P);
    if (P > 2.7 && P < 5) eco(V, P);
    if (P > 4.7) scene6(V, P);
  }

  const PAL = [[C.cyan, C.violet], [C.violet, C.cyan], [C.cyan, C.mag], [C.mag, C.violet], [C.violet, C.cyan], [C.cyan, C.violet]];
  function drawBg(V, P) {
    const ctx = V.ctx, { W, H } = V, r = V.reg[clamp(Math.round(P), 0, 5)], big = Math.max(W, H);
    const i0 = clamp(Math.floor(P), 0, 5), i1 = clamp(i0 + 1, 0, 5), f = inOut(frac(Math.max(0, P)));
    const sway = Math.sin(P * 1.3) * 0.06;
    [[i0, 1 - f], [i1, f]].forEach(([i, w]) => {
      if (w < 0.01) return;
      bloom(ctx, PAL[i][0], r.cx + sway * W, r.cy, big * 0.55, 0.13 * w * V.bgA);
      bloom(ctx, PAL[i][1], r.cx + (0.18 - sway) * W, r.cy - 0.28 * H, big * 0.38, 0.1 * w * V.bgA);
    });
    // a quiet instrument dial around the stage: concentric rings and ticks that turn with the story
    const s = r.s, rot = P * 0.12;
    ctx.lineWidth = 1;
    ctx.strokeStyle = rgba(C.violet, 0.05 * V.bgA);
    ctx.beginPath(); [190, 330, 460].forEach((rad) => { ctx.moveTo(r.cx + rad * s, r.cy); ctx.arc(r.cx, r.cy, rad * s, 0, Math.PI * 2); }); ctx.stroke();
    ctx.strokeStyle = rgba(C.cyan, 0.09 * V.bgA); ctx.beginPath();
    for (let k = 0; k < 120; k++) {
      const a = rot + (k / 120) * Math.PI * 2, l = k % 10 ? 6 : 14, ca = Math.cos(a), sa = Math.sin(a), R = 460 * s;
      ctx.moveTo(r.cx + ca * R, r.cy + sa * R); ctx.lineTo(r.cx + ca * (R + l * s), r.cy + sa * (R + l * s));
    }
    ctx.stroke();
    // dust at three depths: parallax with the story, drawn as three batched paths
    const conv = seg(P, 4.75, 5.6) * 0.3, ex = V.emb.x, ey = V.emb.y;
    for (let b = 0; b < 3; b++) {
      ctx.beginPath();
      for (let i = b; i < DUST.length; i += 3) {
        const d = DUST[i], span = H * 1.3;
        let x = d.x * W + Math.sin(P * 0.8 + d.w) * 22 * d.z, y = ((d.y * span - (P + 1) * 240 * d.z) % span + span) % span - H * 0.15;
        if (conv) { x = lerp(x, ex, conv * d.z); y = lerp(y, ey, conv * d.z); }
        const sz = 0.6 + d.z * 1.5; ctx.rect(x, y, sz, sz);
      }
      ctx.fillStyle = rgba(b === 1 ? C.cyan : b === 2 ? C.violet : C.text, (0.1 + b * 0.09) * V.bgA); ctx.fill();
    }
    // the copy side stays calm and readable
    const sa = V.scrim * (1 - seg(P, 4.72, 4.98));
    if (sa > 0.01 && V.copy) {
      const cp = V.copy;
      let g;
      if (cp.narrow) { g = ctx.createLinearGradient(0, 0, 0, cp.bottom + 60); g.addColorStop(0, rgba(C.ink, 0.86 * sa)); g.addColorStop(0.75, rgba(C.ink, 0.7 * sa)); g.addColorStop(1, rgba(C.ink, 0)); }
      else if (cp.rtl) { g = ctx.createLinearGradient(W, 0, cp.edge - 220, 0); g.addColorStop(0, rgba(C.ink, 0.82 * sa)); g.addColorStop(0.6, rgba(C.ink, 0.55 * sa)); g.addColorStop(1, rgba(C.ink, 0)); }
      else { g = ctx.createLinearGradient(0, 0, cp.edge + 220, 0); g.addColorStop(0, rgba(C.ink, 0.82 * sa)); g.addColorStop(0.6, rgba(C.ink, 0.55 * sa)); g.addColorStop(1, rgba(C.ink, 0)); }
      ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
    }
  }

  /* ---------------- 1 · the digital world ---------------- */
  function scene1(V, P) {
    const ctx = V.ctx, a = clamp(P + 1), t = clamp(P / 0.7), d = clamp((P - 0.7) / 0.3);
    const cam = s1cam(V, P), { X, Y, S, r } = cam;
    const out = 1 - ease(clamp(d * 1.5));
    if (out <= 0.01 && d >= 1) return;
    const build = ease(seg(a, 0.05, 0.5));
    const fs = fz(r, 13.5) * Math.min(1.6, cam.zoom);
    ctx.save();
    // ring between hubs
    ctx.globalAlpha = out;
    ctx.setLineDash([S(3), S(7)]); ctx.lineWidth = 1; ctx.strokeStyle = rgba(C.violet, 0.22 * build);
    ctx.beginPath(); for (let j = 1; j <= 6; j++) { const h = HUBS[j], n = HUBS[j % 6 + 1]; ctx.moveTo(X(h.x), Y(h.y)); ctx.lineTo(X(n.x), Y(n.y)); } ctx.stroke(); ctx.setLineDash([]);
    // satellites and their links
    ctx.lineWidth = 1;
    const satA = (i) => ease(seg(a + t * 0.6, 0.55 + (i / SATS.length) * 0.5, 0.75 + (i / SATS.length) * 0.5));
    ctx.strokeStyle = rgba(C.cyan, 0.13); ctx.beginPath();
    SATS.forEach((sv, i) => { const k = satA(i); if (k <= 0) return; const h = HUBS[sv.h]; ctx.moveTo(X(h.x), Y(h.y)); ctx.lineTo(X(lerp(h.x, sv.x, k)), Y(lerp(h.y, sv.y, k))); });
    ctx.stroke();
    SATS.forEach((sv, i) => {
      const k = satA(i); if (k <= 0) return;
      const tw2 = 0.55 + 0.45 * Math.sin(P * 9 + sv.o * 20);
      ctx.fillStyle = rgba(sv.o > 0.7 ? C.violet : C.cyan, (0.45 + 0.4 * tw2) * k);
      ctx.beginPath(); ctx.arc(X(sv.x), Y(sv.y), S(sv.r) * (0.4 + 0.6 * k), 0, 6.283); ctx.fill();
    });
    // spokes from you to every hub, drawing themselves
    ctx.lineWidth = Math.max(1, S(1.6));
    HUBS.slice(1).forEach((h, i) => {
      const k = ease(seg(a, 0.3 + i * 0.06, 0.72 + i * 0.06)); if (k <= 0) return;
      const sp = SPOKES[i], g = ctx.createLinearGradient(X(0), Y(0), X(h.x), Y(h.y));
      g.addColorStop(0, rgba(C.cyan, 0.55)); g.addColorStop(1, rgba(C.violet, 0.4));
      ctx.strokeStyle = g; ctx.beginPath(); qPart(ctx, X(0), Y(0), X(sp.cx), Y(sp.cy), X(h.x), Y(h.y), k); ctx.stroke();
    });
    // packets: they travel with the scroll, in both directions
    const pk = seg(a, 0.8, 1) * out;
    if (pk > 0) {
      for (let j = 1; j <= 6; j++) {
        const h = HUBS[j], sp = SPOKES[j - 1];
        for (let k = 0; k < 3; k++) {
          let ph = frac(P * 1.25 + k / 3 + j * 0.21); if (j % 2) ph = 1 - ph;
          const [x, y] = qPt(X(0), Y(0), X(sp.cx), Y(sp.cy), X(h.x), Y(h.y), ph);
          const safe = seg(t, 0.36, 0.46) * (1 - seg(t, 0.64, 0.7));
          const col = safe > 0.5 ? C.green : j === 1 && k === 0 && t > 0.62 ? C.text : C.cyan;
          bloom(ctx, col, x, y, S(15), 0.55 * pk);
          ctx.fillStyle = rgba(col, pk); ctx.beginPath(); ctx.arc(x, y, Math.max(1.4, S(2.6)), 0, 6.283); ctx.fill();
        }
      }
    }
    // pulses around "you"
    const you = ease(seg(a, 0.02, 0.4));
    for (let k = 0; k < 3; k++) { const f = frac(P * 1.4 + k / 3); ctx.strokeStyle = rgba(C.cyan, (1 - f) * 0.28 * you); ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(X(0), Y(0), S(46 + f * 120), 0, 6.283); ctx.stroke(); }
    ctx.restore();
    // hubs
    HUBS.forEach((h, j) => {
      const k = j === 0 ? back(seg(a, 0.0, 0.35)) : back(seg(a, 0.22 + j * 0.06, 0.6 + j * 0.06)); if (k <= 0.01) return;
      const files = j === 1;
      const alpha = files ? clamp(k) * (1 - seg(d, 0.04, 0.3)) : clamp(k) * out;
      if (alpha <= 0.01) return;
      const pos = j === 0 ? 1 : ease(clamp(k)), x = X(h.x * pos), y = Y(h.y * pos), rad = S(j === 0 ? 44 : 31) * clamp(k, 0, 1.2);
      ctx.save(); ctx.globalAlpha = alpha;
      bloom(ctx, j === 0 ? C.cyan : C.violet, x, y, rad * 3.2, j === 0 ? 0.42 : 0.24);
      const g = ctx.createRadialGradient(x, y - rad * 0.4, rad * 0.1, x, y, rad);
      g.addColorStop(0, "rgba(40,26,84,.96)"); g.addColorStop(1, "rgba(10,7,26,.96)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, rad, 0, 6.283); ctx.fill();
      ctx.lineWidth = j === 0 ? 1.6 : 1.2; ctx.strokeStyle = j === 0 ? rgba(C.cyan, 0.9) : rgba(C.violet, 0.55); ctx.stroke();
      icon(ctx, h.ic, x, y, rad * (j === 0 ? 0.95 : 1.02), j === 0 ? rgba(C.cyan, 1) : "#e8dcff", 1.6);
      txt(ctx, tr(h.k, h.fb), x, y + rad + fs * 1.05, fs, j === 0 ? "#ffffff" : "#d9cff5", { align: "center", w: j === 0 ? 650 : 500 });
      // "safe" ticks, one per hub, as the second beat lands
      const ok = ease(seg(t, 0.36 + j * 0.025, 0.46 + j * 0.025)) * (1 - seg(d, 0, 0.3));
      if (j && ok > 0.01) {
        const bx = x + rad * 0.78, by = y - rad * 0.78, br = Math.max(6, S(9));
        ctx.globalAlpha = alpha * ok; ctx.fillStyle = "rgba(6,30,18,.95)"; ctx.beginPath(); ctx.arc(bx, by, br, 0, 6.283); ctx.fill();
        ctx.strokeStyle = rgba(C.green, 0.9); ctx.lineWidth = 1.2; ctx.stroke(); icon(ctx, "check", bx, by, br * 1.4, rgba(C.green, 1), 2.6);
      }
      ctx.restore();
    });
    // the one that only looks normal
    const th = ease(seg(t, 0.68, 0.8)) * (1 - seg(d, 0, 0.35));
    if (th > 0.01) {
      const h = HUBS[1], x = X(h.x), y = Y(h.y), rad = S(54) * (1 + (1 - th) * 0.7);
      ctx.save(); ctx.globalAlpha = th;
      bloom(ctx, C.rose, x, y, rad * 2.4, 0.35);
      ctx.setLineDash([S(7), S(6)]); ctx.lineDashOffset = -P * 60; ctx.lineWidth = Math.max(1.5, S(2)); ctx.strokeStyle = rgba(C.rose, 0.95);
      ctx.beginPath(); ctx.arc(x, y, rad, 0, 6.283); ctx.stroke(); ctx.setLineDash([]);
      const label = tr("syLooks", "Looks normal"), lf = fz(r, 13), pw = tw(ctx, label, lf, 600) + lf * 1.6, ph = lf * 2;
      const lx = x + rad * 0.85, ly = y - rad * 1.05 - ph;
      rr(ctx, lx, ly, pw, ph, ph / 2); ctx.fillStyle = "rgba(60,10,32,.88)"; ctx.fill(); ctx.strokeStyle = rgba(C.rose, 0.75); ctx.lineWidth = 1; ctx.stroke();
      txt(ctx, label, lx + pw / 2, ly + ph / 2 + 0.5, lf, "#ffd1dc", { align: "center", w: 600 });
      ctx.restore();
    }
  }

  /* ---------------- 2 · inside a file ---------------- */
  const ROT = [Math.cos(-0.63), Math.sin(-0.63)];
  function scene2(V, P) {
    const ctx = V.ctx, a = clamp((P - 0.7) / 0.3), t = clamp((P - 1) / 0.7), d = clamp((P - 1.7) / 0.3);
    const G = s2geo(V), { ss, side, r } = G;
    const cam = s1cam(V, Math.min(P, 1));
    // arrival: the file grows out of the suspicious node; departure: it folds and flows into the reader
    const arr = expo(a), go = inOut(seg(d, 0.2, 1));
    const read = s3geo(V)[0];
    const cx0 = lerp(cam.fx, G.cx, arr), cy0 = lerp(cam.fy, G.cy, arr);
    const cx = lerp(cx0, read.x + read.w / 2, go), cy = lerp(cy0, read.y + read.h * 0.55, go);
    const k = lerp(0.16, 1, arr) * lerp(1, 0.36, go);
    const alpha = seg(a, 0, 0.18) * (1 - seg(d, 0.62, 0.95));
    const m = inOut(seg(t, 0.26, 0.48)), ex = inOut(seg(t, 0.3, 0.52)) * (1 - inOut(seg(d, 0, 0.4)));
    const hot = ease(seg(t, 0.8, 0.9)) * (1 - seg(d, 0, 0.3));
    const floatY = Math.sin(P * 4) * 4 * ss * (1 - m);
    const gap = 80 * ss * k;
    // scan beam: top to bottom of the opened stack
    const bt = seg(t, 0.44, 0.8), span = (2 * gap * ex + 70 * ss * k);
    const beamY = lerp(cy - span - 10 * ss, cy + span + 10 * ss, bt);
    const layers = [];
    for (let i = 4; i >= 0; i--) {
      const z = (2 - i) * gap * ex;
      const fw = 236 * 1.34 * ss * k, fh = 300 * 1.34 * ss * k, LW = 250 * ss * k, LD = 168 * ss * k;
      const ie1 = [LW * ROT[0], LW * ROT[1] * 0.56], ie2 = [-LD * ROT[1], LD * ROT[0] * 0.56];
      const e1 = [lerp(fw, ie1[0], m), lerp(0, ie1[1], m)], e2 = [lerp(0, ie2[0], m), lerp(fh, ie2[1], m)];
      const lw = lerp(236, 250, m), lh = lerp(300, 168, m);   // local units; the face-on card is drawn 1.34x larger
      const p0 = [cx - (e1[0] + e2[0]) / 2, cy + floatY - z - (e1[1] + e2[1]) / 2];
      layers.push({ i, e1, e2, lw, lh, p0, ccy: p0[1] + (e1[1] + e2[1]) / 2 });
    }
    ctx.save(); ctx.globalAlpha = alpha;
    // the stack's shadow and light
    bloom(ctx, hot > 0.3 ? C.rose : C.violet, cx, cy + 20 * ss * k, 260 * ss * k, 0.22 + 0.12 * ex);
    layers.forEach((L) => {
      const vis = L.i === 0 ? 1 : seg(m, 0.1, 0.6);
      if (vis <= 0.01) return;
      const passed = seg(beamY - L.ccy, -14 * ss, 26 * ss) * (bt > 0 ? 1 : 0);
      const reading = bt > 0 && bt < 1 ? bump(seg(beamY - L.ccy, -40 * ss, 40 * ss)) : 0;
      const isHot = L.i === 1 ? hot : 0;
      ctx.save(); ctx.globalAlpha = alpha * vis;
      const ax = L.e1[0] / L.lw, ay = L.e1[1] / L.lw, bx = L.e2[0] / L.lh, by = L.e2[1] / L.lh;
      ctx.transform(ax, ay, bx, by, L.p0[0], L.p0[1]);
      layerPlate(ctx, L, reading, isHot, passed);
      layerContent(ctx, L, m, hot, passed);
      ctx.restore();
      if (reading > 0.05) bloom(ctx, C.cyan, L.p0[0] + (L.e1[0] + L.e2[0]) / 2, L.ccy, 170 * ss * k, 0.3 * reading);
      if (isHot > 0.05) bloom(ctx, C.rose, L.p0[0] + (L.e1[0] + L.e2[0]) / 2, L.ccy, 200 * ss * k, 0.4 * isHot);
    });
    // the beam
    if (bt > 0 && bt < 1) {
      const bw = 230 * ss * k, g = ctx.createLinearGradient(cx - bw, 0, cx + bw, 0);
      g.addColorStop(0, rgba(C.cyan, 0)); g.addColorStop(0.3, rgba(C.cyan, 0.9)); g.addColorStop(0.5, "rgba(255,255,255,1)"); g.addColorStop(0.7, rgba(C.cyan, 0.9)); g.addColorStop(1, rgba(C.cyan, 0));
      ctx.fillStyle = g; ctx.fillRect(cx - bw, beamY - 1.2, bw * 2, 2.4);
      bloom(ctx, C.cyan, cx, beamY, bw * 0.7, 0.35);
    }
    ctx.restore();
    // labels: one per layer, connected to its corner
    const la = alpha * (1 - seg(d, 0, 0.25));
    if (la > 0.01 && m > 0.5) {
      const nf = fz(r, 15.5, 11), df = fz(r, 13, 10.5), colX = cx + side * (G.compact ? 225 : 250) * ss;
      const LBL = [["syL1", "Name", "syL1d", "What it claims to be"], ["syL2", "First bytes", "syL2d", "What it really is: a program"], ["syL3", "Structure", "syL3d", "How it is built"], ["syL4", "Contents", "syL4d", "Ordered, or scrambled?"], ["syL5", "Fingerprint", "syL5d", "A unique ID for these exact bytes"]];
      layers.forEach((L) => {
        const passed = seg(beamY - L.ccy, -14 * ss, 26 * ss) * (bt > 0 ? 1 : 0);
        const shown = ease(passed) * la; if (shown <= 0.01) return;
        const corner = side > 0 ? [L.p0[0] + L.e1[0] + L.e2[0], L.p0[1] + L.e1[1] + L.e2[1]] : [L.p0[0], L.p0[1]];
        const y = corner[1], x1 = colX - side * 10 * ss;
        const isHot = L.i === 1 ? hot : 0, col = isHot > 0.5 ? C.rose : L.i === 4 ? C.violet : C.cyan;
        ctx.save(); ctx.globalAlpha = shown;
        ctx.strokeStyle = rgba(col, 0.55); ctx.lineWidth = 1; ctx.setLineDash([2, 3]);
        ctx.beginPath(); ctx.moveTo(corner[0], corner[1]); ctx.lineTo(lerp(corner[0], x1, ease(passed)), y); ctx.stroke(); ctx.setLineDash([]);
        ctx.fillStyle = rgba(col, 1); ctx.beginPath(); ctx.arc(corner[0], corner[1], 2.6, 0, 6.283); ctx.fill();
        const tx = colX + side * (1 - ease(passed)) * 18, al = side > 0 ? "left" : "right", L2 = LBL[L.i];
        const twoLines = !G.compact;
        ctx.fillStyle = rgba(col, 0.9); ctx.fillRect(side > 0 ? tx : tx - 3, y - (twoLines ? nf * 0.95 : nf * 0.6), 3, twoLines ? nf * 1.9 : nf * 1.2);
        const tx2 = tx + side * 12;
        txt(ctx, tr(L2[0], L2[1]), tx2, twoLines ? y - nf * 0.42 : y, nf, isHot > 0.5 ? "#ffd1dc" : "#ffffff", { align: al, w: 650 });
        if (twoLines) txt(ctx, tr(L2[2], L2[3]), tx2, y + nf * 0.66, df, isHot > 0.5 ? "#ffb3c6" : rgba(C.muted, 1), { align: al });
        ctx.restore();
      });
    }
    // departure: the bytes stream out of the folded file into the reader
    if (d > 0.12 && d < 1) {
      const p3 = s3geo(V)[0];
      for (let q = 0; q < 26; q++) {
        const g = expo(seg(d, 0.12 + q * 0.018, 0.62 + q * 0.018)); if (g <= 0 || g >= 1) continue;
        const sx = cx0 + Math.sin(q * 7.1) * 60 * ss, sy = cy0 + Math.cos(q * 3.3) * 50 * ss;
        const tx = p3.x + p3.w * (0.18 + (q % 8) * 0.085), ty = p3.y + p3.h * (0.25 + Math.floor(q / 8) * 0.07);
        const x = lerp(sx, tx, g), y = lerp(sy, ty, g) - Math.sin(g * Math.PI) * 60 * ss;
        ctx.globalAlpha = bump(g); txt(ctx, HEX[q], x, y, 12 * p3.ps, q < 2 ? "#ffb3c6" : rgba(C.cyan, 1), { mono: true, align: "center", w: 600 });
        ctx.globalAlpha = 1;
      }
    }
  }
  function layerPlate(ctx, L, reading, hot, passed) {
    const g = ctx.createLinearGradient(0, 0, 0, L.lh);
    g.addColorStop(0, "rgba(34,22,72,.97)"); g.addColorStop(1, "rgba(11,7,28,.97)");
    rr(ctx, 0, 0, L.lw, L.lh, 16); ctx.fillStyle = g; ctx.fill();
    if (hot > 0.01) { ctx.fillStyle = rgba(C.rose, 0.14 * hot); ctx.fill(); }
    ctx.lineWidth = reading > 0.2 || hot > 0.2 ? 2.2 : 1.2;
    ctx.strokeStyle = hot > 0.3 ? rgba(C.rose, 0.95) : reading > 0.05 ? rgba(C.cyan, 0.5 + 0.5 * reading) : passed > 0.5 ? rgba(C.cyan, 0.42) : rgba(C.violet, 0.4);
    ctx.stroke();
  }
  function layerContent(ctx, L, m, hot, passed) {
    const w = L.lw, h = L.lh;
    if (L.i === 0) {
      // face-on: the invoice it pretends to be
      if (m < 0.99) {
        ctx.save(); ctx.globalAlpha *= 1 - m;
        icon(ctx, "file", 30, 34, 24, "#c9b8ff", 1.6);
        txt(ctx, "invoice.pdf", 50, 34, 15, "#ffffff", { w: 600, ltr: true });
        rr(ctx, w - 58, 20, 40, 24, 6); ctx.fillStyle = rgba(C.rose, 0.9); ctx.fill(); txt(ctx, "PDF", w - 38, 32.5, 11, "#fff", { align: "center", w: 700, mono: true });
        ctx.fillStyle = rgba(C.violet, 0.14); ctx.fillRect(18, 56, w - 36, 1);
        txt(ctx, tr("syInv", "Invoice").toUpperCase(), rtl() ? w - 22 : 22, 86, 22, "#ffffff", { w: 750, align: rtl() ? "right" : "left" });
        for (let i = 0; i < 6; i++) { ctx.fillStyle = rgba(C.text, i % 3 === 0 ? 0.22 : 0.12); rr(ctx, 22, 118 + i * 20, (w - 44) * (i % 3 === 0 ? 0.62 : i % 2 ? 0.92 : 0.78), 7, 3.5); ctx.fill(); }
        ctx.fillStyle = rgba(C.violet, 0.14); ctx.fillRect(18, 248, w - 36, 1);
        ctx.fillStyle = rgba(C.text, 0.3); rr(ctx, 22, 264, 70, 9, 4.5); ctx.fill();
        ctx.fillStyle = rgba(C.amber, 0.85); rr(ctx, w - 102, 262, 80, 13, 6.5); ctx.fill();
        ctx.restore();
      }
      if (m > 0.01) {
        ctx.save(); ctx.globalAlpha *= m;
        icon(ctx, "file", 42, h / 2, 34, "#c9b8ff", 1.6);
        txt(ctx, "invoice.pdf", 70, h / 2, 23, "#ffffff", { w: 650, ltr: true });
        if (hot > 0.01) {
          const x = 70 + tw(ctx, "invoice.pdf", 23, 650);
          ctx.globalAlpha *= hot; txt(ctx, ".exe", x + 2, h / 2, 23, "#ff7aa2", { w: 750, ltr: true });
        }
        ctx.restore();
      }
      return;
    }
    if (L.i === 1) {
      txt(ctx, "4D 5A", 26, h * 0.4, 30, hot > 0.3 ? "#ff7aa2" : "#ffb3c6", { mono: true, w: 700 });
      txt(ctx, "90 00 03 00 · ·", 132, h * 0.4, 20, rgba(C.muted, 1), { mono: true });
      txt(ctx, "M   Z", 32, h * 0.72, 20, hot > 0.3 ? "#ff7aa2" : rgba(C.rose, 0.8), { mono: true, w: 700 });
      return;
    }
    if (L.i === 2) {
      let x = 22; const tot = 214, ws = [0.12, 0.42, 0.16, 0.3], cols = [C.blue, C.cyan, C.violet, C.mag], names = ["hdr", ".text", ".data", "UPX1"];
      ws.forEach((f, i) => { const bw = tot * f - 5; rr(ctx, x, h * 0.26, bw, h * 0.36, 6); ctx.fillStyle = rgba(cols[i], 0.24); ctx.fill(); ctx.strokeStyle = rgba(cols[i], 0.7); ctx.lineWidth = 1.2; ctx.stroke(); txt(ctx, names[i], x + bw / 2, h * 0.76, 12, rgba(C.muted, 1), { mono: true, align: "center" }); x += bw + 5; });
      return;
    }
    if (L.i === 3) {
      const n = 18, bw = (w - 44) / n;
      for (let i = 0; i < n; i++) {
        const v = ENT[Math.floor((i / n) * 48)] / 8, bh = (h - 56) * v, hi = v > 0.92;
        ctx.fillStyle = hi ? rgba(C.mag, 0.85) : rgba(C.cyan, 0.6); rr(ctx, 22 + i * bw + 1.5, h - 26 - bh, bw - 3, bh, 2); ctx.fill();
      }
      return;
    }
    txt(ctx, "SHA-256", 24, h * 0.3, 13, rgba(C.muted, 1), { mono: true });
    txt(ctx, "d8957b11…167c97c", 24, h * 0.52, 19, "#ead9ff", { mono: true, w: 600 });
    for (let i = 0; i < 44; i++) { const v = (Math.sin(i * 12.9898) * 43758.5453) % 1; ctx.fillStyle = rgba(C.violet, 0.25 + Math.abs(v) * 0.5); ctx.fillRect(24 + i * 4.8, h * 0.68, Math.abs(v) > 0.5 ? 3 : 1.4, 26); }
  }

  /* ---------------- 3 · the four steps, up close ---------------- */
  function scene3(V, P) {
    const ctx = V.ctx, a = clamp((P - 1.7) / 0.3), t = clamp((P - 2) / 0.7), d = clamp((P - 2.7) / 0.3);
    const PN = s3geo(V), r = V.reg[2];
    const sp = clamp((t - 0.02) / 0.9) * 4;
    // the wiring between the instruments, with the token of work moving along it
    const wire = ease(seg(a, 0.4, 1)) * (1 - seg(d, 0, 0.3));
    if (wire > 0.01) {
      ctx.save(); ctx.globalAlpha = wire;
      for (let k = 0; k < 3; k++) {
        const A = PN[k], B = PN[k + 1], ax = A.x + A.w / 2, ay = A.y + A.h / 2, bx = B.x + B.w / 2, by = B.y + B.h / 2;
        const lit = seg(sp, k + 0.8, k + 1.05);
        ctx.strokeStyle = rgba(C.violet, 0.18); ctx.lineWidth = 1; ctx.setLineDash([3, 5]);
        ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke(); ctx.setLineDash([]);
        if (lit > 0) { ctx.strokeStyle = rgba(C.cyan, 0.55); ctx.lineWidth = 1.6; ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(lerp(ax, bx, lit), lerp(ay, by, lit)); ctx.stroke(); }
        if (lit > 0 && lit < 1) { const x = lerp(ax, bx, lit), y = lerp(ay, by, lit); bloom(ctx, C.cyan, x, y, 40, 0.9); ctx.fillStyle = "#fff"; ctx.beginPath(); ctx.arc(x, y, 3, 0, 6.283); ctx.fill(); }
      }
      ctx.restore();
    }
    PN.forEach((p, k) => {
      const ap = back(seg(a, 0.15 + k * 0.12, 0.62 + k * 0.12)), dp = inOut(seg(d, k * 0.08, 0.55 + k * 0.08));
      const alpha = clamp(ap) * (1 - dp); if (alpha <= 0.01) return;
      const st = sp - k, act = seg(st, -0.05, 0.05) * (1 - seg(st, 0.97, 1.05));
      const sc = lerp(0.9, 1, clamp(ap)) * lerp(1, 0.55, dp) * (1 + 0.012 * act);
      const pcx = p.x + p.w / 2, pcy = p.y + p.h / 2, tx = lerp(pcx, r.cx, dp), ty = lerp(pcy, r.cy, dp);
      ctx.save(); ctx.globalAlpha = alpha;
      ctx.translate(tx, ty); ctx.scale(sc, sc); ctx.translate(-pcx, -pcy);
      panel(ctx, p, k, st, act);
      ctx.save(); rr(ctx, p.x + 1, p.y + 1, p.w - 2, p.h - 2, 18 * p.ps); ctx.clip();
      const local = clamp(st, 0, 1.0001);
      if (k === 0) readPanel(ctx, p, local, st);
      else if (k === 1) measurePanel(ctx, p, local, st);
      else if (k === 2) comparePanel(ctx, p, local, st);
      else explainPanel(ctx, p, local, st, 1 - seg(d, 0, 0.12));
      ctx.restore();
      ctx.restore();
    });
  }
  function panel(ctx, p, k, st, act) {
    const ps = p.ps, R = rtl();
    if (act > 0.01) bloom(ctx, C.cyan, p.x + p.w / 2, p.y + p.h / 2, Math.max(p.w, p.h) * 0.75, 0.13 * act);
    rr(ctx, p.x, p.y, p.w, p.h, 18 * ps);
    const g = ctx.createLinearGradient(p.x, p.y, p.x, p.y + p.h);
    g.addColorStop(0, "rgba(30,20,64,.82)"); g.addColorStop(1, "rgba(9,6,24,.86)");
    ctx.fillStyle = g; ctx.fill();
    ctx.lineWidth = 1 + act * 0.8; ctx.strokeStyle = act > 0.02 ? rgba(C.cyan, 0.3 + 0.55 * act) : st >= 1 ? rgba(C.violet, 0.4) : rgba(C.violet, 0.2); ctx.stroke();
    // a hairline of light along the top edge (glass)
    const hl = ctx.createLinearGradient(p.x, 0, p.x + p.w, 0);
    hl.addColorStop(0, "rgba(255,255,255,0)"); hl.addColorStop(0.5, `rgba(255,255,255,${0.16 + 0.2 * act})`); hl.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = hl; ctx.fillRect(p.x + 18 * ps, p.y + 0.5, p.w - 36 * ps, 1);
    const hy = p.y + 26 * ps, pad = 18 * ps, sx = R ? p.x + p.w - pad : p.x + pad, dir = R ? -1 : 1;
    const chip = String(k + 1).padStart(2, "0"), cw = tw(ctx, chip, 11 * ps, 700, true) + 12 * ps;
    rr(ctx, R ? sx - cw : sx, hy - 10 * ps, cw, 20 * ps, 5 * ps); ctx.fillStyle = st >= 0 ? rgba(C.cyan, 0.95) : rgba(C.violet, 0.25); ctx.fill();
    txt(ctx, chip, sx + dir * cw / 2, hy + 0.5, 11 * ps, st >= 0 ? "#08040f" : "#d8c8ff", { mono: true, w: 700, align: "center" });
    txt(ctx, stepName(k), sx + dir * (cw + 10 * ps), hy, 15.5 * ps, "#ffffff", { w: 650, align: R ? "right" : "left" });
    // status at the far end
    const ex = R ? p.x + pad + 8 * ps : p.x + p.w - pad - 8 * ps;
    if (st >= 1) { ctx.fillStyle = "rgba(10,40,24,.9)"; ctx.beginPath(); ctx.arc(ex, hy, 9 * ps, 0, 6.283); ctx.fill(); ctx.strokeStyle = rgba(C.green, 0.9); ctx.lineWidth = 1.2; ctx.stroke(); icon(ctx, "check", ex, hy, 13 * ps, rgba(C.green, 1), 2.6); }
    else if (st > 0) { bloom(ctx, C.cyan, ex, hy, 22 * ps, 0.9); ctx.fillStyle = rgba(C.cyan, 1); ctx.beginPath(); ctx.arc(ex, hy, 4 * ps, 0, 6.283); ctx.fill(); ctx.strokeStyle = rgba(C.cyan, 0.5); ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(ex, hy, 4 * ps + 6 * ps * frac(st * 6), 0, 6.283); ctx.stroke(); }
    else { ctx.strokeStyle = rgba(C.muted, 0.45); ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(ex, hy, 5 * ps, 0, 6.283); ctx.stroke(); }
    ctx.fillStyle = rgba(C.violet, 0.12); ctx.fillRect(p.x + pad, p.y + 46 * ps, p.w - pad * 2, 1);
  }
  function readPanel(ctx, p, q, st) {
    const ps = p.ps, pad = 18 * ps, fs = 12.2 * ps, lh = 19.5 * ps, cw = tw(ctx, "0", fs, 400, true);
    const top = p.y + 58 * ps, bottom = p.y + p.h - 40 * ps, rows = Math.max(3, Math.floor((bottom - top) / lh));
    const n = st < 0 ? 0 : st >= 1 ? 128 : 128 * q, head = Math.min(15, n / 8);
    const scroll = clamp(head - (rows - 2.6), 0, 16 - rows);
    const totalW = cw * 39, x0 = p.x + Math.max(pad, (p.w - totalW) / 2);
    ctx.save(); ctx.beginPath(); ctx.rect(p.x, top - 2, p.w, rows * lh + 2); ctx.clip();
    for (let row = Math.floor(scroll); row < Math.min(16, Math.floor(scroll) + rows + 1); row++) {
      const y = top + (row - scroll) * lh + lh / 2;
      txt(ctx, (row * 8).toString(16).toUpperCase().padStart(4, "0"), x0, y, fs, rgba(C.muted, 0.6), { mono: true });
      for (let c = 0; c < 8; c++) {
        const i = row * 8 + c, hx = x0 + cw * (6 + c * 3), ax = x0 + cw * (31 + c), done = i < n;
        const isMZ = i < 2, isStr = i >= STR0 && i < STR1;
        if (done && (isMZ || isStr)) { ctx.fillStyle = isMZ ? rgba(C.rose, 0.26) : rgba(C.cyan, 0.13); ctx.fillRect(hx - cw * 0.3, y - lh * 0.42, cw * 2.6, lh * 0.84); }
        txt(ctx, done ? HEX[i] : "··", hx, y, fs, done ? (isMZ ? "#ff9fbd" : isStr ? "#bff8ff" : BYTES[i] ? "#ece6ff" : rgba(C.muted, 0.75)) : rgba(C.muted, 0.25), { mono: true, w: isMZ ? 700 : 400 });
        if (done) txt(ctx, ASC[i], ax, y, fs, isMZ ? "#ff9fbd" : isStr ? rgba(C.cyan, 1) : rgba(C.muted, 0.55), { mono: true });
      }
    }
    // the read head
    if (st > 0 && st < 1) {
      const i = Math.floor(n), row = Math.floor(i / 8), c = i % 8, y = top + (row - scroll) * lh + lh / 2, hx = x0 + cw * (6 + c * 3);
      bloom(ctx, C.cyan, hx + cw, y, 26 * ps, 0.8); ctx.fillStyle = rgba(C.cyan, 0.9); ctx.fillRect(hx - cw * 0.2, y - lh * 0.4, cw * 2.4, lh * 0.8);
    }
    ctx.restore();
    // what the first two bytes say
    const mz = seg(n, 2, 6);
    if (mz > 0) {
      const label = tr("syMZ", "MZ: the mark of a program"), f = 11.5 * ps, w = tw(ctx, label, f, 600) + 18 * ps, h = 22 * ps, R = rtl();
      const x = R ? p.x + pad : p.x + p.w - pad - w, y = p.y + 56 * ps;
      ctx.save(); ctx.globalAlpha *= mz; rr(ctx, x, y, w, h, h / 2); ctx.fillStyle = "rgba(70,12,40,.92)"; ctx.fill(); ctx.strokeStyle = rgba(C.rose, 0.8); ctx.lineWidth = 1; ctx.stroke();
      txt(ctx, label, x + w / 2, y + h / 2 + 0.5, f, "#ffd1dc", { align: "center", w: 600 }); ctx.restore();
    }
    // footer: what has been read, and the promise
    const fy = p.y + p.h - 20 * ps, bw = p.w - pad * 2;
    ctx.fillStyle = rgba(C.violet, 0.15); rr(ctx, p.x + pad, fy - 12 * ps, bw, 3 * ps, 1.5 * ps); ctx.fill();
    const fill = ctx.createLinearGradient(p.x + pad, 0, p.x + pad + bw, 0); fill.addColorStop(0, rgba(C.cyan, 1)); fill.addColorStop(1, rgba(C.mag, 1));
    ctx.fillStyle = fill; const fw = bw * (n / 128); rr(ctx, rtl() ? p.x + pad + bw - fw : p.x + pad, fy - 12 * ps, fw, 3 * ps, 1.5 * ps); ctx.fill();
    txt(ctx, `${Math.round(n)} / 128 KB`, rtl() ? p.x + p.w - pad : p.x + pad, fy + 2 * ps, 11 * ps, rgba(C.muted, 1), { mono: true, align: rtl() ? "right" : "left" });
    txt(ctx, tr("syNeverRun", "read only · never run"), rtl() ? p.x + pad : p.x + p.w - pad, fy + 2 * ps, 11 * ps, rgba(C.green, 0.9), { align: rtl() ? "left" : "right", w: 600 });
  }
  function measurePanel(ctx, p, q, st) {
    const ps = p.ps, pad = 18 * ps, R = rtl();
    const cx0 = p.x + pad + 22 * ps, cx1 = p.x + p.w - pad, cy0 = p.y + 76 * ps, cy1 = p.y + p.h * 0.66;
    const prog = st < 0 ? 0 : st >= 1 ? 1 : q;
    txt(ctx, tr("syEntropy", "Randomness (entropy)"), R ? p.x + p.w - pad : p.x + pad, p.y + 61 * ps, 11.5 * ps, rgba(C.muted, 1), { align: R ? "right" : "left" });
    const Y = (v) => lerp(cy1, cy0, v / 8), X = (i) => lerp(cx0, cx1, i / 47);
    ctx.lineWidth = 1;
    [0, 4, 8].forEach((v) => { ctx.strokeStyle = rgba(C.violet, 0.1); ctx.beginPath(); ctx.moveTo(cx0, Y(v)); ctx.lineTo(cx1, Y(v)); ctx.stroke(); txt(ctx, String(v), cx0 - 8 * ps, Y(v), 10 * ps, rgba(C.muted, 0.7), { mono: true, align: "right" }); });
    ctx.strokeStyle = rgba(C.rose, 0.55); ctx.setLineDash([4, 4]); ctx.beginPath(); ctx.moveTo(cx0, Y(7.2)); ctx.lineTo(cx1, Y(7.2)); ctx.stroke(); ctx.setLineDash([]);
    const upto = prog * 47;
    // the packed stretch
    const band = clamp(upto, 28, 41) - 28;
    if (upto > 28) {
      ctx.fillStyle = rgba(C.mag, 0.1); ctx.fillRect(X(28), cy0 - 4 * ps, X(28 + band) - X(28), cy1 - cy0 + 4 * ps);
      bloom(ctx, C.mag, X(28 + band / 2), Y(7.8), (X(28 + band) - X(28)) * 0.8, 0.22);
    }
    if (upto > 0.5) {
      const g = ctx.createLinearGradient(0, cy0, 0, cy1); g.addColorStop(0, rgba(C.mag, 0.45)); g.addColorStop(0.45, rgba(C.cyan, 0.22)); g.addColorStop(1, rgba(C.cyan, 0));
      ctx.beginPath(); ctx.moveTo(X(0), cy1);
      const last = Math.floor(upto);
      for (let i = 0; i <= last; i++) ctx.lineTo(X(i), Y(ENT[i]));
      const fe = upto - last, ev = last < 47 ? lerp(ENT[last], ENT[last + 1], fe) : ENT[47];
      ctx.lineTo(X(upto), Y(ev)); ctx.lineTo(X(upto), cy1); ctx.closePath(); ctx.fillStyle = g; ctx.fill();
      ctx.beginPath(); for (let i = 0; i <= last; i++) { if (i) ctx.lineTo(X(i), Y(ENT[i])); else ctx.moveTo(X(i), Y(ENT[i])); } ctx.lineTo(X(upto), Y(ev));
      ctx.strokeStyle = "#f2ecff"; ctx.lineWidth = 1.6 * ps; ctx.stroke();
      if (prog < 1) { bloom(ctx, ev > 7.2 ? C.mag : C.cyan, X(upto), Y(ev), 24 * ps, 0.9); ctx.fillStyle = "#fff"; ctx.beginPath(); ctx.arc(X(upto), Y(ev), 3 * ps, 0, 6.283); ctx.fill(); }
    }
    const lab = seg(upto, 33, 37);
    if (lab > 0) {
      const s = `7.9 / 8 · ${tr("syPacked", "scrambled: packed or encrypted")}`, f = 11 * ps, w = tw(ctx, s, f, 600) + 16 * ps, h = 21 * ps;
      const x = clamp(X(34.5) - w / 2, p.x + pad, p.x + p.w - pad - w), y = cy0 - 30 * ps;
      ctx.save(); ctx.globalAlpha *= lab; rr(ctx, x, y, w, h, h / 2); ctx.fillStyle = "rgba(60,10,52,.92)"; ctx.fill(); ctx.strokeStyle = rgba(C.mag, 0.8); ctx.lineWidth = 1; ctx.stroke();
      txt(ctx, s, x + w / 2, y + h / 2 + 0.5, f, "#ffd6f5", { align: "center", w: 600 }); ctx.restore();
    }
    // the file's sections, measured left to right
    const by = p.y + p.h * 0.77, bh = 16 * ps; let x = cx0; const tot = cx1 - cx0;
    SECTS.forEach(([name, n, col]) => {
      const w = (n / 48) * tot - 3, shown = clamp((upto - (x - cx0) / tot * 47) / (n * 0.9));
      if (shown > 0) {
        rr(ctx, x, by, w * shown, bh, 4 * ps); ctx.fillStyle = rgba(col, name === "UPX1" ? 0.5 : 0.28); ctx.fill();
        if (shown >= 1) { ctx.strokeStyle = rgba(col, 0.8); ctx.lineWidth = 1; ctx.stroke(); }
        if (name === "UPX1" && shown >= 1) bloom(ctx, C.mag, x + w / 2, by + bh / 2, w * 0.6, 0.35);
        ctx.save(); ctx.globalAlpha *= shown; txt(ctx, name, x + w / 2, by + bh + 13 * ps, 10.5 * ps, name === "UPX1" ? "#ffc0f0" : rgba(C.muted, 0.9), { mono: true, align: "center" }); ctx.restore();
      }
      x += w + 3;
    });
  }
  function comparePanel(ctx, p, q, st) {
    const ps = p.ps, pad = 18 * ps, R = rtl();
    const top = p.y + 62 * ps, bottom = p.y + p.h - 44 * ps, rh = (bottom - top) / RULES.length;
    const prog = st < 0 ? 0 : st >= 1 ? 1 : q;
    const scanY = top + prog * (bottom - top);
    RULES.forEach((ru, i) => {
      const y = top + rh * i + rh / 2, ev = seg(prog * RULES.length, i + 0.55, i + 0.85);
      const L = (v) => (R ? p.x + p.w - v : p.x + v);
      // row
      rr(ctx, p.x + pad, y - rh * 0.4, p.w - pad * 2, rh * 0.8, 10 * ps);
      ctx.fillStyle = ev > 0.5 && ru.m ? rgba(C.rose, 0.08) : "rgba(255,255,255,.025)"; ctx.fill();
      ctx.strokeStyle = ev > 0.5 && ru.m ? rgba(C.rose, 0.35) : rgba(C.violet, 0.12); ctx.lineWidth = 1; ctx.stroke();
      const tf = 9.5 * ps, tgw = tw(ctx, ru.tag, tf, 700, true) + 10 * ps;
      rr(ctx, R ? L(pad + 10 * ps) - tgw : L(pad + 10 * ps), y - rh * 0.2 - 9 * ps, tgw, 16 * ps, 4 * ps); ctx.fillStyle = rgba(C.violet, 0.16); ctx.fill();
      txt(ctx, ru.tag, R ? L(pad + 10 * ps) - tgw / 2 : L(pad + 10 * ps) + tgw / 2, y - rh * 0.2 - 1 * ps, tf, "#d8c8ff", { mono: true, w: 700, align: "center" });
      const nameW = p.w - pad * 2 - 110 * ps;
      ctx.save(); ctx.beginPath(); ctx.rect(R ? L(pad + 10 * ps + nameW) : L(pad + 10 * ps), y - rh * 0.4, nameW, rh * 0.8); ctx.clip();
      txt(ctx, tr(ru.k, ru.fb), L(pad + 10 * ps), y + rh * 0.16, 13 * ps, "#f1ecff", { w: 550, align: R ? "right" : "left" });
      ctx.restore();
      // result
      const rx = L(p.w - pad - 12 * ps);
      if (ev > 0) {
        ctx.save(); ctx.globalAlpha *= ev;
        if (ru.m) {
          const s = tr("syMatch", "Match"), f = 11 * ps, w = tw(ctx, s, f, 700) + 14 * ps;
          rr(ctx, R ? rx : rx - w, y - rh * 0.2 - 10 * ps, w, 19 * ps, 9.5 * ps); ctx.fillStyle = rgba(C.rose, 0.9); ctx.fill();
          txt(ctx, s, R ? rx + w / 2 : rx - w / 2, y - rh * 0.2, f, "#fff", { align: "center", w: 700 });
          // weight of the clue
          const bw = 70 * ps, bx = R ? rx : rx - bw, byy = y + rh * 0.16;
          ctx.fillStyle = rgba(C.text, 0.1); rr(ctx, bx, byy - 2.5 * ps, bw, 5 * ps, 2.5 * ps); ctx.fill();
          const g = ctx.createLinearGradient(bx, 0, bx + bw, 0); g.addColorStop(0, rgba(C.amber, 1)); g.addColorStop(1, rgba(C.rose, 1));
          ctx.fillStyle = g; const fw = bw * ru.w * ease(ev); rr(ctx, R ? bx + bw - fw : bx, byy - 2.5 * ps, fw, 5 * ps, 2.5 * ps); ctx.fill();
          bloom(ctx, C.rose, R ? rx + w / 2 : rx - w / 2, y - rh * 0.2, 30 * ps, 0.35 * bump(ev));
        } else txt(ctx, tr("syNoMatch", "No match"), rx, y, 11.5 * ps, rgba(C.muted, 0.95), { align: R ? "left" : "right", w: 600 });
        ctx.restore();
      } else { ctx.fillStyle = rgba(C.muted, 0.3); ctx.beginPath(); ctx.arc(R ? rx + 4 * ps : rx - 4 * ps, y, 3 * ps, 0, 6.283); ctx.fill(); }
    });
    if (prog > 0 && prog < 1) {
      const g = ctx.createLinearGradient(p.x, 0, p.x + p.w, 0); g.addColorStop(0, rgba(C.cyan, 0)); g.addColorStop(0.5, rgba(C.cyan, 0.95)); g.addColorStop(1, rgba(C.cyan, 0));
      ctx.fillStyle = g; ctx.fillRect(p.x + pad, scanY - 1, p.w - pad * 2, 2); bloom(ctx, C.cyan, p.x + p.w / 2, scanY, p.w * 0.35, 0.22);
    }
    txt(ctx, "SHA-256 d8957b11…167c97c", rtl() ? p.x + p.w - pad : p.x + pad, p.y + p.h - 22 * ps, 10.5 * ps, rgba(C.muted, 0.85), { mono: true, align: rtl() ? "right" : "left" });
  }
  function explainPanel(ctx, p, q, st, gaugeA) {
    const ps = p.ps, pad = 18 * ps, G = gaugeGeo(p), prog = st < 0 ? 0 : st >= 1 ? 1 : q;
    const v = 55 * ease(seg(prog, 0.02, 0.42));
    const a0 = Math.PI, a1 = Math.PI * 2, lw = 10 * ps;
    ctx.save(); ctx.globalAlpha *= gaugeA;
    ctx.lineCap = "round"; ctx.lineWidth = lw; ctx.strokeStyle = "rgba(255,255,255,.07)"; ctx.beginPath(); ctx.arc(G.x, G.y, G.R, a0, a1); ctx.stroke();
    // ranges: calm, worth a look, dangerous
    [[0, 0.25, C.green], [0.25, 0.7, C.amber], [0.7, 1, C.rose]].forEach(([s0, s1, c]) => { ctx.strokeStyle = rgba(c, 0.18); ctx.lineWidth = 2 * ps; ctx.beginPath(); ctx.arc(G.x, G.y, G.R + lw, a0 + s0 * Math.PI + 0.02, a0 + s1 * Math.PI - 0.02); ctx.stroke(); });
    if (v > 0.2) {
      const g = ctx.createLinearGradient(G.x - G.R, 0, G.x + G.R, 0); g.addColorStop(0, rgba(C.green, 1)); g.addColorStop(0.5, rgba(C.amber, 1)); g.addColorStop(1, rgba(C.rose, 1));
      ctx.strokeStyle = g; ctx.lineWidth = lw; ctx.beginPath(); ctx.arc(G.x, G.y, G.R, a0, a0 + (v / 100) * Math.PI); ctx.stroke();
      const na = a0 + (v / 100) * Math.PI, nx = G.x + Math.cos(na) * G.R, ny = G.y + Math.sin(na) * G.R;
      bloom(ctx, C.amber, nx, ny, 34 * ps, 0.8); ctx.fillStyle = "#fff"; ctx.beginPath(); ctx.arc(nx, ny, 4.5 * ps, 0, 6.283); ctx.fill();
    }
    ctx.lineCap = "butt";
    txt(ctx, st < 0 ? "--" : String(Math.round(v)), G.x, G.y - G.R * 0.28, 40 * ps, "#ffffff", { mono: true, w: 700, align: "center" });
    txt(ctx, "/100", G.x, G.y + 4 * ps, 11 * ps, rgba(C.muted, 1), { mono: true, align: "center" });
    ctx.restore();
    const vl = seg(prog, 0.3, 0.42);
    if (vl > 0) { ctx.save(); ctx.globalAlpha *= vl; txt(ctx, tr("syRes", "Suspicious"), G.x, G.y + 26 * ps, 17 * ps, "#ffc768", { align: "center", w: 700 }); ctx.restore(); }
    // the plain-language verdict, written out
    const s = tr("syResWhy", "A program pretending to be a document. A warning sign, not proof."), f = 13.5 * ps, R = rtl();
    const lines = wrap(ctx, s, f, 500, p.w - pad * 2.4), total = lines.reduce((n, l) => n + l.length, 0);
    let left = Math.floor(total * seg(prog, 0.42, 0.95));
    const y0 = G.y + 52 * ps, lh = f * 1.5, x = R ? p.x + p.w - pad * 1.2 : p.x + pad * 1.2;
    let cx = x, cy = y0;
    lines.forEach((l, i) => {
      if (left <= 0) return;
      const part = l.slice(0, left); left -= l.length;
      const y = y0 + i * lh; txt(ctx, part, x, y, f, "#f4efff", { align: R ? "right" : "left", w: 500 });
      cx = x + (R ? -1 : 1) * tw(ctx, part, f, 500); cy = y;
    });
    if (prog > 0.42 && prog < 1) { ctx.fillStyle = rgba(C.cyan, 1); ctx.fillRect(cx + (R ? -4 : 2), cy - f * 0.6, 2, f * 1.2); }
    txt(ctx, "invoice.pdf.exe", R ? p.x + p.w - pad : p.x + pad, p.y + p.h - 22 * ps, 10.5 * ps, rgba(C.amber, 0.85), { mono: true, align: R ? "right" : "left" });
  }

  /* ---------------- 4 · beyond files, 5 · one ecosystem ---------------- */
  function eco(V, P) {
    const ctx = V.ctx, a = clamp((P - 2.7) / 0.3), t4 = clamp((P - 3) / 0.7), t5 = clamp((P - 4) / 0.7), d = clamp((P - 4.7) / 0.3);
    const r = V.reg[P < 3.85 ? 3 : 4], s = r.s;
    const coreR = 74 * s, R = 280 * s;
    const ex = s3geo(V)[3], G = gaugeGeo(ex);
    const fly = expo(a), out = inOut(seg(d, 0.3, 1)), mo = inOut(seg(d, 0.35, 1));
    const emR = V.emb.size * 0.42;
    const cx = lerp(lerp(G.x, r.cx, fly), V.emb.x, out), cy = lerp(lerp(G.y, r.cy, fly), V.emb.y, out);
    const rad = lerp(lerp(G.R, coreR, ease(a)), emR, out);
    const rot = (rtl() ? -1 : 1) * 0.62 * inOut(seg(P, 3.75, 4.6));
    const conv = 1 - inOut(seg(d, 0, 0.55)), dA = 1 - seg(d, 0.3, 0.6);
    // where each domain is, and how far it has come out
    const nodes = DOMS.map((D, i) => {
      const grp = i === 0 || i === 1 || i === 2 || i === 3 || i === 4 ? 0 : 1, idx = grp ? i - 5 : i;
      const st0 = grp ? 0.34 + idx * 0.045 : -0.02 + idx * 0.045;
      const ap = back(seg(t4, st0, st0 + 0.17)), ang = -Math.PI / 2 + (i / 10) * Math.PI * 2 + rot;
      const rr0 = R * clamp(ap, 0, 1.15) * conv;
      return { D, i, ap: clamp(ap), ang, x: cx + Math.cos(ang) * rr0, y: cy + Math.sin(ang) * rr0, ca: Math.cos(ang), sa: Math.sin(ang) };
    });
    const ns = 50 * s;
    // shockwave as the core lands
    const sw = seg(P, 2.93, 3.3);
    if (sw > 0 && sw < 1) { ctx.strokeStyle = rgba(C.cyan, (1 - sw) * 0.6); ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(cx, cy, coreR * (1 + sw * 4.4), 0, 6.283); ctx.stroke(); bloom(ctx, C.cyan, cx, cy, coreR * (1 + sw * 4), 0.15 * (1 - sw)); }
    // orbit
    const orbA = ease(seg(t4, 0, 0.3)) * dA;
    if (orbA > 0.01) { ctx.save(); ctx.globalAlpha = orbA; ctx.setLineDash([2, 7]); ctx.strokeStyle = rgba(C.violet, 0.25); ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(cx, cy, R * conv, 0, 6.283); ctx.stroke(); ctx.setLineDash([]); ctx.restore(); }
    // spokes
    const spokeDim = lerp(1, 0.35, seg(t5, 0, 0.3)) * dA;
    nodes.forEach((n) => {
      if (n.ap <= 0.01) return;
      const col = n.D.st === "live" ? C.cyan : n.D.st === "part" ? C.violet : C.muted, al = (n.D.st === "dev" ? 0.38 : 0.6) * spokeDim;
      ctx.strokeStyle = rgba(col, al); ctx.lineWidth = n.D.st === "dev" ? 1 : 1.5;
      if (n.D.st === "dev") ctx.setLineDash([4, 5]);
      ctx.beginPath(); ctx.moveTo(cx + n.ca * rad, cy + n.sa * rad); ctx.lineTo(n.x - n.ca * ns * 0.55, n.y - n.sa * ns * 0.55); ctx.stroke(); ctx.setLineDash([]);
    });
    // threats arriving from outside (scene 4)
    const cometA = seg(P, 3.02, 3.15) * (1 - seg(P, 3.85, 4.15));
    if (cometA > 0.01) {
      nodes.forEach((n, k) => {
        if (n.ap < 0.6) return;
        const ph = frac(P * 1.5 + k * 0.137 + 0.4), off = (k % 2 ? 0.32 : -0.32);
        const fa = n.ang + off, far = R + 280 * s;
        const sx = cx + Math.cos(fa) * far, sy = cy + Math.sin(fa) * far, tx = n.x + n.ca * ns * 0.7, ty = n.y + n.sa * ns * 0.7;
        const e = ease(ph), hx = lerp(sx, tx, e), hy = lerp(sy, ty, e), tl = clamp(e - 0.18);
        const qx = lerp(sx, tx, tl), qy = lerp(sy, ty, tl);
        const g = ctx.createLinearGradient(qx, qy, hx, hy); g.addColorStop(0, rgba(C.mag, 0)); g.addColorStop(1, rgba(C.mag, 0.85 * cometA * (1 - seg(ph, 0.86, 1))));
        ctx.strokeStyle = g; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(qx, qy); ctx.lineTo(hx, hy); ctx.stroke();
        bloom(ctx, C.mag, hx, hy, 18 * s, 0.7 * cometA * (1 - seg(ph, 0.86, 1)));
        if (ph > 0.84) { const f = seg(ph, 0.84, 1); ctx.strokeStyle = rgba(C.mag, (1 - f) * 0.7 * cometA); ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(n.x, n.y, ns * (0.7 + f * 0.6), 0, 6.283); ctx.stroke(); }
      });
    }
    // relations between the areas (scene 5)
    const relA = dA;
    if (t5 > 0 && relA > 0.01) {
      ctx.save(); ctx.globalAlpha = relA;
      RELS.forEach(([i, j], k) => {
        const p = ease(seg(t5, 0.02 + k * 0.022, 0.24 + k * 0.022)); if (p <= 0) return;
        const A = nodes[i], B = nodes[j], mx = lerp((A.x + B.x) / 2, cx, 0.42), my = lerp((A.y + B.y) / 2, cy, 0.42);
        ctx.strokeStyle = rgba(C.violet, 0.42); ctx.lineWidth = 1.3; ctx.beginPath(); qPart(ctx, A.x, A.y, mx, my, B.x, B.y, p); ctx.stroke();
      });
      // one chain: an email, the link inside it, the file behind the link, then to the core; then a secret in code
      const chain = [[4, 2], [2, 0]], pc = seg(t5, 0.35, 0.58) * 3;
      const lit = new Set();
      if (pc > 0 && pc < 3.2) {
        const trail = [];
        for (let k = 0; k <= 10; k++) {
          const u = pc - k * 0.05; if (u < 0) break;
          let x, y;
          if (u < 2) { const [i, j] = chain[Math.floor(u)], A = nodes[i], B = nodes[j], mx = lerp((A.x + B.x) / 2, cx, 0.42), my = lerp((A.y + B.y) / 2, cy, 0.42); [x, y] = qPt(A.x, A.y, mx, my, B.x, B.y, frac(u)); }
          else { const A = nodes[0]; x = lerp(A.x, cx, clamp(u - 2)); y = lerp(A.y, cy, clamp(u - 2)); }
          trail.push([x, y]);
        }
        trail.forEach(([x, y], k) => { if (!k) bloom(ctx, C.cyan, x, y, 36 * s, 0.9); ctx.fillStyle = rgba(k ? C.cyan : "255,255,255", 1 - k / 11); ctx.beginPath(); ctx.arc(x, y, (k ? 2.6 : 3.6) * Math.max(0.7, s), 0, 6.283); ctx.fill(); });
        lit.add(4); if (pc > 0.9) lit.add(2); if (pc > 1.9) lit.add(0);
      }
      const pk = seg(t5, 0.52, 0.66);
      if (pk > 0 && pk < 1) { const A = nodes[8], x = lerp(A.x, cx, ease(pk)), y = lerp(A.y, cy, ease(pk)); bloom(ctx, C.amber, x, y, 30 * s, 0.9); ctx.fillStyle = "#fff"; ctx.beginPath(); ctx.arc(x, y, 3, 0, 6.283); ctx.fill(); lit.add(8); }
      V._lit = lit;
      // many → one: a ring closes from the orbit onto the core, and every spoke carries its answer in
      const cv = seg(t5, 0.66, 0.96);
      if (cv > 0 && cv < 1) {
        const rc = lerp(R * 1.1, rad * 1.25, inOut(cv));
        ctx.strokeStyle = rgba(C.cyan, 0.7 * bump(cv)); ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(cx, cy, rc, 0, 6.283); ctx.stroke();
        bloom(ctx, C.cyan, cx, cy, rc * 1.1, 0.12 * bump(cv));
        nodes.forEach((n, k) => { const f = frac(cv * 2 + k * 0.1), x = lerp(n.x, cx, ease(f)), y = lerp(n.y, cy, ease(f)); ctx.fillStyle = rgba(C.cyan, 0.9 * (1 - f)); ctx.beginPath(); ctx.arc(x, y, 2.2, 0, 6.283); ctx.fill(); });
      }
      ctx.restore();
    } else V._lit = null;
    // the domains
    const lf = fz(r, 12.5, 10.5), legend = seg(t4, 0.68, 0.78) * (1 - seg(t5, 0, 0.2));
    nodes.forEach((n) => {
      if (n.ap <= 0.01) return;
      const al = n.ap * dA; if (al <= 0.01) return;
      const live = n.D.st === "live", part = n.D.st === "part", col = live ? C.cyan : part ? C.violet : C.muted;
      const isLit = V._lit && V._lit.has(n.i);
      const emph = legend * (live ? 1 : -0.35);
      ctx.save(); ctx.globalAlpha = al * clamp(1 + Math.min(0, emph));
      const sz = ns * (0.7 + 0.3 * n.ap) * (isLit ? 1.12 : 1);
      if (live || isLit) bloom(ctx, isLit ? C.cyan : col, n.x, n.y, sz * (1.6 + Math.max(0, emph)), isLit ? 0.6 : 0.22 + 0.25 * Math.max(0, emph));
      rr(ctx, n.x - sz / 2, n.y - sz / 2, sz, sz, sz * 0.28); ctx.fillStyle = "rgba(12,8,30,.95)"; ctx.fill();
      ctx.lineWidth = isLit ? 2 : 1.4; ctx.strokeStyle = rgba(isLit ? C.cyan : col, live || part || isLit ? 0.85 : 0.55);
      if (n.D.st === "dev" && !isLit) { ctx.setLineDash([4, 3]); ctx.lineDashOffset = -P * 30; }
      ctx.stroke(); ctx.setLineDash([]);
      icon(ctx, n.D.ic, n.x, n.y, sz * 0.5, isLit ? "#ffffff" : live ? rgba(C.cyan, 1) : part ? "#e2cbff" : "#b9b1d6", 1.7);
      const label = tr(n.D.k, n.D.fb), w = tw(ctx, label, lf, 500);
      const lx = n.x + n.ca * (sz * 0.62 + 10 * s) + n.ca * w / 2, ly = n.y + n.sa * (sz * 0.62 + lf * 0.9);
      txt(ctx, label, lx, ly, lf, isLit ? "#ffffff" : live || part ? "#e6defb" : "#b9b1d6", { align: "center", w: 500 });
      ctx.restore();
    });
    // the core: the verdict that became the centre; it later folds into the shield
    const ca = ease(seg(a, 0, 0.3));
    if (ca > 0.01) {
      const glow = 0.35 + 0.35 * seg(t5, 0.7, 1) + 0.25 * mo;
      bloom(ctx, C.cyan, cx, cy, rad * 3.2, glow * ca);
      morphPath(ctx, cx, cy, rad, mo);
      const g = ctx.createRadialGradient(cx, cy - rad * 0.4, rad * 0.05, cx, cy, rad * 1.1);
      g.addColorStop(0, rgba(C.cyan, 0.42)); g.addColorStop(0.55, "rgba(22,14,56,.92)"); g.addColorStop(1, "rgba(8,5,22,.96)");
      ctx.globalAlpha = ca * clamp(a * 2); ctx.fillStyle = g; ctx.fill(); ctx.globalAlpha = 1;
      // the ring: during the hand-off it is still the 55/100 arc, then it closes
      const arcF = lerp(0.55, 1, ease(seg(a, 0.2, 0.9)));
      ctx.lineWidth = lerp(10 * ex.ps, 1.8, ease(a)); ctx.strokeStyle = a < 0.9 ? rgba(C.amber, 1 - seg(a, 0.5, 0.9)) : rgba(C.cyan, 0.95);
      if (a < 0.9) { ctx.lineCap = "round"; ctx.beginPath(); ctx.arc(cx, cy, rad, Math.PI, Math.PI + arcF * Math.PI * 2); ctx.stroke(); ctx.lineCap = "butt"; }
      ctx.strokeStyle = rgba(C.cyan, 0.95 * seg(a, 0.5, 1)); ctx.lineWidth = 1.8; morphPath(ctx, cx, cy, rad, mo); ctx.stroke();
      ctx.strokeStyle = rgba(C.cyan, 0.28 * seg(a, 0.5, 1) * (1 - mo)); ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(cx, cy, rad * 1.18, 0, 6.283); ctx.stroke();
      const ta = seg(a, 0.6, 1) * (1 - seg(d, 0.2, 0.5));
      if (ta > 0.01) { ctx.globalAlpha = ta; txt(ctx, "CyberScan", cx, cy, fz(r, 16, 11), "#ffffff", { w: 700, align: "center", ltr: true }); ctx.globalAlpha = 1; }
    }
  }

  /* ---------------- 6 · the shield ---------------- */
  function scene6(V, P) {
    const ctx = V.ctx, a = clamp((P - 4.7) / 0.3), t = clamp((P - 5) / 0.7);
    const E = V.emb, rad = E.size * 0.42, x = E.x, y = E.y;
    // light around the mark: rays and rings that open as the scene arrives
    const open = ease(seg(a, 0.3, 1));
    if (open > 0.01) {
      const rot = P * 0.18, L = Math.max(V.W, V.H) * 0.55 * open;
      ctx.lineWidth = 1;
      for (let k = 0; k < 48; k++) {
        const an = rot + (k / 48) * Math.PI * 2, r0 = rad * 1.5, len = L * (0.35 + 0.65 * Math.abs(Math.sin(k * 2.7)));
        const g = ctx.createLinearGradient(x + Math.cos(an) * r0, y + Math.sin(an) * r0, x + Math.cos(an) * (r0 + len), y + Math.sin(an) * (r0 + len));
        g.addColorStop(0, rgba(k % 3 ? C.violet : C.cyan, 0.16 * open)); g.addColorStop(1, rgba(C.violet, 0));
        ctx.strokeStyle = g; ctx.beginPath(); ctx.moveTo(x + Math.cos(an) * r0, y + Math.sin(an) * r0); ctx.lineTo(x + Math.cos(an) * (r0 + len), y + Math.sin(an) * (r0 + len)); ctx.stroke();
      }
      [1.55, 2.3, 3.4, 5].forEach((m, k) => {
        const rr0 = rad * m * lerp(0.7, 1, open);
        ctx.strokeStyle = rgba(k % 2 ? C.violet : C.cyan, (0.22 - k * 0.04) * open); ctx.lineWidth = 1;
        if (k === 1) ctx.setLineDash([2, 6]);
        ctx.beginPath(); ctx.arc(x, y, rr0, 0, 6.283); ctx.stroke(); ctx.setLineDash([]);
      });
      const pulse = frac(P * 1.6);
      ctx.strokeStyle = rgba(C.cyan, 0.35 * (1 - pulse) * open); ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, y, rad * (1.2 + pulse * 2.4), 0, 6.283); ctx.stroke();
    }
    if (P >= 5 || V.still) {
      bloom(ctx, C.cyan, x, y, rad * 3.6, 0.75);
      morphPath(ctx, x, y, rad, 1);
      const g = ctx.createRadialGradient(x, y - rad * 0.4, rad * 0.05, x, y, rad * 1.1);
      g.addColorStop(0, rgba(C.cyan, 0.42)); g.addColorStop(0.55, "rgba(22,14,56,.92)"); g.addColorStop(1, "rgba(8,5,22,.96)");
      ctx.fillStyle = g; ctx.fill(); ctx.strokeStyle = rgba(C.cyan, 0.95); ctx.lineWidth = 1.8; ctx.stroke();
      ctx.save(); ctx.translate(x, y); ctx.scale(0.8, 0.8); morphPath(ctx, 0, 0, rad, 1); ctx.restore();
      ctx.strokeStyle = rgba(C.violet, 0.35); ctx.lineWidth = 1; ctx.stroke();
      // the check draws itself
      const ck = V.still ? 1 : ease(seg(P, 4.96, 5.22));
      if (ck > 0) {
        const pts = [[-0.36, 0.02], [-0.08, 0.3], [0.4, -0.26]], L1 = Math.hypot(0.28, 0.28), L2 = Math.hypot(0.48, 0.56), want = ck * (L1 + L2);
        ctx.beginPath(); ctx.moveTo(x + pts[0][0] * rad, y + pts[0][1] * rad);
        if (want <= L1) { const f = want / L1; ctx.lineTo(x + lerp(pts[0][0], pts[1][0], f) * rad, y + lerp(pts[0][1], pts[1][1], f) * rad); }
        else { ctx.lineTo(x + pts[1][0] * rad, y + pts[1][1] * rad); const f = (want - L1) / L2; ctx.lineTo(x + lerp(pts[1][0], pts[2][0], f) * rad, y + lerp(pts[1][1], pts[2][1], f) * rad); }
        ctx.strokeStyle = "#ffffff"; ctx.lineWidth = Math.max(2, rad * 0.09); ctx.lineCap = "round"; ctx.lineJoin = "round"; ctx.stroke(); ctx.lineCap = "butt";
        bloom(ctx, C.cyan, x, y, rad * 1.4, 0.35 * ck);
      }
    }
    void t;
  }

  /* ================================================================ the page side ================================================================ */
  const scenes = [...root.querySelectorAll(".sy-scene")];
  const N = scenes.length;
  const bg = root.querySelector(".sy-bg"), cv = root.querySelector(".sy-cv");
  root.classList.add("sy-js");
  let still = isStill();
  root.classList.toggle("still", still);

  /* split titles into masked words; the wordmark into letters */
  const titles = [];
  scenes.forEach((sc) => { const el = sc.querySelector(".sy-title:not(.sy-tagline)"); if (el) titles.push({ el, words: [] }); });
  function split(rec) {
    const text = rec.el.textContent.trim();
    rec.el.setAttribute("aria-label", text);
    rec.el.classList.add("sy-split");
    rec.el.replaceChildren(...text.split(/\s+/).flatMap((w, i) => {
      const m = document.createElement("span"), s = document.createElement("span");
      m.className = "sy-wm"; s.className = "sy-w"; s.textContent = w; m.setAttribute("aria-hidden", "true"); m.appendChild(s);
      return i ? [document.createTextNode(" "), m] : [m];
    }));
    rec.words = [...rec.el.querySelectorAll(".sy-w")];
  }
  titles.forEach(split);
  const word = root.querySelector(".sy-word");
  let letters = [];
  if (word) {
    const text = word.textContent; word.setAttribute("aria-label", text);
    letters = [...text].map((c) => { const s = document.createElement("span"); s.className = "sy-l"; s.textContent = c; s.setAttribute("aria-hidden", "true"); return s; });
    word.replaceChildren(...letters);
    letters.forEach((l, i) => { l.style.backgroundSize = `${letters.length * 100}% 100%`; l.style.backgroundPosition = `${(i / Math.max(1, letters.length - 1)) * 100}% 0`; });
  }
  const stepNames = () => root.querySelectorAll("[data-step]").forEach((n) => { n.textContent = stepName(Number(n.dataset.step)); });
  stepNames();

  const SC = scenes.map((sc, i) => ({
    sc, i, stage: sc.querySelector(".sy-stage"), copy: sc.querySelector(".sy-copy"),
    kicker: sc.querySelector(".sy-kicker"), kbar: sc.querySelector(".sy-kbar"), title: titles.find((r) => sc.contains(r.el)),
    beats: [...sc.querySelectorAll(".sy-beat")], note: sc.querySelector(".sy-note"),
    end: i === N - 1 ? [sc.querySelector(".sy-tagline"), sc.querySelector(".sy-state"), sc.querySelector(".sy-ctas")].filter(Boolean) : [],
    top: 0, len: 1, h: 1, pin: 0, pinS: 0, pinE: 1,
  }));
  // a write only when the value changed: the page restyles only what moves
  function set(el, tf, op) {
    if (!el) return;
    if (el._tf !== tf) { el._tf = tf; el.style.transform = tf; }
    if (el._op !== op) { el._op = op; el.style.opacity = op; }
  }

  /* ---------------- measuring ---------------- */
  const V = { ctx: cv ? cv.getContext("2d") : null, W: 1, H: 1, dpr: 1, reg: [], emb: { x: 0, y: 0, size: 140 }, bgA: 1, scrim: 1, copy: null, still: false };
  let narrow = false;
  function pickDpr(w, h) {
    const low = html.classList.contains("perf-low") || html.classList.contains("fx-glow-flat");
    const want = Math.min(window.devicePixelRatio || 1, low ? 1 : 1.75);
    return Math.max(1, Math.min(want, Math.sqrt(4.2e6 / Math.max(1, w * h))));
  }
  function measure() {
    SANS = getComputedStyle(document.body).fontFamily || SANS;
    MEASURE.clear();
    if (still) { measureStill(); return; }
    const vh = innerHeight, rr0 = root.getBoundingClientRect(), W = Math.min(root.clientWidth, document.documentElement.clientWidth || root.clientWidth);
    narrow = W < 901;
    SC.forEach((S) => {
      S.h = S.stage.offsetHeight;
      S.pin = S.i === N - 1 ? 0 : narrow ? 70 : Math.max(84, Math.round((vh - S.h) / 2));
      if (S.i !== N - 1) S.stage.style.top = `${S.pin}px`;
      S.top = S.sc.offsetTop; S.len = S.sc.offsetHeight;
      S.pinS = S.top - S.pin; S.pinE = S.top + S.len - S.h - S.pin;
    });
    // the visual region of each scene: beside the copy (wide) or under it (narrow)
    const R = rtl();
    V.reg = SC.map((S) => {
      if (S.i === N - 1) return mkReg(0, 70, W, vh);
      const sr = S.stage.getBoundingClientRect(), cr = S.copy.getBoundingClientRect();
      if (narrow) return mkReg(14, S.pin + (cr.bottom - sr.top) + 12, W - 14, vh - 14);
      const cl = cr.left - rr0.left, cR = cr.right - rr0.left;
      return R ? mkReg(58, 76, cl - 44, vh - 34) : mkReg(cR + 44, 76, W - 58, vh - 34);
    });
    const c0 = SC[0], cr0 = c0.copy.getBoundingClientRect(), sr0 = c0.stage.getBoundingClientRect();
    V.copy = narrow ? { narrow: true, bottom: c0.pin + (cr0.bottom - sr0.top) } : { rtl: R, edge: R ? cr0.left - rr0.left : cr0.right - rr0.left };
    const last = SC[N - 1], em = last.sc.querySelector(".sy-emblem");
    if (em) { const er = em.getBoundingClientRect(), sr = last.stage.getBoundingClientRect(); V.emb = { x: er.left - rr0.left + er.width / 2, y: er.top - sr.top + er.height / 2, size: er.width }; }
    V.W = W; V.H = vh; V.dpr = pickDpr(W, vh);
    if (cv) {
      const pw = Math.round(W * V.dpr), ph = Math.round(vh * V.dpr);
      if (cv.width !== pw || cv.height !== ph) { cv.width = pw; cv.height = ph; }
    }
    lastP = NaN;
  }
  // static frames: each scene's finished picture, drawn once into its own canvas
  const STILL_P = [0.62, 1.66, 2.69, 3.62, 4.62];
  function measureStill() {
    SANS = getComputedStyle(document.body).fontFamily || SANS;
    SC.forEach((S) => {
      if (S.i === N - 1) return;
      let c = S.sc.querySelector(".sy-still");
      if (!c) { c = document.createElement("canvas"); c.className = "sy-still"; c.setAttribute("aria-hidden", "true"); S.copy.after(c); }
      const w = c.clientWidth, h = c.clientHeight; if (!w || !h) return;
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      c.width = Math.round(w * dpr); c.height = Math.round(h * dpr);
      const reg = mkReg(10, 10, w - 10, h - 10);
      const SV = { ctx: c.getContext("2d"), W: w, H: h, dpr, reg: [reg, reg, reg, reg, reg, reg], emb: { x: w / 2, y: h / 2, size: Math.min(w, h) * 0.4 }, bgA: 0.7, scrim: 0, copy: null, still: true };
      draw(SV, STILL_P[S.i]);
    });
  }

  /* ---------------- the story position ---------------- */
  function progress(ys) {
    const f = SC[0];
    if (ys < f.pinS) return -1 + clamp((ys - (f.pinS - innerHeight * 0.8)) / (innerHeight * 0.8));
    for (let i = 0; i < N; i++) {
      const S = SC[i];
      if (ys <= S.pinE) return i + 0.7 * clamp((ys - S.pinS) / Math.max(1, S.pinE - S.pinS));
      if (i < N - 1 && ys < SC[i + 1].pinS) return i + 0.7 + 0.3 * (ys - S.pinE) / Math.max(1, SC[i + 1].pinS - S.pinE);
    }
    return N - 1 + 0.7 + 0.3 * clamp((ys - SC[N - 1].pinE) / innerHeight);
  }

  /* ---------------- the copy: kicker, title, beats ---------------- */
  function copyAt(S, ys) {
    const vh = innerHeight, prev = SC[S.i - 1], next = SC[S.i + 1];
    const inD = prev ? Math.max(1, S.pinS - prev.pinE) : vh * 0.55, outD = next ? Math.max(1, next.pinS - S.pinE) : vh;
    // far away: settle once into the waiting (or finished) state, then skip
    const far = ys < S.pinS - inD - vh * 0.2 ? -1 : ys > S.pinE + outD + 40 ? 1 : 0;
    if (far && S.far === far) return;
    S.far = far;
    const e = clamp((ys - (S.pinS - inD)) / inD), x = next ? clamp((ys - S.pinE) / outD) : 0, t = clamp((ys - S.pinS) / Math.max(1, S.pinE - S.pinS));
    const sgn = rtl() ? 1 : -1;
    if (S.kicker) { const k = ease(seg(e, 0, 0.55)), o = ease(seg(x, 0, 0.45)); set(S.kicker, `translate(${(sgn * (1 - k) * 28).toFixed(1)}px, ${(-o * 14).toFixed(1)}px)`, (k * (1 - o)).toFixed(3)); }
    if (S.kbar) set(S.kbar, `scaleX(${t.toFixed(4)})`, "");
    if (S.title) {
      const n = S.title.words.length;
      S.title.words.forEach((w, k) => {
        const st = (k / Math.max(1, n)) * 0.42, ek = expo(seg(e, 0.12 + st, 0.6 + st)), xk = ease(seg(x, st * 0.5, 0.42 + st * 0.5));
        const y = (1 - ek) * 108 - xk * 108;
        set(w, `translateY(${y.toFixed(2)}%) rotate(${((1 - ek) * (rtl() ? -5 : 5)).toFixed(2)}deg)`, (Math.min(1, ek * 1.4) * (1 - xk)).toFixed(3));
      });
    }
    const nb = S.beats.length;
    if (nb) {
      // scene 3 follows the four instruments; the others split their hold evenly
      const starts = S.i === 2 ? [0, 0.245, 0.47, 0.695] : S.beats.map((_, j) => j / nb);
      S.beats.forEach((b, j) => {
        const s0 = starts[j], s1 = j < nb - 1 ? starts[j + 1] : 2;
        const inn = j === 0 ? ease(seg(e, 0.4, 1)) : ease(seg(t, s0 - 0.03, s0 + 0.04));
        const out = j < nb - 1 ? ease(seg(t, s1 - 0.045, s1 + 0.005)) : ease(seg(x, 0.05, 0.5));
        const o = inn * (1 - out);
        set(b, `translateY(${((1 - inn) * 22 - out * 16).toFixed(1)}px)`, o.toFixed(3));
        const vis = o < 0.01 ? "hidden" : ""; if (b._v !== vis) { b._v = vis; b.style.visibility = vis; }
        if (b.classList.contains("sy-st")) b.classList.toggle("on", o > 0.5 && x < 0.5);
      });
    }
    if (S.note) set(S.note, "", (ease(seg(e, 0.6, 1)) * (1 - ease(seg(x, 0, 0.4)))).toFixed(3));
    if (S.end.length) {
      S.end.forEach((el, k) => { const v = ease(seg(e, 0.35 + k * 0.12, 0.75 + k * 0.12)); set(el, `translateY(${((1 - v) * 26).toFixed(1)}px)`, v.toFixed(3)); });
      const sweep = seg(e, 0.4, 1) * 1.3 - 0.15;
      letters.forEach((l, k) => {
        const a0 = 0.05 + k * 0.03, v = ease(seg(e, a0, a0 + 0.32));
        set(l, `translateY(${((1 - v) * 0.55).toFixed(3)}em) rotateX(${((1 - v) * 80).toFixed(1)}deg) scale(${(0.7 + 0.3 * v).toFixed(3)})`, v.toFixed(3));
        const g = Math.max(0, 1 - Math.abs(sweep - k / Math.max(1, letters.length - 1)) * 5);
        const f = g > 0.02 ? `drop-shadow(0 0 ${(18 * g).toFixed(1)}px rgba(34, 232, 255, ${(0.9 * g).toFixed(2)})) brightness(${(1 + 0.6 * g).toFixed(2)})` : "";
        if (l._f !== f) { l._f = f; l.style.filter = f; }
      });
    }
  }

  /* ---------------- the loop: damped, and only while something moves ---------------- */
  const navLinks = [...root.querySelectorAll(".sy-nav a")];
  let ys = null, target = 0, raf = 0, lastT = 0, lastP = NaN, onScreen = false, cur = -1;
  function frameAt(y) {
    const P = progress(y);
    if (V.ctx && !(Math.abs(P - lastP) <= 1e-5)) { lastP = P; draw(V, P); }
    SC.forEach((S) => copyAt(S, y));
    const idx = clamp(Math.floor(P + 0.3), 0, N - 1);
    if (idx !== cur) {
      cur = idx;
      SC.forEach((S) => S.sc.classList.toggle("on", S.i === idx && P > -0.4));
      navLinks.forEach((a) => { const on = a.dataset.go === String(idx + 1); a.classList.toggle("on", on); if (on) a.setAttribute("aria-current", "step"); else a.removeAttribute("aria-current"); });
    }
  }
  function tick(now) {
    raf = 0;
    if (still) return;
    target = -root.getBoundingClientRect().top;
    const dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 1 / 60; lastT = now;
    if (ys == null || Math.abs(target - ys) > innerHeight * 3) ys = target;
    else ys += (target - ys) * (1 - Math.exp(-dt * 11));
    if (Math.abs(target - ys) < 0.35) ys = target;
    frameAt(ys);
    if (ys !== target && onScreen) raf = requestAnimationFrame(tick); else lastT = 0;
  }
  const kick = () => { if (!raf && onScreen && !still) raf = requestAnimationFrame(tick); };
  const io = new IntersectionObserver((es) => { es.forEach((e) => { onScreen = e.isIntersecting; }); if (onScreen) kick(); }, { rootMargin: "200px 0px" });
  io.observe(root);
  addEventListener("scroll", kick, { passive: true });
  let rt = 0;
  const remeasure = () => { clearTimeout(rt); rt = setTimeout(() => { measure(); SC.forEach((S) => { S.far = 0; }); if (!still) { lastP = NaN; ys = null; kick(); } }, 120); };
  addEventListener("resize", remeasure, { passive: true });
  addEventListener("cs:perf", remeasure);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(remeasure);
  // layout above the story can change (lazy content, the deep dive opening): stay in step
  if ("ResizeObserver" in window) { let first = true; new ResizeObserver(() => { if (first) { first = false; return; } remeasure(); }).observe(root); }

  function clearStyles() {
    root.querySelectorAll(".sy-kicker, .sy-kbar, .sy-w, .sy-beat, .sy-note, .sy-l, .sy-tagline, .sy-state, .sy-ctas, .sy-stage").forEach((n) => {
      n.style.transform = ""; n.style.opacity = ""; n.style.visibility = ""; n.style.filter = ""; n.style.top = ""; n._tf = n._op = n._f = n._v = undefined;
    });
    root.querySelectorAll(".sy-scene.on, .sy-st.on").forEach((n) => n.classList.remove("on"));
  }
  function setStill() {
    const s = isStill();
    if (s === still) return;
    still = s; root.classList.toggle("still", s);
    if (s) { clearStyles(); cancelAnimationFrame(raf); raf = 0; }
    measure(); if (!s) { ys = null; kick(); }
  }
  new MutationObserver(setStill).observe(html, { attributes: true, attributeFilter: ["class"] });
  const mq = matchMedia("(prefers-reduced-motion: reduce)"); if (mq.addEventListener) mq.addEventListener("change", setStill);

  /* ---------------- chapter rail: plain scrolling, never hijacked ---------------- */
  navLinks.forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault();
    const S = SC[Number(a.dataset.go) - 1]; if (!S) return;
    const base = root.getBoundingClientRect().top + scrollY;
    const top = still ? S.sc.getBoundingClientRect().top + scrollY - 80 : base + S.pinS + 2;
    scrollTo({ top, behavior: still ? "auto" : "smooth" });
    const h = S.sc.querySelector(".sy-title"); h.setAttribute("tabindex", "-1");
    setTimeout(() => h.focus({ preventScroll: true }), still ? 0 : 700);
  }));

  /* ---------------- the deep dive: collapsed behind a button ---------------- */
  (function () {
    const deep = document.getElementById("sci-deep"), btn = document.getElementById("sci-deep-toggle");
    if (!deep || !btn) return;
    const head = deep.querySelector(".sci-deep-head");
    const parts = [...head.children].filter((n) => n !== btn && !n.matches(".sci-deep-title, .sci-deep-note")).concat([document.getElementById("sci-deep-body")]).filter(Boolean);
    const setOpen = (open) => {
      parts.forEach((p) => { p.hidden = !open; });
      btn.setAttribute("aria-expanded", String(open));
      const label = btn.querySelector("span"); label.dataset.i18n = open ? "sciDeepHide" : "sciDeepShow";
      label.textContent = (CS.t && CS.t(label.dataset.i18n)) || label.textContent;
    };
    deep.classList.add("sy-ready");
    setOpen(location.hash.startsWith("#sci-"));
    btn.addEventListener("click", () => setOpen(btn.getAttribute("aria-expanded") !== "true"));
  })();

  if (CS.onLang) CS.onLang(() => { titles.forEach(split); stepNames(); remeasure(); });

  measure();
  if (!still) { target = -root.getBoundingClientRect().top; ys = target; frameAt(ys); }
})();
