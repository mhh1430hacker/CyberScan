/* The explainer video: 74 seconds, eight scenes, drawn live on a canvas.
 *
 * - English narration through the browser's own speech voice (no files)
 * - English and Arabic subtitles burned in at the bottom, read from
 *   captions/en.vtt and captions/ar.vtt
 * - chapters, seeking, keyboard control, fullscreen
 * - "Export video" records the canvas to a .webm file (subtitles included)
 */
(function () {
  "use strict";
  const { $, el, t, toast } = window.CS;
  const canvas = $("film-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = 1280, H = 720, DURATION = 74;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const C = { cyan: "#22e8ff", violet: "#b46cff", pink: "#ff4fd8", green: "#3dffb0", red: "#ff4f6d", ink: "#e9f3ff", dim: "#7f8bb3", bg: "#07051a" };
  const CHAPTERS = [0, 7, 16, 26, 38, 48, 58, 66];

  let time = 0, playing = false, last = 0, raf = 0, cues = { en: [], ar: [] }, spoken = new Set(), voiceOn = true, subsOn = true, recorder = null;

  /* ---------------- captions ---------------- */
  function parseVtt(text) {
    const toSec = (s) => { const [h, m, rest] = s.trim().split(":"); return Number(h) * 3600 + Number(m) * 60 + Number(rest); };
    return text.replace(/\r/g, "").split(/\n\n+/).map((block) => {
      const lines = block.split("\n");
      const i = lines.findIndex((l) => l.includes("-->"));
      if (i < 0) return null;
      const [a, b] = lines[i].split("-->");
      return { start: toSec(a), end: toSec(b), text: lines.slice(i + 1).join(" ").trim() };
    }).filter(Boolean);
  }
  Promise.all(["en", "ar"].map((l) => fetch(`captions/${l}.vtt`).then((r) => r.text()).then((x) => { cues[l] = parseVtt(x); })))
    .then(() => draw()).catch(() => {});
  const cueAt = (lang, s) => cues[lang].find((c) => s >= c.start && s < c.end);

  /* ---------------- drawing helpers ---------------- */
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const ease = (x) => { x = clamp(x); return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2; };
  const span = (s, a, b) => clamp((s - a) / (b - a));
  function glowText(text, x, y, size, color, opts = {}) {
    ctx.save();
    ctx.font = `${opts.weight || 800} ${size}px ${opts.mono ? "Consolas, monospace" : '"Segoe UI", Tahoma, sans-serif'}`;
    ctx.textAlign = opts.align || "center"; ctx.textBaseline = "middle";
    ctx.direction = opts.rtl ? "rtl" : "ltr";
    ctx.globalAlpha = opts.alpha ?? 1;
    ctx.shadowColor = color; ctx.shadowBlur = opts.blur ?? 22;
    ctx.fillStyle = color;
    ctx.fillText(text, x, y);
    ctx.shadowBlur = 0;
    if (opts.core) { ctx.fillStyle = opts.core; ctx.fillText(text, x, y); }
    ctx.restore();
  }
  function roundRect(x, y, w, h, r) {
    ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  function hexPath(x, y, r, rot = 0) {
    ctx.beginPath();
    for (let i = 0; i < 6; i++) { const a = rot + Math.PI / 6 + (i * Math.PI) / 3; ctx[i ? "lineTo" : "moveTo"](x + Math.cos(a) * r, y + Math.sin(a) * r); }
    ctx.closePath();
  }
  const SHIELD = new Path2D("M32 6 12 14v14c0 13 8.7 23 20 26 11.3-3 20-13 20-26V14z");
  const TICK = new Path2D("m23 31 6.5 6.5 12.5-13.5");
  function logo(x, y, scale, k, alpha = 1) {
    ctx.save();
    ctx.translate(x, y); ctx.scale(scale, scale); ctx.translate(-32, -32);
    ctx.globalAlpha = alpha;
    ctx.lineJoin = "round"; ctx.lineCap = "round";
    ctx.shadowColor = C.cyan; ctx.shadowBlur = 18 / scale;
    ctx.strokeStyle = C.cyan; ctx.lineWidth = 2.6;
    ctx.setLineDash([140]); ctx.lineDashOffset = 140 * (1 - ease(k));
    ctx.stroke(SHIELD);
    ctx.strokeStyle = "#bff7ff"; ctx.lineWidth = 3;
    ctx.setLineDash([30]); ctx.lineDashOffset = 30 * (1 - ease((k - 0.5) * 2));
    ctx.stroke(TICK);
    ctx.restore();
  }

  function background(s) {
    const g = ctx.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, "#0a0624"); g.addColorStop(0.62, "#07041a"); g.addColorStop(1, "#04020c");
    ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
    // neon sun haze
    const haze = ctx.createRadialGradient(W / 2, H * 0.62, 0, W / 2, H * 0.62, W * 0.55);
    haze.addColorStop(0, "rgba(180,108,255,0.20)"); haze.addColorStop(0.5, "rgba(34,232,255,0.06)"); haze.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = haze; ctx.fillRect(0, 0, W, H);
    // perspective grid floor
    const horizon = H * 0.62;
    ctx.save();
    ctx.beginPath(); ctx.rect(0, horizon, W, H - horizon); ctx.clip();
    ctx.strokeStyle = "rgba(34,232,255,0.22)"; ctx.lineWidth = 1;
    for (let i = -14; i <= 14; i++) { ctx.beginPath(); ctx.moveTo(W / 2 + i * 18, horizon); ctx.lineTo(W / 2 + i * 150, H); ctx.stroke(); }
    const off = (s * 0.35) % 1;
    for (let i = 0; i < 12; i++) {
      const z = (i + off) / 12;
      const y = horizon + Math.pow(z, 2.2) * (H - horizon);
      ctx.strokeStyle = `rgba(180,108,255,${(0.08 + z * 0.3).toFixed(3)})`;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
    }
    ctx.restore();
    const fade = ctx.createLinearGradient(0, horizon - 2, 0, horizon + 60);
    fade.addColorStop(0, "rgba(7,4,26,0.9)"); fade.addColorStop(1, "rgba(7,4,26,0)");
    ctx.fillStyle = fade; ctx.fillRect(0, horizon - 2, W, 62);
  }

  function overlay(s) {
    // scanlines + vignette
    ctx.fillStyle = "rgba(0,0,0,0.12)";
    for (let y = (s * 40) % 3; y < H; y += 3) ctx.fillRect(0, y, W, 1);
    const v = ctx.createRadialGradient(W / 2, H / 2, H * 0.35, W / 2, H / 2, H * 0.95);
    v.addColorStop(0, "rgba(0,0,0,0)"); v.addColorStop(1, "rgba(0,0,0,0.55)");
    ctx.fillStyle = v; ctx.fillRect(0, 0, W, H);
    // HUD corners + timecode
    ctx.strokeStyle = "rgba(34,232,255,0.55)"; ctx.lineWidth = 2;
    [[24, 24, 1, 1], [W - 24, 24, -1, 1], [24, H - 24, 1, -1], [W - 24, H - 24, -1, -1]].forEach(([x, y, dx, dy]) => {
      ctx.beginPath(); ctx.moveTo(x, y + dy * 26); ctx.lineTo(x, y); ctx.lineTo(x + dx * 26, y); ctx.stroke();
    });
    glowText(`REC ● ${fmt(s)}  ·  CYBERSCAN://EXPLAINER`, 44, 46, 14, "rgba(34,232,255,0.8)", { mono: true, align: "left", blur: 8, weight: 600 });
  }

  function subtitles(s) {
    if (!subsOn) return;
    const en = cueAt("en", s), ar = cueAt("ar", s);
    if (!en && !ar) return;
    const y = H - 104;
    ctx.save();
    ctx.fillStyle = "rgba(4,2,14,0.72)";
    roundRect(110, y - 34, W - 220, 108, 14); ctx.fill();
    ctx.strokeStyle = "rgba(34,232,255,0.25)"; ctx.stroke();
    ctx.restore();
    if (en) wrapText(en.text, W / 2, y - 6, W - 280, 24, "#f1f7ff", false, 600);
    if (ar) wrapText(ar.text, W / 2, y + 38, W - 280, 22, "#7ff3ff", true, 600);
  }
  function wrapText(text, x, y, max, size, color, rtl, weight) {
    ctx.save();
    ctx.font = `${weight} ${size}px "Segoe UI", Tahoma, sans-serif`;
    ctx.direction = rtl ? "rtl" : "ltr";
    let line = text;
    if (ctx.measureText(text).width > max) {
      // shrink rather than wrap: two lines of subtitles must stay readable
      const k = max / ctx.measureText(text).width;
      ctx.font = `${weight} ${Math.max(14, Math.floor(size * k))}px "Segoe UI", Tahoma, sans-serif`;
    }
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillStyle = color;
    ctx.shadowColor = "rgba(0,0,0,0.9)"; ctx.shadowBlur = 6;
    ctx.fillText(line, x, y);
    ctx.restore();
  }

  /* ---------------- scenes ---------------- */
  const SCENES = [
    [0, 7, sceneIntro], [7, 16, sceneFile], [16, 26, sceneRead], [26, 38, sceneEngines],
    [38, 48, sceneVerdict], [48, 58, sceneRepair], [58, 66, scenePrivate], [66, 74, sceneEnd],
  ];

  function sceneIntro(p, s) {
    const cx = W / 2, cy = H * 0.4;
    ctx.save(); ctx.translate(cx, cy); ctx.rotate(s * 0.15);
    ctx.strokeStyle = "rgba(180,108,255,0.5)"; ctx.lineWidth = 1.5; hexPath(0, 0, 150 * ease(p * 2)); ctx.stroke();
    ctx.rotate(-s * 0.3); ctx.strokeStyle = "rgba(34,232,255,0.35)"; hexPath(0, 0, 180 * ease(p * 2 - 0.2)); ctx.stroke();
    ctx.restore();
    logo(cx, cy, 3.2, p * 2.2);
    const word = "CYBERSCAN";
    const shown = Math.floor(clamp((p - 0.35) / 0.35) * word.length);
    glowText(word.slice(0, shown), cx, H * 0.67, 64, C.cyan, { core: "#eaffff", blur: 30 });
    glowText("STATIC ANALYSIS  ·  EXPLAINED", cx, H * 0.75, 18, C.violet, { mono: true, alpha: ease((p - 0.7) / 0.2), blur: 12, weight: 600 });
  }

  function fileCard(x, y, w, h, alpha, label, labelColor) {
    ctx.save();
    ctx.globalAlpha = alpha;
    ctx.fillStyle = "rgba(20,14,48,0.92)";
    ctx.strokeStyle = C.violet; ctx.lineWidth = 2; ctx.shadowColor = C.violet; ctx.shadowBlur = 24;
    ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x + w - 46, y); ctx.lineTo(x + w, y + 46); ctx.lineTo(x + w, y + h); ctx.lineTo(x, y + h); ctx.closePath();
    ctx.fill(); ctx.stroke(); ctx.shadowBlur = 0;
    ctx.fillStyle = "rgba(180,108,255,0.18)";
    for (let i = 0; i < 6; i++) ctx.fillRect(x + 30, y + 110 + i * 26, i % 3 === 2 ? 120 : 200, 9);
    ctx.restore();
    glowText(label, x + w / 2, y + 62, 34, labelColor, { blur: 18, alpha });
  }

  function sceneFile(p, s) {
    const enter = ease(p / 0.25);
    const x = -300 + (W / 2 - 150 + 300) * enter;
    const flip = s > 11.6;
    fileCard(x, 170, 300, 340, 1, flip ? "EXE" : "PDF", flip ? C.pink : C.cyan);
    glowText("invoice_2026.pdf.exe", x + 150, 545, 20, C.ink, { mono: true, blur: 8, weight: 600 });
    if (flip) glowText("…it's really a program", x + 150, 140, 20, C.pink, { alpha: ease((s - 11.6) / 0.6), blur: 14, weight: 600 });
    if (s > 12.2) {
      const k = ease((s - 12.2) / 0.8);
      [[C.red, 0], [C.green, 1]].forEach(([col, i]) => {
        const on = Math.floor(s * 2.2) % 2 === i;
        ctx.save(); ctx.globalAlpha = k * (on ? 1 : 0.25);
        ctx.fillStyle = col; ctx.shadowColor = col; ctx.shadowBlur = on ? 40 : 0;
        ctx.beginPath(); ctx.arc(W * 0.8, 260 + i * 110, 40, 0, Math.PI * 2); ctx.fill(); ctx.restore();
      });
      glowText("TRUST US?", W * 0.8, 450, 22, C.dim, { mono: true, alpha: k, blur: 0, weight: 700 });
    }
  }

  const GRID_C = 20, GRID_R = 10;
  const cells = Array.from({ length: GRID_C * GRID_R }, (_, i) => ({ i, seed: Math.random(), e: i < 20 ? 2.5 : i < 120 ? 5.6 + Math.random() : i > 170 ? 7.6 : 4 + Math.random() * 1.5 }));
  function entropyColor(e) {
    const stops = [[0, [40, 60, 160]], [4, [34, 232, 255]], [6.2, [180, 108, 255]], [8, [255, 79, 216]]];
    for (let i = 1; i < stops.length; i++) if (e <= stops[i][0]) {
      const [e0, c0] = stops[i - 1], [e1, c1] = stops[i], k = (e - e0) / (e1 - e0);
      return `rgb(${c0.map((v, j) => Math.round(v + (c1[j] - v) * k)).join(",")})`;
    }
    return "rgb(255,79,216)";
  }
  function sceneRead(p, s) {
    const size = 36, gx = W / 2 - (GRID_C * size) / 2, gy = 150;
    const fx = W / 2 - 150, fy = 170;
    const beam = gx + (GRID_C * size + 40) * ease((p - 0.45) / 0.5);
    cells.forEach((c) => {
      const col = c.i % GRID_C, row = Math.floor(c.i / GRID_C);
      const sx = fx + (col / GRID_C) * 300, sy = fy + (row / GRID_R) * 340;
      const tx = gx + col * size, ty = gy + row * size;
      const k = ease((p * 2.2 - c.seed * 0.6));
      const x = sx + (tx - sx) * k, y = sy + (ty - sy) * k - Math.sin(k * Math.PI) * 60 * c.seed;
      const lit = tx < beam;
      ctx.fillStyle = lit ? entropyColor(c.e) : "rgba(180,108,255,0.35)";
      ctx.globalAlpha = 0.9;
      ctx.fillRect(x + 3, y + 3, size * (0.4 + 0.5 * k) , size * (0.4 + 0.5 * k));
      ctx.globalAlpha = 1;
    });
    if (p > 0.45 && p < 0.97) {
      ctx.save(); ctx.shadowColor = C.cyan; ctx.shadowBlur = 30; ctx.fillStyle = "#cffaff";
      ctx.fillRect(beam, gy - 20, 3, GRID_R * size + 40); ctx.restore();
    }
    // byte stream
    ctx.font = "600 14px Consolas, monospace"; ctx.fillStyle = "rgba(34,232,255,0.55)";
    for (let i = 0; i < 26; i++) {
      const x = ((i * 97 + s * 160) % (W + 100)) - 50;
      ctx.fillText(["4D", "5A", "90", "00", "FF", "E8", "PE", "3C", "7F"][i % 9], x, 118 + (i % 3) * 14);
    }
    const badge = ease((p - 0.15) / 0.2);
    ctx.save(); ctx.globalAlpha = badge;
    ctx.strokeStyle = C.green; ctx.shadowColor = C.green; ctx.shadowBlur = 16; ctx.lineWidth = 2;
    roundRect(W / 2 - 170, gy + GRID_R * size + 30, 340, 46, 23); ctx.stroke(); ctx.restore();
    glowText("🔒  READ-ONLY  ·  NEVER RUN", W / 2, gy + GRID_R * size + 53, 18, C.green, { mono: true, alpha: badge, blur: 10, weight: 700 });
  }

  const ENGINES = ["FILE TYPE", "RANDOMNESS", "WARNING SIGNS", "YARA", "PE ANATOMY", "ARCHIVES", "SIGNATURE", "ML MODEL", "THREAT INTEL"];
  function sceneEngines(p, s) {
    const cx = W / 2, cy = H * 0.42, R = 230;
    const core = 0.6 + 0.4 * Math.sin(s * 3);
    ctx.save(); ctx.shadowColor = C.violet; ctx.shadowBlur = 40 * core;
    ctx.strokeStyle = C.violet; ctx.lineWidth = 3; hexPath(cx, cy, 56, s * 0.5); ctx.stroke(); ctx.restore();
    glowText("∑", cx, cy + 2, 46, C.violet, { blur: 20 });
    ENGINES.forEach((name, i) => {
      const a = -Math.PI / 2 + (i / ENGINES.length) * Math.PI * 2;
      const x = cx + Math.cos(a) * R * 1.35, y = cy + Math.sin(a) * R * 0.95;
      const on = s >= 26.6 + i * 1.15;
      const k = on ? ease((s - (26.6 + i * 1.15)) / 0.5) : 0;
      ctx.strokeStyle = on ? `rgba(34,232,255,${0.25 + 0.5 * k})` : "rgba(127,139,179,0.2)";
      ctx.lineWidth = on ? 2 : 1;
      ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(cx, cy); ctx.stroke();
      if (on) {
        const q = (s * 0.9 + i * 0.37) % 1;
        ctx.save(); ctx.fillStyle = C.cyan; ctx.shadowColor = C.cyan; ctx.shadowBlur = 14;
        ctx.beginPath(); ctx.arc(x + (cx - x) * q, y + (cy - y) * q, 4, 0, Math.PI * 2); ctx.fill(); ctx.restore();
      }
      ctx.save(); ctx.globalAlpha = 0.35 + 0.65 * k;
      ctx.fillStyle = "rgba(14,10,36,0.95)"; ctx.strokeStyle = on ? C.cyan : "rgba(127,139,179,0.4)";
      ctx.shadowColor = C.cyan; ctx.shadowBlur = on ? 18 * k : 0; ctx.lineWidth = 1.5;
      roundRect(x - 78, y - 20, 156, 40, 10); ctx.fill(); ctx.stroke(); ctx.restore();
      glowText(name, x, y + 1, 14, on ? "#dffbff" : C.dim, { mono: true, blur: on ? 8 : 0, weight: 700, alpha: 0.5 + 0.5 * k });
    });
  }

  function sceneVerdict(p, s) {
    const cx = W * 0.3, cy = H * 0.4, R = 120;
    const fill = ease(p / 0.45);
    ctx.lineWidth = 16; ctx.lineCap = "round";
    ctx.strokeStyle = "rgba(127,139,179,0.2)"; ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();
    ctx.save(); ctx.shadowColor = C.pink; ctx.shadowBlur = 30; ctx.strokeStyle = C.pink;
    ctx.beginPath(); ctx.arc(cx, cy, R, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * 0.87 * fill); ctx.stroke(); ctx.restore();
    glowText(String(Math.round(87 * fill)), cx, cy - 4, 72, "#ffe6f7", { blur: 24 });
    glowText("/ 100", cx, cy + 50, 18, C.dim, { mono: true, blur: 0, weight: 600 });
    const tx = W * 0.5;
    glowText("THIS LOOKS SUSPICIOUS", tx, H * 0.22, 34, C.pink, { align: "left", alpha: ease((p - 0.2) / 0.2), blur: 22 });
    ["Named like a PDF, really a program", "Data hidden after the end of the file", "Encoded PowerShell command"].forEach((f, i) => {
      const k = ease((p - 0.32 - i * 0.08) / 0.15);
      ctx.save(); ctx.globalAlpha = k; ctx.translate((1 - k) * 40, 0);
      ctx.fillStyle = "rgba(20,14,48,0.9)"; roundRect(tx, H * 0.3 + i * 64, 470, 50, 10); ctx.fill();
      ctx.fillStyle = [C.red, C.pink, C.violet][i]; ctx.fillRect(tx, H * 0.3 + i * 64, 4, 50);
      ctx.restore();
      glowText(f, tx + 22, H * 0.3 + i * 64 + 25, 18, C.ink, { align: "left", alpha: k, blur: 0, weight: 600 });
    });
    const lang = s > 44.5 && Math.floor(s) % 2 === 0;
    glowText(lang ? "AR · العربية" : "EN · ENGLISH", tx + 470, H * 0.3 + 3 * 64 + 22, 15, C.cyan, { align: "right", mono: true, alpha: ease((p - 0.55) / 0.1), blur: 8, weight: 700 });
  }

  function sceneRepair(p, s) {
    const n = 40, bw = 22, gap = 4, total = n * (bw + gap), x0 = W / 2 - total / 2 - 60, y0 = H * 0.36;
    const bad = (i) => i >= 26 && i < 33;
    const cut = ease((p - 0.25) / 0.3), close = ease((p - 0.55) / 0.2);
    const vx = W * 0.82, vy = H * 0.24;
    let xi = x0;
    for (let i = 0; i < n; i++) {
      if (bad(i)) {
        const k = cut;
        const x = xi + (vx - xi) * k, y = y0 + (vy - y0) * k - Math.sin(k * Math.PI) * 80;
        ctx.save(); ctx.globalAlpha = 1 - clamp((k - 0.85) / 0.15);
        ctx.fillStyle = C.red; ctx.shadowColor = C.red; ctx.shadowBlur = 18;
        ctx.fillRect(x, y, bw * (1 - k * 0.6), 70 * (1 - k * 0.6)); ctx.restore();
        xi += (bw + gap) * (1 - close);
      } else {
        ctx.fillStyle = `hsl(${190 + (i % 7) * 10} 90% 62% / .85)`;
        ctx.fillRect(xi, y0, bw, 70);
        xi += bw + gap;
      }
    }
    // vault
    const lit = clamp((p - 0.4) / 0.2);
    ctx.save(); ctx.strokeStyle = C.cyan; ctx.lineWidth = 2.5; ctx.shadowColor = C.cyan; ctx.shadowBlur = 10 + 30 * lit;
    hexPath(vx, vy, 62, 0); ctx.stroke();
    ctx.fillStyle = "#dffbff"; roundRect(vx - 18, vy - 4, 36, 28, 5); ctx.fill();
    ctx.beginPath(); ctx.arc(vx, vy - 4 + (1 - ease((p - 0.5) / 0.15)) * -8, 12, Math.PI, 0); ctx.lineWidth = 4; ctx.strokeStyle = "#dffbff"; ctx.stroke();
    ctx.restore();
    glowText("ENCRYPTED VAULT", vx, vy + 92, 14, C.cyan, { mono: true, blur: 8, weight: 700 });
    const done = ease((p - 0.72) / 0.15);
    if (done > 0) {
      ctx.save(); ctx.strokeStyle = C.green; ctx.lineWidth = 6; ctx.lineCap = "round"; ctx.shadowColor = C.green; ctx.shadowBlur = 24; ctx.globalAlpha = done;
      ctx.beginPath(); ctx.arc(W / 2 - 60, y0 + 190, 40, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * done); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(W / 2 - 78, y0 + 190); ctx.lineTo(W / 2 - 64, y0 + 204); ctx.lineTo(W / 2 - 40, y0 + 176); ctx.stroke(); ctx.restore();
      glowText("REPAIRED COPY  ·  ORIGINAL KEPT", W / 2 - 60, y0 + 270, 20, C.green, { mono: true, alpha: done, blur: 12, weight: 700 });
    }
  }

  function scenePrivate(p, s) {
    const cx = W / 2, cy = H * 0.38;
    ctx.save(); ctx.strokeStyle = C.cyan; ctx.lineWidth = 3; ctx.shadowColor = C.cyan; ctx.shadowBlur = 20;
    roundRect(cx - 170, cy - 100, 340, 210, 14); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(cx - 220, cy + 130); ctx.lineTo(cx + 220, cy + 130); ctx.stroke(); ctx.restore();
    logo(cx, cy + 4, 2.1, 1);
    for (let i = 0; i < 26; i++) {
      const a = s * 0.6 + (i / 26) * Math.PI * 2;
      const x = cx + Math.cos(a) * 280, y = cy + Math.sin(a) * 150;
      ctx.fillStyle = i % 3 ? "rgba(34,232,255,0.7)" : "rgba(180,108,255,0.8)";
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
    }
    glowText("LOCAL  ·  NOTHING UPLOADED", cx, cy + 190, 24, C.cyan, { mono: true, alpha: ease(p / 0.25), blur: 14, weight: 700 });
    if (s > 62.5) glowText("NOT SURE?  IT SAYS SO.", cx, cy - 150, 26, C.violet, { mono: true, alpha: ease((s - 62.5) / 0.6), blur: 16, weight: 800 });
  }

  function sceneEnd(p, s) {
    logo(W / 2, H * 0.3, 2.6, 1);
    glowText("DROP A FILE TO BEGIN", W / 2, H * 0.52, 44, C.cyan, { core: "#eaffff", blur: 28, alpha: ease(p / 0.2) });
    const k = ease((p - 0.2) / 0.2), pulse = 0.6 + 0.4 * Math.sin(s * 4);
    ctx.save(); ctx.globalAlpha = k; ctx.strokeStyle = C.pink; ctx.lineWidth = 2; ctx.shadowColor = C.pink; ctx.shadowBlur = 20 * pulse;
    roundRect(W / 2 - 150, H * 0.6, 300, 56, 28); ctx.stroke(); ctx.restore();
    glowText("CYBERSCAN", W / 2, H * 0.6 + 29, 22, C.pink, { mono: true, alpha: k, blur: 14, weight: 800 });
    if (p > 0.9) { ctx.fillStyle = `rgba(0,0,0,${(p - 0.9) * 10})`; ctx.fillRect(0, 0, W, H); }
  }

  function draw() {
    // before the first play, show a frame where the logo is already drawn
    const poster = !playing && time === 0;
    const s = poster ? 5.4 : time;
    background(s);
    SCENES.forEach(([a, b, fn]) => {
      const fadeIn = clamp((s - a) / 0.6), fadeOut = clamp((b - s) / 0.6);
      const alpha = Math.min(fadeIn, fadeOut);
      if (s < a - 0.01 || s > b + 0.01 || alpha <= 0) return;
      ctx.save(); ctx.globalAlpha = alpha;
      fn(clamp((s - a) / (b - a)), s);
      ctx.restore();
    });
    overlay(poster ? 0 : s);
    if (!poster) subtitles(s);
    updateUi();
  }

  /* ---------------- narration ---------------- */
  let voice = null;
  function pickVoice() {
    const all = window.speechSynthesis ? speechSynthesis.getVoices() : [];
    const en = all.filter((v) => /^en[-_]/i.test(v.lang));
    // best first: neural "Natural" voices, then Google's, then the better Windows voices
    const rank = (v) =>
      /natural/i.test(v.name) ? 0 :
      /online/i.test(v.name) ? 1 :
      /google/i.test(v.name) ? 2 :
      /aria|jenny|guy|ava|andrew|emma|brian/i.test(v.name) ? 3 :
      /zira|hazel|susan/i.test(v.name) ? 4 : 5;
    voice = en.sort((a, b) => rank(a) - rank(b) || (/en-US/i.test(b.lang) - /en-US/i.test(a.lang)))[0] || null;
  }

  /* spoken text reads better than written text: say the filename like a person would */
  function forSpeech(text) {
    return text
      .replace("invoice_2026.pdf.exe", "invoice twenty twenty-six, dot P D F, dot E X E")
      .replace(/YARA/g, "Yara")
      .replace(/CyberScan/g, "Cyber Scan");
  }
  if (window.speechSynthesis) { pickVoice(); speechSynthesis.onvoiceschanged = pickVoice; }
  function speak(s) {
    if (!voiceOn || !window.speechSynthesis || recorder) return;
    const cue = cues.en.find((c) => s >= c.start && s < c.start + 0.4 && !spoken.has(c.start));
    if (!cue) return;
    spoken.add(cue.start);
    // short phrases with their own pauses sound far less mechanical than one long sentence
    const phrases = forSpeech(cue.text).split(/(?<=[.?!:])\s+/).filter(Boolean);
    const natural = voice && /natural|online/i.test(voice.name);
    phrases.forEach((phrase, i) => {
      const u = new SpeechSynthesisUtterance(phrase);
      u.lang = voice ? voice.lang : "en-US";
      if (voice) u.voice = voice;
      u.rate = natural ? 1.0 : 0.93;   // older voices sound better a little slower
      u.pitch = natural ? 1.0 : 1.04;
      u.volume = 0.95;
      if (i === 0) u.onstart = () => window.CSSound && CSSound.setDuck(0.35);
      if (i === phrases.length - 1) u.onend = () => window.CSSound && CSSound.setDuck(1);
      speechSynthesis.speak(u);
    });
  }

  /* ---------------- playback ---------------- */
  function frame(now) {
    if (!playing) return;
    time += Math.min(0.1, (now - last) / 1000); last = now;
    if (time >= DURATION) { time = DURATION; stop(); draw(); finishExport(); return; }
    speak(time);
    draw();
    raf = requestAnimationFrame(frame);
  }
  function play() {
    if (time >= DURATION - 0.05) seek(0);
    playing = true; last = performance.now();
    $("film-player").classList.add("playing");
    raf = requestAnimationFrame(frame);
  }
  function stop() {
    playing = false;
    cancelAnimationFrame(raf);
    $("film-player").classList.remove("playing");
    if (window.speechSynthesis) speechSynthesis.cancel();
    window.CSSound && CSSound.setDuck(1);
  }
  function seek(s) {
    time = clamp(s, 0, DURATION);
    if (window.speechSynthesis) speechSynthesis.cancel();
    spoken = new Set(cues.en.filter((c) => c.start < time - 0.2).map((c) => c.start));
    draw();
  }
  const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
  function updateUi() {
    $("film-fill").style.transform = `scaleX(${time / DURATION})`;
    $("film-time").textContent = `${fmt(time)} / ${fmt(DURATION)}`;
    $("film-seek").setAttribute("aria-valuenow", String(Math.round(time)));
    const ch = CHAPTERS.filter((c) => c <= time + 0.01).length - 1;
    $("film-chaps").querySelectorAll("li").forEach((li, i) => li.classList.toggle("on", i === ch));
  }

  function buildChapters() {
    const names = t("filmChapters");
    $("film-chapters").replaceChildren(...CHAPTERS.slice(1).map((c) => { const i = el("i"); i.style.left = `${(c / DURATION) * 100}%`; return i; }));
    $("film-chaps").replaceChildren(...CHAPTERS.map((c, i) => {
      const li = el("li");
      const b = el("button", "", "");
      b.type = "button";
      b.append(el("span", "fc-time", fmt(c)), el("span", "fc-name", names[i]));
      b.addEventListener("click", () => { seek(c); if (!playing) play(); });
      li.append(b);
      return li;
    }));
    updateUi();
  }

  /* ---------------- export ---------------- */
  function exportVideo() {
    if (recorder) return;
    if (!canvas.captureStream || !window.MediaRecorder) { toast(t("filmNoExport")); return; }
    const type = ["video/webm;codecs=vp9", "video/webm;codecs=vp8", "video/webm"].find((m) => MediaRecorder.isTypeSupported(m));
    const chunks = [];
    recorder = new MediaRecorder(canvas.captureStream(30), { mimeType: type, videoBitsPerSecond: 6_000_000 });
    recorder.ondataavailable = (e) => { if (e.data.size) chunks.push(e.data); };
    recorder.onstop = () => {
      const url = URL.createObjectURL(new Blob(chunks, { type: "video/webm" }));
      const a = el("a"); a.href = url; a.download = "cyberscan-explainer.webm"; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      recorder = null;
      $("film-export").textContent = t("filmExport");
      $("film-player").classList.remove("exporting");
      toast(t("filmExported"));
    };
    stop(); seek(0);
    $("film-player").classList.add("exporting");
    $("film-export").textContent = t("filmExporting");
    recorder.start(1000);
    play();
  }
  function finishExport() { if (recorder && recorder.state === "recording") recorder.stop(); }

  /* ---------------- controls ---------------- */
  const toggle = () => (playing ? stop() : play());
  $("film-play").addEventListener("click", toggle);
  $("film-big").addEventListener("click", toggle);
  canvas.addEventListener("click", toggle);
  const seekbar = $("film-seek");
  const seekTo = (e) => { const r = seekbar.getBoundingClientRect(); let k = (e.clientX - r.left) / r.width; if (document.documentElement.dir === "rtl") k = 1 - k; seek(k * DURATION); };
  seekbar.addEventListener("pointerdown", (e) => { seekbar.setPointerCapture(e.pointerId); seekTo(e); seekbar.onpointermove = seekTo; });
  seekbar.addEventListener("pointerup", () => { seekbar.onpointermove = null; });
  seekbar.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight") seek(time + 5); else if (e.key === "ArrowLeft") seek(time - 5); else if (e.key === " ") { e.preventDefault(); toggle(); }
  });
  $("film-voice").addEventListener("click", (e) => { voiceOn = !voiceOn; e.currentTarget.classList.toggle("on", voiceOn); if (!voiceOn && window.speechSynthesis) speechSynthesis.cancel(); });
  $("film-subs").addEventListener("click", (e) => { subsOn = !subsOn; e.currentTarget.classList.toggle("on", subsOn); draw(); });
  $("film-export").addEventListener("click", exportVideo);
  $("film-full").addEventListener("click", () => { const f = $("film-player"); if (document.fullscreenElement) document.exitFullscreen(); else f.requestFullscreen && f.requestFullscreen(); });
  // pause when scrolled away
  new IntersectionObserver((entries) => { if (!entries[0].isIntersecting && playing && !recorder) stop(); }, { threshold: 0.15 }).observe(canvas);

  window.CS.onLang(buildChapters);
  buildChapters();
  draw();
  window.CSFilm = { seek, play, stop, draw, get time() { return time; } };
})();
