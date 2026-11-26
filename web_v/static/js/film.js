/* The explainer video: 86 seconds, eight scenes, drawn live on a canvas.
 *
 * - English narration: one continuous recorded track that is also the film's clock
 *   (falls back to the browser's speech voice if the track can't be loaded)
 * - English and Arabic subtitles burned in at the bottom, read from
 *   captions/en.vtt and captions/ar.vtt
 * - chapters, seeking, keyboard control, fullscreen
 * - "Export video" records the canvas to a .webm file (subtitles included)
 * - subtitles keep a readable size on screen at any player size (one language on small players),
 *   each line on its own soft plate, always above the controls
 * - touch: a tap shows the controls, a second tap plays or pauses, a double tap on a side skips 10 s
 * - a mini player keeps the film going in a corner when the visitor scrolls away
 * - "Continue from 0:42": the position is remembered between visits
 * - an ambient glow behind the frame takes its colours from the picture (off at low performance levels)
 */
(function () {
  "use strict";
  const { $, el, t, toast } = window.CS;
  const canvas = $("film-canvas");
  if (!canvas) return;
  const I18 = window.I18N;
  if (I18 && I18.en && I18.ar) {
    Object.assign(I18.en, { filmResume: "Continue from {t}", filmMiniBack: "Back to the film", filmMiniClose: "Close the mini player", filmMeta: "{d} · {n} chapters · English voice · Arabic and English subtitles" });
    Object.assign(I18.ar, { filmResume: "تابع من {t}", filmMiniBack: "العودة إلى الفيلم", filmMiniClose: "إغلاق المشغّل الصغير", filmMeta: "{d} · {n} فصول · تعليق صوتي بالإنجليزية · ترجمة عربية وإنجليزية" });
  }
  const ctx = canvas.getContext("2d");
  const W = 1280, H = 720, DURATION = 86;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const C = { cyan: "#22e8ff", violet: "#b46cff", pink: "#ff4fd8", green: "#3dffb0", red: "#ff4f6d", ink: "#e9f3ff", dim: "#7f8bb3", bg: "#07051a" };
  const CHAPTERS = [0, 7, 19.3, 30.3, 46.5, 57.9, 71.4, 79.7];

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
    const cw = canvas.clientWidth || W, chh = canvas.clientHeight || H;
    let showEn = !!en && ccMode !== "ar", showAr = !!ar && ccMode !== "en";
    // a small player shows one language, the page's own: two at that size can't both be read
    if (!recorder && cw < 640 && showEn && showAr) { if (document.documentElement.lang === "ar") showEn = false; else showAr = false; }
    if (!showEn && !showAr) return;
    // the type keeps about the same size on screen whatever the player's size (an export uses the base)
    const k = recorder ? 1 : clamp((W / cw) * 0.8, 1, 2.8);
    const size = Math.round(25 * k);
    // above the controls while they are shown (never in an exported video)
    const pl = document.getElementById("film-player"), ui = document.getElementById("film-ui");
    const lift = !recorder && pl && ui && !pl.classList.contains("mini") && (pl.classList.contains("ui") || !playing) ? ui.offsetHeight * (H / chh) : 0;
    const lines = [];
    if (showEn) wrapLines(en.text, size, false).forEach((l) => lines.push([l, false]));
    if (showAr) wrapLines(ar.text, size, true).forEach((l) => lines.push([l, true]));
    const lh = size * 1.55;
    let y = H - 26 * k - lift - lh * (lines.length - 1) - lh / 2;
    lines.forEach(([txt, rtl]) => { plate(txt, W / 2, y, size, rtl ? "#a5f6ff" : "#f5f9ff", rtl); y += lh; });
  }
  const subFont = (size) => `600 ${size}px "Segoe UI", Tahoma, sans-serif`;
  // at most two balanced lines per language; shrink only if even that is too wide
  function wrapLines(text, size, rtl) {
    ctx.save(); ctx.font = subFont(size); ctx.direction = rtl ? "rtl" : "ltr";
    const max = W - 180;
    let out = [text];
    if (ctx.measureText(text).width > max) {
      const w = text.split(" ");
      let best = null;
      for (let i = 1; i < w.length; i++) {
        const a = w.slice(0, i).join(" "), b = w.slice(i).join(" ");
        const m = Math.max(ctx.measureText(a).width, ctx.measureText(b).width);
        if (!best || m < best[0]) best = [m, a, b];
      }
      if (best) out = [best[1], best[2]];
    }
    ctx.restore();
    return out;
  }
  function plate(text, x, y, size, color, rtl) {
    ctx.save();
    ctx.font = subFont(size); ctx.direction = rtl ? "rtl" : "ltr";
    const max = W - 180, wd = ctx.measureText(text).width;
    if (wd > max) ctx.font = subFont(Math.floor(size * max / wd));
    const tw = Math.min(wd, max), padX = size * 0.5, padY = size * 0.28;
    ctx.fillStyle = "rgba(4, 2, 14, 0.62)";
    roundRect(x - tw / 2 - padX, y - size / 2 - padY, tw + padX * 2, size + padY * 2, size * 0.32); ctx.fill();
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillStyle = color; ctx.shadowColor = "rgba(0,0,0,0.9)"; ctx.shadowBlur = 6;
    ctx.fillText(text, x, y + size * 0.04);
    ctx.restore();
  }
  function wrapText(text, x, y, max, size, color, rtl, weight) {
    ctx.save();
    ctx.font = `${weight} ${size}px "Segoe UI", Tahoma, sans-serif`;
    ctx.direction = rtl ? "rtl" : "ltr";
    if (ctx.measureText(text).width > max) ctx.font = `${weight} ${Math.max(14, Math.floor(size * max / ctx.measureText(text).width))}px "Segoe UI", Tahoma, sans-serif`;
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillStyle = color;
    ctx.shadowColor = "rgba(0,0,0,0.9)"; ctx.shadowBlur = 6;
    ctx.fillText(text, x, y);
    ctx.restore();
  }

  /* ---------------- scenes ---------------- */
  const SCENES = [
    // timed to the narration (captions/voice/en.json): each line ends inside its own scene
    [0, 7, sceneIntro], [7, 19.3, sceneFile], [19.3, 30.3, sceneRead], [30.3, 46.5, sceneEngines],
    [46.5, 57.9, sceneVerdict], [57.9, 71.4, sceneRepair], [71.4, 79.7, scenePrivate], [79.7, 86, sceneEnd],
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
    const flip = s > 13.9;
    fileCard(x, 170, 300, 340, 1, flip ? "EXE" : "PDF", flip ? C.pink : C.cyan);
    glowText("invoice_2026.pdf.exe", x + 150, 545, 20, C.ink, { mono: true, blur: 8, weight: 600 });
    if (flip) glowText("…it's really a program", x + 150, 140, 20, C.pink, { alpha: ease((s - 13.9) / 0.6), blur: 14, weight: 600 });
    if (s > 14.8) {
      const k = ease((s - 14.8) / 0.8);
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
      const at = 31.3 + i * 1.6;   // each engine lights as the narrator names it
      const on = s >= at;
      const k = on ? ease((s - at) / 0.5) : 0;
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
    glowText("EXPLAINED · EN · العربية", tx + 470, H * 0.3 + 3 * 64 + 22, 15, C.cyan, { align: "right", mono: true, alpha: ease((p - 0.55) / 0.1), blur: 8, weight: 700 });
  }

  function sceneRepair(p, s) {
    const n = 40, bw = 18, gap = 4, total = n * (bw + gap), x0 = W / 2 - total / 2 - 90, y0 = H * 0.36;   // narrow enough to leave the vault its room
    const bad = (i) => i >= 26 && i < 33;
    const cut = ease((p - 0.25) / 0.3), close = ease((p - 0.55) / 0.2);
    const vx = W * 0.86, vy = H * 0.24;
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
    // what the viewer is looking at, until the cut
    const lab = ease(p / 0.08) * (1 - ease((p - 0.22) / 0.1));
    if (lab > 0) {
      glowText("YOUR FILE", x0, y0 - 28, 15, C.ink, { align: "left", mono: true, alpha: lab, blur: 0, weight: 700 });
      glowText("SUSPICIOUS PART", x0 + 29.5 * (bw + gap), y0 + 104, 15, C.red, { mono: true, alpha: lab, blur: 10, weight: 700 });
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
    // the narration says "it all happens on your computer": true of the apps, not of this website
    glowText("DESKTOP & ANDROID APPS: ON YOUR DEVICE", cx, cy + 186, 22, C.cyan, { mono: true, alpha: ease(p / 0.25), blur: 14, weight: 700 });
    glowText("THIS WEBSITE: CHECKED ON OUR SERVER, THEN DELETED", cx, cy + 220, 17, C.ink, { mono: true, alpha: ease((p - 0.08) / 0.25), blur: 10, weight: 600 });
    if (s > 76.6) glowText("NOT SURE?  IT SAYS SO.", cx, cy - 150, 26, C.violet, { mono: true, alpha: ease((s - 76.6) / 0.6), blur: 16, weight: 800 });
  }

  function sceneEnd(p, s) {
    logo(W / 2, H * 0.3, 2.6, 1);
    glowText("DROP A FILE TO BEGIN", W / 2, H * 0.52, 44, C.cyan, { core: "#eaffff", blur: 28, alpha: ease(p / 0.2) });
    const k = ease((p - 0.2) / 0.2), pulse = 0.6 + 0.4 * Math.sin(s * 4);
    ctx.save(); ctx.globalAlpha = k; ctx.strokeStyle = C.pink; ctx.lineWidth = 2; ctx.shadowColor = C.pink; ctx.shadowBlur = 20 * pulse;
    roundRect(W / 2 - 150, H * 0.6, 300, 56, 28); ctx.stroke(); ctx.restore();
    glowText("CYBERSCAN", W / 2, H * 0.6 + 29, 22, C.pink, { mono: true, alpha: k, blur: 14, weight: 800 });
    glowText("SEE BEYOND THE FILE", W / 2, H * 0.6 + 96, 16, C.dim, { mono: true, alpha: ease((p - 0.45) / 0.25), blur: 0, weight: 700 });
  }

  /* ---------------- the cinematic layer ----------------
   * Everything here is a function of the film's time, so seeking, replaying and exporting all
   * give the same frames. Lighter at low performance levels (js/performance/). */
  const lite = () => window.CSAdapt && CSAdapt.level >= 4;
  const sprite = (() => {
    const c = document.createElement("canvas"); c.width = c.height = 32;
    const x = c.getContext("2d"), g = x.createRadialGradient(16, 16, 0, 16, 16, 16);
    g.addColorStop(0, "rgba(255,255,255,1)"); g.addColorStop(0.3, "rgba(255,255,255,.4)"); g.addColorStop(1, "rgba(255,255,255,0)");
    x.fillStyle = g; x.fillRect(0, 0, 32, 32); return c;
  })();
  const DUST = Array.from({ length: 54 }, (_, i) => {
    const h = (k) => { const v = Math.sin(i * 12.9898 + k * 78.233) * 43758.5453; return v - Math.floor(v); };
    return { x: h(1), y: h(2), z: 0.25 + h(3) * 0.75, vx: (h(4) - 0.5) * 6, vy: 6 + h(5) * 14, tw: h(6) * 6.28, violet: h(7) > 0.6 };
  });
  function dust(s) {
    const n = lite() ? 20 : DUST.length;
    ctx.save(); ctx.globalCompositeOperation = "lighter";
    for (let i = 0; i < n; i++) {
      const d = DUST[i];
      const x = ((d.x * W + s * d.vx * d.z) % W + W) % W;
      const y = H - (((d.y * H + s * d.vy * d.z) % (H * 1.1)) + H * 1.1) % (H * 1.1);
      const r = 2 + d.z * 9;
      ctx.globalAlpha = (0.1 + 0.22 * d.z) * (0.6 + 0.4 * Math.sin(s * 1.3 + d.tw));
      ctx.filter = "none";
      ctx.drawImage(sprite, x - r, y - r, r * 2, r * 2);
      if (d.violet) { ctx.globalAlpha *= 0.5; ctx.drawImage(sprite, x - r * 1.8, y - r * 1.8, r * 3.6, r * 3.6); }
    }
    ctx.restore();
  }
  function sweep(s) {
    // a band of light crosses the frame for half a second after each cut
    for (let i = 1; i < CHAPTERS.length; i++) {
      const d = s - CHAPTERS[i];
      if (d < 0 || d > 0.6) continue;
      const k = d / 0.6, x = -260 + k * (W + 520);
      const g = ctx.createLinearGradient(x - 160, 0, x + 160, 0);
      g.addColorStop(0, "rgba(34,232,255,0)"); g.addColorStop(0.5, `rgba(190,240,255,${(0.22 * (1 - k)).toFixed(3)})`); g.addColorStop(1, "rgba(180,108,255,0)");
      ctx.save(); ctx.globalCompositeOperation = "lighter"; ctx.fillStyle = g; ctx.fillRect(x - 160, 0, 320, H); ctx.restore();
    }
  }
  let vignette = null, grain = null, grainPat = null, grainN = 0;
  function grade() {
    if (!vignette) {
      vignette = ctx.createRadialGradient(W / 2, H * 0.46, H * 0.35, W / 2, H * 0.5, H * 0.95);
      vignette.addColorStop(0, "rgba(0,0,0,0)"); vignette.addColorStop(1, "rgba(0,0,0,0.55)");
      grain = document.createElement("canvas"); grain.width = grain.height = 160;
      const gx = grain.getContext("2d"), img = gx.createImageData(160, 160);
      for (let i = 0; i < img.data.length; i += 4) { const v = Math.random() * 255; img.data[i] = img.data[i + 1] = img.data[i + 2] = v; img.data[i + 3] = 255; }
      gx.putImageData(img, 0, 0);
      grainPat = ctx.createPattern(grain, "repeat");
    }
    ctx.save(); ctx.fillStyle = vignette; ctx.fillRect(0, 0, W, H);
    if (!lite()) {
      grainN = (grainN + 1) % 8;                              // the grain shifts every frame, like film
      ctx.globalAlpha = 0.045; ctx.globalCompositeOperation = "overlay";
      ctx.translate((grainN * 37) % 160, (grainN * 71) % 160);
      ctx.fillStyle = grainPat; ctx.fillRect(-160, -160, W + 320, H + 320);
    }
    ctx.restore();
  }

  function draw() {
    // before the first play, show a frame where the logo is already drawn
    const poster = !playing && time === 0;
    const s = poster ? 5.4 : time;
    background(s);
    dust(s);
    SCENES.forEach(([a, b, fn]) => {
      // the last scene holds its card when the film ends instead of fading to an empty frame
      const fadeIn = clamp((s - a) / 0.6), fadeOut = b >= DURATION ? 1 : clamp((b - s) / 0.6);
      const alpha = Math.min(fadeIn, fadeOut);
      if (s < a - 0.01 || s > b + 0.01 || alpha <= 0) return;
      const pp = clamp((s - a) / (b - a));
      ctx.save(); ctx.globalAlpha = alpha;
      // a slow push in, as if a camera moved closer through the scene
      const z = 1 + 0.045 * pp;
      ctx.translate(W / 2, H * 0.42); ctx.scale(z, z); ctx.translate(-W / 2, -H * 0.42);
      fn(pp, s);
      ctx.restore();
    });
    sweep(s);
    grade();
    overlay(poster ? 0 : s);
    if (!poster) subtitles(s);
    updateUi();
    feedAmbient();
  }

  /* ---------------- narration ----------------
   * One continuous track, captions/voice/en-full.mp3, built from the recorded lines by
   * web_v/make_narration_track.py with every line at its exact start (verified against the
   * clips). It is the film's clock: while it plays, the picture and the subtitles read
   * audio.currentTime every frame, so voice and picture cannot drift, and seeking, pausing,
   * speed (pitch preserved) and volume all act on this single source. If the track can't be
   * loaded, the film falls back to its own clock and the browser's speech voice. */
  const audio = new Audio();
  audio.preload = "none";
  audio.preservesPitch = true; audio.mozPreservesPitch = true; audio.webkitPreservesPitch = true;
  let track = "unknown";                       // "unknown" | "loading" | "ok" | "failed"
  let rate = 1, waiting = false, trackLoad = null;
  /* The track is downloaded once and played from memory (a blob: URL). Seeking then works the same
   * everywhere, whether or not the server answers HTTP range requests. It starts when the film is
   * about a screen away, so pressing play is immediate. */
  function loadTrack() {
    if (trackLoad) return trackLoad;
    track = "loading";
    trackLoad = fetch("captions/voice/en.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)).then((meta) => {
      if (!meta || !meta.track || !meta.track.file) throw new Error("no track");
      return fetch(`captions/voice/${meta.track.file}`).then((r) => { if (!r.ok) throw new Error(r.status); return r.blob(); });
    }).then((blob) => {
      audio.src = URL.createObjectURL(blob); audio.preload = "auto"; audio.load();
      track = "ok"; return true;
    }).catch(() => { track = "failed"; return false; });
    return trackLoad;
  }
  audio.addEventListener("error", () => { if (track === "ok") { track = "failed"; if (playing) { last = performance.now(); } } });
  audio.addEventListener("waiting", () => { waiting = true; player.classList.add("loading"); });
  audio.addEventListener("playing", () => { waiting = false; player.classList.remove("loading"); });
  audio.addEventListener("ended", () => { if (playing) finish(); });
  const useTrack = () => track === "ok";

  // fallback narration: the browser's own voice, one line at a time
  let voice = null;
  function pickVoice() {
    const all = window.speechSynthesis ? speechSynthesis.getVoices() : [];
    const en = all.filter((v) => /^en[-_]/i.test(v.lang));
    const rank = (v) => (/natural/i.test(v.name) ? 0 : /online/i.test(v.name) ? 1 : /google/i.test(v.name) ? 2 : /aria|jenny|guy|ava|andrew|emma|brian/i.test(v.name) ? 3 : 5);
    voice = en.sort((a, b) => rank(a) - rank(b))[0] || null;
  }
  const forSpeech = (text) => text.replace("invoice_2026.pdf.exe", "invoice twenty twenty-six, dot P D F, dot E X E").replace(/YARA/g, "Yara").replace(/CyberScan/g, "Cyber Scan");
  if (window.speechSynthesis) { pickVoice(); speechSynthesis.onvoiceschanged = pickVoice; }
  function speak(s) {
    if (muted || !window.speechSynthesis || recorder) return;
    const cue = cues.en.find((c) => s >= c.start && s < c.start + 0.4 && !spoken.has(c.start));
    if (!cue) return;
    spoken.add(cue.start);
    const u = new SpeechSynthesisUtterance(forSpeech(cue.text));
    u.lang = voice ? voice.lang : "en-US"; if (voice) u.voice = voice;
    u.rate = rate; u.volume = volume;
    speechSynthesis.speak(u);
  }

  /* ---------------- playback ---------------- */
  const player = $("film-player");
  let volume = 1, muted = false;
  audio.hidden = true; audio.className = "film-audio"; player.append(audio);   // in the page, so it is inspectable and stays with the player
  function frame(now) {
    if (!playing) return;
    if (useTrack()) {
      time = audio.currentTime;
    } else {
      time += Math.min(0.1, (now - last) / 1000) * rate; last = now;
      speak(time);
    }
    if (time >= DURATION - 0.02) { finish(); return; }
    draw();
    raf = requestAnimationFrame(frame);
  }
  function play() {
    if (playing) return Promise.resolve(true);
    if (time >= DURATION - 0.05) seek(0);
    playing = true; last = performance.now();
    player.classList.add("playing");
    hideTap();
    // the visitor's own background music (if on) is ducked under the narration; the film never starts it
    if (window.CSSound && CSSound.on) CSSound.setDuck(0.25);
    raf = requestAnimationFrame(frame);
    emit("play");
    if (track === "unknown" || track === "loading") {
      // the picture waits for the voice: nothing starts until the narration is ready
      cancelAnimationFrame(raf); player.classList.add("loading");
      return loadTrack().then(() => { if (!playing) return false; playing = false; return play(); });
    }
    if (!useTrack()) return Promise.resolve(true);
    if (Math.abs(audio.currentTime - time) > 0.05) audio.currentTime = time;
    audio.playbackRate = rate;
    player.classList.add("loading");
    return audio.play().then(() => { player.classList.remove("loading"); return true; }).catch(() => {
      // the browser refused sound without a tap (autoplay policy): stop and ask for one
      player.classList.remove("loading");
      pause(); showTap();
      return false;
    });
  }
  function pause() {
    if (!playing) return;
    playing = false;
    cancelAnimationFrame(raf);
    if (useTrack()) { audio.pause(); time = audio.currentTime; }
    if (window.speechSynthesis) speechSynthesis.cancel();
    player.classList.remove("playing", "loading");
    window.CSSound && CSSound.setDuck(1);
    draw(); emit("pause");
  }
  function finish() {
    pause();
    time = DURATION; draw(); finishExport(); emit("ended");
  }
  function seek(s) {
    time = clamp(s, 0, DURATION);
    if (useTrack()) audio.currentTime = time;                 // voice and picture move together
    if (window.speechSynthesis) speechSynthesis.cancel();
    spoken = new Set(cues.en.filter((c) => c.start < time - 0.2).map((c) => c.start));
    draw(); emit("seek");
  }
  function emit(state) { window.dispatchEvent(new CustomEvent("cs:film", { detail: { state, time } })); }
  const stop = pause;

  /* ---------------- interface ---------------- */
  const fmt = (s) => { s = Math.max(0, s); return `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`; };
  const CH_END = CHAPTERS.slice(1).concat([DURATION]);
  let lastCh = -1;
  function chapterAt(s) { return Math.max(0, CHAPTERS.filter((c) => c <= s + 0.01).length - 1); }
  function updateUi() {
    const k = time / DURATION;   // the time axis runs left to right in every language (as in the control bar)
    $("film-fill").style.transform = `scaleX(${k})`;
    $("film-knob").style.left = `${k * 100}%`;
    $("film-cur").textContent = fmt(time);
    $("film-left").textContent = `−${fmt(DURATION - time)}`;
    const seekbar = $("film-seek");
    seekbar.setAttribute("aria-valuenow", String(Math.round(time)));
    seekbar.setAttribute("aria-valuetext", `${fmt(time)} / ${fmt(DURATION)}`);
    const ch = chapterAt(time);
    chapItems.forEach((li, i) => {
      const p = clamp((time - CHAPTERS[i]) / (CH_END[i] - CHAPTERS[i]));
      li.fill.style.transform = `scaleX(${p})`;
      if (i === ch) { if (!li.classList.contains("on")) { li.classList.add("on"); li.btn.setAttribute("aria-current", "true"); } }
      else if (li.classList.contains("on")) { li.classList.remove("on"); li.btn.removeAttribute("aria-current"); }
      li.classList.toggle("done", i < ch);
    });
    if (ch !== lastCh) { lastCh = ch; chapterChanged(ch); }
  }
  // the area around the film follows the scene: chapter card, accent colour, a short transition
  const ACCENT = ["#22e8ff", "#ff4f6d", "#22e8ff", "#b46cff", "#ffb347", "#3dffb0", "#22e8ff", "#ff4fd8"];
  function chapterChanged(ch) {
    const names = t("filmChapters"), desc = t("filmChapDesc") || [];
    $("cine-idx").textContent = `${String(ch + 1).padStart(2, "0")} / ${String(CHAPTERS.length).padStart(2, "0")}`;
    $("cine-name").textContent = names[ch] || "";
    $("cine-desc").textContent = desc[ch] || "";
    const sec = $("film");
    sec.style.setProperty("--cine-accent", ACCENT[ch % ACCENT.length]);
    const info = $("cine-info");
    info.classList.remove("swap"); void info.offsetWidth; info.classList.add("swap");
    player.classList.remove("cut"); void player.offsetWidth; if (playing) player.classList.add("cut");
    // a scrollable chapter strip (phones) keeps the current chapter in view, without moving the page
    const strip = $("film-chaps"), li = chapItems[ch];
    if (li && strip.scrollWidth > strip.clientWidth + 2) strip.scrollTo({ left: li.offsetLeft - (strip.clientWidth - li.offsetWidth) / 2, behavior: "smooth" });
  }

  let chapItems = [];
  function buildChapters() {
    const names = t("filmChapters");
    $("film-ticks").replaceChildren(...CHAPTERS.slice(1).map((c) => { const i = el("i"); i.style.left = `${(c / DURATION) * 100}%`; return i; }));
    chapItems = CHAPTERS.map((c, i) => {
      const len = CH_END[i] - c;
      const li = el("li");
      li.style.flexGrow = String(len);
      const b = el("button");
      b.type = "button";
      const fill = el("i", "cine-seg-fill");
      // the button's name is its visible text ("Intro 0:00 · 7s"; the space is a grid gap on screen),
      // so what a screen reader announces and what a voice-control user reads are the same words
      b.append(el("span", "cine-seg-bar"), el("span", "cine-seg-name", names[i]), " ", el("span", "cine-seg-len", `${fmt(c)} · ${Math.round(len)}s`));
      b.querySelector(".cine-seg-bar").append(fill);
      b.addEventListener("click", () => { seek(c); if (!playing) play(); });
      li.append(b); li.btn = b; li.fill = fill;
      return li;
    });
    $("film-chaps").replaceChildren(...chapItems);
    lastCh = -1;
    updateUi();
  }

  /* captions: both languages, one, or none (burned into the picture, so exported videos keep them) */
  let ccMode = "both";
  try { ccMode = localStorage.getItem("cs-film-cc") || "both"; } catch { /* storage off */ }
  subsOn = ccMode !== "off";
  const CC = ["both", "en", "ar", "off"];
  function buildCc() {
    const menu = $("film-cc-menu");
    menu.replaceChildren(...CC.map((m) => {
      const b = el("button", "", t(`filmCc_${m}`));
      b.type = "button"; b.setAttribute("role", "menuitemradio"); b.setAttribute("aria-checked", String(m === ccMode));
      b.addEventListener("click", () => { ccMode = m; subsOn = m !== "off"; try { localStorage.setItem("cs-film-cc", m); } catch { /* storage off */ } buildCc(); closeCc(); draw(); });
      return b;
    }));
    $("film-cc").classList.toggle("on", ccMode !== "off");
  }
  function closeCc() { $("film-cc-menu").hidden = true; $("film-cc").setAttribute("aria-expanded", "false"); }
  $("film-cc").addEventListener("click", (e) => { e.stopPropagation(); const m = $("film-cc-menu"); m.hidden = !m.hidden; $("film-cc").setAttribute("aria-expanded", String(!m.hidden)); if (!m.hidden) m.querySelector("[aria-checked=true]").focus(); });
  document.addEventListener("click", (e) => { if (!e.target.closest(".film-pop-wrap")) closeCc(); });
  $("film-cc-menu").addEventListener("keydown", (e) => { if (e.key === "Escape") { closeCc(); $("film-cc").focus(); } });

  /* speed: 0.75× – 1.5×, pitch preserved */
  const SPEEDS = [0.75, 1, 1.25, 1.5];
  $("film-speed").addEventListener("click", () => {
    rate = SPEEDS[(SPEEDS.indexOf(rate) + 1) % SPEEDS.length];
    audio.playbackRate = rate;
    $("film-speed").textContent = `${rate}×`;
    nameButtons();
  });

  /* volume and mute (iOS ignores volume: the slider hides there, mute still works) */
  const vol = $("film-volume");
  function applyVolume() {
    audio.volume = volume; audio.muted = muted;
    vol.value = String(muted ? 0 : volume);
    $("film-mute").setAttribute("aria-pressed", String(muted));
    player.classList.toggle("muted", muted);
  }
  function setVolume(v) { volume = clamp(v); muted = volume === 0; applyVolume(); }
  vol.addEventListener("input", () => { const v = Number(vol.value); if (v === 0) { muted = true; applyVolume(); } else setVolume(v); });
  $("film-mute").addEventListener("click", () => { muted = !muted; if (!muted && volume === 0) volume = 0.8; applyVolume(); if (muted && window.speechSynthesis) speechSynthesis.cancel(); });
  audio.volume = 0.5; if (audio.volume !== 0.5) player.classList.add("no-volume"); audio.volume = 1;

  /* controls appear when needed: on pointer movement, focus or pause; touch keeps them reachable */
  let hideTimer = 0;
  function showUi() {
    const was = player.classList.contains("ui");
    player.classList.add("ui");
    if (!was && !playing) draw();
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => { if (playing && !player.contains(document.activeElement) && $("film-cc-menu").hidden) player.classList.remove("ui"); }, 2600);
  }
  ["pointermove", "pointerdown", "focusin"].forEach((ev) => player.addEventListener(ev, showUi));
  window.addEventListener("cs:film", showUi);

  function showTap() { $("film-tap").hidden = false; player.classList.add("needs-tap"); }
  function hideTap() { $("film-tap").hidden = true; player.classList.remove("needs-tap"); }

  /* ---------------- export (kept: the canvas and the narration track are recorded together) ---------------- */
  let recDest = null, actx = null;
  function exportVideo() {
    if (recorder) return;
    if (!canvas.captureStream || !window.MediaRecorder) { toast(t("filmNoExport")); return; }
    const chunks = [];
    const stream = canvas.captureStream(30);
    if (useTrack()) {
      try {
        if (!actx) {
          actx = new (window.AudioContext || window.webkitAudioContext)();
          const src = actx.createMediaElementSource(audio);
          recDest = actx.createMediaStreamDestination();
          src.connect(actx.destination); src.connect(recDest);
        }
        actx.resume();
        recDest.stream.getAudioTracks().forEach((tr) => stream.addTrack(tr));
      } catch { /* video only */ }
    }
    const withAudio = stream.getAudioTracks().length > 0;
    const type = (withAudio ? ["video/webm;codecs=vp9,opus", "video/webm;codecs=vp8,opus"] : []).concat(["video/webm;codecs=vp9", "video/webm;codecs=vp8", "video/webm"]).find((m) => MediaRecorder.isTypeSupported(m));
    recorder = new MediaRecorder(stream, { mimeType: type, videoBitsPerSecond: 6_000_000, audioBitsPerSecond: 128_000 });
    recorder.ondataavailable = (e) => { if (e.data.size) chunks.push(e.data); };
    recorder.onstop = () => {
      const url = URL.createObjectURL(new Blob(chunks, { type: "video/webm" }));
      const a = el("a"); a.href = url; a.download = "cyberscan-explainer.webm"; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      recorder = null; player.classList.remove("exporting"); toast(t("filmExported"));
    };
    pause(); seek(0); rate = 1; audio.playbackRate = 1; $("film-speed").textContent = "1×"; nameButtons();
    player.classList.add("exporting"); toast(t("filmExporting"));
    recorder.start(1000);
    play();
  }
  function finishExport() { if (recorder && recorder.state === "recording") recorder.stop(); }

  /* ---------------- controls ---------------- */
  const toggle = () => (playing ? pause() : play());
  $("film-play").addEventListener("click", toggle);
  $("film-big").addEventListener("click", toggle);
  $("film-tap").addEventListener("click", () => play());
  // mouse: a click plays or pauses. Touch: the first tap only shows the controls; with them shown,
  // a tap plays or pauses, and a double tap on the left or right third skips 10 s back or forward
  let pType = "mouse", uiBefore = false, lastTap = 0, lastX = 0, tapTimer = 0;
  canvas.addEventListener("pointerdown", (e) => { pType = e.pointerType; uiBefore = player.classList.contains("ui"); });
  canvas.addEventListener("click", (e) => {
    if (player.classList.contains("mini")) { backToFilm(); return; }
    if (pType !== "touch") { toggle(); return; }
    const r = canvas.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, now = performance.now();
    if (now - lastTap < 320 && Math.abs(x - lastX) < 0.2 && (x < 0.34 || x > 0.66)) {
      clearTimeout(tapTimer); lastTap = 0;
      const fwd = x > 0.5;                              // the time axis runs left to right in every language
      seek(time + (fwd ? 10 : -10)); skipFlash(fwd); return;
    }
    lastTap = now; lastX = x;
    if (playing && !uiBefore) return;
    clearTimeout(tapTimer); tapTimer = setTimeout(toggle, 280);
  });
  const frameBox = player.querySelector(".film-frame");
  const skipEl = el("div", "film-skip"); skipEl.setAttribute("aria-hidden", "true"); frameBox.append(skipEl);
  function skipFlash(fwd) {
    skipEl.textContent = fwd ? "+10" : "−10";
    skipEl.classList.toggle("fwd", fwd); skipEl.classList.remove("go"); void skipEl.offsetWidth; skipEl.classList.add("go");
  }

  /* the poster's line under the play button: length, chapters, voice and subtitles */
  const meta = el("p", "film-meta");
  frameBox.append(meta);
  const paintMeta = () => { meta.textContent = t("filmMeta").replace("{d}", fmt(DURATION)).replace("{n}", String(CHAPTERS.length)); };
  paintMeta();
  // "ended": the end card stays readable (no big button over it; replay from the bar or the frame)
  const fresh = (e) => { player.classList.toggle("fresh", !playing && time < 0.05); if (e && e.detail) player.classList.toggle("ended", e.detail.state === "ended"); };
  window.addEventListener("cs:film", fresh); fresh();

  /* "Continue from 0:42": the position is kept between visits, and offered once */
  const POS = "cs-film-pos";
  let savedPos = 0;
  try { savedPos = Number(localStorage.getItem(POS)) || 0; } catch { /* storage off */ }
  const resume = el("button", "film-resume"); resume.type = "button"; resume.hidden = true;
  frameBox.append(resume);
  const paintResume = () => { resume.textContent = t("filmResume").replace("{t}", fmt(savedPos)); };
  paintResume();                                      // always named, even before it is offered
  if (savedPos > 4 && savedPos < DURATION - 4) resume.hidden = false;
  resume.addEventListener("click", (e) => { e.stopPropagation(); resume.hidden = true; seek(savedPos); play(); });
  window.addEventListener("cs:film", (e) => { if (e.detail.state === "play") resume.hidden = true; if (e.detail.state === "ended") { try { localStorage.removeItem(POS); } catch { /* storage off */ } } });
  setInterval(() => { if (playing && time > 4 && time < DURATION - 4) { try { localStorage.setItem(POS, time.toFixed(1)); } catch { /* storage off */ } } }, 2000);

  /* the mini player: scrolling away while the film plays keeps it going in a corner */
  const miniBar = el("div", "film-mini-bar");
  const miniBtn = (cls, label, svg, fn) => { const b = el("button", `film-btn icon ${cls}`); b.type = "button"; b.setAttribute("aria-label", label); b.title = label; b.innerHTML = svg; b.addEventListener("click", (e) => { e.stopPropagation(); fn(); }); return b; };
  const ICON_BACK = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 15v5h-5M4 4l6 6M20 20l-6-6"/></svg>';
  const ICON_X = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"/></svg>';
  const ICON_PP = '<svg viewBox="0 0 24 24" aria-hidden="true"><path class="i-play" d="M8 5v14l11-7z"/><path class="i-pause" d="M7 5h4v14H7zM13 5h4v14h-4z"/></svg>';
  const bPP = miniBtn("film-mini-pp", "", ICON_PP, toggle);
  const bBack = miniBtn("film-mini-back", "", ICON_BACK, () => backToFilm());
  const bClose = miniBtn("film-mini-close", "", ICON_X, () => { miniClosed = true; pause(); setMini(false); });
  miniBar.append(bPP, bBack, bClose);
  frameBox.append(miniBar);
  const paintMini = () => { const pp = t(playing ? "ariaPause" : "ariaPlay"); bPP.setAttribute("aria-label", pp); bPP.title = pp; bBack.setAttribute("aria-label", t("filmMiniBack")); bBack.title = t("filmMiniBack"); bClose.setAttribute("aria-label", t("filmMiniClose")); bClose.title = t("filmMiniClose"); };
  paintMini();
  let miniClosed = false;
  window.addEventListener("cs:film", (e) => { if (e.detail.state === "play") miniClosed = false; paintMini(); });
  function setMini(on) {
    if (on === player.classList.contains("mini")) return;
    if (on) player.style.minHeight = `${player.offsetHeight}px`;        // the page keeps its place
    player.classList.toggle("mini", on);
    if (!on) player.style.minHeight = "";
    draw();
  }
  function backToFilm() { player.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" }); }

  /* the ambient glow: a tiny copy of the picture, blurred behind the frame */
  const ambi = el("canvas", "film-ambi"); ambi.width = 32; ambi.height = 18; ambi.setAttribute("aria-hidden", "true");
  player.prepend(ambi);
  const actx2 = ambi.getContext("2d");
  let ambiAt = 0;
  const ambiOn = () => !window.CSAdapt || (CSAdapt.level <= 3 && CSAdapt.budget("css").lighting !== "flat");
  function feedAmbient() {
    if (!ambiOn()) { player.classList.add("no-ambi"); return; }
    player.classList.remove("no-ambi");
    const now = performance.now();
    if (now - ambiAt < 200) return;
    ambiAt = now; actx2.drawImage(canvas, 0, 0, 32, 18);
  }
  const seekbar = $("film-seek");
  const posToTime = (e) => { const r = seekbar.getBoundingClientRect(); return clamp((e.clientX - r.left) / r.width) * DURATION; };
  const peek = $("film-peek");
  seekbar.addEventListener("pointermove", (e) => {
    const s = posToTime(e), r = seekbar.getBoundingClientRect();
    peek.hidden = false; peek.textContent = `${fmt(s)} · ${t("filmChapters")[chapterAt(s)] || ""}`;
    peek.style.left = `${clamp((e.clientX - r.left) / r.width) * 100}%`;
  });
  seekbar.addEventListener("pointerleave", () => { peek.hidden = true; });
  seekbar.addEventListener("pointerdown", (e) => { seekbar.setPointerCapture(e.pointerId); seek(posToTime(e)); seekbar.onpointermove = (ev) => seek(posToTime(ev)); });
  seekbar.addEventListener("pointerup", () => { seekbar.onpointermove = null; });
  const keys = (e) => {
    if (e.target.closest && e.target.closest("input, .film-pop")) return;
    const k = e.key.toLowerCase(), back = "arrowleft";
    if (k === " " || k === "k") { e.preventDefault(); toggle(); }
    else if (k === "arrowright" || k === "arrowleft") { e.preventDefault(); seek(time + (k === back ? -5 : 5)); }
    else if ((k === "home" || k === "end") && e.target === seekbar) { e.preventDefault(); seek(k === "home" ? 0 : DURATION - 0.05); }
    else if ((k === "pageup" || k === "pagedown") && e.target === seekbar) { e.preventDefault(); seek(time + (k === "pageup" ? 10 : -10)); }
    else if (k === "arrowup" || k === "arrowdown") { e.preventDefault(); setVolume(volume + (k === "arrowup" ? 0.1 : -0.1)); }
    else if (k === "m") $("film-mute").click();
    else if (k === "c") { ccMode = CC[(CC.indexOf(ccMode) + 1) % CC.length]; subsOn = ccMode !== "off"; buildCc(); draw(); }
    else if (k === "f") $("film-full").click();
    else return;
    showUi();
  };
  player.addEventListener("keydown", keys);
  $("film-export").addEventListener("click", exportVideo);
  $("film-full").addEventListener("click", () => {
    if (document.fullscreenElement || document.webkitFullscreenElement) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
    else if (player.requestFullscreen) player.requestFullscreen();
    else if (player.webkitRequestFullscreen) player.webkitRequestFullscreen();
    else if (canvas.webkitEnterFullscreen) canvas.webkitEnterFullscreen();
  });
  // leaving the film pauses it (not while exporting, and not while the guided journey holds it on screen)
  new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) { setMini(false); return; }
    if (!playing || recorder || document.body.classList.contains("touring") || document.fullscreenElement) return;
    if (miniClosed) pause(); else setMini(true);
  }, { threshold: 0.15 }).observe(player);
  document.addEventListener("visibilitychange", () => { if (document.hidden && playing && !recorder) pause(); });
  // the 1 MB narration is fetched only when someone shows they want the film: a pointer over the
  // play button, keyboard focus on it, or the first press of play (play() waits for it)
  // (a pointer that merely passes over the button while the page scrolls doesn't count: it has to rest there)
  let warmT = 0;
  const warm = () => loadTrack();
  ["film-big", "film-play"].forEach((id) => {
    const b = $(id); if (!b) return;
    b.addEventListener("pointerenter", () => { clearTimeout(warmT); warmT = setTimeout(warm, 400); });
    b.addEventListener("pointerleave", () => clearTimeout(warmT));
    addEventListener("scroll", () => clearTimeout(warmT), { passive: true });
    b.addEventListener("focus", warm, { once: true });
  });

  /* ---------------- cinematic entrance (scroll drives the presentation, never the film's time) ---------------- */
  (function entrance() {
    const sec = $("film");
    const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");
    if (!sec || still()) { sec && sec.classList.add("cine-still"); return; }
    sec.classList.add("cine-js");
    const head = sec.querySelector(".cine-head"), frameEl = sec.querySelector(".film-frame"), corners = [...sec.querySelectorAll(".cine-corners path")];
    const info = $("cine-info"), line = $("film-chaps"), glow = sec;
    const ease3 = (x) => 1 - Math.pow(1 - clamp(x), 3);
    let ticking = false, visible = false;
    function render() {
      ticking = false;
      if (!visible) return;
      const r = sec.getBoundingClientRect();
      // 0 when the section's top reaches the bottom of the screen, 1 when it is near the top
      const p = clamp((innerHeight - r.top) / (innerHeight * 0.85));
      const e = ease3((p - 0.12) / 0.75), h = ease3(p / 0.5);
      head.style.opacity = h.toFixed(3);
      head.style.transform = `translateY(${((1 - h) * 40).toFixed(1)}px)`;
      frameEl.style.opacity = clamp(e * 1.4).toFixed(3);
      frameEl.style.transform = `perspective(1400px) rotateX(${((1 - e) * 24).toFixed(2)}deg) scale(${(0.8 + 0.2 * e).toFixed(4)}) translateY(${((1 - e) * 60).toFixed(1)}px)`;
      corners.forEach((c, i) => { c.style.strokeDashoffset = (1 - ease3((p - 0.45 - i * 0.04) / 0.4)).toFixed(4); });
      const u = ease3((p - 0.55) / 0.4);
      info.style.opacity = u.toFixed(3); info.style.transform = `translateY(${((1 - u) * 24).toFixed(1)}px)`;
      line.style.opacity = u.toFixed(3); line.style.transform = `translateY(${((1 - u) * 30).toFixed(1)}px)`;
      glow.style.setProperty("--cine-glow", e.toFixed(3));
    }
    const schedule = () => { if (!ticking) { ticking = true; requestAnimationFrame(render); } };
    new IntersectionObserver((es) => { visible = es[0].isIntersecting; schedule(); }, { rootMargin: "30% 0px" }).observe(sec);
    addEventListener("scroll", schedule, { passive: true });
    addEventListener("resize", schedule, { passive: true });
    render();
  })();

  // the speed and subtitle buttons show "1×" and "CC": their names contain those words too
  function nameButtons() {
    const sp = $("film-speed"), cc = $("film-cc");
    if (sp) sp.setAttribute("aria-label", `${t("filmSpeed") || "Playback speed"} ${sp.textContent}`);
    if (cc) cc.setAttribute("aria-label", `${t("filmSubs") || "Subtitles"} ${cc.textContent}`);
  }
  nameButtons();
  window.CS.onLang(() => { nameButtons(); buildChapters(); buildCc(); chapterChanged(chapterAt(time)); paintMeta(); paintMini(); paintResume(); draw(); });
  buildChapters();
  buildCc();
  draw();
  // for the guided journey (js/tour.js)
  window.CSFilm = {
    play, pause, seek, draw, DURATION,
    get time() { return time; }, get playing() { return playing; },
    unlock() {   // called inside the journey's click: lets the browser play the narration later
      loadTrack();
      if (!useTrack()) return;
      audio.muted = true;
      const p = audio.play();
      if (p && p.then) p.then(() => { audio.pause(); audio.currentTime = time; audio.muted = muted; }).catch(() => { audio.muted = muted; });
    },
  };
})();
