/* The pinned scroll story: one file, scanned, cut, sealed and rebuilt.
 *
 * Scrolling through #story drives a single progress value p (0..1) that is
 * eased every frame. Five acts of 0.2 each:
 *   0 the file floats as a page of cells
 *   1 the cells fly into byte order
 *   2 a beam sweeps them; three regions light up red with labels
 *   3 the red cells are sealed into an encrypted vault
 *   4 what is left reassembles as a smaller, healthy page
 */
(function () {
  "use strict";
  const { $, el, t } = window.CS;
  const section = $("story");
  const canvas = $("story-canvas");
  const ctx = canvas.getContext("2d");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const DOC_COLS = 16, DOC_ROWS = 20, N = DOC_COLS * DOC_ROWS;
  const GRID_COLS = 32;
  const REGIONS = [
    { from: 0, to: 9 },        // disguised name, in the header
    { from: 150, to: 172 },    // encoded PowerShell, mid-file
    { from: 284, to: N },      // data after the end
  ];
  const regionOf = (i) => REGIONS.findIndex((r) => i >= r.from && i < r.to);

  const cells = [];
  for (let i = 0; i < N; i++) {
    const tt = i / N;
    let e = tt < 0.05 ? 2.2 + Math.random() * 0.8 : tt < 0.45 ? 5.4 + Math.random() * 0.9 : tt < 0.85 ? 3.2 + Math.random() * 1.6 : 7.4 + Math.random() * 0.5;
    cells.push({ i, e, region: regionOf(i), rgb: CyberCube.entropyColor(e), seed: Math.random(), x: 0, y: 0 });
  }
  const kept = cells.filter((c) => c.region < 0);

  let W = 0, H = 0, dpr = 1, stage = null, size = 10;
  let target = 0, p = 0, raf = 0, visible = false;

  const ease = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const lerp = (a, b, x) => a + (b - a) * x;
  const rtl = () => document.documentElement.dir === "rtl";

  function layout() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const wide = W > 900;
    stage = wide
      ? { x: rtl() ? 0 : W * 0.4, y: 0, w: W * 0.6, h: H }
      : { x: 0, y: H * 0.04, w: W, h: H * 0.56 };
    size = Math.min((stage.w * 0.86) / GRID_COLS, (stage.h * 0.62) / DOC_ROWS * 1.0);
  }

  const gap = () => size * 0.18;
  function docPos(index, cols, rows) {
    const s = size * 1.02;
    const w = cols * s, h = rows * s;
    const cx = stage.x + stage.w / 2, cy = stage.y + stage.h / 2 + size;
    const col = index % cols, row = Math.floor(index / cols);
    return [cx - w / 2 + col * s, cy - h / 2 + row * s];
  }
  function gridPos(index) {
    const rows = Math.ceil(N / GRID_COLS);
    const s = size;
    const w = GRID_COLS * s, h = rows * s;
    const cx = stage.x + stage.w / 2, cy = stage.y + stage.h / 2;
    const col = rtl() ? GRID_COLS - 1 - (index % GRID_COLS) : index % GRID_COLS;
    return [cx - w / 2 + col * s, cy - h / 2 + Math.floor(index / GRID_COLS) * s];
  }
  function vaultPos() {
    return [stage.x + stage.w * (rtl() ? 0.16 : 0.84), stage.y + stage.h * 0.2];
  }
  // the folded corner of the page: skip a little triangle at the top right
  const folded = (index) => { const c = index % DOC_COLS, r = Math.floor(index / DOC_COLS); return c - (DOC_COLS - 4) > r; };

  function act(n) { return clamp((p - n * 0.2) / 0.2); }

  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }

  function draw(now) {
    ctx.clearRect(0, 0, W, H);
    const a1 = act(1), a2 = act(2), a3 = act(3), a4 = act(4);
    const s = size - gap();
    const gridW = GRID_COLS * size;
    const grid0 = [stage.x + stage.w / 2 - gridW / 2, gridPos(0)[1]];
    const beamX = grid0[0] - size * 2 + (gridW + size * 4) * (rtl() ? 1 - a2 : a2);
    const [vx, vy] = vaultPos();
    const keptIndex = new Map(kept.map((c, k) => [c.i, k]));
    const newRows = Math.ceil(kept.length / DOC_COLS);
    let flagged = 0;

    // stage glow
    const glow = ctx.createRadialGradient(stage.x + stage.w / 2, stage.y + stage.h / 2, 0, stage.x + stage.w / 2, stage.y + stage.h / 2, Math.max(stage.w, stage.h) * 0.55);
    const healthy = a4;
    glow.addColorStop(0, `rgba(${lerp(56, 52, healthy) | 0},${lerp(189, 211, healthy) | 0},${lerp(248, 153, healthy) | 0},0.10)`);
    glow.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = glow;
    ctx.fillRect(stage.x, stage.y, stage.w, stage.h);

    // vault
    const vaultIn = clamp((p - 0.52) / 0.1) * (1 - clamp((p - 0.92) / 0.08) * 0.6);
    if (vaultIn > 0) drawVault(vx, vy, vaultIn, a3, now);

    for (const c of cells) {
      if (c.region >= 0 ? false : folded(c.i) && a1 < 0.05) continue;
      // positions for each act
      const [dx, dy] = docPos(c.i, DOC_COLS, DOC_ROWS);
      const [gx, gy] = gridPos(c.i);
      const stagger = c.seed * 0.45;
      const t1 = ease(clamp((a1 - stagger * 0.8) / 0.55));
      let x = lerp(dx, gx, t1), y = lerp(dy, gy, t1) - Math.sin(t1 * Math.PI) * size * 6 * (c.seed - 0.3);
      const float = Math.sin(now / 900 + c.i * 0.15) * size * 0.12 * (1 - t1);
      y += float;
      let alpha = 1, scale = 1;
      let rgb = [lerp(71, c.rgb[0], t1), lerp(85, c.rgb[1], t1), lerp(105, c.rgb[2], t1)];
      let red = 0;

      if (c.region >= 0) {
        const passed = rtl() ? gx + s / 2 >= beamX : gx + s / 2 <= beamX;
        if (passed && a2 > 0) { red = 1; flagged++; }
        if (a3 > 0) {
          const t3 = ease(clamp((a3 - c.seed * 0.5) / 0.5));
          x = lerp(gx, vx - s / 2, t3) + Math.sin(t3 * Math.PI) * size * 4 * (c.seed - 0.5);
          y = lerp(gy, vy - s / 2, t3) - Math.sin(t3 * Math.PI) * size * 5;
          scale = lerp(1, 0.2, t3);
          alpha = 1 - clamp((t3 - 0.85) / 0.15);
        }
        if (red) {
          const pulse = 0.7 + 0.3 * Math.sin(now / 180 + c.i);
          rgb = [248, 90 + 30 * pulse, 90];
        }
      } else if (a4 > 0) {
        const k = keptIndex.get(c.i);
        const [rx, ry] = docPos(k, DOC_COLS, newRows);
        const t4 = ease(clamp((a4 - c.seed * 0.4) / 0.6));
        x = lerp(gx, rx, t4); y = lerp(gy, ry, t4) - Math.sin(t4 * Math.PI) * size * 4 * (c.seed - 0.4);
        rgb = [lerp(rgb[0], 52, t4 * 0.65), lerp(rgb[1], 211, t4 * 0.65), lerp(rgb[2], 153, t4 * 0.65)];
      }
      if (alpha <= 0.01) continue;
      const ss = s * scale;
      if (red && a3 < 0.9) {
        ctx.fillStyle = `rgba(248,113,113,${0.18 * alpha})`;
        ctx.fillRect(x - ss * 0.5, y - ss * 0.5, ss * 2, ss * 2);
      }
      ctx.globalAlpha = alpha * (0.55 + 0.45 * (c.e / 8));
      ctx.fillStyle = `rgb(${rgb[0] | 0},${rgb[1] | 0},${rgb[2] | 0})`;
      roundRect(x, y, ss, ss, Math.min(3, ss * 0.25));
      ctx.fill();
      ctx.globalAlpha = 1;
    }

    // the scanning beam
    if (a2 > 0 && a2 < 1) {
      const bh = Math.ceil(N / GRID_COLS) * size + size * 6;
      const by = grid0[1] - size * 3;
      const g = ctx.createLinearGradient(beamX - 60, 0, beamX + 4, 0);
      g.addColorStop(0, "rgba(56,189,248,0)");
      g.addColorStop(1, "rgba(125,211,252,0.35)");
      ctx.fillStyle = g;
      if (rtl()) { ctx.save(); ctx.translate(beamX * 2, 0); ctx.scale(-1, 1); }
      ctx.fillRect(beamX - 60, by, 64, bh);
      if (rtl()) ctx.restore();
      ctx.fillStyle = "rgba(186,230,253,0.95)";
      ctx.shadowColor = "#38bdf8"; ctx.shadowBlur = 18;
      ctx.fillRect(beamX - 1, by, 2, bh);
      ctx.shadowBlur = 0;
    }

    // region labels
    if (a2 > 0 && a3 < 0.6) {
      const tags = t("storyTags");
      REGIONS.forEach((r, k) => {
        const mid = Math.floor((r.from + r.to) / 2);
        const [mx, my] = gridPos(mid);
        const passed = rtl() ? mx >= beamX : mx <= beamX;
        if (!passed) return;
        const fade = 1 - clamp(a3 / 0.4);
        drawTag(tags[k], mx + size / 2, my - size * (k === 1 ? 3 : 2.4) - (k === 1 ? 0 : size * 1.4), mx + size / 2, my, fade);
      });
    }

    // filename before, healed label after
    const nameFade = 1 - clamp(a1 / 0.25);
    if (nameFade > 0) {
      const [x0, y0] = docPos(0, DOC_COLS, DOC_ROWS);
      drawFileLabel("invoice_2026.pdf.exe", x0, y0 - size * 2.2, nameFade, "#c4b5fd");
    }
    if (a4 > 0.55) {
      const fade = clamp((a4 - 0.55) / 0.3);
      const [x0, y0] = docPos(0, DOC_COLS, newRows);
      drawFileLabel(t("storyHealed") + " ✓", x0, y0 - size * 2.2, fade, "#6ee7b7");
      drawCheck(stage.x + stage.w / 2, docPos(kept.length - 1, DOC_COLS, newRows)[1] + size * 3.4, fade);
    }

    // HUD
    const score = Math.round(a4 > 0 ? 87 * (1 - ease(a4)) : 87 * ease(a2));
    $("hud-cells").textContent = String(a3 > 0 ? Math.round(N - (N - kept.length) * ease(a3)) : Math.round(N * clamp(a1 * 1.4)));
    $("hud-bad").textContent = String(a3 > 0 ? Math.round(flagged * (1 - a3)) : flagged);
    $("hud-score").textContent = String(score);
    $("story-meter").style.transform = `scaleX(${p})`;
    const step = Math.min(4, Math.floor(p * 5 + 0.0001));
    $("story-steps").querySelectorAll(".sstep").forEach((n, k) => n.classList.toggle("on", k === step));
    section.style.setProperty("--heal", healthy.toFixed(3));
  }

  function drawVault(x, y, k, seal, now) {
    const r = size * 3.2;
    ctx.save();
    ctx.globalAlpha = k;
    ctx.translate(x, y);
    ctx.rotate(Math.sin(now / 1600) * 0.05);
    ctx.beginPath();
    for (let i = 0; i < 6; i++) { const a = Math.PI / 6 + (i * Math.PI) / 3; ctx[i ? "lineTo" : "moveTo"](Math.cos(a) * r, Math.sin(a) * r); }
    ctx.closePath();
    const lit = clamp(seal * 1.2);
    ctx.fillStyle = `rgba(56,189,248,${0.06 + 0.12 * lit})`;
    ctx.fill();
    ctx.lineWidth = 1.6;
    ctx.strokeStyle = `rgba(125,211,252,${0.5 + 0.5 * lit})`;
    ctx.shadowColor = "#38bdf8"; ctx.shadowBlur = 20 * lit;
    ctx.stroke();
    ctx.shadowBlur = 0;
    // lock: shackle drops when sealed
    const bw = r * 0.62, bh = r * 0.5, drop = lerp(-r * 0.18, 0, ease(clamp((seal - 0.6) / 0.4)));
    ctx.strokeStyle = "rgba(224,242,254,0.95)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(0, -bh * 0.1 + drop, bw * 0.32, Math.PI, 0);
    ctx.lineTo(bw * 0.32, bh * 0.1 + drop);
    ctx.moveTo(-bw * 0.32, -bh * 0.1 + drop);
    ctx.lineTo(-bw * 0.32, bh * 0.1);
    ctx.stroke();
    ctx.fillStyle = "rgba(224,242,254,0.95)";
    roundRect(-bw / 2, bh * 0.1, bw, bh * 0.75, 3);
    ctx.fill();
    ctx.fillStyle = "#0b1222";
    ctx.beginPath(); ctx.arc(0, bh * 0.45, 2.4, 0, Math.PI * 2); ctx.fill();
    ctx.restore();
    ctx.save();
    ctx.globalAlpha = k * 0.85;
    ctx.fillStyle = "#bae6fd";
    ctx.font = `600 ${Math.max(11, size * 0.9)}px "Segoe UI", Tahoma, sans-serif`;
    ctx.textAlign = "center";
    ctx.direction = rtl() ? "rtl" : "ltr";
    ctx.fillText(t("storyVault"), x, y + r + size * 1.6);
    ctx.restore();
  }

  function drawTag(text, x, y, tx, ty, alpha) {
    ctx.save();
    ctx.globalAlpha = alpha;
    ctx.font = `600 ${Math.max(11, size * 0.85)}px "Segoe UI", Tahoma, sans-serif`;
    ctx.direction = rtl() ? "rtl" : "ltr";
    const w = ctx.measureText(text).width + 22, h = Math.max(22, size * 1.6);
    ctx.strokeStyle = "rgba(248,113,113,0.7)";
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(x, y + h / 2); ctx.stroke();
    ctx.fillStyle = "rgba(40,10,14,0.88)";
    roundRect(x - w / 2, y - h / 2, w, h, h / 2);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = "#fecaca";
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(text, x, y + 1);
    ctx.restore();
  }

  function drawFileLabel(text, x, y, alpha, color) {
    ctx.save();
    ctx.globalAlpha = alpha;
    ctx.font = `600 ${Math.max(12, size * 1.0)}px Consolas, ui-monospace, monospace`;
    ctx.fillStyle = color;
    ctx.textBaseline = "middle";
    ctx.direction = "ltr";
    ctx.fillText(text, x, y);
    ctx.restore();
  }

  function drawCheck(x, y, k) {
    const r = size * 1.6;
    ctx.save();
    ctx.globalAlpha = k;
    ctx.strokeStyle = "#34d399"; ctx.lineWidth = 2.5; ctx.lineCap = "round"; ctx.lineJoin = "round";
    ctx.shadowColor = "#34d399"; ctx.shadowBlur = 16;
    ctx.beginPath(); ctx.arc(x, y, r, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * k); ctx.stroke();
    if (k > 0.5) {
      const c = clamp((k - 0.5) / 0.5);
      ctx.beginPath(); ctx.moveTo(x - r * 0.45, y); ctx.lineTo(x - r * 0.1, y + r * 0.35 * Math.min(1, c * 2));
      if (c > 0.5) ctx.lineTo(x - r * 0.1 + r * 0.6 * ((c - 0.5) * 2), y + r * 0.35 - r * 0.75 * ((c - 0.5) * 2));
      ctx.stroke();
    }
    ctx.restore();
  }

  function measure() {
    const r = section.getBoundingClientRect();
    const total = r.height - innerHeight;
    target = clamp(-r.top / (total || 1));
    visible = r.top < innerHeight && r.bottom > 0;
    document.body.classList.toggle("in-story", r.top < innerHeight * 0.3 && r.bottom > innerHeight * 0.7);
  }

  function frame(now) {
    raf = requestAnimationFrame(frame);
    if (!visible || section.offsetParent === null) return;
    p = reduced ? target : p + (target - p) * 0.09;
    draw(now);
  }

  function buildSteps() {
    const box = $("story-steps");
    box.replaceChildren(...t("story").map(([title, body], k) => {
      const n = el("div", "sstep");
      n.append(el("span", "snum", String(k + 1).padStart(2, "0")), el("h3", "", title), el("p", "", body));
      return n;
    }));
  }

  window.addEventListener("scroll", measure, { passive: true });
  window.addEventListener("resize", () => { layout(); measure(); });
  new ResizeObserver(() => { layout(); }).observe(canvas);
  window.CS.onLang(() => { buildSteps(); layout(); });
  buildSteps();
  layout();
  measure();
  raf = requestAnimationFrame(frame);
})();
