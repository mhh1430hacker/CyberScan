/* Flying cells: a field of hexagonal cells drifting in 3D.
 *
 * The cells tell the product's story: some turn red ("infected"); a scan
 * wave sweeps through and heals them back to cyan. The cursor parts the
 * cells, a click sends a healing shockwave, and warp() rushes them past the
 * camera for the transition into the app.
 *
 *   const field = CyberCells.create(canvas);
 *   field.setMode("hero" | "ambient" | "scan");
 *   await field.warp(x, y);
 */
(function () {
  "use strict";

  const TAU = Math.PI * 2;
  const COLORS = {
    clean: [56, 189, 248],
    alt: [129, 140, 248],
    infected: [248, 113, 113],
    healed: [52, 211, 153],
  };
  const MODES = {
    hero: { density: 1, speed: 1, link: 1, alpha: 1, infect: 0.0025, waveEvery: 5200 },
    ambient: { density: 0.55, speed: 0.45, link: 0.55, alpha: 0.42, infect: 0.0006, waveEvery: 9000 },
    scan: { density: 0.7, speed: 1.6, link: 0.8, alpha: 0.75, infect: 0, waveEvery: 900 },
  };

  const mix = (a, b, t) => a + (b - a) * t;
  const mixColor = (a, b, t) => [mix(a[0], b[0], t), mix(a[1], b[1], t), mix(a[2], b[2], t)];
  const rand = (lo, hi) => lo + Math.random() * (hi - lo);

  function create(canvas, options = {}) {
    const ctx = canvas.getContext("2d");
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let width = 0, height = 0, dpr = 1;
    let cells = [];
    let mode = MODES[options.mode || "hero"];
    let modeName = options.mode || "hero";
    let current = { ...mode };
    let running = true;
    let raf = 0;
    let last = performance.now();
    let lastWave = last;
    const waves = [];
    const mouse = { x: -9999, y: -9999, tx: 0, ty: 0, px: 0, py: 0, active: false };
    let warping = null;

    function capacity() {
      const area = width * height;
      const base = Math.min(120, Math.max(36, Math.round(area / 10500)));
      return Math.round(base * (width < 700 ? 0.7 : 1));
    }

    function spawn(cell = {}) {
      cell.x = rand(-1.25, 1.25);
      cell.y = rand(-1.1, 1.1);
      cell.z = cell.z === undefined ? rand(0.15, 1.6) : 1.6;
      cell.vx = rand(-0.02, 0.02);
      cell.vy = rand(-0.025, 0.012);
      cell.vz = rand(-0.03, -0.006);
      cell.r = rand(9, 22);
      cell.rot = rand(0, TAU);
      cell.vr = rand(-0.4, 0.4);
      cell.state = Math.random() < 0.08 ? "infected" : "clean";
      cell.heal = 0; // 1 → 0 green flash after healing
      cell.hue = Math.random() < 0.3 ? 1 : 0;
      cell.phase = rand(0, TAU);
      cell.sx = 0; cell.sy = 0; cell.scale = 0; cell.px = null; cell.py = null;
      return cell;
    }

    function resize() {
      dpr = window.CSPerf ? window.CSPerf.dpr(1.5) : Math.min(window.devicePixelRatio || 1, 1.5);
      width = canvas.clientWidth || window.innerWidth;
      height = canvas.clientHeight || window.innerHeight;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const want = Math.round(capacity() * mode.density);
      while (cells.length < want) cells.push(spawn());
      if (cells.length > want) cells.length = want;
      if (reduced) draw(0);
    }

    function project(c) {
      const camX = mouse.px * 0.12, camY = mouse.py * 0.08;
      const p = 1 / (c.z + 0.35);
      const unit = Math.min(width, height) * 0.62;
      c.sx = width / 2 + (c.x - camX * (1.8 - c.z)) * unit * p * 0.9;
      c.sy = height / 2 + (c.y - camY * (1.8 - c.z)) * unit * p * 0.9;
      c.scale = p;
    }

    function hexPath(x, y, r, rot) {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const a = rot + (i * TAU) / 6;
        const px = x + Math.cos(a) * r, py = y + Math.sin(a) * r;
        if (i === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py);
      }
      ctx.closePath();
    }

    function colorOf(c, now) {
      if (c.state === "infected") {
        const pulse = 0.65 + 0.35 * Math.sin(now / 260 + c.phase);
        return { rgb: COLORS.infected, glow: pulse };
      }
      const base = c.hue ? COLORS.alt : COLORS.clean;
      if (c.heal > 0) return { rgb: mixColor(base, COLORS.healed, c.heal), glow: c.heal };
      return { rgb: base, glow: 0 };
    }

    function wave(x, y, strength = 1) {
      waves.push({ x, y, r: 0, max: Math.hypot(width, height) * (0.55 + 0.3 * strength), speed: 520 + 380 * strength, life: 1 });
    }

    function update(dt, now) {
      // ease the active mode's numbers toward the target
      for (const key of ["speed", "link", "alpha", "infect", "waveEvery", "density"]) {
        current[key] = mix(current[key], mode[key], Math.min(1, dt * 2.2));
      }
      mouse.px = mix(mouse.px, mouse.tx, Math.min(1, dt * 3));
      mouse.py = mix(mouse.py, mouse.ty, Math.min(1, dt * 3));

      if (!warping && current.waveEvery && now - lastWave > current.waveEvery) {
        lastWave = now;
        if (modeName === "scan") wave(rand(0, width), rand(0, height), 0.6);
        else wave(rand(width * 0.15, width * 0.85), rand(height * 0.2, height * 0.8), 1);
      }
      for (let i = waves.length - 1; i >= 0; i--) {
        const w = waves[i];
        w.r += w.speed * dt;
        w.life = 1 - w.r / w.max;
        if (w.life <= 0) waves.splice(i, 1);
      }

      const speed = current.speed * (warping ? 1 : 1);
      for (const c of cells) {
        c.px = c.sx; c.py = c.sy;
        if (warping) {
          c.vz -= 2.6 * dt * warping.k;
          c.z += c.vz * dt;
        } else {
          c.x += c.vx * dt * speed;
          c.y += c.vy * dt * speed;
          c.z += c.vz * dt * speed;
        }
        c.rot += c.vr * dt * speed;
        if (c.heal > 0) c.heal = Math.max(0, c.heal - dt * 0.7);
        if (c.state === "clean" && Math.random() < current.infect * dt * 60 * 0.05) c.state = "infected";
        project(c);

        // the cursor parts the field
        if (mouse.active && !warping) {
          const dx = c.sx - mouse.x, dy = c.sy - mouse.y;
          const d2 = dx * dx + dy * dy, R = 150;
          if (d2 < R * R && d2 > 1) {
            const f = (1 - Math.sqrt(d2) / R) * 0.35 * dt;
            c.x += (dx / Math.sqrt(d2)) * f;
            c.y += (dy / Math.sqrt(d2)) * f;
          }
        }
        // waves heal what they pass through
        for (const w of waves) {
          if (c.state !== "infected") continue;
          const d = Math.hypot(c.sx - w.x, c.sy - w.y);
          if (Math.abs(d - w.r) < 26) { c.state = "clean"; c.heal = 1; }
        }
        const out = c.z < -0.3 || c.z > 2.2 || c.sx < -120 || c.sx > width + 120 || c.sy < -120 || c.sy > height + 120;
        if (out && !warping) { spawn(c); c.z = rand(1.2, 1.8); c.px = null; }
        if (out && warping && c.z < -0.3) { c.dead = true; }
      }
    }

    function draw(now) {
      ctx.clearRect(0, 0, width, height);
      const alpha = current.alpha;
      const sorted = cells.slice().sort((a, b) => b.z - a.z);

      // links
      const L = 150 * current.link;
      if (L > 10 && !warping) {
        ctx.lineWidth = 1;
        for (let i = 0; i < sorted.length; i++) {
          const a = sorted[i];
          for (let j = i + 1; j < sorted.length; j++) {
            const b = sorted[j];
            if (Math.abs(a.z - b.z) > 0.45) continue;
            const dx = a.sx - b.sx, dy = a.sy - b.sy;
            const d2 = dx * dx + dy * dy;
            if (d2 > L * L) continue;
            const t = 1 - Math.sqrt(d2) / L;
            const depth = Math.min(a.scale, b.scale);
            const bad = a.state === "infected" || b.state === "infected";
            const rgb = bad ? COLORS.infected : COLORS.clean;
            ctx.strokeStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${(t * t * 0.32 * Math.min(1, depth) * alpha).toFixed(3)})`;
            ctx.beginPath(); ctx.moveTo(a.sx, a.sy); ctx.lineTo(b.sx, b.sy); ctx.stroke();
          }
        }
      }

      // waves
      for (const w of waves) {
        const g = ctx.createRadialGradient(w.x, w.y, Math.max(0, w.r - 40), w.x, w.y, w.r + 4);
        g.addColorStop(0, "rgba(52,211,153,0)");
        g.addColorStop(0.85, `rgba(52,211,153,${(0.10 * w.life * alpha).toFixed(3)})`);
        g.addColorStop(1, `rgba(125,240,200,${(0.35 * w.life * alpha).toFixed(3)})`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(w.x, w.y, w.r + 4, 0, TAU); ctx.fill();
      }

      // cells
      for (const c of sorted) {
        if (c.dead) continue;
        const r = c.r * c.scale;
        if (r < 0.6) continue;
        const { rgb, glow } = colorOf(c, now);
        const depthAlpha = Math.max(0, Math.min(1, (2.1 - c.z) / 1.6)) * alpha;
        const col = `${rgb[0] | 0},${rgb[1] | 0},${rgb[2] | 0}`;
        if (warping && c.px !== null) {
          ctx.strokeStyle = `rgba(${col},${(0.55 * depthAlpha).toFixed(3)})`;
          ctx.lineWidth = Math.max(1, r * 0.25);
          ctx.beginPath(); ctx.moveTo(c.px, c.py); ctx.lineTo(c.sx, c.sy); ctx.stroke();
        }
        if (glow > 0) {
          const g = ctx.createRadialGradient(c.sx, c.sy, 0, c.sx, c.sy, r * 2.6);
          g.addColorStop(0, `rgba(${col},${(0.35 * glow * depthAlpha).toFixed(3)})`);
          g.addColorStop(1, `rgba(${col},0)`);
          ctx.fillStyle = g;
          ctx.beginPath(); ctx.arc(c.sx, c.sy, r * 2.6, 0, TAU); ctx.fill();
        }
        hexPath(c.sx, c.sy, r, c.rot);
        ctx.fillStyle = `rgba(${col},${(0.07 + 0.1 * glow) * depthAlpha})`;
        ctx.fill();
        ctx.lineWidth = Math.max(0.6, 1.4 * c.scale);
        ctx.strokeStyle = `rgba(${col},${(0.55 + 0.4 * glow) * depthAlpha})`;
        ctx.stroke();
        if (r > 7) {
          hexPath(c.sx, c.sy, r * 0.45, -c.rot * 1.3);
          ctx.strokeStyle = `rgba(${col},${0.3 * depthAlpha})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }

    // Hidden behind the WebGL field on the landing page (motion.css sets opacity 0): no work at
    // all then, just a cheap check twice a second. Otherwise 30 fps is plenty for a backdrop.
    const covered = () => document.body.classList.contains("has-gl") && document.body.classList.contains("on-landing");
    let sleeping = 0;
    function frame(now) {
      if (!running) return;
      if (covered() && !warping) {
        sleeping = setTimeout(() => { sleeping = 0; last = performance.now(); raf = requestAnimationFrame(frame); }, 500);
        return;
      }
      raf = requestAnimationFrame(frame);
      if (!warping && now - last < 31) return;
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      update(dt, now);
      draw(now);
    }

    function onMove(e) {
      mouse.x = e.clientX; mouse.y = e.clientY; mouse.active = true;
      mouse.tx = (e.clientX / width - 0.5) * 2;
      mouse.ty = (e.clientY / height - 0.5) * 2;
    }
    function onLeave() { mouse.active = false; mouse.x = mouse.y = -9999; }
    function onVisibility() {
      if (document.hidden) { running = false; cancelAnimationFrame(raf); clearTimeout(sleeping); }
      else if (!reduced && !running) { running = true; last = performance.now(); raf = requestAnimationFrame(frame); }
    }

    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onMove, { passive: true });
    document.addEventListener("pointerleave", onLeave);
    document.addEventListener("visibilitychange", onVisibility);
    resize();
    if (reduced) { running = false; draw(performance.now()); } else raf = requestAnimationFrame(frame);

    return {
      setMode(name) {
        if (!MODES[name]) return;
        modeName = name;
        mode = MODES[name];
        const want = Math.round(capacity() * mode.density);
        while (cells.length < want) { const c = spawn(); c.z = rand(1.3, 1.9); cells.push(c); }
        if (cells.length > want) cells.length = want;
        if (reduced) draw(performance.now());
      },
      pulse(x, y) { wave(x, y, 0.7); },
      heal() { for (const c of cells) if (c.state === "infected") { c.state = "clean"; c.heal = 1; } },
      infect(fraction = 0.3) { for (const c of cells) if (Math.random() < fraction) c.state = "infected"; },
      warp(x = width / 2, y = height / 2, ms = 900) {
        if (reduced) return Promise.resolve();
        warping = { k: 1 };
        for (const c of cells) { c.vz = rand(-0.4, -0.1); c.x += (c.sx - x) / width * 0.0001; }
        return new Promise((resolve) => setTimeout(() => {
          warping = null;
          cells = cells.filter((c) => !c.dead);
          for (const c of cells) { c.vz = rand(-0.03, -0.006); }
          const want = Math.round(capacity() * mode.density);
          while (cells.length < want) { const c = spawn(); c.z = rand(0.6, 1.9); cells.push(c); }
          resolve();
        }, ms));
      },
      destroy() {
        running = false;
        cancelAnimationFrame(raf);
        clearTimeout(sleeping);
        window.removeEventListener("resize", resize);
        window.removeEventListener("pointermove", onMove);
        document.removeEventListener("pointerleave", onLeave);
        document.removeEventListener("visibilitychange", onVisibility);
      },
    };
  }

  window.CyberCells = { create };
})();
