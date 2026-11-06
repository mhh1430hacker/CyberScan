/* The file as a cube of cells.
 *
 * Each cell is one slice of the file, placed along a 3D Hilbert curve so
 * neighbouring bytes stay neighbours. Colour = how random the bytes are;
 * red pulsing cells sit inside a region the engine flagged. Drag to turn,
 * hover to read a cell's offset and randomness.
 *
 *   const cube = CyberCube.create(canvas, tooltipElement);
 *   cube.setData({positions:[x,y,z,...], entropy:[...], flags:[...], offsets:[...]});
 */
(function () {
  "use strict";

  const STOPS = [
    [0, [30, 58, 138]],
    [3.5, [56, 189, 248]],
    [6, [167, 139, 250]],
    [7.4, [244, 114, 182]],
    [8, [251, 191, 36]],
  ];

  function entropyColor(e) {
    for (let i = 1; i < STOPS.length; i++) {
      if (e <= STOPS[i][0]) {
        const [e0, c0] = STOPS[i - 1], [e1, c1] = STOPS[i];
        const t = (e - e0) / (e1 - e0 || 1);
        return [c0[0] + (c1[0] - c0[0]) * t, c0[1] + (c1[1] - c0[1]) * t, c0[2] + (c1[2] - c0[2]) * t];
      }
    }
    return STOPS[STOPS.length - 1][1];
  }

  function create(canvas, tip) {
    const ctx = canvas.getContext("2d");
    const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let w = 0, h = 0, dpr = 1;
    let pts = [];
    let yaw = 0.7, pitch = -0.45, vyaw = reduced ? 0 : 0.22;
    let drag = null;
    let born = performance.now();
    let raf = 0, alive = true, hover = null, inView = true;
    let order = [];

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth; h = canvas.clientHeight;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function setData(s) {
      pts = [];
      if (!s || !s.entropy) return;
      const n = s.entropy.length;
      for (let i = 0; i < n; i++) {
        const e = s.entropy[i];
        pts.push({
          x: s.positions[i * 3], y: s.positions[i * 3 + 1], z: s.positions[i * 3 + 2],
          ox: (Math.random() - 0.5) * 6, oy: (Math.random() - 0.5) * 6, oz: (Math.random() - 0.5) * 6,
          e, flag: s.flags[i] || 0, off: s.offsets ? s.offsets[i] : 0,
          next: s.offsets && i + 1 < n ? s.offsets[i + 1] : s.size,
          rgb: entropyColor(e), sx: 0, sy: 0, depth: 0, delay: (i / n) * 0.6,
        });
      }
      order = pts.slice();
      born = performance.now();
    }

    function frame(now) {
      if (!alive) return;
      raf = requestAnimationFrame(frame);
      if (!inView || !w) return;
      if (!drag) yaw += vyaw / 60;
      const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
      const scale = Math.min(w, h) * 0.78;
      const age = reduced ? 10 : (now - born) / 1000;
      ctx.clearRect(0, 0, w, h);

      for (const p of pts) {
        const t = Math.max(0, Math.min(1, (age - p.delay) / 0.9));
        const k = 1 - Math.pow(1 - t, 3);
        const x0 = p.ox + (p.x - p.ox) * k, y0 = p.oy + (p.y - p.oy) * k, z0 = p.oz + (p.z - p.oz) * k;
        const x1 = x0 * cy - z0 * sy, z1 = x0 * sy + z0 * cy;
        const y2 = y0 * cp - z1 * sp, z2 = y0 * sp + z1 * cp;
        const persp = 1.9 / (2.6 + z2);
        p.sx = w / 2 + x1 * scale * persp;
        p.sy = h / 2 + y2 * scale * persp;
        p.depth = z2;
        p.size = Math.max(1.2, 5.2 * persp * (pts.length > 2000 ? 0.8 : 1.4));
        p.k = k;
      }
      order.sort((a, b) => b.depth - a.depth);
      for (const p of order) {
        if (p.k <= 0) continue;
        const shade = 0.45 + 0.55 * (1 - (p.depth + 0.9) / 1.8);
        let [r, g, b] = p.rgb;
        let a = 0.85 * p.k * Math.max(0.25, shade);
        let s = p.size;
        if (p.flag) {
          const pulse = 0.6 + 0.4 * Math.sin(now / 220 + p.off);
          r = 248; g = 90 + 30 * pulse; b = 90;
          s *= 1.5 + 0.4 * pulse;
          a = Math.min(1, a + 0.3);
          ctx.fillStyle = `rgba(248,113,113,${(0.18 * pulse * p.k).toFixed(3)})`;
          ctx.beginPath(); ctx.arc(p.sx, p.sy, s * 2.4, 0, Math.PI * 2); ctx.fill();
        }
        if (hover === p) { s *= 2.2; a = 1; }
        ctx.fillStyle = `rgba(${r | 0},${g | 0},${b | 0},${a.toFixed(3)})`;
        ctx.fillRect(p.sx - s / 2, p.sy - s / 2, s, s);
      }
    }

    function nearest(mx, my) {
      let best = null, bd = 144;
      for (const p of pts) {
        const d = (p.sx - mx) ** 2 + (p.sy - my) ** 2;
        if (d < bd && p.depth < 0.6) { bd = d; best = p; }
      }
      return best;
    }

    const hex = (n) => "0x" + Number(n || 0).toString(16).toUpperCase();
    canvas.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY }; canvas.setPointerCapture(e.pointerId); vyaw = 0; });
    canvas.addEventListener("pointerup", () => { drag = null; vyaw = reduced ? 0 : 0.12; });
    canvas.addEventListener("pointermove", (e) => {
      const r = canvas.getBoundingClientRect();
      if (drag) {
        yaw += (e.clientX - drag.x) * 0.008;
        pitch = Math.max(-1.3, Math.min(1.3, pitch + (e.clientY - drag.y) * 0.008));
        drag = { x: e.clientX, y: e.clientY };
      }
      hover = nearest(e.clientX - r.left, e.clientY - r.top);
      if (tip) {
        if (hover) {
          tip.hidden = false;
          tip.textContent = `${hex(hover.off)} – ${hex(hover.next)} · ${hover.e.toFixed(2)} / 8${hover.flag ? " ⚠" : ""}`;
          tip.style.transform = `translate(${e.clientX - r.left + 14}px, ${e.clientY - r.top + 14}px)`;
        } else tip.hidden = true;
      }
    });
    canvas.addEventListener("pointerleave", () => { hover = null; if (tip) tip.hidden = true; });

    const io = new IntersectionObserver((entries) => { inView = entries[0].isIntersecting; });
    io.observe(canvas);
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    resize();
    raf = requestAnimationFrame(frame);

    return {
      setData,
      replay() { born = performance.now(); for (const p of pts) { p.ox = (Math.random() - 0.5) * 6; p.oy = (Math.random() - 0.5) * 6; p.oz = (Math.random() - 0.5) * 6; } },
      destroy() { alive = false; cancelAnimationFrame(raf); io.disconnect(); ro.disconnect(); },
    };
  }

  /* A made-up file for the landing page: a program with a packed tail. */
  function demoStructure() {
    const side = 12, n = side * side * side;
    const positions = [], entropy = [], flags = [], offsets = [];
    // walk a simple serpentine path through the cube so neighbours stay close
    let i = 0;
    for (let z = 0; z < side; z++) for (let yy = 0; yy < side; yy++) for (let xx = 0; xx < side; xx++) {
      const y = z % 2 ? side - 1 - yy : yy;
      const x = y % 2 ? side - 1 - xx : xx;
      positions.push(x / (side - 1) - 0.5, y / (side - 1) - 0.5, z / (side - 1) - 0.5);
      const t = i / n;
      let e = t < 0.08 ? 2 + Math.random() : t < 0.55 ? 5.6 + Math.random() * 0.8 : t < 0.8 ? 3.5 + Math.random() * 1.5 : 7.6 + Math.random() * 0.35;
      entropy.push(e);
      flags.push((t > 0.805 && t < 0.83) || (t > 0.52 && t < 0.53) ? 3 : 0);
      offsets.push(i * 512);
      i++;
    }
    return { positions, entropy, flags, offsets, size: n * 512 };
  }

  window.CyberCube = { create, demoStructure, entropyColor };
})();
