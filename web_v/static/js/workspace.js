/* The scan workspace in motion.
 *   - the drop zone holds a swarm that rushes at a file dragged over it,
 *     and settles into a ring once a file is chosen;
 *   - while a scan runs, a scanner ring pulls a stream of bytes through
 *     itself, its four arcs light up stage by stage, and an engine log types;
 *   - a result decodes its fingerprint and target, the tab ink slides,
 *     the verdict card tilts toward the cursor, buttons are magnetic.
 */
(function () {
  "use strict";
  const { $, el, t } = window.CS;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fit = (c) => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = c.clientWidth, h = c.clientHeight;
    if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return [ctx, w, h];
  };

  // Is this canvas on screen? (reading offsetParent every frame forced a full layout)
  const onScreen = new WeakMap();
  const watch = (node) => {
    onScreen.set(node, false);
    if (window.IntersectionObserver) new IntersectionObserver((es) => es.forEach((e) => onScreen.set(e.target, e.isIntersecting))).observe(node);
    else onScreen.set(node, true);
  };

  /* ================= drop-zone swarm ================= */
  const drop = $("drop"), fx = $("drop-fx");
  const swarm = Array.from({ length: 110 }, () => ({ a: Math.random() * Math.PI * 2, r: 0.3 + Math.random() * 0.7, s: 0.2 + Math.random() * 0.8, z: Math.random(), x: 0, y: 0 }));
  const dpt = { x: -1e4, y: -1e4 };
  drop.addEventListener("pointermove", (e) => { const r = drop.getBoundingClientRect(); dpt.x = e.clientX - r.left; dpt.y = e.clientY - r.top; });
  drop.addEventListener("pointerleave", () => { dpt.x = dpt.y = -1e4; });
  let suck = 0, ring = 0;
  function dropFrame(now) {
    requestAnimationFrame(dropFrame);
    if (!onScreen.get(fx) || document.hidden) return;
    const [ctx, w, h] = fit(fx);
    ctx.clearRect(0, 0, w, h);
    suck += ((drop.classList.contains("over") ? 1 : 0) - suck) * 0.08;
    ring += ((drop.classList.contains("chosen") ? 1 : 0) - ring) * 0.06;
    const cx = w / 2, cy = h / 2, R = Math.min(w, h) * 0.42;
    for (const p of swarm) {
      p.a += 0.002 * p.s * (1 + suck * 8) * (reduced ? 0 : 1);
      const free = p.r * (1 - suck * 0.85);
      const rr = (free * (1 - ring) + 0.62 * ring) * R;
      let x = cx + Math.cos(p.a) * rr * (w / h > 2 ? 2.2 : 1.2), y = cy + Math.sin(p.a) * rr * 0.7;
      x += Math.sin(now / 1300 + p.z * 9) * 6 * (1 - ring);
      const dx = x - dpt.x, dy = y - dpt.y, d = Math.hypot(dx, dy);
      if (d < 70) { x += (dx / d) * (70 - d) * 0.6; y += (dy / d) * (70 - d) * 0.6; }
      p.x += (x - p.x) * 0.2; p.y += (y - p.y) * 0.2;
      const hue = ring > 0.5 ? "52,211,153" : suck > 0.3 ? "125,211,252" : "56,189,248";
      ctx.fillStyle = `rgba(${hue},${0.18 + p.z * 0.45 + suck * 0.3})`;
      const s = 1 + p.z * 2.2 + suck * 1.5;
      ctx.beginPath(); ctx.arc(p.x, p.y, s, 0, Math.PI * 2); ctx.fill();
    }
  }
  watch(fx);
  requestAnimationFrame(dropFrame);

  /* ================= scan theater ================= */
  const theater = $("theater");
  const STAGE_HUES = ["#38bdf8", "#a78bfa", "#f472b6", "#34d399"];
  let stages = [], started = 0, pct = 0, running = false, bytes = [], spin = 0, lastLog = [];
  const HEX = "0123456789ABCDEF";
  const randByte = () => HEX[(Math.random() * 16) | 0] + HEX[(Math.random() * 16) | 0];

  window.addEventListener("cs:scan-start", () => {
    stages = []; started = performance.now(); pct = 0; running = true; bytes = []; lastLog = [];
    $("term-log").replaceChildren();
    log("$ cyberscan --static " + (document.getElementById("progress-target").textContent || "input"), "cmd");
  });
  window.addEventListener("cs:stages", (e) => {
    const next = e.detail || [];
    next.forEach((s, i) => {
      const key = `${i}:${s.state}:${s.detail}`;
      if (s.detail && !lastLog.includes(key)) { lastLog.push(key); log(`[${i + 1}/4] ${s.detail}`, s.state === "complete" ? "ok" : "run"); }
    });
    stages = next;
  });
  window.addEventListener("cs:result", () => { running = false; });

  function log(text, kind) {
    const li = el("li", kind);
    const stamp = el("span", "ts", `${((performance.now() - started) / 1000).toFixed(2)}s`);
    const body = el("span", "tx", "");
    li.append(stamp, body);
    const list = $("term-log");
    list.append(li);
    while (list.children.length > 7) list.firstChild.remove();
    if (reduced) { body.textContent = text; return; }
    let i = 0;
    const type = () => { body.textContent = text.slice(0, i += 2); if (i < text.length) setTimeout(type, 12); };
    type();
  }

  function theaterFrame(now) {
    requestAnimationFrame(theaterFrame);
    if (!onScreen.get(theater) || document.hidden) return;
    const [ctx, w, h] = fit(theater);
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2, R = Math.min(w, h) * 0.34;
    const done = stages.filter((s) => s.state === "complete").length;
    const runningStage = stages.findIndex((s) => s.state === "running");
    const target = Math.min(99, done * 25 + (runningStage >= 0 ? 12 : 0) + Math.min(10, (now - started) / 600));
    pct += ((running ? target : 100) - pct) * 0.08;
    $("th-pct").textContent = String(Math.round(pct));
    $("th-time").textContent = `${((now - started) / 1000).toFixed(1)} s`;
    spin += reduced ? 0 : 0.012 + (running ? 0.01 : 0);

    // stream of bytes flowing into the ring
    if (running && !reduced && Math.random() < 0.7) {
      bytes.push({ x: -20, y: cy + (Math.random() - 0.5) * h * 0.55, v: 1.6 + Math.random() * 2.4, t: randByte(), bad: Math.random() < 0.06, a: 0 });
    }
    ctx.font = "600 11px Consolas, monospace";
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    for (let i = bytes.length - 1; i >= 0; i--) {
      const b = bytes[i];
      b.x += b.v;
      const dx = cx - b.x, dy = cy - b.y, d = Math.hypot(dx, dy);
      if (d < R * 1.6) { b.y += dy * 0.05; b.a += 0.06; }
      const inside = d < R * 0.4;
      const alpha = Math.min(1, b.x / 60) * (inside ? Math.max(0, 1 - b.a * 0.5) : 1);
      if (alpha <= 0.02 || b.x > w + 30) { bytes.splice(i, 1); continue; }
      ctx.fillStyle = b.bad ? `rgba(248,113,113,${alpha})` : `rgba(148,197,255,${alpha * 0.8})`;
      const scale = d < R * 1.6 ? Math.max(0.4, d / (R * 1.6)) : 1;
      ctx.save(); ctx.translate(b.x, b.y); ctx.scale(scale, scale); ctx.fillText(b.t, 0, 0); ctx.restore();
    }

    // the ring: four arcs, one per stage
    for (let i = 0; i < 4; i++) {
      const a0 = spin + (i * Math.PI) / 2 + 0.08, a1 = spin + ((i + 1) * Math.PI) / 2 - 0.08;
      const s = stages[i] ? stages[i].state : "pending";
      ctx.lineWidth = s === "complete" ? 6 : 4;
      ctx.lineCap = "round";
      ctx.strokeStyle = s === "pending" ? "rgba(71,85,105,.5)" : STAGE_HUES[i];
      ctx.shadowColor = STAGE_HUES[i];
      ctx.shadowBlur = s === "pending" ? 0 : s === "running" ? 12 + Math.sin(now / 160) * 8 : 18;
      ctx.beginPath();
      if (s === "running") {
        const f = 0.5 + 0.5 * Math.sin(now / 300);
        ctx.arc(cx, cy, R, a0, a0 + (a1 - a0) * (0.35 + f * 0.65));
      } else ctx.arc(cx, cy, R, a0, a1);
      ctx.stroke();
    }
    ctx.shadowBlur = 0;
    // inner rotating dashes and a sweep
    ctx.strokeStyle = "rgba(125,211,252,.35)"; ctx.lineWidth = 1; ctx.setLineDash([2, 7]);
    ctx.beginPath(); ctx.arc(cx, cy, R * 0.78, -spin * 2, -spin * 2 + Math.PI * 2); ctx.stroke();
    ctx.setLineDash([]);
    const g = ctx.createConicGradient ? ctx.createConicGradient(spin * 3, cx, cy) : null;
    if (g) {
      g.addColorStop(0, "rgba(56,189,248,.35)"); g.addColorStop(0.12, "rgba(56,189,248,0)"); g.addColorStop(1, "rgba(56,189,248,0)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R * 0.74, 0, Math.PI * 2); ctx.fill();
    }
  }
  watch(theater);
  requestAnimationFrame(theaterFrame);

  /* ================= result details ================= */
  const GLYPHS = "▚▞▖▗▘▝01ABCDEF#%/\\";
  function decode(node, ms = 900) {
    if (!node || reduced) return;
    const target = node.textContent;
    if (!target) return;
    const start = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - start) / ms);
      const done = Math.floor(p * target.length);
      node.textContent = target.slice(0, done) + [...target.slice(done)].map((c) => (c === " " ? " " : GLYPHS[(Math.random() * GLYPHS.length) | 0])).join("");
      if (p < 1) requestAnimationFrame(step); else node.textContent = target;
    };
    requestAnimationFrame(step);
  }
  window.addEventListener("cs:result", (e) => {
    if (!e.detail.animate) return;
    setTimeout(() => {
      decode($("target"), 1100);
      document.querySelectorAll("#facts dd.hash").forEach((n) => decode(n, 1400));
    }, 250);
    requestAnimationFrame(moveTabInk);
  });

  /* tab ink */
  const rtabs = $("rtabs");
  const tabInk = rtabs.querySelector(".rtab-ink");
  function moveTabInk() {
    const a = rtabs.querySelector(".rtab.active");
    if (!a || !a.offsetParent) return;
    tabInk.style.width = `${a.offsetWidth}px`;
    tabInk.style.transform = `translateX(${a.offsetLeft}px)`;
  }
  rtabs.addEventListener("click", () => requestAnimationFrame(moveTabInk));
  window.addEventListener("resize", moveTabInk);
  window.CS.onLang(() => requestAnimationFrame(moveTabInk));

  /* the verdict card leans toward the cursor */
  const verdict = document.querySelector(".verdict");
  if (!reduced) {
    verdict.addEventListener("pointermove", (e) => {
      const r = verdict.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
      verdict.style.transform = `perspective(1100px) rotateY(${x * 5}deg) rotateX(${-y * 5}deg)`;
      verdict.style.setProperty("--gx", `${(x + 0.5) * 100}%`);
      verdict.style.setProperty("--gy", `${(y + 0.5) * 100}%`);
    });
    verdict.addEventListener("pointerleave", () => { verdict.style.transform = ""; });

    /* every button in the app leans toward the cursor */
    const app = $("app");
    app.addEventListener("pointermove", (e) => {
      const b = e.target.closest(".primary, .actions-bar .ghost, .chip, .nav-btn, .rtab");
      app.querySelectorAll(".mag-on").forEach((m) => { if (m !== b) { m.style.translate = ""; m.classList.remove("mag-on"); } });
      if (!b) return;
      const r = b.getBoundingClientRect();
      const k = b.classList.contains("primary") ? 0.25 : 0.14;
      b.style.translate = `${((e.clientX - r.left - r.width / 2) * k).toFixed(1)}px ${((e.clientY - r.top - r.height / 2) * k * 1.4).toFixed(1)}px`;
      b.classList.add("mag-on");
    });
    app.addEventListener("pointerleave", () => app.querySelectorAll(".mag-on").forEach((m) => { m.style.translate = ""; m.classList.remove("mag-on"); }));
  }
})();
