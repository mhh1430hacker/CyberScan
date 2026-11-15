/* The CyberScan story (#sci-story): six pinned scenes driven by native scroll.
 *
 * Each scene is taller than the screen and its stage is position: sticky (CSS). For every scene
 * on screen, one rect read per frame gives its progress q (0 when the stage pins, 1 when it lets
 * go; negative while it scrolls in). Timelines map q to transform and opacity only.
 * - No scroll hijacking: the page scrolls natively; the chapter rail only calls scrollTo.
 * - Reduced motion / light mode (.still) and no-JS show every scene as a normal section with its
 *   finished composition; this script then writes no styles at all. */
(function () {
  "use strict";
  const root = document.getElementById("sci-story");
  if (!root) return;
  const html = document.documentElement;
  const CS = window.CS || {};
  const isStill = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion") || html.classList.contains("perf-low");
  const rtl = () => html.dir === "rtl";
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const scenes = [...root.querySelectorAll(".sy-scene")];
  const DEF = { o: 1, x: 0, y: 0, xf: 0, yf: 0, s: 1, rx: 0, rz: 0, z: 0, d: 0 };

  root.classList.add("sy-js");
  let still = isStill();
  root.classList.toggle("still", still);

  /* ---------------- timelines ---------------- */
  const TL = new Map();     // scene -> { els: Map(el -> {base, tracks, props}), fns: [fn], box }
  function tl(scene) { if (!TL.has(scene)) TL.set(scene, { els: new Map(), fns: [], vis: scene.querySelector(".sy-visual") }); return TL.get(scene); }
  function add(scene, el, a, b, from, to, opts = {}) {
    if (!el) return;
    const T = tl(scene);
    if (!T.els.has(el)) { T.els.set(el, { base: opts.base || "", after: opts.after || "", tracks: [], props: new Set() }); el.classList.add("sy-anim"); }
    const rec = T.els.get(el);
    rec.tracks.push({ a, b, from, to, ease: opts.ease || ease });
    Object.keys(to).forEach((k) => rec.props.add(k));
  }
  const all = (scene, sel) => [...scene.querySelectorAll(sel)];
  function beats(scene, ranges) {
    all(scene, ".sy-beat").forEach((b, i) => {
      const r = ranges[i]; if (!r) return;
      add(scene, b, r[0], r[1], { o: 0, y: 22 }, { o: 1, y: 0 });
      if (r[2] != null) add(scene, b, r[2], r[3], { o: 1, y: 0 }, { o: 0, y: -22 });
    });
  }
  function frame(scene, last) {   // every scene but the last fades in as it arrives and out as it leaves
    const inner = scene.querySelector(".sy-inner");
    add(scene, inner, -0.55, 0.02, { o: 0, y: 60, s: 0.97 }, { o: 1, y: 0, s: 1 });
    if (!last) add(scene, inner, 0.94, 1.35, { o: 1, y: 0, s: 1 }, { o: 0, y: -40, s: 0.96 });
  }

  function evalEl(el, rec, q, W, H) {
    const v = { ...DEF };
    for (const k of rec.props) {
      let pick = null, first = null;
      for (const t of rec.tracks) if (k in t.to) { if (!first) first = t; if (q >= t.a) pick = t; }
      if (!pick) { v[k] = first.from[k] ?? DEF[k]; continue; }
      const f = pick.from[k] ?? DEF[k];
      v[k] = f + (pick.to[k] - f) * pick.ease(clamp((q - pick.a) / (pick.b - pick.a)));
    }
    if (rec.props.has("d")) { el.style.strokeDashoffset = (1 - v.d).toFixed(4); if (rec.props.size === 1) return; }
    const x = v.x * (rtl() ? -1 : 1) + v.xf * W, y = v.y + v.yf * H;
    el.style.opacity = v.o.toFixed(3);
    el.style.transform = `${rec.base}${rec.props.has("z") ? `translate3d(${x.toFixed(1)}px, ${y.toFixed(1)}px, ${v.z.toFixed(1)}px)` : `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px)`}${v.rx ? ` rotateX(${v.rx.toFixed(2)}deg)` : ""}${v.rz ? ` rotateZ(${v.rz.toFixed(2)}deg)` : ""}${v.s !== 1 ? ` scale(${v.s.toFixed(4)})` : ""}${rec.after}`;
  }

  /* ---------------- scene 1 · the digital world ---------------- */
  (function () {
    const sc = scenes[0]; if (!sc) return;
    frame(sc);
    const pos = all(sc, ".sy-node").map((n) => [parseFloat(getComputedStyle(n).left), parseFloat(getComputedStyle(n).top)]);
    all(sc, ".sy-node").forEach((n, i) => {
      const base = "translate(-50%, -50%) ";
      if (i === 0) { add(sc, n, -0.4, 0.06, { o: 0, s: 0.6 }, { o: 1, s: 1 }, { base }); return; }
      const a = 0.02 + (i - 1) * 0.045;
      add(sc, n, a, a + 0.2, { o: 0, s: 0.45, xf: 0, yf: 0 }, { o: 1, s: 1 }, { base });
      if (!n.classList.contains("n-files")) add(sc, n, 0.64, 0.76, { o: 1 }, { o: 0.32 }, { base });
    });
    // nodes fly in from the centre: offsets are filled in once the box size is known
    TL.get(sc).fly = all(sc, ".sy-node").slice(1);
    all(sc, ".sy-spoke").forEach((p, i) => add(sc, p, 0.12 + i * 0.03, 0.36 + i * 0.03, { d: 0 }, { d: 1 }));
    add(sc, sc.querySelector(".sy-ring"), 0.3, 0.58, { d: 0 }, { d: 1 });
    add(sc, sc.querySelector(".sy-threat"), 0.64, 0.78, { o: 0, s: 1.5 }, { o: 1, s: 1 }, { base: "translate(-50%, -50%) " });
    beats(sc, [[-0.35, 0.0, 0.27, 0.32], [0.33, 0.38, 0.6, 0.65], [0.66, 0.71]]);
    const pk = all(sc, ".sy-pk");
    const ends = all(sc, ".sy-spoke").map((p) => p.getAttribute("d").slice(1).split("L")[0].split(" ").map(Number));
    tl(sc).fns.push((q) => {
      const show = clamp((q - 0.34) / 0.06) * (1 - clamp((q - 0.9) / 0.08));
      pk.forEach((c, i) => {
        const t = (((q - 0.34) * 2.4 + i / 6) % 1 + 1) % 1, [x, y] = ends[i];
        c.setAttribute("cx", (x + (300 - x) * t).toFixed(1)); c.setAttribute("cy", (y + (250 - y) * t).toFixed(1));
        c.setAttribute("opacity", (show * (i === 0 && q > 0.66 ? 0 : 1)).toFixed(2));
      });
    });
    tl(sc).pos = pos;
  })();

  /* ---------------- scene 2 · inside a file ---------------- */
  (function () {
    const sc = scenes[1]; if (!sc) return;
    frame(sc);
    add(sc, sc.querySelector(".sy-stack"), -0.1, 0.34, { rx: 0, rz: 0, s: 0.88 }, { rx: 56, rz: -36, s: 1 }, { ease: inOut });
    const step = () => (matchMedia("(max-width: 720px)").matches ? 30 : 44);
    all(sc, ".sy-layer").forEach((l, i) => {
      add(sc, l, 0.28, 0.58, { z: (4 - i) * 0.6 }, { z: (4 - i) * 44 }, { ease: inOut });
      l._step = step;
    });
    all(sc, ".sy-lbl").forEach((l, i) => { const a = 0.4 + i * 0.075; add(sc, l, a, a + 0.08, { o: 0, x: -24 }, { o: 1, x: 0 }); });
    beats(sc, [[-0.35, 0.0, 0.25, 0.3], [0.32, 0.37, 0.74, 0.79], [0.8, 0.85]]);
    const hot = sc.querySelector('.sy-layer[data-i="1"]'), hotLbl = sc.querySelector('.sy-lbl[data-i="1"]');
    tl(sc).fns.push((q) => { const on = q > 0.8; hot.classList.toggle("hot", on); hotLbl.classList.toggle("hot", on); });
  })();

  /* ---------------- scene 3 · how CyberScan analyzes ---------------- */
  (function () {
    const sc = scenes[2]; if (!sc) return;
    frame(sc);
    const wrap = sc.querySelector(".sy-trackwrap"), track = sc.querySelector(".sy-track"), sts = all(sc, ".sy-st"), token = sc.querySelector(".sy-token");
    const rail = sc.querySelector(".sy-rail i"), capts = all(sc, ".sy-capt"), gauge = sc.querySelector(".sy-gauge i"), score = sc.querySelector(".sy-score b");
    let centers = [], lastK = -1;
    tl(sc).measure = () => { centers = sts.map((s) => s.offsetLeft + s.offsetWidth / 2); };
    capts.forEach((c) => c.classList.add("sy-anim"));
    tl(sc).fns.push((q) => {
      const pos = clamp((q - 0.03) / 0.86) * 5, k = Math.min(5, Math.floor(pos + 0.02));
      if (k !== lastK) { sts.forEach((s, i) => { s.classList.toggle("done", i < k); s.classList.toggle("on", i === k); }); lastK = k; }
      if (centers.length) {
        const i0 = Math.floor(pos), f = pos - i0, cx = centers[Math.min(5, i0)] + ((centers[Math.min(5, i0 + 1)] || centers[5]) - centers[Math.min(5, i0)]) * f;
        token.style.transform = `translateX(${cx.toFixed(1)}px)`;
        // keep the token centred when the track is wider than the screen (phones); works in both directions
        const tw = track.offsetWidth, ww = wrap.clientWidth, tl0 = track.offsetLeft;
        if (tw > ww + 4) {
          const shift = clamp(ww / 2 - (tl0 + cx), ww - (tl0 + tw), -tl0);
          track.style.transform = `translateX(${shift.toFixed(1)}px)`;
        } else track.style.transform = "";
      }
      rail.style.transform = `scaleX(${(pos / 5).toFixed(4)})`;
      capts.forEach((c, i) => {
        const t = pos - i;
        const o = clamp((t + 0.18) / 0.18) * (i === 5 ? 1 : clamp((1 - t) / 0.18));
        c.style.opacity = o.toFixed(3); c.style.transform = `translateY(${((1 - o) * 18).toFixed(1)}px)`;
        c.style.visibility = o < 0.01 ? "hidden" : "";
      });
      const g = clamp((q - 0.86) / 0.08);
      gauge.style.transform = `scaleX(${(0.55 * ease(g)).toFixed(4)})`;
      score.textContent = String(Math.round(55 * ease(g)));
    });
  })();

  /* ---------------- scene 4 · beyond files ---------------- */
  (function () {
    const sc = scenes[3]; if (!sc) return;
    frame(sc);
    add(sc, sc.querySelector(".sy-core"), -0.4, 0.06, { o: 0, s: 0.5 }, { o: 1, s: 1 }, { base: "translate(-50%, -50%) " });
    all(sc, ".sy-dom").forEach((d, i) => { const a = 0.06 + i * 0.045; add(sc, d, a, a + 0.18, { o: 0, s: 0.4 }, { o: 1, s: 1 }, { base: "translate(-50%, -50%) " }); });
    all(sc, ".sy-espoke").forEach((p, i) => { const a = 0.06 + i * 0.045; add(sc, p, a, a + 0.2, { d: 0 }, { d: 1 }); });
    beats(sc, [[-0.35, 0.0, 0.3, 0.35], [0.36, 0.41, 0.66, 0.71], [0.72, 0.77]]);
    tl(sc).fly = all(sc, ".sy-dom");
  })();

  /* ---------------- scene 5 · one ecosystem ---------------- */
  (function () {
    const sc = scenes[4]; if (!sc) return;
    frame(sc);
    const vis = sc.querySelector(".sy-visual"), doms = all(sc, ".sy-dom"), core = sc.querySelector(".sy-core");
    all(sc, ".sy-rel").forEach((p, i) => add(sc, p, 0.24 + i * 0.03, 0.44 + i * 0.03, { d: 0 }, { d: 1 }));
    all(sc, ".sy-espoke").forEach((p) => add(sc, p, 0.25, 0.55, { o: 1 }, { o: 0.3 }));
    add(sc, sc.querySelector(".sy-core-ring"), 0.55, 0.8, { s: 1, o: 0.3 }, { s: 1.35, o: 1 });
    beats(sc, [[-0.35, 0.0, 0.27, 0.32], [0.33, 0.38, 0.62, 0.67], [0.68, 0.73]]);
    // the whole constellation turns and tightens; labels counter-rotate so they stay upright
    tl(sc).fns.push((q) => {
      const k = inOut(clamp(q / 0.85)), a = 40 * k, s = 1 - 0.1 * k;
      vis.style.transform = `rotate(${(rtl() ? -a : a).toFixed(2)}deg) scale(${s.toFixed(4)})`;
      const counter = `rotate(${(rtl() ? a : -a).toFixed(2)}deg) scale(${(1 / s).toFixed(4)})`;
      doms.forEach((d) => { d.style.transform = `translate(-50%, -50%) ${counter}`; });
      core.style.transform = `translate(-50%, -50%) ${counter}`;
    });
  })();

  /* ---------------- scene 6 · closing ---------------- */
  (function () {
    const sc = scenes[5]; if (!sc) return;
    frame(sc, true);
    add(sc, sc.querySelector(".sy-mark svg"), -0.35, 0.12, { o: 0, s: 0.6 }, { o: 1, s: 1 });
    all(sc, ".sy-mark .r").forEach((r, i) => add(sc, r, -0.2 + i * 0.1, 0.2 + i * 0.12, { o: 0, s: 0.4 }, { o: 1, s: 1 }));
    add(sc, sc.querySelector(".sy-word"), 0.08, 0.32, { o: 0, y: 40, s: 0.94 }, { o: 1, y: 0, s: 1 });
    add(sc, sc.querySelector(".sy-tagline"), 0.26, 0.42, { o: 0, y: 24 }, { o: 1, y: 0 });
    add(sc, sc.querySelector(".sy-state"), 0.36, 0.52, { o: 0, y: 24 }, { o: 1, y: 0 });
    add(sc, sc.querySelector(".sy-ctas"), 0.46, 0.6, { o: 0, y: 24 }, { o: 1, y: 0 });
  })();

  /* ---------------- measuring, the frame loop, visibility ---------------- */
  function measure() {
    for (const [sc, T] of TL) {
      const box = T.vis ? T.vis.getBoundingClientRect() : { width: innerWidth, height: innerHeight };
      T.W = box.width; T.H = box.height;
      if (T.measure) T.measure();
      if (T.fly) T.fly.forEach((n) => {   // fly-in offsets: from the centre of the visual to the node's place
        const rec = T.els.get(n); const l = parseFloat(n.style.left || getComputedStyle(n).left) / T.W, t = parseFloat(getComputedStyle(n).top) / T.H;
        const first = rec.tracks[0]; first.from.xf = (0.5 - l) * 0.9; first.from.yf = (0.5 - t) * 0.9; first.to.xf = 0; first.to.yf = 0;
        rec.props.add("xf"); rec.props.add("yf");
      });
      sc.querySelectorAll(".sy-layer").forEach((l, i) => { const rec = T.els.get(l); if (rec) rec.tracks[0].to.z = (4 - i) * l._step(); });
    }
  }
  const active = new Set();
  let ticking = false, cur = 0;
  const navLinks = [...root.querySelectorAll(".sy-nav a")];
  function render() {
    ticking = false;
    if (still) return;
    const vh = innerHeight;
    let best = 0, bestD = Infinity;
    for (const sc of active) {
      const r = sc.getBoundingClientRect();
      const q = clamp(-r.top / Math.max(1, r.height - vh), -1, 1.4);
      apply(sc, q);
      const d = Math.abs(r.top + r.height / 2 - vh / 2) - (q >= 0 && q <= 1 ? r.height : 0);
      if (d < bestD) { bestD = d; best = Number(sc.dataset.scene); }
    }
    if (best && best !== cur) { cur = best; navLinks.forEach((a) => { const on = a.dataset.go === String(best); a.classList.toggle("on", on); if (on) a.setAttribute("aria-current", "step"); else a.removeAttribute("aria-current"); }); }
  }
  function apply(sc, q) {
    const T = TL.get(sc); if (!T) return;
    for (const [el, rec] of T.els) evalEl(el, rec, q, T.W || 1, T.H || 1);
    for (const fn of T.fns) fn(q);
  }
  const schedule = () => { if (!ticking) { ticking = true; requestAnimationFrame(render); } };
  const io = new IntersectionObserver((es) => { es.forEach((e) => (e.isIntersecting ? active.add(e.target) : active.delete(e.target))); schedule(); }, { rootMargin: "10% 0px" });
  scenes.forEach((s) => io.observe(s));
  addEventListener("scroll", schedule, { passive: true });
  let rt = 0;
  addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => { measure(); scenes.forEach((s) => { const r = s.getBoundingClientRect(); apply(s, clamp(-r.top / Math.max(1, r.height - innerHeight), -1, 1.4)); }); }, 120); }, { passive: true });

  function clearStyles() {
    for (const [, T] of TL) for (const [el] of T.els) { el.style.transform = ""; el.style.opacity = ""; el.style.strokeDashoffset = ""; }
    root.querySelectorAll(".sy-capt, .sy-token, .sy-track, .sy-rail i, .sy-gauge i, .sy-dom, .sy-core, .sy-visual").forEach((n) => { n.style.transform = ""; n.style.opacity = ""; n.style.visibility = ""; });
    root.querySelectorAll(".sy-pk").forEach((c) => c.setAttribute("opacity", "0"));
    const score = root.querySelector(".sy-score b"); if (score) score.textContent = "55";
  }
  function setStill() {
    const s = isStill();
    if (s === still) return;
    still = s; root.classList.toggle("still", s);
    if (s) clearStyles(); else { measure(); schedule(); }
  }
  new MutationObserver(setStill).observe(html, { attributes: true, attributeFilter: ["class"] });
  const mq = matchMedia("(prefers-reduced-motion: reduce)"); if (mq.addEventListener) mq.addEventListener("change", setStill);

  /* ---------------- chapter rail: plain scrolling, never hijacked ---------------- */
  navLinks.forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault();
    const sc = document.getElementById(a.getAttribute("href").slice(1)); if (!sc) return;
    const top = sc.getBoundingClientRect().top + scrollY + (still ? -80 : 2);
    scrollTo({ top, behavior: still ? "auto" : "smooth" });
    sc.querySelector(".sy-title").setAttribute("tabindex", "-1");
    setTimeout(() => sc.querySelector(".sy-title").focus({ preventScroll: true }), still ? 0 : 700);
  }));

  /* ---------------- the deep dive: collapsed behind a button ---------------- */
  (function () {
    const deep = document.getElementById("sci-deep"), btn = document.getElementById("sci-deep-toggle");
    if (!deep || !btn) return;
    const head = deep.querySelector(".sci-deep-head");
    const parts = [...head.children].filter((n) => n !== btn && !n.matches(".sci-deep-title, .sci-deep-note")).concat([document.getElementById("sci-deep-body")]).filter(Boolean);
    const set = (open) => {
      parts.forEach((p) => { p.hidden = !open; });
      btn.setAttribute("aria-expanded", String(open));
      const label = btn.querySelector("span"); label.dataset.i18n = open ? "sciDeepHide" : "sciDeepShow";
      label.textContent = (CS.t && CS.t(label.dataset.i18n)) || label.textContent;
    };
    deep.classList.add("sy-ready");
    set(location.hash.startsWith("#sci-"));
    btn.addEventListener("click", () => set(btn.getAttribute("aria-expanded") !== "true"));
  })();

  measure();
  if (still) clearStyles(); else scenes.forEach((s) => { const r = s.getBoundingClientRect(); apply(s, clamp(-r.top / Math.max(1, r.height - innerHeight), -1, 1.4)); });
  schedule();
})();
