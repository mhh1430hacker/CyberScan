/* "صُنع بأيدٍ سعودية" (#saudi): one pinned scene driven by native scroll.
 *
 * The section is 270vh tall and its stage is sticky. One rect read per frame gives the progress q
 * (0 when the stage pins, 1 when it lets go). Every effect is a function of q, so scrolling back
 * plays it backwards, and nothing runs while the section is off screen.
 *   0.00–0.30  the central eight-pointed star draws itself, light rays and glow come up
 *   0.15–0.60  the rings of stars draw outward while the whole pattern turns and the camera pushes in
 *   0.28–0.62  the Kufic headline appears as an outline, then fills with light from right to left
 *   0.55–0.80  the line below, then Vision · Craft · Security rise in
 *   0.78–0.92  the seal stamps in with a flash
 *   0.93–1.30  the scene flies through towards the next section
 * Around it: gold dust rises, beams of light fall from above, gold corners draw a frame, a band of
 * light crosses the filled headline, a ring of text turns around the seal and a burst marks the
 * stamp. Each beat also has a sound (js/sfx.js), played only when scrolling forwards.
 * Reduced motion and no-JS: the finished composition, unpinned; this script writes no styles. */
(function () {
  "use strict";
  const sec = document.getElementById("saudi");
  if (!sec) return;
  const html = document.documentElement;
  // The performance engine's "static scenes" level is honoured when the page loads. If it is reached
  // later, mid-visit, the scenes keep their pinned layout: un-pinning them then removed thousands of
  // pixels above the reader at once (a layout shift of ~0.9 measured on a phone).
  const staticAtStart = html.classList.contains("fx-scenes-static");
  const isStill = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion") || staticAtStart;
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const ease = (t) => 1 - Math.pow(1 - t, 3);
  const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const backOut = (t) => { const c = 1.6, d = t - 1; return 1 + (c + 1) * d * d * d + c * d * d; };
  const seg = (q, a, b, f = ease) => f(clamp((q - a) / (b - a)));
  const $ = (s) => sec.querySelector(s), $$ = (s) => [...sec.querySelectorAll(s)];
  // The section is 180vh (it was 270vh). The scroll progress is mapped so that the headline is
  // already drawn in outline when the stage pins: no near-empty green screen right after the hero.
  // Now 125vh: the build runs while the scene scrolls in (from 0.6 of a screen below the top) and
  // through its short pin, so no stretch of it shows an empty green screen.
  const progress = () => { const r = sec.getBoundingClientRect(), lead = innerHeight * 0.6, span = lead + Math.max(1, r.height - innerHeight); return clamp(-0.2 + 1.25 * ((lead - r.top) / span), -1, 0.95); };   // it no longer flies out: it scrolls away whole (no empty screen after it)

  const stage = $(".ks-center"), pattern = $(".ks-pattern"), rays = $(".ks-rays"), glow = $(".ks-glow");
  const centre = $$(".ks-c, .ks-c2, .ks-c3"), ring1 = $$(".ks-r1"), band = $(".ks-band"), ring2 = $$(".ks-r2"), outer = $(".ks-c4");
  const kicker = $(".ks-kicker"), outline = $(".ks-outline"), fill = $(".ks-fill"), sub = $(".ks-sub"), words = $$(".ks-words li");
  const seal = $(".ks-seal"), flash = $(".ks-flash"), end = $(".ks-end");
  const beams = $(".ks-beams"), corners = $$(".ks-cp"), cdots = $$(".ks-cd"), orn = $(".ks-orn"), burst = $(".ks-burst"), sealText = $(".ks-seal-text"), dust = $(".ks-dust");
  const ornLines = $$(".ks-orn i"), ornGem = $(".ks-orn b");
  const touched = [stage, pattern, rays, glow, kicker, outline, fill, sub, seal, flash, end, ...words, beams, orn, burst, sealText, ...ornLines, ornGem, ...cdots];

  let still = isStill();
  sec.classList.add("ks-js");
  sec.classList.toggle("still", still);

  const draw = (el, t) => { el.style.strokeDashoffset = (1 - t).toFixed(4); };
  const show = (el, o, transform) => { el.style.opacity = o.toFixed(3); if (transform != null) el.style.transform = transform; };

  function apply(q) {
    // the scene arrives from depth and leaves by flying through the screen
    const enter = seg(q, -0.55, 0.02), leave = seg(q, 0.93, 1.3, (t) => t * t);
    stage.style.opacity = (enter * (1 - leave)).toFixed(3);
    stage.style.transform = `translateY(${((1 - enter) * 70 - leave * 30).toFixed(1)}px) scale(${(0.88 + 0.12 * enter + 0.2 * leave).toFixed(4)})`;

    // pattern: the centre draws, then the rings, while everything turns and the camera pushes in
    centre.forEach((p, i) => draw(p, seg(q, -0.3 + i * 0.08, 0.12 + i * 0.08, inOut)));
    ring1.forEach((p, i) => draw(p, seg(q, 0.12 + i * 0.025, 0.32 + i * 0.025)));
    draw(band, seg(q, 0.26, 0.5, inOut));
    ring2.forEach((p, i) => draw(p, seg(q, 0.3 + i * 0.012, 0.48 + i * 0.012)));
    draw(outer, seg(q, 0.4, 0.62, inOut));
    const turn = inOut(clamp((q + 0.4) / 1.6)), push = seg(q, 0.0, 1.0, inOut);
    pattern.style.transform = `rotate(${(-25 + 55 * turn).toFixed(2)}deg) scale(${(0.72 + 0.5 * push + 0.6 * leave).toFixed(4)})`;
    pattern.style.opacity = (seg(q, -0.4, 0.05) * (1 - 0.35 * seg(q, 0.62, 0.85)) * (1 - leave)).toFixed(3);
    rays.style.opacity = (0.5 * seg(q, -0.2, 0.3) * (1 - leave)).toFixed(3);
    glow.style.opacity = (seg(q, -0.2, 0.25) * (1 - leave)).toFixed(3);
    glow.style.transform = `scale(${(0.6 + 0.6 * seg(q, -0.2, 0.6) + 0.4 * seg(q, 0.78, 0.86, backOut)).toFixed(4)})`;

    // headline: kicker, outline, then the fill sweeps in from the right (Arabic reading direction)
    const k = seg(q, -0.1, 0.12);
    show(kicker, k, `translateY(${((1 - k) * 18).toFixed(1)}px)`);
    kicker.style.letterSpacing = html.dir === "rtl" ? "" : `${(0.6 - 0.3 * k).toFixed(3)}em`;
    const o = seg(q, 0.0, 0.3);
    show(outline, o, `translateY(${((1 - o) * 40).toFixed(1)}px) rotateX(${((1 - o) * 55).toFixed(2)}deg) scale(${(0.9 + 0.1 * o).toFixed(4)})`);
    const f = seg(q, 0.2, 0.6, inOut);
    fill.style.clipPath = `inset(-10% 0 -10% ${((1 - f) * 100).toFixed(2)}%)`;
    fill.style.transform = outline.style.transform;
    fill.style.backgroundPosition = `${(100 - 100 * seg(q, 0.25, 0.85, (t) => t)).toFixed(1)}% 0`;

    // the line below, then the three words
    const s = seg(q, 0.52, 0.64);
    show(sub, s, `translateY(${((1 - s) * 26).toFixed(1)}px)`);
    words.forEach((w, i) => { const t = seg(q, 0.6 + i * 0.05, 0.7 + i * 0.05, backOut); show(w, clamp(t), `translateY(${((1 - t) * 30).toFixed(1)}px) scale(${(0.8 + 0.2 * t).toFixed(4)})`); });

    // the seal stamps in with a flash; the closing line follows
    const st = seg(q, 0.76, 0.88, backOut);
    show(seal, clamp(st * 1.4), `scale(${(1.9 - 0.9 * st).toFixed(4)}) rotate(${((1 - st) * -40).toFixed(2)}deg)`);
    const fl = clamp((q - 0.84) / 0.1);
    show(flash, fl > 0 && fl < 1 ? 1 - fl : 0, `scale(${(0.6 + 1.6 * fl).toFixed(4)})`);
    const e = seg(q, 0.84, 0.92);
    show(end, e, `translateY(${((1 - e) * 16).toFixed(1)}px)`);

    // the luxury layers
    beams.style.opacity = (seg(q, -0.3, 0.25) * (1 - leave) * 0.95).toFixed(3);
    beams.style.transform = `rotate(${(-6 + 12 * seg(q, -0.3, 1, (t) => t)).toFixed(2)}deg) scaleY(${(0.7 + 0.3 * seg(q, -0.3, 0.3)).toFixed(3)})`;
    corners.forEach((c, i) => draw(c, seg(q, 0.0 + (i % 2) * 0.06, 0.32 + (i % 2) * 0.06, inOut)));
    const cd = seg(q, 0.3, 0.42);
    cdots.forEach((d) => { d.style.opacity = cd.toFixed(3); });
    const on = seg(q, 0.5, 0.62, inOut);
    ornLines.forEach((l) => { l.style.transform = `scaleX(${on.toFixed(4)})`; });
    const og = seg(q, 0.56, 0.66, backOut);
    show(ornGem, clamp(og), `scale(${og.toFixed(4)})`);
    const sr = seg(q, 0.8, 0.95);
    show(sealText, sr, `scale(${(0.7 + 0.3 * sr).toFixed(4)})`);
    const bu = clamp((q - 0.8) / 0.14);
    show(burst, bu > 0 && bu < 1 ? Math.sin(Math.PI * bu) : 0, `scale(${(0.5 + 0.9 * bu).toFixed(4)}) rotate(${(bu * 30).toFixed(2)}deg)`);
    sec.classList.toggle("lit", q > 0.62 && q < 1.05);
    dustLevel = seg(q, -0.4, 0.1) * (1 - leave);
    dustLift = q;
    sound(q);
  }

  /* ---------- sound: each beat once, scrolling forwards ---------- */
  let lastQ = null;
  const BEATS = [[-0.3, "rise"], [0.0, "boom"], [0.22, "shimmer"], [0.6, "chord"], [0.66, "pluck", { k: 4 }], [0.71, "pluck", { k: 5 }], [0.76, "pluck", { k: 7 }], [0.82, "stamp"], [0.97, "whoosh", { dur: 1.1 }]];
  function sound(q) {
    const fx = window.CSSfx;
    if (!fx) return;
    if (lastQ !== null && q > lastQ && q - lastQ < 0.25) BEATS.forEach(([at, name, o]) => { if (lastQ < at && q >= at) fx.play(name, o); });
    lastQ = q;
    fx.drone(visible ? seg(q, -0.35, 0.1) * (1 - seg(q, 0.92, 1.2)) : 0);
  }

  /* ---------- gold dust: slow motes that rise and drift, drawn only while the scene is on screen ---------- */
  let dustLevel = 0, dustLift = 0, motes = [], dustRaf = 0, dctx = null, dw = 0, dh = 0;
  // one soft glow drawn once per colour (gold, mint), then stamped: no gradient per mote per frame
  const SPRITES = ["255,228,160", "160,255,210"].map((rgb) => {
    const c = document.createElement("canvas"); c.width = c.height = 32;
    const x = c.getContext("2d"), g = x.createRadialGradient(16, 16, 0, 16, 16, 16);
    g.addColorStop(0, `rgba(${rgb},1)`); g.addColorStop(0.35, `rgba(${rgb},.45)`); g.addColorStop(1, `rgba(${rgb},0)`);
    x.fillStyle = g; x.fillRect(0, 0, 32, 32);
    return c;
  });
  function sizeDust() {
    const dpr = Math.min(2, devicePixelRatio || 1);
    dw = dust.clientWidth; dh = dust.clientHeight;
    dust.width = Math.round(dw * dpr); dust.height = Math.round(dh * dpr);
    dctx = dust.getContext("2d"); dctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const n = Math.round(Math.min(90, (dw * dh) / 16000));                // made once at full size; the budget decides how many are drawn
    motes = Array.from({ length: n }, () => ({ x: Math.random() * dw, y: Math.random() * dh, z: 0.3 + Math.random() * 0.7, r: 0.6 + Math.random() * 1.8, s: 6 + Math.random() * 18, w: Math.random() * 6.28, hue: Math.random() < 0.7 ? 0 : 1 }));
  }
  function drawDust(now) {
    dustRaf = 0;
    if (still || !sec.classList.contains("on") || document.hidden) return;
    if (!dctx || dust.clientWidth !== dw || dust.clientHeight !== dh) sizeDust();
    const t = now / 1000;
    dctx.clearRect(0, 0, dw, dh);
    if (dustLevel > 0.01) {
      const lim = Math.round(motes.length * (window.CSAdapt ? CSAdapt.eased("particles") : 1));   // the particle budget, eased
      for (let mi = 0; mi < lim; mi++) {
        const m = motes[mi];
        const y = ((m.y - t * m.s * m.z - dustLift * 260 * m.z) % dh + dh) % dh;
        const x = m.x + Math.sin(t * 0.4 + m.w) * 14 * m.z;
        const tw = 0.55 + 0.45 * Math.sin(t * 2 + m.w * 3);
        dctx.globalAlpha = Math.min(1, dustLevel * tw * m.z);
        const d = m.r * 8;
        dctx.drawImage(SPRITES[m.hue], x - d / 2, y - d / 2, d, d);
      }
      dctx.globalAlpha = 1;
    }
    dustRaf = requestAnimationFrame(drawDust);
  }
  new MutationObserver(() => { if (sec.classList.contains("on") && !dustRaf && !still) dustRaf = requestAnimationFrame(drawDust); }).observe(sec, { attributes: true, attributeFilter: ["class"] });
  if (window.CSAdapt) CSAdapt.register("saudi", sec, "particles");

  function clearStyles() {
    touched.forEach((el) => { el.style.opacity = ""; el.style.transform = ""; el.style.clipPath = ""; el.style.backgroundPosition = ""; el.style.letterSpacing = ""; });
    $$(".ks-p, .ks-cp").forEach((p) => { p.style.strokeDashoffset = ""; });
    ornLines.forEach((l) => { l.style.transform = ""; });
    sec.classList.remove("on", "lit");
    if (window.CSSfx) CSSfx.drone(0);
  }

  let ticking = false, visible = false;
  function render() {
    ticking = false;
    if (still || !visible) return;
    const q = progress();
    apply(q);
    sec.classList.toggle("on", q > -0.4 && q < 1.05);
  }
  const schedule = () => { if (!ticking) { ticking = true; requestAnimationFrame(render); } };
  new IntersectionObserver((es) => { visible = es[0].isIntersecting; if (!visible) { sec.classList.remove("on", "lit"); if (window.CSSfx) CSSfx.drone(0); } schedule(); }, { rootMargin: "20% 0px" }).observe(sec);
  addEventListener("scroll", schedule, { passive: true });
  addEventListener("resize", schedule, { passive: true });

  function setStill() {
    const s = isStill(); if (s === still) return;
    still = s; sec.classList.toggle("still", s);
    if (s) clearStyles(); else { visible = true; schedule(); }
  }
  new MutationObserver(setStill).observe(html, { attributes: true, attributeFilter: ["class"] });
  const mq = matchMedia("(prefers-reduced-motion: reduce)"); if (mq.addEventListener) mq.addEventListener("change", setStill);

  if (still) clearStyles(); else apply(progress());
})();
