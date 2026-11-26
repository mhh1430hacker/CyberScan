/* Scroll scenes for the landing page. Original code; the techniques are the
 * common vocabulary of scroll storytelling:
 *   - inertial wheel scrolling (native scroll position, so sticky pins work)
 *   - a pinned manifesto whose words light up with scroll progress
 *   - a pinned section whose cards travel sideways as you scroll down
 *   - background tint that blends between sections
 *   - mask reveals (circle for the cube, wipe for the repair demo)
 *   - kinetic text bands driven by scroll position
 *   - stacking cards that shrink as the next one covers them
 *   - headings and grids that skew with scroll speed
 * Everything reads layout once per frame and writes transforms only.
 */
(function () {
  "use strict";
  const { $, el, t } = window.CS;
  const landing = $("landing");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(pointer: fine)").matches;
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const lerp = (a, b, k) => a + (b - a) * k;
  const rtl = () => document.documentElement.dir === "rtl";
  const visibleLanding = () => !landing.hidden && document.body.classList.contains("on-landing");

  /* ================= inertial wheel ================= */
  let target = scrollY, current = scrollY, gliding = false;
  const maxScroll = () => document.documentElement.scrollHeight - innerHeight;
  function glide() {
    current = lerp(current, target, 0.095);
    if (Math.abs(target - current) < 0.4) { current = target; gliding = false; }
    window.scrollTo({ top: current, behavior: "instant" });
    if (gliding) requestAnimationFrame(glide);
  }
  if (!reduced && fine) {
    window.addEventListener("wheel", (e) => {
      if (!visibleLanding() || e.ctrlKey || e.defaultPrevented) return;
      if (e.target.closest && e.target.closest("dialog, .palette, textarea, select, .cube-stage, .pal-list")) return;
      e.preventDefault();
      const unit = e.deltaMode === 1 ? 32 : e.deltaMode === 2 ? innerHeight : 1;
      if (!gliding) { current = scrollY; target = scrollY; }
      target = clamp(target + e.deltaY * unit, 0, maxScroll());
      if (!gliding) { gliding = true; requestAnimationFrame(glide); }
    }, { passive: false });
    // keys, scrollbar, anchors: follow the real position
    window.addEventListener("scroll", () => { if (!gliding) { target = current = scrollY; } }, { passive: true });
    window.addEventListener("keydown", () => { gliding = false; target = current = scrollY; });
  }

  /* ================= manifesto ================= */
  const mfSec = $("manifesto"), mfText = $("mf-text"), mfBar = $("mf-progress");
  let mfWords = [];
  function buildManifesto() {
    if (!mfText) return;                  // the manifesto was folded into the hero and the science story
    const keys = new Set(t("mfKeys"));
    mfText.replaceChildren();
    const text = t("manifesto");
    const add = (word, key) => { const span = el("span", key ? "mw key" : "mw", word); mfText.append(span); return span; };
    if (["zh", "ja", "th"].includes(window.CS.lang) && window.Intl && Intl.Segmenter) {
      // no spaces between words here: the browser finds the words, and a word is a key word
      // when it lies inside the first place one of the key phrases appears
      const marks = [...keys].map((k) => [text.indexOf(k), k.length]).filter(([at]) => at >= 0);
      mfWords = [...new Intl.Segmenter(window.CS.lang, { granularity: "word" }).segment(text)]
        .filter((s) => s.segment.trim())
        .map((s) => add(s.segment, marks.some(([at, n]) => s.index >= at && s.index + s.segment.length <= at + n)));
      return;
    }
    mfWords = text.split(/\s+/).map((w, i, all) => {
      const span = add(w, keys.has(w));
      if (i < all.length - 1) span.after(" ");
      return span;
    });
  }

  /* ================= horizontal pin ================= */
  // "How it works" is an ordinary grid now (it used to be a sideways pin): only a .hpin section pins
  const how = $("how") && $("how").classList.contains("hpin") ? $("how") : null;
  const track = how ? $("l-steps") : null;
  let travel = 0;
  function layoutHow() {
    if (!how) return;
    how.style.height = "";
    const viewport = track.parentElement.clientWidth;
    travel = Math.max(0, track.scrollWidth - viewport + 48);
    how.style.height = `${innerHeight + travel * 1.15}px`;
  }

  /* ================= bands ================= */
  function buildBands() {
    if (!$("band-a")) return;             // the decorative bands were removed (page length)
    $("band-a").textContent = t("bandA").repeat(6);
    $("band-b").textContent = t("bandB").repeat(6);
  }

  /* ================= tint ================= */
  const tint = $("tint");
  const tinted = [...document.querySelectorAll("[data-tint]")];
  const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));

  /* ================= per-frame =================
   * Performance rules (this ran at 17 ms a frame before):
   *   - work only while the page moves (scroll, glide, settling speed);
   *   - section positions are measured once (and again on resize), then each
   *     frame uses scrollY only: no layout reads in the loop, except for the
   *     sticky cards and the sideways steps, and only while they're on screen;
   *   - every style write is skipped when the value didn't change. */
  const cube = document.querySelector(".cube-stage");
  const bytes = $("bytes-demo");
  const bands = [...document.querySelectorAll(".band")];
  const bandsBox = document.querySelector(".bands");
  const skewables = [...document.querySelectorAll(".skewable")];
  const privGrid = document.querySelector("#priv-grid.stack");     // a plain grid now (shorter page): only a .stack grid is tracked
  let lastY = scrollY, velocity = 0, skew = 0, dirty = true;
  // page positions (top, height) measured in layout()
  const pos = new Map();
  const measure = (node) => { if (!node) return; const r = node.getBoundingClientRect(); pos.set(node, { top: r.top + scrollY, height: r.height }); };
  const stepOffsets = [];
  // last written values, so unchanged ones are not written again
  const written = new WeakMap();
  const put = (node, prop, value) => {
    let m = written.get(node); if (!m) { m = {}; written.set(node, m); }
    if (m[prop] === value) return;
    m[prop] = value;
    if (prop.startsWith("--")) node.style.setProperty(prop, value); else node.style[prop] = value;
  };
  const near = (p, vh, margin) => p && p.top - scrollY < vh + margin && p.top + p.height - scrollY > -margin;

  // the loop runs only while something moves: a scroll (or a re-measure) wakes it, and it
  // stops by itself once the speed has settled; an idle page costs no frames at all
  let looping = false;
  const wake = () => { if (!looping) { looping = true; requestAnimationFrame(frame); } };
  window.addEventListener("scroll", () => { dirty = true; wake(); }, { passive: true });

  function frame() {
    looping = false;
    if (!visibleLanding()) return;
    const moving = dirty || gliding || Math.abs(velocity) > 0.05 || Math.abs(skew) > 0.01;
    if (!moving) return;
    dirty = false;
    tick();
    wake();
  }
  function tick() {
    if (!visibleLanding()) return;
    const vh = innerHeight, y = scrollY;
    const dy = y - lastY; lastY = y;
    velocity = lerp(velocity, dy, 0.2);
    if (Math.abs(velocity) < 0.05) velocity = 0;

    // manifesto: words light in reading order
    const mpos = pos.get(mfSec);
    if (near(mpos, vh, vh)) {
      const mp = clamp((y - mpos.top) / Math.max(1, mpos.height - vh));
      const lit = mp * mfWords.length * 1.12;
      for (let i = 0; i < mfWords.length; i++) put(mfWords[i], "--k", clamp(lit - i).toFixed(2));
      put(mfBar, "transform", `scaleX(${mp.toFixed(3)})`);
    }

    // horizontal steps
    if (!stepOffsets.length && track && track.children.length) measureAll();   // measured before the steps existed
    const hpos = how && pos.get(how);
    if (how && near(hpos, vh, vh * 0.5)) {
      const hp = clamp((y - hpos.top) / Math.max(1, hpos.height - vh));
      const x = (rtl() ? 1 : -1) * travel * clamp(hp * 1.15 - 0.075);
      put(track, "transform", `translate3d(${x.toFixed(1)}px,0,0)`);
      const step = Math.min(4, 1 + Math.floor(clamp(hp * 1.15 - 0.075) * 4 * 0.999));
      const n = String(step).padStart(2, "0");
      const howN = $("how-n");
      if (howN.textContent !== n) howN.textContent = n;
      stepOffsets.forEach(([li, center]) => put(li, "--off", ((center + x) / innerWidth - 0.5).toFixed(3)));
    }

    // tint: blend the colours of the sections around the middle of the screen
    let a = tinted[0], b = tinted[0], k = 0;
    for (let i = 0; i < tinted.length; i++) {
      const p = pos.get(tinted[i]); if (!p) continue;
      const top = p.top - y;
      if (top <= vh * 0.5) { a = tinted[i]; b = tinted[i + 1] || tinted[i]; k = clamp((vh * 0.5 - top - (p.height - vh * 0.6)) / (vh * 0.6)); }
    }
    const ca = hex(a.dataset.tint), cb = hex(b.dataset.tint);
    put(tint, "background", `rgb(${ca.map((c, i) => Math.round(lerp(c, cb[i], k))).join(",")})`);

    // mask reveals
    const cpos = pos.get(cube);
    if (cube && near(cpos, vh, vh)) {
      const e = clamp((vh - (cpos.top - y)) / (vh * 0.75));
      put(cube, "clipPath", `circle(${(e * 78).toFixed(1)}% at 50% 50%)`);
      put(cube, "transform", `scale(${(0.86 + e * 0.14).toFixed(3)})`);
    }
    const bpos = pos.get(bytes);
    if (bytes && near(bpos, vh, vh)) {
      const e = clamp((vh - (bpos.top - y)) / (vh * 0.7));
      const hide = ((1 - e) * 100).toFixed(1);
      put(bytes, "clipPath", rtl() ? `inset(0 0 0 ${hide}% round 22px)` : `inset(0 ${hide}% 0 0 round 22px)`);
    }

    // kinetic bands
    const kpos = pos.get(bandsBox);
    if (bandsBox && near(kpos, vh, 200)) {
      const base = (vh - (kpos.top - y)) * 0.55;
      bands.forEach((band) => {
        const s = Number(band.dataset.speed);
        put(band.firstElementChild, "transform", `translate3d(${(s * base - (s > 0 ? 600 : 0)).toFixed(1)}px,0,0) skewX(${clamp(-velocity * 0.25 * s, -8, 8).toFixed(2)}deg)`);
      });
    }

    // stacking cards (sticky: their real positions are read, but only while on screen)
    if (privGrid && near(pos.get(privGrid), vh, 100)) {
      const cards = [...privGrid.querySelectorAll(".priv")];
      const rects = cards.map((c) => c.getBoundingClientRect());
      cards.forEach((c, i) => {
        let covered = 0;
        for (let j = i + 1; j < cards.length; j++) covered += clamp((rects[i].bottom - rects[j].top) / rects[i].height);
        put(c, "--covered", covered.toFixed(2));
      });
    }

    // skew with speed
    skew = lerp(skew, clamp(velocity * 0.12, -5, 5), 0.15);
    if (Math.abs(skew) < 0.01) skew = 0;
    const sk = `${skew.toFixed(2)}deg`;
    skewables.forEach((s) => put(s, "--skew", sk));
  }

  function measureAll() {
    pos.clear();
    [mfSec, how, cube, bytes, bandsBox, privGrid, ...tinted].filter(Boolean).forEach(measure);
    // the steps' centres with the track at rest (x = 0)
    stepOffsets.length = 0;
    if (track) {
      const saved = track.style.transform;
      track.style.transform = "none";
      const base = track.getBoundingClientRect().left;
      track.querySelectorAll("li").forEach((li) => { const r = li.getBoundingClientRect(); stepOffsets.push([li, base + (r.left - base) + r.width / 2]); });
      track.style.transform = saved;
    }
    dirty = true;
    wake();
  }
  function layout() { layoutHow(); measureAll(); }
  // fonts, images and translations change the page height: measure again
  if (window.ResizeObserver) new ResizeObserver(() => requestAnimationFrame(measureAll)).observe(landing);
  window.addEventListener("resize", layout);
  window.CS.onLang(() => { buildManifesto(); buildBands(); requestAnimationFrame(layout); });
  window.addEventListener("cs:landing", () => requestAnimationFrame(layout));
  buildManifesto();
  buildBands();
  // positions are measured when the ResizeObserver above reports the landing's first size (after
  // the browser's own layout, in a frame callback), not here: reading them in the middle of the
  // page's start-up forced an extra full-page layout
  layoutHow();
  if (!window.ResizeObserver) requestAnimationFrame(layout);
  if (reduced) {
    mfWords.forEach((w) => w.style.setProperty("--k", "1"));
  }
  wake();
  window.CSScroll = { tick, layout, measure: measureAll };
})();
