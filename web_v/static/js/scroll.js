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
    const keys = new Set(t("mfKeys"));
    mfText.replaceChildren();
    mfWords = t("manifesto").split(/\s+/).map((w, i, all) => {
      const span = el("span", keys.has(w) ? "mw key" : "mw", w);
      mfText.append(span);
      if (i < all.length - 1) mfText.append(" ");
      return span;
    });
  }

  /* ================= horizontal pin ================= */
  const how = $("how"), track = $("l-steps");
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
    $("band-a").textContent = t("bandA").repeat(6);
    $("band-b").textContent = t("bandB").repeat(6);
  }

  /* ================= tint ================= */
  const tint = $("tint");
  const tinted = [...document.querySelectorAll("[data-tint]")];
  const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));

  /* ================= per-frame ================= */
  const cube = document.querySelector(".cube-stage");
  const bytes = $("bytes-demo");
  const bands = [...document.querySelectorAll(".band")];
  const bandsBox = document.querySelector(".bands");
  const skewables = [...document.querySelectorAll(".skewable")];
  let lastY = scrollY, velocity = 0, skew = 0;

  function frame() {
    requestAnimationFrame(frame);
    tick();
  }
  function tick() {
    if (!visibleLanding()) return;
    const vh = innerHeight;
    const dy = scrollY - lastY; lastY = scrollY;
    velocity = lerp(velocity, dy, 0.2);

    // manifesto: words light in reading order
    const mr = mfSec.getBoundingClientRect();
    const mp = clamp(-mr.top / Math.max(1, mr.height - vh));
    const lit = mp * mfWords.length * 1.12;
    mfWords.forEach((w, i) => {
      const k = clamp(lit - i);
      w.style.setProperty("--k", k.toFixed(3));
    });
    mfBar.style.transform = `scaleX(${mp})`;

    // horizontal steps
    const hr = how.getBoundingClientRect();
    const hp = clamp(-hr.top / Math.max(1, hr.height - vh));
    const x = (rtl() ? 1 : -1) * travel * clamp(hp * 1.15 - 0.075);
    track.style.transform = `translate3d(${x.toFixed(1)}px,0,0)`;
    const step = Math.min(4, 1 + Math.floor(clamp(hp * 1.15 - 0.075) * 4 * 0.999));
    $("how-n").textContent = String(step).padStart(2, "0");
    track.querySelectorAll("li").forEach((li) => {
      const r = li.getBoundingClientRect();
      const center = (r.left + r.width / 2) / innerWidth - 0.5;
      li.style.setProperty("--off", center.toFixed(3));
    });

    // tint: blend the colours of the sections around the middle of the screen
    let a = tinted[0], b = tinted[0], k = 0;
    for (let i = 0; i < tinted.length; i++) {
      const r = tinted[i].getBoundingClientRect();
      if (r.top <= vh * 0.5) { a = tinted[i]; b = tinted[i + 1] || tinted[i]; k = clamp((vh * 0.5 - r.top - (r.height - vh * 0.6)) / (vh * 0.6)); }
    }
    const ca = hex(a.dataset.tint), cb = hex(b.dataset.tint);
    tint.style.background = `rgb(${ca.map((c, i) => Math.round(lerp(c, cb[i], k))).join(",")})`;

    // mask reveals
    if (cube) {
      const r = cube.getBoundingClientRect();
      const e = clamp((vh - r.top) / (vh * 0.75));
      cube.style.clipPath = `circle(${(e * 78).toFixed(1)}% at 50% 50%)`;
      cube.style.transform = `scale(${(0.86 + e * 0.14).toFixed(3)})`;
    }
    if (bytes) {
      const r = bytes.getBoundingClientRect();
      const e = clamp((vh - r.top) / (vh * 0.7));
      const hide = ((1 - e) * 100).toFixed(1);
      bytes.style.clipPath = rtl() ? `inset(0 0 0 ${hide}% round 22px)` : `inset(0 ${hide}% 0 0 round 22px)`;
    }

    // kinetic bands
    if (bandsBox) {
      const r = bandsBox.getBoundingClientRect();
      if (r.bottom > -200 && r.top < vh + 200) {
        const base = (vh - r.top) * 0.55;
        bands.forEach((band) => {
          const s = Number(band.dataset.speed);
          band.firstElementChild.style.transform = `translate3d(${(s * base - (s > 0 ? 600 : 0)).toFixed(1)}px,0,0) skewX(${clamp(-velocity * 0.25 * s, -8, 8).toFixed(2)}deg)`;
        });
      }
    }

    // stacking cards
    const cards = [...document.querySelectorAll("#priv-grid .priv")];
    const rects = cards.map((c) => c.getBoundingClientRect());
    cards.forEach((c, i) => {
      let covered = 0;
      for (let j = i + 1; j < cards.length; j++) covered += clamp((rects[i].bottom - rects[j].top) / rects[i].height);
      c.style.setProperty("--covered", covered.toFixed(3));
    });

    // skew with speed
    skew = lerp(skew, clamp(velocity * 0.12, -5, 5), 0.15);
    if (Math.abs(skew) > 0.01) skewables.forEach((s) => s.style.setProperty("--skew", `${skew.toFixed(2)}deg`));
  }

  function layout() { layoutHow(); }
  window.addEventListener("resize", layout);
  window.CS.onLang(() => { buildManifesto(); buildBands(); requestAnimationFrame(layout); });
  window.addEventListener("cs:landing", () => requestAnimationFrame(layout));
  buildManifesto();
  buildBands();
  layout();
  if (reduced) {
    mfWords.forEach((w) => w.style.setProperty("--k", "1"));
  }
  requestAnimationFrame(frame);
  window.CSScroll = { tick, layout };
})();
