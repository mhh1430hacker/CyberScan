/* "Originality" (#origin, origin.css) and the real visit counter (#visits) on the landing.
 *
 * Originality is a pinned scroll scene: the section is taller than the screen and its stage sticks;
 * the scroll position p (0..1) draws a fingerprint ridge by ridge (gold -> violet -> cyan, picking up
 * the Saudi scene's gold), moves a scan beam over it, brings the five pillars in one after another
 * and finally stamps a "Made here" seal. Work happens only while the section is on screen, inside one
 * requestAnimationFrame per scroll event (no loop when nothing moves). Phones (fx-scenes-static),
 * reduced motion and no-JS get the finished frame.
 * The visit counter reads GET /api/visits and counts up to it once it comes into view. */
(function () {
  "use strict";
  const CS = window.CS || {};
  const t = (k) => (CS.t ? CS.t(k) : k);
  const html = document.documentElement;
  const still = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion")
    || html.classList.contains("fx-scenes-static") || innerWidth <= 760;

  /* ---------------- the fingerprint, built once ---------------- */
  const root = document.getElementById("origin");
  if (root) {
    const svg = root.querySelector(".og-print");
    const NS = "http://www.w3.org/2000/svg";
    const ridges = [];
    if (svg) {
      // concentric, slightly irregular loops open at the bottom, like a fingertip's whorl
      const N = 15;
      for (let i = 0; i < N; i++) {
        const r = 14 + i * 9.2, rx = r * (0.82 + 0.03 * Math.sin(i * 1.7)), ry = r * 1.08;
        const gap = 0.32 + 0.05 * Math.sin(i * 2.3) + (i > 10 ? 0.12 : 0);     // the opening at the bottom
        const start = Math.PI / 2 + gap, end = Math.PI * 2.5 - gap;
        let d = "";
        const steps = 64;
        for (let s = 0; s <= steps; s++) {
          const a = start + (end - start) * (s / steps);
          const wob = 1 + 0.025 * Math.sin(a * 5 + i) + 0.015 * Math.sin(a * 11 - i * 2);
          const x = Math.cos(a) * rx * wob, y = Math.sin(a) * ry * wob - 6;
          d += (s ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
        }
        const p = document.createElementNS(NS, "path");
        p.setAttribute("d", d);
        p.setAttribute("pathLength", "1");
        p.setAttribute("class", "og-ridge");
        p.style.setProperty("--i", i);
        p.style.stroke = `url(#og-grad)`;
        svg.querySelector(".og-ridges").append(p);
        ridges.push(p);
      }
    }
    const pillars = [...root.querySelectorAll(".og-pillar")];
    const bar = root.querySelector(".og-progress i");
    const clamp = (x) => Math.max(0, Math.min(1, x));
    let raf = 0, on = false, lastActive = -1;

    function paint(p) {
      // ridges draw inside-out over the first 85% of the scroll
      for (let i = 0; i < ridges.length; i++) {
        const k = clamp((p * 1.18 - (i / ridges.length) * 0.85) / 0.22);
        ridges[i].style.strokeDashoffset = (1 - k).toFixed(3);
        ridges[i].style.opacity = (0.25 + 0.75 * k).toFixed(2);
      }
      root.style.setProperty("--og-p", p.toFixed(3));
      const active = Math.min(pillars.length - 1, Math.floor(p * pillars.length * 0.999));
      if (active !== lastActive) {
        pillars.forEach((el, i) => { el.classList.toggle("is-on", i === active); el.classList.toggle("is-done", i < active); });
        if (lastActive !== -1 && active > lastActive) { try { window.CSAudio?.play?.("tick"); } catch { /* no sound */ } }
        lastActive = active;
      }
      root.classList.toggle("og-sealed", p > 0.9);
      if (bar) bar.style.transform = `scaleX(${p.toFixed(3)})`;
    }
    function measure() {
      raf = 0;
      const r = root.getBoundingClientRect(), span = r.height - innerHeight;
      paint(span > 0 ? clamp(-r.top / span) : 1);
    }
    function apply() {
      const calm = still();
      root.classList.toggle("og-js", !calm);
      root.classList.toggle("still", calm);
      if (calm) { paint(1); pillars.forEach((el) => { el.classList.add("is-done"); el.classList.remove("is-on"); }); }
      else measure();
    }
    if (ridges.length) {
      apply();
      new IntersectionObserver((es) => { on = es[0].isIntersecting; if (on && !still()) measure(); }, { rootMargin: "100px 0px" }).observe(root);
      addEventListener("scroll", () => { if (on && !raf && !still()) raf = requestAnimationFrame(measure); }, { passive: true });
      addEventListener("resize", apply, { passive: true });
      new MutationObserver(apply).observe(html, { attributes: true, attributeFilter: ["class"] });
    }
  }

  /* ---------------- the ledger: counts up when it arrives; borrowed figures read live ---------------- */
  const ledger = document.getElementById("og-ledger");
  if (ledger) {
    const nums = [...ledger.querySelectorAll(".ogl-n")];
    // bar lengths: set through the CSSOM (the page's CSP forbids inline style attributes)
    ledger.querySelectorAll(".ogl-bar[data-w]").forEach((b) => b.style.setProperty("--w", b.dataset.w));
    const nf = () => { try { return new Intl.NumberFormat(CS.lang === "ar" ? "ar-SA-u-nu-latn" : (CS.lang || "en")); } catch { return { format: String }; } };
    const show = (el, v) => { el.textContent = (el.dataset.prefix || "") + nf().format(v); };
    let counted = false;
    function count() {
      counted = true;
      ledger.classList.add("in");
      if (still()) { nums.forEach((el) => show(el, +el.dataset.n)); return; }
      const t0 = performance.now(), dur = 1700;
      const step = (now) => {
        const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 4);
        nums.forEach((el) => show(el, Math.round(+el.dataset.n * e)));
        if (k < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }
    nums.forEach((el) => show(el, still() ? +el.dataset.n : 0));
    if (still()) count();
    else new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { count(); o.disconnect(); } }, { threshold: 0.25 }).observe(ledger);
    // the borrowed figures come from the engine itself, so they stay true after every rules update
    if (CS.api) CS.api("/api/protection").then((p) => {
      nums.forEach((el) => { const v = p && +p[el.dataset.live]; if (el.dataset.live && v > 0) { el.dataset.n = String(v); if (counted) show(el, v); } });
    }).catch(() => { /* the figures from the code stay */ });
    if (CS.onLang) CS.onLang(() => { if (counted) nums.forEach((el) => show(el, +el.dataset.n)); });
  }

  /* ---------------- the real visit counter ---------------- */
  const box = document.getElementById("visits");
  if (!box) return;
  const num = box.querySelector(".vs-n"), since = box.querySelector(".vs-since");
  let data = null, shown = false;
  const fmt = (n) => { try { return new Intl.NumberFormat(CS.lang === "ar" ? "ar-SA-u-nu-latn" : (CS.lang || "en")).format(n); } catch { return String(n); } };
  function label() {
    if (!data) return;
    let d = data.since || "";
    try { if (d) d = new Intl.DateTimeFormat(CS.lang || "en", { year: "numeric", month: "long", day: "numeric" }).format(new Date(d + "T12:00:00")); } catch { /* raw date */ }
    since.textContent = t("vsSince").replace("{d}", d);
    if (shown) num.textContent = fmt(data.count);
  }
  function countUp() {
    if (!data || shown) return;
    shown = true;
    const end = data.count, calm = still();
    if (calm || end < 2) { num.textContent = fmt(end); return; }
    const t0 = performance.now(), dur = 1600;
    const step = (now) => {
      const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 4);
      num.textContent = fmt(Math.round(end * e));
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  fetch("/api/visits", { cache: "no-store" }).then((r) => (r.ok ? r.json() : null)).then((j) => {
    if (!j || typeof j.count !== "number") return;
    data = j; box.hidden = false; label();
    new IntersectionObserver((es, o) => { if (es[0].isIntersecting) { countUp(); o.disconnect(); } }, { threshold: 0.4 }).observe(box);
  }).catch(() => { /* the counter simply stays hidden */ });
  if (CS.onLang) CS.onLang(label);
})();
