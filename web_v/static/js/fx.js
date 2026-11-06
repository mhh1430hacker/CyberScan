/* Page-wide effects: preloader, cursor, scroll progress, section dots,
 * word-by-word headings, marquee that reacts to scroll speed, ripples. */
(function () {
  "use strict";
  const { $, t } = window.CS;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(pointer: fine)").matches;
  const landing = $("landing");

  /* ---------------- preloader ---------------- */
  const pre = $("preloader");
  let seen = false;
  try { seen = sessionStorage.getItem("cs-intro") === "1"; } catch { /* storage off */ }
  const onLandingNow = !/^#\/(scan|history|repair|settings)/.test(location.hash);
  if (reduced || seen || !onLandingNow) {
    pre.remove();
    document.body.classList.add("intro-done");
  } else {
    document.body.classList.add("intro");
    const num = pre.querySelector(".pl-num");
    const bar = pre.querySelector(".pl-bar i");
    const start = performance.now();
    const ms = 1700;
    const tick = (now) => {
      const k = Math.min(1, (now - start) / ms);
      const v = Math.round(100 * (1 - Math.pow(1 - k, 2.4)));
      num.textContent = String(v);
      bar.style.transform = `scaleX(${v / 100})`;
      if (k < 1) requestAnimationFrame(tick);
      else {
        pre.classList.add("open");
        document.body.classList.remove("intro");
        try { sessionStorage.setItem("cs-intro", "1"); } catch { /* storage off */ }
        setTimeout(() => { document.body.classList.add("intro-done"); window.dispatchEvent(new Event("cs:landing")); }, 450);
        setTimeout(() => pre.remove(), 1400);
      }
    };
    requestAnimationFrame(tick);
  }

  /* ---------------- cursor ---------------- */
  if (fine && !reduced) {
    const ring = document.querySelector(".cursor-ring");
    const dot = document.querySelector(".cursor-dot");
    const label = ring.querySelector("span");
    let x = innerWidth / 2, y = innerHeight / 2, rx = x, ry = y;
    document.body.classList.add("has-cursor");
    window.addEventListener("pointermove", (e) => {
      x = e.clientX; y = e.clientY;
      dot.style.transform = `translate(${x}px, ${y}px)`;
      const target = e.target.closest ? e.target.closest("a, button, .row, label.drop, canvas, input, select, textarea, .chip, .feat, .bento-card") : null;
      ring.classList.toggle("hover", !!target && !target.matches("canvas, input, textarea, select"));
      const drag = target && target.matches("#l-cube, #r-cube");
      ring.classList.toggle("drag", !!drag);
      label.textContent = drag ? (window.CS.lang === "ar" ? "اسحب" : "drag") : "";
      ring.classList.toggle("text", !!target && target.matches("input, textarea"));
    }, { passive: true });
    window.addEventListener("pointerdown", () => ring.classList.add("press"));
    window.addEventListener("pointerup", () => ring.classList.remove("press"));
    document.addEventListener("pointerleave", () => { ring.style.opacity = "0"; dot.style.opacity = "0"; });
    document.addEventListener("pointerenter", () => { ring.style.opacity = ""; dot.style.opacity = ""; });
    const follow = () => {
      rx += (x - rx) * 0.18; ry += (y - ry) * 0.18;
      ring.style.transform = `translate(${rx}px, ${ry}px)`;
      requestAnimationFrame(follow);
    };
    follow();
  }

  /* ---------------- ripples on every button ---------------- */
  document.addEventListener("pointerdown", (e) => {
    const b = e.target.closest && e.target.closest(".primary, .ghost, .chip, .tab, .rtab, .nav-btn");
    if (!b || reduced) return;
    const r = b.getBoundingClientRect();
    const s = document.createElement("span");
    s.className = "ripple";
    const d = Math.max(r.width, r.height) * 2.2;
    s.style.width = s.style.height = `${d}px`;
    s.style.left = `${e.clientX - r.left - d / 2}px`;
    s.style.top = `${e.clientY - r.top - d / 2}px`;
    if (getComputedStyle(b).position === "static") b.style.position = "relative";
    b.style.overflow = "hidden";
    b.append(s);
    s.addEventListener("animationend", () => s.remove());
  });

  /* ---------------- in-page links scroll without touching the router ---------------- */
  landing.addEventListener("click", (e) => {
    const a = e.target.closest("a[href^='#']");
    if (!a || a.getAttribute("href").startsWith("#/")) return;
    const target = document.getElementById(a.getAttribute("href").slice(1));
    if (!target) return;
    e.preventDefault();
    target.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  });
  document.querySelector(".side-dots").addEventListener("click", (e) => {
    const a = e.target.closest("a");
    if (!a) return;
    e.preventDefault();
    const target = document.getElementById(a.dataset.sec);
    if (target) target.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  });

  /* ---------------- scroll progress, dots, marquee velocity, parallax ---------------- */
  const bar = document.querySelector(".scroll-progress i");
  const dots = [...document.querySelectorAll(".side-dots a")];
  const track = $("marquee");
  const aurora = document.querySelector(".aurora");
  const heroCopy = document.querySelector(".hero-copy");
  let lastY = scrollY, velocity = 0, offset = 0, lastT = performance.now();
  function onScroll() {
    if (landing.hidden) return;
    const max = document.documentElement.scrollHeight - innerHeight;
    bar.style.transform = `scaleX(${max > 0 ? scrollY / max : 0})`;
    let active = dots[0];
    for (const d of dots) {
      const s = document.getElementById(d.dataset.sec);
      if (s && s.getBoundingClientRect().top < innerHeight * 0.45) active = d;
    }
    dots.forEach((d) => d.classList.toggle("on", d === active));
    if (!reduced) {
      const y = scrollY;
      aurora.style.transform = `translateY(${y * 0.35}px)`;
      heroCopy.style.transform = `translateY(${y * -0.08}px)`;
      heroCopy.style.opacity = String(Math.max(0, 1 - y / (innerHeight * 0.9)));
    }
  }
  window.addEventListener("scroll", onScroll, { passive: true });

  if (!reduced && track) {
    track.style.animation = "none";
    const loop = (now) => {
      requestAnimationFrame(loop);
      if (landing.hidden) return;
      const dt = Math.min(64, now - lastT); lastT = now;
      const dy = scrollY - lastY; lastY = scrollY;
      velocity += (dy - velocity) * 0.12;
      const dir = document.documentElement.dir === "rtl" ? 1 : -1;
      offset += dir * (0.045 * dt + Math.abs(velocity) * 0.9);
      const half = track.scrollWidth / 2 || 1;
      if (Math.abs(offset) > half) offset += offset > 0 ? -half : half;
      const skew = Math.max(-12, Math.min(12, velocity * 0.35));
      track.style.transform = `translateX(${offset}px) skewX(${-skew}deg)`;
    };
    requestAnimationFrame(loop);
  }

  /* ---------------- headings that rise word by word ---------------- */
  const headObserver = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      e.target.classList.add("words-in");
      headObserver.unobserve(e.target);
    });
  }, { threshold: 0.3 });
  function splitHeadings() {
    landing.querySelectorAll(".l-h2").forEach((h) => {
      const text = t(h.dataset.i18n);
      if (typeof text !== "string") return;
      h.removeAttribute("data-reveal");
      h.classList.add("in");
      h.replaceChildren();
      text.split(/\s+/).forEach((word, i, all) => {
        const mask = document.createElement("span");
        mask.className = "wmask";
        const w = document.createElement("span");
        w.className = "wd";
        w.style.setProperty("--i", i);
        w.textContent = word;
        mask.append(w);
        h.append(mask);
        if (i < all.length - 1) h.append(" ");
      });
      if (reduced) h.classList.add("words-in"); else headObserver.observe(h);
    });
  }
  window.CS.onLang(splitHeadings);
  splitHeadings();
  onScroll();
})();
