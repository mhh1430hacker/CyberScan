/* Page-wide effects: preloader, cursor, scroll progress, section dots,
 * word-by-word headings, marquee that reacts to scroll speed, ripples. */
(function () {
  "use strict";
  const { $, t } = window.CS;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(pointer: fine)").matches;
  const landing = $("landing");

  /* ---------------- preloader: see js/intro.js (the opening sequence) ---------------- */

  /* ---------------- cursor: js/cursor.js (the same "< >" cursor on every page) ---------------- */

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

  // the scan page (scan.ainex-ai.xyz) has no landing: cursor and ripples only
  if (!landing) return;

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
    // Runs only while the band is on screen; its width is measured on resize, not every frame.
    let marqueeOn = false, marqueeRaf = 0, half = track.scrollWidth / 2 || 1;
    new ResizeObserver(() => { half = track.scrollWidth / 2 || 1; }).observe(track);
    new IntersectionObserver((entries) => {
      marqueeOn = entries[0].isIntersecting;
      if (marqueeOn && !marqueeRaf) { lastT = performance.now(); lastY = scrollY; marqueeRaf = requestAnimationFrame(loop); }
    }).observe(track);
    const loop = (now) => {
      marqueeRaf = 0;
      if (!marqueeOn || landing.hidden || document.hidden) return;
      marqueeRaf = requestAnimationFrame(loop);
      const dt = Math.min(64, now - lastT); lastT = now;
      const dy = scrollY - lastY; lastY = scrollY;
      velocity += (dy - velocity) * 0.12;
      const dir = document.documentElement.dir === "rtl" ? 1 : -1;
      offset += dir * (0.045 * dt + Math.abs(velocity) * 0.9);
      if (Math.abs(offset) > half) offset += offset > 0 ? -half : half;
      const skew = Math.max(-12, Math.min(12, velocity * 0.35));
      track.style.transform = `translateX(${offset}px) skewX(${-skew}deg)`;
    };
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
    // the film's heading has its own entrance (film.js); rising words on top of it left the title
    // half hidden under the "// 01 · Watch" label while it scrolled in
    landing.querySelectorAll(".l-h2:not(.cine-head .l-h2)").forEach((h) => {
      const text = t(h.dataset.i18n);
      if (typeof text !== "string") return;
      h.removeAttribute("data-reveal");
      h.classList.add("in");
      h.replaceChildren();
      // Japanese, Chinese and Thai have no spaces: the browser finds the words, so a line can
      // only break between them (never inside a word), and nothing extra is inserted between them
      const noSpaces = ["ja", "zh", "th"].includes(window.CS.lang) && window.Intl && Intl.Segmenter;
      const parts = noSpaces ? [...new Intl.Segmenter(window.CS.lang, { granularity: "word" }).segment(text)].map((s) => s.segment).filter((s) => s.trim()) : text.split(/\s+/);
      parts.forEach((word, i, all) => {
        const mask = document.createElement("span");
        mask.className = "wmask";
        const w = document.createElement("span");
        w.className = "wd";
        w.style.setProperty("--i", i);
        w.textContent = word;
        mask.append(w);
        h.append(mask);
        if (i < all.length - 1 && !noSpaces) h.append(" ");
      });
      if (reduced) h.classList.add("words-in"); else headObserver.observe(h);
    });
  }
  window.CS.onLang(splitHeadings);
  splitHeadings();
  onScroll();
})();
