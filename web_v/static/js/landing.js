/* Landing page: content, reveals and motion. */
(function () {
  "use strict";
  const { $, el, t, api, cells } = window.CS;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const landing = $("landing");

  const FEAT_ICONS = [
    "M4 6h16M4 12h10M4 18h7",                                                   // plain words
    "M12 2 3 7v10l9 5 9-5V7zM3 7l9 5 9-5M12 12v10",                              // cube
    "M14.7 6.3a4 4 0 0 0-5.4 5.2L3.5 17.3a1.8 1.8 0 0 0 2.5 2.5l5.8-5.8a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.3-.5-.5-2.3z", // repair
    "M6 10V7a6 6 0 1 1 12 0v3M5 10h14v11H5zM12 14v3",                            // lock
    "M12 3v3M12 18v3M3 12h3M18 12h3M6 6l2 2M16 16l2 2M6 18l2-2M16 8l2-2M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z", // ai
    "M12 4v11m-5-5 5 5 5-5M5 20h14",                                             // downloads
    "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18", // globe
    "M3.5 12a8.5 8.5 0 1 0 2.5-6M3.5 4v4h4M12 7.5V12l3 2",                       // history
  ];
  const PRIV_ICONS = [
    "M4 5h16v11H4zM8 20h8M12 16v4",
    "M12 3 4 6v6c0 5 3.4 8.6 8 9.7 4.6-1.1 8-4.7 8-9.7V6zM9 12l2 2 4-4",
    "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 8v5M12 16h.01",
  ];
  const svg = (d) => `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${d}"/></svg>`;

  /* ---------------- content ---------------- */
  function splitTitle() {
    let i = 0;
    landing.querySelectorAll(".word-wrap").forEach((wrap) => {
      const words = t(wrap.dataset.i18n).split(/\s+/);
      wrap.replaceChildren();
      words.forEach((word, n) => {
        const w = el("span", "w", word);
        w.style.setProperty("--i", i++);
        wrap.append(w);
        if (n < words.length - 1) wrap.append(" ");
      });
    });
  }

  function build() {
    splitTitle();
    const items = t("marquee");
    $("marquee").replaceChildren(...[...items, ...items].map((x) => el("span", "", x)));

    $("l-steps").replaceChildren(...t("steps").map(([title, body], i) => {
      const li = el("li");
      li.setAttribute("data-reveal", "");
      li.style.setProperty("--i", i);
      li.append(el("span", "num", String(i + 1).padStart(2, "0")), el("b", "", title), el("p", "", body));
      return li;
    }));

    const colors = ["rgb(30,58,138)", "rgb(56,189,248)", "rgb(244,114,182)", "rgb(248,113,113)"];
    $("l-legend").replaceChildren(...t("lCubeLegend").map((label, i) => {
      const li = el("li"); const sw = el("i"); sw.style.background = colors[i]; li.append(sw, label); return li;
    }));

    $("feat-grid").replaceChildren(...t("feats").map(([title, body], i) => {
      const card = el("div", "feat");
      card.setAttribute("data-reveal", "");
      card.style.setProperty("--i", i % 4);
      const icon = el("div", "ficon");
      icon.innerHTML = svg(FEAT_ICONS[i]);
      card.append(icon, el("b", "", title), el("p", "", body));
      return card;
    }));

    $("r-checks").replaceChildren(...t("lRepairChecks").map((x, i) => { const li = el("li", "", x); li.style.setProperty("--i", i); return li; }));

    $("priv-grid").replaceChildren(...t("privs").map(([title, body], i) => {
      const card = el("div", "priv");
      card.setAttribute("data-reveal", "");
      card.style.setProperty("--i", i);
      const icon = el("div", "pi");
      icon.innerHTML = svg(PRIV_ICONS[i]);
      card.append(icon, el("b", "", title), el("p", "", body));
      return card;
    }));

    $("stats-grid").replaceChildren(...t("stats").map(([label, key], i) => {
      const card = el("div", "stat");
      card.setAttribute("data-reveal", "");
      card.style.setProperty("--i", i);
      const num = el("b", "", "0");
      num.dataset.stat = key;
      card.append(num, el("span", "", label));
      return card;
    }));
    buildBytes();
    observeReveals();
    wireTilt();
    if (stats) fillStats();
  }

  /* ---------------- reveals ---------------- */
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("in");
      revealObserver.unobserve(entry.target);
      if (entry.target.dataset.stat !== undefined) countStats();
    });
  }, { threshold: 0.15, rootMargin: "0px 0px -6% 0px" });
  function observeReveals() {
    landing.querySelectorAll("[data-reveal]:not(.in)").forEach((node) => {
      if (reduced) node.classList.add("in"); else revealObserver.observe(node);
    });
  }

  /* ---------------- eyebrow scramble ---------------- */
  function scramble(node) {
    if (reduced) return;
    const target = t(node.dataset.i18n);
    const glyphs = "▚▞▖▗▘▝⬡01ABCDEF#%";
    let frame = 0;
    const total = 28;
    const tick = () => {
      frame++;
      const done = Math.floor((frame / total) * target.length);
      node.textContent = target.slice(0, done) + [...target.slice(done)].map((ch) => (ch === " " ? " " : glyphs[(Math.random() * glyphs.length) | 0])).join("");
      if (frame < total) requestAnimationFrame(tick); else node.textContent = target;
    };
    tick();
  }

  /* ---------------- hero card ---------------- */
  const card = landing.querySelector(".scan-card");
  function playCard() {
    card.classList.remove("lit");
    const meter = card.querySelector(".sc-meter");
    const num = card.querySelector(".sc-num");
    meter.style.transition = "none";
    meter.style.strokeDashoffset = 326.73;
    num.textContent = "0";
    void meter.getBoundingClientRect();
    meter.style.transition = "";
    setTimeout(() => {
      card.classList.add("lit");
      meter.style.strokeDashoffset = 326.73 * (1 - 0.87);
      const start = performance.now();
      const step = (now) => {
        const p = Math.min((now - start) / 2000, 1);
        num.textContent = Math.round(87 * (1 - Math.pow(1 - p, 4)));
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }, 500);
  }

  /* ---------------- tilt, spotlight, magnetic ---------------- */
  function wireTilt() {
    landing.querySelectorAll(".feat").forEach((node) => {
      node.addEventListener("pointermove", (e) => {
        const r = node.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
        node.style.setProperty("--mx", `${x * 100}%`);
        node.style.setProperty("--my", `${y * 100}%`);
        if (!reduced) node.style.transform = `perspective(800px) rotateX(${(0.5 - y) * 8}deg) rotateY(${(x - 0.5) * 8}deg) translateZ(4px)`;
      });
      node.addEventListener("pointerleave", () => { node.style.transform = ""; });
    });
  }
  if (!reduced) {
    const visual = landing.querySelector(".hero-visual");
    visual.addEventListener("pointermove", (e) => {
      const r = visual.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform = `rotateY(${x * 18}deg) rotateX(${-y * 14}deg) translateZ(20px)`;
    });
    visual.addEventListener("pointerleave", () => { card.style.transform = ""; });

    document.querySelectorAll(".magnetic").forEach((b) => {
      b.addEventListener("pointermove", (e) => {
        const r = b.getBoundingClientRect();
        b.style.transform = `translate(${(e.clientX - r.left - r.width / 2) * 0.22}px, ${(e.clientY - r.top - r.height / 2) * 0.3}px)`;
      });
      b.addEventListener("pointerleave", () => { b.style.transform = ""; });
    });

    const glow = document.querySelector(".glow-cursor");
    let gx = innerWidth / 2, gy = innerHeight / 2, tx = gx, ty = gy;
    window.addEventListener("pointermove", (e) => { tx = e.clientX; ty = e.clientY; }, { passive: true });
    const follow = () => {
      gx += (tx - gx) * 0.12; gy += (ty - gy) * 0.12;
      glow.style.transform = `translate(${gx}px, ${gy}px)`;
      requestAnimationFrame(follow);
    };
    follow();
  }

  /* clicks on empty space send a healing wave through the cells */
  landing.addEventListener("pointerdown", (e) => {
    if (e.target.closest("a, button, canvas, .scan-card, .feat, input")) return;
    if (cells) cells.pulse(e.clientX, e.clientY);
  });

  /* ---------------- enter ---------------- */
  document.querySelectorAll(".enter").forEach((b) => b.addEventListener("click", (e) => window.CS.enterApp(e.clientX, e.clientY)));

  /* ---------------- scroll effects ---------------- */
  const top = landing.querySelector(".l-top");
  const how = $("how");
  const fill = $("steps-fill");
  function onScroll() {
    if (landing.hidden) return;
    top.classList.toggle("scrolled", scrollY > 30);
    const r = how.getBoundingClientRect();
    const p = Math.max(0, Math.min(1, (innerHeight * 0.75 - r.top) / (r.height * 0.8)));
    fill.style.transform = `scaleX(${p})`;
    $("l-steps").querySelectorAll("li").forEach((li, i, all) => li.classList.toggle("lit", p >= (i + 0.5) / all.length));
  }
  window.addEventListener("scroll", onScroll, { passive: true });

  /* ---------------- cube demo ---------------- */
  let cube = null;
  new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !cube) {
      cube = CyberCube.create($("l-cube"), $("l-cube-tip"));
      cube.setData(CyberCube.demoStructure());
    }
  }, { threshold: 0.2 }).observe($("l-cube"));

  /* ---------------- repair demo ---------------- */
  function buildBytes() {
    const pattern = [];
    for (let i = 0; i < 46; i++) pattern.push(i >= 30 && i < 36 ? "bad" : i === 12 ? "bad" : "");
    ["bytes-before", "bytes-after"].forEach((id) => {
      $(id).replaceChildren(...pattern.map((kind, i) => {
        const b = el("i", kind);
        b.style.setProperty("--h", String(190 + (i % 7) * 9));
        return b;
      }));
    });
  }
  const repairSec = $("repair-sec");
  let repairTimer = null;
  new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
      const cycle = () => {
        repairSec.classList.remove("play");
        void repairSec.offsetWidth;
        setTimeout(() => repairSec.classList.add("play"), 900);
        repairTimer = setTimeout(cycle, 7000);
      };
      if (!repairTimer) cycle();
    } else { clearTimeout(repairTimer); repairTimer = null; }
  }, { threshold: 0.35 }).observe(repairSec);

  /* ---------------- stats ---------------- */
  let stats = null, counted = false;
  api("/api/stats").then((s) => { stats = s; fillStats(); }).catch(() => { stats = { scans: 0 }; fillStats(); });
  function values() { return { scans: stats ? stats.scans : 0, engines: 9, zero: 0, langs: 2 }; }
  function fillStats() { if (counted) countStats(true); }
  function countStats(instant) {
    if (!stats) return;
    counted = true;
    const v = values();
    $("stats-grid").querySelectorAll("[data-stat]").forEach((node) => {
      const target = v[node.dataset.stat] || 0;
      if (instant || reduced) { node.textContent = target.toLocaleString(); return; }
      const start = performance.now();
      const step = (now) => {
        const p = Math.min((now - start) / 1800, 1);
        node.textContent = Math.round(target * (1 - Math.pow(1 - p, 3))).toLocaleString();
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  }
  new IntersectionObserver((entries) => { if (entries[0].isIntersecting && !counted) countStats(); }, { threshold: 0.4 }).observe($("stats-grid"));

  /* ---------------- lifecycle ---------------- */
  function arrive() {
    landing.classList.remove("ready");
    requestAnimationFrame(() => requestAnimationFrame(() => landing.classList.add("ready")));
    scramble(landing.querySelector("[data-scramble]"));
    playCard();
    onScroll();
  }
  window.addEventListener("cs:landing", arrive);
  window.CS.onLang(() => { build(); if (!landing.hidden) { landing.classList.add("ready"); scramble(landing.querySelector("[data-scramble]")); } });
  setInterval(() => { if (!landing.hidden && !document.hidden) playCard(); }, 9000);
  build();
})();
