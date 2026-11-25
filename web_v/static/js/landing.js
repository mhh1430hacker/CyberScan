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
  /* ---------------- the hero title: a word that types itself ----------------
   * "Inspect every / › file▌ / before you open it." The middle word is typed letter by letter
   * (graphemes, so joined scripts stay correct), held, erased, and the next one is typed in its own
   * colours. Cost: one short timer per letter and a class change per word; no animation loop, and
   * nothing runs while the hero is off screen or the tab is hidden. Reduced motion: the first
   * word, still. */
  const title = landing.querySelector(".hero-title");
  const typed = title && title.querySelector(".t-word");
  const PALETTES = 5;
  let typeTimer = 0, typeRun = 0, heroVisible = true;
  const still = () => reduced || document.documentElement.classList.contains("reduce-motion");
  const graphemes = (s) => {
    try { return [...new Intl.Segmenter(window.CS.lang, { granularity: "grapheme" }).segment(s)].map((x) => x.segment); } catch { return [...s]; }
  };
  function words() { const w = t("lTypeWords"); return Array.isArray(w) && w.length ? w : ["file"]; }
  function splitTitle() {
    if (!title) return;
    const list = words();
    title.setAttribute("aria-label", `${t("lTypeLead")} ${list.join(", ")} ${t("lTypeTail")}`.replace(/\s+([,.،。，])/g, "$1"));
    typed.textContent = list[0];
    title.dataset.p = "0";
  }
  function stopTyping() { typeRun++; clearTimeout(typeTimer); }
  function startTyping() {
    if (!title) return;
    stopTyping();
    const run = typeRun, list = words();
    title.classList.add("art-in");
    if (still()) { typed.textContent = list[0]; title.dataset.p = "0"; title.classList.add("t-still"); return; }
    let index = 0;
    const later = (fn, ms) => { typeTimer = setTimeout(() => { if (run === typeRun) fn(); }, ms); };
    const type = (chars, n) => {
      typed.textContent = chars.slice(0, n).join("");
      title.classList.toggle("t-typing", n < chars.length);
      if (n < chars.length) later(() => type(chars, n + 1), 62 + Math.random() * 46);
      else later(() => erase(chars, chars.length), 2100);
    };
    // the old word is selected, as in an editor, then replaced by the next one (fabric.css .t-select)
    const erase = () => {
      title.classList.add("t-select", "t-typing");
      later(() => {
        typed.textContent = "";
        title.classList.remove("t-select");
        index = (index + 1) % list.length;
        title.dataset.p = String(index % PALETTES);
        later(() => type(graphemes(list[index]), 1), 140);
      }, 420);
    };
    title.dataset.p = "0";
    // the first word is already on screen: hold it, then continue the cycle
    typed.textContent = list[0];
    later(() => erase(graphemes(list[0]), graphemes(list[0]).length), 2400);
  }
  function replayTitle() { if (heroVisible && !document.hidden) startTyping(); }
  if (title) {
    new IntersectionObserver((entries) => {
      heroVisible = entries[0].isIntersecting;
      if (heroVisible && !document.hidden) startTyping(); else stopTyping();
    }).observe(title);
    document.addEventListener("visibilitychange", () => { if (document.hidden) stopTyping(); else if (heroVisible) startTyping(); });
  }

  function build() {
    splitTitle();
    const items = t("marquee");
    if ($("marquee")) $("marquee").replaceChildren(...[...items, ...items].map((x) => el("span", "", x)));

    $("l-steps").replaceChildren(...t("steps").map(([title, body], i) => {
      const li = el("li");
      li.setAttribute("data-reveal", "");
      li.style.setProperty("--i", i);
      li.append(el("span", "num", String(i + 1).padStart(2, "0")), el("b", "", title), el("p", "", body));
      return li;
    }));

    const colors = ["rgb(30,58,138)", "rgb(56,189,248)", "rgb(244,114,182)", "rgb(248,113,113)"];
    if ($("l-legend")) $("l-legend").replaceChildren(...t("lCubeLegend").map((label, i) => {
      const li = el("li"); const sw = el("i"); sw.style.background = colors[i]; li.append(sw, label); return li;
    }));

    buildBento();

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

    // the clean-files figure is said plainly (how many were wrongly flagged), not as a double negative
    $("stats-grid").replaceChildren(...t("stats").map(([label, key, unit], i) => {
      if (key === "clean") label = t("statClean");
      const card = el("div", "stat");
      card.setAttribute("data-reveal", "");
      card.style.setProperty("--i", i);
      const num = el("b", "", "0");
      num.dataset.stat = key;
      if (unit) num.dataset.unit = unit;
      card.append(num, el("span", "", label));
      return card;
    }));
    $("stats-note").textContent = t("lStatsNote");
    buildBytes();
    observeReveals();
    wireTilt();
    if (counted) countStats(true);
  }

  /* ---------------- bento ---------------- */
  // order in i18n "feats": verdicts, cube, repair, quarantine, ai, downloads, intel, history
  const AREAS = ["a", "b", "c", "d", "e", "f", "g", "h"];
  // features that need the installed desktop app (Windows key vault, local model, Downloads folder,
  // local history); the website keeps no history and runs none of these
  const DESKTOP_ONLY = new Set([3, 4, 5, 7]);
  let bentoCube = null, bentoTimers = [];
  function viz(i) {
    const box = el("div", "bviz");
    if (i === 0) {
      const bubble = el("div", "bubble");
      bubble.append(el("i", "bdot"), el("span", "btype"));
      box.append(bubble, el("div", "bline w80"), el("div", "bline w60"));
    } else if (i === 1) {
      const c = el("canvas", "bcube");
      box.append(c);
    } else if (i === 2) {
      const strip = el("div", "bstrip");
      for (let k = 0; k < 22; k++) { const b = el("i", k >= 14 && k < 18 ? "bad" : ""); b.style.setProperty("--k", k); strip.append(b); }
      box.append(strip, el("div", "bscissors", "✂"));
    } else if (i === 3) {
      box.innerHTML = '<svg class="block" viewBox="0 0 64 64" aria-hidden="true"><rect class="bfile" x="16" y="6" width="22" height="28" rx="3"/><path class="bshackle" d="M22 34v-6a10 10 0 0 1 20 0v6"/><rect class="bbody" x="16" y="32" width="32" height="24" rx="5"/><circle class="bkey" cx="32" cy="44" r="3"/></svg>';
    } else if (i === 4) {
      const row = el("div", "airow");
      row.append(el("span", "ai-orb"), el("p", "aitype"));
      box.append(row);
    } else if (i === 5) {
      box.innerHTML = '<svg class="bdl" viewBox="0 0 64 64" aria-hidden="true"><path class="arrow" d="M32 8v26m-10-10 10 10 10-10"/><path class="tray" d="M12 40v12h40V40"/></svg>';
      const toast = el("div", "btoast");
      toast.append(el("span", "", t("bentoNew")), el("b", "", t("bentoScan")));
      box.append(toast);
    } else if (i === 6) {
      box.innerHTML = '<svg class="globe" viewBox="0 0 100 100" aria-hidden="true"><circle cx="50" cy="50" r="38"/><ellipse class="m m1" cx="50" cy="50" rx="38" ry="38"/><ellipse class="m m2" cx="50" cy="50" rx="38" ry="38"/><ellipse class="m m3" cx="50" cy="50" rx="38" ry="38"/><path d="M12 50h76M18 32h64M18 68h64"/><circle class="ping" cx="64" cy="38" r="3"/></svg>';
    } else if (i === 7) {
      const list = el("div", "blist");
      const tones = ["--bad", "--warn", "--ok", "--warn", "--bad", "--ok", "--warn", "--ok"];
      const names = ["setup.exe", "invoice.pdf", "photo.jpg", "macro.docm", "update.js", "notes.txt", "tool.zip", "cv.pdf"];
      [...names, ...names].forEach((n, k) => {
        const r = el("div", "brow");
        const d = el("i"); d.style.background = `var(${tones[k % 8]})`;
        r.append(d, el("span", "", n), el("small", "", `${(k * 7 + 12) % 100}`));
        list.append(r);
      });
      box.append(list);
    }
    return box;
  }

  // Typing effects only change the page while their card can be seen (js/lite.js marks the
  // blocks that are off screen); otherwise they check back twice a second.
  const onScreen = (node) => !node.closest(".cs-off") && !document.hidden;

  function typeLoop(node, texts, speed = 38, hold = 1700) {
    let ti = 0, ci = 0, del = false;
    // the card keeps the height of the longest text while it is typed and erased, so the cards
    // around it don't move (they jumped ~28 px as the AI sentence grew a line)
    const reserve = () => { if (!node.isConnected) return; node.style.minHeight = ""; const was = node.textContent; let h = 0; texts.forEach((x) => { node.textContent = x; h = Math.max(h, node.offsetHeight); }); node.textContent = was; node.style.minHeight = `${h}px`; };
    reserve();
    if (window.ResizeObserver) { let rw = node.offsetWidth; new ResizeObserver(() => { if (node.offsetWidth !== rw) { rw = node.offsetWidth; reserve(); } }).observe(node); }
    const step = () => {
      if (!onScreen(node)) { bentoTimers.push(setTimeout(step, 500)); return; }
      const text = texts[ti % texts.length];
      node.textContent = text.slice(0, ci);
      if (!del && ci < text.length) ci++;
      else if (!del) { del = true; bentoTimers.push(setTimeout(step, hold)); return; }
      else if (ci > 0) ci -= 2;
      else { del = false; ti++; }
      bentoTimers.push(setTimeout(step, del ? 14 : speed));
    };
    if (reduced) node.textContent = texts[0]; else step();
  }

  function buildBento() {
    bentoTimers.forEach(clearTimeout); bentoTimers = [];
    if (bentoCube) { bentoCube.destroy(); bentoCube = null; }
    $("feat-grid").replaceChildren(...t("feats").map(([title, body], i) => {
      const card = el("div", `bento-card area-${AREAS[i]}`);
      card.setAttribute("data-reveal", "");
      card.style.setProperty("--i", i % 4);
      const icon = el("div", "ficon");
      icon.innerHTML = svg(FEAT_ICONS[i]);
      const text = el("div", "btext");
      text.append(icon, el("b", "", title), el("p", "", body));
      if (DESKTOP_ONLY.has(i)) { card.classList.add("desk-only"); text.append(el("span", "feat-tag", t("featDesktop"))); }
      card.append(viz(i), text);
      return card;
    }));
    const grid = $("feat-grid");
    const verdictNode = grid.querySelector(".btype");
    const dot = grid.querySelector(".bdot");
    const tones = ["var(--ok)", "var(--warn)", "var(--bad)", "var(--muted)"];
    const verdicts = t("bentoVerdicts");
    let vi = 0;
    const typeVerdict = () => {
      const text = verdicts[vi % verdicts.length];
      dot.style.background = tones[vi % tones.length];
      vi++;
      let ci = 0;
      const step = () => {
        if (!onScreen(verdictNode)) { bentoTimers.push(setTimeout(step, 500)); return; }
        verdictNode.textContent = text.slice(0, ++ci);
        if (ci < text.length) bentoTimers.push(setTimeout(step, 34));
        else bentoTimers.push(setTimeout(typeVerdict, 2200));
      };
      step();
    };
    if (reduced) { verdictNode.textContent = verdicts[0]; dot.style.background = tones[0]; } else typeVerdict();
    typeLoop(grid.querySelector(".aitype"), [t("bentoAi")], 26, 2600);
    const cubeCanvas = grid.querySelector(".bcube");
    new IntersectionObserver((entries, obs) => {
      if (entries[0].isIntersecting && !bentoCube) {
        bentoCube = CyberCube.create(cubeCanvas, null);
        bentoCube.setData(CyberCube.demoStructure());
        obs.disconnect();
      }
    }, { threshold: 0.2 }).observe(cubeCanvas);
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
    if (card.classList.contains("ld-live")) return;   // the live demo (js/live-demo.js) shows a real result
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
    landing.querySelectorAll(".bento-card, .priv, .stat, .l-steps li").forEach((node) => {
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
    // Eases toward the pointer and stops once there; the next move wakes it.
    let glowRaf = 0;
    const follow = () => {
      gx += (tx - gx) * 0.12; gy += (ty - gy) * 0.12;
      if (Math.abs(tx - gx) < 0.3 && Math.abs(ty - gy) < 0.3) { gx = tx; gy = ty; glowRaf = 0; }
      else glowRaf = requestAnimationFrame(follow);
      glow.style.transform = `translate(${gx.toFixed(1)}px, ${gy.toFixed(1)}px)`;
    };
    window.addEventListener("pointermove", () => { if (!glowRaf) glowRaf = requestAnimationFrame(follow); }, { passive: true });
    follow();
  }

  /* clicks on empty space send a healing wave through the cells */
  landing.addEventListener("pointerdown", (e) => {
    if (e.target.closest("a, button, canvas, .scan-card, .bento-card, input")) return;
    if (cells) cells.pulse(e.clientX, e.clientY);
  });

  /* ---------------- enter ---------------- */
  document.querySelectorAll(".enter").forEach((b) => b.addEventListener("click", (e) => window.CS.enterApp(e.clientX, e.clientY)));

  /* ---------------- scroll effects ---------------- */
  const top = landing.querySelector(".l-top");
  let scrolled = null;
  function onScroll() {
    if (landing.hidden) return;
    const s = scrollY > 30;
    if (s !== scrolled) { scrolled = s; top.classList.toggle("scrolled", s); }
  }
  window.addEventListener("scroll", onScroll, { passive: true });

  /* ---------------- cube demo ---------------- */
  let cube = null;
  new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && !cube) {
      cube = CyberCube.create($("l-cube"), $("l-cube-tip"));
      cube.setData(CyberCube.demoStructure());
    }
  }, { threshold: 0.2 }).observe($("l-cube") || document.createElement("i"));

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

  /* ---------------- stats ----------------
   * Measured figures, not promises. Sources (kept in the repo):
   *   fuzz, clean, repair, speed: reports/evaluation/results.json (harness/evaluate.py, 2026-11-06):
   *     parser_fuzz 3000 cases / 0 crashes; strong warning ("Suspicious") on 1 of 245 clean files,
   *     any warning on 7 of 245 (detection.any_warning.fp / strong_warning.fp);
   *     repair 84 of 86 tampered files repaired and validated, 0 of 124 clean files touched;
   *     median scan 0.21 s over 338 files.
   *   zero: the desktop app's default settings; langs: CS_LANGS. */
  let counted = false;
  function values() {
    return { fuzz: { n: 3000 }, clean: { n: 1, of: 245 }, repair: { n: 84, of: 86 }, speed: { n: 0.21, dec: 2 },
      zero: { n: 0 }, langs: { n: window.CS_LANGS ? CS_LANGS.list.length : 2 } };
  }
  const fmt = (x, dec) => x.toLocaleString(undefined, { minimumFractionDigits: dec || 0, maximumFractionDigits: dec || 0 });
  function show(node, v, x) {                                  // the number is isolated LTR; the unit follows the page direction
    let s = fmt(x, v.dec);
    if (v.of) s = `${s}/${fmt(v.of)}`;
    const n = el("bdi", "", s);
    if (node.dataset.unit) node.replaceChildren(n, el("small", "", node.dataset.unit)); else node.replaceChildren(n);
  }
  function countStats(instant) {
    counted = true;
    if (!instant && !reduced && window.CSSfx) {
      const t0 = performance.now();
      const tick = () => { const p = (performance.now() - t0) / 1800; if (p >= 1) { CSSfx.play("chime"); return; } CSSfx.play("tick", { k: Math.round(p * 20) }); setTimeout(tick, 70 + p * 120); };
      tick();
    }
    const v = values();
    // each card counts in turn (120 ms apart) on an expo-out curve, then settles (fabric.css .fx-landed)
    $("stats-grid").querySelectorAll("[data-stat]").forEach((node, i) => {
      const val = v[node.dataset.stat] || { n: 0 };
      if (instant || reduced) { show(node, val, val.n); return; }
      const start = performance.now() + i * 120;
      const step = (now) => {
        const p = Math.max(0, Math.min((now - start) / 1600, 1)), e = p === 1 ? 1 : 1 - Math.pow(2, -10 * p);
        show(node, val, val.dec ? val.n * e : Math.round(val.n * e));
        if (p < 1) requestAnimationFrame(step);
        else { node.classList.remove("fx-landed"); void node.offsetWidth; node.classList.add("fx-landed"); }
      };
      requestAnimationFrame(step);
    });
  }
  new IntersectionObserver((entries) => { if (entries[0].isIntersecting && !counted) countStats(); }, { threshold: 0.4 }).observe($("stats-grid"));

  /* ---------------- header: fits any language, collapses into a menu ----------------
   * Levels, tried in order until the bar fits on one line: full · tight (shorter gaps, icon-only
   * "Get the app" and Calm) · compact (brand, Open the app, menu) · tiny (logo without the word).
   * Measured, not guessed, so a long German or Tamil label collapses it as early as it needs to. */
  const menuBtn = $("l-menu-btn"), sheet = $("l-sheet");
  const LEVELS = ["is-tight", "is-compact", "is-tiny"];
  function fits() {
    const cs = getComputedStyle(top);
    const avail = Math.min(top.clientWidth, innerWidth) - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
    const kids = [...top.children].filter((k) => k !== sheet && k.offsetParent !== null);
    const gap = parseFloat(cs.columnGap) || 0;
    const need = kids.reduce((s, k) => s + k.scrollWidth, 0) + gap * Math.max(0, kids.length - 1);
    // the bar's width before it turns solid: 1240, or 1480 above 1600 px where the tour button shows its label (fabric.css)
    const cap = innerWidth > 1600 ? 1480 : 1240;
    return need <= Math.min(avail, cap - 48) + 0.5;
  }
  function fitHeader() {
    top.classList.remove(...LEVELS);
    const want = innerWidth <= 1000 ? 2 : 0;                 // tablets and phones: the menu (the nav links are hidden below 1000 px)
    for (let i = 0; i < want; i++) top.classList.add(LEVELS[i]);
    for (let i = want; !fits() && i < LEVELS.length; i++) top.classList.add(LEVELS[i]);
    if (!top.classList.contains("is-compact")) setMenu(false);
  }
  function setMenu(open, focus) {
    if (!sheet) return;
    sheet.hidden = !open;
    menuBtn.setAttribute("aria-expanded", String(open));
    menuBtn.setAttribute("aria-label", t(open ? "menuClose" : "menuOpen"));
    if (open && focus) (sheet.querySelector("a, button") || sheet).focus();
  }
  if (menuBtn && sheet) {
    menuBtn.addEventListener("click", (e) => { e.stopPropagation(); setMenu(sheet.hidden, true); });
    sheet.addEventListener("click", (e) => {
      e.stopPropagation();
      if (e.target.closest(".l-sheet-links a, .l-sheet-apk")) setMenu(false);
      if (e.target.closest(".l-sheet-tour")) { setMenu(false); $("tour-start").click(); }
    });
    document.addEventListener("click", (e) => { if (!sheet.hidden && !e.target.closest(".lang-menu")) setMenu(false); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !sheet.hidden && !document.querySelector(".lang-menu")) { setMenu(false); menuBtn.focus(); }
    }, true);                                                // capture: before the language menu closes itself
  }
  let fitRaf = 0;
  const refit = () => { cancelAnimationFrame(fitRaf); fitRaf = requestAnimationFrame(fitHeader); };
  addEventListener("resize", refit, { passive: true });
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(refit);
  refit();

  /* ---------------- back to top ---------------- */
  const toTop = el("button", "to-top");
  toTop.type = "button";
  toTop.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 19V5m-6 6 6-6 6 6"/></svg>';
  const paintTop = () => { toTop.setAttribute("aria-label", t("toTop")); toTop.title = t("toTop"); };
  paintTop();
  toTop.addEventListener("click", () => {
    window.scrollTo({ top: 0, behavior: still() ? "auto" : "smooth" });
    const brand = top.querySelector(".brand"); if (brand) brand.focus({ preventScroll: true });
  });
  document.body.append(toTop);
  let topShown = false, lastY = scrollY, hideFloat = false;
  addEventListener("scroll", () => {
    const y = scrollY;
    const show = y > innerHeight * 1.5 && !landing.hidden;
    if (show !== topShown) { topShown = show; toTop.classList.toggle("on", show); }
    // phones: the corner buttons (Ask the AI, back to top) step aside while you read downwards
    // and come back as soon as you scroll up or reach the end of the page
    const atEnd = y + innerHeight >= document.documentElement.scrollHeight - 140;
    const hide = !atEnd && y > lastY + 2 && y > innerHeight * 0.6 ? true : y < lastY - 2 || atEnd ? false : hideFloat;
    lastY = y;
    if (hide !== hideFloat) { hideFloat = hide; document.body.classList.toggle("float-away", hide); }
  }, { passive: true });

  /* ---------------- lifecycle ---------------- */
  function arrive() {
    landing.classList.remove("ready");
    requestAnimationFrame(() => requestAnimationFrame(() => landing.classList.add("ready")));
    scramble(landing.querySelector("[data-scramble]"));
    replayTitle();
    playCard();
    onScroll();
  }
  window.addEventListener("cs:landing", arrive);
  window.CS.onLang(() => { build(); paintTop(); if (sheet) setMenu(!sheet.hidden); refit(); if (!landing.hidden) { landing.classList.add("ready"); scramble(landing.querySelector("[data-scramble]")); replayTitle(); } });
  setInterval(() => { if (!landing.hidden && !document.hidden && !landing.querySelector(".hero").classList.contains("cs-off")) playCard(); }, 9000);
  build();
})();
