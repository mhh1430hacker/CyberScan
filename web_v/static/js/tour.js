/* «سنقود رحلتك معنا» / Guided journey: an automatic, directed tour of the landing page.
 *
 * The plan is built from the page itself when the tour starts:
 *   - every landing section in order; the science story is split into its pinned scenes and the
 *     collapsed technical deep dive is skipped;
 *   - a pinned scene (taller than ~1.35 screens) is scrolled through at a pace set by its length
 *     and by how much text it shows, so its scroll animations play out at a readable speed;
 *   - an ordinary section is brought into view and held for a reading time from its word count,
 *     then scrolled through if it is taller than the screen;
 *   - the film: the tour waits for its cinematic entrance, plays it (picture and narration share
 *     one clock, js/film.js), and moves on only when the narration has ended.
 * It scrolls with window.scrollTo from one requestAnimationFrame loop, so every existing scroll
 * animation (scroll.js, scrolly.js, saudi.js, the film's entrance) simply follows the position.
 * Any wheel, touch, key or click from the visitor ends the tour at once and hands control back;
 * the film then keeps playing under the visitor's own control. Pause and resume are in the panel.
 * Reduced motion: no smooth travel; each stop is shown and held instead. */
(function () {
  "use strict";
  const startBtn = document.getElementById("tour-start");
  const landing = document.getElementById("landing");
  if (!startBtn || !landing) return;
  const html = document.documentElement;
  const CS = window.CS || {};
  const t = (k, fb) => { const v = CS.t && CS.t(k); return typeof v === "string" ? v : fb; };
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion");
  const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
  const inOut = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
  const smooth = (x) => x * x * (3 - 2 * x);
  const HEADER = 72;

  /* ---------------- reading the page ---------------- */
  const visible = (n) => n.offsetParent !== null && n.offsetHeight > 40 && getComputedStyle(n).visibility !== "hidden";
  const words = (n) => ((n.innerText || "").match(/[\p{L}\p{N}]+/gu) || []).length;
  function label(n) {
    const h = [".sy-title[aria-label]", "h1", "h2", "h3", ".sec-tag"].map((q) => n.querySelector(q)).find((x) => x && x.textContent.trim());
    const text = h ? (h.getAttribute("aria-label") || h.textContent) : "";
    return text.replace(/\s+/g, " ").replace(/^\/\/\s*/, "").trim().slice(0, 48);
  }
  function stops() {
    const out = [];
    for (const n of landing.children) {
      if (!n.matches("section, footer") || !visible(n)) continue;
      if (n.id === "science") {
        const head = n.querySelector(".sci-head");
        if (head && visible(head)) out.push({ el: head, kind: "normal" });
        n.querySelectorAll(".sy-scene").forEach((s) => visible(s) && out.push({ el: s, kind: "auto" }));
        continue;
      }
      out.push({ el: n, kind: n.id === "film" ? "film" : "auto" });
    }
    return out.map((s) => ({ ...s, label: label(s.el) || t("tourLabel", "Guided journey") }));
  }
  const topOf = (el) => el.getBoundingClientRect().top + scrollY;

  /* Each stop becomes a short list of steps: travel to a position, hold, scroll through, or film. */
  function plan(s) {
    const vh = innerHeight, h = s.el.offsetHeight, w = words(s.el);
    const top = () => topOf(s.el);
    if (s.kind === "film") {
      return [
        // centre the film's frame on the screen (below the header)
        { type: "travel", to: () => { const f = document.querySelector("#film-player .film-frame") || s.el; const r = f.getBoundingClientRect(); return scrollY + r.top - (innerHeight - r.height) / 2 - 24; } },
        { type: "hold", ms: 1400 },                       // the cinematic entrance settles
        { type: "film" },
        { type: "hold", ms: 1200 },
      ];
    }
    const pinned = h > vh * 1.35;                            // pinned scenes and long sections are scrolled through
    if (pinned) {
      const screens = Math.max(0.5, (h - vh) / vh);
      const perScreen = 3.1 + clamp(w / (screens * 28), 0, 2.4);     // more text, slower pace
      return [
        { type: "travel", to: top },
        { type: "hold", ms: 700 },
        { type: "through", from: top, to: () => top() + s.el.offsetHeight - vh, ms: clamp(screens * perScreen, 4.5, 24) * 1000 },
        { type: "hold", ms: 900 },
      ];
    }
    const dwell = clamp(w / 4.2, 2.6, 8) * 1000;
    const steps = [{ type: "travel", to: () => top() - HEADER }, { type: "hold", ms: dwell }];
    if (h > vh * 1.1) steps.push({ type: "through", from: () => top() - HEADER, to: () => top() + s.el.offsetHeight - vh, ms: clamp((h - vh) / vh * 4.2, 2.5, 14) * 1000 }, { type: "hold", ms: 1200 });
    return steps;
  }
  const estimate = (st) => st.type === "hold" || st.type === "through" ? st.ms : st.type === "film" ? 88000 : 1400;

  /* ---------------- the panel ---------------- */
  let panel = null;
  function buildPanel() {
    panel = document.createElement("div");
    panel.className = "tour-panel";
    panel.setAttribute("role", "region");
    panel.innerHTML = `
      <span class="tour-dot" aria-hidden="true"></span>
      <div class="tour-text"><small class="tour-title"></small><b class="tour-now" aria-live="polite"></b></div>
      <span class="tour-pct" aria-hidden="true">0%</span>
      <button type="button" class="tour-pp"><svg viewBox="0 0 24 24" aria-hidden="true"><path class="i-pause" d="M7 5h4v14H7zM13 5h4v14h-4z"/><path class="i-play" d="M8 5v14l11-7z"/></svg></button>
      <button type="button" class="tour-x"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
      <i class="tour-bar" aria-hidden="true"><i></i></i>`;
    panel.querySelector(".tour-pp").addEventListener("click", () => (paused ? resume() : pause()));
    panel.querySelector(".tour-x").addEventListener("click", () => exit("closed"));
    document.body.append(panel);
    texts();
  }
  function texts() {
    startBtn.title = t("tourStart", "Guided journey");
    if (!panel) return;
    panel.setAttribute("aria-label", t("tourLabel", "Guided journey"));
    panel.querySelector(".tour-title").textContent = t("tourLabel", "Guided journey");
    panel.querySelector(".tour-pp").setAttribute("aria-label", paused ? t("tourResume", "Resume") : t("tourPause", "Pause"));
    panel.querySelector(".tour-x").setAttribute("aria-label", t("tourExit", "End the journey"));
  }
  function setNow(text) { if (panel) panel.querySelector(".tour-now").textContent = text; }
  function setPct(k) {
    if (!panel) return;
    panel.querySelector(".tour-bar i").style.transform = `scaleX(${clamp(k).toFixed(4)})`;
    panel.querySelector(".tour-pct").textContent = `${Math.round(clamp(k) * 100)}%`;
  }

  /* ---------------- running ---------------- */
  let queue = [], qi = 0, step = null, stepStart = 0, stepFrom = 0, stepTo = 0, raf = 0, active = false, paused = false, pausedAt = 0;
  let total = 1, doneMs = 0, filmWaiting = false;
  function start() {
    if (active) return;
    if (window.CSFilm && CSFilm.unlock) CSFilm.unlock();      // inside the click: the narration may play later
    const list = stops();
    queue = [];
    list.forEach((s, i) => plan(s).forEach((st) => queue.push({ ...st, stop: s, index: i, count: list.length })));
    total = queue.reduce((a, st) => a + estimate(st), 0); doneMs = 0;
    qi = 0; active = true; paused = false;
    document.body.classList.add("touring");
    if (!panel) buildPanel();
    panel.hidden = false; panel.classList.remove("done");
    startBtn.setAttribute("aria-pressed", "true");
    setTimeout(listen, 0);                                   // after this click has finished
    next();
  }
  function next() {
    if (!active) return;
    if (step) doneMs += estimate(step);
    if (qi >= queue.length) { finish(); return; }
    step = queue[qi++];
    setNow(step.stop.label);
    stepStart = performance.now();
    if (step.type === "travel") {
      stepFrom = scrollY; stepTo = clamp(step.to(), 0, document.documentElement.scrollHeight - innerHeight);
      step.ms = reduced() ? 0 : clamp(450 + Math.abs(stepTo - stepFrom) * 0.22, 650, 2400);
    } else if (step.type === "through") {
      stepFrom = clamp(step.from(), 0, Infinity); stepTo = clamp(step.to(), 0, document.documentElement.scrollHeight - innerHeight);
      if (reduced()) { step.ms = Math.min(step.ms, 3500); }
    } else if (step.type === "film") {
      runFilm(); return;
    }
    loop();
  }
  function loop() {
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(tick);
  }
  function tick(now) {
    if (!active || paused || !step) return;
    const k = step.ms ? clamp((now - stepStart) / step.ms) : 1;
    if (step.type === "travel") scrollTo({ top: stepFrom + (stepTo - stepFrom) * inOut(k), behavior: "instant" });
    else if (step.type === "through") {
      if (reduced()) { if (k >= 1) scrollTo({ top: stepTo, behavior: "instant" }); }
      else scrollTo({ top: stepFrom + (stepTo - stepFrom) * smooth(k), behavior: "instant" });
    }
    setPct((doneMs + estimate(step) * k) / total);
    if (k >= 1) next(); else raf = requestAnimationFrame(tick);
  }

  /* the film: play it and wait for the narration to end; never cut a line short */
  function runFilm() {
    const film = window.CSFilm;
    if (!film) { next(); return; }
    setNow(`${step.stop.label} · ${t("tourWatching", "now playing")}`);
    filmWaiting = true;
    film.seek(0);
    film.play().then((ok) => {
      if (!active) return;
      if (!ok) setNow(t("filmTap", "Tap to play with sound"));   // sound needs a tap here; the tour waits for it
    });
    const onFilm = (e) => {
      if (!active) { removeEventListener("cs:film", onFilm); return; }
      if (e.detail.state === "ended") { removeEventListener("cs:film", onFilm); filmWaiting = false; next(); }
    };
    addEventListener("cs:film", onFilm);
    const progress = () => {
      if (!active || !filmWaiting) return;
      if (!paused) setPct((doneMs + (film.time / film.DURATION) * estimate(step)) / total);
      requestAnimationFrame(progress);
    };
    requestAnimationFrame(progress);
  }

  function pause() {
    if (!active || paused) return;
    paused = true; pausedAt = performance.now();
    cancelAnimationFrame(raf);
    if (filmWaiting && window.CSFilm) CSFilm.pause();
    panel.classList.add("paused"); texts();
  }
  function resume() {
    if (!active || !paused) return;
    paused = false;
    stepStart += performance.now() - pausedAt;
    panel.classList.remove("paused"); texts();
    if (filmWaiting && window.CSFilm) CSFilm.play(); else loop();
  }
  function finish() {
    setPct(1); setNow(t("tourDone", "Journey complete"));
    panel.classList.add("done");
    stopRunning();
    setTimeout(() => { if (!active && panel) panel.hidden = true; }, 3200);
  }
  function exit() {
    if (!active) return;
    stopRunning();
    if (panel) panel.hidden = true;
  }
  function stopRunning() {
    active = false; filmWaiting = false; step = null;
    cancelAnimationFrame(raf);
    document.body.classList.remove("touring");
    startBtn.setAttribute("aria-pressed", "false");
    unlisten();
  }

  /* the visitor takes back control: scrolling, keys, touches and clicks outside the panel */
  const takeOver = (e) => {
    if (!active) return;
    if (e.target && e.target.closest && e.target.closest(".tour-panel")) return;
    // the tap that lets the film play with sound belongs to the tour
    if (filmWaiting && e.target && e.target.closest && e.target.closest("#film-tap, #film-big")) return;
    if (e.type === "keydown" && ["Shift", "Control", "Alt", "Meta"].includes(e.key)) return;
    exit("user");
  };
  const EVENTS = ["wheel", "touchstart", "keydown", "pointerdown"];
  function listen() { EVENTS.forEach((ev) => addEventListener(ev, takeOver, { capture: true, passive: true })); }
  function unlisten() { EVENTS.forEach((ev) => removeEventListener(ev, takeOver, { capture: true })); }

  startBtn.addEventListener("click", () => (active ? exit("closed") : start()));
  document.addEventListener("visibilitychange", () => { if (document.hidden && active && !paused) pause(); });
  if (CS.onLang) CS.onLang(texts);
  texts();
  window.CSTour = { start, pause, resume, exit, get active() { return active; }, get paused() { return paused; } };
})();
