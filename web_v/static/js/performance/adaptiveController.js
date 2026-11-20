/* Adaptive Performance Engine, part 6 of 6: the controller every page asks.
 *
 *   CSAdapt.level            the global level now (1 Ultra .. 5 Essential)
 *   CSAdapt.budget(comp)     the profile for one component at its own level (global + its offset)
 *   CSAdapt.eased(comp, key) a numeric budget that glides to a new value over ~1.5 s (particle
 *                            counts), so a change is never a visible jump
 *   CSAdapt.register(name, element, comp)  marks a region as belonging to a component, so slow
 *                            frames are blamed on what was on screen
 *   CSAdapt.on(fn)           called after every change; also fires "cs:perf" (the old event)
 *   CSAdapt.setMode("auto" | 1..5), CSAdapt.info()
 *
 * Decisions (Auto Adaptive only; a level the visitor chose is never changed):
 *   start   the capability ceiling, or what this device settled on recently (remembered 3 days)
 *   lower   after 2 bad windows in a row (or CPU pressure "serious"): first the heavy component
 *           that was on screen (three, particles), up to 2 steps on its own; then everything, one
 *           level at a time, at most once every 6 s
 *   raise   after 3 good windows in a row and 20 s since the last change: one global level first
 *           (never above the ceiling), then the component steps
 *   steady  a raise that has to be undone within 40 s locks raising for 5 minutes (no see-saw)
 * The page shows the level as classes (perf-l1..5, perf-low from 4, fx-*), so CSS adapts too,
 * and as data-perf on <html> for diagnostics. */
(function () {
  "use strict";
  const caps = window.CSCaps.get(), Score = window.CSPerfScore, Prof = window.CSPerfProfiles, Set_ = window.CSPerfSettings, Mon = window.CSPerfMonitor;
  const html = document.documentElement;
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
  const LEARN = "cs-adapt-learned";

  let cap = Score.capability(caps);
  let ceiling = cap.level;
  let level = ceiling;
  const offsets = { three: 0, particles: 0, canvas: 0, css: 0, video: 0 };
  try {
    const l = JSON.parse(localStorage.getItem(LEARN) || "null");
    if (l && l.sig === caps.sig && Date.now() - l.at < 3 * 864e5) { level = clamp(l.level, ceiling, 5); Object.assign(offsets, l.offsets || {}); }
  } catch { /* storage off */ }
  let bad = 0, good = 0, lastChange = 0, lastRaise = 0, lockUntil = 0, history = [], lastReport = null, reason = "capability";

  const manual = () => Set_.mode !== "auto";
  const globalLevel = () => (manual() ? Number(Set_.mode) : level);
  const compLevel = (comp) => clamp(globalLevel() + (manual() ? 0 : offsets[comp] || 0), 1, 5);

  /* ---------- applying a level: classes for CSS, events for scripts ---------- */
  const listeners = [];
  const phoneBrief = matchMedia("(max-width: 760px)").matches;
  function apply(why) {
    const g = globalLevel(), css = Prof.get(compLevel("css"));
    const cl = html.classList;
    for (let i = 1; i <= 5; i++) cl.toggle(`perf-l${i}`, i === g);
    cl.toggle("perf-low", g >= 4);                                          // the old class keeps working
    cl.toggle("fx-blur-light", css.blur === "light"); cl.toggle("fx-blur-off", css.blur === "off");
    cl.toggle("fx-glow-reduced", css.lighting === "reduced"); cl.toggle("fx-glow-flat", css.lighting === "flat");
    cl.toggle("fx-parallax-off", css.parallax === 0);
    cl.toggle("fx-bg-reduced", css.background === "reduced"); cl.toggle("fx-bg-once", css.background === "once"); cl.toggle("fx-bg-static", css.background === "static");
    cl.toggle("fx-scenes-simple", css.scenes === "simple");
    // phones get the short home page (fabric.css): its scroll-driven scenes show their finished frame
    cl.toggle("fx-scenes-static", css.scenes === "static" || phoneBrief);
    html.dataset.perf = JSON.stringify({ mode: Set_.mode, level: g, name: Prof.NAMES[g], ceiling, offsets: manual() ? {} : offsets, reason: why || reason, rm: Set_.reducedMotion() });
    // soften the switch: CSS transitions run while this class is present
    cl.add("perf-shift"); clearTimeout(apply.t); apply.t = setTimeout(() => cl.remove("perf-shift"), 1400);
    listeners.forEach((fn) => { try { fn(info()); } catch { /* listener failed */ } });
    window.dispatchEvent(new CustomEvent("cs:perf", { detail: { low: g >= 4, level: g } }));
  }
  function remember() { try { localStorage.setItem(LEARN, JSON.stringify({ sig: caps.sig, at: Date.now(), level, offsets })); } catch { /* storage off */ } }
  function change(kind, why) {
    const now = Date.now();
    if (kind === "down" && lastRaise && now - lastRaise < 40000) lockUntil = now + 5 * 60000;   // it bounced: stop raising for a while
    if (kind === "up") lastRaise = now;
    lastChange = now; reason = why; bad = 0; good = 0;
    history.push({ at: now, kind, level, offsets: { ...offsets }, why });
    if (history.length > 20) history.shift();
    remember(); apply(why);
  }

  /* ---------- the runtime loop: one decision per monitor window ---------- */
  const regions = [];
  Mon.setOnScreen(() => regions.filter((r) => r.visible).map((r) => r.comp));
  Mon.onReport((rep) => {
    const r = Score.runtime(rep);
    lastReport = { ...rep, score: r.score, verdict: r.verdict };
    if (manual() || rep.reason === "calibrate") return;                      // the window at load measures the display, not the page
    const now = Date.now();
    // a severe window (under ~half speed) counts double, and the next window comes sooner
    if (r.verdict === "bad") { bad += r.score < 40 ? 2 : 1; good = 0; } else if (r.verdict === "good") { good++; bad = 0; } else { bad = 0; }
    Mon.urgent = r.verdict === "bad";
    if (bad >= 2 && now - lastChange > 4000) degrade(rep.onScreen, `slow frames (${Math.round(rep.fps)} fps, ${Math.round(rep.dropped * 100)}% dropped)`);
    else if (good >= 3 && now - lastChange > 20000 && now > lockUntil) restore();
  });
  function degrade(onScreen, why) {
    const heavy = ["three", "particles"].find((c) => onScreen.includes(c) && offsets[c] < 2 && compLevel(c) < 5);
    if (heavy) { offsets[heavy]++; change("down", `${why}: ${heavy} lowered`); return; }
    if (level < 5) { level++; change("down", why); }
  }
  function restore() {
    if (level > ceiling) { level--; change("up", "stable frames"); return; }   // while everything is lowered, component steps change nothing
    const comp = Object.keys(offsets).sort((a, b) => offsets[b] - offsets[a])[0];
    if (offsets[comp] > 0) { offsets[comp]--; change("up", `stable: ${comp} restored`); }
  }
  // the device's own signals
  window.CSCaps.onChange((c) => {
    if (manual()) return;
    if ((c.pressure === "serious" || c.pressure === "critical") && Date.now() - lastChange > 6000 && level < 5) { level++; change("down", `CPU pressure: ${c.pressure}`); }
    const lowBattery = c.battery && !c.battery.charging && c.battery.level < 0.2;
    if (lowBattery && level < 3) { level = 3; change("down", "low battery"); }
  });
  addEventListener("resize", () => {
    clearTimeout(window.__csPerfResize);
    window.__csPerfResize = setTimeout(() => {
      if (Math.abs((window.devicePixelRatio || 1) - caps.dpr) < 0.01 && screen.width === caps.screenW) return;
      window.CSCaps.refreshScreen();
      cap = Score.capability(window.CSCaps.get()); ceiling = cap.level;
      if (level < ceiling) level = ceiling;
      apply("screen changed");
    }, 400);
  });

  /* ---------- eased budgets ---------- */
  const easeState = {};
  function eased(comp, key) {
    const prof = Prof.get(compLevel(comp));
    const target = key ? prof[comp][key] : prof[comp];
    const id = comp + "." + (key || "");
    const now = performance.now();
    let st = easeState[id];
    if (!st) st = easeState[id] = { v: target, from: target, to: target, t0: now };
    if (st.to !== target) { st.from = st.v; st.to = target; st.t0 = now; }
    const k = Math.min(1, (now - st.t0) / 1500);
    st.v = st.from + (st.to - st.from) * (1 - Math.pow(1 - k, 3));
    return st.v;
  }

  function info() {
    const g = globalLevel(), c = window.CSCaps.get();
    return {
      mode: Set_.mode, manual: manual(), level: g, name: Prof.NAMES[g], ceiling, ceilingName: Prof.NAMES[ceiling],
      detected: Prof.NAMES[cap.level], capabilityScore: cap.score, capabilityWhy: cap.why,
      offsets: { ...offsets }, components: Object.fromEntries(Object.keys(offsets).map((k) => [k, Prof.NAMES[compLevel(k)]])),
      webgl: c.webgl2 ? "WebGL2" : c.webgl ? "WebGL1" : "unavailable", software: c.software, renderer: c.renderer,
      webgpu: c.webgpu, cores: c.cores || null, memory: c.memory || null, dpr: c.dpr,
      reducedMotion: Set_.reducedMotion(), lastReport, history: history.slice(-6), lockedUntil: lockUntil > Date.now() ? lockUntil : null, reason,
    };
  }

  window.CSAdapt = {
    get level() { return globalLevel(); },
    get name() { return Prof.NAMES[globalLevel()]; },
    get mode() { return Set_.mode; },
    budget: (comp) => Prof.get(compLevel(comp)),
    componentLevel: compLevel,
    eased,
    register(name, element, comp) {
      if (!element || !("IntersectionObserver" in window)) return;
      const r = { name, comp, visible: false };
      regions.push(r);
      new IntersectionObserver((e) => { r.visible = e[0].isIntersecting; }).observe(element);
    },
    on: (fn) => listeners.push(fn),
    setMode(m) { Set_.set(m); bad = good = 0; apply(m === "auto" ? "auto adaptive" : "chosen by you"); },
    info,
    PROFILES: Prof,
  };

  /* the old interface (js/perf.js) for the scripts that already use it */
  window.CSPerf = {
    get low() { return globalLevel() >= 4; },
    set(value, remember) { window.CSAdapt.setMode(remember ? (value ? 4 : "auto") : "auto"); },
    get fps() { return lastReport ? Math.round(lastReport.fps) : null; },
    particles: (full) => Math.round(full * eased("particles")),
    dpr: (capDpr) => Math.min(window.devicePixelRatio || 1, capDpr, Prof.get(compLevel("canvas")).canvas),
  };

  apply("start");
})();
