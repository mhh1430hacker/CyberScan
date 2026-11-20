/* Adaptive Performance Engine, part 2 of 6: how the page actually runs.
 *
 * Short sampling windows, not a benchmark: a window is ~2.5 s of requestAnimationFrame timestamps,
 * taken only while the visitor is active (scrolling, moving, touching) and the tab is visible,
 * at most one every 8 s. Between windows nothing runs. One extra window right after load gives
 * the display's refresh interval. Each window reports:
 *   fps, mean frame time, its standard deviation (stability), the share of stutters (frames
 *   longer than 2.5x the expected interval: a steady low rate shows in fps, not here), and long main-thread tasks (where the browser
 *   reports them). Attribution: the window also lists which registered components were on screen,
 *   so the controller can tell a slow WebGL scene from a slow video. */
(function () {
  "use strict";
  const WINDOW = 2500, GAP = 8000;
  let interval = 1000 / 60, intervalKnown = false;
  let sampling = false, lastWindow = 0, activeUntil = 0, longTasks = 0;
  const listeners = [];
  let whoIsOnScreen = () => [];

  if ("PerformanceObserver" in window) {
    try { new PerformanceObserver((list) => { longTasks += list.getEntries().length; }).observe({ entryTypes: ["longtask"] }); } catch { /* unsupported */ }
  }

  function sample(reason) {
    if (sampling || document.hidden) return;
    sampling = true; lastWindow = performance.now();
    const times = [];
    const lt0 = longTasks;
    const onScreen = new Set(whoIsOnScreen());
    let start = 0;
    const step = (now) => {
      if (document.hidden) { sampling = false; return; }                   // abandoned: the tab went away
      if (!start) start = now;
      times.push(now);
      whoIsOnScreen().forEach((c) => onScreen.add(c));
      if (now - start < WINDOW) { requestAnimationFrame(step); return; }
      sampling = false;
      finish(times, longTasks - lt0, [...onScreen], reason);
    };
    requestAnimationFrame(step);
  }

  function finish(times, lt, onScreen, reason) {
    if (times.length < 10) return;
    const d = [];
    for (let i = 1; i < times.length; i++) d.push(times[i] - times[i - 1]);
    const sorted = [...d].sort((a, b) => a - b);
    const median = sorted[sorted.length >> 1];
    if (!intervalKnown && reason === "calibrate") {
      // the display's refresh interval: the median gap of a calm window, snapped to common rates
      const hz = [60, 75, 90, 100, 120, 144, 165, 240].reduce((b, r) => (Math.abs(1000 / r - median) < Math.abs(1000 / b - median) ? r : b), 60);
      interval = 1000 / hz; intervalKnown = true;
    }
    const mean = d.reduce((a, b) => a + b, 0) / d.length;
    // stability counts only below 60 Hz: on a fast display, 4-12 ms gaps are not jank
    const c = d.map((x) => Math.max(x, 1000 / 60)), cm = c.reduce((a, b) => a + b, 0) / c.length;
    const sd = Math.sqrt(c.reduce((a, b) => a + (b - cm) ** 2, 0) / c.length);
    const limit = 2.5 * Math.max(interval, 1000 / 60);                       // stutters; a 144 Hz screen at 100 fps is not stuttering
    const dropped = d.filter((x) => x > limit).length / d.length;
    const report = {
      at: Date.now(), reason, frames: d.length,
      fps: 1000 / mean, frameTime: mean, frameSd: sd, cv: sd / cm, p95: sorted[Math.floor(sorted.length * 0.95)],
      dropped, longTasks: lt, refreshHz: Math.round(1000 / interval), onScreen,
    };
    window.CSPerfMonitor.last = report;
    listeners.forEach((fn) => { try { fn(report); } catch { /* listener failed */ } });
  }

  // activity: only measure while something is happening on screen
  const poke = () => {
    activeUntil = performance.now() + 2000;
    if (!sampling && performance.now() - lastWindow > (window.CSPerfMonitor.urgent ? 3000 : GAP)) sample("activity");
  };
  ["scroll", "wheel", "pointermove", "touchmove", "keydown"].forEach((ev) => addEventListener(ev, poke, { passive: true, capture: true }));
  addEventListener("load", () => setTimeout(() => sample("calibrate"), 900));
  document.addEventListener("visibilitychange", () => { if (!document.hidden) lastWindow = performance.now() - GAP + 1500; });

  window.CSPerfMonitor = {
    onReport: (fn) => listeners.push(fn),
    setOnScreen: (fn) => { whoIsOnScreen = fn; },
    sampleNow: () => sample("request"),
    get refreshHz() { return Math.round(1000 / interval); },
    get active() { return performance.now() < activeUntil; },
    urgent: false,                                                           // set by the controller after a bad window
    last: null,
  };
})();
