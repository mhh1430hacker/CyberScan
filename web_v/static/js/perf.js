/* Performance mode for the landing page and the app.
 *
 * "low" (html.perf-low) turns off background blur, lets looping decorations
 * play once, and asks the canvases for fewer particles at lower resolution.
 * Chosen automatically:
 *   - at once on weak devices (≤ 4 GB memory, ≤ 4 cores, data saver);
 *   - otherwise after measuring the frame rate for a few seconds: below
 *     40 frames per second switches to low and is remembered;
 * and the visitor can force either mode with the footer switch.
 * Loaded in <head> so every module sees the decision before it starts. */
(function () {
  "use strict";
  const KEY = "cs-perf";   // "low" | "high" (chosen by the visitor) | "auto-low" (measured)
  let stored = null;
  try { stored = localStorage.getItem(KEY); } catch { /* storage off */ }
  const mem = navigator.deviceMemory, cores = navigator.hardwareConcurrency;
  const saveData = !!(navigator.connection && navigator.connection.saveData);
  const weak = (mem && mem <= 4) || (cores && cores <= 4) || saveData;
  let low = stored === "low" || stored === "auto-low" || (stored !== "high" && weak);

  function apply() {
    document.documentElement.classList.toggle("perf-low", low);
    window.dispatchEvent(new CustomEvent("cs:perf", { detail: { low } }));
  }
  function set(value, remember) {
    low = !!value;
    try { localStorage.setItem(KEY, remember ? (low ? "low" : "high") : (low ? "auto-low" : "")); } catch { /* storage off */ }
    apply();
  }
  document.documentElement.classList.toggle("perf-low", low);

  /* measure once the page has settled; only when nothing was decided yet */
  function measure() {
    if (low || stored === "high") return;
    let frames = 0, start = 0, stalls = 0, last = 0;
    const step = (now) => {
      if (document.hidden) { start = 0; requestAnimationFrame(step); return; }
      if (!start) { start = last = now; }
      frames++;
      if (now - last > 50) stalls++;
      last = now;
      if (now - start < 4000) { requestAnimationFrame(step); return; }
      const fps = (frames * 1000) / (now - start);
      window.CSPerf.fps = Math.round(fps);
      if (fps < 40 || stalls > 25) set(true, false);
    };
    requestAnimationFrame(step);
  }
  window.addEventListener("load", () => setTimeout(measure, 1500));

  window.CSPerf = {
    get low() { return low; },
    set,
    fps: null,
    // particles / resolution budgets the canvases ask for
    particles: (full) => (low ? Math.round(full * 0.35) : full),
    dpr: (cap) => Math.min(window.devicePixelRatio || 1, low ? 1 : cap),
  };
})();
