/* Adaptive Performance Engine, part 5 of 6: the visitor's choice.
 *   "auto"      Auto Adaptive: the engine decides and keeps adjusting
 *   "1".."5"    a fixed level (Ultra .. Essential): the engine never changes it on its own
 * Stored in localStorage as cs-quality. The old two-state switch (cs-perf) is carried over once:
 * "low" (chosen) becomes Optimized, "high" (chosen) becomes High, a measured "auto-low" is dropped
 * so the new engine measures again. Reduced motion (the system setting, or the site's own switch)
 * is a preference, not a performance signal: it is reported separately and always honoured. */
(function () {
  "use strict";
  const KEY = "cs-quality";
  let mode = "auto";
  try {
    const v = localStorage.getItem(KEY);
    if (v === "auto" || /^[1-5]$/.test(v || "")) mode = v;
    else {
      const old = localStorage.getItem("cs-perf");
      if (old === "low") mode = "4"; else if (old === "high") mode = "2";
      if (old) { localStorage.removeItem("cs-perf"); localStorage.setItem(KEY, mode); }
    }
  } catch { /* storage off */ }
  const reducedMotion = () => (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches) || document.documentElement.classList.contains("reduce-motion");
  window.CSPerfSettings = {
    get mode() { return mode; },
    set(v) { mode = v === "auto" || /^[1-5]$/.test(String(v)) ? String(v) : "auto"; try { localStorage.setItem(KEY, mode); } catch { /* storage off */ } return mode; },
    reducedMotion,
  };
})();
