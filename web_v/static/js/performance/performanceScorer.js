/* Adaptive Performance Engine, part 3 of 6: turning evidence into a level.
 *
 * Levels: 1 Ultra, 2 High, 3 Balanced, 4 Optimized, 5 Essential.
 * Two scores, both 0..100:
 *   capability (before anything has run): the GPU path matters most (no WebGL, a software
 *     renderer, WebGL1 only, WebGL2), then memory, cores and the number of pixels to fill.
 *     Cores alone never decide; WebGPU earns only a small nudge, never a level on its own.
 *     The result is a ceiling: the most this device should be asked to do.
 *   runtime (from each monitor window): how close the frame rate stays to 60 (or the display's
 *     rate, if lower), how many frames were dropped, how steady frame times were, and long tasks.
 * The level shown is the capability ceiling, lowered by sustained runtime trouble (adaptiveController). */
(function () {
  "use strict";
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
  const NAMES = ["", "Ultra", "High", "Balanced", "Optimized", "Essential"];

  function capability(c) {
    const why = [];
    let s;
    if (!c.webgl) { s = 30; why.push("no WebGL"); }
    else if (c.software) { s = 26; why.push("software renderer"); }
    else if (!c.webgl2) { s = 50; why.push("WebGL1 only"); }
    else { s = 72; why.push("WebGL2"); }
    const r = (c.renderer || "").toLowerCase();
    if (c.webgl && !c.software) {
      if (/nvidia|geforce|rtx|radeon rx|radeon pro|apple m\d|apple gpu/.test(r)) { s += 10; why.push("dedicated or Apple GPU"); }
      else if (/mali-[gt]?[1-6]\d|adreno \(tm\) [3-5]\d\d|powervr|intel\(r\) hd graphics [2-5]\d\d\b/.test(r)) { s -= 10; why.push("older mobile/integrated GPU"); }
    }
    if (c.maxTexture >= 16384) s += 3;
    if (c.memory) { if (c.memory <= 2) { s -= 18; why.push("≤2 GB memory"); } else if (c.memory <= 4) { s -= 7; why.push("4 GB memory"); } else if (c.memory >= 8) s += 4; }
    if (c.cores) { if (c.cores <= 2) { s -= 14; why.push("≤2 cores"); } else if (c.cores <= 4) { s -= 5; why.push("4 cores"); } else if (c.cores >= 8) s += 3; }
    const px = c.screenW * c.screenH * c.dpr * c.dpr;
    if (px > 8.2e6) { s -= 7; why.push("very high resolution to fill"); } else if (px > 4.5e6) s -= 3;
    if (c.coarse && Math.min(c.screenW, c.screenH) < 500) s -= 4;
    if (c.webgpu === "adapter") s += 3;                                       // a nudge, nothing more
    let level = toLevel(s);
    if (c.saveData) { level = Math.max(level, 4); why.push("data saver"); }
    if (!c.webgl) level = Math.max(level, 4);                               // CSS can still be rich; no 3D
    if (c.software) level = Math.max(level, 4);
    return { score: clamp(Math.round(s), 0, 100), level, why };
  }

  function toLevel(s) { return s >= 82 ? 1 : s >= 66 ? 2 : s >= 50 ? 3 : s >= 34 ? 4 : 5; }

  function runtime(rep) {
    const target = Math.min(60, rep.refreshHz || 60);
    const ratio = clamp(rep.fps / target, 0, 1.05);
    let s = 100 * ratio;
    s -= 140 * rep.dropped;                                                  // stutters: 5 % costs 7 points
    s -= 60 * clamp(rep.cv - 0.2, 0, 1);                                     // jitter beyond normal noise
    s -= 2 * Math.min(10, rep.longTasks);
    s = clamp(Math.round(s), 0, 100);
    // a verdict, with a dead band between "bad" and "good" so the level doesn't wobble
    let verdict = s < 72 ? "bad" : s >= 88 ? "good" : "ok";
    if (rep.fps >= 0.97 * target && rep.dropped < 0.03 && verdict === "bad") verdict = "ok";   // full speed without stutter is never "bad"
    return { score: s, verdict };
  }

  window.CSPerfScore = { capability, runtime, toLevel, NAMES };
})();
