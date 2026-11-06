/* What can this phone do? Measures the device and picks a tier.
 *
 *   full    — the real engine runs on the phone; files up to 40 MB; all effects
 *   light   — the engine runs on demand; files up to 8 MB; fewer effects
 *   viewer  — no on-device engine (old browser / very little memory): the app
 *             explains that cloud scanning is coming soon
 *
 * A short benchmark after the engine loads can lower the tier further.
 */
(function () {
  "use strict";
  const ua = navigator.userAgent || "";
  const ios = /iPhone|iPad|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const android = /Android/i.test(ua);

  function wasmOk() {
    try {
      if (typeof WebAssembly !== "object") return false;
      // the 8-byte header of an empty WebAssembly module
      return WebAssembly.validate(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
    } catch { return false; }
  }
  function webgl() {
    try { return !!document.createElement("canvas").getContext("webgl2"); } catch { return false; }
  }

  async function measure() {
    const conn = navigator.connection || {};
    const storage = navigator.storage && navigator.storage.estimate ? await navigator.storage.estimate().catch(() => null) : null;
    const caps = {
      platform: ios ? "ios" : android ? "android" : "other",
      wasm: wasmOk(),
      workers: typeof Worker === "function",
      memoryGB: navigator.deviceMemory || null,          // Chrome / Android only
      cores: navigator.hardwareConcurrency || null,
      saveData: !!conn.saveData,
      network: conn.effectiveType || null,
      standalone: matchMedia("(display-mode: standalone)").matches || navigator.standalone === true,
      webgl: webgl(),
      subtle: !!(window.crypto && crypto.subtle),
      share: typeof navigator.share === "function",
      vibrate: typeof navigator.vibrate === "function",
      reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches,
      freeMB: storage && storage.quota ? Math.round((storage.quota - (storage.usage || 0)) / 1048576) : null,
      screen: `${screen.width}×${screen.height} @${window.devicePixelRatio || 1}x`,
    };
    caps.tier = tierOf(caps);
    return caps;
  }

  function tierOf(c) {
    if (!c.wasm || !c.workers) return "viewer";
    let score = 0;
    if (c.memoryGB == null) score += c.platform === "ios" ? 2 : 1;   // iOS never reports memory; recent iPhones have ≥4 GB
    else score += c.memoryGB >= 4 ? 2 : c.memoryGB >= 2 ? 1 : -2;
    if (c.cores == null) score += 1;
    else score += c.cores >= 6 ? 2 : c.cores >= 4 ? 1 : 0;
    if (c.saveData) score -= 2;
    if (c.freeMB != null && c.freeMB < 60) score -= 3;               // the engine needs ~25 MB of cache
    return score >= 3 ? "full" : score >= 1 ? "light" : "viewer";
  }

  const LIMITS = { full: 40 * 1048576, light: 8 * 1048576, viewer: 0 };

  /* After the engine is ready: time one small real scan (a short text with a
   * link: every heuristic runs). A desktop takes ~40 ms; a recent phone a few
   * hundred. Slow phones drop a tier so big files don't freeze them. */
  function adjustAfterBenchmark(caps, ms) {
    caps.benchmarkMs = ms;
    if (caps.tier === "full" && ms > 600) caps.tier = "light";
    else if (caps.tier === "light" && ms > 4000) caps.tier = "viewer";
    return caps;
  }

  window.CSCaps = { measure, LIMITS, adjustAfterBenchmark, ios, android };
})();
