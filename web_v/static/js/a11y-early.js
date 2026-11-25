/* Runs in <head>, before every other script: if the visitor chose "Reduce motion"
 * on this site, every module that asks the browser for (prefers-reduced-motion)
 * gets "yes", and CSS gets html.reduce-motion. The OS setting is honoured anyway. */
/* The Accessibility panel's display modes (js/a11y-panel.js): larger text and high contrast,
 * applied here too so the first paint already has them. */
(function () {
  "use strict";
  let modes = "";
  try { modes = localStorage.getItem("cs-a11y") || ""; } catch { /* storage off */ }
  modes.split(",").forEach((m) => { if (m === "large" || m === "contrast") document.documentElement.classList.add(`a11y-${m}`); });
})();
(function () {
  "use strict";
  let reduce = false;
  try { reduce = localStorage.getItem("cs-motion") === "reduce"; } catch { /* storage off */ }
  if (!reduce) return;
  document.documentElement.classList.add("reduce-motion");
  const original = window.matchMedia.bind(window);
  window.matchMedia = (query) => {
    if (!/prefers-reduced-motion\s*:\s*reduce/.test(String(query))) return original(query);
    const noop = () => {};
    return { matches: true, media: String(query), onchange: null, addListener: noop, removeListener: noop, addEventListener: noop, removeEventListener: noop, dispatchEvent: () => false };
  };
})();

/* The scan page (/app.html) has its whole shell in the HTML. When no translation has to be applied
 * first (English, on the scan view), scan.css shows it at the first paint instead of after every
 * script has run; other languages keep waiting for app.js, so they never flash English. */
(function () {
  "use strict";
  let saved = null;
  try { saved = localStorage.getItem("cyberscan-lang"); } catch { /* storage off */ }
  if ((!saved || saved === "en") && /^(#\/?(scan)?)?$/.test(location.hash)) document.documentElement.classList.add("paint-early");
})();
