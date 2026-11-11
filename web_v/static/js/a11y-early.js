/* Runs in <head>, before every other script: if the visitor chose "Reduce motion"
 * on this site, every module that asks the browser for (prefers-reduced-motion)
 * gets "yes", and CSS gets html.reduce-motion. The OS setting is honoured anyway. */
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
