/* Decides, before the first paint, whether the opening sequence (#preloader, js/intro.js) plays.
 * It is skipped for reduced motion, after it has played once in this tab, on the scan page and on
 * app routes. Loaded in <head> so the page never flashes before the overlay or under it. */
(function () {
  "use strict";
  var html = document.documentElement;
  var seen = false;
  try { seen = sessionStorage.getItem("cs-intro") === "1"; } catch (e) { /* storage off */ }
  var reduced = (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches) || html.classList.contains("reduce-motion");
  var app = /^#\/(scan|history|repair|settings)/.test(location.hash) || /app\.html$/.test(location.pathname) || /^scan\./.test(location.hostname);
  // phones get the short, calm page: no opening sequence (it also kept the content hidden for seconds on slow phones)
  var small = (window.innerWidth || 0) <= 760;
  html.classList.add(seen || reduced || app || small ? "boot-skip" : "booting");
})();
