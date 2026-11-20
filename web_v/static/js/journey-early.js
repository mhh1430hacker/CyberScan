/* The File Journey: settles the language and the motion mode before the first paint, so the page
 * never flashes in the wrong direction. Same storage keys as the main site. The language is the
 * site's choice when js/journey-i18n.js has words for it, English otherwise. */
(function () {
  "use strict";
  var html = document.documentElement, lang = "en", dict = window.FJ_I18N || {};
  try {
    var want = String(localStorage.getItem("cyberscan-lang") || "").toLowerCase();
    if (want && dict[want]) lang = want;
  } catch (e) { /* storage off */ }
  html.lang = lang;
  html.dir = (dict[lang] && dict[lang]._dir) === "rtl" ? "rtl" : "ltr";
  html.classList.add("js");
  // the site's capability probe runs next and creates (then drops) a WebGL context, unless this
  // session already has its result: js/journey.js waits a moment before its own context if so
  try { window.__fjFreshProbe = !sessionStorage.getItem("cs-caps-v1"); } catch (e) { window.__fjFreshProbe = true; }
  var rm = false;
  try { rm = localStorage.getItem("cs-motion") === "reduce"; } catch (e) { /* storage off */ }   // the site's own switch
  if (rm) html.classList.add("reduce-motion");
  if (rm || (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches)) html.classList.add("fj-still");
  var T = function (k) { return (dict[lang] && dict[lang][k]) || (dict.en && dict.en[k]) || ""; };
  if (T("docTitle")) document.title = T("docTitle");
})();
