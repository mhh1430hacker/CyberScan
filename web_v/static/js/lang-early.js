/* Per-language addresses (/ar/, /fr/privacy...): the server marks the page with
 * <meta name="cyberscan-lang">. Before any other script reads the saved language, this makes
 * that language the visitor's choice (and skips the first-visit language screen), so /fr/ opens
 * in French. The plain address (/) keeps the usual automatic choice. */
(function () {
  "use strict";
  var m = document.querySelector('meta[name="cyberscan-lang"]');
  var code = m && m.content;
  if (!code || !/^[a-z]{2,3}$/.test(code)) return;
  try {
    localStorage.setItem("cyberscan-lang", code);
    localStorage.setItem("cs-lang-chosen", "1");
  } catch (e) { /* storage off: the page still starts with lang/dir set by the server */ }
})();
