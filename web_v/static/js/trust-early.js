/* The trust pages (/privacy, /terms, /security, /status, /tests, /changelog) carry English and
 * Arabic text side by side. Before the first paint this shows the visitor's language: the
 * per-language address (/ar/privacy: <meta name="cyberscan-lang">), else the language chosen
 * elsewhere on the site, else the browser's. Other languages read the English text for now. */
(function () {
  "use strict";
  var code = "";
  var m = document.querySelector('meta[name="cyberscan-lang"]');
  if (m && m.content) code = m.content;
  if (!code) { try { code = localStorage.getItem("cyberscan-lang") || ""; } catch (e) { /* storage off */ } }
  if (!code) code = String((navigator.languages && navigator.languages[0]) || navigator.language || "en").toLowerCase().split("-")[0];
  var ar = code === "ar";
  document.documentElement.lang = ar ? "ar" : "en";
  document.documentElement.dir = ar ? "rtl" : "ltr";
})();
