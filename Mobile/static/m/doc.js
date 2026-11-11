/* Show the page in the app's language (?lang=ar), otherwise the browser's. */
(function () {
  "use strict";
  const q = new URLSearchParams(location.search).get("lang");
  const lang = q === "ar" || q === "en" ? q : (navigator.language || "").startsWith("ar") ? "ar" : "en";
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  const other = document.getElementById(lang === "ar" ? "en" : "ar");
  if (other) other.hidden = true;
})();
