/* Arriving from another page of the site (js/site-nav.js left a short-lived cookie): the transition
 * veil is in place from the first paint and lifts once the page has painted under it (site-shell.css,
 * html.cs-arriving / .cs-lift). Synchronous in the head, before anything is drawn. */
(function () {
  "use strict";
  try {
    if (!/(?:^|;\s*)cs-arrive=1/.test(document.cookie)) return;
    const root = document.documentElement;
    root.classList.add("cs-arriving");
    const host = location.hostname, base = host.replace(/^(www|scan|j)\./, "");
    const dom = host.includes(".") && !/^[\d.]+$/.test(host) && base.includes(".") ? `; Domain=.${base}` : "";
    document.cookie = `cs-arrive=; Path=/; Max-Age=0${dom}`;
    // lift once the page has painted under the veil (two frames), never later than 1.6 s
    let lifted = false;
    const lift = () => { if (lifted) return; lifted = true; root.classList.add("cs-lift"); setTimeout(() => root.classList.remove("cs-arriving", "cs-lift"), 480); };
    requestAnimationFrame(() => requestAnimationFrame(lift));
    setTimeout(lift, 1600);
  } catch { /* cookies off */ }
})();
