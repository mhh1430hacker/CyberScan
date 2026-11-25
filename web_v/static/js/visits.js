/* The site's real visit counter: one beacon per browser session (web_v/visits.py counts it).
 * sessionStorage makes a reload or moving between pages count once; a browser that blocks storage
 * may count once per page instead. No cookie, nothing personal is sent: the body is empty. */
(function () {
  "use strict";
  try {
    if (sessionStorage.getItem("cs-visit")) return;
    sessionStorage.setItem("cs-visit", "1");
  } catch { /* storage off: still count this page view once */ }
  const send = () => {
    try {
      if (navigator.sendBeacon) navigator.sendBeacon("/api/visit", new Blob([""], { type: "text/plain" }));
      else fetch("/api/visit", { method: "POST", keepalive: true, body: "" }).catch(() => {});
    } catch { /* counting must never disturb the page */ }
  };
  // after the page has settled, so the beacon never competes with loading
  if (document.readyState === "complete") setTimeout(send, 1500);
  else addEventListener("load", () => setTimeout(send, 1500), { once: true });
})();
