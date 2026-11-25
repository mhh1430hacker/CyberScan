/* Real-user speed measurements, without any third party: Largest Contentful Paint, Interaction to
 * Next Paint, Cumulative Layout Shift, Time To First Byte (and First Contentful Paint), measured with
 * PerformanceObserver and sent once, when the page is hidden, to POST /api/vitals with
 * navigator.sendBeacon. Only 1 in 5 page views is measured. Sent: the page path, the numbers, the
 * navigation type and phone/desktop. Nothing personal: no IDs, no cookies, no URL query, no text. */
(function () {
  "use strict";
  if (window.__csVitals || !("PerformanceObserver" in window) || !navigator.sendBeacon) return;
  window.__csVitals = true;
  if (window.parent !== window) return;   // a page inside the persistent player frame is measured by its own visit
  if (Math.random() >= 0.2) return;

  const m = {};
  const supported = (PerformanceObserver.supportedEntryTypes || []);
  function observe(type, fn, opts) {
    if (!supported.includes(type)) return;
    try { new PerformanceObserver((list) => list.getEntries().forEach(fn)).observe(Object.assign({ type, buffered: true }, opts || {})); } catch { /* not supported */ }
  }

  observe("largest-contentful-paint", (e) => { m.LCP = e.startTime; });
  observe("paint", (e) => { if (e.name === "first-contentful-paint") m.FCP = e.startTime; });
  // CLS: the largest session window of layout shifts (gaps < 1 s, window < 5 s), as the Web Vitals definition
  let win = 0, winStart = 0, winLast = 0;
  observe("layout-shift", (e) => {
    if (e.hadRecentInput) return;
    if (win && e.startTime - winLast < 1000 && e.startTime - winStart < 5000) win += e.value;
    else { win = e.value; winStart = e.startTime; }
    winLast = e.startTime;
    m.CLS = Math.max(m.CLS || 0, win);
  });
  // INP: the slowest interaction (an approximation of the 98th percentile, fine for one page view)
  const inter = {};
  observe("event", (e) => {
    if (!e.interactionId) return;
    inter[e.interactionId] = Math.max(inter[e.interactionId] || 0, e.duration);
    const all = Object.values(inter).sort((a, b) => b - a);
    m.INP = all[Math.min(all.length - 1, Math.floor(all.length / 50))];
  }, { durationThreshold: 40 });
  try {
    const nav = performance.getEntriesByType("navigation")[0];
    if (nav) { m.TTFB = Math.max(0, nav.responseStart - (nav.activationStart || 0)); m.nav = nav.type; }
  } catch { /* old browser */ }

  let sent = false;
  function send() {
    if (sent) return;
    const list = ["LCP", "INP", "CLS", "TTFB", "FCP"].filter((k) => typeof m[k] === "number").map((k) => ({ n: k, v: k === "CLS" ? Number(m[k].toFixed(4)) : Math.round(m[k]) }));
    if (!list.length) return;
    sent = true;
    const body = JSON.stringify({ p: location.pathname, m: list, nav: m.nav || "", mob: matchMedia("(pointer: coarse)").matches ? 1 : 0 });
    try { navigator.sendBeacon("/api/vitals", new Blob([body], { type: "text/plain" })); } catch { /* best effort */ }
  }
  addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") send(); });
  addEventListener("pagehide", send);
})();
