/* Script errors, reported to the site itself (no third party): window error and unhandled promise
 * rejections go to POST /api/errors with navigator.sendBeacon. Only the message, the script's
 * address (without query) and line/column; at most 5 reports per page view, never the same one
 * twice. The server removes anything that looks like an email or a long number before storing. */
(function () {
  "use strict";
  if (window.__csErrors || !navigator.sendBeacon) return;
  window.__csErrors = true;
  let left = 5;
  const seen = new Set();
  function report(type, msg, src, line, col) {
    if (left <= 0) return;
    msg = String(msg || "").slice(0, 300);
    src = String(src || "").split("?")[0].split("#")[0].slice(0, 160);
    if (!msg || /^Script error\.?$/.test(msg)) return;   // cross-origin details hidden by the browser: nothing to learn
    if (src && !src.startsWith(location.origin)) return;  // extensions and other sites' scripts are not ours to fix
    const key = `${msg}|${src}|${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    left -= 1;
    const body = JSON.stringify({ type, p: location.pathname, msg, src: src.replace(location.origin, ""), line: Number(line) || 0, col: Number(col) || 0 });
    try { navigator.sendBeacon("/api/errors", new Blob([body], { type: "text/plain" })); } catch { /* best effort */ }
  }
  addEventListener("error", (e) => {
    if (e.target && e.target !== window) return;   // a failed image or script load, not a script error
    report("error", e.message, e.filename, e.lineno, e.colno);
  });
  addEventListener("unhandledrejection", (e) => {
    const r = e.reason;
    const msg = r && r.message ? `${r.name || "Error"}: ${r.message}` : String(r);
    let src = "", line = 0, col = 0;
    const at = r && typeof r.stack === "string" && r.stack.match(/(https?:\/\/[^\s)]+):(\d+):(\d+)/);
    if (at) { src = at[1]; line = at[2]; col = at[3]; } else src = location.href;
    report("rejection", msg, src, line, col);
  });
})();
