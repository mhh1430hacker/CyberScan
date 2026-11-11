/* "Get the app" menu: the signed Android APK (details from downloads/android.json,
 * written by web_v/android/release.ps1) and store badges marked "coming soon". */
(function () {
  "use strict";
  const btn = document.querySelector(".get-app-btn");
  const panel = document.getElementById("get-app-panel");
  if (!btn || !panel) return;
  const t = (k) => (window.CS && window.CS.t ? window.CS.t(k) : k);
  let info = null;

  function render() {
    if (!info) return;
    const link = document.getElementById("apk-link");
    link.href = `downloads/${info.file}`;
    link.setAttribute("download", info.file);
    const meta = t("apkMeta");
    document.getElementById("apk-meta").textContent = typeof meta === "function" ? meta(info.version, (info.size / 1048576).toFixed(1)) : `APK · v${info.version}`;
    const sha = document.getElementById("apk-sha");
    sha.textContent = `SHA-256 ${info.sha256.slice(0, 8)}…${info.sha256.slice(-8)}`;
    sha.title = `SHA-256 of the APK: ${info.sha256}\nSigning certificate: ${info.cert_sha256 || ""}`;
  }
  fetch("downloads/android.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : null)).then((j) => { info = j; render(); }).catch(() => {});
  if (window.CS && window.CS.onLang) window.CS.onLang(render);

  function open(on) {
    panel.hidden = !on;
    btn.setAttribute("aria-expanded", String(on));
  }
  btn.addEventListener("click", (e) => { e.stopPropagation(); open(panel.hidden); });
  panel.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => open(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !panel.hidden) { open(false); btn.focus(); } });
  document.getElementById("apk-link").addEventListener("click", () => setTimeout(() => open(false), 400));
})();
