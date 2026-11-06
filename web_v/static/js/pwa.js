/* Installable app, connection watchdog, desktop-notification switch. */
(function () {
  "use strict";
  const { $, t, toast } = window.CS;
  const CS = window.CS;

  /* ---------------- service worker & install ---------------- */
  let deferred = null;
  if ("serviceWorker" in navigator && window.isSecureContext) {
    navigator.serviceWorker.register("sw.js").catch(() => { /* not fatal */ });
  }
  const installButtons = document.querySelectorAll(".install-btn");
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferred = e;
    installButtons.forEach((b) => { b.hidden = false; });
  });
  window.addEventListener("appinstalled", () => {
    deferred = null;
    installButtons.forEach((b) => { b.hidden = true; });
    toast(t("installed"));
  });
  async function install() {
    if (!deferred) return;
    deferred.prompt();
    await deferred.userChoice.catch(() => null);
    deferred = null;
    installButtons.forEach((b) => { b.hidden = true; });
  }
  installButtons.forEach((b) => b.addEventListener("click", install));
  if (matchMedia("(display-mode: standalone)").matches) document.documentElement.classList.add("standalone");

  /* ---------------- is the local scanner still there? ---------------- */
  const conn = $("conn");
  let down = false, timer = null;
  async function ping() {
    let ok = false;
    try {
      const ctrl = new AbortController();
      const kill = setTimeout(() => ctrl.abort(), 4000);
      const res = await fetch("/api/events?since=999999999", { headers: { "X-CyberScan-Token": document.querySelector('meta[name="cyberscan-token"]').content }, signal: ctrl.signal });
      clearTimeout(kill);
      ok = res.ok;
    } catch { ok = false; }
    if (!ok && !down) { down = true; conn.hidden = false; conn.className = "conn down"; conn.lastChild.textContent = t("connDown"); }
    else if (ok && down) {
      down = false; conn.className = "conn up"; conn.lastChild.textContent = t("connBack");
      setTimeout(() => { if (!down) conn.hidden = true; }, 2500);
    }
    timer = setTimeout(ping, down ? 3000 : 15000);
  }
  window.addEventListener("online", () => { clearTimeout(timer); ping(); });
  window.addEventListener("offline", () => { clearTimeout(timer); ping(); });
  timer = setTimeout(ping, 5000);

  /* ---------------- notifications switch ---------------- */
  const sw = $("notify-toggle");
  const hint = $("notify-hint");
  function sync() {
    const supported = "Notification" in window;
    sw.disabled = !supported || Notification.permission === "denied";
    sw.checked = CS.notificationsOn();
    hint.textContent = !supported ? t("notifyUnsupported") : Notification.permission === "denied" ? t("notifyDenied") : t("setNotifyHint");
  }
  sw.addEventListener("change", async () => {
    if (sw.checked && Notification.permission !== "granted") {
      const answer = await Notification.requestPermission().catch(() => "denied");
      if (answer !== "granted") { sync(); return; }
    }
    try { localStorage.setItem("cs-notify", sw.checked ? "1" : "0"); } catch { /* storage off */ }
    sync();
    if (sw.checked) toast(t("notifyOn"));
  });
  CS.onLang(sync);
  window.addEventListener("cs:view", (e) => { if (e.detail === "settings") sync(); });
  sync();

  window.CSPwa = { canInstall: () => !!deferred, install };
})();
