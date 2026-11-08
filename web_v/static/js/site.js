/* The presentation site's own small core (ainex-ai.xyz). The scan app lives on
 * its own page (scan.ainex-ai.xyz) and app.js is not loaded here. This gives the
 * landing scripts the window.CS they use: language and translations, messages,
 * one API helper, the cells backdrop, and "enter the app" (which opens the scan site). */
"use strict";
(function () {
  const meta = (name, fallback) => {
    const v = (document.querySelector(`meta[name="${name}"]`) || {}).content || "";
    return v && !v.startsWith("__") ? v : fallback;
  };
  const TOKEN = meta("cyberscan-token", "");
  const SCAN_URL = meta("cyberscan-scan-url", "app.html");
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };

  let lang = "en";
  try { lang = localStorage.getItem("cyberscan-lang") === "ar" ? "ar" : "en"; } catch { /* storage off */ }
  const t = (key) => (I18N[lang][key] !== undefined ? I18N[lang][key] : I18N.en[key]);

  const listeners = [];
  function applyLang() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach((n) => { if (n.dataset.keep) return; const v = t(n.dataset.i18n); if (typeof v === "string") n.textContent = v; });
    document.querySelectorAll("[data-i18n-ph]").forEach((n) => { n.placeholder = t(n.dataset.i18nPh); });
    document.querySelectorAll("[data-i18n-aria]").forEach((n) => { const v = t(n.dataset.i18nAria); if (typeof v === "string" && v !== n.dataset.i18nAria) n.setAttribute("aria-label", v); });
    listeners.forEach((fn) => fn());
  }
  function toggleLang() {
    lang = lang === "en" ? "ar" : "en";
    try { localStorage.setItem("cyberscan-lang", lang); } catch { /* storage off */ }
    applyLang();
  }
  document.querySelectorAll(".lang-btn").forEach((b) => b.addEventListener("click", toggleLang));

  async function api(path, options = {}) {
    const res = await fetch(path, { ...options, headers: { "X-CyberScan-Token": TOKEN, ...(options.headers || {}) } });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  function toast(message) {
    const box = el("div", "toast");
    box.append(el("span", "", message));
    $("toasts").append(box);
    setTimeout(() => { box.classList.add("out"); box.addEventListener("animationend", () => box.remove(), { once: true }); }, 2800);
  }

  const cells = window.CyberCells && $("cells") ? CyberCells.create($("cells"), { mode: "hero" }) : null;

  // the scan app is its own site: a short warp, then go there
  async function enterApp(x, y, view) {
    const veil = document.querySelector(".warp-veil");
    if (veil && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      veil.style.setProperty("--wx", `${x ?? innerWidth / 2}px`);
      veil.style.setProperty("--wy", `${y ?? innerHeight / 2}px`);
      veil.classList.remove("go"); void veil.offsetWidth; veil.classList.add("go");
      await new Promise((r) => setTimeout(r, 420));
    }
    location.href = `${SCAN_URL}#/${view || "scan"}`;
  }

  // old addresses (ainex-ai.xyz/#/scan, #/history…) no longer exist here: open the scan site
  function route() {
    const view = location.hash.replace(/^#\/?/, "").split("/")[0];
    if (["scan", "history", "repair", "settings"].includes(view)) { location.replace(`${SCAN_URL}#/${view}`); return true; }
    return false;
  }
  window.addEventListener("hashchange", route);

  window.CS = {
    $, el, t, api, toast, cells, enterApp, toggleLang,
    get lang() { return lang; },
    onLang: (fn) => listeners.push(fn),
    state: { view: null },
    notificationsOn: () => false,
  };

  if (!route()) {
    document.body.classList.add("on-landing");
    applyLang();
    requestAnimationFrame(() => window.dispatchEvent(new Event("cs:landing")));
  }
})();
