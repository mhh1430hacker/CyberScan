/* The Accessibility quick panel, on every page (landing, scan, journey, support, trust pages).
 * A small tab on the start edge opens four switches:
 *   - Larger text       html.a11y-large     (localStorage "cs-a11y")
 *   - High contrast     html.a11y-contrast  (localStorage "cs-a11y")
 *   - Reduce motion     the same switch as the landing footer: localStorage "cs-motion" and
 *                       html.reduce-motion (js/a11y-early.js applies it before the first paint,
 *                       then the page reloads, because animations are set up at load)
 *   - Sound off         music and sound effects off, through the site's audio engine (cs-audio
 *                       cookie, js/cs-audio.js), or the same cookie directly on pages without it.
 * Any element with [data-a11y-open] (e.g. the landing footer link) opens the panel too.
 * Texts: window.CS.t when the page has the site's translations (keys a11y*), else the built-in
 * English / Arabic below. */
(function () {
  "use strict";
  if (window.__csA11yPanel) return;
  window.__csA11yPanel = true;
  try { if (window.parent !== window && window.parent.__csA11yPanel && window.parent.location.origin === location.origin) return; } catch { /* cross-origin parent */ }
  const root = document.documentElement;
  const OWN = {
    en: { a11yOpen: "Accessibility", a11yTitle: "Accessibility", a11yLarge: "Larger text", a11yContrast: "High contrast", a11yMotion: "Reduce motion",
      a11ySound: "Sound off", a11yReset: "Reset", a11yClose: "Close", a11yHint: "Saved in this browser only." },
    ar: { a11yOpen: "إمكانية الوصول", a11yTitle: "إمكانية الوصول", a11yLarge: "نص أكبر", a11yContrast: "تباين عالٍ", a11yMotion: "تقليل الحركة",
      a11ySound: "إيقاف الصوت", a11yReset: "إعادة الضبط", a11yClose: "إغلاق", a11yHint: "يُحفظ في هذا المتصفح فقط." },
  };
  function t(key) {
    const CS = window.CS;
    if (CS && typeof CS.t === "function") { const v = CS.t(key); if (typeof v === "string" && v !== key) return v; }
    return (OWN[root.lang === "ar" ? "ar" : "en"] || OWN.en)[key];
  }

  /* ---------------- state ---------------- */
  function flags() { try { return new Set((localStorage.getItem("cs-a11y") || "").split(",").filter(Boolean)); } catch { return new Set(); } }
  function saveFlags(set) { try { if (set.size) localStorage.setItem("cs-a11y", [...set].join(",")); else localStorage.removeItem("cs-a11y"); } catch { /* storage off */ } }
  function motionReduced() { return root.classList.contains("reduce-motion"); }
  function audioPrefs() {
    const c = document.cookie.match(/(?:^|;\s*)cs-audio=([^;]+)/);
    let raw = "";
    if (c) { try { raw = decodeURIComponent(c[1]); } catch { raw = ""; } }
    if (!raw) { try { raw = localStorage.getItem("cs-audio") || ""; } catch { /* storage off */ } }
    return new URLSearchParams(raw || "m=0&v=0.70&f=1");
  }
  function soundOff() {
    const A = window.CSAudio;
    if (A) return !A.music && !A.fx;
    const q = audioPrefs();
    return q.get("m") !== "1" && q.get("f") === "0";
  }
  function setSound(off) {
    const A = window.CSAudio;
    if (A) { if (off) { A.setMusic(false); A.setFx(false); } else { A.setFx(true); } return; }
    const q = audioPrefs();
    q.set("m", "0"); q.set("f", off ? "0" : "1");
    const host = location.hostname;
    const base = host.replace(/^(www|scan|j)\./, "");
    const domain = host.includes(".") && !/^[\d.]+$/.test(host) && base.includes(".") ? `; Domain=.${base}` : "";
    try { document.cookie = `cs-audio=${encodeURIComponent(q.toString())}; Path=/; Max-Age=31536000; SameSite=Lax${domain}${location.protocol === "https:" ? "; Secure" : ""}`; } catch { /* cookies off */ }
    try { localStorage.setItem("cs-audio", q.toString()); } catch { /* storage off */ }
  }

  /* ---------------- markup ---------------- */
  const make = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text) n.textContent = text; return n; };
  const SVG = "http://www.w3.org/2000/svg";
  function icon(paths) {
    const s = document.createElementNS(SVG, "svg");
    s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true");
    paths.forEach((d) => { const p = document.createElementNS(SVG, "path"); p.setAttribute("d", d); s.append(p); });
    return s;
  }
  const tab = make("button", "a11y-tab");
  tab.type = "button";
  tab.setAttribute("aria-haspopup", "dialog");
  tab.setAttribute("aria-expanded", "false");
  tab.append(icon(["M12 5.5a1.6 1.6 0 1 0 0-3.2 1.6 1.6 0 0 0 0 3.2z", "M5 8.2c2.3.6 4.6.9 7 .9s4.7-.3 7-.9", "M12 9.1v5m0 0-3 6.4m3-6.4 3 6.4"]));
  const panel = make("div", "a11y-panel");
  panel.id = "a11y-panel";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-modal", "false");
  panel.hidden = true;
  tab.setAttribute("aria-controls", panel.id);
  const head = make("div", "a11y-head");
  const title = make("h2", "a11y-title");
  title.id = "a11y-title";
  panel.setAttribute("aria-labelledby", title.id);
  const close = make("button", "a11y-x");
  close.type = "button";
  close.append(icon(["M6 6l12 12M18 6 6 18"]));
  head.append(title, close);
  const list = make("div", "a11y-list");
  const ITEMS = [
    ["large", "a11yLarge", ["M4 18 9 6l5 12M5.8 14h6.4", "M15 18l3-7 3 7m-5-2h4"]],
    ["contrast", "a11yContrast", ["M12 3a9 9 0 1 0 0 18z", "M12 3a9 9 0 0 1 0 18"]],
    ["motion", "a11yMotion", ["M4 12h3l2-5 4 10 2-5h5"]],
    ["sound", "a11ySound", ["M4 9.5h3.5L12 6v12l-4.5-3.5H4z", "m16 9.5 4 5m0-5-4 5"]],
  ];
  const switches = {};
  ITEMS.forEach(([key, label, paths]) => {
    const b = make("button", "a11y-sw");
    b.type = "button";
    b.setAttribute("role", "switch");
    b.dataset.key = key;
    const name = make("span", "a11y-name");
    b.append(icon(paths), name, make("span", "a11y-knob"));
    b.addEventListener("click", () => toggle(key));
    switches[key] = { b, name, label };
    list.append(b);
  });
  const foot = make("div", "a11y-foot");
  const hint = make("p", "a11y-hint");
  const reset = make("button", "a11y-reset");
  reset.type = "button";
  foot.append(hint, reset);
  panel.append(head, list, foot);

  /* ---------------- behaviour ---------------- */
  function state(key) {
    if (key === "motion") return motionReduced();
    if (key === "sound") return soundOff();
    return root.classList.contains(`a11y-${key}`);
  }
  function render() {
    tab.setAttribute("aria-label", t("a11yOpen"));
    tab.title = t("a11yOpen");
    title.textContent = t("a11yTitle");
    close.setAttribute("aria-label", t("a11yClose"));
    hint.textContent = t("a11yHint");
    reset.textContent = t("a11yReset");
    Object.entries(switches).forEach(([key, s]) => {
      s.name.textContent = t(s.label);
      const on = state(key);
      s.b.setAttribute("aria-checked", String(on));
      s.b.classList.toggle("on", on);
    });
  }
  function toggle(key) {
    if (window.CSAudio && window.CSAudio.play) { try { window.CSAudio.play("toggle"); } catch { /* no sound */ } }
    if (key === "motion") {
      try { if (motionReduced()) localStorage.removeItem("cs-motion"); else localStorage.setItem("cs-motion", "reduce"); } catch { /* storage off */ }
      try { sessionStorage.setItem("cs-scroll", String(scrollY)); sessionStorage.setItem("cs-a11y-open", "1"); } catch { /* ignore */ }
      location.reload();   // animations are set up when the page loads
      return;
    }
    if (key === "sound") { setSound(!soundOff()); render(); return; }
    const set = flags();
    if (set.has(key)) set.delete(key); else set.add(key);
    saveFlags(set);
    root.classList.toggle(`a11y-${key}`, set.has(key));
    render();
  }
  reset.addEventListener("click", () => {
    saveFlags(new Set());
    root.classList.remove("a11y-large", "a11y-contrast");
    if (motionReduced()) { toggle("motion"); return; }
    render();
  });

  let opener = null;
  function open(from) {
    opener = from || tab;
    render();
    panel.hidden = false;
    tab.setAttribute("aria-expanded", "true");
    requestAnimationFrame(() => panel.classList.add("in"));
    const first = list.querySelector(".a11y-sw");
    if (first) first.focus({ preventScroll: true });
  }
  function shut(focusBack) {
    if (panel.hidden) return;
    panel.classList.remove("in");
    panel.hidden = true;
    tab.setAttribute("aria-expanded", "false");
    if (focusBack && opener) opener.focus({ preventScroll: true });
  }
  tab.addEventListener("click", () => (panel.hidden ? open(tab) : shut(true)));
  close.addEventListener("click", () => shut(true));
  panel.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); shut(true); return; }
    if (e.key !== "Tab") return;
    const items = [...panel.querySelectorAll("button")];
    const i = items.indexOf(document.activeElement);
    if (e.shiftKey && i === 0) { e.preventDefault(); items[items.length - 1].focus(); }
    else if (!e.shiftKey && i === items.length - 1) { e.preventDefault(); items[0].focus(); }
  });
  document.addEventListener("pointerdown", (e) => { if (!panel.hidden && !panel.contains(e.target) && !tab.contains(e.target) && !e.target.closest("[data-a11y-open]")) shut(false); });
  document.addEventListener("click", (e) => {
    const o = e.target.closest && e.target.closest("[data-a11y-open]");
    if (o) { e.preventDefault(); panel.hidden ? open(o) : shut(true); }
  });

  function mount() {
    document.body.append(tab, panel);
    render();
    if (window.CS && window.CS.onLang) window.CS.onLang(render);
    new MutationObserver(render).observe(root, { attributes: true, attributeFilter: ["lang"] });
    if (window.CSAudio && window.CSAudio.onChange) window.CSAudio.onChange(render);
    try {
      if (sessionStorage.getItem("cs-a11y-open")) { sessionStorage.removeItem("cs-a11y-open"); open(tab); }
      const y = sessionStorage.getItem("cs-scroll");
      if (y && !document.getElementById("motion-btn")) { sessionStorage.removeItem("cs-scroll"); requestAnimationFrame(() => scrollTo(0, Number(y))); }
    } catch { /* ignore */ }
  }
  if (document.body) mount(); else document.addEventListener("DOMContentLoaded", mount);
})();
