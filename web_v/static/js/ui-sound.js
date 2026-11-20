/* Interface sounds: every kind of interaction has its own small sound (js/cs-audio.js plays them).
 *
 *   hover   nav link · link · button · call to action · card   (mouse only, after the first click)
 *   press   button · link · call to action · tab · language · copy
 *   switch  on / off (checkboxes, switches, the sound buttons)
 *   dialogs open / close, <details> open / close
 *   files   dragged over the page, dropped
 *   scan    start · progress · clean · review · threat · error   (the app's cs:* events)
 *   slider  a tick that follows the value
 * Quiet, rate-limited, panned a little toward the pointer, and tuned to the music's key (D).
 * One switch for all of them on every page: the effects buttons (.sfx-btn) and Settings ›
 * Display (#ui-sound-toggle); the choice is shared across the site's pages and subdomains.
 * window.CSUiSound keeps its old interface (on, set, press, hover). */
(function () {
  "use strict";
  const A = window.CSAudio;
  if (!A) return;
  const play = (name, o) => A.play(name, o || {});
  const panOf = (x) => (typeof x === "number" && innerWidth ? (x / innerWidth - 0.5) * 0.9 : 0);

  const BTN = "button, [role=button], input[type=submit], input[type=button], summary, .chip, label.drop, label.setting, .lg-opt, .pal-item, .pipe-node";
  const NAV = "nav a, header a, footer a, .l-links a, .fj-top a, .sp-top a, .sp-foot a, .side-dots a";
  const CTA = ".primary, .sp-cta, .l-cta a, .cta, [data-cta]";
  const CARDS = ".tm-card, .stat, .feat, .priv-card, .bento-card, .sy-dom, .film-chap, .cine-timeline li, .card, .row, [data-cursor=card]";
  const TAB = "[role=tab], .tab, .rtab";
  const LANG = ".lg-opt, [data-lang], #fj-lang, #sp-lang, .lang-btn, .lang-opt";
  const COPY = "[data-copy], .sp-copy, .copy, [data-action*=copy]";
  const SILENT = ".sound-btn, .sfx-btn, #fj-sound, .csm-toggle, .switch, input[type=checkbox], input[type=radio], [role=switch]";
  const closest = (el, sel) => (el && el.closest ? el.closest(sel) : null);

  function hoverKind(el) {
    if (closest(el, CTA)) return "hoverCta";
    if (closest(el, BTN)) return "hoverButton";
    if (closest(el, NAV)) return "hoverNav";
    if (closest(el, "a[href]")) return "hoverLink";
    if (closest(el, CARDS)) return "hoverCard";
    return null;
  }
  function pressKind(el) {
    if (closest(el, SILENT)) return null;               // switches sound when they change
    if (closest(el, ":disabled, [aria-disabled=true]")) return "error";
    if (closest(el, LANG)) return "lang";
    if (closest(el, TAB)) return "tab";
    if (closest(el, COPY)) return "copy";
    if (closest(el, CTA)) return "cta";
    if (closest(el, BTN)) return "press";
    if (closest(el, "a[href]")) return "linkPress";
    return null;
  }

  let hoverEl = null;
  document.addEventListener("pointerover", (e) => {
    if (e.pointerType !== "mouse") return;
    const k = hoverKind(e.target);
    if (!k) { hoverEl = null; return; }
    const el = closest(e.target, k === "hoverCard" ? CARDS : k === "hoverCta" ? CTA : k === "hoverButton" ? BTN : "a[href]");
    if (el === hoverEl || (el && el.contains(e.relatedTarget))) return;
    hoverEl = el;
    play(k, { pan: panOf(e.clientX) });
  }, { passive: true });
  document.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    const k = pressKind(e.target);
    if (k) play(k, { pan: panOf(e.clientX) });
  }, { passive: true });
  document.addEventListener("keydown", (e) => {
    if ((e.key !== "Enter" && e.key !== " ") || e.repeat) return;
    const el = closest(e.target, "button, a[href], [role=button], [role=tab], summary");
    if (!el) return;
    const k = pressKind(el);
    if (k) play(k);
  });
  // switches
  document.addEventListener("change", (e) => {
    const n = e.target;
    if (n && n.matches && n.matches("input[type=checkbox], input[type=radio]") && n.id !== "ui-sound-toggle") play(n.checked ? "toggleOn" : "toggleOff");
  });
  document.addEventListener("click", (e) => {
    const sw = closest(e.target, "[role=switch]");
    if (sw && !sw.matches("input")) setTimeout(() => play(sw.getAttribute("aria-checked") === "true" ? "toggleOn" : "toggleOff"), 0);
  });
  // sliders
  document.addEventListener("input", (e) => {
    const n = e.target;
    if (!n || n.type !== "range") return;
    const min = +n.min || 0, max = +n.max || 100;
    play("slider", { v: (n.value - min) / (max - min || 1) });
  });
  // dialogs and disclosures
  new MutationObserver((ms) => ms.forEach((m) => {
    if (m.target.tagName === "DIALOG") play(m.target.open ? "dialogOpen" : "dialogClose");
  })).observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ["open"] });
  document.addEventListener("toggle", (e) => { if (e.target.tagName === "DETAILS") play(e.target.open ? "dialogOpen" : "dialogClose"); }, true);
  // copying, files
  document.addEventListener("copy", () => play("copy"));
  let dragAt = 0;
  document.addEventListener("dragenter", (e) => {
    if (!e.dataTransfer || ![...(e.dataTransfer.types || [])].includes("Files")) return;
    if (performance.now() - dragAt > 1200) play("dragIn");
    dragAt = performance.now();
  });
  document.addEventListener("drop", () => play("drop"), true);
  // the scan (app.js tells the page what happens)
  addEventListener("cs:scan-start", () => play("scanStart"));
  let tickK = 0;
  addEventListener("cs:stages", () => play("scanTick", { k: tickK++ }));
  addEventListener("cs:upload", (e) => { if (e.detail && !e.detail.done) play("scanTick", { k: tickK++ }); });
  addEventListener("cs:scan-error", () => play("error"));
  addEventListener("cs:result", (e) => {
    const d = e.detail || {}, r = d.result || {};
    if (!d.animate) return;
    tickK = 0;
    const ds = r.detection_summary || {};
    const fin = [ds.final_score, r.final_score].find((v) => v !== undefined && v !== null && Number.isFinite(Number(v)));
    const score = fin !== undefined ? Number(fin) : Math.max(Number(r.combined_score) || 0, Number(ds.content_score) || 0);
    const cls = ds.classification || r.classification || "";
    setTimeout(() => play(cls === "KNOWN_MALWARE" || score >= 50 ? "threat" : score > 0 ? "review" : "clean"), 120);
  });
  // a new language
  if (window.CS && CS.onLang) { let first = true; CS.onLang(() => { if (first) { first = false; return; } play("lang"); }); }

  /* ---------- the effects switch ---------- */
  const sw = document.getElementById("ui-sound-toggle");
  const fxBtns = [...document.querySelectorAll(".sfx-btn")].filter((b) => b.id !== "fj-sound");
  const OWN = { en: { sfxOn: "Sound effects on (click to mute)", sfxOff: "Sound effects off (click to turn on)" }, ar: { sfxOn: "المؤثرات الصوتية مفعّلة (اضغط للكتم)", sfxOff: "المؤثرات الصوتية متوقفة (اضغط للتفعيل)" } };
  const T = (k) => (window.CS && CS.t ? CS.t(k) : OWN[document.documentElement.lang === "ar" ? "ar" : "en"][k] || k);
  function paint() {
    const on = A.fx;
    fxBtns.forEach((b) => { b.setAttribute("aria-pressed", String(on)); b.classList.toggle("off", !on); b.setAttribute("aria-label", T(on ? "sfxOn" : "sfxOff")); b.title = T(on ? "sfxOn" : "sfxOff"); });
    if (sw) sw.checked = on;
  }
  function set(v) {
    if (!v) play("toggleOff");
    A.setFx(!!v);
    if (v) setTimeout(() => play("toggleOn"), 30);
  }
  if (sw) sw.addEventListener("change", () => set(sw.checked));
  fxBtns.forEach((b) => b.addEventListener("click", () => set(!A.fx)));
  A.onChange(paint, window);
  if (window.CS && CS.onLang) CS.onLang(paint);
  paint();

  window.CSUiSound = { get on() { return A.fx; }, set, press: () => play("press"), hover: () => play("hoverButton") };
})();
