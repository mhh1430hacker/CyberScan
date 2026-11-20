/* First visit: ask which language to use before anything else.
 * The answer is remembered; the top-bar language menu still changes it later.
 * The list is the shared picker (js/languages.js): search by native, English or Arabic name,
 * arrows move through the grid (mirrored in RTL), Enter or a click chooses. Styles: lang-gate.css. */
(function () {
  "use strict";
  const gate = document.getElementById("lang-gate");
  if (!gate) return;
  let chosen = false;
  try { chosen = localStorage.getItem("cs-lang-chosen") === "1"; } catch { /* storage off: ask every time */ }
  if (chosen || !window.CS_LANGS || !window.CS_LANGS.picker) { gate.remove(); return; }

  const L = window.CS_LANGS;
  const suggest = L.suggest();
  const box = gate.querySelector(".lg-box");
  const make = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text) n.textContent = text; return n; };

  // the same mark as the preloader, drawn in
  const mark = box.querySelector(".lg-logo");
  const head = make("div", "lgx-head");
  const kicker = make("p", "lgx-kicker", "CyberScan");
  const title = make("h2", "lgx-title");
  title.id = "lg-title";
  const en = make("span", "", "Choose your language");
  const ar = make("span", "", "اختر لغتك");
  ar.lang = "ar"; ar.dir = "rtl";
  title.append(en, ar);
  if (mark) head.append(mark);
  head.append(kicker, title);

  let done = false;
  const p = L.picker({ current: suggest, suggested: suggest, variant: "grid", onChoose: (code, btn) => choose(code, btn) });
  const note = make("p", "lgx-note");
  const noteAr = make("span", "", "يمكنك تغييرها في أي وقت من الشريط العلوي.");
  noteAr.lang = "ar"; noteAr.dir = "rtl";
  note.append(make("span", "", "You can change this any time from the top bar."), noteAr);
  box.replaceChildren(head, p.root, note);
  box.tabIndex = -1;

  gate.hidden = false;
  document.body.classList.add("lang-asking");
  requestAnimationFrame(() => requestAnimationFrame(() => gate.classList.add("in")));
  // keyboard and mouse users land on the suggested language (typing searches); touch users get no keyboard popping up
  setTimeout(() => { if (matchMedia("(pointer: fine)").matches) p.focusList(); else box.focus({ preventScroll: true }); }, 420);

  async function choose(lang, btn) {
    if (done) return;
    done = true;
    if (btn) btn.classList.add("picked");
    try { localStorage.setItem("cs-lang-chosen", "1"); } catch { /* storage off */ }
    try { if (window.CS.lang !== lang) await window.CS.setLang(lang); } catch { /* the menu can still change it */ }
    gate.classList.remove("in");
    gate.classList.add("out");
    document.body.classList.remove("lang-asking");
    setTimeout(() => { gate.remove(); window.dispatchEvent(new Event("cs:landing")); }, 560);
  }

  // a modal: Tab stays inside, Escape keeps the suggested language
  gate.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); choose(suggest); return; }
    if (e.key !== "Tab") return;
    e.preventDefault();
    if (document.activeElement === p.input) p.focusList(); else p.input.focus();
  });
})();
