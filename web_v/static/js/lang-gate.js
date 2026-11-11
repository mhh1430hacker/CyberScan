/* First visit: ask which language to use before anything else.
 * The answer is remembered; the top-bar language menu still changes it later. */
(function () {
  "use strict";
  const gate = document.getElementById("lang-gate");
  if (!gate) return;
  let chosen = false;
  try { chosen = localStorage.getItem("cs-lang-chosen") === "1"; } catch { /* storage off: ask every time */ }
  if (chosen) { gate.remove(); return; }

  // every language, the browser's own first; the person decides
  const suggest = window.CS_LANGS.suggest();
  const box = gate.querySelector(".lg-options");
  box.replaceChildren();
  const ordered = [...window.CS_LANGS.list].sort((a, b) => (a[0] === suggest ? -1 : b[0] === suggest ? 1 : 0));
  for (const [code, name] of ordered) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "lg-opt" + (code === suggest ? " suggested" : "");
    b.dataset.lang = code;
    b.lang = code;
    b.dir = window.CS_LANGS.dir(code);
    const c = document.createElement("span"); c.className = "lg-code"; c.textContent = code.toUpperCase();
    const n = document.createElement("b"); n.textContent = name;
    b.append(c, n);
    box.append(b);
  }
  const options = [...box.querySelectorAll(".lg-opt")];
  gate.classList.add("many");
  gate.hidden = false;
  document.body.classList.add("lang-asking");
  requestAnimationFrame(() => gate.classList.add("in"));
  setTimeout(() => options[0].focus(), 400);

  async function choose(lang) {
    try { localStorage.setItem("cs-lang-chosen", "1"); } catch { /* storage off */ }
    if (window.CS.lang !== lang) await window.CS.setLang(lang);
    gate.classList.remove("in");
    gate.classList.add("out");
    document.body.classList.remove("lang-asking");
    setTimeout(() => { gate.remove(); window.dispatchEvent(new Event("cs:landing")); }, 700);
  }
  options.forEach((b) => b.addEventListener("click", () => choose(b.dataset.lang)));
  gate.addEventListener("keydown", (e) => {
    const i = options.indexOf(document.activeElement);
    if (i < 0) return;
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (step) { options[(i + step + options.length) % options.length].focus(); e.preventDefault(); }
  });
})();
