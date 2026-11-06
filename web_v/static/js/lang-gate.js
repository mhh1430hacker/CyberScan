/* First visit: ask which language to use before anything else.
 * The answer is remembered; the top-bar switch still changes it later. */
(function () {
  "use strict";
  const gate = document.getElementById("lang-gate");
  if (!gate) return;
  let chosen = false;
  try { chosen = localStorage.getItem("cs-lang-chosen") === "1"; } catch { /* storage off: ask every time */ }
  if (chosen) { gate.remove(); return; }

  // suggest the browser's language, but the person decides
  const suggest = /^ar\b/i.test(navigator.language || "") ? "ar" : "en";
  const options = [...gate.querySelectorAll(".lg-opt")];
  options.forEach((b) => b.classList.toggle("suggested", b.dataset.lang === suggest));
  gate.hidden = false;
  document.body.classList.add("lang-asking");
  requestAnimationFrame(() => gate.classList.add("in"));
  setTimeout(() => (options.find((b) => b.dataset.lang === suggest) || options[0]).focus(), 400);

  function choose(lang) {
    try { localStorage.setItem("cs-lang-chosen", "1"); } catch { /* storage off */ }
    if (window.CS.lang !== lang) window.CS.toggleLang();
    gate.classList.remove("in");
    gate.classList.add("out");
    document.body.classList.remove("lang-asking");
    setTimeout(() => { gate.remove(); window.dispatchEvent(new Event("cs:landing")); }, 700);
  }
  options.forEach((b) => b.addEventListener("click", () => choose(b.dataset.lang)));
  gate.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      const i = options.indexOf(document.activeElement);
      options[(i + 1) % options.length].focus();
      e.preventDefault();
    }
  });
})();
