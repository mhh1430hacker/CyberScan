/* Sound effects for the landing's scenes. The sounds themselves live in js/cs-audio.js (one set for
 * the whole site); this file keeps window.CSSfx.play(name, opts) and CSSfx.drone(level) for the
 * scripts that know their own timing (saudi, team, stats, toolbox, landing), and wires the scenes
 * that don't call it themselves. Effects follow the one effects switch (js/ui-sound.js).
 *
 *   - the scroll story (scrolly.js): a soft whoosh when a scene arrives, a note for each pipeline step;
 *   - arriving at the big sections: a soft downward whoosh, once each time they enter;
 *   - the guided journey: a rise.
 * Hover, press, dialogs, the language switch and the scan are in js/ui-sound.js. */
(function () {
  "use strict";
  const A = window.CSAudio;
  const play = (name, opts) => { if (A) A.play(name, opts || {}); };
  window.CSSfx = { play, drone: (level) => { if (A) A.drone(level); } };

  const watch = (sel, cls, fn) => {
    const mo = new MutationObserver((ms) => ms.forEach((m) => { const n = m.target; const had = (m.oldValue || "").split(/\s+/).includes(cls); if (!had && n.classList.contains(cls)) fn(n); }));
    document.querySelectorAll(sel).forEach((n) => mo.observe(n, { attributes: true, attributeFilter: ["class"], attributeOldValue: true }));
  };
  watch(".sy-scene", "on", () => play("whoosh", { dur: 0.9 }));
  watch(".sy-st", "on", (n) => play("step", { k: [...n.parentNode.children].indexOf(n) + 3 }));

  const SECTIONS = "#film, #manifesto, #how, #pipeline, #science, #features, #repair-sec, #privacy, .stats-sec, #team, .l-cta";
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) play("whoosh", { dur: 0.6, peak: 0.04, down: true, key: e.target.id || e.target.className }); }), { threshold: 0.25 });
  document.querySelectorAll(SECTIONS).forEach((s) => io.observe(s));

  const tourBtn = document.getElementById("tour-start");
  if (tourBtn) tourBtn.addEventListener("click", () => setTimeout(() => play("rise"), 60));
})();
