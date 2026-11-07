/* Accessibility helpers for the landing page:
 * - the "Reduce motion" switch in the footer (remembered; see a11y-early.js)
 * - a readable transcript of the film's narration, in the page language
 * - Play / Pause names on the film buttons that follow the player's state */
(function () {
  "use strict";
  const CS = window.CS;
  const t = (k) => (CS && CS.t ? CS.t(k) : k);
  const $ = (id) => document.getElementById(id);

  /* ---------------- reduce motion ---------------- */
  const btn = $("motion-btn");
  const reduced = document.documentElement.classList.contains("reduce-motion");
  function label() {
    if (!btn) return;
    btn.setAttribute("aria-pressed", String(reduced));
    btn.classList.toggle("on", reduced);
    btn.querySelector("span").textContent = t(reduced ? "motionOn" : "motionReduce");
  }
  if (btn) {
    btn.addEventListener("click", () => {
      try {
        if (reduced) localStorage.removeItem("cs-motion");
        else localStorage.setItem("cs-motion", "reduce");
      } catch { /* storage off: nothing to remember */ }
      // the animations are set up when the page loads, so reload where we are
      try { sessionStorage.setItem("cs-scroll", String(scrollY)); } catch { /* ignore */ }
      location.reload();
    });
  }
  try {
    const y = sessionStorage.getItem("cs-scroll");
    if (y) { sessionStorage.removeItem("cs-scroll"); requestAnimationFrame(() => window.scrollTo(0, Number(y))); }
  } catch { /* ignore */ }

  /* ---------------- film transcript ---------------- */
  const list = $("film-transcript");
  const cache = {};
  function stamp(sec) { return `${Math.floor(sec / 60)}:${String(Math.floor(sec % 60)).padStart(2, "0")}`; }
  function parse(vtt) {
    const out = [];
    vtt.replace(/\r/g, "").split(/\n\n+/).forEach((block) => {
      const lines = block.split("\n");
      const i = lines.findIndex((l) => l.includes("-->"));
      if (i < 0) return;
      const [h, m, s] = lines[i].split("-->")[0].trim().split(":");
      out.push([Number(h) * 3600 + Number(m) * 60 + parseFloat(s), lines.slice(i + 1).join(" ").trim()]);
    });
    return out;
  }
  async function transcript() {
    if (!list) return;
    const lang = CS && CS.lang === "ar" ? "ar" : "en";
    try {
      if (!cache[lang]) cache[lang] = parse(await fetch(`captions/${lang}.vtt`).then((r) => r.text()));
      list.replaceChildren(...cache[lang].map(([at, text]) => {
        const li = document.createElement("li");
        const time = document.createElement("time");
        time.textContent = stamp(at);
        li.append(time, " ", text);
        return li;
      }));
    } catch { /* captions unavailable */ }
  }

  /* ---------------- film button names ---------------- */
  const player = $("film-player");
  function playNames() {
    if (!player) return;
    const name = t(player.classList.contains("playing") ? "ariaPause" : "ariaPlay");
    ["film-play", "film-big"].forEach((id) => { const b = $(id); if (b) b.setAttribute("aria-label", name); });
  }
  if (player) new MutationObserver(playNames).observe(player, { attributes: true, attributeFilter: ["class"] });

  function onLang() { label(); transcript(); playNames(); }
  if (CS && CS.onLang) CS.onLang(onLang);
  onLang();
})();
