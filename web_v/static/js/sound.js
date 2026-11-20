/* The music switch (js/cs-audio.js plays the music itself: one piece for the whole site).
 *
 * The landing's header buttons (.sound-btn) turn it on and off. A page without one (the scan page,
 * the support page) gets a small floating player: an on/off button and a volume slider. The choice
 * and the volume are shared by every page and subdomain. window.CSSound keeps its old interface
 * (set, setDuck, on): the film's narrator lowers the music while it speaks. */
(function () {
  "use strict";
  const A = window.CSAudio;
  if (!A) return;
  const OWN = {
    en: { soundOn: "Music on", soundOff: "Music off", vol: "Music volume", group: "Music" },
    ar: { soundOn: "الموسيقى تعمل", soundOff: "الموسيقى متوقفة", vol: "مستوى الموسيقى", group: "الموسيقى" },
  };
  const own = (k) => OWN[(document.documentElement.lang || "en").slice(0, 2) === "ar" ? "ar" : "en"][k];
  const T = (k) => {
    if (window.CS && typeof CS.t === "function") { const s = CS.t(k); if (s && s !== k) return s; }
    return own(k);
  };

  const buttons = [...document.querySelectorAll(".sound-btn")];
  let pill = null, vol = null;
  if (!buttons.length && !document.getElementById("fj-sound")) {
    pill = document.createElement("div");
    pill.className = "csm-pill";
    pill.setAttribute("role", "group");
    pill.innerHTML = '<button type="button" class="csm-toggle sound-btn" aria-pressed="false"><span class="eq" aria-hidden="true"><i></i><i></i><i></i><i></i></span><span class="sound-label"></span></button>' +
      '<input class="csm-vol" type="range" min="0" max="100" step="5">';
    document.body.append(pill);
    buttons.push(pill.querySelector("button"));
    vol = pill.querySelector("input");
    vol.addEventListener("input", () => A.setVolume(vol.value / 100));
  }

  function paint() {
    const on = A.music;
    buttons.forEach((b) => {
      b.setAttribute("aria-pressed", String(on));
      b.classList.toggle("on", on);
      const s = T(on ? "soundOn" : "soundOff");
      const l = b.querySelector(".sound-label");
      if (l) l.textContent = s;
      b.setAttribute("aria-label", s);
    });
    if (pill) {
      pill.classList.toggle("on", on);
      pill.classList.toggle("playing", A.musicPlaying());
      pill.setAttribute("aria-label", own("group"));
      vol.value = String(Math.round(A.volume * 100));
      vol.setAttribute("aria-label", own("vol"));
      vol.setAttribute("aria-valuetext", `${Math.round(A.volume * 100)}%`);
    }
  }
  buttons.forEach((b) => b.addEventListener("click", () => {
    const next = !A.music;
    if (!next) A.play("toggleOff");
    A.setMusic(next);
    if (next) setTimeout(() => A.play("toggleOn"), 30);
  }));
  A.onChange(paint, window);
  if (window.CS && CS.onLang) CS.onLang(paint);
  new MutationObserver(paint).observe(document.documentElement, { attributes: true, attributeFilter: ["lang"] });
  paint();

  window.CSSound = { set: (v) => A.setMusic(v), setDuck: (k) => A.setDuck(k), get on() { return A.music; } };
})();
