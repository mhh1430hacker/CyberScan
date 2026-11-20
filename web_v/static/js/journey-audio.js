/* The File Journey's sound (journey.html): the site's one music (js/cs-audio.js) with the journey's
 * adaptive layer on top. js/journey.js drives it every frame through window.FJAudio:
 *   update(s, vel)  s = progress 0..1, vel = progress per second (signed): the stage colours the
 *                   piece (darker at the entry, brighter at the verdict), a D pedal follows the depth
 *                   and "wind" follows the scroll speed, so moving sounds like moving;
 *   event(name, o)  the journey's moments (breach, layer, ring, node, cage, check, monolith, whoosh,
 *                   chime, finale), tuned to the music's key;
 *   set(v), on      the speaker button: the site's shared music switch;
 *   setLabels(fn)   the button's accessible name in the page's language.
 * Nothing plays until the visitor turns the music on (here or on any other page of the site). */
(function () {
  "use strict";
  const A = window.CSAudio;
  const btn = document.getElementById("fj-sound");
  let label = (on) => (on ? "Sound on (click to mute)" : "Sound off (click to turn on)");
  function paint() {
    if (!btn) return;
    const on = !!(A && A.music);
    btn.setAttribute("aria-pressed", String(on)); btn.classList.toggle("off", !on);
    btn.setAttribute("aria-label", label(on)); btn.title = label(on);
  }
  function set(v) {
    if (!A) return;
    if (!v) A.play("toggleOff");
    A.setMusic(!!v);
    if (v) setTimeout(() => A.play("toggleOn"), 30);
  }
  if (btn) btn.addEventListener("click", () => set(!(A && A.music)));
  if (A) A.onChange(paint, window);
  paint();

  window.FJAudio = {
    update(s, vel) { if (A) A.journey.update(s, vel, window); },
    event(name, o) { if (A) A.journey.event(name, o || {}); },
    set,
    get on() { return !!(A && A.music); },
    setLabels(fn) { label = fn; paint(); },
  };
  if (!window.CSUiSound && A) window.CSUiSound = { get on() { return A.fx; }, set: (v) => A.setFx(v) };
})();
