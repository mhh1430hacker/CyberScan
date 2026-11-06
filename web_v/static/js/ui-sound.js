/* Button sounds, synthesized: a faint tick when the pointer reaches
 * something clickable, a short two-step "bip" when it's pressed, and an
 * up/down blip for switches. Nothing plays on scroll, on section changes or
 * on its own. On by default; Settings › Display can turn it off. */
(function () {
  "use strict";
  const CLICKABLE = "button, a[href], [role=button], .row, label.drop, .chip, .pal-item, .pipe-node, .lg-opt, .bento-card";
  let on = true;
  try { on = localStorage.getItem("cs-ui-sound") !== "0"; } catch { /* storage off */ }
  let ctx = null, out = null, lastHover = 0;

  function ensure() {
    if (!ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      ctx = new AC();
      out = ctx.createGain(); out.gain.value = 0.9;
      const lp = ctx.createBiquadFilter(); lp.type = "lowpass"; lp.frequency.value = 5200;
      out.connect(lp).connect(ctx.destination);
    }
    if (ctx.state === "suspended") ctx.resume();
    return ctx;
  }

  function blip(freq, at, dur, type, level) {
    const o = ctx.createOscillator(); o.type = type; o.frequency.setValueAtTime(freq, at);
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, at);
    g.gain.exponentialRampToValueAtTime(level, at + 0.004);
    g.gain.exponentialRampToValueAtTime(0.0001, at + dur);
    o.connect(g).connect(out); o.start(at); o.stop(at + dur + 0.02);
  }

  function hover() {
    if (!on || !ctx || ctx.state !== "running") return; // only after the first click
    const now = performance.now();
    if (now - lastHover < 60) return;
    lastHover = now;
    blip(2600 + Math.random() * 300, ctx.currentTime, 0.022, "sine", 0.018);
  }
  function press() {
    if (!on || !ensure()) return;
    const t = ctx.currentTime;
    blip(880, t, 0.045, "square", 0.028);
    blip(1320, t + 0.045, 0.06, "square", 0.022);
  }
  function toggle(up) {
    if (!on || !ensure()) return;
    const t = ctx.currentTime;
    blip(up ? 660 : 990, t, 0.05, "triangle", 0.05);
    blip(up ? 990 : 660, t + 0.055, 0.07, "triangle", 0.045);
  }

  document.addEventListener("pointerover", (e) => {
    const el = e.target.closest && e.target.closest(CLICKABLE);
    if (el && !el.contains(e.relatedTarget)) hover();
  });
  document.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    const el = e.target.closest && e.target.closest(CLICKABLE);
    if (el && !el.closest(".switch")) press();
  });
  document.addEventListener("change", (e) => {
    if (e.target.matches && e.target.matches("input[type=checkbox]")) toggle(e.target.checked);
  });
  document.addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") && e.target.closest && e.target.closest("button, a[href]")) press();
  });

  // the Settings switch
  const sw = document.getElementById("ui-sound-toggle");
  if (sw) {
    sw.checked = on;
    sw.addEventListener("change", () => {
      on = sw.checked;
      try { localStorage.setItem("cs-ui-sound", on ? "1" : "0"); } catch { /* storage off */ }
      if (on) toggle(true);
    });
  }

  window.CSUiSound = { get on() { return on; }, press, hover };
})();
