/* The opening sequence (#preloader). The look and most of the timing are CSS (intro.css), so it
 * starts at the first paint; this script adds what CSS cannot do:
 *   - the wordmark decodes: each letter cycles through glyphs, then locks, left to right;
 *   - the counter follows real loading (document parsed, fonts ready, window loaded), not a timer;
 *   - the exit (an iris opening from the logo) starts when the page has loaded and the sequence
 *     has had ~2.4s, or after 4.2s at the latest; any click, tap, key or wheel skips straight to it;
 *   - when the iris opens, the landing page gets the same signals as before (body.intro-done and
 *     the "cs:landing" event), so the hero's own entrance, the particles and the scroll scenes
 *     start exactly as they did.
 * intro-early.js has already decided whether to play (reduced motion, once per tab, app pages). */
(function () {
  "use strict";
  const html = document.documentElement;
  const boot = document.getElementById("preloader");
  const finishSignals = () => { document.body.classList.remove("intro"); document.body.classList.add("intro-done"); window.dispatchEvent(new Event("cs:landing")); };
  if (!boot || !html.classList.contains("booting") || !document.getElementById("landing")) {
    if (boot) boot.remove();
    html.classList.remove("booting");
    document.body.classList.add("intro-done");
    return;
  }
  document.body.classList.add("intro");
  const t0 = performance.now();
  const MIN = 2400, MAX = 4200;

  /* the wordmark decodes */
  const word = boot.querySelector(".boot-word");
  const letters = [...word.querySelectorAll("span")];
  const finals = letters.map((l) => l.textContent);
  const GLYPHS = "01<>/#%&$@ABCDEF0123456789";
  let decodeRaf = 0;
  function decode(now) {
    const t = now - t0;
    let pending = false;
    letters.forEach((l, i) => {
      const lockAt = 820 + i * 95;
      if (t < 420 + i * 40) { l.textContent = " "; pending = true; return; }
      if (t < lockAt) { l.textContent = GLYPHS[(Math.random() * GLYPHS.length) | 0]; l.classList.add("on"); pending = true; return; }
      if (!l.classList.contains("lock")) { l.textContent = finals[i]; l.classList.add("lock"); }
    });
    if (pending) decodeRaf = requestAnimationFrame(decode);
  }
  decodeRaf = requestAnimationFrame(decode);

  /* the counter: real loading milestones, eased */
  const num = boot.querySelector(".boot-pct"), bar = boot.querySelector(".boot-bar i");
  let target = 12, shown = 0, loaded = document.readyState === "complete";
  const raise = (v) => { target = Math.max(target, v); };
  if (document.readyState !== "loading") raise(40);
  document.addEventListener("DOMContentLoaded", () => raise(40));
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => raise(70));
  addEventListener("load", () => { loaded = true; raise(100); });
  if (loaded) raise(100);
  let opened = false;
  function count(now) {
    if (opened) return;
    const t = now - t0;
    const cap = loaded ? 100 : Math.min(96, target);                      // never claim 100 before the page has loaded
    shown += (Math.min(cap, target) - shown) * 0.08;
    const v = Math.min(100, Math.round(t > MAX - 300 ? Math.max(shown, 100 * (t / MAX)) : shown));
    num.textContent = String(v).padStart(3, "0");
    bar.style.transform = `scaleX(${v / 100})`;
    if ((loaded && t >= MIN && v >= 99) || t >= MAX) { open(); return; }
    requestAnimationFrame(count);
  }
  requestAnimationFrame(count);

  /* the exit: an iris opens from the logo, the mark flies through, the page arrives */
  function open() {
    if (opened) return;
    opened = true;
    cancelAnimationFrame(decodeRaf);
    letters.forEach((l, i) => { l.textContent = finals[i]; l.classList.add("on", "lock"); });
    num.textContent = "100"; bar.style.transform = "scaleX(1)";
    // first visit: the language screen is waiting under the overlay. A circle opening over it cut
    // its options in half for a second or two, so the overlay fades out whole instead
    boot.classList.add(document.body.classList.contains("lang-asking") ? "fade" : "open");
    html.classList.remove("booting");
    try { sessionStorage.setItem("cs-intro", "1"); } catch { /* storage off */ }
    setTimeout(finishSignals, 380);                                     // the hero starts while the iris widens
    setTimeout(() => boot.remove(), 1500);
    ["pointerdown", "keydown", "wheel", "touchstart"].forEach((ev) => removeEventListener(ev, skip, true));
  }
  const skip = (e) => { if (e.type === "keydown" && ["Shift", "Control", "Alt", "Meta", "Tab"].includes(e.key)) return; open(); };
  ["pointerdown", "keydown", "wheel", "touchstart"].forEach((ev) => addEventListener(ev, skip, { capture: true, passive: true }));
})();
