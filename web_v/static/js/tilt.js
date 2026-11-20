/* Subtle parallax: decorative layers (only elements marked data-depth: backgrounds, auroras,
 * patterns, seals; never text or buttons) shift up to 8px against the device's tilt, for a sense
 * of spatial depth.
 *
 * - Phones: DeviceOrientationEvent. iOS 13+ needs DeviceOrientationEvent.requestPermission(), which
 *   may only be called from a tap: a small "Enable depth effect" pill offers it; nothing is ever
 *   requested automatically. Android needs no permission, so it starts on its own.
 * - The neutral position is the way the visitor holds the phone: the first reading, slowly
 *   re-centred, so holding the phone at any angle is "straight". Landscape swaps the axes.
 * - Readings are low-pass filtered and the layers glide towards them (requestAnimationFrame,
 *   exponential smoothing); the loop stops as soon as everything has settled.
 * - Only the CSS `translate` property is written. It composes with each element's own transform
 *   and animations, and moves a composited layer without repainting the page.
 * - Fallbacks: desktop pointers drive the same small offsets; a phone without a working sensor
 *   simply stays still. prefers-reduced-motion (or the site's reduce-motion setting) disables it.
 * - The pill's choice is remembered (localStorage "cs-tilt": "on" | "off"). Nothing is recorded. */
(function () {
  "use strict";
  const html = document.documentElement;
  const MAX = 8;                        // px, at depth 1
  const KEY = "cs-tilt";
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion");
  const coarse = matchMedia("(pointer: coarse)").matches;
  const fine = matchMedia("(pointer: fine)").matches;
  const hasOrientation = "DeviceOrientationEvent" in window;
  const needsPermission = hasOrientation && typeof DeviceOrientationEvent.requestPermission === "function";
  const t = (k, fb) => (window.CS && CS.t && CS.t(k)) || fb;
  const store = (v) => { try { localStorage.setItem(KEY, v); } catch { /* storage off */ } };
  const stored = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
  const clamp = (x, a = -1, b = 1) => Math.max(a, Math.min(b, x));

  /* ---------------- targets: decorative layers that are on screen ---------------- */
  const layers = [...document.querySelectorAll("[data-depth]")].map((el) => ({ el, depth: Number(el.dataset.depth) || 1, on: false, last: "" }));
  if (!layers.length) return;
  const io = new IntersectionObserver((es) => es.forEach((e) => { const l = layers.find((x) => x.el === e.target); if (l) l.on = e.isIntersecting; }), { rootMargin: "10% 0px" });
  layers.forEach((l) => io.observe(l.el));

  /* ---------------- the smoothed position, and the frame loop ---------------- */
  let tx = 0, ty = 0, x = 0, y = 0, running = false, enabled = false;
  function frame() {
    x += (tx - x) * 0.085; y += (ty - y) * 0.085;           // exponential smoothing: no jitter, no jumps
    const settled = Math.abs(tx - x) < 0.002 && Math.abs(ty - y) < 0.002;
    if (settled) { x = tx; y = ty; }
    for (const l of layers) {
      if (!l.on) continue;
      const v = `${(-x * MAX * l.depth).toFixed(2)}px ${(-y * MAX * l.depth).toFixed(2)}px`;
      if (v !== l.last) { l.el.style.translate = v; l.last = v; }   // write only when it changed
    }
    running = !settled && !document.hidden;
    if (running) requestAnimationFrame(frame);
  }
  const kick = () => { if (!running && enabled && !document.hidden) { running = true; requestAnimationFrame(frame); } };
  function reset() { tx = ty = x = y = 0; layers.forEach((l) => { l.el.style.translate = ""; l.last = ""; }); }

  /* ---------------- phones: the orientation sensor ---------------- */
  let base = null, fx = 0, fy = 0, gotReading = false;
  function onOrientation(e) {
    if (e.beta == null || e.gamma == null || document.hidden) return;
    gotReading = true;
    const angle = (screen.orientation && screen.orientation.angle) || window.orientation || 0;
    let gx = e.gamma, gy = e.beta;                                  // portrait: gamma = left/right, beta = front/back
    if (angle === 90) { gx = e.beta; gy = -e.gamma; }
    else if (angle === -90 || angle === 270) { gx = -e.beta; gy = e.gamma; }
    if (!base) base = { x: gx, y: gy };
    base.x += (gx - base.x) * 0.004; base.y += (gy - base.y) * 0.004;   // slowly re-centre on how the phone is held
    fx += (clamp((gx - base.x) / 22) - fx) * 0.25;                  // low-pass filter on the raw sensor
    fy += (clamp((gy - base.y) / 22) - fy) * 0.25;
    tx = fx; ty = fy; kick();
  }
  function startSensor() {
    enabled = true; base = null;
    addEventListener("deviceorientation", onOrientation, { passive: true });
    // a phone that never reports (no gyroscope, or blocked) falls back to staying still
    setTimeout(() => { if (!gotReading) stopSensor(); }, 2500);
  }
  function stopSensor() { removeEventListener("deviceorientation", onOrientation); enabled = false; reset(); }

  /* ---------------- desktop fallback: the pointer ---------------- */
  function startPointer() {
    enabled = true;
    addEventListener("pointermove", (e) => {
      if (e.pointerType !== "mouse" || reduced()) return;
      tx = clamp((e.clientX / innerWidth) * 2 - 1); ty = clamp((e.clientY / innerHeight) * 2 - 1); kick();
    }, { passive: true });
    document.addEventListener("pointerleave", () => { tx = ty = 0; kick(); });
  }

  /* ---------------- iOS: ask only when the visitor taps the pill ---------------- */
  let pill = null;
  function offer() {
    if (pill || stored() === "off") return;
    pill = document.createElement("div");
    pill.className = "tilt-opt";
    pill.setAttribute("role", "group");
    const go = document.createElement("button");
    go.type = "button"; go.className = "tilt-go";
    go.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 3h8a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zM11 18h2M3 9c-1 2-1 4 0 6M21 9c1 2 1 4 0 6"/></svg>';
    const label = document.createElement("span"); go.append(label);
    const x = document.createElement("button");
    x.type = "button"; x.className = "tilt-x"; x.textContent = "×";
    const texts = () => { label.textContent = t("tiltOn", "Enable depth effect"); go.title = t("tiltHint", ""); x.setAttribute("aria-label", t("tiltClose", "Not now")); };
    texts(); if (window.CS && CS.onLang) CS.onLang(texts);
    go.addEventListener("click", async () => {
      let state = "denied";
      try { state = await DeviceOrientationEvent.requestPermission(); } catch { /* not allowed here */ }
      if (state === "granted") { store("on"); startSensor(); } else store("off");
      close();
    });
    x.addEventListener("click", () => { store("off"); close(); });
    pill.append(go, x);
    document.body.append(pill);
  }
  function close() { if (pill) { pill.remove(); pill = null; } }

  /* ---------------- start ---------------- */
  function init() {
    if (reduced()) return;
    if (coarse && hasOrientation) {
      if (!needsPermission) { startSensor(); return; }                 // Android and most others
      if (!window.isSecureContext) return;                           // iOS only allows it over HTTPS
      if (stored() === "on") {                                      // granted before: iOS may still allow it this session
        startSensor();
        setTimeout(() => { if (!gotReading) offer(); }, 2600);
      } else offer();
      return;
    }
    if (fine) startPointer();                                        // desktops: the mouse, same 8px limit
  }
  new MutationObserver(() => { if (reduced()) { enabled = false; reset(); close(); } }).observe(html, { attributes: true, attributeFilter: ["class"] });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) kick(); });
  init();
})();
