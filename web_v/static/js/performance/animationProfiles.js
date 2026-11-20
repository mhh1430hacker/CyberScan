/* Adaptive Performance Engine, part 4 of 6: what each level means, component by component.
 *
 * Levels change the amount of motion as well as the rendering budget. Every level keeps the
 * identity (colours, type, layout, the cinematic beats); lower levels draw less, not uglier.
 *   three      the Three.js journey: resolution cap, dust share, instanced objects share, speed
 *              streaks, light beams, and whether the camera flies or holds a view per stage
 *   particles  2D/WebGL particle fields (hero, Saudi dust): share of the full count
 *   canvas     other canvases (cells, story, cube): resolution cap
 *   blur       backdrop/blur effects: full, light, off
 *   lighting   glows and light layers: full, reduced, flat
 *   parallax   decorative depth layers: multiplier (0 = off)
 *   background ambient CSS animations: live, reduced, once (play once, then rest), static
 *   scenes     scroll-driven scenes (story, Saudi, team scrub): full, simple (no 3D turns), static
 *   video      the film: always full (it is content, and cheap); listed so it can be watched apart */
(function () {
  "use strict";
  const P = {
    1: { three: { dpr: 2, dust: 1, inst: 1, streaks: true, beams: 1, flight: true }, particles: 1, canvas: 2, blur: "full", lighting: "full", parallax: 1, background: "live", scenes: "full", video: "full" },
    2: { three: { dpr: 1.75, dust: 0.75, inst: 1, streaks: true, beams: 0.9, flight: true }, particles: 0.8, canvas: 1.75, blur: "full", lighting: "full", parallax: 1, background: "live", scenes: "full", video: "full" },
    3: { three: { dpr: 1.5, dust: 0.5, inst: 0.75, streaks: false, beams: 0.7, flight: true }, particles: 0.55, canvas: 1.5, blur: "light", lighting: "reduced", parallax: 0.6, background: "reduced", scenes: "full", video: "full" },
    4: { three: { dpr: 1.25, dust: 0.3, inst: 0.5, streaks: false, beams: 0.45, flight: true }, particles: 0.3, canvas: 1.25, blur: "off", lighting: "reduced", parallax: 0, background: "once", scenes: "simple", video: "full" },
    5: { three: { dpr: 1, dust: 0.18, inst: 0.4, streaks: false, beams: 0.3, flight: false }, particles: 0.12, canvas: 1, blur: "off", lighting: "flat", parallax: 0, background: "static", scenes: "static", video: "full" },
  };
  const NAMES = { 1: "Ultra", 2: "High", 3: "Balanced", 4: "Optimized", 5: "Essential" };
  // the components the controller can lower one by one, and which profile keys each one owns
  const COMPONENTS = { three: ["three"], particles: ["particles"], canvas: ["canvas"], css: ["blur", "lighting", "parallax", "background", "scenes"], video: ["video"] };
  window.CSPerfProfiles = { get: (level) => P[Math.max(1, Math.min(5, level))], NAMES, COMPONENTS };
})();
