/* The File Journey: a 3D dive into a file, driven entirely by the scroll.
 *
 * One source of truth for motion:
 *   the page's real scroll position  ->  P (0..1, the raw progress)
 *   P  ->  s, a critically damped follower of P (every animation reads s, nothing else).
 * Wheels are smoothed before they reach the page: each notch is normalised (lines/pages to px,
 * clamped) and eased into the real scroll, so a coarse mechanical wheel glides instead of jumping,
 * a reversal takes effect at once, and keyboard, scrollbar and touch keep their native behaviour.
 * Because everything is a pure function of s, scrolling up replays the journey backwards exactly.
 *
 * Rendering is on demand: a frame is drawn only while something changes (the scroll, the follower
 * settling, a short ambient tail after the last movement, a resize, a new quality level). When the
 * visitor stops, the loop stops: an idle page costs nothing. Hidden tabs and the text version stop
 * it too. Ambient motion (the handheld drift, pulses) runs on a clock that only advances while
 * frames are drawn, so a pause never makes anything jump.
 *
 * One world, one road. Everything hangs on a single winding spine (spine(), shared with the shaders):
 * a river of bytes flows along it, one floor runs under it, hexagonal gates frame it from the file
 * to the cage, and the file's core rides it ahead of the camera. Nothing cuts: the places overlap,
 * and the atmosphere (sky, fog, light ahead, dust, river, floor, and the page's own UI colour) is one
 * continuous grade along the story, dark and unknown -> mapped -> analysed -> weighed -> verified ->
 * a dawn over the verdict.
 *   0.00-0.16  THE ENTRY         a file floating in the dark; the camera breaks through, its core is born
 *   0.16-0.34  THE STRUCTURE     a city of bytes along the road: towers, translucent layers, signatures
 *   0.34-0.52  THE ANALYSIS      the gates close in to a scanning tunnel; features are pulled into the river
 *   0.52-0.70  THE INTELLIGENCE  the road opens into a layered network; activation travels layer by layer
 *   0.70-0.86  THE VERIFICATION  the core is caught in a quarantine cage; a gauge and a ring of checks
 *   0.86-1.00  THE VERDICT       the core rises over three possible outcomes; the camera pulls back
 * The world is built in chunks across frames (sky, entry and river first, so the first view appears
 * at once); each chunk's shaders compile asynchronously, so loading never blocks the page for long.
 *
 * Budgets: the site's Adaptive Performance Engine (js/performance/) sets a ceiling; on top of it a
 * local governor measures this page's own frame times while it draws and steps down (resolution,
 * dust, instanced objects, speed streaks, light beams, CSS blur) when frames run slow, and back up
 * when they are fast again. At Essential, and with reduced motion (a preference, not a performance
 * signal), the camera holds one still view per stage and views crossfade; nothing animates.
 * No WebGL: the text version.
 *
 * Words: js/journey-i18n.js (window.FJ_I18N), one dictionary for every language. */
import * as THREE from "../vendor/three/three.module.min.js";

const html = document.documentElement;
const DICT = window.FJ_I18N || { en: {} };
const langOf = () => (DICT[html.lang] ? html.lang : "en");
const T = (k) => { const d = DICT[langOf()] || {}; return d[k] != null ? d[k] : (DICT.en && DICT.en[k] != null ? DICT.en[k] : ""); };
const RTL = () => (DICT[langOf()] || {})._dir === "rtl";
const clamp = (x, a = 0, b = 1) => (x < a ? a : x > b ? b : x);
const lerp = (a, b, t) => a + (b - a) * t;
const ease = (t) => 1 - Math.pow(1 - t, 3);
const inOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const seg = (s, a, b, f = ease) => f(clamp((s - a) / (b - a)));
const rnd = (() => { let x = 1234567; return () => ((x = (x * 16807) % 2147483647) / 2147483647); })();   // deterministic
const pause = () => new Promise((r) => setTimeout(r, 0));                   // give the page a turn between chunks
const nn = (i) => String(i + 1).padStart(2, "0");

/* ===================================================================== text */
// the six stages (names: s1..s6, subtitles: s1sub..s6sub in the dictionary)
const STAGES = [{ a: 0.0, b: 0.16 }, { a: 0.16, b: 0.34 }, { a: 0.34, b: 0.52 }, { a: 0.52, b: 0.7 }, { a: 0.7, b: 0.86 }, { a: 0.86, b: 1.0 }];
// [from, to, size]; the words are l1..l17 in the dictionary, "[[...]]" marks the words that glow.
// Each line appears as the camera reaches what it talks about and leaves the way it came.
const LINES = [
  [0.008, 0.062, "big"], [0.066, 0.128, "mid"], [0.172, 0.222, "mid"], [0.226, 0.276, "mid"], [0.282, 0.334, "big"],
  [0.352, 0.392, "big"], [0.396, 0.436, "big"], [0.442, 0.512, "mid"], [0.53, 0.574, "big"], [0.578, 0.622, "big"],
  [0.628, 0.694, "mid"], [0.708, 0.744, "big"], [0.748, 0.79, "big"], [0.796, 0.856, "mid"], [0.806, 0.856, "small"],
  [0.905, 0.94, "mid"], [0.942, 0.972, "big"],
];
const FINAL_HELD = 0.97;                                                     // held views: from here on, the ending

/* ===================================================================== modes */
const rm = html.classList.contains("fj-still");                             // reduced motion: the visitor's preference
const touch = matchMedia("(pointer: coarse)").matches;
const A = window.CSAdapt || null;                                          // the Adaptive Performance Engine
const tb = () => (A ? A.budget("three").three : { dpr: 1.75, dust: 1, inst: 1, streaks: true, beams: 1, flight: true });
let still = rm || !tb().flight;                                            // held views: reduced motion, or Essential
html.classList.toggle("fj-still", still);
// the soundtrack's API (js/journey-audio.js), read when used: every call is optional
const AUD = () => window.FJAudio || null;
const sfx = (name, o) => { AUD()?.event?.(name, o); };

/* ===================================================================== DOM: text, rail, HUD */
const $ = (id) => document.getElementById(id);
const textBox = $("fj-text"), rail = $("fj-rail"), labelsBox = $("fj-labels"), finalBox = $("fj-final"), staticBox = $("fj-static");
let lineEls = [], labelEls = [], finalParts = [], lastStage = -1, labelsOn = false;
// the four layers of the city carry a label in the page's language (drawn into their texture)
const LAYER_DEF = [["layer1", "0x0000", -48], ["layer2", "0x0200", -84], ["layer3", "0x4A00", -120], ["layer4", "0x9E40", -152]];
let LAYERS = [];

function words(str) {
  // "[[...]]" segments glow; every word is its own unit so it can arrive on its own beat. Pieces
  // with no space between them (a word and its comma) stay one unit: punctuation never wraps alone.
  const out = [];
  let unit = null;
  str.split(/(\[\[.*?\]\])/).forEach((part) => {
    if (!part) return;
    const hot = part.startsWith("[[");
    const txt = hot ? part.slice(2, -2) : part;
    txt.split(/(\s+)/).forEach((w) => {
      if (!w) return;
      if (/^\s+$/.test(w)) { out.push(document.createTextNode(w)); unit = null; return; }
      const el = document.createElement(hot ? "em" : "span"); el.textContent = w;
      if (unit) { unit.append(el); return; }
      unit = document.createElement("span"); unit.className = "w"; unit.append(el); out.push(unit);
    });
  });
  return out;
}
function buildText() {
  html.dir = RTL() ? "rtl" : "ltr";
  document.title = T("docTitle");
  document.querySelectorAll("[data-t]").forEach((n) => { n.textContent = T(n.dataset.t); });
  document.querySelectorAll("[data-t-aria]").forEach((n) => { n.setAttribute("aria-label", T(n.dataset.tAria)); });
  const lb = $("fj-lang");
  lb.textContent = T("langSwitch"); lb.setAttribute("aria-label", T("langSwitchAria")); lb.lang = langOf() === "ar" ? "en" : "ar";
  $("fj-hint-t").textContent = T(touch ? "hintTouch" : "hint");
  AUD()?.setLabels?.((on) => T(on ? "sfxOn" : "sfxOff"));

  lineEls = LINES.map(([a, b, size], i) => {
    const p = document.createElement("p");
    p.className = `fj-l ${size}${LINES[i + 1] && LINES[i + 1][2] === "small" && LINES[i + 1][0] < b ? " lift" : ""}`;
    p.append(...words(T(`l${i + 1}`)));
    const lift = p.classList.contains("lift");
    p.style.setProperty("--y", `${size === "small" ? 110 : lift ? -44 : size === "mid" ? (i % 2 ? 30 : -30) : 0}px`);
    const ws = [...p.querySelectorAll(".w")];
    ws.forEach((w, k) => w.style.setProperty("--k", String(Math.min(k, 14))));
    return { el: p, a, b, on: null, past: null };
  });
  textBox.replaceChildren(...lineEls.map((l) => l.el));

  const ol = document.createElement("ol");
  STAGES.forEach((st, i) => {
    const li = document.createElement("li");
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("aria-label", `${T("stageOf").replace("{n}", i + 1)}: ${T(`s${i + 1}`)}${T("listSep")}${T(`s${i + 1}sub`)}`);
    const dot = document.createElement("span"); dot.className = "dot"; dot.textContent = nn(i); dot.setAttribute("aria-hidden", "true");
    const lbl = document.createElement("span"); lbl.className = "lbl"; lbl.setAttribute("aria-hidden", "true");
    const code = document.createElement("b"); code.textContent = T(`s${i + 1}`);
    const sub = document.createElement("small"); sub.textContent = T(`s${i + 1}sub`);
    lbl.append(code, sub); b.append(dot, lbl);
    b.addEventListener("click", () => goTo(i === 0 ? 0 : (still ? (st.a + st.b) / 2 : st.a + 0.012)));
    li.append(b); ol.append(li);
  });
  rail.replaceChildren(ol);
  lastStage = -1;

  const lab = (cls, word, cap, c) => { const d = document.createElement("div"); d.className = `fj-lab ${cls}`; d.style.setProperty("--c", c); const b = document.createElement("b"); b.textContent = word; const s = document.createElement("small"); s.textContent = cap; d.append(b, s); return d; };
  labelEls = [lab("c", T("clean"), T("cleanCap"), "#3dffa8"), lab("s", T("suspicious"), T("suspiciousCap"), "#ffc24d"), lab("m", T("malicious"), T("maliciousCap"), "#ff6b85")];
  labelsBox.replaceChildren(...labelEls);
  labelsOn = false;

  const h = document.createElement("h2"); h.className = "brand"; h.id = "fj-final-h"; h.textContent = "CYBERSCAN";
  const tag = document.createElement("p"); tag.className = "tag"; tag.textContent = T("tagline");
  const motto = document.createElement("p"); motto.className = "motto"; motto.textContent = T("motto");
  const ctas = document.createElement("div"); ctas.className = "ctas";
  const go = document.createElement("a"); go.className = "go"; go.href = "/#/scan"; go.textContent = T("start");
  const home = document.createElement("a"); home.href = "/"; home.textContent = T("home");
  ctas.append(go, home);
  const note = document.createElement("p"); note.className = "note"; note.textContent = T("note");
  finalBox.replaceChildren(h, tag, motto, ctas, note);
  finalParts = [h, tag, motto, ctas, note];
  finalParts.forEach((p, k) => p.style.setProperty("--k", String(k)));
  finalOn = null;
  buildStatic();
  relabelLayers();
}
function buildStatic() {
  // the text version, in the page's language (no WebGL, screen readers, "text version" mode)
  const h1 = document.createElement("h1"); h1.id = "fj-static-h"; h1.tabIndex = -1; h1.textContent = T("textTitle");
  const parts = [h1];
  STAGES.forEach((st, i) => {
    const h2 = document.createElement("h2"); h2.textContent = `${nn(i)} · ${T(`s${i + 1}`)}`;
    const h3 = document.createElement("h3"); h3.textContent = T(`s${i + 1}sub`);
    parts.push(h2, h3);
    LINES.forEach((l, k) => { if (l[0] >= st.a && l[0] < st.b) { const p = document.createElement("p"); p.textContent = T(`l${k + 1}`).replace(/\[\[|\]\]/g, ""); parts.push(p); } });
  });
  const end = document.createElement("p"); end.textContent = `CYBERSCAN · ${T("tagline")} ${T("motto")}`;
  const back = document.createElement("p"); const a = document.createElement("a"); a.href = "/"; a.textContent = T("home"); back.append(a);
  const note = document.createElement("p"); note.textContent = T("note");
  $("fj-static-body").replaceChildren(...parts, end, note, back);
  staticFocus(html.classList.contains("fj-textmode") || html.classList.contains("fj-nogl"));
}
$("fj-lang").addEventListener("click", () => {
  const next = langOf() === "ar" ? "en" : "ar";
  html.lang = next;
  try { localStorage.setItem("cyberscan-lang", next); } catch { /* storage off */ }
  buildText();
  sfx("chime");
  forceRender = true; wake();
});

/* ---------- the text version as a mode: the skip link opens it, visibly, for everyone ---------- */
// While it is only there for screen readers (visually hidden), its links and button stay out of the
// Tab order: a sighted keyboard user never lands on something invisible.
function staticFocus(on) { staticBox.querySelectorAll("a, button").forEach((e) => { if (on) e.removeAttribute("tabindex"); else e.setAttribute("tabindex", "-1"); }); }
function openText() {
  html.classList.add("fj-textmode"); staticFocus(true); stopLoop();
  staticBox.scrollTop = 0;
  const h = $("fj-static-h"); if (h) h.focus();
}
function closeText() {
  html.classList.remove("fj-textmode"); staticFocus(false);
  $("fj-skip").focus();
  forceRender = true; wake();
}
$("fj-skip").addEventListener("click", (e) => { if (html.classList.contains("fj-nogl")) return; e.preventDefault(); openText(); });
$("fj-static-close").addEventListener("click", closeText);
addEventListener("keydown", (e) => { if (e.key === "Escape" && html.classList.contains("fj-textmode")) closeText(); });

/* ===================================================================== scroll: one source, smoothed */
const maxScroll = () => Math.max(1, document.documentElement.scrollHeight - innerHeight);
let wheelTarget = scrollY, wheelCur = scrollY, wheeling = false;
addEventListener("wheel", (e) => {
  if (still || e.ctrlKey || html.classList.contains("fj-nogl") || html.classList.contains("fj-textmode")) return;   // zoom and the text version stay native
  e.preventDefault();
  let d = e.deltaY * (e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? innerHeight : 1);
  d = clamp(d, -280, 280);                                                  // one coarse notch never teleports
  if (wheeling && Math.sign(d) !== Math.sign(wheelTarget - wheelCur) && Math.abs(wheelTarget - wheelCur) > 2) wheelTarget = wheelCur;   // instant reversal
  if (!wheeling) wheelCur = wheelTarget = scrollY;
  wheelTarget = clamp(wheelTarget + d, 0, maxScroll());
  wheeling = true;
  wake();
}, { passive: false });
addEventListener("scroll", () => {
  // anything that is not our own wheel easing (keys, scrollbar, touch, find-in-page) takes over at once
  if (!wheeling || Math.abs(scrollY - Math.round(wheelCur)) > 3) { wheeling = false; wheelCur = wheelTarget = scrollY; }
  wake();
}, { passive: true });
function stepWheel(dt) {
  if (!wheeling) return;
  wheelCur += (wheelTarget - wheelCur) * (1 - Math.exp(-dt * 12));
  if (Math.abs(wheelTarget - wheelCur) < 0.6) { wheelCur = wheelTarget; wheeling = false; }
  scrollTo(0, wheelCur);
}
function goTo(p) {
  const y = clamp(p) * maxScroll();
  if (still) { scrollTo(0, y); wake(); return; }
  wheelCur = scrollY; wheelTarget = y; wheeling = true;
  sfx("whoosh");
  wake();
}
const rawP = () => clamp(scrollY / maxScroll());
let s = rawP(), sPrev = s, vel = 0;

/* ===================================================================== the loop's controls (defined early: the text and scroll handlers wake it) */
let raf = 0, last = performance.now(), activeUntil = 0, forceRender = true, ready = false;
let running = !document.hidden;
function wake(ms = 0) {
  const now = performance.now();
  if (ms) activeUntil = Math.max(activeUntil, now + ms);
  if (!raf && ready && running && !html.classList.contains("fj-textmode")) { last = now; raf = requestAnimationFrame(frame); }
}
function stopLoop() { if (raf) cancelAnimationFrame(raf); raf = 0; }

/* ===================================================================== WebGL */
// The words come first (they are the page for a moment); the context is asked for only after the
// first paint. On the first page of a session the site's capability probe (js/performance/) has
// just created and dropped a WebGL context; asking for ours while the GPU process tears that one
// down blocks the page for ~250 ms, so then we wait a moment first (journey-early.js notes it).
const canvas = $("fj-gl");
let finalOn = null;
buildText();
const afterPaint = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, window.__fjFreshProbe ? 280 : 0)));
await afterPaint();
let renderer;
try {
  renderer = new THREE.WebGLRenderer({ canvas, antialias: A ? A.componentLevel("three") <= 2 : true, powerPreference: "high-performance", alpha: false });
  renderer.debug.checkShaderErrors = false;                                 // no synchronous log reads after each link
} catch {
  html.classList.add("fj-nogl");
}
if (!renderer) { staticFocus(true); await new Promise(() => {}); }           // no WebGL: the text version stays; nothing else runs

/* ---------- quality: the site's ceiling, then this page's own governor ---------- */
// Each step draws less: resolution, dust, instanced objects, streaks, beams; from step 2 the CSS
// blur over the canvas goes too. The governor reads the time between frames it actually drew.
const QSTEPS = [
  { dpr: 2, dust: 1, inst: 1, streaks: true, beams: 1 },
  { dpr: 1.25, dust: 0.6, inst: 1, streaks: true, beams: 1 },
  { dpr: 1, dust: 0.35, inst: 0.7, streaks: false, beams: 0.7 },
  { dpr: 0.75, dust: 0.2, inst: 0.5, streaks: false, beams: 0.5 },
];
let q = 0;
try { q = clamp(Number(sessionStorage.getItem("fj-q")) || 0, 0, 3); } catch { /* storage off */ }
const PIXELS = 2.4e6;                                                       // a big screen does not need 4K of dust
const dprFor = () => Math.max(0.5, Math.min(devicePixelRatio || 1, tb().dpr, QSTEPS[q].dpr, Math.sqrt(PIXELS / Math.max(1, innerWidth * innerHeight))));
let dpr = dprFor();
renderer.setPixelRatio(dpr);
if (A) A.register("journey", canvas, "three");
renderer.setClearColor(0x020409, 1);
const scene = new THREE.Scene();
scene.fog = new THREE.FogExp2(0x020409, 0.012);
const camera = new THREE.PerspectiveCamera(62, 1, 0.3, 900);
const xf = $("fj-xfade"), xctx = xf ? xf.getContext("2d") : null;
function resize() {
  renderer.setSize(innerWidth, innerHeight, false);
  camera.aspect = innerWidth / innerHeight;
  camera.fov = innerWidth < innerHeight ? 78 : 62;                       // portrait screens see wider
  camera.updateProjectionMatrix();
  if (xf) { xf.width = Math.max(1, Math.round(innerWidth / 2)); xf.height = Math.max(1, Math.round(innerHeight / 2)); }
}
function setQ(n, why) {
  q = clamp(n, 0, 3);
  try { sessionStorage.setItem("fj-q", String(q)); } catch { /* storage off */ }
  html.classList.toggle("fj-q2", q >= 2);
  canvas.dataset.q = `${q} ${why || ""}`.trim();
  const d = dprFor(); if (d !== dpr) { dpr = d; renderer.setPixelRatio(dpr); resize(); }
  forceRender = true;
}
html.classList.toggle("fj-q2", q >= 2);
canvas.dataset.q = String(q);
addEventListener("resize", () => { const d = dprFor(); if (d !== dpr) { dpr = d; renderer.setPixelRatio(dpr); } resize(); forceRender = true; wake(); });
resize();
const gov = { d: [], lastChange: 0, lastUp: 0, lockUp: 0, good: 0 };
function govSample(ms) {
  gov.d.push(ms);
  if (gov.d.length < 36) return;
  const d = gov.d.sort((x, y) => x - y), p50 = d[18], p90 = d[32];
  gov.d = [];
  const now = performance.now();
  if ((p50 > 21 || p90 > 34) && q < 3 && now - gov.lastChange > 1200) {
    if (now - gov.lastUp < 30000) gov.lockUp = now + 120000;              // it bounced: stay down for a while
    gov.lastChange = now; gov.good = 0; setQ(q + 1, `slow ${Math.round(1000 / p50)} fps`);
  } else if (p50 < 12.5 && p90 < 18 && q > 0 && now - gov.lastChange > 10000 && now > gov.lockUp) {
    if (++gov.good >= 3) { gov.lastChange = gov.lastUp = now; gov.good = 0; setQ(q - 1, "fast"); }
  } else gov.good = 0;
}
// the combined budgets
const bud = { dust: 1, inst: 1, beams: 1, streaks: true };
function budgets() {
  const Q = QSTEPS[q], site = tb();
  const e = (k) => (A ? A.eased("three", k) : site[k]);
  const phone = touch && Math.min(innerWidth, innerHeight) < 600;          // a phone: fewer points, the same story
  bud.dust = e("dust") * Q.dust * (still ? 0.5 : 1) * (phone ? 0.6 : 1);   // held views are calmer
  bud.inst = Math.min(e("inst"), Q.inst);
  bud.beams = e("beams") * Q.beams * (still ? 0.6 : 1);
  bud.streaks = site.streaks && Q.streaks && !still;
}

const U = { uTime: { value: 0 }, uVel: { value: 0 } };
const fogU = THREE.UniformsLib.fog;
const add = (o) => (scene.add(o), o);
const glowMat = (color, opacity = 1) => new THREE.MeshBasicMaterial({ color, transparent: true, opacity, blending: THREE.AdditiveBlending, depthWrite: false, fog: true });
const lineMat = (color, opacity = 1) => new THREE.LineBasicMaterial({ color, transparent: true, opacity, blending: THREE.AdditiveBlending, depthWrite: false, fog: true });
const tmpM = new THREE.Matrix4(), tmpQ = new THREE.Quaternion(), tmpS = new THREE.Vector3(), tmpP = new THREE.Vector3(), tmpV = new THREE.Vector3(), tmpSp = new THREE.Vector3(), tmpSp2 = new THREE.Vector3();
const up = new THREE.Vector3(0, 1, 0), zAxis = new THREE.Vector3(0, 0, 1);
const flip = new THREE.Quaternion().setFromAxisAngle(new THREE.Vector3(1, 0, 0), Math.PI);
const built = { entry: false, city: false, tunnel: false, net: false, vault: false, verdict: false };
// colours given as they should look (raw sRGB numbers, for the hand-written shaders)
const raw = (hex) => new THREE.Color().setHex(hex, THREE.LinearSRGBColorSpace);

/* ---------------------------------------------------------- the spine: one curve the whole world hangs on */
// Flat at the file and at the verdict, it winds in between; JS and GLSL share the same formula, so
// the river of bytes, the gates, the towers, the network and the camera all follow one road.
const sst = (a, b, x) => { const t = clamp((x - a) / (b - a)); return t * t * (3 - 2 * t); };
const envZ = (z) => sst(-6, -60, z) * sst(-486, -430, z);
function spine(z, out = tmpSp) { const e = envZ(z); return out.set(e * (9 * Math.sin(z * 0.012 + 0.4) + 3.5 * Math.sin(z * 0.031)), e * 3.2 * Math.sin(z * 0.019 + 1.3), z); }
const SPINE_GLSL = `float sst(float a,float b,float x){ float t=clamp((x-a)/(b-a),0.,1.); return t*t*(3.-2.*t); }
  vec3 spine(float z){ float e=sst(-6.,-60.,z)*sst(-486.,-430.,z); return vec3(e*(9.*sin(z*.012+.4)+3.5*sin(z*.031)), e*3.2*sin(z*.019+1.3), z); }`;

/* ---------------------------------------------------------- the mood: one continuous grade along the story */
// [s, horizon/fog, zenith, the light ahead, accent (stream, floor, UI), fog density, light strength]
// dark and unknown -> blueprint blue -> cyan analysis -> violet intelligence -> magenta tension,
// amber scrutiny -> a lavender dawn once the verdict is in.
const MOOD = [
  [0.0, 0x0a0620, 0x020108, 0x7246e0, 0xc9a2ff, 0.018, 0.5],
  [0.12, 0x070a24, 0x02020a, 0x4a6dff, 0x9ec4ff, 0.016, 0.55],
  [0.25, 0x05142e, 0x01040c, 0x2f8cff, 0x5cc8ff, 0.0135, 0.7],
  [0.42, 0x041c28, 0x01060a, 0x22e8ff, 0x22e8ff, 0.0125, 0.85],
  [0.6, 0x140830, 0x04020e, 0xa35cff, 0xc9a2ff, 0.0125, 0.9],
  [0.74, 0x200826, 0x06020b, 0xff4fd8, 0xff7ae0, 0.0135, 1.0],
  [0.83, 0x1d0e1a, 0x07030a, 0xffb36b, 0xffc98a, 0.0125, 1.0],
  [0.92, 0x1d1638, 0x060512, 0xffd6f2, 0xd9b8ff, 0.008, 1.35],
  [1.0, 0x231b42, 0x070616, 0xfff0e4, 0xd9b8ff, 0.0045, 1.5],
].map(([s, h, z, g, a, d, k]) => ({ s, h: raw(h), z: raw(z), g: raw(g), a: raw(a), d, k }));
const M = { h: new THREE.Color(), z: new THREE.Color(), g: new THREE.Color(), a: new THREE.Color(), d: 0, k: 0 };
function moodAt(sv) {
  let i = 0; while (i < MOOD.length - 2 && sv > MOOD[i + 1].s) i++;
  const A_ = MOOD[i], B_ = MOOD[i + 1], t = sst(A_.s, B_.s, sv);
  M.h.copy(A_.h).lerp(B_.h, t); M.z.copy(A_.z).lerp(B_.z, t); M.g.copy(A_.g).lerp(B_.g, t); M.a.copy(A_.a).lerp(B_.a, t);
  M.d = lerp(A_.d, B_.d, t); M.k = lerp(A_.k, B_.k, t);
  return M;
}
// the colour of a place (gates): what the story is at that depth
const ZT = [[30, 0x7246e0], [-20, 0x6f8cff], [-150, 0x2f8cff], [-185, 0x22e8ff], [-292, 0x22e8ff], [-318, 0xc9a2ff], [-412, 0xff4fd8], [-470, 0xffb36b], [-560, 0xffd6f2]].map(([z, c]) => [z, raw(c)]);
function zTone(z, out) {
  let i = 0; while (i < ZT.length - 2 && z < ZT[i + 1][0]) i++;
  return out.copy(ZT[i][1]).lerp(ZT[i + 1][1], sst(ZT[i][0], ZT[i + 1][0], z));
}

// a soft round sprite for every glow point
const dotTex = (() => {
  const c = document.createElement("canvas"); c.width = c.height = 64;
  const x = c.getContext("2d"), g = x.createRadialGradient(32, 32, 0, 32, 32, 32);
  g.addColorStop(0, "rgba(255,255,255,1)"); g.addColorStop(0.25, "rgba(255,255,255,.55)"); g.addColorStop(1, "rgba(255,255,255,0)");
  x.fillStyle = g; x.fillRect(0, 0, 64, 64);
  return new THREE.CanvasTexture(c);
})();
// a volumetric beam: an open cone, bright at its source, fading along its length and at its edges
function beam(radius, height, color, strength = 0.35) {
  const geo = new THREE.CylinderGeometry(radius * 0.08, radius, height, 48, 1, true);
  geo.translate(0, -height / 2, 0);
  const mat = new THREE.ShaderMaterial({
    uniforms: { uColor: { value: new THREE.Color(color) }, uStrength: { value: strength }, uH: { value: height } },
    vertexShader: `varying float vY; varying vec3 vN; varying vec3 vV;
      void main(){ vY = -position.y; vec4 mv = modelViewMatrix * vec4(position,1.); vN = normalize(normalMatrix*normal); vV = normalize(-mv.xyz); gl_Position = projectionMatrix*mv; }`,
    fragmentShader: `uniform vec3 uColor; uniform float uStrength; uniform float uH; varying float vY; varying vec3 vN; varying vec3 vV;
      void main(){ float along = 1. - clamp(vY/uH,0.,1.); float edge = pow(abs(dot(vN,vV)), 1.6); gl_FragColor = vec4(uColor, along*along*edge*uStrength); }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide,
  });
  return new THREE.Mesh(geo, mat);
}
function textTex(str, { size = 64, color = "#9fe8ff", w = 512, h = 128 } = {}) {
  const c = document.createElement("canvas"); c.width = w; c.height = h;
  const x = c.getContext("2d"); x.font = `600 ${size}px Consolas, monospace`; x.fillStyle = color; x.textAlign = "center"; x.textBaseline = "middle";
  x.shadowColor = color; x.shadowBlur = 18; x.fillText(str, w / 2, h / 2);
  return new THREE.CanvasTexture(c);
}

/* ---------------------------------------------------------- the sky: a gradient dome with the light ahead */
// It travels with the camera. The light at the end of the road (the verdict) grows as the file
// becomes known; a faint nebula drifts in the horizon band. The fog takes the horizon's colour, so
// the whole world dissolves into one atmosphere instead of into black.
const skyU = { uZen: { value: new THREE.Color() }, uHor: { value: new THREE.Color() }, uGlow: { value: new THREE.Color() }, uGs: { value: 0.5 }, uTime: U.uTime };
let sky;
function buildSky() {
  sky = new THREE.Mesh(new THREE.SphereGeometry(520, 32, 18), new THREE.ShaderMaterial({
    uniforms: skyU,
    vertexShader: `varying vec3 vD; void main(){ vD = position; gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.); }`,
    fragmentShader: `uniform vec3 uZen; uniform vec3 uHor; uniform vec3 uGlow; uniform float uGs; uniform float uTime; varying vec3 vD;
      float h21(vec2 p){ return fract(sin(dot(p, vec2(127.1,311.7)))*43758.5453); }
      float vn(vec2 p){ vec2 i=floor(p), f=fract(p); f=f*f*(3.-2.*f);
        return mix(mix(h21(i),h21(i+vec2(1.,0.)),f.x), mix(h21(i+vec2(0.,1.)),h21(i+vec2(1.,1.)),f.x), f.y); }
      void main(){
        vec3 d = normalize(vD); float h = d.y;
        vec3 c = mix(uHor, uZen, smoothstep(-.02, .6, abs(h)));
        vec2 q = vec2(atan(d.x, -d.z)*2.6, h*6.);
        float n = vn(q*1.6 + vec2(uTime*.012, 0.));
        float fwd = max(dot(d, normalize(vec3(0., .05, -1.))), 0.);
        c += uGlow * (pow(fwd, 6.)*.22 + pow(fwd, 40.)*.65) * uGs;           // the light at the end of the road
        c += uGlow * smoothstep(.5, 1., n) * .16 * (1. - smoothstep(0., .5, abs(h))) * uGs;   // nebula in the horizon band
        c += uGlow * exp(-abs(h)*18.) * .08 * uGs;                           // the horizon line
        gl_FragColor = vec4(c, 1.);
      }`,
    side: THREE.BackSide, depthWrite: false, depthTest: false, fog: false,
  }));
  sky.renderOrder = -10; sky.frustumCulled = false;
  add(sky);
}

/* ---------------------------------------------------------- 1. THE ENTRY: the file */
const FW = 14, FH = 18;
let file, front, back, fileEdges, halo, halo2, glowDisc, spot;
function buildEntry() {
  file = add(new THREE.Group());
  const fileTex = (() => {
    const c = document.createElement("canvas"); c.width = 560; c.height = 720;
    const x = c.getContext("2d");
    const g = x.createLinearGradient(0, 0, 0, 720); g.addColorStop(0, "#1a1240"); g.addColorStop(1, "#0a0820");
    x.fillStyle = g; x.fillRect(0, 0, 560, 720);
    x.fillStyle = "#2a1d5c"; x.beginPath(); x.moveTo(440, 0); x.lineTo(560, 120); x.lineTo(440, 120); x.closePath(); x.fill();   // folded corner
    x.strokeStyle = "rgba(201,162,255,.6)"; x.lineWidth = 3; x.beginPath(); x.moveTo(440, 0); x.lineTo(440, 120); x.lineTo(560, 120); x.stroke();
    x.fillStyle = "#c9a2ff"; x.font = "800 46px Segoe UI, sans-serif"; x.fillText("PDF", 44, 92);
    x.fillStyle = "#ece4ff"; x.font = "600 26px Segoe UI, sans-serif"; x.fillText("quarterly-report.pdf", 44, 150);
    x.fillStyle = "#8f84b8"; x.font = "500 20px Segoe UI, sans-serif"; x.fillText("2.4 MB", 44, 182);
    for (let i = 0; i < 11; i++) { x.fillStyle = `rgba(190,170,240,${0.14 + (i % 3) * 0.04})`; x.fillRect(44, 230 + i * 30, 300 + ((i * 97) % 170), 10); }
    x.fillStyle = "rgba(34,232,255,.75)"; x.font = "500 19px Consolas, monospace";
    ["25 50 44 46 2D 31 2E 37  %PDF-1.7", "0A 25 E2 E3 CF D3 0A 31  .%......1", "20 30 20 6F 62 6A 0A 3C   0 obj.<"].forEach((l, i) => x.fillText(l, 44, 600 + i * 30));
    return new THREE.CanvasTexture(c);
  })();
  fileTex.colorSpace = THREE.SRGBColorSpace;
  // the two faces have a hole that opens as the camera arrives, with a glowing rim
  const faceMat = (map) => new THREE.ShaderMaterial({
    uniforms: { map: { value: map }, uHole: { value: 0 }, uHas: { value: map ? 1 : 0 }, uTime: U.uTime, uGlow: { value: 0 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix*modelViewMatrix*vec4(position,1.); }`,
    fragmentShader: `uniform sampler2D map; uniform float uHole; uniform float uHas; uniform float uTime; uniform float uGlow; varying vec2 vUv;
      void main(){
        vec2 p = (vUv-.5)*vec2(${FW.toFixed(1)}, ${FH.toFixed(1)});
        float d = length(p);
        if (uHole > 0.001 && d < uHole) discard;
        vec3 c = uHas > .5 ? texture2D(map, vUv).rgb : vec3(.04,.03,.1);
        float scan = smoothstep(.0,.02, abs(fract(vUv.y*1.5 - uTime*.12) - .5) - .47);
        c += vec3(.5,.4,1.) * (1.-scan) * .22 * uGlow;
        float rim = uHole > .001 ? smoothstep(uHole+1.2, uHole, d) : 0.;
        c += mix(vec3(.79,.64,1.), vec3(.13,.91,1.), rim) * rim * 1.7;
        gl_FragColor = vec4(c, .96);
      }`,
    transparent: true, side: THREE.DoubleSide,
  });
  front = new THREE.Mesh(new THREE.PlaneGeometry(FW, FH), faceMat(fileTex)); front.position.z = 0.35; file.add(front);
  back = new THREE.Mesh(new THREE.PlaneGeometry(FW, FH), faceMat(null)); back.position.z = -0.35; file.add(back);
  fileEdges = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(FW, FH, 0.7)), lineMat(0xc9a2ff, 0.9)); file.add(fileEdges);
  halo = new THREE.Mesh(new THREE.RingGeometry(13, 13.15, 128), glowMat(0x22e8ff, 0.45)); halo.position.z = -1; file.add(halo);
  halo2 = new THREE.Mesh(new THREE.RingGeometry(16, 16.06, 128), glowMat(0xc9a2ff, 0.4)); halo2.position.z = -2; file.add(halo2);
  glowDisc = new THREE.Mesh(new THREE.CircleGeometry(30, 64), new THREE.ShaderMaterial({
    uniforms: { uO: { value: 1 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.); }`,
    fragmentShader: `uniform float uO; varying vec2 vUv; void main(){ float d = length(vUv-.5)*2.; gl_FragColor = vec4(vec3(.32,.18,.7)*pow(1.-clamp(d,0.,1.),2.2)*uO, 1.); }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
  }));
  glowDisc.position.z = -8; file.add(glowDisc);
  spot = beam(13, 40, 0xb79bff, 0.26); spot.position.set(0, 34, 2); add(spot);
  built.entry = true;
}

/* ---------------------------------------------------------- the file's core: the one thing that makes the whole trip */
// Born when the camera breaks through the file, it rides the river ahead of the camera, is caught
// in the quarantine cage, turns from amber to mint as the checks pass, and rises over the verdict.
let packet, pCore, pHeart, pWire;
const pCol = new THREE.Color(), cAmber = raw(0xffb36b), cMint = raw(0x8dffd0), cDawn = raw(0xfff1e6);
function buildPacket() {
  packet = add(new THREE.Group());
  const sm = (o) => new THREE.SpriteMaterial({ map: dotTex, transparent: true, opacity: o, depthWrite: false, blending: THREE.AdditiveBlending, fog: false });
  pCore = new THREE.Sprite(sm(0.9)); pCore.scale.setScalar(7); packet.add(pCore);
  pHeart = new THREE.Sprite(sm(1)); pHeart.scale.setScalar(1.7); pHeart.material.color.set(0xffffff); packet.add(pHeart);
  pWire = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.OctahedronGeometry(1.15, 0)), lineMat(0xffffff, 0.9)); packet.add(pWire);
  packet.visible = false;
}
const VZ = -496, VDZ = -582;
const packetPos = new THREE.Vector3();
function placePacket(sv, camZ, t) {
  const born = seg(sv, 0.122, 0.175, inOut);
  packet.visible = born > 0.001;
  if (!packet.visible) return;
  spine(camZ - 13, packetPos); packetPos.y -= 2.6 - Math.sin(t * 1.3) * 0.25;
  packetPos.lerpVectors(tmpV.set(0, 0, -0.5), packetPos, born);
  packetPos.lerp(tmpV.set(0, 0, VZ), seg(sv, 0.69, 0.75, inOut));                 // into the cage
  const r = seg(sv, 0.862, 0.915, inOut);                                       // and up over the three outcomes
  packetPos.lerp(tmpV.set(0, 37, VDZ - 3), r); packetPos.y += Math.sin(r * Math.PI) * 6;
  packet.position.copy(packetPos);
  // its colour: the mood until the cage, amber under scrutiny, mint once verified, then the dawn
  pCol.copy(M.a).lerp(cAmber, seg(sv, 0.72, 0.77)).lerp(cMint, seg(sv, 0.8, 0.85)).lerp(cDawn, r);
  pCore.material.color.copy(pCol); pWire.material.color.copy(pCol);
  const sc = born * (1 + r * 0.6) * (1 + Math.sin(t * 2.1) * 0.04);
  packet.scale.setScalar(Math.max(0.001, sc));
  pWire.rotation.set(t * 0.7 + sv * 8, t * 0.9 + sv * 5, 0);
}

/* ---------------------------------------------------------- everywhere: dust, the river of bytes, streaks */
const dustN = 4200;
const dustU = { uA: { value: new THREE.Color() }, uB: { value: new THREE.Color() } };
let dustGeo, dustMat, nodeMat = null, streaks = null;
function buildDust() {
  dustGeo = new THREE.BufferGeometry();
  const p = new Float32Array(dustN * 3), sd = new Float32Array(dustN);
  for (let i = 0; i < dustN; i++) { p[i * 3] = (rnd() - 0.5) * 90; p[i * 3 + 1] = (rnd() - 0.5) * 56; p[i * 3 + 2] = lerp(50, -640, rnd()); sd[i] = rnd(); }
  dustGeo.setAttribute("position", new THREE.BufferAttribute(p, 3));
  dustGeo.setAttribute("aSeed", new THREE.BufferAttribute(sd, 1));
  dustMat = new THREE.ShaderMaterial({
    uniforms: { map: { value: dotTex }, uTime: U.uTime, uScale: { value: 1 }, ...dustU, ...THREE.UniformsUtils.clone(fogU) },
    vertexShader: `attribute float aSeed; uniform float uTime; uniform float uScale; uniform vec3 uA; uniform vec3 uB; varying vec3 vC; varying float vA;
      #include <fog_pars_vertex>
      void main(){
        vec3 p = position; p.y += sin(uTime*.3 + aSeed*30.)*.6; p.x += cos(uTime*.25 + aSeed*20.)*.6;
        vec4 mvPosition = modelViewMatrix*vec4(p,1.);
        vC = mix(uA, uB, fract(aSeed*7.13));                                  // the dust takes the mood of the moment
        float d = -mvPosition.z;
        float near = smoothstep(7., 1., d);                                   // very close: a large, faint bokeh disc
        gl_PointSize = (1.2 + aSeed*2.2) * uScale * (260. / d) * (1. + near*5.);
        vA = (.3 + .7*aSeed) * (1. - near*.85) * smoothstep(.4, 2., d);
        gl_Position = projectionMatrix*mvPosition;
        #include <fog_vertex>
      }`,
    fragmentShader: `uniform sampler2D map; varying vec3 vC; varying float vA;
      #include <fog_pars_fragment>
      void main(){ float a = texture2D(map, gl_PointCoord).a*vA; gl_FragColor = vec4(vC*a, a);
        #include <fog_fragment>
      }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true,
  });
  const dust = new THREE.Points(dustGeo, dustMat); dust.frustumCulled = false; add(dust);
  // streaks: short lines around the camera that stretch with speed (a motion blur cue)
  const streakN = 260;
  const sp = new Float32Array(streakN * 6), e = new Float32Array(streakN * 2);
  for (let i = 0; i < streakN; i++) {
    const a = rnd() * 6.283, r = 4 + rnd() * 14, z = -rnd() * 60;
    for (let k = 0; k < 2; k++) { sp[i * 6 + k * 3] = Math.cos(a) * r; sp[i * 6 + k * 3 + 1] = Math.sin(a) * r; sp[i * 6 + k * 3 + 2] = z; e[i * 2 + k] = k; }
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute("position", new THREE.BufferAttribute(sp, 3)); g.setAttribute("aEnd", new THREE.BufferAttribute(e, 1));
  const m = new THREE.ShaderMaterial({
    uniforms: { uVel: U.uVel, uOff: { value: 0 }, uC: dustU.uB },
    vertexShader: `attribute float aEnd; uniform float uVel; uniform float uOff; varying float vE;
      void main(){ vec3 p = position; p.z = mod(p.z + uOff, 60.) - 60.; p.z += aEnd * uVel * 9.; vE = aEnd;
        gl_Position = projectionMatrix*modelViewMatrix*vec4(p,1.); }`,
    fragmentShader: `uniform float uVel; uniform vec3 uC; varying float vE; void main(){ float a = min(1., abs(uVel)*.8) * (1.-vE) * .5; gl_FragColor = vec4(mix(uC, vec3(1.), .4)*a, a); }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
  });
  streaks = new THREE.LineSegments(g, m); streaks.frustumCulled = false;
  camera.add(streaks); scene.add(camera);
}
// the river: thousands of bytes flowing along the spine, a road of light just under the eye line.
// World-anchored (they wrap around a window that travels with the camera), so the camera really
// moves through them; the river widens while the file is analysed and narrows into the cage.
const streamN = 3600;
const streamU = { uCamZ: { value: 0 }, uFlow: { value: 0 }, uW: { value: 2 }, uScale: { value: 1 }, uA: { value: new THREE.Color() }, uB: { value: new THREE.Color() }, uO: { value: 0 } };
let streamGeo;
function buildStream() {
  streamGeo = new THREE.BufferGeometry();
  const u = new Float32Array(streamN), r = new Float32Array(streamN), sd = new Float32Array(streamN);
  for (let i = 0; i < streamN; i++) { u[i] = rnd(); const g = (rnd() + rnd() + rnd()) / 3 - 0.5; r[i] = g * 2; sd[i] = rnd(); }
  streamGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(streamN * 3), 3));   // unused: the shader places them
  streamGeo.setAttribute("aU", new THREE.BufferAttribute(u, 1));
  streamGeo.setAttribute("aR", new THREE.BufferAttribute(r, 1));
  streamGeo.setAttribute("aSeed", new THREE.BufferAttribute(sd, 1));
  const mat = new THREE.ShaderMaterial({
    uniforms: { map: { value: dotTex }, uTime: U.uTime, ...streamU, ...THREE.UniformsUtils.clone(fogU) },
    vertexShader: `attribute float aU; attribute float aR; attribute float aSeed;
      uniform float uTime; uniform float uCamZ; uniform float uFlow; uniform float uW; uniform float uScale; uniform vec3 uA; uniform vec3 uB; uniform float uO;
      varying vec3 vC; varying float vA;
      ${SPINE_GLSL}
      #include <fog_pars_vertex>
      void main(){
        float L = 190.;
        float k = aU*L + uFlow*(.75 + aSeed*.5);
        float z = uCamZ + 30. - mod(uCamZ + 30. + k, L);
        vec3 p = spine(z);
        float w = uW * (1. + .35*sin(z*.05 + aSeed*6.));
        p.x += aR * w + sin(z*.21 + aSeed*40.)*.18;
        p.y += -3.4 + sin(aSeed*50. + z*.13 + uTime*.8)*.22*(.4 + abs(aR)) + aR*aR*.6;
        vec4 mvPosition = modelViewMatrix*vec4(p,1.);
        float d = -mvPosition.z;
        float hot = step(.94, aSeed);
        vC = mix(mix(uA, uB, smoothstep(.2,.9,abs(aR))), vec3(1.), hot*.7);
        gl_PointSize = min(16., (1. + aSeed*1.4 + hot*1.8) * uScale * (190. / d));
        vA = uO * (.4 + .8*aSeed) * smoothstep(3., 10., d) * smoothstep(uCamZ, uCamZ - 10., z);
        gl_Position = projectionMatrix*mvPosition;
        #include <fog_vertex>
      }`,
    fragmentShader: `uniform sampler2D map; varying vec3 vC; varying float vA;
      #include <fog_pars_fragment>
      void main(){ float a = texture2D(map, gl_PointCoord).a*vA; gl_FragColor = vec4(vC*a*1.1, a);
        #include <fog_fragment>
      }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true,
  });
  const pts = new THREE.Points(streamGeo, mat); pts.frustumCulled = false; add(pts);
}

/* ---------------------------------------------------------- the ground: one floor from the file to the verdict */
// A single long grid under the whole road. It is nearly invisible in the unknown, draws itself
// as the structure is mapped, dims in the tunnel, and rises to become the verdict's plaza.
const floorU = { uC: { value: new THREE.Color() }, uK: { value: 0 }, uCamZ: { value: 0 }, uTime: U.uTime };
let ground;
function buildFloor() {
  const g = new THREE.PlaneGeometry(240, 740, 1, 180); g.rotateX(-Math.PI / 2); g.translate(0, 0, -300);
  ground = new THREE.Mesh(g, new THREE.ShaderMaterial({
    uniforms: { ...floorU, ...THREE.UniformsUtils.clone(fogU) },
    vertexShader: `uniform float uCamZ; varying vec3 vW;
      ${SPINE_GLSL}
      #include <fog_pars_vertex>
      void main(){ vec3 p = position; p.y = mix(-16., -0.05, sst(-490., -570., p.z)); p.x += spine(p.z).x*.6; vW = p;
        vec4 mvPosition = modelViewMatrix*vec4(p,1.); gl_Position = projectionMatrix*mvPosition;
        #include <fog_vertex>
      }`,
    fragmentShader: `uniform vec3 uC; uniform float uK; uniform float uCamZ; uniform float uTime; varying vec3 vW;
      ${SPINE_GLSL}
      #include <fog_pars_fragment>
      float gridL(vec2 p, float s){ vec2 q = p/s; vec2 g = abs(fract(q - .5) - .5)/fwidth(q); return 1. - min(min(g.x, g.y), 1.); }
      void main(){
        float z = vW.z;
        vec2 p = vec2(vW.x - spine(z).x*.6, z);
        float zone = sst(14., -30., z)*.9 - sst(-170., -200., z)*.55 + sst(-300., -330., z)*.25 + sst(-500., -560., z)*.9;
        float l = gridL(p, 4.)*.45 + gridL(p, 20.)*.8;
        float wave = exp(-pow((z - (uCamZ - 26. - mod(uTime*14., 70.)))*.25, 2.));           // a scan wave running ahead
        float side = 1. - smoothstep(30., 110., abs(p.x));
        float plaza = smoothstep(46., 0., length(vec2(vW.x, z + 582.)));
        vec3 c = uC * (l * (zone + plaza*.4) * (1. + wave*1.6) * side * uK * .42);
        c += uC * plaza * plaza * .06 * uK;
        gl_FragColor = vec4(c, 1.);
        #include <fog_fragment>
      }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true,
  }));
  ground.frustumCulled = false; add(ground);
}

/* ---------------------------------------------------------- the gates: hexagonal frames along the whole road */
// One instanced set from the file to the cage: sparse and faint in the structure, close together in
// the analysis (the tunnel), wide in the network, then a funnel narrowing onto the cage. Each takes
// the colour of its place, and lights up as the camera passes through it.
const GATES = [];
let gates;
function buildGates() {
  for (let z = -22; z > -478;) {
    const tun = z <= -176 && z >= -292;
    const R = z > -150 ? 15.5 : z > -176 ? lerp(15.5, 14.6, sst(-150, -176, z)) : tun ? 14.6 : z > -420 ? lerp(14.6, 20, sst(-292, -312, z)) : lerp(20, 10.8, sst(-420, -478, z));
    const base = tun ? 0.4 : z > -176 ? 0.2 : z > -420 ? 0.22 : 0.4;
    GATES.push({ z, R, base, tun, c: zTone(z, new THREE.Color()), tw: z * 0.035, ey: tun ? 1 : z > -420 ? 0.8 : lerp(0.8, 1, sst(-420, -470, z)) });
    z -= tun ? 4.3 : z > -420 ? 13 : 7;
  }
  gates = new THREE.InstancedMesh(new THREE.RingGeometry(0.986, 1, 6, 1), new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide, fog: true }), GATES.length);
  GATES.forEach((g, i) => {
    spine(g.z, tmpP); spine(g.z - 1, tmpSp2).sub(spine(g.z + 1, tmpV)).normalize();
    tmpQ.setFromUnitVectors(zAxis, tmpSp2.negate());
    tmpQ.multiply(new THREE.Quaternion().setFromAxisAngle(zAxis, g.tw));
    tmpS.set(g.R, g.R * g.ey, 1);
    tmpM.compose(tmpP, tmpQ, tmpS); gates.setMatrixAt(i, tmpM);
    gates.setColorAt(i, g.c);
  });
  add(gates);
  RING_Z = GATES.filter((g) => g.tun).map((g) => g.z);
}
const gCol = new THREE.Color();
let gatesZ = null;
function updateGates(camZ, sv) {
  if (gatesZ !== null && Math.abs(camZ - gatesZ) < 0.01) return;
  gatesZ = camZ;
  const pulse = seg(sv, 0.34, 0.38) * (1 - seg(sv, 0.5, 0.54));
  GATES.forEach((g, i) => {
    const d = g.z - (camZ - 8);
    const near = Math.exp(-(d * d) / 90);                                   // the gate the camera passes through flares
    const behind = clamp((g.z - camZ) / 6);                                  // and fades once behind
    const k = g.base * (1 + near * 1.8 + (g.tun ? pulse * 0.5 : 0)) * (1 - behind * 0.8);
    gates.setColorAt(i, gCol.copy(g.c).multiplyScalar(k));
  });
  gates.instanceColor.needsUpdate = true;
}

/* ---------------------------------------------------------- 2. THE STRUCTURE: a city of bytes */
const CITY = { z0: -24, z1: -196, rows: 40, cols: 8 };
const cityN = CITY.rows * CITY.cols * 2;
let towers, caps, sigSprites = [], cityBeams = [];
const cityData = [];
function drawLayer(c, label) {
  const x = c.getContext("2d");
  x.clearRect(0, 0, 1024, 512);
  x.strokeStyle = "rgba(110,170,255,.3)"; x.lineWidth = 1;
  for (let i = 0; i <= 1024; i += 32) { x.beginPath(); x.moveTo(i, 0); x.lineTo(i, 512); x.stroke(); }
  for (let j = 0; j <= 512; j += 32) { x.beginPath(); x.moveTo(0, j); x.lineTo(1024, j); x.stroke(); }
  x.strokeStyle = "rgba(140,190,255,.85)"; x.lineWidth = 4; x.strokeRect(2, 2, 1020, 508);
  x.fillStyle = "rgba(210,225,255,.95)";
  x.font = RTL() ? "700 44px Segoe UI, Tahoma, sans-serif" : "700 40px Consolas, monospace";
  x.direction = RTL() ? "rtl" : "ltr"; x.textAlign = RTL() ? "right" : "left";
  x.fillText(label, RTL() ? 984 : 40, 70);
}
function relabelLayers() {
  LAYERS.forEach((m, i) => { const [k, hex] = LAYER_DEF[i]; drawLayer(m.material.map.image, `${T(k)} · ${hex}`); m.material.map.needsUpdate = true; });
}
function buildCity() {
  const towerGeo = new THREE.BoxGeometry(1, 1, 1); towerGeo.translate(0, 0.5, 0);
  towers = new THREE.InstancedMesh(towerGeo, new THREE.MeshBasicMaterial({ color: 0x0c1430, fog: true }), cityN);
  const capGeo = new THREE.PlaneGeometry(1, 1); capGeo.rotateX(-Math.PI / 2);
  caps = new THREE.InstancedMesh(capGeo, new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true }), cityN);
  let k = 0;
  for (let r = 0; r < CITY.rows; r++) for (let c = 0; c < CITY.cols; c++) for (const side of [-1, 1]) {
    const z = lerp(CITY.z0, CITY.z1, r / (CITY.rows - 1)) + (rnd() - 0.5) * 1.5;
    const open = sst(-150, -196, z) * 9;                                     // the avenue opens into the tunnel
    const x = spine(z).x + side * (8 + open + c * 3.6 + rnd() * 0.8);
    const byte = Math.floor(rnd() * 256), h = (1.5 + (byte / 255) ** 1.6 * 22) * (1 - sst(-160, -196, z) * 0.6);
    const floor = (k % 3) !== 0;                                            // a third hang from the ceiling
    cityData.push({ x, z, h: floor ? h + 5 : h, w: 2 + rnd() * 1.2, floor, byte });
    k++;
  }
  // shuffled, so drawing fewer instances (a lower level) thins the whole city evenly
  for (let i = cityData.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [cityData[i], cityData[j]] = [cityData[j], cityData[i]]; }
  const col = new THREE.Color();
  cityData.forEach((d, i) => caps.setColorAt(i, col.setHSL(0.6 + (d.byte / 255) * 0.14, 0.9, 0.3 + (d.byte / 255) * 0.3)));
  add(towers); add(caps);
  cityZ = null; updateCity(48);
  built.city = true;
}
function buildCityLayers() {
  // translucent layers the camera passes through, one per part of the file
  LAYERS = LAYER_DEF.map(([key, hex, z]) => {
    const c = document.createElement("canvas"); c.width = 1024; c.height = 512;
    drawLayer(c, `${T(key)} · ${hex}`);
    const mat = new THREE.MeshBasicMaterial({ map: new THREE.CanvasTexture(c), transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide, fog: true });
    const m = new THREE.Mesh(new THREE.PlaneGeometry(30, 15), mat); m.position.copy(spine(z)); m.position.y += 1; add(m); return m;
  });
}
function buildCitySigns() {
  // floating signatures: one texture per signature, shared by its sprites
  const SIGS = ["4D 5A 90 00", "%PDF-1.7", "50 4B 03 04", "7F 45 4C 46", "/JavaScript", "/OpenAction", "obj << >>", "stream", "FF D8 FF E0", "vbaProject.bin", "/EmbeddedFile", "D0 CF 11 E0"];
  const sigTex = SIGS.map((str) => textTex(str, { size: 54, color: "#b9c8ff" }));
  for (let i = 0; i < 34; i++) {
    const m = new THREE.SpriteMaterial({ map: sigTex[i % SIGS.length], transparent: true, opacity: 0.75, depthWrite: false, blending: THREE.AdditiveBlending, fog: true });
    const sp = new THREE.Sprite(m); sp.scale.set(512 / 128 * 2.2, 2.2, 1);
    const side = i % 2 ? 1 : -1, z = lerp(-30, -160, rnd());
    sp.position.set(spine(z).x + side * (5 + rnd() * 7), (rnd() - 0.5) * 14, z);
    sp.userData.base = sp.position.clone(); sp.userData.w = rnd() * 6.28;
    add(sp); sigSprites.push(sp);
  }
  // god rays falling into the city
  cityBeams = [[-10, -60], [9, -100], [-6, -140]].map(([x, z]) => { const b = beam(9, 36, 0x6f8cff, 0.22); b.position.set(spine(z).x + x, 26, z); add(b); return b; });
}
let cityZ = null, cityCount = -1;
function updateCity(camZ) {
  const gate = clamp((6 - camZ) / 16);                                     // nothing of the city before the breach
  towers.visible = caps.visible = gate > 0.001;
  if (!towers.visible) return;
  const n = towers.count;
  if (cityZ !== null && Math.abs(camZ - cityZ) < 0.004 && n === cityCount) return;   // nothing moved
  cityZ = camZ; cityCount = n;
  for (let i = 0; i < n; i++) {
    const d = cityData[i];
    // towers grow out of the floor (or ceiling) as the camera approaches, and settle behind it
    const ahead = camZ - d.z;                                               // positive: the tower is in front
    const grow = clamp(1 - (ahead - 18) / 60) * gate;
    const h = Math.max(0.05, d.h * ease(grow));
    const y = d.floor ? -16 : 13;
    const q_ = d.floor ? tmpQ.identity() : flip;
    tmpS.set(d.w, h, d.w); tmpP.set(d.x, y, d.z);
    tmpM.compose(tmpP, q_, tmpS); towers.setMatrixAt(i, tmpM);
    tmpS.set(d.w * 0.92, 1, d.w * 0.92); tmpP.set(d.x, d.floor ? y + h + 0.02 : y - h - 0.02, d.z);
    tmpM.compose(tmpP, q_, tmpS); caps.setMatrixAt(i, tmpM);
  }
  towers.instanceMatrix.needsUpdate = true; caps.instanceMatrix.needsUpdate = true;
}

/* ---------------------------------------------------------- 3. THE ANALYSIS: the scanning tunnel */
const T0 = -176, T1 = -292, TR = 14;
const barN = 520, featN = 140;
let bars, feats, scanDisc;
const barData = [], featData = [];
function buildTunnel() {
  // entropy bars around the wall, pointing inwards (their place and direction never change: kept)
  const barGeo = new THREE.BoxGeometry(0.35, 1, 0.35); barGeo.translate(0, 0.5, 0);
  const barMat = new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, depthWrite: false, fog: true });
  // fade what is within a few units of the camera, so nothing slams into the lens
  barMat.onBeforeCompile = (sh) => {
    sh.vertexShader = sh.vertexShader.replace("#include <fog_vertex>", "#include <fog_vertex>\n  vNearFade = smoothstep(4., 16., -mvPosition.z);").replace("void main() {", "varying float vNearFade;\nvoid main() {");
    sh.fragmentShader = sh.fragmentShader.replace("void main() {", "varying float vNearFade;\nvoid main() {").replace("#include <fog_fragment>", "#include <fog_fragment>\n  gl_FragColor.rgb *= vNearFade * .8;");
  };
  bars = new THREE.InstancedMesh(barGeo, barMat, barN);
  const col = new THREE.Color();
  for (let i = 0; i < barN; i++) {
    const th = rnd() * Math.PI * 2, z = lerp(T0 - 4, T1 + 4, rnd());
    const e = 0.25 + 0.75 * Math.abs(Math.sin(z * 0.07 + th * 3)) * rnd();   // a made-up entropy profile
    const q_ = new THREE.Quaternion().setFromUnitVectors(up, tmpV.set(-Math.cos(th), -Math.sin(th), 0));
    const c = spine(z);
    barData.push({ th, z, e, q: q_, p: new THREE.Vector3(c.x + Math.cos(th) * TR, c.y + Math.sin(th) * TR, z) });
    bars.setColorAt(i, col.setHSL(lerp(0.5, 0.78, e), 0.95, 0.55));
  }
  add(bars);
  // features pulled out of the wall to the axis, then streamed ahead
  feats = new THREE.InstancedMesh(new THREE.BoxGeometry(0.5, 0.5, 0.5), new THREE.MeshBasicMaterial({ color: 0x8fe9ff, transparent: true, opacity: 0.75, blending: THREE.AdditiveBlending, depthWrite: false, fog: true }), featN);
  for (let i = 0; i < featN; i++) featData.push({ th: rnd() * 6.283, z: lerp(T0, T1, rnd()), sp: rnd() });
  add(feats);
  // a scanning disc sweeping the tunnel
  scanDisc = new THREE.Mesh(new THREE.CircleGeometry(TR, 96), new THREE.ShaderMaterial({
    uniforms: { uTime: U.uTime, uA: { value: 0 } },
    vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.); }`,
    fragmentShader: `uniform float uTime; uniform float uA; varying vec2 vUv;
      void main(){ vec2 p = vUv-.5; float d = length(p)*2.; float a = atan(p.y,p.x);
        float sweep = pow(fract((a/6.2832) - uTime*.35), 6.);
        float rim = smoothstep(.9,1.,d)*smoothstep(1.02,.98,d);
        float grid = step(.96, fract(d*9.))*.25;
        vec3 c = vec3(.13,.91,1.)*(sweep*.45 + rim*1.1 + grid*(1.-d));
        gl_FragColor = vec4(c*uA, 1.); }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide,
  }));
  add(scanDisc);
  barZ = featS = null; updateBars(48); updateFeats(0);
  built.tunnel = true;
}
let barZ = null, barCount = -1, featS = null, featCount = -1;
function updateBars(camZ) {
  const n = bars.count;
  if (barZ !== null && Math.abs(camZ - barZ) < 0.004 && n === barCount) return;
  barZ = camZ; barCount = n;
  for (let i = 0; i < n; i++) {
    const d = barData[i];
    const grow = ease(clamp(1 - (camZ - d.z - 10) / 45));
    tmpS.set(1, Math.max(0.02, d.e * 5 * grow), 1);
    tmpM.compose(d.p, d.q, tmpS);
    bars.setMatrixAt(i, tmpM);
  }
  bars.instanceMatrix.needsUpdate = true;
}
function updateFeats(sv) {
  const n = feats.count;
  if (featS === sv && n === featCount) return;
  featS = sv; featCount = n;
  for (let i = 0; i < n; i++) {
    const d = featData[i];
    const t = seg(sv, 0.36 + d.sp * 0.1, 0.46 + d.sp * 0.1, inOut);
    const r = lerp(TR - 0.8, 0.6 + d.sp * 1.2, t);
    const z = d.z - t * 18, c = spine(z);
    tmpP.set(c.x + Math.cos(d.th + t * 1.5) * r, c.y + Math.sin(d.th + t * 1.5) * r - t * 2.4, z);   // pulled down into the river
    tmpQ.setFromAxisAngle(up, t * 6 + d.sp * 6);
    tmpS.setScalar(0.4 + t * 0.15);
    tmpM.compose(tmpP, tmpQ, tmpS); feats.setMatrixAt(i, tmpM);
  }
  feats.instanceMatrix.needsUpdate = true;
}

/* ---------------------------------------------------------- 4. THE INTELLIGENCE: the network */
const NL = 6, NZ0 = -300, NDZ = 20, perLayer = 34;
const actU = { value: new Float32Array(NL) };
function buildNet() {
  const nodes = [];
  for (let l = 0; l < NL; l++) {
    const count = l === NL - 1 ? 3 : perLayer;
    const z = NZ0 - l * NDZ, c = spine(z);
    for (let i = 0; i < count; i++) {
      let x, y;
      if (l === NL - 1) { x = (i - 1) * 9; y = 0; }
      else { const r = 17 * Math.sqrt((i + 0.5) / count), a = i * 2.39996 + l; x = Math.cos(a) * r; y = Math.sin(a) * r * 0.75; }
      nodes.push({ l, x: x + c.x, y: y + c.y, z, out: l === NL - 1 ? i : -1 });
    }
  }
  const nodeGeo = new THREE.BufferGeometry();
  nodeGeo.setAttribute("position", new THREE.Float32BufferAttribute(nodes.flatMap((n) => [n.x, n.y, n.z]), 3));
  nodeGeo.setAttribute("aLayer", new THREE.Float32BufferAttribute(nodes.map((n) => n.l), 1));
  nodeGeo.setAttribute("aOut", new THREE.Float32BufferAttribute(nodes.map((n) => n.out), 1));
  nodeMat = new THREE.ShaderMaterial({
    uniforms: { map: { value: dotTex }, uAct: actU, uTime: U.uTime, uScale: { value: 1 }, ...THREE.UniformsUtils.clone(fogU) },
    vertexShader: `attribute float aLayer; attribute float aOut; uniform float uAct[${NL}]; uniform float uTime; uniform float uScale; varying vec3 vC; varying float vA;
      #include <fog_pars_vertex>
      void main(){ int li = int(aLayer+.5); float act = 0.;
        for (int k=0;k<${NL};k++){ if(k==li) act = uAct[k]; }
        vec4 mvPosition = modelViewMatrix*vec4(position,1.);
        float tw = .75 + .25*sin(uTime*2. + position.x*1.7 + position.y);
        vC = aOut < -.5 ? mix(vec3(.5,.3,.95), vec3(1.,.55,.95), act) : (aOut < .5 ? vec3(.24,1.,.66) : (aOut < 1.5 ? vec3(1.,.76,.3) : vec3(1.,.3,.43)));
        vA = (.25 + .75*act)*tw;
        gl_PointSize = (aOut < -.5 ? 2.2 : 5.) * (1. + act) * uScale * 300. / -mvPosition.z;
        gl_Position = projectionMatrix*mvPosition;
        #include <fog_vertex>
      }`,
    fragmentShader: `uniform sampler2D map; varying vec3 vC; varying float vA;
      #include <fog_pars_fragment>
      void main(){ vec4 t = texture2D(map, gl_PointCoord); gl_FragColor = vec4(vC*t.a*vA*1.4, t.a*vA);
        #include <fog_fragment>
      }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true,
  });
  add(new THREE.Points(nodeGeo, nodeMat));
  // connections, with pulses running along them once their source layer is active
  const linkPos = [], linkT = [], linkSeed = [], linkLayer = [];
  for (let l = 0; l < NL - 1; l++) {
    const As = nodes.filter((n) => n.l === l), Bs = nodes.filter((n) => n.l === l + 1);
    As.forEach((a) => {
      for (let j = 0; j < 3; j++) {
        const b = l === NL - 2 ? Bs[j] : Bs[Math.floor(rnd() * Bs.length)];
        linkPos.push(a.x, a.y, a.z, b.x, b.y, b.z); linkT.push(0, 1);
        const sd = rnd(); linkSeed.push(sd, sd); linkLayer.push(l, l);
      }
    });
  }
  const linkGeo = new THREE.BufferGeometry();
  linkGeo.setAttribute("position", new THREE.Float32BufferAttribute(linkPos, 3));
  linkGeo.setAttribute("aT", new THREE.Float32BufferAttribute(linkT, 1));
  linkGeo.setAttribute("aSeed", new THREE.Float32BufferAttribute(linkSeed, 1));
  linkGeo.setAttribute("aLayer", new THREE.Float32BufferAttribute(linkLayer, 1));
  const linkMat = new THREE.ShaderMaterial({
    uniforms: { uAct: actU, uTime: U.uTime, ...THREE.UniformsUtils.clone(fogU) },
    vertexShader: `attribute float aT; attribute float aSeed; attribute float aLayer; uniform float uAct[${NL}]; varying float vT; varying float vSeed; varying float vAct;
      #include <fog_pars_vertex>
      void main(){ vT = aT; vSeed = aSeed; int li = int(aLayer+.5); float act = 0.; for (int k=0;k<${NL};k++){ if(k==li) act = uAct[k]; } vAct = act;
        vec4 mvPosition = modelViewMatrix*vec4(position,1.); gl_Position = projectionMatrix*mvPosition;
        #include <fog_vertex>
      }`,
    fragmentShader: `uniform float uTime; varying float vT; varying float vSeed; varying float vAct;
      #include <fog_pars_fragment>
      void main(){ float p = fract(uTime*.45 + vSeed); float pulse = smoothstep(.08, 0., abs(vT - p));
        vec3 base = vec3(.5,.28,.9)*.22; vec3 c = base*(.4+vAct) + vec3(1.,.6,.95)*pulse*vAct*1.3;
        gl_FragColor = vec4(c, 1.);
        #include <fog_fragment>
      }`,
    transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true,
  });
  add(new THREE.LineSegments(linkGeo, linkMat));
  built.net = true;
}

/* ---------------------------------------------------------- 5. THE VERIFICATION: gauge, cage, checks (around the file's core) */
const G0 = Math.PI * 1.15, GSPAN = Math.PI * 1.3;                         // from the left, clockwise over the top
const tickN = 72;
let vault, cage = [], gaugeTrack, gaugeFill, needle, ticks, vaultBeam, gaugeAng = -1, okPrev = -1;
const cGrey = new THREE.Color(0x3a2c4c), cGreen = new THREE.Color(0x5dffb8);
function buildVault() {
  vault = new THREE.Group(); vault.position.z = VZ; add(vault);
  const cageGeo = new THREE.PlaneGeometry(7, 7);
  const cageEdges = new THREE.EdgesGeometry(cageGeo);
  [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]].forEach((n) => {
    const g = new THREE.Group();
    const m = new THREE.Mesh(cageGeo, glowMat(0xc9a2ff, 0.08)); m.material.side = THREE.DoubleSide;
    const e = new THREE.LineSegments(cageEdges, lineMat(0xe0c8ff, 0.9));
    g.add(m, e);
    g.lookAt(new THREE.Vector3(...n)); g.userData.n = new THREE.Vector3(...n);
    vault.add(g); cage.push(g);
  });
  // the risk gauge behind the vault: a track, a fill and a needle
  gaugeTrack = new THREE.Mesh(new THREE.RingGeometry(15, 15.5, 160, 1, G0 - GSPAN, GSPAN), glowMat(0x6a5a90, 0.5)); gaugeTrack.position.z = VZ - 6; add(gaugeTrack);
  gaugeFill = new THREE.Mesh(new THREE.RingGeometry(15, 15.5, 160, 1, G0 - 0.001, 0.001), glowMat(0xffc24d, 0.95)); gaugeFill.position.z = VZ - 5.9; add(gaugeFill);
  [gaugeTrack, gaugeFill].forEach((m) => { m.material.side = THREE.DoubleSide; });
  needle = new THREE.Mesh(new THREE.PlaneGeometry(0.18, 13), glowMat(0xffffff, 0.9)); needle.geometry.translate(0, 6.5, 0); needle.position.z = VZ - 5.8; add(needle);
  // the ring of integrity checks: ticks that turn green one after another
  ticks = new THREE.InstancedMesh(new THREE.BoxGeometry(0.22, 1.1, 0.2), new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false, fog: true }), tickN);
  const one = new THREE.Vector3(1, 1, 1);
  for (let i = 0; i < tickN; i++) { const a = (i / tickN) * Math.PI * 2; tmpQ.setFromAxisAngle(zAxis, a - Math.PI / 2); tmpM.compose(tmpP.set(Math.cos(a) * 10.5, Math.sin(a) * 10.5, VZ), tmpQ, one); ticks.setMatrixAt(i, tmpM); ticks.setColorAt(i, cGrey); }
  add(ticks);
  vaultBeam = beam(8, 30, 0xffb3e8, 0.22); vaultBeam.position.set(0, 26, VZ); add(vaultBeam);
  built.vault = true;
}

/* ---------------------------------------------------------- 6. THE VERDICT: three outcomes, under the dawn */
let VERD = [];
function buildVerdict() {
  VERD = [[-17, 0x3dffa8], [0, 0xffc24d], [17, 0xff4d6d]].map(([x, color], i) => {
    const g = new THREE.Group(); g.position.set(x, -24, VDZ - (i === 1 ? 4 : 0)); add(g);
    const body = new THREE.Mesh(new THREE.BoxGeometry(6, 20, 1.2), new THREE.MeshBasicMaterial({ color: 0x0a0716, fog: true })); body.position.y = 10; g.add(body);
    const edges = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(6, 20, 1.2)), lineMat(color, 1)); edges.position.y = 10; g.add(edges);
    const face = new THREE.Mesh(new THREE.PlaneGeometry(5.2, 19), new THREE.ShaderMaterial({
      uniforms: { uC: { value: new THREE.Color(color) }, uTime: U.uTime, uA: { value: 0 } },
      vertexShader: `varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.); }`,
      fragmentShader: `uniform vec3 uC; uniform float uTime; uniform float uA; varying vec2 vUv;
        void main(){ float l = step(.93, fract(vUv.y*24. - uTime*.6)); float g = pow(1.-abs(vUv.x-.5)*2., 2.);
          gl_FragColor = vec4(uC*(.18 + l*.35)*g*uA, 1.); }`,
      transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
    }));
    face.position.set(0, 10, 0.65); g.add(face);
    const base = new THREE.Mesh(new THREE.RingGeometry(4.2, 4.5, 64), glowMat(color, 0.8)); base.rotation.x = -Math.PI / 2; base.position.y = 0.05; g.add(base);
    const b = beam(6, 34, color, 0.18); b.position.y = 40; g.add(b);
    return { g, body, edges, face, base, b, x, color };
  });
  built.verdict = true;
}

/* ===================================================================== the camera path */
// [s, position, look-at, roll]: offsets from the spine at that depth (the z is absolute), through a
// Catmull-Rom spline, so the flight follows the road's bends and never kinks.
const KEYS = [
  [0.0, [0, 1.6, 48], [0, 0, 0], 0],
  [0.06, [4, 1.2, 31], [0, 0, 0], -0.03],
  [0.115, [0.6, 0.4, 11], [0, 0, -6], 0],
  [0.15, [0, 0, -4], [0, -1, -40], 0],
  [0.2, [-3, -1, -32], [0, -2, -72], 0.05],
  [0.26, [4, 1.5, -72], [0, -1.5, -112], -0.06],
  [0.32, [-2.5, -1.5, -126], [0, -1, -170], 0.04],
  [0.36, [0, 0, -170], [0, -1, -214], 0],
  [0.44, [0, 0.5, -222], [0, -1, -264], 0.4],
  [0.51, [0, 0.5, -282], [0, -1, -322], 0.75],
  [0.565, [6, 3.5, -300], [0, -0.5, -340], 0.12],
  [0.63, [-8, 3, -340], [2, -0.5, -382], -0.08],
  [0.695, [3, 0, -392], [0, -1, -432], 0.04],
  [0.745, [0, 2, -448], [0, 0, -490], 0],
  [0.8, [-7, 1.5, -474], [0, 0, -496], 0],
  [0.855, [6.5, 2.5, -480], [0, 0, -498], 0],
  // over the cage, not through it: the camera rises on its way to the verdict
  [0.88, [3, 15, -498], [0, 10, -582], 0],
  [0.905, [0, 9, -518], [0, 11, -582], 0],
  [0.95, [0, 8.5, -528], [0, 12, -582], 0],
  [1.0, [0, 60, -360], [0, 4, -570], 0],
];
const kv = (i, j) => KEYS[clamp(i, 0, KEYS.length - 1)][j];
const cr = (p0, p1, p2, p3, t) => 0.5 * (2 * p1 + (-p0 + p2) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t * t + (-p0 + 3 * p1 - 3 * p2 + p3) * t * t * t);
const camPos = new THREE.Vector3(), camLook = new THREE.Vector3();
function pathAt(sv, out, j) {
  let i = 0; while (i < KEYS.length - 2 && sv > KEYS[i + 1][0]) i++;
  const t = clamp((sv - KEYS[i][0]) / (KEYS[i + 1][0] - KEYS[i][0]));
  if (j === 3) return cr(kv(i - 1, 3), kv(i, 3), kv(i + 1, 3), kv(i + 2, 3), t);
  for (let a = 0; a < 3; a++) out.setComponent(a, cr(kv(i - 1, j)[a], kv(i, j)[a], kv(i + 1, j)[a], kv(i + 2, j)[a], t));
  const sp = spine(out.z, tmpSp2); out.x += sp.x; out.y += sp.y;              // ride the road
  return out;
}

/* ===================================================================== per-frame: world, grade, text, HUD */
const stageOf = (sv) => { for (let i = STAGES.length - 1; i >= 0; i--) if (sv >= STAGES[i].a) return i; return 0; };
// held views: one still per stage (its centre), and the ending
const heldS = (P) => (P >= FINAL_HELD ? 1 : (STAGES[stageOf(P)].a + STAGES[stageOf(P)].b) / 2);
const fogC = new THREE.Color();
let gradeKey = "", gradeAt = 0;
function grade(m) {
  // the page's own colour follows the world: the HUD, the rail, the words and the veil take the
  // accent and the light of the moment. A custom property on the root restyles the whole page, so
  // it is coarse (16 levels a channel) and at most a few times a second; the eye reads it as a drift.
  const now = performance.now();
  if (now - gradeAt < 350) return;
  const q4 = (c) => [c.r, c.g, c.b].map((v) => Math.round(clamp(v) * 15) * 17).join(",");
  const k = `${q4(m.a)}|${q4(m.g)}`;
  if (k === gradeKey) return;
  gradeKey = k; gradeAt = now;
  const [a, g] = k.split("|");
  html.style.setProperty("--tone", `rgb(${a})`); html.style.setProperty("--tone-rgb", a);
  html.style.setProperty("--light-rgb", g);
}

function updateWorld(sv, t) {
  budgets();
  pathAt(sv, camPos, 1); pathAt(sv, camLook, 2);
  const roll = pathAt(sv, null, 3);
  // a gentle handheld drift on top of the path (only while the clock runs)
  camPos.x += Math.sin(t * 0.37) * 0.25; camPos.y += Math.sin(t * 0.29) * 0.2;
  // portrait screens are narrow: step back for the wide set pieces (the gauge, the three monoliths)
  const narrow = camera.aspect < 1 ? Math.min(1.4, 1 / camera.aspect - 1) : 0;
  if (narrow) {
    camPos.z += narrow * 15 * seg(sv, 0.7, 0.745, inOut) * (1 - seg(sv, 0.96, 1, inOut));
    camPos.y += narrow * 4 * seg(sv, 0.86, 0.9, inOut) * (1 - seg(sv, 0.96, 1, inOut));   // and look at the monoliths from a little higher
  }
  camera.position.copy(camPos);
  camera.up.set(Math.sin(roll), Math.cos(roll), 0);
  camera.lookAt(camLook);
  const camZ = camPos.z;

  // the atmosphere: one continuous grade, never a cut
  const m = moodAt(sv);
  fogC.setRGB(m.h.r, m.h.g, m.h.b, THREE.SRGBColorSpace);
  scene.fog.color.copy(fogC); renderer.setClearColor(fogC, 1);
  scene.fog.density = m.d;
  sky.position.copy(camPos);
  skyU.uZen.value.copy(m.z); skyU.uHor.value.copy(m.h); skyU.uGlow.value.copy(m.g); skyU.uGs.value = m.k;
  dustU.uA.value.copy(m.a).multiplyScalar(0.9); dustU.uB.value.copy(m.g);
  streamU.uA.value.copy(m.a); streamU.uB.value.copy(m.g);
  streamU.uCamZ.value = camZ; streamU.uFlow.value = t * 7 + sv * 60;
  streamU.uW.value = lerp(0.6, 2.6, seg(sv, 0.1, 0.3)) * (1 - 0.65 * seg(sv, 0.66, 0.75)) * (1 + 1.2 * seg(sv, 0.9, 1));
  streamU.uO.value = seg(sv, 0.11, 0.17) * (1 - 0.6 * seg(sv, 0.86, 0.92));
  floorU.uC.value.copy(m.a); floorU.uK.value = (0.5 + 0.5 * m.k) * (still ? 0.7 : 1); floorU.uCamZ.value = camZ;
  grade(m);
  const bm = bud.beams;

  // 1. the file: turns to face the camera, glows, then opens as the camera breaks through
  if (built.entry) {
    file.visible = spot.visible = camZ > -60;
    if (file.visible) {
      file.rotation.y = (1 - seg(sv, 0, 0.11, inOut)) * 0.55 + Math.sin(t * 0.5) * 0.04;
      file.rotation.x = Math.sin(t * 0.4) * 0.03;
      file.position.y = Math.sin(t * 0.8) * 0.3;
      const hole = seg(sv, 0.118, 0.152, (x) => x * x) * 16;
      front.material.uniforms.uHole.value = hole; back.material.uniforms.uHole.value = Math.max(0, hole - 1.5);
      front.material.uniforms.uGlow.value = seg(sv, 0.04, 0.11);
      halo.scale.setScalar(1 + seg(sv, 0.1, 0.15) * 0.6); halo.material.opacity = 0.45 * (1 - seg(sv, 0.13, 0.16));
      halo2.rotation.z = t * 0.05; halo.rotation.z = -t * 0.08;
      fileEdges.material.opacity = 0.9 * (1 - seg(sv, 0.14, 0.17));
      spot.material.uniforms.uStrength.value = 0.26 * bm * (1 - seg(sv, 0.12, 0.16));
      glowDisc.visible = sv < 0.15;
      glowDisc.material.uniforms.uO.value = 1 - seg(sv, 0.11, 0.142);
    }
  }
  placePacket(sv, camZ, t);
  // the gates along the whole road
  if (gates) { gates.visible = camZ > -560 || camPos.y > 20; if (gates.visible) updateGates(camZ, sv); }
  // 2. the city
  if (built.city) {
    towers.count = caps.count = Math.max(1, Math.floor(cityN * bud.inst));
    const on = camZ < 30 && camZ > -250;
    LAYERS.forEach((l) => { l.visible = on; }); sigSprites.forEach((sp) => { sp.visible = on; }); cityBeams.forEach((b) => { b.visible = on; });
    if (on) {
      updateCity(camZ);
      LAYERS.forEach((l) => { const d = camZ - l.position.z; l.material.opacity = 0.5 * clamp((d - 7) / 16) * clamp(1 - (d - 50) / 40) * (camZ < 4 ? 1 : 0); });
      sigSprites.forEach((sp) => { sp.position.y = sp.userData.base.y + Math.sin(t * 0.6 + sp.userData.w) * 0.6; const d = camZ - sp.position.z; sp.material.opacity = 0.75 * clamp((d - 8) / 14) * clamp(1 - (d - 45) / 30) * (camZ < 4 ? 1 : 0); });
      cityBeams.forEach((b, i) => { b.material.uniforms.uStrength.value = 0.22 * bm * (0.7 + 0.3 * Math.sin(t * 0.7 + i)); });
    } else towers.visible = caps.visible = false;
  }
  // 3. the tunnel
  if (built.tunnel) {
    bars.count = Math.max(1, Math.floor(barN * bud.inst));
    feats.count = Math.max(1, Math.floor(featN * bud.inst));
    const on = camZ < -100 && camZ > -360;
    bars.visible = feats.visible = scanDisc.visible = on;
    if (on) {
      updateBars(camZ); updateFeats(sv);
      const dz = Math.min(lerp(T0, T1, Math.sin(t * 0.5) * 0.5 + 0.5), camZ - 14);
      scanDisc.position.copy(spine(dz));
      scanDisc.material.uniforms.uA.value = seg(sv, 0.34, 0.38) * (1 - seg(sv, 0.5, 0.54)) * (still ? 0.6 : 1);
    }
  }
  // 4. the network: activation runs layer by layer with the scroll
  for (let l = 0; l < NL; l++) actU.value[l] = seg(sv, 0.535 + l * 0.022, 0.565 + l * 0.022);
  // 5. the verification; it fades away as the camera comes close, so nothing fills the lens
  if (built.vault) {
    const vf = clamp((camZ - VZ - 5) / 12) * (1 - seg(sv, 0.862, 0.888));    // and once the verdict begins, it is no longer the subject
    const on = camZ < -360 && vf > 0.01;
    vault.visible = gaugeTrack.visible = gaugeFill.visible = needle.visible = ticks.visible = vaultBeam.visible = on;
    if (on) {
      const g = seg(sv, 0.705, 0.765, inOut);
      const risk = 0.62 + Math.sin(sv * 90) * 0.04 * (1 - seg(sv, 0.76, 0.79));   // the indicators weigh in, then it settles
      const ang = g * risk * GSPAN;
      if (Math.abs(ang - gaugeAng) > 0.004) {                               // rebuild the arc only when it moved
        gaugeAng = ang;
        gaugeFill.geometry.dispose();
        gaugeFill.geometry = new THREE.RingGeometry(15, 15.5, 120, 1, G0 - Math.max(0.001, ang), Math.max(0.001, ang));
      }
      gaugeFill.material.color.setHSL(lerp(0.36, 0.08, g * risk), 1, 0.55);
      gaugeFill.material.opacity = 0.95 * vf; gaugeTrack.material.opacity = 0.5 * vf; needle.material.opacity = 0.9 * vf; ticks.material.opacity = vf;
      needle.rotation.z = G0 - ang - Math.PI / 2;
      const close = seg(sv, 0.752, 0.812, inOut);
      cage.forEach((c) => { c.position.copy(c.userData.n).multiplyScalar(lerp(16, 3.5, close)); c.children[0].material.opacity = (0.05 + close * 0.1) * vf; c.children[1].material.opacity = 0.9 * vf; c.children[1].material.color.setHSL(lerp(0.8, 0.42, seg(sv, 0.8, 0.85)), 1, 0.7); });
      const okN = Math.floor(seg(sv, 0.8, 0.85, (x) => x) * tickN);
      if (okN !== okPrev) { okPrev = okN; for (let i = 0; i < tickN; i++) ticks.setColorAt(i, i < okN ? cGreen : cGrey); ticks.instanceColor.needsUpdate = true; }
      vault.rotation.z = Math.sin(t * 0.2) * 0.05;
      vaultBeam.material.uniforms.uStrength.value = 0.22 * bm * vf;
    }
  }
  // 6. the verdict: the monoliths rise one after another
  if (built.verdict) {
    const on = camZ < -420 || camPos.y > 20;
    VERD.forEach((v) => { v.g.visible = on; });
    if (on) {
      VERD.forEach((v, i) => {
        const r = seg(sv, 0.858 + i * 0.006, 0.878 + i * 0.006, (x) => 1 + 2.4 * Math.pow(x - 1, 3) + 1.4 * Math.pow(x - 1, 2));
        v.g.position.y = lerp(-24, 0, clamp(r, 0, 1.2));
        v.face.material.uniforms.uA.value = seg(sv, 0.866 + i * 0.006, 0.886 + i * 0.006);
        v.b.material.uniforms.uStrength.value = 0.18 * bm * seg(sv, 0.87 + i * 0.006, 0.9);
      });
    }
  }
  // dust, river and streaks, at this level's budget
  dustGeo.setDrawRange(0, Math.floor(dustN * bud.dust));
  streamGeo.setDrawRange(0, Math.floor(streamN * Math.min(1, 0.35 + bud.dust * 0.65)));
  streaks.visible = bud.streaks;
  const sc = Math.min(innerWidth, innerHeight) / 900;
  dustMat.uniforms.uScale.value = sc * dpr; streamU.uScale.value = sc * dpr; if (nodeMat) nodeMat.uniforms.uScale.value = sc * dpr;
  streaks.material.uniforms.uOff.value = -camZ % 60;
  canvas.dataset.budget = `${Math.floor(dustN * bud.dust)}/${built.city ? towers.count : 0}/${dpr.toFixed(2)}/q${q}`;   // diagnostics
}

const hint = $("fj-hint"), codeEl = $("fj-code"), stageEl = $("fj-stage"), subEl = $("fj-sub"), stateEl = $("fj-state"), chapEl = $("fj-chap"), depthEl = $("fj-depth"), play = $("fj-play");
// timeline ticks at the stage borders
STAGES.slice(1).forEach((st) => { const i = document.createElement("span"); i.className = "seg"; i.style.left = `${st.a * 100}%`; $("fj-line").append(i); });

// Text is time-based, not scrubbed: a line is "on" while the camera is inside its window, and CSS
// brings it to full opacity in about half a second (words on their own beat, from depth with a blur
// when the quality allows). However slowly or quickly the visitor scrolls, a line in view is fully
// readable, and nothing is written to the DOM per frame.
function updateText(P, sv) {
  const x = still ? P : sv;
  for (const l of lineEls) {
    const on = x >= l.a && x < l.b, past = x >= l.b;
    if (on !== l.on) { l.on = on; l.el.classList.toggle("on", on); }
    if (past !== l.past) { l.past = past; l.el.classList.toggle("past", past); }
  }
  // the ending
  const f = still ? sv >= 0.999 : sv >= 0.974;
  if (f !== finalOn) { finalOn = f; finalBox.classList.toggle("show", f); html.classList.toggle("fj-end", f); }
}
// the verdict labels follow their monoliths on screen (they read the world, so they use its s);
// each appears (CSS fade) once its monolith has risen, and all leave before the ending
function updateLabels(sv) {
  const any = built.verdict && sv >= 0.868 && sv < 0.962;
  if (!any && !labelsOn) return;
  labelsOn = any;
  VERD.forEach((v, i) => {
    const el = labelEls[i], on = any && sv >= 0.874 + i * 0.006;
    if (el.classList.contains("on") !== on) el.classList.toggle("on", on);
    if (!any) return;
    tmpP.set(v.x, v.g.position.y + 21.5, v.g.position.z).project(camera);
    const x = (tmpP.x * 0.5 + 0.5) * innerWidth, y = (-tmpP.y * 0.5 + 0.5) * innerHeight;
    // on a narrow screen the three labels cannot sit side by side: the middle one stacks above
    const lift = i === 1 && innerWidth < 600 ? " translateY(calc(-100% - 8px))" : "";
    el.style.transform = `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) translate(-50%, -100%)${lift}`;
  });
}

/* the soundtrack (js/journey-audio.js): beats in the progress, and things the camera passes in space */
const BEATS = [[0.135, "breach"], [0.79, "cage"], [0.975, "finale"]];
for (let l = 0; l < NL; l++) BEATS.push([0.55 + l * 0.022, "node", { i: l }]);
[0, 1, 2].forEach((i) => BEATS.push([0.872 + i * 0.006, "monolith", { i }]));
for (let i = 0; i < 12; i++) BEATS.push([0.8 + i * 0.0042, "check", { i }]);   // the integrity ring turning green
let RING_Z = [];                                                             // the tunnel's gates (filled once they are built)
const LAYER_Z = LAYER_DEF.map((d) => d[2]);
let sndPrev = null, zPrev = null, hudDepth = "", hintGone = null, playKey = "", railKey = "";
const railFill = () => rail.querySelector("ol");
function updateHUD(P, sv) {
  const st = stageOf(P);
  if (st !== lastStage) {
    rail.querySelectorAll("li").forEach((li, i) => { li.classList.toggle("on", i === st); li.classList.toggle("done", i < st); const b = li.querySelector("button"); if (i === st) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current"); });
    codeEl.textContent = nn(st);
    stageEl.textContent = T(`s${st + 1}`);
    subEl.textContent = T(`s${st + 1}sub`);
    stateEl.textContent = T(`s${st + 1}state`);
    // the chapter card turns over with the stage (a short settle, not a cut)
    if (!still && lastStage !== -1 && chapEl.animate) {
      chapEl.animate([{ opacity: 0, transform: "translateY(10px)", filter: "blur(6px)" }, { opacity: 1, transform: "none", filter: "blur(0)" }], { duration: 700, easing: "cubic-bezier(.22,1,.36,1)" });
    }
    if (lastStage !== -1) AUD()?.stage?.(st);
    lastStage = st;
  }
  const pk = P.toFixed(4);
  if (pk !== playKey) { playKey = pk; play.style.transform = `scaleX(${pk})`; }
  // the rail's line fills continuously between the stage markers
  const frac = clamp((P - STAGES[st].a) / (STAGES[st].b - STAGES[st].a));
  const rk = clamp((st + frac) / (STAGES.length - 1)).toFixed(3);
  if (rk !== railKey) { railKey = rk; const ol = railFill(); if (ol) ol.style.setProperty("--p", rk); }
  const dp = "0x" + Math.floor(P * 0x9e4f2c).toString(16).toUpperCase().padStart(6, "0");
  if (dp !== hudDepth) { hudDepth = dp; depthEl.textContent = dp; }
  const g = P > 0.012;
  if (g !== hintGone) { hintGone = g; hint.classList.toggle("gone", g); }
  // sound: each beat once, forwards only (the score and the wind follow both ways, in frame())
  const au = AUD();
  if (au && au.on) {
    const fwd = sndPrev !== null && sv > sndPrev && sv - sndPrev < 0.05;
    if (fwd) BEATS.forEach(([at, name, o]) => { if (sndPrev < at && sv >= at) au.event?.(name, o); });
    const z = camera.position.z;
    if (fwd && zPrev !== null && z < zPrev) {
      RING_Z.forEach((rz, i) => { if (zPrev > rz && z <= rz) au.event?.("ring", { i }); });
      LAYER_Z.forEach((lz, i) => { if (zPrev > lz && z <= lz) au.event?.("layer", { i }); });
    }
    zPrev = z;
  }
  sndPrev = sv;
}

/* ===================================================================== the loop: on demand */
let clock = 0, lastS = null, lastClock = -1, prevDrawnAt = 0;
function setStill(v) {
  still = v;
  html.classList.toggle("fj-still", v);
  lineEls.forEach((l) => { l.on = l.past = null; });
  finalOn = null;
  wheeling = false;
}
function snapshot(fromS) {
  // held views crossfade: draw the old view once more, copy it, then fade the copy out over the new one
  if (!xctx) return;
  updateWorld(fromS, clock); renderer.render(scene, camera);
  xctx.drawImage(canvas, 0, 0, xf.width, xf.height);
  xf.classList.remove("go"); xf.classList.add("on");
  requestAnimationFrame(() => requestAnimationFrame(() => { xf.classList.remove("on"); xf.classList.add("go"); }));
}
function frame(now) {
  raf = 0;
  const dt = clamp((now - last) / 1000, 0, 0.05); last = now;
  stepWheel(dt);
  const P = rawP();
  const held = rm || !tb().flight;
  if (held !== still) { setStill(held); forceRender = true; }
  let sv;
  if (still) sv = heldS(P);
  else {
    s += (P - s) * (1 - Math.exp(-dt * 9));                                // the damped follower: smooth, never far behind
    if (Math.abs(P - s) < 2e-5) s = P;
    sv = s;
  }
  const moving = wheeling || (!still && sv !== P);
  if (moving) activeUntil = Math.max(activeUntil, now + 450);             // a short ambient tail after the last movement
  if (!still && now < activeUntil) clock += dt;                             // ambient motion runs only while drawing
  vel = still ? 0 : lerp(vel, (sv - sPrev) / Math.max(dt, 1e-3), 0.2); sPrev = sv;
  let drawn = false;
  if (forceRender || sv !== lastS || clock !== lastClock) {
    if (still && lastS !== null && sv !== lastS && !forceRender) snapshot(lastS);
    U.uTime.value = clock;
    U.uVel.value = clamp(vel * 6, -1.5, 1.5);
    updateWorld(sv, clock);
    renderer.render(scene, camera);
    updateLabels(sv);
    lastS = sv; lastClock = clock; forceRender = false; drawn = true;
  }
  AUD()?.update?.(sv, vel);
  updateText(P, sv);
  updateHUD(P, sv);
  // the governor: only the gaps between frames drawn back to back, in motion
  if (drawn && !still && prevDrawnAt && now - prevDrawnAt < 250) govSample(now - prevDrawnAt);
  prevDrawnAt = drawn ? now : 0;
  if (moving || now < activeUntil || forceRender) raf = requestAnimationFrame(frame);
  else { vel = 0; AUD()?.update?.(sv, 0); prevDrawnAt = 0; }
}
// a new level from the site's engine: resolution and budgets follow, drawn once
// (one frame now, one when the eased budgets have arrived: no ambient animation for it)
let perfT = 0;
addEventListener("cs:perf", () => {
  const d = dprFor(); if (d !== dpr) { dpr = d; renderer.setPixelRatio(dpr); resize(); }
  forceRender = true; wake();
  clearTimeout(perfT); perfT = setTimeout(() => { forceRender = true; wake(); }, 1600);
});
document.addEventListener("visibilitychange", () => {
  running = !document.hidden;
  if (running) { forceRender = true; wake(); } else stopLoop();
});

/* ===================================================================== start: the entry first, the rest in chunks */
// upload a chunk's textures one per task before anything draws them, so no frame pays for them all
const uploaded = new Set();
async function uploadTextures() {
  const list = [];
  const take = (t) => { if (t && t.isTexture && !uploaded.has(t)) { uploaded.add(t); list.push(t); } };
  scene.traverse((o) => { const m = o.material; if (m) { take(m.map); if (m.uniforms && m.uniforms.map) take(m.uniforms.map.value); } });
  for (const t of list) { renderer.initTexture(t); await pause(); }
}
buildSky(); buildEntry(); buildPacket(); buildDust(); buildStream(); buildFloor();
await uploadTextures();
await renderer.compileAsync(scene, camera).catch(() => {});
ready = true;
forceRender = true;
requestAnimationFrame(() => html.classList.add("fj-glon"));               // the world fades in under the words
wake(still ? 0 : 1800);                                                    // a short living intro, then rest
const chunks = [buildGates, buildCity, buildCityLayers, buildCitySigns, buildTunnel, buildNet, buildVault, buildVerdict];
for (const build of chunks) {
  await pause();
  build();
  await uploadTextures();
  await renderer.compileAsync(scene, camera).catch(() => {});             // shaders compile off the main path
  forceRender = true; wake();
}
html.classList.add("fj-ready");
