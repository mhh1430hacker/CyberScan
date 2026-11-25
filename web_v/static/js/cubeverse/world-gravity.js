/* World A: the Gravity Playground. Real rigid cubes (physics.js) fall into a glass box; drag them by
 * any point and throw them, sweep the pointer fast to push them, click the floor for a shockwave,
 * and turn gravity in any direction (buttons, arrow keys, or the phone's tilt). Impacts flash and
 * ring softly. Everything rests (and the engine draws nothing) once the cubes fall asleep. */
import { THREE, CubeSet, cubeMaterial, roundedBoxGeometry, gradientTexture, Rings, keyLight, disposeScene, OrbitRig, makeTools, press, clamp, rand } from "./core.js";
import { Physics } from "./physics.js";

const saved = { bodies: null, g: "down", cam: null };   // kept for the visit while the world is away
const PALETTE = [["#d4bcff", "#6d28d9"], ["#a5f3fc", "#0891b2"], ["#ffb3ee", "#be1fa8"], ["#f5f3ff", "#8f88c2"], ["#9d8cff", "#2e1f86"], ["#99f6e4", "#0f8f84"]];
const GRAV = { down: [0, -1, 0], up: [0, 1, 0], left: [-1, 0, 0], right: [1, 0, 0], back: [0, 0, -1], front: [0, 0, 1], zero: [0, 0, 0] };
const TXT = {
  ar: { gravity: "الجاذبية", down: "الجاذبية للأسفل", up: "الجاذبية للأعلى", left: "الجاذبية لليسار", right: "الجاذبية لليمين", zero: "انعدام الوزن", zeroT: "بلا وزن",
    tilt: "الإمالة", tiltL: "الجاذبية تتبع إمالة جوالك", act: "أفعال", shake: "هزّ", more: "مكعبات أكثر", reset: "إعادة",
    sayDown: "الجاذبية للأسفل", sayUp: "الجاذبية للأعلى", sayLeft: "الجاذبية لليسار", sayRight: "الجاذبية لليمين", sayZero: "انعدام الوزن: المكعبات تطفو", sayBack: "الجاذبية للخلف", sayFront: "الجاذبية للأمام", sayTilt: "الجاذبية تتبع الجوال", sayFull: "الصندوق ممتلئ",
    fZero: "رقصة انعدام الوزن", fStorm: "عاصفة مكعبات", fCeil: "السقف صار أرضًا" },
  en: { gravity: "Gravity", down: "Gravity down", up: "Gravity up", left: "Gravity left", right: "Gravity right", zero: "Zero gravity", zeroT: "Zero-G",
    tilt: "Tilt", tiltL: "Gravity follows your phone's tilt", act: "Actions", shake: "Shake", more: "More cubes", reset: "Reset",
    sayDown: "Gravity down", sayUp: "Gravity up", sayLeft: "Gravity left", sayRight: "Gravity right", sayZero: "Zero gravity: the cubes float", sayBack: "Gravity backward", sayFront: "Gravity forward", sayTilt: "Gravity follows the phone", sayFull: "The box is full",
    fZero: "The zero-gravity waltz", fStorm: "A storm of cubes", fCeil: "The ceiling became the floor" },
};
const HALVES = [0.34, 0.42, 0.42, 0.5, 0.5, 0.58, 0.68];

export function create(ctx) {
  const { engine } = ctx, tier = engine.tier;
  const scene = new THREE.Scene();
  scene.background = gradientTexture([[0, "#1a1240"], [0.5, "#0b0822"], [1, "#05040e"]]);
  scene.fog = new THREE.Fog(0x07061a, 24, 52);
  scene.environment = engine.env;
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 140);
  const rig = new OrbitRig(camera, { target: [0, 3.6, 0], theta: 0.3, phi: 1.13, radius: 20, minR: 9, maxR: 36, minPhi: 0.32, maxPhi: 1.48, minTheta: -1.25, maxTheta: 1.25 });
  if (saved.cam) rig.state = saved.cam;
  else if (engine.w / engine.h < 0.8) { rig.goal.radius *= 1.4; rig.snap(); }   // a phone held upright: step back

  // light: a soft key with shadows, a violet sky, cyan and magenta rims
  scene.add(new THREE.HemisphereLight(0xa596ff, 0x0b0820, 0.7));
  const key = keyLight(engine, { intensity: 2.5, pos: [5, 17, 10], box: 11 }); scene.add(key, key.target);
  const rimC = new THREE.PointLight(0x22e8ff, 55, 34, 2); rimC.position.set(-9, 7, -6); scene.add(rimC);
  const rimM = new THREE.PointLight(0xff4fd8, 40, 34, 2); rimM.position.set(10, 4, -5); scene.add(rimM);

  // the stage: a dark floor, a soft violet pool of light, the glass box
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(90, 90), new THREE.MeshStandardMaterial({ color: 0x0d0a24, roughness: 0.9, metalness: 0 }));
  floor.rotation.x = -Math.PI / 2; floor.receiveShadow = true; scene.add(floor);
  const pool = new THREE.Mesh(new THREE.PlaneGeometry(30, 24), new THREE.MeshBasicMaterial({ map: gradientTexture([[0, "rgba(140,90,255,0.42)"], [0.45, "rgba(70,40,160,0.14)"], [1, "rgba(0,0,0,0)"]], { radial: true }), transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
  pool.rotation.x = -Math.PI / 2; pool.position.y = 0.01; scene.add(pool);
  const grid = new THREE.GridHelper(14, 14, 0x4c3a99, 0x2a1f60); grid.scale.z = 9 / 14; grid.position.y = 0.015;
  grid.material.transparent = true; grid.material.opacity = 0.45; grid.material.depthWrite = false; scene.add(grid);
  const box = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(14, 10, 9)), new THREE.LineBasicMaterial({ color: 0x9d8cff, transparent: true, opacity: 0.22, depthWrite: false }));
  box.position.y = 5; scene.add(box);

  // the cubes
  const phys = new Physics({ half: [7, 4.5], height: 10, tier });
  const cap = tier === 2 ? 44 : tier === 1 ? 32 : 20, start = tier === 2 ? 30 : tier === 1 ? 22 : 14;
  const cubes = new CubeSet(cap, { geometry: roundedBoxGeometry(0.1, tier === 0 ? 1 : 2), material: cubeMaterial({ physical: tier === 2, roughness: 0.32, envMapIntensity: 0.9 }), castShadow: true, receiveShadow: true });
  scene.add(cubes.mesh);
  const colorOf = [], glow = new Float32Array(cap), hoverAt = new Float32Array(cap);
  const tmpA = new THREE.Color(), tmpB = new THREE.Color();
  function addBody(p, q, half, c) {
    if (phys.bodies.length >= cap) return null;
    const b = phys.add({ pos: p, quat: q, half });
    const i = b.idx; colorOf[i] = c;
    cubes.colors(i, tmpA.set(PALETTE[c][0]), tmpB.set(PALETTE[c][1]));
    cubes.count = phys.bodies.length;
    cubes.c1.needsUpdate = true; cubes.c2.needsUpdate = true;
    return b;
  }
  const randQ = () => new THREE.Quaternion().setFromEuler(new THREE.Euler(rand(Math.PI * 2), rand(Math.PI * 2), rand(Math.PI * 2)));
  function rain(n, fromY = 6.2) {
    // a jittered grid of starting places, so no two cubes start inside each other
    const cols = 5, rows = 3, per = cols * rows;
    for (let k = 0; k < n; k++) {
      const layer = Math.floor(k / per), s = k % per, cx = s % cols, cz = Math.floor(s / cols);
      const p = new THREE.Vector3(-5.6 + cx * 2.8 + rand(-0.4, 0.4), Math.min(9.1, fromY + layer * 1.9 + rand(-0.3, 0.3)), -3 + cz * 3 + rand(-0.3, 0.3));
      addBody(p, randQ(), HALVES[Math.floor(rand(HALVES.length))], Math.floor(rand(PALETTE.length)));
    }
  }
  if (saved.bodies) {
    for (const s of saved.bodies) { const b = addBody(new THREE.Vector3().fromArray(s.p), new THREE.Quaternion().fromArray(s.q), s.h, s.c); if (b && s.sleep) b.sleep = true; }
  } else {
    rain(start);
    if (ctx.reduced()) for (let i = 0; i < 900 && phys.awake(); i++) phys.sub(phys.hstep);   // calm: they are already resting
  }
  let gname = saved.g || "down", tilting = false;
  phys.g.set(...GRAV[gname === "tilt" ? "down" : gname]).multiplyScalar(9.8);
  if (gname === "tilt") gname = "down";
  const rings = new Rings(scene, 12);

  /* ---------- interaction ---------- */
  const ray = (info) => engine.ray(info);
  const pick = (info) => { const h = ray(info).intersectObject(cubes.mesh, false)[0]; return h && h.instanceId != null ? h : null; };
  let drag = null;
  const plane = new THREE.Plane(), hitP = new THREE.Vector3(), camDir = new THREE.Vector3(), right = new THREE.Vector3(), upV = new THREE.Vector3();
  const inBox = (p) => p.set(clamp(p.x, -6.4, 6.4), clamp(p.y, 0.6, 9.4), clamp(p.z, -3.9, 3.9));
  function onDown(info) {
    const h = pick(info); if (!h) return false;
    const b = phys.bodies[h.instanceId];
    const local = h.point.clone().sub(b.p).applyQuaternion(b.q.clone().invert());
    camera.getWorldDirection(camDir);
    plane.setFromNormalAndCoplanarPoint(camDir.negate(), h.point);
    b.drag = { local, target: h.point.clone(), k: 90, c: 13 }; b.wake();
    drag = { b }; glow[b.idx] = Math.max(glow[b.idx], 0.35);
    ctx.sfx("press");
    return true;
  }
  function onDrag(info) {
    if (!drag) return;
    if (ray(info).ray.intersectPlane(plane, hitP)) drag.b.drag.target.copy(inBox(hitP));
  }
  function onUp(info) {
    if (!drag) return;
    drag.b.drag = null; drag.b.wake();
    if (info.speed > 900) ctx.sfx("whoosh", { dur: 0.35, peak: 0.04 });
    drag = null;
  }
  function shock(p, strength) {
    for (const b of phys.bodies) {
      const d = b.p.clone().sub(p), dist = d.length();
      if (dist > 5.5) continue;
      const f = (1 - dist / 5.5) * 7.5 * strength;
      d.y = Math.abs(d.y) + 0.9; d.normalize();
      b.v.addScaledVector(d, f); b.w.add(new THREE.Vector3(rand(-1, 1), rand(-1, 1), rand(-1, 1)).multiplyScalar(f * 0.7)); b.wake();
    }
    rings.spawn(p.clone().setY(Math.max(0.03, p.y)), new THREE.Vector3(0, 1, 0), 0x22e8ff, 2.6 * strength);
    ctx.sfx("drop");
  }
  function onTap(info) {
    const h = pick(info);
    if (h) {   // a flick: the cube hops and spins
      const b = phys.bodies[h.instanceId];
      b.v.y += 5.5; b.w.add(new THREE.Vector3(rand(-6, 6), rand(-6, 6), rand(-6, 6))); b.wake(); glow[b.idx] = 0.6;
      ctx.sfx("pluck", { k: colorOf[b.idx] * 2 + 3 });
      return;
    }
    const r = ray(info).ray;
    const t = Math.abs(r.direction.y) > 1e-3 ? -r.origin.y / r.direction.y : -1;
    const p = t > 0 ? r.at(t, new THREE.Vector3()) : r.at(16, new THREE.Vector3());
    inBox(p); if (t > 0) p.y = 0;
    shock(p, 1 + Math.min(1.5, info.speed / 1800));
  }
  // a fast sweep pushes the cubes it crosses, in the pointer's direction; a slow one just lights them
  let hovered = -1;
  function onHover(info) {
    const h = pick(info);
    hovered = h ? h.instanceId : -1;
    if (!h || info.speed < 650) return;
    const i = h.instanceId, now = performance.now();
    if (now - hoverAt[i] < 140) return;
    hoverAt[i] = now;
    const b = phys.bodies[i];
    camera.getWorldDirection(camDir); right.crossVectors(camDir, camera.up).normalize(); upV.crossVectors(right, camDir).normalize();
    const k = Math.min(7, info.speed / 380);
    b.v.addScaledVector(right, (info.vx / (info.speed || 1)) * k).addScaledVector(upV, (-info.vy / (info.speed || 1)) * k * 0.8).y += 1.2;
    b.w.add(new THREE.Vector3(rand(-1, 1), rand(-1, 1), rand(-1, 1)).multiplyScalar(k)); b.wake();
    glow[i] = Math.max(glow[i], 0.5);
    ctx.sfx("tick", { k: i });
  }
  function onLeave() { hovered = -1; }

  /* ---------- gravity ---------- */
  const flips = new Set();
  function setGravity(name, quiet) {
    stopTilt();
    gname = name;
    phys.g.set(...GRAV[name]).multiplyScalar(9.8);
    if (name === "zero") for (const b of phys.bodies) { b.v.add(new THREE.Vector3(rand(-1, 1), rand(0.5, 2), rand(-1, 1))); b.w.add(new THREE.Vector3(rand(-1, 1), rand(-1, 1), rand(-1, 1))); }
    phys.linDamp = name === "zero" ? 0.01 : 0.04;
    phys.wakeAll();
    if (gbtn[name]) press(Object.values(gbtn), gbtn[name]);
    if (!quiet) {
      ctx.sfx(name === "zero" ? "rise" : "toggleOn");
      const T = TXT[ctx.lang()];
      ctx.announce(T[`say${name[0].toUpperCase()}${name.slice(1)}`] || "");
      flips.add(name);
      if (name === "zero") setTimeout(() => { if (gname === "zero") ctx.discover("g-zero", { ar: TXT.ar.fZero, en: TXT.en.fZero }); }, 2500);
      if (name === "up") setTimeout(() => { if (gname === "up") ctx.discover("g-ceil", { ar: TXT.ar.fCeil, en: TXT.en.fCeil }); }, 1800);
    }
    ctx.invalidate(800);
  }
  // the phone's tilt: Android just works; iOS asks first, from this button
  let tiltOn = null;
  function onTilt(e) {
    if (e.gamma == null || !tilting) return;
    const gx = clamp(e.gamma / 40, -1.2, 1.2), gz = clamp(((e.beta ?? 60) - 55) / 40, -1.2, 1.2);
    const v = new THREE.Vector3(gx, -1, gz).normalize().multiplyScalar(9.8);
    if (v.distanceToSquared(phys.g) > 0.5) { phys.g.copy(v); phys.wakeAll(); ctx.invalidate(600); }
  }
  async function startTilt() {
    const D = window.DeviceOrientationEvent; if (!D) return;
    try { if (typeof D.requestPermission === "function" && (await D.requestPermission()) !== "granted") return; } catch { return; }
    tilting = true; gname = "tilt"; tiltOn = onTilt; addEventListener("deviceorientation", tiltOn);
    press(Object.values(gbtn), gbtn.tilt); ctx.announce(TXT[ctx.lang()].sayTilt); ctx.sfx("toggleOn");
  }
  function stopTilt() { if (tiltOn) { removeEventListener("deviceorientation", tiltOn); tiltOn = null; } tilting = false; }

  function shake() {
    for (const b of phys.bodies) { b.v.add(new THREE.Vector3(rand(-5, 5), rand(3, 8), rand(-4, 4))); b.w.add(new THREE.Vector3(rand(-8, 8), rand(-8, 8), rand(-8, 8))); b.wake(); }
    ctx.sfx("boom", { f: 60 });
    storm = performance.now();
  }
  let storm = 0;
  function more() {
    if (phys.bodies.length >= cap) { ctx.announce(TXT[ctx.lang()].sayFull); return; }
    const n = Math.min(6, cap - phys.bodies.length);
    for (let k = 0; k < n; k++) addBody(new THREE.Vector3(rand(-5.5, 5.5), 9 - (k % 2) * 1.6, rand(-3.2, 3.2) + (k - n / 2) * 0.2), randQ(), HALVES[Math.floor(rand(HALVES.length))], Math.floor(rand(PALETTE.length)));
    phys.wakeAll(); ctx.sfx("shimmer", { n: 4 });
    if (phys.bodies.length >= cap) moreBtn.disabled = true;
  }
  function reset() {
    phys.bodies.length = 0; cubes.count = 0; glow.fill(0);
    setGravity("down", true);
    rain(start); moreBtn.disabled = false;
    ctx.sfx("whoosh", { dur: 0.6, down: true });
  }

  /* ---------- controls ---------- */
  const tools = makeTools(ctx, TXT);
  const g1 = tools.group("gravity"), gbtn = {};
  for (const [name, icon] of [["down", "down"], ["up", "up"], ["left", "left"], ["right", "right"]]) gbtn[name] = tools.button(g1, { icon, label: name, pressed: gname === name, onClick: () => setGravity(name) });
  gbtn.zero = tools.button(g1, { icon: "zero", text: "zeroT", label: "zero", pressed: gname === "zero", onClick: () => setGravity("zero") });
  if (window.DeviceOrientationEvent && matchMedia("(pointer: coarse)").matches) gbtn.tilt = tools.button(g1, { icon: "tilt", text: "tilt", label: "tiltL", pressed: false, onClick: startTilt });
  const g2 = tools.group("act");
  tools.button(g2, { icon: "shake", text: "shake", onClick: shake });
  const moreBtn = tools.button(g2, { icon: "plus", text: "more", onClick: more });
  tools.button(g2, { icon: "reset", text: "reset", onClick: reset });
  moreBtn.disabled = phys.bodies.length >= cap;
  tools.paint();

  function onKey(e) {
    const k = e.key, rtl = document.documentElement.dir === "rtl";
    const map = { ArrowDown: "down", ArrowUp: "up", ArrowLeft: "left", ArrowRight: "right", PageUp: "back", PageDown: "front" };
    if (map[k]) { setGravity(map[k]); return true; }
    if (k === "z" || k === "Z") { setGravity("zero"); return true; }
    if (k === " " || k === "Enter") { shock(new THREE.Vector3(0, 0, 0), 1.4); return true; }
    if (k === "s" || k === "S") { shake(); return true; }
    void rtl; return false;
  }

  /* ---------- the frame ---------- */
  const up = new THREE.Vector3(0, 1, 0), BIG = 3.6;
  let lastSound = 0;
  function update(dt) {
    phys.events.length = 0;
    phys.step(dt);
    let active = phys.awake() || drag !== null;
    // impacts: light up, a soft ring and a note for the hardest ones
    if (phys.events.length) {
      phys.events.sort((a, b) => b.s - a.s);
      const now = performance.now();
      for (let k = 0; k < Math.min(3, phys.events.length); k++) {
        const ev = phys.events[k]; if (ev.s < BIG) break;
        ctx.count?.("impacts");   // a badge at 100 (cubeverse.js)
        if (!ctx.reduced()) rings.spawn(ev.p, ev.n, new THREE.Color(PALETTE[colorOf[ev.b.idx]][0]), 0.35 + Math.min(1.4, ev.s * 0.1));
        if (k === 0 && now - lastSound > 70) { lastSound = now; if (ev.s > 7) ctx.sfx("pluck", { k: colorOf[ev.b.idx] * 2 + (ev.b.idx % 3), pan: clamp(ev.p.x / 7, -1, 1) }); else ctx.sfx("tick", { k: ev.b.idx }); }
      }
      if (storm && now - storm < 1500 && phys.events.length > 12) { ctx.discover("g-storm", { ar: TXT.ar.fStorm, en: TXT.en.fStorm }); storm = 0; }
    }
    const B = phys.bodies;
    let glowing = false;
    for (let i = 0; i < B.length; i++) {
      const b = B[i];
      if (b.hit) { glow[i] = Math.max(glow[i], Math.min(0.9, b.hit * 0.09)); b.hit = 0; }
      const target = i === hovered && !drag ? 0.16 : 0;
      if (glow[i] > target) { glow[i] = Math.max(target, glow[i] - dt * 2.2); glowing = true; } else glow[i] = target;
      cubes.set(i, b.p, b.q, b.h * 2); cubes.setGlow(i, glow[i]);
    }
    cubes.flush(false);
    active = rings.update(dt) || glowing || active;
    return active;
  }
  function resize(w, h) { camera.aspect = w / h; camera.fov = w / h < 0.8 ? 58 : 42; camera.updateProjectionMatrix(); }
  function save() {
    saved.bodies = phys.bodies.map((b) => ({ p: b.p.toArray(), q: b.q.toArray(), h: b.h, c: colorOf[b.idx], sleep: b.sleep }));
    saved.g = gname; saved.cam = rig.state;
  }
  function dispose() { save(); stopTilt(); rings.dispose(); cubes.dispose(); disposeScene(scene); }
  return { scene, camera, rig, update, resize, onDown, onDrag, onUp, onTap, onHover, onLeave, onKey, save, dispose, paint: () => tools.paint() };
}
