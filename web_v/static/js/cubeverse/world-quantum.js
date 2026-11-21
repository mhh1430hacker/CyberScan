/* World C: Quantum Cubes, an artistic effect inspired by quantum ideas (not a physics simulation).
 * A field of cubes carries waves from sources the visitor drops; the waves interfere. The pointer
 * lifts the cubes near it (more with speed) and fast sweeps leave a wake. Ghost cubes float in
 * several places at once until the pointer comes close or clicks: they collapse into one solid
 * cube, and their entangled partner collapses at the same moment in the complementary colour. */
import { THREE, CubeSet, cubeMaterial, roundedBoxGeometry, gradientTexture, Rings, keyLight, disposeScene, OrbitRig, makeTools, clamp, rand, lerp } from "./core.js";

const TXT = {
  ar: { waves: "الموجات", add: "مصدر موجة", clear: "تهدئة", pause: "إيقاف الموجات", play: "تشغيل الموجات", ghosts: "الأشباح", collapse: "انهيار الكل",
    art: "تأثير فني، لا محاكاة", added: "مصدر موجة جديد", calm: "هدأ الحقل",
    fSpooky: "تأثير عن بُعد", fCoh: "تماسك تام", fStand: "نمط تداخل" },
  en: { waves: "Waves", add: "Wave source", clear: "Calm", pause: "Pause the waves", play: "Play the waves", ghosts: "Ghosts", collapse: "Collapse all",
    art: "Artistic effect, not a simulation", added: "A new wave source", calm: "The field is calm",
    fSpooky: "Spooky action at a distance", fCoh: "Perfect coherence", fStand: "An interference pattern" },
};
const saved = { sources: null, cam: null, frozen: null };
const CYAN = new THREE.Color("#22e8ff"), MAG = new THREE.Color("#ff4fd8"), DEEP = new THREE.Color("#1a1f6e"), WHITE = new THREE.Color("#e9fbff");

export function create(ctx) {
  const { engine } = ctx, tier = engine.tier, reducedAtStart = ctx.reduced();
  const scene = new THREE.Scene();
  scene.background = gradientTexture([[0, "#062430"], [0.5, "#03121a"], [1, "#010508"]]);
  scene.fog = new THREE.Fog(0x020b10, 20, 46);
  scene.environment = engine.env;
  const camera = new THREE.PerspectiveCamera(44, 1, 0.1, 120);
  const rig = new OrbitRig(camera, { target: [0, 0.8, 0], theta: 0.62, phi: 0.98, radius: 15.5, minR: 7, maxR: 30, minPhi: 0.2, maxPhi: 1.4 });
  if (saved.cam) rig.state = saved.cam;
  else if (engine.w / engine.h < 0.8) { rig.goal.radius *= 1.4; rig.snap(); }   // a phone held upright: step back
  scene.add(new THREE.HemisphereLight(0x67e8f9, 0x05030f, 0.45));
  const key = keyLight(engine, { intensity: 1.5, pos: [4, 14, 6], box: 9 }); key.castShadow = key.castShadow && tier === 2; scene.add(key, key.target);
  const pc = new THREE.PointLight(0x22e8ff, 60, 30, 2); pc.position.set(-6, 5, 4); scene.add(pc);
  const pm = new THREE.PointLight(0xff4fd8, 50, 30, 2); pm.position.set(7, 4, -5); scene.add(pm);
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(90, 90), new THREE.MeshStandardMaterial({ color: 0x03141b, roughness: 0.55, metalness: 0.35 }));
  floor.rotation.x = -Math.PI / 2; floor.position.y = -1.1; floor.receiveShadow = true; scene.add(floor);
  const halo = new THREE.Mesh(new THREE.PlaneGeometry(26, 26), new THREE.MeshBasicMaterial({ map: gradientTexture([[0, "rgba(34,232,255,0.32)"], [0.5, "rgba(20,90,140,0.1)"], [1, "rgba(0,0,0,0)"]], { radial: true }), transparent: true, blending: THREE.AdditiveBlending, depthWrite: false }));
  halo.rotation.x = -Math.PI / 2; halo.position.y = -1.09; scene.add(halo);

  /* ---------- the field ---------- */
  const G = tier === 2 ? 18 : tier === 1 ? 14 : 11, SP = 0.62, SZ = 0.44, half = ((G - 1) * SP) / 2;
  const field = new CubeSet(G * G, { geometry: roundedBoxGeometry(0.12, tier === 0 ? 1 : 2), material: cubeMaterial({ physical: tier === 2, roughness: 0.28, metalness: 0.1, envMapIntensity: 1 }), castShadow: tier === 2, receiveShadow: false });
  field.count = G * G; scene.add(field.mesh);
  const lift = new Float32Array(G * G);
  const X = new Float32Array(G * G), Z = new Float32Array(G * G);
  for (let i = 0; i < G; i++) for (let j = 0; j < G; j++) { const k = i * G + j; X[k] = -half + i * SP; Z[k] = -half + j * SP; }

  // sources: two resident ones that never fade, and the visitor's (and the pointer's wake), which do
  let T = 0, frozen = saved.frozen ?? reducedAtStart, idleSince = performance.now();
  const sources = saved.sources ? saved.sources.map((s) => ({ ...s })) : [
    { x: -2.6, z: -1.4, a: 0.5, t0: -40, resident: true },
    { x: 2.4, z: 1.8, a: 0.5, t0: -40, resident: true },
  ];
  const K = 1.55, W = 2.3, C = W / K;
  function height(x, z, t) {
    let h = 0;
    for (const s of sources) {
      const age = t - s.t0; if (age < 0) continue;
      const dx = x - s.x, dz = z - s.z, r = Math.sqrt(dx * dx + dz * dz);
      const front = clamp((C * age - r) * 1.2, 0, 1);               // the ripple spreads from where it was dropped
      const life = s.resident ? 1 : Math.exp(-age / (s.wake ? 2.5 : 22));
      h += s.a * life * front * Math.sin(K * r - W * age) * Math.exp(-r * 0.07);
    }
    return h;
  }
  const rings = new Rings(scene, 10);
  function addSource(x, z, a = 0.55, wake = false) {
    sources.push({ x, z, a, t0: frozen ? T - 20 : T, wake });
    const user = sources.filter((s) => !s.resident && !s.wake);
    if (user.length > 4) sources.splice(sources.indexOf(user[0]), 1);
    const wakes = sources.filter((s) => s.wake); if (wakes.length > 6) sources.splice(sources.indexOf(wakes[0]), 1);
    if (!wake) {
      rings.spawn(new THREE.Vector3(x, 0.4, z), new THREE.Vector3(0, 1, 0), 0x22e8ff, 1.6);
      ctx.sfx("pluck", { k: Math.floor(rand(8)), pan: clamp(x / 6, -1, 1) });
      if (sources.filter((s) => !s.wake).length >= 4) ctx.discover("q-stand", { ar: TXT.ar.fStand, en: TXT.en.fStand });
    }
  }

  /* ---------- ghost cubes in superposition ---------- */
  const NQ = 6, NG = 4;
  const ghostSet = new CubeSet(NQ * NG, { geometry: roundedBoxGeometry(0.12, 1), material: cubeMaterial({ transparent: true, roughness: 0.2, envMapIntensity: 1.2 }) });
  ghostSet.mesh.renderOrder = 2; ghostSet.count = NQ * NG; scene.add(ghostSet.mesh);
  const solid = new CubeSet(NQ, { geometry: roundedBoxGeometry(0.12, 2), material: cubeMaterial({ physical: tier === 2, roughness: 0.18, envMapIntensity: 1.3 }), castShadow: tier === 2 });
  solid.count = NQ; scene.add(solid.mesh);
  const Q = [];
  const centres = [[-3.6, 2.6, -2.2], [3.4, 3.1, 2.4], [-1.2, 3.4, 3.2], [2.2, 2.4, -3.0], [-4.1, 3.0, 1.4], [4.2, 2.7, -0.6]];
  for (let q = 0; q < NQ; q++) {
    const [cx, cy, cz] = centres[q];
    const cand = Array.from({ length: NG }, (_, g) => { const a = (g / NG) * Math.PI * 2 + q; return new THREE.Vector3(cx + Math.cos(a) * 0.95, cy + Math.sin(a * 1.7) * 0.45, cz + Math.sin(a) * 0.95); });
    Q.push({ c: new THREE.Vector3(cx, cy, cz), cand, w: cand.map(() => rand(0.4, 1)), partner: q ^ 1, state: 0, pick: 0, until: 0, col: q % 2 ? MAG : CYAN, mix: 0, ph: rand(6) });
  }
  const lineGeo = new THREE.BufferGeometry(); lineGeo.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(NQ / 2 * 6), 3));
  const lines = new THREE.LineSegments(lineGeo, new THREE.LineBasicMaterial({ color: 0x9be8ff, transparent: true, opacity: 0.22, blending: THREE.AdditiveBlending, depthWrite: false }));
  scene.add(lines);
  let collapsedRun = [];
  function collapse(q, quiet) {
    const a = Q[q]; if (a.state) return;
    const now = performance.now();
    const total = a.w.reduce((s, v) => s + v, 0); let r = rand(total); a.pick = 0;
    for (let g = 0; g < NG; g++) { r -= a.w[g]; if (r <= 0) { a.pick = g; break; } }
    a.state = 1; a.until = now + 5200; a.flash = 1;
    const b = Q[a.partner];
    if (!b.state) {   // the entangled partner answers at once, in the other colour
      b.pick = (a.pick + 2) % NG; b.state = 1; b.until = a.until; b.flash = 1;
      b.col = a.col === CYAN ? MAG : CYAN;
      if (!quiet) ctx.discover("q-spooky", { ar: TXT.ar.fSpooky, en: TXT.en.fSpooky });
    }
    if (!quiet) ctx.sfx("chime");
    collapsedRun = collapsedRun.filter((t) => now - t < 5200); collapsedRun.push(now);
    if (Q.every((x) => x.state)) ctx.discover("q-coh", { ar: TXT.ar.fCoh, en: TXT.en.fCoh });
  }

  /* ---------- pointer ---------- */
  const plane = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0), hp = new THREE.Vector3(), scr = new THREE.Vector3();
  let ptr = null, ptrSpeed = 0, lastWake = 0;
  function onHover(info) {
    idleSince = performance.now();
    const r = engine.ray(info).ray;
    if (r.intersectPlane(plane, hp) && Math.abs(hp.x) < half + 1.5 && Math.abs(hp.z) < half + 1.5) {
      ptr = hp.clone(); ptrSpeed = info.speed;
      if (info.speed > 1100 && performance.now() - lastWake > 220) { lastWake = performance.now(); addSource(hp.x, hp.z, Math.min(0.5, info.speed / 5000), true); }
    } else ptr = null;
    // close to a ghost on the screen: it collapses
    for (let q = 0; q < NQ; q++) {
      if (Q[q].state) continue;
      scr.copy(Q[q].c).project(camera);
      const sx = (scr.x + 1) / 2 * info.w, sy = (1 - scr.y) / 2 * info.h;
      if (Math.hypot(sx - info.x, sy - info.y) < Math.max(46, info.w * 0.04)) collapse(q);
    }
  }
  function onLeave() { ptr = null; }
  function onTap(info) {
    idleSince = performance.now();
    const rc = engine.ray(info);
    const hs = rc.intersectObject(ghostSet.mesh, false)[0];
    if (hs && hs.instanceId != null) { collapse(Math.floor(hs.instanceId / NG)); return; }
    if (rc.ray.intersectPlane(plane, hp) && Math.abs(hp.x) < half + 0.5 && Math.abs(hp.z) < half + 0.5) addSource(hp.x, hp.z);
  }
  function onDown() { idleSince = performance.now(); return false; }
  function onKey(e) {
    if (e.key === " " || e.key === "Enter") { addSource(rand(-half, half) * 0.8, rand(-half, half) * 0.8); return true; }
    if (e.key === "c" || e.key === "C") { for (let q = 0; q < NQ; q++) collapse(q, q > 0); return true; }
    return false;
  }

  /* ---------- controls ---------- */
  const tools = makeTools(ctx, TXT);
  const g1 = tools.group("waves");
  tools.button(g1, { icon: "wave", text: "add", onClick: () => { idleSince = performance.now(); addSource(rand(-half, half) * 0.8, rand(-half, half) * 0.8); ctx.announce(TXT[ctx.lang()].added); } });
  tools.button(g1, { icon: "reset", text: "clear", onClick: () => { sources.length = 0; ctx.announce(TXT[ctx.lang()].calm); ctx.sfx("whoosh", { dur: 0.6, down: true }); } });
  const bPause = tools.button(g1, { icon: frozen ? "play" : "pause", label: frozen ? "play" : "pause", onClick: () => toggleFreeze() });
  const g2 = tools.group("ghosts");
  tools.button(g2, { icon: "collapse", text: "collapse", onClick: () => { for (let q = 0; q < NQ; q++) collapse(q, q > 0); } });
  tools.text(g2, "cv-label").dataset.k = "art";
  const artEl = g2.lastChild;
  const paintTools = () => { tools.paint(); artEl.textContent = TXT[ctx.lang()].art; const l = TXT[ctx.lang()][frozen ? "play" : "pause"]; bPause.setAttribute("aria-label", l); bPause.title = l; };
  function toggleFreeze() {
    frozen = !frozen; idleSince = performance.now();
    bPause.innerHTML = (frozen ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4.5v15l12-7.5z"/></svg>' : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14M16 5v14"/></svg>');
    paintTools(); ctx.sfx(frozen ? "toggleOff" : "toggleOn");
  }
  paintTools();

  /* ---------- the frame ---------- */
  const c1 = new THREE.Color(), c2 = new THREE.Color(), p = new THREE.Vector3(), qq = new THREE.Quaternion(), e = new THREE.Euler();
  let settled = false;
  function update(dt) {
    const now = performance.now(), reduced = ctx.reduced();
    // after a long quiet spell the field comes to rest (and the engine stops drawing)
    const resting = frozen || reduced || now - idleSince > 45000;
    if (!resting) T += dt;
    let moving = !resting;
    // the field
    for (let k = 0; k < G * G; k++) {
      let target = 0;
      if (ptr) { const dx = X[k] - ptr.x, dz = Z[k] - ptr.z; target = Math.exp(-(dx * dx + dz * dz) / 1.6) * (0.35 + Math.min(1.2, ptrSpeed / 1300)); }
      const l = lift[k] + (target - lift[k]) * Math.min(1, dt * 7);
      if (Math.abs(l - lift[k]) > 1e-4) moving = true;
      lift[k] = l;
      const h = height(X[k], Z[k], T), v = clamp(h / 0.8, -1, 1);
      p.set(X[k], h + l, Z[k]);
      e.set(h * 0.25, 0, -h * 0.2); qq.setFromEuler(e);
      field.set(k, p, qq, SZ * (1 + Math.abs(v) * 0.15 + l * 0.2));
      if (v >= 0) c1.copy(DEEP).lerp(CYAN, v); else c1.copy(DEEP).lerp(MAG, -v);
      c1.lerp(WHITE, Math.min(0.6, l * 0.5));
      c2.copy(c1).multiplyScalar(0.35);
      field.colors(k, c1, c2); field.setGlow(k, Math.abs(v) * 0.32 + l * 0.45);
    }
    field.flush(true);
    // the ghosts and the collapsed cubes
    const pos = lineGeo.attributes.position;
    for (let q = 0; q < NQ; q++) {
      const a = Q[q];
      if (a.state && now > a.until) a.state = 0;   // decoherence: back to many places
      a.mix = reduced ? (a.state ? 1 : 0) : a.mix + ((a.state ? 1 : 0) - a.mix) * Math.min(1, dt * 6);
      if (Math.abs(a.mix - (a.state ? 1 : 0)) > 0.002) moving = true;
      if (a.state) moving = true;   // a collapsed cube waits to decohere
      const tt = reduced ? 0 : now / 1000;
      for (let g = 0; g < NG; g++) {
        const i = q * NG + g, cd = a.cand[g];
        p.copy(cd).lerp(a.cand[a.pick], a.mix);
        if (!reduced) { p.x += Math.sin(tt * 1.3 + g + a.ph) * 0.12 * (1 - a.mix); p.y += Math.sin(tt * 1.7 + g * 2 + a.ph) * 0.1 * (1 - a.mix); }
        e.set(tt * 0.6 + g, tt * 0.8 + q, 0); qq.setFromEuler(e);
        ghostSet.set(i, p, qq, 0.62);
        const prob = a.w[g] * (reduced ? 0.8 : 0.65 + 0.35 * Math.sin(tt * 2.2 + g * 1.7 + a.ph));
        ghostSet.setFade(i, clamp(1 - prob * 0.55 - 0.1, 0.25, 0.95) + a.mix * 0.6);
        c1.copy(CYAN).lerp(MAG, g / (NG - 1)); ghostSet.colors(i, c1, c2.copy(c1).multiplyScalar(0.4)); ghostSet.setGlow(i, 0.5);
      }
      p.copy(a.cand[a.pick]);
      a.flash = Math.max(0, (a.flash || 0) - dt * 1.6);
      solid.set(q, p, qq.identity(), 0.62 * (0.2 + a.mix * 0.8) * (a.mix > 0.01 ? 1 : 0));
      solid.colors(q, c1.copy(a.col).lerp(WHITE, 0.25), c2.copy(a.col).multiplyScalar(0.4)); solid.setGlow(q, 0.25 + a.flash);
      if (q % 2 === 0) {   // the thread between partners, while both are undecided
        const b = Q[q + 1], show = 1 - Math.max(a.mix, b.mix);
        pos.setXYZ(q, a.c.x, a.c.y, a.c.z); pos.setXYZ(q + 1, show > 0.05 ? b.c.x : a.c.x, show > 0.05 ? b.c.y : a.c.y, show > 0.05 ? b.c.z : a.c.z);
      }
    }
    pos.needsUpdate = true;
    ghostSet.flush(true); solid.flush(true);
    if (!reduced) moving = rings.update(dt) || moving;
    if (!moving && !settled) settled = true; else if (moving) settled = false;
    return moving;
  }
  function resize(w, h) { camera.aspect = w / h; camera.fov = w / h < 0.8 ? 60 : 44; camera.updateProjectionMatrix(); }
  function save() { saved.sources = sources.filter((s) => !s.wake).map((s) => ({ ...s, t0: s.t0 - T })); saved.cam = rig.state; saved.frozen = frozen; }
  function dispose() { save(); rings.dispose(); field.dispose(); ghostSet.dispose(); solid.dispose(); disposeScene(scene); }
  return { scene, camera, rig, update, resize, onHover, onLeave, onTap, onDown, onKey, save, dispose, paint: paintTools };
}
