/* World E: the Infinite Cube. A cube frame holds a smaller, turned cube frame, which holds another,
 * without end. Zooming is a continuous "depth": every level is k times the next, so when one level
 * grows past the camera the next takes its place, seamlessly, forever (both ways). Each level is a
 * small world of its own: its colour, its turn and a motif (face stones, edge beads, an orbit). */
import { THREE, CubeSet, cubeMaterial, roundedBoxGeometry, gradientTexture, disposeScene, OrbitRig, makeTools, clamp, easeInOut, lerp } from "./core.js";

const TXT = {
  ar: { depth: "العمق", dive: "اغطس", rise: "اصعد", auto: "انجراف تلقائي", autoOn: "إيقاف الانجراف", autoOff: "تشغيل الانجراف", level: "العمق",
    f7: "سبعة عوالم إلى الداخل", fOut: "من الخارج إلى الداخل", f20: "المكعب الذي لا ينتهي" },
  en: { depth: "Depth", dive: "Dive", rise: "Rise", auto: "Drift", autoOn: "Stop the drift", autoOff: "Start the drift", level: "Depth",
    f7: "Seven worlds deep", fOut: "Outside, looking in", f20: "The cube that never ends" },
};
const saved = { z: 0, cam: null, drift: null };
const K = 0.38, BEFORE = 2, AFTER = 6;   // each level is K times its parent; levels drawn around the current depth

export function create(ctx) {
  const { engine } = ctx, tier = engine.tier;
  const scene = new THREE.Scene();
  scene.background = gradientTexture([[0, "#160830"], [0.5, "#08030f"], [1, "#020106"]]);
  scene.environment = engine.env;
  const camera = new THREE.PerspectiveCamera(50, 1, 0.05, 200);
  const rig = new OrbitRig(camera, { target: [0, 0, 0], theta: 0.5, phi: 1.2, radius: 7.2, minR: 7.2, maxR: 7.2, minPhi: 0.25, maxPhi: 2.9, lambda: 6 });
  if (saved.cam) rig.state = saved.cam;
  rig.goal.radius = 7.2;
  scene.add(new THREE.HemisphereLight(0xc9a2ff, 0x05020c, 0.75));
  const kl = new THREE.DirectionalLight(0xffffff, 1.4); kl.position.set(4, 8, 6); scene.add(kl);
  const pc = new THREE.PointLight(0x22e8ff, 30, 30, 2); pc.position.set(-4, 2, 6); scene.add(pc);
  const pmg = new THREE.PointLight(0xff4fd8, 30, 30, 2); pmg.position.set(5, -3, 4); scene.add(pmg);
  // dust far away, for depth
  { const n = tier === 0 ? 220 : 520, a = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) { const u = Math.random() * 2 - 1, t = Math.random() * Math.PI * 2, r = 30 + Math.random() * 40, q = Math.sqrt(1 - u * u); a.set([r * q * Math.cos(t), r * u, r * q * Math.sin(t)], i * 3); }
    const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.BufferAttribute(a, 3));
    scene.add(new THREE.Points(g, new THREE.PointsMaterial({ color: 0xc9a2ff, size: 0.16, transparent: true, opacity: 0.55, depthWrite: false }))); }

  // one level's pieces in its own unit space (the frame spans -1..1)
  const parts = [];
  for (let a = 0; a < 3; a++) for (const u of [-1, 1]) for (const v of [-1, 1]) {   // 12 edges
    const p = [0, 0, 0]; p[(a + 1) % 3] = u; p[(a + 2) % 3] = v;
    const sc = [0.06, 0.06, 0.06]; sc[a] = 2.06;
    parts.push({ p, sc, kind: "edge" });
  }
  for (const x of [-1, 1]) for (const y of [-1, 1]) for (const z of [-1, 1]) parts.push({ p: [x, y, z], sc: [0.22, 0.22, 0.22], kind: "corner" });
  const motifs = [
    [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]].map((p) => ({ p, sc: [0.2, 0.2, 0.2], kind: "face" })),
    parts.filter((q) => q.kind === "edge").map((q) => ({ p: q.p, sc: [0.13, 0.13, 0.13], kind: "bead" })),
    Array.from({ length: 8 }, (_, i) => ({ orbit: (i / 8) * Math.PI * 2, sc: [0.14, 0.14, 0.14], kind: "sat" })),
  ];
  const PER = parts.length + 12, LEVELS = BEFORE + AFTER + 1;
  const set = new CubeSet(PER * LEVELS, { geometry: roundedBoxGeometry(0.16, tier === 0 ? 1 : 2), material: cubeMaterial({ physical: tier === 2, roughness: 0.24, metalness: 0.25, envMapIntensity: 1.2 }) });
  scene.add(set.mesh);
  set.material.userData.u.uBg.value.set("#0a0418");
  const axis = new THREE.Vector3(1, 2.2, 0.6).normalize();
  const qL = new THREE.Quaternion(), q2 = new THREE.Quaternion(), p = new THREE.Vector3(), sc = new THREE.Vector3(), c1 = new THREE.Color(), c2 = new THREE.Color(), c3 = new THREE.Color();
  const levelColor = (n, out, light) => out.setHSL((((0.76 + n * 0.173) % 1) + 1) % 1, 0.82, light);

  let z = saved.z, drift = saved.drift ?? !ctx.reduced(), tween = null, idleSince = performance.now(), hoverLevel = null, spin = 0;
  let maxDepth = Math.floor(z), minDepth = Math.floor(z);
  function dive(dz) {
    const from = z, target = Math.round(z) + dz;
    if (ctx.reduced()) { z = target; tween = null; } else tween = { from, to: target, t: 0 };
    idleSince = performance.now();
    ctx.sfx("whoosh", { dur: 0.6, down: dz < 0 });
  }
  function onWheel(f) { tween = null; z += -Math.log(f) * 1.6; idleSince = performance.now(); return true; }
  function onPinch(f) { return onWheel(f); }
  function onTap(info) {
    const h = engine.ray(info).intersectObject(set.mesh, false)[0];
    if (h) dive(1);
  }
  function onHover(info) {
    idleSince = performance.now();
    const h = engine.ray(info).intersectObject(set.mesh, false)[0];
    hoverLevel = h && h.instanceId != null ? Math.floor(h.instanceId / PER) : null;
    if (!ctx.reduced()) spin += Math.min(0.6, info.speed / 9000);
  }
  function onLeave() { hoverLevel = null; }
  function onDown() { idleSince = performance.now(); return false; }
  function onKey(e) {
    if (e.key === " " || e.key === "Enter" || e.key === "PageDown") { dive(1); return true; }
    if (e.key === "PageUp" || e.key === "Backspace") { dive(-1); return true; }
    if (e.key === "d" || e.key === "D") { toggleDrift(); return true; }
    return false;
  }

  const tools = makeTools(ctx, TXT);
  const g1 = tools.group("depth");
  tools.button(g1, { icon: "rise", text: "rise", onClick: () => dive(-1) });
  tools.button(g1, { icon: "dive", text: "dive", onClick: () => dive(1) });
  const bDrift = tools.button(g1, { icon: "pause", label: "autoOn", onClick: () => toggleDrift() });
  const depthEl = tools.text(g1);
  const paintTools = () => {
    tools.paint();
    bDrift.innerHTML = drift ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14M16 5v14"/></svg>' : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4.5v15l12-7.5z"/></svg>';
    const l = TXT[ctx.lang()][drift ? "autoOn" : "autoOff"]; bDrift.setAttribute("aria-label", l); bDrift.title = l; bDrift.setAttribute("aria-pressed", String(drift));
    depthEl.textContent = `${TXT[ctx.lang()].level} ${Math.floor(z)}`;
  };
  function toggleDrift() { drift = !drift; idleSince = performance.now(); paintTools(); ctx.sfx(drift ? "toggleOn" : "toggleOff"); }
  paintTools();

  let shownDepth = Math.floor(z), lastZ = NaN;
  function update(dt, t) {
    const now = performance.now(), reduced = ctx.reduced();
    let active = false;
    if (tween) {
      tween.t = Math.min(1, tween.t + dt / 1.15);
      z = lerp(tween.from, tween.to, easeInOut(tween.t));
      if (tween.t >= 1) tween = null;
      active = true;
    } else if (drift && !reduced && now - idleSince < 60000) { z += dt * 0.11; active = true; }
    if (spin > 0.001) { spin *= Math.exp(-dt * 1.5); active = true; } else spin = 0;
    const turn = reduced ? 0 : t * 0.05 + spin;
    const zi = Math.floor(z);
    if (zi !== shownDepth) {
      shownDepth = zi; depthEl.textContent = `${TXT[ctx.lang()].level} ${zi}`;
      if (zi > maxDepth) { maxDepth = zi; ctx.sfx("step", { k: ((zi % 12) + 12) % 12 }); }
      minDepth = Math.min(minDepth, zi);
      if (zi >= 7) ctx.discover("i-7", { ar: TXT.ar.f7, en: TXT.en.f7 });
      if (zi >= 20) ctx.discover("i-20", { ar: TXT.ar.f20, en: TXT.en.f20 });
      if (zi <= -2) ctx.discover("i-out", { ar: TXT.ar.fOut, en: TXT.en.fOut });
    }
    if (!active && z === lastZ && hoverLevel === null && !engine.input.active) return false;
    lastZ = z;
    let i = 0;
    for (let L = 0; L < LEVELS; L++) {
      const n = zi - BEFORE + L, s = Math.pow(K, n - z);
      // a level too big to be in front of the camera fades away; a tiny one fades in
      const big = clamp((s - 1.55) / 1.5, 0, 1), tiny = clamp((0.012 - s) / 0.01, 0, 1), fade = Math.max(big, tiny);
      const hidden = s > 3.1 || s < 0.0025;
      qL.setFromAxisAngle(axis, n * 0.62 + turn * (n % 2 ? 1 : -1) * 0.6);
      levelColor(n, c1, 0.74); levelColor(n + 0.5, c2, 0.34);
      const glowBase = hoverLevel === L ? 0.4 : 0;
      const list = parts.concat(motifs[((n % 3) + 3) % 3]);
      for (let k = 0; k < PER; k++) {
        const part = list[k];
        if (!part || hidden) { set.set(i, p.set(0, 0, 0), null, 0); i++; continue; }
        if (part.orbit !== undefined) {
          const a = part.orbit + (reduced ? 0 : t * 0.5 * (n % 2 ? 1 : -1));
          p.set(Math.cos(a) * 1.5, Math.sin(a * 2) * 0.12, Math.sin(a) * 1.5);
        } else p.set(part.p[0], part.p[1], part.p[2]);
        p.applyQuaternion(qL).multiplyScalar(s);
        const thin = 1 - big * 0.97;   // a level passing the camera thins away instead of darkening
        sc.set(part.sc[0] * s * (part.kind === "edge" && part.sc[0] > 1 ? 1 : thin), part.sc[1] * s * (part.sc[1] > 1 ? 1 : thin), part.sc[2] * s * (part.sc[2] > 1 ? 1 : thin));
        q2.copy(qL);
        set.set(i, p, q2, sc);
        if (part.kind === "edge") { set.colors(i, c1, c2); set.setGlow(i, 0.38 + glowBase); }
        else if (part.kind === "corner") { set.colors(i, c3.copy(c1).offsetHSL(0.08, 0, 0.08), c2); set.setGlow(i, 0.2 + glowBase); }
        else { set.colors(i, c3.copy(c2).offsetHSL(-0.1, 0, 0.35), c1); set.setGlow(i, 0.5 + glowBase); }
        set.setFade(i, Math.max(big * 0.35, tiny));
        i++;
      }
    }
    set.count = i; set.flush(true);
    return active || !!tween;
  }
  function resize(w, h) { camera.aspect = w / h; camera.fov = w / h < 0.8 ? 66 : 50; camera.updateProjectionMatrix(); }
  function save() { saved.z = z; saved.cam = rig.state; saved.drift = drift; }
  function dispose() { save(); set.dispose(); disposeScene(scene); }
  return { scene, camera, rig, update, resize, onWheel, onPinch, onTap, onHover, onLeave, onDown, onKey, save, dispose, paint: paintTools };
}
