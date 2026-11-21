/* World D: Dimension Shift. The same cubes seen through a camera that glides between flat 2D (an
 * orthographic look: a long lens far away, the classic dolly zoom) and full 3D perspective, between
 * paper and dusk. From the isometric angle three straight arms close into an impossible triangle;
 * from the front, a perfect flat grid turns out to be scattered through depth; Warp bends space. */
import { THREE, CubeSet, cubeMaterial, roundedBoxGeometry, keyLight, disposeScene, OrbitRig, makeTools, press, clamp, lerp, easeInOut } from "./core.js";

const TXT = {
  ar: { dims: "الأبعاد", slider: "2D ↔ 3D", view: "الزاوية", flat: "مسطح", iso: "متساوي القياس", persp: "منظور", warp: "التواء",
    sayFlat: "منظر مسطح ثنائي الأبعاد", sayIso: "منظر متساوي القياس", sayPersp: "منظور ثلاثي الأبعاد",
    fTri: "المثلث المستحيل", fGrid: "الشبكة المسطحة لم تكن مسطحة", fFold: "المكان ينطوي" },
  en: { dims: "Dimensions", slider: "2D ↔ 3D", view: "View", flat: "Flat", iso: "Isometric", persp: "Perspective", warp: "Warp",
    sayFlat: "Flat 2D view", sayIso: "Isometric view", sayPersp: "3D perspective",
    fTri: "The impossible triangle", fGrid: "The flat grid was never flat", fFold: "Space folds" },
};
const saved = { dim: 0, flat: 0, warp: 0, cam: null, sawFlatGrid: false, first: true };
const ISO_PHI = Math.acos(1 / Math.sqrt(3));
const FOV3D = 42, FOV2D = 1.6;
const PAPER = new THREE.Color("#f3eee4"), DUSK = new THREE.Color("#120f2c");

export function create(ctx) {
  const { engine } = ctx, tier = engine.tier;
  const scene = new THREE.Scene();
  const bg = new THREE.Color(); scene.background = bg;
  scene.fog = new THREE.Fog(0xffffff, 60, 140);
  scene.environment = engine.env;
  const camera = new THREE.PerspectiveCamera(FOV3D, 1, 0.1, 200);
  const rig = new OrbitRig(camera, { target: [0, 2.2, 0], theta: 0.62, phi: 1.02, radius: 22, minR: 10, maxR: 40, minPhi: 0.08, maxPhi: Math.PI / 2 + 0.25, lambda: 6 });
  if (saved.cam) rig.state = saved.cam;
  else { rig.goal.theta = Math.PI / 4 - 0.42; rig.goal.phi = ISO_PHI + 0.08; rig.snap(); }   // first visit: paper, almost the magic angle

  const hemi = new THREE.HemisphereLight(0xffffff, 0xb9b0d0, 1.4); scene.add(hemi);
  const key = keyLight(engine, { intensity: 1.6, pos: [-7, 15, 9], box: 12 }); scene.add(key, key.target);
  const rimC = new THREE.PointLight(0x22e8ff, 0, 40, 2); rimC.position.set(-9, 6, -7); scene.add(rimC);
  const rimM = new THREE.PointLight(0xff4fd8, 0, 40, 2); rimM.position.set(10, 3, -4); scene.add(rimM);
  const floorMat = new THREE.MeshStandardMaterial({ color: 0x17133a, roughness: 0.85, transparent: true });
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(80, 80), floorMat); floor.rotation.x = -Math.PI / 2; floor.position.y = -3.2; floor.receiveShadow = true; scene.add(floor);
  const grid = new THREE.GridHelper(40, 40, 0x6d5bd0, 0x3a2f80); grid.position.y = -3.19; grid.material.transparent = true; grid.material.depthWrite = false; scene.add(grid);

  const mat = cubeMaterial({ warp: true, roughness: 0.4, envMapIntensity: 0.6 });
  const U = mat.userData.u;

  // the impossible triangle: three arms along x, y and z; their ends meet only when seen along (1,1,1)
  const n = 6, tri = [];
  for (let i = 0; i <= n; i++) tri.push([i, 0, 0]);
  for (let j = 1; j <= n; j++) tri.push([n, j, 0]);
  for (let k = 1; k < n; k++) tri.push([n, n, k]);
  const triOff = new THREE.Vector3(-n / 2 - 0.5, -n / 2 + 1.4, -n / 2 + 0.3);
  // the mural: a perfect grid from the front, really scattered through depth
  const MW = 6, MH = 4, mural = [];
  for (let i = 0; i < MW; i++) for (let j = 0; j < MH; j++) {
    const seed = Math.sin(i * 12.9898 + j * 78.233) * 43758.5453, r = seed - Math.floor(seed);
    mural.push([-7.5 + i * 3, -1.4 + j * 2.7, -13 - r * 16]);
  }
  const total = tri.length + mural.length;
  const cubes = new CubeSet(total, { geometry: roundedBoxGeometry(0.06, tier === 0 ? 1 : 2), material: mat, castShadow: true, receiveShadow: true });
  cubes.count = total; scene.add(cubes.mesh);
  const cA = new THREE.Color(), cB = new THREE.Color();
  const hues = [["#c4b5fd", "#6d28d9"], ["#a5f3fc", "#0e7490"], ["#fbcfe8", "#be185d"]];
  tri.forEach((_, i) => { const f = i / (tri.length - 1), seg = Math.min(2, Math.floor(f * 3)), h = hues[seg]; cubes.colors(i, cA.set(h[0]), cB.set(h[1])); });
  mural.forEach((_, i) => { const k = tri.length + i, odd = (Math.floor(i / MH) + (i % MH)) % 2; cubes.colors(k, cA.set(odd ? "#ffffff" : "#ffd7a8"), cB.set(odd ? "#b9b2d6" : "#f0568c")); });

  /* ---------- state: dim (0 flat 2D .. 1 perspective 3D), flat (paper-thin), warp ---------- */
  let dim = saved.dim, flat = saved.flat, warp = saved.warp;
  let tween = null;   // { from:{dim,flat}, to:{dim,flat}, t }
  let glowTri = 0, sawFlatGrid = saved.sawFlatGrid;
  function to(view) {
    const V = {
      flat: { theta: 0, phi: Math.PI / 2, dim: 0, flat: 1, say: "sayFlat" },
      iso: { theta: Math.PI / 4, phi: ISO_PHI, dim: 0, flat: 0, say: "sayIso" },
      persp: { theta: 0.62, phi: 1.02, dim: 1, flat: 0, say: "sayPersp" },
    }[view];
    rig.goal.theta = nearestAngle(rig.goal.theta, V.theta); rig.goal.phi = V.phi; rig.goal.radius = camera.aspect < 0.8 ? 30 : 22; rig.goalTarget.set(0, 2.2, 0);
    rig.vel = 0; rig.velPhi = 0;
    if (ctx.reduced()) { dim = V.dim; flat = V.flat; rig.snap(); }
    else tween = { from: { dim, flat }, to: { dim: V.dim, flat: V.flat }, t: 0 };
    press(viewBtns, vb[view]);
    ctx.announce(TXT[ctx.lang()][V.say]);
    ctx.sfx(view === "persp" ? "rise" : "tab");
  }
  const nearestAngle = (from, a) => a + Math.round((from - a) / (Math.PI * 2)) * Math.PI * 2;

  /* ---------- controls ---------- */
  const tools = makeTools(ctx, TXT);
  const g1 = tools.group("dims");
  const sl = tools.range(g1, { label: "slider", min: 0, max: 1, step: 0.01, value: dim, onInput: (v) => { tween = null; dim = v; if (v > 0.1) flat = Math.min(flat, 1 - v); press(viewBtns, null); } });
  const g2 = tools.group("view"), vb = {};
  vb.flat = tools.button(g2, { icon: "flat", text: "flat", pressed: false, onClick: () => to("flat") });
  vb.iso = tools.button(g2, { icon: "iso", text: "iso", pressed: false, onClick: () => to("iso") });
  vb.persp = tools.button(g2, { icon: "persp", text: "persp", pressed: false, onClick: () => to("persp") });
  const viewBtns = Object.values(vb);
  const g3 = tools.group(null);
  const wl = tools.range(g3, { label: "warp", min: 0, max: 1, step: 0.01, value: warp, onInput: (v) => { warp = v; if (v > 0.92) ctx.discover("d-fold", { ar: TXT.ar.fFold, en: TXT.en.fFold }); } });
  tools.paint();

  function onKey(e) {
    if (e.key === "1" && e.shiftKey) return false;
    if (e.key === "f" || e.key === "F") { to("flat"); return true; }
    if (e.key === "i" || e.key === "I") { to("iso"); return true; }
    if (e.key === "p" || e.key === "P") { to("persp"); return true; }
    if (e.key === "[") { dim = clamp(dim - 0.1, 0, 1); sl.value = String(dim); return true; }
    if (e.key === "]") { dim = clamp(dim + 0.1, 0, 1); sl.value = String(dim); return true; }
    return false;
  }
  let tapAt = 0;
  function onTap() { tapAt = performance.now(); ctx.sfx("soft"); }

  /* ---------- the frame ---------- */
  const p = new THREE.Vector3(), s = new THREE.Vector3(), dir = new THREE.Vector3(), magic = new THREE.Vector3(1, 1, 1).normalize();
  let tone = "", lastDim = -1, lastWarp = -1, lastFlat = -1;
  function update(dt, t) {
    let active = false;
    if (tween) {
      tween.t = Math.min(1, tween.t + dt / 1.3);
      const k = easeInOut(tween.t);
      dim = lerp(tween.from.dim, tween.to.dim, k); flat = lerp(tween.from.flat, tween.to.flat, k);
      sl.value = String(dim.toFixed(2));
      if (tween.t >= 1) tween = null;
      active = true;
    }
    const d = easeInOut(clamp(dim, 0, 1));
    // the dolly zoom: a narrower lens, further away, the same framing
    const fov = lerp(FOV2D, FOV3D, d), base = rig.cur.radius;
    const r = base * Math.tan((FOV3D * Math.PI) / 360) / Math.tan((fov * Math.PI) / 360);
    dir.subVectors(camera.position, rig.target).normalize();
    camera.position.copy(rig.target).addScaledVector(dir, r);
    camera.fov = fov; camera.near = Math.max(0.1, r - 60); camera.far = r + 80; camera.updateProjectionMatrix();
    camera.lookAt(rig.target);
    // paper to dusk
    bg.copy(PAPER).lerp(DUSK, d); scene.fog.color.copy(bg); scene.fog.near = r + 10; scene.fog.far = r + 90;
    U.uBg.value.copy(bg);
    hemi.intensity = lerp(1.6, 0.55, d); hemi.groundColor.set(0xb9b0d0).lerp(new THREE.Color(0x0b0820), d);
    key.intensity = lerp(1.4, 2.3, d); rimC.intensity = 70 * d; rimM.intensity = 55 * d;
    floorMat.opacity = d; floor.visible = d > 0.02; grid.material.opacity = d * 0.5; grid.visible = d > 0.02;
    const nextTone = d < 0.5 ? "light" : "dark";
    if (nextTone !== tone) { tone = nextTone; ctx.setTone(tone); }
    // warp
    U.uWarp.value = warp; U.uTwist.value = warp * 1.1;
    if (warp > 0.001 && !ctx.reduced()) { U.uTime.value = t; active = true; }
    // the cubes (flattened toward paper in Flat)
    const fl = clamp(flat, 0, 1);
    const sel = performance.now() - tapAt < 400 ? 0.2 : 0;
    camera.getWorldDirection(dir);
    const align = -dir.dot(magic);   // 1 when looking straight down (1,1,1)
    const triOn = align > 0.9975 && d < 0.08;
    glowTri += ((triOn ? 0.55 : 0) - glowTri) * Math.min(1, dt * 5);
    if (Math.abs(glowTri - (triOn ? 0.55 : 0)) > 0.01) active = true;
    if (triOn && glowTri > 0.3) ctx.discover("d-tri", { ar: TXT.ar.fTri, en: TXT.en.fTri });
    if (d < 0.05 && fl > 0.9 && Math.abs(rig.cur.theta % (Math.PI * 2)) < 0.05) sawFlatGrid = true;
    if (sawFlatGrid && d > 0.9) { ctx.discover("d-grid", { ar: TXT.ar.fGrid, en: TXT.en.fGrid }); sawFlatGrid = false; }
    if (d !== lastDim || fl !== lastFlat || warp !== lastWarp || active) {
      tri.forEach(([x, y, z], i) => {
        p.set(x, y, z).add(triOff);
        s.set(0.98, 0.98, lerp(0.98, 0.06, fl));
        cubes.set(i, p, null, s); cubes.setGlow(i, glowTri + sel);
      });
      mural.forEach(([x, y, z], i) => {
        p.set(x, y, lerp(z, -9, fl * 0.0));
        s.set(1.2, 1.2, lerp(1.2, 0.06, fl));
        cubes.set(tri.length + i, p, null, s); cubes.setGlow(tri.length + i, sel * 0.5);
      });
      cubes.flush(false);
      lastDim = d; lastFlat = fl; lastWarp = warp;
    }
    return active || sel > 0;
  }
  function resize(w, h) { camera.aspect = w / h; camera.updateProjectionMatrix(); rig.lim.maxR = w / h < 0.8 ? 46 : 40; if (w / h < 0.8 && rig.goal.radius < 30) { rig.goal.radius = 30; } }
  function save() { saved.dim = dim; saved.flat = flat; saved.warp = warp; saved.cam = rig.state; saved.sawFlatGrid = sawFlatGrid; }
  function dispose() { save(); cubes.dispose(); disposeScene(scene); }
  void wl;
  return { scene, camera, rig, update, resize, onKey, onTap, save, dispose, paint: () => tools.paint() };
}
