/* World B: Cube Architecture. A bright studio with a 12 x 12 grid: place cubes on the floor or on any
 * face, remove them, choose colours and sizes, orbit freely. Five shapes hide a geometric figure
 * that lights up when built (a tower, stairs, a gate, a well, a cube of cubes). The build is kept
 * for the visit (memory and sessionStorage). */
import { THREE, CubeSet, cubeMaterial, roundedBoxGeometry, gradientTexture, keyLight, disposeScene, OrbitRig, makeTools, press, clamp } from "./core.js";

const N = 12, HMAX = 10;
const PALETTE = [["#e3d2ff", "#7c3aed"], ["#c4f7ff", "#0891b2"], ["#ffc6f3", "#c026d3"], ["#ffffff", "#c6c0dc"], ["#ffdcae", "#ef5a8a"], ["#7a74a8", "#1e1b3a"]];
const SIZES = [0.94, 0.7, 0.46];
const TXT = {
  ar: { tool: "الأداة", build: "ابنِ", erase: "امسح", color: "اللون", size: "الحجم", L: "كبير", M: "متوسط", S: "صغير", sizeL: "مكعب كبير", sizeM: "مكعب متوسط", sizeS: "مكعب صغير",
    edit: "تعديل", undo: "تراجع", clear: "مسح الكل", sure: "متأكد؟", shapes: "الأشكال", full: "الاستوديو ممتلئ", placed: "وُضع مكعب", removed: "أُزيل مكعب", cleared: "مُسح البناء",
    c0: "بنفسجي", c1: "سماوي", c2: "وردي", c3: "لؤلؤي", c4: "غروب", c5: "حبر",
    tower: "المسلّة", stairs: "درج إلى اللامكان", gate: "البوابة", well: "بئر الأمنيات", meta: "المكعب الفائق (تسراكت)",
    share: "مشاركة", link: "رابط", image: "صورة", linkLabel: "انسخ رابطًا لهذا البناء", imageLabel: "احفظ البناء صورةً PNG",
    linkCopied: "نُسخ رابط البناء", linkFail: "تعذّر نسخ الرابط", saved: "حُفظت الصورة", empty: "ابنِ شيئًا أولًا", loaded: "فُتح البناء المشارك ({n} مكعب)", shareTitle: "بنائي في عالم المكعبات" },
  en: { tool: "Tool", build: "Build", erase: "Erase", color: "Colour", size: "Size", L: "L", M: "M", S: "S", sizeL: "Large cube", sizeM: "Medium cube", sizeS: "Small cube",
    edit: "Edit", undo: "Undo", clear: "Clear", sure: "Sure?", shapes: "Shapes", full: "The studio is full", placed: "Cube placed", removed: "Cube removed", cleared: "Build cleared",
    c0: "Violet", c1: "Cyan", c2: "Magenta", c3: "Pearl", c4: "Sunset", c5: "Ink",
    tower: "The Obelisk", stairs: "Stairs to Nowhere", gate: "The Portal", well: "The Wishing Well", meta: "The Tesseract",
    share: "Share", link: "Link", image: "Image", linkLabel: "Copy a link to this build", imageLabel: "Save the build as a PNG image",
    linkCopied: "Link to the build copied", linkFail: "The link could not be copied", saved: "Image saved", empty: "Build something first", loaded: "Shared build opened ({n} cubes)", shareTitle: "My build in the Cubeverse" },
};
const KEY = (x, y, z) => x + z * N + y * N * N;
const XYZ = (k) => [k % N, Math.floor(k / (N * N)), Math.floor((k % (N * N)) / N)];
const saved = { vox: null, cam: null, tool: "build", color: 0, size: 0, found: [] };
/* a build as a link: "#build=" + base64url of 2 bytes per cube (cell 11 bits, colour 3, size 2), after a version byte */
const b64u = (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export function encodeBuild(list) {
  const u8 = new Uint8Array(1 + list.length * 2); u8[0] = 1;
  list.forEach(([k, c, s], i) => { const v = (k & 0x7ff) | ((c & 7) << 11) | ((s & 3) << 14); u8[1 + i * 2] = v & 255; u8[2 + i * 2] = v >> 8; });
  return b64u(u8);
}
export function decodeBuild(str) {
  try {
    const bin = atob(String(str).replace(/-/g, "+").replace(/_/g, "/"));
    if (bin.charCodeAt(0) !== 1 || bin.length > 1 + 640 * 2) return null;
    const out = [], seen = new Set();
    for (let i = 1; i + 1 < bin.length; i += 2) {
      const v = bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8), k = v & 0x7ff, c = (v >> 11) & 7, s = (v >> 14) & 3;
      if (k >= N * N * HMAX || c >= PALETTE.length || s >= SIZES.length || seen.has(k)) continue;
      seen.add(k); out.push([k, c, s]);
    }
    return out;
  } catch { return null; }
}
function sharedFromHash() {
  const m = /^#build=([A-Za-z0-9_-]{3,1800})$/.exec(location.hash || "");
  if (!m) return null;
  const list = decodeBuild(m[1]);
  try { history.replaceState(null, "", location.pathname + location.search); } catch { /* keep the hash */ }
  return list && list.length ? list : null;
}
function loadSession() {
  if (saved.vox) return;
  try { const s = JSON.parse(sessionStorage.getItem("cv-arch") || "null"); if (s && Array.isArray(s.v)) { saved.vox = s.v; saved.found = s.found || []; } } catch { /* storage off */ }
}

export function create(ctx) {
  const { engine } = ctx, tier = engine.tier;
  loadSession();
  const shared = sharedFromHash();
  if (shared) { saved.vox = shared; saved.found = saved.found || []; }
  const scene = new THREE.Scene();
  scene.background = gradientTexture([[0, "#fbfaff"], [0.55, "#ece9f6"], [1, "#d9d4ea"]]);
  scene.fog = new THREE.Fog(0xe8e5f2, 34, 80);
  scene.environment = engine.env;
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 160);
  const rig = new OrbitRig(camera, { target: [0, 1.4, 0], theta: 0.78, phi: 0.98, radius: 21, minR: 7, maxR: 38, minPhi: 0.18, maxPhi: 1.42 });
  if (saved.cam) rig.state = saved.cam;
  else if (engine.w / engine.h < 0.8) { rig.goal.radius *= 1.38; rig.snap(); }   // a phone held upright: step back

  scene.add(new THREE.HemisphereLight(0xffffff, 0xc9c0e6, 1.25));
  const key = keyLight(engine, { intensity: 2.1, pos: [-8, 16, 9], box: 10, bias: -0.0006 }); scene.add(key, key.target);
  const fill = new THREE.DirectionalLight(0xe8e0ff, 0.55); fill.position.set(9, 6, -6); scene.add(fill);

  // the studio: a soft floor, a raised white board with a fine grid
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(120, 120), new THREE.MeshStandardMaterial({ color: 0xe6e2f1, roughness: 1 }));
  floor.rotation.x = -Math.PI / 2; floor.position.y = -0.2; floor.receiveShadow = true; scene.add(floor);
  const board = new THREE.Mesh(new THREE.BoxGeometry(N + 0.6, 0.2, N + 0.6), new THREE.MeshStandardMaterial({ color: 0xfbfaff, roughness: 0.75 }));
  board.position.y = -0.1; board.receiveShadow = true; scene.add(board);
  const grid = new THREE.GridHelper(N, N, 0xc4bbe0, 0xd9d3ea); grid.position.y = 0.004; grid.material.transparent = true; grid.material.opacity = 0.9; scene.add(grid);

  const cap = tier === 0 ? 320 : 640;
  const cubes = new CubeSet(cap, { geometry: roundedBoxGeometry(0.08, tier === 0 ? 1 : 2), material: cubeMaterial({ physical: tier === 2, roughness: 0.42, clearcoat: 0.4, envMapIntensity: 0.55 }), castShadow: true, receiveShadow: true });
  scene.add(cubes.mesh);

  // the marker (ghost cube) where the next cube goes, or the cube that would be removed
  const ghostMat = new THREE.MeshStandardMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.28, depthWrite: false, roughness: 0.5 });
  const ghost = new THREE.Mesh(new THREE.BoxGeometry(1, 1, 1), ghostMat);
  const ghostEdge = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(1.02, 1.02, 1.02)), new THREE.LineBasicMaterial({ color: 0x6d28d9, transparent: true, opacity: 0.8 }));
  ghost.add(ghostEdge); ghost.visible = false; scene.add(ghost);

  /* ---------- the build ---------- */
  const vox = new Map();   // key -> { c, s }
  if (saved.vox) for (const [k, c, s] of saved.vox) vox.set(k, { c, s });
  else for (const [x, y, z, c] of [[5, 0, 5, 0], [6, 0, 5, 1], [5, 0, 6, 3], [5, 1, 5, 2]]) vox.set(KEY(x, y, z), { c, s: 0 });
  const found = new Set(saved.found);
  let tool = saved.tool, color = saved.color, size = saved.size;
  const undo = [];
  const anim = new Map();   // key -> { t, dir, c, s }  (appear: dir 1, vanish: dir -1)
  let order = [];           // instance index -> key
  const glowOf = new Map(); // key -> glow until (ms)
  const c1 = new THREE.Color(), c2 = new THREE.Color(), pos = new THREE.Vector3();
  let dirty = true;
  const cellPos = (x, y, z, s) => pos.set(x - N / 2 + 0.5, y + SIZES[s] / 2 + (s ? 0 : 0.03), z - N / 2 + 0.5);
  function rebuild(now) {
    order = [];
    let i = 0;
    const draw = (k, v, scale) => {
      if (i >= cap) return;
      const [x, y, z] = XYZ(k);
      cellPos(x, y, z, v.s);
      cubes.set(i, pos, null, SIZES[v.s] * scale);
      const p = PALETTE[v.c]; cubes.colors(i, c1.set(p[0]), c2.set(p[1]));
      const g = glowOf.get(k); cubes.setGlow(i, g && g > now ? 0.35 + 0.25 * Math.sin(now / 120) : 0);
      order[i++] = k;
    };
    for (const [k, v] of vox) { const a = anim.get(k); draw(k, v, a ? easeBack(a.t) : 1); }
    for (const [k, a] of anim) if (a.dir < 0) draw(k, a, 1 - a.t * a.t);
    cubes.count = i; cubes.flush(true);
  }
  const easeBack = (t) => { const c = 1.9; return 1 + (c + 1) * Math.pow(t - 1, 3) + c * Math.pow(t - 1, 2); };
  let store = 0;
  function persist() {
    saved.vox = [...vox].map(([k, v]) => [k, v.c, v.s]); saved.found = [...found];
    clearTimeout(store);
    store = setTimeout(() => { try { sessionStorage.setItem("cv-arch", JSON.stringify({ v: saved.vox, found: saved.found })); } catch { /* storage off */ } }, 300);
  }
  function place(k, quiet) {
    if (vox.has(k)) return false;
    if (vox.size >= cap) { ctx.announce(TXT[ctx.lang()].full); return false; }
    const v = { c: color, s: size };
    vox.set(k, v); undo.push({ add: k, v }); if (undo.length > 300) undo.shift();
    if (!ctx.reduced()) anim.set(k, { t: 0, dir: 1 });
    dirty = true; persist(); check(k);
    if (!quiet) ctx.sfx("pluck", { k: XYZ(k)[1] + color });
    return true;
  }
  function remove(k) {
    const v = vox.get(k); if (!v) return false;
    vox.delete(k); undo.push({ del: k, v });
    if (!ctx.reduced()) anim.set(k, { t: 0, dir: -1, c: v.c, s: v.s });
    dirty = true; persist(); check(-1);
    ctx.sfx("tick", { k: 3 });
    return true;
  }
  function doUndo() {
    const u = undo.pop(); if (!u) return;
    if (u.add !== undefined) { vox.delete(u.add); anim.delete(u.add); }
    else { vox.set(u.del, u.v); if (!ctx.reduced()) anim.set(u.del, { t: 0, dir: 1 }); }
    dirty = true; persist(); check(-1); ctx.sfx("tab");
  }
  let clearArmed = 0;
  function doClear(b) {
    if (!vox.size) return;
    if (performance.now() - clearArmed > 3000) { clearArmed = performance.now(); b.querySelector("span").textContent = TXT[ctx.lang()].sure; setTimeout(() => tools.paint(), 3000); return; }
    clearArmed = 0;
    if (!ctx.reduced()) for (const [k, v] of vox) anim.set(k, { t: 0, dir: -1, c: v.c, s: v.s });
    vox.clear(); undo.length = 0; dirty = true; persist(); check(-1);
    tools.paint(); ctx.sfx("whoosh", { dur: 0.5, down: true }); ctx.announce(TXT[ctx.lang()].cleared);
  }

  /* ---------- hidden figures ---------- */
  const has = (x, y, z) => x >= 0 && z >= 0 && x < N && z < N && y >= 0 && vox.has(KEY(x, y, z));
  const colH = (x, z) => { let y = 0; while (y < HMAX && has(x, y, z)) y++; return y; };
  function findShapes() {
    const out = {};
    for (let x = 0; x < N; x++) for (let z = 0; z < N; z++) {
      const hh = colH(x, z);
      if (hh >= 5 && !out.tower) out.tower = { at: [x, hh, z], cells: Array.from({ length: hh }, (_, y) => [x, y, z]) };
      if (hh === 1 && !out.stairs) for (const [dx, dz] of [[1, 0], [0, 1], [-1, 0], [0, -1]]) {
        if (colH(x + dx, z + dz) === 2 && colH(x + 2 * dx, z + 2 * dz) === 3 && colH(x + 3 * dx, z + 3 * dz) === 4) {
          const cells = []; for (let s = 0; s < 4; s++) for (let y = 0; y <= s; y++) cells.push([x + s * dx, y, z + s * dz]);
          out.stairs = { at: [x + 3 * dx, 4, z + 3 * dz], cells }; break;
        }
      }
      if (!out.gate) for (const [dx, dz] of [[1, 0], [0, 1]]) {
        const ok = has(x, 0, z) && has(x, 1, z) && has(x + 2 * dx, 0, z + 2 * dz) && has(x + 2 * dx, 1, z + 2 * dz) && has(x, 2, z) && has(x + dx, 2, z + dz) && has(x + 2 * dx, 2, z + 2 * dz) && !has(x + dx, 0, z + dz) && !has(x + dx, 1, z + dz);
        if (ok) { out.gate = { at: [x + dx, 1, z + dz], dir: dx ? "x" : "z", cells: [[x, 0, z], [x, 1, z], [x + 2 * dx, 0, z + 2 * dz], [x + 2 * dx, 1, z + 2 * dz], [x, 2, z], [x + dx, 2, z + dz], [x + 2 * dx, 2, z + 2 * dz]] }; break; }
      }
      if (!out.well && x + 2 < N && z + 2 < N && !has(x + 1, 0, z + 1)) {
        const ring = [[0, 0], [1, 0], [2, 0], [0, 1], [2, 1], [0, 2], [1, 2], [2, 2]];
        if (ring.every(([a, b]) => has(x + a, 0, z + b))) out.well = { at: [x + 1, 0, z + 1], cells: ring.map(([a, b]) => [x + a, 0, z + b]) };
      }
    }
    if (!out.meta) for (const k of vox.keys()) {
      const [x, y, z] = XYZ(k); let ok = true; const cells = [];
      for (let a = 0; a < 2 && ok; a++) for (let b = 0; b < 2 && ok; b++) for (let c = 0; c < 2 && ok; c++) { if (!has(x + a, y + b, z + c)) ok = false; cells.push([x + a, y + b, z + c]); }
      if (ok) { out.meta = { at: [x + 0.5, y + 2, z + 0.5], cells }; break; }
    }
    return out;
  }
  const figures = {};
  const neon = (color, opacity = 0.9) => new THREE.MeshBasicMaterial({ color, transparent: true, opacity, blending: THREE.NormalBlending, depthWrite: false });
  function figure(name) {
    if (figures[name]) return figures[name];
    const g = new THREE.Group();
    if (name === "tower") {
      const m = new THREE.Mesh(new THREE.OctahedronGeometry(0.9, 0), new THREE.MeshStandardMaterial({ color: 0xffffff, emissive: 0x8b5cf6, emissiveIntensity: 0.55, roughness: 0.2, metalness: 0.1, flatShading: true }));
      m.castShadow = true; g.add(m);
      g.add(new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.OctahedronGeometry(1.25, 0)), new THREE.LineBasicMaterial({ color: 0x7c3aed })));
    } else if (name === "stairs") {
      for (let i = 0; i < 9; i++) {
        const c = new THREE.Mesh(new THREE.BoxGeometry(0.26, 0.26, 0.26), new THREE.MeshStandardMaterial({ color: new THREE.Color().setHSL(0.75 - i * 0.05, 0.7, 0.62), emissive: 0x5b21b6, emissiveIntensity: 0.25 }));
        c.position.set(Math.cos(i * 0.8) * 0.9, i * 0.28, Math.sin(i * 0.8) * 0.9); c.castShadow = true; g.add(c);
      }
    } else if (name === "gate") {
      g.add(new THREE.Mesh(new THREE.TorusGeometry(0.62, 0.06, 12, 48), neon(0x0891b2, 0.95)));
      const disc = new THREE.Mesh(new THREE.CircleGeometry(0.58, 48), new THREE.MeshBasicMaterial({ map: gradientTexture([[0, "rgba(255,255,255,.95)"], [0.4, "rgba(103,232,249,.7)"], [1, "rgba(124,58,237,.15)"]], { radial: true, size: 128 }), transparent: true, depthWrite: false, side: THREE.DoubleSide }));
      g.add(disc);
    } else if (name === "well") {
      const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.34, 0.42, 5, 32, 1, true), new THREE.MeshBasicMaterial({ map: gradientTexture([[0, "rgba(255,255,255,0)"], [0.6, "rgba(196,181,253,.35)"], [1, "rgba(236,72,153,.7)"]], { size: 128 }), transparent: true, depthWrite: false, side: THREE.DoubleSide }));
      beam.position.y = 2.5; g.add(beam);
      for (let i = 0; i < 6; i++) { const c = new THREE.Mesh(new THREE.BoxGeometry(0.16, 0.16, 0.16), neon(0xc026d3, 0.85)); c.position.set(Math.cos(i) * 0.5, 0.8 + i * 0.6, Math.sin(i) * 0.5); g.add(c); }
    } else if (name === "meta") {
      const m1 = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(1.6, 1.6, 1.6)), new THREE.LineBasicMaterial({ color: 0x6d28d9 }));
      const m2 = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(0.8, 0.8, 0.8)), new THREE.LineBasicMaterial({ color: 0xc026d3 }));
      const pts = []; for (const sx of [-1, 1]) for (const sy of [-1, 1]) for (const sz of [-1, 1]) pts.push(sx * 0.8, sy * 0.8, sz * 0.8, sx * 0.4, sy * 0.4, sz * 0.4);
      const lg = new THREE.BufferGeometry(); lg.setAttribute("position", new THREE.Float32BufferAttribute(pts, 3));
      g.add(m1, m2, new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0x0891b2 })));
    }
    g.visible = false; g.userData.born = 0; scene.add(g);
    return (figures[name] = g);
  }
  let shapes = {}, figuresAlive = 0;
  function check(changed) {
    shapes = findShapes();
    const now = performance.now();
    for (const name of ["tower", "stairs", "gate", "well", "meta"]) {
      const s = shapes[name];
      if (!s) { if (figures[name]) figures[name].visible = false; continue; }
      const f = figure(name), [x, y, z] = s.at;
      f.position.set(x - N / 2 + 0.5, y + (name === "gate" ? 0.5 : name === "well" ? 0 : name === "tower" ? 1.75 : 1.1), z - N / 2 + 0.5);
      if (name === "gate") f.rotation.y = s.dir === "x" ? 0 : Math.PI / 2;
      const isNew = !f.visible; f.visible = true;
      if (isNew) {
        f.userData.born = now; figuresAlive = now + 6000;
        for (const [a, b, c] of s.cells) glowOf.set(KEY(a, b, c), now + 2200);
        if (!found.has(name)) { found.add(name); persist(); }
        if (found.size >= 5) ctx.achieve?.("shapes");
        if (changed >= 0) ctx.discover(`a-${name}`, { ar: TXT.ar[name], en: TXT.en[name] });
        dirty = true;
      }
    }
    countEl.textContent = `${TXT[ctx.lang()].shapes} ${found.size}/5`;
  }

  /* ---------- pointer and keys ---------- */
  const plane0 = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0), hp = new THREE.Vector3();
  const inGrid = (x, y, z) => x >= 0 && z >= 0 && x < N && z < N && y >= 0 && y < HMAX;
  // where the pointer points: the cube under it (and the face), or the floor cell
  function target(info) {
    const rc = engine.ray(info);
    const h = rc.intersectObject(cubes.mesh, false)[0];
    if (h && h.instanceId != null && order[h.instanceId] !== undefined && vox.has(order[h.instanceId])) {
      const k = order[h.instanceId], [x, y, z] = XYZ(k);
      const n = h.face.normal, ax = Math.abs(n.x), ay = Math.abs(n.y), az = Math.abs(n.z);
      const d = ax > ay && ax > az ? [Math.sign(n.x), 0, 0] : ay > az ? [0, Math.sign(n.y), 0] : [0, 0, Math.sign(n.z)];
      return { hit: k, cell: inGrid(x + d[0], y + d[1], z + d[2]) ? KEY(x + d[0], y + d[1], z + d[2]) : -1 };
    }
    if (rc.ray.intersectPlane(plane0, hp)) {
      const x = Math.floor(hp.x + N / 2), z = Math.floor(hp.z + N / 2);
      if (inGrid(x, 0, z)) return { hit: -1, cell: has(x, 0, z) ? -1 : KEY(x, 0, z) };
    }
    return null;
  }
  function showGhost(k, erase) {
    if (k < 0 || k === undefined) { ghost.visible = false; return; }
    const v = erase ? vox.get(k) : { s: size };
    if (!v) { ghost.visible = false; return; }
    const [x, y, z] = XYZ(k);
    ghost.position.copy(cellPos(x, y, z, v.s)); ghost.scale.setScalar(SIZES[v.s] * (erase ? 1.06 : 1));
    ghostMat.color.set(erase ? 0xef4444 : PALETTE[color][1]); ghostEdge.material.color.set(erase ? 0xb91c1c : PALETTE[color][1]);
    ghostMat.opacity = erase ? 0.35 : 0.3;
    ghost.visible = true;
  }
  let kb = null;   // the keyboard marker: a column
  function onHover(info) {
    kb = null;
    const t = target(info);
    if (!t) { ghost.visible = false; return; }
    if (tool === "erase") showGhost(t.hit, true); else showGhost(t.cell, false);
  }
  function act(info, erase) {
    const t = target(info); if (!t) return;
    if (erase) { if (t.hit >= 0) remove(t.hit); }
    else if (t.cell >= 0) place(t.cell);
    onHover(info);
  }
  function onTap(info) { act(info, tool === "erase" || info.button === 2 || info.shift || info.alt); }
  function onLongPress(info) { act(info, true); if (navigator.vibrate) try { navigator.vibrate(12); } catch { /* none */ } }
  function onLeave() { if (!kb) ghost.visible = false; }
  function columnTop(x, z) { let y = HMAX - 1; while (y >= 0 && !has(x, y, z)) y--; return y; }
  function showKb() { const top = columnTop(kb[0], kb[1]); if (tool === "erase") showGhost(top >= 0 ? KEY(kb[0], top, kb[1]) : -1, true); else showGhost(top + 1 < HMAX ? KEY(kb[0], top + 1, kb[1]) : -1, false); }
  function onKey(e) {
    const k = e.key;
    const moves = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    if (moves[k]) {
      if (!kb) kb = [5, 5];
      // the marker moves the way the camera looks
      const th = rig.cur.theta, [mx, mz] = moves[k];
      const fx = -Math.sin(th), fz = -Math.cos(th), rx = Math.cos(th), rz = -Math.sin(th);
      const dx = mx * rx - mz * fx, dz = mx * rz - mz * fz;
      const sx = Math.abs(dx) > Math.abs(dz) ? Math.sign(dx) : 0, sz = sx ? 0 : Math.sign(dz);
      kb = [clamp(kb[0] + sx, 0, N - 1), clamp(kb[1] + sz, 0, N - 1)];
      showKb(); ctx.sfx("tick", { k: kb[0] + kb[1] }); return true;
    }
    if (k === "Enter" || k === " ") { if (!kb) kb = [5, 5]; const top = columnTop(kb[0], kb[1]); if (tool === "erase") { if (top >= 0) remove(KEY(kb[0], top, kb[1])); } else if (top + 1 < HMAX) place(KEY(kb[0], top + 1, kb[1])); showKb(); return true; }
    if (k === "Delete" || k === "Backspace") { if (!kb) kb = [5, 5]; const top = columnTop(kb[0], kb[1]); if (top >= 0) remove(KEY(kb[0], top, kb[1])); showKb(); return true; }
    if ((k === "z" || k === "Z") && (e.ctrlKey || e.metaKey)) { doUndo(); return true; }
    return false;
  }

  /* ---------- controls ---------- */
  const tools = makeTools(ctx, TXT);
  const g1 = tools.group("tool");
  const bBuild = tools.button(g1, { icon: "build", text: "build", pressed: tool === "build", onClick: () => { tool = "build"; press([bBuild, bErase], bBuild); ghost.visible = false; } });
  const bErase = tools.button(g1, { icon: "erase", text: "erase", pressed: tool === "erase", onClick: () => { tool = "erase"; press([bBuild, bErase], bErase); ghost.visible = false; } });
  const g2 = tools.group("color");
  const sw = PALETTE.map(([a, b], i) => tools.button(g2, { cls: "cv-swatch", label: `c${i}`, pressed: i === color, style: { background: `linear-gradient(135deg, ${a}, ${b})` },
    onClick: (e, btn) => { color = i; press(sw, btn); if (tool !== "build") bBuild.click(); ctx.sfx("soft"); } }));
  const g3 = tools.group("size");
  const sz = ["L", "M", "S"].map((n, i) => tools.button(g3, { text: n, label: `size${n}`, pressed: i === size, onClick: (e, btn) => { size = i; press(sz, btn); ctx.sfx("soft"); } }));
  const g4 = tools.group("edit");
  tools.button(g4, { icon: "undo", text: "undo", onClick: doUndo });
  tools.button(g4, { icon: "trash", text: "clear", onClick: (e, b) => doClear(b) });
  const countEl = tools.text(g4);
  const g5 = tools.group("share");
  tools.button(g5, { icon: "link", text: "link", label: "linkLabel", onClick: shareLink });
  tools.button(g5, { icon: "image", text: "image", label: "imageLabel", onClick: saveImage });
  tools.paint();
  check(-1);

  /* ---------- save and share ---------- */
  async function shareLink() {
    const t = TXT[ctx.lang()];
    if (!vox.size) { ctx.announce(t.empty); return; }
    const url = `${location.origin}${location.pathname}#build=${encodeBuild([...vox].map(([k, v]) => [k, v.c, v.s]))}`;
    if (navigator.share && matchMedia("(pointer: coarse)").matches) {
      try { await navigator.share({ title: t.shareTitle, url }); ctx.sfx("chime"); return; } catch (e) { if (e && e.name === "AbortError") return; }
    }
    let ok = false;
    try { await navigator.clipboard.writeText(url); ok = true; } catch {
      const ta = document.createElement("textarea"); ta.value = url; ta.setAttribute("readonly", ""); document.body.append(ta); ta.select();
      try { ok = document.execCommand("copy"); } catch { /* refused */ } ta.remove();
    }
    ctx.announce(ok ? t.linkCopied : t.linkFail); ctx.toast?.(ok ? t.linkCopied : t.linkFail); ctx.sfx(ok ? "chime" : "tick");
  }
  function saveImage() {
    const t = TXT[ctx.lang()];
    if (!vox.size) { ctx.announce(t.empty); return; }
    ghost.visible = false;
    engine.renderer.render(scene, camera);                  // read the frame in the same task it was drawn (no preserved buffer)
    const url = engine.renderer.domElement.toDataURL("image/png");
    const a = document.createElement("a"); a.href = url; a.download = `cubeverse-build-${new Date().toISOString().slice(0, 10)}.png`;
    document.body.append(a); a.click(); a.remove();
    ctx.announce(t.saved); ctx.toast?.(t.saved); ctx.sfx("shimmer", { n: 3 });
  }
  if (shared) setTimeout(() => { ctx.announce(TXT[ctx.lang()].loaded.replace("{n}", String(vox.size))); ctx.toast?.(TXT[ctx.lang()].loaded.replace("{n}", String(vox.size))); }, 900);

  /* ---------- the frame ---------- */
  let lastT = 0;
  function update(dt, t) {
    const now = performance.now();
    if (anim.size) {
      for (const [k, a] of anim) { a.t = Math.min(1, a.t + dt * (a.dir > 0 ? 3.6 : 4.5)); if (a.t >= 1) anim.delete(k); }
      dirty = true;
    }
    let glowing = false;
    for (const [k, g] of glowOf) { if (g > now) glowing = true; else glowOf.delete(k); }
    if (glowing) dirty = true;
    if (dirty) { rebuild(now); dirty = glowing || anim.size > 0; }
    // the figures turn for a few seconds after they appear, then rest
    const alive = now < figuresAlive && !ctx.reduced();
    if (alive) for (const f of Object.values(figures)) if (f.visible) { f.rotation.y += dt * 0.9; if (f.children.length === 9) f.rotation.y += dt * 0.6; }
    lastT = t;
    return anim.size > 0 || glowing || alive;
  }
  function resize(w, h) { camera.aspect = w / h; camera.fov = w / h < 0.8 ? 56 : 40; camera.updateProjectionMatrix(); }
  function save() { saved.cam = rig.state; saved.tool = tool; saved.color = color; saved.size = size; persist(); }
  function dispose() { save(); cubes.dispose(); disposeScene(scene); }
  return { scene, camera, rig, update, resize, onTap, onLongPress, onHover, onLeave, onKey, save, dispose, paint: () => { tools.paint(); check(-1); } };
}
