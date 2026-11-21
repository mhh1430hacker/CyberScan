/* The Cubeverse engine: one renderer and one canvas shared by every world, rendering only when
 * something moves (zero frames at rest), adaptive resolution, a small orbit camera, unified
 * pointer / touch / keyboard input, and the gradient cube material every world draws with.
 * Three.js comes from the vendored module (no CDN, no build step). */
import * as THREE from "../../vendor/three/three.module.min.js";

export { THREE };
export const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);
export const lerp = (a, b, t) => a + (b - a) * t;
export const damp = (a, b, lambda, dt) => lerp(a, b, 1 - Math.exp(-lambda * dt));
export const smooth = (t) => t * t * (3 - 2 * t);
export const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
export const rand = (a = 1, b) => (b === undefined ? Math.random() * a : a + Math.random() * (b - a));
export const col = (hex) => new THREE.Color(hex);

/* ---------------- quality: what this device can comfortably draw ---------------- */
export function qualityTier(gl) {
  const cores = navigator.hardwareConcurrency || 4, mem = navigator.deviceMemory || 4;
  const small = Math.min(screen.width, screen.height) < 520;
  const coarse = matchMedia("(pointer: coarse)").matches;
  let tier = 2;
  if (cores <= 4 || mem <= 3 || (coarse && small)) tier = 1;
  if (cores <= 2 || mem <= 2) tier = 0;
  try {   // a software renderer (no GPU) can draw only the lightest version
    const ext = gl && gl.getExtension("WEBGL_debug_renderer_info");
    const name = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : "";
    if (/swiftshader|llvmpipe|software|basic render/i.test(name)) tier = 0;
  } catch { /* no info */ }
  return tier;
}

/* ---------------- geometry: a cube with softly rounded edges ----------------
 * A box whose edge rows are bent around a radius r, with analytic normals: smooth highlights on the
 * edges, flat faces, few vertices (k segments per rounded edge). */
export function roundedBoxGeometry(r = 0.08, k = 2) {
  const n = 2 * k + 1, g = new THREE.BoxGeometry(1, 1, 1, n, n, n);
  const pos = g.attributes.position, nor = g.attributes.normal, inner = 0.5 - r;
  const map = (u) => {
    const i = Math.round((u + 0.5) * n);
    if (i <= k) return -inner - r * Math.tan((Math.PI / 4) * (k - i) / k);
    if (i >= n - k) return inner + r * Math.tan((Math.PI / 4) * (i - (n - k)) / k);
    return -inner + (2 * inner) * (i - k) / (n - 2 * k);
  };
  const c = new THREE.Vector3(), cl = new THREE.Vector3(), d = new THREE.Vector3();
  for (let i = 0; i < pos.count; i++) {
    c.set(map(pos.getX(i)), map(pos.getY(i)), map(pos.getZ(i)));
    cl.set(clamp(c.x, -inner, inner), clamp(c.y, -inner, inner), clamp(c.z, -inner, inner));
    d.subVectors(c, cl);
    const len = d.length();
    if (len < 1e-6) continue;
    d.divideScalar(len);
    pos.setXYZ(i, cl.x + d.x * r, cl.y + d.y * r, cl.z + d.z * r);
    nor.setXYZ(i, d.x, d.y, d.z);
  }
  g.deleteAttribute("uv");
  g.computeBoundingSphere(); g.computeBoundingBox();
  return g;
}

/* ---------------- the cube material ----------------
 * A standard (or physical, on capable devices) material patched to read per-instance attributes:
 * aC1/aC2 a two-colour gradient across the cube, aGlow an emissive pulse, aFade a fade toward the
 * background (opaque) or toward transparent (ghosts). Optional warp: the Dimension Shift world bends
 * space in the vertex shader. */
const WARP_GLSL = `uniform float uWarp; uniform float uTwist; uniform float uTime;
vec3 cvWarp(vec3 p) {
  float a = uTwist * p.y * 0.22;
  float s = sin(a), c = cos(a);
  p.xz = mat2(c, -s, s, c) * p.xz;
  p.y += uWarp * 0.9 * sin(p.x * 0.55 + uTime * 0.6) * cos(p.z * 0.45 - uTime * 0.4);
  p.x += uWarp * 0.35 * sin(p.y * 0.7 + uTime * 0.5);
  return p;
}`;
const PROJECT_WARP = `vec4 mvPosition = vec4( transformed, 1.0 );
#ifdef USE_INSTANCING
mvPosition = instanceMatrix * mvPosition;
#endif
vec4 cvW = modelMatrix * mvPosition;
cvW.xyz = cvWarp(cvW.xyz);
mvPosition = viewMatrix * cvW;
gl_Position = projectionMatrix * mvPosition;`;
export function cubeMaterial(opts = {}) {
  const { physical = false, transparent = false, roughness = 0.36, metalness = 0.04, clearcoat = 0.6, envMapIntensity = 0.8, warp = false, side = THREE.FrontSide } = opts;
  const M = physical ? THREE.MeshPhysicalMaterial : THREE.MeshStandardMaterial;
  const m = new M({ color: 0xffffff, roughness, metalness, transparent, depthWrite: !transparent, envMapIntensity, side });
  if (physical) { m.clearcoat = clearcoat; m.clearcoatRoughness = 0.22; }
  const u = { uBg: { value: new THREE.Color(0) }, uWarp: { value: 0 }, uTwist: { value: 0 }, uTime: { value: 0 } };
  m.userData.u = u;
  m.onBeforeCompile = (sh) => {
    Object.assign(sh.uniforms, u);
    sh.vertexShader = sh.vertexShader
      .replace("#include <common>", `#include <common>
attribute vec3 aC1; attribute vec3 aC2; attribute float aGlow; attribute float aFade;
varying vec3 vCv; varying float vGlow; varying float vFade;
${warp ? WARP_GLSL : ""}`)
      .replace("#include <begin_vertex>", `#include <begin_vertex>
float cvT = clamp(0.5 + position.y * 0.95 + (position.x - position.z) * 0.2, 0.0, 1.0);
vCv = mix(aC2, aC1, cvT); vGlow = aGlow; vFade = aFade;`);
    if (warp) sh.vertexShader = sh.vertexShader.replace("#include <project_vertex>", PROJECT_WARP);
    sh.fragmentShader = sh.fragmentShader
      .replace("#include <common>", `#include <common>
varying vec3 vCv; varying float vGlow; varying float vFade; uniform vec3 uBg;`)
      .replace("#include <color_fragment>", `#include <color_fragment>
diffuseColor.rgb *= vCv;${transparent ? "\ndiffuseColor.a *= 1.0 - vFade;" : ""}`)
      .replace("#include <emissivemap_fragment>", `#include <emissivemap_fragment>
totalEmissiveRadiance += vCv * vGlow;`)
      .replace("#include <fog_fragment>", `#include <fog_fragment>${transparent ? "" : "\ngl_FragColor.rgb = mix(gl_FragColor.rgb, uBg, vFade);"}`);
  };
  m.customProgramCacheKey = () => `cv-${warp ? "w" : ""}${physical ? "p" : ""}${transparent ? "t" : ""}`;
  return m;
}

/* ---------------- a set of cubes drawn in one call ---------------- */
const _m4 = new THREE.Matrix4(), _q = new THREE.Quaternion(), _s = new THREE.Vector3(), _p = new THREE.Vector3();
export class CubeSet {
  constructor(capacity, { geometry, material, castShadow = false, receiveShadow = false } = {}) {
    const base = geometry || roundedBoxGeometry();
    const g = new THREE.BufferGeometry();
    for (const [k, a] of Object.entries(base.attributes)) g.setAttribute(k, a);
    g.setIndex(base.index);
    g.boundingSphere = base.boundingSphere; g.boundingBox = base.boundingBox;
    this.c1 = new THREE.InstancedBufferAttribute(new Float32Array(capacity * 3).fill(1), 3);
    this.c2 = new THREE.InstancedBufferAttribute(new Float32Array(capacity * 3).fill(1), 3);
    this.glow = new THREE.InstancedBufferAttribute(new Float32Array(capacity), 1);
    this.fade = new THREE.InstancedBufferAttribute(new Float32Array(capacity), 1);
    for (const a of [this.c1, this.c2, this.glow, this.fade]) a.setUsage(THREE.DynamicDrawUsage);
    g.setAttribute("aC1", this.c1); g.setAttribute("aC2", this.c2); g.setAttribute("aGlow", this.glow); g.setAttribute("aFade", this.fade);
    this.geometry = g; this.ownBase = !geometry ? base : null;
    this.material = material || cubeMaterial();
    this.mesh = new THREE.InstancedMesh(g, this.material, capacity);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.castShadow = castShadow; this.mesh.receiveShadow = receiveShadow;
    this.mesh.frustumCulled = false;
    this.capacity = capacity; this.mesh.count = 0;
  }
  set count(n) { this.mesh.count = Math.min(n, this.capacity); }
  get count() { return this.mesh.count; }
  set(i, pos, quat, scale) {
    if (typeof scale === "number") _s.set(scale, scale, scale); else _s.copy(scale);
    _m4.compose(pos, quat || _q.identity(), _s);
    this.mesh.setMatrixAt(i, _m4);
  }
  setXYZ(i, x, y, z, quat, scale) { _p.set(x, y, z); this.set(i, _p, quat, scale); }
  colors(i, a, b) { this.c1.setXYZ(i, a.r, a.g, a.b); this.c2.setXYZ(i, b.r, b.g, b.b); }
  setGlow(i, v) { this.glow.setX(i, v); }
  setFade(i, v) { this.fade.setX(i, v); }
  flush(colors = true) {
    this.mesh.instanceMatrix.needsUpdate = true;
    this.glow.needsUpdate = true; this.fade.needsUpdate = true;
    if (colors) { this.c1.needsUpdate = true; this.c2.needsUpdate = true; }
  }
  dispose() { this.geometry.dispose(); this.ownBase?.dispose(); this.material.dispose(); this.mesh.dispose?.(); }
}

/* ---------------- small helpers worlds share ---------------- */
export function gradientTexture(stops, { radial = false, size = 256 } = {}) {
  const c = document.createElement("canvas"); c.width = radial ? size : 4; c.height = size;
  const x = c.getContext("2d");
  const g = radial ? x.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2) : x.createLinearGradient(0, 0, 0, size);
  for (const [o, s] of stops) g.addColorStop(o, s);
  x.fillStyle = g; x.fillRect(0, 0, c.width, c.height);
  const t = new THREE.CanvasTexture(c); t.colorSpace = THREE.SRGBColorSpace;
  return t;
}
// soft impact rings: a small pool of additive rings that grow and fade
export class Rings {
  constructor(scene, n = 10) {
    this.geo = new THREE.RingGeometry(0.82, 1, 48);
    this.items = [];
    for (let i = 0; i < n; i++) {
      const m = new THREE.Mesh(this.geo, new THREE.MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide }));
      m.visible = false; scene.add(m); this.items.push({ m, life: 0, size: 1 });
    }
    this.next = 0;
  }
  spawn(pos, normal, color, size = 1) {
    const it = this.items[this.next++ % this.items.length];
    it.m.position.copy(pos); it.m.lookAt(_p.copy(pos).add(normal));
    it.m.material.color.set(color); it.life = 1; it.size = size; it.m.visible = true;
  }
  update(dt) {
    let any = false;
    for (const it of this.items) {
      if (it.life <= 0) continue;
      it.life -= dt * 1.8; any = true;
      if (it.life <= 0) { it.m.visible = false; continue; }
      const k = 1 - it.life; it.m.scale.setScalar(it.size * (0.2 + k * 1.4)); it.m.material.opacity = it.life * it.life * 0.85;
    }
    return any;
  }
  dispose() { this.geo.dispose(); for (const it of this.items) { it.m.material.dispose(); it.m.removeFromParent(); } }
}
// dispose everything a scene holds (geometries, materials, textures)
export function disposeScene(scene) {
  scene.traverse((o) => {
    if (o.geometry) o.geometry.dispose();
    const mats = Array.isArray(o.material) ? o.material : o.material ? [o.material] : [];
    for (const m of mats) { for (const v of Object.values(m)) if (v && v.isTexture) v.dispose(); m.dispose(); }
  });
  if (scene.background && scene.background.isTexture) scene.background.dispose();
}

/* ---------------- an orbit camera (drag, wheel, pinch, keys) with inertia ---------------- */
export class OrbitRig {
  constructor(camera, o = {}) {
    this.camera = camera;
    this.target = new THREE.Vector3(...(o.target || [0, 0, 0]));
    this.goalTarget = this.target.clone();
    this.goal = { theta: o.theta ?? 0.5, phi: o.phi ?? 1.05, radius: o.radius ?? 14 };
    this.cur = { ...this.goal };
    this.lim = { minR: o.minR ?? 4, maxR: o.maxR ?? 40, minPhi: o.minPhi ?? 0.2, maxPhi: o.maxPhi ?? 1.5, minTheta: o.minTheta ?? -Infinity, maxTheta: o.maxTheta ?? Infinity };
    this.vel = 0; this.velPhi = 0; this.dragging = false; this.auto = 0;
    this.lambda = o.lambda ?? 9;
    this.apply();
  }
  rotate(dx, dy) {
    const k = 0.0058;
    this.goal.theta = clamp(this.goal.theta - dx * k, this.lim.minTheta, this.lim.maxTheta);
    this.goal.phi = clamp(this.goal.phi - dy * k, this.lim.minPhi, this.lim.maxPhi);
    this.vel = -dx * k * 30; this.velPhi = -dy * k * 30;
  }
  zoom(f) { this.goal.radius = clamp(this.goal.radius * f, this.lim.minR, this.lim.maxR); }
  update(dt) {
    if (!this.dragging) {
      if (Math.abs(this.vel) > 1e-4 || Math.abs(this.velPhi) > 1e-4) {
        this.goal.theta = clamp(this.goal.theta + this.vel * dt, this.lim.minTheta, this.lim.maxTheta);
        this.goal.phi = clamp(this.goal.phi + this.velPhi * dt, this.lim.minPhi, this.lim.maxPhi);
        const k = Math.exp(-5 * dt); this.vel *= k; this.velPhi *= k;
        if (Math.abs(this.vel) < 1e-3) this.vel = 0;
        if (Math.abs(this.velPhi) < 1e-3) this.velPhi = 0;
      }
    }
    if (this.auto) this.goal.theta += this.auto * dt;
    const c = this.cur, g = this.goal;
    const moving = Math.abs(c.theta - g.theta) > 1e-4 || Math.abs(c.phi - g.phi) > 1e-4 || Math.abs(c.radius - g.radius) > 1e-3 || this.target.distanceToSquared(this.goalTarget) > 1e-7 || this.vel !== 0 || this.velPhi !== 0 || this.auto !== 0;
    if (!moving) return false;
    c.theta = damp(c.theta, g.theta, this.lambda, dt); c.phi = damp(c.phi, g.phi, this.lambda, dt); c.radius = damp(c.radius, g.radius, this.lambda, dt);
    this.target.lerp(this.goalTarget, 1 - Math.exp(-this.lambda * dt));
    this.apply();
    return true;
  }
  apply() {
    const c = this.cur, s = Math.sin(c.phi);
    this.camera.position.set(this.target.x + c.radius * s * Math.sin(c.theta), this.target.y + c.radius * Math.cos(c.phi), this.target.z + c.radius * s * Math.cos(c.theta));
    this.camera.lookAt(this.target);
  }
  snap() { Object.assign(this.cur, this.goal); this.target.copy(this.goalTarget); this.apply(); }
  get state() { return { ...this.goal, target: this.goalTarget.toArray() }; }
  set state(s) { if (!s) return; Object.assign(this.goal, { theta: s.theta, phi: s.phi, radius: s.radius }); if (s.target) this.goalTarget.fromArray(s.target); this.snap(); }
}

/* ---------------- input: pointers, touch gestures, wheel and keys on the canvas ---------------- */
class Input {
  constructor(engine) {
    this.e = engine; this.ptrs = new Map(); this.mode = ""; this.gest = null; this.hover = { x: 0, y: 0, t: 0, vx: 0, vy: 0 };
    const c = engine.canvas;
    c.addEventListener("pointerdown", (ev) => this.down(ev));
    c.addEventListener("pointermove", (ev) => this.move(ev));
    c.addEventListener("pointerup", (ev) => this.up(ev, false));
    c.addEventListener("pointercancel", (ev) => this.up(ev, true));
    c.addEventListener("pointerleave", () => { if (!this.ptrs.size) this.e.world?.onLeave?.(); });
    c.addEventListener("wheel", (ev) => this.wheel(ev), { passive: false });
    c.addEventListener("contextmenu", (ev) => ev.preventDefault());
    c.addEventListener("keydown", (ev) => this.key(ev));
  }
  get active() { return this.ptrs.size > 0; }
  info(ev, p) {
    const r = this.e.canvas.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
    return { x, y, w: r.width, h: r.height, ndc: new THREE.Vector2((x / r.width) * 2 - 1, -(y / r.height) * 2 + 1), vx: p ? p.vx : this.hover.vx, vy: p ? p.vy : this.hover.vy,
      speed: p ? Math.hypot(p.vx, p.vy) : Math.hypot(this.hover.vx, this.hover.vy), button: ev.button, type: ev.pointerType, shift: ev.shiftKey, alt: ev.altKey || ev.ctrlKey || ev.metaKey, id: ev.pointerId };
  }
  track(p, ev) {
    const now = performance.now(), dt = Math.max(1, now - p.t);
    const k = Math.min(1, dt / 60);
    p.vx = p.vx * (1 - k) + ((ev.clientX - p.x) / dt) * 1000 * k; p.vy = p.vy * (1 - k) + ((ev.clientY - p.y) / dt) * 1000 * k;
    p.dx = ev.clientX - p.x; p.dy = ev.clientY - p.y; p.x = ev.clientX; p.y = ev.clientY; p.t = now;
  }
  down(ev) {
    const w = this.e.world; if (!w) return;
    this.e.canvas.focus({ preventScroll: true });
    try { this.e.canvas.setPointerCapture(ev.pointerId); } catch { /* not capturable */ }
    const p = { x: ev.clientX, y: ev.clientY, sx: ev.clientX, sy: ev.clientY, t: performance.now(), t0: performance.now(), vx: 0, vy: 0, dx: 0, dy: 0, moved: false, cap: false };
    this.ptrs.set(ev.pointerId, p);
    this.e.invalidate(300);
    if (this.ptrs.size === 1) {
      this.multi = false;
      p.cap = ev.button === 2 ? false : w.onDown?.(this.info(ev, p)) === true;
      this.mode = p.cap ? "world" : "orbit";
      if (!p.cap && w.rig) w.rig.dragging = true;
      clearTimeout(this.lp);
      if (ev.pointerType !== "mouse") this.lp = setTimeout(() => { if (!p.moved && this.ptrs.size === 1 && !p.cap) { p.long = true; w.onLongPress?.(this.info(ev, p)); this.e.invalidate(300); } }, 520);
    } else if (this.ptrs.size === 2) {
      clearTimeout(this.lp);
      for (const q of this.ptrs.values()) if (q.cap) { q.cap = false; w.onUp?.(this.info(ev, q), true); }
      this.multi = true; this.mode = "gesture"; this.gest = this.pair();
      if (w.rig) w.rig.dragging = true;
    }
  }
  pair() { const [a, b] = [...this.ptrs.values()]; return { d: Math.hypot(a.x - b.x, a.y - b.y), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }; }
  move(ev) {
    const w = this.e.world; if (!w) return;
    const p = this.ptrs.get(ev.pointerId);
    if (!p) {   // hover (mouse / pen)
      const h = this.hover, now = performance.now(), dt = Math.max(1, now - h.t), k = Math.min(1, dt / 60);
      if (h.t) { h.vx = h.vx * (1 - k) + ((ev.clientX - h.x) / dt) * 1000 * k; h.vy = h.vy * (1 - k) + ((ev.clientY - h.y) / dt) * 1000 * k; }
      h.x = ev.clientX; h.y = ev.clientY; h.t = now;
      if (w.onHover) { w.onHover(this.info(ev, null)); this.e.invalidate(200); }
      return;
    }
    this.track(p, ev);
    if (!p.moved && Math.hypot(p.x - p.sx, p.y - p.sy) > 6) { p.moved = true; clearTimeout(this.lp); }
    this.e.invalidate(300);
    if (this.mode === "gesture" && this.ptrs.size >= 2) {
      const g = this.pair(), r = w.rig;
      if (r && this.gest) {
        if (g.d > 0 && this.gest.d > 0) { const f = this.gest.d / g.d; if (w.onPinch?.(f) !== true) r.zoom(f); }
        r.rotate((g.x - this.gest.x) * 0.9, (g.y - this.gest.y) * 0.9);
      }
      this.gest = g;
      return;
    }
    if (p.cap) { w.onDrag?.(this.info(ev, p)); return; }
    if (this.mode === "orbit" && p.moved && w.rig && !this.multi) {
      if (w.onOrbitDrag?.(this.info(ev, p), p.dx, p.dy) === true) return;
      w.rig.rotate(p.dx, p.dy);
    }
  }
  up(ev, cancel) {
    const w = this.e.world, p = this.ptrs.get(ev.pointerId);
    if (!p) return;
    this.ptrs.delete(ev.pointerId); clearTimeout(this.lp);
    try { this.e.canvas.releasePointerCapture(ev.pointerId); } catch { /* released */ }
    this.e.invalidate(400);
    if (!w) return;
    const inf = this.info(ev, p);
    if (p.cap) w.onUp?.(inf, cancel);
    else if (!cancel && !p.moved && !p.long && !this.multi && performance.now() - p.t0 < 650) w.onTap?.(inf);
    if (!this.ptrs.size) { this.mode = ""; this.gest = null; if (w.rig) w.rig.dragging = false; }
    else if (this.ptrs.size === 1) this.gest = null;
  }
  wheel(ev) {
    const w = this.e.world; if (!w) return;
    ev.preventDefault();
    const d = clamp(ev.deltaMode === 1 ? ev.deltaY * 16 : ev.deltaY, -240, 240), f = Math.exp(d * 0.0012);
    if (w.onWheel?.(f, ev) !== true && w.rig) w.rig.zoom(f);
    this.e.invalidate(500);
  }
  key(ev) {
    const w = this.e.world; if (!w || ev.target !== this.e.canvas) return;
    if (w.onKey?.(ev) === true) { ev.preventDefault(); this.e.invalidate(500); return; }
    const r = w.rig; if (!r) return;
    const k = ev.key;
    const step = 0.14 * (document.documentElement.dir === "rtl" && (k === "ArrowLeft" || k === "ArrowRight") ? -1 : 1);
    let used = true;
    if (k === "ArrowLeft" || k === "q" || k === "Q") r.goal.theta -= step;
    else if (k === "ArrowRight" || k === "e" || k === "E") r.goal.theta += step;
    else if (k === "ArrowUp") r.goal.phi = clamp(r.goal.phi - 0.1, r.lim.minPhi, r.lim.maxPhi);
    else if (k === "ArrowDown") r.goal.phi = clamp(r.goal.phi + 0.1, r.lim.minPhi, r.lim.maxPhi);
    else if (k === "+" || k === "=") { if (w.onWheel?.(0.85) !== true) r.zoom(0.85); }
    else if (k === "-" || k === "_") { if (w.onWheel?.(1.18) !== true) r.zoom(1.18); }
    else used = false;
    if (used) { ev.preventDefault(); r.goal.theta = clamp(r.goal.theta, r.lim.minTheta, r.lim.maxTheta); this.e.invalidate(600); }
  }
}

/* ---------------- an image-based light, made once: a dim room with three soft panels ---------------- */
function studioEnvironment(renderer) {
  const pm = new THREE.PMREMGenerator(renderer), s = new THREE.Scene();
  const geos = [], mats = [];
  const add = (geo, mat, f) => { geos.push(geo); mats.push(mat); const m = new THREE.Mesh(geo, mat); f(m); s.add(m); };
  add(new THREE.BoxGeometry(20, 20, 20), new THREE.MeshBasicMaterial({ color: 0x15112a, side: THREE.BackSide }), () => {});
  const panel = (hex, k, pos, w, h) => add(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ color: new THREE.Color(hex).multiplyScalar(k), side: THREE.DoubleSide }), (m) => { m.position.set(...pos); m.lookAt(0, 0, 0); });
  panel(0xffffff, 5, [0, 9.5, 2], 12, 8);
  panel(0xd9c4ff, 2.6, [-9.5, 2, 3], 6, 9);
  panel(0x9ff6ff, 2.4, [9.5, 1, -2], 6, 9);
  panel(0xffb3f0, 1.2, [0, 1, -9.5], 10, 4);
  const rt = pm.fromScene(s, 0.035);
  geos.forEach((g) => g.dispose()); mats.forEach((m) => m.dispose()); pm.dispose();
  return rt;
}

/* ---------------- the engine ---------------- */
export class Engine {
  constructor(canvas) {
    this.canvas = canvas;
    // a throwaway context tells what the device is (three.js needs WebGL 2)
    const probeCanvas = document.createElement("canvas"), probe = probeCanvas.getContext("webgl2");
    if (!probe) throw new Error("no webgl2");
    this.tier = qualityTier(probe);
    probe.getExtension("WEBGL_lose_context")?.loseContext();
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: this.tier >= 1, powerPreference: "high-performance", stencil: false });
    const r = this.renderer;
    r.outputColorSpace = THREE.SRGBColorSpace;
    r.toneMapping = THREE.ACESFilmicToneMapping; r.toneMappingExposure = 1.05;
    r.shadowMap.enabled = this.tier >= 1; r.shadowMap.type = THREE.PCFSoftShadowMap;
    this.shadowSize = this.tier === 2 ? 2048 : 1024;
    this.maxDpr = Math.min(devicePixelRatio || 1, this.tier === 2 ? 2 : this.tier === 1 ? 1.5 : 1);
    this.dpr = this.maxDpr; this.dprAt = 0;
    this.envRT = this.tier >= 1 ? studioEnvironment(r) : null;
    this.env = this.envRT ? this.envRT.texture : null;
    this.world = null; this.paused = new Set(); this.running = false; this.until = 0; this.last = 0;
    this.stats = { dts: [], cpu: [], frames: 0 };
    this.input = new Input(this);
    this.ro = new ResizeObserver(() => { this.resize(); this.invalidate(100); });
    this.ro.observe(canvas);
    this.onVis = () => { if (document.hidden) this.pause("hidden"); else this.resume("hidden"); };
    document.addEventListener("visibilitychange", this.onVis);
    this.resize();
  }
  get reduced() { return matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion"); }
  resize() {
    const w = Math.max(1, this.canvas.clientWidth), h = Math.max(1, this.canvas.clientHeight);
    this.w = w; this.h = h;
    this.renderer.setPixelRatio(this.dpr);
    this.renderer.setSize(w, h, false);
    this.world?.resize?.(w, h);
  }
  setWorld(world) { this.world = world; this.stats.dts.length = 0; this.stats.cpu.length = 0; if (world) { this.resize(); this.invalidate(500); } }
  invalidate(ms = 0) { this.until = Math.max(this.until, performance.now() + ms); this.kick(); }
  kick() { if (!this.running && !this.paused.size && this.world) { this.running = true; this.last = performance.now(); requestAnimationFrame(this.frame); } }
  pause(reason) { this.paused.add(reason); }
  resume(reason) { this.paused.delete(reason); this.invalidate(200); }
  frame = (now) => {
    const w = this.world;
    if (this.paused.size || !w) { this.running = false; return; }
    const dtMs = now - this.last, dt = Math.min(0.05, Math.max(0.001, dtMs / 1000)); this.last = now;
    const t0 = performance.now();
    let active = w.rig ? w.rig.update(dt) : false;
    active = w.update(dt, now / 1000) || active;
    this.renderer.render(w.scene, w.camera);
    const cpu = performance.now() - t0;
    const s = this.stats; s.frames++;
    if (dtMs < 250) { s.dts.push(dtMs); s.cpu.push(cpu); if (s.dts.length > 240) { s.dts.shift(); s.cpu.shift(); } }
    this.adapt(now);
    if (active || now < this.until || this.input.active) requestAnimationFrame(this.frame);
    else this.running = false;
  };
  // adaptive resolution: step down when frames are slow, back up when there is room
  adapt(now) {
    const d = this.stats.dts; if (d.length < 40 || now - this.dprAt < 1500) return;
    let sum = 0; for (let i = d.length - 40; i < d.length; i++) sum += d[i];
    const avg = sum / 40;
    let next = this.dpr;
    if (avg > 26 && this.dpr > 0.6) next = Math.max(0.6, this.dpr * 0.8);
    else if (avg < 17.5 && this.dpr < this.maxDpr && now - this.dprAt > 4000) next = Math.min(this.maxDpr, this.dpr * 1.15);
    if (Math.abs(next - this.dpr) > 0.01) { this.dpr = next; this.dprAt = now; this.resize(); d.length = 0; this.stats.cpu.length = 0; }
  }
  raycaster = new THREE.Raycaster();
  ray(info) { this.raycaster.setFromCamera(info.ndc, this.world.camera); return this.raycaster; }
  frameStats() {
    const d = this.stats.dts, c = this.stats.cpu;
    if (!d.length) return null;
    const sorted = [...d].sort((a, b) => a - b);
    return { avg: +(d.reduce((a, b) => a + b, 0) / d.length).toFixed(2), p95: +sorted[Math.floor(sorted.length * 0.95)].toFixed(2), cpu: +(c.reduce((a, b) => a + b, 0) / c.length).toFixed(2), n: d.length, dpr: +this.dpr.toFixed(2), tier: this.tier };
  }
  dispose() {
    this.ro.disconnect(); document.removeEventListener("visibilitychange", this.onVis);
    this.envRT?.dispose(); this.renderer.dispose();
  }
}

// a shadow-casting key light sized to a box of the world
export function keyLight(engine, { color = 0xffffff, intensity = 2.4, pos = [6, 14, 8], box = 10, bias = -0.0004 } = {}) {
  const l = new THREE.DirectionalLight(color, intensity);
  l.position.set(...pos);
  if (engine.renderer.shadowMap.enabled) {
    l.castShadow = true;
    l.shadow.mapSize.set(engine.shadowSize, engine.shadowSize);
    const c = l.shadow.camera; c.left = -box; c.right = box; c.top = box; c.bottom = -box; c.near = 1; c.far = 60;
    l.shadow.bias = bias; l.shadow.normalBias = 0.02; l.shadow.radius = 4;
  }
  return l;
}

/* ---------------- the world's controls (bottom bar), relabelled when the language changes ---------------- */
export const ICONS = {
  down: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v15m-6-6 6 6 6-6"/></svg>',
  up: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 20V5m-6 6 6-6 6 6"/></svg>',
  left: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 12H5m6-6-6 6 6 6"/></svg>',
  right: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12h15m-6-6 6 6-6 6"/></svg>',
  zero: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/></svg>',
  tilt: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="7" y="3" width="10" height="18" rx="2" transform="rotate(-14 12 12)"/><path d="M3 8a10 10 0 0 0 0 8M21 8a10 10 0 0 1 0 8"/></svg>',
  shake: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 6h8v12H8z"/><path d="M4 9v6M20 9v6M2 11v2M22 11v2"/></svg>',
  plus: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>',
  reset: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12a8 8 0 1 0 2.4-5.7"/><path d="M4 4v4.5h4.5"/></svg>',
  undo: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-3"/></svg>',
  trash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
  build: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12v9M4 7.5 12 12l8-4.5"/></svg>',
  erase: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m16 4 5 5-10 10H6l-3-3z"/><path d="m10 10 5 5M6 19h14"/></svg>',
  wave: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12c2.5-4 5-4 7.5 0s5 4 7.5 0 3.5-3 5-2"/></svg>',
  collapse: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4l5 5M20 4l-5 5M4 20l5-5M20 20l-5-5"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>',
  pause: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14M16 5v14"/></svg>',
  play: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4.5v15l12-7.5z"/></svg>',
  dive: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3h18v18H3z"/><path d="M8 8h8v8H8z"/><path d="M3 3l5 5M21 3l-5 5M3 21l5-5M21 21l-5-5"/></svg>',
  rise: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 8h8v8H8z"/><path d="M3 3h18v18H3z" stroke-dasharray="2 2"/></svg>',
  flat: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 5h14v14H5z"/></svg>',
  iso: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12v9M4 7.5 12 12l8-4.5"/></svg>',
  persp: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20 9 6h6l5 14z"/><path d="M6.5 13h11"/></svg>',
  eye: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.6-6 10-6 10 6 10 6-3.6 6-10 6S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
};
export function makeTools(ctx, TXT) {
  const root = ctx.tools, painters = [];
  const tr = (k) => { const t = TXT[ctx.lang()] || TXT.en; return t[k] ?? k; };
  const api = {
    tr,
    group(labelKey) {
      const g = document.createElement("div"); g.className = "cv-group"; g.setAttribute("role", "group");
      if (labelKey) { const s = document.createElement("span"); s.className = "cv-label"; s.setAttribute("aria-hidden", "true"); g.append(s); painters.push(() => { s.textContent = tr(labelKey); g.setAttribute("aria-label", tr(labelKey)); }); }
      root.append(g); return g;
    },
    button(g, { icon, text, label, pressed, onClick, cls, style }) {
      const b = document.createElement("button"); b.type = "button";
      b.className = `cv-btn${cls ? ` ${cls}` : ""}${icon && !text ? " is-icon" : ""}`;
      if (icon) b.innerHTML = ICONS[icon] || icon;
      if (style) Object.assign(b.style, style);
      let span = null; if (text) { span = document.createElement("span"); b.append(span); }
      if (pressed !== undefined) b.setAttribute("aria-pressed", String(!!pressed));
      b.addEventListener("click", (e) => { onClick(e, b); ctx.invalidate(400); });
      painters.push(() => { if (span) span.textContent = tr(text); const l = label ? tr(label) : null; if (l) { b.setAttribute("aria-label", l); b.title = l; } });
      g.append(b); return b;
    },
    range(g, { label, min = 0, max = 1, step = 0.01, value = 0, onInput }) {
      const w = document.createElement("label"); w.className = "cv-range";
      const s = document.createElement("span"); const i = document.createElement("input");
      i.type = "range"; i.dir = "ltr"; i.min = String(min); i.max = String(max); i.step = String(step); i.value = String(value);
      i.addEventListener("input", () => { onInput(Number(i.value)); ctx.invalidate(600); });
      w.append(s, i); g.append(w);
      painters.push(() => { s.textContent = tr(label); });
      return i;
    },
    text(g, cls = "cv-count") { const s = document.createElement("span"); s.className = cls; g.append(s); return s; },
    paint() { painters.forEach((f) => f()); },
  };
  return api;
}
export function press(buttons, active) { for (const b of buttons) b.setAttribute("aria-pressed", String(b === active)); }
