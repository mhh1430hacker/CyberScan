/* A small rigid-body engine for cubes (no library): gravity, cube-cube collisions found with the
 * separating-axis test, a closed container (floor, ceiling, four walls), sequential impulses with
 * Coulomb friction and restitution, speculative contacts (no tunnelling at normal speeds), a
 * spring for dragging a cube by any point, and sleeping bodies (no work when nothing moves).
 * A uniform cube's inertia is the same about every axis, which keeps the maths short. */
import { THREE } from "./core.js";

const V = () => new THREE.Vector3();
const tA = V(), tB = V(), tC = V(), tD = V(), tE = V(), tF = V(), rA = V(), rB = V(), vel = V();
const SIGNS = [[-1, -1, -1], [1, -1, -1], [-1, 1, -1], [1, 1, -1], [-1, -1, 1], [1, -1, 1], [-1, 1, 1], [1, 1, 1]];

export class Body {
  constructor({ pos, quat, half = 0.5, density = 1 }) {
    this.p = pos.clone(); this.q = quat ? quat.clone() : new THREE.Quaternion();
    this.v = V(); this.w = V(); this.h = half;
    const s = half * 2, m = s * s * s * density;
    this.m = m; this.im = 1 / m; this.ii = 1 / (m * s * s / 6);
    this.ax = [V(), V(), V()]; this.axes();
    this.sleep = false; this.sleepT = 0; this.drag = null; this.hit = 0; this.lastHit = 0;
  }
  axes() {
    const q = this.q, x = q.x, y = q.y, z = q.z, w = q.w;
    this.ax[0].set(1 - 2 * (y * y + z * z), 2 * (x * y + z * w), 2 * (x * z - y * w));
    this.ax[1].set(2 * (x * y - z * w), 1 - 2 * (x * x + z * z), 2 * (y * z + x * w));
    this.ax[2].set(2 * (x * z + y * w), 2 * (y * z - x * w), 1 - 2 * (x * x + y * y));
  }
  vertex(i, out) {
    const s = SIGNS[i], h = this.h;
    return out.copy(this.p).addScaledVector(this.ax[0], s[0] * h).addScaledVector(this.ax[1], s[1] * h).addScaledVector(this.ax[2], s[2] * h);
  }
  extent(n) { return this.h * (Math.abs(n.dot(this.ax[0])) + Math.abs(n.dot(this.ax[1])) + Math.abs(n.dot(this.ax[2]))); }
  wake() { this.sleep = false; this.sleepT = 0; }
  energy() { return this.v.lengthSq() + this.w.lengthSq() * this.h * this.h * 4; }
}

class Contact {
  constructor() { this.p = V(); this.n = V(); this.ra = V(); this.rb = V(); this.t1 = V(); this.t2 = V(); }
}

export class Physics {
  constructor({ half = [7, 4.5], height = 10, gravity = [0, -9.8, 0], tier = 2 } = {}) {
    this.bodies = [];
    this.g = new THREE.Vector3(...gravity);
    this.bx = half[0]; this.bz = half[1]; this.by = height;
    this.planes = [
      { n: new THREE.Vector3(0, 1, 0), d: 0 }, { n: new THREE.Vector3(0, -1, 0), d: -height },
      { n: new THREE.Vector3(1, 0, 0), d: -half[0] }, { n: new THREE.Vector3(-1, 0, 0), d: -half[0] },
      { n: new THREE.Vector3(0, 0, 1), d: -half[1] }, { n: new THREE.Vector3(0, 0, -1), d: -half[1] },
    ];
    this.hstep = tier === 0 ? 1 / 60 : tier === 1 ? 1 / 90 : 1 / 120;
    this.iters = tier === 0 ? 6 : tier === 1 ? 8 : 10;
    this.cost = 0;   // ms per frame (smoothed): a slow device gets a lighter solver
    this.acc = 0; this.pool = []; this.nC = 0;
    this.friction = 0.55; this.restitution = 0.32; this.margin = 0.03;
    this.events = [];
    this.linDamp = 0.04; this.angDamp = 0.5;
  }
  add(opts) { const b = new Body(opts); b.idx = this.bodies.length; this.bodies.push(b); return b; }
  wakeAll() { for (const b of this.bodies) b.wake(); }
  awake() { for (const b of this.bodies) if (!b.sleep) return true; return false; }
  contact() { if (this.nC >= this.pool.length) this.pool.push(new Contact()); return this.pool[this.nC++]; }

  step(dt) {
    this.acc = Math.min(this.acc + dt, this.hstep * 3);
    let n = 0;
    const t0 = performance.now();
    while (this.acc >= this.hstep) { this.sub(this.hstep); this.acc -= this.hstep; n++; }
    if (n) {
      this.cost = this.cost * 0.9 + (performance.now() - t0) * 0.1;
      if (this.cost > 4.5 && (this.iters > 5 || this.hstep < 1 / 60)) {   // too slow here: fewer, larger steps
        if (this.iters > 6) this.iters -= 2; else if (this.hstep < 1 / 60) this.hstep = this.hstep < 1 / 100 ? 1 / 90 : 1 / 60;
        else this.iters = 5;
        this.cost = 2.5;
      }
    }
    return n;
  }

  sub(h) {
    const B = this.bodies;
    // forces: gravity, the drag spring, damping
    for (const b of B) {
      if (b.sleep) continue;
      b.v.addScaledVector(this.g, h);
      if (b.drag) {
        const d = b.drag;
        tA.copy(d.local).applyQuaternion(b.q); rA.copy(tA);
        tB.copy(b.p).add(tA);                                      // the anchor in the world
        vel.crossVectors(b.w, rA).add(b.v);                        // its velocity
        tC.subVectors(d.target, tB).multiplyScalar(d.k).addScaledVector(vel, -d.c).multiplyScalar(b.m);
        const f = tC.length(), fmax = 260 * b.m; if (f > fmax) tC.multiplyScalar(fmax / f);
        b.v.addScaledVector(tC, b.im * h);
        tD.crossVectors(rA, tC); b.w.addScaledVector(tD, b.ii * h);
        b.w.multiplyScalar(1 - Math.min(0.5, 6 * h));
      }
      b.v.multiplyScalar(1 / (1 + h * this.linDamp)); b.w.multiplyScalar(1 / (1 + h * this.angDamp));
      b.axes();
    }
    // contacts
    this.nC = 0;
    for (const b of B) {
      if (b.sleep) continue;
      for (const pl of this.planes) {
        if (pl.n.dot(b.p) - pl.d > b.h * 1.75 + this.margin) continue;
        for (let i = 0; i < 8; i++) {
          b.vertex(i, tA);
          const sep = pl.n.dot(tA) - pl.d;
          if (sep < this.margin) { const c = this.contact(); c.a = null; c.b = b; c.p.copy(tA); c.n.copy(pl.n); c.sep = sep; }
        }
      }
    }
    for (let i = 0; i < B.length; i++) {
      const a = B[i];
      for (let j = i + 1; j < B.length; j++) {
        const b = B[j];
        if (a.sleep && b.sleep) continue;
        const r = (a.h + b.h) * 1.733 + this.margin;
        if (a.p.distanceToSquared(b.p) > r * r) continue;
        this.collide(a, b);
      }
    }
    // a moving body that touches a sleeping one wakes it
    for (let k = 0; k < this.nC; k++) {
      const c = this.pool[k]; if (!c.a) continue;
      if (c.a.sleep !== c.b.sleep) { const mover = c.a.sleep ? c.b : c.a, sleeper = c.a.sleep ? c.a : c.b; if (mover.energy() > 0.3 || c.sep < -0.04 || mover.drag) sleeper.wake(); }
    }
    // prepare
    for (let k = 0; k < this.nC; k++) {
      const c = this.pool[k], a = c.a, b = c.b;
      const ima = a && !a.sleep ? a.im : 0, iia = a && !a.sleep ? a.ii : 0, imb = !b.sleep ? b.im : 0, iib = !b.sleep ? b.ii : 0;
      c.ima = ima; c.iia = iia; c.imb = imb; c.iib = iib;
      if (a) c.ra.subVectors(c.p, a.p); else c.ra.set(0, 0, 0);
      c.rb.subVectors(c.p, b.p);
      const n = c.n;
      if (Math.abs(n.x) > 0.57) c.t1.set(n.y, -n.x, 0).normalize(); else c.t1.set(0, n.z, -n.y).normalize();
      c.t2.crossVectors(n, c.t1);
      c.mn = 1 / this.kmass(c, n); c.m1 = 1 / this.kmass(c, c.t1); c.m2 = 1 / this.kmass(c, c.t2);
      const vn = this.relVel(c, tE).dot(n);
      c.vn0 = vn;
      if (c.sep > 0) c.target = -c.sep / h;
      else c.target = Math.max(vn < -1.1 ? -this.restitution * vn : 0, Math.min(3, (0.22 / h) * Math.max(0, -c.sep - 0.004)));
      c.pn = 0; c.p1 = 0; c.p2 = 0;
    }
    // solve
    for (let it = 0; it < this.iters; it++) {
      for (let k = 0; k < this.nC; k++) {
        const c = this.pool[k];
        if (c.ima + c.imb === 0) continue;
        this.relVel(c, tE);
        const vn = tE.dot(c.n);
        let dp = -(vn - c.target) * c.mn;
        const p0 = c.pn; c.pn = Math.max(0, p0 + dp); dp = c.pn - p0;
        if (dp) this.apply(c, c.n, dp);
        const lim = this.friction * c.pn;
        this.relVel(c, tE);
        let d1 = -tE.dot(c.t1) * c.m1; const q1 = c.p1; c.p1 = Math.max(-lim, Math.min(lim, q1 + d1)); d1 = c.p1 - q1;
        if (d1) this.apply(c, c.t1, d1);
        this.relVel(c, tE);
        let d2 = -tE.dot(c.t2) * c.m2; const q2 = c.p2; c.p2 = Math.max(-lim, Math.min(lim, q2 + d2)); d2 = c.p2 - q2;
        if (d2) this.apply(c, c.t2, d2);
      }
    }
    // impacts worth seeing and hearing
    for (let k = 0; k < this.nC; k++) {
      const c = this.pool[k];
      if (c.vn0 < -2.2 && c.pn > 0) {
        const s = -c.vn0, b = c.b;
        if (s > b.hit) b.hit = s;
        if (c.a && s > c.a.hit) c.a.hit = s;
        if (this.events.length < 24) this.events.push({ p: c.p.clone(), n: c.n.clone(), s, a: c.a, b });
      }
    }
    // integrate, then rest
    for (const b of B) {
      if (b.sleep) continue;
      const sp = b.v.length(); if (sp > 40) b.v.multiplyScalar(40 / sp);
      const ws = b.w.length(); if (ws > 30) b.w.multiplyScalar(30 / ws);
      b.p.addScaledVector(b.v, h);
      const q = b.q, wx = b.w.x * h * 0.5, wy = b.w.y * h * 0.5, wz = b.w.z * h * 0.5;
      const x = q.x, y = q.y, z = q.z, w = q.w;
      q.set(x + wx * w + wy * z - wz * y, y + wy * w + wz * x - wx * z, z + wz * w + wx * y - wy * x, w - wx * x - wy * y - wz * z).normalize();
      // never leave the box, whatever happens
      const lim = b.h * 0.6;
      b.p.x = Math.max(-this.bx + lim, Math.min(this.bx - lim, b.p.x));
      b.p.z = Math.max(-this.bz + lim, Math.min(this.bz - lim, b.p.z));
      b.p.y = Math.max(lim, Math.min(this.by - lim, b.p.y));
      if (!b.drag && b.v.lengthSq() < 0.03 && b.w.lengthSq() < 0.05) { b.sleepT += h; if (b.sleepT > 0.45) { b.sleep = true; b.v.set(0, 0, 0); b.w.set(0, 0, 0); } }
      else b.sleepT = 0;
    }
  }
  kmass(c, n) {
    tF.crossVectors(c.ra, n); const ka = c.iia * tF.lengthSq();
    tF.crossVectors(c.rb, n); const kb = c.iib * tF.lengthSq();
    return c.ima + c.imb + ka + kb || 1e9;
  }
  relVel(c, out) {
    const b = c.b; out.crossVectors(b.w, c.rb).add(b.v);
    if (c.a) { tF.crossVectors(c.a.w, c.ra).add(c.a.v); out.sub(tF); }
    return out;
  }
  apply(c, dir, mag) {
    const b = c.b, a = c.a;
    if (c.imb) { b.v.addScaledVector(dir, mag * c.imb); tF.crossVectors(c.rb, dir); b.w.addScaledVector(tF, mag * c.iib); }
    if (a && c.ima) { a.v.addScaledVector(dir, -mag * c.ima); tF.crossVectors(c.ra, dir); a.w.addScaledVector(tF, -mag * c.iia); }
  }

  // separating axes for two oriented cubes; contacts are the vertices of each inside the other,
  // or the closest points of two edges when only edges touch
  collide(A, B) {
    const d = tA.subVectors(B.p, A.p);
    let best = -Infinity, type = 0, ei = 0, ej = 0;
    const n = tB;
    const test = (L, t, i, j) => {
      const len = L.length(); if (len < 1e-5) return true;
      L.divideScalar(len);
      const s = Math.abs(d.dot(L)) - (A.extent(L) + B.extent(L));
      if (s > this.margin) return false;
      const bias = t === 2 ? 0.015 : 0;   // prefer faces: steadier stacks
      if (s > best + bias) { best = s; type = t; ei = i; ej = j; n.copy(L); if (d.dot(n) < 0) n.negate(); }
      return true;
    };
    for (let i = 0; i < 3; i++) if (!test(tC.copy(A.ax[i]), 0, i, 0)) return;
    for (let j = 0; j < 3; j++) if (!test(tC.copy(B.ax[j]), 1, 0, j)) return;
    for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) if (!test(tC.crossVectors(A.ax[i], B.ax[j]), 2, i, j)) return;
    const start = this.nC, extA = A.extent(n), extB = B.extent(n), m = this.margin + 0.01;
    if (type !== 2) {
      for (let k = 0; k < 8; k++) {   // B's corners inside A
        B.vertex(k, tC); tD.subVectors(tC, A.p);
        if (Math.abs(tD.dot(A.ax[0])) > A.h + m || Math.abs(tD.dot(A.ax[1])) > A.h + m || Math.abs(tD.dot(A.ax[2])) > A.h + m) continue;
        const sep = Math.max(best, tD.dot(n) - extA);
        if (sep < this.margin) { const c = this.contact(); c.a = A; c.b = B; c.p.copy(tC); c.n.copy(n); c.sep = sep; }
      }
      for (let k = 0; k < 8; k++) {   // A's corners inside B
        A.vertex(k, tC); tD.subVectors(tC, B.p);
        if (Math.abs(tD.dot(B.ax[0])) > B.h + m || Math.abs(tD.dot(B.ax[1])) > B.h + m || Math.abs(tD.dot(B.ax[2])) > B.h + m) continue;
        const sep = Math.max(best, -tD.dot(n) - extB);
        if (sep < this.margin) { const c = this.contact(); c.a = A; c.b = B; c.p.copy(tC); c.n.copy(n); c.sep = sep; }
      }
    }
    if (this.nC === start) {   // edge on edge: the closest points of the two supporting edges
      if (type !== 2) {   // the edges most perpendicular to the normal
        let mi = 2, mj = 2;
        for (let k = 0; k < 3; k++) {
          const x = Math.abs(n.dot(A.ax[k])), y = Math.abs(n.dot(B.ax[k]));
          if (x < mi) { mi = x; ei = k; }
          if (y < mj) { mj = y; ej = k; }
        }
      }
      const ca = tC.copy(A.p), cb = tD.copy(B.p);
      for (let k = 0; k < 3; k++) {
        if (k !== ei) ca.addScaledVector(A.ax[k], Math.sign(n.dot(A.ax[k]) || 1) * A.h);
        if (k !== ej) cb.addScaledVector(B.ax[k], -Math.sign(n.dot(B.ax[k]) || 1) * B.h);
      }
      const u = A.ax[ei], v = B.ax[ej], w0 = tE.subVectors(ca, cb);
      const b = u.dot(v), dd = u.dot(w0), e = v.dot(w0), den = 1 - b * b;
      let s = den > 1e-6 ? (b * e - dd) / den : 0, t = den > 1e-6 ? (e - b * dd) / den : 0;
      s = Math.max(-A.h, Math.min(A.h, s)); t = Math.max(-B.h, Math.min(B.h, t));
      ca.addScaledVector(u, s); cb.addScaledVector(v, t);
      const c = this.contact(); c.a = A; c.b = B; c.p.addVectors(ca, cb).multiplyScalar(0.5); c.n.copy(n); c.sep = best;
    }
  }
}
