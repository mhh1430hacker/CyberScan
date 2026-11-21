/* The Cubeverse without WebGL 2: a lighter gallery of CSS 3D cubes, one small scene per world, with
 * light interaction (drag to turn, tap a cube, a few buttons). It never loads three.js. */

const TXT = {
  ar: { act: "أفعال", drop: "أسقطها", add: "أضف مكعبًا", remove: "أزل مكعبًا", collapse: "انهيار", flat: "مسطح", depth: "عمق", dive: "اغطس", turn: "اسحب لتدوير المكعبات، وانقر مكعبًا." },
  en: { act: "Actions", drop: "Drop them", add: "Add a cube", remove: "Remove a cube", collapse: "Collapse", flat: "Flat", depth: "Depth", dive: "Dive", turn: "Drag to turn the cubes; tap a cube." },
};
const COLORS = [["#e4d4ff", "#7c3aed"], ["#c8fbff", "#0e9ec0"], ["#ffd1f4", "#c026d3"], ["#ffffff", "#9b94c9"]];

function cube(size, [a, b], ghost) {
  const c = document.createElement("div"); c.className = `cvf-cube${ghost ? " is-ghost" : ""}`;
  c.style.setProperty("--s", `${size}px`); c.style.setProperty("--a", a); c.style.setProperty("--b", b);
  for (let i = 0; i < 6; i++) c.append(document.createElement("b"));
  return c;
}
const place = (c, x, y, z, extra = "") => { c.style.transform = `translate3d(${x}px, ${y}px, ${z}px) ${extra}`; c.dataset.base = c.style.transform; };

export function create(id, root, ctx) {
  const reduced = ctx.reduced();
  const tr = (k) => (TXT[ctx.lang()] || TXT.en)[k];
  root.replaceChildren();
  const scene = document.createElement("div"); scene.className = "cvf-scene"; scene.tabIndex = 0; scene.setAttribute("role", "img");
  const rot = document.createElement("div"); rot.className = "cvf-rot";
  const hint = document.createElement("p"); hint.className = "cvf-hint";
  scene.append(rot); root.append(scene, hint);
  let rx = -22, ry = 32;
  const apply = () => { rot.style.transform = `rotateX(${rx}deg) rotateY(${ry}deg)`; };
  apply();
  // drag (or arrow keys) to turn
  let drag = null;
  scene.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, moved: false }; scene.setPointerCapture(e.pointerId); });
  scene.addEventListener("pointermove", (e) => { if (!drag) return; const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true; ry += dx * 0.4; rx = Math.max(-80, Math.min(80, rx - dy * 0.4)); drag.x = e.clientX; drag.y = e.clientY; apply(); });
  scene.addEventListener("pointerup", (e) => { const was = drag; drag = null; if (was && !was.moved) tap(e.target.closest(".cvf-cube")); });
  scene.addEventListener("keydown", (e) => {
    const m = { ArrowLeft: [0, -8], ArrowRight: [0, 8], ArrowUp: [8, 0], ArrowDown: [-8, 0] }[e.key];
    if (m) { e.preventDefault(); rx = Math.max(-80, Math.min(80, rx + m[0])); ry += m[1]; apply(); }
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); tap(cubes[Math.floor(Math.random() * cubes.length)]); }
  });
  const anim = (n, kf, o) => (reduced || !n.animate ? null : n.animate(kf, o));
  const cubes = [];
  const add = (c) => { rot.append(c); cubes.push(c); return c; };
  const S = Math.min(innerWidth, innerHeight) < 600 ? 0.7 : 1;
  let tap = () => {};
  const tools = ctx.tools, painters = [];
  const group = () => { const g = document.createElement("div"); g.className = "cv-group"; tools.append(g); return g; };
  const button = (g, k, fn) => { const b = document.createElement("button"); b.type = "button"; b.className = "cv-btn"; b.addEventListener("click", fn); g.append(b); painters.push(() => { b.textContent = tr(k); }); return b; };
  const g = group();

  if (id === "gravity") {
    for (let i = 0; i < 7; i++) place(add(cube(54 * S, COLORS[i % 4])), (i - 3) * 64 * S, 90 * S, ((i * 37) % 3 - 1) * 50 * S);
    tap = (c) => { if (c) anim(c, [{ transform: c.dataset.base }, { transform: `${c.dataset.base} translateY(${-160 * S}px) rotateX(180deg)` }, { transform: c.dataset.base }], { duration: 900, easing: "cubic-bezier(.3,.7,.3,1)" }); ctx.sfx("pluck", { k: 3 }); };
    button(g, "drop", () => cubes.forEach((c, i) => anim(c, [{ transform: `${c.dataset.base} translateY(${-320 * S}px) rotateZ(90deg)` }, { transform: c.dataset.base, offset: 0.7 }, { transform: `${c.dataset.base} translateY(-18px)`, offset: 0.85 }, { transform: c.dataset.base }], { duration: 1100, delay: i * 70, easing: "ease-in" })));
  } else if (id === "architecture") {
    let n = 0;
    const put = () => { if (n >= 12) return; const x = (n % 3) - 1, y = Math.floor(n / 3); const c = add(cube(58 * S, COLORS[n % 4])); place(c, x * 60 * S, (120 - y * 60) * S, 0); anim(c, [{ opacity: 0, transform: `${c.dataset.base} scale(.2)` }, { opacity: 1, transform: c.dataset.base }], { duration: 300, easing: "cubic-bezier(.3,1.4,.5,1)" }); n++; ctx.sfx("pluck", { k: n }); };
    for (let i = 0; i < 4; i++) put();
    tap = () => put();
    button(g, "add", put);
    button(g, "remove", () => { const c = cubes.pop(); if (c) { c.remove(); n--; ctx.sfx("tick"); } });
  } else if (id === "quantum") {
    for (let i = 0; i < 3; i++) {
      const main = add(cube(56 * S, COLORS[i % 3])); place(main, (i - 1) * 140 * S, 0, 0);
      for (let k = 0; k < 3; k++) { const gh = cube(56 * S, COLORS[(i + k + 1) % 3], true); place(gh, (i - 1) * 140 * S + Math.cos(k * 2.1) * 40 * S, Math.sin(k * 2.1) * 40 * S, Math.sin(k) * 40 * S); gh.dataset.of = String(i); rot.append(gh); }
    }
    const ghosts = () => [...rot.querySelectorAll(".is-ghost")];
    tap = () => { ghosts().forEach((gh) => { gh.style.transition = reduced ? "none" : "transform .5s, opacity .5s"; gh.style.opacity = "0"; }); ctx.sfx("chime"); setTimeout(() => ghosts().forEach((gh) => { gh.style.opacity = ""; }), 3500); };
    button(g, "collapse", () => tap());
  } else if (id === "dimension") {
    for (let i = 0; i < 5; i++) for (let j = 0; j < 3; j++) place(add(cube(44 * S, COLORS[(i + j) % 4])), (i - 2) * 70 * S, (j - 1) * 70 * S, ((i * 7 + j * 13) % 5 - 2) * 70 * S);
    let flat = false;
    const set = () => { scene.style.perspective = flat ? "100000px" : ""; root.style.perspective = flat ? "100000px" : ""; rx = flat ? 0 : -22; ry = flat ? 0 : 32; rot.style.transition = reduced ? "none" : "transform .9s cubic-bezier(.6,0,.3,1)"; apply(); };
    tap = () => { flat = !flat; set(); ctx.sfx("tab"); };
    button(g, "flat", () => { flat = true; set(); });
    button(g, "depth", () => { flat = false; set(); });
  } else {
    [220, 120, 64, 34].forEach((s, i) => { const c = add(cube(s * S, COLORS[i % 4], i === 0)); place(c, 0, 0, 0, `rotateY(${i * 28}deg) rotateX(${i * 20}deg)`); });
    tap = () => anim(rot, [{ transform: rot.style.transform }, { transform: `${rot.style.transform} scale(3)`, opacity: 0, offset: 0.7 }, { transform: `${rot.style.transform} scale(.4)`, opacity: 0, offset: 0.71 }, { transform: rot.style.transform, opacity: 1 }], { duration: 1500, easing: "ease-in-out" });
    button(g, "dive", () => { tap(); ctx.sfx("whoosh"); });
  }
  const paint = () => { painters.forEach((f) => f()); hint.textContent = tr("turn"); scene.setAttribute("aria-label", tr("turn")); };
  paint();
  return { paint, save() {}, dispose() { root.replaceChildren(); tools.replaceChildren(); } };
}
