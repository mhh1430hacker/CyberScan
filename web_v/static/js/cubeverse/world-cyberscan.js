/* World F: the CyberScan Cube. A file drawn as a cube of 9 x 9 x 9 small cubes in five nested shells,
 * one per thing CyberScan reads: its name, its first bytes, its structure, the entropy of its contents
 * and, at the core, its fingerprint (SHA-256) with the verdict. The visitor takes it apart shell by
 * shell (tap the cube, the Peel button, Enter) and puts it back (Rebuild, Backspace). Each shell is
 * coloured by what it stands for: the header bytes, the sections, the entropy along the file.
 * Three example files, and the visitor's own last scan when the scan page left one in this tab
 * (sessionStorage "cs-journey-file", written by js/journey-hook.js). State is kept for the visit. */
import { THREE, CubeSet, cubeMaterial, roundedBoxGeometry, gradientTexture, keyLight, disposeScene, OrbitRig, makeTools, press, clamp } from "./core.js";

const TXT = {
  ar: { layer: "الطبقة", file: "الملف", peel: "انزع طبقة", back: "أعِد طبقة", rebuild: "أعِد البناء", of: "من",
    L0: "الاسم", L1: "أول البايتات", L2: "البنية", L3: "إنتروبيا المحتوى", L4: "البصمة",
    d0: "ما يراه الجميع: الاسم والحجم والنوع. الاسم وحده لا يكفي للحكم على الملف.",
    d1: "التوقيع السحري في أول البايتات يكشف النوع الحقيقي مهما كان الامتداد.",
    d2: "أجزاء الملف ومواضعها: هنا تختبئ الأشياء غير المتوقعة.",
    d3: "مدى عشوائية البيانات على امتداد الملف (0 إلى 8 بت لكل بايت). القريب من 8 مضغوط أو مشفّر.",
    d4: "بصمة SHA-256: هوية الملف التي تُقارن بقوائم البرمجيات الضارة المعروفة، ومعها الحكم.",
    size: "الحجم", type: "النوع", magic: "التوقيع", mean: "المتوسط", peak: "الذروة", noBytes: "أول البايتات غير محفوظة في نتيجة هذا الفحص.",
    sample: "مثال توضيحي، ليس نتيجة فحص حقيقية.", mine: "من آخر فحص أجريته في هذه النافذة.", myScan: "فحصي الأخير",
    pdf: "PDF", exe: "برنامج", docm: "مستند بماكرو",
    clean: "لا مؤشرات", review: "يستحق المراجعة", suspicious: "مريب", malware: "برمجية ضارة معروفة", unknown: "غير حاسم",
    peeled: "نُزعت طبقة: {l}", rebuilt: "أُعيد بناء المكعب", core: "وصلت إلى اللبّ: البصمة", fCore: "قلب الملف" },
  en: { layer: "Layer", file: "File", peel: "Peel a layer", back: "Put one back", rebuild: "Rebuild", of: "of",
    L0: "Name", L1: "First bytes", L2: "Structure", L3: "Content entropy", L4: "Fingerprint",
    d0: "What everyone sees: the name, the size, the type. A name alone says nothing reliable about a file.",
    d1: "The magic signature in the first bytes tells the real type, whatever the extension claims.",
    d2: "The file's parts and where they sit: this is where unexpected things hide.",
    d3: "How random the data is along the file (0 to 8 bits per byte). Close to 8 is compressed or encrypted.",
    d4: "The SHA-256 fingerprint: the file's identity, checked against known-malware lists, with the verdict.",
    size: "Size", type: "Type", magic: "Signature", mean: "mean", peak: "peak", noBytes: "This scan's result does not keep the first bytes.",
    sample: "An illustrative example, not a real scan result.", mine: "From your last scan in this tab.", myScan: "My last scan",
    pdf: "PDF", exe: "Program", docm: "Macro document",
    clean: "No indicators", review: "Worth reviewing", suspicious: "Suspicious", malware: "Known malware", unknown: "Inconclusive",
    peeled: "Layer peeled: {l}", rebuilt: "The cube is rebuilt", core: "You reached the core: the fingerprint", fCore: "The heart of the file" },
};
const VCOL = { clean: ["#c8ffe6", "#14b884"], review: ["#ffe7b0", "#e0a020"], suspicious: ["#ffc2d6", "#e5336b"], malware: ["#ffb3c0", "#c81e3a"], unknown: ["#e2dcf5", "#7d74a8"] };
const SAMPLES = {
  pdf: { name: "quarterly-report.pdf", size: 2516582, type: "PDF document", magic: "%PDF-1.7", bytes: "25 50 44 46 2D 31 2E 37 0A 25 E2 E3 CF D3 0A 31",
    layers: [["Header", "0x000000"], ["Objects (412)", "0x00000F"], ["Streams (38)", "0x002A10"], ["Cross-reference table", "0x24C1F0"], ["Trailer", "0x24C9A0"]],
    entropy: [4.1, 4.6, 7.4, 7.6, 7.5, 5.2, 7.7, 7.6, 4.8, 7.5, 7.6, 7.4, 5.0, 4.2, 3.9, 3.6],
    sha: "8f3a9c0e5b7d21f6a4c38e90b1d7f2a65c0e9b84d3f71a2c6e5b09d8f4a7c13e", verdict: "clean" },
  exe: { name: "setup_patch.exe", size: 1183744, type: "Windows program (PE)", magic: "MZ", bytes: "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
    layers: [["DOS header", "0x000000"], ["PE header", "0x000080"], ["UPX0", "0x000400"], ["UPX1", "0x000400"], [".rsrc", "0x11A000"]],
    entropy: [3.2, 5.1, 7.9, 7.9, 7.95, 7.92, 7.94, 7.9, 7.93, 7.91, 7.95, 7.9, 7.88, 6.2, 5.4, 4.9],
    sha: "c41e07b95a2f8d63e1b0974fa5c2d8e36b9f1a07d4c5e28b3f6a90d1e7c4b258", verdict: "suspicious" },
  docm: { name: "invoice_Q3.docm", size: 48211, type: "Word document with macros", magic: "PK", bytes: "50 4B 03 04 14 00 06 00 08 00 00 00 21 00 DF A4",
    layers: [["[Content_Types].xml", "0x0000"], ["word/document.xml", "0x02B4"], ["word/vbaProject.bin", "0x5A10"], ["word/styles.xml", "0x9C80"], ["docProps", "0xB9E0"]],
    entropy: [5.8, 7.6, 7.7, 7.5, 7.8, 7.7, 6.9, 5.1, 5.3, 7.6, 7.7, 7.5, 7.4, 6.8, 7.2, 5.9],
    sha: "2b7d5e91c0f84a36e8d1b57c9a20f6e34d8b1c75a09e2f63b4d8c1a57e09f3b6", verdict: "review" },
};
const VERD = { NO_INDICATORS_OBSERVED: "clean", REVIEW: "review", SUSPICIOUS: "suspicious", KNOWN_MALWARE: "malware", UNKNOWN: "unknown" };
const N = 9, H = (N - 1) / 2, GAP = 0.56, SIZE = 0.47;
const saved = { sample: "pdf", peeled: 0, cam: null };
try { const s = JSON.parse(sessionStorage.getItem("cv-cyber") || "null"); if (s) { saved.sample = s.sample || "pdf"; saved.peeled = clamp(Number(s.peeled) || 0, 0, 4); } } catch { /* storage off */ }

// the visitor's own last scan, as js/journey-hook.js stored it
function myScan() {
  try {
    const d = JSON.parse(sessionStorage.getItem("cs-journey-file") || "null");
    if (!d || !d.n) return null;
    const ent = Array.isArray(d.e) && d.e.length > 1 ? d.e.map(Number) : (d.em != null ? [Number(d.em)] : [5]);
    const layers = (Array.isArray(d.L) && d.L.length ? d.L : [["Content", "0x0"]]).slice(0, 6).map((l) => [String(l[0]).slice(0, 40), String(l[1] || "")]);
    return { name: String(d.n).slice(0, 80), size: Number(d.s) || 0, type: String(d.t || "file").slice(0, 40), magic: d.mg ? String(d.mg).slice(0, 24) : "", bytes: d.fb ? String(d.fb).slice(0, 47) : "",
      layers, entropy: ent.slice(0, 64), sha: /^[0-9a-f]{64}$/i.test(d.h || "") ? d.h.toLowerCase() : "", verdict: VERD[d.c] || "unknown", score: d.sc, mine: true };
  } catch { return null; }
}
const fmtBytes = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
const hexBytes = (s) => String(s || "").trim().split(/\s+/).filter((x) => /^[0-9a-f]{2}$/i.test(x)).map((x) => parseInt(x, 16));

export function create(ctx) {
  const { engine } = ctx, tier = engine.tier;
  const tr = (k) => (TXT[ctx.lang()] || TXT.en)[k];
  const scene = new THREE.Scene();
  scene.background = gradientTexture([[0, "#0b0722"], [0.55, "#070414"], [1, "#04030c"]]);
  scene.fog = new THREE.Fog(0x05030f, 24, 60);
  scene.environment = engine.env;
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 140);
  const rig = new OrbitRig(camera, { target: [0, 0, 0], theta: 0.72, phi: 1.08, radius: 15.5, minR: 6, maxR: 32, minPhi: 0.2, maxPhi: 2.9 });
  if (saved.cam) rig.state = saved.cam;
  else if (engine.w / engine.h < 0.8) { rig.goal.radius *= 1.45; rig.snap(); }

  scene.add(new THREE.HemisphereLight(0xd8ccff, 0x0a0620, 0.9));
  const key = keyLight(engine, { intensity: 2.2, pos: [-7, 12, 9], box: 8 }); scene.add(key, key.target);
  const rim = new THREE.PointLight(0x22e8ff, 30, 30, 2); rim.position.set(7, -2, -6); scene.add(rim);
  const rim2 = new THREE.PointLight(0xff4fd8, 18, 30, 2); rim2.position.set(-6, 5, -7); scene.add(rim2);

  // a soft floor glow and a faint grid under the cube
  const glow = new THREE.Mesh(new THREE.CircleGeometry(9, 64), new THREE.MeshBasicMaterial({ map: gradientTexture([[0, "rgba(124,58,237,.45)"], [0.5, "rgba(34,232,255,.10)"], [1, "rgba(0,0,0,0)"]], { radial: true, size: 256 }), transparent: true, depthWrite: false }));
  glow.rotation.x = -Math.PI / 2; glow.position.y = -4.2; scene.add(glow);
  const grid = new THREE.GridHelper(24, 24, 0x3b2a78, 0x1d1540); grid.position.y = -4.25; grid.material.transparent = true; grid.material.opacity = 0.5; scene.add(grid);

  // the cubes: one per cell of the 9 x 9 x 9 grid; its shell is 4 - (Chebyshev distance from the centre)
  const cells = [];
  for (let x = -H; x <= H; x++) for (let y = -H; y <= H; y++) for (let z = -H; z <= H; z++) {
    const L = H - Math.max(Math.abs(x), Math.abs(y), Math.abs(z));
    const dir = new THREE.Vector3(x, y, z); if (dir.lengthSq() < 1e-6) dir.set(0, 1, 0); dir.normalize();
    cells.push({ x, y, z, L, dir, d: Math.random() * 0.35, spin: new THREE.Vector3(Math.random() - 0.5, Math.random() - 0.5, Math.random() - 0.5).normalize(), sp: 2 + Math.random() * 3, t: 0 });
  }
  const cubes = new CubeSet(cells.length, { geometry: roundedBoxGeometry(0.1, tier === 0 ? 1 : 2), material: cubeMaterial({ physical: tier === 2, roughness: 0.32, clearcoat: 0.7, envMapIntensity: 0.9 }), castShadow: tier >= 1, receiveShadow: tier >= 1 });
  scene.add(cubes.mesh);
  const group = cubes.mesh;

  /* ---------- the file and its colours ---------- */
  let file = null, sampleId = saved.sample;
  const layerT = [0, 0, 0, 0, 0];                       // 0 attached .. 1 gone, per shell
  let peeled = saved.peeled;
  const c1 = new THREE.Color(), c2 = new THREE.Color(), tmpP = new THREE.Vector3(), tmpQ = new THREE.Quaternion(), tmpS = new THREE.Vector3();
  function pick(id) {
    const mine = id === "mine" ? myScan() : null;
    sampleId = mine ? "mine" : SAMPLES[id] ? id : "pdf";
    file = mine || SAMPLES[sampleId];
    paintColors(); paintCard();
    persist();
  }
  function paintColors() {
    const bytes = hexBytes(file.bytes), ent = file.entropy, secs = file.layers.length, v = VCOL[file.verdict] || VCOL.unknown;
    cells.forEach((c, i) => {
      if (c.L === 0) {                                  // the name: the site's violet
        const k = (c.x + c.y * 3 + c.z * 7 + 40) % 5;
        c1.set(k ? "#e3d2ff" : "#f4ecff"); c2.set(k % 2 ? "#7c3aed" : "#5b21b6"); cubes.setGlow(i, 0);
      } else if (c.L === 1) {                           // the first bytes: brightness is the byte's value
        const b = bytes.length ? bytes[Math.abs(c.x * 5 + c.y * 3 + c.z) % bytes.length] : 96;
        c1.setHSL(0.52, 0.9, 0.42 + (b / 255) * 0.42); c2.setHSL(0.55, 0.95, 0.14 + (b / 255) * 0.25); cubes.setGlow(i, b > 200 ? 0.25 : 0);
      } else if (c.L === 2) {                           // the structure: one colour per section, in bands along the file
        const s = Math.min(secs - 1, Math.floor(((c.y + 2) / 5) * secs));
        c1.setHSL(0.72 + s * 0.09, 0.85, 0.72); c2.setHSL(0.72 + s * 0.09, 0.9, 0.32); cubes.setGlow(i, 0);
      } else if (c.L === 3) {                           // the entropy: cool -> hot, glowing near 8 bits per byte
        const u = (Math.atan2(c.z, c.x) / (Math.PI * 2) + 0.5 + (c.y + 1) / 3) / 2;
        const e = ent[Math.min(ent.length - 1, Math.floor(clamp(u, 0, 0.999) * ent.length))] || 0, k = clamp(e / 8, 0, 1);
        c1.setHSL(0.6 - k * 0.5, 0.95, 0.5 + k * 0.2); c2.setHSL(0.66 - k * 0.5, 0.95, 0.2 + k * 0.12); cubes.setGlow(i, e > 7.2 ? 0.45 : 0);
      } else { c1.set(v[0]); c2.set(v[1]); cubes.setGlow(i, 0.55); }
      cubes.colors(i, c1, c2);
    });
    cubes.flush(true);
  }

  /* ---------- the card: what the current shell means ---------- */
  const stage = document.querySelector(".cv-stage");
  const card = document.createElement("aside"); card.className = "cv-file"; card.setAttribute("aria-live", "polite");
  stage?.append(card);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  function paintCard() {
    const L = Math.min(peeled, 4), parts = [];
    const head = el("div", "cv-file-head");
    head.append(el("span", "cv-file-k", `${tr("layer")} ${L + 1} ${tr("of")} 5`), el("b", "cv-file-t", tr(`L${L}`)));
    const dots = el("span", "cv-file-dots"); for (let i = 0; i < 5; i++) dots.append(el("i", i < L ? "done" : i === L ? "on" : ""));
    head.append(dots); parts.push(head, el("p", "cv-file-d", tr(`d${L}`)));
    const body = el("div", "cv-file-b");
    if (L === 0) {
      const n = el("bdi", "cv-file-name", file.name); n.dir = "ltr"; body.append(n);
      const dl = el("dl", "cv-file-dl");
      [[tr("size"), file.size ? fmtBytes(file.size) : "–"], [tr("type"), file.type]].forEach(([k, v]) => { dl.append(el("dt", "", k)); const dd = el("dd"); const b = el("bdi", "", v); b.dir = "ltr"; dd.append(b); dl.append(dd); });
      body.append(dl);
    } else if (L === 1) {
      if (file.bytes) {
        const hex = el("code", "cv-file-hex", file.bytes); hex.dir = "ltr"; body.append(hex);
        if (file.magic) { const m = el("p", "cv-file-m"); m.append(el("span", "", `${tr("magic")}: `)); const b = el("bdi", "", file.magic); b.dir = "ltr"; m.append(b); body.append(m); }
      } else body.append(el("p", "cv-file-m", tr("noBytes")));
    } else if (L === 2) {
      const ol = el("ol", "cv-file-secs");
      file.layers.forEach(([name, off], i) => { const li = el("li"); li.style.setProperty("--h", String(0.72 + i * 0.09)); const a = el("bdi", "", name); a.dir = "ltr"; const o = el("code", "", off); o.dir = "ltr"; li.append(a, o); ol.append(li); });
      body.append(ol);
    } else if (L === 3) {
      const bars = el("div", "cv-file-bars"); bars.setAttribute("aria-hidden", "true");
      const ent = file.entropy.length > 1 ? file.entropy : [file.entropy[0], file.entropy[0]];
      ent.slice(0, 48).forEach((e) => { const i = el("i"); i.style.height = `${Math.max(4, (clamp(e, 0, 8) / 8) * 100)}%`; i.style.setProperty("--k", String(clamp(e / 8, 0, 1))); bars.append(i); });
      const mean = ent.reduce((a, b) => a + b, 0) / ent.length, peak = Math.max(...ent);
      body.append(bars, el("p", "cv-file-m", `${tr("mean")} ${mean.toFixed(2)} · ${tr("peak")} ${peak.toFixed(2)}`));
    } else {
      if (file.sha) { const h = el("code", "cv-file-sha", file.sha.match(/.{1,16}/g).join(" ")); h.dir = "ltr"; body.append(h); }
      const v = el("span", `cv-file-v v-${file.verdict}`, tr(file.verdict) + (file.score != null ? ` · ${file.score}/100` : "")); body.append(v);
    }
    parts.push(body, el("p", "cv-file-src", file.mine ? tr("mine") : tr("sample")));
    card.replaceChildren(...parts);
  }

  /* ---------- peeling ---------- */
  let spinUntil = 0;
  function setPeeled(n, quiet) {
    n = clamp(n, 0, 4);
    if (n === peeled) return;
    const up = n > peeled; peeled = n;
    paintCard(); persist();
    spinUntil = performance.now() + 2600;
    if (!quiet) {
      if (up) { ctx.sfx("whoosh", { dur: 0.45 }); ctx.sfx("pluck", { k: 4 + n * 2 }); ctx.announce(tr("peeled").replace("{l}", tr(`L${n - 1}`)) + `. ${tr(`L${n}`)}: ${tr(`d${n}`)}`); }
      else { ctx.sfx("tab"); ctx.announce(n === 0 ? tr("rebuilt") : `${tr(`L${n}`)}: ${tr(`d${n}`)}`); }
    }
    if (n === 4 && up) { ctx.discover("f-core", { ar: TXT.ar.fCore, en: TXT.en.fCore }); ctx.achieve?.("core"); }
    if (ctx.reduced()) for (let i = 0; i < 5; i++) layerT[i] = i < peeled ? 1 : 0;
    ctx.invalidate(1800);
  }
  const peel = () => setPeeled(peeled + 1);
  const unpeel = () => setPeeled(peeled - 1);
  const rebuild = () => { if (peeled) { setPeeled(0, true); ctx.sfx("shimmer", { n: 3 }); ctx.announce(tr("rebuilt")); } };
  for (let i = 0; i < 5; i++) layerT[i] = i < peeled ? 1 : 0;

  function onTap(info) {
    const h = engine.ray(info).intersectObject(cubes.mesh, false)[0];
    if (h) { if (peeled < 4) peel(); else rebuild(); }
  }
  function onKey(e) {
    if (e.key === "Enter" || e.key === " ") { if (peeled < 4) peel(); else rebuild(); return true; }
    if (e.key === "Backspace" || e.key === "Delete") { unpeel(); return true; }
    if (e.key === "r" || e.key === "R") { rebuild(); return true; }
    return false;
  }

  /* ---------- controls ---------- */
  const tools = makeTools(ctx, TXT);
  const g1 = tools.group("layer");
  tools.button(g1, { icon: "dive", text: "peel", onClick: () => { if (peeled < 4) peel(); } });
  tools.button(g1, { icon: "undo", text: "back", onClick: unpeel });
  tools.button(g1, { icon: "reset", text: "rebuild", onClick: rebuild });
  const g2 = tools.group("file");
  const ids = ["pdf", "exe", "docm"]; if (myScan()) ids.push("mine");
  const fb = ids.map((id) => tools.button(g2, { text: id === "mine" ? "myScan" : id, pressed: id === sampleId, onClick: (e, b) => { pick(id); press(fb, b); setPeeled(0, true); ctx.sfx("soft"); } }));
  tools.paint();
  pick(sampleId === "mine" && !myScan() ? "pdf" : sampleId);
  press(fb, fb[ids.indexOf(sampleId)] || fb[0]);

  function persist() { try { sessionStorage.setItem("cv-cyber", JSON.stringify({ sample: sampleId, peeled })); } catch { /* storage off */ } }

  /* ---------- the frame ---------- */
  let first = true;
  function update(dt, t) {
    const now = performance.now();
    let moving = false;
    for (let L = 0; L < 5; L++) {
      const goal = L < peeled ? 1 : 0;
      if (layerT[L] !== goal) { const s = dt * (goal ? 1.25 : 1.6); layerT[L] = goal ? Math.min(1, layerT[L] + s) : Math.max(0, layerT[L] - s); moving = true; }
    }
    const spin = !ctx.reduced() && now < spinUntil;
    if (moving || spin || first) {
      const pulse = 0.5 + 0.5 * Math.sin(t * 2.4);
      cells.forEach((c, i) => {
        const lt = layerT[c.L], k = clamp((lt - c.d) / 0.65, 0, 1), e = k * k * (3 - 2 * k);
        const r = 1 + e * (3.2 + c.sp * 0.6);
        tmpP.set(c.x * GAP, c.y * GAP, c.z * GAP).multiplyScalar(r).addScaledVector(c.dir, e * 1.5);
        tmpP.y += e * e * 2.2;
        tmpQ.setFromAxisAngle(c.spin, e * c.sp * 2.2);
        const s = SIZE * (1 - e) * (c.L === 4 ? 1.9 + (peeled === 4 ? pulse * 0.12 : 0) : 1);
        tmpS.setScalar(Math.max(0.0001, s));
        cubes.set(i, tmpP, tmpQ, tmpS);
        if (c.L === 4) cubes.setGlow(i, peeled === 4 ? 0.4 + pulse * 0.4 : 0.3);
      });
      cubes.count = cells.length; cubes.flush(false);
      first = false;
    }
    if (spin) group.rotation.y += dt * 0.35 * clamp((spinUntil - now) / 1200, 0, 1);
    return moving || spin || peeled === 4 && !ctx.reduced() && now < spinUntil + 4000;
  }
  function resize(w, h) { camera.aspect = w / h; camera.fov = w / h < 0.8 ? 56 : 40; camera.updateProjectionMatrix(); }
  function save() { saved.cam = rig.state; saved.sample = sampleId; saved.peeled = peeled; persist(); }
  function dispose() { save(); card.remove(); cubes.dispose(); disposeScene(scene); }
  return { scene, camera, rig, update, resize, onTap, onKey, save, dispose, paint: () => { tools.paint(); paintCard(); } };
}
