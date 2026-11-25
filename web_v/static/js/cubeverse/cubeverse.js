/* The Cubeverse shell: the calm page folds into cubes and becomes the world. This module is small;
 * it owns the world menu (dock), the world's caption and controls, the transitions (the page
 * morph, the cube wipe between worlds) and loads the 3D engine (core.js + three.js) and each world
 * only when they are needed. Without WebGL 2 it opens a lighter CSS gallery (fallback.js).
 * The support button and modal belong to the page (js/support.js) and work everywhere. */

const ICON = {
  home: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 11.5 12 5l8 6.5"/><path d="M6.5 10v9h11v-9"/></svg>',
  gravity: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4h10v10H7z"/><path d="M12 16.5V21m-3-2.6L12 21l3-2.6"/></svg>',
  architecture: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h16M5 20v-5h5v5M10 20v-10h5v10M15 20v-14h4v14"/></svg>',
  quantum: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 9h8v8H5z"/><path d="M9 5h10v10" stroke-dasharray="2 2.2"/><path d="M3 21c3-2.5 5-2.5 8 0s5 2.5 10 0" /></svg>',
  dimension: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 8.5h8v8h-8z"/><path d="m13.5 8 4-3 4 3v8l-4 3-4-3z"/><path d="M13.5 8l4 3 4-3M17.5 11v8"/></svg>',
  infinite: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 3h18v18H3z"/><path d="M7 7h10v10H7z"/><path d="M10.2 10.2h3.6v3.6h-3.6z"/></svg>',
  cyberscan: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m12 2.8 8 4.6v9.2l-8 4.6-8-4.6V7.4z"/><path d="m12 7.2 4.2 2.4v4.8L12 16.8l-4.2-2.4V9.6z"/><path d="M12 2.8v4.4M20 7.4l-3.8 2.2M4 7.4l3.8 2.2"/></svg>',
  badges: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 4h8v5a4 4 0 0 1-8 0z"/><path d="M8 6H5a3 3 0 0 0 3 4M16 6h3a3 3 0 0 1-3 4M12 13v3M10 16h4v4h-4z"/></svg>',
};

export const WORLDS = [
  { id: "gravity", tone: "dark", wipe: ["#2a1b6e", "#7c3aed"],
    ar: { title: "ملعب الجاذبية", short: "مكعبات تسقط وتتصادم: اسحبها وارمها، وغيّر اتجاه الجاذبية.",
      controls: ["اسحب مكعبًا وارمه، وأفلته ليطير.", "انقر في مكان فارغ لموجة دفع، ومرّر المؤشر بسرعة فوق المكعبات لتدفعها.", "أزرار الجاذبية (أو الأسهم عندما يكون التركيز على العالم) تقلب اتجاهها، وعلى الجوال يتبع زر «الإمالة» حركة جوالك.", "اسحب الخلفية لتدور حول المشهد، وكبّر بعجلة الفأرة أو بإصبعين."] },
    en: { title: "Gravity Playground", short: "Cubes fall and collide: drag and fling them, and turn gravity around.",
      controls: ["Drag a cube and throw it; let go and it flies.", "Click empty space for a shockwave; sweep fast across the cubes to push them.", "The gravity buttons (or the arrow keys while the world has focus) turn gravity; on a phone, Tilt follows your phone.", "Drag the background to orbit; wheel or pinch to zoom."] } },
  { id: "architecture", tone: "light", wipe: ["#e9e4ff", "#b9a6f5"],
    ar: { title: "عمارة المكعبات", short: "ابنِ أشكالًا من المكعبات، وبعض الأشكال تخفي مفاجأة هندسية.",
      controls: ["انقر على الأرضية أو على وجه مكعب لتضع مكعبًا، والنقر الأيمن أو الضغط المطوّل يزيله (أو أداة «امسح»).", "اختر اللون والحجم من الشريط بالأسفل، ومعهما «تراجع» و«مسح الكل».", "اسحب لتدور، وكبّر بالعجلة أو بإصبعين.", "لوحة المفاتيح: الأسهم تحرّك المؤشر، Enter يضع، Delete يزيل، Q وE للدوران.", "جرّب: برجًا، أو درجًا، أو بوابة، أو بئرًا، أو مكعبًا من المكعبات."] },
    en: { title: "Cube Architecture", short: "Build shapes from cubes; some shapes hide a geometric surprise.",
      controls: ["Click the floor or a cube's face to place a cube; right-click or long-press removes one (or use Erase).", "Pick a colour and a size below; Undo and Clear are there too.", "Drag to orbit; wheel or pinch to zoom.", "Keyboard: arrows move the marker, Enter places, Delete removes, Q and E orbit.", "Try a tower, stairs, a gate, a well or a cube of cubes."] } },
  { id: "quantum", tone: "dark", wipe: ["#03222b", "#0e7490"],
    ar: { title: "المكعبات الكمّية", short: "حقل من المكعبات تتداخل فيه الموجات، ومكعبات شبحية في أكثر من مكان حتى تلمسها. (تأثير فني، لا محاكاة فيزيائية).",
      controls: ["انقر على الحقل لتضع مصدر موجة، والموجات تتداخل.", "حرّك المؤشر فوق الحقل: ترتفع المكعبات القريبة منه، وأكثر مع السرعة.", "المكعبات الشبحية الطافية في عدة أماكن معًا: مرّر المؤشر عليها أو انقرها لتنهار إلى مكان واحد، وشريكها المتشابك ينهار معها.", "اسحب لتدور، وكبّر بالعجلة أو بإصبعين."], note: "تأثير فني مستوحى من أفكار الكم، وليس محاكاة فيزيائية حقيقية." },
    en: { title: "Quantum Cubes", short: "A field where waves interfere, and ghost cubes that are in several places until you touch them. (An artistic effect, not a physics simulation.)",
      controls: ["Click the field to drop a wave source; the waves interfere.", "Move the pointer over the field: cubes rise near it, more with speed.", "Ghost cubes float in several places at once: hover or click to collapse one, and its entangled partner collapses too.", "Drag to orbit; wheel or pinch to zoom."], note: "An artistic effect inspired by quantum ideas, not a real physics simulation." } },
  { id: "dimension", tone: "light", wipe: ["#f4efe6", "#d9cbb4"],
    ar: { title: "تحوّل الأبعاد", short: "عالم يتنقّل بسلاسة بين مساحة ثنائية الأبعاد مسطحة وثلاثية الأبعاد بمنظور.",
      controls: ["حرّك شريط 2D ↔ 3D: تنبسط الكاميرا إلى إسقاط متعامد أو تنفتح إلى منظور.", "«مسطح» و«متساوي القياس» و«منظور» تنقلك إلى زاوية، و«التواء» يثني المكان.", "ابحث عن الزاوية التي تنغلق فيها الأذرع الثلاثة على مثلث مستحيل.", "اسحب لتدور، وكبّر بالعجلة أو بإصبعين."] },
    en: { title: "Dimension Shift", short: "A cube world that glides between flat 2D space and 3D perspective.",
      controls: ["Move the 2D ↔ 3D slider: the camera flattens into an orthographic view or opens into perspective.", "Flat, Isometric and Perspective jump to a view; Warp bends the space.", "Find the angle where the three arms close into an impossible triangle.", "Drag to orbit; wheel or pinch to zoom."] } },
  { id: "infinite", tone: "dark", wipe: ["#1a0526", "#a21caf"],
    ar: { title: "المكعب اللانهائي", short: "مكعبات داخل مكعبات بلا نهاية: كل مستوى عالم هندسي صغير.",
      controls: ["مرّر العجلة أو باعد إصبعيك أو اضغط «اغطس» للتكبير، فالمكعبات داخل المكعبات لا تنتهي.", "انقر مكعبًا لتغطس إلى العالم التالي.", "اسحب لتدير البنية.", "لوحة المفاتيح: + و− للتكبير، والأسهم للتدوير."] },
    en: { title: "Infinite Cube", short: "Cubes nested inside cubes, without end: every level is a small geometric world.",
      controls: ["Scroll, pinch or press Dive to zoom; the cubes inside cubes never end.", "Click a cube to dive into the next world.", "Drag to turn the structure.", "Keyboard: + and − zoom, the arrows turn."] } },
  { id: "cyberscan", tone: "dark", wipe: ["#06142a", "#22b8e8"],
    ar: { title: "مكعب CyberScan", short: "ملف على هيئة مكعب: فكّكه طبقة بعد طبقة، من اسمه إلى بصمته، كما يقرؤه CyberScan.",
      controls: ["انقر على المكعب أو اضغط «انزع طبقة» لتنزع الغلاف الخارجي، و«أعِد طبقة» لتعيده.", "خمس طبقات: الاسم، أول البايتات، البنية، إنتروبيا المحتوى، ثم البصمة والحكم في اللبّ.", "اختر ملفًا من الأمثلة، أو «فحصي الأخير» إن كنت فحصت ملفًا في هذه النافذة.", "لوحة المفاتيح: Enter ينزع طبقة، Backspace يعيدها، R يعيد البناء. اسحب لتدور وكبّر بالعجلة."] },
    en: { title: "CyberScan Cube", short: "A file as a cube: take it apart layer by layer, from its name to its fingerprint, the way CyberScan reads it.",
      controls: ["Click the cube or press Peel to remove the outer shell; Put one back returns it.", "Five layers: the name, the first bytes, the structure, the content entropy, then the fingerprint and the verdict at the core.", "Pick an example file, or My last scan if you scanned a file in this tab.", "Keyboard: Enter peels, Backspace puts back, R rebuilds. Drag to orbit, wheel to zoom."] } },
];
/* small achievements, kept in this browser (localStorage "cv-badges") */
const BADGES = [
  { id: "shapes", ar: ["مهندس الأشكال", "اكتشف الأشكال الخمسة في عمارة المكعبات."], en: ["Shape finder", "Find all five shapes in Cube Architecture."] },
  { id: "depth20", ar: ["الغوّاص", "اغطس إلى العمق 20 في المكعب اللانهائي."], en: ["Deep diver", "Dive to depth 20 in the Infinite Cube."] },
  { id: "impacts100", ar: ["مئة اصطدام", "100 اصطدام في ملعب الجاذبية."], en: ["Hundred impacts", "100 impacts in the Gravity Playground."] },
  { id: "explorer", ar: ["المستكشف", "زُر العوالم الستة كلها."], en: ["Explorer", "Visit all six worlds."] },
  { id: "core", ar: ["قلب الملف", "فكّك مكعب CyberScan حتى بصمته."], en: ["To the core", "Take the CyberScan Cube apart down to its fingerprint."] },
];
const badges = (() => {
  let st = { got: {}, n: {}, seen: [] };
  try { const s = JSON.parse(localStorage.getItem("cv-badges") || "null"); if (s && typeof s === "object") st = { got: s.got || {}, n: s.n || {}, seen: Array.isArray(s.seen) ? s.seen : [] }; } catch { /* storage off */ }
  let t = 0;
  const store = () => { clearTimeout(t); t = setTimeout(() => { try { localStorage.setItem("cv-badges", JSON.stringify(st)); } catch { /* storage off */ } }, 250); };
  return { st, store };
})();
const UI = {
  ar: { dock: "عوالم المكعبات", home: "العودة إلى الصفحة الهادئة", help: "طريقة اللعب", hideHelp: "إخفاء", of: "من", tools: "أدوات العالم",
    canvas: "عالم تفاعلي ثلاثي الأبعاد", found: "اكتشاف", loading: "يجهّز العالم…", welcome: "مرحبًا بك في عالم المكعبات", worldN: "العالم",
    fallbackNote: "متصفحك لا يدعم WebGL 2، فهذه نسخة أخف من العوالم بمكعبات CSS.", exploreAgain: "العودة إلى عالم المكعبات", keysHint: "الأرقام 1–6 تنقلك بين العوالم.",
    badges: "الأوسمة", badgesOf: "{n} من {m}", badge: "وسام جديد", locked: "لم يُفتح بعد", earned: "حصلت عليه" },
  en: { dock: "Cubeverse worlds", home: "Back to the calm page", help: "How to play", hideHelp: "Hide", of: "of", tools: "World controls",
    canvas: "Interactive 3D world", found: "Discovered", loading: "Preparing the world…", welcome: "Welcome to the Cubeverse", worldN: "World",
    fallbackNote: "Your browser has no WebGL 2, so here is a lighter version of the worlds made with CSS cubes.", exploreAgain: "Back to the Cubeverse", keysHint: "Keys 1–6 move between worlds.",
    badges: "Badges", badgesOf: "{n} of {m}", badge: "New badge", locked: "Not yet earned", earned: "Earned" },
};

let page = null, built = false, engine = null, core = null, fallback = null, mode = "";   // mode: "gl" | "css"
let current = null, currentId = "", busy = false, queued = null, inside = false, savedScroll = 0;
const mods = new Map(), discovered = new Set();
const el = {};
const lang = () => page.lang;
const L = () => UI[lang()];
const reduced = () => page.motionOff();
const sfx = (n, o) => page.sfx(n, o);
const ss = (k, v) => { try { if (v === undefined) return sessionStorage.getItem(k); sessionStorage.setItem(k, v); } catch { /* storage off */ } return null; };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const worldOf = (id) => WORLDS.find((w) => w.id === id);
const h = (tag, cls, attrs = {}) => { const n = document.createElement(tag); if (cls) n.className = cls; for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); return n; };

function loadCss() {
  if (document.querySelector('link[data-cv-css]')) return Promise.resolve();
  return new Promise((res) => {
    const l = h("link", "", { rel: "stylesheet", "data-cv-css": "" });
    l.href = new URL("../../cubeverse.css", import.meta.url).href;
    l.onload = res; l.onerror = res; document.head.append(l);
  });
}

/* ---------------- the DOM the Cubeverse adds (once) ---------------- */
function build() {
  if (built) return;
  built = true;
  // the dock: the way back, then the five worlds (one tab stop; arrows move between them)
  const dock = el.dock = h("nav", "cv-dock", { "aria-label": "" });
  const home = el.home = h("button", "cv-home", { type: "button", "data-go": "calm" });
  home.innerHTML = ICON.home;
  dock.append(home, h("span", "cv-sep", { "aria-hidden": "true" }));
  el.chips = WORLDS.map((w, i) => {
    const b = h("button", "cv-chip", { type: "button", "data-go": w.id, "data-n": String(i + 1) });
    b.innerHTML = `${ICON[w.id]}<span class="cv-chip-label"></span>`;
    b.addEventListener("pointerenter", () => { if (mode === "gl") loadWorld(w.id).catch(() => {}); }, { once: true });
    dock.append(b); return b;
  });
  dock.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-go]"); if (!b) return;
    if (b.dataset.go === "calm") leave(); else go(b.dataset.go, b);
  });
  dock.addEventListener("keydown", (e) => {
    const items = [home, ...el.chips], i = items.indexOf(document.activeElement); if (i < 0) return;
    const rtl = document.documentElement.dir === "rtl";
    let j = -1;
    if (e.key === (rtl ? "ArrowLeft" : "ArrowRight")) j = (i + 1) % items.length;
    else if (e.key === (rtl ? "ArrowRight" : "ArrowLeft")) j = (i - 1 + items.length) % items.length;
    else if (e.key === "Home") j = 0; else if (e.key === "End") j = items.length - 1;
    if (j >= 0) { e.preventDefault(); roving(items[j]); items[j].focus(); }
  });
  // the badges: a small button at the end of the dock and its panel
  const bb = el.badgeBtn = h("button", "cv-badge-btn", { type: "button", "aria-expanded": "false", "aria-controls": "cv-badges" });
  bb.innerHTML = `${ICON.badges}<span class="cv-badge-n"></span>`;
  dock.append(h("span", "cv-sep", { "aria-hidden": "true" }), bb);
  el.badges = h("section", "cv-badges", { id: "cv-badges", hidden: "", "aria-labelledby": "cv-badges-t" });
  bb.addEventListener("click", (e) => { e.stopPropagation(); toggleBadges(); });
  el.badges.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); toggleBadges(false); bb.focus(); } });
  document.addEventListener("pointerdown", (e) => { if (!el.badges.hidden && !el.badges.contains(e.target) && !bb.contains(e.target)) toggleBadges(false); });
  document.getElementById("sp-top-slot").append(dock);
  // the caption and the discovery card sit under the header, whatever its height
  const top = document.querySelector(".sp-top");
  new ResizeObserver(() => document.body.style.setProperty("--cv-head", `${Math.round(top.getBoundingClientRect().height)}px`)).observe(top);

  // the stage: caption, canvas, controls
  const root = el.root = h("div", "cv-root", { hidden: "" });
  const hud = el.hud = h("section", "cv-hud", { "aria-labelledby": "cv-title" });
  hud.innerHTML = `<p class="cv-step" id="cv-step"></p><h2 id="cv-title" tabindex="-1"></h2><p class="cv-short" id="cv-short"></p>
    <button class="cv-help-btn" id="cv-help-btn" type="button" aria-expanded="false" aria-controls="cv-help"></button>
    <div class="cv-help" id="cv-help" hidden><ul id="cv-controls"></ul><p class="cv-note" id="cv-note"></p><p class="cv-keys" id="cv-keys"></p></div>`;
  const stage = el.stage = h("div", "cv-stage");
  const canvas = el.canvas = h("canvas", "cv-canvas", { tabindex: "0", role: "application", "aria-describedby": "cv-short cv-sr" });
  const sr = h("div", "cv-sr", { id: "cv-sr" });
  const css = el.css = h("div", "cv-css", { hidden: "" });
  stage.append(canvas, css, sr);
  const tools = el.tools = h("div", "cv-tools", { role: "toolbar", "aria-label": "" });
  const found = el.found = h("div", "cv-found", { "aria-hidden": "true" });
  const live = el.live = h("p", "cv-live", { "aria-live": "polite" });
  const loading = el.loading = h("div", "cv-loading", { hidden: "" });
  loading.innerHTML = '<span class="cv-spin" aria-hidden="true"><i></i><i></i><i></i></span><span class="cv-loading-text"></span>';
  root.append(hud, stage, tools, found, live, loading, el.badges);   // tab order: caption, world, controls
  document.querySelector(".sp-foot").after(root);
  el.wipe = h("div", "cv-wipe", { "aria-hidden": "true" });
  el.morph = h("div", "cv-morph", { "aria-hidden": "true" });
  document.body.append(el.wipe, el.morph);
  el.helpBtn = hud.querySelector("#cv-help-btn"); el.help = hud.querySelector("#cv-help");
  el.helpBtn.addEventListener("click", () => toggleHelp());
  hud.addEventListener("keydown", (e) => { if (e.key === "Escape" && !el.help.hidden) { e.stopPropagation(); toggleHelp(false); el.helpBtn.focus(); } });

  // keys 1..5 move between worlds (not while typing or in a dialog)
  document.addEventListener("keydown", (e) => {
    if (!inside || e.altKey || e.ctrlKey || e.metaKey || page.isModalOpen()) return;
    if (e.target.closest && e.target.closest("input, textarea, select, dialog")) return;
    const n = Number(e.key); if (n >= 1 && n <= WORLDS.length) { e.preventDefault(); go(WORLDS[n - 1].id, el.chips[n - 1]); }
  });
  document.addEventListener("sp:lang", () => { paint(); current?.paint?.(); });
  document.addEventListener("sp:modal", (e) => { if (!engine) return; if (e.detail) engine.pause("modal"); else if (inside) engine.resume("modal"); });
  paint();
}
function paintBadges() {
  const u = L(), got = badges.st.got, n = BADGES.filter((b) => got[b.id]).length;
  el.badgeBtn.querySelector(".cv-badge-n").textContent = `${n}/${BADGES.length}`;
  el.badgeBtn.setAttribute("aria-label", `${u.badges}: ${fill(u.badgesOf, { n, m: BADGES.length })}`); el.badgeBtn.title = u.badges;
  const head = h("h3", "", { id: "cv-badges-t", tabindex: "-1" }); head.textContent = u.badges;
  const ul = h("ul");
  for (const b of BADGES) {
    const [name, how] = b[lang()] || b.en, on = !!got[b.id];
    const li = h("li", on ? "is-on" : "");
    li.innerHTML = `<span class="cv-badge-ico" aria-hidden="true">${ICON.badges}</span>`;
    const tx = h("span", "cv-badge-tx"); const nb = h("b"); nb.textContent = name; const sm = h("small"); sm.textContent = how; tx.append(nb, sm);
    const st = h("span", "cv-badge-st"); st.textContent = on ? u.earned : u.locked;
    li.append(tx, st); ul.append(li);
  }
  el.badges.replaceChildren(head, ul);
}
function toggleBadges(force) {
  const open = force ?? el.badges.hidden;
  if (open) paintBadges();
  el.badges.hidden = !open; el.badgeBtn.setAttribute("aria-expanded", String(open));
  if (open) el.badges.querySelector("h3")?.focus({ preventScroll: true });
}
const fill = (s, o) => s.replace(/\{(\w+)\}/g, (m, k) => (o[k] != null ? o[k] : m));
function achieve(id) {
  const b = BADGES.find((x) => x.id === id); if (!b || badges.st.got[id]) return false;
  badges.st.got[id] = Date.now(); badges.store();
  discover(`badge-${id}`, { ar: `${UI.ar.badge}: ${b.ar[0]}`, en: `${UI.en.badge}: ${b.en[0]}` });
  sfx("shimmer", { n: 6 });
  if (el.badgeBtn) { paintBadges(); el.badgeBtn.classList.remove("is-new"); void el.badgeBtn.offsetWidth; el.badgeBtn.classList.add("is-new"); }
  return true;
}
function count(key, by = 1) {
  const n = (badges.st.n[key] = (Number(badges.st.n[key]) || 0) + by); badges.store();
  if (key === "impacts" && n >= 100) achieve("impacts100");
  return n;
}
function visit(id) {
  if (!badges.st.seen.includes(id)) { badges.st.seen.push(id); badges.store(); }
  if (WORLDS.every((w) => badges.st.seen.includes(w.id))) achieve("explorer");
}
function toggleHelp(force) {
  const open = force ?? el.help.hidden;
  el.help.hidden = !open; el.helpBtn.setAttribute("aria-expanded", String(open));
  el.helpBtn.textContent = open ? L().hideHelp : L().help;
  el.hud.classList.toggle("is-open", open);
}
function roving(active) { for (const b of [el.home, ...el.chips]) b.tabIndex = b === active ? 0 : -1; }
function paint() {
  const u = L();
  el.dock.setAttribute("aria-label", u.dock);
  el.home.setAttribute("aria-label", u.home); el.home.title = u.home;
  WORLDS.forEach((w, i) => { const t = w[lang()], c = el.chips[i]; c.querySelector(".cv-chip-label").textContent = t.title; c.setAttribute("aria-label", `${i + 1}. ${t.title}`); c.title = t.title; });
  el.tools.setAttribute("aria-label", u.tools);
  el.loading.querySelector(".cv-loading-text").textContent = u.loading;
  el.helpBtn.textContent = el.help.hidden ? u.help : u.hideHelp;
  paintBadges();
  if (currentId) caption(currentId);
}
function caption(id) {
  const w = worldOf(id), t = w[lang()], u = L(), i = WORLDS.indexOf(w);
  document.getElementById("cv-step").textContent = `${u.worldN} ${i + 1} ${u.of} ${WORLDS.length}`;
  document.getElementById("cv-title").textContent = t.title;
  document.getElementById("cv-short").textContent = t.short;
  const ul = document.getElementById("cv-controls"); ul.replaceChildren(...t.controls.map((c) => { const li = h("li"); li.textContent = c; return li; }));
  document.getElementById("cv-note").textContent = mode === "css" ? u.fallbackNote : t.note || "";
  document.getElementById("cv-keys").textContent = u.keysHint;
  el.canvas.setAttribute("aria-label", `${t.title}. ${u.canvas}`);
  el.canvas.setAttribute("aria-roledescription", u.canvas);
  document.getElementById("cv-sr").textContent = `${t.controls.join(" ")} ${t.note || ""}`;
}
function setTone(tone) { document.body.dataset.cvTone = tone; }
function announce(text) { el.live.textContent = ""; setTimeout(() => { el.live.textContent = text; }, 60); }
// a discovery: a short, quiet card at the top, said aloud too (once per visit each)
// a short confirmation in the same quiet card (a link copied, an image saved)
function flash(text) {
  const n = h("span", "cv-found-n"); n.textContent = text;
  el.found.replaceChildren(n);
  el.found.classList.remove("is-on"); void el.found.offsetWidth; el.found.classList.add("is-on");
  clearTimeout(el.found.t); el.found.t = setTimeout(() => el.found.classList.remove("is-on"), 2400);
}
function discover(key, names) {
  const name = names[lang()] || names.en;
  const first = !discovered.has(key); discovered.add(key);
  el.found.replaceChildren();
  const k = h("span", "cv-found-k"); k.textContent = L().found;
  const n = h("span", "cv-found-n"); n.textContent = name;
  el.found.append(k, n);
  el.found.classList.remove("is-on"); void el.found.offsetWidth; el.found.classList.add("is-on");
  clearTimeout(el.found.t); el.found.t = setTimeout(() => el.found.classList.remove("is-on"), 3600);
  announce(`${L().found}: ${name}`);
  if (first) sfx("shimmer", { n: 5 });
  return first;
}

/* ---------------- loading ---------------- */
async function loadCore() {
  if (mode) return mode;
  try {
    // no WebGL 2 here: don't download the 3D engine at all
    const probe = document.createElement("canvas").getContext("webgl2");
    if (!probe) throw new Error("no webgl2");
    probe.getExtension("WEBGL_lose_context")?.loseContext();
    core = await import("./core.js");
    engine = new core.Engine(el.canvas);
    mode = "gl";
    window.__cubeverse = { engine, stats: () => engine.frameStats(), world: () => currentId };
  } catch (e) {
    if (!/webgl/i.test(String(e && e.message))) console.warn("Cubeverse: 3D unavailable,", e);
    fallback = await import("./fallback.js");
    mode = "css";
    el.canvas.hidden = true; el.css.hidden = false;
    window.__cubeverse = { mode: "css", world: () => currentId };
  }
  return mode;
}
function loadWorld(id) {
  if (!mods.has(id)) {
    const p = import(`./world-${id}.js`).catch((e) => { mods.delete(id); throw e; });
    mods.set(id, p);
  }
  return mods.get(id);
}
function ctxFor(id) {
  return { engine, core, THREE: core && core.THREE, id, lang, reduced, sfx, announce, discover, setTone, tools: el.tools,
    text: (o) => o[lang()] || o.en, invalidate: (ms) => engine && engine.invalidate(ms), achieve, count, toast: flash };
}
let loaderTimer = 0;
function showLoader(on) {
  clearTimeout(loaderTimer);
  if (on) loaderTimer = setTimeout(() => { el.loading.hidden = false; }, 260);
  else el.loading.hidden = true;
}

/* ---------------- a world in, a world out ---------------- */
async function mount(id) {
  const w = worldOf(id);
  if (current) { try { current.dispose(); } catch (e) { console.warn(e); } current = null; }
  el.tools.replaceChildren();
  setTone(w.tone);
  document.body.dataset.cvWorld = id;
  currentId = id; ss("cv-world", id);
  if (mode === "gl") {
    const m = await loadWorld(id);
    current = m.create(ctxFor(id));
    engine.setWorld(current);
  } else {
    current = fallback.create(id, el.css, ctxFor(id), WORLDS);
  }
  visit(id);
  el.chips.forEach((c) => { const on = c.dataset.go === id; c.setAttribute("aria-current", on ? "true" : "false"); c.classList.toggle("is-on", on); });
  roving(el.chips[WORLDS.indexOf(w)]);
  caption(id);
}
async function go(id, from) {
  if (!inside) return;
  if (id === currentId && !busy) { from?.focus(); return; }
  if (busy) { queued = id; return; }
  busy = true;
  const w = worldOf(id);
  try {
    showLoader(true);
    if (mode === "gl") await loadWorld(id);
    showLoader(false);
    sfx("whoosh", { dur: 0.5 });
    await wipe(w.wipe, () => mount(id));
    const t = w[lang()];
    announce(`${L().worldN} ${WORLDS.indexOf(w) + 1}: ${t.title}. ${t.short}`);
  } catch (e) {
    console.warn("Cubeverse world:", e); showLoader(false);
  } finally {
    busy = false;
    if (queued && queued !== currentId) { const q = queued; queued = null; go(q, el.chips[WORLDS.findIndex((x) => x.id === q)]); }
    else queued = null;
  }
}

/* ---------------- the cube wipe between worlds ---------------- */
async function wipe(colors, swap) {
  if (reduced() || !el.wipe.animate) {
    await swap();
    if (el.stage.animate && !reduced()) el.stage.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180 });
    return;
  }
  const W = innerWidth, H = innerHeight, size = Math.max(64, Math.min(130, Math.min(W, H) / 5.5));
  const cols = Math.ceil(W / size), rows = Math.ceil(H / size), rtl = document.documentElement.dir === "rtl";
  const layer = el.wipe; layer.replaceChildren(); layer.classList.add("is-on");
  const tiles = [];
  for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
    const t = h("i");
    t.style.left = `${c * size}px`; t.style.top = `${r * size}px`; t.style.width = `${size + 1}px`; t.style.height = `${size + 1}px`;
    t.style.background = `linear-gradient(135deg, ${colors[0]}, ${colors[1]})`;
    const order = (rtl ? cols - 1 - c : c) + r;
    tiles.push([t, order]); layer.append(t);
  }
  const maxO = cols + rows - 2 || 1;
  await Promise.all(tiles.map(([t, o]) => t.animate([{ transform: "perspective(700px) rotateY(90deg) scale(.55)", opacity: 0 }, { transform: "none", opacity: 1 }],
    { duration: 300, delay: (o / maxO) * 260, easing: "cubic-bezier(.3,.7,.2,1)", fill: "both" }).finished.catch(() => {})));
  await swap();
  if (engine && mode === "gl") { engine.invalidate(600); await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))); }
  await Promise.all(tiles.map(([t, o]) => t.animate([{ transform: "none", opacity: 1 }, { transform: "perspective(700px) rotateX(-90deg) scale(.55)", opacity: 0 }],
    { duration: 320, delay: (o / maxO) * 240, easing: "cubic-bezier(.6,0,.4,1)", fill: "both" }).finished.catch(() => {})));
  layer.replaceChildren(); layer.classList.remove("is-on");
}

/* ---------------- the page folds into cubes (and back) ---------------- */
function tilesFromPage() {
  const vw = innerWidth, vh = innerHeight;
  const els = [...document.querySelectorAll(".sp-main [data-cv]")].map((n) => [n, n.getBoundingClientRect()])
    .filter(([, r]) => r.width > 4 && r.height > 4 && r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw);
  const area = els.reduce((a, [, r]) => a + r.width * r.height, 0) || 1;
  const maxTiles = engine && engine.tier === 0 ? 70 : vw < 600 ? 90 : 150;
  const T = Math.max(20, Math.min(84, Math.sqrt(area / maxTiles)));
  const out = [], photo = document.getElementById("sp-photo");
  let k = 0;
  for (const [n, r] of els) {
    const cols = Math.max(1, Math.round(r.width / T)), rows = Math.max(1, Math.round(r.height / T)), w = r.width / cols, hh = r.height / rows;
    const isPhoto = n.dataset.cv === "photo";
    for (let j = 0; j < rows; j++) for (let i = 0; i < cols; i++) {
      const t = h("i", isPhoto ? "is-photo" : `c${k++ % 3}`);
      t.style.left = `${r.left + i * w}px`; t.style.top = `${r.top + j * hh}px`; t.style.width = `${w + 0.5}px`; t.style.height = `${hh + 0.5}px`;
      if (isPhoto) { t.style.backgroundImage = `url("${photo.currentSrc || photo.src}")`; t.style.backgroundSize = `${r.width}px ${r.height}px`; t.style.backgroundPosition = `${-i * w}px ${-j * hh}px`; }
      out.push({ t, x: r.left + i * w + w / 2, y: r.top + j * hh + hh / 2 });
    }
  }
  return out;
}
function flight(tiles, origin) {
  const vw = innerWidth, vh = innerHeight, cx = vw / 2, cy = vh * 0.38;
  const maxD = Math.hypot(vw, vh) || 1;
  return tiles.map((o) => {
    const ang = Math.random() * Math.PI * 2, rad = Math.random() * Math.min(vw, vh) * 0.16;
    return { ...o, dx: cx + Math.cos(ang) * rad - o.x, dy: cy + Math.sin(ang) * rad * 0.6 - o.y, dz: -200 - Math.random() * 400,
      rx: (Math.random() - 0.5) * 540, ry: (Math.random() - 0.5) * 540, delay: (Math.hypot(o.x - origin.x, o.y - origin.y) / maxD) * 380 };
  });
}
async function foldOut() {
  const main = document.getElementById("sp-main"), foot = document.querySelector(".sp-foot");
  if (reduced() || !main.animate) { main.hidden = true; foot.hidden = true; return; }
  const r = page.explore.getBoundingClientRect(), origin = { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  const plan = flight(tilesFromPage(), origin);
  const layer = el.morph; layer.replaceChildren(...plan.map((p) => p.t)); layer.classList.add("is-on");
  const fade = main.animate([{ opacity: 1, filter: "blur(0)" }, { opacity: 0, filter: "blur(6px)" }], { duration: 420, easing: "ease-in", fill: "forwards" });
  foot.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 300, fill: "forwards" });
  const anims = plan.map((p) => p.t.animate([
    { transform: "translate3d(0,0,0) rotateX(0) rotateY(0) scale(.7)", opacity: 0 },
    { transform: "translate3d(0,0,0) rotateX(0) rotateY(0) scale(1)", opacity: 1, offset: 0.16 },
    { transform: `translate3d(${p.dx * 0.25}px, ${p.dy * 0.25 - 30}px, 80px) rotateX(${p.rx * 0.35}deg) rotateY(${p.ry * 0.35}deg) scale(.92)`, opacity: 1, offset: 0.5 },
    { transform: `translate3d(${p.dx}px, ${p.dy}px, ${p.dz}px) rotateX(${p.rx}deg) rotateY(${p.ry}deg) scale(.22)`, opacity: 0 },
  ], { duration: 1150, delay: p.delay, easing: "cubic-bezier(.55,0,.25,1)", fill: "both" }));
  await fade.finished.catch(() => {});
  main.hidden = true; foot.hidden = true;
  fade.cancel(); main.getAnimations().forEach((a) => a.cancel()); foot.getAnimations().forEach((a) => a.cancel());
  return Promise.all(anims.map((a) => a.finished.catch(() => {}))).then(() => { layer.replaceChildren(); layer.classList.remove("is-on"); });
}
async function foldIn(placed) {
  const main = document.getElementById("sp-main"), foot = document.querySelector(".sp-foot");
  main.hidden = false; foot.hidden = false;
  placed();
  if (reduced() || !main.animate) return;
  main.style.opacity = "0"; foot.style.opacity = "0";
  const r = page.explore.getBoundingClientRect(), origin = { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  const plan = flight(tilesFromPage(), origin);
  const layer = el.morph; layer.replaceChildren(...plan.map((p) => p.t)); layer.classList.add("is-on");
  const anims = plan.map((p) => p.t.animate([
    { transform: `translate3d(${p.dx}px, ${p.dy}px, ${p.dz}px) rotateX(${p.rx}deg) rotateY(${p.ry}deg) scale(.22)`, opacity: 0 },
    { transform: `translate3d(${p.dx * 0.25}px, ${p.dy * 0.25 - 30}px, 80px) rotateX(${p.rx * 0.35}deg) rotateY(${p.ry * 0.35}deg) scale(.92)`, opacity: 1, offset: 0.5 },
    { transform: "translate3d(0,0,0) rotateX(0) rotateY(0) scale(1)", opacity: 1, offset: 0.84 },
    { transform: "translate3d(0,0,0) rotateX(0) rotateY(0) scale(1)", opacity: 0 },
  ], { duration: 1000, delay: 380 - p.delay, easing: "cubic-bezier(.3,.6,.25,1)", fill: "both" }));
  await wait(720);
  main.style.opacity = ""; foot.style.opacity = "";
  main.animate([{ opacity: 0, filter: "blur(6px)" }, { opacity: 1, filter: "blur(0)" }], { duration: 520, easing: "ease-out" });
  foot.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 400 });
  await Promise.all(anims.map((a) => a.finished.catch(() => {})));
  layer.replaceChildren(); layer.classList.remove("is-on");
}

/* ---------------- entering and leaving ---------------- */
export async function enter(p) {
  page = p;
  if (inside || busy) return;
  busy = true;
  try {
    await loadCss();
    build(); paint();
    savedScroll = scrollY;
    const id = worldOf(ss("cv-world")) ? ss("cv-world") : "gravity";
    sfx("whoosh", { dur: 0.9 });
    page.away(true);
    // the engine and the first world load while the page folds away
    const ready = loadCore().then(async (m) => { if (m === "gl") await loadWorld(id); return m; });
    const folding = foldOut();
    document.body.classList.add("cv-on");
    el.root.hidden = false; el.stage.classList.remove("is-in");
    inside = true;
    let done = false; ready.finally(() => { done = true; });
    await folding.then(() => { if (!done) showLoader(true); });
    await ready;
    showLoader(false);
    window.scrollTo(0, 0);
    if (!current || currentId !== id) await mount(id);
    else { setTone(document.body.dataset.cvTone || worldOf(id).tone); caption(id); }
    engine?.resume("calm");
    requestAnimationFrame(() => { el.stage.classList.add("is-in"); document.body.classList.add("cv-ready"); });
    document.getElementById("cv-title").focus({ preventScroll: true });
    const t = worldOf(id)[lang()];
    announce(`${L().welcome}. ${L().worldN} ${WORLDS.findIndex((w) => w.id === id) + 1}: ${t.title}. ${t.short}`);
    page.markVisited?.();
  } catch (e) {
    console.warn("Cubeverse:", e);
    await exitNow();
    throw e;
  } finally { busy = false; }
}
async function exitNow() {
  inside = false;
  document.body.classList.remove("cv-on", "cv-ready");
  if (el.root) el.root.hidden = true;
  const main = document.getElementById("sp-main"), foot = document.querySelector(".sp-foot");
  main.hidden = false; foot.hidden = false; main.style.opacity = ""; foot.style.opacity = "";
  page.away(false);
}
// back to the calm page: the world pauses (its state is kept), the cubes fly back into the card
async function leave() {
  if (!inside || busy) return;
  busy = true;
  try {
    sfx("whoosh", { dur: 0.8, down: true });
    current?.save?.();
    engine?.pause("calm");
    el.stage.classList.remove("is-in");
    if (!reduced()) await wait(260);
    inside = false;
    document.body.classList.remove("cv-on", "cv-ready");
    el.root.hidden = true;
    const back = foldIn(() => window.scrollTo(0, savedScroll));
    page.away(false);
    await back;
    page.explore.focus({ preventScroll: true });
    announce("");
  } finally { busy = false; }
}
