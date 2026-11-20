// Support the developer: words (AR/EN), the bank details, and Bit, a small 2D robot with emotions.

const T = {
  ar: {
    kicker: "المطوّر", name: "مهدي آل حاجي", role: "مطوّر برمجيات وباحث في الذكاء الاصطناعي",
    bio1: "مطوّر برمجيات وباحث في الذكاء الاصطناعي، مهتم بتطوير الأنظمة الذكية والحلول التقنية المبتكرة، مع تركيز على الأمن السيبراني وتعلّم الآلة وهندسة البرمجيات.",
    bio2: "أعمل على تحويل الأفكار والنماذج النظرية إلى منتجات تقنية قابلة للتطبيق، وأقود حالياً التطوير التقني لمشروع CyberScan، وهو مشروع متعدد المنصات لتحليل الملفات واكتشاف التهديدات الأمنية المحتملة.",
    t1: "الأمن السيبراني", t2: "تعلّم الآلة", t3: "هندسة البرمجيات",
    cta: "ادعم المطوّر", ctaOpen: "إخفاء بيانات الدعم",
    bankTitle: "الدعم عبر التحويل البنكي", bankNote: "يمكنك الدعم بالتحويل من أي بنك سعودي باستخدام رقم الآيبان، أو بمسح الرمز من تطبيق البنك.",
    holder: "اسم المستفيد", bank: "البنك", bankName: "مصرف الراجحي", iban: "رقم الآيبان (IBAN)", account: "رقم الحساب",
    copy: "نسخ", copied: "تم النسخ", qr: "امسحه من تطبيق البنك",
    thanks: "شكرًا لدعمك، كل مساهمة تساعد على استمرار CyberScan وتطويره.", back: "العودة إلى CyberScan",
    title: "ادعم المطوّر · CyberScan", photo: "صورة مهدي آل حاجي", qrAlt: "رمز QR لبيانات الحساب البنكي",
  },
  en: {
    kicker: "The developer", name: "Mahdi Al-Hajji", role: "Software developer and AI researcher",
    bio1: "Software developer and AI researcher, focused on intelligent systems and innovative technical solutions, with an emphasis on cybersecurity, machine learning and software engineering.",
    bio2: "I turn ideas and theoretical models into working technical products, and I currently lead the technical development of CyberScan, a multi-platform project for analysing files and detecting potential security threats.",
    t1: "Cybersecurity", t2: "Machine learning", t3: "Software engineering",
    cta: "Support the developer", ctaOpen: "Hide the support details",
    bankTitle: "Support by bank transfer", bankNote: "You can transfer from any Saudi bank using the IBAN, or scan the code from your bank app.",
    holder: "Beneficiary", bank: "Bank", bankName: "Al Rajhi Bank", iban: "IBAN", account: "Account number",
    copy: "Copy", copied: "Copied", qr: "Scan it from your bank app",
    thanks: "Thank you for your support: every contribution keeps CyberScan going and growing.", back: "Back to CyberScan",
    title: "Support the developer · CyberScan", photo: "Photo of Mahdi Al-Hajji", qrAlt: "QR code with the bank account details",
  },
};
let lang = "ar";
try { lang = localStorage.getItem("cyberscan-lang") === "en" ? "en" : "ar"; } catch { /* storage off */ }
const $ = (id) => document.getElementById(id);
const cta = $("sp-cta"), bank = $("sp-bank");

function paint() {
  const t = T[lang];
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.title = t.title;
  document.querySelectorAll("[data-t]").forEach((n) => { if (t[n.dataset.t]) n.textContent = t[n.dataset.t]; });
  cta.querySelector("span").textContent = bank.hidden ? t.cta : t.ctaOpen;
  $("sp-photo").alt = t.photo; $("sp-qr").alt = t.qrAlt;
  $("sp-lang").textContent = lang === "ar" ? "EN" : "ع";
}
$("sp-lang").addEventListener("click", () => { lang = lang === "ar" ? "en" : "ar"; try { localStorage.setItem("cyberscan-lang", lang); } catch { /* storage off */ } paint(); });
cta.addEventListener("click", () => {
  bank.hidden = !bank.hidden;
  cta.setAttribute("aria-expanded", String(!bank.hidden));
  paint();
  if (!bank.hidden) { bank.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" }); robot.cheer(); }
});
document.querySelectorAll(".sp-copy").forEach((b) => b.addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(b.dataset.copy); } catch {
    const ta = document.createElement("textarea"); ta.value = b.dataset.copy; document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove();
  }
  const toast = $("sp-toast"); toast.textContent = T[lang].copied; toast.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => { toast.hidden = true; }, 1600);
}));
paint();

/* ---------------- Bit: a small 2D robot with a mind of its own ----------------
 * Two minds work together:
 *   - a language model (POST /api/bit: Amazon Bedrock on the site, Ollama on a computer) is asked
 *     every few seconds what Bit should do next: mood, tactic, expression, cursor effect, a line;
 *   - a fast local engine runs every frame: five emotions that drift with what the visitor does, a
 *     softmax over tactics, and a small bandit that learns which tactics bring the pointer closer to
 *     the support button (remembered between visits). It fills every gap the model leaves.
 * On a computer the page draws the only cursor: the system one is hidden, and on the first click
 * the page takes real control of it (Pointer Lock) so Bit can genuinely pull it. Esc always gives
 * it back (the browser enforces that). On a phone Bit floats with the phone's tilt and reacts to
 * taps. Reduced motion: Bit stays calm and no cursor tricks are played. */
const robot = (() => {
  const canvas = $("sp-robot"), ctx = canvas.getContext("2d");
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fine = matchMedia("(pointer: fine)").matches;
  const token = (document.querySelector('meta[name="cyberscan-token"]') || {}).content || "";
  let calm = false;
  try { calm = localStorage.getItem("sp-bit-calm") === "1"; } catch { /* storage off */ }
  const drawnCursor = fine && !reduced;
  if (drawnCursor) document.body.classList.add("sp-fake-cursor");
  const mischiefOK = () => drawnCursor && !calm;

  const rnd = (a = 1, b) => (b === undefined ? Math.random() * a : a + Math.random() * (b - a));
  const pickOf = (arr) => arr[Math.floor(rnd(arr.length))];
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const W = () => innerWidth, H = () => innerHeight;
  let dpr = 1;
  function size() { dpr = Math.min(devicePixelRatio || 1, 2); canvas.width = W() * dpr; canvas.height = H() * dpr; }
  size(); addEventListener("resize", size);
  const born = performance.now();

  // ---------- perception
  const P = { x: W() / 2, y: H() / 2, vx: 0, vy: 0, last: performance.now(), still: 0, over: "" };
  const V = { x: W() / 2, y: H() / 2 };   // the page's own cursor while it holds the pointer
  const shown = { x: P.x, y: P.y, scale: 1, rot: 0 };
  let pointerSeen = false, locked = false;
  function hoverOf(el) {
    return !el || !el.closest ? "" : el.closest("#sp-cta") ? "cta" : el.closest(".sp-photo") ? "photo" : el.closest(".sp-copy") ? "copy" : el.closest("a,button") ? "link" : el.closest("p,h1,li") ? "text" : "";
  }
  addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch") return;
    const now = performance.now(), dt = Math.max(1, now - P.last);
    let x = e.clientX, y = e.clientY;
    if (locked) {
      let [mx, my] = trickInput(e.movementX, e.movementY);
      const a = aggression();
      if (a > 0) {
        const c = ctaCenter(), dx = c.x - V.x, dy = c.y - V.y, d = Math.hypot(dx, dy) || 1, ux = dx / d, uy = dy / d;
        const along = mx * ux + my * uy;                       // + toward the button, - away from it
        const px = mx - along * ux, py = my - along * uy;      // the sideways part
        const k = along < 0 ? 1 - 0.62 * a : 1 + 0.45 * a;     // heavy away, slippery toward
        const bend = along < 0 ? Math.abs(along) * 0.35 * a : 0; // moving away curves the path back
        mx = ux * (along * k + bend) + px * (1 - 0.25 * a);
        my = uy * (along * k + bend) + py * (1 - 0.25 * a);
        if (along < -2) fight(Math.abs(along));                // the visitor is pushing back
      }
      V.x = clamp(V.x + mx, 0, W() - 1); V.y = clamp(V.y + my, 0, H() - 1); x = V.x; y = V.y;
    }
    P.vx = (x - P.x) / dt * 16; P.vy = (y - P.y) / dt * 16;
    P.x = x; P.y = y; P.last = now; P.still = 0; pointerSeen = true;
    P.over = hoverOf(locked ? document.elementFromPoint(x, y) : e.target);
  }, { passive: true });
  // how strongly Bit bends the cursor right now: mood and tactic, minus the visitor's frustration
  let frustration = 0, backOffUntil = 0, lastYank = 0;
  function aggression() {
    const now = performance.now();
    if (!locked || calm || now < backOffUntil || !bank.hidden) return 0;
    const tacticBoost = tactic === "grab" ? 0.35 : tactic === "tug" || tactic === "block" ? 0.25 : tactic === "beckon" ? 0.15 : 0;
    return clamp((0.35 + E.mischief * 0.6 + tacticBoost) * (1 - frustration * 0.7), 0, 0.85);
  }
  function fight(amount) {
    frustration = clamp(frustration + amount * 0.004, 0, 1);
    if (frustration > 0.85 && performance.now() > backOffUntil) {
      // a clever pest knows when to stop: back off, say so, try something else later
      backOffUntil = performance.now() + rnd(3500, 6000); frustration = 0.3; E.mischief = 0.2; E.affection = Math.min(1, E.affection + 0.3);
      bubble = { text: pickOf(lang === "ar" ? ["حسنًا حسنًا 😅", "آسف! 🙈", "سأتركك قليلًا", "خلاص خلاص"] : ["ok ok 😅", "sorry! 🙈", "fine, for now", "alright alright"]), until: performance.now() + 2000 };
      nextTalk = performance.now() + 3000;
    }
  }
  const ctaCenter = () => { const r = cta.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, r }; };

  // ---------- feelings
  const E = { joy: 0.45, mischief: 0.35, affection: 0.2, boredom: 0.1, curiosity: 0.4 };
  const rest = { joy: 0.4, mischief: 0.3, affection: 0.15, boredom: 0, curiosity: 0.35 };
  function feel(dt, o) {
    const k = dt / 1000, nudge = (n, a) => { E[n] = clamp(E[n] + a * k, 0, 1); };
    for (const n in E) E[n] += (rest[n] - E[n]) * Math.min(1, 0.35 * k);
    if (o.awayFast && !o.bankOpen) nudge("mischief", 0.9 + rnd(0.4));
    if (o.toward) { nudge("joy", 0.6); nudge("mischief", -0.5); }
    if (o.near) { nudge("affection", 1.1); nudge("joy", 0.5); nudge("mischief", -0.8); }
    if (o.still > 2500) nudge("boredom", 0.35); else nudge("boredom", -0.9);
    if (P.over === "photo" || P.over === "text") nudge("curiosity", 0.5);
    if (o.bankOpen) { nudge("joy", 0.4); nudge("affection", 0.3); nudge("mischief", -1); }
    if (calm) E.mischief = Math.min(E.mischief, 0.05);
  }
  const MOOD_SHIFT = { playful: { joy: 0.3 }, mischievous: { mischief: 0.5 }, affectionate: { affection: 0.5 }, excited: { joy: 0.5 },
    bored: { boredom: 0.5 }, curious: { curiosity: 0.5 }, proud: { joy: 0.3 }, shy: { affection: 0.3, mischief: -0.3 }, grumpy: { mischief: 0.3, joy: -0.3 }, silly: { joy: 0.4, mischief: 0.2 } };

  // ---------- tactics, the local chooser and what it has learned
  const TACTICS = {
    follow: (o) => 0.5 + E.affection * 0.4, orbit: (o) => 0.2 + E.joy * 0.8 + (o.near ? 0.6 : 0),
    tug: (o) => (mischiefOK() ? 0.1 + E.mischief * 1.6 + (o.awayFast ? 0.5 : 0) : -9),
    grab: (o) => (mischiefOK() && o.speed > 6 ? E.mischief * 1.3 - 0.3 : -9),
    block: (o) => (o.away ? E.mischief * 1.2 : -1), beckon: (o) => (o.near ? -0.5 : 0.25 + (o.away ? 0.4 : 0)),
    dance: (o) => (o.near || o.bankOpen ? 0.4 + E.joy + E.affection : -9), peek: () => E.curiosity * 0.9 - 0.2,
    nap: () => E.boredom * 2.2 - 0.6, zoom: () => E.joy * 0.6 + E.mischief * 0.4 - 0.4, hide: () => E.affection < 0.3 ? E.curiosity * 0.5 - 0.2 : -1,
    spin: () => E.joy * 0.7 - 0.3,
  };
  let Q = { tug: 0, grab: 0, block: 0, beckon: 0, zoom: 0, spin: 0 };
  try { Q = { ...Q, ...JSON.parse(localStorage.getItem("sp-bit-q") || "{}") }; } catch { /* storage off */ }
  let tactic = "follow", tacticSince = 0, nextDecision = 0, judge = null;
  let ai = null;   // the model's latest decision {tactic, expression, cursor_fx, until}
  function setTactic(name, now, o) {
    if (name === tactic) return;
    if (judge && now - judge.at > 1400) {
      const gained = (judge.dist - o.dist) / Math.max(120, judge.dist);
      Q[judge.name] = clamp(Q[judge.name] * 0.85 + gained * 0.15, -1, 1);
      try { localStorage.setItem("sp-bit-q", JSON.stringify(Q)); } catch { /* storage off */ }
      judge = null;
    }
    if (name in Q) judge = { name, at: now, dist: o.dist };
    tactic = name; tacticSince = now; maybeSay(name);
  }
  function decide(now, o) {
    nextDecision = now + rnd(260, 900);
    if (ai && now < ai.until) { if (TACTICS[ai.tactic](o) > -5) setTactic(ai.tactic, now, o); return; }
    const temp = 0.25 + E.boredom * 0.3 + (1 - E.affection) * 0.15;
    const exps = Object.entries(TACTICS).map(([n, f]) => [n, Math.exp((f(o) + (Q[n] || 0) * 0.8 + (n === tactic ? 0.15 : 0) + rnd(-0.15, 0.15)) / temp)]);
    let r = rnd(exps.reduce((a, [, e]) => a + e, 0)), pick = exps[0][0];
    for (const [n, e] of exps) { r -= e; if (r <= 0) { pick = n; break; } }
    setTactic(pick, now, o);
  }

  // ---------- asking the model (a few seconds apart; the local engine never waits for it)
  let asking = false, nextAsk = performance.now() + 1500, aiSource = "local";
  async function askModel(now, o) {
    if (asking || now < nextAsk || document.hidden || !token) return;
    asking = true; nextAsk = now + rnd(5000, 7000);
    const state = { lang, touch: !fine, dist: Math.round(o.dist), trend: o.toward ? "toward" : o.away ? "away" : "still", speed: Math.round(o.speed),
      still: Math.round(o.still / 1000), hover: P.over, bankOpen: o.bankOpen, age: Math.round((now - born) / 1000), tactic,
      joy: E.joy, mischief: E.mischief, affection: E.affection, boredom: E.boredom, outcomes: Q };
    try {
      const res = await fetch("/api/bit", { method: "POST", headers: { "Content-Type": "application/json", "X-CyberScan-Token": token }, body: JSON.stringify(state) });
      const d = res.ok ? await res.json() : null;
      if (d && d.source && d.source !== "none") {
        aiSource = d.source;
        ai = { ...d, until: performance.now() + 4500 };
        for (const [k, v] of Object.entries(MOOD_SHIFT[d.mood] || {})) E[k] = clamp(E[k] + v, 0, 1);
        if (d.line) { bubble = { text: d.line, until: performance.now() + 2200 }; nextTalk = performance.now() + 3000; }
        nextDecision = 0;
      } else if (d && d.reason !== "rate") nextAsk = now + 30000;   // no model here: stop asking for a while
    } catch { nextAsk = now + 30000; }
    asking = false;
  }

  // ---------- body
  const B = { x: W() / 2, y: H() * 0.45, vx: 0, vy: 0, tilt: 0, flip: 1, eyeX: 0, eyeY: 0, squash: 1, spin: 0 };
  let particles = [], cheerUntil = 0, bubble = null, nextTalk = 0, grabbing = false;
  const tilt = { x: 0, y: 0, on: false };
  function steer(now, o, dt) {
    const c = o.c, k = dt / 16, t = (now - tacticSince) / 1000;
    const vlen = Math.hypot(P.vx, P.vy) || 1;
    let tx = P.x - (P.vx / vlen) * 46 - 14, ty = P.y - (P.vy / vlen) * 46 - 26;
    if (!pointerSeen) { tx = c.x + Math.cos(now / 900) * 120; ty = c.y - 120 + Math.sin(now / 700) * 30; }
    switch (tactic) {
      case "orbit": tx = P.x + Math.cos(t * 3) * 70; ty = P.y + Math.sin(t * 3) * 50 - 20; break;
      case "block": { const ax = P.x - c.x, ay = P.y - c.y, d = Math.hypot(ax, ay) || 1; tx = P.x + (ax / d) * 60; ty = P.y + (ay / d) * 60; break; }
      case "beckon": tx = P.x * 0.4 + c.x * 0.6; ty = P.y * 0.4 + c.y * 0.6 - 40; break;
      case "dance": tx = c.x + Math.sin(t * 4) * 60; ty = c.r.top - 46 - Math.abs(Math.sin(t * 8)) * 18; break;
      case "peek": { const card = document.querySelector(".sp-card").getBoundingClientRect(); tx = document.documentElement.dir === "rtl" ? card.left - 20 : card.right + 20; ty = clamp(P.y, card.top + 40, card.bottom - 40); break; }
      case "nap": tx = B.x; ty = Math.min(H() - 60, B.y + 0.6); break;
      case "grab": tx = P.x; ty = P.y - 18; break;
      case "zoom": tx = W() / 2 + Math.cos(t * 2.2) * W() * 0.38; ty = H() / 2 + Math.sin(t * 4.4) * H() * 0.3; break;
      case "hide": tx = P.x < W() / 2 ? W() - 40 : 40; ty = H() - 60; break;
      case "spin": tx = P.x + 40; ty = P.y - 50; break;
    }
    if (!fine) {   // phones: the phone's tilt is gravity; Bit also heads for the last tap
      tx = B.x + tilt.x * 60 + (P.x - B.x) * 0.25; ty = B.y + tilt.y * 60 + (P.y - B.y) * 0.25;
    }
    const stiff = tactic === "grab" || tactic === "zoom" ? 0.07 : 0.035;
    B.vx = (B.vx + (tx - B.x) * stiff * k + rnd(-0.3, 0.3) * (E.joy + E.mischief)) * 0.86;
    B.vy = (B.vy + (ty - B.y) * stiff * k + Math.sin(now / 260) * 0.15) * 0.86;
    B.x = clamp(B.x + B.vx * k, 30, W() - 30); B.y = clamp(B.y + B.vy * k, 40, H() - 30);
    B.tilt += (clamp(B.vx * 0.04, -0.5, 0.5) - B.tilt) * 0.15;
    B.spin = tactic === "spin" ? B.spin + 0.25 * k : B.spin * 0.9;
    if (Math.abs(B.vx) > 0.4) B.flip = B.vx > 0 ? 1 : -1;
    const lx = P.x - B.x, ly = P.y - B.y, ll = Math.hypot(lx, ly) || 1;
    B.eyeX += ((lx / ll) * 3.5 - B.eyeX) * 0.2; B.eyeY += ((ly / ll) * 3 - B.eyeY) * 0.2;
  }

  // ---------- the cursor and what Bit does to it
  let cursorFx = "none", fxUntil = 0, trail = [], ghosts = [];
  const FX_BY_MOOD = () => (E.mischief > 0.55 ? pickOf(["shake", "rubber", "ghosts", "spin", "jelly", "shrink"]) : E.affection > 0.5 ? pickOf(["heart", "sparkle", "grow", "trail"]) : pickOf(["trail", "sparkle", "none", "magnet"]));
  function cursor(now, o, dt) {
    if (now > fxUntil) { cursorFx = ai && now < ai.until && ai.cursor_fx ? ai.cursor_fx : FX_BY_MOOD(); fxUntil = now + rnd(2500, 5000); }
    if (calm) cursorFx = "none";
    const dx = o.c.x - P.x, dy = o.c.y - P.y, d = Math.hypot(dx, dy) || 1;
    if (locked) {
      // real control: Bit moves the cursor itself (bounded; the hand on the mouse always wins)
      frustration = Math.max(0, frustration - dt / 9000);
      const a = aggression();
      let force = a === 0 || o.dist < 60 ? 0 : (tactic === "grab" ? 7 : tactic === "tug" ? 3.6 : tactic === "beckon" ? 1.6 : tactic === "block" ? 2.2 : 0.8) * a;
      if (a > 0 && o.dist < 260) force += (260 - o.dist) / 260 * 4 * a;             // the button's gravity well
      if (cursorFx === "magnet" && a > 0) force += 1.5;
      if (a > 0.45 && o.dist > 250 && now - lastYank > rnd(5000, 9000) && o.speed > 1) {   // a sudden yank
        lastYank = now; force += o.dist * rnd(0.12, 0.22) / (dt / 16);
        shown.scale = 1.6; particles.push({ x: V.x, y: V.y, vx: 0, vy: 0, life: 1, kind: "ring" });
        if (now > nextTalk) { bubble = { text: pickOf(lang === "ar" ? ["هوب! 😈", "تعال!", "خطفتك!"] : ["yoink! 😈", "come here!", "gotcha!"]), until: now + 1500 }; nextTalk = now + 2500; }
      }
      if (trick === "freeze" || trick === "carry" || trick === "orbit") force = 0;
      if (force) { V.x = clamp(V.x + (dx / d) * force, 0, W() - 1); V.y = clamp(V.y + (dy / d) * force, 0, H() - 1); P.x = V.x; P.y = V.y; }
      trickTick(now, o);
      shown.x = V.x; shown.y = V.y;
    } else {
      const pull = mischiefOK() && o.speed > 3 ? (tactic === "tug" ? 26 : tactic === "grab" ? 40 : cursorFx === "rubber" ? 30 : 10) : 0;
      const ease = o.speed > 3 ? 0.3 : 0.6;   // slow pointer: the drawn cursor sits exactly on the real one
      shown.x += (P.x + (dx / d) * pull - shown.x) * ease; shown.y += (P.y + (dy / d) * pull - shown.y) * ease;
    }
    if (cursorFx === "shake" && o.speed > 2) { shown.x += rnd(-2.5, 2.5); shown.y += rnd(-2.5, 2.5); }
    const targetScale = cursorFx === "shrink" ? 0.55 : cursorFx === "grow" ? 1.6 : cursorFx === "jelly" ? 1 + Math.sin(now / 70) * 0.25 : o.near ? 1.25 : 1;
    shown.scale += (targetScale - shown.scale) * 0.15;
    shown.rot = cursorFx === "spin" ? shown.rot + 0.18 : shown.rot * 0.85;
    grabbing = tactic === "grab" && (locked || (mischiefOK() && o.speed > 3));
    if (cursorFx === "trail" || cursorFx === "sparkle") { trail.push({ x: shown.x, y: shown.y, life: 1, s: cursorFx === "sparkle" }); if (trail.length > 24) trail.shift(); }
    if (cursorFx === "ghosts" && rnd() < 0.3) ghosts.push({ x: shown.x + rnd(-30, 30), y: shown.y + rnd(-30, 30), life: 1 });
  }

  // pointer lock: the first click hands the cursor to the page; clicks land where Bit's cursor is
  document.addEventListener("click", (e) => {
    if (locked && e.isTrusted) {
      e.preventDefault(); e.stopPropagation();
      const target = document.elementFromPoint(V.x, V.y);
      ripple(V.x, V.y);
      if (catchClick(target)) return;
      if (target) { if (target.focus) target.focus({ preventScroll: true }); target.click(); }
      return;
    }
    if (!locked && drawnCursor && e.isTrusted && document.body.requestPointerLock) {
      V.x = e.clientX; V.y = e.clientY;
      try { const r = document.body.requestPointerLock(); if (r && r.catch) r.catch(() => {}); } catch { /* refused */ }
    }
  }, true);
  document.addEventListener("pointerlockchange", () => {
    locked = document.pointerLockElement === document.body;
    if (locked) { E.mischief = Math.max(E.mischief, 0.6); bubble = { text: lang === "ar" ? "الآن المؤشر لي 😈 (Esc)" : "the cursor's mine now 😈 (Esc)", until: performance.now() + 2600 }; }
  });
  addEventListener("pointerdown", (e) => { if (!locked) { shown.x = e.clientX; shown.y = e.clientY; } ripple(locked ? V.x : e.clientX, locked ? V.y : e.clientY); }, { passive: true });
  function ripple(x, y) { particles.push({ x, y, vx: 0, vy: 0, life: 1, kind: "ring" }); }

  // ---------- tricks: real effects on the cursor and the page while the page holds the pointer
  // Each trick is short, has a cooldown, is chosen by mood + what has worked before (a bandit,
  // remembered between visits) and never runs when Bit is calm, backing off, or the visitor is
  // already at the button or has the details open.
  const TRICKS = {
    invert:   { ms: 1600, w: () => E.mischief * 1.2, ar: ["مقلوب! 🙃", "يمين؟ يسار؟"], en: ["flipped! 🙃", "left? right?"] },
    freeze:   { ms: 1100, w: () => E.mischief, ar: ["جلست عليه 😌", "استراحة!"], en: ["I'm sitting on it 😌", "break time!"] },
    teleport: { ms: 300, w: () => 0.5 + E.mischief * 0.6, ar: ["تيليبورت ✨", "اختصرت لك الطريق"], en: ["teleport ✨", "shortcut!"] },
    carry:    { ms: 1700, w: () => E.mischief * 1.1 + E.joy * 0.3, ar: ["سأوصلك 🚀", "اركب معي"], en: ["I'll take you 🚀", "hop on"] },
    slowmo:   { ms: 1800, w: () => E.mischief * 0.8, ar: ["بطيييء…", "حركة بطيئة 🐢"], en: ["sloooow…", "slow motion 🐢"] },
    turbo:    { ms: 1400, w: () => E.joy * 0.8, ar: ["توربو! ⚡", "أسرع!"], en: ["turbo! ⚡", "faster!"] },
    wobble:   { ms: 1800, w: () => E.joy * 0.5 + E.mischief * 0.5, ar: ["دايخ 😵", "تمايل"], en: ["dizzy 😵", "wobble"] },
    orbit:    { ms: 2000, w: () => E.affection * 0.8 + E.joy * 0.4, ar: ["لف لف 🌀", "حول الزر"], en: ["round and round 🌀", "orbit!"] },
    field:    { ms: 2200, w: () => E.mischief * 0.9, ar: ["ممنوع المرور 🛑", "حقل قوة!"], en: ["no entry 🛑", "force field!"] },
    dodge:    { ms: 3000, w: () => E.mischief * 0.7 + E.curiosity * 0.4, ar: ["الأزرار تهرب 😂", "اتبع الزر الصحيح"], en: ["buttons run away 😂", "only one button stays"] },
    chase:    { ms: 2600, w: () => E.affection * 0.7 + E.joy * 0.5, ar: ["الزر قادم إليك 💜", "هو يحبك"], en: ["the button's coming 💜", "it likes you"] },
    scroll:   { ms: 900, w: () => (Math.abs(ctaCenter().y - H() / 2) > H() * 0.3 ? 1 : -9), ar: ["من هنا 👇", "انزل معي"], en: ["this way 👇", "scroll with me"] },
  };
  let trick = null, nextTrick = performance.now() + 4000, trickStart = 0, trickFrom = null, field = null;
  let TQ = {};
  try { TQ = JSON.parse(localStorage.getItem("sp-bit-tricks") || "{}"); } catch { /* storage off */ }
  function trickAllowed(o) { return locked && !calm && performance.now() > backOffUntil && bank.hidden && o.dist > 90; }
  function startTrick(now, o) {
    const scores = Object.entries(TRICKS).map(([n, t]) => [n, t.w() + (TQ[n] || 0) + rnd(-0.3, 0.3)]).filter(([, s]) => s > -5);
    const exps = scores.map(([n, s]) => [n, Math.exp(s / 0.35)]);
    let r = rnd(exps.reduce((a, [, e]) => a + e, 0)), name = exps[0][0];
    for (const [n, e] of exps) { r -= e; if (r <= 0) { name = n; break; } }
    trick = name; trickStart = now; trickFrom = o.dist;
    const t = TRICKS[name];
    if (now > nextTalk - 1500) { bubble = { text: pickOf(t[lang]), until: now + 1500 }; nextTalk = now + 2600; }
    if (name === "teleport") {
      const c = ctaCenter(), ang = rnd(Math.PI * 2);
      V.x = clamp(c.x + Math.cos(ang) * 120, 0, W() - 1); V.y = clamp(c.y + Math.sin(ang) * 90, 0, H() - 1); P.x = V.x; P.y = V.y;
      particles.push({ x: V.x, y: V.y, vx: 0, vy: 0, life: 1, kind: "ring" });
    }
    if (name === "field") {   // a wall between the cursor and the way out: perpendicular to "away"
      const c = ctaCenter(), dx = V.x - c.x, dy = V.y - c.y, d = Math.hypot(dx, dy) || 1;
      field = { x: V.x + (dx / d) * 40, y: V.y + (dy / d) * 40, nx: dx / d, ny: dy / d };
    }
    if (name === "scroll") { const c = ctaCenter(); scrollBy({ top: (c.y - H() / 2) * 0.8, behavior: "smooth" }); }
  }
  function endTrick(o) {
    if (!trick) return;
    const gained = (trickFrom - o.dist) / Math.max(120, trickFrom);
    TQ[trick] = clamp((TQ[trick] || 0) * 0.8 + gained * 0.4, -1, 1);
    try { localStorage.setItem("sp-bit-tricks", JSON.stringify(TQ)); } catch { /* storage off */ }
    if (trick === "dodge" || trick === "chase") resetDodge();
    trick = null; field = null; nextTrick = performance.now() + rnd(3500, 7500) * (1 + frustration * 2);
  }
  // the visitor's own movement, transformed by the running trick
  function trickInput(mx, my) {
    const now = performance.now();
    switch (trick) {
      case "invert": return [-mx, -my];
      case "freeze": case "carry": case "orbit": return [mx * 0.08, my * 0.08];
      case "slowmo": return [mx * 0.3, my * 0.3];
      case "turbo": return [mx * 2.2, my * 2.2];
      case "wobble": { const a = Math.sin(now / 90) * 0.9; return [mx * Math.cos(a) - my * Math.sin(a), mx * Math.sin(a) + my * Math.cos(a)]; }
      case "field": {
        if (!field) return [mx, my];
        const out = mx * field.nx + my * field.ny, beyond = (V.x + mx - field.x) * field.nx + (V.y + my - field.y) * field.ny;
        if (out > 0 && beyond > 0) { particles.push({ x: V.x, y: V.y, vx: 0, vy: 0, life: 0.6, kind: "ring" }); return [mx - field.nx * out * 2.2, my - field.ny * out * 2.2]; }
        return [mx, my];
      }
      default: return [mx, my];
    }
  }
  // every frame while a trick runs
  function trickTick(now, o) {
    if (!trick) { if (trickAllowed(o) && now > nextTrick && aggression() > 0.25) startTrick(now, o); return; }
    const t = (now - trickStart) / 1000;
    if (!trickAllowed(o) || now - trickStart > TRICKS[trick].ms) { endTrick(o); return; }
    if (trick === "carry") { V.x += (B.x + 10 - V.x) * 0.25; V.y += (B.y + 22 - V.y) * 0.25; P.x = V.x; P.y = V.y; grabbing = true; }
    if (trick === "orbit") { const c = o.c, r = Math.max(70, o.dist * 0.9); V.x = c.x + Math.cos(t * 4) * r; V.y = c.y + Math.sin(t * 4) * r * 0.7; P.x = V.x; P.y = V.y; }
    if (trick === "dodge") dodge(o);
    if (trick === "chase") { const dx = V.x - o.c.x, dy = V.y - o.c.y, k = Math.min(1, t / 1.2); cta.style.translate = `${clamp(dx * 0.35 * k, -160, 160)}px ${clamp(dy * 0.35 * k, -120, 120)}px`; }
  }
  // other buttons and links really move out of the cursor's way (the support button stays)
  const dodgers = () => [...document.querySelectorAll("a, button, .sp-tags li, .sp-copy")].filter((n) => n !== cta && !n.classList.contains("sp-calm") && n.offsetParent);
  function dodge(o) {
    for (const n of dodgers()) {
      const r = n.getBoundingClientRect(), cx = r.left + r.width / 2, cy = r.top + r.height / 2, dx = cx - V.x, dy = cy - V.y, d = Math.hypot(dx, dy) || 1;
      const push = d < 160 ? (160 - d) * 0.6 : 0;
      n.style.transition = "translate .25s ease-out"; n.style.translate = push ? `${(dx / d) * push}px ${(dy / d) * push}px` : "";
    }
  }
  function resetDodge() { for (const n of dodgers()) n.style.translate = ""; cta.style.translate = ""; }
  // the first click on anything but the support button is caught once ("are you sure?")
  const caught = new WeakSet();
  function catchClick(target) {
    if (!target || calm || !bank.hidden || target.closest("#sp-cta, .sp-copy, .sp-calm") || caught.has(target)) return false;
    const el = target.closest("a, button");
    if (!el || caught.has(el) || rnd() > 0.6 + E.mischief * 0.4) return false;
    caught.add(el);
    bubble = { text: pickOf(lang === "ar" ? ["متأكد؟ 🥺", "مو هذا! الزر هناك 👉", "أمسكتها! اضغط مرة ثانية"] : ["are you sure? 🥺", "not that one! 👉", "caught it! click again"]), until: performance.now() + 1900 };
    nextTalk = performance.now() + 2600; E.mischief = Math.min(1, E.mischief + 0.2);
    particles.push({ x: V.x, y: V.y, vx: 0, vy: 0, life: 1, kind: "ring" });
    return true;
  }

  // ---------- phones: tilt and taps
  function onTilt(e) {
    if (e.gamma == null) return;
    tilt.on = true; tilt.x = clamp(e.gamma / 35, -1, 1); tilt.y = clamp((e.beta - 35) / 35, -1, 1);
  }
  if (!fine) {
    const start = () => {
      const D = window.DeviceOrientationEvent;
      if (D && typeof D.requestPermission === "function") D.requestPermission().then((s) => { if (s === "granted") addEventListener("deviceorientation", onTilt); }).catch(() => {});
      else addEventListener("deviceorientation", onTilt);
    };
    addEventListener("pointerdown", (e) => {
      start();
      P.x = e.clientX; P.y = e.clientY; P.vx = 0; P.vy = 0; P.still = 0; pointerSeen = true; P.over = hoverOf(e.target);
      E.joy = Math.min(1, E.joy + 0.15);
    }, { passive: true, once: false });
  }

  // ---------- speech: pieces chosen by mood and moment (the model may speak too)
  const SAY = {
    ar: { away: ["لا لا لا", "إلى أين؟", "هيه!", "تعال هنا", "الزر هناك", "لا تهرب 😤"], near: ["يس!", "قريب جدًا", "اضغطه 🥺", "هيا هيا", "♥", "أنت تقريبًا هناك"], bored: ["زززز", "أنا هنا…", "ممل", "ألعب وحدي؟"],
      happy: ["شكرًا!", "أنت رائع", "♥♥", "يااي!", "أحبك يا صديقي"], tug: ["سأسحبك قليلًا", "هههه", "تعال تعال", "من هنا!"], peek: ["بيك-أ-بو", "أراك"], zoom: ["ووووش", "انطلاق!"], spin: ["دوخة 😵", "ويييي"] },
    en: { away: ["nope", "where to?", "hey!", "come back", "button's there", "don't run 😤"], near: ["yes!", "so close", "click it 🥺", "go go", "♥", "almost there"], bored: ["zzz", "still here…", "bored", "solo play?"],
      happy: ["thank you!", "you rock", "♥♥", "yay!", "best human"], tug: ["just a little pull", "hehe", "this way", "over here!"], peek: ["peekaboo", "I see you"], zoom: ["wheee", "zoom!"], spin: ["dizzy 😵", "wheee"] },
  };
  let lastObs = null;
  function maybeSay(reason) {
    const now = performance.now();
    if (now < nextTalk || reduced) return;
    const s = SAY[lang], o = lastObs;
    const pool = o && o.bankOpen ? s.happy : reason === "nap" ? s.bored : reason === "tug" || reason === "grab" ? s.tug : s[reason]
      || (o && o.near ? s.near : o && o.away ? s.away : null);
    if (!pool || rnd() > 0.35 + E.joy * 0.3 + E.mischief * 0.3) return;
    bubble = { text: pickOf(pool), until: now + 1700 };
    nextTalk = now + rnd(2200, 5200);
  }

  // ---------- the page plays along
  function page(o) {
    const beckon = (tactic === "beckon" || tactic === "dance") && !o.near && o.dist > 220;
    cta.style.transform = beckon ? `rotate(${Math.sin(performance.now() / 110) * 2}deg)` : o.near ? "scale(1.04)" : "";
  }

  // ---------- faces: the expression comes from the model when it spoke recently, else from the emotions
  function expression(now, o) {
    if (tactic === "nap") return "sleepy";
    if (now < cheerUntil || o.bankOpen) return pickOf(["starry", "love", "laugh"]);
    if (ai && now < ai.until && ai.expression) return ai.expression;
    if (tactic === "spin") return "dizzy";
    if (E.affection > 0.65) return o.near ? "love" : "happy";
    if (E.mischief > 0.7) return o.awayFast ? "angry" : "smug";
    if (E.mischief > 0.5) return "wink";
    if (E.boredom > 0.5) return "sad";
    if (E.curiosity > 0.6) return "curious";
    if (E.joy > 0.7) return "laugh";
    return "happy";
  }
  function face(expr, now, hue) {
    const eye = expr === "love" || expr === "starry" ? "#ff8fe6" : E.mischief > 0.5 ? "#5ef1ff" : "#9df7ff";
    ctx.fillStyle = eye; ctx.strokeStyle = eye; ctx.lineWidth = 1.8; ctx.lineCap = "round";
    const ex = B.eyeX * B.flip, ey = B.eyeY, blink = now % 3700 < 110 && expr !== "sleepy";
    const eyes = (fn) => { for (const s of [-1, 1]) fn(s * 6 + ex, -1 + ey, s); };
    const heart = (x, y, r) => { ctx.beginPath(); ctx.moveTo(x, y + r); ctx.bezierCurveTo(x - r * 1.6, y - r * 0.4, x - r * 0.6, y - r * 1.6, x, y - r * 0.5); ctx.bezierCurveTo(x + r * 0.6, y - r * 1.6, x + r * 1.6, y - r * 0.4, x, y + r); ctx.fill(); };
    const star = (x, y, r) => { ctx.beginPath(); for (let i = 0; i < 10; i++) { const a = -Math.PI / 2 + i * Math.PI / 5, rr = i % 2 ? r * 0.45 : r; ctx.lineTo(x + Math.cos(a) * rr, y + Math.sin(a) * rr); } ctx.closePath(); ctx.fill(); };
    const arc = (x, y, r, up) => { ctx.beginPath(); ctx.arc(x, y + (up ? 1.5 : -1.5), r, up ? Math.PI * 1.1 : 0.1, up ? Math.PI * 1.9 : Math.PI - 0.1); ctx.stroke(); };
    const mouth = (kind) => {
      ctx.strokeStyle = "#ff8fe6"; ctx.fillStyle = "#ff8fe6"; ctx.beginPath();
      if (kind === "o") ctx.arc(0, 6, 2.2, 0, Math.PI * 2), ctx.stroke();
      else if (kind === "open") { ctx.ellipse(0, 6, 3.6, 2.6 + Math.abs(Math.sin(now / 90)), 0, 0, Math.PI); ctx.fill(); }
      else if (kind === "frown") { ctx.arc(0, 9, 3.5, Math.PI * 1.15, Math.PI * 1.85); ctx.stroke(); }
      else if (kind === "smirk") { ctx.moveTo(-3, 6); ctx.quadraticCurveTo(1, 7.5, 4.5, 4.5); ctx.stroke(); }
      else if (kind === "flat") { ctx.moveTo(-3, 6); ctx.lineTo(3, 6); ctx.stroke(); }
      else if (kind === "wavy") { ctx.moveTo(-4, 6); ctx.quadraticCurveTo(-2, 4, 0, 6); ctx.quadraticCurveTo(2, 8, 4, 6); ctx.stroke(); }
      else { ctx.moveTo(-4, 5); ctx.quadraticCurveTo(0, 9 + E.joy * 2, 4, 5); ctx.stroke(); }
    };
    if (blink) { eyes((x, y) => { ctx.beginPath(); ctx.moveTo(x - 2.5, y); ctx.lineTo(x + 2.5, y); ctx.stroke(); }); mouth("smile"); return; }
    switch (expr) {
      case "love": eyes((x, y) => heart(x, y, 3.2 + Math.sin(now / 150) * 0.4)); mouth("smile"); break;
      case "starry": eyes((x, y) => star(x, y, 3.6)); mouth("open"); break;
      case "laugh": eyes((x, y) => arc(x, y, 2.6, true)); mouth("open"); break;
      case "cry_laugh": eyes((x, y) => arc(x, y, 2.6, true)); mouth("open"); ctx.fillStyle = "#5ec8ff"; ctx.beginPath(); ctx.ellipse(-10, 3 + (now / 40) % 8, 1.4, 2, 0, 0, Math.PI * 2); ctx.fill(); break;
      case "wink": eyes((x, y, s) => { if (s < 0) { ctx.beginPath(); ctx.moveTo(x - 2.5, y); ctx.lineTo(x + 2.5, y); ctx.stroke(); } else { ctx.beginPath(); ctx.ellipse(x, y, 2.6, 3.2, 0, 0, Math.PI * 2); ctx.fill(); } }); mouth("smirk"); break;
      case "surprised": eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y, 3.2, 4.2, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("o"); break;
      case "angry": eyes((x, y, s) => { ctx.beginPath(); ctx.ellipse(x, y + 0.5, 2.6, 2.2, 0, 0, Math.PI * 2); ctx.fill(); ctx.beginPath(); ctx.moveTo(x + s * 3.5, y - 5); ctx.lineTo(x - s * 2, y - 3); ctx.stroke(); }); mouth("frown"); break;
      case "sad": eyes((x, y, s) => { ctx.beginPath(); ctx.ellipse(x, y + 1, 2.4, 2.8, 0, 0, Math.PI * 2); ctx.fill(); ctx.beginPath(); ctx.moveTo(x - s * 3, y - 5); ctx.lineTo(x + s * 2, y - 3.5); ctx.stroke(); }); mouth("frown"); break;
      case "dizzy": eyes((x, y) => { ctx.beginPath(); for (let i = 0; i < 18; i++) { const a = i * 0.7 + now / 120, r = i * 0.18; ctx.lineTo(x + Math.cos(a) * r, y + Math.sin(a) * r); } ctx.stroke(); }); mouth("wavy"); break;
      case "sleepy": eyes((x, y) => arc(x, y + 1, 2.4, false)); mouth("o"); break;
      case "smug": eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y + 1, 2.8, 1.6, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("smirk"); break;
      case "curious": eyes((x, y, s) => { ctx.beginPath(); ctx.ellipse(x, y, s > 0 ? 3.4 : 2.2, s > 0 ? 4 : 2.6, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("flat"); break;
      case "neutral": eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y, 2.6, 3, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("flat"); break;
      default: eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y, 2.8, 3.4 + E.joy, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("smile");
    }
  }

  // ---------- drawing
  function drawCursor(now, o) {
    for (const t of trail) {
      t.life -= 0.05; if (t.life <= 0) continue;
      ctx.globalAlpha = t.life * 0.6; ctx.fillStyle = t.s ? (rnd() < 0.5 ? "#22e8ff" : "#ff4fd8") : "#c9a2ff";
      ctx.beginPath(); ctx.arc(t.x + (t.s ? rnd(-6, 6) : 0), t.y + (t.s ? rnd(-6, 6) : 0), t.s ? 1.6 : 2.5 * t.life + 0.5, 0, Math.PI * 2); ctx.fill();
    }
    trail = trail.filter((t) => t.life > 0);
    ghosts = ghosts.filter((g) => (g.life -= 0.04) > 0);
    const arrow = (x, y, alpha, scale, rot, heartShape) => {
      ctx.save(); ctx.globalAlpha = alpha; ctx.translate(x, y); ctx.rotate(rot); ctx.scale(scale, scale);
      if (heartShape) { ctx.fillStyle = "#ff4fd8"; ctx.beginPath(); ctx.moveTo(7, 16); ctx.bezierCurveTo(-4, 9, -1, 0, 7, 5); ctx.bezierCurveTo(15, 0, 18, 9, 7, 16); ctx.fill(); }
      else { ctx.fillStyle = "#fff"; ctx.strokeStyle = "#07040f"; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(0, 17); ctx.lineTo(4.5, 13); ctx.lineTo(8, 20); ctx.lineTo(10.5, 19); ctx.lineTo(7, 12); ctx.lineTo(12.5, 12); ctx.closePath(); ctx.fill(); ctx.stroke(); }
      ctx.restore();
    };
    for (const g of ghosts) arrow(g.x, g.y, g.life * 0.35, 1, 0, false);
    if (cursorFx === "rubber" && !locked) {   // a stretchy band from the real pointer to the drawn one
      ctx.strokeStyle = "rgba(201,162,255,.5)"; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(P.x, P.y); ctx.lineTo(shown.x, shown.y); ctx.stroke();
    }
    arrow(shown.x, shown.y, 1, shown.scale, shown.rot, cursorFx === "heart" || (o.near && E.affection > 0.6));
    if (grabbing) {
      ctx.strokeStyle = "#c9a2ff"; ctx.lineWidth = 3; ctx.lineCap = "round";
      ctx.beginPath(); ctx.moveTo(B.x, B.y + 6); ctx.quadraticCurveTo((B.x + shown.x) / 2, Math.max(B.y, shown.y) + 18, shown.x + 2, shown.y + 2); ctx.stroke();
    }
  }
  function draw(now, o) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W(), H());
    if (!reduced && rnd() < E.affection * 0.25 + E.mischief * 0.15 + (tactic === "nap" ? 0.04 : 0)) {
      const kind = tactic === "nap" ? "z" : E.affection > E.mischief ? "♥" : "✦";
      particles.push({ x: B.x + rnd(-12, 12), y: B.y - 20, vx: rnd(-0.6, 0.6), vy: rnd(-1.4, -0.6), life: 1, kind });
    }
    particles = particles.filter((p) => (p.life -= p.kind === "ring" ? 0.04 : 0.014) > 0);
    for (const p of particles) {
      ctx.globalAlpha = p.life;
      if (p.kind === "ring") { ctx.strokeStyle = "#22e8ff"; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(p.x, p.y, (1 - p.life) * 26, 0, Math.PI * 2); ctx.stroke(); continue; }
      p.x += p.vx; p.y += p.vy;
      ctx.fillStyle = p.kind === "♥" ? "#ff4fd8" : p.kind === "z" ? "#b3a7d6" : "#22e8ff"; ctx.font = "13px system-ui"; ctx.fillText(p.kind, p.x, p.y);
    }
    ctx.globalAlpha = 1;
    if (field) {   // the force field the cursor bounces off
      ctx.strokeStyle = `rgba(255,79,216,${0.5 + Math.sin(now / 80) * 0.3})`; ctx.lineWidth = 3; ctx.setLineDash([8, 6]);
      ctx.beginPath(); ctx.moveTo(field.x - field.ny * 90, field.y + field.nx * 90); ctx.lineTo(field.x + field.ny * 90, field.y - field.nx * 90); ctx.stroke(); ctx.setLineDash([]);
    }
    if (drawnCursor && pointerSeen) drawCursor(now, o);
    // Bit
    const happy = now < cheerUntil || o.bankOpen;
    B.squash += ((happy ? 1 + Math.sin(now / 90) * 0.06 : 1) - B.squash) * 0.2;
    ctx.save(); ctx.translate(B.x, B.y); ctx.rotate(B.tilt + B.spin); ctx.scale(B.flip * B.squash, 2 - B.squash);
    const flame = 6 + Math.sin(now / 50) * 2 + Math.abs(B.vy) * 0.6;
    const g = ctx.createRadialGradient(0, 20, 0, 0, 20, flame + 8); g.addColorStop(0, "rgba(34,232,255,.95)"); g.addColorStop(1, "rgba(180,108,255,0)");
    ctx.fillStyle = g; ctx.beginPath(); ctx.ellipse(0, 22 + flame / 2, 6, flame, 0, 0, Math.PI * 2); ctx.fill();
    const hue = 268 - E.mischief * 40 + E.affection * 50;
    const body = ctx.createLinearGradient(0, -22, 0, 22); body.addColorStop(0, `hsl(${hue},70%,72%)`); body.addColorStop(1, `hsl(${hue},55%,42%)`);
    ctx.fillStyle = body; ctx.beginPath(); ctx.ellipse(0, 0, 22, 20, 0, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "rgba(255,255,255,.35)"; ctx.beginPath(); ctx.ellipse(-8, -10, 7, 4, -0.5, 0, Math.PI * 2); ctx.fill();
    ctx.strokeStyle = `hsl(${hue},60%,75%)`; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(0, -19); ctx.quadraticCurveTo(4 * Math.sin(now / 200), -28, 0, -32); ctx.stroke();
    ctx.fillStyle = E.mischief > E.affection ? "#22e8ff" : "#ff4fd8"; ctx.beginPath(); ctx.arc(0, -33, 3.5 + Math.sin(now / 160), 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#0b0720"; ctx.beginPath(); ctx.ellipse(0, 1, 15, 11, 0, 0, Math.PI * 2); ctx.fill();
    face(expression(now, o), now, hue);
    if (E.affection > 0.3) { ctx.fillStyle = `rgba(255,79,216,${(E.affection - 0.3) * 0.9})`; for (const s of [-1, 1]) { ctx.beginPath(); ctx.ellipse(s * 11, 4, 3, 1.8, 0, 0, Math.PI * 2); ctx.fill(); } }
    ctx.restore();
    if (bubble && now < bubble.until) {
      ctx.font = "600 13px system-ui, 'Segoe UI', Tahoma"; const w = ctx.measureText(bubble.text).width + 18;
      const bx = clamp(B.x - w / 2, 8, W() - w - 8), by = B.y - 66;
      ctx.fillStyle = "rgba(26,16,64,.92)"; ctx.strokeStyle = "rgba(196,160,255,.5)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.roundRect(bx, by, w, 26, 13); ctx.fill(); ctx.stroke();
      ctx.fillStyle = "#f3eeff"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.direction = lang === "ar" ? "rtl" : "ltr";
      ctx.fillText(bubble.text, bx + w / 2, by + 13); ctx.textAlign = "start"; ctx.textBaseline = "alphabetic";
    }
  }

  // ---------- the loop
  let last = performance.now(), lastDist = null;
  let frameNo = 0;
  function frame(now) {
    requestAnimationFrame(frame);
    // calm moments (pointer still, no trick running) draw every other frame: half the work
    if (P.still > 2500 && !trick && tactic !== "zoom" && (frameNo++ & 1)) return;
    const dt = Math.min(50, now - last); last = now;
    if (document.hidden) return;
    P.still += dt;
    const c = ctaCenter(), dist = Math.hypot(P.x - c.x, P.y - c.y), speed = Math.hypot(P.vx, P.vy);
    P.vx *= 0.9; P.vy *= 0.9;
    const trend = lastDist === null ? 0 : lastDist - dist; lastDist = dist;
    const o = { c, dist, speed, still: P.still, near: dist < 140 || P.over === "cta", toward: trend > 1.2, away: trend < -1.2, awayFast: trend < -4, bankOpen: !bank.hidden };
    lastObs = o;
    feel(dt, o);
    askModel(now, o);
    if (now > nextDecision) decide(now, o);
    steer(now, o, dt);
    cursor(now, o, dt);
    if (!reduced) page(o);
    draw(now, o);
  }
  requestAnimationFrame(frame);

  // ---------- the calm switch (stops the mischief; the drawn cursor stays)
  const calmBtn = document.createElement("button");
  calmBtn.className = "sp-calm"; calmBtn.type = "button";
  const paintCalm = () => {
    calmBtn.textContent = calm ? (lang === "ar" ? "🤖 أطلق Bit" : "🤖 Let Bit play") : (lang === "ar" ? "😌 هدّئ Bit" : "😌 Calm Bit");
    calmBtn.title = aiSource === "local" ? "" : `AI: ${aiSource}`;
    calmBtn.setAttribute("aria-pressed", String(calm));
  };
  calmBtn.addEventListener("click", () => {
    calm = !calm; try { localStorage.setItem("sp-bit-calm", calm ? "1" : "0"); } catch { /* storage off */ }
    if (calm && document.pointerLockElement) document.exitPointerLock();
    paintCalm();
  });
  document.body.append(calmBtn); paintCalm();
  $("sp-lang").addEventListener("click", paintCalm);
  return { cheer() { cheerUntil = performance.now() + 2600; E.joy = 1; E.affection = 1; E.mischief = 0; bubble = null; nextTalk = 0; maybeSay("happy"); } };
})();
