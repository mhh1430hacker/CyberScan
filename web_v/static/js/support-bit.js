/* ---------------- Bit: a small 2D robot companion on the calm support page ----------------
 * A guest, never a pest: Bit floats beside the card (or in the header on small screens), leans
 * toward the pointer, says a short line about what the visitor looks at, and thanks them when they
 * open the support details, copy, share or scan. It never moves the cursor and never plays tricks.
 * Two minds work together:
 *   - a language model (POST /api/bit: Amazon Bedrock on the site, Ollama on a computer) is asked
 *     every few seconds for a mood, a gentle tactic, an expression and maybe a line;
 *   - a fast local engine runs every frame: five emotions that drift with what the visitor does
 *     and a softmax over the gentle tactics. It fills every gap the model leaves.
 * When the visitor enters the Cubeverse, Bit waves goodbye and sleeps (no frames) until they come
 * back. Reduced motion (the OS setting or html.reduce-motion): Bit stays in one place and only
 * blinks and waves. The loop stops while the tab is hidden and draws fewer frames when idle. */
export function startBit({ getLang, cta, modal, motionOff }) {
  const canvas = document.getElementById("sp-robot"), ctx = canvas.getContext("2d");
  if (!ctx) return { thank() {}, away() {} };
  const fine = matchMedia("(pointer: fine)").matches;
  const token = (document.querySelector('meta[name="cyberscan-token"]') || {}).content || "";
  const lang = () => getLang();
  let reduced = motionOff();
  const ss = (k, v) => { try { if (v === undefined) return sessionStorage.getItem(k); sessionStorage.setItem(k, v); } catch { /* storage off */ } return null; };
  let visitor = { n: 0, last: 0 };
  try { visitor = { ...visitor, ...JSON.parse(localStorage.getItem("sp-bit-visitor") || "{}") }; } catch { /* storage off */ }
  const prevVisit = { ...visitor }, newVisit = !ss("sp-bit-seen");
  if (newVisit) { visitor = { n: (Number(visitor.n) || 0) + 1, last: Date.now() }; ss("sp-bit-seen", "1"); }
  try { localStorage.setItem("sp-bit-visitor", JSON.stringify(visitor)); } catch { /* storage off */ }
  const said = [], actions = [];
  const remember = (list, item, max) => { list.push(String(item).slice(0, 40)); if (list.length > max) list.shift(); };
  const act = (a) => { if (actions[actions.length - 1] !== a) remember(actions, a, 6); };

  const rnd = (a = 1, b) => (b === undefined ? Math.random() * a : a + Math.random() * (b - a));
  const pickOf = (arr) => arr[Math.floor(rnd(arr.length))];
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const W = () => innerWidth, H = () => innerHeight;
  let dpr = 1, S = 1;
  function size() { dpr = Math.min(devicePixelRatio || 1, 2); canvas.width = W() * dpr; canvas.height = H() * dpr; S = W() < 520 ? 0.6 : W() < 900 ? 0.8 : 1; }
  size(); addEventListener("resize", size);
  const born = performance.now();

  // ---------- perception
  const P = { x: W() / 2, y: H() / 2, vx: 0, vy: 0, last: performance.now(), still: 0, over: "" };
  let pointerSeen = false;
  function hoverOf(el) {
    if (!el || !el.closest) return "";
    const tagged = el.closest("[data-bit]");
    return el.closest(".sp-copy") ? "copy" : el.closest(".sp-explore") ? "explore" : tagged ? tagged.dataset.bit : el.closest("a,button") ? "link" : el.closest("p,h1,li") ? "text" : "";
  }
  addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch" || isAway) return;
    const now = performance.now(), dt = Math.max(1, now - P.last);
    P.vx = (e.clientX - P.x) / dt * 16; P.vy = (e.clientY - P.y) / dt * 16;
    P.x = e.clientX; P.y = e.clientY; P.last = now; P.still = 0; pointerSeen = true;
    P.over = hoverOf(e.target);
    react(P.over);
  }, { passive: true });
  const ctaCenter = () => { const r = cta.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, r }; };

  // ---------- feelings
  const E = { joy: 0.45, mischief: 0.05, affection: 0.2, boredom: 0.1, curiosity: 0.4 };
  const rest = { joy: 0.4, mischief: 0.05, affection: 0.15, boredom: 0, curiosity: 0.35 };
  function feel(dt, o) {
    const k = dt / 1000, nudge = (n, a) => { E[n] = clamp(E[n] + a * k, 0, 1); };
    for (const n in E) E[n] += (rest[n] - E[n]) * Math.min(1, 0.35 * k);
    if (o.toward) nudge("joy", 0.6);
    if (o.near) { nudge("affection", 1.1); nudge("joy", 0.5); }
    if (o.still > 2500) nudge("boredom", 0.35); else nudge("boredom", -0.9);
    if (P.over === "photo" || P.over === "text" || P.over === "explore") nudge("curiosity", 0.5);
    if (o.bankOpen) { nudge("joy", 0.4); nudge("affection", 0.3); }
    E.mischief = Math.min(E.mischief, 0.1);
  }
  const MOOD_SHIFT = { playful: { joy: 0.3 }, affectionate: { affection: 0.5 }, excited: { joy: 0.5 }, bored: { boredom: 0.5 }, curious: { curiosity: 0.5 }, proud: { joy: 0.3 }, shy: { affection: 0.3 }, silly: { joy: 0.4 } };

  // ---------- gentle tactics only
  const TACTICS = {
    follow: () => 0.5 + E.affection * 0.4,
    beckon: (o) => (o.near ? -0.5 : 0.25 + (o.away ? 0.4 : 0)),
    dance: (o) => (o.near || o.bankOpen ? 0.4 + E.joy + E.affection : -9),
    peek: () => E.curiosity * 0.9 - 0.2,
    nap: () => E.boredom * 2.2 - 0.6,
  };
  let tactic = "follow", tacticSince = 0, nextDecision = 0, ai = null;
  function setTactic(name, now) { if (name === tactic) return; tactic = name; tacticSince = now; maybeSay(name); }
  function decide(now, o) {
    nextDecision = now + rnd(400, 1100);
    if (ai && now < ai.until && TACTICS[ai.tactic]) { if (TACTICS[ai.tactic](o) > -5) setTactic(ai.tactic, now); return; }
    const temp = 0.25 + E.boredom * 0.3;
    const exps = Object.entries(TACTICS).map(([n, f]) => [n, Math.exp((f(o) + (n === tactic ? 0.15 : 0) + rnd(-0.15, 0.15)) / temp)]);
    let r = rnd(exps.reduce((a, [, e]) => a + e, 0)), pick = exps[0][0];
    for (const [n, e] of exps) { r -= e; if (r <= 0) { pick = n; break; } }
    setTactic(pick, now);
  }

  // ---------- asking the model (a few seconds apart; the local engine never waits for it)
  let asking = false, nextAsk = performance.now() + 1500;
  async function askModel(now, o) {
    if (asking || now < nextAsk || document.hidden || !token || reduced || isAway) return;
    if (o.still > 30000) return;   // nobody is there: don't spend a model call on an empty room
    asking = true; nextAsk = now + rnd(6000, 9000);
    const state = { lang: lang(), touch: !fine, dist: Math.round(o.dist), trend: o.toward ? "toward" : o.away ? "away" : "still", speed: Math.round(o.speed),
      still: Math.round(o.still / 1000), hover: P.over, bankOpen: o.bankOpen, age: Math.round((now - born) / 1000), tactic,
      joy: E.joy, mischief: E.mischief, affection: E.affection, boredom: E.boredom, outcomes: {},
      playing: false, visits: visitor.n, escapedLast: false, daypart: daypart(), said: said.slice(-4), actions: actions.slice(-6) };
    try {
      const res = await fetch("/api/bit", { method: "POST", headers: { "Content-Type": "application/json", "X-CyberScan-Token": token }, body: JSON.stringify(state) });
      const d = res.ok ? await res.json() : null;
      if (d && d.source && d.source !== "none" && !isAway) {
        ai = { ...d, until: performance.now() + 4500 };
        for (const [k, v] of Object.entries(MOOD_SHIFT[d.mood] || {})) E[k] = clamp(E[k] + v, 0, 1);
        if (d.line && performance.now() > quietUntil) { say(d.line, 2400); nextTalk = performance.now() + 3000; }
        nextDecision = 0;
      } else if (d && d.reason !== "rate") nextAsk = now + 30000;   // no model here: stop asking for a while
    } catch { nextAsk = now + 30000; }
    asking = false;
  }

  // ---------- body
  const B = { x: W() / 2, y: H() * 0.45, vx: 0, vy: 0, tilt: 0, flip: 1, eyeX: 0, eyeY: 0, squash: 1 };
  let particles = [], cheerUntil = 0, bubble = null, nextTalk = 0, quietUntil = 0, tapAt = 0, waveUntil = 0;
  const tilt = { x: 0, y: 0, on: false };
  const rtl = () => document.documentElement.dir === "rtl";
  const card = document.querySelector(".sp-card"), textBox = document.querySelector(".sp-text");
  // Bit's resting place: in the side margin by the support button when the screen is wide enough,
  // else in the header between the logo and the language button (never over the text)
  function home() {
    const r = card.getBoundingClientRect(), c = ctaCenter();
    const side = rtl() ? r.left : W() - r.right;
    if (side >= 170) return { x: rtl() ? r.left / 2 : r.right + side / 2, y: clamp(c.y - 40, 120, H() - 110) };
    const top = document.querySelector(".sp-top").getBoundingClientRect(), y = Math.max(28 * S + 6, top.top + top.height / 2);
    const a = document.querySelector(".sp-brand").getBoundingClientRect(), l = document.getElementById("sp-lang").getBoundingClientRect();
    const gl = Math.min(a.right, l.right), gr = Math.max(a.left, l.left);
    return { x: (gl + gr) / 2, y };
  }
  function avoidText(x, y) {
    if (W() >= 760) return [x, y];
    const pad = 26 * S, r = textBox.getBoundingClientRect();
    if (x > r.left - pad && x < r.right + pad && y > r.top - pad && y < r.bottom + pad) x = x < W() / 2 ? 20 * S + 2 : W() - 20 * S - 2;
    return [x, y];
  }
  function steer(now, o, dt) {
    const k = dt / 16, t = (now - tacticSince) / 1000, h = home();
    if (reduced) { B.x = h.x; B.y = h.y; B.vx = B.vy = 0; B.tilt = 0; lookAt(); return; }
    let tx = h.x + (pointerSeen && fine ? clamp((P.x - h.x) * 0.06, -24, 24) : 0) + Math.sin(now / 1300) * 8;
    let ty = h.y + Math.sin(now / 900) * 6 + (tactic === "nap" ? 8 : tactic === "dance" ? -Math.abs(Math.sin(t * 5)) * 8 : tactic === "beckon" ? Math.sin(t * 3) * 4 : 0);
    if (!fine) {   // phones: the phone's tilt nudges Bit; a tap draws it close for a moment
      if (tilt.on) { tx += tilt.x * 18; ty += tilt.y * 12; }
      if (now - tapAt < 2500) { tx = tx * 0.75 + P.x * 0.25; ty = ty * 0.75 + (P.y - 40) * 0.25; }
    }
    [tx, ty] = avoidText(tx, ty);
    B.vx = (B.vx + (tx - B.x) * 0.035 * k + rnd(-0.06, 0.06)) * 0.86;
    B.vy = (B.vy + (ty - B.y) * 0.035 * k + Math.sin(now / 260) * 0.15) * 0.86;
    const m = 22 * S + 4;
    B.x = clamp(B.x + B.vx * k, m, W() - m); B.y = clamp(B.y + B.vy * k, 38 * S + 4, H() - m);
    B.tilt += (clamp(B.vx * 0.04, -0.5, 0.5) - B.tilt) * 0.15;
    if (Math.abs(B.vx) > 0.4) B.flip = B.vx > 0 ? 1 : -1;
    lookAt();
  }
  function lookAt() {
    const lx = P.x - B.x, ly = P.y - B.y, ll = Math.hypot(lx, ly) || 1;
    B.eyeX += ((lx / ll) * 3.5 - B.eyeX) * 0.2; B.eyeY += ((ly / ll) * 3 - B.eyeY) * 0.2;
  }

  // ---------- phones: tilt (where the browser allows it without asking) and taps
  if (!fine && window.DeviceOrientationEvent && typeof window.DeviceOrientationEvent.requestPermission !== "function") {
    addEventListener("deviceorientation", (e) => { if (e.gamma == null) return; tilt.on = true; tilt.x = clamp(e.gamma / 35, -1, 1); tilt.y = clamp((e.beta - 35) / 35, -1, 1); });
  }
  if (!fine) {
    addEventListener("pointerdown", (e) => {
      if (isAway) return;
      P.x = e.clientX; P.y = e.clientY; P.vx = 0; P.vy = 0; P.still = 0; pointerSeen = true; P.over = hoverOf(e.target); tapAt = performance.now();
      E.joy = Math.min(1, E.joy + 0.15); react(P.over); wake();
    }, { passive: true });
  }

  // ---------- speech
  const SAY = {
    ar: { near: ["إيه! قربت 🥺", "♥", "هلا والله"], bored: ["زززز", "أنا هنا ترى…", "طفشت 😴"], happy: ["مشكور! 💜", "كفو والله", "♥♥", "تسلم يا الغالي"], peek: ["بِخ! 👀", "شايفك"] },
    en: { near: ["oh hi! 🥺", "♥", "hello there"], bored: ["zzz", "still here…", "bored 😴"], happy: ["thank you! 💜", "you're awesome", "♥♥", "you made my day"], peek: ["boo! 👀", "I see you"] },
  };
  const HOVER = {
    ar: { sec: ["الأمن السيبراني؟ هذا شغلنا 🛡️", "نحمي ملفاتك من الهكر 😎"], ml: ["تعلّم الآلة… يعني أنا! 🤖", "أنا بعد أتعلّم كل يوم"],
      se: ["كود مرتب ونظيف 👌", "هندسة برمجيات؟ هذي سالفته 😄"], photo: ["هذا مهدي، اللي سوّاني 😊", "وسيم صح؟ 😄"],
      cta: ["إيه هذا هو! 🥺", "ضغطة وحدة بس 💜"], explore: ["فيه عالم مكعبات هنا! 🧊", "جرّبه، يستاهل ✨"] },
    en: { sec: ["cybersecurity? that's our thing 🛡️", "keeping your files safe 😎"], ml: ["machine learning… that's me! 🤖", "I learn something every day"],
      se: ["clean, tidy code 👌", "software engineering, his favourite"], photo: ["that's Mahdi, he made me 😊", "looking sharp, right? 😄"],
      cta: ["yes, that one! 🥺", "just one click 💜"], explore: ["there's a world of cubes in there! 🧊", "go on, it's fun ✨"] },
  };
  const THANKS = {
    ar: { copy: "نسخته؟ تسلم يدك 💜", open: "يا هلا! شكرًا إنك فتحتها 🥹", qr: "صوّره وخلاص، الله يعطيك العافية 📱💜", share: "تنشرها؟ والله إنك كفو 🥹💜" },
    en: { copy: "copied? you're the best 💜", open: "aww, thanks for opening it 🥹", qr: "scan away, thank you 📱💜", share: "sharing it? you legend 🥹💜" },
  };
  let queue = [];
  function say(text, ms = 1800) { bubble = { text, until: performance.now() + ms }; queue = []; if (said[said.length - 1] !== text) remember(said, text, 4); wake(); }
  function sayLater(text, ms) { queue.push({ text, ms }); }
  let lastObs = null;
  function maybeSay(reason) {
    const now = performance.now();
    if (now < nextTalk || now < quietUntil || reduced) return;
    const s = SAY[lang()], o = lastObs;
    const pool = o && o.bankOpen ? s.happy : reason === "nap" ? s.bored : reason === "peek" ? s.peek : null;
    if (!pool || rnd() > 0.45) return;
    say(pickOf(pool), 1700); nextTalk = now + rnd(3500, 6500);
  }
  const reacted = {};
  let lastReact = 0, lastOver = "";
  function react(what) {
    if (what === lastOver) return;
    lastOver = what;
    const lines = HOVER[lang()][what], now = performance.now();
    if (!lines) return;
    act(`hover:${what}`);
    if (now - lastReact < 2500 || now < quietUntil || (reacted[what] || 0) >= 2) return;
    reacted[what] = (reacted[what] || 0) + 1; lastReact = now;
    say(lines[(reacted[what] - 1) % lines.length], 2200); nextTalk = now + 2600;
    E.curiosity = Math.min(1, E.curiosity + 0.2);
  }
  function daypart() { const h = new Date().getHours(); return h < 5 ? "late" : h < 12 ? "morning" : h < 17 ? "day" : h < 22 ? "evening" : "late"; }
  function greet() {
    const ar = lang() === "ar", part = daypart();
    const hello = ar ? { late: "سهران؟ 🌙", morning: "صباح الخير ☀️", day: "هلا والله 👋", evening: "مساء الخير 🌆" }[part]
      : { late: "up late? 🌙", morning: "good morning ☀️", day: "hey there 👋", evening: "good evening 🌆" }[part];
    const gone = prevVisit.last ? (Date.now() - prevVisit.last) / 86400000 : 0;
    let first;
    if (!newVisit) first = ar ? "هلا مرة ثانية 😄" : "hi again 😄";
    else if (prevVisit.n > 0 && gone > 7) first = ar ? "وينك من زمان؟ 🥹 حيّاك" : "long time no see 🥹 welcome back";
    else if (prevVisit.n > 0) first = ar ? "رجعت! 😄 حيّاك الله" : "you're back! 😄";
    else first = ar ? `${hello} أنا Bit` : `${hello} I'm Bit`;
    say(first, 2800); lastReact = performance.now() - 1200;
    if (newVisit && prevVisit.n > 0) sayLater(hello, 1800);
    nextTalk = performance.now() + 9000;
  }
  const thanked = new Set();
  function thank(kind) {
    act(kind === "open" ? "opened_bank" : kind);
    if (thanked.has(kind) || isAway) return;
    thanked.add(kind);
    const now = performance.now();
    cheerUntil = now + 2800; quietUntil = now + 3200; E.joy = 1; E.affection = 1;
    say(THANKS[lang()][kind], 2800); nextTalk = now + 4000;
    if (!reduced) for (let i = 0; i < 18; i++) {
      const a = (i / 18) * Math.PI * 2;
      particles.push({ x: B.x, y: B.y, vx: Math.cos(a) * rnd(1.2, 2.6), vy: Math.sin(a) * rnd(1.2, 2.6) - 0.6, life: 1, kind: "♥" });
    }
    wake();
  }

  // ---------- faces
  function expression(now, o) {
    if (now < cheerUntil) return ["love", "starry", "laugh"][Math.floor(now / 900) % 3];
    if (reduced) return "happy";
    if (tactic === "nap") return "sleepy";
    if (o.bankOpen) return ["starry", "love", "laugh"][Math.floor(now / 1400) % 3];
    if (ai && now < ai.until && ai.expression && !["angry", "smug"].includes(ai.expression)) return ai.expression;
    if (E.affection > 0.65) return o.near ? "love" : "happy";
    if (E.boredom > 0.5) return "sad";
    if (E.curiosity > 0.6) return "curious";
    if (E.joy > 0.7) return "laugh";
    return "happy";
  }
  function face(expr, now) {
    const eye = expr === "love" || expr === "starry" ? "#ff8fe6" : "#9df7ff";
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
      case "laugh": case "cry_laugh": eyes((x, y) => arc(x, y, 2.6, true)); mouth("open"); break;
      case "wink": eyes((x, y, s) => { if (s < 0) { ctx.beginPath(); ctx.moveTo(x - 2.5, y); ctx.lineTo(x + 2.5, y); ctx.stroke(); } else { ctx.beginPath(); ctx.ellipse(x, y, 2.6, 3.2, 0, 0, Math.PI * 2); ctx.fill(); } }); mouth("smirk"); break;
      case "surprised": eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y, 3.2, 4.2, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("o"); break;
      case "sad": eyes((x, y, s) => { ctx.beginPath(); ctx.ellipse(x, y + 1, 2.4, 2.8, 0, 0, Math.PI * 2); ctx.fill(); ctx.beginPath(); ctx.moveTo(x - s * 3, y - 5); ctx.lineTo(x + s * 2, y - 3.5); ctx.stroke(); }); mouth("frown"); break;
      case "dizzy": eyes((x, y) => { ctx.beginPath(); for (let i = 0; i < 18; i++) { const a = i * 0.7 + now / 120, r = i * 0.18; ctx.lineTo(x + Math.cos(a) * r, y + Math.sin(a) * r); } ctx.stroke(); }); mouth("wavy"); break;
      case "sleepy": eyes((x, y) => arc(x, y + 1, 2.4, false)); mouth("o"); break;
      case "curious": eyes((x, y, s) => { ctx.beginPath(); ctx.ellipse(x, y, s > 0 ? 3.4 : 2.2, s > 0 ? 4 : 2.6, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("flat"); break;
      case "neutral": eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y, 2.6, 3, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("flat"); break;
      default: eyes((x, y) => { ctx.beginPath(); ctx.ellipse(x, y, 2.8, 3.4 + E.joy, 0, 0, Math.PI * 2); ctx.fill(); }); mouth("smile");
    }
  }

  // ---------- drawing
  let glowHue = 0;
  function draw(now, o) {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W(), H());
    if (!reduced && rnd() < E.affection * 0.2 + (tactic === "nap" ? 0.04 : 0)) {
      particles.push({ x: B.x + rnd(-12, 12), y: B.y - 20, vx: rnd(-0.6, 0.6), vy: rnd(-1.4, -0.6), life: 1, kind: tactic === "nap" ? "z" : "♥" });
    }
    particles = particles.filter((p) => (p.life -= 0.014) > 0);
    for (const p of particles) {
      ctx.globalAlpha = p.life; p.x += p.vx; p.y += p.vy;
      ctx.fillStyle = p.kind === "♥" ? "#ff4fd8" : "#b3a7d6"; ctx.font = "13px system-ui"; ctx.fillText(p.kind, p.x, p.y);
    }
    ctx.globalAlpha = 1;
    const happy = now < cheerUntil || o.bankOpen;
    B.squash += ((happy && !reduced ? 1 + Math.sin(now / 90) * 0.06 : 1) - B.squash) * 0.2;
    ctx.save(); ctx.translate(B.x, B.y); ctx.rotate(B.tilt); ctx.scale(B.flip * B.squash * S, (2 - B.squash) * S);
    const flame = (reduced ? 6 : 6 + Math.sin(now / 50) * 2) + Math.abs(B.vy) * 0.6;
    const g = ctx.createRadialGradient(0, 20, 0, 0, 20, flame + 8); g.addColorStop(0, "rgba(34,232,255,.95)"); g.addColorStop(1, "rgba(180,108,255,0)");
    ctx.fillStyle = g; ctx.beginPath(); ctx.ellipse(0, 22 + flame / 2, 6, flame, 0, 0, Math.PI * 2); ctx.fill();
    const hue = 268 + E.affection * 50;
    const waving = now < waveUntil || now < cheerUntil || (reduced && now % 7000 < 1600);
    if (waving) {
      const a = -0.9 + Math.sin(now / 120) * 0.45;
      ctx.strokeStyle = `hsl(${hue},60%,70%)`; ctx.lineWidth = 3.2; ctx.lineCap = "round";
      ctx.beginPath(); ctx.moveTo(18, 2); ctx.lineTo(18 + Math.cos(a) * 13, 2 + Math.sin(a) * 13); ctx.stroke();
      ctx.fillStyle = `hsl(${hue},70%,78%)`; ctx.beginPath(); ctx.arc(18 + Math.cos(a) * 15, 2 + Math.sin(a) * 15, 3.4, 0, Math.PI * 2); ctx.fill();
    }
    const body = ctx.createLinearGradient(0, -22, 0, 22); body.addColorStop(0, `hsl(${hue},70%,72%)`); body.addColorStop(1, `hsl(${hue},55%,42%)`);
    ctx.fillStyle = body; ctx.beginPath(); ctx.ellipse(0, 0, 22, 20, 0, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "rgba(255,255,255,.35)"; ctx.beginPath(); ctx.ellipse(-8, -10, 7, 4, -0.5, 0, Math.PI * 2); ctx.fill();
    const sway = reduced ? 0 : 4 * Math.sin(now / 200);
    ctx.strokeStyle = `hsl(${hue},60%,75%)`; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(0, -19); ctx.quadraticCurveTo(sway, -28, 0, -32); ctx.stroke();
    ctx.fillStyle = "#ff4fd8"; ctx.beginPath(); ctx.arc(0, -33, 3.5 + (reduced ? 0 : Math.sin(now / 160)), 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#0b0720"; ctx.beginPath(); ctx.ellipse(0, 1, 15, 11, 0, 0, Math.PI * 2); ctx.fill();
    face(expression(now, o), now);
    if (E.affection > 0.3) { ctx.fillStyle = `rgba(255,79,216,${(E.affection - 0.3) * 0.9})`; for (const s of [-1, 1]) { ctx.beginPath(); ctx.ellipse(s * 11, 4, 3, 1.8, 0, 0, Math.PI * 2); ctx.fill(); } }
    ctx.restore();
    if (Math.abs(hue - glowHue) > 3) { glowHue = hue; cta.style.setProperty("--bit-hue", String(Math.round(hue))); }
    if ((!bubble || now > bubble.until) && queue.length) { const q = queue.shift(); bubble = { text: q.text, until: now + q.ms }; remember(said, q.text, 4); }
    if (bubble && now < bubble.until) {
      ctx.font = "600 13px system-ui, 'Segoe UI', Tahoma"; const w = Math.min(W() - 16, ctx.measureText(bubble.text).width + 18);
      const bx = clamp(B.x - w / 2, 8, W() - w - 8);
      let by = B.y - 44 * S - 26;
      if (by < 6) by = B.y + 30 * S + 4;
      ctx.fillStyle = "rgba(26,16,64,.94)"; ctx.strokeStyle = "rgba(196,160,255,.5)"; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.roundRect(bx, by, w, 26, 13); ctx.fill(); ctx.stroke();
      ctx.fillStyle = "#f3eeff"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.direction = lang() === "ar" ? "rtl" : "ltr";
      ctx.fillText(bubble.text, bx + w / 2, by + 13, w - 12); ctx.textAlign = "start"; ctx.textBaseline = "alphabetic";
    }
  }

  // ---------- the loop: stops while the tab is hidden or Bit is away, fewer frames when idle
  let last = performance.now(), lastDist = null, frameNo = 0, running = false, isAway = false, leaveAt = 0;
  function frame(now) {
    if (document.hidden || (isAway && now > leaveAt)) { running = false; if (isAway) ctx.clearRect(0, 0, canvas.width, canvas.height); return; }
    requestAnimationFrame(frame);
    frameNo++;
    if (frameNo % 60 === 0) reduced = motionOff();
    const talking = (bubble && now < bubble.until) || now < cheerUntil || queue.length || now < waveUntil;
    const skip = reduced ? 3 : !talking && P.still > 2500 ? 3 : 1;
    if (frameNo % skip) return;
    const dt = Math.min(50, now - last); last = now;
    P.still += dt;
    const c = ctaCenter(), dist = Math.hypot(P.x - c.x, P.y - c.y), speed = Math.hypot(P.vx, P.vy);
    P.vx *= 0.9; P.vy *= 0.9;
    const trend = lastDist === null ? 0 : lastDist - dist; lastDist = dist;
    const o = { c, dist, speed, still: P.still, near: dist < 140 || P.over === "cta", toward: trend > 1.2, away: trend < -1.2, bankOpen: modal.open };
    lastObs = o;
    feel(dt, o);
    askModel(now, o);
    if (now > nextDecision) decide(now, o);
    steer(now, o, dt);
    draw(now, o);
  }
  function wake() { if (!running && !document.hidden && (!isAway || performance.now() < leaveAt)) { running = true; last = performance.now(); requestAnimationFrame(frame); } }
  { const h = home(); B.x = h.x; B.y = h.y; }
  wake();
  document.addEventListener("visibilitychange", () => { if (!document.hidden) wake(); });

  // the visitor goes into the Cubeverse (Bit waves and rests) or comes back (Bit says hello again)
  function away(on) {
    if (on === isAway) return;
    isAway = on;
    if (on) {
      waveUntil = performance.now() + 900; leaveAt = performance.now() + 900;
      say(lang() === "ar" ? "استمتع! 👋" : "have fun! 👋", 900);
      canvas.style.opacity = "0";
    } else {
      canvas.style.opacity = "";
      const h = home(); B.x = h.x; B.y = h.y; B.vx = B.vy = 0;
      waveUntil = performance.now() + 2200; nextTalk = performance.now() + 6000;
      wake();
      setTimeout(() => { if (!isAway) say(lang() === "ar" ? "رجعت! كيف كانت المكعبات؟ 😄" : "you're back! how were the cubes? 😄", 2600); }, 450);
    }
  }
  setTimeout(() => { waveUntil = performance.now() + 3200; greet(); }, 650);
  return { thank, away };
}
