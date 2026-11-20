/* ONYX | The minds behind CyberScan (#team, team.css).
 * The members are data, below; their photos and the team logo are looked up by the server
 * (/api/team), which finds team/0..6 with whatever extension they have. A missing or broken photo
 * becomes a drawn placeholder (initials, number), so every card is complete either way.
 * Motion: cards rise in as they enter the screen, the emblem drifts a little with the scroll, and a
 * light follows the pointer over a card. All of it is off with reduced motion. */
"use strict";
(function () {
  const I = window.I18N, CS = window.CS;
  const root = document.getElementById("team");
  if (!I || !CS || !root) return;

  Object.assign(I.en, {
    tmNav: "Team", tmKicker: "The minds behind CyberScan", tmTitle: "ONYX",
    tmLead: "Six people, one product. The team that plans CyberScan, builds it, designs it and tells its story.",
    tmClose1: "ONE TEAM. ONE VISION. ONE MISSION.", tmClose2: "ONYX — Building the Future of Cybersecurity.",
    tmLogoAlt: "The ONYX team logo",
  });
  Object.assign(I.ar, {
    tmNav: "الفريق", tmKicker: "العقول خلف CyberScan", tmTitle: "ONYX",
    tmLead: "ستة أشخاص ومنتج واحد. الفريق الذي يخطط لـ CyberScan ويبنيه ويصممه ويروي قصته.",
    tmClose1: "ONE TEAM. ONE VISION. ONE MISSION.", tmClose2: "ONYX — Building the Future of Cybersecurity.",
    tmLogoAlt: "شعار فريق ONYX",
  });

  /* the members, in order; n is the number shown on the card, photo is the file name in team/
   * (each photo stays with its person, whatever position they hold) */
  const MEMBERS = [
    { n: 1, photo: 1, ar: "عاصم حمد الجعيد", en: "Asim Hamad Al-Juaid", role: "Project Manager | Software Developer",
      dar: "مدير المشروع، والمسؤول عن قيادته وتنسيق مسارات العمل. يمتلك اهتماماً بتطوير البرمجيات، والأمن السيبراني، وتطوير الويب، وبناء الأدوات والأنظمة الأمنية.",
      den: "Leads the project and coordinates its lines of work. His interests are software development, cybersecurity, web development and building security tools and systems." },
    { n: 2, photo: 6, ar: "مهدي حسن آل حاجي", en: "Mahdi Hassan Al-Hajji", role: "Technical Developer | Core Development", core: true,
      dar: "المسؤول عن التطوير التقني للمشروع، وتنفيذ الأنظمة البرمجية، وتطوير المكونات الأساسية ودمجها ضمن CyberScan.",
      den: "Responsible for the project's technical development: he builds its software systems and develops the core components and integrates them into CyberScan." },
    { n: 3, ar: "عبدالهادي صالح الحبابي", en: "Abdulhadi Saleh Al-Habbabi", role: "Media & Marketing Manager",
      dar: "المسؤول عن الجانب الإعلامي والتسويقي للمشروع، وإدارة المحتوى التعريفي، وإبراز هوية CyberScan وإيصال رسالته إلى الجمهور.",
      den: "Runs the project's media and marketing, manages its introductory content, and carries CyberScan's identity and message to its audience." },
    { n: 4, ar: "غالب مشعل الحربي", en: "Ghaleb Meshal Al-Harbi", role: "Official Spokesperson | Product & Visual Designer",
      dar: "المتحدث الرسمي باللغة الإنجليزية، والمصمم الفني للمنتجات، والمسؤول عن الجانب البصري والإبداعي، وتحويل الأفكار إلى تصاميم مرئية تعكس هوية المشروع.",
      den: "The project's official English-language spokesperson. He designs the products and owns the visual and creative side, turning ideas into designs that reflect the project's identity." },
    { n: 5, ar: "معاذ بدر القحطاني", en: "Muath Bader Al-Qahtani", role: "Operations & Task Coordinator",
      dar: "مسؤول سير العمليات وتوزيع المهام، يعمل على تنظيم مراحل التنفيذ، وتنسيق الجهود بين أعضاء الفريق، ومتابعة تقدم الأعمال.",
      den: "Runs operations and assigns tasks: he organises the stages of delivery, coordinates the team's work and tracks its progress." },
    { n: 6, photo: 2, ar: "سعود صالح العسكر", en: "Saud Saleh Al-Askar", role: "General Assistant",
      dar: "المساعدة في اختبار المكونات ومراجعة وظائفها. كما يشارك في متابعة المتطلبات التطويرية والتعاون مع الفريق لتحسين تكامل أجزاء المشروع وجودة تنفيذها.",
      den: "Helps test the components and review how they work. He also follows the development requirements and works with the team to improve how the project's parts fit together and the quality of their delivery." },
  ];

  const html = document.documentElement;
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || html.classList.contains("reduce-motion") || html.classList.contains("fx-scenes-static");
  const isAr = () => CS.lang === "ar";
  const NS = "http://www.w3.org/2000/svg";
  const svg = (tag, attrs) => { const n = document.createElementNS(NS, tag); for (const k in attrs) n.setAttribute(k, attrs[k]); return n; };
  const pad = (n) => String(n).padStart(2, "0");
  const initials = (name) => { const w = name.replace(/^(Al-|آل |ال)/, "").split(/\s+/).filter(Boolean); return (w[0][0] + (w.length > 1 ? "\u200c" + w[w.length - 1].replace(/^(Al-|آل|ال)/, "")[0] : "")).toUpperCase(); };   // ZWNJ: Arabic initials stay apart

  let photos = {};

  /* ---------- placeholders ---------- */
  function personPlaceholder(m, name) {
    const ph = CS.el("div", "tm-ph");
    ph.setAttribute("aria-hidden", "true");
    const s = svg("svg", { viewBox: "0 0 120 150", class: "tm-ph-fig" });
    s.append(svg("path", { d: "M10 150c3-30 24-48 50-48s47 18 50 48" }));
    ph.append(s, CS.el("b", "tm-ph-ini", initials(name)), CS.el("span", "tm-ph-no", pad(m.n)));
    return ph;
  }
  function logoPlaceholder() {
    const ph = CS.el("div", "tm-logo-ph");
    ph.setAttribute("aria-hidden", "true");
    const s = svg("svg", { viewBox: "0 0 120 120" });
    s.append(svg("path", { d: "M60 8 105 34v52L60 112 15 86V34Z", class: "h1" }), svg("path", { d: "M60 28 88 44v32L60 92 32 76V44Z", class: "h2" }));
    ph.append(s, CS.el("b", "", "ONYX"));
    return ph;
  }
  function photo(slot, alt, fallback, cls) {
    const src = photos[slot];
    if (!src) return fallback();
    const img = CS.el("img", cls);
    img.alt = alt; img.decoding = "async"; img.loading = slot === "0" ? "eager" : "lazy";
    img.addEventListener("error", () => img.replaceWith(fallback()), { once: true });   // a broken file still gives a whole card
    img.src = src;
    return img;
  }

  /* ---------- render ---------- */
  function render() {
    // this file's own strings: the page may have applied the language before they were registered
    document.querySelectorAll('[data-i18n^="tm"]').forEach((n) => { n.textContent = CS.t(n.dataset.i18n); });
    const emblem = document.getElementById("tm-emblem-art");
    emblem.replaceChildren(photo("0", CS.t("tmLogoAlt"), logoPlaceholder, "tm-logo"));
    const grid = document.getElementById("tm-grid");
    grid.replaceChildren(...MEMBERS.map((m, i) => {
      const name = isAr() ? m.ar : m.en;
      const card = CS.el("article", "tm-card" + (m.core ? " core" : ""));
      card.style.setProperty("--i", i);
      const frame = CS.el("div", "tm-photo");
      frame.append(photo(String(m.photo || m.n), name, () => personPlaceholder(m, name), "tm-img"), CS.el("span", "tm-scan"), CS.el("span", "tm-no", pad(m.n)));
      const body = CS.el("div", "tm-body");
      // "Al-Habbabi" stays one word: a non-breaking hyphen, so a line never ends on "AL-"
      const h = CS.el("h3", "tm-name", name.replace(/(\bAl)-/g, "$1\u2011"));
      const role = CS.el("p", "tm-role", m.role);
      role.dir = "ltr";
      body.append(h, role, CS.el("p", "tm-desc", isAr() ? m.dar : m.den));
      card.append(frame, body);
      return card;
    }));
    if (!reduced()) grid.classList.add("scrub");                  // hidden until the scroll brings each card in
    requestAnimationFrame(frame);
  }

  /* ---------- scroll: the intro fades up; the cards are scrubbed by the scroll position ---------- */
  const parts = [...root.querySelectorAll("[data-tm-reveal]")];
  if (reduced() || !("IntersectionObserver" in window)) parts.forEach((p) => p.classList.add("in"));
  else {
    const pio = new IntersectionObserver((entries) => entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); pio.unobserve(e.target); } }), { threshold: 0.3 });
    parts.forEach((p) => pio.observe(p));
  }

  /* Each card's entrance follows the scroll, forwards and backwards:
   *   0 -> 1 while its top travels from the bottom of the screen to 45% of its height, a little later
   *   for each column. The card swings in from its own side (left column from the left, right from the
   *   right), rises, untilts and grows to full size; then a scan line runs down the photo and uncovers it.
   * Reads first, then writes, once per frame, and only while the section is on screen. */
  const emblem = document.getElementById("tm-emblem");
  const closeEl = root.querySelector(".tm-close");
  const clamp = (v) => (v < 0 ? 0 : v > 1 ? 1 : v);
  const ease = (v) => 1 - Math.pow(1 - v, 3);
  let onScreen = false, raf = 0;
  const lastWipe = new WeakMap();                                       // for the scan sound, forwards only
  new IntersectionObserver((e) => { onScreen = e[0].isIntersecting; if (onScreen) frame(); }, { rootMargin: "20% 0px" }).observe(root);
  function frame() {
    raf = 0;
    const grid = document.getElementById("tm-grid");
    if (reduced()) { grid.classList.remove("scrub"); return; }
    if (!onScreen) return;
    grid.classList.add("scrub");
    const H = innerHeight;
    const g = grid.getBoundingClientRect();
    const cards = [...grid.children];
    // layout boxes, not getBoundingClientRect(): the cards' own transforms must not move their trigger
    const boxes = cards.map((c) => { const top = g.top + c.offsetTop, left = g.left + c.offsetLeft; return { top, left, width: c.offsetWidth, height: c.offsetHeight }; });
    const single = boxes.length > 1 && Math.abs(boxes[0].left - boxes[1].left) < 2;
    const er = emblem.getBoundingClientRect(), cr = closeEl.getBoundingClientRect();

    cards.forEach((card, i) => {
      const r = boxes[i];
      const cx = r.left + r.width / 2 - (g.left + g.width / 2);
      const side = single ? (i % 2 ? 0.55 : -0.55) : Math.max(-1, Math.min(1, cx / (g.width / 3)));
      const turn = html.classList.contains("fx-scenes-simple") ? 0 : 1;   // Optimized: the rise without the 3D turns
      const col = single ? 0 : Math.round((side + 1) * 1);                    // 0, 1, 2 from left to right
      const lag = (document.dir === "rtl" ? 2 - col : col) * 0.07;            // reading order sets the stagger
      const p = clamp((H - r.top) / (H * 0.55 + r.height * 0.45) - lag);
      const e = ease(p), k = 1 - e;
      const wipe = ease(clamp((p - 0.3) / 0.7));
      const s = card.style;
      s.setProperty("--so", Math.min(1, p * 1.8).toFixed(3));
      s.setProperty("--sx", `${(side * k * 70).toFixed(1)}px`);
      s.setProperty("--sy", `${(k * 150).toFixed(1)}px`);
      s.setProperty("--ss", (0.8 + 0.2 * e).toFixed(4));
      s.setProperty("--srx", `${(k * 32 * turn).toFixed(2)}deg`);
      s.setProperty("--sry", `${(-side * k * 22 * turn).toFixed(2)}deg`);
      s.setProperty("--srz", `${(side * k * 5 * turn).toFixed(2)}deg`);
      s.setProperty("--wipe", wipe.toFixed(4));
      const was = lastWipe.get(card) || 0;
      if (was < 0.15 && wipe >= 0.15 && window.CSSfx) CSSfx.play("scan", { k: i, pan: side * 0.6, key: i });
      lastWipe.set(card, wipe);
      s.setProperty("--sg", Math.sin(Math.PI * wipe).toFixed(3));            // the scan line glows mid-way
      const q = Math.max(-1, Math.min(1, (r.top + r.height / 2 - H / 2) / H));
      s.setProperty("--py", `${(q * -5).toFixed(2)}%`);                       // the photo drifts inside its frame
    });

    const q = Math.max(-1, Math.min(1, (er.top + er.height / 2 - H / 2) / H));
    emblem.style.transform = `translate3d(0, ${(q * 26).toFixed(1)}px, 0) rotate(${(q * -3).toFixed(2)}deg)`;
    closeEl.style.setProperty("--mp", ease(clamp((H - cr.top) / (H * 0.6))).toFixed(3));
  }
  addEventListener("scroll", () => { if (!raf && onScreen) raf = requestAnimationFrame(frame); }, { passive: true });
  addEventListener("resize", () => { if (!raf) raf = requestAnimationFrame(frame); });

  /* ---------- a light that follows the pointer, and a slight tilt (mouse only) ---------- */
  const grid = document.getElementById("tm-grid");
  let tiltRaf = 0, last = null;
  grid.addEventListener("pointermove", (e) => {
    if (e.pointerType !== "mouse" || reduced()) return;
    last = e;
    if (!tiltRaf) tiltRaf = requestAnimationFrame(() => {
      tiltRaf = 0;
      const card = last.target.closest && last.target.closest(".tm-card");
      if (!card) return;
      const r = card.getBoundingClientRect();
      const x = (last.clientX - r.left) / r.width, y = (last.clientY - r.top) / r.height;
      card.style.setProperty("--mx", `${(x * 100).toFixed(1)}%`);
      card.style.setProperty("--my", `${(y * 100).toFixed(1)}%`);
      card.style.setProperty("--rx", `${((0.5 - y) * 5).toFixed(2)}deg`);
      card.style.setProperty("--ry", `${((x - 0.5) * 6).toFixed(2)}deg`);
    });
  });
  grid.addEventListener("pointerout", (e) => {
    const card = e.target.closest && e.target.closest(".tm-card");
    if (card && !card.contains(e.relatedTarget)) { card.style.setProperty("--rx", "0deg"); card.style.setProperty("--ry", "0deg"); }
  });

  /* ---------- start ---------- */
  render();                                                    // placeholders at once, photos when known
  CS.onLang(render);
  CS.api("/api/team").then((d) => { photos = (d && d.photos) || {}; if (Object.keys(photos).length) render(); }).catch(() => { /* placeholders stay */ });
})();
