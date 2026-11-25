// Support the developer: words (AR/EN), the support modal (bank details, copy, share, QR), the floating
// support button, and the door to the Cubeverse. Nothing 3D loads here: the Cubeverse's modules are
// fetched only when the visitor asks for them (js/cubeverse/cubeverse.js). Bit, the small robot
// companion, loads after the page is idle (js/support-bit.js).

const T = {
  ar: {
    kicker: "المطوّر · Mynex", name: "مهدي آل حاجي", role: "مطوّر برمجيات وباحث في الذكاء الاصطناعي",
    bio1: "مطوّر برمجيات وباحث في الذكاء الاصطناعي، مهتم بتطوير الأنظمة الذكية والحلول التقنية المبتكرة، مع تركيز على الأمن السيبراني وتعلّم الآلة وهندسة البرمجيات.",
    bio2: "أعمل على تحويل الأفكار والنماذج النظرية إلى منتجات تقنية قابلة للتطبيق، وأقود حالياً التطوير التقني لمشروع CyberScan، وهو مشروع متعدد المنصات لتحليل الملفات واكتشاف التهديدات الأمنية المحتملة.",
    t1: "الأمن السيبراني", t2: "تعلّم الآلة", t3: "هندسة البرمجيات",
    cta: "ادعم المطوّر", fab: "ادعم", fabLabel: "ادعم المطوّر: بيانات التحويل البنكي",
    bankTitle: "الدعم عبر التحويل البنكي", bankNote: "يمكنك الدعم بالتحويل من أي بنك سعودي باستخدام رقم الآيبان، أو بمسح الرمز من تطبيق البنك.",
    holder: "اسم المستفيد", bank: "البنك", bankName: "مصرف الراجحي", iban: "رقم الآيبان (IBAN)", account: "رقم الحساب",
    copy: "نسخ", copied: "تم النسخ", copyIban: "نسخ رقم الآيبان", copyAccount: "نسخ رقم الحساب", qr: "امسحه من تطبيق البنك",
    thanks: "شكرًا لدعمك، كل مساهمة تساعد على استمرار CyberScan وتطويره.", back: "العودة إلى CyberScan",
    title: "ادعم المطوّر · CyberScan", photo: "صورة مهدي آل حاجي", qrAlt: "رمز QR لبيانات الحساب البنكي",
    share: "مشاركة البيانات", allCopied: "تم نسخ كل البيانات", close: "إغلاق", qrOpen: "تكبير رمز QR",
    uses: "بصراحة: دعمك يروح لتكاليف تشغيل CyberScan فعليًا، الخوادم وتكلفة نماذج الذكاء الاصطناعي ورسوم النشر في متاجر التطبيقات.",
    optional: "الدعم اختياري تمامًا، ولا يتوقف عليه أي شيء في هذه الصفحة.",
    exTitle: "في هذه الصفحة عالم مخفي",
    exText: "ستة عوالم صغيرة من المكعبات: تسقط وتُبنى وتتموّج وتتداخل في بعضها، وواحد يفكّك ملفًا طبقةً بعد طبقة. استكشفها متى شئت، وزر الدعم يبقى معك.",
    explore: "ادخل عالم المكعبات", exploreAgain: "العودة إلى عالم المكعبات", loading: "يجهّز العالم…", loadFail: "تعذّر تحميل عالم المكعبات، حاول مرة أخرى.",
    wTitle: "الأبحاث والأعمال", wLead: "أبحاث منشورة ومشاريع مفتوحة المصدر.", wPapers: "أبحاث منشورة", wViews: "مشاهدة للأبحاث",
    wDownloads: "تنزيل للأبحاث", wRepos: "مستودع مفتوح المصدر", wPapersH: "الأبحاث (Zenodo)", wJan: "يناير 2026", wPre: "ورقة أولية · يناير 2026",
    wV: "مشاهدة", wD: "تنزيل", wProjH: "مشاريع مختارة (GitHub)",
    wP1: "تجربة حسابية تُظهر انهيار النماذج اللغوية حين تتدرّب على مخرجاتها، مع إصدار موثّق بمعرّف DOI.",
    wP2: "إطار لاختبار ثبات النماذج اللغوية الكبيرة تحت الضغط، يرصد تراجع التنوّع والانحراف الدلالي.",
    wP3: "شبكة مذبذبات مكانية مخمّدة كسريًا: استكشاف عددي للفوضى والجواذب والارتباطات المكانية.",
    wP4: "منصة ذكاء اصطناعي للتحضير لاختبارات قياس.", wAsof: "الأرقام من السجلات العامة حتى نوفمبر 2026.",
    vKicker: "أحدث فيديو · YouTube", vBadge: "اضغط للتشغيل", vPlay: "تشغيل الفيديو: {t}", vFrame: "فيديو YouTube: {t}",
    vNote: "لا يتصل متصفحك بـ YouTube قبل أن تضغط تشغيل؛ عندها يُحمَّل الفيديو من youtube-nocookie.com.", vChannel: "قناة Ainex على YouTube",
    wLive: "أرقام مباشرة من Zenodo وGitHub، آخر تحديث {d}.", wStars: "{n} نجمة على GitHub",
    tlTitle: "المحطات",
    tl1d: "أكتوبر 2024", tl1: "حساب GitHub", tl1p: "بداية المستودعات المفتوحة المصدر على github.com/mhh1430hacker.",
    tl2d: "يناير 2026", tl2: "إصدار Ainex-Limit-Experiment", tl2p: "التجربة الحسابية لانهيار النماذج اللغوية، بإصدار مؤرشف على Zenodo بمعرّف DOI.",
    tl3d: "يناير 2026", tl3: "أبحاث Ainex الثلاثة", tl3p: "نشر ثلاث أوراق على Zenodo: حد Ainex، وتفرّد Ainex، والتباعد البنيوي.",
    tl4d: "2026", tl4: "تطوير CyberScan وإطلاق ainex-ai.xyz", tl4p: "منصة لتحليل الملفات واكتشاف التهديدات، متاحة على الويب.",
    tl5d: "نوفمبر 2026", tl5: "تطبيق الجوال 1.1.0 وتطبيق Windows 2.0.0", tl5p: "CyberScan على الجوال وعلى سطح المكتب.",
    langLabel: "English",
  },
  en: {
    kicker: "The developer · Mynex", name: "Mahdi Al-Hajji", role: "Software developer and AI researcher",
    bio1: "Software developer and AI researcher, focused on intelligent systems and innovative technical solutions, with an emphasis on cybersecurity, machine learning and software engineering.",
    bio2: "I turn ideas and theoretical models into working technical products, and I currently lead the technical development of CyberScan, a multi-platform project for analysing files and detecting potential security threats.",
    t1: "Cybersecurity", t2: "Machine learning", t3: "Software engineering",
    cta: "Support the developer", fab: "Support", fabLabel: "Support the developer: bank transfer details",
    bankTitle: "Support by bank transfer", bankNote: "You can transfer from any Saudi bank using the IBAN, or scan the code from your bank app.",
    holder: "Beneficiary", bank: "Bank", bankName: "Al Rajhi Bank", iban: "IBAN", account: "Account number",
    copy: "Copy", copied: "Copied", copyIban: "Copy the IBAN", copyAccount: "Copy the account number", qr: "Scan it from your bank app",
    thanks: "Thank you for your support: every contribution keeps CyberScan going and growing.", back: "Back to CyberScan",
    title: "Support the developer · CyberScan", photo: "Photo of Mahdi Al-Hajji", qrAlt: "QR code with the bank account details",
    share: "Share the details", allCopied: "All the details copied", close: "Close", qrOpen: "Enlarge the QR code",
    uses: "Honestly: your support pays for what keeps CyberScan running: the servers, the AI model costs and the app store publishing fees.",
    optional: "Support is entirely optional; nothing on this page depends on it.",
    exTitle: "There is a world hidden in this page",
    exText: "Six small worlds of cubes that fall, build, ripple and fold into each other, and one that takes a file apart layer by layer. Explore whenever you like; the support button stays with you.",
    explore: "Enter the Cubeverse", exploreAgain: "Back to the Cubeverse", loading: "Preparing the world…", loadFail: "The Cubeverse could not load. Please try again.",
    wTitle: "Research & work", wLead: "Published research and open-source projects.", wPapers: "published papers", wViews: "paper views",
    wDownloads: "paper downloads", wRepos: "open-source repositories", wPapersH: "Research (Zenodo)", wJan: "January 2026", wPre: "Preprint · January 2026",
    wV: "views", wD: "downloads", wProjH: "Selected projects (GitHub)",
    wP1: "A computational experiment showing language models collapsing when trained on their own outputs, with a DOI-archived release.",
    wP2: "A stability stress-testing framework for large language models that detects variance decay and semantic divergence.",
    wP3: "A fractionally damped spatial oscillator network: a numerical exploration of chaos, attractors and spatial correlations.",
    wP4: "An AI platform for preparing for the Qiyas exams.", wAsof: "Figures from public records as of November 2026.",
    vKicker: "Latest video · YouTube", vBadge: "Click to play", vPlay: "Play the video: {t}", vFrame: "YouTube video: {t}",
    vNote: "Your browser contacts YouTube only when you press play; the video then loads from youtube-nocookie.com.", vChannel: "Ainex on YouTube",
    wLive: "Live figures from Zenodo and GitHub, last updated {d}.", wStars: "{n} stars on GitHub",
    tlTitle: "Milestones",
    tl1d: "October 2024", tl1: "GitHub account", tl1p: "The open-source repositories begin at github.com/mhh1430hacker.",
    tl2d: "January 2026", tl2: "Ainex-Limit-Experiment release", tl2p: "The computational experiment on language-model collapse, with a release archived on Zenodo under a DOI.",
    tl3d: "January 2026", tl3: "The three Ainex papers", tl3p: "Three papers published on Zenodo: the Ainex Limit, the Ainex Singularity and the Structural Divergence.",
    tl4d: "2026", tl4: "CyberScan, and ainex-ai.xyz goes live", tl4p: "A platform for analysing files and detecting threats, open on the web.",
    tl5d: "November 2026", tl5: "Phone app 1.1.0 and Windows 2.0.0", tl5p: "CyberScan on the phone and on the desktop.",
    langLabel: "العربية",
  },
};
let lang = "ar";
try { lang = localStorage.getItem("cyberscan-lang") === "en" ? "en" : "ar"; } catch { /* storage off */ }
const $ = (id) => document.getElementById(id);
const cta = $("sp-cta"), fab = $("sp-fab"), modal = $("sp-support"), explore = $("sp-explore");
const motionOff = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");
const sfx = (name, opts) => { try { window.CSAudio?.play?.(name, opts); } catch { /* no sound */ } };
let bit = null;        // the robot, once loaded
let visited = false;   // the visitor has been inside the Cubeverse (the door then says "back to")

function paint() {
  const t = T[lang];
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.title = t.title;
  document.querySelectorAll("[data-t]").forEach((n) => { if (t[n.dataset.t]) n.textContent = t[n.dataset.t]; });
  $("sp-photo").alt = t.photo; $("sp-qr").alt = t.qrAlt; $("sp-qr-big").alt = t.qrAlt; $("sp-qr-open").setAttribute("aria-label", t.qrOpen);
  $("sp-support-close").setAttribute("aria-label", t.close);
  fab.setAttribute("aria-label", t.fabLabel);
  document.querySelectorAll(".sp-copy").forEach((b) => b.setAttribute("aria-label", b.dataset.label === "iban" ? t.copyIban : t.copyAccount));
  explore.querySelector("span").textContent = visited ? t.exploreAgain : t.explore;
  paintVideo(); paintLive();
  $("sp-lang").textContent = lang === "ar" ? "EN" : "ع";
  $("sp-lang").setAttribute("aria-label", t.langLabel);
}
$("sp-lang").addEventListener("click", () => {
  lang = lang === "ar" ? "en" : "ar";
  try { localStorage.setItem("cyberscan-lang", lang); } catch { /* storage off */ }
  paint();
  document.dispatchEvent(new CustomEvent("sp:lang", { detail: lang }));
});

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const ta = document.createElement("textarea"); ta.value = text; ta.setAttribute("readonly", "");
    (modal.open ? modal : document.body).append(ta); ta.select();
    let ok = false; try { ok = document.execCommand("copy"); } catch { /* refused */ }
    ta.remove(); return ok;
  }
}
// the toast lives inside the open dialog (a modal dialog covers everything else)
function toast(text) {
  const n = $("sp-toast");
  const host = $("sp-qr-dialog").open ? $("sp-qr-dialog") : modal.open ? modal : document.body;
  if (n.parentElement !== host) host.append(n);
  n.textContent = text; n.hidden = false;
  clearTimeout(n.t); n.t = setTimeout(() => { n.hidden = true; }, 1900);
}

/* ---------------- the support modal ---------------- */
let opener = null;
function openSupport(from) {
  if (modal.open) return;
  opener = from || document.activeElement;
  document.dispatchEvent(new CustomEvent("sp:modal", { detail: true }));
  modal.showModal();
  $("sp-support-close").focus();
  if (!motionOff() && modal.animate) {
    modal.animate([{ opacity: 0, transform: "translateY(18px) scale(.97)" }, { opacity: 1, transform: "none" }], { duration: 340, easing: "cubic-bezier(.22,1,.36,1)" });
  }
  bit?.thank("open");
}
let closing = false;
async function closeSupport() {
  if (!modal.open || closing) return;
  closing = true;
  if (!motionOff() && modal.animate) {
    try { await modal.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: "translateY(12px) scale(.98)" }], { duration: 200, easing: "ease-in" }).finished; } catch { /* cancelled */ }
  }
  modal.close();
  closing = false;
}
modal.addEventListener("close", () => {
  const back = opener && opener.isConnected && opener.offsetParent !== null ? opener : fab;
  back.focus({ preventScroll: true });
  opener = null;
  document.dispatchEvent(new CustomEvent("sp:modal", { detail: false }));
});
modal.addEventListener("cancel", (e) => { e.preventDefault(); closeSupport(); });   // Esc: the same gentle close
modal.addEventListener("click", (e) => {   // a click on the backdrop (outside the panel) closes
  if (e.target !== modal) return;
  const r = modal.getBoundingClientRect();
  if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) closeSupport();
});
$("sp-support-close").addEventListener("click", closeSupport);
cta.addEventListener("click", () => openSupport(cta));
fab.addEventListener("click", () => openSupport(fab));

document.querySelectorAll(".sp-copy").forEach((b) => b.addEventListener("click", async () => {
  await copyText(b.dataset.copy);
  toast(T[lang].copied);
  b.textContent = `${T[lang].copied} ✓`; b.classList.add("is-done");
  clearTimeout(b.t); b.t = setTimeout(() => { b.textContent = T[lang].copy; b.classList.remove("is-done"); }, 1800);
  bit?.thank("copy");
}));
// share: the bank, the holder, the IBAN and the account in one message (or all copied at once)
$("sp-share").addEventListener("click", async () => {
  const t = T[lang], [iban, account] = [...document.querySelectorAll(".sp-copy")].map((b) => b.dataset.copy);
  const text = `${t.bank}: ${t.bankName}
${t.holder}: ${$("sp-holder").textContent.trim()}
${t.iban}: ${iban}
${t.account}: ${account}`;
  if (navigator.share) {
    try { await navigator.share({ title: t.bankTitle, text }); bit?.thank("share"); return; } catch (e) { if (e && e.name === "AbortError") return; }
  }
  await copyText(text); toast(t.allCopied); bit?.thank("share");
});
// the QR, large enough to scan from another phone (Esc or the button closes it)
const qrDialog = $("sp-qr-dialog");
$("sp-qr-open").addEventListener("click", () => { if (qrDialog.showModal) { qrDialog.showModal(); $("sp-qr-close").focus(); } bit?.thank("qr"); });
$("sp-qr-close").addEventListener("click", () => qrDialog.close());
qrDialog.addEventListener("click", (e) => { if (e.target === qrDialog) qrDialog.close(); });
qrDialog.addEventListener("close", () => $("sp-qr-open").focus({ preventScroll: true }));
/* ---------------- the featured video: a click-to-load facade ----------------
 * Until the visitor presses play the page shows a still served by this site (support/yt-featured.jpg, or the
 * latest video's still that /api/profile embeds as a data: image) and makes no request to YouTube. The press
 * swaps the still for the privacy-enhanced player (youtube-nocookie.com). */
const video = { id: "BMldxyd71ws", title: "CyberScan IN 1 MINUTE" };
const fill = (s, o) => s.replace(/\{(\w+)\}/g, (m, k) => (o[k] != null ? o[k] : m));
function paintVideo() {
  const b = $("sp-video-play"); if (!b) return;
  b.setAttribute("aria-label", fill(T[lang].vPlay, { t: video.title }));
  const f = $("sp-video-frame").querySelector("iframe"); if (f) f.title = fill(T[lang].vFrame, { t: video.title });
}
$("sp-video-play")?.addEventListener("click", () => {
  const box = $("sp-video-frame");
  if (!/^[\w-]{11}$/.test(video.id) || box.querySelector("iframe")) return;
  const f = document.createElement("iframe");
  f.src = `https://www.youtube-nocookie.com/embed/${video.id}?autoplay=1&rel=0&modestbranding=1&hl=${lang}`;
  f.title = fill(T[lang].vFrame, { t: video.title });
  f.allow = "autoplay; encrypted-media; picture-in-picture; fullscreen";
  f.referrerPolicy = "strict-origin-when-cross-origin";
  box.replaceChildren(f);
  box.classList.add("is-live");
  f.focus();
  try { window.CSAudio?.music && window.CSAudio.setMusic(false); } catch { /* no music */ }   // the site's music makes way for the video
});

/* ---------------- live numbers (GET /api/profile, cached six hours on the server) ---------------- */
let live = null;
const nf = (n) => Number(n).toLocaleString("en-US");
function countTo(node, to) {
  const from = Number(String(node.textContent).replace(/[^\d]/g, "")) || 0;
  if (from === to) return;
  if (motionOff() || !node.isConnected) { node.textContent = nf(to); return; }
  const t0 = performance.now(), run = (now) => { const k = Math.min(1, (now - t0) / 900), e = 1 - Math.pow(1 - k, 3); node.textContent = nf(Math.round(from + (to - from) * e)); if (k < 1) requestAnimationFrame(run); };
  requestAnimationFrame(run);
}
function paintLive() {
  if (!live) return;
  const asof = $("sp-asof");
  if (asof && live.checked) asof.textContent = fill(T[lang].wLive, { d: new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-nu-latn-ca-gregory" : "en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(live.checked * 1000)) });
  const stars = live.github && live.github.stars;
  const gh = document.querySelector('.sp-links a[href="https://github.com/mhh1430hacker"]');
  if (gh && stars != null) gh.title = fill(T[lang].wStars, { n: nf(stars) });
}
function applyLive(d) {
  live = d;
  const tot = d.totals || {}, gh = d.github || {};
  const set = (sel, v) => { const n = document.querySelector(sel); if (n && Number.isFinite(Number(v))) countTo(n, Number(v)); };
  set('[data-stat="papers"]', tot.papers); set('[data-stat="views"]', tot.views); set('[data-stat="downloads"]', tot.downloads); set('[data-stat="repos"]', gh.repos);
  for (const [rec, p] of Object.entries(d.papers || {})) { set(`[data-pv="${rec}"]`, p.views); set(`[data-pd="${rec}"]`, p.downloads); }
  const v = d.video;
  if (v && /^[\w-]{11}$/.test(v.id) && !$("sp-video-frame").querySelector("iframe")) {
    video.id = v.id; video.title = v.title || video.title;
    $("sp-video-play").dataset.video = v.id;
    $("sp-video-title").textContent = video.title;
    if (v.thumb && /^data:image\/jpeg;base64,/.test(v.thumb)) $("sp-video-thumb").src = v.thumb;
  }
  paintVideo(); paintLive();
}
(async () => {
  try {
    const token = document.querySelector('meta[name="cyberscan-token"]')?.content || "";
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 9000);
    const r = await fetch("/api/profile", { headers: { "X-CyberScan-Token": token }, signal: ctl.signal, cache: "no-store" });
    clearTimeout(timer);
    if (r.ok) applyLive(await r.json());
  } catch { /* offline or blocked: the fixed numbers in the page stay */ }
})();
paint();

/* ---------------- the Cubeverse: loaded only when asked for ---------------- */
let cvLoad = null;
const loadCubeverse = () => (cvLoad ||= import("./cubeverse/cubeverse.js").catch((e) => { cvLoad = null; throw e; }));
// a hover or a focus on the door already fetches the small shell (the 3D engine waits for the click)
explore.addEventListener("pointerenter", () => { loadCubeverse().catch(() => {}); }, { once: true });
explore.addEventListener("focus", () => { loadCubeverse().catch(() => {}); }, { once: true });
const page = {
  get lang() { return lang; },
  T: (k) => T[lang][k],
  motionOff,
  sfx,
  openSupport,
  isModalOpen: () => modal.open,
  explore,
  // the calm page steps aside / comes back
  away(on) { bit?.away(on); },
  markVisited() { visited = true; paint(); },
};
let entering = false;
explore.addEventListener("click", async () => {
  if (entering) return;
  entering = true; explore.setAttribute("aria-busy", "true");
  try {
    const m = await loadCubeverse();
    await m.enter(page);
  } catch (e) {
    console.warn("Cubeverse:", e);
    toast(T[lang].loadFail);
  } finally { entering = false; explore.removeAttribute("aria-busy"); }
});

// a shared Cube Architecture build (#build=...): open the Cubeverse straight into it
if (/^#build=[A-Za-z0-9_-]{3,}/.test(location.hash)) {
  try { sessionStorage.setItem("cv-world", "architecture"); } catch { /* storage off */ }
  addEventListener("load", () => setTimeout(() => explore.click(), 350), { once: true });
}

/* ---------------- Bit: a small companion on the calm page, loaded once the page is idle ---------------- */
const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 600));
addEventListener("load", () => idle(() => {
  import("./support-bit.js").then((m) => { bit = m.startBit({ getLang: () => lang, cta, modal, motionOff, away: () => document.body.classList.contains("cv-on") }); })
    .catch(() => { /* Bit is optional */ });
}, { timeout: 2500 }));
