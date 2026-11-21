// Support the developer: words (AR/EN), the support modal (bank details, copy, share, QR), the floating
// support button, and the door to the Cubeverse. Nothing 3D loads here: the Cubeverse's modules are
// fetched only when the visitor asks for them (js/cubeverse/cubeverse.js). Bit, the small robot
// companion, loads after the page is idle (js/support-bit.js).

const T = {
  ar: {
    kicker: "المطوّر", name: "مهدي آل حاجي", role: "مطوّر برمجيات وباحث في الذكاء الاصطناعي",
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
    exText: "خمسة عوالم صغيرة من المكعبات: تسقط وتُبنى وتتموّج وتتداخل في بعضها. استكشفها متى شئت، وزر الدعم يبقى معك.",
    explore: "ادخل عالم المكعبات", exploreAgain: "العودة إلى عالم المكعبات", loading: "يجهّز العالم…", loadFail: "تعذّر تحميل عالم المكعبات، حاول مرة أخرى.",
    langLabel: "English",
  },
  en: {
    kicker: "The developer", name: "Mahdi Al-Hajji", role: "Software developer and AI researcher",
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
    exText: "Five small worlds of cubes that fall, build, ripple and fold into each other. Explore whenever you like; the support button stays with you.",
    explore: "Enter the Cubeverse", exploreAgain: "Back to the Cubeverse", loading: "Preparing the world…", loadFail: "The Cubeverse could not load. Please try again.",
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

/* ---------------- Bit: a small companion on the calm page, loaded once the page is idle ---------------- */
const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 600));
addEventListener("load", () => idle(() => {
  import("./support-bit.js").then((m) => { bit = m.startBit({ getLang: () => lang, cta, modal, motionOff, away: () => document.body.classList.contains("cv-on") }); })
    .catch(() => { /* Bit is optional */ });
}, { timeout: 2500 }));
