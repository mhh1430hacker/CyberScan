/* The scan page's extra ways in (loaded after js/scan-center.js):
 *
 *   - Camera: "Scan a QR code" under Link reads a code live with the browser's BarcodeDetector (shown
 *     only where the browser has one), or from a photo or screenshot (BarcodeDetector, else the
 *     server's own decoder at /api/tools/qr); the decoded link goes straight to the link check.
 *   - Email: under Text, "Email with headers" analyses a whole raw email (web_v/email_check.py via
 *     POST /api/email): sender, delivery path, SPF/DKIM/DMARC, links, attachments, a phishing read.
 *   - Many files: a "Choose several files" button opens the batch scan (js/batch.js).
 *   - History: the new filter labels (type, custom date range).
 * All text from the server goes in as text, never as HTML. */
(function () {
  "use strict";
  const CS = window.CS;
  if (!CS || !document.getElementById("form")) return;
  const { $, el, toast } = CS;

  const STR = {
    en: {
      hCustom: "Custom range…", hFrom: "From", hTo: "To", hType: "Type", htAll: "All types", htDoc: "Documents", htProgram: "Programs", htArchive: "Archives",
      htImage: "Images", htScript: "Scripts and web pages", htUrl: "Links", htText: "Text", htOther: "Other files",
      many: "Choose several files", manyHint: "or drop many at once: each gets its own progress and you get one summary",
      qr: "Scan a QR code", qrPhoto: "From a photo or screenshot", qrAim: "Point the camera at a QR code. It's read on this device.", qrCancel: "Cancel",
      qrFound: "QR code read: checking the link", qrText: "The QR code holds text, not a link: it's in the Text box", qrNone: "No QR code found in this picture.",
      qrNoCam: "The camera isn't available. Choose a photo of the code instead.", qrBusy: "Reading the picture…",
      tText: "Text", tEmail: "Email with headers", emailPh: "Paste the whole email here, headers included.\nIn most mail apps: “Show original”, “View source” or “Download message”.",
      emailHint: "This looks like an email. Analyse its headers, links and attachments too?", emailSwitch: "Analyse as email", emailSample: "Try a sample email",
      eTitle: "Email analysis", eNew: "Check another", eSender: "Sender", eAuth: "Sender authentication", ePath: "Delivery path", eLinks: "Links", eAtt: "Attachments", eFind: "What we found",
      eFrom: "From", eName: "Display name", eReply: "Reply-To", eReturn: "Return-Path", eTo: "To", eSubject: "Subject", eDate: "Date",
      eNoLinks: "No links in the message.", eNoAtt: "No attachments.", eNoHops: "No Received headers: the delivery path is unknown.", eNone: "No warning signs in this email.",
      eShows: "shows {a}, goes to {b}", eHop: "{a} → {b}", eRisk: { high: "risky", medium: "check", low: "archive", none: "" },
      auth: { pass: "pass", fail: "fail", softfail: "soft fail", none: "not checked", neutral: "neutral", temperror: "temporary error", permerror: "error", policy: "policy", bestguesspass: "likely pass" },
      authWhat: { spf: "Is the sending server allowed for this domain?", dkim: "Was the message signed by the domain, and unchanged?", dmarc: "Does the visible sender's domain pass its own policy?" },
      eAsk: "Ask about this email", eVerdict: { NO_INDICATORS_OBSERVED: "No warning signs observed", REVIEW: "Needs review", SUSPICIOUS: "Likely phishing" },
      eAdvice: { NO_INDICATORS_OBSERVED: "Nothing suspicious in the headers, links or attachments. Still, be careful with unexpected requests.",
        REVIEW: "Some signs are worth a closer look. Don't open attachments or links until you've confirmed the sender another way.",
        SUSPICIOUS: "Strong signs of phishing. Don't click its links, open its attachments or reply. Report it and delete it." },
      sev: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
      labels: {},
    },
    ar: {
      hCustom: "نطاق مخصص…", hFrom: "من", hTo: "إلى", hType: "النوع", htAll: "كل الأنواع", htDoc: "مستندات", htProgram: "برامج", htArchive: "أرشيفات",
      htImage: "صور", htScript: "سكربتات وصفحات ويب", htUrl: "روابط", htText: "نصوص", htOther: "ملفات أخرى",
      many: "اختر عدة ملفات", manyHint: "أو أفلت عدة ملفات معًا: لكل ملف تقدّمه الخاص وتحصل على ملخص واحد",
      qr: "امسح رمز QR", qrPhoto: "من صورة أو لقطة شاشة", qrAim: "وجّه الكاميرا نحو رمز QR. تتم القراءة على هذا الجهاز.", qrCancel: "إلغاء",
      qrFound: "قُرئ الرمز: جارٍ فحص الرابط", qrText: "يحمل الرمز نصًا وليس رابطًا: وضعناه في خانة النص", qrNone: "لم يُعثر على رمز QR في هذه الصورة.",
      qrNoCam: "الكاميرا غير متاحة. اختر صورة للرمز بدلًا من ذلك.", qrBusy: "جارٍ قراءة الصورة…",
      tText: "نص", tEmail: "بريد مع الترويسات", emailPh: "الصق الرسالة كاملة هنا مع الترويسات.\nفي معظم تطبيقات البريد: «إظهار الأصل» أو «عرض المصدر» أو «تنزيل الرسالة».",
      emailHint: "يبدو هذا رسالة بريد. هل نحلّل ترويساتها وروابطها ومرفقاتها أيضًا؟", emailSwitch: "حلّلها كرسالة بريد", emailSample: "جرّب رسالة نموذجية",
      eTitle: "تحليل البريد", eNew: "افحص رسالة أخرى", eSender: "المرسل", eAuth: "التحقق من المرسل", ePath: "مسار التسليم", eLinks: "الروابط", eAtt: "المرفقات", eFind: "ما وجدناه",
      eFrom: "من", eName: "الاسم الظاهر", eReply: "الرد إلى", eReturn: "مسار الإرجاع", eTo: "إلى", eSubject: "الموضوع", eDate: "التاريخ",
      eNoLinks: "لا روابط في الرسالة.", eNoAtt: "لا مرفقات.", eNoHops: "لا ترويسات Received: مسار التسليم غير معروف.", eNone: "لا علامات تحذير في هذه الرسالة.",
      eShows: "يُظهر {a} ويذهب إلى {b}", eHop: "{a} ← {b}", eRisk: { high: "خطر", medium: "تحقق", low: "أرشيف", none: "" },
      auth: { pass: "ناجح", fail: "فاشل", softfail: "فشل جزئي", none: "لم يُفحص", neutral: "محايد", temperror: "خطأ مؤقت", permerror: "خطأ", policy: "سياسة", bestguesspass: "ناجح غالبًا" },
      authWhat: { spf: "هل يُسمح لخادم الإرسال بالإرسال عن هذا النطاق؟", dkim: "هل وقّع النطاق الرسالة ولم تتغير؟", dmarc: "هل يجتاز نطاق المرسل الظاهر سياسته الخاصة؟" },
      eAsk: "اسأل عن هذه الرسالة", eVerdict: { NO_INDICATORS_OBSERVED: "لم تُرصد علامات تحذير", REVIEW: "تحتاج مراجعة", SUSPICIOUS: "تصيّد على الأرجح" },
      eAdvice: { NO_INDICATORS_OBSERVED: "لا شيء مريب في الترويسات أو الروابط أو المرفقات. ومع ذلك، احذر من الطلبات غير المتوقعة.",
        REVIEW: "بعض العلامات تستحق نظرة أدق. لا تفتح المرفقات أو الروابط حتى تتأكد من المرسل بوسيلة أخرى.",
        SUSPICIOUS: "علامات قوية على التصيّد. لا تنقر روابطها ولا تفتح مرفقاتها ولا ترد عليها. أبلغ عنها واحذفها." },
      sev: { critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة" },
      labels: {
        "Suspicious link in message": "رابط مريب في الرسالة", "Risky attachment": "مرفق خطر", "Sender display name impersonates a brand": "الاسم الظاهر للمرسل ينتحل علامة تجارية",
        "Link text shows a different address": "نص الرابط يُظهر عنوانًا مختلفًا", "Email authentication failed": "فشل التحقق من البريد", "Credential or verification request": "طلب بيانات دخول أو تحقق",
        "Reply-To differs from sender": "عنوان الرد يختلف عن المرسل", "Urgent call to action with link": "دعوة عاجلة للتصرف مع رابط", "Urgency or threat language": "لغة استعجال أو تهديد",
        "Envelope sender differs from From": "مرسل الظرف يختلف عن حقل From", "Display name shows a different email address": "الاسم الظاهر يعرض عنوان بريد مختلفًا",
        "No authentication results": "لا نتائج تحقق", "Sender authentication passed": "نجح التحقق من المرسل", "Signed by a different domain": "موقّعة من نطاق مختلف",
        "Request to share a one-time code": "طلب مشاركة رمز لمرة واحدة", "Payment or gift-card pressure": "ضغط للدفع أو لبطاقات الهدايا", "Prize, lottery or inheritance lure": "طُعم جائزة أو يانصيب أو ميراث",
        "Parcel delivery lure": "طُعم توصيل طرد", "Authority impersonation": "انتحال جهة رسمية", "Malformed email headers": "ترويسات بريد مشوّهة",
      },
    },
  };
  const L = () => STR[CS.lang === "ar" ? "ar" : "en"];
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] != null ? o[k] : ""));
  const I = window.I18N;
  if (I && I.en && I.ar) {
    ["hCustom", "hFrom", "hTo", "hType", "htAll", "htDoc", "htProgram", "htArchive", "htImage", "htScript", "htUrl", "htText", "htOther"].forEach((k) => { I.en[k] = STR.en[k]; I.ar[k] = STR.ar[k]; });
  }
  const modeNow = () => (CS.state && CS.state.mode) || "file";
  const form = $("form");

  /* ================================================================ many files */
  const filePanel = form.querySelector('[data-panel="file"]');
  const manyRow = el("div", "sx-many");
  const manyBtn = el("button", "ghost small sx-many-btn"); manyBtn.type = "button";
  const manyHint = el("small", "sx-many-hint");
  const manyInput = el("input"); manyInput.type = "file"; manyInput.multiple = true; manyInput.hidden = true;
  manyBtn.addEventListener("click", () => manyInput.click());
  manyInput.addEventListener("change", () => { const files = [...manyInput.files]; manyInput.value = ""; if (files.length > 1 && window.CSBatch) window.CSBatch.start(files); else if (files.length) CS.chooseFiles(files); });
  manyRow.append(manyBtn, manyHint, manyInput);
  const seen = $("seen");
  if (filePanel) (seen || filePanel.lastElementChild).before(manyRow);

  /* ================================================================ camera: QR codes */
  const urlInput = $("url");
  const qrRow = el("div", "sx-qr"); qrRow.dataset.panel = "url";
  const liveOk = "BarcodeDetector" in window && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
  const qrBtn = el("button", "ghost small sx-qr-btn"); qrBtn.type = "button"; qrBtn.hidden = !liveOk;
  const photoBtn = el("button", "ghost small sx-qr-btn"); photoBtn.type = "button";
  const photoInput = el("input"); photoInput.type = "file"; photoInput.accept = "image/*"; photoInput.hidden = true;
  const camIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h3l2-2h6l2 2h3v12H4z"/><circle cx="12" cy="13" r="3.5"/></svg>';
  const qrIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM14 18h2v2h-2zM18 18h2v2h-2z"/></svg>';
  qrRow.append(qrBtn, photoBtn, photoInput);
  urlInput.after(qrRow);
  qrRow.hidden = modeNow() !== "url";

  function useDecoded(raw) {
    const text = String(raw || "").trim();
    if (!text) { toast(L().qrNone); return; }
    if (/^https?:\/\//i.test(text) || /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i.test(text)) {
      CS.setMode("url");
      urlInput.value = /^https?:\/\//i.test(text) ? text : `https://${text}`;
      urlInput.dispatchEvent(new Event("input", { bubbles: true }));
      toast(L().qrFound);
      setTimeout(() => { if (!$("go").disabled) $("go").click(); }, 350);
    } else {
      CS.setMode("text");
      $("text").value = text;
      $("text").dispatchEvent(new Event("input", { bubbles: true }));
      toast(L().qrText);
    }
  }
  let stream = null, timer = 0, camDialog = null;
  function stopCam() {
    clearTimeout(timer); timer = 0;
    if (stream) { stream.getTracks().forEach((tr) => tr.stop()); stream = null; }
    if (camDialog) { camDialog.remove(); camDialog = null; }
  }
  async function openCam() {
    const l = L();
    let detector;
    try { detector = new window.BarcodeDetector({ formats: ["qr_code"] }); } catch { toast(l.qrNoCam); return; }
    camDialog = el("div", "rp-modal-back sx-cam");
    const box = el("div", "rp-modal"); box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-label", l.qr);
    const video = el("video", "sx-video"); video.muted = true; video.playsInline = true; video.setAttribute("playsinline", "");
    const frame = el("div", "sx-frame"); frame.append(video, el("i", "sx-aim"));
    const status = el("p", "sx-status", l.qrAim); status.setAttribute("role", "status");
    const cancel = el("button", "ghost", l.qrCancel); cancel.type = "button"; cancel.addEventListener("click", stopCam);
    box.append(frame, status, cancel); camDialog.append(box); document.body.append(camDialog);
    camDialog.addEventListener("keydown", (e) => { if (e.key === "Escape") stopCam(); });
    cancel.focus();
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
      video.srcObject = stream; await video.play();
    } catch { status.textContent = l.qrNoCam; return; }
    const tick = async () => {
      if (!stream) return;
      try {
        const codes = await detector.detect(video);
        if (codes && codes.length) { const v = codes[0].rawValue; stopCam(); useDecoded(v); return; }
      } catch { /* a frame that couldn't be read */ }
      timer = setTimeout(tick, 250);
    };
    tick();
  }
  async function fromPhoto(file) {
    const l = L();
    if (!file) return;
    toast(l.qrBusy);
    if ("BarcodeDetector" in window) {
      try {
        const bmp = await createImageBitmap(file);
        const codes = await new window.BarcodeDetector({ formats: ["qr_code"] }).detect(bmp);
        if (codes && codes.length) { useDecoded(codes[0].rawValue); return; }
      } catch { /* fall back to the server */ }
    }
    try {
      const res = await CS.api("/api/tools/qr", { method: "POST", headers: { "X-Filename": encodeURIComponent(file.name || "qr.png"), "Content-Type": "application/octet-stream" }, body: file });
      const r = res.result || res;
      const codes = r.codes || [];
      const first = codes.map((c) => c.text || c.value || c.payload || c.raw || c.url || "").find(Boolean);
      if (first) useDecoded(first); else toast(l.qrNone);
    } catch (e) { toast(CS.friendlyError ? CS.friendlyError(e) : String(e.message || e)); }
  }
  qrBtn.addEventListener("click", openCam);
  photoBtn.addEventListener("click", () => photoInput.click());
  photoInput.addEventListener("change", () => { const f = photoInput.files[0]; photoInput.value = ""; fromPhoto(f); });

  /* ================================================================ email analysis */
  const textArea = $("text");
  const textPanel = form.querySelector('[data-panel="text"]');
  let emailMode = false;
  const seg = el("div", "sx-seg"); seg.setAttribute("role", "group");
  const segText = el("button", "sx-seg-btn"); segText.type = "button";
  const segMail = el("button", "sx-seg-btn"); segMail.type = "button";
  seg.append(segText, segMail);
  textPanel.prepend(seg);
  const hint = el("div", "sx-hint"); hint.hidden = true;
  const hintText = el("span");
  const hintBtn = el("button", "link-btn"); hintBtn.type = "button";
  hint.append(hintText, hintBtn);
  textArea.after(hint);
  const sampleMail = el("button", "link-btn sx-sample"); sampleMail.type = "button"; sampleMail.hidden = true;
  ($("sample") || textArea).after(sampleMail);
  function setEmail(on) {
    emailMode = on;
    segText.setAttribute("aria-pressed", String(!on)); segMail.setAttribute("aria-pressed", String(on));
    textArea.placeholder = on ? L().emailPh : (CS.t("textPh") || "");
    textArea.rows = on ? 10 : 5;
    if ($("sample")) $("sample").hidden = on;
    sampleMail.hidden = !on;
    textPanel.classList.toggle("sx-email", on);
    syncHint();
  }
  const looksEmail = (v) => (v.slice(0, 20000).match(/^(?:from|to|subject|received|return-path|reply-to|message-id|authentication-results|date|dkim-signature):/gim) || []).length >= 2;
  function syncHint() { hint.hidden = emailMode || !looksEmail(textArea.value); }
  textArea.addEventListener("input", syncHint);
  segText.addEventListener("click", () => setEmail(false));
  segMail.addEventListener("click", () => setEmail(true));
  hintBtn.addEventListener("click", () => setEmail(true));
  const SAMPLE = [
    "Received: from mail.mailbox-help.top (mail.mailbox-help.top [203.0.113.45]) by mx.example.com; Mon, 16 Nov 2026 08:01:02 +0000",
    "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-security.xyz; dkim=none; dmarc=fail header.from=paypal.com",
    "Return-Path: <bounce@mailbox-help.top>", "From: \"PayPal Support\" <service@paypal.com.account-verify.xyz>", "Reply-To: refund@mailbox-help.top",
    "To: you@example.com", "Subject: Urgent: your account will be suspended", "Date: Mon, 16 Nov 2026 08:01:00 +0000", "MIME-Version: 1.0",
    "Content-Type: multipart/mixed; boundary=\"XX\"", "", "--XX", "Content-Type: text/html; charset=utf-8", "",
    "<p>Dear customer, verify your account within 24 hours or it will be closed.</p>",
    "<a href=\"http://paypa1-secure-login.com.verify-account.xyz/login\">https://www.paypal.com/signin</a>", "--XX",
    "Content-Type: application/octet-stream; name=\"invoice_2026.pdf.exe\"", "Content-Disposition: attachment; filename=\"invoice_2026.pdf.exe\"",
    "Content-Transfer-Encoding: base64", "", "U3ludGhldGljIHRlc3QgZmlsZQ==", "--XX--", "",
  ].join("\n");
  sampleMail.addEventListener("click", () => { textArea.value = SAMPLE; textArea.dispatchEvent(new Event("input", { bubbles: true })); textArea.focus(); });

  // the email result, in place of the composer
  const out = el("section", "card sx-email-out"); out.hidden = true; out.setAttribute("aria-live", "polite");
  ($("error") || $("progress")).after(out);
  const composer = document.querySelector(".composer");
  new MutationObserver(() => { if (composer && !composer.hidden) out.hidden = true; }).observe(composer, { attributes: true, attributeFilter: ["hidden"] });
  window.addEventListener("cs:scan-start", () => { out.hidden = true; });

  // intercept the form's submit only for an email (capture on the document runs before app.js's handler)
  document.addEventListener("submit", (e) => {
    if (e.target !== form || modeNow() !== "text" || !emailMode) return;
    e.preventDefault(); e.stopImmediatePropagation();
    analyseEmail();
  }, true);
  let lastEmail = null;
  async function analyseEmail() {
    const go = $("go"); go.disabled = true;
    try {
      const res = await CS.postJSON("/api/email", { raw: textArea.value });
      lastEmail = res;
      renderEmail(res, true);
    } catch (err) {
      toast(String((err && err.message) || err));
    }
    go.disabled = false;
  }
  function renderEmail(r, animate) {
    const l = L();
    composer.hidden = true;
    $("result").hidden = true; $("error").hidden = true; $("batch").hidden = true;
    const tone = r.classification === "SUSPICIOUS" ? "bad" : r.classification === "REVIEW" ? "warn" : "ok";
    out.className = `card sx-email-out t-${tone}`;
    out.replaceChildren();
    const head = el("div", "sx-e-head");
    const score = el("div", "sx-e-score"); score.append(el("b", "", String(r.score)), el("small", "", "/100"));
    const ht = el("div");
    ht.append(el("small", "sx-kicker", l.eTitle), el("h2", "", l.eVerdict[r.classification] || r.classification), el("p", "", l.eAdvice[r.classification] || ""));
    head.append(score, ht);
    out.append(head);
    const sec = (title) => { const s = el("section", "sx-e-sec"); s.append(el("h3", "", title)); out.append(s); return s; };
    const kv = (rows) => {
      const dl = el("dl", "sx-kv");
      rows.filter(([, v]) => v).forEach(([k, v, mono]) => { dl.append(el("dt", "", k)); const d = el("dd", mono ? "mono" : "", v); d.dir = mono ? "ltr" : "auto"; dl.append(d); });
      return dl;
    };
    // findings first: the phishing read
    const f = sec(l.eFind);
    const weighted = (r.findings || []).filter((x) => x.weight > 0);
    if (!weighted.length) f.append(el("p", "sx-none", l.eNone));
    const ul = el("ul", "sx-finds");
    (r.findings || []).forEach((x) => {
      const li = el("li", `s-${x.severity}`);
      const top = el("div", "sx-f-top");
      top.append(el("span", "sx-sev", l.sev[x.severity] || x.severity), el("b", "", l.labels[x.label] || x.label));
      if (x.weight) top.append(el("span", "sx-w", `+${x.weight}`));
      const p = el("p", "", x.explanation); p.dir = "auto";
      li.append(top, p); ul.append(li);
    });
    f.append(ul);
    // sender
    const h = r.headers || {};
    sec(l.eSender).append(kv([[l.eName, h.display_name], [l.eFrom, h.from, true], [l.eReply, h.reply_to, true], [l.eReturn, h.return_path, true], [l.eTo, h.to, true], [l.eSubject, h.subject], [l.eDate, h.date, true]]));
    // authentication
    const a = sec(l.eAuth);
    const pills = el("div", "sx-auth");
    ["spf", "dkim", "dmarc"].forEach((m) => {
      const res = ((r.auth || {})[m] || {}).result || "none";
      const t = res === "pass" || res === "bestguesspass" ? "ok" : /fail|error/.test(res) ? "bad" : "muted";
      const card = el("div", `sx-auth-card t-${t}`);
      card.append(el("b", "", m.toUpperCase()), el("span", "sx-auth-res", l.auth[res] || res), el("small", "", l.authWhat[m]));
      const det = (r.auth[m] || {}).detail || (r.auth[m] || {}).signed_by;
      if (det) { const c = el("code", "", det); c.dir = "ltr"; card.append(c); }
      pills.append(card);
    });
    a.append(pills);
    // delivery path
    const pth = sec(l.ePath);
    if (!(r.received || []).length) pth.append(el("p", "sx-none", l.eNoHops));
    else {
      const ol = el("ol", "sx-hops");
      r.received.forEach((hop) => {
        const li = el("li");
        const line = el("span", "mono", fill(l.eHop, { a: hop.from || "?", b: hop.by || "?" })); line.dir = "ltr";
        li.append(line);
        if (hop.ip) { const ip = el("code", "", hop.ip); ip.dir = "ltr"; li.append(document.createTextNode(" "), ip); }
        if (hop.when) li.append(el("small", "", ` · ${new Date(hop.when).toString() !== "Invalid Date" ? new Intl.DateTimeFormat(CS.lang, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(hop.when)) : hop.when}`));
        ol.append(li);
      });
      pth.append(ol);
    }
    // links
    const lk = sec(l.eLinks);
    if (!(r.links || []).length) lk.append(el("p", "sx-none", l.eNoLinks));
    else {
      const ulL = el("ul", "sx-links");
      r.links.forEach((x) => {
        const li = el("li", x.score >= 50 ? "bad" : x.score > 0 ? "warn" : "");
        const u = el("code", "", x.url); u.dir = "ltr";
        const sc = el("span", "sx-lscore", `${x.score}/100`);
        li.append(sc, u);
        if (x.text && x.text !== x.url) { const t = el("small", "", `“${x.text}”`); t.dir = "auto"; li.append(t); }
        if ((x.flags || []).length) li.append(el("small", "sx-flags", x.flags.join(" · ")));
        ulL.append(li);
      });
      lk.append(ulL);
      (r.link_text_mismatch || []).forEach((m) => { const p = el("p", "sx-mismatch", fill(l.eShows, { a: m.shown, b: m.real })); p.dir = "auto"; lk.append(p); });
    }
    // attachments
    const at = sec(l.eAtt);
    if (!(r.attachments || []).length) at.append(el("p", "sx-none", l.eNoAtt));
    else {
      const ulA = el("ul", "sx-att");
      r.attachments.forEach((x) => {
        const li = el("li", `r-${x.risk}`);
        const n = el("code", "", x.name); n.dir = "ltr";
        li.append(n, el("small", "", ` · ${x.type} · ${CS.formatBytes(x.size || 0)}`));
        if (l.eRisk[x.risk]) li.append(el("span", "sx-risk", l.eRisk[x.risk]));
        ulA.append(li);
      });
      at.append(ulA);
    }
    out.append(el("p", "rc-note", r.note || ""));
    const row = el("div", "sx-e-actions");
    const again = el("button", "primary", l.eNew); again.type = "button";
    again.addEventListener("click", () => { out.hidden = true; CS.newScan(); CS.setMode("text"); setEmail(true); });
    row.append(again);
    if (window.CSAsk) {
      const ask = el("button", "ghost", l.eAsk); ask.type = "button";
      ask.addEventListener("click", () => window.CSAsk.open(undefined, {
        verdict: r.classification, score: r.score, mode: "email",
        findings: (r.findings || []).slice(0, 8).map((x) => ({ title: x.label, severity: x.severity, weight: x.weight, source: x.category })),
      }, `${l.eVerdict[r.classification] || r.classification}, ${r.score}/100`, ask));
      row.append(ask);
    }
    out.append(row);
    out.hidden = false;
    if (animate) { out.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" }); }
  }

  /* ================================================================ texts */
  function texts() {
    const l = L();
    manyBtn.textContent = l.many; manyHint.textContent = l.manyHint;
    qrBtn.innerHTML = camIcon; qrBtn.append(document.createTextNode(` ${l.qr}`));
    photoBtn.innerHTML = qrIcon; photoBtn.append(document.createTextNode(` ${l.qrPhoto}`));
    segText.textContent = l.tText; segMail.textContent = l.tEmail;
    hintText.textContent = `${l.emailHint} `; hintBtn.textContent = l.emailSwitch;
    sampleMail.textContent = l.emailSample;
    setEmail(emailMode);
    if (!out.hidden && lastEmail) renderEmail(lastEmail, false);
  }
  CS.onLang(() => requestAnimationFrame(texts));
  texts();
})();
