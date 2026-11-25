/* The CyberScan scan report (report.html), printable and savable as PDF from the browser.
 * The scan page stores the result in this browser (localStorage, key in the URL hash) together with
 * what it already worked out in the reader's language (the one score and verdict, the findings, the
 * engines' states, the scan's own time) and opens this page; nothing is sent anywhere. The score is
 * shown as weighted evidence (not a probability), model output only if a model produced any, and the
 * limits of static analysis. All text from the result is inserted as text, never as HTML.
 *
 * A shared result (#r=…, js/share-code.js) is rendered read-only from the link itself: nothing was
 * uploaded and nothing is fetched. The printed report carries a QR code that opens that shared view,
 * and prints in a light or a dark design. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const shared = /^#r=/.test(location.hash) ? location.hash.slice(3) : null;
  let data = null;
  if (!shared) { try { data = JSON.parse(localStorage.getItem(location.hash.slice(1)) || "null"); } catch { data = null; } }
  // the report's language: the scan's, else the one chosen in the app
  let saved = "";
  try { saved = localStorage.getItem("cyberscan-lang") || ""; } catch { /* storage off */ }
  const ar = data ? data.lang === "ar" : saved === "ar";
  document.documentElement.lang = ar ? "ar" : "en";
  document.documentElement.dir = ar ? "rtl" : "ltr";
  const T = ar ? {
    title: "تقرير فحص CyberScan", print: "اطبع أو احفظ بصيغة PDF", pdf: "تنزيل PDF", pLight: "طباعة فاتحة", pDark: "طباعة داكنة", pTheme: "تصميم الطباعة",
    fp: "بصمة الملف", fpNote: "أي تغيير ولو بايت واحد في الملف يغيّر هذه البصمة كليًا.", qrTitle: "تحقّق", qrNote: "يفتح هذا الرمز ملخصًا للقراءة فقط لهذه النتيجة. لم يُرفع أي ملف: الملخص كله داخل الرابط.",
    shTitle: "نتيجة CyberScan مشارَكة", shNote: "ملخص للقراءة فقط شاركه أحدهم برابط. لم يُرفع الملف، ولا يحفظ أي خادم هذه النتيجة: كل ما تراه موجود داخل الرابط نفسه.",
    shVerify: "تحقّق بنفسك: افحص الملف نفسه في CyberScan وتأكد أن بصمة SHA-256 تطابق البصمة أعلاه. إن اختلفت البصمة فهو ملف آخر.",
    shScan: "افتح الماسح", shBad: "رابط المشاركة هذا تالف أو ناقص.", shOld: "هذا المتصفح لا يفتح الروابط المضغوطة. جرّب إصدارًا حديثًا من Chrome أو Edge أو Firefox أو Safari.",
    shRules: "القواعد المطابِقة", shName: "الاسم", shNoName: "لم يُدرجه المرسل", shTop: "أبرز الأدلة", shLink: "رابط المشاركة", missing: "لم يُعثر على بيانات هذا التقرير في هذا المتصفح. افتحه من نتيجة الفحص في CyberScan.",
    s: ["تعريف الفحص", "ما فُحص", "الملخص التنفيذي", "التصنيف", "تقييم الخطورة", "أدلة الكشف", "النتائج التقنية", "الإجراءات الموصى بها", "بيانات الفحص الوصفية", "حدود هذا التقرير وإخلاء المسؤولية"],
    id: "معرّف التقرير", generated: "تاريخ الإنشاء", scanned: "وقت الفحص", engine: "المحرك", target: "الهدف", type: "النوع", size: "الحجم", sha: "SHA-256", mode: "نوع الفحص",
    modes: { file: "ملف", url: "رابط", text: "نص" },
    score: "الدرجة", band: "النطاق", scoreNote: "الدرجة أدلة موزونة من كل فحوص CyberScan، من 0 إلى 100: كل نتيجة تضيف وزنها، وأقوى دليل يحدد الحد الأدنى. ليست احتمالًا لوجود برمجية خبيثة.",
    model: "نموذج التعلّم الآلي", modelNone: "غير متاح: لا يوجد نموذج معتمد مثبّت، فاعتمدت النتيجة على الأدلة الساكنة فقط.", modelNote: "درجات النموذج غير معايَرة وليست احتمالات.",
    sev: "الخطورة", finding: "الدليل", detail: "الشرح", source: "المصدر", contrib: "الوزن", none: "لم تُرصد علامات تحذير.",
    evCaption: "كل ما وجدته الفحوص، مرتبًا حسب وزنه في الدرجة.",
    engines: "حالة المحركات", mitre: "تقنيات MITRE ATT&CK", pe: "بنية البرنامج (PE)", entropy: "الإنتروبيا", mean: "المتوسط", peak: "الذروة", jumps: "قفزات", status: "الحالة", complete: "مكتمل", partial: "جزئي (لم يكتمل فحص المحتوى)",
    verdict: "النتيجة", elapsed: "مدة الفحص", seconds: "{s} ث", agree: "توافق الأدلة", agreeMany: "اتفقت {n} فحوص مستقلة", agreeOne: "فحص واحد", agreeNone: "لا أدلة",
    staticScore: "درجة القواعد الساكنة", contentScore: "درجة فحص المحتوى", finalScore: "الدرجة النهائية",
    peKeys: { machine: "المعمارية", subsystem: "النظام الفرعي", imports: "الدوال المستوردة", suspicious: "استيرادات مشبوهة", sections: "الأقسام" },
    cats: { yara: "قواعد YARA", heuristic: "القواعد الاستدلالية", structural: "تحليل البنية", content: "فحص المحتوى", url: "تحليل الرابط", phishing: "فحص التصيّد", osint: "البحث عبر الإنترنت", model: "نموذج التعلّم", archive: "فحص الأرشيف", tradecraft: "أساليب المهاجمين", hash: "قاعدة البصمات", privacy: "الخصوصية", secrets: "الأسرار" },
    disclaimer: ["أُعدّ هذا التقرير آليًا بواسطة CyberScan، وهو مشروع بحثي تعليمي دفاعي، وليس بديلًا عن برامج الحماية التجارية.", "التحليل ساكن فقط: لم يُفتح الهدف ولم يُشغَّل، ولا يمكن رؤية السلوك الذي يظهر عند التشغيل فقط.", "«لم تُرصد علامات تحذير» لا تعني أن الهدف آمن، والدرجة ليست احتمالًا.", "لا يتضمن هذا التقرير أي شهادة أو ضمان أمني."],
    cls: { EMPTY: "ملف فارغ", KNOWN_MALWARE: "برنامج ضار معروف", NO_INDICATORS_OBSERVED: "لم تُرصد علامات تحذير", REVIEW: "يحتاج مراجعة", SUSPICIOUS: "مشبوه", UNKNOWN: "غير حاسم" },
    sevs: { critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة" },
    bands: ["0: لا مؤشرات", "1–49: مراجعة", "50+: مشبوه"],
    recos: { KNOWN_MALWARE: ["احذفه ولا تفتحه أو تشغّله.", "إن فُتح، افصل الجهاز عن الشبكة وشغّل فحصًا كاملًا.", "أبلغ فريق الأمن عن مصدره."], NO_INDICATORS_OBSERVED: ["لم تجد هذه الفحوص مؤشرات مشبوهة.", "هذا ليس ضمانًا؛ فضّل المصادر الموثوقة."], REVIEW: ["راجع الأدلة قبل فتحه.", "تحقق من مصدره عبر وسيلة أخرى."], SUSPICIOUS: ["لا تفتحه ولا تشغّله.", "أبلغ عنه واحذفه إن وصل بالبريد أو المحادثة.", "إن فُتح، افصل الجهاز عن الشبكة وشغّل فحصًا كاملًا."], UNKNOWN: ["لم يكتمل التحليل: عامله على أنه غير متحقق منه.", "أعد الفحص أو استخدم أداة أخرى قبل فتحه."] },
  } : {
    title: "CyberScan scan report", print: "Print or save as PDF", pdf: "Download PDF", pLight: "Light print", pDark: "Dark print", pTheme: "Print design",
    fp: "File fingerprint", fpNote: "Changing even one byte of the file changes this fingerprint completely.", qrTitle: "Verify", qrNote: "This code opens a read-only summary of this result. No file was uploaded: the whole summary is inside the link.",
    shTitle: "Shared CyberScan result", shNote: "A read-only summary someone shared by link. The file was not uploaded and no server keeps this result: everything you see is inside the link itself.",
    shVerify: "Verify it yourself: scan the same file in CyberScan and check that its SHA-256 matches the one above. A different fingerprint means a different file.",
    shScan: "Open the scanner", shBad: "This shared link is damaged or incomplete.", shOld: "This browser can't open compressed links. Try a recent Chrome, Edge, Firefox or Safari.",
    shRules: "Matched rules", shName: "Name", shNoName: "not included by the sender", shTop: "Top evidence", shLink: "Shared link", missing: "This report's data isn't in this browser. Open it from a scan result in CyberScan.",
    s: ["Scan identification", "What was checked", "Executive summary", "Classification", "Risk assessment", "Detection evidence", "Technical findings", "Recommended actions", "Scan metadata", "Limitations and disclaimers"],
    id: "Report ID", generated: "Generated", scanned: "Scanned", engine: "Engine", target: "Target", type: "Type", size: "Size", sha: "SHA-256", mode: "Scan type",
    modes: { file: "File", url: "Link", text: "Text" },
    score: "Score", band: "Band", scoreNote: "The score is weighted evidence from all of CyberScan's checks, from 0 to 100: each finding adds its weight, and the strongest piece of evidence sets the minimum. It is not a probability of malware.",
    model: "Machine-learning model", modelNone: "Not available: no approved model is installed, so the result rests on static evidence only.", modelNote: "Model scores are uncalibrated and are not probabilities.",
    sev: "Severity", finding: "Finding", detail: "Explanation", source: "Source", contrib: "Weight", none: "No warning signs were observed.",
    evCaption: "Everything the checks found, ordered by its weight in the score.",
    engines: "Engine status", mitre: "MITRE ATT&CK techniques", pe: "Program structure (PE)", entropy: "Entropy", mean: "mean", peak: "peak", jumps: "sudden jumps", status: "Status", complete: "Complete", partial: "Partial (content inspection incomplete)",
    verdict: "Result", elapsed: "Scan duration", seconds: "{s} s", agree: "Evidence agreement", agreeMany: "{n} independent checks agreed", agreeOne: "One check", agreeNone: "No evidence",
    staticScore: "Static rules score", contentScore: "Content inspection score", finalScore: "Final score",
    peKeys: { machine: "Machine", subsystem: "Subsystem", imports: "Imported functions", suspicious: "Suspicious imports", sections: "Sections" },
    cats: { yara: "YARA rules", heuristic: "Heuristic rules", structural: "Structure analysis", content: "Content inspection", url: "Link analysis", phishing: "Phishing check", osint: "Online lookups", model: "Learning model", archive: "Archive check", tradecraft: "Attacker techniques", hash: "Hash database", privacy: "Privacy", secrets: "Secrets" },
    disclaimer: ["This report was generated automatically by CyberScan, a defensive research and education project. It is not a replacement for commercial security products.", "The analysis is static only: nothing was opened or run, so behaviour that only appears at run time cannot be seen.", "\"No warning signs observed\" does not mean the target is safe, and the score is not a probability.", "This report carries no certification or security guarantee."],
    cls: { EMPTY: "Empty file", KNOWN_MALWARE: "Known malware", NO_INDICATORS_OBSERVED: "No warning signs observed", REVIEW: "Needs review", SUSPICIOUS: "Suspicious", UNKNOWN: "Inconclusive" },
    sevs: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
    bands: ["0: no indicators", "1–49: review", "50+: suspicious"],
    recos: { KNOWN_MALWARE: ["Delete it; do not open or run it.", "If it was opened, disconnect the computer from the network and run a full scan.", "Report where it came from to your security team."], NO_INDICATORS_OBSERVED: ["No suspicious indicators were found by these checks.", "That is not a guarantee; prefer trusted sources."], REVIEW: ["Review the evidence before opening it.", "Verify where it came from through another channel."], SUSPICIOUS: ["Do not open or run it.", "If it arrived by email or chat, report it and delete it.", "If it was opened, disconnect the computer from the network and run a full scan."], UNKNOWN: ["The analysis was incomplete: treat it as unverified.", "Scan again or use another tool before opening it."] },
  };
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] != null ? o[k] : ""));
  /* External intelligence (VirusTotal and the other services): one row per service that answered */
  const EXT = ar ? { h: "الاستخبارات الخارجية", svc: "الخدمة", ans: "الإجابة", rep: "التقرير", note: "استعلام بالبصمة أو الرابط فقط؛ لم يُرفع الملف إلى أي جهة.",
    chip: { bad: "مُشار إليه", warn: "إشارة ضعيفة", ok: "سليم", neutral: "غير موجود", quota: "نفدت الحصة", error: "غير متاح" }, ratio: "{m} / {t} محركًا" }
    : { h: "External intelligence", svc: "Service", ans: "Answer", rep: "Report", note: "Looked up by fingerprint or link only; the file was never uploaded anywhere.",
      chip: { bad: "Flagged", warn: "Weak signal", ok: "Clean", neutral: "Not found", quota: "Quota reached", error: "Unavailable" }, ratio: "{m} / {t} engines" };
  const extTable = (rows, links) => {
    const answered = (rows || []).filter((x) => x && EXT.chip[x.chip]);
    if (!answered.length) return null;
    const wrap = el("div", "table-wrap");
    const tb = el("table"); const thead = el("thead"); const trh = el("tr");
    [EXT.svc, EXT.ans].concat(links ? [EXT.rep] : []).forEach((h) => { const th = el("th", "", h); th.scope = "col"; trh.append(th); });
    thead.append(trh); tb.append(thead);
    const tbody = el("tbody");
    answered.forEach((x) => {
      const tr = el("tr", x.chip === "bad" ? "s-high" : x.chip === "warn" ? "s-medium" : "");
      const th = el("th", "", x.name); th.scope = "row"; th.dir = "ltr"; tr.append(th);
      const total = Number(x.engines_total) || 0;
      const words = [EXT.chip[x.chip], total ? fill(EXT.ratio, { m: Number(x.malicious) || 0, t: total }) : "", x.label || x.family || x.signature || ""].filter(Boolean).join(" · ");
      const td = el("td", "", words); td.dir = "auto"; tr.append(td);
      if (links) {
        const tl = el("td");
        if (x.link && /^https:\/\//.test(x.link)) { const a = el("a", "mono", new URL(x.link).host); a.href = x.link; a.rel = "noopener noreferrer"; a.target = "_blank"; tl.append(a); }
        tr.append(tl);
      }
      tbody.append(tr);
    });
    tb.append(tbody); wrap.append(tb);
    return wrap;
  };
  document.title = shared ? T.shTitle : T.title;
  // the toolbar: Download PDF (the browser's print dialog, "Save as PDF") and the print design
  $("print").textContent = T.pdf;
  $("print").title = T.print;
  $("print").addEventListener("click", () => window.print());
  let theme = "light";
  try { theme = localStorage.getItem("cs-report-theme") === "dark" ? "dark" : "light"; } catch { /* storage off */ }
  const themeBox = el("div", "theme"); themeBox.setAttribute("role", "group"); themeBox.setAttribute("aria-label", T.pTheme);
  const setTheme = (k) => {
    theme = k; document.documentElement.dataset.print = k;
    themeBox.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.k === k)));
    try { localStorage.setItem("cs-report-theme", k); } catch { /* storage off */ }
  };
  [["light", T.pLight], ["dark", T.pDark]].forEach(([k, label]) => { const b = el("button", "", label); b.type = "button"; b.dataset.k = k; b.addEventListener("click", () => setTheme(k)); themeBox.append(b); });
  $("bar").append(themeBox);
  setTheme(theme);
  const doc = $("doc");
  const logo = () => { const i = el("img", "logo"); i.src = "icon.svg"; i.alt = ""; i.width = 34; i.height = 34; return i; };
  const qrBlock = (link) => {
    const box = el("div", "qr");
    const code = window.CSQR && window.CSQR.svg(link, { label: T.qrTitle });
    if (!code) return null;
    const txt = el("div", "qr-text");
    txt.append(el("b", "", T.qrTitle), el("p", "note", T.qrNote));
    const a = el("a", "mono qr-link", link.length > 90 ? `${link.slice(0, 88)}…` : link); a.href = link; a.dir = "ltr";
    txt.append(a);
    box.append(code, txt);
    return box;
  };
  const fpBlock = (sha) => {
    if (!sha) return null;
    const box = el("div", "fp");
    const code = el("code", "mono", sha.replace(/(.{16})/g, "$1 ").trim()); code.dir = "ltr";
    box.append(el("small", "", T.fp), code, el("p", "note", T.fpNote));
    return box;
  };

  /* ---------- a shared result: everything comes from the link ---------- */
  if (shared) {
    (async () => {
      let o = null, err = "";
      try { o = await window.CSShare.decode(shared); } catch (e) { err = String(e && e.message) === "unsupported" ? T.shOld : T.shBad; }
      if (!o) { $("loading").textContent = err || T.shBad; $("loading").classList.add("missing"); $("bar").hidden = true; return; }
      doc.replaceChildren();
      const tone = o.c === "SUSPICIOUS" || o.c === "KNOWN_MALWARE" ? "bad" : o.c === "REVIEW" ? "warn" : o.c === "NO_INDICATORS_OBSERVED" ? "ok" : "neutral";
      const head = el("header", "head");
      const brand = el("div", "brand"); const bl = el("span", "brand-l"); bl.append(logo(), el("b", "", "CyberScan")); brand.append(bl);
      head.append(brand, el("h1", "", T.shTitle), el("p", `verdict t-${tone}`, `${T.cls[o.c] || o.c} · ${o.s}/100`));
      doc.append(head);
      const note = el("p", "shared-note", T.shNote); doc.append(note);
      const sec = (title) => { const x = el("section", "sec"); x.append(el("h2", "", title)); doc.append(x); return x; };
      const kvs = (rows) => {
        const dl = el("dl", "kv");
        rows.filter(([, v]) => v != null && v !== "").forEach(([k, v, mono]) => { dl.append(el("dt", "", k)); const d = el("dd"); const b = el("bdi", mono ? "mono" : "", String(v)); b.dir = mono ? "ltr" : "auto"; d.append(b); dl.append(d); });
        return dl;
      };
      const s1 = sec(T.s[1]);
      s1.append(kvs([[T.shName, o.n || T.shNoName], [T.mode, T.modes[o.m] || o.m], [T.type, o.t], [T.scanned, o.d ? new Intl.DateTimeFormat(ar ? "ar" : "en", { dateStyle: "long", timeStyle: "short" }).format(new Date(o.d)) : ""],
        [T.engine, o.e ? `Sentinel ${o.e}` : "", true]]));
      const fp = fpBlock(o.h); if (fp) s1.append(fp);
      const s2 = sec(T.s[4]);
      const scale = el("div", `scale t-${tone}`); const mk = el("i", "mk"); mk.style.insetInlineStart = `${o.s}%`; scale.append(el("span", "z0"), el("span", "z1"), el("span", "z2"), mk);
      s2.append(kvs([[T.score, `${o.s} / 100`], [T.band, o.s >= 50 ? T.bands[2] : o.s > 0 ? T.bands[1] : T.bands[0]]]), scale, el("p", "note", T.scoreNote));
      const s3 = sec(T.shTop);
      if (!o.f || !o.f.length) s3.append(el("p", "", T.none));
      else {
        const tb = el("table"); const thead = el("thead"); const trh = el("tr");
        [T.sev, T.finding, T.contrib, T.source].forEach((h) => { const th = el("th", "", h); th.scope = "col"; trh.append(th); });
        thead.append(trh); tb.append(thead);
        const tbody = el("tbody");
        o.f.forEach(([title, sev, w, cat]) => {
          const tr = el("tr", `s-${sev}`);
          [T.sevs[sev] || sev, title, w ? `+${w}` : "–", T.cats[String(cat).toLowerCase()] || String(cat).replace(/_/g, " ")].forEach((v, i) => {
            const td = el(i === 1 ? "th" : "td", i === 0 ? "sev" : i === 2 ? "num" : "", String(v)); td.dir = "auto"; if (i === 1) td.scope = "row"; tr.append(td);
          });
          tbody.append(tr);
        });
        tb.append(tbody); const wrap = el("div", "table-wrap"); wrap.append(tb); s3.append(wrap);
      }
      const sx = extTable((o.x || []).map(([name, chip, m, t, label]) => ({ name, chip, malicious: m, engines_total: t, label })), false);
      if (sx) s3.append(el("h3", "", EXT.h), sx, el("p", "note", EXT.note));
      if (o.y && o.y.length) { s3.append(el("h3", "", T.shRules)); const ul = el("ul"); o.y.forEach((y) => { const li = el("li"); const b = el("bdi", "mono", y); b.dir = "ltr"; li.append(b); ul.append(li); }); s3.append(ul); }
      const s4 = sec(T.qrTitle);
      s4.append(el("p", "lead", T.shVerify));
      const cta = el("a", "cta", T.shScan); cta.href = "/#/scan"; s4.append(cta);
      const q = qrBlock(location.href); if (q) s4.append(q);
      const s5 = sec(T.s[9]); const ul = el("ul"); T.disclaimer.forEach((x) => ul.append(el("li", "", x))); s5.append(ul);
      const foot = el("footer", "foot"); foot.append(document.createTextNode("CyberScan · " + T.shTitle)); doc.append(foot);
    })();
    return;
  }
  if (!data || !data.result) {
    // nothing to print: say how to get the report, without a Print button
    $("bar").hidden = true;
    $("loading").textContent = T.missing;
    $("loading").classList.add("missing");
    return;
  }
  const r = data.result, finds = data.findings || [];
  const view = data.view || {};
  // the page's own score and verdict (the scan page worked them out); older reports fall back to the result
  const ds = r.detection_summary || {};
  const score = view.score != null ? view.score : Math.max(0, Math.min(100, Math.round(Number(ds.final_score != null ? ds.final_score : r.combined_score) || 0)));
  let cls = view.cls || ds.classification || r.classification || "UNKNOWN";
  if (!view.cls && cls !== "KNOWN_MALWARE" && cls !== "UNKNOWN" && cls !== "EMPTY") cls = score >= 50 ? "SUSPICIOUS" : score > 0 ? "REVIEW" : "NO_INDICATORS_OBSERVED";
  const mode = view.mode || (String(r.mode || "").toLowerCase() === "url" ? "url" : String(r.mode || "").toLowerCase() === "text" ? "text" : "file");
  const tone = cls === "SUSPICIOUS" || cls === "KNOWN_MALWARE" ? "bad" : cls === "REVIEW" ? "warn" : cls === "NO_INDICATORS_OBSERVED" ? "ok" : "neutral";
  const fmtDate = (d) => new Intl.DateTimeFormat(ar ? "ar" : "en", { dateStyle: "long", timeStyle: "medium" }).format(d);
  const scannedAt = view.scanned || r.timestamp || r.scanned_at || null;
  const reportId = (r.record_id || (r.sha256 || "").slice(0, 16) || "local") + "-" + new Date(data.generated).getTime().toString(36);
  // a value that reads left to right (an ID, a hash, a link) sits in its own isolated run, aligned with the rest of the column
  const ltr = (v) => { const b = el("bdi", "mono", String(v)); b.dir = "ltr"; return b; };
  const kv = (rows) => {
    const dl = el("dl", "kv");
    rows.filter(([, v]) => v != null && v !== "").forEach(([k, v, mono]) => {
      dl.append(el("dt", "", k));
      const d = el("dd");
      // the value is isolated (its own direction) while the column keeps the page's alignment
      if (mono) d.append(ltr(v)); else { const b = el("bdi", "", String(v)); b.dir = "auto"; d.append(b); }
      dl.append(d);
    });
    return dl;
  };
  let n = 0;
  const section = (title) => { const s = el("section", "sec"); s.append(el("h2", "", `${++n}. ${title}`)); doc.append(s); return s; };
  doc.replaceChildren();

  // 1. branding: the product, and the site it came from when it isn't this computer
  const head = el("header", "head");
  const brand = el("div", "brand"); const bl = el("span", "brand-l"); bl.append(logo(), el("b", "", "CyberScan")); brand.append(bl);
  if (view.host) brand.append(ltr(view.host));
  head.append(brand, el("h1", "", T.title), el("p", `verdict t-${tone}`, `${T.cls[cls] || cls} · ${score}/100`));
  doc.append(head);
  // 2-3. identification and target
  section(T.s[0]).append(kv([[T.id, reportId, true], [T.scanned, scannedAt ? fmtDate(new Date(scannedAt)) : ""], [T.generated, fmtDate(new Date(data.generated))],
    [T.engine, r.detection_engine ? `Sentinel ${r.detection_engine.version || ""}`.trim() : "CyberScan", true]]));
  const name = view.target || (mode === "url" ? String(r.target || "") : String(r.target || "").split(/[\\/]/).filter(Boolean).pop() || r.target);
  section(T.s[1]).append(kv([[T.target, name, mode === "url"], [T.mode, T.modes[mode]], [T.type, mode === "file" ? view.type : ""],
    [T.size, mode === "file" && r.size ? `${Number(r.size).toLocaleString(ar ? "ar" : "en")} B` : ""]]));
  if (mode === "file") { const fp = fpBlock(r.sha256); if (fp) doc.lastElementChild.append(fp); }
  // 4. executive summary
  const ex = section(T.s[2]);
  const counts = {}; finds.forEach((f) => { counts[f.sev] = (counts[f.sev] || 0) + 1; });
  ex.append(el("p", "lead", `${T.cls[cls] || cls}. ${(T.recos[cls] || T.recos.UNKNOWN)[0]}`));
  ex.append(el("p", "", ["critical", "high", "medium", "low", "info"].filter((k) => counts[k]).map((k) => `${T.sevs[k]}: ${counts[k]}`).join(" · ") || T.none));
  // 5. classification
  const cl = section(T.s[3]);
  cl.append(kv([[T.verdict, T.cls[cls] || cls], [T.status, (r.detection_status && r.detection_status !== "complete") ? T.partial : T.complete]]));
  // 6. risk assessment
  const rk = section(T.s[4]);
  const scale = el("div", `scale t-${tone}`); const mk = el("i", "mk"); mk.style.insetInlineStart = `${score}%`; scale.append(el("span", "z0"), el("span", "z1"), el("span", "z2"), mk);
  rk.append(kv([[T.score, `${score} / 100`], [T.band, score >= 50 ? T.bands[2] : score > 0 ? T.bands[1] : T.bands[0]]]), scale, el("p", "note", T.scoreNote));
  const pred = r.prediction || {}, cs = pred.class_scores || {};
  const hasModel = pred.status && !/untrained|unavailable|unapproved|missing|disabled/i.test(String(pred.status)) && Object.keys(cs).length;
  rk.append(el("h3", "", T.model), el("p", "", hasModel ? Object.entries(cs).map(([k, v]) => `${k}: ${Number(v).toFixed(1)}%`).join(" · ") : T.modelNone));
  if (hasModel) rk.append(el("p", "note", T.modelNote));
  // 7. detection evidence: each row says which check found it
  const sourceOf = (f) => f.where || T.cats[String(f.cat || "").toLowerCase()] || String(f.cat || "").replace(/_/g, " ") || "–";
  const ev = section(T.s[5]);
  if (!finds.length) ev.append(el("p", "", T.none));
  else {
    const wrap = el("div", "table-wrap");
    const tb = el("table"); tb.append(el("caption", "", T.evCaption));
    const thead = el("thead"); const trh = el("tr");
    [T.sev, T.finding, T.detail, T.source, T.contrib].forEach((h) => { const th = el("th", "", h); th.scope = "col"; trh.append(th); });
    thead.append(trh); tb.append(thead);
    const tbody = el("tbody");
    finds.forEach((f) => {
      const tr = el("tr", `s-${f.sev}`);
      const cells = [T.sevs[f.sev] || f.sev, f.title + (f.count > 1 ? ` ×${f.count}` : ""), f.text && f.text.trim() !== String(f.title).trim() ? f.text : "", sourceOf(f), f.contrib ? `+${f.contrib}` : "–"];
      cells.forEach((v, i) => {
        const td = el(i === 1 ? "th" : "td", i === 0 ? "sev" : i === 4 ? "num" : "", String(v || ""));
        if (i === 1) td.scope = "row";
        td.dir = "auto";
        tr.append(td);
      });
      tbody.append(tr);
    });
    tb.append(tbody); wrap.append(tb); ev.append(wrap);
  }
  const xt = extTable(r.external && r.external.rows, true);
  if (xt) ev.append(el("h3", "", EXT.h), xt, el("p", "note", EXT.note));
  // 8. technical findings
  const te = section(T.s[6]);
  const en = r.entropy || {};
  if (mode === "file" && en.mean != null) te.append(el("h3", "", T.entropy), el("p", "", `${T.mean} ${Number(en.mean).toFixed(2)} · ${T.peak} ${Number(en.peak).toFixed(2)} · ${T.jumps} ${en.anomalies}`));
  if (r.pe) te.append(el("h3", "", T.pe), kv([[T.peKeys.machine, r.pe.machine, true], [T.peKeys.subsystem, r.pe.subsystem, true], [T.peKeys.imports, r.pe.import_count],
    [T.peKeys.suspicious, (r.pe.suspicious_imports || []).join(", "), true], [T.peKeys.sections, (r.pe.sections || []).map((s) => `${s.name} (${Number(s.entropy).toFixed(2)})`).join(", "), true]]));
  const mitre = view.mitre || (r.mitre || []).filter((m) => m && m.id && !/^n\/?a$/i.test(String(m.id))).map((m) => [m.id, m.name]);
  if (mitre.length) { te.append(el("h3", "", T.mitre)); const ul = el("ul"); mitre.forEach(([id, nm]) => { const li = el("li"); li.append(ltr(id), document.createTextNode(` · ${nm || ""}`)); ul.append(li); }); te.append(ul); }
  const engines = view.engines || Object.entries(r.engines || {});
  if (engines.length) te.append(el("h3", "", T.engines), kv(engines));
  // 9. recommended actions
  const rc = section(T.s[7]); const ol = el("ol"); (T.recos[cls] || T.recos.UNKNOWN).forEach((x) => ol.append(el("li", "", x))); rc.append(ol);
  // 10. metadata: the duration, how the score was put together, and how many checks agreed
  const kinds = new Set(finds.map((f) => String(f.cat || "").toLowerCase()).filter(Boolean));
  const agree = kinds.size >= 2 ? fill(T.agreeMany, { n: kinds.size }) : kinds.size === 1 ? T.agreeOne : T.agreeNone;
  const secs = view.elapsed != null ? view.elapsed : (r.elapsed != null ? Number(r.elapsed) : null);
  section(T.s[8]).append(kv([[T.elapsed, secs != null ? fill(T.seconds, { s: Number(secs).toFixed(2) }) : ""], [T.finalScore, `${score} / 100`],
    [T.staticScore, r.heuristic_score != null ? `${r.heuristic_score} / 100` : ""], [T.contentScore, ds.content_score != null ? `${ds.content_score} / 100` : ""], [T.agree, agree]]));
  // 11. limits
  const li = section(T.s[9]); const ul = el("ul"); T.disclaimer.forEach((x) => ul.append(el("li", "", x))); li.append(ul);
  const limits = view.limits != null ? view.limits : (ar ? "" : r.limitations);
  if (limits) { const p = el("p", "note", limits); p.dir = "auto"; li.append(p); }
  // the verify code: a QR that opens the shareable, read-only summary of this result (no file name)
  if (window.CSShare && window.CSQR) {
    const vs = section(T.qrTitle);
    const sv = view.verify || {};
    window.CSShare.url({ c: cls, s: score, m: mode, h: mode === "file" ? r.sha256 : "", t: mode === "file" ? (view.type || "") : "",
      e: (r.detection_engine && r.detection_engine.version) || "", d: scannedAt || data.generated,
      f: finds.slice(0, 6).map((f) => [sv.titles && sv.titles[f.title] || f.title, f.sev, f.contrib, f.cat]),
      y: (r.yara || []).map((y) => y.rule_name), x: window.CSShare.externalOf ? window.CSShare.externalOf(r) : undefined }).then((link) => { const q = qrBlock(link); if (q) vs.append(q); }).catch(() => vs.remove());
  }
  const foot = el("footer", "foot"); foot.append(document.createTextNode("CyberScan · "), ltr(reportId)); doc.append(foot);
})();
