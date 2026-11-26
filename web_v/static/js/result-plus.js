/* The result, explained and passed on (scan page; listens to "cs:rc-built" from js/scan-center.js).
 *
 *   - "Why this result?": every weighted piece of evidence → its weight → the final score, drawn as a
 *     flow (bars and curves into the score), with a "Simple (explain like I'm 10)" / "Expert" switch
 *     over the same result;
 *   - "Where each detection comes from": the rule (and its rule set, author, licence, reference), the
 *     hash databases asked, the link lists, the ATT&CK technique, with a link to a description when one
 *     exists; and "Wrong result?", which prepares an email the person sends from their own mail app
 *     (hash, verdict, rule ids: never the file), only after they agree;
 *   - "Share": a link to a read-only summary in report.html#r=… (js/share-code.js), with a QR code; the
 *     file name only if they tick it; nothing is uploaded or stored;
 *   - "Ask about this result": opens Ask the AI with the result's summary (js/ask.js, CSAsk);
 *   - Bit, a quiet guide: a tiny robot beside the summary with one plain-language line; dismissible,
 *     still under reduced motion.
 * All result text goes in as text, never as HTML. */
(function () {
  "use strict";
  const CS = window.CS;
  if (!CS || !document.getElementById("form")) return;
  const { el, toast } = CS;
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");
  const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage off */ } } };
  const sess = { get(k) { try { return sessionStorage.getItem(k); } catch { return null; } }, set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage off */ } } };
  const CONTACT = "mahdi-alhajji@zohomail.sa";   // the developer's public address (the site's About section)

  const STR = {
    en: {
      whyTitle: "Why this result?", whySub: "Each piece of evidence, how much it weighs, and how they make the score.",
      simple: "Simple", simpleHint: "explain like I'm 10", expert: "Expert", modeLabel: "Explanation level",
      total: "Total weight", capped: "capped at 100", strongest: "Strongest single piece", final: "Final score",
      noWeight: "{n} more signal(s) were noted but add no weight.", noneWeighted: "Nothing added weight to the score.",
      w: ["counts a little", "counts some", "counts a lot"],
      rule: "Score rule", sevLabel: "Severity", catLabel: "Category", agree: "Evidence agreement", host: "Static checks score", content: "Content inspection score", engines: "Found by",
      kid: {
        SUSPICIOUS: "Think of a parcel that's ticking and has no return address. Nobody opened it, but several clues say: don't open this one.",
        KNOWN_MALWARE: "This is like a photo on a \"wanted\" poster: this exact file has already been caught doing harm somewhere else.",
        REVIEW: "Something about it is a bit odd, like a letter with a spelling mistake in the bank's name. It might be fine, but look closer first.",
        NO_INDICATORS_OBSERVED: "We looked at it carefully, like a detective with a magnifying glass, and found no clues of trouble. That's good, but not a promise.",
        UNKNOWN: "We couldn't finish looking, like a book with missing pages. Better to check again before trusting it.",
        EMPTY: "The box is empty: there was nothing inside to check.",
      },
      kidCat: { yara: "It matches the description of a known trick, like a fingerprint on file.", heuristic: "It shows a warning sign that careful checkers look for.",
        structural: "Its shape looks odd for this kind of file.", content: "Something written inside looks like a trick.", tradecraft: "It does something attackers often do.",
        url: "The link looks like it's pretending to be somewhere else.", phishing: "It looks like bait to make you type a password.", hash: "This exact file is on a list of known bad files.",
        osint: "Other security services have reported it.", privacy: "It holds private information, like names or phone numbers.", secrets: "It contains secret keys or passwords.",
        archive: "It's a box of files; we looked inside.", model: "A computer that learned from examples thought it looked risky.", other: "It's a clue worth noticing." },
      srcTitle: "Where each detection comes from", srcSub: "The rules, lists and databases behind the findings, with a description where one exists.",
      srcRule: "Rule", srcSet: "Rule set", srcBy: "Author", srcLic: "Licence", srcRef: "Description", srcHashes: "Known-malware hash databases", srcLists: "Link lists", srcExternal: "External intelligence",
      srcMitre: "MITRE ATT&CK", srcNone: "No rule, list or database matched: the findings come from CyberScan's own structure and content checks.",
      hashSt: { found: "listed", matched: "listed", not_found: "not listed", no_match: "not listed", no_key: "not asked (no key)", unavailable: "unavailable", disabled: "off", timeout: "timed out", error: "error" },
      wrong: "Wrong result?", wrongTitle: "Report a wrong result", wrongBody: "This prepares an email to the developer in your own mail app. It contains only what's below: no file, no file name, nothing else. You can read and edit it before sending.",
      wrongConsent: "I agree to send these details by email.", wrongGo: "Prepare the email", wrongCopy: "Copy the details", wrongCancel: "Cancel",
      wrongKind: "I think it's", wrongFalsePos: "safe (a false alarm)", wrongFalseNeg: "harmful (it was missed)", wrongSubject: "CyberScan: possible wrong result",
      share: "Share", shareTitle: "Share this result", shareBody: "Creates a link to a read-only summary. The file isn't uploaded and no server keeps the result: the summary travels inside the link.",
      shareName: "Include the file name", shareMake: "Create the link", shareCopy: "Copy", shareCopied: "Link copied", shareNative: "Share…",
      shareHas: "The link holds: verdict, score, SHA-256, top findings, rule names, engine version and date{n}.", shareHasName: ", and the file name",
      shareQr: "Scan to open on a phone", shareClose: "Close",
      ask: "Ask about this result", askLabel: "{v}, {s}/100",
      bitDismiss: "Hide Bit's tip", bitName: "Bit",
      bit: {
        SUSPICIOUS: "I'd leave this one closed. Several warning signs point the same way.",
        KNOWN_MALWARE: "This exact file is on a known-malware list. Delete it; don't open it.",
        REVIEW: "Probably worth a second look. Read the top finding before you open it.",
        NO_INDICATORS_OBSERVED: "Nothing worrying here. Still, only open files from people you trust.",
        UNKNOWN: "The check didn't finish. Try scanning it again.",
        EMPTY: "This file is empty, so there was nothing to check.",
      },
      bitLink: { SUSPICIOUS: "This link shows warning signs. Don't open it or type anything there.", REVIEW: "Look closely at this link's address before you open it.", NO_INDICATORS_OBSERVED: "No warning signs on this link. Still check the address before you sign in." },
      sev: { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" },
    },
    ar: {
      whyTitle: "لماذا هذه النتيجة؟", whySub: "كل دليل، وكم يزن، وكيف تتكوّن الدرجة منها.",
      simple: "بسيط", simpleHint: "اشرح لي كأنني في العاشرة", expert: "خبير", modeLabel: "مستوى الشرح",
      total: "مجموع الأوزان", capped: "بحد أقصى 100", strongest: "أقوى دليل منفرد", final: "الدرجة النهائية",
      noWeight: "رُصدت {n} إشارة أخرى لكنها لا تضيف وزنًا.", noneWeighted: "لم يُضف أي دليل وزنًا إلى الدرجة.",
      w: ["يزن قليلًا", "يزن بعض الشيء", "يزن كثيرًا"],
      rule: "قاعدة الدرجة", sevLabel: "الخطورة", catLabel: "الفئة", agree: "توافق الأدلة", host: "درجة الفحوص الساكنة", content: "درجة فحص المحتوى", engines: "رصده",
      kid: {
        SUSPICIOUS: "تخيّل طردًا يصدر صوت تكتكة وليس عليه عنوان مرسل. لم يفتحه أحد، لكن عدة أدلة تقول: لا تفتح هذا.",
        KNOWN_MALWARE: "هذا مثل صورة على ملصق «مطلوب»: هذا الملف بعينه سبق أن ضُبط وهو يؤذي في مكان آخر.",
        REVIEW: "فيه شيء غريب قليلًا، مثل رسالة فيها خطأ إملائي في اسم البنك. قد يكون سليمًا، لكن انظر عن قرب أولًا.",
        NO_INDICATORS_OBSERVED: "فحصناه بعناية مثل محقق يحمل عدسة مكبّرة، ولم نجد أدلة على مشكلة. هذا جيد، لكنه ليس وعدًا.",
        UNKNOWN: "لم نكمل الفحص، مثل كتاب تنقصه صفحات. الأفضل أن تعيد الفحص قبل أن تثق به.",
        EMPTY: "الصندوق فارغ: لم يكن بداخله شيء يُفحص.",
      },
      kidCat: { yara: "يطابق وصف حيلة معروفة، مثل بصمة محفوظة في السجل.", heuristic: "تظهر فيه علامة تحذير يبحث عنها الفاحصون الحذرون.",
        structural: "شكله غريب بالنسبة لهذا النوع من الملفات.", content: "شيء مكتوب بداخله يبدو كحيلة.", tradecraft: "يفعل شيئًا يفعله المهاجمون عادةً.",
        url: "يبدو الرابط كأنه يتظاهر بأنه مكان آخر.", phishing: "يبدو كطُعم ليجعلك تكتب كلمة مرورك.", hash: "هذا الملف بعينه موجود في قائمة ملفات ضارة معروفة.",
        osint: "أبلغت عنه خدمات أمنية أخرى.", privacy: "يحتوي معلومات خاصة مثل الأسماء أو أرقام الهواتف.", secrets: "يحتوي مفاتيح سرية أو كلمات مرور.",
        archive: "إنه صندوق ملفات، وقد نظرنا بداخله.", model: "حاسوب تعلّم من الأمثلة رأى أنه يبدو خطرًا.", other: "إنه دليل يستحق الانتباه." },
      srcTitle: "من أين جاء كل كشف", srcSub: "القواعد والقوائم وقواعد البيانات وراء النتائج، مع وصف حيث يوجد.",
      srcRule: "القاعدة", srcSet: "مجموعة القواعد", srcBy: "المؤلف", srcLic: "الترخيص", srcRef: "الوصف", srcHashes: "قواعد بصمات البرامج الضارة المعروفة", srcLists: "قوائم الروابط", srcExternal: "الاستخبارات الخارجية",
      srcMitre: "MITRE ATT&CK", srcNone: "لم تطابق أي قاعدة أو قائمة أو قاعدة بيانات: النتائج من فحوص CyberScan الخاصة للبنية والمحتوى.",
      hashSt: { found: "مُدرج", matched: "مُدرج", not_found: "غير مُدرج", no_match: "غير مُدرج", no_key: "لم يُسأل (لا مفتاح)", unavailable: "غير متاح", disabled: "متوقف", timeout: "انتهت المهلة", error: "خطأ" },
      wrong: "نتيجة خاطئة؟", wrongTitle: "أبلغ عن نتيجة خاطئة", wrongBody: "يُعدّ هذا رسالة بريد إلى المطوّر في تطبيق البريد لديك. لا تحتوي إلا ما يظهر أدناه: لا ملف ولا اسم ملف ولا شيء آخر. يمكنك قراءتها وتعديلها قبل الإرسال.",
      wrongConsent: "أوافق على إرسال هذه التفاصيل بالبريد.", wrongGo: "جهّز الرسالة", wrongCopy: "انسخ التفاصيل", wrongCancel: "إلغاء",
      wrongKind: "أظن أنه", wrongFalsePos: "سليم (إنذار كاذب)", wrongFalseNeg: "ضار (لم يُكشف)", wrongSubject: "CyberScan: نتيجة قد تكون خاطئة",
      share: "مشاركة", shareTitle: "شارك هذه النتيجة", shareBody: "يُنشئ رابطًا إلى ملخص للقراءة فقط. لا يُرفع الملف ولا يحفظ أي خادم النتيجة: الملخص ينتقل داخل الرابط.",
      shareName: "أدرج اسم الملف", shareMake: "أنشئ الرابط", shareCopy: "انسخ", shareCopied: "نُسخ الرابط", shareNative: "شارك…",
      shareHas: "يحتوي الرابط: الحكم والدرجة وبصمة SHA-256 وأبرز النتائج وأسماء القواعد وإصدار المحرك والتاريخ{n}.", shareHasName: "، واسم الملف",
      shareQr: "امسحه لفتحه على الهاتف", shareClose: "إغلاق",
      ask: "اسأل عن هذه النتيجة", askLabel: "{v}، {s}/100",
      bitDismiss: "أخفِ نصيحة Bit", bitName: "Bit",
      bit: {
        SUSPICIOUS: "لو كنت مكانك لما فتحته. عدة علامات تحذير تشير إلى الاتجاه نفسه.",
        KNOWN_MALWARE: "هذا الملف بعينه في قائمة البرامج الضارة المعروفة. احذفه ولا تفتحه.",
        REVIEW: "يستحق نظرة ثانية على الأرجح. اقرأ أبرز نتيجة قبل أن تفتحه.",
        NO_INDICATORS_OBSERVED: "لا شيء مقلق هنا. ومع ذلك، لا تفتح إلا ملفات ممن تثق بهم.",
        UNKNOWN: "لم يكتمل الفحص. جرّب فحصه مرة أخرى.",
        EMPTY: "هذا الملف فارغ، فلم يكن هناك ما يُفحص.",
      },
      bitLink: { SUSPICIOUS: "يظهر على هذا الرابط علامات تحذير. لا تفتحه ولا تكتب فيه شيئًا.", REVIEW: "انظر جيدًا في عنوان هذا الرابط قبل فتحه.", NO_INDICATORS_OBSERVED: "لا علامات تحذير على هذا الرابط. ومع ذلك تحقق من العنوان قبل تسجيل الدخول." },
      sev: { critical: "حرج", high: "مرتفع", medium: "متوسط", low: "منخفض", info: "معلومة" },
    },
  };
  const L = () => STR[CS.lang === "ar" ? "ar" : "en"];
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] != null ? o[k] : ""));
  const svgEl = (tag, attrs) => { const n = document.createElementNS("http://www.w3.org/2000/svg", tag); Object.entries(attrs || {}).forEach(([k, v]) => n.setAttribute(k, v)); return n; };
  const verdictName = (cls) => { const w = CS.verdictWords(cls); return w[1] || w[0] || cls; };
  const isHttp = (u) => /^https?:\/\//i.test(String(u || ""));

  /* ------------------------------------------------------------ the evidence: one list for every view */
  function evidenceOf(r, finds) {
    const ev = Array.isArray(r.evidence) ? r.evidence : [];
    return finds.map((f) => {
      const raw = ev.find((e) => CS.loc(e.evidence) === f.title || (f.cat && String(e.category) === String(f.cat) && Number(e.contribution) === Number(f.contrib))) || null;
      return { ...f, raw, engines: raw ? (raw.engines || []) : [], also: raw ? (raw.also || []) : [] };
    });
  }

  /* ------------------------------------------------------------ 1. why this result */
  let explainMode = store.get("cs-explain") === "expert" ? "expert" : "simple";
  // one switch for the whole result: technical ids and numbers (.x-only) show only in Expert mode
  document.documentElement.dataset.explain = explainMode;
  function whyCard(r, cls, items) {
    const l = L();
    const card = el("section", "card rp-why");
    const head = el("div", "rp-head");
    const ht = el("div"); ht.append(el("h3", "", l.whyTitle), el("p", "rc-note", l.whySub));
    const seg = el("div", "rp-seg"); seg.setAttribute("role", "group"); seg.setAttribute("aria-label", l.modeLabel);
    const body = el("div", "rp-why-body");
    [["simple", `${l.simple}`, l.simpleHint], ["expert", l.expert, ""]].forEach(([k, label, hint]) => {
      const b = el("button", "rp-seg-btn", label); b.type = "button"; b.dataset.k = k;
      if (hint) { b.title = hint; b.append(el("small", "", ` · ${hint}`)); }
      b.setAttribute("aria-pressed", String(explainMode === k));
      b.addEventListener("click", () => { explainMode = k; store.set("cs-explain", k); document.documentElement.dataset.explain = k; seg.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.k === k))); paint(); });
      seg.append(b);
    });
    head.append(ht, seg);
    card.append(head, body);
    const shown = CS.verdictOf(r);
    const weighted = items.filter((f) => f.contrib > 0).slice(0, 8);
    const quiet = items.length - weighted.length;
    const sum = weighted.reduce((a, f) => a + f.contrib, 0);
    const strongest = weighted.reduce((a, f) => Math.max(a, f.contrib), 0);
    function paint() {
      body.replaceChildren();
      body.dataset.mode = explainMode;
      if (explainMode === "simple") body.append(el("p", "rp-kid", l.kid[cls] || l.kid.UNKNOWN));
      // the flow: evidence → weight → score
      const flow = el("div", "rp-flow");
      const list = el("ol", "rp-ev");
      if (!weighted.length) list.append(el("li", "rp-ev-none", l.noneWeighted));
      weighted.forEach((f, i) => {
        const li = el("li", `rp-ev-row s-${f.sev}`); li.style.setProperty("--i", i);
        const btn = el("button", "rp-ev-btn"); btn.type = "button"; btn.setAttribute("aria-expanded", "false");
        const name = el("span", "rp-ev-name", f.title + (f.count > 1 ? ` ×${f.count}` : "")); name.dir = "auto";
        const bar = el("span", "rp-ev-bar"); const fillBar = el("i"); fillBar.style.width = `${Math.max(4, f.contrib)}%`; bar.append(fillBar);
        const wTxt = explainMode === "simple" ? l.w[f.contrib >= 45 ? 2 : f.contrib >= 20 ? 1 : 0] : `+${f.contrib}`;
        btn.append(name, bar, el("b", "rp-ev-w", wTxt));
        const more = el("div", "rp-ev-more"); more.hidden = true;
        if (explainMode === "simple") more.append(el("p", "", l.kidCat[String(f.cat || "").toLowerCase()] || l.kidCat.other));
        else {
          if (f.text && f.text.trim() !== f.title.trim()) { const p = el("p", "", f.text); p.dir = "auto"; more.append(p); }
          const dl = el("dl", "rp-kv");
          const add = (k, v) => { if (!v) return; dl.append(el("dt", "", k)); const d = el("dd", "", v); d.dir = "auto"; dl.append(d); };
          add(l.sevLabel, CS.sevWord(f.sev));
          add(l.engines, [...new Set([...(f.engines || []), ...(f.also || [])])].join(" · ") || f.where || "");
          add(l.catLabel, String(f.cat || "").replace(/_/g, " "));
          more.append(dl);
        }
        btn.addEventListener("click", () => { const open = more.hidden; more.hidden = !open; btn.setAttribute("aria-expanded", String(open)); li.classList.toggle("open", open); drawCurves(flow, list, node, curves, weighted); });
        btn.addEventListener("mouseenter", () => flow.classList.add("focus-" + i));
        btn.addEventListener("mouseleave", () => flow.classList.remove("focus-" + i));
        li.append(btn, more);
        list.append(li);
      });
      const node = el("div", "rp-score");
      node.append(el("small", "", l.final), el("b", "", String(shown.score)), el("span", "", "/100"));
      const curves = svgEl("svg", { class: "rp-curves", "aria-hidden": "true" });
      flow.append(list, curves, node);
      body.append(flow);
      // the arithmetic under the flow
      const math = el("div", "rp-math");
      const part = (k, v, cls2) => { const s = el("span", cls2 || ""); s.append(el("small", "", k), el("b", "", v)); return s; };
      math.append(part(l.total, `${sum}${sum > 100 ? ` → 100 (${l.capped})` : ""}`), part(l.strongest, `+${strongest}`), part(l.final, `${shown.score}/100`, "fin"));
      body.append(math);
      if (quiet > 0) body.append(el("p", "rc-note", fill(l.noWeight, { n: quiet })));
      if (explainMode === "expert") {
        const ds = r.detection_summary || {};
        const dl = el("dl", "rp-kv rp-expert");
        const add = (k, v, mono) => { if (v == null || v === "") return; dl.append(el("dt", "", k)); const d = el("dd", mono ? "mono" : "", String(v)); d.dir = mono ? "ltr" : "auto"; dl.append(d); };
        add(l.host, ds.host_score != null ? `${ds.host_score}/100` : (r.heuristic_score != null ? `${r.heuristic_score}/100` : ""));
        add(l.content, ds.content_score != null ? `${ds.content_score}/100` : "");
        add(l.agree, ds.evidence_agreement ? String(ds.evidence_agreement).replace(/-/g, " ") : "");
        add(l.rule, ds.score_rule || "", true);
        body.append(dl);
      }
      requestAnimationFrame(() => drawCurves(flow, list, node, curves, weighted));
    }
    paint();
    return card;
  }
  // curves from each evidence bar into the score, their width following the weight
  function drawCurves(flow, list, node, svg, weighted) {
    if (!flow.isConnected) return;
    const fr = flow.getBoundingClientRect();
    if (!fr.width || getComputedStyle(svg).display === "none") return;
    svg.setAttribute("viewBox", `0 0 ${fr.width} ${fr.height}`);
    svg.setAttribute("width", fr.width); svg.setAttribute("height", fr.height);
    svg.replaceChildren();
    const nr = node.getBoundingClientRect();
    const rtl = getComputedStyle(flow).direction === "rtl";
    const tx = (rtl ? nr.right : nr.left) - fr.left, ty = nr.top + nr.height / 2 - fr.top;
    [...list.querySelectorAll(".rp-ev-bar")].forEach((bar, i) => {
      const br = bar.getBoundingClientRect(), f = weighted[i];
      if (!f) return;
      const sx = (rtl ? br.left : br.right) - fr.left, sy = br.top + br.height / 2 - fr.top;
      const mx = (sx + tx) / 2;
      const p = svgEl("path", { d: `M${sx},${sy} C${mx},${sy} ${mx},${ty} ${tx},${ty}`, class: `rp-curve s-${f.sev} c-${i}`, "stroke-width": String(1 + f.contrib / 12) });
      svg.append(p);
      if (!reduced()) p.animate([{ strokeDashoffset: 400, strokeDasharray: "400" }, { strokeDashoffset: 0, strokeDasharray: "400" }], { duration: 900, delay: 120 + i * 80, easing: "cubic-bezier(.22,1,.36,1)", fill: "backwards" });
    });
  }

  /* ------------------------------------------------------------ 2. where each detection comes from */
  const mitreUrl = (id) => { const m = /^T(\d{4})(?:\.(\d{3}))?$/.exec(String(id)); return m ? `https://attack.mitre.org/techniques/T${m[1]}${m[2] ? `/${m[2]}` : ""}/` : ""; };
  function ruleSetUrl(source) {
    const s = String(source || "").toLowerCase();
    if (s.includes("forge")) return "https://yarahq.github.io/";
    if (s.includes("gitleaks")) return "https://github.com/gitleaks/gitleaks";
    return "";
  }
  function linkOrText(text, href) {
    if (!isHttp(href)) return el("span", "", text);
    const a = el("a", "", text); a.href = href; a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
  }
  function sourcesCard(r, cls, items) {
    const l = L();
    const card = el("section", "card rp-src");
    const head = el("div", "rp-head");
    const ht = el("div"); ht.append(el("h3", "", l.srcTitle), el("p", "rc-note", l.srcSub));
    const wrongBtn = el("button", "ghost small rp-wrong", l.wrong); wrongBtn.type = "button";
    wrongBtn.addEventListener("click", () => wrongDialog(r, cls, items));
    head.append(ht, wrongBtn);
    card.append(head);
    const intel = r.intel || {};
    const rules = Array.isArray(intel.rules) ? intel.rules : (r.yara || []).map((y) => ({ rule: y.rule_name, source: "CyberScan rules", description: y.description }));
    let any = false;
    if (rules.length) {
      any = true;
      const ul = el("ul", "rp-src-list");
      rules.slice(0, 20).forEach((x) => {
        const li = el("li", "rp-src-item");
        const top = el("div", "rp-src-top");
        const nm = el("code", "", x.rule); nm.dir = "ltr";
        top.append(el("span", "rp-src-kind", l.srcRule), nm);
        li.append(top);
        if (x.description) { const p = el("p", "", x.description); p.dir = "auto"; li.append(p); }
        const meta = el("div", "rp-src-meta");
        const setLink = linkOrText(x.source || "CyberScan rules", ruleSetUrl(x.source));
        const m1 = el("span"); m1.append(el("small", "", `${l.srcSet}: `), setLink); meta.append(m1);
        if (x.author) { const m = el("span"); m.append(el("small", "", `${l.srcBy}: `), document.createTextNode(x.author)); meta.append(m); }
        if (x.license) { const m = el("span"); m.append(el("small", "", `${l.srcLic}: `), document.createTextNode(x.license)); meta.append(m); }
        const ref = String(x.reference || "").split(/[\s,]+/).find(isHttp);
        if (ref) { const m = el("span"); m.append(el("small", "", `${l.srcRef}: `), linkOrText(new URL(ref).host, ref)); meta.append(m); }
        li.append(meta);
        ul.append(li);
      });
      card.append(ul);
    }
    // link lists: findings that came from URLhaus / Phishing.Database / look-alike checks
    const listHits = items.filter((f) => /url|phishing/i.test(String(f.cat)) && f.contrib > 0);
    if (listHits.length) {
      any = true;
      const box = el("div", "rp-src-group"); box.append(el("h4", "", l.srcLists));
      const ul = el("ul", "rp-src-flat");
      listHits.slice(0, 8).forEach((f) => {
        const li = el("li"); const t = el("span", "", f.title); t.dir = "auto"; li.append(t);
        const txt = `${f.title} ${f.text}`;
        const href = /urlhaus/i.test(txt) ? "https://urlhaus.abuse.ch/" : /phishing\.database|phishing database/i.test(txt) ? "https://github.com/Phishing-Database/Phishing.Database" : "";
        if (href) { li.append(document.createTextNode(" · ")); li.append(linkOrText(new URL(href).host, href)); }
        ul.append(li);
      });
      box.append(ul); card.append(box);
    }
    const hs = intel.hash_sources || {};
    if (Object.keys(hs).length && CS.modeOf(r) === "file") {
      any = true;
      const box = el("div", "rp-src-group"); box.append(el("h4", "", l.srcHashes));
      const ul = el("ul", "rp-src-flat");
      Object.entries(hs).forEach(([name, st]) => {
        const status = String((st && st.status) || "").toLowerCase();
        const li = el("li", /found|match/.test(status) && !/not|no_/.test(status) ? "hit" : "");
        li.append(el("b", "", name), document.createTextNode(` · ${l.hashSt[status] || status.replace(/_/g, " ")}`));
        if (st && st.entries) li.append(el("small", "", ` (${Number(st.entries).toLocaleString(CS.lang)})`));
        if (/malwarebazaar/i.test(name) && li.className === "hit" && r.sha256) { li.append(document.createTextNode(" · ")); li.append(linkOrText("bazaar.abuse.ch", `https://bazaar.abuse.ch/sample/${r.sha256}/`)); }
        ul.append(li);
      });
      box.append(ul); card.append(box);
    }
    // external intelligence (VirusTotal and the others): the services that answered, with their public report
    const ext = ((r.external && r.external.rows) || []).filter((x) => !["off", "not_configured"].includes(x.chip));
    if (ext.length) {
      any = true;
      const box = el("div", "rp-src-group"); box.append(el("h4", "", l.srcExternal));
      const ul = el("ul", "rp-src-flat");
      ext.forEach((x) => {
        const li = el("li", x.chip === "bad" || x.chip === "warn" ? "hit" : "");
        li.append(el("b", "", x.name), document.createTextNode(` · ${window.CSExternal ? window.CSExternal.lineOf(x) : String(x.status || "").replace(/_/g, " ")}`));
        if (x.link && /^https:\/\//.test(x.link)) { li.append(document.createTextNode(" · ")); li.append(linkOrText(new URL(x.link).host, x.link)); }
        ul.append(li);
      });
      box.append(ul); card.append(box);
    }
    const mitre = CS.mitreOf(r);
    if (mitre.length) {
      any = true;
      const box = el("div", "rp-src-group"); box.append(el("h4", "", l.srcMitre));
      const ul = el("ul", "rp-src-flat");
      mitre.slice(0, 10).forEach((m) => { const li = el("li"); li.append(linkOrText(m.id, mitreUrl(m.id)), document.createTextNode(m.name ? ` · ${m.name}` : "")); ul.append(li); });
      box.append(ul); card.append(box);
    }
    if (!any) card.append(el("p", "rc-none", l.srcNone));
    return card;
  }

  /* "Wrong result?": an email the person sends themselves, after they agree */
  function modal(title) {
    const back = el("div", "rp-modal-back");
    const box = el("div", "rp-modal"); box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true");
    const h = el("h3", "", title); h.id = `rp-m-${Date.now()}`; box.setAttribute("aria-labelledby", h.id);
    box.append(h); back.append(box); document.body.append(back);
    const opener = document.activeElement;
    const close = () => { back.remove(); document.removeEventListener("keydown", onKey, true); if (opener && opener.focus) opener.focus({ preventScroll: true }); };
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); close(); }
      if (e.key === "Tab") {   // keep focus inside the dialog
        const f = [...box.querySelectorAll("button, input, a[href], textarea, select")].filter((n) => !n.disabled && n.offsetParent !== null);
        if (!f.length) return;
        if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
        else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
      }
    };
    document.addEventListener("keydown", onKey, true);
    back.addEventListener("click", (e) => { if (e.target === back) close(); });
    return { box, close };
  }
  function wrongDialog(r, cls, items) {
    const l = L();
    const { box, close } = modal(l.wrongTitle);
    box.append(el("p", "", l.wrongBody));
    const kind = el("fieldset", "rp-kind"); kind.append(el("legend", "", l.wrongKind));
    const radios = [["fp", l.wrongFalsePos], ["fn", l.wrongFalseNeg]].map(([v, label], i) => {
      const lab = el("label"); const inp = el("input"); inp.type = "radio"; inp.name = "rp-kind"; inp.value = v;
      inp.checked = i === (cls === "NO_INDICATORS_OBSERVED" ? 1 : 0); lab.append(inp, document.createTextNode(` ${label}`)); kind.append(lab); return inp;
    });
    box.append(kind);
    const rules = [...new Set(((r.intel && r.intel.rules) || []).map((x) => x.rule).concat((r.yara || []).map((y) => y.rule_name)).filter(Boolean))];
    const v = CS.verdictOf(r);
    const details = () => {
      const k = radios.find((x) => x.checked);
      return [
        `${l.wrongKind}: ${k && k.value === "fn" ? l.wrongFalseNeg : l.wrongFalsePos}`,
        `Verdict: ${v.cls} (${v.score}/100)`,
        `Mode: ${CS.modeOf(r)}`,
        r.sha256 && CS.modeOf(r) === "file" ? `SHA-256: ${r.sha256}` : "",
        rules.length ? `Rules: ${rules.slice(0, 15).join(", ")}` : "",
        `Findings: ${items.filter((f) => f.contrib > 0).slice(0, 8).map((f) => `${CS.loc(f.raw ? f.raw.evidence : f.title)} (+${f.contrib})`).join("; ") || "none"}`,
        `Engine: ${(r.detection_engine && r.detection_engine.version) || "?"}`,
        `Scanned: ${CS.scanTime(r) || new Date().toISOString()}`,
      ].filter(Boolean).join("\n");
    };
    const pre = el("pre", "rp-pre"); pre.dir = "ltr";
    const sync = () => { pre.textContent = details(); };
    radios.forEach((x) => x.addEventListener("change", sync)); sync();
    box.append(pre);
    const consent = el("label", "rp-consent"); const cb = el("input"); cb.type = "checkbox"; consent.append(cb, document.createTextNode(` ${l.wrongConsent}`));
    box.append(consent);
    const row = el("div", "rp-modal-actions");
    const go = el("button", "primary", l.wrongGo); go.type = "button"; go.disabled = true;
    const copy = el("button", "ghost", l.wrongCopy); copy.type = "button"; copy.disabled = true;
    const cancel = el("button", "ghost", l.wrongCancel); cancel.type = "button";
    cb.addEventListener("change", () => { go.disabled = copy.disabled = !cb.checked; });
    go.addEventListener("click", () => {
      if (!cb.checked) return;
      location.href = `mailto:${CONTACT}?subject=${encodeURIComponent(l.wrongSubject)}&body=${encodeURIComponent(details() + "\n\n")}`;
      close();
    });
    copy.addEventListener("click", async () => { if (!cb.checked) return; try { await navigator.clipboard.writeText(details()); toast(CS.t("copied")); } catch { /* clipboard off */ } });
    cancel.addEventListener("click", close);
    row.append(go, copy, cancel); box.append(row);
    cb.focus();
  }

  /* ------------------------------------------------------------ 3. share */
  function shareDialog(r) {
    const l = L();
    const { box, close } = modal(l.shareTitle);
    box.append(el("p", "", l.shareBody));
    const opt = el("label", "rp-consent"); const cb = el("input"); cb.type = "checkbox"; opt.append(cb, document.createTextNode(` ${l.shareName}`));
    const has = el("p", "rc-note");
    const syncHas = () => { has.textContent = fill(l.shareHas, { n: cb.checked ? l.shareHasName : "" }); out.hidden = true; };
    const out = el("div", "rp-share-out"); out.hidden = true;
    cb.addEventListener("change", syncHas);
    const row = el("div", "rp-modal-actions");
    const make = el("button", "primary", l.shareMake); make.type = "button";
    const closeBtn = el("button", "ghost", l.shareClose); closeBtn.type = "button"; closeBtn.addEventListener("click", close);
    row.append(make, closeBtn);
    box.append(opt, has, row, out);
    syncHas();
    make.addEventListener("click", async () => {
      make.disabled = true;
      try {
        const link = await window.CSShare.url(window.CSShare.fromResult(r, cb.checked));
        out.replaceChildren();
        const field = el("input", "field rp-share-link"); field.readOnly = true; field.value = link; field.dir = "ltr";
        field.setAttribute("aria-label", l.shareTitle);
        const act = el("div", "rp-share-act");
        const cp = el("button", "ghost small", l.shareCopy); cp.type = "button";
        cp.addEventListener("click", async () => { try { await navigator.clipboard.writeText(link); toast(l.shareCopied); } catch { field.select(); } });
        act.append(cp);
        if (navigator.share) { const sh = el("button", "ghost small", l.shareNative); sh.type = "button"; sh.addEventListener("click", () => navigator.share({ title: "CyberScan", url: link }).catch(() => {})); act.append(sh); }
        const qr = window.CSQR && window.CSQR.svg(link, { label: l.shareQr });
        const qrBox = el("figure", "rp-qr");
        if (qr) { qrBox.append(qr, el("figcaption", "", l.shareQr)); }
        out.append(field, act, qrBox);
        out.hidden = false;
        field.focus(); field.select();
      } catch (e) { toast(String((e && e.message) || e)); }
      make.disabled = false;
    });
    cb.focus();
  }

  /* ------------------------------------------------------------ 4. ask about this result */
  function askContext(r, items) {
    const v = CS.verdictOf(r);
    const mode = CS.modeOf(r);
    return {
      verdict: v.cls, score: v.score, mode,
      type: mode === "file" ? ((r.content_analysis && r.content_analysis.file_type) || "") : "",
      findings: items.slice(0, 8).map((f) => ({ title: f.title, severity: f.sev, weight: f.contrib, source: f.where || String(f.cat || "") })),
    };
  }

  /* ------------------------------------------------------------ 5. Bit, a quiet guide */
  const BOT = '<svg viewBox="0 0 40 40" aria-hidden="true"><path class="mx-ant" d="M20 9V4"/><circle class="mx-tip" cx="20" cy="3.6" r="2.2"/><rect class="mx-head" x="7" y="9" width="26" height="21" rx="9"/><rect class="mx-face" x="11" y="13.5" width="18" height="11" rx="5.5"/><circle class="mx-eye" cx="16.5" cy="19" r="1.9"/><circle class="mx-eye" cx="23.5" cy="19" r="1.9"/><path class="mx-smile" d="M17.5 22.6q2.5 1.6 5 0"/><path class="mx-ear" d="M7 17.5H5m30 0h-2"/><path class="mx-body" d="M14 30.5h12l-1.5 5h-9z"/></svg>';
  function bitTip(r, cls) {
    if (sess.get("cs-bit-off") === "1") return null;
    const l = L();
    const line = (CS.modeOf(r) === "url" && l.bitLink[cls]) || l.bit[cls] || l.bit.UNKNOWN;
    const box = el("aside", "rp-bit"); box.setAttribute("aria-label", l.bitName);
    const bot = el("span", "rp-bit-bot"); bot.innerHTML = BOT;   // a static, trusted drawing
    const say = el("p", "rp-bit-say"); say.append(el("b", "", `${l.bitName}: `), document.createTextNode(line)); say.setAttribute("role", "status");
    const x = el("button", "rp-bit-x"); x.type = "button"; x.setAttribute("aria-label", l.bitDismiss);
    x.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6 6 18"/></svg>';
    x.addEventListener("click", () => { sess.set("cs-bit-off", "1"); box.remove(); });
    box.append(bot, say, x);
    if (reduced()) box.classList.add("still");
    return box;
  }

  /* ------------------------------------------------------------ wiring */
  let last = null;
  window.addEventListener("cs:rc-built", (e) => {
    const { rc, result: r, cls, findings } = e.detail || {};
    if (!rc || !r) return;
    const l = L();
    const items = evidenceOf(r, findings || []);
    last = { r, cls, items };
    const sum = rc.querySelector(".rc-sum");
    const actRow = rc.querySelector(".rc-actions");
    if (actRow) {
      const extra = el("div", "rp-actions");
      const askB = el("button", "ghost rp-ask", l.ask); askB.type = "button";
      askB.addEventListener("click", () => {
        if (!window.CSAsk) return;
        const v = CS.verdictOf(r);
        window.CSAsk.open(undefined, askContext(r, items), fill(l.askLabel, { v: verdictName(v.cls), s: v.score }), askB);
      });
      askB.hidden = !window.CSAsk;
      const shareB = el("button", "ghost rp-share", l.share); shareB.type = "button";
      shareB.hidden = !window.CSShare;
      shareB.addEventListener("click", () => shareDialog(r));
      extra.append(askB, shareB);
      actRow.after(extra);
    }
    const tip = bitTip(r, cls);
    if (tip && sum) sum.querySelector(".rc-sum-head") ? sum.querySelector(".rc-sum-head").append(tip) : sum.prepend(tip);
    const why = whyCard(r, cls, items);
    const src = sourcesCard(r, cls, items);
    const whyOld = rc.querySelector(".rc-why");
    if (whyOld) { whyOld.before(why); whyOld.after(src); } else { rc.append(why, src); }
  });
  // the curves follow the layout
  let rz = 0;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(rz);
    rz = requestAnimationFrame(() => document.querySelectorAll(".rp-flow").forEach((flow) => {
      const list = flow.querySelector(".rp-ev"), node = flow.querySelector(".rp-score"), svg = flow.querySelector(".rp-curves");
      if (last && list && node && svg) drawCurves(flow, list, node, svg, last.items.filter((f) => f.contrib > 0).slice(0, 8));
    }));
  });
})();
