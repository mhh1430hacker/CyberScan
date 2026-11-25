/* CyberScan scan page: detection sources, intelligence results and in-place repair.
 *
 *   - "Detection sources" (before a scan): what this installation checks with right now, read from
 *     /api/protection: YARA-Forge and CyberScan rules, the known-malware hash database, link lists,
 *     online hash lookups (and which keys are present), and the automatic update schedule.
 *   - "Intelligence" (in the results): every hash source's answer, each rule that matched with its
 *     origin, author and score, and the files scanned inside an archive.
 *   - "Repair" (in the results, files only): the repair engine's findings for this same file; a copy
 *     is repaired, verified and inspected again, and the before/after is shown. The original is kept.
 * Nothing is simulated: a source that did not answer says so, and so does a repair that was refused.
 */
(function () {
  "use strict";
  const CS = window.CS;
  if (!CS) return;
  const { $, el, api, postJSON, formatBytes } = CS;
  const isAr = () => CS.lang === "ar";
  const TEXT = {
    en: {
      srcTitle: "Detection sources", srcLede: "What every scan on this installation checks against, right now.",
      forge: "YARA-Forge rules", forgeOff: "not loaded", bundled: "CyberScan rules", rulesFiles: "{n} rule file(s)",
      hashes: "Known-malware hashes", hashesOff: "database not built", lists: "Malicious link lists",
      listsVal: "{u} malware URLs · {p} phishing domains", online: "External intelligence",
      onlineOn: "on: only the SHA-256 is sent (CIRCL{keys})", onlineOff: "off: turn on in Settings to ask VirusTotal and the other services",
      onlineWeb: "on for every scan unless you switch it off: only the fingerprint or the link is sent", onlineLocal: "on: only the fingerprint or the link is sent",
      extActive: "active", extNoKey: "not configured", extQuota: "VirusTotal today: {u} of {d} lookups ({m} a minute)",
      onlinePublic: "not used on the public site", keysNone: "", update: "Automatic updates",
      every: "hashes every {h} h · rules every {r} h", updatedAt: "rules {a} · hashes {b}", updateNow: "Update now",
      updating: "Updating… (downloads run in the background; scans keep working)", updFailed: "Last update failed: {m}",
      publicUpd: "refreshed with every release of the site", never: "never",
      intelTitle: "Intelligence sources", intelLede: "Who was asked about this exact file, and what each one answered.",
      hashCol: "Source", ansCol: "Answer",
      st: { match: "Listed as malware", not_found: "Not listed", known_good: "Known software", unavailable: "Not available", no_key: "No key saved",
        timeout: "No answer in time", error: "Error", few: "A few engines flag it", clean_report: "Engines report it clean",
        several: "Several engines flag it", quota: "Quota reached", seen: "Seen, nothing flagged", not_applicable: "Doesn't apply" },
      rulesTitle: "Rules that matched", ruleBy: "by {a}", ruleScore: "rule score {s}", noRules: "No rule matched this file.",
      archTitle: "Files inside the archive", archLede: "{n} scanned in memory, {s} skipped ({why}).", archClean: "no match",
      archHit: "match", archNone: "No file inside could be scanned.",
      repTitle: "Repair", repLede: "CyberScan looks for parts that don't belong in this file's format, removes them from a copy, then checks the copy still opens as the same kind of file. Your original is never changed.",
      repStart: "Look for repairable parts", repLooking: "Reading the file's structure…", repNone: "Nothing in this file can be removed safely. If it is malware, delete it: a program cannot be \"cleaned\" by cutting bytes.",
      repRun: "Repair a copy", repRunning: "Repairing and verifying…", repReportOnly: "Report only", repReason: "Why not",
      repRecommended: "recommended", repDone: "Repaired copy ready", repFail: "The copy was not written",
      repVerified: "Verified: the copy still opens as the same kind of file.", repUnverified: "Saved, but full verification could not complete.",
      repRemoved: "{b} removed · repairable problems: {x} before, {y} after", repBefore: "Before (scan)", repAfter: "After (scan of the copy)", repDownload: "Download the repaired copy",
      repSaved: "Saved next to the original: {p}", repNoFile: "Repair works on files. Choose the file again to repair it.",
      repMalware: "This file is listed as known malware. Repair can remove added parts, but the safe action is to delete it.",
      sev: { high: "High", medium: "Medium", low: "Low" },
      statusOn: "Protection active", statusPartial: "Protection partly available", statusUnknown: "Protection status unavailable", statusLoading: "Checking protection…", statRulesOff: "The large rule set isn't loaded here; the built-in rules still run.",
      statusUpdated: "Rules updated {d}", statRules: "threat rules", statHashes: "known-malware fingerprints", statLinks: "malicious links & domains",
      recentTitle: "Recent scans", recentAll: "All history",
      howTitle: "How a scan works",
      howSteps: [["Read", "The file is read as data, never opened or run."], ["Match", "Thousands of threat rules and known-malware fingerprints."], ["Measure", "Structure, entropy and hidden data, byte by byte."], ["Explain", "Every finding in plain words, with its source."]],
      promises: ["Nothing you check is ever run", "The uploaded copy is deleted after the check", "Repairs work on a copy and are verified", "Online checks send only the fingerprint, and only if you allow it"],
      insp: { SAFE: "No warning signs", UNKNOWN: "Needs review", SUSPICIOUS: "Suspicious" }, inspFindings: "{n} finding(s)",
      noRulesUrl: "No rule matched this link.", noRulesText: "No rule matched this text.",
      linkTitle: "Malicious-link lists", linkListed: "Listed as malicious", linkNotListed: "Not on any malicious-link list", linkNotChecked: "Not checked",
      linkLists: "Checked against: {l}", linkHit: "Listed by: {l}",
      recentMore: "×{n}", recentLink: "Link", recentText: "Pasted text",
      srcNames: { "CyberScan rules": "CyberScan rules", "Offline hash database": "Offline hash database" },
      skip: { too_large: "too large", encrypted: "encrypted", nested: "archive inside an archive", limit: "over the file limit", unsupported: "not readable", error: "unreadable" },
    },
    ar: {
      srcTitle: "مصادر الكشف", srcLede: "ما يفحص به كل فحص على هذا الجهاز، الآن.",
      forge: "قواعد YARA-Forge", forgeOff: "غير محمّلة", bundled: "قواعد CyberScan", rulesFiles: "{n} ملف قواعد",
      hashes: "بصمات البرامج الضارة المعروفة", hashesOff: "القاعدة غير مبنية", lists: "قوائم الروابط الضارة",
      listsVal: "{u} رابط برامج ضارة · {p} نطاق تصيّد", online: "الاستخبارات الخارجية",
      onlineOn: "مفعّل: تُرسل البصمة SHA-256 فقط (CIRCL{keys})", onlineOff: "متوقف: فعّله من الإعدادات لسؤال VirusTotal والخدمات الأخرى",
      onlineWeb: "مفعّل لكل فحص ما لم توقفه: تُرسل البصمة أو الرابط فقط", onlineLocal: "مفعّل: تُرسل البصمة أو الرابط فقط",
      extActive: "فعّالة", extNoKey: "غير مُعدّة", extQuota: "VirusTotal اليوم: {u} من {d} استعلامًا ({m} في الدقيقة)",
      onlinePublic: "غير مستخدم في الموقع العام", keysNone: "", update: "التحديث التلقائي",
      every: "البصمات كل {h} ساعات · القواعد كل {r} ساعة", updatedAt: "القواعد {a} · البصمات {b}", updateNow: "حدّث الآن",
      updating: "جارٍ التحديث… (التنزيل في الخلفية، والفحص يعمل كالمعتاد)", updFailed: "فشل آخر تحديث: {m}",
      publicUpd: "تُحدَّث مع كل إصدار للموقع", never: "لم يحدث",
      intelTitle: "مصادر الاستخبارات", intelLede: "من سُئل عن هذا الملف بعينه، وبماذا أجاب كل مصدر.",
      hashCol: "المصدر", ansCol: "الإجابة",
      st: { match: "مُدرج كبرنامج ضار", not_found: "غير مُدرج", known_good: "برنامج معروف", unavailable: "غير متاح", no_key: "لا يوجد مفتاح",
        timeout: "لم يُجب في الوقت", error: "خطأ", few: "بعض المحركات تشتبه به", clean_report: "المحركات تراه سليمًا",
        several: "عدة محركات تشير إليه", quota: "نفدت الحصة", seen: "شوهد ولم يُشر إليه", not_applicable: "لا ينطبق" },
      rulesTitle: "القواعد التي طابقت", ruleBy: "بواسطة {a}", ruleScore: "درجة القاعدة {s}", noRules: "لم تطابق أي قاعدة هذا الملف.",
      archTitle: "الملفات داخل الأرشيف", archLede: "فُحص {n} في الذاكرة، وتُخطّي {s} ({why}).", archClean: "لا تطابق",
      archHit: "تطابق", archNone: "لم يمكن فحص أي ملف بالداخل.",
      repTitle: "الإصلاح", repLede: "يبحث CyberScan عن أجزاء لا تنتمي إلى صيغة هذا الملف، فيزيلها من نسخة، ثم يتحقق أن النسخة ما زالت تُفتح كالنوع نفسه. ملفك الأصلي لا يُعدَّل أبدًا.",
      repStart: "ابحث عن أجزاء قابلة للإصلاح", repLooking: "جارٍ قراءة بنية الملف…", repNone: "لا يوجد في هذا الملف ما يمكن إزالته بأمان. إن كان برنامجًا ضارًا فاحذفه: البرنامج لا «يُنظَّف» بقص البايتات.",
      repRun: "أصلح نسخة", repRunning: "جارٍ الإصلاح والتحقق…", repReportOnly: "للعرض فقط", repReason: "السبب",
      repRecommended: "موصى به", repDone: "النسخة المُصلحة جاهزة", repFail: "لم تُكتب النسخة",
      repVerified: "تم التحقق: النسخة ما زالت تُفتح كالنوع نفسه.", repUnverified: "حُفظت، لكن تعذّر إكمال التحقق الكامل.",
      repRemoved: "أُزيل {b} · المشكلات القابلة للإصلاح: {x} قبل، {y} بعد", repBefore: "قبل (الفحص)", repAfter: "بعد (فحص النسخة)", repDownload: "نزّل النسخة المُصلحة",
      repSaved: "حُفظت بجوار الأصل: {p}", repNoFile: "الإصلاح يعمل على الملفات. اختر الملف مرة أخرى لإصلاحه.",
      repMalware: "هذا الملف مُدرج كبرنامج ضار معروف. يمكن للإصلاح إزالة الأجزاء المضافة، لكن الإجراء الآمن هو حذفه.",
      sev: { high: "مرتفع", medium: "متوسط", low: "منخفض" },
      statusOn: "الحماية فعّالة", statusPartial: "الحماية متاحة جزئيًا", statusUnknown: "حالة الحماية غير متاحة", statusLoading: "جارٍ التحقق من الحماية…", statRulesOff: "مجموعة القواعد الكبيرة غير محمّلة هنا؛ القواعد المدمجة ما زالت تعمل.",
      statusUpdated: "حُدّثت القواعد {d}", statRules: "قاعدة تهديد", statHashes: "بصمة برامج ضارة معروفة", statLinks: "رابط ونطاق ضار",
      recentTitle: "آخر الفحوصات", recentAll: "السجل كاملًا",
      howTitle: "كيف يعمل الفحص",
      howSteps: [["القراءة", "يُقرأ الملف كبيانات، ولا يُفتح أو يُشغَّل أبدًا."], ["المطابقة", "آلاف قواعد التهديد وبصمات البرامج الضارة المعروفة."], ["القياس", "البنية والإنتروبيا والبيانات المخفية، بايتًا بايتًا."], ["الشرح", "كل نتيجة بكلمات واضحة، مع مصدرها."]],
      promises: ["لا يُشغَّل أي شيء تفحصه", "تُحذف النسخة المرفوعة بعد الفحص", "الإصلاح يعمل على نسخة ويُتحقق منه", "الفحص عبر الإنترنت يرسل البصمة فقط، وبإذنك فقط"],
      insp: { SAFE: "لا علامات تحذير", UNKNOWN: "يحتاج مراجعة", SUSPICIOUS: "مشبوه" }, inspFindings: "{n} نتيجة", srcNames: { "Offline hash database": "قاعدة البصمات المحلية", "CyberScan rules": "قواعد CyberScan" },
      noRulesUrl: "لم تطابق أي قاعدة هذا الرابط.", noRulesText: "لم تطابق أي قاعدة هذا النص.",
      linkTitle: "قوائم الروابط الضارة", linkListed: "مُدرج كرابط ضار", linkNotListed: "غير مُدرج في أي قائمة للروابط الضارة", linkNotChecked: "لم يُفحص",
      linkLists: "فُحص مقابل: {l}", linkHit: "مُدرج لدى: {l}",
      recentMore: "×{n}", recentLink: "رابط", recentText: "نص ملصق",
      skip: { too_large: "كبير جدًا", encrypted: "مشفّر", nested: "أرشيف داخل أرشيف", limit: "فوق حد الملفات", unsupported: "تتعذّر قراءته", error: "تتعذّر قراءته" },
    },
  };
  const L = () => TEXT[isAr() ? "ar" : "en"];
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] != null ? o[k] : ""));
  const num = (n) => Number(n || 0).toLocaleString(CS.lang);
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------ the side rail (before a scan)
   * Beside the composer on wide screens, below it on phones: live protection status with the real
   * numbers, the detail of every source, recent scans, how a scan works, and the product's promises. */
  const composer = document.querySelector("#view-scan .composer");
  const rail = el("aside", "sp-rail");
  rail.setAttribute("aria-label", "CyberScan");
  if (composer) composer.after(rail);
  const statusCard = el("section", "sp-card sp-status");
  const srcBox = el("details", "sp-sources");
  const recentCard = el("section", "sp-card sp-recent");
  const howCard = el("section", "sp-card sp-how");
  rail.append(statusCard, recentCard, howCard);
  let protection = null, pollTimer = null, recent = null, protLoading = true, protTries = 0;
  async function loadProtection() {
    protLoading = !protection;
    if (protLoading) paintSources();
    try { protection = await api("/api/protection"); } catch { protection = null; }
    protLoading = false;
    // a cold start can fail once: try again before saying the status is unavailable
    if (!protection && protTries++ < 2) { protLoading = true; paintSources(); clearTimeout(pollTimer); pollTimer = setTimeout(loadProtection, 1500); return; }
    paintSources();
    if (protection && protection.updater && protection.updater.running) {
      clearTimeout(pollTimer); pollTimer = setTimeout(loadProtection, 4000);
    }
  }
  function row(dl, k, v, tone) { dl.append(el("dt", "", k)); const d = el("dd", tone ? `t-${tone}` : "", v); dl.append(d); return d; }
  const compact = (n) => { try { return new Intl.NumberFormat(CS.lang, { notation: "compact", maximumFractionDigits: 1 }).format(n || 0); } catch { return num(n); } };
  const SVGNS = "http://www.w3.org/2000/svg";
  function shield() {
    const svg = document.createElementNS(SVGNS, "svg"); svg.setAttribute("viewBox", "0 0 64 64"); svg.setAttribute("aria-hidden", "true");
    const defs = document.createElementNS(SVGNS, "defs"); const g = document.createElementNS(SVGNS, "linearGradient");
    g.id = "sp-grad"; [["x1", "0"], ["y1", "0"], ["x2", "1"], ["y2", "1"]].forEach(([k, v]) => g.setAttribute(k, v));
    [["0", "#7dd3fc"], [".5", "#b46cff"], ["1", "#f0abfc"]].forEach(([o, c]) => { const s = document.createElementNS(SVGNS, "stop"); s.setAttribute("offset", o); s.setAttribute("stop-color", c); g.append(s); });
    defs.append(g); svg.append(defs);
    const body = document.createElementNS(SVGNS, "path"); body.setAttribute("d", "M32 5 9 13v17c0 14 9.6 24.8 23 29 13.4-4.2 23-15 23-29V13z"); body.setAttribute("class", "sh-body");
    const tick = document.createElementNS(SVGNS, "path"); tick.setAttribute("d", "m21 32 8 8 15-16"); tick.setAttribute("class", "sh-tick");
    svg.append(body, tick);
    return svg;
  }
  function paintSources() {
    const l = L(), p = protection;
    statusCard.replaceChildren();
    const head = el("div", "sp-status-head");
    const mark = el("div", "sp-shield"); mark.append(shield());
    const live = p ? [p.forge, p.malware_hashes, p.lists].filter(Boolean).length : 0;
    statusCard.classList.toggle("partial", !!p && live < 3);
    const title = el("div", "sp-status-title");
    statusCard.classList.toggle("loading", protLoading && !p);
    title.append(el("b", "", protLoading && !p ? l.statusLoading : live === 3 ? l.statusOn : p ? l.statusPartial : l.statusUnknown), el("small", "", p ? fill(l.statusUpdated, { d: p.updated || l.never }) : ""));
    head.append(mark, title);
    statusCard.append(head);
    if (p || protLoading) {
      // while /api/protection answers: a placeholder, never a misleading 0; a source that isn't loaded shows a dash
      const stats = el("div", "sp-stats");
      const rules = p ? (Number(p.forge_rules) || 0) : 0;
      const links = p ? (Number(p.urlhaus) || 0) + (Number(p.phishing) || 0) : 0;
      [[p && (rules || null), l.statRules, p && !rules ? l.statRulesOff : ""], [p && (Number(p.malware_hashes) || null), l.statHashes, p && !p.malware_hashes ? l.hashesOff : ""],
        [p && (links || null), l.statLinks, p && !links ? l.forgeOff : ""]].forEach(([n, k, off]) => {
        const s = el("div", `sp-stat${!p ? " skel" : ""}`);
        const b = el("b", "", !p ? "…" : n ? compact(n) : "–"); b.dir = "auto";
        if (off) s.title = off;
        s.append(b, el("span", "", k)); stats.append(s);
      });
      if (!p) stats.setAttribute("aria-busy", "true");
      statusCard.append(stats);
    }
    // every source in detail
    srcBox.replaceChildren();
    const sm = el("summary"); sm.append(el("span", "", l.srcTitle)); srcBox.append(sm);
    statusCard.append(srcBox);
    if (!p) return;
    const body = el("div", "sp-src-body");
    const dl = el("dl", "sp-kv");
    row(dl, l.forge, p.forge ? `${num(p.forge_rules)}${p.forge_version ? ` · ${p.forge_version}` : ""}` : l.forgeOff, p.forge ? "ok" : "off");
    row(dl, l.bundled, fill(l.rulesFiles, { n: num(p.bundled_rules) }), p.bundled_rules ? "ok" : "off");
    row(dl, l.hashes, p.malware_hashes ? `${num(p.malware_hashes)}${(p.hash_sources || []).length ? ` · ${p.hash_sources.join(", ")}` : ""}` : l.hashesOff, p.malware_hashes ? "ok" : "off");
    row(dl, l.lists, p.lists ? fill(l.listsVal, { u: num(p.urlhaus), p: num(p.phishing) }) : l.forgeOff, p.lists ? "ok" : "off");
    // external intelligence: each outside service, set up (has a key here) or not
    const ext = (p.external && p.external.services) || {};
    const extNames = { virustotal: "VirusTotal", safebrowsing: "Google Safe Browsing", malwarebazaar: "MalwareBazaar", urlhaus: "URLhaus", otx: "AlienVault OTX", circl: "CIRCL hashlookup", urlscan: "urlscan.io" };
    const on = Object.keys(extNames).filter((k) => ext[k]), off = Object.keys(extNames).filter((k) => ext[k] === false);
    const extCell = row(dl, l.online, p.online ? (p.public ? l.onlineWeb : l.onlineLocal) : l.onlineOff, p.online ? "ok" : "off");
    if (Object.keys(ext).length) {
      const ul = el("ul", "sp-ext-list");
      on.forEach((k) => { const li = el("li", "on"); li.append(el("b", "", extNames[k]), el("small", "", l.extActive)); ul.append(li); });
      off.forEach((k) => { const li = el("li", "off"); li.append(el("b", "", extNames[k]), el("small", "", l.extNoKey)); ul.append(li); });
      extCell.append(ul);
      const q = p.external.virustotal_quota;
      if (ext.virustotal && q) extCell.append(el("small", "sp-muted", fill(l.extQuota, { u: num(q.used_today), d: num(q.per_day), m: q.per_minute })));
    }
    const up = p.updater || {};
    const updText = !p.auto_update ? l.publicUpd
      : `${fill(l.every, { h: p.schedule.hashes_hours, r: p.schedule.rules_hours })} · ${fill(l.updatedAt, { a: p.updated || l.never, b: (p.hashes_updated || l.never).replace("T", " ") })}`;
    const upCell = row(dl, l.update, updText, p.auto_update ? "ok" : "");
    if (up.running) upCell.append(el("small", "sp-busy", l.updating));
    else if (up.last_error) upCell.append(el("small", "sp-err", fill(l.updFailed, { m: up.last_error })));
    body.append(dl);
    if (p.auto_update) {
      const btn = el("button", "ghost small sp-update", l.updateNow); btn.type = "button"; btn.disabled = !!up.running;
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try { await postJSON("/api/protection/update", {}); } catch (e) { CS.toast(e.message); }
        loadProtection();
      });
      body.append(btn);
    }
    srcBox.append(body);
  }
  const TONE = { KNOWN_MALWARE: "bad", SUSPICIOUS: "bad", REVIEW: "warn", NO_INDICATORS_OBSERVED: "ok" };
  function ago(ts) {
    const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
    try {
      const f = new Intl.RelativeTimeFormat(CS.lang, { numeric: "auto" });
      if (s < 3600) return f.format(-Math.round(s / 60), "minute");
      if (s < 86400) return f.format(-Math.round(s / 3600), "hour");
      return f.format(-Math.round(s / 86400), "day");
    } catch { return new Date(ts).toLocaleString(CS.lang); }
  }
  async function loadRecent() {
    try { recent = await api("/api/history"); } catch { recent = null; }
    paintRecent();
  }
  function paintRecent() {
    const l = L();
    recentCard.replaceChildren();
    // the same file scanned again with the same outcome is one row with a count
    const groups = [];
    const byKey = new Map();
    (Array.isArray(recent) ? recent : []).forEach((r) => {
      const key = r.sha256 || `${r.target}|${r.score}|${r.classification}`;
      if (byKey.has(key)) { byKey.get(key).n += 1; return; }
      const g = { r, n: 1 }; byKey.set(key, g); groups.push(g);
    });
    const rows = groups.slice(0, 4);
    recentCard.hidden = !rows.length;
    if (!rows.length) return;
    const h = el("div", "sp-card-head"); h.append(el("h2", "sp-h", l.recentTitle));
    const all = el("a", "sp-link", l.recentAll); all.href = "#/history"; h.append(all);
    recentCard.append(h);
    const ul = el("ul", "sp-recent-list");
    rows.forEach(({ r, n }) => {
      const li = el("li");
      const b = el("button", `sp-recent-row t-${TONE[r.classification] || "neutral"}`); b.type = "button";
      const target = String(r.target || "");
      const isUrl = /^https?:\/\//i.test(target), isText = /^pasted text$/i.test(target);
      let shownName = target.split(/[\\/]/).filter(Boolean).pop() || target;
      if (isUrl) { try { const u = new URL(target); shownName = u.host + (u.pathname !== "/" ? u.pathname : ""); } catch { shownName = target; } }
      if (isText) shownName = l.recentText;
      const name = el("span", "sp-r-name", shownName); name.dir = isUrl ? "ltr" : "auto"; name.title = target;
      const meta = el("span", "sp-r-meta", `${r.score}/100 · ${ago(r.timestamp)}${n > 1 ? ` · ${fill(l.recentMore, { n })}` : ""}`);
      const txt = el("span", "sp-r-text"); txt.append(name, meta);
      b.append(el("i", "sp-r-dot"), txt);
      b.addEventListener("click", () => CS.openRecord(r.id));
      li.append(b); ul.append(li);
    });
    recentCard.append(ul);
  }
  function paintHow() {
    const l = L();
    howCard.replaceChildren(el("h3", "", l.howTitle));
    howCard.firstChild.replaceWith(el("h2", "sp-h", l.howTitle));
    const ol = el("ol", "sp-how-list");
    l.howSteps.forEach(([t, d]) => { const li = el("li"); li.append(el("b", "", t), el("span", "", d)); ol.append(li); });
    const promises = el("ul", "sp-promises");
    l.promises.forEach((x) => promises.append(el("li", "", x)));
    howCard.append(ol, promises);
  }
  loadProtection(); loadRecent(); paintHow();
  window.addEventListener("hashchange", () => { if (location.hash.startsWith("#/scan")) loadRecent(); });

  /* ------------------------------------------------------------ results: intelligence + repair */
  let scanned = null;   // the File or disk path the last scan was started with
  window.addEventListener("cs:scan-start", () => {
    const s = CS.state || {};
    scanned = s.mode === "file" ? (s.diskPath ? { path: s.diskPath } : s.file ? { file: s.file } : null) : null;
  });

  /* The link-list answer for a link: whichever shape the server sends it in. */
  function linkListOf(r) {
    const intel = r.intel || {}, ca = r.content_analysis || {};
    const v = [r.link_check, r.link_lists, intel.link_lists, r.link_list, intel.link_list, ca.link_lists, ca.threat_lists, r.threat_lists, intel.url_lists].find((x) => x != null);
    if (v == null) return null;
    if (typeof v === "string") return { status: v };
    if (typeof v === "boolean") return { status: v ? "match" : "not_found" };
    return v;
  }
  function linkListRow(r) {
    const l = L(), x = linkListOf(r);
    if (!x) return null;
    const hits = [].concat(x.matched || x.matches || x.listed_by || x.sources_matched || []).map((m) => (typeof m === "string" ? m : m.source || m.list || m.name)).filter(Boolean);
    const lists = [].concat(x.lists || x.checked || x.sources || []).map((m) => (typeof m === "string" ? m : m.name || m.source)).filter(Boolean);
    const st = String(x.status || (hits.length ? "match" : x.checked === false ? "skipped" : "not_found")).toLowerCase();
    const listed = st === "match" || st === "listed" || st === "malicious" || x.listed === true || hits.length > 0;
    const unchecked = !listed && /skip|disabled|unavailable|error|not_checked|off/.test(st);
    const box = el("div", `sp-linklist ${listed ? "a-match" : unchecked ? "a-off" : "a-ok"}`);
    box.append(el("h4", "", l.linkTitle));
    const p = el("p", "", CS.loc(x.text) || (listed ? l.linkListed : unchecked ? l.linkNotChecked : l.linkNotListed));
    p.dir = "auto"; box.append(p);
    if (hits.length) box.append(el("small", "", fill(l.linkHit, { l: hits.join(", ") })));
    else if (lists.length) box.append(el("small", "", fill(l.linkLists, { l: lists.join(", ") })));
    return box;
  }
  function intelCard(r) {
    const l = L(), intel = r.intel || {};
    const mode = CS.modeOf(r);
    const sec = el("section", "card sp-intel");
    sec.append(el("h3", "", l.intelTitle), el("p", "rc-note", mode === "url" ? CS.ax("intelUrl") : mode === "text" ? CS.ax("intelText") : l.intelLede));
    if (mode === "url") { const ll = linkListRow(r); if (ll) sec.append(ll); }
    const sources = Object.entries(intel.hash_sources || {});
    if (sources.length) {
      const table = el("table", "sp-table");
      const head = el("tr"); head.append(el("th", "", l.hashCol), el("th", "", l.ansCol)); const thead = el("thead"); thead.append(head);
      const tb = el("tbody");
      sources.forEach(([name, ans]) => {
        const tr = el("tr", `a-${ans.status}`);
        const detail = [l.st[ans.status] || ans.status, ans.detail, ans.signature, ans.error, ans.entries ? `${num(ans.entries)}` : ""].filter(Boolean);
        const cell = el("td"); cell.append(el("b", "", detail[0]));
        if (detail.length > 1) { const sm = el("small", "", detail.slice(1).join(" · ")); sm.dir = "auto"; cell.append(sm); }
        tr.append(el("td", "", (l.srcNames && l.srcNames[name]) || name), cell); tb.append(tr);
      });
      table.append(thead, tb); sec.append(table);
    }
    sec.append(el("h4", "", l.rulesTitle));
    const rules = intel.rules || [];
    if (!rules.length) sec.append(el("p", "sp-muted", mode === "url" ? l.noRulesUrl : mode === "text" ? l.noRulesText : l.noRules));
    else {
      const ul = el("ul", "sp-rules");
      rules.forEach((x) => {
        const li = el("li");
        const top = el("div", "sp-rule-top"); top.append(el("code", "", x.rule), el("span", "sp-tag", (l.srcNames && l.srcNames[x.source]) || x.source));
        if (x.score) top.append(el("span", "sp-tag", fill(l.ruleScore, { s: x.score })));
        li.append(top);
        if (x.description) { const p = el("p", "", x.description); p.dir = "ltr"; li.append(p); }
        const meta = [x.author && fill(l.ruleBy, { a: x.author }), x.license].filter(Boolean).join(" · ");
        if (meta) li.append(el("small", "", meta));
        ul.append(li);
      });
      sec.append(ul);
    }
    const arch = intel.archive;
    if (arch && arch.status === "ok") {
      sec.append(el("h4", "", l.archTitle));
      const why = Object.entries(arch.skip_reasons || {}).map(([k, v]) => `${(l.skip && l.skip[k]) || String(k).replace(/_/g, " ")}: ${v}`).join(", ") || "–";
      sec.append(el("p", "rc-note", fill(l.archLede, { n: arch.scanned, s: arch.skipped, why })));
      if (!arch.members || !arch.members.length) sec.append(el("p", "sp-muted", l.archNone));
      else {
        const ul = el("ul", "sp-members");
        // one row per member, even if the server lists one twice
        const seenM = new Set();
        arch.members.filter((m) => { const k = `${m.name}|${m.size}`; if (seenM.has(k)) return false; seenM.add(k); return true; }).forEach((m) => {
          const hit = (m.hash && m.hash.status === "match") || (m.yara && m.yara.length);
          const li = el("li", hit ? "hit" : "");
          const name = el("span", "sp-m-name", m.name); name.dir = "ltr";
          li.append(name, el("span", "sp-m-size", formatBytes(m.size)), el("span", "sp-m-verdict", hit ? `${l.archHit}: ${[...(m.yara || []), m.hash && m.hash.status === "match" ? "hash" : ""].filter(Boolean).join(", ")}` : l.archClean));
          ul.append(li);
        });
        sec.append(ul);
      }
    }
    return sec;
  }

  const REPAIRABLE = new Set(["pdf", "exe", "dll", "scr", "sys", "com", "cpl", "elf", "so", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "doc", "xls", "ppt", "msg",
    "zip", "jar", "apk", "png", "jpg", "jpeg", "gif", "pe", "ooxml", "ole", "office", "image"]);
  function repairHelps(r, findings) {
    if ((findings || []).length) return true;
    const ext = String(r.target || "").split(/[\\/]/).pop().split(".").slice(1).pop() || "";
    const type = String((r.content_analysis && r.content_analysis.file_type) || "").toLowerCase();
    return REPAIRABLE.has(ext.toLowerCase()) || REPAIRABLE.has(type);
  }
  function repairCard(r, cls) {
    const l = L();
    const sec = el("section", "card sp-repair");
    sec.append(el("h3", "", l.repTitle), el("p", "rc-note", l.repLede));
    if (cls === "KNOWN_MALWARE") sec.append(el("p", "sp-warn", l.repMalware));
    const body = el("div", "sp-rep-body");
    sec.append(body);
    const source = scanned;
    if (!source || String(r.mode).toLowerCase() !== "file") {
      body.append(el("p", "sp-muted", l.repNoFile));
      return sec;
    }
    const start = el("button", "ghost sp-rep-start", l.repStart); start.type = "button";
    body.append(start);
    start.addEventListener("click", async () => {
      start.disabled = true; start.textContent = l.repLooking;
      try {
        const session = source.path
          ? await postJSON("/api/repair/path", { path: source.path })
          : await api("/api/repair/upload", { method: "POST", headers: { "X-Filename": encodeURIComponent(source.file.name), "Content-Type": "application/octet-stream" }, body: source.file });
        showFindings(body, session);
      } catch (e) {
        start.disabled = false; start.textContent = l.repStart; CS.toast(CS.friendlyError(e));
      }
    });
    return sec;
  }

  function pick(map) { return (map && (map[CS.lang] || map.en)) || ""; }

  function showFindings(body, session) {
    const l = L();
    body.replaceChildren();
    const findings = session.findings || [];
    if (!findings.length) { body.append(el("p", "sp-muted", l.repNone)); return; }
    const list = el("ul", "sp-fixes");
    findings.forEach((f) => {
      const li = el("li", `sev-${f.severity}${f.repairable ? "" : " ro"}`);
      const label = el("label");
      const box = el("input"); box.type = "checkbox"; box.value = f.key; box.disabled = !f.repairable; box.checked = f.repairable && f.recommended;
      const text = el("span", "sp-fix-text");
      const title = el("b", "", pick(f.title)); const tags = el("span", "sp-fix-tags");
      tags.append(el("span", `sp-sev s-${f.severity}`, l.sev[f.severity] || f.severity));
      if (f.recommended && f.repairable) tags.append(el("span", "sp-tag", l.repRecommended));
      if (!f.repairable) tags.append(el("span", "sp-tag", l.repReportOnly));
      text.append(title, tags);
      const p = el("p", "", pick(f.body) || f.detail); p.dir = "auto"; text.append(p);
      if (!f.repairable && pick(f.reason)) { const why = el("small", "", `${l.repReason}: ${pick(f.reason)}`); why.dir = "auto"; text.append(why); }
      label.append(box, text); li.append(label); list.append(li);
    });
    body.append(list);
    const run = el("button", "primary sp-rep-run", l.repRun); run.type = "button";
    const sync = () => { run.disabled = !list.querySelector("input:checked"); };
    list.addEventListener("change", sync); sync();
    body.append(run);
    run.addEventListener("click", async () => {
      const keys = [...list.querySelectorAll("input:checked")].map((x) => x.value);
      run.disabled = true; run.textContent = l.repRunning;
      try { const o = await postJSON(`/api/repair/${session.id}/run`, { keys }); run.remove(); list.querySelectorAll("input").forEach((x) => { x.disabled = true; }); showOutcome(body, session, o); }
      catch (e) { run.disabled = false; run.textContent = l.repRun; CS.toast(CS.friendlyError(e)); }
    });
  }

  function inspectionLine(report) {
    if (!report) return "–";
    const l = L(), s = report.detection_summary || {};
    const code = s.content_classification || report.classification || "";
    const hasScore = s.final_score != null || report.final_score != null || report.combined_score != null || s.content_score != null || report.score != null;
    const v = CS.verdictOf({ ...report, combined_score: report.combined_score != null ? report.combined_score : report.score, detection_summary: { ...s, classification: s.classification || report.classification || code } });
    const word = CS.verdictWords(v.cls)[1] || l.insp[code] || code || "–";
    const n = Array.isArray(report.findings) ? report.findings.length : Number(report.findings_count) || 0;
    return `${word}${hasScore ? ` · ${v.score}/100` : ""} · ${fill(l.inspFindings, { n })}`;
  }

  function showOutcome(body, session, o) {
    const l = L();
    const out = el("div", `sp-outcome ${o.ok ? (o.verification_status === "verified" ? "ok" : "partial") : "fail"}`);
    out.append(el("h4", "", o.ok ? l.repDone : l.repFail));
    if (!o.ok) { const p = el("p", "", o.message || Object.entries(o.failures || {}).map(([k, v]) => `${k}: ${v}`).join("; ")); p.dir = "auto"; out.append(p); }
    else {
      out.append(el("p", "", o.verification_status === "verified" ? l.repVerified : l.repUnverified));
      out.append(el("p", "sp-muted", fill(l.repRemoved, { b: formatBytes(o.removed_bytes || 0), x: o.before, y: o.after })));
      const cmp = el("dl", "sp-kv");
      row(cmp, l.repBefore, inspectionLine(o.scan_before || o.original_security_inspection));
      row(cmp, l.repAfter, inspectionLine(o.scan_after || o.candidate_security_inspection));
      row(cmp, "SHA-256", o.sha256_after || "").classList.add("mono");
      out.append(cmp);
      if (o.saved_to) { const p = el("p", "", fill(l.repSaved, { p: o.saved_to })); p.dir = "auto"; out.append(p); }
      else if (o.download) {
        const dl = el("button", "primary", l.repDownload); dl.type = "button";
        dl.addEventListener("click", () => CS.download(`/api/repair/${session.id}/download`, CS.repairedName).catch((e) => CS.toast(CS.friendlyError(e))));
        out.append(dl);
      }
    }
    body.append(out);
    if (!reduced()) out.animate([{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "none" }], { duration: 320, easing: "cubic-bezier(.22,1,.36,1)" });
  }

  window.addEventListener("cs:rc-built", (e) => {
    const { rc, result, cls, findings } = e.detail || {};
    if (!rc || !result) return;
    const reco = rc.querySelector(".rc-reco");
    const intel = intelCard(result);
    const fix = CS.modeOf(result) === "file" && repairHelps(result, findings) ? repairCard(result, cls) : null;
    if (reco) { reco.before(intel); if (fix) reco.after(fix); }
    else { rc.append(intel); if (fix) rc.append(fix); }
  });
  CS.onLang(() => { paintSources(); paintRecent(); paintHow(); });
  window.addEventListener("cs:result", () => { loadRecent(); if (protection && protection.updater && protection.updater.running) loadProtection(); });
})();
