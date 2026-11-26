/* Layered analysis, the reader's profile and the summary written for them.
 *
 *   - While a scan runs: a grid of small cells (one per layer, grouped by category) lights up as the
 *     layers finish (red = suspicious, green = nothing found, grey = doesn't apply / unavailable),
 *     streamed from the scan status ("cs:job" from app.js, job.layers).
 *   - On the result ("cs:rc-built"): the same grid with counts, the layered score, how it moved the
 *     verdict, the formula, a tap/hover detail per cell, and a plain list for screen readers.
 *   - "Summary for you" at the top of the result: five short questions (saved in this browser only,
 *     skippable, editable from the result and from Settings), then a summary written for that profile
 *     (POST /api/assistant/summary: the result's summary only, never the file or its name).
 *   - window.CSLayers.renderStatic(container, layers, lang) draws the grid and list on report.html.
 * All result text goes in as text, never as HTML. Reduced motion: no animation. */
(function () {
  "use strict";
  const STR = {
    en: {
      title: "Layered analysis", live: "Independent layers", note: "Your input was taken apart once and passed through {n} independent layers, each checking one thing. Red = suspicious, green = nothing found, grey = doesn't apply or wasn't available.",
      done: "{d} / {t} layers", sus: "suspicious", ok: "clean", na: "don't apply", un: "unavailable", priv: "privacy notes", applied: "applied",
      score: "Layered score (an input to the verdict)", noScore: "No layer could answer", effect: "Effect on the verdict", formula: "How the layered score is computed",
      formulaNote: "w = the layer's reliability, c = how sure this answer is. Layers that don't apply or couldn't answer are left out of every sum.",
      list: "List view (all layers)", legendS: "suspicious", legendC: "nothing found", legendN: "doesn't apply / unavailable",
      checks: "Checks", result: "Result", source: "Source", weight: "Reliability", conf: "Confidence", close: "Close",
      st: { suspicious: "Suspicious", clean: "Nothing found", not_applicable: "Doesn't apply", unavailable: "Not available", timeout: "Timed out", error: "Could not run", pending: "Running…" },
      waiting: "Starting the layers…",
      sumTitle: "Summary for you", sumLoading: "Writing your summary…", sumFail: "The summary couldn't be written right now.", writtenFor: "Written for", change: "Change profile",
      srcAI: "written by AI from the result", srcLocal: "written from the result (AI is busy, so CyberScan wrote it itself)",
      steps: "Next steps",
      qIntro: "Five quick questions so the summary fits you. Your answers stay in this browser.", qSave: "Save and write my summary", qSaveOnly: "Save", qSkip: "Skip for now", qCancel: "Cancel",
      q: [
        ["tech", "How comfortable are you with security?", [["beginner", "Beginner"], ["some", "Some"], ["expert", "Expert"]]],
        ["checks", "What do you usually check?", [["personal", "Personal files"], ["work", "Work files"], ["links", "Links and messages"], ["code", "Code"]]],
        ["device", "Which device do you use most?", [["phone", "Phone"], ["windows", "Windows"], ["mac", "Mac"], ["linux", "Linux"]]],
        ["detail", "How much detail do you want?", [["short", "Short"], ["balanced", "Balanced"], ["full", "Full"]]],
        ["tone", "Which tone suits you?", [["calm", "Calm and simple"], ["direct", "Direct"], ["technical", "Technical"]]],
      ],
      setTitle: "About you (for result summaries)", setNone: "Not set yet: summaries use a balanced default.", setEdit: "Edit",
      saved: "Saved", tailor: "Tailor it to me",
      srcPlain: { url_intel: "Link reputation check", executables: "Program check", engine: "Detection engine", secrets: "Secret-key detector", hash_intel: "Known-malware fingerprint lookup", entropy: "Randomness measure", pefile: "Program structure reader", model_runtime: "Machine-learning model", magic_bytes: "File-type check", authenticode: "Digital-signature check", qr_scanner: "QR code reader", file_analyzer: "File analyzer", protection: "Protection rules", pe_decompiler: "Program code reader", nextgen_engine: "Behaviour patterns", surprise_map: "Unusual-bytes map", dissonance: "Mismatch check", documents: "Document check", messages: "Message check" },
    },
    ar: {
      title: "التحليل الطبقي", live: "طبقات مستقلة", note: "فُكّك المدخل مرة واحدة ومرّ عبر {n} طبقة مستقلة، تفحص كل منها شيئًا واحدًا. الأحمر = مشبوه، الأخضر = لم يُعثر على شيء، الرمادي = لا ينطبق أو غير متاح.",
      done: "{d} / {t} طبقة", sus: "مشبوهة", ok: "سليمة", na: "لا تنطبق", un: "غير متاحة", priv: "ملاحظات خصوصية", applied: "طُبّقت",
      score: "الدرجة الطبقية (مُدخل في الحكم)", noScore: "لم تستطع أي طبقة الإجابة", effect: "أثرها على النتيجة", formula: "كيف تُحسب الدرجة الطبقية",
      formulaNote: "w = موثوقية الطبقة، c = مدى تأكد هذه الإجابة. الطبقات التي لا تنطبق أو لم تُجب لا تدخل أي مجموع.",
      list: "عرض القائمة (كل الطبقات)", legendS: "مشبوه", legendC: "لم يُعثر على شيء", legendN: "لا ينطبق / غير متاح",
      checks: "يفحص", result: "النتيجة", source: "المصدر", weight: "الموثوقية", conf: "الثقة", close: "إغلاق",
      st: { suspicious: "مشبوه", clean: "لم يُعثر على شيء", not_applicable: "لا ينطبق", unavailable: "غير متاح", timeout: "انتهى الوقت", error: "تعذّر التشغيل", pending: "قيد التشغيل…" },
      waiting: "تبدأ الطبقات…",
      sumTitle: "ملخص لك", sumLoading: "نكتب ملخصك…", sumFail: "تعذّرت كتابة الملخص الآن.", writtenFor: "مكتوب لـ", change: "تغيير الملف الشخصي",
      srcAI: "كتبه الذكاء الاصطناعي من النتيجة", srcLocal: "كُتب من النتيجة (الذكاء الاصطناعي مشغول، فكتبه CyberScan بنفسه)",
      steps: "الخطوات التالية",
      qIntro: "خمسة أسئلة سريعة ليناسبك الملخص. تبقى إجاباتك في هذا المتصفح.", qSave: "احفظ واكتب ملخصي", qSaveOnly: "حفظ", qSkip: "تخطَّ الآن", qCancel: "إلغاء",
      q: [
        ["tech", "ما مدى معرفتك بالأمن الرقمي؟", [["beginner", "مبتدئ"], ["some", "متوسط"], ["expert", "خبير"]]],
        ["checks", "ماذا تفحص عادةً؟", [["personal", "ملفات شخصية"], ["work", "ملفات العمل"], ["links", "روابط ورسائل"], ["code", "شيفرة برمجية"]]],
        ["device", "أي جهاز تستخدم أكثر؟", [["phone", "الجوال"], ["windows", "ويندوز"], ["mac", "ماك"], ["linux", "لينكس"]]],
        ["detail", "كم من التفاصيل تريد؟", [["short", "مختصر"], ["balanced", "متوازن"], ["full", "مفصّل"]]],
        ["tone", "أي أسلوب يناسبك؟", [["calm", "هادئ وبسيط"], ["direct", "مباشر"], ["technical", "تقني"]]],
      ],
      setTitle: "عنك (لملخصات النتائج)", setNone: "لم يُضبط بعد: تستخدم الملخصات إعدادًا متوازنًا.", setEdit: "تعديل",
      saved: "حُفظ", tailor: "خصّصه لي",
      srcPlain: { url_intel: "فحص سمعة الرابط", executables: "فحص البرامج", engine: "محرك الكشف", secrets: "كاشف المفاتيح السرية", hash_intel: "البحث في بصمات البرامج الضارة المعروفة", entropy: "قياس العشوائية", pefile: "قارئ بنية البرامج", model_runtime: "نموذج التعلّم الآلي", magic_bytes: "فحص نوع الملف", authenticode: "فحص التوقيع الرقمي", qr_scanner: "قارئ رموز QR", file_analyzer: "محلّل الملفات", protection: "قواعد الحماية", pe_decompiler: "قارئ شيفرة البرامج", nextgen_engine: "أنماط السلوك", surprise_map: "خريطة البايتات غير المعتادة", dissonance: "فحص عدم التطابق", documents: "فحص المستندات", messages: "فحص الرسائل" },
    },
  };
  const PROFILE_KEY = "cs-reader-profile", SKIP_KEY = "cs-reader-profile-skipped";
  const ORDER = ["structure", "entropy", "code", "documents", "archives", "content", "web", "links", "email", "reputation", "yara", "ml", "privacy"];
  const langOf = () => ((window.CS && window.CS.lang) || document.documentElement.lang || "en") === "ar" ? "ar" : "en";
  const L = () => STR[langOf()];
  const fill = (s, v) => String(s).replace(/\{(\w+)\}/g, (_, k) => (v[k] != null ? v[k] : ""));
  const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches || document.documentElement.classList.contains("reduce-motion");
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage off */ } },
  };
  const pick = (obj, lang) => (obj && (obj[lang] || obj.en)) || "";
  const stateOf = (e) => (e.signal === 1 ? "s1" : e.signal === 0 ? "s0" : "na");

  /* ------------------------------------------------------------ the grid */
  function groupsOf(items) {
    const by = new Map();
    items.forEach((x) => { if (!by.has(x.category)) by.set(x.category, []); by.get(x.category).push(x); });
    return [...by.entries()].sort((a, b) => ORDER.indexOf(a[0]) - ORDER.indexOf(b[0]));
  }

  /* items: [{id, category, name?}]; categories: {id: {en, ar}}. Returns {root, cells: Map(id -> cell)}. */
  function buildGrid(items, categories, lang) {
    const root = el("div", "lz-grid");
    root.setAttribute("aria-hidden", "true");
    const cells = new Map();
    groupsOf(items).forEach(([cat, list]) => {
      const g = el("div", "lz-group");
      g.append(el("span", "lz-gname", pick(categories && categories[cat], lang) || cat));
      const ul = el("ul", "lz-cells");
      list.forEach((x) => {
        const c = el("li", "lz-cell");
        c.dataset.id = x.id;
        ul.append(c);
        cells.set(x.id, c);
      });
      g.append(ul);
      root.append(g);
    });
    return { root, cells };
  }

  function paint(cell, cls, animate) {
    if (!cell) return;
    cell.className = `lz-cell ${cls}${animate && !reduced() ? " pop" : ""}`;
  }

  /* ------------------------------------------------------------ live grid while the scan runs */
  const CS = window.CS;
  const onScanPage = !!(CS && document.getElementById("form"));
  let catalogP = null;
  const catalog = () => {
    if (!catalogP) catalogP = CS.api("/api/layers").catch(() => { catalogP = null; return null; });
    return catalogP;
  };
  const live = { panel: null, grid: null, seen: 0, counts: null, token: 0 };

  function liveCounts() {
    const l = L(), c = live.counts;
    live.panel.querySelector(".lz-live-count").textContent = fill(l.done, { d: c.done, t: c.total || "…" });
    live.panel.querySelector(".lz-live-sus").textContent = `${c.s1} ${l.sus}`;
    live.panel.querySelector(".lz-live-ok").textContent = `${c.s0} ${l.ok}`;
  }

  function startLive() {
    const progress = document.getElementById("progress");
    if (!progress) return;
    live.token += 1;
    const token = live.token;
    if (!live.panel) {
      live.panel = el("div", "lz-live");
      const head = el("div", "lz-live-head");
      head.append(el("b", "lz-live-title"), el("span", "lz-live-count"), el("span", "lz-live-sus"), el("span", "lz-live-ok"));
      live.panel.append(head, el("p", "lz-live-wait"), el("div", "lz-live-grid"));
      const sr = el("p", "sr-only lz-live-sr"); sr.setAttribute("aria-live", "polite");
      live.panel.append(sr);
      const theater = progress.querySelector(".theater");
      (theater || progress.lastElementChild || progress).after(live.panel);
    }
    live.panel.querySelector(".lz-live-title").textContent = L().live;
    live.panel.querySelector(".lz-live-wait").textContent = L().waiting;
    live.panel.querySelector(".lz-live-wait").hidden = false;
    live.panel.querySelector(".lz-live-grid").replaceChildren();
    live.grid = null; live.seen = 0; live.counts = { done: 0, total: 0, s1: 0, s0: 0 };
    liveCounts();
    catalog().then((cat) => {
      if (!cat || token !== live.token) return;
      const g = buildGrid(cat.layers, cat.categories, langOf());
      live.grid = g;
      live.counts.total = cat.layers.length;
      live.panel.querySelector(".lz-live-grid").replaceChildren(g.root);
      liveCounts();
    });
  }

  let pendingJob = null, frame = 0;
  function onJob(job) {
    pendingJob = job;
    if (!frame) frame = requestAnimationFrame(applyJob);   // one paint per frame, however often we poll
  }
  function applyJob() {
    frame = 0;
    const job = pendingJob;
    if (!job || !live.panel || !job.layers) return;
    const lay = job.layers, cells = lay.cells || [];
    live.panel.querySelector(".lz-live-wait").hidden = true;
    if (!live.grid) return;   // the catalog is still on its way: the next poll paints
    for (let i = live.seen; i < cells.length; i++) {
      const c = cells[i];
      const cls = c.s === 1 ? "s1" : c.s === 0 ? "s0" : "na";
      if (c.s === 1) live.counts.s1 += 1; else if (c.s === 0) live.counts.s0 += 1;
      paint(live.grid.cells.get(c.id), cls, c.st !== "not_applicable");
    }
    live.seen = cells.length;
    live.counts.done = lay.done || cells.length;
    live.counts.total = lay.total || live.counts.total;
    liveCounts();
    if (lay.done >= lay.total) live.panel.querySelector(".lz-live-sr").textContent = `${L().title}: ${fill(L().done, { d: lay.done, t: lay.total })}, ${live.counts.s1} ${L().sus}.`;
  }

  /* ------------------------------------------------------------ the result panel */
  function tipFor(panel) {
    let tip = panel.querySelector(".lz-tip");
    if (!tip) { tip = el("div", "lz-tip"); tip.hidden = true; tip.setAttribute("role", "dialog"); panel.append(tip); }
    return tip;
  }

  function showTip(panel, cell, entry, checks, lang) {
    const l = STR[lang], tip = tipFor(panel);
    tip.replaceChildren();
    const head = el("div", "lz-tip-head");
    head.append(el("b", "", pick(entry.name, lang) || entry.id), el("span", `lz-tip-st ${stateOf(entry)}`, l.st[entry.status] || entry.status));
    const x = el("button", "lz-tip-x", "×"); x.type = "button"; x.setAttribute("aria-label", l.close);
    x.addEventListener("click", () => { tip.hidden = true; });
    head.append(x);
    tip.append(head);
    const dl = el("dl");
    const add = (k, v) => { if (!v) return; dl.append(el("dt", "", k)); const d = el("dd", "", v); d.dir = "auto"; dl.append(d); };
    add(l.checks, checks);
    add(l.result, pick(entry.detail, lang));
    const expert = document.documentElement.dataset.explain === "expert";
    add(l.source, expert ? entry.source : plainSource(entry.source, l));
    if (expert && entry.signal != null) add(`${l.weight} · ${l.conf}`, `${Number(entry.weight).toFixed(1)} · ${Math.round(Number(entry.confidence) * 100)}%`);
    tip.append(dl);
    tip.hidden = false;
    const pr = panel.getBoundingClientRect(), cr = cell.getBoundingClientRect();
    const w = Math.min(300, pr.width - 16);
    tip.style.width = `${w}px`;
    let left = cr.left - pr.left + cr.width / 2 - w / 2;
    left = Math.max(8, Math.min(pr.width - w - 8, left));
    tip.style.left = `${left}px`;
    tip.style.top = `${cr.bottom - pr.top + 8}px`;
  }

  // "detection.url_intel" → "Link reputation check": the module's plain name, or its last word spelled out
  function plainSource(src, l) {
    const s = String(src || "");
    if (!s || /\s/.test(s)) return s;
    const last = s.split(".").pop().toLowerCase();
    return (l.srcPlain && l.srcPlain[last]) || last.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
  }

  function statChip(cls, n, label) { const s = el("span", `lz-stat ${cls}`); s.append(el("b", "", String(n)), el("small", "", label)); return s; }

  /* The panel for one result (scan page and report). opts: {animate, checks: Map(id -> {en, ar})} */
  function panelFor(layers, lang, opts) {
    const l = STR[lang], sum = layers.summary || {}, entries = layers.layers || [];
    const card = el("section", "card lz-card");
    card.setAttribute("aria-labelledby", "lz-title");
    const head = el("div", "lz-head");
    const ht = el("div");
    const h = el("h3", "", l.title); h.id = "lz-title";
    ht.append(h, el("p", "rc-note", fill(l.note, { n: sum.total || entries.length })));
    const scoreBox = el("div", `lz-score ${sum.score == null ? "none" : sum.score >= 50 ? "hi" : sum.score >= 20 ? "mid" : "lo"}`);
    scoreBox.append(el("small", "", l.score), el("b", "", sum.score == null ? "–" : String(sum.score)), el("span", "", sum.score == null ? l.noScore : "/100"));
    head.append(ht, scoreBox);
    card.append(head);
    const stats = el("div", "lz-stats");
    stats.append(statChip("a", sum.applicable ?? "–", l.applied), statChip("s1", sum.suspicious ?? 0, l.sus), statChip("s0", sum.clean ?? 0, l.ok),
      statChip("na", sum.not_applicable ?? 0, l.na), statChip("un", sum.unavailable ?? 0, l.un));
    if (sum.privacy_flags) stats.append(statChip("pv", sum.privacy_flags, l.priv));
    card.append(stats);
    if (sum.effect && (sum.effect.en || sum.effect.ar)) {
      const eff = el("p", `lz-effect${sum.effect.applied ? " moved" : ""}`);
      eff.append(el("b", "", `${l.effect}: `), document.createTextNode(pick(sum.effect, lang)));
      eff.dir = "auto";
      card.append(eff);
    }
    const g = buildGrid(entries, sum.categories, lang);
    const byId = new Map(entries.map((e) => [e.id, e]));
    const wrap = el("div", "lz-grid-wrap");
    wrap.append(g.root);
    card.append(wrap);
    const legend = el("div", "lz-legend"); legend.setAttribute("aria-hidden", "true");
    [["s1", l.legendS], ["s0", l.legendC], ["na", l.legendN]].forEach(([c, t]) => { const s = el("span"); s.append(el("i", `lz-cell ${c}`), document.createTextNode(t)); legend.append(s); });
    card.append(legend);
    // paint: at once, or in quick batches (a sweep) when the result is new and motion is allowed
    const order = entries.filter((e) => e.status !== "not_applicable").concat(entries.filter((e) => e.status === "not_applicable"));
    if (opts && opts.animate && !reduced()) {
      let i = 0;
      const step = () => { const end = Math.min(order.length, i + 9); for (; i < end; i++) paint(g.cells.get(order[i].id), stateOf(order[i]), order[i].status !== "not_applicable"); if (i < order.length) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    } else {
      order.forEach((e) => paint(g.cells.get(e.id), stateOf(e), false));
    }
    // tap / hover detail (the grid itself is hidden from screen readers: the list below says the same)
    const checksOf = (id) => {
      const m = opts && (typeof opts.checks === "function" ? opts.checks() : opts.checks);
      const c = m && m.get(id);
      return c ? pick(c, lang) : "";
    };
    const open = (target) => { const cell = target.closest && target.closest(".lz-cell"); if (!cell || !cell.dataset.id) return; const e = byId.get(cell.dataset.id); if (e) showTip(card, cell, e, checksOf(e.id), lang); };
    g.root.addEventListener("click", (ev) => open(ev.target));
    g.root.addEventListener("pointerover", (ev) => { if (ev.pointerType === "mouse") open(ev.target); });
    card.addEventListener("keydown", (ev) => { if (ev.key === "Escape") tipFor(card).hidden = true; });
    // the formula
    if (sum.formula) {
      const f = el("details", "lz-formula");
      f.append(el("summary", "", l.formula));
      const p = el("p", "lz-math", pick(sum.formula, lang)); p.dir = "auto";
      f.append(p, el("p", "rc-note", l.formulaNote));
      if (sum.effect && sum.effect.rule) { const r = el("p", "rc-note", pick(sum.effect.rule, lang)); r.dir = "auto"; f.append(r); }
      if (sum.log_odds != null) f.append(el("p", "lz-math", `L = ${sum.log_odds} · Σw·c(1) = ${sum.suspicious_weight} · Σw·c(0) = ${sum.clean_weight} · Σw = ${sum.answer_weight}`));
      card.append(f);
    }
    // the same results as a list (screen readers, keyboard, print)
    const det = el("details", "lz-list");
    det.append(el("summary", "", l.list));
    groupsOf(entries).forEach(([cat, list]) => {
      det.append(el("h4", "", pick(sum.categories && sum.categories[cat], lang) || cat));
      const ul = el("ul");
      list.forEach((e) => {
        const li = el("li", `lz-li ${stateOf(e)}`);
        li.append(el("b", "", pick(e.name, lang) || e.id), document.createTextNode(` — ${l.st[e.status] || e.status}`));
        if (e.status !== "not_applicable") { const d = el("span", "", `: ${pick(e.detail, lang)}`); d.dir = "auto"; li.append(d); }
        ul.append(li);
      });
      det.append(ul);
    });
    card.append(det);
    return card;
  }

  // one listener for every panel: a tap outside closes the open detail
  document.addEventListener("click", (ev) => {
    document.querySelectorAll(".lz-card .lz-tip:not([hidden])").forEach((tip) => { if (!tip.parentNode.contains(ev.target)) tip.hidden = true; });
  });
  document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") document.querySelectorAll(".lz-tip").forEach((t) => { t.hidden = true; }); });

  /* ------------------------------------------------------------ the profile (5 questions) */
  function guessDevice() {
    const ua = navigator.userAgent || "";
    if (/Android|iPhone|iPad|Mobile/i.test(ua)) return "phone";
    if (/Mac OS X|Macintosh/i.test(ua)) return "mac";
    if (/Linux|X11/i.test(ua)) return "linux";
    return "windows";
  }
  function loadProfile() {
    try { const p = JSON.parse(store.get(PROFILE_KEY) || "null"); return p && typeof p === "object" ? p : null; } catch { return null; }
  }
  const defaults = () => ({ tech: "some", checks: "personal", device: guessDevice(), detail: "balanced", tone: "calm" });
  function profileWords(p, lang) {
    const q = STR[lang].q, w = (key) => { const row = q.find((x) => x[0] === key); const o = row && row[2].find((x) => x[0] === p[key]); return o ? o[1] : ""; };
    return [w("tech"), w("device"), w("checks"), w("detail"), w("tone")].filter(Boolean).join(" · ");
  }

  function surveyForm(initial, opts) {
    const l = L(), lang = langOf();
    const form = el("form", "lz-survey");
    form.noValidate = true;
    form.append(el("p", "rc-note", l.qIntro));
    const p = { ...defaults(), ...(initial || {}) };
    l.q.forEach(([key, question, options], qi) => {
      const fs = el("fieldset", "lz-q");
      fs.append(el("legend", "", `${qi + 1}. ${question}`));
      const row = el("div", "lz-chips");
      options.forEach(([value, label]) => {
        const lab = el("label", "lz-chip");
        const input = el("input"); input.type = "radio"; input.name = `lz-${key}-${opts.uid}`; input.value = value; input.checked = p[key] === value;
        lab.append(input, el("span", "", label));
        row.append(lab);
      });
      fs.append(row);
      form.append(fs);
    });
    const actions = el("div", "lz-q-actions");
    const save = el("button", "primary", opts.saveLabel || l.qSave); save.type = "submit";
    actions.append(save);
    if (opts.onSkip) { const skip = el("button", "ghost", opts.skipLabel || l.qSkip); skip.type = "button"; skip.addEventListener("click", opts.onSkip); actions.append(skip); }
    form.append(actions);
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const out = {};
      l.q.forEach(([key]) => { const c = form.querySelector(`input[name="lz-${key}-${opts.uid}"]:checked`); out[key] = c ? c.value : p[key]; });
      store.set(PROFILE_KEY, JSON.stringify({ ...out, v: 1 }));
      window.dispatchEvent(new CustomEvent("cs:profile", { detail: out }));
      opts.onSave(out);
    });
    form.lang = lang;
    return form;
  }

  /* ------------------------------------------------------------ the summary written for the reader */
  function contextOf(r) {
    const v = CS.verdictOf(r), lang = langOf();
    const lay = r.layers && r.layers.summary;
    const suspicious = r.layers ? (r.layers.layers || []).filter((e) => e.signal === 1 && e.affects_score !== false)
      .sort((a, b) => b.weight * b.confidence - a.weight * a.confidence).map((e) => pick(e.name, lang)) : [];
    return {
      verdict: v.cls, score: v.score, mode: CS.modeOf(r),
      type: CS.modeOf(r) === "file" ? String((r.content_analysis && r.content_analysis.file_type) || "") : "",
      findings: CS.findingsOf(r).slice(0, 6).map((f) => ({ title: f.title, severity: f.sev, weight: f.contrib })),
      layers: lay ? { score: lay.score, suspicious: lay.suspicious, clean: lay.clean, answered: lay.answered, applicable: lay.applicable,
        total: lay.total, privacy: lay.privacy_flags, top: suspicious.slice(0, 5), categories: lay.suspicious_categories || [] } : undefined,
    };
  }

  let uid = 0;
  const summaries = new WeakMap();   // result -> (profile + language -> answer): a language switch re-asks, a re-render doesn't
  const animated = new WeakSet();    // results whose grid already swept in once
  function summaryCard(r) {
    const l = L();
    const card = el("section", "card lz-ai");
    card.setAttribute("aria-live", "polite");
    const head = el("div", "lz-ai-head");
    head.append(el("h3", "", l.sumTitle));
    card.append(head);
    const body = el("div", "lz-ai-body");
    card.append(body);
    const showSurvey = (initial, skippable) => {
      uid += 1;
      const form = surveyForm(initial, {
        uid,
        onSave: (p) => write(p),
        onSkip: skippable ? () => { store.set(SKIP_KEY, "1"); write(null); } : () => write(loadProfile()),
        skipLabel: skippable ? l.qSkip : l.qCancel,
      });
      body.replaceChildren(form);
      const first = form.querySelector("input:checked") || form.querySelector("input");
      if (first && skippable) first.focus({ preventScroll: true });
    };
    const write = (profile) => {
      const lang = langOf();
      body.replaceChildren(el("p", "lz-ai-loading", l.sumLoading));
      const used = profile || defaults();
      const key = JSON.stringify([lang, used.tech, used.checks, used.device, used.detail, used.tone]);
      const memo = summaries.get(r) || new Map();
      summaries.set(r, memo);
      if (!memo.has(key)) memo.set(key, CS.postJSON("/api/assistant/summary", { context: contextOf(r), profile: used, lang }));
      memo.get(key).then((out) => {
        body.replaceChildren();
        const p = el("p", "lz-ai-text", out.text || ""); p.dir = "auto";
        body.append(p);
        if (Array.isArray(out.steps) && out.steps.length) {
          body.append(el("h4", "", l.steps));
          const ol = el("ol", "lz-ai-steps");
          out.steps.forEach((s) => { const li = el("li", "", s); li.dir = "auto"; ol.append(li); });
          body.append(ol);
        }
        const foot = el("div", "lz-ai-foot");
        const who = el("span", "lz-ai-who");
        who.append(el("b", "", `${l.writtenFor}: `), document.createTextNode(profileWords(out.profile || used, lang)));
        const src = el("small", "lz-ai-src", out.source === "local" ? l.srcLocal : l.srcAI);
        const change = el("button", "ghost small", loadProfile() ? l.change : l.tailor); change.type = "button";
        change.addEventListener("click", () => showSurvey(loadProfile() || used, false));
        foot.append(who, change, src);
        body.append(foot);
      }).catch(() => { memo.delete(key); body.replaceChildren(el("p", "lz-ai-loading", l.sumFail)); });
    };
    write(loadProfile());
    return card;
  }

  /* ------------------------------------------------------------ Settings: edit the profile */
  function settingsCard() {
    const host = document.querySelector("#view-settings .settings");
    if (!host) return;
    let box = host.querySelector(".lz-settings");
    const l = L(), lang = langOf();
    if (!box) { box = el("div", "lz-settings"); host.append(box); }
    box.replaceChildren(el("h3", "", l.setTitle));
    const p = loadProfile();
    const line = el("p", "rc-note", p ? profileWords(p, lang) : l.setNone);
    const edit = el("button", "ghost small", l.setEdit); edit.type = "button";
    edit.addEventListener("click", () => {
      uid += 1;
      const form = surveyForm(loadProfile(), { uid, saveLabel: l.qSaveOnly, onSave: () => { settingsCard(); CS.toast && CS.toast(l.saved); }, onSkip: () => settingsCard(), skipLabel: l.qCancel });
      box.replaceChildren(el("h3", "", l.setTitle), form);
    });
    box.append(line, edit);
  }

  /* ------------------------------------------------------------ wiring */
  let catalogChecks = null;
  if (onScanPage) {
    window.addEventListener("cs:scan-start", startLive);
    window.addEventListener("cs:job", (e) => onJob(e.detail));
    window.addEventListener("cs:rc-built", (e) => {
      const { rc, result: r } = e.detail || {};
      if (!rc || !r) return;
      const sum = rc.querySelector(".rc-sum");
      // the summary written for the reader, at the top
      const ai = summaryCard(r);
      if (sum) sum.before(ai); else rc.prepend(ai);
      if (!r.layers || !Array.isArray(r.layers.layers)) return;
      const lang = langOf();
      const build = () => {
        const card = panelFor(r.layers, lang, { animate: !animated.has(r), checks: () => catalogChecks });
        animated.add(r);
        const old = rc.querySelector(".lz-card");
        if (old) old.replaceWith(card); else if (sum) sum.after(card); else rc.append(card);
      };
      build();
      // "what each layer checks" comes from the catalog (fetched once)
      if (!catalogChecks) catalog().then((cat) => { if (cat) { catalogChecks = new Map(cat.layers.map((x) => [x.id, x.checks])); } });
      // "Why this result?" (js/result-plus.js) documents the layered score and its formula too
      const why = rc.querySelector(".rp-why .rp-why-body") || rc.querySelector(".rp-why");
      const s = r.layers.summary || {};
      if (why && s.formula && !why.querySelector(".lz-why")) {
        const box = el("div", "lz-why x-only");
        box.append(el("h4", "", `${STR[lang].score}: ${s.score == null ? "–" : s.score}/100`));
        const p = el("p", "rc-note", pick(s.formula, lang)); p.dir = "auto";
        box.append(p);
        if (s.effect) { const q = el("p", "rc-note", pick(s.effect, lang)); q.dir = "auto"; box.append(q); }
        why.append(box);
      }
    });
    // the live grid hides with the progress card; the settings card follows the language
    const ready = () => settingsCard();
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready); else ready();
    if (CS.onLang) CS.onLang(() => settingsCard());
    window.addEventListener("cs:profile", () => settingsCard());
  }

  /* ------------------------------------------------------------ report.html */
  window.CSLayers = {
    renderStatic(container, layers, lang) {
      if (!container || !layers || !Array.isArray(layers.layers)) return null;
      const card = panelFor(layers, lang === "ar" ? "ar" : "en", { animate: false });
      card.classList.add("lz-static");
      card.querySelector(".lz-list").open = true;   // printed reports show every layer
      container.append(card);
      return card;
    },
  };
})();
