/* The trust pages: the English / Arabic switch, and the live parts of /status and /tests.
 * /status reads /api/health (this server instance) and /api/protection (rules and known-malware
 * hashes) every 30 s; /tests reads data/bench.json, written by tools/bench_engine.py. */
(function () {
  "use strict";
  const root = document.documentElement;
  const $ = (id) => document.getElementById(id);
  const lang = () => (root.lang === "ar" ? "ar" : "en");
  const token = (document.querySelector('meta[name="cyberscan-token"]') || {}).content || "";
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined && text !== null) n.textContent = String(text); return n; };

  const L = {
    en: {
      other: "العربية", up: "All systems working", down: "The server did not answer", checking: "Checking…",
      version: "Website version", released: "released", uptime: "Server instance uptime", uptimeHint: "since this instance started (online, AWS Lambda starts instances on demand)",
      latency: "Response time", latencyHint: "health check from your browser, just now",
      rules: "YARA rules", rulesHint: (f, b) => `${f} YARA-Forge + ${b} built-in`, hashes: "Known-malware hashes", phishing: "Phishing domains", urlhaus: "Malware links (URLhaus)",
      secrets: "Secret-detection rules", updated: "Threat lists last updated", hashesUpdated: "Hash list last updated", never: "not yet",
      mode: "Mode", checked: "Last checked", engines: "Engines", available: "available", missing: "not available",
      d: "d", h: "h", m: "m", s: "s",
      fpTitle: "False alarms on clean files", fpSusp: "called “Suspicious”", fpAny: "got at least a “take a look” note", files: "clean files scanned",
      median: "median time per file", p95: "95% of files finished within", group: "Group", n: "Files", susp: "Suspicious", review: "Take a look", clean: "Nothing found",
      sample: "Synthetic sample", expected: "Expected", result: "Result", flag: "a warning", cleanW: "no warning", pass: "as expected", fail: "missed",
      synthLine: (a, b, c, d) => `${a} of ${b} attack-shaped samples were flagged; ${c} of ${d} clean samples stayed clean.`,
      reasons: "Most common reason for a “take a look” note on a clean file", count: "Files",
      generated: "Measured", on: "on", engine: "engine", machine: "machine", unavailable: "The measurements file could not be loaded.",
    },
    ar: {
      other: "English", up: "كل الأنظمة تعمل", down: "لم يستجب الخادم", checking: "جارٍ الفحص…",
      version: "إصدار الموقع", released: "صدر في", uptime: "مدة تشغيل نسخة الخادم", uptimeHint: "منذ بدء هذه النسخة (على الإنترنت يشغّل AWS Lambda النسخ عند الحاجة)",
      latency: "زمن الاستجابة", latencyHint: "فحص من متصفحك الآن",
      rules: "قواعد YARA", rulesHint: (f, b) => `${f} من YARA-Forge و${b} مدمجة`, hashes: "بصمات برمجيات خبيثة معروفة", phishing: "نطاقات تصيّد", urlhaus: "روابط برمجيات خبيثة (URLhaus)",
      secrets: "قواعد كشف الأسرار", updated: "آخر تحديث لقوائم التهديدات", hashesUpdated: "آخر تحديث لقائمة البصمات", never: "ليس بعد",
      mode: "الوضع", checked: "آخر فحص", engines: "المحركات", available: "متاح", missing: "غير متاح",
      d: "ي", h: "س", m: "د", s: "ث",
      fpTitle: "الإنذارات الكاذبة على ملفات نظيفة", fpSusp: "وُصفت بأنها «مشبوهة»", fpAny: "حصلت على ملاحظة «يستحق نظرة» على الأقل", files: "ملفًا نظيفًا فُحص",
      median: "الوقت الوسيط لكل ملف", p95: "انتهى 95% من الملفات خلال", group: "المجموعة", n: "الملفات", susp: "مشبوه", review: "يستحق نظرة", clean: "لا شيء",
      sample: "عينة اصطناعية", expected: "المتوقع", result: "النتيجة", flag: "تحذير", cleanW: "بلا تحذير", pass: "كما هو متوقع", fail: "فاتته",
      synthLine: (a, b, c, d) => `نُبّه إلى ${a} من ${b} عينات على شكل هجوم، وبقيت ${c} من ${d} عينات نظيفة بلا تحذير.`,
      reasons: "أكثر أسباب ملاحظة «يستحق نظرة» على ملف نظيف", count: "الملفات",
      generated: "تاريخ القياس", on: "على", engine: "المحرك", machine: "الجهاز", unavailable: "تعذّر تحميل ملف القياسات.",
    },
  };
  const t = (k, ...a) => { const v = L[lang()][k]; return typeof v === "function" ? v(...a) : v; };
  const num = (n) => (typeof n === "number" ? n.toLocaleString(lang() === "ar" ? "ar-SA-u-nu-latn" : "en-US") : "—");
  const pct = (x) => (typeof x === "number" ? `${(x * 100).toFixed(1)}%` : "—");
  const when = (iso) => { if (!iso) return t("never"); const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString(lang() === "ar" ? "ar-SA-u-nu-latn-ca-gregory" : "en-GB", { dateStyle: "medium", timeStyle: "short" }); };

  /* ---------------- language switch ---------------- */
  const btn = $("tr-lang");
  const listeners = [];
  function applyLang() {
    if (btn) { btn.textContent = t("other"); btn.lang = lang() === "ar" ? "en" : "ar"; }
    const title = document.body.dataset[lang() === "ar" ? "titleAr" : "titleEn"];
    if (title) document.title = title;
    listeners.forEach((fn) => fn());
  }
  if (btn) btn.addEventListener("click", () => {
    const next = lang() === "ar" ? "en" : "ar";
    root.lang = next; root.dir = next === "ar" ? "rtl" : "ltr";
    try { localStorage.setItem("cyberscan-lang", next); } catch { /* storage off */ }
    applyLang();
  });

  /* ---------------- /status ---------------- */
  const status = $("st-root");
  if (status) {
    let health = null, prot = null, ms = null, failed = false, checked = null;
    const stat = (label, value, hint, cls) => {
      const c = el("div", `tr-stat${cls ? " " + cls : ""}`); const v = el("b"); v.append(el("bdi", "", value));
      c.append(v, el("span", "", label)); if (hint) c.append(el("span", "", hint)); return c;
    };
    function dur(s) {
      if (typeof s !== "number") return "—";
      const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
      const u = (n, k) => (lang() === "ar" ? `${n} ${t(k)}` : `${n}${t(k)}`);
      return d ? `${u(d, "d")} ${u(h, "h")}` : h ? `${u(h, "h")} ${u(m, "m")}` : `${u(m, "m")} ${u(s % 60, "s")}`;
    }
    function render() {
      const light = $("st-light");
      light.className = `tr-light ${failed ? "bad" : health ? "ok" : "wait"}`;
      light.textContent = failed ? t("down") : health ? t("up") : t("checking");
      $("st-checked").textContent = checked ? `${t("checked")}: ${checked.toLocaleTimeString(lang() === "ar" ? "ar-SA-u-nu-latn" : "en-GB")}` : "";
      const grid = $("st-grid");
      grid.replaceChildren();
      if (health) {
        grid.append(stat(t("version"), health.version || "—", health.released ? `${t("released")} ${health.released}${health.commit ? ` · ${health.commit}` : ""}` : ""));
        grid.append(stat(t("uptime"), dur(health.uptime_s), t("uptimeHint")));
        grid.append(stat(t("latency"), ms === null ? "—" : `${ms} ms`, t("latencyHint"), ms !== null && ms < 800 ? "ok" : "warn"));
      }
      if (prot) {
        grid.append(stat(t("rules"), num((prot.forge_rules || 0) + (prot.bundled_rules || 0)), t("rulesHint", num(prot.forge_rules || 0), num(prot.bundled_rules || 0))));
        grid.append(stat(t("hashes"), num(prot.malware_hashes), `${t("hashesUpdated")}: ${when(prot.hashes_updated)}`));
        grid.append(stat(t("phishing"), num(prot.phishing)));
        grid.append(stat(t("urlhaus"), num(prot.urlhaus)));
        grid.append(stat(t("secrets"), num(prot.secret_rules)));
        grid.append(stat(t("updated"), when(prot.updated), "", "date"));
      }
    }
    async function check() {
      const t0 = performance.now();
      try {
        const r = await fetch("/api/health", { cache: "no-store" });
        if (!r.ok) throw new Error(String(r.status));
        health = await r.json();
        ms = Math.round(performance.now() - t0);
        failed = false;
      } catch { failed = true; health = null; ms = null; }
      try {
        const r = await fetch("/api/protection", { cache: "no-store", headers: { "X-CyberScan-Token": token } });
        if (r.ok) prot = await r.json();
      } catch { /* keep the last numbers */ }
      checked = new Date();
      render();
    }
    listeners.push(render);
    render();
    check();
    setInterval(() => { if (!document.hidden) check(); }, 30000);
  }

  /* ---------------- /tests ---------------- */
  const tests = $("tests-root");
  if (tests) {
    let data = null, error = false;
    const GROUPS_AR = {
      "PE binaries (.pyd/.dll from .venv packages)": "برامج Windows (‎.pyd/.dll من حزم .venv)",
      "Python source (.venv packages)": "شيفرة Python (حزم .venv)",
      "Data and text (.json/.txt/.md/.toml/.cfg)": "بيانات ونصوص (‎.json/.txt/.md/.toml/.cfg)",
      "Website code (.js/.css/.html)": "شيفرة الموقع (‎.js/.css/.html)",
      "Images, fonts and audio": "صور وخطوط وصوت",
      "Archives and documents (.zip/.whl/.pdf)": "أرشيفات ومستندات (‎.zip/.whl/.pdf)",
    };
    function render() {
      const out = $("tests-live");
      out.replaceChildren();
      if (error || !data) { if (error) out.append(el("p", "", t("unavailable"))); return; }
      const b = data.benign, sp = data.speed, sy = data.synthetic;
      const grid = el("div", "tr-grid");
      const stat = (v, label, cls) => { const c = el("div", `tr-stat${cls ? " " + cls : ""}`); const b = el("b"); b.append(el("bdi", "", v)); c.append(b, el("span", "", label)); return c; };
      grid.append(stat(num(b.files), t("files")), stat(`${num(b.suspicious)} · ${pct(b.fp_suspicious_rate)}`, t("fpSusp"), b.suspicious ? "warn" : "ok"),
        stat(`${num(b.suspicious + b.review)} · ${pct(b.fp_any_rate)}`, t("fpAny"), "warn"),
        stat(`${sp.median_s}s`, t("median")), stat(sp.p95_s !== null ? `${sp.p95_s}s` : "—", t("p95")));
      out.append(grid);

      const card = el("section", "tr-card");
      card.append(el("h2", "", t("fpTitle")));
      const wrap = el("div", "tr-table-wrap"); const table = el("table", "tr-table");
      const head = el("tr"); [t("group"), t("n"), t("susp"), t("review"), t("clean")].forEach((h, i) => { const th = el("th", i ? "num" : "", h); th.scope = "col"; head.append(th); });
      table.append(el("thead")); table.tHead.append(head);
      const body = el("tbody");
      Object.entries(b.groups).forEach(([name, g]) => {
        const tr = el("tr");
        tr.append(el("td", "", lang() === "ar" ? GROUPS_AR[name] || name : name), el("td", "num", num(g.files)), el("td", "num", num(g.suspicious)), el("td", "num", num(g.review)), el("td", "num", num(g.clean)));
        body.append(tr);
      });
      table.append(body); wrap.append(table); card.append(wrap);
      if (b.top_reasons && b.top_reasons.length) {
        card.append(el("h3", "", t("reasons")));
        const ul = el("ul");
        b.top_reasons.forEach(([why, n]) => { const li = el("li"); const c = el("code", "", why); c.lang = "en"; li.append(c, ` × ${num(n)}`); ul.append(li); });
        card.append(ul);
      }
      out.append(card);

      const sc = el("section", "tr-card");
      sc.append(el("h2", "", t("sample")));
      sc.append(el("p", "", t("synthLine", sy.flagged_of_expected[0], sy.flagged_of_expected[1], sy.clean_of_expected[0], sy.clean_of_expected[1])));
      const w2 = el("div", "tr-table-wrap"); const t2 = el("table", "tr-table");
      const h2 = el("tr"); [t("sample"), t("expected"), t("result"), ""].forEach((h) => { const th = el("th", "", h); th.scope = "col"; h2.append(th); });
      t2.append(el("thead")); t2.tHead.append(h2);
      const b2 = el("tbody");
      sy.samples.forEach((s) => {
        const tr = el("tr"); const name = el("td", "", s.name); name.lang = "en";
        const verdict = el("td"); const code = el("code", "", `${s.classification} · ${s.score}`); code.lang = "en"; verdict.append(code);
        const ok = el("td"); ok.append(el("span", `tr-pill ${s.ok ? "ok" : "bad"}`, s.ok ? t("pass") : t("fail")));
        tr.append(name, el("td", "", s.expected === "flag" ? t("flag") : t("cleanW")), verdict, ok);
        b2.append(tr);
      });
      t2.append(b2); w2.append(t2); sc.append(w2);
      out.append(sc);
      $("tests-stamp").textContent = `${t("generated")}: ${when(data.generated)} · ${t("engine")} ${data.engine} · ${t("machine")}: ${data.machine}`;
    }
    listeners.push(render);
    fetch("data/bench.json", { cache: "no-cache" }).then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d) => { data = d; render(); }).catch(() => { error = true; render(); });
  }

  applyLang();
})();
