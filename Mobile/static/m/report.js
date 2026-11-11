/* Export a result as a standalone HTML page, plain text or JSON.
 * The HTML page has no scripts and loads nothing from the network. */
(function () {
  "use strict";
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const TONE = { ok: "#1f9d6a", warn: "#b7791f", danger: "#d22d4b", neutral: "#5b6478", info: "#1d7fa8" };
  const SEV = { critical: "#d22d4b", high: "#d22d4b", medium: "#b7791f", low: "#1d7fa8", info: "#5b6478" };

  const W = {
    en: { title: "CyberScan report", score: "Risk score", found: "What we found", none: "No warning signs.", details: "Details", fps: "Fingerprints", yara: "Known-pattern rules (YARA)", pe: "Program details", sections: "Sections", imports: "Unusual imports", checks: "Checks", engines: "Engines", mitre: "MITRE ATT&CK", lookups: "Public threat lists", made: "Made on the phone with CyberScan · nothing was uploaded", when: "Checked", limits: "Limits" },
    ar: { title: "تقرير CyberScan", score: "درجة الخطورة", found: "ما وجدناه", none: "لا توجد علامات تحذير.", details: "التفاصيل", fps: "البصمات", yara: "قواعد الأنماط المعروفة (YARA)", pe: "تفاصيل البرنامج", sections: "الأقسام", imports: "استدعاءات غير معتادة", checks: "الفحوصات", engines: "المحركات", mitre: "MITRE ATT&CK", lookups: "قوائم التهديدات العامة", made: "أُنشئ على الهاتف باستخدام CyberScan · لم يُرفع أي شيء", when: "وقت الفحص", limits: "الحدود" },
  };

  function html(r, lang, verdictName, lookups) {
    const w = W[lang] || W.en, p = (r.plain && (r.plain[lang] || r.plain.en)) || null, s = p && p.summary;
    const tone = TONE[s && s.tone] || "#1d7fa8";
    const sec = (title, body) => (body ? `<section><h2>${esc(title)}</h2>${body}</section>` : "");
    const list = (items) => (items.length ? `<ul>${items.join("")}</ul>` : "");
    const findings = p ? p.details.findings : [];
    const fp = r.fingerprints || (r.sha256 ? { sha256: r.sha256 } : null);
    const parts = [
      sec(w.found, findings.length
        ? list(findings.map((f) => `<li style="border-color:${SEV[f.severity] || "#5b6478"}"><b>${esc(f.title)}${f.count > 1 ? ` ×${f.count}` : ""}</b>${f.body && f.body !== f.title ? `<span>${esc(f.body)}</span>` : ""}</li>`))
        : `<p>${esc(w.none)}</p>`),
      sec(w.yara, list((r.yara || []).map((y) => `<li><b>${esc(y.rule_name)}</b><span>${esc(y.description)}</span><code>${esc((y.matched_strings || []).join("  "))}</code></li>`))),
      sec(w.lookups, list((lookups || []).map((l) => `<li><b>${esc(l.source)}: ${esc(l.label)}</b>${l.detail ? `<span>${esc(l.detail)}</span>` : ""}</li>`))),
      sec(w.details, p && p.details.facts.length ? `<dl>${p.details.facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : ""),
      sec(w.fps, fp ? `<dl>${Object.entries(fp).map(([k, v]) => `<dt>${esc(k.toUpperCase())}</dt><dd><code>${esc(v)}</code></dd>`).join("")}</dl>` : ""),
      sec(w.pe, r.pe ? `<dl>${[["Machine", r.pe.machine], ["Subsystem", r.pe.subsystem], ["Timestamp", r.pe.timestamp], ["Imports", r.pe.import_count]].filter(([, v]) => v != null).map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
        ${(r.pe.sections || []).length ? `<h3>${esc(w.sections)}</h3><table>${r.pe.sections.map((x) => `<tr><td><code>${esc(x.name)}</code></td><td>${esc(x.entropy)}</td><td>${esc(x.size)}</td></tr>`).join("")}</table>` : ""}
        ${(r.pe.suspicious_imports || []).length ? `<h3>${esc(w.imports)}</h3><p><code>${r.pe.suspicious_imports.map(esc).join(", ")}</code></p>` : ""}` : ""),
      sec(w.checks, list(((p && p.details.checks) || []).map((c) => `<li><b>${esc(c.symbol)} ${esc(c.name)}</b><span>${esc(c.reason || c.state)}</span></li>`))),
      sec(w.engines, list(Object.entries(r.engines || {}).map(([k, v]) => `<li><b>${esc(k)}</b><span>${esc(v)}</span></li>`))),
      sec(w.mitre, list((r.mitre || []).map((m) => `<li><b>${esc(m.id)}</b><span>${esc(m.name || "")}</span></li>`))),
      sec(w.limits, r.limitations ? `<p>${esc(r.limitations)}</p>` : ""),
    ].join("");
    return `<!doctype html>
<html lang="${lang}" dir="${lang === "ar" ? "rtl" : "ltr"}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(w.title)} · ${esc(r.target)}</title>
<style>
body{margin:0;background:#f6f7fb;color:#151a2d;font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans Arabic",Tahoma,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 18px 40px}
header{background:#0b0824;color:#eef6ff;border-radius:18px;padding:22px;display:grid;gap:6px}
header small{color:#97a3c6}
.score{display:flex;align-items:center;gap:16px}
.score b{font-size:44px;line-height:1;color:${tone}}
.badge{display:inline-block;padding:3px 12px;border-radius:99px;background:${tone};color:#fff;font-weight:700;font-size:12px;letter-spacing:.06em}
h1{font-size:22px;margin:4px 0 0}
section{background:#fff;border:1px solid #e3e6ef;border-radius:14px;padding:14px 16px;margin-top:14px}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:#5b6478;margin:0 0 8px}
[dir=rtl] h2{text-transform:none;letter-spacing:0}
h3{font-size:13px;margin:12px 0 6px}
ul{list-style:none;margin:0;padding:0;display:grid;gap:8px}
li{border-inline-start:3px solid #c9cfdd;padding-inline-start:10px}
li b{display:block}
li span{color:#5b6478}
dl{display:grid;grid-template-columns:38% 1fr;gap:6px 12px;margin:0}
dt{color:#5b6478}
dd{margin:0;overflow-wrap:anywhere}
code{font:12.5px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere;direction:ltr;unicode-bidi:plaintext}
table{border-collapse:collapse;width:100%}
td{border-top:1px solid #eef0f5;padding:4px 6px}
.target{font:13px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere;direction:ltr;unicode-bidi:plaintext;color:#cfd8ec}
footer{color:#5b6478;font-size:12px;text-align:center;margin-top:20px}
@media print{body{background:#fff}header{background:#fff;color:#000;border:1px solid #ccc}section{break-inside:avoid}}
</style></head><body><main>
<header>
  <small>${esc(w.title)}</small>
  <div class="score"><b>${esc(r.combined_score)}</b><div><span class="badge">${esc(verdictName)}</span><h1>${esc(s ? s.headline : r.classification)}</h1></div></div>
  <p>${esc(s ? s.sentence : r.summary)}</p>
  ${s && s.advice ? `<p><b>${esc(s.advice)}</b></p>` : ""}
  <div class="target">${esc(r.target)}</div>
  <small>${esc(w.when)}: ${esc(new Date(r.when || Date.now()).toLocaleString(lang))}</small>
</header>
${parts}
<footer>${esc(w.made)}</footer>
</main></body></html>`;
  }

  function json(r, lookups) {
    const out = { ...r, lookups: lookups || undefined, exported_by: "CyberScan for Android", exported_at: new Date().toISOString() };
    return JSON.stringify(out, null, 2);
  }

  function text(r) { return r.report_text || JSON.stringify(r, null, 2); }

  function fileName(r, ext) {
    const base = String(r.target || "report").split(/[\\/]/).pop().replace(/[^\w.\-]+/g, "_").slice(0, 60) || "report";
    const stamp = new Date(r.when || Date.now()).toISOString().slice(0, 16).replace(/[:T]/g, "-");
    return `cyberscan-${base}-${stamp}.${ext}`;
  }

  window.CSReport = { html, json, text, fileName };
})();
