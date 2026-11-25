/* "Watch this file's journey": a small bridge from the scan result to the File Journey (journey.html).
 *
 * Listens to "cs:rc-built" (js/scan-center.js, after the results center renders a result), keeps a compact,
 * privacy-light summary of the scanned file in sessionStorage "cs-journey-file" and adds one button under
 * the result. The journey reads the summary (or the same payload in ?f=<base64url JSON>) and tells that
 * file's story: its name, its real parts, its entropy curve, the rules that matched, its real verdict.
 * The summary holds no file contents beyond the first 16 bytes (the magic signature), read locally from
 * the file the visitor picked; nothing is sent anywhere. Only files: a link or a text has no journey. */
(function () {
  "use strict";
  const KEY = "cs-journey-file";
  const T = {
    en: { watch: "Watch this file's journey", hint: "Follow this file from its first byte to its verdict, in 3D." },
    ar: { watch: "شاهد رحلة هذا الملف", hint: "تابع هذا الملف من أول بايت إلى الحكم، بالأبعاد الثلاثة." },
  };
  const lang = () => (window.CS && window.CS.lang === "ar") || document.documentElement.lang === "ar" ? "ar" : "en";
  const cut = (s, n) => String(s == null ? "" : s).slice(0, n);
  const b64u = (str) => btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  // its small stylesheet (journey-hook.css), so the scan page's own CSS stays untouched
  if (!document.querySelector('link[href="journey-hook.css"]')) { const l = document.createElement("link"); l.rel = "stylesheet"; l.href = "journey-hook.css"; document.head.append(l); }
  let firstBytes = null;   // { name, size, hex } of the file last picked on the scan page

  // the first 16 bytes of the picked file (read here, locally): the magic signature the journey shows
  document.addEventListener("change", (e) => {
    const inp = e.target;
    if (!inp || inp.type !== "file" || !inp.files || !inp.files[0]) return;
    const f = inp.files[0];
    f.slice(0, 16).arrayBuffer().then((buf) => {
      firstBytes = { name: f.name, size: f.size, hex: [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ") };
    }).catch(() => {});
  }, true);
  window.addEventListener("cs:upload", (e) => {
    const f = e.detail && (e.detail.file || (e.detail.files && e.detail.files[0]));
    if (f && f.slice) f.slice(0, 16).arrayBuffer().then((buf) => { firstBytes = { name: f.name, size: f.size, hex: [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ") }; }).catch(() => {});
  });

  // a curve of at most 48 points, one decimal
  function curve(arr) {
    const a = (Array.isArray(arr) ? arr : []).map(Number).filter((v) => Number.isFinite(v));
    if (a.length <= 48) return a.map((v) => Math.round(v * 10) / 10);
    const out = [];
    for (let i = 0; i < 48; i++) {
      const s = Math.floor((i * a.length) / 48), e = Math.max(s + 1, Math.floor(((i + 1) * a.length) / 48));
      let m = 0; for (let k = s; k < e; k++) m += a[k];
      out.push(Math.round((m / (e - s)) * 10) / 10);
    }
    return out;
  }
  // the file's parts: PE sections, the analyser's regions, or what its type is known to contain
  function parts(r, type) {
    const hex = (n) => "0x" + Math.max(0, Number(n) || 0).toString(16).toUpperCase().padStart(4, "0");
    const pe = r.pe && Array.isArray(r.pe.sections) ? r.pe.sections : null;
    if (pe && pe.length) return pe.slice(0, 6).map((s) => [cut(s.name || s.Name || "section", 24), hex(s.offset ?? s.raw_offset ?? s.virtual_address ?? s.PointerToRawData)]);
    const reg = r.structure && Array.isArray(r.structure.regions) ? r.structure.regions : [];
    if (reg.length) return reg.slice(0, 6).map((g) => [cut(g.label || g.name || g.kind || "region", 24), hex(g.start ?? g.offset)]);
    const ca = (r.content_analysis && r.content_analysis.details) || {};
    const t = String(type || "").toLowerCase();
    if (t === "pdf") {
      const kw = ca.keywords || {};
      const out = [["Header", "0x0000"], ["Objects", ""], [`Streams${ca.streams_inflated ? ` (${ca.streams_inflated})` : ""}`, ""]];
      const act = Object.keys(kw).filter((k) => /JS|JavaScript|OpenAction|AA|Launch|EmbeddedFile|URI/i.test(k)).slice(0, 2);
      act.forEach((k) => out.push([`/${k}`, ""]));
      out.push(["Trailer", ""]);
      return out.slice(0, 6);
    }
    if (Array.isArray(ca.members) && ca.members.length) return ca.members.slice(0, 6).map((m) => [cut(m.name || m, 28), ""]);
    return null;
  }

  function summary(r, cls, finds) {
    const ca = r.content_analysis || {};
    const type = ca.file_type || (r.pe ? "pe" : r.kind || "file");
    const name = (window.CS && window.CS.targetLabel ? window.CS.targetLabel(r, false) : "") || String(r.target || "").split(/[\\/]/).pop();
    const ent = r.entropy || {};
    const traj = Array.isArray(ent.trajectory) && ent.trajectory.length > 1 ? ent.trajectory : (r.structure && Array.isArray(r.structure.entropy) ? r.structure.entropy : ent.trajectory);
    const rules = [];
    (Array.isArray(r.yara) ? r.yara : []).forEach((y) => { const n = typeof y === "string" ? y : y && (y.rule || y.name); if (n && rules.length < 6) rules.push(cut(n, 48)); });
    const nYara = rules.length;
    (finds || []).forEach((f) => { if (rules.length < 6 && f && f.title && (f.sev !== "info" || rules.length < 3)) rules.push(cut(f.title, 56)); });
    const v = window.CS && window.CS.verdictOf ? window.CS.verdictOf(r) : { cls, score: r.final_score ?? r.score };
    const out = {
      v: 1, n: cut(name, 96), s: Number(r.size) || 0, t: cut(type, 24), h: /^[0-9a-f]{64}$/i.test(r.sha256 || "") ? r.sha256.toLowerCase() : "",
      e: curve(traj), em: ent.mean != null ? Math.round(Number(ent.mean) * 100) / 100 : null, ep: ent.peak != null ? Math.round(Number(ent.peak) * 100) / 100 : null,
      L: parts(r, type), m: rules, mr: nYara, c: cut(v.cls || cls || "UNKNOWN", 32), sc: Number.isFinite(Number(v.score)) ? Math.round(Number(v.score)) : null,
    };
    if (firstBytes && (!r.size || firstBytes.size === Number(r.size))) out.fb = firstBytes.hex;
    return out;
  }

  window.addEventListener("cs:rc-built", (e) => {
    const { rc, result: r, cls, findings } = e.detail || {};
    if (!rc || !r || (window.CS && window.CS.modeOf && window.CS.modeOf(r) !== "file")) return;
    let data;
    try { data = summary(r, cls, findings); sessionStorage.setItem(KEY, JSON.stringify(data)); } catch { return; }
    const l = T[lang()];
    const box = document.createElement("div"); box.className = "rc-journey";
    const a = document.createElement("a"); a.className = "rc-journey-go";
    a.href = `/journey?f=${b64u(JSON.stringify(data))}`;
    a.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 18c3-6 6-9 9-9h7"/><path d="m16 5 4 4-4 4"/><circle cx="5" cy="18" r="1.6"/></svg>';
    const tx = document.createElement("span"); tx.textContent = l.watch; a.append(tx);
    const hint = document.createElement("small"); hint.textContent = l.hint;
    box.append(a, hint);
    const actions = rc.querySelector(".rc-actions");
    (actions ? actions.parentElement : rc).append(box);
  });
})();
