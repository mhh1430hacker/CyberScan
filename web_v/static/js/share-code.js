/* Shareable results without uploading anything: a compact, privacy-safe summary of a scan lives in the
 * URL fragment of report.html (#r=…), which never reaches a server (browsers don't send fragments).
 *
 * The summary holds only: the file name if the person ticked "include the name", the SHA-256, the
 * verdict and score, the top findings' short labels, severities and weights, matched rule names, the
 * engine version and the scan date. No file content, no path, no link the file contained.
 * JSON → deflate-raw (CompressionStream, when the browser has it) → base64url; "z" marks compressed,
 * "j" plain. Used by the scan page (js/result-plus.js) and the report page (js/report.js). */
(function () {
  "use strict";
  const VERDICTS = ["NO_INDICATORS_OBSERVED", "REVIEW", "SUSPICIOUS", "KNOWN_MALWARE", "UNKNOWN", "EMPTY"];
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const clip = (s, n) => { const t = String(s == null ? "" : s).replace(/\s+/g, " ").trim(); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };

  const b64u = (bytes) => { let s = ""; bytes.forEach((b) => { s += String.fromCharCode(b); }); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
  const unb64u = (str) => { const s = atob(String(str).replace(/-/g, "+").replace(/_/g, "/")); return Uint8Array.from(s, (c) => c.charCodeAt(0)); };
  async function pipe(bytes, stream) {
    const out = new Response(new Blob([bytes]).stream().pipeThrough(stream));
    return new Uint8Array(await out.arrayBuffer());
  }

  /* normalise: only known fields, short, typed */
  function normalise(o) {
    if (!o || typeof o !== "object") return null;
    const cls = VERDICTS.includes(o.c) ? o.c : "UNKNOWN";
    const out = { v: 1, c: cls, s: Math.max(0, Math.min(100, Math.round(Number(o.s) || 0))), m: ["file", "url", "text", "email"].includes(o.m) ? o.m : "file" };
    if (o.h && /^[0-9a-f]{64}$/i.test(o.h)) out.h = String(o.h).toLowerCase();
    if (o.n) out.n = clip(o.n, 120);
    if (o.t) out.t = clip(o.t, 40);
    if (o.e) out.e = clip(o.e, 24);
    if (o.d && !Number.isNaN(new Date(o.d).getTime())) out.d = new Date(o.d).toISOString().slice(0, 19) + "Z";
    if (Array.isArray(o.f)) out.f = o.f.slice(0, 6).map((f) => [clip(f[0], 60), SEVS.includes(f[1]) ? f[1] : "info", Math.max(0, Math.min(100, Math.round(Number(f[2]) || 0))), clip(f[3] || "", 32)]).filter((f) => f[0]);
    if (Array.isArray(o.y)) out.y = o.y.slice(0, 6).map((x) => clip(x, 60)).filter(Boolean);
    return out;
  }

  /* from a scan result on the scan page (window.CS present) */
  function fromResult(r, includeName) {
    const CS = window.CS;
    const v = CS.verdictOf(r);
    const mode = CS.modeOf(r);
    const ev = (Array.isArray(r.evidence) ? r.evidence : []).slice().sort((a, b) => (Number(b.contribution) || 0) - (Number(a.contribution) || 0));
    const rules = ((r.intel && r.intel.rules) || []).map((x) => x.rule).concat((r.yara || []).map((x) => x.rule_name)).filter(Boolean);
    return normalise({
      c: v.cls, s: v.score, m: mode, h: mode === "file" ? r.sha256 : "",
      n: includeName ? CS.targetLabel(r, false) : "",
      t: mode === "file" ? ((r.content_analysis && r.content_analysis.file_type) || "") : "",
      e: (r.detection_engine && r.detection_engine.version) || "",
      d: CS.scanTime(r) || new Date().toISOString(),
      f: ev.map((x) => [CS.loc(x.evidence || x.title || x.category), String(x.severity || "info").toLowerCase(), x.contribution, String(x.category || "")]),
      y: [...new Set(rules)],
    });
  }

  async function encode(obj) {
    const json = new TextEncoder().encode(JSON.stringify(normalise(obj)));
    if (typeof CompressionStream === "function") {
      try { return "z" + b64u(await pipe(json, new CompressionStream("deflate-raw"))); } catch { /* fall through */ }
    }
    return "j" + b64u(json);
  }
  async function decode(str) {
    const s = String(str || "");
    if (s.length > 6000) throw new Error("too long");
    let bytes = unb64u(s.slice(1));
    if (s[0] === "z") {
      if (typeof DecompressionStream !== "function") throw new Error("unsupported");
      bytes = await pipe(bytes, new DecompressionStream("deflate-raw"));
    } else if (s[0] !== "j") throw new Error("bad");
    return normalise(JSON.parse(new TextDecoder().decode(bytes)));
  }
  async function url(obj) {
    return new URL(`report.html#r=${await encode(obj)}`, location.href).href;
  }
  window.CSShare = { normalise, fromResult, encode, decode, url };
})();
