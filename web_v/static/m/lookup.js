/* Optional online lookups in public threat lists (Android app only).
 *
 * Off by default. When the person turns them on, only an indicator is sent:
 * the file's SHA-256 fingerprint, or the link they asked about — never the
 * file and never pasted text. Requests go straight from the phone to each
 * service with the person's own key, through the native HTTP client (the
 * services don't allow browser requests). */
(function () {
  "use strict";
  const C = window.Capacitor;
  const http = () => (C && C.Plugins && C.Plugins.CapacitorHttp) || null;
  const available = () => !!(window.CSNative && http());

  async function post(url, data, headers, form) {
    const res = await http().request({
      url, method: "POST", connectTimeout: 12000, readTimeout: 15000,
      headers: { Accept: "application/json", "Content-Type": form ? "application/x-www-form-urlencoded" : "application/json", ...headers },
      data: form ? new URLSearchParams(data).toString() : data,
    });
    return check(res);
  }
  async function get(url, headers) {
    return check(await http().request({ url, method: "GET", connectTimeout: 12000, readTimeout: 15000, headers: { Accept: "application/json", ...headers } }));
  }
  function check(res) {
    if (res.status === 401 || res.status === 403) throw new Error("key");
    if (res.status === 404) return null;
    if (res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return typeof res.data === "string" ? JSON.parse(res.data || "null") : res.data;
  }

  /* what may be looked up for this result */
  function indicators(r) {
    const out = [];
    const sha = (r.fingerprints && r.fingerprints.sha256) || r.sha256;
    if (r.kind === "file" && sha) out.push({ type: "hash", value: sha });
    if (r.kind === "url" && /^https?:\/\//i.test(r.target)) out.push({ type: "url", value: r.target });
    return out;
  }

  const result = (source, status, label, detail, link) => ({ source, status, label, detail: detail || "", link: link || "" });

  async function malwareBazaar(ind, key) {
    if (ind.type !== "hash") return null;
    const d = await post("https://mb-api.abuse.ch/api/v1/", { query: "get_info", hash: ind.value }, { "Auth-Key": key }, true);
    if (d && d.query_status === "ok" && d.data && d.data[0]) {
      const x = d.data[0];
      return result("MalwareBazaar", "found", x.signature || x.file_type || "malware sample",
        [x.file_name, (x.tags || []).join(", "), x.first_seen].filter(Boolean).join(" · "), `https://bazaar.abuse.ch/sample/${ind.value}/`);
    }
    return result("MalwareBazaar", "clean", "not listed");
  }
  async function urlhaus(ind, key) {
    if (ind.type === "hash") {
      const d = await post("https://urlhaus-api.abuse.ch/v1/payload/", { sha256_hash: ind.value }, { "Auth-Key": key }, true);
      if (d && d.query_status === "ok") return result("URLhaus", "found", d.signature || "malware payload", `${d.url_count || 0} URLs · ${d.firstseen || ""}`);
      return result("URLhaus", "clean", "not listed");
    }
    const d = await post("https://urlhaus-api.abuse.ch/v1/url/", { url: ind.value }, { "Auth-Key": key }, true);
    if (d && d.query_status === "ok") return result("URLhaus", "found", d.threat || "malware URL", [d.url_status, (d.tags || []).join(", ")].filter(Boolean).join(" · "), d.urlhaus_reference);
    return result("URLhaus", "clean", "not listed");
  }
  async function threatfox(ind, key) {
    const d = await post("https://threatfox-api.abuse.ch/api/v1/", { query: "search_ioc", search_term: ind.value, exact_match: true }, { "Auth-Key": key }, false);
    if (d && d.query_status === "ok" && Array.isArray(d.data) && d.data[0]) {
      const x = d.data[0];
      return result("ThreatFox", "found", x.malware_printable || x.threat_type || "indicator", [x.threat_type_desc, x.confidence_level != null ? `${x.confidence_level}%` : ""].filter(Boolean).join(" · "));
    }
    return result("ThreatFox", "clean", "not listed");
  }
  async function otx(ind, key) {
    const path = ind.type === "hash" ? `file/${ind.value}` : `url/${encodeURIComponent(ind.value)}`;
    const d = await get(`https://otx.alienvault.com/api/v1/indicators/${path}/general`, { "X-OTX-API-KEY": key });
    const n = d && d.pulse_info ? d.pulse_info.count : 0;
    return n ? result("AlienVault OTX", "found", `${n} threat report${n > 1 ? "s" : ""}`, (d.pulse_info.pulses || []).slice(0, 2).map((x) => x.name).join(" · ")) : result("AlienVault OTX", "clean", "not listed");
  }

  async function run(r, keys) {
    const inds = indicators(r);
    if (!inds.length) return { sent: [], results: [] };
    const jobs = [];
    for (const ind of inds) {
      if (keys.abuse) {
        jobs.push(["MalwareBazaar", () => malwareBazaar(ind, keys.abuse)], ["URLhaus", () => urlhaus(ind, keys.abuse)], ["ThreatFox", () => threatfox(ind, keys.abuse)]);
      }
      if (keys.otx) jobs.push(["AlienVault OTX", () => otx(ind, keys.otx)]);
    }
    const results = await Promise.all(jobs.map(([name, fn]) => fn().catch((e) => result(name, "error", e.message === "key" ? "key refused" : "unreachable", e.message === "key" ? "" : e.message))));
    return { sent: inds, results: results.filter(Boolean) };
  }

  window.CSLookup = { available, indicators, run };
})();
