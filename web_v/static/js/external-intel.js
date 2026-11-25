/* External intelligence on the scan page (core/external_intel.py on the server).
 *
 *   - The switch under the composer: "Also check with VirusTotal and other services (only the fingerprint
 *     or link is sent, never the file)". On by default on the website; the choice stays in this browser
 *     (localStorage "cs-external-intel"; app.js and batch.js send it with every scan).
 *   - The "External intelligence" card in a result: one row per service with a status chip, the key
 *     numbers (e.g. "54 / 72 engines flag it · Trojan.Agent"), a detection-ratio ring for VirusTotal and a
 *     link to the service's own public report. A service without a key says "Not configured".
 * All text from the server goes in as text, never as HTML. Other languages fall back to English. */
(function () {
  "use strict";
  const CS = window.CS;
  if (!CS || !document.getElementById("form")) return;
  const { el } = CS;
  const KEY = "cs-external-intel";
  const isOn = () => { try { return localStorage.getItem(KEY) !== "0"; } catch { return true; } };
  const save = (on) => { try { localStorage.setItem(KEY, on ? "1" : "0"); } catch { /* storage off: this page only */ } };

  const STR = {
    en: {
      toggle: "Also check with VirusTotal and other services (only the fingerprint or link is sent, never the file)",
      toggleNote: "Services asked where set up: VirusTotal, Google Safe Browsing, URLhaus, MalwareBazaar, AlienVault OTX, CIRCL and urlscan.io. Lookups only: nothing is uploaded or submitted.",
      toggleLocalOff: "Online lookups are off in Settings; turn them on there to use this.", privacy: "What is sent",
      title: "External intelligence",
      ledeFile: "What outside services already know about this file's fingerprint (SHA-256). Only the fingerprint was sent, never the file.",
      ledeUrl: "What outside services already know about this link and its site. Only the link was sent; nothing was submitted for scanning.",
      ledeText: "Outside services look up files and links. Pasted text isn't sent anywhere.",
      ledeOffFile: "Outside services that can look up this file's fingerprint. Nothing was sent to them this time.",
      ledeOffUrl: "Outside services that can look up this link. Nothing was sent to them this time.",
      off_for_scan: "You turned these lookups off for this scan.", disabled: "External lookups are turned off.",
      disabledLocal: "Online lookups are off in Settings.", rate_limited: "Skipped: too many lookups from your connection in a short time. Try again in a few minutes.",
      skipped: "Skipped: the scan reached its time limit.", noneConfigured: "No service is set up with a key on this server yet, so only key-free sources answered.",
      chip: { bad: "Flagged", warn: "Weak signal", ok: "Clean", neutral: "Not found", not_configured: "Not configured", quota: "Quota reached", error: "Unavailable", off: "Not asked" },
      open: "Open report", cached: "cached", engines: "{m} / {t} engines flag it", vendors: "{m} / {t} security vendors flag it",
      firstSeen: "first seen {d}", vtNever: { file: "VirusTotal has never seen this file", link: "VirusTotal has no report for this link", site: "VirusTotal has no report for this site" },
      noKey: "No API key on this server", quota: "Free quota used up for now; try again later", error: "Couldn't be reached", timeout: "Didn't answer in time",
      off: "Not asked for this scan", na: "Not applicable (a private or local address)",
      circlGood: "Known, legitimate software{p}", circlNone: "Not in the known-files database", mbHit: "A known malware sample{s}", mbNone: "Not a known malware sample",
      sbHit: "Listed: {t}", sbNone: "Not on Google's unsafe-site lists", uhHit: "Listed as a malware link{t}", uhHost: "The site has {n} listed malware link(s)", uhNone: "Not listed",
      otxHit: "In {n} community threat pulse(s)", otxAllow: "On an allow list", otxNone: "No threat pulses",
      usHit: "{f} public scan(s) marked malicious", usSeen: "{n} public scan(s), none marked malicious", usNone: "No public scans of this site",
      listed: "Listed as malicious", ring: "{m} of {t} engines flag it",
    },
    ar: {
      toggle: "افحص أيضًا عبر VirusTotal وخدمات أخرى (تُرسل البصمة أو الرابط فقط، لا الملف أبدًا)",
      toggleNote: "الخدمات التي تُسأل متى ما أُعدّت: VirusTotal وGoogle Safe Browsing وURLhaus وMalwareBazaar وAlienVault OTX وCIRCL وurlscan.io. استعلام فقط: لا يُرفع أي شيء ولا يُرسل للفحص.",
      toggleLocalOff: "البحث عبر الإنترنت متوقف في الإعدادات؛ فعّله هناك لاستخدام هذا الخيار.", privacy: "ما الذي يُرسل",
      title: "الاستخبارات الخارجية",
      ledeFile: "ما تعرفه الخدمات الخارجية مسبقًا عن بصمة هذا الملف (SHA-256). أُرسلت البصمة فقط، لا الملف.",
      ledeUrl: "ما تعرفه الخدمات الخارجية مسبقًا عن هذا الرابط وموقعه. أُرسل الرابط فقط، ولم يُرسل شيء للفحص.",
      ledeText: "الخدمات الخارجية تبحث عن الملفات والروابط. النص الملصق لا يُرسل إلى أي جهة.",
      ledeOffFile: "الخدمات الخارجية التي يمكنها البحث عن بصمة هذا الملف. لم يُرسل إليها شيء هذه المرة.",
      ledeOffUrl: "الخدمات الخارجية التي يمكنها البحث عن هذا الرابط. لم يُرسل إليها شيء هذه المرة.",
      off_for_scan: "أوقفت هذا البحث لهذا الفحص.", disabled: "البحث الخارجي متوقف.",
      disabledLocal: "البحث عبر الإنترنت متوقف في الإعدادات.", rate_limited: "تُخطّي: طلبات كثيرة من اتصالك في وقت قصير. أعد المحاولة بعد دقائق.",
      skipped: "تُخطّي: بلغ الفحص حدّه الزمني.", noneConfigured: "لم تُعدّ أي خدمة بمفتاح على هذا الخادم بعد، لذا أجابت المصادر التي لا تحتاج مفتاحًا فقط.",
      chip: { bad: "مُشار إليه", warn: "إشارة ضعيفة", ok: "سليم", neutral: "غير موجود", not_configured: "غير مُعدّ", quota: "نفدت الحصة", error: "غير متاح", off: "لم يُسأل" },
      open: "افتح التقرير", cached: "محفوظ مؤقتًا", engines: "{m} / {t} محركًا يشير إليه", vendors: "{m} / {t} جهة أمنية تشير إليه",
      firstSeen: "أول ظهور {d}", vtNever: { file: "لم يرَ VirusTotal هذا الملف من قبل", link: "لا يوجد تقرير في VirusTotal لهذا الرابط", site: "لا يوجد تقرير في VirusTotal لهذا الموقع" },
      noKey: "لا يوجد مفتاح API على هذا الخادم", quota: "نفدت الحصة المجانية مؤقتًا؛ حاول لاحقًا", error: "تعذّر الوصول إليه", timeout: "لم يُجب في الوقت المحدد",
      off: "لم يُسأل في هذا الفحص", na: "لا ينطبق (عنوان خاص أو محلي)",
      circlGood: "برنامج معروف وموثوق{p}", circlNone: "غير موجود في قاعدة الملفات المعروفة", mbHit: "عيّنة برمجية ضارة معروفة{s}", mbNone: "ليس عيّنة ضارة معروفة",
      sbHit: "مُدرج: {t}", sbNone: "غير مُدرج في قوائم Google للمواقع غير الآمنة", uhHit: "مُدرج كرابط برمجيات ضارة{t}", uhHost: "للموقع {n} رابط ضار مُدرج", uhNone: "غير مُدرج",
      otxHit: "ورد في {n} تقرير تهديد مجتمعي", otxAllow: "في قائمة سماح", otxNone: "لا تقارير تهديد",
      usHit: "{f} فحص علني وصفه بالضار", usSeen: "{n} فحص علني، لم يوصف أي منها بالضار", usNone: "لا فحوص علنية لهذا الموقع",
      listed: "مُدرج كضار", ring: "{m} من {t} محركًا يشير إليه",
    },
  };
  const L = () => STR[CS.lang === "ar" ? "ar" : "en"];
  const fill = (s, o) => String(s).replace(/\{(\w+)\}/g, (_, k) => (o[k] != null ? o[k] : ""));
  const num = (n) => Number(n || 0).toLocaleString(CS.lang === "ar" ? "ar" : "en");
  const SVGNS = "http://www.w3.org/2000/svg";

  /* ------------------------------------------------------------ the per-scan switch */
  let protection = null;
  const box = el("div", "ext-toggle");
  const label = el("label", "ext-toggle-row");
  const input = el("input"); input.type = "checkbox"; input.className = "switch"; input.id = "ext-intel";
  const words = el("span", "ext-toggle-text");
  label.append(input, words);
  const note = el("small", "ext-toggle-note");
  box.append(label, note);
  const go = document.getElementById("go");
  if (go) go.before(box);   // just above the Start button
  input.checked = isOn();
  input.addEventListener("change", () => save(input.checked));
  function paintToggle() {
    const l = L();
    const localOff = protection && !protection.public && !protection.online;
    words.textContent = l.toggle;
    note.replaceChildren(document.createTextNode(localOff ? l.toggleLocalOff : l.toggleNote), document.createTextNode(" "));
    const a = el("a", "", l.privacy); a.href = "/privacy#external"; a.target = "_blank"; a.rel = "noopener";
    note.append(a);
    input.disabled = !!localOff;
    box.classList.toggle("is-off", !!localOff);
  }
  paintToggle();
  CS.api("/api/protection").then((p) => { protection = p; paintToggle(); }).catch(() => { /* the switch still works */ });

  /* ------------------------------------------------------------ the result card */
  function ring(m, t) {
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("viewBox", "0 0 44 44"); svg.setAttribute("class", "ext-ring"); svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", fill(L().ring, { m: num(m), t: num(t) }));
    const r = 18, c = 2 * Math.PI * r, frac = t > 0 ? Math.min(1, m / t) : 0;
    const back = document.createElementNS(SVGNS, "circle");
    [["cx", 22], ["cy", 22], ["r", r], ["class", "ext-ring-bg"]].forEach(([k, v]) => back.setAttribute(k, v));
    const arc = document.createElementNS(SVGNS, "circle");
    [["cx", 22], ["cy", 22], ["r", r], ["class", `ext-ring-fg ${m >= 5 ? "bad" : m > 0 ? "warn" : "ok"}`],
      ["stroke-dasharray", `${(c * frac).toFixed(2)} ${c.toFixed(2)}`], ["transform", "rotate(-90 22 22)"]].forEach(([k, v]) => arc.setAttribute(k, v));
    const txt = document.createElementNS(SVGNS, "text");
    [["x", 22], ["y", 25], ["text-anchor", "middle"], ["class", "ext-ring-txt"]].forEach(([k, v]) => txt.setAttribute(k, v));
    txt.textContent = String(m);
    svg.append(back, arc, txt);
    return svg;
  }
  function vtWhat(name) { return name === "VirusTotal (link)" ? "link" : name === "VirusTotal (site)" ? "site" : "file"; }
  function lineOf(row) {
    const l = L(), st = String(row.status || ""), name = String(row.name || "");
    if (row.chip === "not_configured") return l.noKey;
    if (st === "quota") return l.quota;
    if (st === "timeout") return l.timeout;
    if (st === "error" || row.chip === "error") return l.error + (row.error ? ` (${row.error})` : "");
    if (st === "off") return l.off;
    if (st === "not_applicable") return l.na;
    if (name.startsWith("VirusTotal")) {
      if (st === "not_found") return l.vtNever[vtWhat(name)];
      const t = Number(row.engines_total) || 0, m = Number(row.malicious) || 0;
      let s = fill(vtWhat(name) === "file" ? l.engines : l.vendors, { m: num(m), t: num(t) });
      const tag = row.label || row.family;
      if (tag && m) s += ` · ${tag}`;
      if (row.first_seen) s += ` · ${fill(l.firstSeen, { d: row.first_seen })}`;
      return s;
    }
    if (name === "CIRCL hashlookup") return st === "known_good" ? fill(l.circlGood, { p: row.product ? ` · ${row.product}` : "" }) : st === "match" ? `${l.listed}${row.detail ? ` · ${row.detail}` : ""}` : l.circlNone;
    if (name === "MalwareBazaar") return st === "match" ? fill(l.mbHit, { s: row.signature ? ` · ${row.signature}` : "" }) : l.mbNone;
    if (name === "Google Safe Browsing") return st === "match" ? fill(l.sbHit, { t: (row.threats || []).map((x) => String(x).replace(/_/g, " ").toLowerCase()).join(", ") }) : l.sbNone;
    if (name === "URLhaus") return st === "match" ? fill(l.uhHit, { t: row.threat ? ` · ${row.threat}` : "" }) : st === "few" ? fill(l.uhHost, { n: num(row.urls_count) }) : l.uhNone;
    if (name === "AlienVault OTX") return st === "few" ? fill(l.otxHit, { n: num(row.pulses) }) : st === "clean_report" ? l.otxAllow : l.otxNone;
    if (name === "urlscan.io") return st === "few" ? fill(l.usHit, { f: num(row.flagged) }) : st === "seen" ? fill(l.usSeen, { n: num(row.scans) }) : l.usNone;
    return row.detail || st.replace(/_/g, " ");
  }
  function card(r) {
    const x = r.external;
    if (!x || !Array.isArray(x.rows)) return null;
    const l = L(), mode = CS.modeOf(r);
    const sec = el("section", "card ext-card");
    sec.setAttribute("aria-label", l.title);
    sec.append(el("h3", "", l.title));
    sec.append(el("p", "rc-note", mode === "text" ? l.ledeText : !x.ran ? (mode === "url" ? l.ledeOffUrl : l.ledeOffFile) : mode === "url" ? l.ledeUrl : l.ledeFile));
    if (!x.ran && x.rows.length) {
      const why = x.status === "disabled" && protection && !protection.public ? l.disabledLocal : l[x.status] || l.disabled;
      sec.append(el("p", "ext-why", why));
    } else if (x.ran && x.any_configured === false && x.rows.length) {
      sec.append(el("p", "ext-why", l.noneConfigured));
    }
    if (!x.rows.length) return sec;
    const ul = el("ul", "ext-rows");
    x.rows.forEach((row) => {
      const li = el("li", `ext-row chip-${row.chip}`);
      const isVt = String(row.name).startsWith("VirusTotal") && Number(row.engines_total) > 0;
      if (isVt) li.append(ring(Number(row.malicious) || 0, Number(row.engines_total) || 0));
      else li.append(el("span", "ext-dot", ""));
      const main = el("div", "ext-main");
      const top = el("div", "ext-top");
      const nm = el("b", "ext-name", row.name); nm.dir = "ltr";
      top.append(nm, el("span", `ext-chip chip-${row.chip}`, l.chip[row.chip] || row.chip));
      if (row.cached) top.append(el("small", "ext-cached", l.cached));
      main.append(top);
      const p = el("p", "ext-line", lineOf(row)); p.dir = "auto"; main.append(p);
      if (Array.isArray(row.detections) && row.detections.length && Number(row.malicious) > 0) {
        const d = el("small", "ext-dets", row.detections.slice(0, 4).join(" · ")); d.dir = "ltr"; main.append(d);
      }
      li.append(main);
      if (row.link && /^https:\/\//.test(row.link)) {
        const a = el("a", "ext-link", l.open); a.href = row.link; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.setAttribute("aria-label", `${l.open}: ${row.name}`);
        li.append(a);
      }
      ul.append(li);
    });
    sec.append(ul);
    return sec;
  }

  let last = null;
  function place(rc, result) {
    rc.querySelectorAll(".ext-card").forEach((n) => n.remove());
    const c = card(result);
    if (!c) return;
    const after = rc.querySelector(".sp-intel");
    const reco = rc.querySelector(".rc-reco");
    if (after) after.after(c); else if (reco) reco.before(c); else rc.append(c);
  }
  window.addEventListener("cs:rc-built", (e) => {
    const { rc, result } = e.detail || {};
    if (!rc || !result) return;
    last = { rc, result };
    place(rc, result);
  });
  CS.onLang(() => { paintToggle(); if (last && last.rc.isConnected) place(last.rc, last.result); });
  window.CSExternal = { card, lineOf, isOn };
})();
