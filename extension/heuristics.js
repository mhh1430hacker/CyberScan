/* CyberScan extension: instant, local checks of a link or a file name.
 *
 * Everything here runs in the browser. Nothing is sent anywhere: these checks read only the text
 * of the address or the name (no page is fetched). They are the same signs the CyberScan phone
 * app reads (phone/lib/engine/link_scan.dart), ported to JavaScript. They are hints, not proof:
 * for the full check the extension opens the CyberScan scan page with the link filled in.
 *
 * analyzeLink(url)      -> { level: "high" | "review" | "low", score, host, reasons: [{ id, en, ar, weight }] }
 * analyzeFileName(name) -> same shape, for a downloaded file's name
 */
(function (root) {
  "use strict";

  const BRANDS = {
    paypal: ["paypal.com", "paypal.me"], apple: ["apple.com", "icloud.com"], icloud: ["icloud.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com"], outlook: ["outlook.com", "live.com", "office.com"],
    office365: ["office.com", "microsoft.com"], google: ["google.com", "gmail.com", "youtube.com"], gmail: ["gmail.com", "google.com"],
    facebook: ["facebook.com", "fb.com", "fb.me"], instagram: ["instagram.com"], whatsapp: ["whatsapp.com", "wa.me"],
    netflix: ["netflix.com"], amazon: ["amazon.com", "amazon.sa", "amazon.ae", "amazon.co.uk", "amazonaws.com"],
    binance: ["binance.com"], coinbase: ["coinbase.com"], metamask: ["metamask.io"],
    dhl: ["dhl.com", "dhl.de"], fedex: ["fedex.com"], aramex: ["aramex.com"], smsa: ["smsaexpress.com"],
    usps: ["usps.com"], linkedin: ["linkedin.com"], dropbox: ["dropbox.com"], docusign: ["docusign.com", "docusign.net"],
    adobe: ["adobe.com"], steam: ["steampowered.com", "steamcommunity.com"], telegram: ["telegram.org", "t.me"],
    tiktok: ["tiktok.com"], snapchat: ["snapchat.com"], twitter: ["twitter.com", "x.com", "t.co"],
    alrajhi: ["alrajhibank.com.sa"], absher: ["absher.sa"], tawakkalna: ["tawakkalna.gov.sa"],
    stcpay: ["stcpay.com.sa"], alinma: ["alinma.com"], riyadbank: ["riyadbank.com"], chase: ["chase.com"],
    visa: ["visa.com"], mastercard: ["mastercard.com"], ebay: ["ebay.com"],
  };
  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "v.gd"]);
  const RISKY_TLDS = new Set(["zip", "mov", "xyz", "top", "click", "link", "work", "gq", "tk", "ml", "cf", "ga", "cam", "rest", "country", "kim", "support", "icu", "buzz", "cyou", "sbs", "monster"]);
  const BAIT = ["login", "signin", "sign-in", "verify", "verification", "account", "secure", "update", "wallet", "billing", "payment", "confirm", "unlock", "recovery", "suspended", "reset", "password", "otp", "refund", "invoice"];
  const RUNNABLE = new Set(["exe", "scr", "msi", "bat", "cmd", "js", "jse", "vbs", "vbe", "hta", "ps1", "apk", "jar", "lnk", "iso", "img", "dll", "com", "pif", "cpl", "msix", "appx", "wsf", "reg"]);
  const DECOY = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp4", "mp3", "zip", "rar", "csv", "rtf", "html"]);
  const MACRO = new Set(["docm", "xlsm", "pptm", "xlam", "dotm"]);
  const SECOND_LEVEL = new Set(["co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "nic", "mil", "sch", "ltd", "plc"]);
  const OWN = ["ainex-ai.xyz"]; // CyberScan's own site
  const CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g",
    "ո": "n", "ս": "u", "ⅼ": "l", "ӏ": "l", "ı": "i", "ɑ": "a", "ο": "o", "ν": "v", "τ": "t", "κ": "k", "α": "a", "ρ": "p", "ε": "e",
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s",
  };
  const HIDDEN = /[‪-‮⁦-⁩‎‏؜​﻿]/;
  const DISPLAY = { paypal: "PayPal", icloud: "iCloud", office365: "Office 365", whatsapp: "WhatsApp", linkedin: "LinkedIn", docusign: "DocuSign",
    tiktok: "TikTok", metamask: "MetaMask", dhl: "DHL", usps: "USPS", smsa: "SMSA", fedex: "FedEx", alrajhi: "Al Rajhi", stcpay: "STC Pay",
    riyadbank: "Riyad Bank", ebay: "eBay" };
  const iso = (s) => "⁨" + s + "⁩"; // keeps a Latin address in one piece inside Arabic text
  const cap = (s) => DISPLAY[s] || (s ? s[0].toUpperCase() + s.slice(1) : s);

  /* RFC 3492 punycode decoding, so "xn--pypal-4ve.com" can be compared as "pаypal.com". */
  function punyDecode(label) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    let n = 128, i = 0, bias = 72;
    const b = label.lastIndexOf("-");
    const out = b > 0 ? Array.from(label.slice(0, b)) : [];
    const adapt = (delta, num, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / num);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
      return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
    };
    for (let p = b > 0 ? b + 1 : 0; p < label.length;) {
      const old = i;
      for (let w = 1, k = base; ; k += base) {
        if (p >= label.length) return null;
        const c = label.charCodeAt(p++);
        const d = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (d >= base) return null;
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      bias = adapt(i - old, out.length + 1, old === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      out.splice(i++, 0, String.fromCodePoint(n));
    }
    return out.join("");
  }
  const unicodeHost = (host) => host.split(".").map((l) => (l.startsWith("xn--") ? punyDecode(l.slice(4)) || l : l)).join(".");
  const skeleton = (s) => Array.from(s.toLowerCase()).map((c) => CONFUSABLES[c] || c).join("");

  function registeredDomain(host) {
    const parts = host.split(".");
    if (parts.length <= 2) return host;
    return SECOND_LEVEL.has(parts[parts.length - 2]) ? parts.slice(-3).join(".") : parts.slice(-2).join(".");
  }
  const official = (host, domains) => domains.some((d) => host === d || host.endsWith("." + d));
  function nearMiss(a, b) {
    if (Math.abs(a.length - b.length) > 1 || a === b) return false;
    let i = 0, j = 0, edits = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++edits > 1) return false;
      if (a.length > b.length) i++; else if (b.length > a.length) j++; else { i++; j++; }
    }
    return edits + (a.length - i) + (b.length - j) <= 1;
  }

  function verdict(reasons, host) {
    reasons.sort((a, b) => b.weight - a.weight);
    const top = reasons.length ? reasons[0].weight : 0;
    const score = Math.min(100, top + Math.max(0, reasons.length - 1) * 5 * (top > 0 ? 1 : 0));
    return { level: score >= 50 ? "high" : score > 0 ? "review" : "low", score, host, reasons };
  }

  function analyzeLink(raw) {
    const reasons = [];
    const add = (id, weight, en, ar) => reasons.push({ id, weight, en, ar });
    let text = String(raw || "").trim();
    if (/^(javascript|data|vbscript):/i.test(text)) {
      add("script_scheme", 60, "A link that runs code (javascript:, data: or vbscript:) instead of opening a site.",
        "رابط يشغّل كودًا (javascript: أو data: أو vbscript:) بدل فتح موقع.");
      return verdict(reasons, "");
    }
    if (!/^[a-z][a-z0-9+.-]*:/i.test(text)) text = "http://" + text;
    let url;
    try { url = new URL(text); } catch (_) { return verdict(reasons, ""); }
    if (!/^https?:$|^ftp:$/.test(url.protocol)) return verdict(reasons, url.hostname);
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!host) return verdict(reasons, "");
    if (official(host, OWN)) return verdict(reasons, host);
    const uhost = unicodeHost(host);
    const reg = registeredDomain(host);
    const path = (url.pathname + url.search).toLowerCase();

    if (/^[a-z]+:\/\/[^/]*@/i.test(text)) {
      add("userinfo", 55, `The real address is hidden after "@": the link goes to ${host}.`, `العنوان الحقيقي مخفي بعد "@": الرابط يذهب إلى ${iso(host)}.`);
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) {
      add("ip_host", 35, "A bare IP address instead of a site name.", "عنوان IP مجرد بدل اسم موقع.");
    }
    if (host.split(".").some((l) => l.startsWith("xn--"))) {
      const mixed = /[a-z]/.test(uhost) && /[^\x00-\x7F]/.test(uhost);
      add("punycode", mixed ? 55 : 30, `Letters from another alphabet in the address (${uhost}). Look-alike letters are a classic way to fake a known site.`,
        `حروف من أبجدية أخرى في العنوان (${iso(uhost)}). الحروف المتشابهة حيلة معروفة لتقليد المواقع.`);
    }
    const hostSkel = skeleton(uhost.replace(/-/g, "").replace(/\./g, " "));
    const labels = skeleton(uhost).split(/[.\-]/);
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (official(host, domains)) continue;
      const named = hostSkel.includes(brand) || labels.some((l) => l.length >= 4 && nearMiss(l, brand));
      const inPath = path.includes(brand) && BAIT.some((w) => path.includes(w));
      if (named || inPath) {
        add("lookalike", named ? 65 : 45, `Looks like ${cap(brand)}, but the site is ${reg}, not ${domains[0]}.`,
          `يبدو كأنه ${iso(cap(brand))}، لكن الموقع هو ${iso(reg)} وليس ${iso(domains[0])}.`);
        break;
      }
    }
    const tld = host.split(".").pop();
    if (RISKY_TLDS.has(tld)) add("risky_tld", 15, `An ending often used by throwaway scam sites (.${tld}). Not proof on its own.`, `امتداد يكثر في مواقع الاحتيال المؤقتة (.${tld})، وليس دليلًا وحده.`);
    if (SHORTENERS.has(host)) add("shortener", 15, "A shortened link hides where it really goes.", "الرابط المختصر يخفي وجهته الحقيقية.");
    if (host.split(".").length >= 5) add("deep_subdomains", 15, `A long chain of sub-names before the real site (${reg}).`, `سلسلة طويلة من الأسماء الفرعية قبل الموقع الحقيقي (${iso(reg)}).`);
    const baitHits = BAIT.filter((w) => host.includes(w) || path.includes(w));
    if (baitHits.length >= 2 || (baitHits.length && reasons.some((r) => r.weight >= 35))) {
      add("bait_words", 25, `Login or payment words in the address ("${baitHits.slice(0, 3).join('", "')}").`, `كلمات دخول أو دفع في العنوان ("${baitHits.slice(0, 3).join('"، "')}").`);
    }
    const last = decodeURIComponent(url.pathname.split("/").pop() || "");
    const nameCheck = last.includes(".") ? fileNameReasons(last) : [];
    reasons.push(...nameCheck);
    if (url.protocol === "http:" && baitHits.length) add("no_https", 10, "Not encrypted (http) on a page that asks for logins or payments.", "غير مشفّر (http) في صفحة تطلب الدخول أو الدفع.");
    if (url.port && !["80", "443"].includes(url.port)) add("odd_port", 12, `An unusual port (:${url.port}).`, `منفذ غير معتاد (:${url.port}).`);
    return verdict(reasons, host);
  }

  function fileNameReasons(name) {
    const reasons = [];
    const add = (id, weight, en, ar) => reasons.push({ id, weight, en, ar });
    const clean = String(name || "").split(/[\\/]/).pop();
    if (HIDDEN.test(clean)) add("hidden_chars", 70, "The name contains invisible direction characters that disguise its real ending.", "يحتوي الاسم على رموز اتجاه خفية تُخفي امتداده الحقيقي.");
    const parts = clean.toLowerCase().replace(HIDDEN, "").split(".");
    const ext = parts.length > 1 ? parts.pop() : "";
    const prev = parts.length > 1 ? parts[parts.length - 1] : "";
    if (RUNNABLE.has(ext) && DECOY.has(prev)) {
      add("double_extension", 70, `Double extension: it looks like .${prev} but it is really a .${ext} program.`, `امتداد مزدوج: يبدو كملف .${prev} لكنه في الحقيقة برنامج .${ext}.`);
    } else if (RUNNABLE.has(ext)) {
      add("runnable", 30, `A file that can run on your device (.${ext}). Open it only if you expected it from a source you trust.`, `ملف يمكن تشغيله على جهازك (.${ext}). افتحه فقط إن كنت تتوقعه من مصدر تثق به.`);
    } else if (MACRO.has(ext)) {
      add("macro", 30, `An Office file that can hold macros (.${ext}).`, `ملف Office يمكن أن يحتوي على وحدات ماكرو (.${ext}).`);
    }
    if (/\s{6,}\S/.test(clean)) add("padding", 30, "Many spaces inside the name push the real ending out of sight.", "مسافات كثيرة داخل الاسم تُبعد الامتداد الحقيقي عن النظر.");
    return reasons;
  }

  const analyzeFileName = (name) => verdict(fileNameReasons(name), "");

  root.CSHeuristics = { analyzeLink, analyzeFileName, punyDecode, registeredDomain };
})(typeof self !== "undefined" ? self : globalThis);
