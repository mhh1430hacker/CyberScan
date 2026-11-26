"""Layers: links, reputation and external services, YARA rule families, machine learning.

External layers never make a request of their own: they read the answers the scan already got
within its time budget (``ui.scan_service``: VirusTotal, CIRCL, MalwareBazaar, URLhaus, OTX,
urlscan.io, Google Safe Browsing, the public feeds). No key, quota, timeout or online lookups
switched off -> ``None`` ("not available"), never a guess.
"""
from __future__ import annotations

import importlib
import re
from typing import Any

from core.layers.base import Layer, clean, hit, register, unavailable
from core.layers.catalog_structure import label_layer
from core.layers.context import LayerContext

_LINKS = lambda f: f["mode"] == "url" or (f["mode"] in {"file", "text"} and f["has_urls"])  # noqa: E731
U = "detection.url_intel"

# =============================================================== links (every link in the input, or the link itself)
for _id, _en, _ar, _cen, _car, _labels, _w, _c in (
    ("link_ip_host", "Bare IP address", "عنوان IP مجرد", "Flags links that point to a numeric IP address instead of a name.",
     "يرصد الروابط التي تشير إلى عنوان IP رقمي بدل اسم.", ("Direct IPv4 URL host", "Direct IPv6 URL host"), 1.2, 0.65),
    ("link_obfuscated_ip", "Disguised IP address", "عنوان IP متنكر", "Flags IP addresses written in decimal, octal or hex to look harmless.",
     "يرصد عناوين IP المكتوبة بالعشري أو الثماني أو السداسي لتبدو بريئة.", ("Obfuscated IP address host",), 1.8, 0.8),
    ("link_punycode", "International domain (punycode)", "نطاق دولي (punycode)", "Flags xn-- domains, which can spell look-alike names in other alphabets.",
     "يرصد نطاقات xn-- التي قد تكتب أسماء شبيهة بحروف أبجديات أخرى.", ("Internationalized domain name",), 0.5, 0.45),
    ("link_homograph", "Mixed alphabets", "أبجديات مختلطة", "Flags domain names mixing letters from different alphabets (paypal with a Cyrillic 'а').",
     "يرصد أسماء نطاقات تخلط حروفًا من أبجديات مختلفة.", ("Mixed-script domain (homograph)", "Lookalike (homoglyph) domain"), 2.0, 0.85),
    ("link_brand_lookalike", "Brand look-alike", "شبيه علامة تجارية", "Compares the domain with well-known brands (typos, brand in a subdomain, odd TLD).",
     "يقارن النطاق بالعلامات التجارية المعروفة (أخطاء إملائية، العلامة في نطاق فرعي، امتداد غريب).",
     ("Brand impersonation in domain name", "Brand name in subdomain of unrelated domain", "Brand name inside unrelated domain",
      "Brand name on unusual TLD", "Typosquatting domain", "Possible typosquatting domain", "Lookalike of", "Lookalike letters imitating"), 1.8, 0.8),
    ("link_shortener", "Link shortener", "مختصر روابط", "Flags shortened links that hide where they really go.", "يرصد الروابط المختصرة التي تخفي وجهتها الحقيقية.",
     ("URL shortener domain",), 0.6, 0.5),
    ("link_abused_tld", "Abused domain ending", "امتداد نطاق كثير الإساءة", "Flags domain endings over-represented in abuse reports.",
     "يرصد امتدادات نطاقات تكثر في بلاغات الإساءة.", ("Frequently abused TLD",), 0.4, 0.4),
    ("link_free_hosting", "Free hosting or tunnel", "استضافة مجانية أو نفق", "Flags free hosting, page builders and tunnels often used for throw-away phishing pages.",
     "يرصد الاستضافة المجانية وأدوات بناء الصفحات والأنفاق المستخدمة لصفحات تصيد مؤقتة.", ("Free hosting or tunnel platform",), 0.6, 0.5),
    ("link_deep_subdomains", "Deep or very long host", "مضيف عميق أو طويل جدًا", "Flags many subdomain levels or a very long host name.",
     "يرصد مستويات نطاقات فرعية كثيرة أو اسم مضيف طويلًا جدًا.", ("Deep subdomain nesting", "Very long host name"), 0.5, 0.45),
    ("link_noisy_domain", "Noisy domain name", "اسم نطاق مشوّش", "Flags many hyphens or long digit runs in the domain.", "يرصد كثرة الشرطات أو تتابع الأرقام الطويل في النطاق.",
     ("Many hyphens in domain", "Long digit run in domain"), 0.4, 0.4),
    ("link_credential_words", "Login bait words", "كلمات طُعم الدخول", "Looks for words like login, verify, account and password in the address.",
     "يبحث عن كلمات مثل login وverify وaccount وpassword في العنوان.", ("Credential-harvesting keywords",), 0.6, 0.5),
    ("link_no_tls_login", "Login over plain http", "دخول عبر http غير مشفر", "Flags login-style addresses that don't use HTTPS.",
     "يرصد عناوين تشبه صفحات الدخول ولا تستخدم HTTPS.", ("Credential wording without TLS",), 0.8, 0.55),
    ("link_script_scheme", "Script or data link", "رابط سكربت أو بيانات", "Flags javascript:, vbscript: and data: links that run or carry content.",
     "يرصد روابط javascript: وvbscript: وdata: التي تشغّل أو تحمل محتوى.", ("Script URL scheme", "Data URL"), 1.6, 0.75),
    ("link_odd_port", "Unusual port", "منفذ غير معتاد", "Flags links that use a non-standard port.", "يرصد الروابط التي تستخدم منفذًا غير قياسي.",
     ("Non-standard port",), 0.4, 0.4),
    ("link_encoding_tricks", "Encoded address", "عنوان مرمّز", "Flags percent-encoded host names or paths that hide what they say.",
     "يرصد أسماء مضيفين أو مسارات مرمّزة بالنسبة المئوية تخفي محتواها.", ("Percent-encoded host", "Heavily percent-encoded path"), 0.9, 0.6),
    ("link_direct_download", "Direct file download", "تنزيل ملف مباشر", "Flags links that download a program or an archive directly.",
     "يرصد الروابط التي تنزّل برنامجًا أو أرشيفًا مباشرة.", ("Direct download of executable content", "Direct archive download"), 1.0, 0.6),
    ("link_userinfo_trick", "user@host trick", "خدعة user@host", "Flags addresses like https://bank.com@evil.example that show one site and open another.",
     "يرصد عناوين مثل https://bank.com@evil.example تُظهر موقعًا وتفتح آخر.", ("Embedded credential marker in URL",), 1.4, 0.7),
    ("link_long", "Very long address", "عنوان طويل جدًا", "Flags extremely long links used to push the real destination out of view.",
     "يرصد الروابط الطويلة جدًا المستخدمة لإبعاد الوجهة الحقيقية عن النظر.", ("Excessively long URL", "Very long URL"), 0.3, 0.35),
    ("link_malformed", "Malformed address", "عنوان مشوّه", "Flags control characters, missing hosts and unparseable links that confuse filters.",
     "يرصد محارف التحكم والمضيفين المفقودين والروابط غير القابلة للتحليل التي تربك المرشحات.",
     ("Control characters in URL", "Malformed URL", "URL without host"), 0.8, 0.55),
    ("link_local_file", "Local or network file link", "رابط ملف محلي أو شبكي", "Flags file:// and \\\\server links that open files directly.",
     "يرصد روابط file:// و‎\\\\server‎ التي تفتح ملفات مباشرة.", ("Local/UNC file link",), 1.0, 0.6),
    ("link_exfil_webhook", "Chat-bot data drop", "مكان تسريب عبر بوت محادثة", "Flags Discord/Telegram webhook and bot links often used to send stolen data.",
     "يرصد روابط Discord/Telegram المستخدمة كثيرًا لإرسال البيانات المسروقة.", ("Webhook or bot API exfiltration link",), 1.4, 0.7),
    ("link_redirector", "Hidden second destination", "وجهة ثانية مخفية", "Looks inside query parameters for another address the link forwards to.",
     "يبحث داخل معاملات الاستعلام عن عنوان آخر يحوّل إليه الرابط.", ("Embedded redirect target", "Suspicious redirect destination"), 1.0, 0.6),
    ("link_internal_address", "Internal network address", "عنوان شبكة داخلية", "Flags links to private or local network addresses (unusual in mail and documents).",
     "يرصد الروابط إلى عناوين شبكات خاصة أو محلية (غير معتادة في البريد والمستندات).", ("Internal network address",), 0.3, 0.35),
):
    label_layer(_id, _en, _ar, "links", _cen, _car, labels=_labels, applies=_LINKS, weight=_w, conf=_c,
                scope=("urls", "protection") if _id == "link_brand_lookalike" else ("urls", "heuristics") if _id == "link_userinfo_trick" else ("urls",),
                source=U if _id != "link_brand_lookalike" else "detection.url_intel + core.protection")

label_layer("link_qr_code", "Link inside a QR code", "رابط داخل رمز QR", "links",
            "Decodes QR codes in pictures and checks the link they open (quishing).", "يفك رموز QR في الصور ويفحص الرابط الذي تفتحه (التصيد بالرمز).",
            labels=("Suspicious link in QR code",), applies=lambda f: f["mode"] == "file" and f["kind"] == "image", weight=1.4, conf=0.7,
            source="core.qr_scanner")

# =============================================================== reputation (offline lists and online answers)


def _offline_hash(ctx: LayerContext) -> dict[str, Any]:
    from core import hash_intel  # noqa: PLC0415

    answer = hash_intel.offline_lookup(ctx.sha256(), ctx.md5())
    status = answer.get("status")
    if status == "match":
        return hit(0.99, "This exact file is in the offline known-malware table.", "هذا الملف بعينه في جدول البرمجيات الخبيثة دون إنترنت.",
                   hard="known_malware")
    if status == "not_found":
        return clean(0.35, f"Not among {int(answer.get('entries', 0)):,} known-malware fingerprints.",
                     f"ليس بين {int(answer.get('entries', 0)):,} بصمة لبرمجيات خبيثة معروفة.")
    return unavailable("The offline table is not installed.", "الجدول دون إنترنت غير مثبت.")


register(Layer("offline_hash_table", "Known-malware fingerprints (offline)", "بصمات البرمجيات الخبيثة (دون إنترنت)", "reputation",
               "Looks the file's SHA-256/MD5 up in the bundled table of ~1.5 million known-malware fingerprints.",
               "يبحث عن بصمة SHA-256/MD5 للملف في الجدول المرفق لنحو 1.5 مليون بصمة برمجيات خبيثة معروفة.", 3.0,
               lambda f: f["mode"] == "file" and f["size"] > 0, _offline_hash, "core.hash_intel"))


def _hash_sources(ctx: LayerContext) -> dict[str, Any] | None:
    intel = getattr(ctx.result, "osint_summary", None) or {}
    sources = intel.get("hash_sources")
    return sources if isinstance(sources, dict) else None


def _osint_off(ctx: LayerContext) -> dict[str, Any]:
    status = str((getattr(ctx.result, "osint_summary", None) or {}).get("status", ""))
    if status in {"disabled", "visitor_limit", "user_off"} or status.endswith("_off"):
        return unavailable("Online lookups were off for this scan.", "كانت عمليات البحث عبر الإنترنت متوقفة في هذا الفحص.")
    return unavailable("This service did not answer for this scan.", "لم تُجب هذه الخدمة في هذا الفحص.")


def _service_status(entry: dict[str, Any]) -> str:
    return str((entry or {}).get("status", ""))


_NO_ANSWER = {"no_key": ("No API key is configured.", "لم يُضبط مفتاح الخدمة."), "quota": ("The daily quota is used up.", "نفدت الحصة اليومية."),
              "timeout": ("It did not answer in time.", "لم تُجب في الوقت."), "error": ("It returned an error.", "أعادت خطأ."),
              "unavailable": ("It was unreachable.", "تعذّر الوصول إليها."), "not_applicable": ("Does not apply.", "لا ينطبق.")}


def _no_answer(status: str) -> dict[str, Any]:
    en, ar = _NO_ANSWER.get(status, ("No answer.", "لا إجابة."))
    return unavailable(en, ar, status="not_applicable" if status == "not_applicable" else "unavailable")


def _vt_read(entry: dict[str, Any], what_en: str, what_ar: str) -> dict[str, Any]:
    from core.external_intel import widely_clean  # noqa: PLC0415

    status = _service_status(entry)
    bad, total = int(entry.get("malicious") or 0), int(entry.get("engines_total") or 0)
    if status == "match":
        return hit(0.97, f"{bad}/{total} engines flag {what_en}.", f"{bad}/{total} محركًا تصنّف {what_ar} ضارًا.", hard="many_engines")
    if status == "several":
        return hit(0.85, f"{bad}/{total} engines flag {what_en}.", f"{bad}/{total} محركًا تصنّف {what_ar} ضارًا.",
                   hard="many_engines" if bad >= 5 else None)
    if status == "few":
        return hit(0.35, f"Only {bad}/{total} engine(s) flag {what_en} (often a false alarm).", f"{bad}/{total} فقط تصنّف {what_ar} ضارًا (كثيرًا ما يكون إنذارًا كاذبًا).")
    if status == "clean_report":
        wide = widely_clean(entry)
        return clean(0.75 if wide else 0.5, f"0/{total} engines flag {what_en}" + (" (long known)." if wide else "."),
                     f"0/{total} محركًا تصنّف {what_ar} ضارًا.")
    if status == "not_found":
        return unavailable(f"VirusTotal has never seen {what_en}.", f"لم يرَ VirusTotal {what_ar} من قبل.")
    return _no_answer(status)


def _file_service(name: str):
    def run(ctx: LayerContext) -> dict[str, Any]:
        sources = _hash_sources(ctx)
        if sources is None:
            return _osint_off(ctx)
        entry = sources.get(name) or {}
        status = _service_status(entry)
        if name == "VirusTotal":
            return _vt_read(entry, "this file", "هذا الملف")
        if name == "MalwareBazaar":
            if status == "match":
                return hit(0.97, "MalwareBazaar lists this exact file" + (f": {entry.get('signature')}" if entry.get("signature") else "."),
                           "MalwareBazaar يدرج هذا الملف بعينه.", hard="known_malware")
            if status == "not_found":
                return clean(0.3, "Not in MalwareBazaar's collection.", "ليس ضمن مجموعة MalwareBazaar.")
            return _no_answer(status)
        if name == "CIRCL hashlookup":
            if status == "known_good":
                return clean(0.85, "Known software in CIRCL's database (NSRL): not a modified copy.", "برنامج معروف في قاعدة CIRCL (NSRL): ليس نسخة معدّلة.")
            if status == "not_found":
                return unavailable("Not in CIRCL's known-software list (most files aren't).", "ليس في قائمة CIRCL للبرامج المعروفة (معظم الملفات ليست فيها).",
                                   status="not_applicable")
            return _no_answer(status)
        return _no_answer(status)
    return run


for _id, _svc, _en, _ar, _cen, _car, _w in (
    ("virustotal_file", "VirusTotal", "VirusTotal (file)", "VirusTotal (الملف)", "Reads VirusTotal's report for this file's SHA-256 (the file is never uploaded).",
     "يقرأ تقرير VirusTotal عن بصمة SHA-256 لهذا الملف (لا يُرفع الملف أبدًا).", 2.6),
    ("malwarebazaar", "MalwareBazaar", "MalwareBazaar", "MalwareBazaar", "Asks abuse.ch MalwareBazaar whether this exact file is a collected malware sample.",
     "يسأل MalwareBazaar من abuse.ch إن كان هذا الملف بعينه عينة برمجية خبيثة.", 2.8),
    ("circl_known_good", "CIRCL hashlookup", "CIRCL known software", "CIRCL للبرامج المعروفة", "Asks CIRCL hashlookup (NSRL) whether this is a known, unmodified software file.",
     "يسأل CIRCL hashlookup (NSRL) إن كان هذا ملف برنامج معروفًا غير معدّل.", 1.2),
):
    register(Layer(_id, _en, _ar, "reputation", _cen, _car, _w, lambda f: f["mode"] == "file" and f["has_result"] and f["size"] > 0,
                   _file_service(_svc), _svc, online=True))


def _link_sources(ctx: LayerContext) -> dict[str, Any] | None:
    sources = (getattr(ctx.result, "osint_summary", None) or {}).get("link_sources")
    return sources if isinstance(sources, dict) else None


def _link_service(name: str):
    def run(ctx: LayerContext) -> dict[str, Any]:
        sources = _link_sources(ctx)
        if sources is None:
            return _osint_off(ctx)
        entry = sources.get(name) or {}
        status = _service_status(entry)
        if name.startswith("VirusTotal"):
            return _vt_read(entry, "the link" if name.endswith("(link)") else "the site", "الرابط" if name.endswith("(link)") else "الموقع")
        if status == "match":
            return hit(0.95, f"{name} lists it" + (f": {entry.get('detail')}" if entry.get("detail") else "."), f"{name} يدرجه في قائمته.",
                       hard="listed_link" if name in {"Google Safe Browsing", "URLhaus"} else None)
        if status == "few":
            return hit(0.55, f"{name}: {entry.get('detail') or 'reports about this site'}", f"{name}: بلاغات عن هذا الموقع.")
        if status in {"not_found", "clean_report", "seen"}:
            return clean(0.5, f"Not listed by {name}.", f"غير مدرج لدى {name}.")
        return _no_answer(status)
    return run


for _id, _svc, _en, _ar, _cen, _car, _w in (
    ("virustotal_link", "VirusTotal (link)", "VirusTotal (link)", "VirusTotal (الرابط)", "Reads VirusTotal's vendors' verdicts on this exact link.",
     "يقرأ أحكام مزودي VirusTotal على هذا الرابط بعينه.", 2.4),
    ("virustotal_domain", "VirusTotal (site)", "VirusTotal (site)", "VirusTotal (الموقع)", "Reads VirusTotal's verdicts on the link's domain.",
     "يقرأ أحكام VirusTotal على نطاق الرابط.", 1.6),
    ("safe_browsing", "Google Safe Browsing", "Google Safe Browsing", "التصفح الآمن من Google", "Asks Google Safe Browsing whether the link is listed as phishing or malware.",
     "يسأل التصفح الآمن من Google إن كان الرابط مدرجًا كتصيد أو برمجية خبيثة.", 2.6),
    ("urlhaus_online", "URLhaus", "URLhaus (online)", "URLhaus (عبر الإنترنت)", "Asks abuse.ch URLhaus whether the link or its host serves malware.",
     "يسأل URLhaus من abuse.ch إن كان الرابط أو مضيفه يوزّع برمجيات خبيثة.", 2.4),
    ("otx_pulses", "AlienVault OTX", "AlienVault OTX", "AlienVault OTX", "Counts AlienVault OTX community threat reports (pulses) about the host.",
     "يحصي بلاغات مجتمع AlienVault OTX عن المضيف.", 0.8),
    ("urlscan_verdicts", "urlscan.io", "urlscan.io", "urlscan.io", "Reads other people's public urlscan.io scans of the site for malicious verdicts.",
     "يقرأ فحوص urlscan.io العامة التي أجراها آخرون للموقع بحثًا عن أحكام بالخطورة.", 1.0),
):
    register(Layer(_id, _en, _ar, "reputation", _cen, _car, _w, lambda f: f["mode"] == "url" and f["has_result"], _link_service(_svc), _svc, online=True))


def _offline_lists(ctx: LayerContext) -> dict[str, Any]:
    from core import protection  # noqa: PLC0415

    if not protection.lists_available():
        return unavailable("The offline threat lists are not installed.", "قوائم التهديد دون إنترنت غير مثبتة.")
    listed = [label for label in ctx.protection_labels() if label.startswith(("Known malware", "Known phishing"))]
    if listed:
        return hit(0.95, "On an offline threat list: " + "; ".join(sorted(set(listed))[:2]), "مدرج في قائمة تهديد دون إنترنت.", hard="listed_link")
    return clean(0.45, f"{len(ctx.urls())} link(s) checked against the offline URLhaus and phishing lists.",
                 f"فُحص {len(ctx.urls())} رابط(ة) مقابل قوائم URLhaus والتصيد دون إنترنت.")


register(Layer("offline_link_lists", "Threat lists (offline)", "قوائم التهديد (دون إنترنت)", "reputation",
               "Looks every link up in the bundled URLhaus malware list and Phishing.Database list.",
               "يبحث عن كل رابط في قائمة URLhaus للبرمجيات الخبيثة وقائمة Phishing.Database المرفقتين.", 2.6,
               _LINKS, _offline_lists, "core.protection"))


def _feeds(ctx: LayerContext) -> dict[str, Any]:
    intel = getattr(ctx.result, "osint_summary", None) or {}
    feeds = intel.get("feeds") or {}
    answered = {name: f for name, f in feeds.items() if isinstance(f, dict) and f.get("status") in {"matched", "no_match"}}
    if not answered:
        return _osint_off(ctx)
    matched = [name for name, f in answered.items() if f.get("status") == "matched"]
    if matched:
        return hit(0.7, "Reported by " + ", ".join(matched), "أبلغت عنه " + ", ".join(matched))
    return clean(0.4, "No report in " + ", ".join(answered), "لا بلاغات في " + ", ".join(answered))


register(Layer("public_threat_feeds", "Public threat feeds", "خلاصات التهديد العامة", "reputation",
               "Asks ThreatFox, URLhaus and OTX feeds about the fingerprint, address or domain.",
               "يسأل خلاصات ThreatFox وURLhaus وOTX عن البصمة أو العنوان أو النطاق.", 1.2,
               lambda f: f["mode"] in {"file", "text"} and f["has_result"], _feeds, "core.global_intelligence", online=True))

# =============================================================== YARA rule families
_FAMILIES = (
    ("yara_ransomware", "Ransomware rules", "قواعد برامج الفدية", r"ransom|locker|crypt(?:o)?lock|wannacry|lockbit|conti|ryuk", 2.6),
    ("yara_rat_backdoor", "Remote-access trojans", "أحصنة التحكم عن بعد", r"\brat\b|_rat_|rat_|backdoor|remote.?access|njrat|asyncrat|darkcomet|quasar|remcos", 2.4),
    ("yara_infostealer", "Info-stealers", "سارقو المعلومات", r"stealer|steal|keylog|credential|redline|raccoon|vidar|lumma|agenttesla|formbook", 2.4),
    ("yara_loader", "Loaders and droppers", "المحمّلات والمسقطات", r"loader|dropper|downloader|stager|shellcode", 2.0),
    ("yara_exploit", "Exploit rules", "قواعد الاستغلال", r"exploit|cve[-_]?\d{4}", 2.2),
    ("yara_webshell", "Web shells", "صدفات الويب", r"webshell|web_shell|china.?chopper", 2.2),
    ("yara_hacktool", "Hacking tools", "أدوات الاختراق", r"hacktool|mimikatz|cobalt.?strike|sliver|metasploit|meterpreter|impacket|bloodhound|rubeus", 2.0),
    ("yara_packer", "Packer and crypter rules", "قواعد الضغط والتشفير", r"packer|packed|crypter|obfusc|upx|themida|vmprotect|enigma|aspack|mpress", 0.9),
    ("yara_miner", "Coin-miner rules", "قواعد المعدّنات", r"miner|xmrig|monero|cryptonight|coinhive", 1.8),
    ("yara_maldoc", "Malicious document rules", "قواعد المستندات الخبيثة", r"maldoc|phish|macro|\bvba\b|office|\bpdf\b|\brtf\b|\bole\b|\bxlm\b", 1.6),
    ("yara_suspicious", "Generic suspicious rules", "قواعد الاشتباه العامة", r"^susp|suspicious|anomal|\bsusp_|_susp_", 0.8),
)
_ORDERED = [(family[0], re.compile(family[3], re.I)) for family in _FAMILIES]


def _rule_text(match: dict[str, Any]) -> str:
    meta = match.get("meta") or {}
    return " ".join([str(match.get("rule_name", "")), " ".join(map(str, match.get("tags") or [])),
                     str(meta.get("description", ""))[:200], str(meta.get("malware_family", meta.get("family", "")))])


def _family_of(match: dict[str, Any]) -> str:
    """Each rule counts in exactly one family: the first that fits, else "other known families"."""
    text = _rule_text(match)
    for family, pattern in _ORDERED:
        if pattern.search(text):
            return family
    return "yara_other_family"


def _yara_family(family: str, en: str, ar: str):
    def run(ctx: LayerContext) -> dict[str, Any]:
        matches = list(getattr(ctx.result, "yara_matches", None) or [])
        mine = [m for m in matches if _family_of(m) == family]
        if mine:
            names = ", ".join(str(m.get("rule_name", "?")) for m in mine[:3])
            return hit(0.85, f"{len(mine)} rule(s): {names}", f"{len(mine)} قاعدة: {names}")
        return clean(0.55, f"No {en.lower()} matched.", f"لم تطابق أي {ar}.")
    return run


for _id, _en, _ar, _pattern, _w in (*_FAMILIES, ("yara_other_family", "Other known families", "عائلات معروفة أخرى", "", 2.0)):
    register(Layer(_id, _en, _ar, "yara",
                   f"Runs the 5,000+ YARA-Forge and bundled rules and counts matches in the '{_en}' family.",
                   f"يشغّل أكثر من 5,000 قاعدة YARA-Forge والقواعد المرفقة ويحصي المطابقات في عائلة «{_ar}».",
                   _w, lambda f: f["mode"] == "file" and f["yara"], _yara_family(_id, _en, _ar), "YARA-X + YARA-Forge"))

# =============================================================== machine learning


def _structural(ctx: LayerContext) -> dict[str, Any]:
    prediction = getattr(ctx.result, "structural_prediction", None) or {}
    label = prediction.get("label")
    if prediction.get("status") in {None, "untrained"} or label is None:
        return unavailable("No approved structural model is installed.", "لا يوجد نموذج بنيوي معتمد مثبت.")
    if prediction.get("abstained"):
        return unavailable("The model was not sure and abstained.", "لم يكن النموذج متأكدًا فامتنع.")
    if label in {"malware", "suspicious"}:
        return hit(0.6, f"The structural model says '{label}' (uncalibrated).", f"النموذج البنيوي يقول «{label}» (غير معاير).")
    return clean(0.5, "The structural model says 'clean' (uncalibrated).", "النموذج البنيوي يقول «سليم» (غير معاير).")


register(Layer("ml_structural", "Structural model", "النموذج البنيوي", "ml",
               "A trained classifier reads a 4,096-dimension structural fingerprint of the bytes.",
               "مصنّف مدرَّب يقرأ بصمة بنيوية من 4,096 بُعدًا للبايتات.", 1.0,
               lambda f: f["mode"] == "file" and f["has_result"] and f["size"] > 0, _structural, "ml.model_runtime"))

# The EMBER2024 models (core.ml_malware, PE and PDF): the scan's own assessment is read first
# (feature_summary["ml_malware_model"]); otherwise the module is imported defensively and asked.
def _ml_record(ctx: LayerContext) -> dict[str, Any] | None:
    record = ctx.feature_summary.get("ml_malware_model")
    if isinstance(record, dict) and record.get("status"):
        return record
    try:
        ml_malware = importlib.import_module("core.ml_malware")
    except Exception:  # noqa: BLE001 - ImportError or a broken module: "not available"
        return None
    try:
        out = ml_malware.assess(ctx.raw)
    except Exception:  # noqa: BLE001
        return None
    return out if isinstance(out, dict) else None


def _ember(ctx: LayerContext) -> dict[str, Any]:
    record = _ml_record(ctx)
    if record is None:
        return unavailable("The EMBER2024 model is not available in this build.", "نموذج EMBER2024 غير متاح في هذه النسخة.")
    status = record.get("status")
    if status == "not_applicable":
        return unavailable(str(record.get("detail", "No model for this kind of file."))[:200], "لا يوجد نموذج لهذا النوع من الملفات.",
                           status="not_applicable")
    if status != "scored":
        return unavailable(f"Model {status}: {str(record.get('detail', ''))[:150]}", "تعذّر على النموذج تقييم هذا الملف.")
    score, band = float(record.get("score", 0.0)), str(record.get("band", ""))
    model = str(record.get("model", "EMBER2024 model"))
    if band in {"high", "elevated"}:
        return hit(0.8 if band == "high" else 0.5, f"{model} scores {score:.2f} ({band}; review threshold {record.get('threshold_review')}).",
                   f"النموذج يعطي {score:.2f} ({'مرتفع' if band == 'high' else 'مرتفع نسبيًا'}).")
    return clean(0.6 if band == "low" else 0.35, f"{model} scores {score:.2f} ({band}).",
                 f"النموذج يعطي {score:.2f} ({'منخفض' if band == 'low' else 'غير حاسم'}).")


register(Layer("ml_ember2024", "EMBER2024 malware model", "نموذج EMBER2024 للبرمجيات الخبيثة", "ml",
               "A gradient-boosted model trained on EMBER2024 reads 2,568 static features of a Windows program or PDF.",
               "نموذج معزز بالتدرج مدرَّب على EMBER2024 يقرأ 2,568 خاصية ساكنة لبرنامج ويندوز أو ملف PDF.", 1.4,
               lambda f: f["mode"] == "file" and f["kind"] in {"pe", "pdf"}, _ember, "core.ml_malware (EMBER2024)"))
