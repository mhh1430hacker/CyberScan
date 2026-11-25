"""Stable codes and plain-language text (English and Arabic) for what the engines report.

The engines describe themselves in compact, technical status strings ("not_pe",
"partial_timeout", "available; 5090 rule(s) loaded"). Those strings stay in the result for the
advanced view and the reports, but a person should never have to read them. Every function here
turns one of them into::

    {"code": "<stable identifier>", "state": "<ran|not_applicable|disabled|unavailable|partial|failed>",
     "en": "<sentence>", "ar": "<sentence>"}

``code`` never changes wording-wise, so the interface (or another language) can key on it.
Nothing here changes a score, a verdict or a finding.
"""
from __future__ import annotations

import re
from typing import Any

# ----------------------------------------------------------------------------- helpers


def _size(size: int, lang: str) -> str:
    if size >= 1024 * 1024:
        value = f"{size / (1024 * 1024):.1f} MB"
    elif size >= 1024:
        value = f"{size / 1024:.1f} KB"
    else:
        value = f"{size} B"
    return f"⁨{value}⁩" if lang == "ar" else value


def _n(value: int, lang: str) -> str:
    text = f"{int(value):,}"
    return f"⁨{text}⁩" if lang == "ar" else text


def text(code: str, en: str, ar: str, state: str | None = None, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "en": en, "ar": ar}
    if state is not None:
        out["state"] = state
    out.update(extra)
    return out


# ----------------------------------------------------------------------------- scan stages

STAGE_RUNNING = {
    0: ("stage.static.running", "Reading the target and running the static checks", "نقرأ الهدف ونُجري الفحوص الثابتة"),
    1: ("stage.entropy.running", "Measuring how random the content is", "نقيس مدى عشوائية المحتوى"),
    2: ("stage.structure.running", "Building the structural fingerprint", "نبني البصمة البنيوية"),
    3: ("stage.osint.running", "Checking public threat-intelligence sources", "نراجع مصادر معلومات التهديدات العامة"),
}


def stage_running(index: int) -> dict[str, Any]:
    code, en, ar = STAGE_RUNNING[index]
    return text(code, en, ar)


def stage_static_done(mode: str, size: int) -> dict[str, Any]:
    if mode == "URL":
        return text("stage.static.done_url", "Checked the link's address against the rules and threat lists",
                    "فحصنا عنوان الرابط بالقواعد وقوائم التهديدات")
    if mode != "File":
        return text("stage.static.done_text", f"Checked the text ({size:,} characters) against the rules",
                    f"فحصنا النص ({_n(size, 'ar')} حرفًا) بالقواعد")
    if size == 0:
        return text("stage.static.empty", "The file is empty: there is nothing to check", "الملف فارغ: لا يوجد ما يُفحص")
    return text("stage.static.done_file", f"Read the whole file ({_size(size, 'en')}) and ran the static checks",
                f"قرأنا الملف كاملًا ({_size(size, 'ar')}) وأجرينا الفحوص الثابتة")


def stage_entropy_done(windows: int, enabled: bool = True) -> dict[str, Any]:
    if not enabled:
        return text("stage.entropy.disabled", "Randomness measurement is turned off in Settings", "قياس العشوائية متوقف في الإعدادات")
    if windows <= 1:
        return text("stage.entropy.done_one", "Measured how random the content is", "قسنا مدى عشوائية المحتوى")
    return text("stage.entropy.done", f"Measured randomness across {windows:,} parts of the content",
                f"قسنا العشوائية عبر {_n(windows, 'ar')} جزءًا من المحتوى")


def stage_structure_done(prediction: dict[str, Any] | None) -> dict[str, Any]:
    prediction = prediction or {}
    status = str(prediction.get("status") or "untrained")
    label = prediction.get("label")
    if prediction.get("abstained"):
        return text("stage.structure.model_unsure", "Structural fingerprint ready; the learning model wasn't sure",
                    "البصمة البنيوية جاهزة؛ لم يكن نموذج التعلّم متأكدًا")
    if label:
        return text("stage.structure.model_ran", f"Structural fingerprint ready; the learning model suggests: {label}",
                    f"البصمة البنيوية جاهزة؛ يرجّح نموذج التعلّم: {label}", label=str(label))
    if status in {"untrained", "unavailable", "unapproved"}:
        return text("stage.structure.no_model", "Structural fingerprint ready (no learning model is installed)",
                    "البصمة البنيوية جاهزة (لا يوجد نموذج تعلّم مثبّت)")
    return text("stage.structure.done", "Structural fingerprint ready", "البصمة البنيوية جاهزة")


def stage_skipped(index: int) -> dict[str, Any]:
    return text("stage.skipped_time_limit", "Skipped: the time limit was reached", "تُخطّي: بلغ الفحص حدّه الزمني")


# ----------------------------------------------------------------------------- online lookups

OSINT = {
    "matched": ("osint.matched", "ran", "A public threat-intelligence source lists this", "أحد مصادر معلومات التهديدات العامة يُدرج هذا الهدف"),
    "no_match": ("osint.no_match", "ran", "Public sources checked: not listed", "راجعنا المصادر العامة: غير مُدرج"),
    "partial_timeout": ("osint.partial_timeout", "partial", "Some public sources didn't answer in time", "بعض المصادر العامة لم تُجب في الوقت المحدد"),
    "unavailable": ("osint.unavailable", "unavailable", "Public sources aren't reachable right now (offline or no keys)",
                    "المصادر العامة غير متاحة الآن (لا اتصال أو لا مفاتيح)"),
    "disabled": ("osint.disabled", "disabled", "Online lookups are turned off in Settings", "عمليات البحث عبر الإنترنت متوقفة في الإعدادات"),
    "not_requested": ("osint.disabled", "disabled", "Online lookups are turned off in Settings", "عمليات البحث عبر الإنترنت متوقفة في الإعدادات"),
    "not_applicable": ("osint.not_applicable", "not_applicable", "Online lookups don't apply to free text",
                       "البحث عبر الإنترنت لا ينطبق على النص الحر"),
    "invalid_indicator": ("osint.not_applicable", "not_applicable", "Online lookups don't apply to free text",
                          "البحث عبر الإنترنت لا ينطبق على النص الحر"),
    "skipped": ("osint.skipped_time_limit", "partial", "Skipped: the time limit was reached", "تُخطّي: بلغ الفحص حدّه الزمني"),
    "off_for_scan": ("osint.off_for_scan", "disabled", "Online lookups were turned off for this scan", "أُوقف البحث عبر الإنترنت لهذا الفحص"),
    "rate_limited": ("osint.rate_limited", "disabled", "Online lookups skipped: too many from your connection in a short time; try again in a few minutes",
                     "تُخطّي البحث عبر الإنترنت: طلبات كثيرة من اتصالك في وقت قصير؛ أعد المحاولة بعد دقائق"),
}


def osint_text(status: Any, *, file_mode: bool = False) -> dict[str, Any]:
    code, state, en, ar = OSINT.get(str(status or "").strip(), ("osint.unknown", "unknown", "Online lookups: no answer", "البحث عبر الإنترنت: لا إجابة"))
    if file_mode and state in {"ran", "partial"}:
        en += " (only the file's fingerprint was sent, never its contents)"
        ar += " (أُرسلت بصمة الملف فقط، لا محتواه)"
    return text(code, en, ar, state)


HASH_SOURCE = {
    "match": ("hash.match", "Lists this exact file as malware", "يُدرج هذا الملف بعينه كبرنامج ضار"),
    "not_found": ("hash.not_found", "Not listed", "غير مُدرج"),
    "known_good": ("hash.known_good", "Known, legitimate software", "برنامج معروف وموثوق"),
    "few": ("hash.few", "A few antivirus engines flag it", "عدد قليل من محركات مكافحة الفيروسات يشير إليه"),
    "clean_report": ("hash.clean", "Known and not flagged", "معروف ولا يُشار إليه بشيء"),
    "no_key": ("hash.no_key", "Not checked: no API key is saved", "لم يُفحص: لا يوجد مفتاح API محفوظ"),
    "timeout": ("hash.timeout", "Didn't answer in time", "لم يُجب في الوقت المحدد"),
    "error": ("hash.error", "Couldn't be reached", "تعذّر الوصول إليه"),
    "unavailable": ("hash.unavailable", "Database not installed", "قاعدة البيانات غير مثبّتة"),
    "several": ("hash.several", "Several antivirus engines flag it", "عدة محركات لمكافحة الفيروسات تشير إليه"),
    "quota": ("hash.quota", "Not checked: the free quota is used up for now", "لم يُفحص: نفدت الحصة المجانية مؤقتًا"),
    "seen": ("hash.seen", "Seen before, nothing flagged", "شوهد من قبل ولم يُشر إليه بشيء"),
    "not_applicable": ("hash.not_applicable", "Doesn't apply here", "لا ينطبق هنا"),
}


def hash_source_text(entry: Any) -> dict[str, Any]:
    status = str((entry or {}).get("status", "")) if isinstance(entry, dict) else str(entry or "")
    code, en, ar = HASH_SOURCE.get(status, ("hash.unknown", "No answer", "لا إجابة"))
    return text(code, en, ar)


# ----------------------------------------------------------------------------- engine statuses

ENGINE_NAMES = {
    "YARA": ("Known-pattern rules", "قواعد الأنماط المعروفة"),
    "PE": ("Program structure", "بنية البرنامج"),
    "ML": ("Learning model", "نموذج التعلّم"),
    "Dissonance": ("Claim versus abilities", "الادعاء مقابل القدرات"),
    "Surprise map": ("Out-of-place content", "محتوى في غير موضعه"),
    "Archive": ("Archive contents", "محتويات الأرشيف"),
    "OSINT": ("Online lookups", "البحث عبر الإنترنت"),
    "Heuristics": ("Warning-sign rules", "قواعد علامات التحذير"),
    "YARA-Forge": ("Community rules (YARA-Forge)", "قواعد المجتمع (YARA-Forge)"),
    "Threat lists": ("Link threat lists", "قوائم الروابط الخطرة"),
    "Secret patterns": ("Secret patterns", "أنماط الأسرار"),
    "Hash database": ("Known-malware fingerprints", "بصمات البرامج الضارة المعروفة"),
    "Content inspection": ("Content inspection", "فحص المحتوى"),
}


def _number(pattern: str, raw: str) -> int | None:
    match = re.search(pattern, raw.replace(",", ""))
    return int(match.group(1)) if match else None


def engine_text(name: str, raw: Any) -> dict[str, Any]:
    """Plain words (and a coverage state) for one ``engine_status`` entry."""
    status = str(raw or "").strip()
    low = status.lower()
    names = ENGINE_NAMES.get(name, (name, name))
    base = {"engine": name, "name_en": names[0], "name_ar": names[1], "raw": status}

    def out(code: str, state: str, en: str, ar: str) -> dict[str, Any]:
        return {**base, **text(code, en, ar, state)}

    if name == "YARA":
        rules = _number(r"(\d+) rule", low)
        if low.startswith("available") and rules:
            if re.search(r"loaded\s*\(", low):   # "... rule(s) loaded (<error>)": the scan stopped part-way
                return out("yara.partial", "partial", f"Checked with {rules:,} rules, but part of the rule scan didn't finish",
                           f"فُحص بـ {_n(rules, 'ar')} قاعدة، لكن جزءًا من الفحص لم يكتمل")
            return out("yara.ran", "ran", f"Checked with {rules:,} rules", f"فُحص بـ {_n(rules, 'ar')} قاعدة")
        if "no rules" in low:
            return out("yara.no_rules", "unavailable", "No rules are installed", "لا توجد قواعد مثبّتة")
        return out("yara.unavailable", "unavailable", "The rule engine isn't available on this computer", "محرك القواعد غير متاح على هذا الجهاز")
    if name == "PE":
        if low == "ok":
            return out("pe.ok", "ran", "Read the Windows program's structure", "قرأنا بنية برنامج ويندوز")
        if low.startswith("malformed"):
            return out("pe.malformed", "ran", "Starts like a Windows program, but its header is damaged and can't be read",
                       "يبدأ كبرنامج ويندوز، لكن ترويسته تالفة ولا يمكن قراءتها")
        if low in {"not_pe", "not a program"}:
            return out("pe.not_applicable", "not_applicable", "Not a Windows program, so this check doesn't apply",
                       "ليس برنامج ويندوز، لذا لا ينطبق هذا الفحص")
        if "disabled" in low:
            return out("pe.disabled", "disabled", "Turned off in Settings", "متوقف في الإعدادات")
        return out("pe.failed", "failed", "Couldn't read the program's structure", "تعذّرت قراءة بنية البرنامج")
    if name == "ML":
        if "disabled" in low:
            return out("ml.disabled", "disabled", "Turned off in Settings", "متوقف في الإعدادات")
        if "not sure" in low:
            return out("ml.unsure", "ran", "Ran, but wasn't sure; the verdict rests on the other checks",
                       "عمل لكنه لم يكن متأكدًا؛ الحكم يعتمد على الفحوص الأخرى")
        if "loaded" in low and "4096" in low:
            return out("ml.ran", "ran", "Ran (its scores are a guide, not a probability)", "عمل (درجاته إرشادية وليست احتمالًا)")
        if "rejected" in low:
            return out("ml.rejected", "unavailable", "The installed model was rejected, so it wasn't used", "رُفض النموذج المثبّت فلم يُستخدم")
        return out("ml.not_installed", "unavailable", "No approved learning model is installed; the verdict rests on the other checks",
                   "لا يوجد نموذج تعلّم معتمد مثبّت؛ الحكم يعتمد على الفحوص الأخرى")
    if name == "Dissonance":
        if low.startswith("skipped"):
            return out("dissonance.skipped_malformed", "not_applicable", "Skipped: the program's header is damaged",
                       "تُخطّي: ترويسة البرنامج تالفة")
        if low.startswith("not a program"):
            return out("dissonance.not_applicable", "not_applicable", "Only applies to programs", "ينطبق على البرامج فقط")
        if low.startswith("low"):
            return out("dissonance.agree", "ran", "What it claims to be matches what it can do", "ما يدّعيه يطابق ما يستطيع فعله")
        if low.startswith(("medium", "high")):
            return out("dissonance.disagree", "ran", "What it claims to be and what it can do differ", "ما يدّعيه يختلف عمّا يستطيع فعله")
        if "time limit" in low:
            return out("dissonance.skipped_time", "partial", "Skipped: the time limit was reached", "تُخطّي: بلغ الفحص حدّه الزمني")
        return out("dissonance.unknown", "unknown", "No answer", "لا إجابة")
    if name == "Surprise map":
        if low.startswith("skipped"):
            return out("surprise.skipped_malformed", "not_applicable", "Skipped: the program's header is damaged", "تُخطّي: ترويسة البرنامج تالفة")
        if low.startswith("not a program"):
            return out("surprise.not_applicable", "not_applicable", "Only applies to programs", "ينطبق على البرامج فقط")
        if "profile unavailable" in low:
            return out("surprise.no_profile", "unavailable", "Its reference profile isn't installed", "ملف المرجع الخاص به غير مثبّت")
        if "time limit" in low:
            return out("surprise.skipped_time", "partial", "Skipped: the time limit was reached", "تُخطّي: بلغ الفحص حدّه الزمني")
        regions = _number(r"(\d+) foreign", low) or 0
        if regions:
            return out("surprise.found", "ran", f"Found {regions:,} out-of-place region(s) in the program code",
                       f"وُجدت {_n(regions, 'ar')} منطقة في غير موضعها داخل شيفرة البرنامج")
        return out("surprise.clean", "ran", "Nothing out of place in the program code", "لا شيء في غير موضعه داخل شيفرة البرنامج")
    if name == "Archive":
        if low.startswith("not a zip"):
            return out("archive.not_applicable", "not_applicable", "Not an archive", "ليس أرشيفًا")
        members = _number(r"(\d+) member", low) or 0
        scanned = _number(r"(\d+) scanned", low)
        if "time limit" in low:
            return out("archive.members_skipped_time", "partial",
                       f"Listed {members:,} file(s) inside; scanning them was skipped at the time limit",
                       f"عُدّت {_n(members, 'ar')} ملفات داخله؛ وتُخطّي فحصها عند بلوغ الحد الزمني")
        if scanned is not None:
            state = "ran" if scanned >= members else "partial"
            return out("archive.members_scanned" if state == "ran" else "archive.members_partly_scanned", state,
                       f"Opened in memory: {scanned:,} of {members:,} file(s) inside were scanned",
                       f"فُتح في الذاكرة: فُحص {_n(scanned, 'ar')} من {_n(members, 'ar')} ملفات داخله")
        if "disabled" in low:
            return out("archive.members_disabled", "partial", f"Listed {members:,} file(s) inside; scanning them is turned off in Settings",
                       f"عُدّت {_n(members, 'ar')} ملفات داخله؛ وفحصها متوقف في الإعدادات")
        return out("archive.structure_only", "partial", f"Listed {members:,} file(s) inside; their contents weren't scanned",
                   f"عُدّت {_n(members, 'ar')} ملفات داخله؛ ولم يُفحص محتواها")
    if name == "OSINT":
        return {**base, **osint_text(low)}
    if name == "Heuristics":
        if "disabled" in low:
            return out("heuristics.disabled", "disabled", "Turned off in Settings", "متوقف في الإعدادات")
        return out("heuristics.ran", "ran", "Checked", "تم الفحص")
    if name == "YARA-Forge":
        rules = _number(r"(\d+) rules", low)
        return out("forge.loaded", "ran", f"{rules:,} community rules loaded" if rules else "Community rules loaded",
                   f"حُمّلت {_n(rules, 'ar')} قاعدة من قواعد المجتمع" if rules else "حُمّلت قواعد المجتمع")
    if name == "Threat lists":
        urlhaus = _number(r"urlhaus (\d+)", low) or 0
        phishing = _number(r"phishing (\d+)", low) or 0
        return out("lists.loaded", "ran", f"Malware links (URLhaus, {urlhaus:,}) and phishing sites ({phishing:,}) loaded",
                   f"حُمّلت روابط البرامج الضارة (URLhaus، {_n(urlhaus, 'ar')}) ومواقع التصيّد ({_n(phishing, 'ar')})")
    if name == "Secret patterns":
        rules = _number(r"(\d+) rules", low)
        return out("secrets.loaded", "ran", f"{rules:,} secret patterns loaded" if rules else "Secret patterns loaded",
                   f"حُمّل {_n(rules, 'ar')} نمطًا للأسرار" if rules else "حُمّلت أنماط الأسرار")
    if name == "Hash database":
        count = _number(r"(\d+) known", low)
        return out("hashes.loaded", "ran", f"{count:,} known-malware fingerprints loaded" if count else "Known-malware fingerprints loaded",
                   f"حُمّلت {_n(count, 'ar')} بصمة لبرامج ضارة معروفة" if count else "حُمّلت بصمات البرامج الضارة المعروفة")
    if name == "Content inspection":
        if low == "complete":
            return out("content.complete", "ran", "Checked the content independently", "فُحص المحتوى بشكل مستقل")
        if low == "partial":
            return out("content.partial", "partial", "Only part of the content could be inspected", "لم يُفحص سوى جزء من المحتوى")
        if low == "timeout":
            return out("content.timeout", "partial", "Didn't finish within the time limit", "لم يكتمل ضمن الحد الزمني")
        if low == "busy":
            return out("content.busy", "partial", "Skipped: the scanner was busy", "تُخطّي: كان الماسح مشغولًا")
        return out("content.failed", "failed", "Couldn't run", "تعذّر التشغيل")
    return out("engine.other", "unknown", status or "No answer", status or "لا إجابة")


# ----------------------------------------------------------------------------- verdicts and errors

VERDICTS = {
    "KNOWN_MALWARE": ("Known malware", "برنامج ضار معروف",
                      "This exact file is listed as malware by a threat-intelligence source. Delete it.",
                      "هذا الملف بعينه مُدرج كبرنامج ضار لدى مصدر لمعلومات التهديدات. احذفه."),
    "SUSPICIOUS": ("Suspicious", "مريب",
                   "Strong warning signs. Don't open or run it unless you know exactly where it came from.",
                   "علامات تحذير قوية. لا تفتحه ولا تشغّله إلا إذا كنت تعرف مصدره بدقة."),
    "REVIEW": ("Worth a closer look", "يستحق نظرة أدق",
               "A few things stood out. They are often harmless, but read the findings before you trust it.",
               "لفتت انتباهنا بعض الأمور. غالبًا ما تكون غير ضارة، لكن اقرأ النتائج قبل أن تثق به."),
    "NO_INDICATORS_OBSERVED": ("No warning signs found", "لم نجد علامات تحذير",
                               "The checks we ran found nothing concerning. This is not a guarantee, only that nothing stood out.",
                               "لم تجد الفحوص التي أجريناها ما يثير القلق. هذا ليس ضمانًا، بل يعني أن شيئًا لم يلفت الانتباه."),
    "UNKNOWN": ("We couldn't finish the check", "لم نتمكن من إكمال الفحص",
                "Part of the analysis didn't complete, so this result can't confirm the target is clean.",
                "لم يكتمل جزء من التحليل، لذا لا يمكن لهذه النتيجة تأكيد سلامة الهدف."),
    "EMPTY": ("Empty file: nothing to analyse", "ملف فارغ: لا يوجد ما يُحلَّل",
              "The file has 0 bytes, so there is nothing inside it to check. If you expected content, the file may be broken or still downloading.",
              "حجم الملف 0 بايت، فلا يوجد بداخله ما يُفحص. إن كنت تتوقع محتوى، فقد يكون الملف تالفًا أو لم يكتمل تنزيله."),
}


def verdict_text(classification: str, score: int | None = None) -> dict[str, Any]:
    title_en, title_ar, body_en, body_ar = VERDICTS.get(classification, VERDICTS["UNKNOWN"])
    return {"code": f"verdict.{classification.lower()}", "classification": classification, "score": score,
            "title": {"en": title_en, "ar": title_ar}, "body": {"en": body_en, "ar": body_ar}}


ERRORS = {
    "timeout": ("The check took longer than its time limit, so it was stopped. Try again; a busy computer is the usual cause.",
                "استغرق الفحص أطول من حدّه الزمني فأُوقف. حاول مرة أخرى؛ انشغال الجهاز هو السبب المعتاد."),
    "partial_timeout": ("Part of the check didn't finish within the time limit. What finished is shown below.",
                        "لم يكتمل جزء من الفحص ضمن الحد الزمني. يظهر أدناه ما اكتمل."),
    "busy": ("The scanner is busy with other checks. Try again in a moment.", "الماسح مشغول بفحوص أخرى. حاول بعد لحظات."),
    "too_large": ("The file is larger than this scanner accepts.", "الملف أكبر مما يقبله هذا الماسح."),
    "empty_input": ("There is nothing to check: the input is empty.", "لا يوجد ما يُفحص: المُدخل فارغ."),
    "not_found": ("The file is no longer where it was.", "لم يعد الملف في مكانه."),
    "unreadable": ("The file couldn't be read. It may be open in another program or you may not have permission.",
                   "تعذّرت قراءة الملف. ربما هو مفتوح في برنامج آخر أو ليست لديك صلاحية."),
    "analysis_failed": ("The check couldn't finish because of an internal problem. Try again; if it keeps happening, the file may be unusual or damaged.",
                        "تعذّر إكمال الفحص بسبب مشكلة داخلية. حاول مرة أخرى؛ وإن تكرر ذلك فقد يكون الملف غير معتاد أو تالفًا."),
    "empty_file": ("Empty file: there is nothing to analyse. The file has 0 bytes; if you expected content, it may be broken or still downloading.",
                   "ملف فارغ: لا يوجد ما يُحلَّل. حجم الملف 0 بايت؛ إن كنت تتوقع محتوى فقد يكون تالفًا أو لم يكتمل تنزيله."),
    "content_incomplete": ("The independent content inspection didn't finish, so the result rests on the other checks only.",
                           "لم يكتمل فحص المحتوى المستقل، لذا تعتمد النتيجة على الفحوص الأخرى فقط."),
}


def error_text(code: str) -> dict[str, Any]:
    en, ar = ERRORS.get(code, ERRORS["analysis_failed"])
    return {"code": code if code in ERRORS else "analysis_failed", "message": en, "en": en, "ar": ar}


# ----------------------------------------------------------------------------- link threat lists


def link_check_text(status: dict[str, Any]) -> dict[str, Any]:
    """Words for ``core.protection.url_list_status``: were the link lists checked, and the answer."""
    if not status.get("checked"):
        return text("links.unavailable", "The link threat lists aren't installed, so this link wasn't checked against them",
                    "قوائم الروابط الخطرة غير مثبّتة، لذا لم يُطابَق هذا الرابط معها", "unavailable")
    if status.get("urlhaus") == "listed_url":
        return text("links.listed_malware_url", "Listed: URLhaus lists this exact address as serving malware",
                    "مُدرج: تُدرج URLhaus هذا العنوان بعينه كمصدر لبرامج ضارة", "ran")
    if status.get("urlhaus") == "listed_host":
        return text("links.listed_malware_host", "Listed: URLhaus lists this site as serving malware",
                    "مُدرج: تُدرج URLhaus هذا الموقع كمصدر لبرامج ضارة", "ran")
    if status.get("phishing") == "listed":
        return text("links.listed_phishing", "Listed: this site is on the list of active phishing sites",
                    "مُدرج: هذا الموقع ضمن قائمة مواقع التصيّد النشطة", "ran")
    return text("links.not_listed", "Checked against the malware-link (URLhaus) and phishing lists: not listed",
                "طابقناه مع قائمتي روابط البرامج الضارة (URLhaus) والتصيّد: غير مُدرج", "ran")
