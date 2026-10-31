"""Plain words for the engine's findings, in English and Arabic.

The engine names its findings in technical English ("Entropy discontinuity",
"EncodedPowerShell", "Header mismatch"). This catalogue gives each known one
a plain title and a one-line explanation of what it means, in both languages.
Explanations that carry measured values (offsets, counts, deltas) are parsed
so the numbers appear in the plain sentence unchanged.

Nothing here changes a finding: severity, category, contribution and the
engine's own text are kept and shown as-is in the advanced data. A finding
that is not in the catalogue keeps the engine's words.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ui.plain_language import humanize_title, isolate


@dataclass(frozen=True)
class PlainText:
    title: str
    body: str
    known: bool


# title -> ((english title, english body), (arabic title, arabic body))
_CATALOGUE: dict[str, tuple[tuple[str, str], tuple[str, str]]] = {}


def _add(names: tuple[str, ...], en: tuple[str, str], ar: tuple[str, str]) -> None:
    for name in names:
        _CATALOGUE[name.casefold()] = (en, ar)


_add(
    ("Double extension", "Double extension spoofing"),
    ("Disguised file type", "The name ends in a harmless-looking type followed by a program type, a common trick to make a program look like a document."),
    ("نوع ملف مموَّه", "ينتهي الاسم بنوع يبدو آمنًا يليه نوع برنامج، وهي حيلة شائعة لجعل البرنامج يبدو كأنه مستند."),
)
_add(
    ("Executable extension", "Executable file extension"),
    ("Program file type", "Its file type means it can run as a program when opened."),
    ("نوع ملف برنامج", "نوع هذا الملف يعني أنه قد يعمل كبرنامج عند فتحه."),
)
_add(
    ("Header mismatch",),
    ("The content doesn't match the name", "The name says one file type, but the content starts like another."),
    ("المحتوى لا يطابق الاسم", "الاسم يدل على نوع ملف، بينما يبدأ المحتوى كنوع آخر."),
)
_add(
    ("High entropy",),
    ("Very random content", "Large parts look scrambled. That is normal for compressed or encrypted data, and is also a way to hide code."),
    ("محتوى عشوائي جدًا", "أجزاء كبيرة تبدو مبعثرة. هذا طبيعي في البيانات المضغوطة أو المشفّرة، وهو أيضًا طريقة لإخفاء الشيفرة."),
)
_add(
    ("Entropy discontinuity",),
    ("Sudden change in the content", "The content changes abruptly in one place. Hidden or packed data often looks like this."),
    ("تغيّر مفاجئ في المحتوى", "يتغيّر المحتوى فجأة في موضع ما. البيانات المخفية أو المضغوطة كثيرًا ما تبدو هكذا."),
)
_add(
    ("Static decoding indicator", "PE structural obfuscation indicator"),
    ("Unusual code patterns", "The code contains patterns often used to make programs hard to inspect. A reason to look closer, not proof."),
    ("أنماط شيفرة غير عادية", "تحتوي الشيفرة على أنماط تُستخدم كثيرًا لجعل البرامج صعبة الفحص. سبب للتدقيق، وليس دليلًا."),
)
_add(
    ("Suspicious PE imports",),
    ("Asks for risky abilities", "The program uses Windows functions often used to write into other programs' memory."),
    ("يطلب قدرات خطرة", "يستخدم البرنامج دوال Windows تُستخدم كثيرًا للكتابة في ذاكرة برامج أخرى."),
)
_add(
    ("YARA match",),
    ("Matches a known risky pattern", "One of the known-pattern rules matched this file."),
    ("يطابق نمطًا خطرًا معروفًا", "طابقت إحدى قواعد الأنماط المعروفة هذا الملف."),
)
_add(
    ("EncodedPowerShell", "Encoded PowerShell execution", "Base64 encoded PowerShell"),
    ("Hidden PowerShell command", "Contains a PowerShell command that is encoded to hide what it does."),
    ("أمر PowerShell مخفي", "يحتوي على أمر PowerShell مُرمَّز لإخفاء ما يفعله."),
)
_add(
    ("SuspiciousProcessInjection",),
    ("Can tamper with other programs", "Contains functions used to put code inside other running programs."),
    ("قد يعبث ببرامج أخرى", "يحتوي على دوال تُستخدم لزرع شيفرة داخل برامج أخرى قيد التشغيل."),
)
_add(
    ("ShadowCopyDeletion",),
    ("Can delete backup copies", "Contains a command that deletes Windows backup copies, a step ransomware often takes."),
    ("قد يحذف النسخ الاحتياطية", "يحتوي على أمر يحذف نسخ Windows الاحتياطية، وهي خطوة تقوم بها برامج الفدية كثيرًا."),
)
_add(
    ("In-memory script execution",),
    ("Runs a script straight from memory", "Uses a command that runs code without saving it to a file first."),
    ("يشغّل سكربتًا من الذاكرة مباشرة", "يستخدم أمرًا يشغّل شيفرة دون حفظها في ملف أولًا."),
)
_add(
    ("Remote payload download behavior",),
    ("Downloads something from the internet", "Contains a command that fetches a file or code from the internet."),
    ("ينزّل شيئًا من الإنترنت", "يحتوي على أمر يجلب ملفًا أو شيفرة من الإنترنت."),
)
_add(
    ("Obfuscated command execution",),
    ("Disguised command", "A command is hidden behind an encoding."),
    ("أمر مموَّه", "أمرٌ مخفي خلف ترميز."),
)
_add(
    ("Direct IPv4 URL host",),
    ("Link uses a bare IP address", "Trusted sites usually use a name, not bare numbers."),
    ("الرابط يستخدم عنوان IP مجردًا", "المواقع الموثوقة تستخدم عادة اسمًا، لا أرقامًا مجردة."),
)
_add(
    ("URL shortener domain",),
    ("Shortened link", "The real destination is hidden behind a short link."),
    ("رابط مختصر", "الوجهة الحقيقية مخفية خلف رابط مختصر."),
)
_add(
    ("Webhook or bot API exfiltration link",),
    ("Link to a chat-bot channel", "Links like this are sometimes used to send stolen data out."),
    ("رابط إلى قناة روبوت محادثة", "تُستخدم روابط كهذه أحيانًا لإرسال بيانات مسروقة."),
)
_add(
    ("Embedded credential marker in URL",),
    ("Link hides a name before '@'", "Text before '@' can make a link look like it goes somewhere else."),
    ("الرابط يخفي اسمًا قبل '@'", "النص قبل '@' قد يجعل الرابط يبدو متجهًا إلى مكان آخر."),
)
_add(
    ("Unusual capitalization pattern",),
    ("Strange use of capital letters", "Unusual mixes of capitals are sometimes used to slip past simple filters."),
    ("استخدام غريب للحروف الكبيرة", "الخلط غير المعتاد للحروف الكبيرة يُستخدم أحيانًا للتسلل عبر المرشحات البسيطة."),
)
_add(
    ("EICAR test marker",),
    ("Antivirus test file", "Contains the standard harmless test text. It is not a virus."),
    ("ملف اختبار لمضادات الفيروسات", "يحتوي على نص الاختبار القياسي غير الضار. إنه ليس فيروسًا."),
)
_add(
    ("Encrypted archive members skipped",),
    ("Locked files inside the archive", "Some files inside are password-protected and couldn't be checked."),
    ("ملفات مقفلة داخل الأرشيف", "بعض الملفات بداخله محمية بكلمة مرور ولم يمكن فحصها."),
)
_add(
    ("Unsafe archive member paths skipped",),
    ("Archive tries to write outside its folder", "Some paths inside could place files outside the folder they are unpacked into. Nothing was unpacked."),
    ("الأرشيف يحاول الكتابة خارج مجلده", "بعض المسارات بداخله قد تضع ملفات خارج المجلد الذي تُفك فيه. لم يُفك أي شيء."),
)
_add(
    ("External threat-intelligence match",),
    ("Reported online", "A public threat list mentions this item. That is a strong reason for caution, though not proof."),
    ("مُبلَّغ عنه عبر الإنترنت", "تذكر قائمة تهديدات عامة هذا العنصر. هذا سبب قوي للحذر، وإن لم يكن دليلًا قاطعًا."),
)

_PATTERNS = {
    "ANTI_DISASSEMBLY_GAP": ("gaps that confuse code readers", "فجوات تربك أدوات قراءة الشيفرة"),
    "REPETITIVE_INSTRUCTION_SEQUENCE": ("long repeated instruction runs", "تعليمات متكررة طويلة"),
    "XOR_DECODING_LOOP": ("a decoding loop", "حلقة فك ترميز"),
    "STACK_STRING_CONSTRUCTION": ("text built piece by piece", "نص يُبنى قطعة قطعة"),
}

_ENTROPY = re.compile(r"Entropy changed by ([+-]?\d+(?:\.\d+)?) bits/byte across offsets (0x[0-9A-Fa-f]+)-(0x[0-9A-Fa-f]+)")
_COUNT = re.compile(r"^(\d+) ")
_MEMBERS = re.compile(r"recorded (\d+) member\(s\)")


def _patterns(text: str, language: str) -> str:
    names = re.findall(r"[A-Z][A-Z0-9_]{3,}", text)
    index = 1 if language == "ar" else 0
    words = [_PATTERNS[name][index] if name in _PATTERNS else humanize_title(name).lower() for name in names]
    return ("، " if language == "ar" else ", ").join(words)


def plain(title: str, explanation: str, language: str) -> PlainText:
    """Plain title and body for one engine finding, in ``language``."""
    ar = language == "ar"
    key = title.strip().casefold()
    if key.startswith("zip structure"):
        members = _MEMBERS.search(explanation)
        count = members.group(1) if members else "?"
        if ar:
            return PlainText("محتويات الأرشيف", f"اطّلعنا على قائمة الملفات بداخله ({isolate(count, language)}) لكننا لم نفحص كل ملف منها.", True)
        return PlainText("What's inside the archive", f"We looked at the list of files inside ({count}) but did not scan each one.", True)
    entry = _CATALOGUE.get(key)
    if entry is None:
        return PlainText(humanize_title(title), explanation, False)
    plain_title, body = entry[1] if ar else entry[0]
    entropy = _ENTROPY.search(explanation)
    if entropy:
        delta = float(entropy.group(1))
        start, end = entropy.group(2), entropy.group(3)
        size = f"{abs(delta):.1f}"
        if ar:
            way = "أكثر" if delta > 0 else "أقل"
            body = (
                f"يصبح المحتوى فجأة {way} عشوائية بين الموضعين {isolate(start, language)} و{isolate(end, language)} "
                f"(تغيّر بمقدار {isolate(size, language)} بت لكل بايت). البيانات المخفية أو المضغوطة كثيرًا ما تبدو هكذا."
            )
        else:
            way = "more" if delta > 0 else "less"
            body = f"The content suddenly becomes {way} random between positions {start} and {end} (a change of {size} bits per byte). Hidden or packed data often looks like this."
    elif key in {"static decoding indicator", "pe structural obfuscation indicator"} and _patterns(explanation, language):
        seen = _patterns(explanation, language)
        body = f"{body} ({'ظهر' if ar else 'Seen'}: {seen})"
    elif key in {"encrypted archive members skipped", "unsafe archive member paths skipped"}:
        count = _COUNT.match(explanation)
        if count:
            number = isolate(count.group(1), language)
            body = f"{body} ({number})" if ar else f"{body} ({count.group(1)})"
    return PlainText(plain_title, body, True)
