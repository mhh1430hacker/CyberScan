"""Layers: file structure, randomness (entropy) and program code (PE / ELF)."""
from __future__ import annotations

import re
import time
from typing import Any

from core.layers.base import Layer, clean, found_labels, hit, register, unavailable
from core.layers.context import LayerContext, shannon

_IS_FILE = lambda f: f["mode"] == "file"  # noqa: E731
_BINARY = lambda f: f["mode"] == "file" and f["kind"] not in {"text", "empty"}  # noqa: E731
_PE = lambda f: f["mode"] == "file" and f["kind"] == "pe"  # noqa: E731


def kinds(*names: str):
    return lambda f: f["mode"] == "file" and f["kind"] in names


def label_layer(id: str, en: str, ar: str, category: str, checks_en: str, checks_ar: str, *, labels: tuple[str, ...],
                applies, weight: float, source: str, scope: tuple[str, ...] = ("inspection",), conf: float = 0.8,
                clean_conf: float = 0.5, affects_score: bool = True) -> Layer:
    """A layer answered by specific findings of an existing engine (one aspect = one label family)."""
    def run(ctx: LayerContext) -> dict[str, Any]:
        pool: list[str] = []
        for part in scope:
            if part == "inspection":
                if ctx.inspection() is None:
                    return unavailable("The content inspection did not run.", "لم يعمل فحص المحتوى.")
                pool += ctx.inspection_labels()
            elif part == "heuristics":
                pool += ctx.heuristic_labels()
            elif part == "urls":
                pool += ctx.url_labels()
            elif part == "protection":
                pool += ctx.protection_labels()
        got = ctx.match(pool, labels)
        if got:
            return hit(conf, f"Found: {found_labels(got)}", f"وُجد: {found_labels(got)}")
        return clean(clean_conf)
    return register(Layer(id, en, ar, category, checks_en, checks_ar, weight, applies, run, source, affects_score=affects_score,
                          tags=tuple(labels) + tuple(f"scope:{part}" for part in scope)))


# =============================================================== structure
def _magic(ctx: LayerContext) -> dict[str, Any]:
    from core.magic_bytes import detect_magic_issue  # noqa: PLC0415

    issue = detect_magic_issue(ctx.raw[:8], ctx.facts["ext"])
    if issue.get("mismatch"):
        return hit(0.85, str(issue.get("explanation", "Extension and content differ.")),
                   "امتداد الملف لا يطابق ما يحتويه فعلًا.")
    return clean(0.7, "The extension matches the content.", "الامتداد يطابق المحتوى.")


register(Layer("magic_vs_extension", "Extension vs real type", "الامتداد مقابل النوع الحقيقي", "structure",
               "Compares the file name's extension with the type its first bytes reveal.",
               "يقارن امتداد اسم الملف بالنوع الذي تكشفه بايتاته الأولى.", 1.5,
               lambda f: _IS_FILE(f) and bool(f["ext"]) and f["size"] > 0, _magic, "core.magic_bytes"))


def _double(ctx: LayerContext) -> dict[str, Any]:
    from core.magic_bytes import detect_double_extension  # noqa: PLC0415

    if detect_double_extension(ctx.name):
        return hit(0.9, "A harmless-looking extension hides a program extension.", "امتداد يبدو بريئًا يخفي امتداد برنامج.")
    return clean(0.7, "No disguising double extension.", "لا يوجد امتداد مزدوج مخادع.")


register(Layer("double_extension", "Double extension", "الامتداد المزدوج", "structure",
               "Looks for names like invoice.pdf.exe that hide the real extension.",
               "يبحث عن أسماء مثل invoice.pdf.exe تخفي الامتداد الحقيقي.", 2.0,
               lambda f: _IS_FILE(f) and bool(f["ext"]), _double, "core.magic_bytes"))

_BIDI = re.compile("[‪-‮⁦-⁩‎‏؜]")


def _bidi(ctx: LayerContext) -> dict[str, Any]:
    if _BIDI.search(ctx.name):
        return hit(0.95, "The name contains invisible direction characters that reverse how it reads.",
                   "الاسم يحتوي على محارف اتجاه خفية تعكس طريقة قراءته.")
    return clean(0.8, "No hidden direction characters in the name.", "لا محارف اتجاه خفية في الاسم.")


register(Layer("bidi_name", "Right-to-left name trick", "خدعة الاسم المعكوس", "structure",
               "Looks for invisible right-to-left characters that make 'exe.pdf' read as 'fdp.exe'.",
               "يبحث عن محارف خفية تعكس اتجاه الاسم لتخفي امتداد البرنامج.", 2.5,
               lambda f: _IS_FILE(f) and f["size"] > 0, _bidi, "CyberScan name check"))


def _tail(ctx: LayerContext) -> dict[str, Any]:
    from core.file_analyzer import hidden_tail_findings  # noqa: PLC0415

    found = [f for f in hidden_tail_findings(ctx.raw, ctx.name or "upload.bin") if f.contribution > 0]
    if found:
        strong = any(f.contribution >= 40 for f in found)
        return hit(0.8 if strong else 0.5, f"{found[0].evidence}: {found[0].explanation}"[:200],
                   "توجد بيانات مخزّنة بعد نهاية الملف الرسمية" + (" تبدأ كبرنامج أو أرشيف أو سكربت." if strong else "."))
    return clean(0.6, "Nothing stored after the end of the format.", "لا شيء مخزّن بعد نهاية الصيغة.")


register(Layer("data_after_end", "Data after the end", "بيانات بعد النهاية", "structure",
               "Finds bytes stored after the point where the format (picture, PDF, archive) ends.",
               "يجد بايتات مخزّنة بعد النقطة التي تنتهي عندها الصيغة (صورة، PDF، أرشيف).", 1.2,
               kinds("pdf", "image", "zip", "rtf"), _tail, "core.file_analyzer"))

_DOS_STUB = b"This program cannot be run in DOS mode"


def _embedded_program(ctx: LayerContext) -> dict[str, Any]:
    at = ctx.raw.find(_DOS_STUB, 1)
    if at < 0:
        for m in re.finditer(rb"MZ", ctx.raw[1:8 * 1024 * 1024]):
            start = m.start() + 1
            lfanew = int.from_bytes(ctx.raw[start + 0x3C:start + 0x40] or b"\0\0\0\0", "little")
            if 0 < lfanew < 4096 and ctx.raw[start + lfanew:start + lfanew + 4] == b"PE\x00\x00":
                at = start
                break
    if at >= 0:
        return hit(0.8, f"A Windows program is embedded at offset 0x{at:X}.", f"برنامج ويندوز مضمّن عند الإزاحة 0x{at:X}.")
    return clean(0.6, "No embedded Windows program.", "لا يوجد برنامج ويندوز مضمّن.")


register(Layer("embedded_program", "Program hidden inside", "برنامج مخفي بالداخل", "structure",
               "Searches a non-program file (document, picture, data) for a whole Windows program inside it.",
               "يبحث داخل ملف ليس برنامجًا (مستند، صورة، بيانات) عن برنامج ويندوز كامل.", 1.8,
               lambda f: _IS_FILE(f) and f["kind"] not in {"pe", "elf", "empty", "zip"}, _embedded_program, "CyberScan byte scan"))


def _hidden_archive(ctx: LayerContext) -> dict[str, Any]:
    start = ctx.raw.find(b"PK\x03\x04", 1)
    if start > 0 and ctx.raw.find(b"PK\x05\x06", start) > start:
        return hit(0.6, f"A ZIP archive is appended inside the file from offset 0x{start:X}.",
                   f"أرشيف ZIP ملحق داخل الملف بدءًا من الإزاحة 0x{start:X}.")
    return clean(0.5, "No archive hidden inside another format.", "لا يوجد أرشيف مخفي داخل صيغة أخرى.")


register(Layer("hidden_archive", "Archive inside another format", "أرشيف داخل صيغة أخرى", "structure",
               "Looks for a complete ZIP archive inside a program, PDF, picture or RTF (a polyglot file).",
               "يبحث عن أرشيف ZIP كامل داخل برنامج أو PDF أو صورة أو RTF (ملف متعدد الصيغ).", 0.6,
               kinds("pe", "pdf", "image", "rtf", "ole", "binary"), _hidden_archive, "CyberScan byte scan"))


def _dissonance(ctx: LayerContext) -> dict[str, Any]:
    report = ctx.feature_summary.get("dissonance")
    if not isinstance(report, dict):
        return unavailable("Not assessed for this program.", "لم يُقيَّم لهذا البرنامج.")
    signed = str(ctx.feature_summary.get("authenticode", "")).startswith("valid")
    level = str(report.get("level", "low"))
    if level in {"high", "medium"} and not signed:
        return hit(0.8 if level == "high" else 0.55, f"What it claims to be and what it can do disagree ({level}).",
                   "ما يدّعيه البرنامج لا يتفق مع ما يستطيع فعله.")
    return clean(0.6, "Its claimed role fits its abilities.", "الدور الذي يدّعيه يتفق مع قدراته.")


register(Layer("claim_vs_abilities", "Claim vs abilities", "الادعاء مقابل القدرات", "structure",
               "Compares what a program says it is (name, version info) with what its code can do.",
               "يقارن ما يقوله البرنامج عن نفسه (الاسم ومعلومات الإصدار) بما تستطيع شيفرته فعله.", 1.0,
               lambda f: _PE(f) and f["has_result"], _dissonance, "core.dissonance"))


def _surprise(ctx: LayerContext) -> dict[str, Any]:
    report = ctx.feature_summary.get("surprise_map")
    if not isinstance(report, dict):
        return unavailable("No surprise map for this program.", "لا توجد خريطة مفاجأة لهذا البرنامج.")
    code = [r for r in report.get("regions") or [] if r.get("role") == "code"]
    if code:
        return hit(0.6, f"{len(code)} stretch(es) of the code section don't look like code.",
                   f"{len(code)} مقطع(ة) من قسم الشيفرة لا تشبه الشيفرة.")
    return clean(0.6, "The code section looks like ordinary code.", "قسم الشيفرة يبدو شيفرة عادية.")


register(Layer("foreign_code_regions", "Foreign bytes in code", "بايتات غريبة في الشيفرة", "structure",
               "Measures how far each part of the code section is from honest compiled code.",
               "يقيس مدى ابتعاد كل جزء من قسم الشيفرة عن الشيفرة المترجمة العادية.", 0.8,
               lambda f: _PE(f) and f["has_result"], _surprise, "core.surprise_map"))

label_layer("malformed_container", "Damaged container", "حاوية تالفة", "structure",
            "Checks whether the ZIP, Office, program or app container parses cleanly (damage is used to evade scanners).",
            "يتحقق من أن حاوية ZIP أو أوفيس أو البرنامج أو التطبيق سليمة (التلف يُستخدم للتهرب من الفاحصات).",
            labels=("Unreadable ZIP container", "Malformed OLE container", "Malformed PE file", "Malformed Android manifest",
                    "Malformed extension manifest"),
            applies=kinds("zip", "ole", "pe"), weight=0.8, conf=0.6, source="detection.engine")


# =============================================================== entropy
def _overall_entropy(ctx: LayerContext) -> dict[str, Any]:
    from core.magic_bytes import naturally_compressed  # noqa: PLC0415

    value = ctx.cached("entropy", lambda: shannon(ctx.raw[:16 * 1024 * 1024]))
    if naturally_compressed(ctx.raw[:16]):
        return unavailable(f"{value:.2f} bits/byte; this format is compressed by design.",
                           f"{value:.2f} بت/بايت؛ هذه الصيغة مضغوطة بطبيعتها.", status="not_applicable")
    if value > 7.2:
        return hit(0.55, f"{value:.2f} bits/byte: close to random, as packed or encrypted data is.",
                   f"{value:.2f} بت/بايت: قريب من العشوائية كما في البيانات المضغوطة أو المشفرة.")
    return clean(0.6, f"{value:.2f} bits/byte: ordinary.", f"{value:.2f} بت/بايت: طبيعي.")


register(Layer("overall_entropy", "Overall randomness", "العشوائية الكلية", "entropy",
               "Measures the whole file's entropy; packed or encrypted content is close to 8 bits/byte.",
               "يقيس إنتروبيا الملف كله؛ المحتوى المضغوط أو المشفر يقترب من 8 بت/بايت.", 0.7,
               lambda f: _BINARY(f) and f["size"] >= 512, _overall_entropy, "core.entropy"))


def _entropy_jump(ctx: LayerContext) -> dict[str, Any]:
    from core.magic_bytes import naturally_compressed  # noqa: PLC0415

    if naturally_compressed(ctx.raw[:16]):
        return unavailable("Compressed format: jumps are normal.", "صيغة مضغوطة: القفزات طبيعية.", status="not_applicable")
    topo = ctx.topography()
    if not isinstance(topo, dict):
        return unavailable()
    jumps = [a for a in topo.get("anomalies") or [] if a.get("high_entropy_boundary")]
    if jumps:
        a = jumps[0]
        return hit(0.5, f"{len(jumps)} sharp jump(s) into random-looking data (first at 0x{int(a.get('offset_start', 0)):X}).",
                   f"{len(jumps)} قفزة حادة نحو بيانات عشوائية المظهر.")
    return clean(0.55, "No sharp jump into random-looking data.", "لا قفزات حادة نحو بيانات عشوائية.")


register(Layer("entropy_jump", "Randomness jumps", "قفزات العشوائية", "entropy",
               "Walks the file in windows and flags a sudden switch from ordinary to random-looking bytes.",
               "يمر على الملف نافذةً نافذة ويرصد الانتقال المفاجئ من بايتات عادية إلى بايتات عشوائية المظهر.", 0.7,
               lambda f: _BINARY(f) and f["size"] >= 4096, _entropy_jump, "core.nextgen_engine"))


def _sections(ctx: LayerContext) -> list[Any]:
    pe = ctx.pe()
    return list(getattr(pe, "sections", []) or []) if pe is not None else []


def _sname(section: Any) -> str:
    return section.Name.rstrip(b"\x00").decode("latin-1", "replace")


def _section_entropy(ctx: LayerContext) -> dict[str, Any]:
    if ctx.pe() is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    high = [(_sname(s), shannon(s.get_data()[:4 * 1024 * 1024])) for s in _sections(ctx) if _sname(s).lower() != ".rsrc"]
    high = [(n, e) for n, e in high if e > 7.2]
    if high:
        return hit(0.6, "High-entropy section(s): " + ", ".join(f"{n or '?'} {e:.2f}" for n, e in high[:4]),
                   "أقسام عالية الإنتروبيا: " + ", ".join(f"{n or '?'} {e:.2f}" for n, e in high[:4]))
    return clean(0.6, "No section looks packed or encrypted.", "لا قسم يبدو مضغوطًا أو مشفرًا.")


register(Layer("pe_section_entropy", "Section randomness", "عشوائية الأقسام", "entropy",
               "Measures each program section's entropy (code and data sections are normally below 7).",
               "يقيس إنتروبيا كل قسم من أقسام البرنامج (أقسام الشيفرة والبيانات عادةً أقل من 7).", 1.0,
               _PE, _section_entropy, "pefile"))


def _resources(ctx: LayerContext) -> list[bytes]:
    def compute() -> list[bytes]:
        pe = ctx.pe()
        out: list[bytes] = []
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)

        def walk(directory: Any, depth: int) -> None:
            for entry in getattr(directory, "entries", []) or []:
                if len(out) >= 300:
                    return
                if hasattr(entry, "directory") and depth < 4:
                    walk(entry.directory, depth + 1)
                elif hasattr(entry, "data"):
                    struct = entry.data.struct
                    out.append(pe.get_data(struct.OffsetToData, min(int(struct.Size), 4 * 1024 * 1024)))
        if root is not None:
            walk(root, 0)
        return out
    return ctx.cached("pe_resources", compute) or []


_MEDIA = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"PK\x03\x04", b"MSCF", b"RIFF", b"\x1f\x8b", b"BM")


def _resource_entropy(ctx: LayerContext) -> dict[str, Any]:
    if ctx.pe() is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    big = [r for r in _resources(ctx) if len(r) >= 32 * 1024 and not r.startswith(_MEDIA)]
    dense = [r for r in big if shannon(r[:1024 * 1024]) > 7.6]
    if dense:
        return hit(0.55, f"{len(dense)} large resource(s) of random-looking data (not pictures or archives).",
                   f"{len(dense)} مورد(ة) كبيرة من بيانات عشوائية المظهر (ليست صورًا أو أرشيفات).")
    return clean(0.5, "No large random-looking resource.", "لا توجد موارد كبيرة عشوائية المظهر.")


register(Layer("pe_resource_entropy", "Resource randomness", "عشوائية الموارد", "entropy",
               "Measures large embedded resources; an encrypted blob that is not a picture can be a hidden payload.",
               "يقيس الموارد المضمّنة الكبيرة؛ كتلة مشفرة ليست صورة قد تكون حمولة مخفية.", 0.7,
               _PE, _resource_entropy, "pefile"))


# =============================================================== program code
label_layer("packer", "Known packer", "أداة ضغط معروفة", "code",
            "Recognises packers and protectors (UPX, Themida, VMProtect...) by their section names and markers.",
            "يتعرف على أدوات الضغط والحماية (UPX وThemida وVMProtect...) من أسماء أقسامها وعلاماتها.",
            labels=("Known packer or protector",), applies=kinds("pe", "elf"), weight=1.0, conf=0.7,
            source="detection.executables")

_STANDARD_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".tls", ".bss", ".crt",
                      ".gfids", ".00cfg", ".didat", ".xdata", ".sxdata", ".debug", ".textbss", ".symtab", ".ndata", "code",
                      "data", "bss", ".itext", ".didata", "init", "page", ".orpc", ".retplne", ".voltbl", ".fptable", ".wixburn",
                      ".mrdata", ".a64xrm", ".detourc", ".detourd", ".imrsiv", ".nep", ".rodata", ".eh_fram", ".init", ".fini",
                      ".ctors", ".dtors", ".gnu_deb", ".jcr", ".buildid", ".cormeta", ".sdata", ".srdata", "_rdata"}


def _odd_sections(ctx: LayerContext) -> dict[str, Any]:
    if ctx.pe() is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    from detection.executables import PACKER_SECTIONS  # noqa: PLC0415 - packers are the "packer" layer's

    odd = []
    for s in _sections(ctx):
        raw = s.Name.rstrip(b"\x00")
        name = raw.decode("latin-1", "replace")
        if not raw or any(b < 0x20 or b > 0x7e for b in raw):
            odd.append(repr(name))
        elif name.lower() not in _STANDARD_SECTIONS and name.lower() not in PACKER_SECTIONS \
                and not name.startswith((".", "/", "_")):
            odd.append(name)
    if odd:
        return hit(0.45, "Unusual section name(s): " + ", ".join(odd[:4]), "أسماء أقسام غير معتادة: " + ", ".join(odd[:4]))
    return clean(0.5, "Section names look ordinary.", "أسماء الأقسام تبدو عادية.")


register(Layer("odd_section_names", "Unusual section names", "أسماء أقسام غير معتادة", "code",
               "Flags empty, unprintable or random section names that compilers don't produce.",
               "يرصد أسماء الأقسام الفارغة أو غير القابلة للطباعة أو العشوائية التي لا ينتجها المترجم.", 0.4,
               _PE, _odd_sections, "pefile"))


def _timestamp(ctx: LayerContext) -> dict[str, Any]:
    pe = ctx.pe()
    if pe is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    stamp = int(pe.FILE_HEADER.TimeDateStamp)
    now = time.time()
    if stamp == 0:
        return hit(0.4, "The build time was wiped (zero).", "وقت البناء ممسوح (صفر).")
    if stamp > now + 86400:
        return hit(0.35, "The build time is in the future (forged, or a reproducible-build hash).",
                   "وقت البناء في المستقبل (مزوّر أو بصمة بناء قابل للتكرار).")
    if stamp < 631152000:  # 1990-01-01
        return hit(0.3, "The build time is before 1990 (forged or a very old tool).", "وقت البناء قبل 1990 (مزوّر أو أداة قديمة جدًا).")
    return clean(0.5, time.strftime("Built %Y-%m-%d (plausible).", time.gmtime(stamp)),
                 time.strftime("بُني في %Y-%m-%d (معقول).", time.gmtime(stamp)))


register(Layer("pe_timestamp", "Build time", "وقت البناء", "code",
               "Checks the program's compile time for zero, future or impossible dates.",
               "يفحص وقت ترجمة البرنامج بحثًا عن تواريخ صفرية أو مستقبلية أو مستحيلة.", 0.3,
               _PE, _timestamp, "pefile"))


def import_layer(id: str, en: str, ar: str, checks_en: str, checks_ar: str, *, weight: float, test, describe_en: str,
                 describe_ar: str, conf: float) -> None:
    def run(ctx: LayerContext) -> dict[str, Any]:
        if ctx.pe() is None:
            return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
        names = {n.casefold() for n in ctx.pe_imports()}
        found = test(names)
        if found:
            shown = ", ".join(sorted(found)[:4])
            return hit(conf, f"{describe_en}: {shown}", f"{describe_ar}: {shown}")
        return clean(0.5, "Not imported.", "غير مستوردة.")
    register(Layer(id, en, ar, "code", checks_en, checks_ar, weight, _PE, run, "pefile imports"))


def _injection(names: set[str]) -> set[str]:
    from core.file_analyzer import injection_chain  # noqa: PLC0415

    return {n for n in names if n in {"writeprocessmemory", "createremotethread", "queueuserapc", "ntcreatethreadex",
                                      "setthreadcontext", "virtualallocex"}} if injection_chain(names) else set()


import_layer("injection_imports", "Process injection", "حقن العمليات",
             "Looks for the import pair that writes into another program and starts code there.",
             "يبحث عن زوج الدوال التي تكتب داخل برنامج آخر ثم تشغّل شيفرة فيه.", weight=1.6, conf=0.75, test=_injection,
             describe_en="Writes into and runs code in other processes", describe_ar="يكتب داخل عمليات أخرى ويشغّل فيها شيفرة")


def _any_suspicious(names: set[str]) -> set[str]:
    from core.pe_decompiler import SUSPICIOUS_IMPORTS  # noqa: PLC0415

    wanted = {s.casefold() for s in SUSPICIOUS_IMPORTS} - {"createprocessa", "createprocessw"}
    return {n for n in names if n in wanted or n.rstrip("aw") in wanted}


import_layer("sensitive_imports", "Sensitive functions", "دوال حساسة", "Lists imported functions often misused (memory, other processes, hooks).",
             "يرصد الدوال المستوردة التي يكثر إساءة استخدامها (الذاكرة، العمليات الأخرى، الخطافات).", weight=0.4, conf=0.4,
             test=_any_suspicious, describe_en="Imports", describe_ar="يستورد")


def _keylog(names: set[str]) -> set[str]:
    hooks = {n for n in names if n.startswith("setwindowshookex")}
    keys = {n for n in names if n in {"getasynckeystate", "getkeyboardstate"}}
    return hooks | keys if hooks and keys else set()


import_layer("keylogger_imports", "Keyboard capture", "التقاط لوحة المفاتيح", "Looks for a global keyboard hook together with key-state polling.",
             "يبحث عن خطاف لوحة مفاتيح عام مع قراءة حالة المفاتيح.", weight=0.9, conf=0.6, test=_keylog,
             describe_en="Hooks and reads the keyboard", describe_ar="يعترض لوحة المفاتيح ويقرؤها")


def _antidebug(names: set[str]) -> set[str]:
    strong = {n for n in names if n in {"checkremotedebuggerpresent", "ntqueryinformationprocess", "ntsetinformationthread",
                                        "zwqueryinformationprocess", "zwsetinformationthread"}}
    return strong | ({"isdebuggerpresent"} & names) if len(strong) >= 1 and len(strong | ({"isdebuggerpresent"} & names)) >= 2 else set()


import_layer("anti_debug_imports", "Anti-debugging", "مقاومة التصحيح", "Looks for several functions used together to detect or hide from a debugger.",
             "يبحث عن عدة دوال تُستخدم معًا لاكتشاف المصحح أو الاختباء منه.", weight=0.5, conf=0.45, test=_antidebug,
             describe_en="Checks for a debugger", describe_ar="يتحقق من وجود مصحح")


def _download_exec(names: set[str]) -> set[str]:
    direct = {n for n in names if n.startswith("urldownloadtofile")}
    fetch = {n for n in names if n in {"internetreadfile", "winhttpreaddata"}}
    run = {n for n in names if n in {"winexec", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw"}}
    return direct | (fetch | run if fetch and run else set())


import_layer("download_exec_imports", "Download and run", "التنزيل ثم التشغيل", "Looks for imports that download a file and then run it.",
             "يبحث عن دوال مستوردة تنزّل ملفًا ثم تشغّله.", weight=0.9, conf=0.6, test=_download_exec,
             describe_en="Can download and run files", describe_ar="يستطيع تنزيل الملفات وتشغيلها")


def _crypto_walk(names: set[str]) -> set[str]:
    crypt = {n for n in names if n in {"cryptencrypt", "bcryptencrypt", "cryptgenkey", "cryptimportkey"}}
    walk = {n for n in names if n.startswith(("findfirstfile", "findnextfile"))}
    return crypt | walk if crypt and walk else set()


import_layer("encrypt_files_imports", "Encrypts while walking folders", "يشفّر أثناء تصفح المجلدات",
             "Looks for file-encryption functions together with folder walking (a ransomware shape; backup tools do it too).",
             "يبحث عن دوال تشفير الملفات مع تصفح المجلدات (شكل برامج الفدية؛ وأدوات النسخ الاحتياطي أيضًا).", weight=0.5, conf=0.4,
             test=_crypto_walk, describe_en="Encryption plus folder walking", describe_ar="تشفير مع تصفح المجلدات")

label_layer("dynamic_api_resolution", "Hidden imports", "استيراد مخفي", "code",
            "Flags a program that imports almost nothing and looks up its functions at run time.",
            "يرصد برنامجًا لا يستورد شيئًا تقريبًا ويبحث عن دواله أثناء التشغيل.",
            labels=("Minimal imports with dynamic API resolution",), applies=_PE, weight=0.9, conf=0.6, source="detection.executables")
label_layer("no_import_table", "No import table", "لا جدول استيراد", "code",
            "Flags a program with no import table at all, typical of packed or hand-built code.",
            "يرصد برنامجًا بلا جدول استيراد إطلاقًا، وهو شائع في الشيفرة المضغوطة أو المصنوعة يدويًا.",
            labels=("No import table",), applies=_PE, weight=0.6, conf=0.5, source="detection.executables")
label_layer("tls_callbacks", "Early start code (TLS)", "شيفرة تعمل مبكرًا (TLS)", "code",
            "Flags TLS callbacks: code that runs before the program's normal start.",
            "يرصد استدعاءات TLS: شيفرة تعمل قبل البداية العادية للبرنامج.",
            labels=("TLS callbacks",), applies=_PE, weight=0.4, conf=0.4, source="detection.executables")
label_layer("writable_executable", "Writable and executable", "قابل للكتابة والتنفيذ", "code",
            "Flags a section that is both writable and executable (self-modifying or unpacking code).",
            "يرصد قسمًا قابلًا للكتابة والتنفيذ معًا (شيفرة تعدّل نفسها أو تفك ضغطها).",
            labels=("Writable and executable section",), applies=_PE, weight=1.0, conf=0.6, source="detection.executables")
label_layer("entry_point", "Odd starting point", "نقطة بداية غريبة", "code",
            "Checks that the program starts inside an executable section, not outside or in the last one.",
            "يتحقق من أن البرنامج يبدأ داخل قسم قابل للتنفيذ، لا خارجه ولا في القسم الأخير.",
            labels=("Entry point outside all sections", "Entry point in non-executable section", "Entry point in last section"),
            applies=_PE, weight=1.0, conf=0.6, source="detection.executables")
label_layer("credential_theft_strings", "Browser and wallet theft", "سرقة المتصفح والمحافظ", "code",
            "Looks for the paths and strings info-stealers use to read browser passwords and crypto wallets.",
            "يبحث عن المسارات والنصوص التي تستخدمها برامج سرقة المعلومات لقراءة كلمات مرور المتصفح ومحافظ العملات.",
            labels=("Browser/wallet credential theft indicators",), applies=_PE, weight=1.8, conf=0.75, source="detection.executables")
label_layer("elf_structure", "Linux program structure", "بنية برنامج لينكس", "code",
            "Checks a Linux (ELF) program for truncation, a damaged header or stripped section headers.",
            "يفحص برنامج لينكس (ELF) بحثًا عن بتر أو ترويسة تالفة أو حذف ترويسات الأقسام.",
            labels=("Truncated ELF file", "Malformed ELF header", "ELF without section headers"),
            applies=kinds("elf"), weight=0.7, conf=0.5, source="detection.executables")


def _checksum(ctx: LayerContext) -> dict[str, Any]:
    pe = ctx.pe()
    if pe is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    stored = int(pe.OPTIONAL_HEADER.CheckSum)
    if stored == 0:
        return clean(0.3, "No checksum set (common outside drivers).", "لا مجموع تحقق (شائع خارج برامج التشغيل).")
    actual = int(pe.generate_checksum())
    if stored != actual:
        return hit(0.45, f"Stored checksum 0x{stored:X} ≠ actual 0x{actual:X}: changed after it was built.",
                   f"مجموع التحقق المخزّن 0x{stored:X} ≠ الفعلي 0x{actual:X}: عُدّل بعد بنائه.")
    return clean(0.6, "The checksum matches.", "مجموع التحقق مطابق.")


register(Layer("pe_checksum", "Header checksum", "مجموع تحقق الترويسة", "code",
               "Recomputes the program's checksum; a mismatch means the file was changed after it was built.",
               "يعيد حساب مجموع تحقق البرنامج؛ عدم التطابق يعني أن الملف تغيّر بعد بنائه.", 0.5,
               _PE, _checksum, "pefile"))


def _virtual_stub(ctx: LayerContext) -> dict[str, Any]:
    if ctx.pe() is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    empty = [_sname(s) for s in _sections(ctx) if int(s.SizeOfRawData) == 0 and int(s.Misc_VirtualSize) > 4096
             and int(s.Characteristics) & 0x20000000]
    if empty:
        return hit(0.6, "Executable section(s) empty on disk but large in memory: " + ", ".join(empty[:3]),
                   "أقسام تنفيذية فارغة على القرص وكبيرة في الذاكرة: " + ", ".join(empty[:3]))
    return clean(0.55, "No empty executable section waiting to be filled.", "لا أقسام تنفيذية فارغة تنتظر الملء.")


register(Layer("unpack_target_section", "Empty code waiting to fill", "شيفرة فارغة تنتظر الملء", "code",
               "Finds executable sections that are empty in the file but large in memory: room for unpacked code.",
               "يجد أقسامًا تنفيذية فارغة في الملف وكبيرة في الذاكرة: مساحة لشيفرة تُفك لاحقًا.", 0.8,
               _PE, _virtual_stub, "pefile"))


def _decoder(ctx: LayerContext) -> dict[str, Any]:
    pe_info = getattr(ctx.result, "pe_analysis", None) or {}
    if pe_info.get("status") != "ok":
        return unavailable("No decoded code for this program.", "لا توجد شيفرة مفككة لهذا البرنامج.")
    patterns = list((pe_info.get("cfg_topology") or {}).get("evidence_patterns") or [])
    if patterns:
        return hit(0.55, "Decoder-loop shapes in the code: " + ", ".join(patterns[:3]), "أشكال حلقات فك تشفير في الشيفرة: " + ", ".join(patterns[:3]))
    return clean(0.5, "No decoder-loop shape in the code.", "لا أشكال حلقات فك تشفير في الشيفرة.")


register(Layer("decoder_loops", "Decoder loops", "حلقات فك التشفير", "code",
               "Disassembles the start of the code and looks for in-place decoding loops.",
               "يفكك بداية الشيفرة ويبحث عن حلقات فك تشفير في المكان.", 0.9,
               lambda f: _PE(f) and f["has_result"], _decoder, "core.pe_decompiler"))


def _security_dir(ctx: LayerContext) -> tuple[int, int]:
    pe = ctx.pe()
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] if pe is not None and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else None
    return (int(entry.VirtualAddress), int(entry.Size)) if entry is not None else (0, 0)


def _overlay(ctx: LayerContext) -> dict[str, Any]:
    pe = ctx.pe()
    if pe is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    start = pe.get_overlay_data_start_offset()
    if start is None:
        return clean(0.5, "Nothing after the last section.", "لا شيء بعد القسم الأخير.")
    cert_at, cert_size = _security_dir(ctx)
    extra = len(ctx.raw) - start
    if cert_size and cert_at >= start:
        extra -= cert_size
    if extra < 1024:
        return clean(0.5, "Only the signature follows the last section.", "لا يلي القسم الأخير سوى التوقيع.")
    dense = shannon(ctx.raw[start:start + 1024 * 1024]) > 7.5
    return hit(0.4 if not dense else 0.5, f"{extra:,} bytes after the last section" + (" (random-looking)" if dense else "") + "; installers do this too.",
               f"{extra:,} بايت بعد القسم الأخير" + (" (عشوائية المظهر)" if dense else "") + "؛ وبرامج التثبيت تفعل هذا أيضًا.")


register(Layer("pe_overlay", "Data after the program", "بيانات بعد البرنامج", "code",
               "Measures data appended after the program's last section (where droppers keep payloads).",
               "يقيس البيانات الملحقة بعد آخر قسم في البرنامج (حيث تحفظ برامج الإسقاط حمولتها).", 0.5,
               _PE, _overlay, "pefile"))


def _signed(ctx: LayerContext) -> dict[str, Any]:
    if ctx.pe() is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    _, size = _security_dir(ctx)
    if size > 0:
        return clean(0.5, "Carries a digital signature block.", "يحمل كتلة توقيع رقمي.")
    return hit(0.3, "No digital signature: the publisher can't be confirmed (common for small tools).",
               "لا توقيع رقمي: لا يمكن تأكيد الناشر (شائع في الأدوات الصغيرة).")


register(Layer("signature_present", "Digital signature present", "وجود توقيع رقمي", "code",
               "Checks whether the program carries an Authenticode signature at all.",
               "يتحقق مما إذا كان البرنامج يحمل توقيع Authenticode أصلًا.", 0.4, _PE, _signed, "pefile"))


def _sig_valid(ctx: LayerContext) -> dict[str, Any]:
    _, size = _security_dir(ctx) if ctx.pe() is not None else (0, 0)
    state = str(ctx.feature_summary.get("authenticode", ""))
    if state.startswith("valid"):
        return clean(0.9, "The signature checks out and is trusted.", "التوقيع سليم وموثوق.")
    if not size:
        return unavailable("No signature to verify.", "لا يوجد توقيع للتحقق منه.", status="not_applicable")
    if state == "unsigned or invalid":
        return hit(0.7, "A signature is attached but does not verify (tampered or untrusted).",
                   "يوجد توقيع لكنه لا يُتحقق منه (معدّل أو غير موثوق).")
    return unavailable("Signature verification is only available on Windows.", "التحقق من التوقيع متاح على ويندوز فقط.")


register(Layer("signature_valid", "Signature validity", "صحة التوقيع", "code",
               "Verifies the attached signature (WinVerifyTrust, offline): a broken signature means a changed file.",
               "يتحقق من التوقيع المرفق (WinVerifyTrust دون إنترنت): التوقيع المكسور يعني ملفًا معدّلًا.", 1.2,
               lambda f: _PE(f) and f["has_result"], _sig_valid, "core.authenticode"))


def _version_info(ctx: LayerContext) -> dict[str, Any]:
    pe = ctx.pe()
    if pe is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    if int(pe.FILE_HEADER.Characteristics) & 0x2000 or int(pe.OPTIONAL_HEADER.Subsystem) != 2:
        return unavailable("Only checked for desktop (GUI) programs.", "يُفحص لبرامج سطح المكتب فقط.", status="not_applicable")
    if getattr(pe, "VS_VERSIONINFO", None) or getattr(pe, "FileInfo", None):
        return clean(0.4, "Has version information (name, company, version).", "يحمل معلومات إصدار (الاسم، الشركة، الإصدار).")
    return hit(0.3, "A desktop program with no version information at all.", "برنامج سطح مكتب بلا أي معلومات إصدار.")


register(Layer("version_info", "Version information", "معلومات الإصدار", "code",
               "Checks that a desktop program describes itself (product, company, version), as published software does.",
               "يتحقق من أن برنامج سطح المكتب يعرّف نفسه (المنتج، الشركة، الإصدار) كما تفعل البرامج المنشورة.", 0.3,
               _PE, _version_info, "pefile"))


def _resource_program(ctx: LayerContext) -> dict[str, Any]:
    if ctx.pe() is None:
        return unavailable("The program header could not be parsed.", "تعذّر تحليل ترويسة البرنامج.")
    inner = [r for r in _resources(ctx) if r[:2] == b"MZ" and _DOS_STUB in r[:512]]
    if inner:
        return hit(0.75, f"{len(inner)} complete program(s) stored as resources.", f"{len(inner)} برنامج(ة) كامل مخزّن كموارد.")
    return clean(0.55, "No program hidden among the resources.", "لا برامج مخفية بين الموارد.")


register(Layer("resource_program", "Program in resources", "برنامج داخل الموارد", "code",
               "Looks inside the program's resources for another complete program (a dropper's payload).",
               "يبحث داخل موارد البرنامج عن برنامج كامل آخر (حمولة برنامج إسقاط).", 1.4,
               _PE, _resource_program, "pefile"))
