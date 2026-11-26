"""Layers: documents, archives and apps, scripts and commands, web pages, email, secrets and privacy."""
from __future__ import annotations

import base64
import binascii
import re
import sys
from pathlib import Path
from typing import Any

from core.layers.base import Layer, clean, hit, register, unavailable
from core.layers.catalog_structure import kinds, label_layer
from core.layers.context import LayerContext, shannon

_OFFICE = lambda f: f["mode"] == "file" and (f["kind"] == "ole" or f["container"] == "ooxml")  # noqa: E731
_PDF = kinds("pdf")
_RTF = kinds("rtf")
_ZIP = lambda f: f["mode"] == "file" and f["kind"] == "zip"  # noqa: E731
_ARCHIVE = lambda f: _ZIP(f) and f["container"] in {"archive", None}  # noqa: E731
_APK = lambda f: _ZIP(f) and f["container"] == "apk"  # noqa: E731
_EXT = lambda f: _ZIP(f) and f["container"] == "browser-extension"  # noqa: E731
_CONTENT = lambda f: f["mode"] in {"file", "text"} and f["size"] > 0  # noqa: E731
_TEXTUAL = lambda f: f["mode"] in {"file", "text"} and f["is_text"] and f["size"] > 0  # noqa: E731
_HTML = lambda f: f["mode"] in {"file", "text"} and f["is_html"]  # noqa: E731
_EMAIL = lambda f: f["mode"] in {"file", "text"} and f["is_email"]  # noqa: E731

D = "detection.documents"
A = "detection.archives"
S = "detection.script_rules"
H = "core.heuristic_engine"

# =============================================================== documents (Office, PDF, RTF)
label_layer("macros_present", "Macros present", "وجود وحدات ماكرو", "documents",
            "Checks whether the Office document carries macro (VBA) code at all.",
            "يتحقق مما إذا كان مستند أوفيس يحمل شيفرة ماكرو (VBA) أصلًا.",
            labels=("VBA macros present", "VBA project present (source not recoverable)"), applies=_OFFICE, weight=0.8, conf=0.6, source=D)
label_layer("auto_exec_macro", "Macro runs on open", "ماكرو يعمل عند الفتح", "documents",
            "Looks for macros that start by themselves when the document opens (AutoOpen, Document_Open...).",
            "يبحث عن وحدات ماكرو تبدأ وحدها عند فتح المستند (AutoOpen وDocument_Open...).",
            labels=("Auto-executing macro", "Auto-executing macro with dangerous capabilities"), applies=_OFFICE, weight=1.5, conf=0.75, source=D)
label_layer("dangerous_macro", "Macro can run programs", "ماكرو يستطيع تشغيل برامج", "documents",
            "Reads the macro code for shell, download, file-write and process functions.",
            "يقرأ شيفرة الماكرو بحثًا عن دوال الأوامر والتنزيل وكتابة الملفات والعمليات.",
            labels=("Macro with dangerous capabilities", "Auto-executing macro with dangerous capabilities"), applies=_OFFICE, weight=1.8, conf=0.8, source=D)
label_layer("obfuscated_macro", "Scrambled macro", "ماكرو مموّه", "documents",
            "Looks for macro code that hides its strings (Chr() chains, string splitting, encoding).",
            "يبحث عن شيفرة ماكرو تخفي نصوصها (سلاسل Chr() وتقسيم النصوص والترميز).",
            labels=("Obfuscated macro code",), applies=_OFFICE, weight=1.2, conf=0.65, source=D)
label_layer("macro_urls", "Links inside macros", "روابط داخل الماكرو", "documents",
            "Looks for web addresses written inside macro code (where a payload may be fetched from).",
            "يبحث عن عناوين ويب مكتوبة داخل شيفرة الماكرو (قد تُجلب منها حمولة).",
            labels=("URLs embedded in macro code",), applies=_OFFICE, weight=1.0, conf=0.6, source=D)
label_layer("xlm_macro", "Excel 4.0 macros", "ماكرو إكسل 4.0", "documents",
            "Looks for old Excel 4.0 (XLM) macro sheets, a favourite of malicious spreadsheets.",
            "يبحث عن أوراق ماكرو إكسل 4.0 (XLM) القديمة المفضلة في جداول البيانات الخبيثة.",
            labels=("Excel 4.0 (XLM) macro sheet",), applies=_OFFICE, weight=1.5, conf=0.75, source=D)
label_layer("macro_in_macrofree", "Macros in a macro-free type", "ماكرو في صيغة بلا ماكرو", "documents",
            "Flags a macro project inside a .docx/.xlsx, which Office won't run but attackers rename to.",
            "يرصد مشروع ماكرو داخل ملف ‎.docx/.xlsx‎ لا يشغّله أوفيس لكن يُعاد تسميته للخداع.",
            labels=("Macro project in a macro-free file type",), applies=_OFFICE, weight=1.0, conf=0.6, source=D)
label_layer("office_embedded_objects", "Embedded objects", "كائنات مضمّنة", "documents",
            "Looks for files or programs embedded in the document as OLE objects or packages.",
            "يبحث عن ملفات أو برامج مضمّنة في المستند ككائنات OLE أو حزم.",
            labels=("Embedded executable package", "Embedded executable object", "Embedded OLE package", "Embedded objects"),
            applies=_OFFICE, weight=1.2, conf=0.65, source=D)
label_layer("activex_controls", "ActiveX controls", "عناصر ActiveX", "documents",
            "Flags ActiveX controls, which can run code inside Office.", "يرصد عناصر ActiveX التي تستطيع تشغيل شيفرة داخل أوفيس.",
            labels=("ActiveX controls",), applies=_OFFICE, weight=0.6, conf=0.5, source=D)
label_layer("external_relationships", "Fetches content on open", "يجلب محتوى عند الفتح", "documents",
            "Reads the document's relationships for remote templates, external objects and network paths.",
            "يقرأ علاقات المستند بحثًا عن قوالب بعيدة وكائنات خارجية ومسارات شبكة.",
            labels=("Remote template injection", "External object loaded on open", "UNC or file path reference"),
            applies=lambda f: _OFFICE(f) or _RTF(f), weight=1.8, conf=0.8, source=D)
label_layer("dde_fields", "DDE commands", "أوامر DDE", "documents",
            "Looks for DDE fields and links that make Office start a command.", "يبحث عن حقول وروابط DDE تجعل أوفيس يشغّل أمرًا.",
            labels=("DDE field (command execution)", "DDE link in workbook"), applies=_OFFICE, weight=1.6, conf=0.75, source=D)
label_layer("office_password", "Password-protected document", "مستند محمي بكلمة مرور", "documents",
            "Flags an encrypted Office document, whose contents scanners (including this one) can't read.",
            "يرصد مستند أوفيس مشفرًا لا تستطيع الفاحصات (ومنها هذا) قراءة محتواه.",
            labels=("Password-protected Office document",), applies=_OFFICE, weight=0.7, conf=0.5, source=D)
label_layer("lure_document", "Single-link lure", "طُعم الرابط الواحد", "documents",
            "Flags a short document whose only purpose seems to be one link to click.", "يرصد مستندًا قصيرًا هدفه الوحيد على ما يبدو رابط واحد للنقر.",
            labels=("Single-link lure document",), applies=lambda f: _OFFICE(f) or _PDF(f), weight=0.9, conf=0.55, source=D)
label_layer("pdf_javascript", "JavaScript in PDF", "جافاسكربت في PDF", "documents",
            "Looks for JavaScript inside the PDF.", "يبحث عن جافاسكربت داخل ملف PDF.",
            labels=("PDF contains JavaScript",), applies=_PDF, weight=1.0, conf=0.6, source=D)
label_layer("pdf_auto_action", "PDF runs code on open", "PDF يشغّل شيفرة عند الفتح", "documents",
            "Looks for OpenAction / AA entries that start JavaScript when the PDF opens.",
            "يبحث عن مدخلات OpenAction/AA التي تشغّل جافاسكربت عند فتح PDF.",
            labels=("PDF auto-executes JavaScript",), applies=_PDF, weight=1.6, conf=0.75, source=D)
label_layer("pdf_launch", "PDF launches programs", "PDF يشغّل برامج", "documents",
            "Looks for /Launch actions that start a program from the PDF.", "يبحث عن إجراءات ‎/Launch‎ التي تشغّل برنامجًا من PDF.",
            labels=("PDF launch action",), applies=_PDF, weight=1.8, conf=0.8, source=D)
label_layer("pdf_embedded_files", "Files inside the PDF", "ملفات داخل PDF", "documents",
            "Looks for files attached inside the PDF, and whether one is a program.", "يبحث عن ملفات مرفقة داخل PDF، وهل أحدها برنامج.",
            labels=("PDF embeds an executable file", "PDF has embedded files"), applies=_PDF, weight=1.0, conf=0.6, source=D)
label_layer("pdf_obfuscated_names", "Disguised PDF keywords", "كلمات PDF متنكرة", "documents",
            "Looks for PDF keywords written in hex escapes (/J#61vaScript) to slip past filters.",
            "يبحث عن كلمات PDF مكتوبة بترميز سداسي (‎/J#61vaScript‎) للتسلل من المرشحات.",
            labels=("Obfuscated PDF name objects",), applies=_PDF, weight=1.6, conf=0.75, source=D)
label_layer("pdf_form_submit", "PDF sends form data", "PDF يرسل بيانات النموذج", "documents",
            "Looks for forms that submit what you type to an address.", "يبحث عن نماذج ترسل ما تكتبه إلى عنوان ما.",
            labels=("PDF form submits data",), applies=_PDF, weight=0.6, conf=0.5, source=D)
label_layer("pdf_remote_goto", "PDF jumps to remote files", "PDF يقفز إلى ملفات بعيدة", "documents",
            "Looks for GoToR/GoToE actions that open other (remote or embedded) documents.", "يبحث عن إجراءات GoToR/GoToE التي تفتح مستندات أخرى.",
            labels=("Remote/embedded go-to action",), applies=_PDF, weight=0.5, conf=0.45, source=D)
label_layer("pdf_rich_media", "PDF Flash or 3D media", "وسائط فلاش أو ثلاثية في PDF", "documents",
            "Flags RichMedia (Flash/3D) content, a historic exploit route.", "يرصد محتوى RichMedia (فلاش/ثلاثي الأبعاد)، وهو طريق استغلال قديم.",
            labels=("PDF rich media (Flash/3D)",), applies=_PDF, weight=0.5, conf=0.45, source=D)
label_layer("pdf_jbig2", "JBIG2 image stream", "تدفق صور JBIG2", "documents",
            "Flags JBIG2 image streams, the decoder abused by zero-click exploits.", "يرصد تدفقات صور JBIG2، المفكك الذي استُغل في هجمات بلا نقر.",
            labels=("JBIG2 image stream",), applies=_PDF, weight=0.4, conf=0.4, source=D)
label_layer("pdf_header_offset", "PDF header moved", "ترويسة PDF مزاحة", "documents",
            "Checks that '%PDF' is at the very start (a shifted header hides the type from some scanners).",
            "يتحقق من أن '%PDF' في البداية تمامًا (الترويسة المزاحة تخفي النوع عن بعض الفاحصات).",
            labels=("PDF header not at file start",), applies=_PDF, weight=0.6, conf=0.5, source=D)
label_layer("rtf_objects", "Objects in RTF", "كائنات في RTF", "documents",
            "Looks for OLE objects embedded in an RTF, and \\objupdate that loads them on open.",
            "يبحث عن كائنات OLE مضمّنة في RTF، و‎\\objupdate‎ الذي يحمّلها عند الفتح.",
            labels=("RTF embedded OLE object",), applies=_RTF, weight=1.0, conf=0.6, source=D)
label_layer("rtf_exploit_objects", "RTF exploit objects", "كائنات استغلال في RTF", "documents",
            "Looks for Equation Editor and OLE2Link objects used by well-known Office exploits (CVE-2017-11882, CVE-2017-0199).",
            "يبحث عن كائنات Equation Editor وOLE2Link المستخدمة في ثغرات أوفيس المعروفة.",
            labels=("Equation Editor object", "OLE2Link object"), applies=_RTF, weight=2.2, conf=0.85, source=D)
label_layer("rtf_package", "Files packaged in RTF", "ملفات محزومة في RTF", "documents",
            "Looks for Package objects or whole Office files carried inside the RTF.", "يبحث عن كائنات Package أو ملفات أوفيس كاملة داخل RTF.",
            labels=("Embedded Package object", "Embedded OLE compound file"), applies=_RTF, weight=0.8, conf=0.55, source=D)

# =============================================================== archives and apps
label_layer("archive_bomb", "Decompression bomb", "قنبلة فك الضغط", "archives",
            "Compares packed and unpacked sizes to catch archives built to explode when opened.",
            "يقارن الأحجام المضغوطة وغير المضغوطة لاكتشاف أرشيفات مصممة لتنفجر عند فتحها.",
            labels=("Potential decompression bomb", "Overlapping archive entries"), applies=_ZIP, weight=1.4, conf=0.75, source=A)
label_layer("archive_encrypted", "Encrypted entries", "مدخلات مشفرة", "archives",
            "Flags password-protected entries that no scanner can look into.", "يرصد مدخلات محمية بكلمة مرور لا يستطيع أي فاحص رؤية داخلها.",
            labels=("Encrypted archive entries",), applies=_ZIP, weight=0.6, conf=0.5, source=A)
label_layer("archive_encrypted_programs", "Locked programs inside", "برامج مقفلة بالداخل", "archives",
            "Flags a password-protected archive that holds programs (a classic way to slip past mail filters).",
            "يرصد أرشيفًا محميًا بكلمة مرور يحوي برامج (طريقة معروفة لتجاوز مرشحات البريد).",
            labels=("Password-protected archive with executables",), applies=_ZIP, weight=1.6, conf=0.75, source=A)
label_layer("archive_path_traversal", "Path escape", "الهروب من المسار", "archives",
            "Looks for entry names like ../../ that would write outside the folder you extract to.",
            "يبحث عن أسماء مدخلات مثل ‎../../‎ تكتب خارج المجلد الذي تستخرج إليه.",
            labels=("Archive path traversal entry",), applies=_ZIP, weight=1.6, conf=0.8, source=A)
label_layer("archive_programs_inside", "Programs inside", "برامج بالداخل", "archives",
            "Lists programs and scripts packed inside the archive.", "يحصي البرامج والسكربتات المحزومة داخل الأرشيف.",
            labels=("Archive contains executable or script files",), applies=_ARCHIVE, weight=0.7, conf=0.5, source=A)
label_layer("archive_double_extension", "Disguised names inside", "أسماء متنكرة بالداخل", "archives",
            "Looks for entries named like documents that are really programs (report.pdf.exe).",
            "يبحث عن مدخلات تبدو مستندات وهي برامج في الحقيقة (report.pdf.exe).",
            labels=("Double-extension file in archive",), applies=_ZIP, weight=1.8, conf=0.8, source=A)


def _members(ctx: LayerContext) -> list[dict[str, Any]] | None:
    report = ctx.feature_summary.get("archive_members")
    return list(report.get("members") or []) if isinstance(report, dict) else None


def _member_known(ctx: LayerContext) -> dict[str, Any]:
    members = _members(ctx)
    if members is None:
        return unavailable("The files inside were not scanned.", "لم تُفحص الملفات الداخلية.")
    bad = [m for m in members if (m.get("hash") or {}).get("status") == "match"]
    if bad:
        return hit(0.97, f"{len(bad)} file(s) inside are listed as known malware.", f"{len(bad)} ملف(ات) بالداخل مدرجة كبرمجيات خبيثة معروفة.",
                   hard="known_malware")
    return clean(0.6, f"{len(members)} file(s) inside checked against the known-malware list.", f"فُحص {len(members)} ملف(ات) داخلية مقابل قائمة البرمجيات الخبيثة.")


register(Layer("archive_member_hashes", "Known malware inside", "برمجيات خبيثة معروفة بالداخل", "archives",
               "Fingerprints every file inside the archive and looks each one up in the offline known-malware table.",
               "يأخذ بصمة كل ملف داخل الأرشيف ويبحث عنها في جدول البرمجيات الخبيثة دون إنترنت.", 3.0,
               lambda f: _ZIP(f) and f["has_result"], _member_known, "core.archive_scan + core.hash_intel"))


def _member_yara(ctx: LayerContext) -> dict[str, Any]:
    members = _members(ctx)
    if members is None:
        return unavailable("The files inside were not scanned.", "لم تُفحص الملفات الداخلية.")
    rules = sorted({str(r) for m in members for r in m.get("yara") or []})
    if rules:
        return hit(0.8, "Rules matched files inside: " + ", ".join(rules[:3]), "قواعد طابقت ملفات بالداخل: " + ", ".join(rules[:3]))
    return clean(0.6, f"No rule matched the {len(members)} file(s) inside.", f"لم تطابق أي قاعدة الملفات الداخلية ({len(members)}).")


register(Layer("archive_member_rules", "Rules on files inside", "القواعد على الملفات الداخلية", "archives",
               "Runs the YARA rules on every file inside the archive, in memory.", "يشغّل قواعد YARA على كل ملف داخل الأرشيف في الذاكرة.", 1.8,
               lambda f: _ZIP(f) and f["has_result"], _member_yara, "core.archive_scan + YARA"))

label_layer("apk_dangerous_combos", "Android abuse combinations", "تركيبات إساءة أندرويد", "archives",
            "Looks for permission combinations typical of banking trojans and SMS fraud (accessibility + overlay, OTP reading, device admin + SMS).",
            "يبحث عن تركيبات أذونات معتادة في أحصنة طروادة المصرفية واحتيال الرسائل.",
            labels=("Accessibility + overlay/SMS combination", "OTP interception capability", "Device admin + SMS sending",
                    "Starts at boot with accessibility access"), applies=_APK, weight=1.8, conf=0.75, source=A)
label_layer("apk_sensitive_permissions", "Sensitive Android permissions", "أذونات أندرويد حساسة", "archives",
            "Flags an app that reads SMS and notifications with network access.", "يرصد تطبيقًا يقرأ الرسائل والإشعارات مع وصول للشبكة.",
            labels=("Sensitive Android permissions",), applies=_APK, weight=0.7, conf=0.5, source=A)
label_layer("apk_build_hygiene", "App build hygiene", "سلامة بناء التطبيق", "archives",
            "Checks the manifest for debuggable builds and unencrypted HTTP traffic.", "يفحص ملف البيان بحثًا عن بناء قابل للتصحيح وحركة HTTP غير مشفرة.",
            labels=("Debuggable release build", "Cleartext network traffic allowed"), applies=_APK, weight=0.4, conf=0.4, source=A)
label_layer("apk_hidden_code", "Hidden app code", "شيفرة تطبيق مخفية", "archives",
            "Looks for a second code file (dex) hidden among the app's assets.", "يبحث عن ملف شيفرة ثانٍ (dex) مخفي بين أصول التطبيق.",
            labels=("Secondary code hidden in assets",), applies=_APK, weight=1.2, conf=0.65, source=A)
label_layer("extension_permissions", "Extension reach", "مدى صلاحيات الإضافة", "archives",
            "Checks a browser extension for access to every site's sessions and for accepting messages from any website.",
            "يفحص إضافة المتصفح بحثًا عن وصول لجلسات كل المواقع وقبول رسائل من أي موقع.",
            labels=("Extension can harvest sessions on all sites", "Any website can message the extension", "Powerful browser-extension permissions"),
            applies=_EXT, weight=1.4, conf=0.65, source=A)
label_layer("extension_hygiene", "Extension safety settings", "إعدادات أمان الإضافة", "archives",
            "Checks for a weakened content-security policy and updates from outside the official store.",
            "يفحص سياسة أمان محتوى مضعفة وتحديثات من خارج المتجر الرسمي.",
            labels=("Weakened extension CSP", "Off-store update URL"), applies=_EXT, weight=0.8, conf=0.5, source=A)

# =============================================================== scripts and commands (tradecraft rules)
for _id, _en, _ar, _cen, _car, _labels, _w in (
    ("script_shell_object", "Script opens a shell", "السكربت يفتح موجه أوامر", "Looks for WScript.Shell / Shell.Application objects that run commands.",
     "يبحث عن كائنات WScript.Shell/Shell.Application التي تشغّل أوامر.", ("Script host creates a shell object",), 0.9),
    ("lolbin_proxy", "Windows tools abused to run code", "أدوات ويندوز تُستغل للتشغيل", "Looks for mshta, regsvr32 and rundll32 command lines that run remote or inline script.",
     "يبحث عن أوامر mshta وregsvr32 وrundll32 التي تشغّل سكربتًا بعيدًا أو مضمّنًا.",
     ("mshta runs remote or inline script", "regsvr32 scriptlet execution", "rundll32 runs script or remote code"), 1.8),
    ("download_tools", "Command-line downloaders", "أدوات تنزيل من سطر الأوامر", "Looks for certutil, bitsadmin and curl|sh used to fetch files.",
     "يبحث عن certutil وbitsadmin وcurl|sh المستخدمة لجلب الملفات.",
     ("certutil used to download or decode", "bitsadmin file transfer", "Download piped to shell"), 1.6),
    ("persistence_commands", "Starts itself again", "يعيد تشغيل نفسه", "Looks for Run keys, scheduled tasks and Linux start-up files written for persistence.",
     "يبحث عن مفاتيح Run والمهام المجدولة وملفات بدء لينكس المكتوبة للاستمرار.",
     ("Run-key persistence", "Scheduled task created", "Linux persistence or preload hijack"), 1.2),
    ("recovery_sabotage", "Destroys backups", "يدمّر النسخ الاحتياطية", "Looks for shadow-copy deletion and disabled boot recovery (ransomware's first steps).",
     "يبحث عن حذف النسخ الظلية وتعطيل استرداد الإقلاع (أولى خطوات برامج الفدية).", ("Shadow copy deletion", "Boot recovery disabled"), 2.2),
    ("security_disabled", "Turns off protection", "يعطّل الحماية", "Looks for commands that switch off Defender or the firewall.",
     "يبحث عن أوامر تعطّل Defender أو الجدار الناري.", ("Security tooling disabled",), 2.0),
    ("log_clearing", "Erases event logs", "يمسح سجلات الأحداث", "Looks for wevtutil cl / Clear-EventLog that wipe evidence.",
     "يبحث عن wevtutil cl/Clear-EventLog التي تمحو الأدلة.", ("Event logs cleared",), 1.6),
    ("hidden_launcher", "Hidden PowerShell launcher", "مشغّل PowerShell مخفي", "Looks for PowerShell started hidden with the execution policy bypassed.",
     "يبحث عن PowerShell يُشغَّل مخفيًا مع تجاوز سياسة التنفيذ.", ("Execution policy bypass with hidden window",), 1.0),
    ("reflective_load", "Loads code from memory", "يحمّل شيفرة من الذاكرة", "Looks for .NET assemblies loaded from bytes instead of files.",
     "يبحث عن تجميعات ‎.NET‎ تُحمَّل من بايتات بدل الملفات.", ("Reflective .NET assembly load",), 1.6),
    ("amsi_bypass", "Blinds antivirus scanning", "يعمي فحص مكافح الفيروسات", "Looks for tampering with AMSI, Windows' script-scanning interface.",
     "يبحث عن العبث بواجهة AMSI لفحص السكربتات في ويندوز.", ("AMSI bypass",), 2.6),
    ("credential_dumping", "Password dumping", "تفريغ كلمات المرور", "Looks for Mimikatz commands and LSASS memory dumping.",
     "يبحث عن أوامر Mimikatz وتفريغ ذاكرة LSASS.", ("Credential dumping tooling",), 2.6),
    ("cryptominer", "Cryptocurrency mining", "تعدين العملات المشفرة", "Looks for mining-pool (stratum) addresses.",
     "يبحث عن عناوين مجمّعات التعدين (stratum).", ("Cryptominer pool protocol",), 1.6),
    ("reverse_shell", "Remote control shell", "صدفة تحكم عن بعد", "Looks for one-liners that connect a shell to a remote machine.",
     "يبحث عن أوامر قصيرة تربط موجه الأوامر بجهاز بعيد.", ("Reverse shell one-liner",), 2.6),
):
    label_layer(_id, _en, _ar, "content", _cen, _car, labels=_labels, applies=_CONTENT, weight=_w, conf=0.8, source=S)

for _id, _en, _ar, _cen, _car, _labels, _w, _c in (
    ("encoded_powershell", "Encoded PowerShell", "PowerShell مرمّز", "Looks for PowerShell run with an encoded (-enc) command.",
     "يبحث عن PowerShell يعمل بأمر مرمّز (‎-enc‎).", ("Encoded PowerShell execution", "Base64 encoded PowerShell"), 1.6, 0.75),
    ("in_memory_execution", "Runs text as code", "يشغّل نصًا كشيفرة", "Looks for Invoke-Expression / IEX that runs downloaded or built-up text.",
     "يبحث عن Invoke-Expression/IEX الذي يشغّل نصًا منزّلًا أو مُركّبًا.", ("In-memory script execution",), 1.2, 0.65),
    ("download_api_calls", "Fetches a payload", "يجلب حمولة", "Looks for DownloadString / DownloadFile calls in scripts.",
     "يبحث عن استدعاءات DownloadString/DownloadFile في السكربتات.", ("Remote payload download behavior",), 1.2, 0.65),
    ("obfuscated_command", "Disguised command", "أمر متنكر", "Looks for base64 next to powershell, cmd or curl.",
     "يبحث عن base64 بجوار powershell أو cmd أو curl.", ("Obfuscated command execution",), 1.0, 0.6),
    ("indicator_hidden_by_encoding", "Hidden by encoding", "مخفي بالترميز", "Decodes base64, UTF-16, caret and spacing tricks, then re-checks the warning-sign rules.",
     "يفك ترميز base64 وUTF-16 وحيل الإقحام والتباعد ثم يعيد فحص قواعد علامات التحذير.", ("Indicator hidden by encoding",), 1.4, 0.7),
    ("case_obfuscation", "Random capitalisation", "أحرف كبيرة وصغيرة عشوائية", "Flags commands written like pOwErShElL to dodge simple filters.",
     "يرصد أوامر مكتوبة مثل pOwErShElL لتفادي المرشحات البسيطة.", ("Unusual capitalization pattern",), 0.6, 0.5),
    ("injection_api_names", "Injection recipe in text", "وصفة حقن في النص", "Looks for VirtualAlloc, WriteProcessMemory and CreateRemoteThread named together in a script.",
     "يبحث عن VirtualAlloc وWriteProcessMemory وCreateRemoteThread مذكورة معًا في سكربت.", ("Process-injection API names together",), 1.4, 0.7),
):
    label_layer(_id, _en, _ar, "content", _cen, _car, labels=_labels,
                applies=(lambda f: _CONTENT(f) and f["kind"] != "pe") if _id == "injection_api_names" else _CONTENT,
                weight=_w, conf=_c, scope=("heuristics",), source=H)

_B64 = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){256,}")
_HEADERS = {b"MZ": "Windows program", b"\x7fELF": "Linux program", b"PK\x03\x04": "ZIP archive", b"%PDF": "PDF",
            b"\xd0\xcf\x11\xe0": "Office file", b"\x1f\x8b": "gzip data"}


def _decoded_kind(blob: bytes) -> str | None:
    return next((name for magic, name in _HEADERS.items() if blob.startswith(magic)), None)


def _base64_payload(ctx: LayerContext) -> dict[str, Any]:
    text = (ctx.text() or "")[:4_000_000]
    blobs = _B64.findall(text)
    if not blobs:
        return clean(0.5, "No long base64 block.", "لا كتل base64 طويلة.")
    for blob in blobs[:20]:
        try:
            raw = base64.b64decode(blob[: len(blob) - len(blob) % 4], validate=False)
        except (binascii.Error, ValueError):
            continue
        kind = _decoded_kind(raw)
        if kind:
            return hit(0.85, f"A {len(blob):,}-character base64 block decodes to a {kind}.", f"كتلة base64 بطول {len(blob):,} محرفًا تفك إلى {kind}.")
    if ctx.facts.get("is_email"):
        return clean(0.4, f"{len(blobs)} base64 block(s), as email attachments use (none is a program).",
                     f"{len(blobs)} كتلة base64 كما في مرفقات البريد (لا شيء منها برنامج).")
    return hit(0.35, f"{len(blobs)} long base64 block(s) carrying opaque data.", f"{len(blobs)} كتلة base64 طويلة تحمل بيانات مبهمة.")


register(Layer("base64_payload", "Base64-wrapped payload", "حمولة ملفوفة بـ base64", "content",
               "Decodes long base64 blocks and checks whether one is a program, archive or document in disguise.",
               "يفك كتل base64 الطويلة ويتحقق مما إذا كانت إحداها برنامجًا أو أرشيفًا أو مستندًا متنكرًا.", 1.4,
               _TEXTUAL, _base64_payload, "CyberScan decoder"))


def _hex_payload(ctx: LayerContext) -> dict[str, Any]:
    text = (ctx.text() or "")[:4_000_000]
    for blob in _HEX.findall(text)[:20]:
        kind = _decoded_kind(bytes.fromhex(blob[:64]))
        if kind:
            return hit(0.85, f"A {len(blob) // 2:,}-byte hex block decodes to a {kind}.", f"كتلة سداسية بحجم {len(blob) // 2:,} بايت تفك إلى {kind}.")
    return clean(0.5, "No hex-encoded program or archive.", "لا برامج أو أرشيفات مرمّزة سداسيًا.")


register(Layer("hex_payload", "Hex-wrapped payload", "حمولة ملفوفة سداسيًا", "content",
               "Decodes long hexadecimal strings and checks whether one is a program or archive.",
               "يفك السلاسل السداسية الطويلة ويتحقق مما إذا كانت إحداها برنامجًا أو أرشيفًا.", 1.4,
               _TEXTUAL, _hex_payload, "CyberScan decoder"))

_JS_TRICKS = (
    (re.compile(r"\beval\s*\(\s*(?:unescape|atob|decodeURIComponent|String\.fromCharCode)\s*\(", re.I), "eval of decoded text"),
    (re.compile(r"(?:String\.fromCharCode\s*\([^)]{0,400}\)[^;]{0,40}){8,}", re.I), "many fromCharCode chains"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){60,}"), "long \\x escape runs"),
    (re.compile(r"(?:%u[0-9a-fA-F]{4}){30,}", re.I), "%u-encoded shellcode-like runs"),
    (re.compile(r"\bdocument\.write\s*\(\s*(?:unescape|atob)\s*\(", re.I), "document.write of decoded text"),
)


def _js_obfuscation(ctx: LayerContext) -> dict[str, Any]:
    text = (ctx.text() or "")[:2_000_000]
    found = [name for pattern, name in _JS_TRICKS if pattern.search(text)]
    if found:
        return hit(0.7, "Script obfuscation: " + ", ".join(found), "تمويه سكربت: " + ", ".join(found))
    return clean(0.5, "No script obfuscation tricks.", "لا حيل تمويه في السكربت.")


register(Layer("script_obfuscation", "Script obfuscation", "تمويه السكربت", "content",
               "Looks for eval of decoded text, fromCharCode chains, escape runs and %u shellcode strings.",
               "يبحث عن eval لنص مفكوك وسلاسل fromCharCode وتتابعات الهروب وسلاسل ‎%u‎.", 1.3,
               _TEXTUAL, _js_obfuscation, "CyberScan script check"))

_ENC = re.compile(r"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{24,})")
_PS_BAD = re.compile(r"(?i)downloadstring|downloadfile|invoke-webrequest|iwr\s|invoke-expression|\biex\b|start-process|frombase64string|net\.webclient")


def _decoded_ps(ctx: LayerContext) -> dict[str, Any]:
    text = (ctx.text() or "")[:2_000_000]
    blobs = _ENC.findall(text) if re.search(r"(?i)powershell|pwsh", text) else []
    if not blobs:
        return unavailable("No encoded PowerShell command to decode.", "لا يوجد أمر PowerShell مرمّز لفكه.", status="not_applicable")
    for blob in blobs[:10]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-16-le", "ignore")
        except (binascii.Error, ValueError):
            continue
        bad = _PS_BAD.findall(decoded)
        if bad:
            return hit(0.9, "The decoded command does: " + ", ".join(sorted({b.strip().lower() for b in bad})[:4]),
                       "الأمر بعد فكه يفعل: " + ", ".join(sorted({b.strip().lower() for b in bad})[:4]))
    return clean(0.5, "The decoded command does not download or run anything.", "الأمر بعد فكه لا ينزّل ولا يشغّل شيئًا.")


register(Layer("decoded_powershell", "What the encoded command does", "ماذا يفعل الأمر المرمّز", "content",
               "Decodes -EncodedCommand blobs and reads what the hidden PowerShell actually does.",
               "يفك كتل ‎-EncodedCommand‎ ويقرأ ما يفعله PowerShell المخفي فعلًا.", 1.8,
               _CONTENT, _decoded_ps, "CyberScan decoder"))

# =============================================================== web pages (HTML)
_FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION = re.compile(r"""\baction\s*=\s*["']?([^"'\s>]+)""", re.I)
_PASSWORD = re.compile(r"""<input\b[^>]*type\s*=\s*["']?password""", re.I)


def _forms(ctx: LayerContext) -> list[tuple[str, str]]:
    html = ctx.html()
    out = []
    for m in _FORM.finditer(html[:2_000_000]):
        tag = html[m.start():m.start() + 400]
        action = _ACTION.search(tag.split(">", 1)[0] if ">" in tag else tag)
        out.append(((action.group(1) if action else ""), m.group(0)))
    return out


def _password_form(ctx: LayerContext) -> dict[str, Any]:
    forms = [body for _, body in _forms(ctx) if _PASSWORD.search(body)]
    if forms:
        return hit(0.6, f"{len(forms)} form(s) ask for a password in a saved web page.", f"{len(forms)} نموذج(ة) تطلب كلمة مرور داخل صفحة ويب محفوظة.")
    return clean(0.55, "No password field in a form.", "لا حقل كلمة مرور في أي نموذج.")


register(Layer("html_password_form", "Password form", "نموذج كلمة مرور", "web",
               "Looks for a form asking for a password inside an HTML file or attachment (login pages don't arrive as files).",
               "يبحث عن نموذج يطلب كلمة مرور داخل ملف HTML أو مرفق (صفحات الدخول الحقيقية لا تصل كملفات).", 1.2,
               _HTML, _password_form, "CyberScan HTML check"))


def _form_target(ctx: LayerContext) -> dict[str, Any]:
    from detection.url_intel import _parse_ip_host  # noqa: PLC0415

    bad = []
    for action, _ in _forms(ctx):
        lowered = action.lower()
        if lowered.startswith(("http://", "https://", "//")):
            host = re.sub(r"^(?:https?:)?//", "", lowered).split("/")[0].split("@")[-1].split(":")[0].strip("[]")
            if _parse_ip_host(host) is not None:
                bad.append(f"IP address {host}")
            elif lowered.startswith("http://"):
                bad.append(f"unencrypted {host}")
        elif lowered.startswith(("data:", "javascript:")):
            bad.append(lowered.split(":", 1)[0] + ":")
    if bad:
        return hit(0.8, "Form data is sent to " + ", ".join(bad[:3]), "تُرسل بيانات النموذج إلى " + ", ".join(bad[:3]))
    return clean(0.5, "No form sends data to a bare IP address or over plain http.", "لا نموذج يرسل بيانات إلى عنوان IP مجرد أو عبر http غير مشفر.")


register(Layer("html_form_target", "Where the form sends data", "إلى أين يرسل النموذج", "web",
               "Reads each form's destination: a bare IP address, plain http or a script URL is a phishing hallmark.",
               "يقرأ وجهة كل نموذج: عنوان IP مجرد أو http غير مشفر أو رابط سكربت من علامات التصيد.", 1.6,
               _HTML, _form_target, "CyberScan HTML check"))

_REFRESH = re.compile(r"""<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*url\s*=\s*([^"'>\s]+)""", re.I)


def _meta_refresh(ctx: LayerContext) -> dict[str, Any]:
    m = _REFRESH.search(ctx.html())
    if m and m.group(1).lower().startswith(("http", "//")):
        return hit(0.6, "The page sends you elsewhere automatically: " + m.group(1)[:80], "الصفحة تنقلك تلقائيًا إلى مكان آخر: " + m.group(1)[:80])
    return clean(0.5, "No automatic redirect.", "لا تحويل تلقائي.")


register(Layer("html_auto_redirect", "Automatic redirect", "تحويل تلقائي", "web",
               "Looks for a meta refresh that forwards the reader to another site.", "يبحث عن meta refresh ينقل القارئ إلى موقع آخر.", 0.8,
               _HTML, _meta_refresh, "CyberScan HTML check"))

_IFRAME = re.compile(r"<iframe\b[^>]*>", re.I)


def _hidden_iframe(ctx: LayerContext) -> dict[str, Any]:
    hidden = [t for t in _IFRAME.findall(ctx.html()) if re.search(
        r"""(?:width|height)\s*=\s*["']?0*[01]\b|display\s*:\s*none|visibility\s*:\s*hidden""", t, re.I)]
    if hidden:
        return hit(0.7, f"{len(hidden)} invisible frame(s) load another page.", f"{len(hidden)} إطار(ات) خفية تحمّل صفحة أخرى.")
    return clean(0.5, "No invisible frames.", "لا إطارات خفية.")


register(Layer("html_hidden_iframe", "Invisible frame", "إطار خفي", "web",
               "Looks for zero-size or hidden iframes that load content the reader can't see.", "يبحث عن إطارات iframe بحجم صفر أو مخفية تحمّل محتوى لا يراه القارئ.", 1.2,
               _HTML, _hidden_iframe, "CyberScan HTML check"))

_SMUGGLE = (re.compile(r"new\s+Blob\s*\(", re.I), re.compile(r"createObjectURL|msSaveOrOpenBlob", re.I),
            re.compile(r"""\.download\s*=|download\s*=\s*["'][^"']+\.(?:exe|zip|iso|img|js|vbs|hta|lnk|msi|scr)""", re.I))


def _smuggling(ctx: LayerContext) -> dict[str, Any]:
    html = ctx.html()
    if all(p.search(html) for p in _SMUGGLE) and (_B64.search(html) or re.search(r"atob\s*\(", html, re.I)):
        return hit(0.85, "The page builds a file from embedded data and saves it (HTML smuggling).",
                   "الصفحة تبني ملفًا من بيانات مضمّنة وتحفظه (تهريب HTML).")
    return clean(0.55, "The page does not assemble a download from embedded data.", "الصفحة لا تجمع ملفًا للتنزيل من بيانات مضمّنة.")


register(Layer("html_smuggling", "HTML smuggling", "تهريب HTML", "web",
               "Looks for pages that rebuild a file from embedded base64 and trigger a download, bypassing mail filters.",
               "يبحث عن صفحات تعيد بناء ملف من base64 مضمّن وتطلق تنزيله متجاوزةً مرشحات البريد.", 2.0,
               _HTML, _smuggling, "CyberScan HTML check"))

# =============================================================== email
M = "detection.messages"
for _id, _en, _ar, _cen, _car, _labels, _w, _c in (
    ("email_brand_display_name", "Sender pretends to be a brand", "المرسل ينتحل علامة تجارية", "Compares the sender's display name with the real address's domain.",
     "يقارن اسم العرض للمرسل بنطاق العنوان الحقيقي.", ("Sender display name impersonates a brand",), 1.6, 0.75),
    ("email_display_address", "Two addresses in the sender", "عنوانان في خانة المرسل", "Flags a display name that shows a different email address than the real sender.",
     "يرصد اسم عرض يُظهر عنوان بريد مختلفًا عن المرسل الحقيقي.", ("Display name shows a different email address",), 1.4, 0.7),
    ("email_reply_to", "Replies go elsewhere", "الردود تذهب لمكان آخر", "Compares the Reply-To domain with the sender's domain.",
     "يقارن نطاق Reply-To بنطاق المرسل.", ("Reply-To differs from sender",), 0.8, 0.55),
    ("email_envelope", "Bounce address differs", "عنوان الارتداد مختلف", "Compares the Return-Path with the From address (weak alone: mailing services do it).",
     "يقارن Return-Path بعنوان From (إشارة ضعيفة وحدها).", ("Envelope sender differs from From",), 0.3, 0.35),
    ("email_authentication", "SPF / DKIM / DMARC", "SPF وDKIM وDMARC", "Reads the receiving server's Authentication-Results for failed sender checks.",
     "يقرأ نتائج Authentication-Results لدى الخادم المستقبل بحثًا عن فشل التحقق من المرسل.", ("Email authentication failed",), 1.6, 0.75),
    ("email_urgent_link", "Urgent call to action", "دعوة عاجلة للتصرف", "Looks for pressure wording (suspended, verify now) next to a link.",
     "يبحث عن عبارات ضغط (معلّق، تحقق الآن) بجوار رابط.", ("Urgent call to action with link",), 1.0, 0.6),
    ("email_executable_attachment", "Program attached", "برنامج مرفق", "Looks for attachments that are programs or scripts.",
     "يبحث عن مرفقات هي برامج أو سكربتات.", ("Email carries executable attachment",), 1.8, 0.8),
    ("email_headers_damaged", "Damaged headers", "ترويسات تالفة", "Checks that the message headers parse cleanly.",
     "يتحقق من أن ترويسات الرسالة سليمة.", ("Malformed email headers",), 0.4, 0.4),
):
    label_layer(_id, _en, _ar, "email", _cen, _car, labels=_labels, applies=_EMAIL, weight=_w, conf=_c, source=M)

# =============================================================== secrets and privacy (reported, never scored)
for _id, _en, _ar, _cen, _car, _types in (
    ("secret_private_key", "Private keys", "مفاتيح خاصة", "Looks for PEM / OpenSSH private-key blocks.", "يبحث عن كتل المفاتيح الخاصة PEM/OpenSSH.", ("private_key",)),
    ("secret_cloud_keys", "Cloud keys", "مفاتيح السحابة", "Looks for AWS access keys and Google API keys.", "يبحث عن مفاتيح وصول AWS ومفاتيح Google API.",
     ("aws_access_key_id", "aws_secret_access_key", "google_api_key")),
    ("secret_code_tokens", "Code-hosting tokens", "رموز استضافة الشيفرة", "Looks for GitHub, GitLab and npm tokens.", "يبحث عن رموز GitHub وGitLab وnpm.",
     ("github_token", "gitlab_token", "npm_token")),
    ("secret_chat_tokens", "Chat bot tokens and webhooks", "رموز وروابط بوتات المحادثة", "Looks for Slack, Discord and Telegram tokens and webhooks.",
     "يبحث عن رموز وروابط Slack وDiscord وTelegram.", ("slack_token", "slack_webhook", "discord_webhook", "telegram_bot_token")),
    ("secret_service_keys", "Payment and messaging API keys", "مفاتيح واجهات الدفع والمراسلة", "Looks for Stripe, SendGrid and Twilio keys.",
     "يبحث عن مفاتيح Stripe وSendGrid وTwilio.", ("stripe_secret_key", "sendgrid_api_key", "twilio_api_key")),
    ("secret_ai_keys", "AI service keys", "مفاتيح خدمات الذكاء الاصطناعي", "Looks for OpenAI and Anthropic API keys.", "يبحث عن مفاتيح OpenAI وAnthropic.",
     ("openai_api_key", "anthropic_api_key")),
    ("secret_jwt", "Session tokens (JWT)", "رموز الجلسات (JWT)", "Looks for JSON Web Tokens that may grant a logged-in session.",
     "يبحث عن رموز JWT التي قد تمنح جلسة مسجلة.", ("jwt",)),
    ("secret_connection_string", "Database passwords in URLs", "كلمات مرور قواعد البيانات في الروابط", "Looks for database and broker URLs with a password inside.",
     "يبحث عن روابط قواعد بيانات ووسطاء رسائل تتضمن كلمة مرور.", ("connection_string",)),
    ("secret_hardcoded_password", "Hard-coded passwords", "كلمات مرور مكتوبة في الشيفرة", "Looks for password/secret assignments with real-looking values.",
     "يبحث عن تعيينات كلمات مرور وأسرار بقيم تبدو حقيقية.", ("generic_secret",)),
    ("privacy_payment_cards", "Payment card numbers", "أرقام بطاقات الدفع", "Looks for Luhn-valid card numbers of known brands.",
     "يبحث عن أرقام بطاقات صالحة بخوارزمية Luhn من علامات معروفة.", ("payment_card",)),
):
    def _secret_run(ctx: LayerContext, _types=_types) -> dict[str, Any]:
        if ctx.inspection() is None:
            return unavailable("The content inspection did not run.", "لم يعمل فحص المحتوى.")
        found = [t for t in ctx.privacy_types() if t in _types]
        if found:
            return hit(0.85, f"{len(found)} item(s) found (values are never shown or sent).", f"وُجد {len(found)} عنصر (لا تُعرض القيم ولا تُرسل).")
        return clean(0.5, "None found.", "لا شيء.")
    register(Layer(_id, _en, _ar, "privacy", _cen, _car, 1.0, _CONTENT, _secret_run, "detection.secrets", affects_score=False))


def _pii(ctx: LayerContext) -> list[dict[str, Any]]:
    def compute() -> list[dict[str, Any]]:
        tools = str(Path(__file__).resolve().parents[2] / "Tools")
        if tools not in sys.path:
            sys.path.append(tools)
        from security_toolkit import pii  # noqa: PLC0415

        return pii.find((ctx.text() or "")[:2_000_000], max_items=500)
    return ctx.cached("pii", compute) or []


for _id, _en, _ar, _cen, _car, _kinds, _min in (
    ("privacy_national_ids", "National ID and passport numbers", "أرقام الهوية والجواز", "Looks for validated Saudi ID/Iqama, US SSN, UK NI and passport numbers.",
     "يبحث عن أرقام هوية سعودية/إقامة وضمان اجتماعي أمريكي وتأمين بريطاني وجوازات سفر صالحة.", ("saudi_id", "us_ssn", "uk_nino", "passport"), 1),
    ("privacy_bank_accounts", "Bank account numbers (IBAN)", "أرقام الحسابات البنكية (IBAN)", "Looks for checksum-valid IBANs.",
     "يبحث عن أرقام IBAN صالحة بالمجموع التحققي.", ("iban",), 1),
    ("privacy_birth_dates", "Dates of birth", "تواريخ الميلاد", "Looks for dates labelled as dates of birth.", "يبحث عن تواريخ موسومة كتواريخ ميلاد.", ("date_of_birth",), 1),
    ("privacy_contact_bulk", "Bulk contact details", "بيانات اتصال بالجملة", "Counts email addresses and phone numbers; 20 or more is a contact list.",
     "يحصي عناوين البريد وأرقام الهواتف؛ 20 أو أكثر تعني قائمة جهات اتصال.", ("email", "phone"), 20),
):
    def _pii_run(ctx: LayerContext, _kinds=_kinds, _min=_min) -> dict[str, Any]:
        items = _pii(ctx)
        count = sum(1 for item in items if item.get("kind") in _kinds)
        if count >= _min:
            return hit(0.8, f"{count} item(s) found (values are never shown or sent).", f"وُجد {count} عنصر (لا تُعرض القيم ولا تُرسل).")
        return clean(0.5, "None found." if not count else f"{count} found, below the reporting threshold.",
                     "لا شيء." if not count else f"وُجد {count}، أقل من حد الإبلاغ.")
    register(Layer(_id, _en, _ar, "privacy", _cen, _car, 0.8, _TEXTUAL if _id != "privacy_contact_bulk" else _CONTENT, _pii_run,
                   "Tools/security_toolkit.pii", affects_score=False))


def _gps(ctx: LayerContext) -> dict[str, Any]:
    tools = str(Path(__file__).resolve().parents[2] / "Tools")
    if tools not in sys.path:
        sys.path.append(tools)
    from security_toolkit import metadata  # noqa: PLC0415

    values = metadata.exif_values(ctx.raw)
    if values is None:
        return unavailable("The picture reader (Pillow) is not installed.", "قارئ الصور (Pillow) غير مثبت.")
    gps = values.get("GPS") if isinstance(values, dict) else None
    if gps and metadata.gps_coordinates(gps):
        return hit(0.9, "The picture stores the GPS location where it was taken.", "الصورة تخزّن موقع GPS حيث التُقطت.")
    return clean(0.6, "No GPS location stored.", "لا موقع GPS مخزّن.")


register(Layer("privacy_photo_location", "Photo location (GPS)", "موقع الصورة (GPS)", "privacy",
               "Reads the picture's EXIF data for the GPS position where it was taken.", "يقرأ بيانات EXIF في الصورة بحثًا عن موقع GPS حيث التُقطت.", 0.8,
               kinds("image"), _gps, "Tools/security_toolkit.metadata", affects_score=False))

# shannon is re-exported for tests that check the decoders' inputs
__all__ = ["shannon"]
