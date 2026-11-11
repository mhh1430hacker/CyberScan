"""Static inspection of PDF, Office (OOXML and legacy OLE), Outlook .msg and RTF documents.

Nothing is rendered or executed. PDF streams are inflated with hard per-stream and total
caps; OOXML parts are read through ``zipfile`` with per-member caps and never written to
disk; XML is scanned with bounded regular expressions rather than an XML parser so that
entity-expansion tricks cannot be triggered.
"""
from __future__ import annotations

import re
import struct
import zipfile
import zlib
from typing import Any, Callable

from detection.common import (
    MAX_PDF_INFLATED_PER_STREAM, MAX_PDF_INFLATED_TOTAL, MAX_PDF_STREAMS, MAX_URLS_PER_INPUT,
    MAX_ZIP_MEMBER_READ, Indicator,
)
from detection.ole import OleError, OleFile, extract_vba_sources
from detection.url_intel import analyze_url_intel

AddFn = Callable[..., None]

EXECUTABLE_NAME_RE = re.compile(
    r"\.(?:exe|scr|com|pif|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|msi|dll|cpl|jar|reg|iso|img|vhdx?|chm|scf|url)$",
    re.IGNORECASE,
)


def _link_findings(urls: list[str], add: AddFn, where: str) -> list[dict[str, Any]]:
    """Analyze links found in a document; report only those with real red flags."""
    results: list[dict[str, Any]] = []
    for url in list(dict.fromkeys(urls))[:MAX_URLS_PER_INPUT]:
        analysis = analyze_url_intel(url)
        results.append({"url": url[:500], "score": analysis["score"],
                        "registrable_domain": analysis.get("registrable_domain"),
                        "findings": [item["label"] for item in analysis["findings"]]})
    worst = max(results, key=lambda item: item["score"], default=None)
    if worst and worst["score"] >= 30:
        add("high" if worst["score"] >= 50 else "medium", "Suspicious link in document",
            min(55, int(worst["score"] * 0.8)),
            f"A link in the {where} points to '{worst['registrable_domain'] or worst['url'][:80]}' "
            f"({'; '.join(worst['findings'][:3])}).", category="phishing", url=worst["url"])
    return results


# ---------------------------------------------------------------------------
# VBA
# ---------------------------------------------------------------------------

_VBA_AUTOEXEC = re.compile(
    r"\b(?:Auto_?Open|Auto_?Close|AutoExec|AutoNew|AutoExit|Document_(?:Open|Close|New|ContentControlOnEnter)|"
    r"DocumentOpen|DocumentBeforeClose|Workbook_(?:Open|Activate|BeforeClose|Deactivate)|Auto_Activate|"
    r"\w+_(?:Painted|Layout|GotFocus|MouseMove|Resize|Change))\b", re.IGNORECASE)
_VBA_CAPABILITIES: dict[str, tuple[str, re.Pattern[str]]] = {
    "execution": ("launches programs", re.compile(
        r"\bShell\s*\(|\bShell\s+\"|WScript\.Shell|Shell\.Application|\.ShellExecute\b|\.Run\s*\(|\.Exec\s*\(|"
        r"\bpowershell\b|\bcmd(?:\.exe)?\s*/c\b|\bmshta\b|\brundll32\b|\bregsvr32\b|\bcertutil\b|\bbitsadmin\b|"
        r"Win32_Process|\bMacScript\b|ExecuteExcel4Macro", re.IGNORECASE)),
    "download": ("downloads data", re.compile(
        r"URLDownloadToFile|MSXML2\.(?:Server)?XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest|"
        r"InternetOpen(?:Url)?|\.Open\s+\"GET\"|\.ResponseBody\b", re.IGNORECASE)),
    "file_write": ("writes files", re.compile(
        r"ADODB\.Stream|\.SaveToFile\b|\.Write\s|Scripting\.FileSystemObject|\bOpen\s+\S+\s+For\s+(?:Output|Binary|Append)\b|\bKill\s",
        re.IGNORECASE)),
    "win32_api": ("calls Windows APIs directly", re.compile(
        r"\bDeclare\s+(?:PtrSafe\s+)?(?:Function|Sub)\b.*\bLib\b|VirtualAlloc|RtlMoveMemory|CreateThread|"
        r"WriteProcessMemory|EnumSystemLanguageGroups|CallWindowProc", re.IGNORECASE)),
    "obfuscation": ("uses string obfuscation", re.compile(
        r"StrReverse|CallByName|\bChrW?\$?\s*\(\s*\d+\s*[\)\+\-]|FromBase64|Base64Decode|\bXor\b", re.IGNORECASE)),
    "environment": ("inspects the environment", re.compile(r"\bEnviron\$?\s*\(|Application\.UserName|GetObject\s*\(\s*\"winmgmts", re.IGNORECASE)),
}


def analyze_vba(sources: list[dict[str, str]], add: AddFn, *, where: str) -> dict[str, Any]:
    if not sources:
        return {"modules": 0}
    code = "\n".join(item["code"] for item in sources)[:4_000_000]
    autoexec = sorted({match.group(0) for match in _VBA_AUTOEXEC.finditer(code)})[:10]
    capabilities: dict[str, list[str]] = {}
    for key, (_, pattern) in _VBA_CAPABILITIES.items():
        hits = sorted({match.group(0).strip()[:40] for match in pattern.finditer(code)})
        if hits:
            capabilities[key] = hits[:8]
    chr_calls = len(re.findall(r"\bChrW?\$?\s*\(", code, re.IGNORECASE))
    if chr_calls >= 40:
        capabilities.setdefault("obfuscation", []).append(f"{chr_calls} Chr() calls")

    add("medium", "VBA macros present", 25,
        f"The {where} contains {len(sources)} VBA module(s). Macros can run arbitrary code when enabled.",
        modules=[item["module"] for item in sources][:20])
    if autoexec:
        add("medium", "Auto-executing macro", 25,
            f"Macro entry points run automatically on open/close: {', '.join(autoexec[:5])}.", entry_points=autoexec)
    dangerous = [key for key in ("execution", "download", "file_write", "win32_api") if key in capabilities]
    if dangerous:
        described = ", ".join(_VBA_CAPABILITIES[key][0] for key in dangerous)
        if autoexec:
            add("critical", "Auto-executing macro with dangerous capabilities", 75,
                f"An auto-run macro {described} ({'; '.join(sum((capabilities[k][:2] for k in dangerous), []))}). "
                "This is the dominant pattern of macro malware droppers.", capabilities=capabilities)
        else:
            add("high", "Macro with dangerous capabilities", 45,
                f"Macro code {described} ({'; '.join(sum((capabilities[k][:2] for k in dangerous), []))}).",
                capabilities=capabilities)
    if "obfuscation" in capabilities:
        add("medium", "Obfuscated macro code", 25,
            f"Macro code uses obfuscation primitives: {', '.join(capabilities['obfuscation'][:4])}.")
    urls = re.findall(r"https?://[^\s\"'<>()]{4,300}", code)
    links = _link_findings(urls, add, "macro code") if urls else []
    if urls:
        add("medium", "URLs embedded in macro code", 20,
            f"Macro code references {len(set(urls))} URL(s), e.g. {urls[0][:80]}.", urls=list(dict.fromkeys(urls))[:10])
    return {"modules": len(sources), "module_names": [item["module"] for item in sources][:50],
            "autoexec": autoexec, "capabilities": capabilities, "urls": links}


# ---------------------------------------------------------------------------
# OLE containers (legacy Office, .msg, embedded objects)
# ---------------------------------------------------------------------------

def _ole10native_name(raw: bytes) -> str | None:
    """Return the label/filename stored in an ``\\x01Ole10Native`` package stream."""
    try:
        body = raw[6:]  # 4-byte size + 2-byte flags
        label, _, rest = body.partition(b"\x00")
        filename, _, _ = rest.partition(b"\x00")
        name = (filename or label).decode("latin-1", errors="replace").strip()
        return name or None
    except (IndexError, ValueError):
        return None


def _biff_macro_sheets(workbook: bytes) -> int:
    """Count BOUNDSHEET records whose sheet type is 'macro sheet' (Excel 4.0 / XLM)."""
    count, pos = 0, 0
    limit = min(len(workbook), 8 * 1024 * 1024)
    while pos + 4 <= limit:
        record_type, length = struct.unpack_from("<HH", workbook, pos)
        if record_type == 0x0085 and length >= 6 and pos + 4 + length <= limit:
            sheet_type = workbook[pos + 4 + 5]
            if sheet_type == 0x01:
                count += 1
        if record_type == 0x000A and count == 0 and pos > 0:  # EOF of the globals substream
            break
        pos += 4 + length
    return count


def inspect_ole(data: bytes, add: AddFn, *, file_name: str = "", nested: bool = False) -> dict[str, Any]:
    try:
        ole = OleFile(data)
    except OleError as exc:
        add("low", "Malformed OLE container", 10, f"The compound file could not be parsed ({exc}).")
        return {"type": "ole", "error": str(exc)}

    stream_names = [entry.path for entry in ole.streams()]
    lower = {name.lower() for name in stream_names}
    if "encryptioninfo" in lower and "encryptedpackage" in lower:
        kind = "encrypted-ooxml"
    elif "worddocument" in lower:
        kind = "word"
    elif "workbook" in lower or "book" in lower:
        kind = "excel"
    elif "powerpoint document" in lower:
        kind = "powerpoint"
    elif any(name.startswith("__substg1.0_") for name in lower):
        kind = "outlook-msg"
    else:
        kind = "ole"
    details: dict[str, Any] = {"type": kind, "streams": stream_names[:100]}

    if kind == "encrypted-ooxml":
        add("medium", "Password-protected Office document", 20,
            "The document is encrypted, so its content cannot be inspected. Encryption is used to bypass mail and AV scanning; "
            "the password is usually sent in the same message.")

    try:
        sources = extract_vba_sources(ole)
    except OleError:
        sources = []
    has_vba_storage = any(entry.name.upper() == "VBA" for entry in ole.storages())
    if sources:
        details["vba"] = analyze_vba(sources, add, where="document" if not nested else "embedded object")
    elif has_vba_storage:
        add("medium", "VBA project present (source not recoverable)", 25,
            "A VBA storage exists but no module source could be decompressed; p-code-only or stomped projects hide their source.")

    if kind == "excel":
        workbook_entry = ole.find("Workbook") or ole.find("Book")
        try:
            macro_sheets = _biff_macro_sheets(ole.read(workbook_entry)) if workbook_entry else 0
        except (OleError, struct.error):
            macro_sheets = 0
        if macro_sheets:
            add("high", "Excel 4.0 (XLM) macro sheet", 45,
                f"The workbook defines {macro_sheets} Excel 4.0 macro sheet(s); XLM macros are a common, less-inspected malware vector.")
        details["xlm_macro_sheets"] = macro_sheets

    packages = []
    for entry in ole.streams():
        if entry.name == "\x01Ole10Native":
            name = _ole10native_name(ole.read(entry, limit=4096))
            if name:
                packages.append(name)
    if packages:
        details["embedded_packages"] = packages[:20]
        executable = [name for name in packages if EXECUTABLE_NAME_RE.search(name.split("\\")[-1])]
        if executable:
            add("high", "Embedded executable package", 55,
                f"An OLE Package object carries '{executable[0][:120]}', which runs when the icon is double-clicked.")
        else:
            add("low", "Embedded OLE package", 10, f"The document embeds file(s): {', '.join(p[:60] for p in packages[:3])}.")

    if kind == "outlook-msg":
        details.update(_inspect_msg(ole, add))
    return details


def _inspect_msg(ole: OleFile, add: AddFn) -> dict[str, Any]:
    from detection.messages import analyze_message  # local import: messages imports url_intel only

    def text_of(entry) -> str:
        raw = ole.read(entry, limit=1_000_000)
        return raw.decode("utf-16-le" if entry.name.endswith("001F") else "latin-1", errors="replace")

    attachments, body = [], ""
    for entry in ole.streams():
        name = entry.name.upper()
        if name in {"__SUBSTG1.0_1000001F", "__SUBSTG1.0_1000001E"} and not body:
            body = text_of(entry)
        elif name in {"__SUBSTG1.0_3707001F", "__SUBSTG1.0_3707001E", "__SUBSTG1.0_3704001F"}:
            attachments.append(text_of(entry).strip("\x00 "))
    headers = next((text_of(e) for e in ole.streams() if e.name.upper() == "__SUBSTG1.0_007D001F"), "")
    message = analyze_message((headers + "\n\n" + body) if headers else body)
    for item in message["indicators"]:
        add(item.severity, item.label, item.contribution, item.explanation, category=item.category)
    executable = [name for name in attachments if EXECUTABLE_NAME_RE.search(name)]
    if executable:
        add("high", "Email carries executable attachment", 50, f"Attachment '{executable[0][:100]}' runs code when opened.")
    return {"msg_attachments": list(dict.fromkeys(attachments))[:30], "msg_links": message["links"][:10]}


# ---------------------------------------------------------------------------
# OOXML
# ---------------------------------------------------------------------------

_REL_RE = re.compile(r"<Relationship\b[^>]{0,2000}?>", re.IGNORECASE)
_ATTR_RE = re.compile(r'\b(Type|Target|TargetMode)\s*=\s*"([^"]{0,2048})"', re.IGNORECASE)


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = MAX_ZIP_MEMBER_READ) -> bytes:
    with archive.open(info) as handle:
        return handle.read(limit)


def inspect_ooxml(archive: zipfile.ZipFile, add: AddFn, *, file_name: str = "") -> dict[str, Any]:
    infos = archive.infolist()[:5000]
    names = [info.filename for info in infos]
    lower_names = [name.lower() for name in names]
    details: dict[str, Any] = {"type": "ooxml", "parts": len(names)}
    extension = file_name.lower().rsplit(".", 1)[-1] if "." in file_name else ""

    # Macros
    vba_parts = [info for info in infos if info.filename.lower().endswith("vbaproject.bin")]
    if vba_parts:
        vba_details = []
        for info in vba_parts[:3]:
            try:
                ole = OleFile(_read_member(archive, info, 16 * 1024 * 1024))
                sources = extract_vba_sources(ole)
            except Exception:  # corrupt member or container: report "not recoverable" below
                sources = []
            if sources:
                vba_details.append(analyze_vba(sources, add, where="document"))
            else:
                add("medium", "VBA project present (source not recoverable)", 25,
                    "A vbaProject.bin part exists but no module source could be decompressed.")
        details["vba"] = vba_details
        if extension in {"docx", "xlsx", "pptx"}:
            add("medium", "Macro project in a macro-free file type", 20,
                f"A VBA project is packaged inside a .{extension} file, whose type should never contain macros.")
    if any(name.startswith("xl/macrosheets/") for name in lower_names):
        add("high", "Excel 4.0 (XLM) macro sheet", 45,
            "The workbook contains an Excel 4.0 macro sheet; XLM macros are a common, less-inspected malware vector.")

    # Relationships: remote templates, external objects, hyperlinks
    external_urls: list[str] = []
    remote_templates: list[str] = []
    for info in infos:
        if not info.filename.lower().endswith(".rels"):
            continue
        try:
            xml = _read_member(archive, info, 1024 * 1024).decode("utf-8", errors="replace")
        except Exception:
            continue
        for element in _REL_RE.findall(xml):
            attributes = {key.lower(): value for key, value in _ATTR_RE.findall(element)}
            if attributes.get("targetmode", "").lower() != "external":
                continue
            target = attributes.get("target", "")
            rel_type = attributes.get("type", "").rsplit("/", 1)[-1].lower()
            if rel_type in {"attachedtemplate"} or (rel_type in {"oleobject", "frame", "subdocument"} and target.lower().startswith(("http", "\\\\", "file:"))):
                if rel_type == "attachedtemplate":
                    remote_templates.append(target)
                else:
                    add("high", "External object loaded on open", 45,
                        f"A '{rel_type}' relationship loads content from '{target[:120]}' when the document opens "
                        "(remote object / CVE-2017-0199 style).", target=target[:300])
            if target.lower().startswith(("http://", "https://", "//")):
                external_urls.append(target)
            elif target.lower().startswith(("\\\\", "file:")):
                add("medium", "UNC or file path reference", 25,
                    f"The document references '{target[:120]}'; opening it can send Windows credentials (NTLM) to that host.")
    if remote_templates:
        add("high", "Remote template injection", 55,
            f"The document loads its template from '{remote_templates[0][:120]}'. Remote templates are used to fetch "
            "macro payloads after the document passes scanning (ATT&CK T1221).", targets=remote_templates[:5])
    details["external_links"] = _link_findings(external_urls, add, "document") if external_urls else []

    # DDE fields in Word body/headers/footers; DDE links in Excel
    instructions = []
    for info in infos:
        name = info.filename.lower()
        if name.startswith("word/") and name.endswith(".xml") and ("document" in name or "header" in name or "footer" in name):
            try:
                xml = _read_member(archive, info, 8 * 1024 * 1024).decode("utf-8", errors="replace")
            except Exception:
                continue
            instructions.append("".join(re.findall(r"<w:instrText[^>]*>([^<]*)</w:instrText>", xml)))
            instructions.extend(re.findall(r'w:instr="([^"]*)"', xml))
    field_code = " ".join(instructions)
    if re.search(r"\bDDE(?:AUTO)?\b", field_code, re.IGNORECASE):
        add("high", "DDE field (command execution)", 50,
            "A Word field uses DDE/DDEAUTO, which can launch commands when the document is opened (ATT&CK T1559.002).",
            snippet=field_code[:160])
    if any(name.startswith("xl/externallinks/") for name in lower_names):
        for info in infos:
            if info.filename.lower().startswith("xl/externallinks/") and info.filename.lower().endswith(".xml"):
                try:
                    if b"ddeLink" in _read_member(archive, info, 1024 * 1024):
                        add("high", "DDE link in workbook", 45, "The workbook contains a DDE link, which can launch commands.")
                        break
                except Exception:
                    continue

    # Embedded objects and ActiveX
    embedded = [info for info in infos if "/embeddings/" in info.filename.lower()]
    if embedded:
        details["embedded_objects"] = [info.filename for info in embedded][:30]
        for info in embedded[:10]:
            base = info.filename.rsplit("/", 1)[-1]
            if EXECUTABLE_NAME_RE.search(base):
                add("high", "Embedded executable object", 55, f"The document embeds '{base}'.")
                continue
            if base.lower().endswith(".bin"):
                try:
                    raw = _read_member(archive, info, 8 * 1024 * 1024)
                except Exception:
                    continue
                if raw.startswith(b"\xD0\xCF\x11\xE0"):
                    details.setdefault("embedded_ole", []).append(inspect_ole(raw, add, nested=True))
        add("low", "Embedded objects", 5, f"The document embeds {len(embedded)} object(s).")
    if any("/activex/" in name for name in lower_names):
        add("low", "ActiveX controls", 15, "The document contains ActiveX controls, which can run code and auto-trigger macros.")

    details["metadata"] = _ooxml_metadata(archive, infos)
    return details


def _ooxml_metadata(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo]) -> dict[str, str]:
    wanted = {"docprops/core.xml", "docprops/app.xml"}
    fields = ("dc:creator", "cp:lastModifiedBy", "dcterms:created", "dcterms:modified", "dc:title",
              "Application", "AppVersion", "Template", "Company")
    metadata: dict[str, str] = {}
    for info in infos:
        if info.filename.lower() not in wanted:
            continue
        try:
            xml = _read_member(archive, info, 256 * 1024).decode("utf-8", errors="replace")
        except Exception:
            continue
        for name in fields:
            match = re.search(rf"<{re.escape(name)}\b[^>]*>([^<]{{0,200}})</{re.escape(name)}>", xml)
            if match and match.group(1).strip():
                metadata[name.split(":")[-1]] = match.group(1).strip()
    return metadata


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

_PDF_NAME_RE = re.compile(rb"/([A-Za-z0-9#]{2,40})")
_PDF_KEYWORDS = {
    "JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "RichMedia", "XFA",
    "AcroForm", "SubmitForm", "ImportData", "GoToR", "GoToE", "URI", "ObjStm", "Encrypt", "JBIG2Decode",
}
_PDF_JS_SUSPICIOUS = [
    (rb"eval\s*\(", "eval()"), (rb"unescape\s*\(", "unescape()"), (rb"String\.fromCharCode", "String.fromCharCode"),
    (rb"app\.launchURL", "app.launchURL"), (rb"util\.printf", "util.printf (CVE-2008-2992)"),
    (rb"Collab\.(?:getIcon|collectEmailInfo)", "Collab.* (known exploited APIs)"), (rb"media\.newPlayer", "media.newPlayer"),
    (rb"getAnnots", "getAnnots"), (rb"exportDataObject", "exportDataObject (drops embedded file)"),
    (rb"%u0c0c%u0c0c|%u0a0a%u0a0a|%u9090%u9090", "heap-spray pattern"), (rb"app\.setTimeOut", "app.setTimeOut"),
    (rb"spell\.customDictionaryOpen", "spell.customDictionaryOpen"), (rb"this\.submitForm", "submitForm"),
]


def _decode_pdf_name(raw: bytes) -> str:
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1")


def _pdf_inflate_streams(data: bytes) -> tuple[bytes, int, int]:
    inflated = bytearray()
    streams = failed = 0
    for match in re.finditer(rb"stream\r?\n", data):
        if streams >= MAX_PDF_STREAMS or len(inflated) >= MAX_PDF_INFLATED_TOTAL:
            break
        start = match.end()
        end = data.find(b"endstream", start, start + 64 * 1024 * 1024)
        if end < 0:
            continue
        streams += 1
        decompressor = zlib.decompressobj()
        try:
            chunk = decompressor.decompress(data[start:end], MAX_PDF_INFLATED_PER_STREAM)
        except zlib.error:
            failed += 1
            continue
        inflated += chunk[: MAX_PDF_INFLATED_TOTAL - len(inflated)] + b"\n"
    return bytes(inflated), streams, failed


def inspect_pdf(data: bytes, add: AddFn, *, truncated: bool = False) -> dict[str, Any]:
    header_offset = data.find(b"%PDF")
    if header_offset > 0:
        add("low", "PDF header not at file start", 10,
            f"The %PDF header is at offset {header_offset}; data before it can make the file a polyglot that other programs parse differently.")
    inflated, stream_count, _ = _pdf_inflate_streams(data)
    corpus = data + b"\n" + inflated

    counts: dict[str, int] = {}
    obfuscated: set[str] = set()
    for match in _PDF_NAME_RE.finditer(corpus):
        raw = match.group(1)
        name = _decode_pdf_name(raw) if b"#" in raw else raw.decode("latin-1")
        if name in _PDF_KEYWORDS:
            counts[name] = counts.get(name, 0) + 1
            if b"#" in raw:
                obfuscated.add(name)

    has_js = bool(counts.get("JavaScript") or counts.get("JS"))
    auto_action = bool(counts.get("OpenAction") or counts.get("AA"))
    if has_js and auto_action:
        add("high", "PDF auto-executes JavaScript", 50,
            "The PDF contains JavaScript and an automatic action (/OpenAction or /AA) that runs when the file is opened.")
    elif has_js:
        add("medium", "PDF contains JavaScript", 30, "The PDF contains JavaScript; legitimate documents rarely need it.")
    if has_js:
        hits = [label for pattern, label in _PDF_JS_SUSPICIOUS if re.search(pattern, corpus, re.IGNORECASE)]
        if hits:
            add("high" if len(hits) >= 2 else "medium", "Suspicious JavaScript functions in PDF",
                45 if len(hits) >= 2 else 25, f"PDF JavaScript uses {', '.join(hits[:5])}.", functions=hits)
    if counts.get("Launch"):
        target = re.search(rb"/Launch.{0,400}?/(?:F|Win)\s*(?:<<.{0,200}?/F\s*)?\(([^)]{1,200})\)", corpus, re.DOTALL)
        detail = f" Target: {target.group(1).decode('latin-1', 'replace')}." if target else ""
        add("high", "PDF launch action", 55, "A /Launch action can start external programs or open files." + detail)
    if counts.get("EmbeddedFile") or counts.get("EmbeddedFiles"):
        names = [m.decode("latin-1", "replace") for m in re.findall(rb"/(?:UF|F)\s*\(([^)]{1,200})\)", corpus)]
        executable = [name for name in names if EXECUTABLE_NAME_RE.search(name.strip())]
        if executable:
            add("high", "PDF embeds an executable file", 55, f"The PDF carries an attached file '{executable[0][:100]}'.",
                files=names[:10])
        else:
            add("low", "PDF has embedded files", 10, f"The PDF carries attached file(s){': ' + ', '.join(names[:3]) if names else ''}.")
    if obfuscated:
        add("high", "Obfuscated PDF name objects", 40,
            f"Security-relevant names are hex-escaped ({', '.join(sorted(obfuscated))}) to evade keyword scanners; "
            "legitimate PDF writers do not do this.")
    if counts.get("RichMedia"):
        add("low", "PDF rich media (Flash/3D)", 10, "The PDF embeds rich media content, a historical exploit vector.")
    if counts.get("JBIG2Decode"):
        add("low", "JBIG2 image stream", 5, "JBIG2 decoders have a history of memory-corruption exploits; weak signal on its own.")
    if counts.get("GoToR") or counts.get("GoToE"):
        add("low", "Remote/embedded go-to action", 10, "The PDF jumps to another (remote or embedded) document.")
    if counts.get("SubmitForm") and counts.get("AcroForm"):
        add("low", "PDF form submits data", 10, "An interactive form submits entered data to a remote address.")

    uris = [m.decode("latin-1", "replace") for m in re.findall(rb"/URI\s*\(([^)]{4,2048})\)", corpus)]
    links = _link_findings(uris, add, "PDF") if uris else []
    if uris and len(data) < 200_000 and len(uris) == 1 and not counts.get("AcroForm") and links and links[0]["score"] >= 30:
        add("medium", "Single-link lure document", 15,
            "A small PDF whose only action is one suspicious link: the typical shape of PDF phishing lures.")
    return {
        "type": "pdf", "keywords": counts, "streams_inflated": stream_count, "uri_count": len(uris), "links": links[:10],
        "encrypted": bool(counts.get("Encrypt")), "truncated_input": truncated,
    }


# ---------------------------------------------------------------------------
# RTF
# ---------------------------------------------------------------------------

def inspect_rtf(data: bytes, add: AddFn) -> dict[str, Any]:
    lowered = data[:32 * 1024 * 1024].lower()
    details: dict[str, Any] = {"type": "rtf"}
    if not lowered.startswith(b"{\\rtf1"):
        add("low", "Non-standard RTF header", 10,
            "The file starts with '{\\rt' but not '{\\rtf1'; Word tolerates this, and malformed headers are used to evade parsers.")
    has_object = b"\\objdata" in lowered
    details["objects"] = lowered.count(b"\\object")
    hex_region = b""
    if has_object:
        start = lowered.find(b"\\objdata")
        hex_region = re.sub(rb"[^0-9a-f]", b"", lowered[start + 8: start + 8 + 4 * 1024 * 1024])
        severity, weight = ("high", 45) if b"\\objupdate" in lowered else ("medium", 25)
        add(severity, "RTF embedded OLE object" + (" with auto-update" if weight == 45 else ""), weight,
            "The RTF embeds an OLE object" + (" and \\objupdate forces it to load on open." if weight == 45 else "."))
    signatures = {
        b"4571756174696f6e2e33": ("high", "Equation Editor object", 60,
                                   "Equation.3 objects are used to exploit CVE-2017-11882 / CVE-2018-0802."),
        b"4f4c45324c696e6b": ("high", "OLE2Link object", 50, "OLE2Link objects fetch remote content (CVE-2017-0199)."),
        b"5061636b616765": ("medium", "Embedded Package object", 30, "A Package object can carry an arbitrary file, including executables."),
        b"d0cf11e0a1b11ae1": ("low", "Embedded OLE compound file", 10, "An OLE compound file is embedded inside the RTF."),
    }
    corpus = hex_region + lowered.replace(b" ", b"") if hex_region else lowered
    for signature, (severity, label, weight, explanation) in signatures.items():
        if signature in corpus or (label == "Equation Editor object" and b"equation.3" in lowered):
            add(severity, label, weight, explanation)
    if re.search(rb"\\\*\\template\s*https?://", lowered):
        add("high", "Remote template injection", 55, "The RTF loads its template from a remote URL (ATT&CK T1221).")
    return details
