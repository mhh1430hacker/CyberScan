"""Content disarm: take the active parts out of a document and keep the document.

Each routine does one documented thing and refuses (``Refused``) when it
can't do it exactly:

  neutralize_pdf_names        rename the PDF names that trigger code or
                              automatic actions (/JavaScript, /JS,
                              /OpenAction, /AA, /Launch, ...) to names of no
                              meaning, byte for byte the same length, so every
                              cross-reference offset stays valid;
  rebuild_pdf_without_active  rewrite the PDF with pypdf, without automatic
                              actions, scripts and attachments (for active
                              content hidden in compressed object streams);
  zero_ole_vba                overwrite every stream of an older Office file's
                              VBA project with zeros, in place (same sizes,
                              same sectors), so no macro code is left;
  neutralize_ooxml_external   point remote templates, linked objects, frames
                              and sub-documents at about:blank;
  disarm_markup               remove scripts, frames, plug-ins, event
                              handlers and script URLs from HTML/SVG/HTA;
  remove_rtf_objects          remove embedded OLE object groups from RTF.

The ``Removed`` records carry what was taken out. For edits that don't cut
a byte range (a rename, a rebuild) the offsets are those of the original
token, or 0..0 when the document was rewritten as a whole.
"""
from __future__ import annotations

import html
import io
import re
import zipfile

from repair_engine.executor.common import Refused, Removed

# ---------------------------------------------------------------- PDF
PDF_DANGEROUS = {
    b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile", b"EmbeddedFiles",
    b"RichMedia", b"RichMediaExecute", b"SubmitForm", b"ImportData", b"GoToE", b"GoToR",
}
_PDF_NAME = re.compile(rb"/([^\s/<>\[\]()%{}]+)")
_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _pdf_name(raw: bytes) -> bytes:
    return _NAME_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), raw) if b"#" in raw else raw


def pdf_active_tokens(data: bytes, before: int | None = None) -> list[tuple[int, int, bytes]]:
    """(start, end, decoded name) of every dangerous name in object dictionaries (not stream data)."""
    from repair_engine.parsers import parse

    regions = parse(data)
    if regions.format != "pdf":
        raise Refused("not a PDF")
    streams = [(s.start, s.end) for s in regions.of_kind("pdf_stream")]
    found = []
    for obj in regions.of_kind("pdf_object"):
        if before is not None and obj.start >= before:
            continue
        inner = [(a, b) for a, b in streams if obj.start <= a < obj.end]
        for match in _PDF_NAME.finditer(data, obj.start, obj.end):
            if any(a <= match.start() < b for a, b in inner):
                continue
            name = _pdf_name(match.group(1))
            if name in PDF_DANGEROUS:
                found.append((match.start(), match.end(), name))
    return found


def neutralize_pdf_names(data: bytes, before: int | None = None) -> tuple[bytes, list[Removed]]:
    tokens = pdf_active_tokens(data, before)
    if not tokens:
        raise Refused("no active PDF names outside compressed streams")
    out = bytearray(data)
    removed = []
    for start, end, name in tokens:
        width = end - start - 1
        out[start + 1:end] = (b"zz" + b"z" * width)[:width]   # /zz...: a name no reader gives meaning to
        removed.append(Removed(start, end, "pdf_active_name", data[start:end]))
    return bytes(out), removed


_PDF_BAD_ACTIONS = {"/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToE", "/GoToR", "/RichMediaExecute", "/Rendition"}
_PDF_BAD_KEYS = {"/OpenAction", "/AA", "/JS", "/JavaScript", "/EmbeddedFiles", "/EmbeddedFile", "/RichMedia", "/RichMediaContent"}
_PDF_BAD_ANNOTS = {"/FileAttachment", "/RichMedia", "/Screen", "/Movie", "/Sound"}


def rebuild_pdf_without_active(data: bytes) -> tuple[bytes, list[Removed]]:
    try:
        from pypdf import PdfReader, PdfWriter
        from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject
    except ImportError as exc:
        raise Refused("pypdf is not installed") from exc
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise Refused("the PDF is encrypted")
        pages = len(reader.pages)
        writer = PdfWriter(clone_from=reader)
    except Refused:
        raise
    except Exception as exc:  # noqa: BLE001 - pypdf raises many kinds on damaged input
        raise Refused(f"pypdf could not read the PDF ({type(exc).__name__})") from exc
    dropped: list[str] = []
    seen: set[int] = set()

    def clean(node, depth: int = 0) -> None:
        if depth > 60:
            return
        if isinstance(node, IndirectObject):
            key = (node.idnum, node.generation)
            if key in seen:
                return
            seen.add(key)
            try:
                node = node.get_object()
            except Exception:  # noqa: BLE001
                return
        if isinstance(node, DictionaryObject):
            for key in [k for k in list(node.keys()) if k in _PDF_BAD_KEYS]:
                del node[key]
                dropped.append(key)
            action = node.get("/A")
            try:
                action_type = action.get_object().get("/S") if action is not None else None
            except Exception:  # noqa: BLE001
                action_type = None
            if action_type in _PDF_BAD_ACTIONS:
                del node["/A"]
                dropped.append(f"/A {action_type}")
            if node.get("/S") in _PDF_BAD_ACTIONS:
                dropped.append(f"/S {node['/S']}")
                for key in list(node.keys()):
                    if key not in {"/Type"}:
                        del node[key]
            annots = node.get("/Annots")
            if annots is not None:
                try:
                    items = annots.get_object()
                    keep = ArrayObject([a for a in items if a.get_object().get("/Subtype") not in _PDF_BAD_ANNOTS])
                    if len(keep) != len(items):
                        dropped.append("annotation")
                        node[next(k for k in node.keys() if k == "/Annots")] = keep
                except Exception:  # noqa: BLE001
                    pass
            for value in list(node.values()):
                clean(value, depth + 1)
        elif isinstance(node, ArrayObject):
            for value in node:
                clean(value, depth + 1)

    clean(writer._root_object)
    for page in writer.pages:
        clean(page)
    if not dropped:
        raise Refused("pypdf found no active content to drop")
    try:   # drop the now unreferenced scripts and attachments (argument names changed in pypdf 6)
        writer.compress_identical_objects(remove_duplicates=False, remove_unreferenced=True)
    except TypeError:
        try:
            writer.compress_identical_objects(remove_identicals=False, remove_orphans=True)
        except Exception:  # noqa: BLE001 - very old pypdf: they stay, unreferenced
            pass
    except Exception:  # noqa: BLE001
        pass
    buffer = io.BytesIO()
    writer.write(buffer)
    out = buffer.getvalue()
    try:
        if len(PdfReader(io.BytesIO(out), strict=False).pages) != pages:
            raise Refused("the rebuilt PDF lost pages")
    except Refused:
        raise
    except Exception as exc:  # noqa: BLE001
        raise Refused(f"the rebuilt PDF does not open ({type(exc).__name__})") from exc
    return out, [Removed(0, 0, "pdf_rebuilt_without_active", ", ".join(sorted(set(dropped))).encode())]


# ---------------------------------------------------------------- OLE (VBA)
_VBA_STORAGES = {"macros", "_vba_project_cur", "vba"}
_ENDOFCHAIN = 0xFFFFFFFE


def vba_streams(ole) -> list[list[str]]:
    return [path for path in ole.listdir(streams=True, storages=False)
            if any(part.lower() in _VBA_STORAGES for part in path[:-1]) or path[-1].lower() == "_vba_project"]


def _chain(table, start: int, limit: int) -> list[int]:
    out, sect = [], start
    while sect not in (_ENDOFCHAIN, 0xFFFFFFFF) and len(out) < limit:
        if sect >= len(table) or sect in out[-1:]:
            raise Refused("the sector chain is damaged")
        out.append(sect)
        sect = table[sect]
    return out


def ole_vba_has_code(data: bytes) -> bool:
    """True when any VBA stream still holds a non-zero byte."""
    import olefile

    try:
        ole = olefile.OleFileIO(data)
    except Exception:  # noqa: BLE001
        return False
    with ole:
        for path in vba_streams(ole):
            try:
                if ole.openstream(path).read().strip(b"\x00"):
                    return True
            except Exception:  # noqa: BLE001
                return True
    return False


def zero_ole_vba(data: bytes) -> tuple[bytes, list[Removed]]:
    try:
        import olefile
    except ImportError as exc:
        raise Refused("olefile is not installed") from exc
    try:
        ole = olefile.OleFileIO(data)
    except Exception as exc:  # noqa: BLE001
        raise Refused(f"not a readable Office file ({type(exc).__name__})") from exc
    out = bytearray(data)
    removed: list[Removed] = []
    with ole:
        paths = vba_streams(ole)
        if not paths:
            raise Refused("no VBA project in this file")
        size = ole.sectorsize
        mini = ole.minisectorsize
        limit = len(data) // mini + 2
        ministream: list[int] | None = None
        for path in paths:
            entry = ole.direntries[ole._find(path)]
            length = entry.size
            if not length:
                continue
            if length < ole.minisectorcutoff:
                if ministream is None:
                    ole.loadminifat()
                    ministream = _chain(ole.fat, ole.root.isectStart, limit)
                spans = []
                for index in _chain(ole.minifat, entry.isectStart, limit):
                    at = index * mini
                    big = at // size
                    if big >= len(ministream):
                        raise Refused("a macro stream points outside the mini stream")
                    spans.append((ministream[big] + 1) * size + at % size)
                step = mini
            else:
                spans = [(sect + 1) * size for sect in _chain(ole.fat, entry.isectStart, limit)]
                step = size
            left = length
            for offset in spans:
                take = min(step, left)
                if offset + take > len(out):
                    raise Refused("a macro stream runs past the end of the file")
                removed.append(Removed(offset, offset + take, "ole_vba:" + "/".join(path), bytes(out[offset:offset + take])))
                out[offset:offset + take] = b"\x00" * take
                left -= take
                if left <= 0:
                    break
            if left > 0:
                raise Refused(f"the stream {'/'.join(path)} is shorter on disk than its size")
    result = bytes(out)
    if ole_vba_has_code(result):
        raise Refused("macro bytes remained after zeroing")
    return result, removed


# ---------------------------------------------------------------- OOXML links
RISKY_LINK_TYPES = {"attachedtemplate", "oleobject", "frame", "subdocument"}
_RELATIONSHIP = re.compile(rb"<Relationship\b[^>]*?/?>", re.IGNORECASE)
_TARGET = re.compile(rb'Target\s*=\s*"([^"]*)"')
_TYPE = re.compile(rb'Type\s*=\s*"([^"]*)"')
_EXTERNAL = re.compile(rb'TargetMode\s*=\s*"External"', re.IGNORECASE)


def _rewrite_package(data: bytes, edit) -> tuple[bytes, list[Removed]]:
    try:
        source = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise Refused(f"not a readable package: {exc}") from exc
    removed: list[Removed] = []
    buffer = io.BytesIO()
    with source, zipfile.ZipFile(buffer, "w") as target:
        for info in source.infolist():
            content = source.read(info)
            new = edit(info.filename, content, removed)
            clone = zipfile.ZipInfo(info.filename, info.date_time)
            clone.compress_type = info.compress_type
            clone.external_attr = info.external_attr
            clone.create_system = info.create_system
            target.writestr(clone, new)
    if not removed:
        raise Refused("nothing to change in the package")
    return buffer.getvalue(), removed


def neutralize_ooxml_external(data: bytes) -> tuple[bytes, list[Removed]]:
    def edit(name: str, content: bytes, removed: list[Removed]) -> bytes:
        if not name.lower().endswith(".rels"):
            return content

        def one(match: re.Match) -> bytes:
            tag = match.group(0)
            kind = _TYPE.search(tag)
            target = _TARGET.search(tag)
            if not (_EXTERNAL.search(tag) and kind and target):
                return tag
            if kind.group(1).rsplit(b"/", 1)[-1].decode("ascii", "replace").lower() not in RISKY_LINK_TYPES:
                return tag
            if target.group(1) == b"about:blank":
                return tag
            removed.append(Removed(0, 0, f"ooxml_external:{name}", target.group(1)))
            return tag[:target.start(1)] + b"about:blank" + tag[target.end(1):]

        return _RELATIONSHIP.sub(one, content)

    return _rewrite_package(data, edit)


# ---------------------------------------------------------------- markup
_TAG_START = re.compile(rb"<([A-Za-z][A-Za-z0-9:_-]*)")
_TAG_STOP = re.compile(rb"[>\"']")
_PAIRED = (b"script", b"iframe", b"frame", b"object", b"applet", b"foreignobject", b"handler", b"noembed", b"frameset")
_SINGLE = (b"embed", b"base", b"frame", b"param")
_CLOSE = {name: re.compile(rb"</" + name + rb"\s*>", re.IGNORECASE) for name in _PAIRED}
_EVENT_ATTR = re.compile(rb"""\s(on[a-z][a-z0-9_:-]*)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.IGNORECASE)
_URL_ATTR = re.compile(rb"""(\s(?:href|src|xlink:href|action|formaction|data|to|values|from|by|background|lowsrc|dynsrc)\s*=\s*)("[^"]*"|'[^']*'|[^\s>]+)""", re.IGNORECASE)
_MARKUP_HEAD = re.compile(rb"<(?:!doctype\s+html|html|svg|hta:application|head|body|script|iframe)\b", re.IGNORECASE)
# Quote-agnostic backstops for the final check (each '<' scans only up to the next '<' or '>').
_CRUDE_EVENT = re.compile(rb"<[A-Za-z][^<>]*?[\s/\"']on[a-z]+\s*=", re.IGNORECASE)
_CRUDE_URL = re.compile(rb"""(?:href|src|action|data|to|values)\s*=\s*["']?\s*(?:javascript|vbscript|livescript)\s*:""", re.IGNORECASE)


def looks_like_markup(data: bytes) -> bool:
    head = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n")
    return bool(_MARKUP_HEAD.search(head))


def _bad_url(value: bytes) -> bool:
    text = html.unescape(value.strip(b"\"'").decode("latin-1"))
    text = re.sub(r"[\x00-\x20]", "", text).lower()
    return text.startswith(("javascript:", "vbscript:", "data:text/html", "data:application/x-javascript", "data:image/svg+xml", "livescript:"))


def _tags(data: bytes):
    """(start, end, lower-case name) of each start tag, in one linear pass.

    Quotes count only where an attribute value starts (after '='), as in
    browsers; a tag left open at the end of the file runs to the end. The
    raw text of <script> and the other removed elements is skipped whole:
    (start, end) then covers the element through its closing tag.
    """
    pos, n = 0, len(data)
    while True:
        match = _TAG_START.search(data, pos)
        if match is None:
            return
        start, name = match.start(), match.group(1).lower()
        i, end = match.end(), n
        while True:
            stop = _TAG_STOP.search(data, i)
            if stop is None:
                break
            if stop.group(0) == b">":
                end = stop.end()
                break
            before = data[max(match.end(), stop.start() - 64):stop.start()].rstrip()
            if before.endswith(b"="):
                close = data.find(stop.group(0), stop.end())
                if close < 0:
                    break
                i = close + 1
            else:
                i = stop.end()
        if name in _PAIRED and not data[start:end].rstrip(b">").rstrip().endswith(b"/"):
            close = _CLOSE[name].search(data, end)
            end = close.end() if close else n
            yield start, end, name, True
        else:
            yield start, end, name, False
        pos = end


def markup_active(data: bytes) -> list[str]:
    """What still runs in this markup (empty when nothing does)."""
    found = []
    for start, end, name, element in _tags(data):
        text = data[start:end] if not element else b""
        if element or name in _SINGLE:
            found.append(f"<{name.decode('latin-1')}>")
            continue
        if _EVENT_ATTR.search(text):
            found.append("event handler")
        if any(_bad_url(m.group(2)) for m in _URL_ATTR.finditer(text)):
            found.append("script URL")
        lower = text.lower()
        if name == b"meta" and b"refresh" in lower:
            found.append("automatic redirect")
        if name in {b"set", b"animate"} and (b"href" in lower or b"javascript:" in lower):
            found.append("SVG animation of a link")
    if _CRUDE_EVENT.search(data):
        found.append("event handler")
    if _CRUDE_URL.search(data):
        found.append("script URL")
    return sorted(set(found))


def disarm_markup(data: bytes) -> tuple[bytes, list[Removed]]:
    if not looks_like_markup(data):
        raise Refused("not HTML or SVG")
    removed: list[Removed] = []
    out, cursor = bytearray(), 0
    for start, end, name, element in _tags(data):
        text = data[start:end]
        lower = text.lower()
        if element or name in _SINGLE or (name == b"meta" and b"refresh" in lower) or \
                (name in {b"set", b"animate"} and (b"href" in lower or b"javascript:" in lower)):
            replacement, label = b"", f"<{name.decode('latin-1')}>"
        else:
            replacement = _EVENT_ATTR.sub(b"", text)
            replacement = _URL_ATTR.sub(lambda m: m.group(1) + b'"#"' if _bad_url(m.group(2)) else m.group(0), replacement)
            if replacement == text:
                continue
            label = "attribute"
        out += data[cursor:start] + replacement
        removed.append(Removed(start, end, f"markup:{label}", text))
        cursor = end
    if not removed:
        raise Refused("no active markup found")
    out += data[cursor:]
    result = bytes(out)
    left = markup_active(result)
    if left:
        raise Refused("active markup remained after disarming: " + ", ".join(left[:3]))
    return result, removed


# ---------------------------------------------------------------- RTF
_RTF_OBJECT = re.compile(rb"\{\s*(?:\\\*\s*)?\\(?:object|objdata)(?![a-z])")


def looks_like_rtf(data: bytes) -> bool:
    return data[:16].lstrip().startswith(b"{\\rt")


def _group_end(data: bytes, start: int) -> int:
    depth, i, n = 0, start, len(data)
    while i < n:
        ch = data[i]
        if ch == 0x5C:  # backslash: skip the escaped character (\{ \} \\)
            i += 2
            continue
        if ch == 0x7B:
            depth += 1
        elif ch == 0x7D:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise Refused("the RTF braces don't balance")


def rtf_objects(data: bytes) -> list[tuple[int, int]]:
    spans, cursor = [], 0
    for match in _RTF_OBJECT.finditer(data):
        if match.start() < cursor:
            continue
        end = _group_end(data, match.start())
        spans.append((match.start(), end))
        cursor = end
    return spans


def remove_rtf_objects(data: bytes) -> tuple[bytes, list[Removed]]:
    if not looks_like_rtf(data):
        raise Refused("not an RTF document")
    _group_end(data, data.find(b"{"))   # the document itself must balance
    spans = rtf_objects(data)
    if not spans:
        raise Refused("no embedded objects")
    out, cursor, removed = bytearray(), 0, []
    for start, end in spans:
        out += data[cursor:start]
        removed.append(Removed(start, end, "rtf_object", data[start:end]))
        cursor = end
    out += data[cursor:]
    return bytes(out), removed
