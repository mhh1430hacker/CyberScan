"""Content disarm in the repair engine: every fixture is synthetic and inert.

Each case: analyze() offers the finding with a plan, repair() succeeds and
validates, the active content is gone, and the result still opens as the
same kind of file.
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib

import pytest

from repair_engine.analyze import analyze, repair
from repair_engine.executor import Plan, apply
from repair_engine.parsers import parse


def _offer(data: bytes, name: str, key_prefix: str):
    report = analyze(data, name)
    found = [f for f in report.findings if f.key.startswith(key_prefix)]
    assert found, [(f.key, f.reason) for f in report.findings]
    assert all(f.repairable for f in found), [(f.key, f.reason) for f in found]
    return report, found


def _repair(data: bytes, name: str, findings):
    result = repair(data, name, findings)
    assert result.ok, (result.message, result.steps, result.validation and result.validation.checks)
    assert result.repaired is not None and result.validation.passed
    return result


# ---------------------------------------------------------------- PDF helpers
def _pdf(objects: dict[int, bytes]) -> bytes:
    """A classic PDF with a correct xref table."""
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for number in sorted(objects):
        offsets[number] = len(out)
        out += b"%d 0 obj\n" % number + objects[number] + b"\nendobj\n"
    xref = len(out)
    size = max(objects) + 1
    out += b"xref\n0 %d\n0000000000 65535 f \n" % size
    for number in range(1, size):
        out += b"%010d 00000 n \n" % offsets[number] if number in offsets else b"0000000000 65535 f \n"
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, xref)
    return bytes(out)


PAGES = {
    2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [6 0 R] >>",
    6: b"<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /A << /S /URI /URI (https://example.org/) >> >>",
}


def _pages(data: bytes) -> int:
    from pypdf import PdfReader
    return len(PdfReader(io.BytesIO(data), strict=False).pages)


@pytest.mark.parametrize("js_name", [b"/JavaScript", b"/J#61vaScript"])
def test_pdf_base_revision_scripts_are_renamed_in_place(js_name):
    data = _pdf({1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
                 4: b"<< /S " + js_name + b" /JS (app.alert\\(1\\)) >>", **PAGES})
    _report, found = _offer(data, "letter.pdf", "pdf_active_base")
    assert found[0].recommended
    result = _repair(data, "letter.pdf", found)
    out = result.repaired
    assert len(out) == len(data)                       # same length: the xref stays valid
    assert not re.search(rb"/(OpenAction|JS|JavaScript|J#61vaScript)\b", out)
    assert b"/URI (https://example.org/)" in out       # links are kept
    assert _pages(out) == 1
    assert not [f for f in analyze(out, "letter.pdf").findings if f.kind == "pdf_active"]


def _objstm_pdf() -> bytes:
    """Catalog and a JavaScript action only inside a compressed object stream, with an xref stream."""
    inner = {2: b"<< /Type /Catalog /Pages 3 0 R /OpenAction 5 0 R >>",
             5: b"<< /S /JavaScript /JS (app.alert\\(2\\)) >>"}
    body, header = b"", b""
    for number, text in inner.items():
        header += b"%d %d " % (number, len(body))
        body += text + b"\n"
    raw = header + body
    packed = zlib.compress(raw)
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    offsets[1] = len(out)
    out += b"1 0 obj\n<< /Type /ObjStm /N 2 /First %d /Filter /FlateDecode /Length %d >>\nstream\n" % (len(header), len(packed)) + packed + b"\nendstream\nendobj\n"
    offsets[3] = len(out)
    out += b"3 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n"
    offsets[4] = len(out)
    out += b"4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
    offsets[6] = len(out)
    rows = b""
    for number in range(7):
        if number == 0:
            rows += struct.pack(">BIH", 0, 0, 65535)
        elif number in (2, 5):
            rows += struct.pack(">BIH", 2, 1, list(inner).index(number))
        else:
            rows += struct.pack(">BIH", 1, offsets[number], 0)
    xref = zlib.compress(rows)
    out += (b"6 0 obj\n<< /Type /XRef /Size 7 /Root 2 0 R /W [1 4 2] /Filter /FlateDecode /Length %d >>\nstream\n" % len(xref)
            + xref + b"\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n" % offsets[6])
    return bytes(out)


def test_pdf_scripts_hidden_in_object_streams_are_rebuilt_out():
    data = _objstm_pdf()
    assert _pages(data) == 1
    _report, found = _offer(data, "form.pdf", "pdf_objstm")
    result = _repair(data, "form.pdf", found)
    out = result.repaired
    assert _pages(out) == 1
    from pypdf import PdfReader
    root = PdfReader(io.BytesIO(out), strict=False).trailer["/Root"].get_object()
    assert "/OpenAction" not in root
    assert b"app.alert" not in out and b"/JavaScript" not in out


# ---------------------------------------------------------------- OLE helpers
FREE, END, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def _cfb(tree: dict) -> bytes:
    """A minimal compound file (v3, 512-byte sectors). ``tree``: {name: bytes | {name: ...}}."""
    entries = [{"name": "Root Entry", "type": 5, "data": b"", "kids": []}]

    def add(node: dict, parent: int) -> None:
        for name, value in node.items():
            entries.append({"name": name, "type": 1 if isinstance(value, dict) else 2,
                            "data": b"" if isinstance(value, dict) else value, "kids": []})
            index = len(entries) - 1
            entries[parent]["kids"].append(index)
            if isinstance(value, dict):
                add(value, index)

    add(tree, 0)
    mini = bytearray()
    minifat: list[int] = []
    big_streams = []
    for entry in entries[1:]:
        data = entry["data"]
        if entry["type"] != 2 or not data:
            entry["start"], entry["size"] = END if entry["type"] == 2 else 0, len(data)
            continue
        if len(data) < 4096:
            first = len(mini) // 64
            count = -(-len(data) // 64)
            mini += data + b"\x00" * (count * 64 - len(data))
            minifat += [first + i + 1 for i in range(count - 1)] + [END]
            entry["start"], entry["size"] = first, len(data)
        else:
            big_streams.append(entry)
            entry["size"] = len(data)
    dir_count = -(-len(entries) // 4)
    minifat_count = -(-len(minifat) // 128) if minifat else 0
    mini_count = -(-len(mini) // 512) if mini else 0
    fat: list[int] = [FATSECT]
    sector = 1

    def chain(count: int) -> int:
        nonlocal sector
        if not count:
            return END
        first = sector
        for i in range(count):
            fat.append(first + i + 1 if i < count - 1 else END)
        sector += count
        return first

    dir_start = chain(dir_count)
    minifat_start = chain(minifat_count)
    mini_start = chain(mini_count)
    blobs = []
    for entry in big_streams:
        count = -(-entry["size"] // 512)
        entry["start"] = chain(count)
        blobs.append(entry["data"] + b"\x00" * (count * 512 - entry["size"]))
    assert len(fat) <= 128
    entries[0]["start"], entries[0]["size"] = (mini_start if mini else END), len(mini)

    def direntry(entry: dict | None) -> bytes:
        if entry is None:
            return b"\x00" * 64 + struct.pack("<HBBIII", 0, 0, 1, FREE, FREE, FREE) + b"\x00" * 16 + b"\x00" * 20 + struct.pack("<III", 0, 0, 0)
        name = entry["name"].encode("utf-16-le")
        kids = entry["kids"]
        child = kids[0] if kids else FREE
        return (name + b"\x00" * (64 - len(name)) + struct.pack("<HBBIII", len(name) + 2, entry["type"], 1, FREE, entry.get("right", FREE), child)
                + b"\x00" * 16 + b"\x00" * 4 + b"\x00" * 16 + struct.pack("<III", entry["start"], entry["size"], 0))

    for entry in entries:   # siblings as a right-leaning chain (all black): olefile walks it
        for a, b in zip(entry["kids"], entry["kids"][1:]):
            entries[a]["right"] = b
    directory = b"".join(direntry(e) for e in entries) + direntry(None) * (dir_count * 4 - len(entries))
    header = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, 1, dir_start, 0, 4096, minifat_start if minifat else END, minifat_count, END, 0)
              + struct.pack("<I", 0) + struct.pack("<I", FREE) * 108)
    fat_sector = struct.pack("<128I", *(fat + [FREE] * (128 - len(fat))))
    minifat_bytes = struct.pack(f"<{len(minifat)}I", *minifat) + struct.pack("<I", FREE) * (minifat_count * 128 - len(minifat))
    return header + fat_sector + directory + minifat_bytes + bytes(mini) + b"\x00" * (mini_count * 512 - len(mini)) + b"".join(blobs)


MODULE = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  Shell \"calc.exe\"\r\nEnd Sub\r\n" * 60   # > 4096 bytes


def test_ole_macros_are_zeroed_in_place():
    olefile = pytest.importorskip("olefile")
    data = _cfb({"WordDocument": b"Hello document text" * 30,
                 "Macros": {"PROJECT": b"ID=\"{00000000}\"\r\nModule=Module1\r\n",
                            "VBA": {"dir": b"\x01" * 300, "_VBA_PROJECT": b"\xcc\x61" * 10, "Module1": MODULE}}})
    with olefile.OleFileIO(data) as ole:
        assert ole.openstream("Macros/VBA/Module1").read() == MODULE
    _report, found = _offer(data, "report.doc", "ole_vba")
    result = _repair(data, "report.doc", found)
    out = result.repaired
    assert len(out) == len(data)
    assert b"Attribute VB_" not in out and b"calc.exe" not in out
    with olefile.OleFileIO(out) as ole:
        assert ole.openstream("WordDocument").read() == b"Hello document text" * 30   # the document is kept
        assert not ole.openstream("Macros/VBA/Module1").read().strip(b"\x00")
        assert not ole.openstream("Macros/VBA/dir").read().strip(b"\x00")
    assert not [f for f in analyze(out, "report.doc").findings if f.kind == "ole_vba"]


# ---------------------------------------------------------------- OOXML
def _docx(rels: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   b'<Default Extension="xml" ContentType="application/xml"/></Types>')
        z.writestr("_rels/.rels", b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr("word/document.xml", b"<w:document><w:body><w:p>Hello</w:p></w:body></w:document>")
        z.writestr("word/settings.xml", b'<w:settings><w:attachedTemplate r:id="rId1"/></w:settings>')
        for name, text in rels.items():
            z.writestr(name, text)
    return buffer.getvalue()


def test_ooxml_remote_template_is_pointed_at_about_blank():
    rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    data = _docx({
        "word/_rels/settings.xml.rels": f'<Relationships><Relationship Id="rId1" Type="{rel}/attachedTemplate" '
                                        f'Target="http://203.0.113.9/t.dotm" TargetMode="External"/></Relationships>'.encode(),
        "word/_rels/document.xml.rels": f'<Relationships><Relationship Id="rId5" Type="{rel}/hyperlink" '
                                        f'Target="https://example.org/" TargetMode="External"/></Relationships>'.encode(),
    })
    _report, found = _offer(data, "cv.docx", "ooxml_link")
    result = _repair(data, "cv.docx", found)
    with zipfile.ZipFile(io.BytesIO(result.repaired)) as z:
        assert z.testzip() is None
        assert b"203.0.113.9" not in z.read("word/_rels/settings.xml.rels")
        assert b'Target="about:blank"' in z.read("word/_rels/settings.xml.rels")
        assert b"https://example.org/" in z.read("word/_rels/document.xml.rels")   # hyperlinks kept
        assert z.read("word/document.xml") == b"<w:document><w:body><w:p>Hello</w:p></w:body></w:document>"
    assert parse(result.repaired).format == "ooxml"
    assert not [f for f in analyze(result.repaired, "cv.docx").findings if f.kind == "ooxml_link"]


# ---------------------------------------------------------------- markup
HTML = (b"<!doctype html><html><head><title>Invoice</title><script>fetch('//x')</script>"
        b"<meta http-equiv=\"refresh\" content=\"0;url=https://x.invalid\"></head>"
        b"<body onload=\"run()\"><h1>Invoice 42</h1><a href=\"jav&#x61;script:alert(1)\">pay</a>"
        b"<a href=\"https://example.org/\">site</a><iframe src=\"https://x.invalid\"></iframe>"
        b"<img src=\"logo.png\" onerror='go()'><p>Total: 10</p></body></html>")
SVG = (b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" onload=\"alert(1)\">"
       b"<script type=\"text/javascript\"><![CDATA[alert(2)]]></script><circle r=\"5\"/>"
       b"<a xlink:href=\"javascript:alert(3)\"><text>hi</text></a>"
       b"<set attributeName=\"href\" to=\"javascript:alert(4)\"/>"
       b"<foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><iframe/></body></foreignObject></svg>")


@pytest.mark.parametrize("data,name", [(HTML, "invoice.html"), (SVG, "logo.svg"), (HTML, "app.hta")])
def test_markup_is_disarmed(data, name):
    _report, found = _offer(data, name, "markup_active")
    result = _repair(data, name, found)
    out = result.repaired.lower()
    for bad in (b"<script", b"<iframe", b"onload", b"onerror", b"javascript:", b"jav&#x61;script", b"refresh", b"<set", b"foreignobject"):
        assert bad not in out, bad
    if name.endswith(".svg"):
        assert b"<circle r=\"5\"/>" in result.repaired and b"<text>hi</text>" in result.repaired
    else:
        assert b"<h1>Invoice 42</h1>" in result.repaired and b"https://example.org/" in result.repaired
        assert b"<img src=\"logo.png\">" in result.repaired


def test_clean_markup_is_left_alone():
    assert not [f for f in analyze(b"<html><body><p>Hello</p></body></html>", "a.html").findings if f.kind == "markup_active"]


# ---------------------------------------------------------------- ZIP
def test_zip_disguised_program_is_removed_and_the_rest_kept():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", b"Read me first.\n" * 20)
        z.writestr("invoice.pdf.exe", b"MZ" + b"\x00" * 200)
        z.writestr("tools/setup.exe", b"MZ" + b"\x01" * 200)
    data = buffer.getvalue()
    report = analyze(data, "invoice.zip")
    members = {f.detail.split("'")[1]: f for f in report.findings if f.kind == "zip_member"}
    assert set(members) == {"invoice.pdf.exe", "setup.exe"}
    assert members["invoice.pdf.exe"].recommended and not members["setup.exe"].recommended
    result = _repair(data, "invoice.zip", [members["invoice.pdf.exe"]])
    with zipfile.ZipFile(io.BytesIO(result.repaired)) as z:
        assert z.testzip() is None
        assert sorted(z.namelist()) == ["readme.txt", "tools/setup.exe"]
        assert z.read("readme.txt") == b"Read me first.\n" * 20
    both = _repair(data, "invoice.zip", list(members.values()))
    with zipfile.ZipFile(io.BytesIO(both.repaired)) as z:
        assert z.namelist() == ["readme.txt"]


def test_app_packages_are_not_flagged():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        z.writestr("manifest.json", b"{}")
        z.writestr("background.js", b"console.log(1)")
    assert not [f for f in analyze(buffer.getvalue(), "ext.zip").findings if f.kind == "zip_member"]


# ---------------------------------------------------------------- RTF
RTF = (rb"{\rtf1\ansi{\fonttbl{\f0 Arial;}}\f0 Dear customer,\par "
       rb"{\object\objemb\objupdate{\*\objclass Equation.3}\objw380\objh260{\*\objdata 01050000020000000b000000"
       rb"4571756174696f6e2e3300000000000000000000\}}{\result {\pict\wmetafile8 0000}}}"
       rb" Please see the attachment.\par}")


def test_rtf_objects_are_removed():
    _report, found = _offer(RTF, "letter.rtf", "rtf_object")
    result = _repair(RTF, "letter.rtf", found)
    out = result.repaired
    assert b"\\object" not in out and b"\\objdata" not in out and b"Equation" not in out
    assert b"Dear customer" in out and b"Please see the attachment." in out
    assert out.count(b"{") == out.count(b"}")


def test_unbalanced_rtf_is_refused():
    broken = rb"{\rtf1 {\object{\*\objdata 0102}"
    outcome = apply(broken, [Plan("remove_rtf_objects")])
    assert outcome.refused and "balance" in outcome.refused
