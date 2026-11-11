"""Fusion/calibration, secrets, the web upload API, and robustness against malformed input."""
from __future__ import annotations

import json
import os
import random
import tempfile

import pytest

from core.file_analyzer import analyze_file
from core.scanner import scan_target
from detection.common import Indicator, fuse, fuse_correlated, noisy_or
from detection.engine import analyze_text_json, analyze_upload, inspect_content, safe_file_name, sniff_type
from detection.secrets import scan_secrets
from detection_fixtures import BENIGN_PDF_OBJECTS, make_apk, make_docx, make_pdf, make_vba_project, make_zip

AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example key, split to avoid secret scanners
GITHUB_FAKE = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


# --- calibration -------------------------------------------------------------------------------

def test_noisy_or_properties():
    assert noisy_or([]) == 0
    assert noisy_or([60]) == 60
    assert noisy_or([50, 50]) == 75
    assert noisy_or([10] * 6) < 50  # six weak hints are not a verdict
    assert noisy_or([10] * 50) <= 100


def test_correlated_evidence_counts_once():
    # YARA and import analysis reading the same API names are one observation, not two.
    assert fuse_correlated([("Capability: process injection", 35), ("SuspiciousProcessInjection", 20)]) == 35
    assert fuse_correlated([("Capability: process injection", 35), ("Known packer or protector", 25)]) == noisy_or([35, 25])


def test_evidence_agreement_reflects_independent_categories():
    one = fuse([Indicator("phishing", "high", "a", "", 55)])
    three = fuse([Indicator("phishing", "high", "a", "", 55), Indicator("email_headers", "high", "b", "", 40),
                  Indicator("social_engineering", "medium", "c", "", 30)])
    assert one["evidence_agreement"] == "single-source"
    assert three["evidence_agreement"] == "strong"


# --- secrets / privacy ----------------------------------------------------------------------------

def test_secrets_are_detected_and_redacted():
    text = f"aws_access_key_id = {AWS_EXAMPLE_KEY}\ntoken: {GITHUB_FAKE}\npassword = 'Zx9!qL2#vT8m'\n"
    result = scan_secrets(text)
    types = {item["type"] for item in result["findings"]}
    assert {"aws_access_key_id", "github_token", "generic_secret"} <= types
    rendered = json.dumps(result["findings"])
    assert AWS_EXAMPLE_KEY not in rendered and GITHUB_FAKE not in rendered and "Zx9!qL2#vT8m" not in rendered
    assert result["findings"][0]["line"] == 1


@pytest.mark.parametrize("text", ["password = 'changeme123'", "api_key = '${API_KEY}'", "secret: 'xxxxxxxxxxxx'",
                                  "password = os.environ['DB_PASSWORD']", "token = 'aaaaaaaaaaaaaaaa'"])
def test_placeholders_and_references_are_not_secrets(text):
    assert scan_secrets(text)["count"] == 0


def test_payment_card_requires_luhn_and_brand():
    assert scan_secrets("card 4111 1111 1111 1111")["findings"][0]["type"] == "payment_card"
    assert scan_secrets("order 4111 1111 1111 1112")["count"] == 0  # fails Luhn
    assert scan_secrets("id 1234567812345670")["count"] == 0  # Luhn-valid, no card brand


def test_privacy_findings_do_not_raise_the_threat_score(tmp_path):
    sample = tmp_path / "settings.ini"
    sample.write_text(f"[aws]\naccess_key = {AWS_EXAMPLE_KEY}\n", encoding="utf-8")
    result = analyze_file(str(sample))
    assert result.classification == "SAFE"
    assert result.content_analysis["privacy"]["exposure_level"] == "high"
    assert AWS_EXAMPLE_KEY not in result.as_text()


def test_text_scan_reports_privacy_separately():
    result = scan_target(f"here is my key {AWS_EXAMPLE_KEY} please keep it")
    assert result.classification == "SAFE"
    assert result.content_analysis["privacy"]["count"] == 1


# --- web-facing API --------------------------------------------------------------------------------

def test_analyze_upload_returns_json_and_cleans_up():
    before = set(os.listdir(tempfile.gettempdir()))
    payload = analyze_upload(make_docx(extra={"word/vbaProject.bin": make_vba_project(
        'Attribute VB_Name = "M"\r\nSub AutoOpen()\r\nShell "cmd /c calc"\r\nEnd Sub\r\n')}), "../../Invoice.docm",
        {"ml_analysis": False})
    json.dumps(payload)  # fully serialisable
    assert payload["target"] == "Invoice.docm"
    assert payload["classification"] == "SUSPICIOUS"
    assert payload["content_analysis"]["file_type"] == "ooxml"
    leftovers = {name for name in set(os.listdir(tempfile.gettempdir())) - before if name.startswith("cyberscan-upload-")}
    assert leftovers == set()


def test_analyze_upload_rejects_oversized_input():
    with pytest.raises(ValueError, match="maximum file size"):
        analyze_upload(b"x" * 101, "a.bin", {"maximum_file_size": 100})


def test_analyze_text_json_for_url():
    payload = analyze_text_json("http://paypal-secure-login.com/webscr")
    json.dumps(payload)
    assert payload["classification"] == "SUSPICIOUS"


@pytest.mark.parametrize("name,expected", [("../../etc/passwd", "passwd"), ("C:\\Users\\x\\a.exe", "a.exe"), ("CON.txt", "upload.bin"),
                                           ("a\x00b.pdf", "ab.pdf"), ("", "upload.bin"), ("x" * 400 + ".pdf", "x" * 180)])
def test_safe_file_name(name, expected):
    assert safe_file_name(name) == expected


def test_type_is_sniffed_from_content_not_extension():
    assert sniff_type(make_pdf(BENIGN_PDF_OBJECTS)) == "pdf"
    result = inspect_content(make_pdf(BENIGN_PDF_OBJECTS), "holiday.jpg")
    assert result["file_type"] == "pdf"


@pytest.mark.parametrize("data", [b"", b"\x00" * 10, os.urandom(4096), b"plain text only"])
def test_unsupported_or_empty_input_is_handled(data):
    result = inspect_content(data, "blob")
    assert result["analyzer_errors"] == [] and result["classification"] in {"SAFE", "UNKNOWN"}


# --- robustness ----------------------------------------------------------------------------------

SEEDS = {
    "pdf": make_pdf(BENIGN_PDF_OBJECTS),
    "docm": make_docx(extra={"word/vbaProject.bin": make_vba_project('Attribute VB_Name = "M"\r\nSub A()\r\nEnd Sub\r\n')}),
    "ole": make_vba_project('Attribute VB_Name = "M"\r\nSub A()\r\nEnd Sub\r\n'),
    "apk": make_apk(["INTERNET", "READ_SMS"]),
    "zip": make_zip({"a.txt": b"hello" * 50, "b/run.js": b"var x = 1;"}),
}


@pytest.mark.parametrize("kind", sorted(SEEDS))
def test_mutated_inputs_never_raise_or_hit_analyzer_errors(kind):
    rng = random.Random(f"cyberscan-{kind}")
    seed = SEEDS[kind]
    for _ in range(150):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 8)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.2:
            data = data[: rng.randrange(8, len(data))]
        result = inspect_content(bytes(data), f"fuzz.{kind}")
        assert 0 <= result["score"] <= 100
        assert result["analyzer_errors"] == [], result["analyzer_errors"]
