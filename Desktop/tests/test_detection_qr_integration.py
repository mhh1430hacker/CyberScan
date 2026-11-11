"""detection.engine <-> core.qr_scanner (Guardian) integration. Images are generated locally."""
from __future__ import annotations

from io import BytesIO

import pytest
from PIL import Image

from detection.engine import analyze_upload, inspect_content

zxingcpp = pytest.importorskip("zxingcpp")


def _qr_png(payload: str) -> bytes:
    barcode = zxingcpp.create_barcode(payload, zxingcpp.BarcodeFormat.QRCode)
    output = BytesIO()
    Image.fromarray(barcode.to_image(scale=6)).save(output, format="PNG")
    return output.getvalue()


def test_quishing_qr_code_is_suspicious():
    result = inspect_content(_qr_png("http://paypal-secure-login.com/webscr"), "parking-ticket.png")
    assert result["file_type"] == "image"
    assert result["details"]["qr_codes"]["status"] == "decoded"
    assert any(item.label == "Suspicious link in QR code" for item in result["indicators"])
    assert result["classification"] == "SUSPICIOUS"


def test_benign_qr_code_is_safe():
    result = inspect_content(_qr_png("https://www.example.com/menu"), "menu.png")
    assert result["details"]["qr_codes"]["status"] == "decoded"
    assert result["score"] == 0


def test_sms_scam_payload_in_qr_code_is_analyzed():
    result = inspect_content(_qr_png("SMSTO:+15550100:URGENT your account is suspended, send us the verification code you received"), "a.png")
    assert any(item.label.endswith("(QR code)") for item in result["indicators"])


def test_image_without_qr_code_is_safe():
    output = BytesIO()
    Image.new("RGB", (64, 64), "white").save(output, format="PNG")
    result = inspect_content(output.getvalue(), "blank.png")
    assert result["details"]["qr_codes"]["status"] == "no_qr_found"
    assert result["score"] == 0


def test_corrupt_image_degrades_to_status():
    result = inspect_content(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50, "broken.png")
    assert result["details"]["qr_codes"]["status"] == "not_decodable"
    assert result["analyzer_errors"] == []


def test_qr_findings_flow_through_the_upload_api():
    payload = analyze_upload(_qr_png("http://paypa1.com/login"), "scan-me.png", {"ml_analysis": False})
    assert payload["classification"] == "SUSPICIOUS"
    assert payload["content_analysis"]["details"]["qr_codes"]["codes"][0]["kind"] == "url"
