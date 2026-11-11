from __future__ import annotations

from io import BytesIO

import pytest
from PIL import Image

import core.qr_scanner as qr_scanner
zxingcpp = pytest.importorskip("zxingcpp")

analyze_qr_image = qr_scanner.analyze_qr_image


def _qr_png(payload: str) -> bytes:
    barcode = zxingcpp.create_barcode(payload, zxingcpp.BarcodeFormat.QRCode)
    image = Image.fromarray(barcode.to_image(scale=6))
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_qr_upload_decodes_and_analyzes_url_without_network(monkeypatch):
    observed: list[str] = []

    def offline_assessment(url: str):
        observed.append(url)
        return {
            "score": 35,
            "classification": "UNKNOWN",
            "findings": [{"label": "URL shortener domain"}],
            "evidence_agreement": "single-source",
        }

    monkeypatch.setattr("detection.url_intel.analyze_url_intel", offline_assessment)
    payload = "https://bit.ly/account-check"

    result = analyze_qr_image(_qr_png(payload), "poster.png")

    assert result["status"] == "decoded"
    assert result["file_name"] == "poster.png"
    assert result["codes"][0]["payload"] == payload
    assert result["codes"][0]["risk"]["score"] == 35
    assert result["codes"][0]["recommendation"]
    assert observed == [payload]


def test_qr_upload_decodes_non_url_as_text():
    result = analyze_qr_image(_qr_png("wifi:T:WPA;S:guest;P:example-password;;"))

    assert result["status"] == "decoded"
    assert result["codes"][0]["kind"] == "text"
    assert "risk" not in result["codes"][0]
    assert result["codes"][0]["recommendation"]


def test_qr_image_validation_rejects_empty_oversized_and_non_image_inputs():
    with pytest.raises(ValueError, match="empty"):
        analyze_qr_image(b"")
    with pytest.raises(ValueError, match="exceeds"):
        analyze_qr_image(b"x" * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="not a readable image"):
        analyze_qr_image(b"not an image")


def test_qr_image_pixel_limit_is_checked_before_decode():
    image = Image.new("RGB", (4100, 4000), "white")
    output = BytesIO()
    image.save(output, format="PNG")

    with pytest.raises(ValueError, match="pixel limit"):
        analyze_qr_image(output.getvalue())


def test_qr_no_result_is_not_reported_as_safe():
    image = Image.new("RGB", (64, 64), "white")
    output = BytesIO()
    image.save(output, format="PNG")

    result = analyze_qr_image(output.getvalue())

    assert result["status"] == "no_qr_found"
    assert "classification" not in result


def test_qr_decoder_timeout_is_explicit(monkeypatch):
    monkeypatch.setattr(qr_scanner, "_decode_in_process", lambda _data: ("timeout", None))
    result = analyze_qr_image(_qr_png("https://example.com"))

    assert result["status"] == "decoder_timeout"
    assert "5-second limit" in result["limitations"][0]
