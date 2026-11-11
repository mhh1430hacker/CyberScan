from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

import pytest

from Tools.registry import ToolRegistry


TOOLS_ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = [
    "file_security",
    "malware_analysis",
    "url_domain_security",
    "website_security",
    "email_security",
]


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _zip_file(name: str, content: bytes = b"sample") -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return stream.getvalue()


def _certificate(expired: bool) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(days=30)
    not_after = now - timedelta(days=1) if expired else now + timedelta(days=30)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before.replace(tzinfo=None))
            .not_valid_after(not_after.replace(tzinfo=None))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def _signature_case() -> tuple[dict, dict]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payload = b"benign signed content"
    signature = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    base = {
        "file_base64": _b64(payload),
        "signature_base64": _b64(signature),
        "public_key_pem": public_key,
        "algorithm": "rsa-pkcs1v15-sha256",
    }
    altered = {**base, "file_base64": _b64(b"altered content")}
    return base, altered


VALID_CERTIFICATE = _certificate(expired=False)
EXPIRED_CERTIFICATE = _certificate(expired=True)
VALID_SIGNATURE, INVALID_SIGNATURE = _signature_case()
YARA_RULE = 'rule local_test { strings: $a = "EVIL" condition: $a }'

TOOL_CASES = {
    "cyberscan.file.hash_analyzer": (
        {"data_base64": _b64(b"alpha")},
        {"data_base64": _b64(b"beta")},
        "sha256",
    ),
    "cyberscan.file.digital_signature_validator": (
        VALID_SIGNATURE,
        INVALID_SIGNATURE,
        "Detached signature is invalid",
    ),
    "cyberscan.file.type_mismatch_detector": (
        {"file_name": "notes.txt", "data_base64": _b64(b"plain text")},
        {"file_name": "invoice.pdf", "data_base64": _b64(b"plain text")},
        "mismatch",
    ),
    "cyberscan.file.entropy_analyzer": (
        {"data_base64": _b64(b"A" * 2048)},
        {"data_base64": _b64(bytes(range(256)) * 8)},
        "high_entropy",
    ),
    "cyberscan.file.pe_structure_analyzer": (
        {"data_base64": _b64(b"plain text")},
        {"data_base64": _b64(b"MZ" + b"\0" * 128)},
        "Malformed PE structure",
    ),
    "cyberscan.file.digital_certificate_inspector": (
        {"certificate_pem": VALID_CERTIFICATE},
        {"certificate_pem": EXPIRED_CERTIFICATE},
        "Certificate is expired",
    ),
    "cyberscan.file.embedded_payload_detector": (
        {"data_base64": _b64(b"ordinary document text")},
        {"data_base64": _b64(b"ordinary text MZ" + b"\0" * 64)},
        "Embedded file-like content",
    ),
    "cyberscan.file.archive_security_analyzer": (
        {"data_base64": _b64(_zip_file("readme.txt"))},
        {"data_base64": _b64(_zip_file("../payload.exe"))},
        "Archive path traversal names",
    ),
    "cyberscan.file.macro_security_analyzer": (
        {"data_base64": _b64(_zip_file("word/document.xml", b"<w:document/>"))},
        {"data_base64": _b64(_zip_file("word/vbaProject.bin", b"macro"))},
        "Macro-related content found",
    ),
    "cyberscan.file.pdf_active_content_analyzer": (
        {"data_base64": _b64(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj")},
        {"data_base64": _b64(b"%PDF-1.4\n/OpenAction /JavaScript /JS")},
        "PDF active-content indicators",
    ),
    "cyberscan.malware.yara_rule_scanner": (
        {"data_base64": _b64(b"BENIGN"), "rules": YARA_RULE},
        {"data_base64": _b64(b"EVIL"), "rules": YARA_RULE},
        "YARA",
    ),
    "cyberscan.malware.suspicious_api_detector": (
        {"data_base64": _b64(b"ordinary application string")},
        {"data_base64": _b64(b"CreateRemoteThread")},
        "Suspicious API names",
    ),
    "cyberscan.malware.packer_indicator_detector": (
        {"data_base64": _b64(b"plain text")},
        {"data_base64": _b64(b"MZ" + b"\0" * 128)},
        "Malformed PE structure",
    ),
    "cyberscan.malware.executable_section_analyzer": (
        {"data_base64": _b64(b"plain text")},
        {"data_base64": _b64(b"MZ" + b"\0" * 128)},
        "Malformed PE structure",
    ),
    "cyberscan.malware.script_obfuscation_detector": (
        {"script": "Write-Output 'hello'"},
        {"script": "powershell.exe -EncodedCommand SGVsbG8="},
        "Encoded PowerShell command",
    ),
    "cyberscan.malware.malware_indicator_analyzer": (
        {"data_base64": _b64(b"ordinary text")},
        {"data_base64": _b64(b"%PDF-1.4 /OpenAction /JavaScript /JS")},
        "JavaScript",
    ),
    "cyberscan.malware.persistence_indicator_detector": (
        {"content": "application settings"},
        {"content": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"},
        "Windows Run key",
    ),
    "cyberscan.malware.ransomware_indicator_detector": (
        {"content": "Your documents are available."},
        {"content": "vssadmin delete shadows /all"},
        "Shadow-copy deletion command",
    ),
    "cyberscan.malware.shellcode_pattern_detector": (
        {"data_base64": _b64(b"ordinary bytes")},
        {"data_base64": _b64(b"\x90" * 20)},
        "Long NOP sled",
    ),
    "cyberscan.malware.malware_similarity_analyzer": (
        {"left_base64": _b64(b"unique left bytes"), "right_base64": _b64(b"unrelated right bytes")},
        {"left_base64": _b64(b"same sample bytes"), "right_base64": _b64(b"same sample bytes")},
        "exact_match",
    ),
    "cyberscan.url.url_reputation_analyzer": (
        {"url": "https://example.com/"},
        {"url": "javascript:alert(1)"},
        "reputation",
    ),
    "cyberscan.url.phishing_url_detector": (
        {"url": "https://example.com/"},
        {"url": "javascript:alert(1)"},
        "Script URL scheme",
    ),
    "cyberscan.url.domain_reputation_analyzer": (
        {"domain": "example.com"},
        {"domain": "paypal-login-secure-attacker.invalid"},
        "reputation",
    ),
    "cyberscan.url.homograph_attack_detector": (
        {"url": "https://example.com/"},
        {"url": "https://xn--ypal-43d9g.com/"},
        "Internationalized",
    ),
    "cyberscan.url.redirect_chain_analyzer": (
        {"redirects": ["https://example.com/"]},
        {"redirects": ["https://example.com/", "javascript:alert(1)"]},
        "Script URL scheme",
    ),
    "cyberscan.url.url_shortener_analyzer": (
        {"url": "https://example.com/"},
        {"url": "https://bit.ly/abc"},
        "Known URL shortener",
    ),
    "cyberscan.url.dns_record_analyzer": (
        {"domain": "example.com", "records": ["A 192.0.2.1", "TXT v=spf1 -all"]},
        {"domain": "example.com", "records": ["TXT v=spf1 -all", "TXT v=spf1 ~all"]},
        "Multiple SPF records",
    ),
    "cyberscan.url.ssl_certificate_inspector": (
        {"certificate_pem": VALID_CERTIFICATE},
        {"certificate_pem": EXPIRED_CERTIFICATE},
        "Certificate is expired",
    ),
    "cyberscan.url.domain_expiration_checker": (
        {"domain": "example.com", "expires_at": "2099-01-01T00:00:00Z"},
        {"domain": "example.com", "expires_at": "2000-01-01T00:00:00Z"},
        "expiration date has passed",
    ),
    "cyberscan.url.suspicious_subdomain_detector": (
        {"domain": "www.example.com"},
        {"domain": "login-paypal.attacker.com"},
        "deceptive subdomain",
    ),
    "cyberscan.website.http_security_headers_analyzer": (
        {"headers": {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()"}},
        {"headers": {}},
        "Missing HSTS",
    ),
    "cyberscan.website.csp_analyzer": (
        {"content_security_policy": "default-src 'self'; object-src 'none'"},
        {"content_security_policy": "default-src * 'unsafe-inline' 'unsafe-eval'"},
        "unsafe-inline",
    ),
    "cyberscan.website.cors_configuration_analyzer": (
        {"headers": {"access-control-allow-origin": "https://example.com"}},
        {"headers": {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}},
        "Wildcard CORS with credentials",
    ),
    "cyberscan.website.cookie_security_analyzer": (
        {"set_cookie": ["session=abc; Secure; HttpOnly; SameSite=Lax"]},
        {"set_cookie": ["session=abc"]},
        "Cookie lacks Secure",
    ),
    "cyberscan.website.https_configuration_checker": (
        {"url": "https://example.com/", "hsts_header": "max-age=31536000"},
        {"url": "http://example.com/"},
        "does not use HTTPS",
    ),
    "cyberscan.website.mixed_content_detector": (
        {"html": '<img src="https://example.com/logo.png">'},
        {"html": '<img src="http://example.invalid/logo.png">'},
        "Potential mixed content",
    ),
    "cyberscan.website.tls_configuration_analyzer": (
        {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
        {"tls_version": "TLSv1.0", "cipher": "DES-CBC"},
        "Legacy TLS protocol",
    ),
    "cyberscan.website.security_txt_validator": (
        {"security_txt": "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n"},
        {"security_txt": "Expires: 2000-01-01T00:00:00Z\n"},
        "Missing Contact field",
    ),
    "cyberscan.website.server_configuration_analyzer": (
        {"headers": {"content-type": "text/html"}},
        {"headers": {"x-powered-by": "ExampleFramework/1.0"}},
        "Technology header disclosed",
    ),
    "cyberscan.website.technology_fingerprinter": (
        {"html": "<html><body>plain page</body></html>", "headers": {}},
        {"html": "<script id='__NEXT_DATA__'>{}"},
        "Next.js",
    ),
    "cyberscan.email.email_header_analyzer": (
        {"message": "From: Alice <alice@example.com>\nReturn-Path: <alice@example.com>\nSubject: Hello\n\n"},
        {"message": "From: Alice <alice@example.com>\nReturn-Path: <bounce@evil.example>\nSubject: Hello\n\n"},
        "From and Return-Path domains differ",
    ),
    "cyberscan.email.spf_validator": (
        {"spf_record": "v=spf1 ip4:192.0.2.1 -all"},
        {"spf_record": "v=spf1 " + " ".join(f"include:d{i}.example" for i in range(11)) + " -all"},
        "lookup limit exceeded",
    ),
    "cyberscan.email.dkim_validator": (
        {"dkim_signature": "v=1; a=rsa-sha256; b=abc; bh=abc; d=example.com; h=from:to; s=mail", "public_key_record": "v=DKIM1; k=rsa; p=abc"},
        {"dkim_signature": "v=1; d=evil.example", "public_key_record": "not-a-key"},
        "Incomplete DKIM-Signature",
    ),
    "cyberscan.email.dmarc_validator": (
        {"dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"},
        {"dmarc_record": "v=DMARC1; p=invalid; pct=101"},
        "Invalid or incomplete DMARC record",
    ),
    "cyberscan.email.email_spoofing_detector": (
        {"message": "From: Alice <alice@example.com>\nSubject: Hello\n\nHi"},
        {"message": "From: CEO <ceo@example.com>\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nUrgent"},
        "Email authentication failed",
    ),
    "cyberscan.email.sender_identity_analyzer": (
        {"message": "From: Alice <alice@example.com>\nReply-To: Alice <alice@example.com>\n\n"},
        {"message": "From: Alice <alice@example.com>\nReply-To: thief@evil.example\n\n"},
        "Reply-To domain differs",
    ),
    "cyberscan.email.email_phishing_detector": (
        {"message": "From: Alice <alice@example.com>\nSubject: Hello\n\nMeeting notes attached."},
        {"message": "From: Security <security@example.com>\nSubject: Urgent account verification\n\nYour account is locked; click http://example.invalid/login immediately."},
        "Credential",
    ),
    "cyberscan.email.email_url_extractor": (
        {"message": "Hello, see https://example.com/."},
        {"message": "Verify account at http://example.invalid/login"},
        "urls",
    ),
    "cyberscan.email.email_attachment_risk_analyzer": (
        {"attachments": [{"file_name": "report.pdf", "content_type": "application/pdf"}]},
        {"attachments": [{"file_name": "invoice.pdf.exe", "content_type": "application/octet-stream"}]},
        "Risky email attachment name",
    ),
    "cyberscan.email.display_name_impersonation_detector": (
        {"message": "From: Alice <alice@example.com>\n\n", "brands": ["PayPal"]},
        {"message": "From: PayPal Support <alert@evil.example>\n\n", "brands": ["PayPal"]},
        "Brand in display name",
    ),
}


@pytest.fixture(scope="module")
def approved_registry():
    discovery = ToolRegistry(TOOLS_ROOT, approved_directories=CATEGORIES)
    records = discovery.discover()
    assert len(records) == 50
    assert all(record.status == "disabled" for record in records)
    runtime_hash = hashlib.sha256((TOOLS_ROOT / "tool_runtime.py").read_bytes()).hexdigest()
    for record in records:
        source = (TOOLS_ROOT / record.relative_path).read_text(encoding="utf-8")
        assert f'_RUNTIME_SHA256 = "{runtime_hash}"' in source
    approvals = {record.tool_id: record.sha256 for record in records if record.tool_id}
    return ToolRegistry(
        TOOLS_ROOT,
        approved_directories=CATEGORIES,
        trusted_tools=approvals,
    )


def _execute_and_validate(registry: ToolRegistry, tool_id: str, input_data: dict) -> dict:
    execution = registry.execute(tool_id, input_data)
    assert execution.status == "ok", execution.as_dict()
    result = execution.result
    assert result is not None
    assert result["tool_id"] == tool_id
    assert result["status"] in {"success", "partial", "error"}
    assert result["classification"] in {"clean", "suspicious", "unknown"}
    assert isinstance(result["risk_score"], int) and 0 <= result["risk_score"] <= 100
    assert isinstance(result["findings"], list)
    assert isinstance(result["evidence"], list)
    assert {"version", "execution_mode", "execution_time_ms", "source", "license", "timeout_seconds"} <= result["metadata"].keys()
    assert result["metadata"]["timeout_enforced"] is False
    return result


@pytest.mark.parametrize("tool_id", sorted(TOOL_CASES))
def test_each_tool_runs_benign_and_suspicious_inputs(approved_registry, tool_id):
    benign, suspicious, expected = TOOL_CASES[tool_id]
    benign_result = _execute_and_validate(approved_registry, tool_id, benign)
    suspicious_result = _execute_and_validate(approved_registry, tool_id, suspicious)

    rendered = json.dumps(suspicious_result, sort_keys=True).lower()
    if tool_id == "cyberscan.file.hash_analyzer":
        assert benign_result["metadata"]["details"]["sha256"] != suspicious_result["metadata"]["details"]["sha256"]
    elif tool_id == "cyberscan.malware.yara_rule_scanner":
        assert "yara" in rendered
    elif tool_id == "cyberscan.url.url_reputation_analyzer":
        assert suspicious_result["metadata"]["details"]["reputation"] == "unavailable"
    elif tool_id == "cyberscan.url.domain_reputation_analyzer":
        assert suspicious_result["metadata"]["details"]["reputation"] == "unavailable"
    elif tool_id == "cyberscan.malware.malware_similarity_analyzer":
        assert suspicious_result["metadata"]["details"]["exact_match"] is True
    else:
        assert expected.lower() in rendered


def test_archive_entry_limit_is_checked_before_zip_directory_parsing(approved_registry):
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED) as archive:
        for index in range(10_001):
            archive.writestr(f"entry-{index}.txt", b"x")

    result = _execute_and_validate(
        approved_registry,
        "cyberscan.file.archive_security_analyzer",
        {"data_base64": _b64(stream.getvalue())},
    )

    assert result["status"] == "partial"
    assert "10000-entry inspection limit" in result["metadata"]["details"]["limit_rejection"]


def test_default_registry_does_not_discover_unapproved_categories():
    records = ToolRegistry(TOOLS_ROOT).discover()
    discovered_ids = {record.tool_id for record in records}
    assert not (discovered_ids & TOOL_CASES.keys())


def test_invalid_file_encoding_returns_unified_error(approved_registry):
    result = _execute_and_validate(
        approved_registry,
        "cyberscan.file.hash_analyzer",
        {"data_base64": "not base64!"},
    )

    assert result["status"] == "error"
    assert result["classification"] == "unknown"


def test_changed_shared_runtime_is_rejected_before_tool_import(tmp_path):
    category = tmp_path / "file_security"
    category.mkdir()
    source_path = TOOLS_ROOT / "file_security" / "file_hash_analyzer.py"
    (category / source_path.name).write_bytes(source_path.read_bytes())
    runtime = TOOLS_ROOT / "tool_runtime.py"
    (tmp_path / "tool_runtime.py").write_bytes(runtime.read_bytes() + b"\n# test-only change\n")

    discovery = ToolRegistry(tmp_path, approved_directories=["file_security"])
    record = discovery.discover()[0]
    registry = ToolRegistry(
        tmp_path,
        approved_directories=["file_security"],
        trusted_tools={record.tool_id: record.sha256},
    )

    result = registry.execute(record.tool_id, {"data_base64": _b64(b"sample")})

    assert result.status == "import_error"
    assert "runtime hash does not match" in result.error["message"]
