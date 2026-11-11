"""Bounded, offline implementations shared by the first CyberScan tool set."""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import math
import re
import struct
import time
import zipfile
from datetime import datetime, timezone
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from io import BytesIO
from typing import Any
from urllib.parse import urlsplit


MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_TEXT_LENGTH = 1_000_000
LICENSE_NOTICE = "UNSPECIFIED: the repository contains no applicable license declaration."
MAX_ARCHIVE_ENTRIES = 10_000
MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024


def _decode(value: str, field: str = "data_base64") -> bytes:
    if not isinstance(value, str) or len(value) > (MAX_FILE_BYTES * 4 // 3) + 8:
        raise ValueError(f"{field} must be a base64 string within the 50 MiB limit.")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} must contain valid base64.") from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"{field} exceeds the 50 MiB limit.")
    return data


def _bytes(input_data: dict[str, Any], key: str = "data_base64") -> bytes:
    data = _decode(input_data[key], key)
    if not data:
        raise ValueError(f"{key} must not be empty.")
    return data


def _text(input_data: dict[str, Any], key: str, limit: int = MAX_TEXT_LENGTH) -> str:
    value = input_data[key]
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string.")
    if len(value) > limit:
        raise ValueError(f"{key} exceeds the {limit}-character limit.")
    return value


def _finding(label: str, severity: str, detail: str, evidence: Any = None) -> dict[str, Any]:
    item: dict[str, Any] = {"label": label, "severity": severity, "detail": detail}
    if evidence is not None:
        item["evidence"] = evidence
    return item


def _risk(findings: list[dict[str, Any]]) -> int:
    weights = {"info": 0, "low": 15, "medium": 40, "high": 70, "critical": 90}
    return min(100, max((weights.get(item.get("severity", "info"), 0) for item in findings), default=0))


def _result(
    tool_id: str,
    findings: list[dict[str, Any]],
    evidence: list[Any],
    started: float,
    *,
    status: str = "success",
    classification: str | None = None,
    details: dict[str, Any] | None = None,
    version: str = "1.0.0",
    execution_mode: str = "local",
    source: str = "CyberScan local implementation",
    license_info: str = LICENSE_NOTICE,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    detail_values = dict(details or {})
    risk_score = detail_values.pop("_risk_score", _risk(findings))
    if classification is None:
        classification = "suspicious" if risk_score else "clean"
    metadata: dict[str, Any] = {
        "version": version,
        "execution_mode": execution_mode,
        "execution_time_ms": max(0, round((time.perf_counter() - started) * 1000)),
        "source": source,
        "license": license_info,
        "timeout_seconds": timeout_seconds,
        "timeout_enforced": False,
    }
    if detail_values:
        metadata["details"] = detail_values
    return {
        "tool_id": tool_id,
        "status": status,
        "classification": classification,
        "risk_score": risk_score,
        "findings": findings,
        "evidence": evidence,
        "metadata": metadata,
    }


def _content_analysis(data: bytes, file_name: str = "") -> dict[str, Any]:
    from detection.engine import inspect_content

    return inspect_content(data, file_name)


def _translate_indicators(report: dict[str, Any]) -> tuple[list[dict[str, Any]], list[Any]]:
    findings: list[dict[str, Any]] = []
    evidence: list[Any] = []
    for item in report.get("indicators", []):
        label = getattr(item, "label", None) or item.get("label", "Indicator")
        severity = getattr(item, "severity", None) or item.get("severity", "low")
        explanation = getattr(item, "explanation", None) or item.get("explanation", "")
        findings.append(_finding(str(label), str(severity), str(explanation)))
        evidence.append({"label": str(label), "category": getattr(item, "category", None) or item.get("category")})
    return findings, evidence


def _inspect_certificate(pem_or_base64: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        raw = pem_or_base64.encode("utf-8")
        cert = x509.load_pem_x509_certificate(raw)
    except (ValueError, TypeError):
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(pem_or_base64, validate=True))
        except (ValueError, binascii.Error) as exc:
            raise ValueError("certificate_pem must be a PEM certificate or base64-encoded DER certificate.") from exc

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    public_key = cert.public_key()
    key_type = type(public_key).__name__
    key_size = getattr(public_key, "key_size", None)
    sans: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(name.value) for name in extension.value]
    except x509.ExtensionNotFound:
        pass
    details = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_currently_valid": not_before <= now <= not_after,
        "public_key_type": key_type,
        "public_key_size": key_size,
        "signature_hash_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
        "subject_alternative_names": sans[:100],
        "certificate_der_sha256": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
    }
    findings: list[dict[str, Any]] = []
    if now < not_before:
        findings.append(_finding("Certificate is not yet valid", "medium", "The current time is before notBefore."))
    elif now > not_after:
        findings.append(_finding("Certificate is expired", "high", "The certificate is past notAfter."))
    if key_size is not None and key_size < 2048 and key_type == "RSAPublicKey":
        findings.append(_finding("Weak RSA key", "medium", f"The RSA key is {key_size} bits."))
    if details["signature_hash_algorithm"] in {"md5", "sha1"}:
        findings.append(_finding("Weak certificate signature hash", "medium", "The certificate uses a legacy hash algorithm."))
    return details, findings


def _url_analysis(url: str) -> dict[str, Any]:
    from detection.url_intel import analyze_url_intel

    return analyze_url_intel(url)


def _parse_headers(headers: dict[str, Any]) -> dict[str, str]:
    if not isinstance(headers, dict):
        raise ValueError("headers must be an object.")
    if len(headers) > 100:
        raise ValueError("headers may contain at most 100 entries.")
    return {str(key).strip().lower(): str(value)[:8192] for key, value in headers.items()}


def _zip_limit_error(data: bytes) -> str | None:
    tail = data[-(65_535 + 22):]
    offset = tail.rfind(b"PK\x05\x06")
    record = None
    while offset >= 0:
        if offset + 22 <= len(tail):
            try:
                record = struct.unpack_from("<4s4H2LH", tail, offset)
            except struct.error:
                record = None
            if record and offset + 22 + record[-1] == len(tail):
                break
        offset = tail.rfind(b"PK\x05\x06", 0, offset)
    if not record or offset < 0 or offset + 22 + record[-1] != len(tail):
        return "ZIP end-of-central-directory record is missing or malformed."
    _, disk_number, directory_disk, disk_entries, total_entries, directory_size, directory_offset, _ = record
    if disk_number or directory_disk or disk_entries != total_entries:
        return "Multi-disk ZIP archives are not supported."
    if total_entries == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF:
        return "ZIP64 archives are not supported by this bounded analyzer."
    if total_entries > MAX_ARCHIVE_ENTRIES:
        return f"Archive exceeds the {MAX_ARCHIVE_ENTRIES}-entry inspection limit."
    if directory_size > MAX_CENTRAL_DIRECTORY_BYTES:
        return "Archive central directory exceeds the 8 MiB inspection limit."
    if directory_offset + directory_size > len(data):
        return "Archive central directory points outside the supplied bytes."
    return None


def _dispatch(tool_id: str, data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[Any], str, dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    evidence: list[Any] = []
    status = "success"
    details: dict[str, Any] = {}

    if tool_id == "cyberscan.file.hash_analyzer":
        content = _bytes(data)
        details = {
            "file_name": data.get("file_name", "")[:255],
            "size_bytes": len(content),
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha512": hashlib.sha512(content).hexdigest(),
        }
        evidence.append({"sha256": details["sha256"], "size_bytes": len(content)})

    elif tool_id == "cyberscan.file.digital_signature_validator":
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        content = _bytes(data, "file_base64")
        signature = _decode(data["signature_base64"], "signature_base64")
        key = load_pem_public_key(data["public_key_pem"].encode("utf-8"))
        algorithm = data["algorithm"]
        try:
            if isinstance(key, rsa.RSAPublicKey) and algorithm == "rsa-pkcs1v15-sha256":
                key.verify(signature, content, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(key, ec.EllipticCurvePublicKey) and algorithm == "ecdsa-sha256":
                key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
            elif isinstance(key, ed25519.Ed25519PublicKey) and algorithm == "ed25519":
                key.verify(signature, content)
            else:
                raise ValueError("The selected algorithm does not match the supplied key type.")
            valid = True
        except InvalidSignature:
            valid = False
            findings.append(_finding("Detached signature is invalid", "high",
                                     "The supplied signature does not verify for the supplied file and public key."))
        details = {"signature_valid": valid, "algorithm": algorithm, "key_type": type(key).__name__,
                   "trust_chain_checked": False}
        evidence.append("Signature math was checked; certificate trust and signer identity are not checked.")

    elif tool_id == "cyberscan.file.type_mismatch_detector":
        from detection.engine import sniff_type

        name = data["file_name"][:255]
        content = _bytes(data)
        detected = sniff_type(content)
        extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        groups = {
            "pdf": {"pdf"}, "pe": {"exe", "dll", "sys", "scr"}, "elf": {"elf", "so"},
            "zip": {"zip", "docx", "xlsx", "pptx", "jar", "apk"},
            "image": {"png", "jpg", "jpeg", "gif", "bmp", "webp"},
        }
        expected = next((kind for kind, extensions in groups.items() if extension in extensions), None)
        mismatch = expected is not None and detected != expected
        details = {"file_name": name, "extension": extension, "detected_type": detected,
                   "expected_type_for_extension": expected, "mismatch": mismatch}
        if mismatch:
            findings.append(_finding("File extension and content disagree", "medium",
                                     f"The extension suggests {expected}, while the bytes resemble {detected}.", details))

    elif tool_id == "cyberscan.file.entropy_analyzer":
        content = _bytes(data)
        counts = [0] * 256
        for byte in content:
            counts[byte] += 1
        entropy = -sum((count / len(content)) * math.log2(count / len(content)) for count in counts if count)
        details = {"size_bytes": len(content), "shannon_entropy_bits_per_byte": round(entropy, 5),
                   "high_entropy": entropy >= 7.2}
        if entropy >= 7.2 and len(content) >= 1024:
            findings.append(_finding("High-entropy content", "low",
                                     "High entropy can result from compression or encryption; it is not proof of malware.",
                                     {"entropy": details["shannon_entropy_bits_per_byte"]}))

    elif tool_id in {"cyberscan.file.pe_structure_analyzer", "cyberscan.malware.executable_section_analyzer",
                     "cyberscan.malware.packer_indicator_detector"}:
        content = _bytes(data)
        try:
            import pefile
        except ImportError:
            report = _content_analysis(content, data.get("file_name", ""))
            findings, evidence = _translate_indicators(report)
            details = {"detected_type": report.get("sniffed_type"), "pefile_available": False}
            status = "partial" if report.get("sniffed_type") == "pe" else "success"
        else:
            try:
                pe = pefile.PE(data=content, fast_load=True)
            except pefile.PEFormatError as exc:
                if content[:2] == b"MZ":
                    findings.append(_finding("Malformed PE structure", "medium", "The PE parser rejected the executable structure."))
                    details = {"parse_error": str(exc)[:200], "sections": []}
                else:
                    details = {"detected_type": "not-pe", "sections": []}
            else:
                sections = []
                packer_hits = []
                for section in pe.sections[:96]:
                    name = section.Name.rstrip(b"\0").decode("ascii", "replace")
                    entropy = float(section.get_entropy())
                    item = {"name": name, "virtual_size": int(section.Misc_VirtualSize),
                            "raw_size": int(section.SizeOfRawData), "entropy": round(entropy, 5),
                            "executable": bool(section.Characteristics & 0x20000000),
                            "writable": bool(section.Characteristics & 0x80000000)}
                    sections.append(item)
                    if re.search(r"upx|aspack|packed|themida|vmp", name, re.I) or entropy >= 7.4:
                        packer_hits.append(item)
                details = {"machine": int(pe.FILE_HEADER.Machine), "section_count": len(sections),
                           "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "sections": sections,
                           "packer_indicators": packer_hits}
                if tool_id.endswith("packer_indicator_detector") and packer_hits:
                    findings.append(_finding("Possible packing indicators", "medium",
                                             "High section entropy or a packer-associated section name was observed.",
                                             packer_hits))
                if any(item["writable"] and item["executable"] for item in sections):
                    findings.append(_finding("Writable and executable section", "medium",
                                             "A PE section is both writable and executable."))
                if len(sections) > 0 and not details["entry_point"]:
                    findings.append(_finding("Zero PE entry point", "low", "The optional header has no entry point."))

    elif tool_id == "cyberscan.file.digital_certificate_inspector":
        details, findings = _inspect_certificate(_text(data, "certificate_pem", 100_000))
        evidence.append({"certificate_der_sha256": details["certificate_der_sha256"]})

    elif tool_id == "cyberscan.file.embedded_payload_detector":
        content = _bytes(data)
        report = _content_analysis(content, data.get("file_name", ""))
        report_findings, evidence = _translate_indicators(report)
        markers = [(b"MZ", "PE executable header"), (b"%PDF-", "PDF header"),
                   (b"PK\x03\x04", "ZIP local-file header")]
        embedded = []
        for marker, label in markers:
            offset = content.find(marker, 1)
            if offset >= 0:
                embedded.append({"offset": offset, "type": label})
        details = {"sniffed_type": report.get("sniffed_type"), "embedded_markers": embedded,
                   "bounded_analysis_findings": len(report_findings)}
        findings.extend(report_findings)
        if embedded:
            findings.append(_finding("Embedded file-like content", "medium",
                                     "A secondary file signature occurs inside the input; this is a heuristic, not extraction.",
                                     embedded))

    elif tool_id == "cyberscan.file.archive_security_analyzer":
        content = _bytes(data)
        limit_error = _zip_limit_error(content) if content.startswith(b"PK") else None
        archive = None
        if limit_error:
            status = "partial"
            details = {"archive_type": "zip", "parseable": False, "limit_rejection": limit_error}
            findings.append(_finding("Archive inspection limit reached", "medium", limit_error))
        else:
            try:
                archive = zipfile.ZipFile(BytesIO(content))
            except (zipfile.BadZipFile, OSError):
                pass
        if archive is None and not limit_error:
            report = _content_analysis(content, data.get("file_name", ""))
            details = {"archive_type": "unknown", "parseable": False}
            if content.startswith((b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c")):
                status = "partial"
                evidence.append("RAR/7z signature detected; this offline tool does not unpack that format.")
            else:
                status = "partial" if report.get("sniffed_type") == "zip" else "success"
                if report.get("sniffed_type") == "zip":
                    findings.append(_finding("Unreadable ZIP archive", "low", "The ZIP container could not be parsed."))
        elif archive is not None:
            infos = archive.infolist()
            total = sum(max(0, info.file_size) for info in infos)
            names = [info.filename for info in infos]
            risky_paths = [name for name in names if name.startswith(("/", "\\")) or
                           re.match(r"^[A-Za-z]:", name) or ".." in name.replace("\\", "/").split("/")]
            suspicious_exts = [name for name in names if re.search(r"\.(?:exe|dll|js|vbs|ps1|bat|cmd|scr|hta)$", name, re.I)]
            ratios = [info.file_size / max(1, info.compress_size) for info in infos]
            details = {"archive_type": "zip", "entry_count": len(archive.infolist()),
                       "listed_entry_count": len(infos), "total_uncompressed_bytes": total,
                       "encrypted_entry_count": sum(bool(info.flag_bits & 1) for info in infos),
                       "suspicious_paths": risky_paths[:50], "executable_or_script_entries": suspicious_exts[:50],
                       "maximum_compression_ratio": round(max(ratios, default=0), 2)}
            archive.close()
            if risky_paths:
                findings.append(_finding("Archive path traversal names", "high",
                                         "One or more member names escape a normal extraction directory.", risky_paths[:20]))
            if suspicious_exts:
                findings.append(_finding("Executable or script in archive", "medium",
                                         "The archive includes executable or script-like file names.", suspicious_exts[:20]))
            if total > 500 * 1024 * 1024 or details["maximum_compression_ratio"] > 1000:
                findings.append(_finding("Archive resource-exhaustion risk", "high",
                                         "Declared sizes or compression ratios exceed conservative limits."))

    elif tool_id == "cyberscan.file.macro_security_analyzer":
        content = _bytes(data)
        limit_error = _zip_limit_error(content) if content.startswith(b"PK") else None
        try:
            if limit_error:
                names = []
                status = "partial"
            else:
                with zipfile.ZipFile(BytesIO(content)) as archive:
                    names = archive.namelist()
        except (zipfile.BadZipFile, OSError):
            names = []
        macro_files = [name for name in names if re.search(r"vbaproject\.bin|vbaData\.xml|macrosheets/", name, re.I)]
        report = {"sniffed_type": "zip", "indicators": []} if limit_error else _content_analysis(
            content, data.get("file_name", "")
        )
        report_findings, evidence = _translate_indicators(report)
        details = {"container_type": report.get("sniffed_type"), "macro_related_entries": macro_files[:50]}
        if limit_error:
            details["limit_rejection"] = limit_error
        findings.extend(report_findings)
        if macro_files:
            findings.append(_finding("Macro-related content found", "medium",
                                     "Macro-related parts are present; their code was not executed.", macro_files[:20]))

    elif tool_id == "cyberscan.file.pdf_active_content_analyzer":
        content = _bytes(data)
        if not content.startswith(b"%PDF-"):
            status = "partial"
            findings.append(_finding("Input is not identified as PDF", "info", "PDF token checks were applied to non-PDF bytes."))
        tokens = [token.decode("ascii") for token in
                  (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/RichMedia")
                  if token in content]
        details = {"pdf_signature": content.startswith(b"%PDF-"), "active_content_tokens": tokens}
        if tokens:
            findings.append(_finding("PDF active-content indicators", "medium",
                                     "The document contains active-content markers; no PDF action was executed.", tokens))

    elif tool_id == "cyberscan.malware.yara_rule_scanner":
        content = _bytes(data)
        rules = _text(data, "rules", 100_000)
        try:
            import yara
        except ImportError:
            status = "partial"
            findings.append(_finding("YARA dependency unavailable", "info",
                                     "The YARA Python module is not installed; no YARA matching was performed."))
            details = {"matches": [], "scanner_available": False}
        else:
            try:
                compiled = yara.compile(source=rules)
                matches = compiled.match(data=content, timeout=5)
            except (yara.Error, TimeoutError, ValueError) as exc:
                raise ValueError(f"YARA rules could not be compiled or matched: {type(exc).__name__}.") from exc
            details = {"matches": [str(match) for match in matches[:100]], "scanner_available": True}
            for name in details["matches"]:
                findings.append(_finding("YARA rule matched", "medium", "A supplied local YARA rule matched.", name))

    elif tool_id == "cyberscan.malware.suspicious_api_detector":
        content = _bytes(data)
        strings = [item.decode("ascii", "ignore") for item in re.findall(rb"[\x20-\x7e]{4,}", content)]
        known = ("VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx",
                 "URLDownloadToFile", "WinExec", "ShellExecute", "NtUnmapViewOfSection")
        hits = sorted({api for api in known if any(api.lower() in text.lower() for text in strings)})
        details = {"matched_api_names": hits, "note": "String presence does not establish that an API is called."}
        if hits:
            findings.append(_finding("Suspicious API names in file", "low",
                                     "Potentially sensitive API names occur in printable strings.", hits))

    elif tool_id == "cyberscan.malware.script_obfuscation_detector":
        text = _text(data, "script", 200_000)
        rules = [
            ("Encoded PowerShell command", r"(?i)\b(?:powershell|pwsh)\b.{0,80}(?:-enc(?:odedcommand)?\s+|frombase64string)"),
            ("Dynamic code evaluation", r"(?i)\b(?:eval|exec|invoke-expression|iex)\s*\("),
            ("Long encoded string", r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/])"),
            ("Character-code construction", r"(?i)(?:chr|char)\s*\(\s*\d{2,3}\s*\)"),
        ]
        hits = [label for label, pattern in rules if re.search(pattern, text)]
        details = {"indicators": hits, "analyzed_characters": len(text)}
        for label in hits:
            findings.append(_finding(label, "medium", "A common obfuscation pattern was found; context is required."))
        if not text.strip():
            status = "partial"
            findings.append(_finding("Empty script input", "info", "No script content was supplied for analysis."))

    elif tool_id == "cyberscan.malware.malware_indicator_analyzer":
        content = _bytes(data)
        report = _content_analysis(content, data.get("file_name", ""))
        findings, evidence = _translate_indicators(report)
        details = {"detected_type": report.get("sniffed_type"), "analyzer_errors": report.get("analyzer_errors", []),
                   "truncated_input": report.get("truncated_input", False), "_risk_score": report.get("score", 0)}
        if details["analyzer_errors"] or details["truncated_input"]:
            status = "partial"

    elif tool_id == "cyberscan.malware.persistence_indicator_detector":
        text = _text(data, "content")
        patterns = {
            "Windows Run key": r"(?i)\\software\\microsoft\\windows\\currentversion\\run",
            "Scheduled task command": r"(?i)\bschtasks(?:\.exe)?\b.{0,120}/create",
            "Systemd persistence path": r"(?i)/(?:etc/systemd/system|\.config/systemd/user)/[^ \r\n]+",
            "Startup folder path": r"(?i)\\startup\\",
            "Launch agent or daemon path": r"(?i)/library/launch(?:agents|daemons)/",
        }
        hits = [label for label, pattern in patterns.items() if re.search(pattern, text)]
        details = {"indicators": hits}
        for label in hits:
            findings.append(_finding(label, "medium", "Text refers to a common persistence location or mechanism."))

    elif tool_id == "cyberscan.malware.ransomware_indicator_detector":
        text = _text(data, "content")
        patterns = {
            "Shadow-copy deletion command": r"(?i)\bvssadmin\b.{0,100}\bdelete\s+shadows",
            "Backup catalog deletion": r"(?i)\bwbadmin\b.{0,100}\bdelete\s+catalog",
            "Ransom note language": r"(?i)(your files (?:are|have been) encrypted|decrypt your files|pay.{0,40}(?:bitcoin|btc|ransom))",
            "Bulk file encryption API": r"(?i)\b(?:CryptEncrypt|BCryptEncrypt)\b",
        }
        hits = [label for label, pattern in patterns.items() if re.search(pattern, text)]
        details = {"indicators": hits, "note": "Static text matches do not prove ransomware activity."}
        for label in hits:
            findings.append(_finding(label, "high" if "deletion" in label.lower() else "medium",
                                     "A ransomware-associated string pattern was found."))

    elif tool_id == "cyberscan.malware.shellcode_pattern_detector":
        content = _bytes(data)
        nop_sled = re.search(rb"\x90{16,}", content) is not None
        patterns = {"x86/x64 syscall sequence": b"\x0f\x05", "int 0x80 instruction": b"\xcd\x80",
                    "call-pop position-independent pattern": b"\xe8\x00\x00\x00\x00\x5b"}
        hits = [name for name, sequence in patterns.items() if sequence in content]
        if nop_sled:
            hits.append("Long NOP sled")
        details = {"matched_patterns": hits, "size_bytes": len(content)}
        for label in hits:
            findings.append(_finding(label, "low", "A byte pattern associated with shellcode was found; it may be benign."))

    elif tool_id == "cyberscan.malware.malware_similarity_analyzer":
        left, right = _bytes(data, "left_base64"), _bytes(data, "right_base64")
        def shingles(blob: bytes) -> set[bytes]:
            window = 16
            if len(blob) < window:
                return {blob}
            return {hashlib.sha256(blob[index:index + window]).digest()[:8]
                    for index in range(0, min(len(blob) - window + 1, 200_000), 8)}
        left_shingles, right_shingles = shingles(left), shingles(right)
        union = left_shingles | right_shingles
        similarity = len(left_shingles & right_shingles) / len(union) if union else 1.0
        details = {"left_sha256": hashlib.sha256(left).hexdigest(), "right_sha256": hashlib.sha256(right).hexdigest(),
                   "exact_match": left == right, "sampled_16_byte_shingle_jaccard": round(similarity, 5),
                   "method": "sampled byte shingles; not a malware-family attribution"}
        if similarity >= 0.8:
            findings.append(_finding("High byte-shingle similarity", "info",
                                     "The inputs share many sampled byte windows; this is not attribution.",
                                     {"similarity": details["sampled_16_byte_shingle_jaccard"]}))

    elif tool_id in {"cyberscan.url.url_reputation_analyzer", "cyberscan.url.phishing_url_detector",
                     "cyberscan.url.domain_reputation_analyzer", "cyberscan.url.homograph_attack_detector"}:
        is_domain = tool_id.endswith("domain_reputation_analyzer")
        value = _text(data, "domain" if is_domain else "url", 2048)
        analyzed = "http://" + value if is_domain and "://" not in value else value
        report = _url_analysis(analyzed)
        findings = [dict(item) for item in report.get("findings", [])]
        evidence = [{"url": report.get("url"), "host": report.get("host"),
                     "registrable_domain": report.get("registrable_domain"),
                     "source": "CyberScan offline URL heuristics; no reputation service queried"}]
        if tool_id.endswith("homograph_attack_detector"):
            unicode_host = report.get("unicode_host")
            ascii_host = report.get("host")
            if unicode_host and ascii_host and unicode_host.lower() != ascii_host.lower():
                findings.append(_finding("Internationalized hostname", "low",
                                         "The hostname has an internationalized form; compare its script and intended brand.",
                                         {"unicode_host": unicode_host, "ascii_host": ascii_host}))
        details = {"url_analysis": {key: value for key, value in report.items()
                                    if key not in {"findings", "indicators"}},
                   "reputation_data_source": "none", "_risk_score": report.get("score", 0)}
        if tool_id.endswith("url_reputation_analyzer") or is_domain:
            details["reputation"] = "unavailable"
            status = "partial"
        if tool_id.endswith("phishing_url_detector"):
            findings = [item for item in findings if item.get("severity") not in {"info", "informational"}]
            status = "partial" if not findings else "success"

    elif tool_id == "cyberscan.url.redirect_chain_analyzer":
        urls = data["redirects"]
        analyzed = []
        for url in urls[:20]:
            report = _url_analysis(url)
            analyzed.append({"url": url[:2048], "host": report.get("host"), "score": report.get("score"),
                             "classification": report.get("classification")})
            for item in report.get("findings", []):
                findings.append(_finding(item.get("label", "URL indicator"), item.get("severity", "low"),
                                         item.get("explanation", ""), url[:300]))
        details = {"observed_hops": analyzed, "hops_analyzed": len(analyzed),
                   "network_following_performed": False}
        if not urls:
            status = "partial"
            evidence.append("No observed redirect hops supplied; this tool does not make HTTP requests.")

    elif tool_id == "cyberscan.url.url_shortener_analyzer":
        url = _text(data, "url", 2048)
        host = (urlsplit(url if "://" in url else "//" + url).hostname or "").lower().rstrip(".")
        shorteners = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
                      "rebrand.ly", "shorturl.at", "goo.gl", "tiny.cc", "rb.gy"}
        match = any(host == item or host.endswith("." + item) for item in shorteners)
        details = {"host": host, "known_shortener": match, "redirect_resolved": False}
        if match:
            findings.append(_finding("Known URL shortener", "low",
                                     "The destination is hidden behind a recognized shortener; no redirect was followed.", host))

    elif tool_id == "cyberscan.url.dns_record_analyzer":
        domain, records = _text(data, "domain", 253), data["records"]
        normalized = [str(item)[:4096] for item in records[:100]]
        record_types = {kind: sum(item.upper().startswith(kind) for item in normalized)
                        for kind in ("A ", "AAAA ", "MX ", "NS ", "TXT ", "CNAME ")}
        txt_records = [item for item in normalized if item.upper().startswith("TXT ")]
        details = {"domain": domain, "provided_record_count": len(normalized),
                   "record_type_counts": record_types, "spf_records": [item for item in txt_records if "v=spf1" in item.lower()],
                   "dns_queried": False}
        if not normalized:
            status = "partial"
            evidence.append("No DNS records supplied; the tool performs no DNS lookup.")
        if len(details["spf_records"]) > 1:
            findings.append(_finding("Multiple SPF records supplied", "medium",
                                     "A domain should publish at most one SPF record."))

    elif tool_id == "cyberscan.url.ssl_certificate_inspector":
        details, findings = _inspect_certificate(_text(data, "certificate_pem", 100_000))
        details["live_tls_connection_performed"] = False

    elif tool_id == "cyberscan.url.domain_expiration_checker":
        value = _text(data, "expires_at", 100)
        try:
            expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expires_at must be an ISO-8601 timestamp.") from exc
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        days = (expires.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds() / 86400
        details = {"domain": data.get("domain"), "expires_at": expires.isoformat(),
                   "days_until_expiration": round(days, 2), "registry_queried": False}
        if days < 0:
            findings.append(_finding("Domain expiration date has passed", "high",
                                     "The supplied expiration timestamp is in the past."))
        elif days < 30:
            findings.append(_finding("Domain expires soon", "medium",
                                     "The supplied expiration timestamp is within 30 days."))
        if not data.get("domain_expiration_source"):
            status = "partial"
            evidence.append("Expiration was evaluated from user-supplied data; no registrar query was made.")

    elif tool_id == "cyberscan.url.suspicious_subdomain_detector":
        host = _text(data, "domain", 253).lower().rstrip(".")
        parts = [part for part in host.split(".") if part]
        suspicious = [part for part in parts[:-2] if re.search(r"login|verify|secure|account|payment|support|update|auth", part)]
        details = {"host": host, "subdomain_labels": parts[:-2], "suspicious_labels": suspicious}
        if suspicious:
            findings.append(_finding("Potentially deceptive subdomain labels", "low",
                                     "A subdomain contains terms often used in lures; review the registered domain.", suspicious))

    elif tool_id == "cyberscan.website.http_security_headers_analyzer":
        headers = _parse_headers(data["headers"])
        checks = {"strict-transport-security": "HSTS", "content-security-policy": "CSP",
                  "x-content-type-options": "X-Content-Type-Options",
                  "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy"}
        missing = [label for name, label in checks.items() if not headers.get(name)]
        details = {"present_headers": [name for name in checks if headers.get(name)],
                   "missing_headers": missing, "live_http_request_performed": False}
        for label in missing:
            findings.append(_finding(f"Missing {label}", "low", f"The supplied response headers omit {label}."))

    elif tool_id == "cyberscan.website.csp_analyzer":
        csp = _text(data, "content_security_policy", 8192)
        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            tokens = part.strip().split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]
        weak = []
        for name, values in directives.items():
            if "*" in values:
                weak.append((name, "wildcard source"))
            if "'unsafe-inline'" in values:
                weak.append((name, "unsafe-inline"))
            if "'unsafe-eval'" in values:
                weak.append((name, "unsafe-eval"))
        details = {"directives": directives, "weak_directives": weak,
                   "default_src_present": "default-src" in directives}
        if "default-src" not in directives:
            findings.append(_finding("Missing default-src", "low", "The policy has no default-src fallback."))
        for directive, issue in weak:
            findings.append(_finding(f"CSP {issue}", "medium", f"{directive} permits {issue}."))

    elif tool_id == "cyberscan.website.cors_configuration_analyzer":
        headers = _parse_headers(data["headers"])
        origin = headers.get("access-control-allow-origin", "")
        credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        details = {"allow_origin": origin, "allow_credentials": credentials,
                   "wildcard_origin": origin == "*"}
        if origin == "*" and credentials:
            findings.append(_finding("Wildcard CORS with credentials", "high",
                                     "The supplied response allows all origins and credentials."))
        elif origin == "*":
            findings.append(_finding("Wildcard CORS origin", "low", "The supplied response allows any origin."))

    elif tool_id == "cyberscan.website.cookie_security_analyzer":
        cookies = data["set_cookie"]
        parsed = []
        for cookie in cookies[:100]:
            parts = [part.strip() for part in str(cookie)[:8192].split(";")]
            attrs = {part.split("=", 1)[0].lower(): part.split("=", 1)[1] if "=" in part else True
                     for part in parts[1:]}
            name = parts[0].split("=", 1)[0] if parts else ""
            parsed.append({"name": name, "secure": "secure" in attrs,
                           "httponly": "httponly" in attrs, "samesite": attrs.get("samesite"),
                           "domain": attrs.get("domain"), "path": attrs.get("path")})
            if "secure" not in attrs:
                findings.append(_finding("Cookie lacks Secure", "low", f"Cookie {name!r} lacks Secure."))
            if "httponly" not in attrs:
                findings.append(_finding("Cookie lacks HttpOnly", "low", f"Cookie {name!r} lacks HttpOnly."))
            if "samesite" not in attrs:
                findings.append(_finding("Cookie lacks SameSite", "low", f"Cookie {name!r} has no SameSite attribute."))
        details = {"cookies": parsed}

    elif tool_id == "cyberscan.website.https_configuration_checker":
        url = _text(data, "url", 2048)
        scheme = urlsplit(url if "://" in url else "//" + url).scheme.lower()
        hsts = data.get("hsts_header", "")
        details = {"scheme": scheme or "relative", "uses_https": scheme == "https",
                   "hsts_header_present": bool(hsts), "live_connection_performed": False}
        if scheme != "https":
            findings.append(_finding("URL does not use HTTPS", "medium",
                                     "Only the supplied URL scheme was checked; no connection was made."))
        if scheme == "https" and not hsts:
            findings.append(_finding("HSTS header not supplied", "low",
                                     "No HSTS header was provided for evaluation."))

    elif tool_id == "cyberscan.website.mixed_content_detector":
        markup = _text(data, "html", 500_000)
        matches = re.findall(r"""(?is)(?:src|href|action)\s*=\s*['"]\s*(http://[^'"]+)""", html.unescape(markup))
        details = {"http_resource_urls": matches[:100], "count": len(matches)}
        if matches:
            findings.append(_finding("Potential mixed content", "medium",
                                     "The supplied markup references HTTP resources.", matches[:20]))

    elif tool_id == "cyberscan.website.tls_configuration_analyzer":
        version = _text(data, "tls_version", 100).upper()
        cipher = _text(data, "cipher", 200).upper()
        weak_version = version in {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1"}
        weak_cipher = any(item in cipher for item in ("RC4", "3DES", "NULL", "EXPORT", "MD5", "DES-CBC"))
        details = {"supplied_tls_version": version, "supplied_cipher": cipher,
                   "live_handshake_performed": False}
        if weak_version:
            findings.append(_finding("Legacy TLS protocol", "high", f"The supplied protocol is {version}."))
        if weak_cipher:
            findings.append(_finding("Weak TLS cipher indicator", "medium", "The supplied cipher name contains a weak algorithm marker."))

    elif tool_id == "cyberscan.website.security_txt_validator":
        text = _text(data, "security_txt", 20_000)
        fields: dict[str, list[str]] = {}
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if ":" not in line:
                findings.append(_finding("Malformed security.txt line", "low", "A non-comment line has no field separator.", line[:200]))
                continue
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
        if not fields.get("contact"):
            findings.append(_finding("Missing Contact field", "medium", "security.txt should provide a Contact field."))
        expiries = fields.get("expires", [])
        if not expiries:
            findings.append(_finding("Missing Expires field", "low", "security.txt should provide an Expires field."))
        else:
            try:
                expires = datetime.fromisoformat(expiries[0].replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires < datetime.now(timezone.utc):
                    findings.append(_finding("Expired security.txt", "medium", "The supplied Expires date has passed."))
            except ValueError:
                findings.append(_finding("Invalid Expires value", "low", "Expires is not a valid ISO-8601 timestamp."))
        details = {"fields": fields}

    elif tool_id == "cyberscan.website.server_configuration_analyzer":
        headers = _parse_headers(data["headers"])
        exposed = {key: headers[key] for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator") if headers.get(key)}
        details = {"exposed_technology_headers": exposed}
        for name, value in exposed.items():
            findings.append(_finding("Technology header disclosed", "low",
                                     f"{name} exposes server or framework information.", value[:300]))
        if headers.get("server", "").lower().startswith(("apache/2.2", "nginx/1.", "microsoft-iis/6")):
            findings.append(_finding("Potentially outdated server banner", "medium",
                                     "The supplied banner resembles a legacy server version."))

    elif tool_id == "cyberscan.website.technology_fingerprinter":
        headers = _parse_headers(data.get("headers", {}))
        markup = _text(data, "html", 200_000).lower()
        signatures = {
            "WordPress": ("wp-content", "wp-includes"),
            "Drupal": ("drupal.settings", "sites/default/files"),
            "React": ("react-dom", "__react"),
            "Next.js": ("__next_data__", "/_next/static"),
            "Vue.js": ("__vue__", "vue.runtime"),
            " jQuery": ("jquery-", "jquery.min.js"),
        }
        found = [name.strip() for name, needles in signatures.items() if any(item in markup for item in needles)]
        if "x-powered-by" in headers:
            found.append(headers["x-powered-by"][:100])
        details = {"passive_fingerprints": sorted(set(found)), "network_requests_performed": False}
        evidence.extend(found)

    elif tool_id == "cyberscan.email.email_header_analyzer":
        raw = _text(data, "message", 200_000)
        parsed = Parser(policy=policy.default).parsestr(raw, headersonly=True)
        header_names = ("from", "to", "reply-to", "return-path", "subject", "date",
                        "message-id", "received", "authentication-results", "received-spf", "dkim-signature")
        headers = {name: [str(value)[:2048] for value in parsed.get_all(name, [])[:20]]
                   for name in header_names if parsed.get_all(name)}
        from_address = parseaddr(parsed.get("from", ""))[1]
        return_path = parseaddr(parsed.get("return-path", ""))[1]
        details = {"headers": headers, "from_address": from_address, "return_path": return_path,
                   "from_return_path_domain_match": (from_address.rsplit("@", 1)[-1].lower() ==
                                                     return_path.rsplit("@", 1)[-1].lower())
                   if "@" in from_address and "@" in return_path else None}
        if details["from_return_path_domain_match"] is False:
            findings.append(_finding("From and Return-Path domains differ", "low",
                                     "A mismatch may be legitimate but warrants context review."))

    elif tool_id == "cyberscan.email.spf_validator":
        record = _text(data, "spf_record", 4096).strip()
        tokens = record.split()
        valid = bool(tokens and tokens[0].lower() == "v=spf1")
        if not valid:
            findings.append(_finding("Invalid SPF version prefix", "high", "An SPF record must start with v=spf1."))
        mechanisms = tokens[1:] if valid else []
        lookups = sum(1 for token in mechanisms if re.match(r"(?i)^(include:|a(?::|$)|mx(?::|$)|ptr(?::|$)|exists:|redirect=)", token))
        all_positions = [index for index, token in enumerate(mechanisms) if token.lower().endswith("all")]
        if len(all_positions) > 1:
            findings.append(_finding("Multiple SPF all mechanisms", "medium", "The record contains more than one all mechanism."))
        if all_positions and all_positions[0] != len(mechanisms) - 1:
            findings.append(_finding("SPF all mechanism is not last", "low", "Terms after all are generally ineffective."))
        if lookups > 10:
            findings.append(_finding("SPF DNS lookup limit exceeded", "high", f"The record has {lookups} counted DNS-lookup mechanisms."))
        details = {"syntax_prefix_valid": valid, "mechanisms": mechanisms,
                   "counted_dns_lookups": lookups, "dns_evaluation_performed": False}
        status = "partial"
        evidence.append("Syntax-only check; DNS mechanisms and the sender IP were not evaluated.")

    elif tool_id == "cyberscan.email.dkim_validator":
        signature = _text(data, "dkim_signature", 8192)
        key_record = _text(data, "public_key_record", 8192)
        tags = {}
        for item in signature.split(";"):
            if "=" in item:
                key, value = item.split("=", 1)
                tags[key.strip().lower()] = value.strip()
        required = {"v", "a", "b", "bh", "d", "h", "s"}
        missing = sorted(required - tags.keys())
        if missing:
            findings.append(_finding("Incomplete DKIM-Signature header", "medium",
                                     "Required signature tags are missing.", missing))
        if "v=DKIM1" not in key_record.upper():
            findings.append(_finding("Invalid DKIM key version", "medium", "The supplied key record lacks v=DKIM1."))
        details = {"signature_tags": tags, "missing_signature_tags": missing,
                   "key_record_provided": bool(key_record), "cryptographic_signature_verified": False}
        status = "partial"
        evidence.append("The tool validates supplied DKIM metadata only; it does not fetch DNS records or verify canonicalized message bytes.")

    elif tool_id == "cyberscan.email.dmarc_validator":
        record = _text(data, "dmarc_record", 4096).strip()
        tags = {}
        for item in record.split(";"):
            if "=" in item:
                key, value = item.split("=", 1)
                tags[key.strip().lower()] = value.strip()
        valid = record.lower().startswith("v=dmarc1") and tags.get("p", "").lower() in {"none", "quarantine", "reject"}
        if not valid:
            findings.append(_finding("Invalid or incomplete DMARC record", "medium",
                                     "A DMARC record must include v=DMARC1 and a valid p policy."))
        pct = tags.get("pct")
        if pct and (not pct.isdigit() or int(pct) > 100):
            findings.append(_finding("Invalid DMARC pct value", "low", "pct must be an integer from 0 to 100."))
        details = {"tags": tags, "syntax_valid": valid, "dns_queried": False}
        status = "partial"
        evidence.append("The supplied record was checked; no DNS lookup or policy enforcement evaluation was performed.")

    elif tool_id == "cyberscan.email.email_spoofing_detector":
        message = _text(data, "message", 200_000)
        from detection.messages import analyze_message

        report = analyze_message(message)
        findings, evidence = _translate_indicators(report)
        details = {"authentication_failures": report.get("email_headers", {}).get("authentication_failures", []),
                   "header_analysis": report.get("email_headers", {}), "_risk_score": report.get("score", 0)}
        if not report.get("is_email"):
            status = "partial"
            evidence.append("Input did not contain recognizable email headers.")

    elif tool_id == "cyberscan.email.sender_identity_analyzer":
        message = Parser(policy=policy.default).parsestr(_text(data, "message", 200_000), headersonly=True)
        display, address = parseaddr(message.get("from", ""))
        domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
        reply_to = parseaddr(message.get("reply-to", ""))[1]
        reply_domain = reply_to.rsplit("@", 1)[-1].lower() if "@" in reply_to else ""
        details = {"display_name": display, "address": address, "domain": domain,
                   "reply_to": reply_to, "reply_to_domain": reply_domain,
                   "from_reply_domain_match": domain == reply_domain if domain and reply_domain else None}
        if domain and reply_domain and domain != reply_domain:
            findings.append(_finding("Reply-To domain differs from From", "medium",
                                     "A different reply domain may redirect responses."))

    elif tool_id == "cyberscan.email.email_phishing_detector":
        from detection.messages import analyze_message

        report = analyze_message(_text(data, "message", 200_000))
        findings, evidence = _translate_indicators(report)
        details = {"is_email": report.get("is_email"), "links": report.get("links", [])[:20],
                   "score": report.get("score"), "classification": report.get("classification"),
                   "_risk_score": report.get("score", 0)}
        if not report.get("is_email"):
            status = "partial"

    elif tool_id == "cyberscan.email.email_url_extractor":
        from detection.messages import extract_urls

        message = _text(data, "message", 200_000)
        urls = extract_urls(message, limit=100)
        analyzed = []
        for url in urls:
            report = _url_analysis(url)
            analyzed.append({"url": url[:500], "host": report.get("host"),
                             "score": report.get("score"), "classification": report.get("classification")})
        details = {"urls": analyzed, "count": len(analyzed),
                   "_risk_score": max((item["score"] or 0 for item in analyzed), default=0)}
        evidence.extend(analyzed)

    elif tool_id == "cyberscan.email.email_attachment_risk_analyzer":
        attachments = data["attachments"]
        inspected = []
        risky = re.compile(r"\.(?:exe|dll|scr|js|jse|vbs|vbe|bat|cmd|ps1|hta|lnk|iso|img|docm|xlsm|pptm|jar)$", re.I)
        for item in attachments[:100]:
            name = str(item.get("file_name", ""))[:255]
            extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            double_extension = bool(re.search(r"\.(?:pdf|docx|xlsx|jpg|png)\.(?:exe|scr|js|vbs|hta|bat)$", name, re.I))
            entry = {"file_name": name, "extension": extension,
                     "declared_content_type": str(item.get("content_type", ""))[:150],
                     "risky_extension": bool(risky.search(name)), "double_extension": double_extension}
            inspected.append(entry)
            if entry["risky_extension"] or double_extension:
                findings.append(_finding("Risky email attachment name", "medium",
                                         "The filename has a script/executable extension or misleading double extension.", entry))
        details = {"attachments": inspected}

    elif tool_id == "cyberscan.email.display_name_impersonation_detector":
        message = Parser(policy=policy.default).parsestr(_text(data, "message", 200_000), headersonly=True)
        display, address = parseaddr(message.get("from", ""))
        domain = address.rsplit("@", 1)[-1].lower()
        brands = [str(item).strip().lower() for item in data["brands"][:50] if str(item).strip()]
        matching = [brand for brand in brands if brand in display.lower() and domain and
                    not domain == brand and not domain.startswith(brand + ".") and not domain.endswith("." + brand)]
        details = {"display_name": display, "sender_domain": domain, "matched_brands": matching}
        for brand in matching:
            findings.append(_finding("Brand in display name with unrelated domain", "medium",
                                     f"The display name includes {brand!r}, but the sender domain does not match it."))

    else:
        raise ValueError(f"Unknown tool implementation: {tool_id}")

    return findings, evidence, status, details


def run_tool(
    tool_id: str,
    input_data: dict[str, Any],
    options: dict[str, Any] | None = None,
    *,
    version: str = "1.0.0",
    source: str = "CyberScan local implementation",
    license_info: str = LICENSE_NOTICE,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Run a bounded analysis and return the common JSON result envelope."""
    del options
    started = time.perf_counter()
    try:
        findings, evidence, status, details = _dispatch(tool_id, input_data)
        return _result(tool_id, findings, evidence, started, status=status, details=details,
                       version=version, source=source, license_info=license_info,
                       timeout_seconds=timeout_seconds)
    except (ValueError, KeyError, TypeError, ImportError) as exc:
        return _result(
            tool_id,
            [_finding("Analysis could not be completed", "info", f"{type(exc).__name__}: {str(exc)[:240]}")],
            [],
            started,
            status="error",
            classification="unknown",
            details={"error_type": type(exc).__name__},
            version=version,
            source=source,
            license_info=license_info,
            timeout_seconds=timeout_seconds,
        )
