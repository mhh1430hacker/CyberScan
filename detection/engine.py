"""Unified content inspection and the web-facing entry points.

``inspect_content``  — bytes in, structured evidence out (used by ``core.file_analyzer``).
``analyze_upload``   — raw upload bytes + client file name in, JSON-serialisable scan result out.
``analyze_text_json``— URL / message / hash string in, JSON-serialisable scan result out.

File type is decided from content (magic bytes), never from the client-supplied extension.
"""
from __future__ import annotations

import dataclasses
import os
import re
import shutil
import tempfile
import unicodedata
import zipfile
from typing import Any

from detection.archives import classify_zip, inspect_apk, inspect_archive, inspect_browser_extension, open_zip
from detection.common import MAX_DEEP_SCAN_BYTES, Indicator, fuse, heuristic_dicts
from detection.documents import inspect_ole, inspect_ooxml, inspect_pdf, inspect_rtf
from detection.executables import inspect_elf, inspect_pe
from detection.messages import _looks_like_email, analyze_message
from detection.script_rules import scan_command_text
from detection.secrets import scan_secrets

CONTAINER_TYPES = {"pdf", "ole", "rtf", "zip", "pe", "elf"}


def sniff_type(data: bytes) -> str:
    head = data[:1024]
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"Cr24")):
        return "zip"
    if b"%PDF-" in head:
        return "pdf"
    if head.lstrip()[:4].lower() == b"{\\rt":
        return "rtf"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM", b"II*\x00", b"MM\x00*")) or (
            head.startswith(b"RIFF") and head[8:12] == b"WEBP"):
        return "image"
    sample = data[:8192]
    if not sample:
        return "empty"
    if b"\x00" in sample and not (sample.startswith((b"\xff\xfe", b"\xfe\xff"))):
        return "binary"
    printable = sum(1 for byte in sample if byte >= 0x20 or byte in (9, 10, 13))
    return "text" if printable / len(sample) > 0.9 else "binary"


def needs_full_read(data: bytes) -> bool:
    """Containers keep their directory at the end (ZIP) or anywhere (PDF), so the head is not enough."""
    return sniff_type(data) in CONTAINER_TYPES


def _decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _container_details(archive: zipfile.ZipFile, add, file_name: str, depth: int = 0) -> dict[str, Any]:
    kind = classify_zip(archive)
    if kind == "ooxml":
        return inspect_ooxml(archive, add, file_name=file_name)
    if kind in {"apk", "browser-extension"}:
        # Apps and extensions consist of code by design: keep only dangerous-structure findings from the
        # generic archive pass (bombs, Zip Slip, disguised names, script tradecraft), not "contains scripts".
        def structural_only(severity, label, contribution, explanation, **extra):
            if label not in {"Archive contains executable or script files", "Encrypted archive entries"}:
                add(severity, label, contribution, explanation, **extra)

        specific = inspect_apk(archive, add) if kind == "apk" else inspect_browser_extension(archive, add)
        specific["archive"] = inspect_archive(archive, structural_only, depth=depth)
        return specific
    return inspect_archive(archive, add, depth=depth)


def _inspect_qr(data: bytes, file_name: str, add) -> dict[str, Any]:
    """Adapter for Guardian's ``core.qr_scanner`` (contract agreed in collaboration/DISCUSSION.md).

    The decoder runs in its own process with size, pixel and time limits. Decoded URLs are already
    scored by ``url_intel``; non-URL payloads (SMS/e-mail QR codes) go through message analysis.
    Any decoder failure degrades to a status, never an exception.
    """
    try:
        from core.qr_scanner import analyze_qr_image
        report = analyze_qr_image(data, file_name)
    except ImportError:
        return {"status": "decoder_unavailable", "codes": [], "limitations": ["QR decoder module is not installed."]}
    except (ValueError, TypeError) as exc:
        return {"status": "not_decodable", "codes": [], "limitations": [str(exc)[:200]]}

    for code in report.get("codes", [])[:10]:
        risk = code.get("risk") or {}
        if code.get("kind") == "url" and risk.get("score", 0) > 0:
            score = int(risk["score"])
            add("high" if score >= 50 else "medium" if score >= 25 else "low", "Suspicious link in QR code",
                min(70, score),
                f"A QR code in the image opens '{str(code.get('payload'))[:100]}' "
                f"({'; '.join(item['label'] for item in risk.get('findings', [])[:3])}). "
                "QR phishing ('quishing') hides links from mail filters and from the reader.",
                category="phishing", url=str(code.get("payload"))[:500])
        elif code.get("kind") == "text" and code.get("payload"):
            message = analyze_message(str(code["payload"]))
            for item in message["indicators"]:
                add(item.severity, f"{item.label} (QR code)", item.contribution, item.explanation, category=item.category)
    return report


def inspect_content(data: bytes, file_name: str = "", *, total_size: int | None = None,
                    path: str | None = None) -> dict[str, Any]:
    """Inspect file bytes and return evidence. Never raises for malformed input.

    ``path`` lets ZIP containers larger than the read window be opened by seeking (the central
    directory is at the end of the file); the file is still only read, never extracted."""
    indicators: list[Indicator] = []

    def add(severity: str, label: str, contribution: int, explanation: str, category: str = "content", **extra: Any) -> None:
        # The same label once; and a whole-file match is not counted again when it was already found
        # inside one of the container's members ("Shadow copy deletion (in run.bat)").
        if any(item.label == label or item.label.startswith(label + " (in ") for item in indicators):
            return
        indicators.append(Indicator(category, severity, label, explanation, int(contribution), extra))

    kind = sniff_type(data)
    details: dict[str, Any] = {}
    errors: list[str] = []
    truncated = total_size is not None and total_size > len(data)
    try:
        if kind == "pdf":
            details = inspect_pdf(data, add, truncated=truncated)
        elif kind == "ole":
            details = inspect_ole(data, add, file_name=file_name)
        elif kind == "rtf":
            details = inspect_rtf(data, add)
        elif kind == "zip":
            archive = open_zip(data)
            if archive is None and truncated and path:
                try:
                    archive = zipfile.ZipFile(path)
                except Exception:
                    archive = None
            if archive is None:
                add("low", "Unreadable ZIP container", 10, "The ZIP directory could not be read; the file is damaged or deliberately malformed.")
            else:
                details = _container_details(archive, add, file_name)
        elif kind == "pe":
            details = inspect_pe(data, add, file_size=total_size or len(data))
        elif kind == "elf":
            details = inspect_elf(data, add)
        elif kind == "image" and not truncated:
            details = {"type": "image", "qr_codes": _inspect_qr(data, file_name, add)}
    except Exception as exc:  # a bug in one analyzer must not hide the others' evidence
        errors.append(f"{kind} analyzer failed: {type(exc).__name__}")

    # Tradecraft and secrets apply to every format; binaries contribute their ASCII + UTF-16 strings.
    if kind in {"text", "empty"}:
        text = _decode_text(data[:4 * 1024 * 1024])
    else:
        ascii_strings = b"\n".join(re.findall(rb"[\x20-\x7e\t]{6,}", data[:8 * 1024 * 1024]))
        wide = b"\n".join(m.replace(b"\x00", b"") for m in re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data[:8 * 1024 * 1024]))
        text = (ascii_strings + b"\n" + wide).decode("latin-1")
    for finding in scan_command_text(text):
        add(finding["severity"], finding["label"], finding["contribution"], finding["explanation"], category="tradecraft",
            matched=finding["matched"])

    message: dict[str, Any] | None = None
    if kind == "text" and _looks_like_email(text):
        message = analyze_message(text)
        for item in message["indicators"]:
            add(item.severity, item.label, item.contribution, item.explanation, category=item.category)
        details = {"type": "email", "links": message["links"][:15], "email_headers": message["email_headers"]}
    elif kind == "text":
        details = {"type": "text"}

    privacy = scan_secrets(text[:2 * 1024 * 1024])
    for item in privacy["indicators"]:
        indicators.append(item)

    fused = fuse(indicators)
    return {
        "file_type": details.get("type", kind),
        "sniffed_type": kind,
        "details": details,
        "indicators": indicators,
        "findings": heuristic_dicts([item for item in indicators if item.category != "privacy"]),
        "privacy": {key: value for key, value in privacy.items() if key != "indicators"},
        "analyzer_errors": errors,
        "truncated_input": truncated,
        **fused,
    }


def read_for_inspection(path: str, head: bytes, file_size: int, limit: int = MAX_DEEP_SCAN_BYTES) -> bytes:
    """Return the bytes ``inspect_content`` should see: the head for plain files, more for containers."""
    if file_size <= len(head) or not needs_full_read(head):
        return head
    with open(path, "rb") as handle:
        return handle.read(min(file_size, limit))


# ---------------------------------------------------------------------------
# Web-facing entry points
# ---------------------------------------------------------------------------

def safe_file_name(name: str, default: str = "upload.bin") -> str:
    """Reduce a client-supplied name to a safe basename (no paths, control chars or reserved names)."""
    base = re.split(r"[\\/]", unicodedata.normalize("NFC", name or ""))[-1]
    base = "".join(char for char in base if unicodedata.category(char)[0] != "C").strip(" .")
    base = re.sub(r'[<>:"|?*]', "_", base)[:180]
    stem = base.split(".")[0].upper()
    if not base or stem in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}:
        return default
    return base


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def analyze_upload(data: bytes, file_name: str, settings: dict | None = None) -> dict[str, Any]:
    """Analyze an uploaded file given as bytes. The bytes are written to a private temporary
    directory only because the PE/YARA engines take paths; nothing is executed, and the
    directory is removed before returning."""
    from core.file_analyzer import analyze_file
    from detection.host import resolve_host_settings

    resolved = resolve_host_settings(settings)
    if len(data) > int(resolved["maximum_file_size"]):
        raise ValueError("File exceeds configured maximum file size.")
    name = safe_file_name(file_name)
    workdir = tempfile.mkdtemp(prefix="cyberscan-upload-")
    try:
        os.chmod(workdir, 0o700)
        path = os.path.join(workdir, name)
        with open(path, "xb") as handle:
            handle.write(data)
        try:
            result = analyze_file(path, settings=resolved)
        except TimeoutError:
            # The host analyzer ran out of time. The content inspection below is fast and bounded,
            # so the caller still gets what completed, marked as incomplete (never an exception).
            result = None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if result is None:
        payload = {"target": name, "combined_score": 0, "heuristic_score": 0, "classification": "UNKNOWN",
                   "evidence": [], "engine_status": {}, "feature_summary": {"file_size": len(data)},
                   "analysis_incomplete": [{"code": "host_timeout", "stage": "static",
                                            "message": "The file analysis didn't finish within its time limit."}]}
    else:
        payload = _jsonable(result)
    payload["target"] = name
    if not payload.get("content_analysis"):
        # Host analyzers that predate detection/ (e.g. the website's core.file_analyzer) do not run
        # content inspection; run it here so this entry point means the same thing on every host.
        payload["content_analysis"] = content_summary(
            inspect_content(data[:MAX_DEEP_SCAN_BYTES], name, total_size=len(data)))
    payload["detection_summary"] = detection_summary(payload)
    return payload


def analyze_text_json(value: str, settings: dict | None = None) -> dict[str, Any]:
    """Analyze a URL, message or hash string and return a JSON-serialisable result."""
    from core.scanner import scan_target

    text = value or ""
    payload = _jsonable(scan_target(text, is_file=False, settings=settings))
    if not payload.get("content_analysis") and text.strip():
        payload["content_analysis"] = _text_content_analysis(text)
    payload["detection_summary"] = detection_summary(payload)
    return payload


# ---------------------------------------------------------------------------
# Result shaping shared by every host
# ---------------------------------------------------------------------------

BENIGN_HOST_CLASSIFICATIONS = {"SAFE", "CLEAN", "NO_INDICATORS_OBSERVED"}


def content_summary(report: dict[str, Any]) -> dict[str, Any]:
    """The JSON shape of ``ScanResult.content_analysis`` (privacy values are already redacted)."""
    return _jsonable({
        "file_type": report.get("file_type"),
        "score": report.get("score", 0),
        "classification": report.get("classification", "SAFE"),
        "evidence_agreement": report.get("evidence_agreement", "none"),
        "corroborating_categories": report.get("corroborating_categories", []),
        "details": report.get("details", {}),
        "findings": [item.as_dict() for item in report.get("indicators", []) if item.category != "privacy"],
        "privacy": report.get("privacy", {}),
        "analyzer_errors": report.get("analyzer_errors", []),
    })


def _text_content_analysis(text: str) -> dict[str, Any]:
    from detection.url_intel import analyze_url_intel

    token = text.strip()
    if not re.search(r"\s", token) and re.match(r"^(?:[a-z][a-z0-9+.-]*:|www\.|(?:[a-z0-9-]+\.)+[a-z]{2,24}/)", token, re.IGNORECASE):
        intel = analyze_url_intel(token)
        return _jsonable({key: value for key, value in intel.items() if key != "indicators"})
    message = analyze_message(text)
    privacy = scan_secrets(text)
    return _jsonable({
        **{key: value for key, value in message.items() if key != "indicators"},
        "privacy": {key: value for key, value in privacy.items() if key != "indicators"},
    })


def band(score: int) -> str:
    """The one score-to-verdict rule: 0 = no indicators observed, 1-49 = review, 50+ = suspicious."""
    return "SUSPICIOUS" if score >= 50 else "REVIEW" if score > 0 else "NO_INDICATORS_OBSERVED"


def final_verdict(host_score: Any, host_classification: str, content_score: Any, *,
                  incomplete: bool = False) -> tuple[int, str]:
    """ONE final score and the verdict that matches it.

    ``final_score = max(host combined score, content score)``: the strongest evidence from either
    engine sets the score (as within each engine). The verdict is KNOWN_MALWARE when the exact file
    is listed (an identity, not a score); else SUSPICIOUS at 50+, even if part of the analysis is
    missing (what was found stands); else UNKNOWN when the analysis is incomplete (a low score
    can't vouch for what wasn't checked); else the score's band."""
    def number(value: Any) -> int:
        try:
            return max(0, min(100, int(round(float(value or 0)))))
        except (TypeError, ValueError):
            return 0

    score = max(number(host_score), number(content_score))
    if str(host_classification) == "KNOWN_MALWARE":
        return score, "KNOWN_MALWARE"
    if score >= 50:
        return score, "SUSPICIOUS"
    if incomplete or str(host_classification) == "UNKNOWN":
        return score, "UNKNOWN"
    return score, band(score)


def detection_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """One verdict for the UI, without hiding either source.

    ``final_score`` and ``classification`` follow ``final_verdict``: the score shown is the stronger
    of the host's combined score and the content inspection's score, and the verdict is that
    score's band (so a 35 is always "review", never "suspicious"). Host analyzers that use another
    vocabulary (desktop: SAFE/UNKNOWN/SUSPICIOUS) are read the same way: UNKNOWN means incomplete.
    """
    content = payload.get("content_analysis") or {}
    host_classification = str(payload.get("classification", "UNKNOWN"))
    if host_classification in {"SAFE", "CLEAN"}:
        host_classification = "NO_INDICATORS_OBSERVED"
    content_score = int(content.get("score", 0) or 0)
    content_classification = str(content.get("classification") or ("SUSPICIOUS" if content_score >= 50 else
                                                                   "UNKNOWN" if content_score > 0 else "SAFE"))
    host_score = payload.get("combined_score", 0)
    incomplete = bool(payload.get("analysis_incomplete")) or bool(content.get("analyzer_errors"))
    final_score, classification = final_verdict(host_score, host_classification, content_score, incomplete=incomplete)
    return {
        "classification": classification,
        "final_score": final_score,
        "host_score": int(host_score or 0) if isinstance(host_score, (int, float)) else 0,
        "needs_attention": classification not in BENIGN_HOST_CLASSIFICATIONS,
        "host_classification": host_classification,
        "content_classification": content_classification,
        "content_score": content_score,
        "score_rule": "final_score = max(host_score, content_score); verdict = band(final_score) "
                      "(0 none, 1-49 review, 50+ suspicious), KNOWN_MALWARE for an exact listing, UNKNOWN when incomplete",
        "evidence_agreement": content.get("evidence_agreement", "none"),
        "privacy_exposure": (content.get("privacy") or {}).get("exposure_level", "none"),
    }
