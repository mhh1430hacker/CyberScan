from __future__ import annotations

import multiprocessing
from io import BytesIO
from multiprocessing.connection import Connection
from typing import Any
from importlib.util import find_spec
from urllib.parse import urlsplit

MAX_PDF_BYTES = 16 * 1024 * 1024
MAX_PDF_OBJECTS = 5000
MAX_PDF_DEPTH = 24
MAX_PDF_LINKS = 100
MAX_PDF_LINK_LENGTH = 2048
MAX_PDF_METADATA_FIELDS = 64
PDF_SCAN_TIMEOUT_SECONDS = 8.0
SUSPICIOUS_ACTIONS = {
    "/JavaScript": ("high", "JavaScript action"),
    "/JS": ("high", "JavaScript action"),
    "/OpenAction": ("medium", "active open action"),
    "/AA": ("high", "additional automatic action"),
    "/Launch": ("high", "launch action"),
    "/EmbeddedFiles": ("medium", "embedded-file collection"),
}


def _inspect_worker(data: bytes, sender: Connection) -> None:
    try:
        sender.send(("ok", _inspect_pdf(data)))
    except Exception as exc:
        sender.send(("error", type(exc).__name__))
    finally:
        sender.close()


def _inspect_in_process(data: bytes) -> tuple[str, Any]:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_inspect_worker, args=(data, sender), daemon=True)
    try:
        process.start()
    except Exception as exc:
        receiver.close()
        sender.close()
        return "error", type(exc).__name__
    sender.close()
    try:
        if not receiver.poll(PDF_SCAN_TIMEOUT_SECONDS):
            if process.is_alive():
                process.terminate()
            process.join()
            return "timeout", None
        outcome = receiver.recv()
        process.join(timeout=0.25)
        if process.is_alive():
            process.terminate()
            process.join()
        return outcome
    except EOFError:
        process.join(timeout=0.25)
        return "error", f"Worker exited with code {process.exitcode}."
    finally:
        receiver.close()


def _inspect_pdf(data: bytes) -> dict[str, Any]:
    from pypdf import PdfReader
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, TextStringObject

    reader = PdfReader(BytesIO(data), strict=False)
    if reader.is_encrypted:
        return {
            "status": "encrypted",
            "findings": [],
            "metadata": {},
            "limitations": ["The PDF is encrypted; its objects could not be inspected without a password."],
        }

    actions: dict[str, int] = {}
    links: list[str] = []
    seen_indirect: set[tuple[int, int]] = set()
    visited_objects = 0
    limit_reasons: set[str] = set()

    def visit(value: Any, depth: int) -> None:
        nonlocal visited_objects
        if depth > MAX_PDF_DEPTH or visited_objects >= MAX_PDF_OBJECTS:
            limit_reasons.add(f"Inspection stopped at the {MAX_PDF_OBJECTS}-object or {MAX_PDF_DEPTH}-level limit.")
            return
        if isinstance(value, IndirectObject):
            key = (value.idnum, value.generation)
            if key in seen_indirect:
                return
            seen_indirect.add(key)
            value = value.get_object()
        visited_objects += 1
        if isinstance(value, DictionaryObject):
            for key, child in value.items():
                name = str(key)
                if name in SUSPICIOUS_ACTIONS:
                    actions[name] = actions.get(name, 0) + 1
                if name == "/OpenAction" and _has_active_open_action(child, IndirectObject, DictionaryObject):
                    actions[name] = actions.get(name, 0) + 1
                if name == "/URI" and isinstance(child, (str, TextStringObject)):
                    url = str(child).strip()
                    if url and url not in links:
                        if len(url) > MAX_PDF_LINK_LENGTH:
                            limit_reasons.add(f"A URI longer than {MAX_PDF_LINK_LENGTH} characters was omitted.")
                            return
                        if len(links) >= MAX_PDF_LINKS:
                            limit_reasons.add(f"Inspection stopped at the {MAX_PDF_LINKS}-link limit.")
                            return
                        links.append(url)
                visit(child, depth + 1)
                if limit_reasons:
                    return
        elif isinstance(value, ArrayObject):
            for child in value:
                visit(child, depth + 1)
                if limit_reasons:
                    return

    visit(reader.trailer.get("/Root"), 0)
    metadata: dict[str, str] = {}
    if reader.metadata:
        for index, (key, value) in enumerate(reader.metadata.items()):
            if index >= MAX_PDF_METADATA_FIELDS:
                limit_reasons.add(f"Metadata was capped at {MAX_PDF_METADATA_FIELDS} fields.")
                break
            if value is not None:
                metadata[str(key)[:80]] = str(value).replace("\x00", "")[:300]

    findings: list[dict[str, Any]] = []
    for action, count in sorted(actions.items()):
        severity, label = SUSPICIOUS_ACTIONS[action]
        findings.append({
            "severity": severity,
            "type": "active_content",
            "evidence": f"{label} dictionary entry {action} observed {count} time(s)",
            "count": count,
        })
    if links:
        findings.append({
            "severity": "info",
            "type": "links",
            "evidence": f"{len(links)} URI link(s) extracted for offline assessment",
            "count": len(links),
        })

    return {
        "status": "partial" if limit_reasons else "parsed",
        "version": str(reader.pdf_header or "")[:20],
        "encrypted": False,
        "object_count_inspected": visited_objects,
        "actions": actions,
        "links": links,
        "findings": findings,
        "metadata": metadata,
        "limitations": sorted(limit_reasons) + ["Parser success does not establish that the PDF is safe or fully intact."],
    }


def _has_active_open_action(value: Any, indirect_type: type, dictionary_type: type) -> bool:
    if isinstance(value, indirect_type):
        value = value.get_object()
    if not isinstance(value, dictionary_type):
        return False
    return str(value.get("/S", "")) in {"/JavaScript", "/Launch", "/GoToR", "/SubmitForm", "/ImportData"}


def analyze_pdf(data: bytes, file_name: str = "") -> dict[str, Any]:
    """Inspect PDF structure and active objects without opening links or executing content."""
    if not isinstance(data, bytes):
        raise TypeError("PDF data must be bytes.")
    if not data:
        raise ValueError("PDF data is empty.")
    if len(data) > MAX_PDF_BYTES:
        raise ValueError(f"PDF exceeds the {MAX_PDF_BYTES}-byte limit.")
    if b"%PDF-" not in data[:1024]:
        raise ValueError("Input does not contain a PDF header in the first 1024 bytes.")

    if find_spec("pypdf") is None:
        return {
            "status": "parser_unavailable",
            "file_name": file_name,
            "findings": [],
            "limitations": ["Install the pypdf dependency to inspect PDF object structure."],
        }

    status, result = _inspect_in_process(data)
    if status == "timeout":
        return {
            "status": "timeout",
            "file_name": file_name,
            "findings": [],
            "limitations": [f"PDF inspection exceeded the {PDF_SCAN_TIMEOUT_SECONDS:g}-second limit."],
        }
    if status != "ok":
        return {
            "status": "parse_error",
            "file_name": file_name,
            "findings": [],
            "limitations": [f"PDF parser failed: {result}."],
        }
    return {"file_name": file_name, **result}


def assess_pdf_links(report: dict[str, Any]) -> dict[str, Any]:
    """Assess extracted links with CyberScan's existing local URL analysis."""
    from core.url_analyzer import analyze_url

    assessed = []
    for url in report.get("links", []):
        try:
            scheme = urlsplit(url).scheme.lower()
            if scheme in {"javascript", "data", "file"}:
                parsed = {
                    "score": None,
                    "classification": "SUSPICIOUS",
                    "findings": [{
                        "severity": "high",
                        "evidence": f"URI uses the {scheme}: scheme instead of a normal web destination.",
                    }],
                }
            elif scheme in {"http", "https"}:
                parsed = analyze_url(url)
            else:
                parsed = {
                    "score": None,
                    "classification": "UNASSESSED",
                    "findings": [{"severity": "info", "evidence": "This URI scheme is not assessed as a web address."}],
                }
        except ValueError:
            parsed = {
                "score": None,
                "classification": "UNASSESSED",
                "findings": [{"severity": "info", "evidence": "The URI could not be parsed as a web address."}],
            }
        assessed.append({
            "url": url,
            "score": parsed.get("score"),
            "classification": parsed.get("classification"),
            "findings": parsed.get("findings", []),
        })
    high_action = any(SUSPICIOUS_ACTIONS.get(action, ("info", ""))[0] == "high" for action in report.get("actions", {}))
    high_link = any(item["classification"] == "SUSPICIOUS" for item in assessed)
    has_observations = bool(report.get("actions") or assessed)
    if report.get("status") not in {"parsed", "partial"}:
        risk_level = "UNASSESSED"
    elif high_action or high_link:
        risk_level = "SUSPICIOUS"
    elif has_observations or report.get("status") == "partial":
        risk_level = "REVIEW"
    else:
        risk_level = "NO_INDICATORS_OBSERVED"
    recommendations = [
        "Do not open a document from an untrusted source; use the full file scanner for broader static checks."
    ]
    if report.get("actions"):
        recommendations.append("Review active actions before opening; use a trusted PDF viewer with JavaScript and automatic actions disabled.")
    if assessed:
        recommendations.append("Check each extracted destination independently. CyberScan did not open or visit these links.")
    return {
        **report,
        "link_assessments": assessed,
        "risk_level": risk_level,
        "recommendations": recommendations,
    }
