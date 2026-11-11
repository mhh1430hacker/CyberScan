"""Features behind the web API that reuse the desktop app's own modules.

Everything a user sees in plain words (verdict headline, advice, finding
titles in Arabic and English) comes from ``ui.plain_language`` and
``ui.finding_text`` so both interfaces say exactly the same thing.
"""
from __future__ import annotations

import dataclasses
import hashlib
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from config import DATA_DIR
from core.models import ScanResult
from ui import plain_language
from ui.copy import tr
from ui.file_kind import kind_for_target
from ui.i18n import supported
from ui.result_view import build_result_view
from ui.structure import build_structure

LANGS = ("en", "ar")   # always sent; the visitor's own language is added (ui/i18n.py)


def langs_for(extra: str | None = None) -> tuple[str, ...]:
    code = supported(extra)
    return LANGS + ((code,) if code and code not in LANGS else ())
MAX_CELLS_SENT = 4096


# ------------------------------------------------------------ presentation
def _mode_for(target: str, mode: str | None) -> str:
    if mode:
        return mode
    if target.startswith(("http://", "https://")):
        return "URL"
    if Path(target).is_absolute():
        return "File"
    return "Text"


def present(result: ScanResult, target: str, mode: str | None, raw: bytes | None, elapsed: float | None,
            lang: str | None = None) -> dict[str, Any]:
    """Plain-language summary and details in both languages, plus the
    structure cube, for one scan result."""
    mode = _mode_for(target, mode)
    nextgen = result.nextgen_analysis or {}
    view = build_result_view(result, nextgen)
    kind = kind_for_target(target, mode)
    out: dict[str, Any] = {"mode": mode, "kind": kind.key, "kind_hue": kind.hue, "plain": {}}
    for lang in langs_for(lang):
        try:
            s = plain_language.summary(view, kind, elapsed, lang, mode=mode, target=target)
            d = plain_language.details(view, kind, lang)
        except Exception:  # noqa: BLE001 - presentation must never break a result
            continue
        out["plain"][lang] = {
            "summary": dataclasses.asdict(s),
            "details": {
                "findings": [dataclasses.asdict(f) for f in d.findings],
                "places": [list(p) for p in d.places],
                "checks": [dataclasses.asdict(c) for c in d.checks],
                "facts": [list(f) for f in d.facts],
                "score_line": d.score_line,
            },
            "kind_label": tr(kind.label, lang),
        }
    out["sha256"] = view.sha256 or ""
    out["structure"] = structure_payload(result, raw)
    pe = result.pe_analysis or {}
    if pe.get("status") == "ok":
        header = pe.get("header_summary") or {}
        out["pe"] = {
            "machine": header.get("machine"),
            "timestamp": header.get("timestamp"),
            "subsystem": header.get("subsystem"),
            "import_count": pe.get("import_count"),
            "suspicious_imports": list(pe.get("suspicious_imports") or [])[:40],
            "high_entropy_sections": list(pe.get("high_entropy_sections") or []),
            "findings": list(pe.get("findings") or [])[:20],
            "sections": [
                {
                    "name": s.get("name"),
                    "entropy": round(float(s.get("entropy") or 0), 2),
                    "size": s.get("raw_size") or s.get("size"),
                }
                for s in (pe.get("sections") or [])[:24] if isinstance(s, dict)
            ],
        }
    else:
        out["pe"] = None
    return out


def structure_payload(result: ScanResult, raw: bytes | None) -> dict[str, Any] | None:
    nextgen = result.nextgen_analysis or {}
    try:
        built = build_structure(
            raw,
            int(nextgen.get("file_size") or 0) or None,
            nextgen.get("entropy_topography"),
            (result.feature_summary or {}).get("position_aware_evidence"),
        )
    except Exception:  # noqa: BLE001
        return None
    if built is None or built.count == 0:
        return None
    n = min(built.count, MAX_CELLS_SENT)
    return {
        "size": built.file_size,
        "source": built.source,
        "positions": [round(float(v), 3) for v in built.positions[:n].reshape(-1)],
        "entropy": [round(float(v), 2) for v in built.entropy[:n]],
        "flags": [int(v) for v in built.flags[:n]],
        "offsets": [int(v) for v in built.offsets[:n, 0]],
        "regions": [
            {"start": r.offset_start, "end": r.offset_end, "severity": r.severity, "delta": r.delta}
            for r in built.regions[:40]
        ],
    }


# ------------------------------------------------------------ native helpers
_PICK_SCRIPT = (
    "import sys, tkinter as tk\n"
    "from tkinter import filedialog\n"
    "root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True)\n"
    "if sys.argv[1] == 'folder':\n"
    "    print(filedialog.askdirectory() or '')\n"
    "else:\n"
    "    print(filedialog.askopenfilename() or '')\n"
)
_pick_lock = threading.Lock()


def pick(kind: str = "file") -> str:
    """Open the system file (or folder) chooser and return the chosen path."""
    if not _pick_lock.acquire(blocking=False):
        raise RuntimeError("A chooser is already open.")
    try:
        done = subprocess.run(
            [sys.executable, "-I", "-c", _PICK_SCRIPT, "folder" if kind == "folder" else "file"],
            capture_output=True, text=True, timeout=600,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return done.stdout.strip().replace("/", "\\") if sys.platform == "win32" else done.stdout.strip()
    finally:
        _pick_lock.release()


def reveal(path: str) -> None:
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(path)
    if sys.platform == "win32":
        subprocess.Popen(["explorer", f"/select,{target}"])  # noqa: S603,S607
    else:
        subprocess.Popen(["xdg-open", str(target.parent)])  # noqa: S603,S607


# ------------------------------------------------------------ quarantine
def quarantine(path: str) -> str:
    from ui import vault

    return str(vault.quarantine(path, Path(DATA_DIR), Path(DATA_DIR) / "quarantine"))


def restore(sealed: str, original: str) -> str:
    from ui import vault

    restored = vault.restore(sealed, original, Path(DATA_DIR))
    Path(sealed).unlink(missing_ok=True)
    return str(restored)


# ------------------------------------------------------------ secrets
def secret_store():
    from ui.secrets import SecretStore

    return SecretStore(Path(DATA_DIR) / "secrets.bin")


def keys_status() -> dict[str, bool]:
    from ui.secrets import KEY_ENV

    saved = secret_store().load()
    return {key: bool(saved.get(key)) for key in KEY_ENV}


def save_keys(changes: dict[str, Any]) -> dict[str, bool]:
    from ui.secrets import KEY_ENV, apply_to_environment

    store = secret_store()
    saved = store.load()
    for key, value in changes.items():
        if key not in KEY_ENV or not isinstance(value, str):
            raise ValueError(f"unknown key {key}")
        if value.strip():
            saved[key] = value.strip()
        else:
            saved.pop(key, None)
    store.save(saved)
    apply_to_environment(store.load())
    return keys_status()


def load_keys_into_environment() -> None:
    try:
        from ui.secrets import apply_to_environment

        apply_to_environment(secret_store().load())
    except Exception:  # noqa: BLE001 - online lookups simply stay keyless
        pass


# ------------------------------------------------------------ AI summary
class AiJob:
    def __init__(self) -> None:
        self.id = uuid.uuid4().hex
        self.text = ""
        self.status = "running"
        self.error = ""
        self.stop = False


AI_JOBS: dict[str, AiJob] = {}


def ai_status(model: str) -> dict[str, Any]:
    from ui import ai_summary

    status = ai_summary.runtime_status(model)
    return {"state": status.state, "models": list(status.models), "model": model}


def ai_start(result: ScanResult, target: str, mode: str | None, lang: str, model: str) -> AiJob:
    from ui import ai_summary

    mode = _mode_for(target, mode)
    view = build_result_view(result, result.nextgen_analysis or {})
    kind = kind_for_target(target, mode)
    s = plain_language.summary(view, kind, None, lang, mode=mode, target=target)
    d = plain_language.details(view, kind, lang)
    size = plain_language.format_size(view.file_size) if view.file_size is not None else ""
    facts = ai_summary.build_facts(s, d, tr(kind.label, lang), size, view.score)
    job = AiJob()
    if len(AI_JOBS) > 16:
        for key in [k for k, j in AI_JOBS.items() if j.status != "running"][:8]:
            AI_JOBS.pop(key, None)
    AI_JOBS[job.id] = job

    def run() -> None:
        def on_text(text: str) -> None:
            job.text = text

        try:
            job.text = ai_summary.summarize(facts, lang, model, on_text=on_text, should_stop=lambda: job.stop)
            job.status = "done"
        except ai_summary.AiUnavailable as exc:
            job.status, job.error, job.text = "failed", exc.code, ""
        except Exception as exc:  # noqa: BLE001
            job.status, job.error, job.text = "failed", f"{type(exc).__name__}", ""

    threading.Thread(target=run, daemon=True).start()
    return job


# ------------------------------------------------------------ downloads monitor
class Monitor:
    """Watches a folder and queues new files for the page to offer a scan."""

    def __init__(self) -> None:
        self.events: deque[dict[str, Any]] = deque(maxlen=50)
        self.counter = 0
        self.monitor = None
        self.directory = ""
        self.lock = threading.Lock()

    def _found(self, path: str) -> None:
        with self.lock:
            self.counter += 1
            self.events.append({"id": self.counter, "path": path, "name": Path(path).name, "at": time.time()})

    def apply(self, enabled: bool, directory: str) -> str:
        from monitoring.downloads_monitor import DownloadMonitor

        with self.lock:
            if self.monitor is not None and (not enabled or directory != self.directory):
                try:
                    self.monitor.stop()
                except Exception:  # noqa: BLE001
                    pass
                self.monitor = None
            if enabled and self.monitor is None:
                if not Path(directory).expanduser().is_dir():
                    return "missing_folder"
                self.monitor = DownloadMonitor(directory, callback=self._found)
                self.monitor.start()
                self.directory = directory
            return "on" if self.monitor is not None else "off"

    def since(self, last: int) -> list[dict[str, Any]]:
        with self.lock:
            return [e for e in self.events if e["id"] > last]

    def stop(self) -> None:
        self.apply(False, "")


# ------------------------------------------------------------ repair
REPAIR_MAX = 200 * 1024 * 1024


class RepairSession:
    def __init__(self, data: bytes, name: str, path: Path | None) -> None:
        self.id = uuid.uuid4().hex
        self.data = data
        self.name = name
        self.path = path
        self.report = None
        self.output: bytes | None = None
        self.output_name = ""
        self.created = time.time()


REPAIRS: dict[str, RepairSession] = {}


def verify_uploaded_bytes(
    data: bytes,
    *,
    expected_sha256: str | None = None,
    max_file_size: int = 50 * 1024 * 1024,
) -> dict[str, Any]:
    """Run the read-only integrity verifier on a private temporary copy."""
    from core.file_integrity import verify_file_integrity

    with tempfile.TemporaryDirectory(prefix="cyberscan-integrity-") as directory:
        target = Path(directory) / "candidate.bin"
        target.write_bytes(data)
        return verify_file_integrity(
            target,
            expected_sha256=expected_sha256,
            max_file_size=max_file_size,
        )


def summarize_inspection(report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    from detection.common import Indicator
    from detection.engine import content_summary, detection_summary

    indicators = []
    for item in report.get("indicators", []):
        if not isinstance(item, dict) or item.get("category") == "privacy":
            continue
        try:
            indicators.append(Indicator(
                category=str(item["category"]),
                severity=str(item["severity"]),
                label=str(item["label"]),
                explanation=str(item["explanation"]),
                contribution=int(item.get("contribution", 0)),
                data=item.get("data") if isinstance(item.get("data"), dict) else {},
            ))
        except (KeyError, TypeError, ValueError):
            continue
    content = content_summary({**report, "indicators": indicators})
    summary = detection_summary({"classification": "UNKNOWN", "content_analysis": content})
    return content, summary


def inspect_uploaded_content(data: bytes, name: str) -> dict[str, Any]:
    """Use Sentinel's bounded request service and return its shared JSON schema."""
    from detection.service import default_service

    envelope = default_service().inspect_upload(data, name)
    if envelope.get("status") != "ok" or not isinstance(envelope.get("result"), dict):
        error = envelope.get("error") or {}
        return {
            "status": "inspection_incomplete",
            "scan_status": envelope.get("status", "error"),
            "error": error.get("message", "Sentinel inspection did not complete."),
            "analyzer_errors": [error.get("message", "Sentinel inspection did not complete.")],
            "indicators": [],
            "engine": envelope.get("engine"),
            "elapsed_ms": envelope.get("elapsed_ms", 0),
        }

    report = envelope["result"]
    content, summary = summarize_inspection(report)
    status = (
        "inspection_incomplete"
        if content.get("analyzer_errors") or report.get("truncated_input")
        else "complete"
    )
    return {
        **content,
        "status": status,
        "scan_status": envelope.get("status"),
        "indicators": content.get("findings", []),
        "detection_summary": summary,
        "engine": envelope.get("engine"),
        "elapsed_ms": envelope.get("elapsed_ms", 0),
        "truncated_input": bool(report.get("truncated_input")),
    }


# One fixed sentence per kind of repair finding (the same sentences as the
# desktop app's ui/repair.py, kept here so the web edition needs no Qt).
# ui.copy translates them.
REPAIR_SUMMARIES = {
    "name_hidden": "The name contains invisible direction characters that make it read as something else.",
    "name_double": "It's named like a document or picture, but the real extension is a program that can run.",
    "name_mismatch": "The name's extension doesn't match what the file really contains.",
    "after_eof": "Data is stored after the point where the format ends. Readers ignore it; other programs can use it.",
    "pe_overlay": "Data after the program's last section. Installers often keep their payload there, so it isn't removed unless you choose to.",
    "pdf_update": "The last update to this PDF only adds active content. Removing that update returns the document to its previous version.",
    "pdf_active": "Part of the document carries active content: JavaScript, automatic actions or embedded files.",
    "ooxml_vba_project": "Code that can run when the document is opened.",
    "ooxml_embedded_object": "Another file stored inside the document; it can be a program.",
    "ooxml_activex": "A control that can run code inside Office.",
    "ooxml_link": "The document fetches something from the internet when it opens.",
    "ole_vba": "This older Office file contains macro code.",
}


def _repair_summary(key: str, lang: str, fallback: str) -> str:
    english = REPAIR_SUMMARIES.get(key)
    if english:
        return tr(english, lang)
    return tr(fallback, lang) if lang != "en" else fallback


def repair_open(data: bytes, name: str, path: Path | None, lang: str | None = None) -> dict[str, Any]:
    from repair_engine.analyze import analyze

    if len(data) > REPAIR_MAX:
        raise ValueError("This file is larger than 200 MB, which Repair doesn't handle yet.")
    session = RepairSession(data, name, path)
    session.report = analyze(data, name)
    session.langs = langs_for(lang)
    now = time.time()
    for key in [k for k, s in REPAIRS.items() if now - s.created > 3600]:
        REPAIRS.pop(key, None)
    REPAIRS[session.id] = session
    return repair_describe(session)


def repair_describe(session: RepairSession) -> dict[str, Any]:
    langs = getattr(session, "langs", LANGS)
    report = session.report
    findings = []
    for f in report.findings:
        findings.append({
            "key": f.key,
            "kind": f.kind,
            "severity": f.severity,
            "repairable": f.repairable,
            "recommended": f.recommended,
            "start": f.start,
            "end": f.end,
            "rename_to": f.rename_to,
            "title": {lang: tr(f.title, lang) for lang in langs},
            "body": {lang: _repair_summary(f.kind, lang, f.detail) for lang in langs},
            "detail": f.detail,
            "reason": {lang: tr(f.reason, lang) if f.reason else "" for lang in langs},
        })
    regions = []
    for r in getattr(report.regions, "regions", []) or []:
        try:
            regions.append({"name": str(r.kind), "start": int(r.start), "end": int(r.end)})
        except (AttributeError, TypeError, ValueError):
            continue
    return {
        "id": session.id,
        "name": session.name,
        "size": report.size,
        "sha256": report.sha256,
        "format": report.format,
        "on_disk": session.path is not None,
        "folder": str(session.path.parent) if session.path else "",
        "findings": findings,
        "regions": regions[:64],
    }


def _free_path(folder: Path, name: str) -> Path:
    candidate = folder / name
    stem, suffix = Path(name).stem, Path(name).suffix
    index = 1
    while candidate.exists():
        candidate = folder / f"{stem} ({index}){suffix}"
        index += 1
    return candidate


def repair_run(session: RepairSession, keys: list[str]) -> dict[str, Any]:
    from repair_engine.analyze import repair

    chosen = [f for f in session.report.findings if f.key in set(keys) and f.repairable]
    if not chosen:
        raise ValueError("Choose at least one problem that can be repaired.")
    result = repair(session.data, session.name, chosen)
    out: dict[str, Any] = {
        "ok": bool(result.ok and result.repaired is not None),
        "message": result.message,
        "before": result.before,
        "after": result.after,
        "removed_bytes": result.removed_bytes,
        "sha256_before": getattr(result, "sha256_before", hashlib.sha256(session.data).hexdigest()),
        "sha256_after": getattr(result, "sha256_after", ""),
        "checks": dict(result.validation.checks) if result.validation else {},
        "failures": dict(result.validation.failures) if result.validation else {},
        "name": result.name,
        "saved_to": "",
        "download": False,
    }
    if not out["ok"]:
        return out
    for key, data, digest in (
        ("original_verification", session.data, out["sha256_before"]),
        ("candidate_verification", result.repaired, out["sha256_after"]),
    ):
        try:
            out[key] = verify_uploaded_bytes(data, expected_sha256=digest)
        except (OSError, ValueError) as exc:
            out[key] = {
                "status": "verification_incomplete",
                "error": f"Independent verification could not complete ({type(exc).__name__}).",
            }
    candidate_status = (out.get("candidate_verification") or {}).get("status")
    out["verification_status"] = (
        "verified" if candidate_status == "structurally_valid"
        else "verification_incomplete" if candidate_status == "verification_incomplete"
        else "damage_detected" if candidate_status == "damage_detected"
        else "verification_incomplete"
    )
    out["data_loss"] = {
        "status": "bytes_removed" if result.removed_bytes else "none_detected",
        "bytes_removed": int(result.removed_bytes or 0),
        "original_preserved": True,
    }
    if candidate_status == "damage_detected":
        out["ok"] = False
        out["message"] = "Independent verification found damage in the repair candidate; it was not saved."
        return out
    out["original_security_inspection"] = inspect_uploaded_content(session.data, session.name)
    out["candidate_security_inspection"] = inspect_uploaded_content(result.repaired, result.name)
    if result.removed:
        try:
            from repair_engine.executor.vault import seal
            from ui.vault import _key

            seal(result.removed, _key(Path(DATA_DIR)), Path(DATA_DIR) / "quarantine" / "repair", result.sha256_before)
        except Exception as exc:  # noqa: BLE001
            out["seal_error"] = f"{type(exc).__name__}: {exc}"
    if session.path is not None:
        try:
            output = _free_path(session.path.parent, result.name)
            temporary = output.with_name(output.name + ".tmp")
            temporary.write_bytes(result.repaired)
            temporary.replace(output)
            out["saved_to"] = str(output)
        except OSError as exc:
            out["ok"] = False
            out["message"] = f"The repaired copy couldn't be saved: {type(exc).__name__}: {exc}"
            return out
    session.output = result.repaired
    session.output_name = result.name
    out["download"] = True
    return out
