"""Unified result contract, execution wrapper and input helpers for tools 051-100.

Every tool returns the same JSON object (``UNIFIED_OUTPUT_SCHEMA``):

    tool_id, status, classification, risk_score, summary, findings, evidence,
    artifacts, limitations, metadata{version, execution_mode, execution_time_ms, ...}

``status``
    success       the analysis ran completely
    partial       it ran, but some checks were skipped (time budget, optional dependency, service down)
    unsupported   the input format or platform is not supported by this tool
    unavailable   a required dependency, service or credential is missing; nothing was analysed
    invalid_input the input passed the schema but is not usable (bad base64, wrong structure, ...)
    error         an unexpected internal failure; the message never contains input data

``classification`` (only meaningful with success/partial)
    clean         nothing risky found (risk_score 0, analysis complete)
    review        something worth a look (0 < risk_score < 50)
    suspicious    strong or several corroborating findings (risk_score >= 50)
    unknown       analysis incomplete or not performed

``risk_score`` fuses finding weights with the frozen engine's noisy-OR (``detection.common.noisy_or``),
so several weak findings corroborate without saturating, and informational findings weigh 0.

Each finding carries an ``assurance`` level so a detected risk is never presented as a confirmed
vulnerability:
    informational       context only
    heuristic           a pattern that often indicates a problem; may be a false positive
    verified_condition  a fact verified from the input (e.g. "certificate expired", "MFA disabled");
                        a weakness, not proof that it is exploitable
    advisory_match      a version matches a published advisory supplied to the tool; exploitability unverified
No tool in this set emits "confirmed vulnerability": static analysis cannot confirm exploitation.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

try:  # the frozen engine's evidence fusion; identical fallback keeps tools usable without it
    from detection.common import noisy_or as _noisy_or
except Exception:  # pragma: no cover - exercised only when detection/ is absent
    def _noisy_or(contributions):
        remaining = 1.0
        for value in contributions:
            remaining *= 1.0 - max(0.0, min(100.0, float(value))) / 100.0
        return int(round(100.0 * (1.0 - remaining)))

TOOLKIT_VERSION = "1.0.0"
STATUSES = ("success", "partial", "unsupported", "unavailable", "invalid_input", "error")
CLASSIFICATIONS = ("clean", "review", "suspicious", "unknown")
SEVERITIES = ("info", "low", "medium", "high", "critical")
ASSURANCES = ("informational", "heuristic", "verified_condition", "advisory_match")
DEFAULT_WEIGHT = {"info": 0, "low": 10, "medium": 25, "high": 45, "critical": 70}
MAX_FINDINGS = 500
MAX_EVIDENCE = 1000

UNIFIED_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["tool_id", "status", "classification", "risk_score", "summary", "findings", "evidence",
                 "artifacts", "limitations", "metadata"],
    "properties": {
        "tool_id": {"type": "string", "minLength": 3, "maxLength": 96},
        "status": {"type": "string", "enum": ["success", "partial", "unsupported", "unavailable", "invalid_input", "error"]},
        "classification": {"type": "string", "enum": ["clean", "review", "suspicious", "unknown"]},
        "risk_score": {"type": "integer"},
        "summary": {"type": "string", "maxLength": 2000},
        "findings": {"type": "array", "maxItems": 500, "items": {
            "type": "object",
            "required": ["id", "title", "severity", "assurance", "weight", "description"],
            "properties": {
                "id": {"type": "string", "minLength": 1, "maxLength": 120},
                "title": {"type": "string", "minLength": 1, "maxLength": 300},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "assurance": {"type": "string", "enum": ["informational", "heuristic", "verified_condition", "advisory_match"]},
                "weight": {"type": "integer"},
                "description": {"type": "string", "maxLength": 2000},
                "location": {"type": ["string", "null"], "maxLength": 500},
                "recommendation": {"type": ["string", "null"], "maxLength": 1000},
                "references": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
            },
            "additionalProperties": False,
        }},
        "evidence": {"type": "array", "maxItems": 1000, "items": {
            "type": "object",
            "required": ["kind", "detail"],
            "properties": {
                "finding_id": {"type": ["string", "null"], "maxLength": 120},
                "kind": {"type": "string", "maxLength": 60},
                "detail": {"type": "string", "maxLength": 600},
                "location": {"type": ["string", "null"], "maxLength": 500},
            },
            "additionalProperties": False,
        }},
        "artifacts": {"type": "object"},
        "limitations": {"type": "array", "maxItems": 50, "items": {"type": "string", "maxLength": 500}},
        "metadata": {"type": "object", "required": ["version", "execution_mode", "execution_time_ms"], "properties": {
            "version": {"type": "string"},
            "execution_mode": {"type": "string", "enum": ["local", "local-system", "network-passive", "network-active-authorized"]},
            "execution_time_ms": {"type": "integer"},
            "toolkit_version": {"type": "string"},
            "timeout_seconds": {"type": "number"},
            "input_kind": {"type": "string"},
        }},
    },
    "additionalProperties": False,
}


# ---- errors a tool raises to end with a specific status -----------------------------------------

class ToolInputError(ValueError):
    """The input is structurally valid JSON but cannot be analysed (status ``invalid_input``)."""


class Unsupported(Exception):
    """Format or platform not supported (status ``unsupported``)."""


class Unavailable(Exception):
    """A required dependency, credential or service is missing (status ``unavailable``)."""


class DeadlineExceeded(Exception):
    """The tool's time budget ran out; findings gathered so far are returned as ``partial``."""


# ---- redaction ----------------------------------------------------------------------------------

_SECRETISH = re.compile(
    r"""(?ix)
    (?P<kv>(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|session|cookie|bearer|
           community|key-string|pre-shared-key|psk|wpa-psk)
        [^\s:=]{0,20}\s*(?:=|:|\s)\s*(?:\d{1,2}\s+)?["']?)(?P<val>[^\s"'&;,]{3,})
    """
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/_\-=.]{20,}")
_URL_CREDS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,20}://)([^\s:/@]{1,64}):([^\s@/]{1,128})@")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    size = len(value)
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def mask(value: str, keep: int = 4) -> str:
    """Show the first few characters and the length only: ``AKIA…[20 chars]``."""
    value = str(value)
    if len(value) <= keep + 2:
        return "*" * len(value)
    return f"{value[:keep]}…[{len(value)} chars]"


def sanitize(text: str, limit: int = 200) -> str:
    """Make an excerpt safe to show: credentials in URLs, key=value secrets and long random tokens are masked."""
    out = str(text)[: limit * 3]
    out = _URL_CREDS.sub(lambda m: f"{m.group(1)}{m.group(2)}:****@", out)
    out = _SECRETISH.sub(lambda m: m.group("kv") + mask(m.group("val"), 2), out)

    def long_token(m: re.Match[str]) -> str:
        token = m.group(0)
        return mask(token) if shannon_entropy(token) >= 3.5 and not token.startswith(("http", "www.")) else token

    out = _LONG_TOKEN.sub(long_token, out)
    out = out.replace("\r", " ").replace("\n", " ")
    return out if len(out) <= limit else out[: limit - 1] + "…"


# ---- time budget --------------------------------------------------------------------------------

class Deadline:
    def __init__(self, seconds: float) -> None:
        self.seconds = float(seconds)
        self.end = time.monotonic() + self.seconds

    def remaining(self) -> float:
        return max(0.0, self.end - time.monotonic())

    def check(self) -> None:
        if time.monotonic() > self.end:
            raise DeadlineExceeded()


# ---- execution context --------------------------------------------------------------------------

@dataclass
class Context:
    tool_id: str
    version: str
    execution_mode: str
    deadline: Deadline
    options: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    partial: bool = False
    input_kind: str = ""
    summary: str = ""
    _keys: set = field(default_factory=set)

    def finding(self, fid: str, title: str, severity: str, description: str, *, assurance: str = "heuristic",
                weight: int | None = None, location: str | None = None, recommendation: str | None = None,
                references: list[str] | None = None, evidence: str | None = None, evidence_kind: str = "excerpt") -> bool:
        """Record one finding (deduplicated by id + location). Returns False if it was a duplicate."""
        if severity not in SEVERITIES or assurance not in ASSURANCES:
            raise ValueError(f"invalid severity/assurance: {severity}/{assurance}")
        key = (fid, location)
        if key in self._keys or len(self.findings) >= MAX_FINDINGS:
            return False
        self._keys.add(key)
        w = DEFAULT_WEIGHT[severity] if weight is None else int(max(0, min(100, weight)))
        if severity == "info" or assurance == "informational":
            w = 0
        item = {"id": fid[:120], "title": title[:300], "severity": severity, "assurance": assurance, "weight": w,
                "description": description[:2000], "location": (location[:500] if location else None),
                "recommendation": (recommendation[:1000] if recommendation else None),
                "references": [r[:300] for r in (references or [])][:10]}
        self.findings.append(item)
        if evidence is not None:
            self.evidence(evidence_kind, evidence, finding_id=fid, location=location)
        return True

    def evidence(self, kind: str, detail: str, *, finding_id: str | None = None, location: str | None = None) -> None:
        if len(self.evidence_items) >= MAX_EVIDENCE:
            return
        self.evidence_items.append({"finding_id": finding_id, "kind": kind[:60], "detail": sanitize(detail, 600),
                                    "location": (location[:500] if location else None)})

    def limit(self, text: str, *, partial: bool = False) -> None:
        if text not in self.limitations and len(self.limitations) < 50:
            self.limitations.append(text[:500])
        if partial:
            self.partial = True

    def check(self) -> None:
        self.deadline.check()


def _classify(status: str, score: int) -> str:
    if status not in ("success", "partial"):
        return "unknown"
    if score >= 50:
        return "suspicious"
    if score > 0:
        return "review"
    return "clean" if status == "success" else "unknown"


def _envelope(ctx: Context, status: str, started: float, summary: str) -> dict[str, Any]:
    score = _noisy_or(f["weight"] for f in ctx.findings) if status in ("success", "partial") else 0
    severity_rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(ctx.findings, key=lambda f: (-severity_rank[f["severity"]], -f["weight"], f["id"]))
    return {
        "tool_id": ctx.tool_id,
        "status": status,
        "classification": _classify(status, score),
        "risk_score": int(score),
        "summary": summary[:2000],
        "findings": findings,
        "evidence": ctx.evidence_items,
        "artifacts": ctx.artifacts,
        "limitations": ctx.limitations,
        "metadata": {
            "version": ctx.version,
            "execution_mode": ctx.execution_mode,
            "execution_time_ms": int((time.monotonic() - started) * 1000),
            "toolkit_version": TOOLKIT_VERSION,
            "timeout_seconds": ctx.deadline.seconds,
            "input_kind": ctx.input_kind,
        },
    }


def _default_summary(ctx: Context) -> str:
    if not ctx.findings:
        return "No issues were found by the checks this tool performs."
    counts: dict[str, int] = {}
    for f in ctx.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if s in counts]
    return f"{len(ctx.findings)} finding(s): " + ", ".join(parts) + "."


def run_tool(*, tool_id: str, version: str, execution_mode: str, timeout_seconds: float,
             input_data: Any, options: dict[str, Any] | None, analyze: Callable[[Context, dict[str, Any]], None]) -> dict[str, Any]:
    """Run ``analyze(ctx, input_data)`` and always return a unified result (never raises)."""
    started = time.monotonic()
    opts = options if isinstance(options, dict) else {}
    requested = opts.get("timeout_seconds")
    budget = timeout_seconds
    if isinstance(requested, (int, float)) and not isinstance(requested, bool) and requested > 0:
        budget = min(float(requested), float(timeout_seconds))
    ctx = Context(tool_id, version, execution_mode, Deadline(budget), opts)
    try:
        if not isinstance(input_data, dict):
            raise ToolInputError("Input must be an object.")
        analyze(ctx, input_data)
        status = "partial" if ctx.partial else "success"
        return _envelope(ctx, status, started, ctx.summary or _default_summary(ctx))
    except DeadlineExceeded:
        ctx.limit(f"The {budget:g}-second time budget ran out; results are incomplete.")
        return _envelope(ctx, "partial", started, "Time budget exhausted. " + _default_summary(ctx))
    except ToolInputError as exc:
        return _envelope(ctx, "invalid_input", started, f"Input rejected: {exc}")
    except Unsupported as exc:
        return _envelope(ctx, "unsupported", started, f"Not supported: {exc}")
    except Unavailable as exc:
        return _envelope(ctx, "unavailable", started, f"Unavailable: {exc}")
    except RecursionError:
        return _envelope(ctx, "invalid_input", started, "Input rejected: it is nested too deeply to analyse safely.")
    except MemoryError:
        return _envelope(ctx, "error", started, "Internal error: the input needed more memory than allowed.")
    except Exception as exc:  # noqa: BLE001 - contract: tools return structured errors, not exceptions
        return _envelope(ctx, "error", started, f"Internal error ({type(exc).__name__}). No input data is included in this message.")


# ---- input helpers ------------------------------------------------------------------------------

def decode_base64(value: str, *, max_bytes: int, field_name: str = "data_base64") -> bytes:
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ToolInputError(f"{field_name} must be valid base64.") from exc
    if not data:
        raise ToolInputError(f"{field_name} decodes to zero bytes.")
    if len(data) > max_bytes:
        raise ToolInputError(f"{field_name} exceeds the {max_bytes:,}-byte limit.")
    return data


def text_or_bytes(input_data: dict[str, Any], *, max_bytes: int, text_key: str = "content",
                  b64_key: str = "data_base64") -> str:
    """Return text from ``content`` or decoded ``data_base64`` (UTF-8 with replacement)."""
    if isinstance(input_data.get(text_key), str):
        text = input_data[text_key]
        if len(text.encode("utf-8", errors="ignore")) > max_bytes:
            raise ToolInputError(f"{text_key} exceeds the {max_bytes:,}-byte limit.")
        return text
    if isinstance(input_data.get(b64_key), str):
        raw = decode_base64(input_data[b64_key], max_bytes=max_bytes, field_name=b64_key)
        for encoding in ("utf-8-sig", "utf-16"):
            try:
                if encoding == "utf-16" and not raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
                    continue
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")
    raise ToolInputError(f"Provide '{text_key}' (text) or '{b64_key}' (base64).")


def file_list(input_data: dict[str, Any], *, max_files: int = 500, max_total: int = 20 * 1024 * 1024,
              max_file: int = 2 * 1024 * 1024) -> list[tuple[str, str]]:
    """Decode ``files: [{path, content | data_base64}]`` into (path, text) pairs with limits."""
    files = input_data.get("files")
    if not isinstance(files, list) or not files:
        raise ToolInputError("Provide 'files' as a non-empty list of {path, content}.")
    out: list[tuple[str, str]] = []
    total = 0
    for item in files[:max_files]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ToolInputError("Each file needs a 'path' string.")
        text = text_or_bytes(item, max_bytes=max_file)
        total += len(text)
        if total > max_total:
            raise ToolInputError(f"Files exceed the {max_total:,}-byte total limit.")
        out.append((item["path"].replace("\\", "/")[:500], text))
    return out


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""
