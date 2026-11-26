"""The input, decomposed once and shared by every layer (thread-safe, lazy, cached).

Each expensive view (parsed PE, content inspection, heuristics, the links and their analysis) is
computed the first time a layer asks for it and then reused, so ~100 layers running in parallel
parse the file once, not 100 times. A view that fails becomes ``None`` (the layers that need it
answer "not available"); nothing here raises into a layer.
"""
from __future__ import annotations

import hashlib
import math
import re
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Callable

_HTML = re.compile(rb"<\s*(?:!doctype\s+html|html|head|body|form|script|iframe)\b", re.IGNORECASE)
_SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".sh", ".py", ".pl", ".rb", ".php"}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _strings(data: bytes) -> str:
    ascii_strings = b"\n".join(re.findall(rb"[\x20-\x7e\t]{6,}", data[:8 * 1024 * 1024]))
    wide = b"\n".join(m.replace(b"\x00", b"") for m in re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data[:8 * 1024 * 1024]))
    return (ascii_strings + b"\n" + wide).decode("latin-1")


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


class LayerContext:
    """``mode``: "file", "url" or "text". ``name``: the file's base name (never sent anywhere).
    ``result``: the host pipeline's ScanResult when there is one (YARA, hash and online answers,
    PE summary, model); ``content``: the content inspection's summary (unused by layers that run
    their own inspection, kept for callers)."""

    def __init__(self, raw: bytes, *, mode: str = "file", name: str = "", target: str = "",
                 result: Any = None, content: dict[str, Any] | None = None) -> None:
        self.raw = raw if isinstance(raw, bytes) else bytes(raw or b"")
        self.mode = mode if mode in {"file", "url", "text"} else "file"
        self.name = Path(str(name or "")).name
        self.target = str(target or "")
        self.result = result
        self.content = content
        self._cache: dict[str, Any] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        self.facts = self._facts()

    # ---------------------------------------------------------------- caching
    def cached(self, key: str, compute: Callable[[], Any]) -> Any:
        if key in self._cache:
            return self._cache[key]
        with self._guard:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._cache:
                try:
                    self._cache[key] = compute()
                except Exception:  # noqa: BLE001 - a view that fails is "not available"
                    self._cache[key] = None
            return self._cache[key]

    # ---------------------------------------------------------------- facts (cheap, eager)
    def _facts(self) -> dict[str, Any]:
        from detection.engine import sniff_type  # noqa: PLC0415

        ext = Path(self.name).suffix.lower() if self.name else ""
        if self.mode == "url":
            kind = "url"
        elif self.mode == "text":
            kind = "text"
        else:
            kind = sniff_type(self.raw)
        head = self.raw[:65536]
        is_text = kind in {"text", "empty"}
        is_html = is_text and bool(_HTML.search(head))
        is_email = False
        if is_text:
            from detection.messages import _looks_like_email  # noqa: PLC0415

            try:
                is_email = _looks_like_email(_decode(self.raw[:200_000]))
            except Exception:  # noqa: BLE001
                is_email = False
        container = None
        if kind == "zip":
            container = self.cached("container", self._container)
        urls = self.urls() if self.mode != "url" else [self.target]
        result = self.result
        engine_status = getattr(result, "engine_status", None) or {}
        return {
            "mode": self.mode, "kind": kind, "container": container, "ext": ext, "size": len(self.raw),
            "is_text": is_text or self.mode == "text", "is_html": is_html, "is_email": is_email,
            "is_script": ext in _SCRIPT_EXT, "has_urls": bool(urls), "has_result": result is not None,
            "yara": str(engine_status.get("YARA", "")).startswith("available"),
        }

    def _container(self) -> str | None:
        from detection.archives import classify_zip, open_zip  # noqa: PLC0415

        archive = open_zip(self.raw)
        return classify_zip(archive) if archive is not None else None

    # ---------------------------------------------------------------- shared views
    @property
    def feature_summary(self) -> dict[str, Any]:
        return dict(getattr(self.result, "feature_summary", None) or {})

    def sha256(self) -> str:
        return self.cached("sha256", lambda: hashlib.sha256(self.raw).hexdigest())

    def md5(self) -> str:
        return self.cached("md5", lambda: hashlib.md5(self.raw).hexdigest())  # noqa: S324 - lookup key only

    def text(self) -> str:
        """Readable text: the decoded input for text, the ASCII + UTF-16 strings for binaries."""
        def compute() -> str:
            if self.mode in {"url", "text"}:
                return _decode(self.raw[:4 * 1024 * 1024])
            if self.facts_kind() in {"text", "empty"}:
                return _decode(self.raw[:4 * 1024 * 1024])
            return _strings(self.raw)
        return self.cached("text", compute)

    def facts_kind(self) -> str:
        facts = getattr(self, "facts", None)
        if facts:
            return facts["kind"]
        from detection.engine import sniff_type  # noqa: PLC0415

        return "url" if self.mode == "url" else "text" if self.mode == "text" else sniff_type(self.raw)

    def inspection(self) -> dict[str, Any] | None:
        """detection.engine.inspect_content once: format analyzers, tradecraft, email, secrets."""
        def compute() -> dict[str, Any] | None:
            if self.mode == "url":
                return None
            from detection.engine import inspect_content  # noqa: PLC0415

            return inspect_content(self.raw, self.name or ("message.txt" if self.mode == "text" else "upload.bin"))
        return self.cached("inspection", compute)

    def inspection_labels(self) -> list[str]:
        def compute() -> list[str]:
            report = self.inspection() or {}
            return [str(getattr(item, "label", "")) for item in report.get("indicators") or []]
        return self.cached("inspection_labels", compute) or []

    def privacy_types(self) -> list[str]:
        def compute() -> list[str]:
            report = self.inspection() or {}
            return [str((getattr(item, "data", None) or {}).get("type", "")) for item in report.get("indicators") or []
                    if getattr(item, "category", "") == "privacy"]
        return self.cached("privacy_types", compute) or []

    def heuristic_labels(self) -> list[str]:
        """core.heuristic_engine over the content as written and its decoded views."""
        def compute() -> list[str]:
            if self.mode == "url":
                return []
            from core.heuristic_engine import evaluate_heuristics  # noqa: PLC0415

            text = self.raw[:400_000].decode("latin-1") if self.mode == "file" else self.text()
            return [str(item.get("label", "")) for item in evaluate_heuristics(text, file_name=self.name or None).get("findings", [])]
        return self.cached("heuristics", compute) or []

    def urls(self) -> list[str]:
        """Web addresses the content contains (the link itself for a link scan), at most 25."""
        def compute() -> list[str]:
            if self.mode == "url":
                return [self.target]
            from detection.url_intel import extract_urls  # noqa: PLC0415

            text = self.text() or ""
            found = extract_urls(text[:2_000_000], limit=25)
            return [u for u in dict.fromkeys(found) if u.lower().startswith(("http://", "https://"))][:25]
        return self.cached("urls", compute) or []

    def url_reports(self) -> list[dict[str, Any]]:
        """detection.url_intel for each link (at most 12), plus the offline lists (core.protection)."""
        def compute() -> list[dict[str, Any]]:
            from detection.url_intel import analyze_url_intel  # noqa: PLC0415

            out = []
            for url in self.urls()[:12]:
                try:
                    report = analyze_url_intel(url)
                    labels = [str(getattr(i, "label", "") or (i.get("label") if isinstance(i, dict) else "")) for i in report.get("indicators") or []]
                except Exception:  # noqa: BLE001
                    labels = []
                try:
                    from core import protection  # noqa: PLC0415

                    listed = [str(item.get("label", "")) for item in protection.check_url(url)]
                except Exception:  # noqa: BLE001
                    listed = []
                out.append({"url": url, "labels": labels, "protection": listed})
            return out
        return self.cached("url_reports", compute) or []

    def url_labels(self) -> list[str]:
        return [label for report in self.url_reports() for label in report["labels"]]

    def protection_labels(self) -> list[str]:
        return [label for report in self.url_reports() for label in report["protection"]]

    def pe(self) -> Any:
        """pefile.PE for a Windows program (None otherwise or when pefile is missing)."""
        def compute() -> Any:
            if self.facts_kind() != "pe":
                return None
            import pefile  # noqa: PLC0415

            return pefile.PE(data=self.raw)
        return self.cached("pe", compute)

    def pe_imports(self) -> set[str]:
        def compute() -> set[str]:
            pe = self.pe()
            names: set[str] = set()
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                for imp in entry.imports or []:
                    if getattr(imp, "name", None):
                        names.add(imp.name.decode("ascii", "ignore"))
            return names
        return self.cached("pe_imports", compute) or set()

    def topography(self) -> dict[str, Any] | None:
        def compute() -> dict[str, Any] | None:
            known = self.feature_summary.get("entropy_topography")
            if isinstance(known, dict) and known.get("trajectory") is not None:
                return known
            from core.nextgen_engine import NextGenCyberEngine  # noqa: PLC0415

            return NextGenCyberEngine.analyze_entropy_topography(self.raw)
        return self.cached("topography", compute)

    def html(self) -> str:
        return self.cached("html", lambda: (self.text() or "")[:2_000_000] if self.facts.get("is_html") else "") or ""

    # ---------------------------------------------------------------- matching helpers
    @staticmethod
    def match(labels: list[str], wanted: tuple[str, ...]) -> list[str]:
        """Labels equal to one of ``wanted`` or reported for a container member ("X (in a.bat)")."""
        out = []
        for label in labels:
            for name in wanted:
                if label == name or label.startswith(name + " (") or label.startswith(name + ":"):
                    out.append(label)
                    break
        return out
