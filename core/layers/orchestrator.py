"""Run every applicable layer in parallel over one shared, decomposed input.

* The input is decomposed once (``LayerContext``); layers share its cached views.
* Layers that don't apply are reported at once (grey); the rest run in a thread pool.
* Each layer has its own time limit and the whole run a budget: a layer that is late is reported
  ``timeout`` (signal ``None``) and the scan goes on without it. A layer that raises reports
  ``error`` (signal ``None``); nothing a layer does can break the scan.
* ``progress(entry, done, total)`` is called as each layer finishes (from the caller's thread),
  so a status API can stream the grid live.
"""
from __future__ import annotations

import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any, Callable

from core.layers.aggregate import aggregate
from core.layers.base import CATEGORIES, REGISTRY, STATUS_WORDS, Layer
from core.layers.context import LayerContext

LAYER_TIMEOUT_SECONDS = 4.0
TOTAL_BUDGET_SECONDS = 15.0
MAX_WORKERS = 12

Progress = Callable[[dict[str, Any], int, int], None]


def _words(status: str) -> dict[str, str]:
    en, ar = STATUS_WORDS.get(status, (status, status))
    return {"en": en, "ar": ar}


def _entry(layer: Layer, out: dict[str, Any] | None, *, status: str | None = None, ms: int = 0) -> dict[str, Any]:
    out = out or {}
    signal = out.get("signal")
    signal = signal if signal in (0, 1) else None
    if status is None:
        status = out.get("status") or ("suspicious" if signal == 1 else "clean" if signal == 0 else "unavailable")
        if signal is not None:
            status = "suspicious" if signal == 1 else "clean"
    try:
        confidence = max(0.0, min(1.0, float(out.get("confidence", 0.0) or 0.0)))
    except (TypeError, ValueError):
        confidence = 0.0
    detail = out.get("detail") if isinstance(out.get("detail"), dict) else _words(status)
    return {
        "id": layer.id, "name": {"en": layer.name_en, "ar": layer.name_ar}, "category": layer.category, "signal": signal, "status": status,
        "confidence": round(confidence if signal is not None else 0.0, 3), "weight": layer.weight,
        "affects_score": layer.affects_score, "detail": {"en": str(detail.get("en", ""))[:220], "ar": str(detail.get("ar", ""))[:220]},
        "source": layer.source, "ms": ms, **({"hard": out["hard"]} if out.get("hard") and signal == 1 else {}),
    }


def _run_one(layer: Layer, ctx: LayerContext, started: dict[str, float]) -> tuple[dict[str, Any] | None, str | None, int]:
    t0 = time.monotonic()
    started[layer.id] = t0
    try:
        out = layer.run(ctx)
        return (out if isinstance(out, dict) else None), None, int((time.monotonic() - t0) * 1000)
    except Exception:  # noqa: BLE001 - a failing layer reports "error", never crashes the scan
        return None, "error", int((time.monotonic() - t0) * 1000)


def run_layers(ctx: LayerContext, *, layers: list[Layer] | None = None, progress: Progress | None = None,
               layer_timeout: float = LAYER_TIMEOUT_SECONDS, budget: float = TOTAL_BUDGET_SECONDS,
               max_workers: int = MAX_WORKERS) -> dict[str, Any]:
    registry = list(REGISTRY if layers is None else layers)
    total = len(registry)
    results: dict[str, dict[str, Any]] = {}
    done = 0
    t_start = time.monotonic()

    def report(entry: dict[str, Any]) -> None:
        nonlocal done
        results[entry["id"]] = entry
        done += 1
        if progress is not None:
            try:
                progress(entry, done, total)
            except Exception:  # noqa: BLE001 - a progress listener can't break the run
                pass

    applicable = [layer for layer in registry if layer.applies_to(ctx.facts)]
    chosen = {layer.id for layer in applicable}
    for layer in registry:
        if layer.id not in chosen:
            report(_entry(layer, None, status="not_applicable"))

    started: dict[str, float] = {}
    pool = ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(applicable) or 1)), thread_name_prefix="cyberscan-layer")
    try:
        pending: dict[Future, Layer] = {pool.submit(_run_one, layer, ctx, started): layer for layer in applicable}
        deadline = t_start + budget
        while pending:
            finished, _ = wait(list(pending), timeout=0.05, return_when=FIRST_COMPLETED)
            for future in finished:
                layer = pending.pop(future)
                out, failure, ms = future.result()
                report(_entry(layer, out, status=failure, ms=ms))
            now = time.monotonic()
            for future, layer in list(pending.items()):
                began = started.get(layer.id)
                late = (began is not None and now - began > layer_timeout) or now > deadline
                if late:
                    pending.pop(future)
                    future.cancel()
                    report(_entry(layer, {"detail": {"en": "Took too long; left out.", "ar": "استغرق وقتًا طويلًا فاستُبعد."}},
                                  status="timeout", ms=int((now - (began or now)) * 1000)))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    entries = [results[layer.id] for layer in registry]
    summary = aggregate(entries)
    summary["elapsed_ms"] = int((time.monotonic() - t_start) * 1000)
    summary["categories"] = {key: {"en": en, "ar": ar} for key, (en, ar) in CATEGORIES.items()}
    summary["facts"] = {k: v for k, v in ctx.facts.items() if k in {"mode", "kind", "container", "is_html", "is_email", "has_urls"}}
    return {"version": 1, "summary": summary, "layers": entries}


def catalog() -> list[dict[str, Any]]:
    """Every layer's description (for the UI's grid before results arrive)."""
    return [layer.describe() for layer in REGISTRY]
