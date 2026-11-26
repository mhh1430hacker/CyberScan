"""Layered analysis: the input is taken apart once and passed through many independent layers.

Each layer (``core.layers.base.Layer``) checks one aspect and returns a binary signal
(1 suspicious, 0 clean, None not applicable / unavailable) with a confidence and its reliability
weight; ``core.layers.orchestrator.run_layers`` runs them in parallel with per-layer time limits;
``core.layers.aggregate.aggregate`` combines the signals (weighted log-odds, formula documented
there). The catalog is in ``catalog_structure`` (structure, entropy, program code),
``catalog_content`` (documents, archives, scripts, web pages, email, privacy) and
``catalog_intel`` (links, reputation and external services, YARA families, machine learning).
Every layer wraps a real check the engine already makes (or a small, distinct check of its own);
none is a duplicate of another.
"""
from __future__ import annotations

from core.layers import catalog_content, catalog_intel, catalog_structure  # noqa: F401 - registers the layers
from core.layers.aggregate import FORMULA, aggregate
from core.layers.base import CATEGORIES, REGISTRY, Layer
from core.layers.context import LayerContext
from core.layers.orchestrator import catalog, run_layers

__all__ = ["CATEGORIES", "FORMULA", "REGISTRY", "Layer", "LayerContext", "aggregate", "analyze", "catalog", "run_layers"]


def analyze(raw: bytes, *, mode: str = "file", name: str = "", target: str = "", result=None, content=None, progress=None) -> dict:
    """Decompose ``raw`` once and run every layer; returns {"summary", "layers", "version"}."""
    ctx = LayerContext(raw, mode=mode, name=name, target=target, result=result, content=content)
    return run_layers(ctx, progress=progress)
