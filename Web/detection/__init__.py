"""Compatibility import path for the canonical Sentinel engine in Tools."""

from pathlib import Path

__path__ = [str(Path(__file__).resolve().parents[2] / "Tools" / "detection")]
