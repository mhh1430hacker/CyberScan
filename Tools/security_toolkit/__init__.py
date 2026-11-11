"""Shared helpers for CyberScan tools 051-100.

This package is not an approved tool directory, so the registry never discovers it as a tool.
Each tool module pins ``digest()`` of this package in its own source (``TOOLKIT_SHA256``) and
refuses to load if the package changed, so approving a tool's hash also binds this code.
Run ``python Tools/maintenance/pin_toolkit.py`` after editing anything here.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def digest(directory: Path = PACKAGE_DIR) -> str:
    """SHA-256 over every ``*.py`` file of the package (name and bytes, in sorted order)."""
    h = hashlib.sha256()
    for path in sorted(directory.glob("*.py")):
        h.update(path.name.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()
