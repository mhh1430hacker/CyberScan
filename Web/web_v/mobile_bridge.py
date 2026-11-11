"""Compatibility exports for the Mobile-owned Pyodide bridge."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT, ROOT / "Web", ROOT / "Web" / "web_v"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from Mobile.mobile_bridge import fingerprints, repair_open, repair_run, run_tool, scan, tools_list, warm  # noqa: E402

__all__ = ["fingerprints", "repair_open", "repair_run", "run_tool", "scan", "tools_list", "warm"]
