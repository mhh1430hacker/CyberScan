"""Backward-compatible launcher for the Desktop component."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for component in (ROOT / "Desktop", ROOT / "Tools"):
    if str(component) not in sys.path:
        sys.path.insert(0, str(component))

from Desktop.main import main  # noqa: E402


if __name__ == "__main__":
    main()
