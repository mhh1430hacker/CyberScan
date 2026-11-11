"""Compatibility wrapper for the Mobile-owned Android asset generator."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / "Mobile" / "android" / "make_android_assets.py"
subprocess.run([sys.executable, str(SCRIPT)], check=True)
