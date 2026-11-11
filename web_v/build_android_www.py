"""Compatibility entry point; Mobile owns the Android www builder."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "Mobile" / "build_android_www.py"


def main() -> None:
    completed = subprocess.run(
        [sys.executable, str(BUILDER), "--sync-web-compat", *sys.argv[1:]],
        cwd=ROOT,
        check=False,
    )
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
