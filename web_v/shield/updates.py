"""Refreshing the open-source protection data (YARA-Forge rules, URLhaus, phishing
domains, secret patterns) with intel/fetch.py, by hand or automatically every few days."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import core, winutil

ROOT = Path(__file__).resolve().parents[2]
AUTO_EVERY = 3 * 86400


def manifest() -> dict[str, Any]:
    try:
        from core import protection  # noqa: PLC0415

        return protection.manifest()
    except Exception:  # noqa: BLE001
        return {}


def start() -> core.Job:
    if core.running("update"):
        raise RuntimeError("An update is already running.")

    def work(job: core.Job) -> dict[str, Any]:
        job.detail = "download"
        done = subprocess.run([sys.executable, str(ROOT / "intel" / "fetch.py")], cwd=str(ROOT), capture_output=True,  # noqa: S603
                              text=True, timeout=1800, creationflags=winutil.NO_WINDOW)
        if done.returncode != 0:
            raise RuntimeError((done.stderr or done.stdout)[-400:])
        try:
            from core import protection  # noqa: PLC0415

            for cached in (protection._forge, protection._phishing, protection._urlhaus):  # noqa: SLF001
                cached.cache_clear()
        except Exception:  # noqa: BLE001
            pass
        cfg = core.load_config()
        cfg["updates"]["last_update"] = int(time.time())
        core.save_config(cfg)
        core.EVENTS.add("update", "info", "updated", manifest().get("updated", ""))
        return manifest()

    return core.start_job("update", work)


def auto_due(config: dict[str, Any]) -> bool:
    if not config["updates"]["auto"] or core.running("update"):
        return False
    last = max(int(config["updates"].get("last_update") or 0), _data_age())
    return time.time() - last > AUTO_EVERY


def _data_age() -> int:
    path = ROOT / "intel" / "data" / "manifest.json"
    try:
        return int(path.stat().st_mtime)
    except OSError:
        return 0
