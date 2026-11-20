"""Keep the protection data current while the local app runs.

Known-malware hashes refresh every HASHES_EVERY hours; YARA-Forge rules, link lists and secret
patterns every RULES_EVERY hours. Each refresh runs intel/fetch.py in its own process (so a slow
download never blocks a scan), writes files atomically, and the scanners pick up the new files on
their next use. Failures keep the previous data and are reported in ``state()``.
"""
from __future__ import annotations

import datetime as dt
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
HASHES_EVERY = 6
RULES_EVERY = 24
_state: dict[str, Any] = {"running": False, "last_run": None, "last_error": None, "step": None}
_lock = threading.Lock()


def _age_hours(stamp: str | None) -> float:
    if not stamp:
        return float("inf")
    try:
        when = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        return (dt.datetime.now(dt.timezone.utc) - when).total_seconds() / 3600
    except ValueError:
        return float("inf")


def due(manifest: dict[str, Any]) -> list[str]:
    steps = []
    if _age_hours(manifest.get("updated")) >= RULES_EVERY:
        steps += ["forge", "lists", "secrets"]
    if _age_hours(manifest.get("hashes_updated")) >= HASHES_EVERY:
        steps.append("hashes")
    return steps


def state() -> dict[str, Any]:
    return dict(_state)


def refresh(steps: list[str] | None = None) -> dict[str, Any]:
    """Run the given fetch steps now (all of them when None). Returns the new state."""
    from core import protection  # noqa: PLC0415

    all_steps = ["forge", "lists", "secrets", "hashes"]
    steps = [s for s in (steps or all_steps) if s in all_steps]
    with _lock:
        if _state["running"]:
            return state()
        _state.update(running=True, step=",".join(steps), last_error=None)
    try:
        skip = [s for s in all_steps if s not in steps]
        command = [sys.executable, str(HERE / "fetch.py"), "--out", str(protection.DATA)] + (["--skip", *skip] if skip else [])
        done = subprocess.run(command, capture_output=True, text=True, timeout=1800, check=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        failed = protection.manifest().get("failed") or []
        if done.returncode != 0 or failed:
            _state["last_error"] = f"failed: {', '.join(failed) or done.stderr.strip()[-200:]}"
        protection.reload()
    except (OSError, subprocess.SubprocessError) as exc:
        _state["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        _state.update(running=False, step=None, last_run=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"))
    return state()


def start_background(check_every_minutes: int = 30) -> None:
    """Check on start, then every ``check_every_minutes``; refresh whatever is due."""
    from core import protection  # noqa: PLC0415

    def loop() -> None:
        time.sleep(20)   # let the app finish starting
        while True:
            steps = due(protection.manifest())
            if steps:
                refresh(steps)
            time.sleep(check_every_minutes * 60)

    threading.Thread(target=loop, name="intel-updater", daemon=True).start()
