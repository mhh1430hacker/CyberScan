"""What runs in the background while the app is open.

    File Shield     watches the folders you choose; every new or changed file is checked
                    by the engine as soon as it finishes writing, and a threat is sealed
                    in quarantine when you allowed that
    device watch    logs when an app starts using the camera or microphone
    scheduler       starts the Smart Scan when it is due, but never during a full-screen
                    game, film or presentation when Do Not Disturb is on
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from . import core, engine, privacy, scans, vault, winutil


class FileShield:
    def __init__(self) -> None:
        self.monitors: dict[str, Any] = {}
        self.lock = threading.Lock()
        self.scanned = 0
        self.blocked = 0
        self.last: dict[str, Any] | None = None

    def apply(self, config: dict[str, Any]) -> None:
        from monitoring.downloads_monitor import DownloadMonitor  # noqa: PLC0415

        wanted = set(config["file_shield_folders"]) if config["file_shield"] else set()
        wanted = {f for f in wanted if Path(f).is_dir()}
        with self.lock:
            for folder in list(self.monitors):
                if folder not in wanted:
                    try:
                        self.monitors.pop(folder).stop()
                    except Exception:  # noqa: BLE001
                        pass
            for folder in wanted - set(self.monitors):
                monitor = DownloadMonitor(folder, callback=self._found, poll_interval=1.5)
                monitor.start()
                self.monitors[folder] = monitor

    def _found(self, path: str) -> None:
        threading.Thread(target=self._check, args=(Path(path),), daemon=True).start()

    def _check(self, path: Path) -> None:
        config = core.load_config()
        if engine.excluded(path, core.exclusions(config)):
            return
        options = {**config["virus_scan"], "archives": config["file_shield_scan_archives"]}
        verdict = engine.inspect(path, options)
        self.scanned += 1
        self.last = {"path": str(path), "status": verdict.get("status"), "at": time.time()}
        status = verdict.get("status")
        if status not in ("threat", "review"):
            return
        action = "none"
        if status == "threat" and config["file_shield_auto_quarantine"]:
            try:
                vault.seal(path, "; ".join(verdict.get("reasons", []))[:400], verdict.get("name", ""), "file_shield",
                           verdict.get("sha256", ""))
                action = "quarantined"
                self.blocked += 1
            except Exception as exc:  # noqa: BLE001
                action = f"failed: {type(exc).__name__}"
        core.EVENTS.add("file_shield", "high" if status == "threat" else "medium",
                        "threat_found" if status == "threat" else "review_found", str(path),
                        name=verdict.get("name", ""), action=action, score=verdict.get("score", 0))

    def status(self) -> dict[str, Any]:
        with self.lock:
            folders = list(self.monitors)
        return {"on": bool(folders), "folders": folders, "scanned": self.scanned, "blocked": self.blocked, "last": self.last}

    def stop(self) -> None:
        with self.lock:
            for monitor in self.monitors.values():
                try:
                    monitor.stop()
                except Exception:  # noqa: BLE001
                    pass
            self.monitors.clear()


class Service:
    """Owns the background pieces; started once by the server (desktop mode only)."""

    def __init__(self) -> None:
        self.file_shield = FileShield()
        self.devices = privacy.DeviceWatch()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.started = 0.0

    def start(self) -> None:
        if self.thread is not None:
            return
        self.started = time.time()
        self.apply(core.load_config())
        self.thread = threading.Thread(target=self._loop, daemon=True, name="shield-service")
        self.thread.start()

    def apply(self, config: dict[str, Any]) -> None:
        try:
            self.file_shield.apply(config)
        except Exception as exc:  # noqa: BLE001
            core.EVENTS.add("file_shield", "medium", "shield_error", str(exc))

    def _loop(self) -> None:
        tick = 0
        while not self.stop_event.wait(5):
            tick += 1
            config = core.load_config()
            if config["webcam_shield"]["mode"] != "off" and tick % 2 == 0:
                self.devices.tick()
            if tick % 12 == 0:   # once a minute
                quiet = config["dnd"]["enabled"] and config["dnd"]["postpone_scans"] and winutil.fullscreen_busy()
                # wait a few minutes after start so the scan doesn't compete with the user opening the app
                if not quiet and time.time() - self.started > 180 and scans.due(config) and not core.running("smart_scan"):
                    try:
                        scans.smart_scan()
                        core.EVENTS.add("smart_scan", "info", "scheduled_start", config["smart_scan"]["schedule"])
                    except RuntimeError:
                        pass
            if tick % 720 == 360:   # hourly, starting half an hour after launch
                from . import updates  # noqa: PLC0415

                if updates.auto_due(config):
                    try:
                        updates.start()
                    except RuntimeError:
                        pass

    def stop(self) -> None:
        self.stop_event.set()
        self.file_shield.stop()
        engine.flush_cache()
        core.EVENTS.flush()


SERVICE = Service()
