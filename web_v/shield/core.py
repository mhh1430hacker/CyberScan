"""Shared state for the protection tools: settings, the event log, background jobs and
the optional settings password.

Settings live in ``data/shield.json`` next to the scanner's own settings. Every change
goes through ``update_config`` which validates each value against ``SCHEMA``: the page
can never write a key or a type this file does not know.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable

from config import DATA_DIR

from . import winutil

CONFIG_PATH = Path(DATA_DIR) / "shield.json"
EVENTS_PATH = Path(DATA_DIR) / "shield_events.json"
_lock = threading.RLock()


def _default_config() -> dict[str, Any]:
    kf = winutil.known_folder
    return {
        "file_shield": True,
        "file_shield_folders": [str(kf("downloads")), str(kf("desktop"))],
        "file_shield_auto_quarantine": True,
        "file_shield_scan_archives": True,
        "behavior_shield": True,
        "behavior_mode": "ask",             # ask | quarantine | alert
        "ransomware_shield": True,
        "ransomware_folders": [str(kf("documents")), str(kf("pictures")), str(kf("desktop"))],
        "ransomware_strict": False,
        "mail_shield": True,
        "web_shield": False,                # opt-in: it changes the system's proxy setting
        "web": {
            "https": True, "uncommon_apps": True, "quic": True, "websocket": True, "dns": True,
            "botnet": True, "scripts": True, "phishing": True, "site_blocking": False, "blocked_sites": [],
        },
        "smart_scan": {"auto_continue": True, "schedule": "auto", "time": "12:00", "day": 1,
                       "last_run": 0, "last_summary": {}},
        "virus_scan": {"archives": True, "pup": True, "heuristics": "normal", "max_mb": 50, "auto_quarantine": False},
        "dnd": {"enabled": True, "postpone_scans": True, "silence": True},
        "webcam_shield": {"mode": "notify", "blocked_apps": []},
        "remote_access": {"enabled": True, "block_bruteforce": True, "allowed_ips": []},
        "sensitive_data": {"folders": [str(kf("documents")), str(kf("desktop"))], "types": ["card", "iban", "secret", "id", "password"]},
        "hack_alerts": {"emails": []},
        "exclusions": {"paths": [], "urls": []},
        "apps": {"blocked": [], "allowed": []},
        "devices": {"usb_storage_blocked": False},
        "notifications": {"popups": True, "sound": False, "quiet_hours": False, "detections_only": False},
        "privacy": {"history_days": 0, "community": False, "crash_reports": False},
        "updates": {"auto": True, "last_check": 0, "last_update": 0},
        "ui": {"language": "", "theme": "dark", "tray": True},
        "password": {"hash": "", "salt": "", "protect": ["settings", "shields", "quarantine"]},
    }


def _is_bool(v: Any) -> bool:
    return isinstance(v, bool)


def _str(max_len: int = 1024) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, str) and len(v) <= max_len


def _choice(*options: str) -> Callable[[Any], bool]:
    return lambda v: v in options


def _int(low: int, high: int) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and low <= v <= high


def _str_list(max_items: int = 200, max_len: int = 1024) -> Callable[[Any], bool]:
    return lambda v: isinstance(v, list) and len(v) <= max_items and all(isinstance(x, str) and 0 < len(x) <= max_len for x in v)


# Validators for every key the page may change, by dotted path.
SCHEMA: dict[str, Callable[[Any], bool]] = {
    "file_shield": _is_bool, "file_shield_folders": _str_list(20), "file_shield_auto_quarantine": _is_bool,
    "file_shield_scan_archives": _is_bool, "behavior_shield": _is_bool, "behavior_mode": _choice("ask", "quarantine", "alert"),
    "ransomware_shield": _is_bool, "ransomware_folders": _str_list(20), "ransomware_strict": _is_bool,
    "mail_shield": _is_bool, "web_shield": _is_bool,
    **{f"web.{k}": _is_bool for k in ("https", "uncommon_apps", "quic", "websocket", "dns", "botnet", "scripts", "phishing", "site_blocking")},
    "web.blocked_sites": _str_list(500, 253),
    "smart_scan.auto_continue": _is_bool, "smart_scan.schedule": _choice("auto", "off", "daily", "weekly", "monthly"),
    "smart_scan.time": lambda v: isinstance(v, str) and len(v) == 5 and v[2] == ":" and v[:2].isdigit() and v[3:].isdigit()
    and int(v[:2]) < 24 and int(v[3:]) < 60,
    "smart_scan.day": _int(0, 31),
    "virus_scan.archives": _is_bool, "virus_scan.pup": _is_bool, "virus_scan.heuristics": _choice("low", "normal", "high"),
    "virus_scan.max_mb": _int(1, 500), "virus_scan.auto_quarantine": _is_bool,
    "dnd.enabled": _is_bool, "dnd.postpone_scans": _is_bool, "dnd.silence": _is_bool,
    "webcam_shield.mode": _choice("notify", "block_untrusted", "block_all", "off"), "webcam_shield.blocked_apps": _str_list(100),
    "remote_access.enabled": _is_bool, "remote_access.block_bruteforce": _is_bool, "remote_access.allowed_ips": _str_list(100, 64),
    "sensitive_data.folders": _str_list(20), "sensitive_data.types": _str_list(10, 20),
    "hack_alerts.emails": _str_list(10, 254),
    "exclusions.paths": _str_list(200), "exclusions.urls": _str_list(200, 2048),
    "apps.blocked": _str_list(200), "apps.allowed": _str_list(200),
    "notifications.popups": _is_bool, "notifications.sound": _is_bool, "notifications.quiet_hours": _is_bool,
    "notifications.detections_only": _is_bool,
    "privacy.history_days": _int(0, 3650), "privacy.community": _is_bool, "privacy.crash_reports": _is_bool,
    "updates.auto": _is_bool,
    "ui.language": _str(12), "ui.theme": _choice("dark", "light", "system"), "ui.tray": _is_bool,
    "password.protect": _str_list(5, 20),
}


def _merge(base: dict[str, Any], saved: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in saved.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _merge(out[key], value)
        elif key in out:
            out[key] = value
    return out


def load_config() -> dict[str, Any]:
    with _lock:
        try:
            saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            saved = {}
        return _merge(_default_config(), saved if isinstance(saved, dict) else {})


def save_config(config: dict[str, Any]) -> None:
    with _lock:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(CONFIG_PATH)


def _set_path(config: dict[str, Any], dotted: str, value: Any) -> None:
    node = config
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def flatten(changes: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in changes.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict) and path not in SCHEMA:
            out.update(flatten(value, path + "."))
        else:
            out[path] = value
    return out


def update_config(changes: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate and apply; returns (old, new). Raises ValueError naming the bad key."""
    flat = flatten(changes)
    with _lock:
        old = load_config()
        new = copy.deepcopy(old)
        for path, value in flat.items():
            check = SCHEMA.get(path)
            if check is None:
                raise ValueError(f"{path} cannot be changed here")
            if not check(value):
                raise ValueError(f"{path} has an invalid value")
            if isinstance(value, list):
                value = list(dict.fromkeys(x.strip() for x in value if x.strip()))
            _set_path(new, path, value)
        save_config(new)
    return old, new


def public_config(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = copy.deepcopy(config or load_config())
    pw = config.pop("password")
    config["password"] = {"set": bool(pw.get("hash")), "protect": pw.get("protect", [])}
    return config


# ---------------------------------------------------------------- password
_unlocks: dict[str, float] = {}
UNLOCK_TTL = 15 * 60


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000).hex()


def password_set() -> bool:
    return bool(load_config()["password"].get("hash"))


def check_password(password: str) -> bool:
    pw = load_config()["password"]
    if not pw.get("hash"):
        return True
    try:
        salt = bytes.fromhex(pw.get("salt", ""))
    except ValueError:
        return False
    return hmac.compare_digest(_hash(password, salt), pw["hash"])


def unlock(password: str) -> str | None:
    if not check_password(password):
        time.sleep(0.8)   # slows guessing
        return None
    token = secrets.token_urlsafe(24)
    now = time.time()
    for key in [k for k, exp in _unlocks.items() if exp < now]:
        _unlocks.pop(key, None)
    _unlocks[token] = now + UNLOCK_TTL
    return token


def unlocked(token: str | None, area: str) -> bool:
    pw = load_config()["password"]
    if not pw.get("hash") or area not in pw.get("protect", []):
        return True
    expiry = _unlocks.get(token or "")
    return bool(expiry and expiry > time.time())


def set_password(current: str, new: str) -> None:
    if not check_password(current):
        raise PermissionError("The current password is wrong.")
    with _lock:
        config = load_config()
        if new:
            if len(new) < 6:
                raise ValueError("Use at least 6 characters.")
            salt = secrets.token_bytes(16)
            config["password"]["hash"] = _hash(new, salt)
            config["password"]["salt"] = salt.hex()
        else:
            config["password"]["hash"] = ""
            config["password"]["salt"] = ""
        save_config(config)
    _unlocks.clear()


# ---------------------------------------------------------------- events
class EventLog:
    """What the shields did: detections, blocks, warnings. The page polls ``since``."""

    def __init__(self) -> None:
        self.items: deque[dict[str, Any]] = deque(maxlen=400)
        self.counter = 0
        self.lock = threading.Lock()
        try:
            saved = json.loads(EVENTS_PATH.read_text(encoding="utf-8"))
            for item in saved[-400:]:
                self.items.append(item)
            self.counter = max((i.get("id", 0) for i in self.items), default=0)
        except (OSError, ValueError, TypeError):
            pass
        self._dirty = False

    def add(self, tool: str, severity: str, title: str, detail: str = "", **extra: Any) -> dict[str, Any]:
        with self.lock:
            self.counter += 1
            item = {"id": self.counter, "tool": tool, "severity": severity, "title": title, "detail": detail[:2000],
                    "at": time.time(), **extra}
            self.items.append(item)
            self._dirty = True
        self.flush()
        return item

    def since(self, last: int) -> list[dict[str, Any]]:
        with self.lock:
            return [e for e in self.items if e["id"] > last]

    def recent(self, tool: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self.lock:
            items = [e for e in self.items if tool is None or e["tool"] == tool]
        return items[-limit:][::-1]

    def clear(self) -> None:
        with self.lock:
            self.items.clear()
            self._dirty = True
        self.flush()

    def flush(self) -> None:
        with self.lock:
            if not self._dirty:
                return
            data = list(self.items)
            self._dirty = False
        try:
            EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            EVENTS_PATH.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass


EVENTS = EventLog()


# ---------------------------------------------------------------- jobs
class Job:
    """A long task (a scan, a network sweep…) the page polls for progress."""

    def __init__(self, kind: str) -> None:
        self.id = uuid.uuid4().hex
        self.kind = kind
        self.status = "running"
        self.progress = 0.0
        self.detail = ""
        self.counts: dict[str, int] = {}
        self.items: list[dict[str, Any]] = []
        self.result: Any = None
        self.error = ""
        self.cancel = False
        self.started = time.time()
        self.finished = 0.0

    def snapshot(self, with_items: bool = True) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "status": self.status, "progress": round(self.progress, 3),
            "detail": self.detail, "counts": self.counts, "items": self.items[-500:] if with_items else [],
            "result": self.result, "error": self.error, "started": self.started, "finished": self.finished,
            "elapsed": round((self.finished or time.time()) - self.started, 1),
        }


JOBS: dict[str, Job] = {}
_jobs_lock = threading.Lock()


def start_job(kind: str, work: Callable[[Job], Any]) -> Job:
    job = Job(kind)
    with _jobs_lock:
        if len(JOBS) > 40:
            for key in [k for k, j in JOBS.items() if j.status != "running"][:20]:
                JOBS.pop(key, None)
        JOBS[job.id] = job

    def run() -> None:
        try:
            job.result = work(job)
            job.status = "cancelled" if job.cancel else "done"
            job.progress = 1.0
        except Exception as exc:  # noqa: BLE001 - shown to the user
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.finished = time.time()

    threading.Thread(target=run, daemon=True, name=f"shield-{kind}").start()
    return job


def running(kind: str) -> Job | None:
    with _jobs_lock:
        return next((j for j in JOBS.values() if j.kind == kind and j.status == "running"), None)


def exclusions(config: dict[str, Any]) -> list[str]:
    """Paths no scan or shield should flag: the user's exceptions and the apps they allowed."""
    return [*config["exclusions"]["paths"], *config["apps"]["allowed"]]
