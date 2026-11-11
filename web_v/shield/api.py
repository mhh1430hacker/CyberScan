"""The /api/shield/* endpoints. The web server (web_v/server.py) checks the host, origin
and token first, then calls ``dispatch``.

Each route says which password area protects it (``settings``, ``shields``, ``quarantine``)
and whether the public website may use it: online, only tools that touch nothing on the
server itself are available (e-mail analysis and the breach check).
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

from . import core, network, privacy, realtime, scans, system, updates, vault, winutil

ROOT = Path(__file__).resolve().parents[2]


class ShieldError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class Request:
    def __init__(self, method: str, query: dict, read_json: Callable[[], Any], read_raw: Callable[[int], bytes],
                 unlock: str | None, history: Callable[[], list], on_restore: Callable[[str], None]) -> None:
        self.method = method
        self.query = query
        self._json = read_json
        self._raw = read_raw
        self.unlock = unlock
        self.history = history
        self.on_restore = on_restore

    def json(self) -> dict[str, Any]:
        data = self._json()
        if not isinstance(data, dict):
            raise ShieldError(400, "expected an object")
        return data

    def raw(self, limit: int) -> bytes:
        return self._raw(limit)

    def q(self, key: str, default: str = "") -> str:
        return (self.query.get(key) or [default])[0]


def _paths(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value) or len(value) > 50:
        raise ShieldError(400, "expected a list of paths")
    return [v.strip().strip('"') for v in value if v.strip()]


# ---------------------------------------------------------------- overview
def overview(req: Request) -> dict[str, Any]:
    config = core.load_config()
    smart = config["smart_scan"]
    return {
        "platform": sys.platform, "windows": winutil.IS_WINDOWS, "admin": winutil.is_admin(),
        "config": core.public_config(config),
        "file_shield": realtime.SERVICE.file_shield.status(),
        "quarantine": vault.stats(),
        "smart": {"last_run": smart.get("last_run"), "last_summary": smart.get("last_summary"), "due": scans.due(config)},
        "dnd": privacy.dnd_state(),
        "jobs": {kind: (j.id if j else None) for kind in ("virus_scan", "smart_scan", "network_scan", "sensitive_scan", "shred", "update")
                 for j in [core.running(kind)]},
        "events": core.EVENTS.recent(limit=8),
        "locked": core.password_set() and not core.unlocked(req.unlock, "settings"),
        "intel": _intel_manifest(),
    }


def _intel_manifest() -> dict[str, Any]:
    try:
        from core import protection  # noqa: PLC0415

        return protection.manifest()
    except Exception:  # noqa: BLE001
        return {}


def config_put(req: Request) -> dict[str, Any]:
    try:
        old, new = core.update_config(req.json())
    except ValueError as exc:
        raise ShieldError(400, str(exc)) from exc
    realtime.SERVICE.apply(new)
    return core.public_config(new)


def unlock(req: Request) -> dict[str, Any]:
    token = core.unlock(str(req.json().get("password", "")))
    if token is None:
        raise ShieldError(403, "wrong_password")
    return {"token": token, "ttl": core.UNLOCK_TTL}


def password(req: Request) -> dict[str, Any]:
    data = req.json()
    try:
        core.set_password(str(data.get("current", "")), str(data.get("new", "")))
    except PermissionError as exc:
        raise ShieldError(403, "wrong_password") from exc
    except ValueError as exc:
        raise ShieldError(400, str(exc)) from exc
    return {"set": core.password_set()}


def events(req: Request) -> dict[str, Any]:
    try:
        since = int(req.q("since", "0"))
    except ValueError:
        since = 0
    tool = req.q("tool") or None
    items = core.EVENTS.since(since) if not tool else core.EVENTS.recent(tool, 100)
    return {"events": items, "last": core.EVENTS.counter, "dnd": privacy.dnd_state()["quiet"]}


def events_clear(req: Request) -> dict[str, Any]:
    core.EVENTS.clear()
    return {"ok": True}


# ---------------------------------------------------------------- jobs
def job_get(req: Request, job_id: str) -> dict[str, Any]:
    job = core.JOBS.get(job_id)
    if job is None:
        raise ShieldError(404, "no such job")
    return job.snapshot()


def job_cancel(req: Request, job_id: str) -> dict[str, Any]:
    job = core.JOBS.get(job_id)
    if job is not None:
        job.cancel = True
    return {"ok": True}


def _start(fn: Callable[[], core.Job]) -> dict[str, Any]:
    try:
        return {"id": fn().id}
    except RuntimeError as exc:
        raise ShieldError(409, str(exc)) from exc
    except (ValueError, PermissionError) as exc:
        raise ShieldError(400, str(exc)) from exc


# ---------------------------------------------------------------- scans and system
def scan(req: Request) -> dict[str, Any]:
    data = req.json()
    kind = data.get("kind")
    if kind not in ("quick", "full", "targeted", "usb"):
        raise ShieldError(400, "kind must be quick, full, targeted or usb")
    targets = _paths(data.get("targets", [])) if kind == "targeted" else None
    return _start(lambda: scans.virus_scan(kind, targets))


def smart(req: Request) -> dict[str, Any]:
    return _start(scans.smart_scan)


def boot_scan(req: Request) -> dict[str, Any]:
    return system.fix("boot_scan")


def system_checks(req: Request) -> dict[str, Any]:
    return {"checks": system.security_checks(), "admin": winutil.is_admin()}


def fix(req: Request) -> dict[str, Any]:
    data = req.json()
    fix_id = str(data.get("id", ""))
    if fix_id not in system.FIX_URIS and fix_id not in system.FIX_SCRIPTS:
        raise ShieldError(400, "unknown fix")
    if fix_id in ("cfa_on",):
        params = core.load_config()["ransomware_folders"]
    else:
        params = None
    out = system.fix(fix_id, params)
    if out.get("ok") and not out.get("opened"):
        core.EVENTS.add("system", "info", "fixed", fix_id)
    return out


def startup(req: Request) -> dict[str, Any]:
    return {"items": system.assess_autoruns(system.autoruns())}


def startup_remove(req: Request) -> dict[str, Any]:
    data = req.json()
    try:
        system.remove_autorun(str(data.get("where", "")), str(data.get("name", "")))
    except (OSError, PermissionError) as exc:
        raise ShieldError(409, str(exc)) from exc
    core.EVENTS.add("startup", "info", "startup_removed", str(data.get("name", "")))
    return {"ok": True}


def processes(req: Request) -> dict[str, Any]:
    procs = system.processes()
    return {"items": [{k: p[k] for k in ("pid", "name", "path")} for p in procs]}


# ---------------------------------------------------------------- quarantine
def quarantine_list(req: Request) -> dict[str, Any]:
    return {"items": vault.listing(req.history()), **vault.stats()}


def quarantine_add(req: Request) -> dict[str, Any]:
    path = Path(str(req.json().get("path", "")).strip('"'))
    if not path.is_absolute() or not path.is_file():
        raise ShieldError(400, "That file doesn't exist.")
    if winutil.protected_path(path.parent) and not str(path.parent).lower().startswith(str(Path.home()).lower()):
        raise ShieldError(400, "CyberScan won't move files out of system folders.")
    item = vault.seal(path, "manual", "", "manual")
    core.EVENTS.add("quarantine", "info", "quarantined", str(path))
    return item


def quarantine_restore(req: Request) -> dict[str, Any]:
    data = req.json()
    item_id = str(data.get("id", ""))
    folder = data.get("folder") or None
    item = next((i for i in vault.listing(req.history()) if i["id"] == item_id), None)
    if item is None:
        raise ShieldError(404, "Not in quarantine.")
    original = item["original"] if Path(str(item["original"])).is_absolute() else str(Path.home() / "Desktop" / str(item["original"]))
    try:
        restored = vault.restore(item_id, original, folder if isinstance(folder, str) else None)
    except (ValueError, FileNotFoundError) as exc:
        raise ShieldError(400, str(exc)) from exc
    req.on_restore(item_id)
    core.EVENTS.add("quarantine", "info", "restored", restored)
    return {"restored": restored}


def quarantine_delete(req: Request) -> dict[str, Any]:
    item_id = str(req.json().get("id", ""))
    try:
        vault.delete(item_id)
    except (ValueError, FileNotFoundError) as exc:
        raise ShieldError(404, str(exc)) from exc
    req.on_restore(item_id)
    return {"ok": True}


# ---------------------------------------------------------------- network
def network_scan(req: Request) -> dict[str, Any]:
    return _start(network.network_scan)


def wifi(req: Request) -> dict[str, Any]:
    return network.wifi_status()


def dns(req: Request) -> dict[str, Any]:
    return network.dns_check()


def firewall(req: Request) -> dict[str, Any]:
    return network.firewall_status()


def firewall_block(req: Request) -> dict[str, Any]:
    program = str(req.json().get("program", "")).strip('"')
    if not Path(program).is_absolute() or not Path(program).is_file():
        raise ShieldError(400, "Choose a program that exists.")
    try:
        return network.block_program(program)
    except ValueError as exc:
        raise ShieldError(400, str(exc)) from exc


def firewall_unblock(req: Request) -> dict[str, Any]:
    return network.unblock_program(str(req.json().get("program", "")))


def remote(req: Request) -> dict[str, Any]:
    return network.remote_access()


# ---------------------------------------------------------------- privacy
def browser(req: Request) -> dict[str, Any]:
    return {"items": privacy.browser_extensions()}


def devices(req: Request) -> dict[str, Any]:
    return {"webcam": privacy.device_access("webcam"), "microphone": privacy.device_access("microphone"),
            "usb_storage_blocked": system.usb_storage_blocked()}


def devices_set(req: Request) -> dict[str, Any]:
    data = req.json()
    cap = data.get("capability")
    if cap not in ("webcam", "microphone") or not isinstance(data.get("allowed"), bool):
        raise ShieldError(400, "expected {capability: webcam|microphone, allowed: bool}")
    return privacy.set_device_access(cap, data["allowed"])


def usb_set(req: Request) -> dict[str, Any]:
    blocked = req.json().get("blocked")
    if not isinstance(blocked, bool):
        raise ShieldError(400, "expected {blocked: bool}")
    out = system.fix("usb_block" if blocked else "usb_allow")
    out["usb_storage_blocked"] = system.usb_storage_blocked()
    return out


def email_check(req: Request) -> dict[str, Any]:
    raw = req.raw(25 * 1024 * 1024)
    if not raw:
        raise ShieldError(400, "empty message")
    return privacy.analyze_email(raw)


def breach(req: Request) -> dict[str, Any]:
    try:
        return privacy.breach_check(str(req.json().get("email", "")))
    except ValueError as exc:
        raise ShieldError(400, str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        raise ShieldError(502, str(exc)) from exc


def sensitive(req: Request) -> dict[str, Any]:
    data = req.json()
    folders = _paths(data["folders"]) if data.get("folders") else None
    return _start(lambda: privacy.sensitive_scan(folders))


def shred(req: Request) -> dict[str, Any]:
    data = req.json()
    method = data.get("method", "dod")
    if method not in privacy.SHRED_METHODS:
        raise ShieldError(400, "unknown method")
    if data.get("confirm") is not True:
        raise ShieldError(400, "confirm is required")
    return _start(lambda: privacy.shred(_paths(data.get("paths")), method))


def dnd(req: Request) -> dict[str, Any]:
    return privacy.dnd_state()


# ---------------------------------------------------------------- updates and troubleshooting
def update(req: Request) -> dict[str, Any]:
    return _start(updates.start)


def update_info(req: Request) -> dict[str, Any]:
    cfg = core.load_config()["updates"]
    job = core.running("update")
    return {"manifest": updates.manifest(), "auto": cfg["auto"], "last_update": cfg.get("last_update"),
            "job": job.id if job else None}


def diagnostics(req: Request) -> dict[str, Any]:
    import platform  # noqa: PLC0415

    return {"python": sys.version.split()[0], "os": platform.platform(), "admin": winutil.is_admin(),
            "data": str(core.CONFIG_PATH.parent), "intel": _intel_manifest(),
            "file_shield": realtime.SERVICE.file_shield.status(), "events": core.EVENTS.counter}


def reset(req: Request) -> dict[str, Any]:
    keep = core.load_config()["password"]
    config = core._default_config()  # noqa: SLF001
    config["password"] = keep
    core.save_config(config)
    realtime.SERVICE.apply(config)
    return core.public_config(config)


def clear_cache(req: Request) -> dict[str, Any]:
    from . import engine  # noqa: PLC0415

    engine.CACHE_PATH.unlink(missing_ok=True)
    engine._cache = None  # noqa: SLF001
    return {"ok": True}


ID = r"([0-9a-f]{32})"
# method, pattern, handler, password area (or ""), allowed on the public website
ROUTES: list[tuple[str, str, Callable[..., Any], str, bool]] = [
    ("GET", r"", overview, "", False),
    ("PUT", r"/config", config_put, "settings", False),
    ("POST", r"/unlock", unlock, "", False),
    ("POST", r"/password", password, "", False),
    ("GET", r"/events", events, "", False),
    ("DELETE", r"/events", events_clear, "settings", False),
    ("GET", rf"/jobs/{ID}", job_get, "", True),
    ("POST", rf"/jobs/{ID}/cancel", job_cancel, "", False),
    ("POST", r"/scan", scan, "", False),
    ("POST", r"/smart", smart, "", False),
    ("POST", r"/boot-scan", boot_scan, "shields", False),
    ("GET", r"/system", system_checks, "", False),
    ("POST", r"/fix", fix, "shields", False),
    ("GET", r"/startup", startup, "", False),
    ("POST", r"/startup/remove", startup_remove, "shields", False),
    ("GET", r"/processes", processes, "", False),
    ("GET", r"/quarantine", quarantine_list, "", False),
    ("POST", r"/quarantine/add", quarantine_add, "", False),
    ("POST", r"/quarantine/restore", quarantine_restore, "quarantine", False),
    ("POST", r"/quarantine/delete", quarantine_delete, "quarantine", False),
    ("POST", r"/network", network_scan, "", False),
    ("GET", r"/wifi", wifi, "", False),
    ("GET", r"/dns", dns, "", False),
    ("GET", r"/firewall", firewall, "", False),
    ("POST", r"/firewall/block", firewall_block, "shields", False),
    ("POST", r"/firewall/unblock", firewall_unblock, "shields", False),
    ("GET", r"/remote", remote, "", False),
    ("GET", r"/browser", browser, "", False),
    ("GET", r"/devices", devices, "", False),
    ("POST", r"/devices", devices_set, "shields", False),
    ("POST", r"/usb", usb_set, "shields", False),
    ("POST", r"/email", email_check, "", True),
    ("POST", r"/breach", breach, "", True),
    ("POST", r"/sensitive", sensitive, "", False),
    ("POST", r"/shred", shred, "", False),
    ("GET", r"/dnd", dnd, "", False),
    ("POST", r"/update", update, "settings", False),
    ("GET", r"/update", update_info, "", False),
    ("GET", r"/diagnostics", diagnostics, "", False),
    ("POST", r"/reset", reset, "settings", False),
    ("POST", r"/cache/clear", clear_cache, "settings", False),
]


def dispatch(method: str, subpath: str, req: Request, public: bool) -> Any:
    for route_method, pattern, handler, area, public_ok in ROUTES:
        if route_method != method:
            continue
        match = re.fullmatch(pattern, subpath)
        if not match:
            continue
        if public and not public_ok:
            raise ShieldError(403, "desktop_only")
        if area and not core.unlocked(req.unlock, area):
            raise ShieldError(423, "locked")
        return handler(req, *match.groups())
    raise ShieldError(404, "not found")
