"""Read-only collection of local system state for the system tools, when ``source: "local"`` is asked for.

Every collector returns data in the same shape a user would supply, so the analysis code is identical
for both sources. Nothing here writes, changes settings, needs administrator rights by design, or runs
anything except fixed, read-only query commands (``netsh ... show``, ``schtasks /query``) with timeouts.
On an unsupported platform the collectors raise ``Unsupported``.
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from security_toolkit.core import Unavailable, Unsupported

RUN_KEYS = [
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKEY_LOCAL_MACHINE", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]
UNINSTALL_KEYS = [
    ("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKEY_LOCAL_MACHINE", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def is_windows() -> bool:
    return platform.system() == "Windows"


def _winreg():
    if not is_windows():
        raise Unsupported("local collection of this data is only implemented on Windows; supply an export instead.")
    import winreg

    return winreg


def _hive(winreg, name):
    return {"HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE, "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER}[name]


def read_values(hive: str, path: str) -> dict[str, Any]:
    """All values of one key ({} if the key is absent or unreadable)."""
    winreg = _winreg()
    values: dict[str, Any] = {}
    try:
        with winreg.OpenKey(_hive(winreg, hive), path, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                values[name.lower()] = value
                index += 1
    except OSError:
        return {}
    return values


def subkeys(hive: str, path: str, limit: int = 5000) -> list[str]:
    winreg = _winreg()
    names: list[str] = []
    try:
        with winreg.OpenKey(_hive(winreg, hive), path, 0, winreg.KEY_READ) as key:
            while len(names) < limit:
                try:
                    names.append(winreg.EnumKey(key, len(names)))
                except OSError:
                    break
    except OSError:
        return []
    return names


def run_entries() -> list[dict[str, str]]:
    entries = []
    for hive, path in RUN_KEYS:
        for name, value in read_values(hive, path).items():
            entries.append({"location": f"{hive}\\{path}", "name": name, "command": str(value)})
    for folder in startup_folders():
        try:
            for item in Path(folder).iterdir():
                if item.is_file() and item.name.lower() != "desktop.ini":
                    entries.append({"location": folder, "name": item.name, "command": str(item)})
        except OSError:
            continue
    return entries


def startup_folders() -> list[str]:
    folders = []
    appdata, programdata = os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")
    if appdata:
        folders.append(str(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup"))
    if programdata:
        folders.append(str(Path(programdata) / "Microsoft/Windows/Start Menu/Programs/StartUp"))
    return folders


def installed_software() -> list[dict[str, str]]:
    out = []
    for hive, path in UNINSTALL_KEYS:
        for sub in subkeys(hive, path):
            values = read_values(hive, f"{path}\\{sub}")
            name = values.get("displayname")
            if name and not values.get("systemcomponent"):
                out.append({"name": str(name), "version": str(values.get("displayversion", "")),
                            "publisher": str(values.get("publisher", "")), "install_location": str(values.get("installlocation", ""))})
    return out


def os_version() -> dict[str, Any]:
    values = read_values("HKEY_LOCAL_MACHINE", r"Software\Microsoft\Windows NT\CurrentVersion")
    return {"product_name": str(values.get("productname", "")), "display_version": str(values.get("displayversion", "")),
            "build": int(values.get("currentbuildnumber") or values.get("currentbuild") or 0), "ubr": int(values.get("ubr") or 0),
            "edition": str(values.get("editionid", ""))}


def run_readonly(arguments: list[str], timeout: float) -> str:
    """Run one fixed read-only query command. Callers pass only literal argument lists."""
    if not is_windows():
        raise Unsupported("this local query is only implemented on Windows; supply an export instead.")
    try:
        completed = subprocess.run(arguments, capture_output=True, timeout=max(1.0, timeout), check=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError as exc:
        raise Unavailable(f"{arguments[0]} is not available on this system.") from exc
    except subprocess.TimeoutExpired as exc:
        raise Unavailable(f"{arguments[0]} did not finish in time.") from exc
    for encoding in ("utf-8", "mbcs", "cp437"):
        try:
            return completed.stdout.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return completed.stdout.decode("utf-8", errors="replace")


def processes(limit: int = 3000) -> list[dict[str, Any]]:
    try:
        import psutil
    except ImportError as exc:
        raise Unavailable("psutil is required to list local processes (pip install psutil).") from exc
    out = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
        info = proc.info
        try:
            parent = psutil.Process(info["ppid"]).name() if info.get("ppid") else ""
        except (psutil.Error, OSError):
            parent = ""
        out.append({"pid": info.get("pid"), "name": info.get("name") or "", "exe": info.get("exe") or "",
                    "cmdline": " ".join(info.get("cmdline") or []), "parent": parent, "user": info.get("username") or ""})
        if len(out) >= limit:
            break
    return out
