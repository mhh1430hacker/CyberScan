"""Small, careful helpers for talking to Windows.

Every command runs without a shell, with a timeout and no console window, and its
output is decoded leniently. Nothing here raises for an ordinary failure: callers get
``None``/empty values and decide what to tell the user.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def run(args: list[str], timeout: float = 20.0, input_text: str | None = None) -> tuple[int, str]:
    """Run a program; returns (exit code, stdout+stderr). -1 when it could not run."""
    try:
        done = subprocess.run(  # noqa: S603 - fixed argument lists, never a shell
            args, capture_output=True, timeout=timeout, input=input_text.encode() if input_text else None,
            creationflags=NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    raw = done.stdout + (b"\n" + done.stderr if done.stderr else b"")
    for enc in ("utf-8", "mbcs" if IS_WINDOWS else "latin-1"):
        try:
            return done.returncode, raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return done.returncode, raw.decode("latin-1", "replace")


def powershell(script: str, timeout: float = 30.0) -> tuple[int, str]:
    """Run a PowerShell snippet (UTF-8 output). The script is a constant written in this
    package; user data is never interpolated into it."""
    if not IS_WINDOWS:
        return -1, ""
    prelude = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';"
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prelude + script], timeout)


def with_params(script: str, params: dict[str, Any] | None) -> str:
    """Prefix a script with ``$P``: the parameters as base64 JSON. User data reaches
    PowerShell only this way, so no quoting mistake can turn it into code."""
    if not params:
        return script
    blob = base64.b64encode(json.dumps(params, ensure_ascii=False).encode("utf-8")).decode("ascii")
    return f"$P=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{blob}'))|ConvertFrom-Json;" + script


def elevated(script: str, params: dict[str, Any] | None = None, timeout: float = 120.0) -> tuple[bool, str]:
    """Run a script as administrator. Windows shows its UAC prompt; returns (ok, message).
    Already elevated: runs directly."""
    if not IS_WINDOWS:
        return False, "Windows only"
    body = with_params(script, params)
    if is_admin():
        code, out = powershell(body, timeout)
        return code == 0, out.strip()
    encoded = base64.b64encode(("$ErrorActionPreference='Stop';try{" + body + ";exit 0}catch{exit 1}").encode("utf-16-le")).decode("ascii")
    outer = ("try{$p=Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru "
             f"-ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{encoded}';"
             "exit $p.ExitCode}catch{Write-Output 'cancelled';exit 1223}")
    code, out = powershell(outer, timeout)
    if code == 1223 or "cancelled" in out:
        return False, "cancelled"
    return code == 0, out.strip()


def powershell_json(script: str, timeout: float = 30.0, params: dict[str, Any] | None = None) -> Any:
    """Run a snippet that ends with ConvertTo-Json; returns the parsed value or None."""
    code, out = powershell(with_params(script, params), timeout)
    text = out.strip()
    if not text:
        return None
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except ValueError:
        return None


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_admin() -> bool:
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def reg_read(root: str, path: str, name: str) -> Any:
    """Read one registry value; root is 'HKLM' or 'HKCU'. None when absent."""
    if not IS_WINDOWS:
        return None
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if root == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def reg_values(root: str, path: str) -> dict[str, Any]:
    if not IS_WINDOWS:
        return {}
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if root == "HKLM" else winreg.HKEY_CURRENT_USER
    out: dict[str, Any] = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                out[name] = value
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(root: str, path: str) -> list[str]:
    if not IS_WINDOWS:
        return []
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if root == "HKLM" else winreg.HKEY_CURRENT_USER
    names: list[str] = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return names


def reg_write(root: str, path: str, name: str, value: Any, kind: str = "sz") -> bool:
    if not IS_WINDOWS:
        return False
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if root == "HKLM" else winreg.HKEY_CURRENT_USER
    reg_type = {"sz": winreg.REG_SZ, "dword": winreg.REG_DWORD}[kind]
    try:
        with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, name, 0, reg_type, value)
        return True
    except OSError:
        return False


def reg_delete(root: str, path: str, name: str) -> bool:
    if not IS_WINDOWS:
        return False
    import winreg  # noqa: PLC0415

    hive = winreg.HKEY_LOCAL_MACHINE if root == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.DeleteValue(key, name)
        return True
    except OSError:
        return False


def known_folder(name: str) -> Path:
    home = Path.home()
    mapping = {
        "downloads": home / "Downloads", "desktop": home / "Desktop", "documents": home / "Documents",
        "pictures": home / "Pictures", "videos": home / "Videos", "music": home / "Music",
        "temp": Path(os.environ.get("TEMP") or os.environ.get("TMP") or home / "AppData" / "Local" / "Temp"),
        "appdata": Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming"),
        "localappdata": Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local"),
        "startup": Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming") / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        "common_startup": Path(os.environ.get("PROGRAMDATA") or "C:/ProgramData") / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
    }
    folder = mapping[name]
    if name in ("documents", "desktop", "pictures") and IS_WINDOWS:
        # OneDrive may have moved the folder; the shell knows where it is now
        shell = reg_values("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        key = {"documents": "Personal", "desktop": "Desktop", "pictures": "My Pictures"}[name]
        value = shell.get(key)
        if isinstance(value, str) and value:
            moved = Path(os.path.expandvars(value))
            if moved.is_dir():
                folder = moved
    return folder


# Places a user should never be able to shred or treat as "their" files.
def protected_path(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return True
    if resolved.parent == resolved:          # a drive root
        return True
    blocked = [os.environ.get("SystemRoot", r"C:\Windows"), os.environ.get("ProgramFiles", r"C:\Program Files"),
               os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), os.environ.get("ProgramData", r"C:\ProgramData"),
               str(Path(__file__).resolve().parents[2])]
    text = str(resolved).casefold()
    for item in blocked:
        if item and (text == item.casefold() or text.startswith(item.casefold().rstrip("\\/") + os.sep)):
            return True
    return resolved == Path.home().resolve()


def fullscreen_busy() -> bool:
    """True while a full-screen game, video or presentation is in front (Windows asks
    apps to stay quiet then)."""
    if not IS_WINDOWS:
        return False
    state = ctypes.c_int(0)
    try:
        if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) != 0:
            return False
    except Exception:  # noqa: BLE001
        return False
    # 2 busy (full-screen app), 3 running a D3D full-screen app, 4 presentation mode, 7 quiet time not counted
    return state.value in (2, 3, 4)


def open_uri(uri: str) -> bool:
    """Open a Windows settings page (ms-settings:, windowsdefender:) — fixed URIs only."""
    if not IS_WINDOWS or not uri.startswith(("ms-settings:", "windowsdefender:")):
        return False
    try:
        os.startfile(uri)  # noqa: S606
        return True
    except OSError:
        return False


def drives(kind: str = "fixed") -> list[Path]:
    """Fixed (3) or removable (2) drives."""
    if not IS_WINDOWS:
        return [Path("/")] if kind == "fixed" else []
    wanted = {"fixed": 3, "removable": 2}[kind]
    out = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if mask & (1 << i):
            root = f"{chr(65 + i)}:\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) == wanted:
                out.append(Path(root))
    return out
