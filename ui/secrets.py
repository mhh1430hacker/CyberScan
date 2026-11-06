"""Online-lookup keys, stored encrypted for the current Windows user.

Keys are encrypted with DPAPI (CryptProtectData, user scope): only the same
Windows account on the same machine can read them. They are handed to the
intelligence engine through this process's environment
(``ABUSECH_AUTH_KEY``, ``OTX_API_KEY``), which the engine already reads; they
are never written to settings, reports or logs. Where DPAPI is not available
the keys are not stored at all.
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path

KEY_ENV = {"abusech": "ABUSECH_AUTH_KEY", "otx": "OTX_API_KEY"}
_ENTROPY = b"CyberScan online lookup keys v1"


class SecretsUnavailable(RuntimeError):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _crypt(function_name: str, data: bytes) -> bytes:
    if sys.platform != "win32":
        raise SecretsUnavailable("Encrypted key storage needs Windows.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = getattr(crypt32, function_name)
    function.argtypes = [
        ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.POINTER(_Blob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob),
    ]
    function.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    source, _keep = _blob(data)
    entropy, _keep_entropy = _blob(_ENTROPY)
    output = _Blob()
    description = None if function_name == "CryptUnprotectData" else ctypes.c_wchar_p("CyberScan")
    ok = function(ctypes.byref(source), description, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(output))
    if not ok:
        raise SecretsUnavailable(f"{function_name} failed ({ctypes.get_last_error()}).")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(output.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    return _crypt("CryptProtectData", data)


def unprotect(data: bytes) -> bytes:
    return _crypt("CryptUnprotectData", data)


class SecretStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, str]:
        if not self.path.is_file():
            return {}
        try:
            document = json.loads(unprotect(self.path.read_bytes()).decode("utf-8"))
        except (OSError, ValueError, SecretsUnavailable):
            return {}
        return {key: str(value) for key, value in document.items() if key in KEY_ENV and value}

    def save(self, keys: dict[str, str]) -> None:
        clean = {key: value.strip() for key, value in keys.items() if key in KEY_ENV and value and value.strip()}
        if not clean:
            self.path.unlink(missing_ok=True)
            return
        payload = protect(json.dumps(clean).encode("utf-8"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_bytes(payload)
        temporary.replace(self.path)


_applied: dict[str, str] = {}


def apply_to_environment(keys: dict[str, str]) -> None:
    """Expose stored keys to the engine in this process only. A key removed
    here is also removed from the environment, unless the user set it there."""
    for key, variable in KEY_ENV.items():
        value = keys.get(key, "")
        if value:
            os.environ[variable] = value
            _applied[variable] = value
        elif variable in _applied:
            if os.environ.get(variable) == _applied.pop(variable):
                os.environ.pop(variable, None)
