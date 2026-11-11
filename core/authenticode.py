"""Is a Windows program signed, and does the signature check out?

Static only: Windows' own WinVerifyTrust reads the file's embedded signature,
or, for system files signed through a catalog, looks the file's hash up in
the installed catalogs. Nothing is run, no window is shown, and no network
lookup happens (revocation checks are off and URL retrieval is cache-only),
so the answer is "the signature is intact and chains to a trusted root on
this machine", not "the publisher is still in good standing".
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

_ACTION = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"  # WINTRUST_ACTION_GENERIC_VERIFY_V2


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


def _guid(text: str) -> _GUID:
    import uuid

    value = uuid.UUID(text)
    guid = _GUID()
    guid.Data1, guid.Data2, guid.Data3 = value.time_low, value.time_mid, value.time_hi_version
    guid.Data4[:] = list(value.bytes[8:])
    return guid


class _FileInfo(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class _CatalogInfo(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD), ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                ("pcwszMemberTag", wintypes.LPCWSTR), ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD), ("pcCatalogContext", ctypes.c_void_p),
                ("hCatAdmin", wintypes.HANDLE)]


class _TrustData(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p), ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", wintypes.DWORD), ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class _CatalogDetails(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


_UI_NONE, _REVOKE_NONE, _CHOICE_FILE, _CHOICE_CATALOG = 2, 0, 1, 2
_VERIFY, _CLOSE = 1, 2
_FLAGS = 0x1000 | 0x10  # cache-only URL retrieval, no revocation check


def _trust(choice: int, info) -> bool:
    wintrust = ctypes.WinDLL("wintrust")
    data = _TrustData()
    data.cbStruct = ctypes.sizeof(_TrustData)
    data.dwUIChoice, data.fdwRevocationChecks, data.dwUnionChoice = _UI_NONE, _REVOKE_NONE, choice
    data.pInfo = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction, data.dwProvFlags = _VERIFY, _FLAGS
    action = _guid(_ACTION)
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(_GUID), ctypes.c_void_p]
    wintrust.WinVerifyTrust.restype = wintypes.LONG
    result = wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    data.dwStateAction = _CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    return result == 0


def _catalog_signed(path: str) -> bool:
    """System files are often signed through a catalog rather than inside the file."""
    wintrust, kernel = ctypes.WinDLL("wintrust"), ctypes.WinDLL("kernel32")
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    handle = kernel.CreateFileW(path, 0x80000000, 1, None, 3, 0, None)  # GENERIC_READ, share read, OPEN_EXISTING
    if handle in (None, ctypes.c_void_p(-1).value):
        return False
    admin = wintypes.HANDLE()
    catalog = None
    try:
        wintrust.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD]
        if not wintrust.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, "SHA256", None, 0):
            return False
        size = wintypes.DWORD(0)
        wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD]
        wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, handle, ctypes.byref(size), None, 0)
        if not size.value:
            return False
        digest = (ctypes.c_ubyte * size.value)()
        if not wintrust.CryptCATAdminCalcHashFromFileHandle2(admin, handle, ctypes.byref(size), digest, 0):
            return False
        wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
        wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        catalog = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size, 0, None)
        if not catalog:
            return False
        details = _CatalogDetails()
        details.cbStruct = ctypes.sizeof(_CatalogDetails)
        wintrust.CryptCATCatalogInfoFromContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        if not wintrust.CryptCATCatalogInfoFromContext(catalog, ctypes.byref(details), 0):
            return False
        tag = "".join(f"{b:02X}" for b in digest)
        info = _CatalogInfo()
        info.cbStruct = ctypes.sizeof(_CatalogInfo)
        info.pcwszCatalogFilePath = details.wszCatalogFile
        info.pcwszMemberTag = tag
        info.pcwszMemberFilePath = path
        info.hMemberFile = handle
        info.pbCalculatedFileHash = ctypes.cast(digest, ctypes.c_void_p)
        info.cbCalculatedFileHash = size.value
        info.hCatAdmin = admin
        return _trust(_CHOICE_CATALOG, info)
    finally:
        if catalog:
            wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
            wintrust.CryptCATAdminReleaseCatalogContext(admin, catalog, 0)
        if admin:
            wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            wintrust.CryptCATAdminReleaseContext(admin, 0)
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle(handle)


def verify(path: str) -> str:
    """"valid" (embedded), "valid-catalog", "unsigned or invalid", or "unavailable" off Windows."""
    if sys.platform != "win32":
        return "unavailable"
    try:
        info = _FileInfo()
        info.cbStruct = ctypes.sizeof(_FileInfo)
        info.pcwszFilePath = path
        if _trust(_CHOICE_FILE, info):
            return "valid"
        if _catalog_signed(path):
            return "valid-catalog"
        return "unsigned or invalid"
    except (OSError, AttributeError, ValueError):
        return "unavailable"
