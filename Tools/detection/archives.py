"""Threat-oriented inspection of ZIP-family containers: generic archives, Android APKs and
browser extensions (CRX/XPI/ZIP with manifest.json).

Archives are never extracted to disk. Member reads are capped individually and in total,
and compression ratios are checked from the central directory *and* enforced on the
actual decompressed stream, so a lying header cannot cause unbounded memory use.

Structural/CRC validation of archives is Guardian's ``core.file_integrity``; this module
looks only at what the archive *contains* (DECISIONS D-006).
"""
from __future__ import annotations

import io
import json
import re
import struct
import zipfile
from typing import Any, Callable

from detection.common import MAX_TOTAL_MEMBER_READ, MAX_ZIP_ENTRIES, MAX_ZIP_MEMBER_READ
from detection.documents import EXECUTABLE_NAME_RE, inspect_ooxml

AddFn = Callable[..., None]

SCRIPT_EXTENSIONS = (".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".wsf", ".sh")
DECOY_EXTENSIONS = r"(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp3|mp4|zip)"
DOUBLE_EXTENSION_RE = re.compile(rf"\.{DECOY_EXTENSIONS}[\s_.\-]*\.(?:exe|scr|com|pif|bat|cmd|vbs|js|jse|ps1|hta|lnk|msi|wsf)$", re.IGNORECASE)


def open_zip(data: bytes) -> zipfile.ZipFile | None:
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # hostile headers raise NotImplementedError, ValueError, OSError, struct.error, ...
        return None


class _ReadBudget:
    def __init__(self, total: int = MAX_TOTAL_MEMBER_READ):
        self.remaining = total

    def read(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = MAX_ZIP_MEMBER_READ) -> bytes | None:
        """Read at most ``limit`` decompressed bytes of a member; None on encryption or corruption."""
        if info.flag_bits & 0x1 or self.remaining <= 0:
            return None
        try:
            with archive.open(info) as handle:
                chunk = handle.read(min(limit, self.remaining))
        except Exception:  # corrupt member, unsupported method, CRC error: inspect what we can
            return None
        self.remaining -= len(chunk)
        return chunk


def classify_zip(archive: zipfile.ZipFile) -> str:
    names = {info.filename.lower() for info in archive.infolist()[:MAX_ZIP_ENTRIES]}
    if "[content_types].xml" in names:
        return "ooxml"
    if "androidmanifest.xml" in names and any(name.endswith(".dex") for name in names):
        return "apk"
    if "manifest.json" in names:
        return "browser-extension"
    return "archive"


def _unsafe_path(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return normalized.startswith("/") or bool(re.match(r"^[a-zA-Z]:", normalized)) or ".." in normalized.split("/")


def inspect_archive(archive: zipfile.ZipFile, add: AddFn, *, depth: int = 0) -> dict[str, Any]:
    from detection.script_rules import scan_script_text

    all_infos = archive.infolist()
    infos = all_infos[:MAX_ZIP_ENTRIES]
    details: dict[str, Any] = {"type": "archive", "entries": len(all_infos), "inspected_entries": len(infos)}
    if len(all_infos) > MAX_ZIP_ENTRIES:
        details["limitation"] = f"Only the first {MAX_ZIP_ENTRIES} of {len(all_infos)} entries were inspected."

    declared = sum(info.file_size for info in infos)
    compressed = sum(info.compress_size for info in infos) or 1
    details["declared_uncompressed_bytes"] = declared
    ratio = declared / compressed
    if declared > 1024 ** 3 or (ratio > 250 and declared > 100 * 1024 * 1024):
        add("high", "Potential decompression bomb", 50,
            f"The archive declares {declared:,} bytes when expanded (ratio {ratio:,.0f}:1); extracting it could exhaust disk or memory.")
    overlapping = len({(info.header_offset) for info in infos}) < len(infos)
    if overlapping:
        add("high", "Overlapping archive entries", 45, "Several entries share the same data offset, a technique used by non-recursive zip bombs.")

    traversal = [info.filename for info in infos if _unsafe_path(info.filename)]
    if traversal:
        add("high", "Archive path traversal entry", 55,
            f"Entry '{traversal[0][:120]}' would be written outside the extraction folder (Zip Slip).", entries=traversal[:10])

    executables = [info for info in infos if not info.is_dir() and EXECUTABLE_NAME_RE.search(info.filename)]
    doubles = [info.filename for info in infos if DOUBLE_EXTENSION_RE.search(info.filename.rsplit("/", 1)[-1])]
    encrypted = [info for info in infos if info.flag_bits & 0x1]
    details.update({
        "executable_entries": [info.filename for info in executables][:30],
        "encrypted_entries": len(encrypted),
    })
    if doubles:
        add("high", "Double-extension file in archive", 50,
            f"'{doubles[0][:120]}' disguises an executable as a document or image.", entries=doubles[:10])
    if executables:
        only = len([info for info in infos if not info.is_dir()]) <= 3
        add("medium" if only else "low", "Archive contains executable or script files", 30 if only else 15,
            f"{len(executables)} entry(ies) run code when opened, e.g. '{executables[0].filename[:100]}'"
            + (" — and little else is in the archive, the usual shape of a malicious attachment." if only else "."))
    if encrypted:
        if any(info.flag_bits & 0x1 for info in executables) or (executables and len(encrypted) == len(infos)):
            add("high", "Password-protected archive with executables", 40,
                "Executables inside an encrypted archive cannot be scanned in transit; this is a standard way to smuggle malware past mail filters.")
        else:
            add("low", "Encrypted archive entries", 10, f"{len(encrypted)} entry(ies) are encrypted and could not be inspected.")

    budget = _ReadBudget()
    nested: list[dict[str, Any]] = []
    script_hits = 0
    for info in infos:
        name = info.filename.lower()
        if info.is_dir() or info.flag_bits & 0x1:
            continue
        if name.endswith(SCRIPT_EXTENSIONS) and script_hits < 20:
            raw = budget.read(archive, info, 512 * 1024)
            if raw:
                script_hits += 1
                for finding in scan_script_text(raw.decode("utf-8", errors="replace")):
                    add(finding["severity"], f"{finding['label']} (in {info.filename.rsplit('/', 1)[-1][:60]})",
                        finding["contribution"], finding["explanation"], category="heuristic")
        elif name.endswith((".zip", ".docm", ".xlsm", ".jar", ".apk", ".docx", ".xlsx")) and depth < 2 and len(nested) < 5:
            raw = budget.read(archive, info, MAX_ZIP_MEMBER_READ * 4)
            inner = open_zip(raw) if raw else None
            if inner is not None:
                from detection.engine import _container_details
                nested.append({"entry": info.filename, **_container_details(inner, add, info.filename, depth + 1)})
    if nested:
        details["nested"] = nested
    return details


# ---------------------------------------------------------------------------
# Android binary XML (AXML)
# ---------------------------------------------------------------------------

_ANDROID_ATTR_IDS = {0x01010003: "name", 0x0101000F: "debuggable", 0x01010280: "allowBackup",
                     0x010104EC: "usesCleartextTraffic", 0x01010006: "permission", 0x01010010: "exported"}


def _axml_strings(data: bytes, offset: int) -> list[str]:
    _, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    count, _, flags, strings_start, _ = struct.unpack_from("<IIIII", data, offset + 8)
    if count > 200_000 or offset + chunk_size > len(data):
        raise ValueError("String pool out of bounds")
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, offset + header_size)
    base = offset + strings_start
    strings: list[str] = []
    for item in offsets:
        pos = base + item
        if pos >= offset + chunk_size:
            strings.append("")
            continue
        if utf8:
            length = data[pos]
            pos += 2 if length & 0x80 else 1
            length = data[pos]
            if length & 0x80:
                length = ((length & 0x7F) << 8) | data[pos + 1]
                pos += 1
            pos += 1
            strings.append(data[pos: pos + length].decode("utf-8", errors="replace"))
        else:
            length = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                pos += 2
            strings.append(data[pos: pos + length * 2].decode("utf-16-le", errors="replace"))
    return strings


def parse_axml(data: bytes) -> list[tuple[str, dict[str, Any]]]:
    """Return (tag, attributes) for every start element of a binary AndroidManifest.xml."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("Not binary XML")
    strings: list[str] = []
    resource_ids: list[int] = []
    elements: list[tuple[str, dict[str, Any]]] = []
    pos = struct.unpack_from("<H", data, 2)[0]
    guard = 0
    while pos + 8 <= len(data) and guard < 200_000:
        guard += 1
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_size < 8 or pos + chunk_size > len(data):
            break
        if chunk_type == 0x0001:
            strings = _axml_strings(data, pos)
        elif chunk_type == 0x0180:
            resource_ids = list(struct.unpack_from(f"<{(chunk_size - header_size) // 4}I", data, pos + header_size))
        elif chunk_type == 0x0102:
            name_index = struct.unpack_from("<I", data, pos + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, pos + 24)
            tag = strings[name_index] if name_index < len(strings) else ""
            attributes: dict[str, Any] = {}
            base = pos + 16 + attr_start
            for index in range(min(attr_count, 256)):
                at = base + index * max(attr_size, 20)
                if at + 20 > pos + chunk_size:
                    break
                _, attr_name, raw_value, _, _, data_type, value = struct.unpack_from("<IIIHBBI", data, at)
                key = strings[attr_name] if attr_name < len(strings) else ""
                if not key and attr_name < len(resource_ids):
                    key = _ANDROID_ATTR_IDS.get(resource_ids[attr_name], "")
                if raw_value != 0xFFFFFFFF and raw_value < len(strings):
                    attributes[key] = strings[raw_value]
                elif data_type == 0x12:
                    attributes[key] = value != 0
                elif data_type == 0x03 and value < len(strings):
                    attributes[key] = strings[value]
                else:
                    attributes[key] = value
            elements.append((tag, attributes))
        pos += chunk_size
    return elements


# (weight, short reason). Weights are small: many legitimate apps use several of these.
DANGEROUS_PERMISSIONS = {
    "SEND_SMS": (15, "send SMS (premium-rate fraud)"), "RECEIVE_SMS": (12, "receive SMS (OTP interception)"),
    "READ_SMS": (12, "read SMS (OTP theft)"), "READ_CALL_LOG": (8, "read call log"), "PROCESS_OUTGOING_CALLS": (10, "redirect calls"),
    "CALL_PHONE": (5, "place calls"), "READ_CONTACTS": (5, "read contacts"), "RECORD_AUDIO": (5, "record audio"),
    "CAMERA": (3, "use the camera"), "ACCESS_FINE_LOCATION": (3, "precise location"), "ACCESS_BACKGROUND_LOCATION": (8, "background location"),
    "SYSTEM_ALERT_WINDOW": (15, "draw over other apps (overlay attacks)"), "REQUEST_INSTALL_PACKAGES": (15, "install other apps"),
    "REQUEST_DELETE_PACKAGES": (8, "uninstall apps"), "QUERY_ALL_PACKAGES": (5, "enumerate installed apps"),
    "PACKAGE_USAGE_STATS": (8, "monitor app usage"), "READ_PHONE_STATE": (5, "read phone identity"),
    "WRITE_SETTINGS": (5, "change system settings"), "MANAGE_EXTERNAL_STORAGE": (5, "access all files"),
    "RECEIVE_BOOT_COMPLETED": (3, "start at boot"), "DISABLE_KEYGUARD": (8, "disable the lock screen"),
    "USE_FULL_SCREEN_INTENT": (5, "full-screen interruptions"), "BIND_DEVICE_ADMIN": (25, "device administrator"),
    "BIND_ACCESSIBILITY_SERVICE": (25, "accessibility service (reads and controls the screen)"),
    "BIND_NOTIFICATION_LISTENER_SERVICE": (15, "read all notifications (OTP theft)"),
}


def inspect_apk(archive: zipfile.ZipFile, add: AddFn) -> dict[str, Any]:
    budget = _ReadBudget()
    infos = archive.infolist()[:MAX_ZIP_ENTRIES]
    names = [info.filename for info in infos]
    details: dict[str, Any] = {"type": "apk"}
    manifest_info = next((info for info in infos if info.filename == "AndroidManifest.xml"), None)
    raw = budget.read(archive, manifest_info, 4 * 1024 * 1024) if manifest_info else None
    elements: list[tuple[str, dict[str, Any]]] = []
    if raw:
        try:
            elements = parse_axml(raw)
        except (ValueError, struct.error, IndexError):
            add("medium", "Malformed Android manifest", 20,
                "AndroidManifest.xml could not be parsed; malformed manifests are used to break analysis tools while Android still installs the app.")

    if raw and not any(tag == "manifest" for tag, _ in elements):
        # add() ignores duplicates, so this is a no-op when the parse error above already reported it.
        add("medium", "Malformed Android manifest", 20,
            "AndroidManifest.xml has no <manifest> element; malformed manifests are used to break analysis tools.")
    permissions: set[str] = set()
    services_bind: set[str] = set()
    receiver_actions: set[str] = set()
    application: dict[str, Any] = {}
    package = ""
    for tag, attributes in elements:
        name = str(attributes.get("name", ""))
        if tag == "manifest":
            package = str(attributes.get("package", ""))
        elif tag in {"uses-permission", "uses-permission-sdk-23"} and name:
            permissions.add(name.rsplit(".", 1)[-1])
        elif tag == "application":
            application = attributes
        elif tag == "service" and attributes.get("permission"):
            services_bind.add(str(attributes["permission"]).rsplit(".", 1)[-1])
        elif tag == "action" and name:
            receiver_actions.add(name.rsplit(".", 1)[-1])
    capabilities = permissions | services_bind
    details.update({
        "package": package, "permissions": sorted(permissions)[:200], "bound_services": sorted(services_bind),
        "intent_actions": sorted(receiver_actions)[:100], "dex_files": [n for n in names if n.endswith(".dex")][:20],
    })

    risky = {perm: DANGEROUS_PERMISSIONS[perm] for perm in capabilities if perm in DANGEROUS_PERMISSIONS}
    if risky:
        total = sum(value[0] for value in risky.values())
        # Below 10 the permissions are ordinary for consumer apps (camera, location, boot): context only.
        weight = min(35, total) if total >= 10 else 0
        add("medium" if weight >= 20 else "low" if weight else "info", "Sensitive Android permissions", weight,
            f"The app can {', '.join(reason for _, reason in list(risky.values())[:6])}.", permissions=sorted(risky))
    if "BIND_ACCESSIBILITY_SERVICE" in capabilities and ("SYSTEM_ALERT_WINDOW" in capabilities or {"READ_SMS", "RECEIVE_SMS"} & capabilities):
        add("high", "Accessibility + overlay/SMS combination", 50,
            "An accessibility service combined with screen overlays or SMS access is the core toolkit of Android banking trojans.")
    elif {"RECEIVE_SMS", "READ_SMS"} & capabilities and "INTERNET" in permissions and "BIND_NOTIFICATION_LISTENER_SERVICE" in capabilities:
        add("high", "OTP interception capability", 40, "The app can read SMS and notifications and has network access.")
    if "BIND_DEVICE_ADMIN" in capabilities and "SEND_SMS" in capabilities:
        add("high", "Device admin + SMS sending", 40, "Device-administrator rights with SMS sending are typical of SMS-fraud and ransomware apps.")
    if application.get("debuggable") is True:
        add("low", "Debuggable release build", 10, "android:debuggable=true lets anyone attach a debugger to the app.")
    if application.get("usesCleartextTraffic") is True:
        add("low", "Cleartext network traffic allowed", 5, "The app permits unencrypted HTTP traffic.")
    if "BOOT_COMPLETED" in receiver_actions and "BIND_ACCESSIBILITY_SERVICE" in capabilities:
        add("medium", "Starts at boot with accessibility access", 15, "Persistence at boot combined with accessibility control.")

    hidden_code = [n for n in names if n.lower().startswith(("assets/", "res/raw/")) and n.lower().endswith((".dex", ".jar", ".apk", ".so"))]
    if hidden_code:
        add("medium", "Secondary code hidden in assets", 25,
            f"Executable code is stored as an asset ('{hidden_code[0][:100]}'); droppers and packers load such code at run time.",
            files=hidden_code[:10])
    signed_v1 = any(re.match(r"META-INF/[^/]+\.(?:RSA|DSA|EC)$", n, re.IGNORECASE) for n in names)
    details["v1_signature"] = signed_v1
    return details


# ---------------------------------------------------------------------------
# Browser extensions
# ---------------------------------------------------------------------------

_EXTENSION_PERMISSIONS = {
    "<all_urls>": (20, "read and change data on every website"), "*://*/*": (20, "read and change data on every website"),
    "http://*/*": (15, "access every HTTP site"), "https://*/*": (15, "access every HTTPS site"),
    "webRequestBlocking": (15, "intercept and modify web traffic"), "webRequest": (8, "observe web traffic"),
    "declarativeNetRequestWithHostAccess": (8, "rewrite requests"), "cookies": (12, "read cookies (session theft)"),
    "history": (8, "read browsing history"), "tabs": (5, "see open tabs and URLs"), "nativeMessaging": (15, "talk to native programs"),
    "debugger": (20, "use the debugger protocol on pages"), "management": (12, "manage other extensions"),
    "proxy": (15, "redirect all traffic through a proxy"), "clipboardRead": (10, "read the clipboard"),
    "downloads": (5, "download files"), "privacy": (8, "change privacy settings"), "scripting": (8, "inject scripts"),
    "desktopCapture": (10, "capture the screen"), "webNavigation": (5, "track navigation"), "identity": (8, "access sign-in identity"),
}


def inspect_browser_extension(archive: zipfile.ZipFile, add: AddFn) -> dict[str, Any]:
    budget = _ReadBudget()
    info = next((item for item in archive.infolist()[:MAX_ZIP_ENTRIES] if item.filename.lower() == "manifest.json"), None)
    raw = budget.read(archive, info, 1024 * 1024) if info else None
    details: dict[str, Any] = {"type": "browser-extension"}
    try:
        manifest = json.loads((raw or b"{}").decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError):
        add("low", "Malformed extension manifest", 10, "manifest.json is not valid JSON.")
        return details
    if not isinstance(manifest, dict):
        return details
    requested: set[str] = set()
    for key in ("permissions", "optional_permissions", "host_permissions"):
        value = manifest.get(key)
        if isinstance(value, list):
            requested.update(str(item) for item in value[:500])
    content_matches: set[str] = set()
    for script in manifest.get("content_scripts", []) if isinstance(manifest.get("content_scripts"), list) else []:
        if isinstance(script, dict) and isinstance(script.get("matches"), list):
            content_matches.update(str(item) for item in script["matches"][:100])
    details.update({
        "name": str(manifest.get("name", ""))[:200], "version": str(manifest.get("version", ""))[:50],
        "manifest_version": manifest.get("manifest_version"), "permissions": sorted(requested)[:200],
        "content_script_matches": sorted(content_matches)[:50],
    })
    risky = {perm: _EXTENSION_PERMISSIONS[perm] for perm in requested if perm in _EXTENSION_PERMISSIONS}
    all_sites = bool({"<all_urls>", "*://*/*", "http://*/*", "https://*/*"} & (requested | content_matches))
    if risky:
        weight = min(35, sum(value[0] for value in risky.values()))
        add("medium" if weight >= 20 else "low", "Powerful browser-extension permissions", weight,
            f"The extension can {', '.join(reason for _, reason in list(risky.values())[:6])}.", permissions=sorted(risky))
    if all_sites and {"cookies", "webRequest", "webRequestBlocking"} & requested:
        add("high", "Extension can harvest sessions on all sites", 40,
            "Access to every site plus cookies/web-request APIs is enough to steal logged-in sessions.")
    csp = json.dumps(manifest.get("content_security_policy", ""))
    if "unsafe-eval" in csp or re.search(r"script-src[^;\"]*https?://", csp):
        add("medium", "Weakened extension CSP", 20, "The content security policy allows eval or remote scripts, enabling code that was never reviewed.")
    if isinstance(manifest.get("externally_connectable"), dict) and "<all_urls>" in json.dumps(manifest["externally_connectable"]):
        add("medium", "Any website can message the extension", 15, "externally_connectable allows every site to send it messages.")
    if manifest.get("update_url") and "google.com" not in str(manifest.get("update_url")) and "mozilla" not in str(manifest.get("update_url")):
        add("low", "Off-store update URL", 10, f"The extension updates from '{str(manifest['update_url'])[:100]}', outside the official store.")
    return details
