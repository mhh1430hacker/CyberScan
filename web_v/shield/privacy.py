"""Privacy tools.

    browser_extensions   add-ons in Chrome, Edge, Brave, Opera, Vivaldi and Firefox, with
                         what each may do and whether it came from the official store
    camera / microphone  which apps used them and when (Windows' own privacy records),
                         and the switch that allows or denies them for this account
    analyze_email        a saved message (.eml): forged senders, failed SPF/DKIM/DMARC,
                         lookalike and known-bad links, risky attachments
    shred                overwrite files before deleting them
    breach_check         has an e-mail address appeared in public data breaches
    sensitive_scan       documents that contain card numbers, IBANs, keys or passwords
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import json
import os
import re
import secrets
import ssl
import time
import urllib.parse
import urllib.request
from email.utils import parseaddr
from pathlib import Path
from typing import Any

from . import core, engine, winutil

# ---------------------------------------------------------------- browser add-ons
CHROMIUM = {
    "Chrome": r"Google\Chrome\User Data", "Edge": r"Microsoft\Edge\User Data", "Brave": r"BraveSoftware\Brave-Browser\User Data",
    "Vivaldi": r"Vivaldi\User Data", "Chromium": r"Chromium\User Data",
}
OPERA = r"Opera Software\Opera Stable"
DANGEROUS_PERMS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "webRequestBlocking", "debugger", "nativeMessaging",
                   "proxy", "management", "cookies", "history", "clipboardRead", "desktopCapture", "privacy",
                   "declarativeNetRequestWithHostAccess", "webRequest", "scripting", "downloads", "tabCapture"}
SEVERE = {"debugger", "nativeMessaging", "proxy", "management", "<all_urls>", "*://*/*"}


def _manifest_name(folder: Path, value: str) -> str:
    if not value.startswith("__MSG_"):
        return value
    key = value[6:-2].lower()
    for loc in ("en", "en_US", "en_GB"):
        try:
            data = json.loads((folder / "_locales" / loc / "messages.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        for k, v in data.items():
            if k.lower() == key and isinstance(v, dict):
                return str(v.get("message", value))
    return value


def _profiles(root: Path) -> list[Path]:
    return [p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))] if root.is_dir() else []


def browser_extensions() -> list[dict[str, Any]]:
    local = winutil.known_folder("localappdata")
    roaming = winutil.known_folder("appdata")
    items: list[dict[str, Any]] = []
    roots = [(name, local / rel) for name, rel in CHROMIUM.items()] + [("Opera", roaming / OPERA)]
    for browser, root in roots:
        profiles = _profiles(root) if browser != "Opera" else ([root] if root.is_dir() else [])
        for profile in profiles:
            prefs: dict[str, Any] = {}
            for prefs_name in ("Secure Preferences", "Preferences"):
                try:
                    data = json.loads((profile / prefs_name).read_text(encoding="utf-8"))
                    prefs.update(data.get("extensions", {}).get("settings", {}) or {})
                except (OSError, ValueError):
                    pass
            ext_root = profile / "Extensions"
            if not ext_root.is_dir():
                continue
            for ext_dir in ext_root.iterdir():
                versions = sorted([v for v in ext_dir.iterdir() if v.is_dir()], key=lambda p: p.name) if ext_dir.is_dir() else []
                if not versions:
                    continue
                folder = versions[-1]
                try:
                    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8-sig"))
                except (OSError, ValueError):
                    continue
                if manifest.get("theme"):
                    continue
                setting = prefs.get(ext_dir.name, {})
                perms = [p for p in manifest.get("permissions", []) + manifest.get("host_permissions", [])
                         + manifest.get("optional_permissions", []) if isinstance(p, str)]
                for cs in manifest.get("content_scripts", []) or []:
                    perms += [m for m in cs.get("matches", []) if isinstance(m, str)]
                update_url = str(manifest.get("update_url", ""))
                store = ("google.com" in update_url or "microsoft.com" in update_url or "edge.microsoft" in update_url
                         or "opera.com" in update_url)
                location = setting.get("location")
                items.append(_assess_ext({
                    "browser": browser, "profile": profile.name, "id": ext_dir.name,
                    "name": _manifest_name(folder, str(manifest.get("name", ext_dir.name)))[:120],
                    "version": str(manifest.get("version", "")), "mv": manifest.get("manifest_version"),
                    "permissions": sorted(set(perms))[:60], "store": store, "path": str(folder),
                    "enabled": setting.get("state", 1) == 1 if "state" in setting else not setting.get("disable_reasons"),
                    # Chrome's install locations: 2/3/6 another program added it, 4/8 unpacked (developer mode)
                    "sideloaded": location in (4, 8) or (not store and location not in (5, 10) and not setting.get("was_installed_by_default")),
                    "by_program": location in (2, 3, 6),
                    "installed": setting.get("first_install_time") or setting.get("install_time"),
                }))
    items += _firefox(roaming)
    order = {"bad": 0, "warn": 1, "ok": 2}
    return sorted(items, key=lambda e: (order[e["risk"]], e["browser"], e["name"].lower()))


def _firefox(roaming: Path) -> list[dict[str, Any]]:
    root = roaming / "Mozilla" / "Firefox" / "Profiles"
    out = []
    if not root.is_dir():
        return out
    for profile in root.iterdir():
        try:
            data = json.loads((profile / "extensions.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for addon in data.get("addons", []):
            if addon.get("type") != "extension" or addon.get("location") in ("app-builtin", "app-system-defaults"):
                continue
            perms = (addon.get("userPermissions") or {}).get("permissions", []) + (addon.get("userPermissions") or {}).get("origins", [])
            out.append(_assess_ext({
                "browser": "Firefox", "profile": profile.name, "id": addon.get("id", ""),
                "name": ((addon.get("defaultLocale") or {}).get("name") or addon.get("id", ""))[:120],
                "version": addon.get("version", ""), "mv": addon.get("manifestVersion"),
                "permissions": sorted(set(p for p in perms if isinstance(p, str)))[:60],
                "store": addon.get("signedState", 0) >= 2, "path": addon.get("path", ""),
                "enabled": addon.get("active", False), "sideloaded": addon.get("signedState", 0) < 2,
                "by_program": addon.get("foreignInstall", False),
                "installed": addon.get("installDate"),
            }))
    return out


def _assess_ext(ext: dict[str, Any]) -> dict[str, Any]:
    perms = set(ext["permissions"])
    reasons = []
    broad = bool(perms & {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})
    if broad:
        reasons.append("all_sites")
    for p in ("debugger", "nativeMessaging", "proxy", "management", "cookies", "history", "clipboardRead",
              "desktopCapture", "webRequestBlocking", "downloads", "privacy"):
        if p in perms:
            reasons.append(p)
    if ext["sideloaded"]:
        reasons.append("not_from_store")
    if ext.get("by_program"):
        reasons.append("by_program")
    if ext.get("mv") == 2 and ext["browser"] != "Firefox":
        reasons.append("old_format")
    severe = perms & SEVERE
    if (ext["sideloaded"] and (broad or severe)) or ({"debugger", "proxy"} & perms and broad):
        risk = "bad"
    elif ext["sideloaded"] or (broad and ({"cookies", "webRequestBlocking", "history", "debugger", "proxy"} & perms)):
        risk = "warn"
    else:
        risk = "ok"
    ext["reasons"] = reasons
    ext["risk"] = risk
    return ext


# ---------------------------------------------------------------- camera and microphone
CONSENT = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def _filetime(value: Any) -> float | None:
    if not isinstance(value, int) or value <= 0:
        return None
    return value / 10_000_000 - 11_644_473_600


def device_access(capability: str) -> dict[str, Any]:
    """capability: webcam | microphone"""
    base = f"{CONSENT}\\{capability}"
    global_value = winutil.reg_read("HKCU", base, "Value")
    machine_value = winutil.reg_read("HKLM", base, "Value")
    apps = []

    def collect(path: str, packaged: bool) -> None:
        for sub in winutil.reg_subkeys("HKCU", path):
            if sub == "NonPackaged":
                continue
            values = winutil.reg_values("HKCU", f"{path}\\{sub}")
            start, stop = _filetime(values.get("LastUsedTimeStart")), _filetime(values.get("LastUsedTimeStop"))
            name = sub.replace("#", "\\") if not packaged else sub.split("_")[0]
            apps.append({"app": name, "packaged": packaged, "allowed": values.get("Value", "Allow") != "Deny",
                         "last_start": start, "last_stop": stop,
                         "in_use": bool(start) and (values.get("LastUsedTimeStop") in (0, None))})

    collect(base, True)
    collect(f"{base}\\NonPackaged", False)
    apps.sort(key=lambda a: -(a["last_start"] or 0))
    return {"capability": capability, "allowed": global_value != "Deny", "policy_denied": machine_value == "Deny",
            "apps": apps[:80], "in_use": [a["app"] for a in apps if a["in_use"]]}


def set_device_access(capability: str, allowed: bool) -> dict[str, Any]:
    if capability not in ("webcam", "microphone"):
        raise ValueError("unknown device")
    ok = winutil.reg_write("HKCU", f"{CONSENT}\\{capability}", "Value", "Allow" if allowed else "Deny")
    if ok:
        core.EVENTS.add("webcam" if capability == "webcam" else "microphone", "info",
                        "device_allowed" if allowed else "device_blocked", capability)
    return {"ok": ok, **device_access(capability)}


class DeviceWatch:
    """Notices when an app starts using the camera or microphone and logs it."""

    def __init__(self) -> None:
        self.seen: dict[str, float] = {}

    def tick(self) -> None:
        for cap in ("webcam", "microphone"):
            try:
                info = device_access(cap)
            except Exception:  # noqa: BLE001
                continue
            for app in info["apps"]:
                if not app["in_use"]:
                    continue
                key = f"{cap}:{app['app']}"
                if self.seen.get(key) != app["last_start"]:
                    self.seen[key] = app["last_start"]
                    core.EVENTS.add("webcam" if cap == "webcam" else "microphone", "medium", "device_in_use", app["app"],
                                    device=cap)


# ---------------------------------------------------------------- e-mail
RISKY_ATTACH = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".lnk", ".iso",
                ".img", ".vhd", ".one", ".docm", ".xlsm", ".pptm", ".jar", ".msi", ".com", ".pif", ".cpl", ".html", ".htm", ".svg"}


def analyze_email(raw: bytes, max_attachment: int = 20 * 1024 * 1024) -> dict[str, Any]:
    from core import protection  # noqa: PLC0415

    msg = email.message_from_bytes(raw, policy=email.policy.default)
    findings: list[dict[str, Any]] = []

    def add(severity: str, key: str, detail: str = "") -> None:
        findings.append({"severity": severity, "key": key, "detail": detail[:400]})

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_addr = parseaddr(str(msg.get("Reply-To", "")))[1]
    return_addr = parseaddr(str(msg.get("Return-Path", "")))[1]
    from_domain = from_addr.rpartition("@")[2].lower()
    auth = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or []).lower()
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", auth)
        if m and m.group(1) in ("fail", "softfail", "permerror", "none") and not (mech == "dkim" and m.group(1) == "none"):
            add("high" if mech == "dmarc" or m.group(1) == "fail" else "medium", f"{mech}_fail", m.group(1))
    if not auth:
        add("low", "no_auth")
    if reply_addr and reply_addr.rpartition("@")[2].lower() != from_domain:
        add("medium", "reply_to_differs", reply_addr)
    if return_addr and from_domain and return_addr.rpartition("@")[2].lower() not in (from_domain, "") and \
            not return_addr.lower().endswith("." + from_domain):
        add("low", "return_path_differs", return_addr)
    if from_name and "@" in from_name:
        shown = parseaddr(from_name)[1] or from_name
        if shown.lower() != from_addr.lower():
            add("high", "display_name_spoof", f"{from_name} <{from_addr}>")
    for brand, domains in protection.BRANDS.items():
        if brand in (from_name or "").lower().replace(" ", "") and from_domain and \
                not any(from_domain == d or from_domain.endswith("." + d) for d in domains):
            add("high", "brand_impersonation", f"{from_name} <{from_addr}>")
            break

    links: list[str] = []
    attachments: list[dict[str, Any]] = []
    body_text = ""
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001
                payload = b""
            ext = Path(filename or "").suffix.lower()
            names = (filename or "").lower().split(".")
            info = {"name": filename or "(unnamed)", "type": ctype, "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(), "risk": "ok", "reasons": []}
            if ext in RISKY_ATTACH:
                info["risk"], info["reasons"] = "bad", ["runs_code"]
            if len(names) > 2 and f".{names[-2]}" in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt", ".xlsx"}:
                info["risk"] = "bad"
                info["reasons"].append("double_extension")
            if payload and len(payload) <= max_attachment:
                kind = engine.sniff(payload[:4096])
                if kind in ("pe", "elf", "script", "lnk") and ext not in RISKY_ATTACH:
                    info["risk"] = "bad"
                    info["reasons"].append("disguised")
                forge = protection.forge_scan(payload, 8)
                if forge.get("matches"):
                    info["risk"] = "bad"
                    info["reasons"].append("yara:" + forge["matches"][0]["rule_name"])
            attachments.append(info)
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                text = part.get_content()
            except Exception:  # noqa: BLE001
                continue
            body_text += text[:200000]
            links += re.findall(r"""https?://[^\s"'<>)\]]+""", text)
            if ctype == "text/html":
                for href, label in re.findall(r"""<a[^>]+href=["'](https?://[^"']+)["'][^>]*>(.*?)</a>""", text, re.I | re.S):
                    shown = re.sub(r"<[^>]+>", "", label).strip()
                    m = re.match(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", shown, re.I)
                    real = urllib.parse.urlsplit(href).hostname or ""
                    if m and real and protection.registered_domain(m.group(1).lower()) != protection.registered_domain(real.lower()):
                        add("high", "link_text_mismatch", f"{shown} → {real}")
    link_rows = []
    for url in list(dict.fromkeys(links))[:60]:
        hits = protection.check_url(url)
        severity = max((h["severity"] for h in hits), key=lambda s: {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(s, 0), default="")
        link_rows.append({"url": url[:500], "risk": "bad" if severity in ("High", "Critical") else ("warn" if severity else "ok"),
                          "reasons": [h["label"] for h in hits][:4]})
    if any(a["risk"] == "bad" for a in attachments):
        add("high", "risky_attachment", ", ".join(a["name"] for a in attachments if a["risk"] == "bad")[:300])
    if any(r["risk"] == "bad" for r in link_rows):
        add("high", "bad_link", next(r["url"] for r in link_rows if r["risk"] == "bad"))
    urgent = re.findall(r"\b(urgent|immediately|suspended|verify your account|password expires|unusual sign-in|"
                        r"confirm your identity|final notice|invoice attached|wire transfer|gift card)\b", body_text, re.I)
    if urgent:
        add("low", "pressure_words", ", ".join(dict.fromkeys(u.lower() for u in urgent))[:200])
    score = min(100, sum({"high": 35, "medium": 15, "low": 5}[f["severity"]] for f in findings))
    return {"from": f"{from_name} <{from_addr}>".strip(), "subject": str(msg.get("Subject", ""))[:300],
            "date": str(msg.get("Date", "")), "findings": findings, "links": link_rows, "attachments": attachments,
            "score": score, "verdict": "bad" if score >= 50 else ("warn" if score >= 15 else "ok")}


# ---------------------------------------------------------------- shredder
SHRED_METHODS = {"quick": 1, "dod": 3, "gutmann_lite": 7}


def shred(paths: list[str], method: str = "dod") -> core.Job:
    passes = SHRED_METHODS.get(method, 3)
    targets = [Path(p) for p in paths if p]
    for t in targets:
        if not t.is_absolute() or not t.exists():
            raise ValueError(f"Not found: {t}")
        if winutil.protected_path(t):
            raise PermissionError(f"CyberScan won't shred a system or program folder: {t}")

    def work(job: core.Job) -> dict[str, Any]:
        files: list[Path] = []
        for t in targets:
            files += [t] if t.is_file() else list(engine.walk([t], []))
        done = failed = 0
        total_bytes = 0
        for i, f in enumerate(files):
            if job.cancel:
                break
            job.detail = str(f)
            try:
                total_bytes += _shred_file(f, passes)
                done += 1
            except OSError as exc:
                failed += 1
                job.items.append({"path": str(f), "error": type(exc).__name__})
            job.progress = (i + 1) / max(len(files), 1)
        for t in targets:   # remove the emptied folders, deepest first
            if t.is_dir():
                for d in sorted([p for p in t.rglob("*") if p.is_dir()], key=lambda p: -len(p.parts)) + [t]:
                    try:
                        d.rmdir()
                    except OSError:
                        pass
        job.counts = {"files": done, "failed": failed, "bytes": total_bytes}
        core.EVENTS.add("shredder", "info", "shred_done", str(done), files=done, failed=failed)
        return job.counts

    return core.start_job("shred", work)


def _shred_file(path: Path, passes: int) -> int:
    size = path.stat().st_size
    os.chmod(path, 0o666)
    with path.open("r+b", buffering=0) as fh:
        for n in range(passes):
            fh.seek(0)
            remaining = size
            pattern = None if n == passes - 1 or n % 3 == 2 else (b"\x00" if n % 3 == 0 else b"\xff")
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                fh.write(secrets.token_bytes(chunk) if pattern is None else pattern * chunk)
                remaining -= chunk
            fh.flush()
            os.fsync(fh.fileno())
        fh.truncate(0)
    # a random name so the old one doesn't survive in the folder's records
    renamed = path.with_name(secrets.token_hex(8))
    path.replace(renamed)
    renamed.unlink()
    return size


# ---------------------------------------------------------------- breach alerts
def breach_check(address: str) -> dict[str, Any]:
    """Look an address up in XposedOrNot's free breach database (only the address is sent)."""
    address = address.strip().lower()
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,253}\.[a-z]{2,}", address):
        raise ValueError("That doesn't look like an e-mail address.")
    url = "https://api.xposedornot.com/v1/check-email/" + urllib.parse.quote(address)
    req = urllib.request.Request(url, headers={"User-Agent": "CyberScan"})
    try:
        with urllib.request.urlopen(req, timeout=12, context=ssl.create_default_context()) as res:  # noqa: S310
            data = json.loads(res.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"address": address, "breaches": [], "checked": time.time()}
        raise RuntimeError(f"The breach service answered {exc.code}.") from exc
    names = []
    for group in data.get("breaches", []) or []:
        names += group if isinstance(group, list) else [group]
    details = _breach_details(names)
    if names:
        core.EVENTS.add("hack_alerts", "high", "breach_found", address, count=len(names))
    return {"address": address, "breaches": details, "checked": time.time()}


def _breach_details(names: list[str]) -> list[dict[str, Any]]:
    if not names:
        return []
    try:
        req = urllib.request.Request("https://api.xposedornot.com/v1/breaches", headers={"User-Agent": "CyberScan"})
        with urllib.request.urlopen(req, timeout=12, context=ssl.create_default_context()) as res:  # noqa: S310
            catalogue = {b.get("breachID"): b for b in json.loads(res.read()).get("exposedBreaches", [])}
    except Exception:  # noqa: BLE001
        catalogue = {}
    out = []
    for n in names:
        b = catalogue.get(n, {})
        out.append({"name": n, "domain": b.get("domain", ""), "date": b.get("breachedDate", "")[:10],
                    "data": b.get("exposedData", [])[:12] if isinstance(b.get("exposedData"), list) else [],
                    "records": b.get("exposedRecords")})
    return sorted(out, key=lambda b: b["date"], reverse=True)


# ---------------------------------------------------------------- sensitive data
TEXT_EXT = {".txt", ".csv", ".log", ".md", ".json", ".xml", ".ini", ".cfg", ".conf", ".env", ".yaml", ".yml", ".sql",
            ".html", ".htm", ".rtf", ".tsv", ".properties", ".ps1", ".py", ".js", ".ts", ".bat", ".sh"}
OFFICE_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods"}
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
PASSWORD = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|كلمة (?:المرور|السر))\s*[:=]\s*\S{4,}")
SAUDI_ID = re.compile(r"\b[12]\d{9}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def _iban_ok(text: str) -> bool:
    s = text.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1
    except ValueError:
        return False


def _office_text(path: Path) -> str:
    import zipfile  # noqa: PLC0415

    try:
        with zipfile.ZipFile(path) as z:
            parts = [n for n in z.namelist() if n.endswith(".xml") and (n.startswith(("word/", "xl/sharedStrings", "xl/worksheets", "ppt/slides")) or n == "content.xml")]
            text = " ".join(z.read(n)[:2_000_000].decode("utf-8", "ignore") for n in parts[:40])
    except (OSError, zipfile.BadZipFile, KeyError):
        return ""
    return re.sub(r"<[^>]+>", " ", text)


def find_sensitive(text: str, types: list[str]) -> dict[str, int]:
    hits: dict[str, int] = {}
    if "card" in types:
        n = sum(1 for m in CARD.finditer(text) if _luhn(re.sub(r"\D", "", m.group())) and 13 <= len(re.sub(r"\D", "", m.group())) <= 19
                and re.sub(r"\D", "", m.group())[0] in "3456")
        if n:
            hits["card"] = n
    if "iban" in types:
        n = sum(1 for m in IBAN.finditer(text) if _iban_ok(m.group()))
        if n:
            hits["iban"] = n
    if "password" in types:
        n = len(PASSWORD.findall(text))
        if n:
            hits["password"] = n
    if "id" in types:
        n = len(SAUDI_ID.findall(text))
        if n >= 1 and re.search(r"(?i)(national|id|هوية|السجل المدني|iqama|إقامة)", text):
            hits["id"] = n
    if "secret" in types:
        n = len(PRIVATE_KEY.findall(text))
        try:
            from core import protection  # noqa: PLC0415

            n += len(protection.find_secrets(text[:500_000], limit=20))
        except Exception:  # noqa: BLE001
            pass
        if n:
            hits["secret"] = n
    return hits


def sensitive_scan(folders: list[str] | None = None) -> core.Job:
    config = core.load_config()
    roots = [Path(f) for f in (folders or config["sensitive_data"]["folders"]) if f and Path(f).exists()]
    types = config["sensitive_data"]["types"]
    if not roots:
        raise ValueError("Choose a folder that exists.")

    def work(job: core.Job) -> dict[str, Any]:
        files = [p for p in engine.walk(roots, core.exclusions(config), stop=lambda: job.cancel)
                 if p.suffix.lower() in TEXT_EXT | OFFICE_EXT]
        for i, path in enumerate(files):
            if job.cancel:
                break
            job.progress = (i + 1) / max(len(files), 1)
            try:
                if path.stat().st_size > 15 * 1024 * 1024:
                    continue
                text = _office_text(path) if path.suffix.lower() in OFFICE_EXT else path.read_text("utf-8", errors="ignore")
            except OSError:
                continue
            hits = find_sensitive(text, types)
            if hits:
                job.items.append({"path": str(path), "hits": hits, "size": path.stat().st_size})
        job.counts = {"files": len(files), "found": len(job.items)}
        return job.counts

    return core.start_job("sensitive_scan", work)


# ---------------------------------------------------------------- do not disturb
def dnd_state() -> dict[str, Any]:
    config = core.load_config()["dnd"]
    busy = winutil.fullscreen_busy()
    return {"enabled": config["enabled"], "fullscreen": busy, "quiet": bool(config["enabled"] and busy)}
