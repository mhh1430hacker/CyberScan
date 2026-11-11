"""Claim-capability dissonance: does the program do what it says it is?

Malware lies about what it is. A "photo viewer" has no business hooking the
keyboard; a file called ``invoice_0423.exe`` is not an invoice; an unsigned
``svchost.exe`` outside Windows is not Windows. This engine reads two things
from a program, statically:

* its **claim**: what its name and version resource (FileDescription,
  ProductName, ...) say it is, reduced to a role (media viewer, installer,
  game, security tool, ...);
* its **capabilities**: what its import table and strings say it can do
  (hook the keyboard, inject into other processes, encrypt files, delete
  shadow copies, ...).

Each role has, for each capability, the probability that a *benign* program of
that role has it. Surprise is ``-log2 p`` bits per observed capability, weighted
by how much harm the capability can do. A browser that talks to the network
costs ~0 bits; a media viewer that steals saved browser passwords costs many.

The probabilities start from an expert prior and are updated from benign
programs only (``fit_profile`` / ``python -m ml.training.fit_dissonance``): the
engine learns what honest software looks like, so it needs no malware corpus.
Explicit lies (a program dressed as a document, an unsigned impersonation of a
Windows process) are scored separately.

Nothing is executed. Capabilities are what the file *could* do, not what it
did; packers hide them, which the ``hidden_imports`` capability accounts for.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILE_FORMAT = "cyberscan-dissonance-profile"
PROFILE_VERSION = 1
PRIOR_STRENGTH = 20.0  # the expert prior counts as this many benign programs per role
MAX_PROFILE_BYTES = 1024 * 1024

# -- capabilities ------------------------------------------------------------------------------

# name: (imports any-of groups that must ALL match, strings any-of, harm weight 0..1, plain-language label)
# Every group is a set of alternatives; a capability needs one member of every group.
CAPABILITIES: dict[str, dict[str, Any]] = {
    "network": {
        "imports": [{"internetopena", "internetopenw", "winhttpopen", "wsastartup", "connect", "urldownloadtofilea",
                     "urldownloadtofilew", "httpsendrequesta", "httpsendrequestw", "getaddrinfo", "winhttpsendrequest"}],
        "harm": 0.15, "label": "connects to the network",
    },
    "download_execute": {
        "imports": [{"urldownloadtofilea", "urldownloadtofilew", "internetreadfile", "winhttpreaddata"},
                    {"shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw", "winexec",
                     "createprocessa", "createprocessw"}],
        "harm": 0.6, "label": "downloads files and starts programs",
    },
    "process_injection": {
        "imports": [{"writeprocessmemory"}, {"createremotethread", "queueuserapc", "ntcreatethreadex",
                                             "setthreadcontext", "rtlcreateuserthread"}],
        "harm": 1.0, "label": "writes code into other running programs",
    },
    "keyboard_hook": {
        "imports": [{"setwindowshookexa", "setwindowshookexw"}],
        "harm": 0.6, "label": "watches the keyboard of the whole system",
    },
    "key_polling": {
        "imports": [{"getasynckeystate"}],
        "harm": 0.3, "label": "polls which keys are pressed",
    },
    "screen_capture": {
        "imports": [{"bitblt"}, {"getdesktopwindow", "getwindowdc"}, {"createcompatiblebitmap"}],
        "harm": 0.4, "label": "takes pictures of the screen",
    },
    "clipboard_read": {
        "imports": [{"getclipboarddata"}],
        "harm": 0.25, "label": "reads the clipboard",
    },
    "encryption": {
        "imports": [{"cryptencrypt", "bcryptencrypt", "cryptgenkey", "bcryptgeneratesymmetrickey"}],
        "harm": 0.35, "label": "encrypts data",
    },
    "file_sweep": {
        "imports": [{"findfirstfilea", "findfirstfilew", "findfirstfileexa", "findfirstfileexw"},
                    {"findnextfilea", "findnextfilew"},
                    {"movefileexa", "movefileexw", "deletefilea", "deletefilew", "setfileattributesa",
                     "setfileattributesw"}],
        "harm": 0.25, "label": "walks through folders and changes or deletes files",
    },
    "autostart_registry": {
        "imports": [{"regsetvalueexa", "regsetvalueexw"}],
        "strings": [r"currentversion\run"],
        "harm": 0.6, "label": "adds itself to the programs that start with Windows",
    },
    "service_install": {
        "imports": [{"createservicea", "createservicew"}],
        "harm": 0.5, "label": "installs a Windows service",
    },
    "scheduled_task": {
        "strings": ["schtasks"],
        "harm": 0.45, "label": "creates scheduled tasks",
    },
    "shadow_copy_destruction": {
        "strings": ["delete shadows", "shadowcopy delete", "wbadmin delete", "recoveryenabled no"],
        "harm": 1.0, "label": "deletes Windows backups and restore points",
    },
    "anti_debugging": {
        # IsDebuggerPresent is in every MSVC runtime and NtQueryInformationProcess in most
        # system software; neither says anything on its own.
        "imports": [{"checkremotedebuggerpresent"}],
        "harm": 0.35, "label": "checks whether it is being analysed",
    },
    "privilege_adjust": {
        "imports": [{"adjusttokenprivileges"}],
        "harm": 0.3, "label": "raises its own privileges",
    },
    "process_enumeration": {
        "imports": [{"createtoolhelp32snapshot", "enumprocesses"},
                    {"process32first", "process32firstw", "process32next", "process32nextw", "enumprocesses"}],
        "harm": 0.2, "label": "lists the running programs",
    },
    "credential_access": {
        "imports": [{"cryptunprotectdata", "credenumeratea", "credenumeratew", "credreada", "credreadw"}],
        "strings": ["login data", "wallet.dat", r"\cookies", "logins.json"],
        "any_source": True,
        "harm": 0.9, "label": "reads saved passwords or wallets",
    },
    "hidden_imports": {
        # Resolving everything at run time leaves an almost empty import table.
        "imports": [{"getprocaddress"}, {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}],
        "max_imports": 12,
        "harm": 0.4, "label": "hides which Windows functions it uses",
    },
}

# -- roles (the claim) -------------------------------------------------------------------------

ROLE_WORDS: dict[str, tuple[str, ...]] = {
    "security_admin": ("antivirus", "anti-virus", "security", "defender", "firewall", "debugger", "remote desktop",
                       "remote access", "remote control", "teamviewer", "anydesk", "vnc", "sysinternals",
                       "process explorer", "process monitor", "backup", "password manager", "keepass", "vault",
                       "endpoint", "monitoring agent", "malware"),
    "installer": ("setup", "install", "installer", "uninstall", "uninstaller", "updater", "update", "bootstrapper",
                  "self-extract", "sfx", "patch"),
    "browser_network": ("browser", "chrome", "firefox", "edge", "opera", "download manager", "ftp", "mail", "outlook",
                        "thunderbird", "chat", "messenger", "telegram", "discord", "slack", "zoom", "vpn", "torrent",
                        "sync", "cloud", "onedrive", "dropbox"),
    "game": ("game", "launcher", "steam", "epic games", "minecraft", "roblox"),
    "media_viewer": ("image viewer", "photo", "picture", "viewer", "player", "media", "video", "music", "audio",
                     "gallery", "wallpaper", "screensaver", "camera", "paint"),
    "utility": ("calculator", "notepad", "editor", "clock", "converter", "archiver", "unzip", "zip", "pdf reader",
                "reader", "font", "printer", "driver"),
}
# File names that pretend a program is a document: lures.
# Only words a program has no reason to be called ("scan", "report" or "order" name real tools).
DOCUMENT_LURE_WORDS = ("invoice", "receipt", "payment", "statement", "contract", "resume", "curriculum",
                       "shipping", "delivery", "quotation", "document", "salary", "payslip", "fax", "pdf", "docx",
                       "xlsx", "jpg", "jpeg", "png")
WINDOWS_PROCESS_NAMES = frozenset({"svchost", "lsass", "csrss", "winlogon", "services", "smss", "explorer",
                                   "spoolsv", "taskhost", "taskhostw", "dwm", "conhost", "rundll32", "wininit",
                                   "lsm", "dllhost", "sihost", "ctfmon", "searchindexer", "msmpeng"})

DEFAULT_RATES: dict[str, float] = {
    "network": 0.45, "download_execute": 0.08, "process_injection": 0.01, "keyboard_hook": 0.06,
    "key_polling": 0.12, "screen_capture": 0.1, "clipboard_read": 0.25, "encryption": 0.15, "file_sweep": 0.3,
    "autostart_registry": 0.04, "service_install": 0.04, "scheduled_task": 0.02, "shadow_copy_destruction": 0.002,
    "anti_debugging": 0.06, "privilege_adjust": 0.12, "process_enumeration": 0.15, "credential_access": 0.03,
    "hidden_imports": 0.06,
}
ROLE_RATES: dict[str, dict[str, float]] = {
    "security_admin": {"process_injection": 0.15, "keyboard_hook": 0.3, "screen_capture": 0.45,
                       "clipboard_read": 0.5, "encryption": 0.6, "file_sweep": 0.7, "autostart_registry": 0.4,
                       "service_install": 0.5, "scheduled_task": 0.2, "anti_debugging": 0.3,
                       "privilege_adjust": 0.7, "process_enumeration": 0.85, "credential_access": 0.25,
                       "network": 0.85, "download_execute": 0.3, "shadow_copy_destruction": 0.05},
    "installer": {"network": 0.8, "download_execute": 0.45, "file_sweep": 0.8, "autostart_registry": 0.25,
                  "service_install": 0.3, "scheduled_task": 0.15, "privilege_adjust": 0.5,
                  "process_enumeration": 0.55, "encryption": 0.4, "hidden_imports": 0.15},
    "browser_network": {"network": 0.98, "download_execute": 0.35, "credential_access": 0.2, "encryption": 0.6,
                        "clipboard_read": 0.6, "file_sweep": 0.5, "autostart_registry": 0.2,
                        "process_enumeration": 0.3, "scheduled_task": 0.1},
    "game": {"network": 0.75, "key_polling": 0.95, "keyboard_hook": 0.15, "anti_debugging": 0.4,
             "screen_capture": 0.25, "process_enumeration": 0.45, "process_injection": 0.04, "encryption": 0.4,
             "hidden_imports": 0.12},
    "media_viewer": {"network": 0.35, "keyboard_hook": 0.03, "key_polling": 0.1, "credential_access": 0.003,
                     "process_injection": 0.003, "encryption": 0.08, "autostart_registry": 0.03,
                     "service_install": 0.01, "scheduled_task": 0.005, "shadow_copy_destruction": 0.0005,
                     "anti_debugging": 0.03, "process_enumeration": 0.05, "download_execute": 0.03},
    "utility": {"network": 0.25, "keyboard_hook": 0.04, "credential_access": 0.01, "process_injection": 0.005,
                "shadow_copy_destruction": 0.001, "service_install": 0.03, "scheduled_task": 0.01},
}

LIES = {
    "document_lure": (7.0, "The file name presents it as a document ({word}), but it is a program."),
    "windows_impersonation": (8.0, "It is named like the Windows process {word}, but it is not signed by Microsoft."),
    "role_conflict": (3.0, "Its name presents it as {name_role}, while its version information describes {info_role}."),
}
MEDIUM_BITS = 8.0
HIGH_BITS = 16.0


@dataclass
class Profile:
    """Benign capability counts per role, on top of the expert prior."""
    counts: dict[str, dict[str, float]] = field(default_factory=dict)  # role -> capability -> programs having it
    totals: dict[str, float] = field(default_factory=dict)  # role -> programs seen
    source: str = "expert prior"

    def rate(self, role: str, capability: str) -> float:
        prior = ROLE_RATES.get(role, {}).get(capability, DEFAULT_RATES[capability])
        seen = self.totals.get(role, 0.0)
        having = self.counts.get(role, {}).get(capability, 0.0)
        return (prior * PRIOR_STRENGTH + having) / (PRIOR_STRENGTH + seen)


def fit_profile(observations: Iterable[tuple[str, Iterable[str]]], source: str) -> Profile:
    """Count capabilities per role over benign programs: (role, capabilities) pairs."""
    profile = Profile(source=source)
    for role, capabilities in observations:
        profile.totals[role] = profile.totals.get(role, 0.0) + 1.0
        bucket = profile.counts.setdefault(role, {})
        for capability in set(capabilities):
            if capability in CAPABILITIES:
                bucket[capability] = bucket.get(capability, 0.0) + 1.0
    return profile


def save_profile(profile: Profile, path: Path) -> str:
    document = {"format": PROFILE_FORMAT, "version": PROFILE_VERSION, "source": profile.source,
                "totals": profile.totals, "counts": profile.counts}
    raw = json.dumps(document, indent=1, sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def load_profile(path: Path, expected_sha256: str) -> Profile:
    """Read a fitted profile whose digest comes from a trusted source."""
    raw = Path(path).read_bytes()[:MAX_PROFILE_BYTES + 1]
    if len(raw) > MAX_PROFILE_BYTES or hashlib.sha256(raw).hexdigest() != str(expected_sha256).lower():
        raise ValueError("Dissonance profile does not match its approved digest.")
    document = json.loads(raw.decode("utf-8"))
    if document.get("format") != PROFILE_FORMAT or document.get("version") != PROFILE_VERSION:
        raise ValueError("Not a dissonance profile.")
    totals = {str(role): float(count) for role, count in document["totals"].items() if float(count) >= 0}
    counts = {
        str(role): {str(cap): min(float(value), totals.get(str(role), 0.0)) for cap, value in caps.items() if cap in CAPABILITIES}
        for role, caps in document["counts"].items()
    }
    return Profile(counts, totals, str(document.get("source", "fitted profile")))


# -- reading the program -----------------------------------------------------------------------

def capabilities_of(import_names: Sequence[str], text: str) -> list[str]:
    """Capabilities evidenced by imports (case-insensitive) and lower-cased strings."""
    imports = {str(name).casefold() for name in import_names}
    found = []
    for name, rule in CAPABILITIES.items():
        groups = rule.get("imports") or []
        by_imports = bool(groups) and all(imports & group for group in groups)
        by_strings = any(marker in text for marker in rule.get("strings", ()))
        if "max_imports" in rule:
            by_imports = by_imports and len(imports) <= rule["max_imports"]
        if rule.get("any_source"):
            matched = by_imports or by_strings
        elif groups and rule.get("strings"):
            matched = by_imports and by_strings
        else:
            matched = by_imports or by_strings
        if matched:
            found.append(name)
    return found


def _words(text: str) -> str:
    return " " + re.sub(r"[^a-z0-9]+", " ", text.casefold()) + " "


def _role_from(text: str) -> str | None:
    words = _words(text)
    for role, markers in ROLE_WORDS.items():
        if any(f" {marker} " in words for marker in markers):
            return role
    return None


def claim_of(file_name: str, version_info: Mapping[str, str] | None) -> dict[str, Any]:
    """The role a program claims, from its version resource first, then its file name."""
    info = version_info or {}
    stem = os.path.splitext(os.path.basename(file_name or ""))[0]
    info_text = " ".join(str(info.get(key, "")) for key in ("FileDescription", "ProductName", "InternalName"))
    info_role = _role_from(info_text) if info_text.strip() else None
    name_role = _role_from(stem.replace("_", " ").replace("-", " "))
    name_words = _words(stem)
    lure = next((word for word in DOCUMENT_LURE_WORDS if f" {word} " in name_words), None)
    impersonates = stem.casefold() if stem.casefold() in WINDOWS_PROCESS_NAMES else None
    role = info_role or name_role or "unknown"
    return {
        "role": role,
        "from": "version information" if info_role else "file name" if name_role else "nothing",
        "info_role": info_role,
        "name_role": name_role,
        "document_lure": lure,
        "impersonates": impersonates,
        "claimed_by": {key: info[key] for key in ("FileDescription", "ProductName", "CompanyName") if info.get(key)},
    }


ROLE_PHRASES = {
    "security_admin": "a security or remote-administration tool", "installer": "an installer or updater",
    "browser_network": "a network client", "game": "a game", "media_viewer": "a media viewer or player",
    "utility": "a small utility", "unknown": "nothing in particular",
}


def assess(
    file_name: str,
    pe_analysis: Mapping[str, Any],
    text: str,
    *,
    signed: bool,
    profile: Profile | None = None,
) -> dict[str, Any]:
    """Dissonance between what a program claims and what it can do. ``text`` is lower-cased content."""
    if pe_analysis.get("status") != "ok":
        return {"status": "not_a_program"}
    profile = profile or Profile()
    claim = claim_of(file_name, pe_analysis.get("version_info"))
    capabilities = capabilities_of(pe_analysis.get("import_names") or [], text)
    role = claim["role"]
    contributions = []
    for capability in capabilities:
        rate = min(0.999, max(1e-4, profile.rate(role, capability)))
        bits = -math.log2(rate) * CAPABILITIES[capability]["harm"]
        contributions.append({
            "capability": capability,
            "label": CAPABILITIES[capability]["label"],
            "benign_rate": round(rate, 4),
            "bits": round(bits, 2),
        })
    lies = []
    if claim["document_lure"] and not claim["info_role"]:
        lies.append(("document_lure", {"word": claim["document_lure"]}))
    if claim["impersonates"] and not signed:
        lies.append(("windows_impersonation", {"word": claim["impersonates"] + ".exe"}))
    if claim["info_role"] and claim["name_role"] and claim["info_role"] != claim["name_role"] \
            and claim["name_role"] in {"media_viewer", "utility", "game"}:
        lies.append(("role_conflict", {"name_role": ROLE_PHRASES[claim["name_role"]],
                                       "info_role": ROLE_PHRASES[claim["info_role"]]}))
    lie_records = [{"kind": kind, "bits": LIES[kind][0], "explanation": LIES[kind][1].format(**values)} for kind, values in lies]
    total = sum(item["bits"] for item in contributions) + sum(item["bits"] for item in lie_records)
    contributions.sort(key=lambda item: -item["bits"])
    return {
        "status": "ok",
        "claim": claim,
        "claimed_role": ROLE_PHRASES.get(role, role),
        "capabilities": contributions,
        "lies": lie_records,
        "dissonance_bits": round(total, 2),
        "level": "high" if total >= HIGH_BITS else "medium" if total >= MEDIUM_BITS else "low",
        "signed": signed,
        "profile": profile.source,
    }


def describe(assessment: Mapping[str, Any], limit: int = 3) -> str:
    """One plain-language paragraph: the claim, then the most surprising capabilities and lies."""
    parts = [f"It presents itself as {assessment['claimed_role']}"]
    surprising = [item["label"] for item in assessment["capabilities"][:limit] if item["bits"] >= 1.0]
    if surprising:
        parts.append(", yet it " + "; it ".join(surprising))
    sentence = "".join(parts) + "."
    for lie in assessment["lies"]:
        sentence += " " + lie["explanation"]
    return sentence + f" ({assessment['dissonance_bits']:.1f} bits of surprise against honest programs of that kind.)"
