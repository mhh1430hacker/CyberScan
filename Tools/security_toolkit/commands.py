"""Command-line and executable-path risk analysis shared by the system tools (062, 063, 067, 070).

Reuses the frozen engine's living-off-the-land tradecraft rules (``detection.script_rules``) and adds
what those rules leave to Desktop's core heuristics (encoded PowerShell), plus path checks:
user-writable launch locations, unquoted paths with spaces, masquerading system binaries and
double extensions.
"""
from __future__ import annotations

import base64
import binascii
import re

from security_toolkit.core import Context, sanitize

try:
    from detection.script_rules import scan_command_text as _engine_rules
except Exception:  # pragma: no cover - detection/ absent: only the local rules below apply
    def _engine_rules(text):
        return []

# Folders where almost nothing legitimate autostarts from (high) ...
TRANSIENT_DIRS = re.compile(
    r"(?ix)(?:\\appdata\\local\\temp\\|\\windows\\temp\\|%temp%|%tmp%|\\users\\public\\|\\downloads\\|\\\$recycle\.bin\\|"
    r"^/tmp/|^/var/tmp/|^/dev/shm/|\s/tmp/|\s/dev/shm/)"
)
# ... and per-user / shared data folders where some legitimate per-user installers also live (medium).
USER_DATA_DIRS = re.compile(r"(?ix)(?:\\appdata\\roaming\\(?!microsoft\\)|\\programdata\\(?!microsoft\\))")
USER_WRITABLE = re.compile(TRANSIENT_DIRS.pattern + "|" + USER_DATA_DIRS.pattern.replace("(?ix)", ""), re.I | re.X)
ENCODED_PS = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*?\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})")
DOUBLE_EXT = re.compile(r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip)\.(?:exe|scr|com|bat|cmd|js|vbs|ps1|hta|lnk|pif)\b")
SCRIPT_HOSTS = re.compile(r"(?i)\b(?:wscript|cscript|mshta|rundll32|regsvr32|powershell|pwsh|cmd)(?:\.exe)?\b")
REMOTE_REF = re.compile(r"(?i)\b(?:https?|ftp)://|\\\\\d{1,3}(?:\.\d{1,3}){3}\\")

# legitimate image name -> directories it lives in (lower-case, as they appear in a path)
SYSTEM_BINARIES = {
    "svchost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "lsass.exe": ("\\windows\\system32\\",), "csrss.exe": ("\\windows\\system32\\",),
    "winlogon.exe": ("\\windows\\system32\\",), "services.exe": ("\\windows\\system32\\",),
    "smss.exe": ("\\windows\\system32\\",), "wininit.exe": ("\\windows\\system32\\",),
    "explorer.exe": ("\\windows\\",), "taskhostw.exe": ("\\windows\\system32\\",),
    "spoolsv.exe": ("\\windows\\system32\\",), "lsm.exe": ("\\windows\\system32\\",),
    "dllhost.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "conhost.exe": ("\\windows\\system32\\",), "rundll32.exe": ("\\windows\\system32\\", "\\windows\\syswow64\\"),
}
LOOKALIKES = {"scvhost.exe": "svchost.exe", "svhost.exe": "svchost.exe", "svchosts.exe": "svchost.exe", "lsas.exe": "lsass.exe",
              "lsasss.exe": "lsass.exe", "isass.exe": "lsass.exe", "csrrs.exe": "csrss.exe", "winlogin.exe": "winlogon.exe",
              "explore.exe": "explorer.exe", "expl0rer.exe": "explorer.exe", "rundll.exe": "rundll32.exe", "svch0st.exe": "svchost.exe"}


_WINDOWS_ROOTS = re.compile(r"(?i)^(?:\\\?\?\\)?(?:%systemroot%|%windir%|\\systemroot)(?=\\)")
_RELATIVE_SYSTEM = re.compile(r"(?i)^(?:system32|syswow64)\\")


def normalize_windows_path(path: str) -> str:
    """Expand the path forms Windows itself uses in services and autostarts (%SystemRoot%, \\SystemRoot, \\??\\,
    'system32\\...') so they compare equal to C:\\Windows\\..."""
    path = path.strip().strip('"')
    path = re.sub(r"(?i)^\\\?\?\\", "", path)
    path = _WINDOWS_ROOTS.sub(r"C:\\Windows", path)
    if _RELATIVE_SYSTEM.match(path):
        path = "C:\\Windows\\" + path
    return path


def executable_of(command: str) -> str:
    """The program a command line starts (quoted path, or the text up to the first .exe/.com/.bat/...)."""
    command = normalize_windows_path(command) if command.strip()[:1] != '"' else command.strip()
    if command.startswith('"'):
        return normalize_windows_path(command[1:].split('"', 1)[0])
    match = re.match(r"(?i)(.+?\.(?:exe|com|bat|cmd|scr|pif|ps1|vbs|js|jar|dll))(?:\s|$|,)", command)
    if match:
        return match.group(1)
    return command.split(" ", 1)[0]


def decode_powershell(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text and sum(ch.isprintable() or ch.isspace() for ch in text) / len(text) > 0.9:
            return text
    return None


def analyze_command(ctx: Context, command: str, *, location: str, context: str, prefix: str) -> int:
    """Add findings for one autostart/task/service/process command. Returns how many were added."""
    before = len(ctx.findings)
    if not command or not command.strip():
        return 0
    exe = executable_of(command)
    lower_exe = exe.lower().replace("/", "\\")
    if TRANSIENT_DIRS.search(lower_exe) or TRANSIENT_DIRS.search(" " + command.lower()):
        ctx.finding(f"{prefix}.transient-path", f"{context} runs from a temporary or download folder", "high",
                    f"'{exe}' is in Temp, Downloads, Public or the Recycle Bin. Malware commonly runs from there; "
                    "legitimate software almost never autostarts from such paths.", location=location, evidence=command)
    elif USER_DATA_DIRS.search(lower_exe):
        ctx.finding(f"{prefix}.user-writable-path", f"{context} runs from a user-writable data folder", "medium",
                    f"'{exe}' is under AppData\\Roaming or ProgramData, which any process of that user can modify. "
                    "Some per-user installers live there legitimately; check the publisher.", location=location, evidence=command)
    name = lower_exe.rsplit("\\", 1)[-1]
    if name in LOOKALIKES:
        ctx.finding(f"{prefix}.lookalike-name", f"{context} uses a look-alike name '{name}'", "high",
                    f"'{name}' imitates the Windows binary '{LOOKALIKES[name]}', a common masquerading technique (T1036.005).",
                    location=location, evidence=command)
    elif name in SYSTEM_BINARIES and "\\" in lower_exe and not any(d in lower_exe for d in SYSTEM_BINARIES[name]):
        ctx.finding(f"{prefix}.masquerade", f"{context} uses system name '{name}' outside its system folder", "high",
                    f"The real {name} lives in {', '.join(SYSTEM_BINARIES[name])}; a copy elsewhere is a masquerading indicator (T1036.005).",
                    location=location, evidence=command)
    if DOUBLE_EXT.search(command):
        ctx.finding(f"{prefix}.double-extension", f"{context} launches a file with a double extension", "high",
                    "A name like 'invoice.pdf.exe' hides the real file type.", location=location, evidence=command)
    unquoted = not command.lstrip().startswith('"') and " " in exe and re.search(r"(?i)^[a-z]:\\", exe)
    if unquoted:
        ctx.finding(f"{prefix}.unquoted-path", f"{context} path has spaces but no quotes", "low",
                    f"Windows tries 'C:\\Program.exe' and similar prefixes before '{exe}'. Exploitable only if one of those parent folders "
                    "is writable by a lower-privileged user (T1574.009); quote the path.",
                    location=location, evidence=command)
    for match in ENCODED_PS.finditer(command):
        decoded = decode_powershell(match.group(1))
        ctx.finding(f"{prefix}.encoded-powershell", f"{context} runs base64-encoded PowerShell", "high",
                    "-EncodedCommand hides the script from casual inspection (T1027 / T1059.001)."
                    + (f" Decoded start: {sanitize(decoded, 120)}" if decoded else ""), location=location, evidence=command)
    for rule in _engine_rules(command):
        slug = re.sub(r"[^a-z0-9]+", "-", rule["label"].lower()).strip("-")[:60]
        ctx.finding(f"{prefix}.{slug}", f"{context}: {rule['label']}", rule["severity"], rule["explanation"],
                    weight=rule.get("contribution"), location=location, evidence=command)
    if SCRIPT_HOSTS.search(exe) and REMOTE_REF.search(command):
        ctx.finding(f"{prefix}.remote-script", f"{context} runs a script host against a remote resource", "high",
                    "A script interpreter is pointed at a URL or remote share, a typical download-and-run pattern.",
                    location=location, evidence=command)
    return len(ctx.findings) - before
