"""Find what was added to a file and can be taken out exactly, then repair a copy.

This is the Repair screen's engine, built only from structure the parsers
can prove (no trained model is involved, and the screen says so):

* data stored after a format's logical end (PNG/JPEG/GIF/ZIP/PDF/OLE/ELF);
* a PDF's last incremental update that adds active content (JavaScript,
  automatic actions, Launch, embedded files);
* Office Open XML parts that run or carry code: VBA projects, embedded
  objects, ActiveX controls;
* names that lie: hidden direction characters, a harmless-looking double
  extension, an extension that contradicts the content.

Content disarm (executor/cdr.py) takes active parts out and keeps the
document: PDF scripts and automatic actions (renamed in place, or the PDF
rebuilt when they hide in compressed object streams), macros in older
Office files (emptied in place), remote templates and linked objects in
Office Open XML, scripts and event handlers in HTML/SVG/HTA, embedded
objects in RTF, and programs or scripts packed in a ZIP archive.

Every byte-changing plan is tried on the real bytes before it is offered.
If the executor would refuse (the cut would not be exact, or would remove
something legitimate), the finding is shown as "report only", with the
executor's reason. Things that are often legitimate (a program's overlay)
are offered but not pre-selected. Things that can't be removed safely yet
(encrypted PDFs, damaged sector chains, unbalanced RTF) are reported,
never touched.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath, PureWindowsPath

from repair_engine.executor import Plan, apply, cdr
from repair_engine.parsers import parse
from repair_engine.regions import RegionMap
from repair_engine.validator import Validation, validate

ACTIVE_PDF = {"javascript", "auto_action", "launch", "embedded_file"}
# Characters that reorder or hide text in a name (kept in step with ui/names.py).
HIDDEN = set("‪‫‬‭‮⁦⁧⁨⁩‎‏؜​‌‍﻿")
RUNS = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "msi", "cpl", "lnk", "jar", "dll"}
LOOKS_HARMLESS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip"}
TRUE_EXTENSION = {"pe": "exe", "pdf": "pdf", "png": "png", "jpeg": "jpg", "gif": "gif", "zip": "zip", "elf": "elf"}
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".xlsb", ".pptm", ".potm", ".ppsm"}
_PDF_ROOT = re.compile(rb"/Root\s+(\d+)\s+\d+\s+R")
_PDF_REFERENCE = re.compile(rb"(\d+)\s+\d+\s+R\b")
SIGNATURES = (b"MZ", b"PK\x03\x04", b"%PDF", b"\x7fELF", b"<script", b"<html", b"powershell", b"#!")


@dataclass
class RepairFinding:
    key: str
    kind: str
    severity: str  # high | medium | low
    title: str  # English, translated by the interface
    detail: str
    start: int | None = None
    end: int | None = None
    plans: list[Plan] = field(default_factory=list)
    rename_to: str | None = None
    recommended: bool = False
    reason: str = ""  # why it is report-only, when it is

    @property
    def repairable(self) -> bool:
        return bool(self.plans) or self.rename_to is not None


@dataclass
class RepairReport:
    name: str
    size: int
    sha256: str
    format: str
    regions: RegionMap
    findings: list[RepairFinding]


@dataclass
class RepairResult:
    ok: bool
    repaired: bytes | None
    name: str
    removed_bytes: int
    removed: list
    steps: list[dict]
    validation: Validation | None
    before: int
    after: int
    sha256_before: str
    sha256_after: str | None
    message: str = ""


def _try(data: bytes, plans: list[Plan]) -> str:
    """'' if the executor accepts the plans on these bytes, else its reason."""
    outcome = apply(data, plans)
    if outcome.refused:
        return outcome.refused
    return "" if outcome.repaired is not None else "nothing would change"


def _severity_of_tail(tail: bytes) -> str:
    head = tail[:4096].lower()
    return "high" if any(signature.lower() in head for signature in SIGNATURES) else "medium"


def _size(count: int) -> str:
    for unit, step in (("MB", 1 << 20), ("KB", 1 << 10)):
        if count >= step:
            return f"{count / step:.1f} {unit}"
    return f"{count} B"


CAUTION = " Renaming shows what it really is; it doesn't make it safe."


def _names(name: str, regions: RegionMap) -> list[RepairFinding]:
    found: list[RepairFinding] = []
    base = PureWindowsPath(name).name or name
    clean = "".join(c for c in base if c not in HIDDEN)
    # A program stays a program under its true name: show it, but never pre-select it.
    runnable = clean.rsplit(".", 1)[-1].lower() in RUNS or regions.format in {"pe", "elf"}
    if clean != base:
        found.append(RepairFinding(
            "name_hidden", "name", "high", "Hidden characters disguise the name",
            "The name contains invisible direction characters that make it read as something else." + (CAUTION if runnable else ""),
            rename_to=clean, recommended=not runnable,
        ))
    pieces = clean.split(".")
    if len(pieces) > 2 and pieces[-1].lower() in RUNS and pieces[-2].lower().strip() in LOOKS_HARMLESS:
        true_name = ".".join(pieces[:-2] + [pieces[-1]])
        found.append(RepairFinding(
            "name_double", "name", "high", "A double extension hides the real type",
            f"It's named like a .{pieces[-2].lower()} but is really a .{pieces[-1].lower()} that can run." + CAUTION,
            rename_to=true_name, recommended=False,
        ))
    mismatch = regions.of_kind("magic_mismatch")
    true_extension = TRUE_EXTENSION.get(regions.format)
    if regions.format == "ooxml":
        true_extension = None
    if mismatch and true_extension:
        stem = clean.rsplit(".", 1)[0] if "." in clean else clean
        found.append(RepairFinding(
            "name_mismatch", "name", "high" if regions.format in {"pe", "elf"} else "medium",
            "The extension doesn't match the content",
            f"The name says {PureWindowsPath(clean).suffix or 'nothing'}, but the content is {regions.format.upper()}." + (CAUTION if runnable else ""),
            rename_to=f"{stem}.{true_extension}", recommended=False,
        ))
    return found


def _tail(data: bytes, regions: RegionMap) -> list[RepairFinding]:
    found: list[RepairFinding] = []
    for region in regions.of_kind("after_eof"):
        tail = data[region.start:region.end]
        if not tail.strip(b"\x00\t\r\n "):
            continue  # padding, not content
        plans = [Plan("truncate_after_eof", region.start)]
        reason = _try(data, plans)
        severity = _severity_of_tail(tail)
        # Some legitimate files keep data there too (phones store a "motion photo"
        # video after the picture), so only a program, archive or script is pre-selected.
        found.append(RepairFinding(
            f"after_eof@{region.start}", "after_eof", severity,
            "Data hidden after the end of the file",
            f"{_size(region.size)} stored after the point where the {regions.format.upper()} format ends. Readers ignore it; other programs can use it."
            + (" It starts like a program, an archive or a script." if severity == "high" else ""),
            region.start, region.end, [] if reason else plans, recommended=not reason and severity == "high", reason=reason,
        ))
    return found


def _pe(data: bytes, regions: RegionMap) -> list[RepairFinding]:
    found: list[RepairFinding] = []
    for region in regions.of_kind("pe_overlay"):
        tail = data[region.start:region.end]
        if not tail.strip(b"\x00"):
            continue
        plans = [Plan("strip_overlay", region.start)]
        reason = _try(data, plans)
        embedded = tail[:2] == b"MZ" or tail[:4] == b"PK\x03\x04"
        found.append(RepairFinding(
            f"pe_overlay@{region.start}", "pe_overlay", "medium" if embedded else "low",
            "Extra data after the end of the program",
            f"{_size(region.size)} after the program's last section. Installers often keep their payload there, so it isn't removed unless you choose to."
            + (" It starts like another program or archive." if embedded else ""),
            region.start, region.end, [] if reason else plans, recommended=False, reason=reason,
        ))
    return found


def _pdf_update_objects(data: bytes, objects: list, active: list, last_start: int) -> set[int]:
    """The objects the executor may take out with the last update.

    The active objects, minus the catalog (the executor then checks that it
    only gained references to them), plus new objects in the update that
    exist only to point at them, such as an attachment's file specification.
    """
    roots = _PDF_ROOT.findall(data[last_start:])
    root = int(roots[-1]) if roots else None
    chosen = {r.metadata["number"] for r in active} - {root}
    earlier = {r.metadata["number"] for r in objects if r.start < last_start}
    candidates = [r for r in objects if r.start >= last_start and r.metadata["number"] not in earlier | chosen | {root}]
    grew = True
    while grew:
        grew = False
        for region in candidates:
            number = region.metadata["number"]
            if number in chosen:
                continue
            references = {int(n) for n in _PDF_REFERENCE.findall(data[region.start:region.end])}
            if references & chosen:
                chosen.add(number)
                grew = True
    return chosen


def _pdf(data: bytes, regions: RegionMap) -> list[RepairFinding]:
    found: list[RepairFinding] = []
    markers = regions.of_kind("pdf_eof_marker")
    last_start = markers[-2].end if len(markers) >= 2 else None
    objects = regions.of_kind("pdf_object")
    active = [r for r in objects if ACTIVE_PDF & set(r.metadata.get("flags") or [])]
    in_update = [r for r in active if last_start is not None and r.start >= last_start]
    base = [r for r in active if r not in in_update]
    if in_update:
        numbers = sorted(_pdf_update_objects(data, objects, in_update, last_start))
        plans = [Plan("remove_pdf_object_and_refs", params={"objects": numbers})]
        reason = _try(data, plans)
        flags = sorted({flag for r in in_update for flag in r.metadata.get("flags") or []} & ACTIVE_PDF)
        found.append(RepairFinding(
            "pdf_update", "pdf_update", "high", "Active content added in a later update",
            f"The last update to this PDF only adds {', '.join(flags).replace('_', ' ')}. Removing that update returns the document to its previous version.",
            min(r.start for r in in_update), len(data), [] if reason else plans, recommended=not reason, reason=reason,
        ))
    try:
        tokens = cdr.pdf_active_tokens(data, last_start if in_update else None)
    except Exception:  # noqa: BLE001 - analysis never raises
        tokens = []
    if base or tokens:
        flags = sorted({flag for r in base for flag in r.metadata.get("flags") or []} & ACTIVE_PDF)
        names = sorted({name.decode("latin-1") for _s, _e, name in tokens})
        plans = [Plan("neutralize_pdf_names", params={"before": last_start if in_update else None})]
        reason = _try(data, plans) if tokens else "The active entries are written in a way that can't be renamed in place."
        found.append(RepairFinding(
            "pdf_active_base", "pdf_active",
            "high" if {"javascript", "launch"} & set(flags) or {"JavaScript", "JS", "Launch"} & set(names) else "medium",
            "Active content inside the document",
            f"{len(base) or len(tokens)} object(s) carry {', '.join(flags).replace('_', ' ') or 'active entries'}"
            + (f" ({', '.join('/' + n for n in names[:6])})" if names else "")
            + ". Disarming renames those entries, letter for letter, to names no PDF reader acts on: the text, pages and links stay.",
            min([r.start for r in base] + [t[0] for t in tokens]), max([r.end for r in base] + [t[1] for t in tokens]),
            [] if reason else plans, recommended=not reason, reason=reason,
        ))
    hidden = [s for s in regions.of_kind("pdf_stream") if ACTIVE_PDF & set(s.metadata.get("decoded_flags") or [])]
    if hidden:
        plans = [Plan("rebuild_pdf_without_active")]
        reason = _try(data, plans)
        found.append(RepairFinding(
            "pdf_objstm", "pdf_active", "high", "Active content hidden in compressed objects",
            "A compressed object stream contains JavaScript or automatic actions. Disarming rebuilds the PDF without "
            "scripts, automatic actions and attachments, and checks it still has every page.",
            hidden[0].start, hidden[0].end, [] if reason else plans, recommended=not reason, reason=reason,
        ))
    return found


def _ooxml(data: bytes, name: str, regions: RegionMap) -> list[RepairFinding]:
    found: list[RepairFinding] = []
    suffix = PureWindowsPath(name).suffix.lower()
    for role, title, why in (
        ("vba_project", "Macros (VBA code)", "Code that can run when the document is opened."),
        ("embedded_object", "Embedded object", "Another file stored inside the document; it can be a program."),
        ("activex", "ActiveX control", "A control that can run code inside Office."),
    ):
        members = [m for m in regions.of_kind("zip_member") if m.metadata.get("role") == role]
        if not members:
            continue
        parts = [m.metadata["name"] for m in members]
        if role == "vba_project":
            folder = str(PurePosixPath(parts[0]).parent)
            parts += [m.metadata["name"] for m in regions.of_kind("zip_member")
                      if str(PurePosixPath(m.metadata["name"]).parent) == folder and PurePosixPath(m.metadata["name"]).name.lower() in {"vbadata.xml", "vbaprojectsignature.bin"}]
        plans = [Plan("remove_ooxml_parts", params={"parts": parts})]
        reason = _try(data, plans)
        unexpected = role == "vba_project" and suffix not in MACRO_EXTENSIONS
        severity = "high" if unexpected else "medium"
        detail = why + (" A " + (suffix or "document") + " file isn't supposed to contain macros at all." if unexpected else "")
        found.append(RepairFinding(
            f"ooxml_{role}", f"ooxml_{role}", severity, title, detail + f" ({len(parts)} part{'s' if len(parts) != 1 else ''})",
            min(m.start for m in members), max(m.end for m in members), [] if reason else plans,
            recommended=not reason and (unexpected or role != "embedded_object"), reason=reason,
        ))
    # Hyperlinks are ordinary; a remote template, linked object, frame or
    # sub-document is fetched when the document opens.
    links = [(link, target) for link in regions.of_kind("ooxml_external_link")
             for target, kind in zip(link.metadata.get("targets", []), link.metadata.get("types") or [])
             if kind.rsplit("/", 1)[-1].lower() in cdr.RISKY_LINK_TYPES and target != "about:blank"]
    if links:
        plans = [Plan("neutralize_ooxml_external")]
        reason = _try(data, plans)
        found.append(RepairFinding(
            "ooxml_link", "ooxml_link", "high", "Loads something from the internet when opened",
            "The document points to: " + ", ".join(t for _l, t in links[:2])
            + ". Disarming points those links at an empty page; hyperlinks in the text are kept.",
            min(link.start for link, _t in links), max(link.end for link, _t in links),
            [] if reason else plans, recommended=not reason, reason=reason,
        ))
    return found


def _ole(data: bytes, regions: RegionMap) -> list[RepairFinding]:
    macros = [r for r in regions.of_kind("ole_stream") if r.metadata.get("role") == "vba"]
    if not macros or not cdr.ole_vba_has_code(data):
        return []   # no project, or one already emptied
    plans = [Plan("zero_ole_vba")]
    reason = _try(data, plans)
    return [RepairFinding(
        "ole_vba", "ole_vba", "high", "Macros (VBA code)",
        "This older Office file contains macro code. Disarming overwrites every part of the macro project with zeros, "
        "in place: the document's text and layout are kept; Office may mention the removed macro project when it opens.",
        min(r.start for r in macros), max(r.end for r in macros),
        [] if reason else plans, recommended=not reason, reason=reason,
    )]


DANGEROUS_MEMBERS = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1",
                     "msi", "lnk", "jar", "dll", "iso", "img", "cpl", "reg", "url", "msc", "vhd", "vhdx"}
SCRIPT_MEMBERS = {"bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "lnk", "reg", "url", "msc"}
CODE_PACKAGES = {".jar", ".apk", ".xpi", ".crx", ".whl", ".nupkg", ".vsix", ".aab", ".ipa"}


def _archive(data: bytes, name: str, regions: RegionMap) -> list[RepairFinding]:
    """Programs and scripts packed in an ordinary ZIP (apps and extensions are code by design)."""
    members = regions.of_kind("zip_member")
    names = {m.metadata.get("name", "") for m in members}
    if PureWindowsPath(name).suffix.lower() in CODE_PACKAGES or names & {"AndroidManifest.xml", "manifest.json", "META-INF/MANIFEST.MF"}:
        return []
    found: list[RepairFinding] = []
    for member in members[:200]:
        member_name = member.metadata.get("name", "")
        if member_name.endswith("/"):
            continue
        slashed = member_name.replace("\\", "/")
        base = PurePosixPath(slashed).name
        pieces = base.lower().split(".")
        extension = pieces[-1] if len(pieces) > 1 else ""
        double = len(pieces) > 2 and extension in RUNS and pieces[-2].strip() in LOOKS_HARMLESS
        escapes = slashed.startswith("/") or ".." in slashed.split("/") or bool(re.match(r"^[A-Za-z]:", slashed))
        hidden = any(c in HIDDEN for c in member_name)
        if not (extension in DANGEROUS_MEMBERS or double or escapes or hidden):
            continue
        plans = [Plan("remove_zip_member", member.start, params={"member": member_name})]
        reason = _try(data, plans)
        if double or hidden:
            title, severity = "A program disguised with a fake extension", "high"
            why = f"'{base}' is named like a document but runs as .{extension}."
        elif escapes:
            title, severity = "A member that writes outside the folder", "high"
            why = f"'{member_name[:80]}' would be extracted outside the destination folder (path traversal)."
        elif extension in SCRIPT_MEMBERS:
            title, severity = "A script inside the archive", "high"
            why = f"'{base}' runs commands when opened."
        else:
            title, severity = "A program inside the archive", "medium"
            why = f"'{base}' is a program. Installers legitimately ship programs, so it isn't removed unless you choose to."
        found.append(RepairFinding(
            f"zip_member@{member.start}", "zip_member", severity, title,
            why + " Removing it leaves every other file in the archive byte-identical.",
            member.start, member.end, [] if reason else plans,
            recommended=not reason and (double or hidden or escapes or extension in SCRIPT_MEMBERS), reason=reason,
        ))
    return found


def _markup(data: bytes) -> list[RepairFinding]:
    if not cdr.looks_like_markup(data):
        return []
    active = cdr.markup_active(data)
    if not active:
        return []
    plans = [Plan("disarm_markup")]
    reason = _try(data, plans)
    strong = {"<script>", "<iframe>", "<object>", "<embed>", "<applet>", "event handler", "script URL"}
    return [RepairFinding(
        "markup_active", "markup_active", "high" if strong & set(active) else "medium",
        "Scripts or active parts in the page",
        "Found: " + ", ".join(active[:6]) + ". Disarming removes them and keeps the page's text, layout and pictures.",
        0, len(data), [] if reason else plans, recommended=not reason, reason=reason,
    )]


def _rtf(data: bytes) -> list[RepairFinding]:
    if not cdr.looks_like_rtf(data):
        return []
    try:
        spans = cdr.rtf_objects(data)
    except Exception as exc:  # noqa: BLE001 - unbalanced braces: report only
        if b"\\object" in data or b"\\objdata" in data:
            return [RepairFinding("rtf_object", "rtf_object", "high", "Embedded objects in the document",
                                  "The document embeds objects, the way most RTF exploits deliver their code.", reason=str(exc))]
        return []
    if not spans:
        return []
    plans = [Plan("remove_rtf_objects")]
    reason = _try(data, plans)
    return [RepairFinding(
        "rtf_object", "rtf_object", "high", "Embedded objects in the document",
        f"{len(spans)} embedded object(s), the way most RTF exploits deliver their code. Removing them keeps the text.",
        spans[0][0], spans[-1][1], [] if reason else plans, recommended=not reason, reason=reason,
    )]


def analyze(data: bytes, name: str) -> RepairReport:
    regions = parse(data, name)
    findings = _names(name, regions) + _tail(data, regions)
    if regions.format == "pe":
        findings += _pe(data, regions)
    elif regions.format == "pdf":
        findings += _pdf(data, regions)
    elif regions.format == "ooxml":
        findings += _ooxml(data, name, regions)
    elif regions.format == "ole":
        findings += _ole(data, regions)
    elif regions.format == "zip":
        findings += _archive(data, name, regions)
    elif regions.format == "unknown":
        findings += _markup(data) + _rtf(data)
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 3), not f.repairable, f.start or 0))
    return RepairReport(PureWindowsPath(name).name or name, len(data), hashlib.sha256(data).hexdigest(), regions.format, regions, findings)


def _byte_findings(findings: list[RepairFinding]) -> list[RepairFinding]:
    """Tail cuts first, latest first (they never move earlier bytes), then name-based edits."""
    tails = [f for f in findings if f.plans and f.plans[0].action in {"truncate_after_eof", "strip_overlay"}]
    others = [f for f in findings if f.plans and f not in tails]
    return sorted(tails, key=lambda f: -(f.start or 0)) + others


def repair(data: bytes, name: str, selected: list[RepairFinding]) -> RepairResult:
    """Apply the selected findings to a copy of ``data``; validate; count what's left."""
    before = analyze(data, name)
    current, removed, steps = data, [], []
    new_name = PureWindowsPath(name).name or name
    for finding in [f for f in selected if f.rename_to]:
        if finding.kind == "name" and finding.key == "name_hidden":
            new_name = finding.rename_to
    for finding in [f for f in selected if f.rename_to and f.key != "name_hidden"]:
        clean = "".join(c for c in new_name if c not in HIDDEN)
        if finding.key == "name_double":
            pieces = clean.split(".")
            new_name = ".".join(pieces[:-2] + [pieces[-1]]) if len(pieces) > 2 else clean
        else:
            new_name = finding.rename_to
    for finding in _byte_findings(selected):
        outcome = apply(current, finding.plans)
        if outcome.refused or outcome.repaired is None:
            steps.append({"finding": finding.key, "refused": outcome.refused or "nothing changed"})
            continue
        current = outcome.repaired
        removed += outcome.removed
        steps.append({"finding": finding.key, "removed": sum(len(r.data) for r in outcome.removed)})
    sha_before = hashlib.sha256(data).hexdigest()
    if current == data and new_name == (PureWindowsPath(name).name or name):
        return RepairResult(False, None, new_name, 0, [], steps, None, len(before.findings), len(before.findings), sha_before, None,
                            "Nothing was changed.")
    validation = validate(data, current) if current != data else None
    if validation is not None and not validation.passed:
        return RepairResult(False, None, new_name, 0, [], steps, validation, len(before.findings), len(before.findings), sha_before, None,
                            "The repaired copy failed its checks, so nothing was written.")
    after = analyze(current, new_name)
    # A cut shrinks the file; a disarm may keep its length (renamed or zeroed bytes) or rewrite it.
    taken = sum(len(r.data) for r in removed if r.end > r.start)
    return RepairResult(
        True, current, new_name, max(len(data) - len(current), taken),
        removed, steps, validation, len(before.findings), len(after.findings), sha_before, hashlib.sha256(current).hexdigest(),
    )
