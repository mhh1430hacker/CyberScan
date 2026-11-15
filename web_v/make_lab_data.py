"""Precompute the data behind the landing page's interactive CyberScan Lab (#lab).

Everything in static/data/lab.json is produced here by CyberScan's own code:

* a tiny, harmless Windows program is assembled byte by byte (it only calls ExitProcess(0)),
  given a misleading name, and parsed with pefile, the parser CyberScan itself uses;
* CyberScan's real website engine (detection.engine.analyze_upload) scans it under that name and
  under an honest one, so the Lab can show the real findings and how the name changes them;
* the real offline URL analyzer (detection.url_intel) checks a few addresses on reserved
  documentation domains (.example, 192.0.2.0/24); nothing is fetched.

static/data/lab-tools.json describes the Tool Registry. It is read from the CyberScan workspace's
Tools/ catalog with Tools.registry.ToolRegistry.discover(), which parses each module's metadata
with Python's ast module and never imports or runs it. Two discoveries are recorded: the real
registry.json, and the same discovery with every category directory allowlisted (read-only: an
in-memory override, registry.json is not changed and no tool is approved).

    python web_v/make_lab_data.py [--tools <CyberScan workspace>]

Re-run after changing an engine or the tool catalog; the page says these figures come from here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import random
import struct
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pefile  # noqa: E402

from core.entropy import shannon_entropy  # noqa: E402
from detection.common import CORRELATED_EVIDENCE  # noqa: E402
from detection.engine import analyze_upload, sniff_type  # noqa: E402
from detection.url_intel import analyze_url_intel  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static" / "data"
DEFAULT_TOOLS = Path.home() / "Documents" / "final" / "CyberScan"
SAMPLE_NAME = "invoice.pdf.exe"
HONEST_NAME = "exit_demo.exe"
URLS = [
    "https://www.example.com/",
    "http://paypa1-account-verify.example/login?next=pay",
    "https://xn--pple-43d.example/signin",
    "http://192.0.2.10/files/invoice.pdf.exe",
]


# ---------------------------------------------------------------------------------- the sample
def build_sample() -> bytes:
    """A minimal PE32 console program: push 0; call [ExitProcess]; ret. Three sections and an
    overlay of 2 KiB of deterministic pseudo-random bytes (data after the end of the image, the
    shape of an appended payload; here it is noise that nothing reads)."""
    file_align, base = 0x200, 0x400000
    text_rva, rdata_rva, data_rva = 0x1000, 0x2000, 0x3000
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 2, 0x90)
    struct.pack_into("<I", dos, 0x3C, 0x80)
    stub = bytes.fromhex("0E1FBA0E00B409CD21B8014CCD21") + b"This program cannot be run in DOS mode.\r\r\n$"
    dos[0x40:0x40 + len(stub)] = stub

    iat, hint_name = rdata_rva, rdata_rva + 0x60
    rdata = bytearray(0x200)
    struct.pack_into("<II", rdata, 0x00, hint_name, 0)                                         # IAT
    struct.pack_into("<IIIII", rdata, 0x10, rdata_rva + 0x40, 0, 0, rdata_rva + 0x50, iat)    # import descriptor
    struct.pack_into("<II", rdata, 0x40, hint_name, 0)                                         # lookup table
    rdata[0x50:0x5D] = b"KERNEL32.dll\0"
    rdata[0x60:0x6E] = b"\0\0ExitProcess\0"
    text = bytearray(0x200)
    code = bytes([0x6A, 0x00, 0xFF, 0x15]) + struct.pack("<I", base + iat) + bytes([0xC3])
    text[:len(code)] = code
    data = bytearray(0x200)
    msg = b"A harmless CyberScan teaching sample. It only calls ExitProcess(0).\0"
    data[:len(msg)] = msg

    coff = struct.pack("<HHIIIHH", 0x14C, 3, 0, 0, 0, 0xE0, 0x0102)
    opt = bytearray(0xE0)
    struct.pack_into("<HBBIIIIII", opt, 0, 0x10B, 14, 0, 0x200, 0x400, 0, text_rva, text_rva, rdata_rva)
    struct.pack_into("<I", opt, 28, base)
    struct.pack_into("<II", opt, 32, 0x1000, file_align)
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<II", opt, 56, 0x4000, 0x200)            # SizeOfImage, SizeOfHeaders
    struct.pack_into("<HH", opt, 68, 3, 0x8540)                # console; NX, no SEH, TS-aware, dynamic base
    struct.pack_into("<IIII", opt, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8 * 1, rdata_rva + 0x10, 0x28)
    struct.pack_into("<II", opt, 96 + 8 * 12, iat, 8)
    table, raw = b"", 0x200
    for name, rva, body, flags in ((b".text", text_rva, text, 0x60000020), (b".rdata", rdata_rva, rdata, 0x40000040),
                                   (b".data", data_rva, data, 0xC0000040)):
        table += struct.pack("<8sIIIIIIHHI", name, 0x100, rva, len(body), raw, 0, 0, 0, 0, flags)
        raw += len(body)
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + table
    headers += b"\0" * (0x200 - len(headers))
    rng = random.Random(20261115)
    overlay = bytes(rng.getrandbits(8) for _ in range(2048))
    return headers + bytes(text) + bytes(rdata) + bytes(data) + overlay


def fields(structure) -> list[list]:
    """[name, value, file offset, size] for every field of a pefile structure."""
    d = structure.dump_dict()
    items = [(k, v) for k, v in d.items() if k != "Structure" and isinstance(v, dict) and "FileOffset" in v]
    out = []
    for i, (k, v) in enumerate(items):
        end = items[i + 1][1]["FileOffset"] if i + 1 < len(items) else structure.get_file_offset() + structure.sizeof()
        value = v["Value"]
        if isinstance(value, bytes):
            value = value.rstrip(b"\0").decode("latin-1")
        elif isinstance(value, str):
            value = value.replace("\\x00", "")
        out.append([k, value, v["FileOffset"], end - v["FileOffset"]])
    return out


def regions(data: bytes) -> tuple[list[dict], dict]:
    pe = pefile.PE(data=data)
    e_lfanew = pe.DOS_HEADER.e_lfanew
    opt_off = pe.OPTIONAL_HEADER.get_file_offset()
    dirs_off = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].get_file_offset()
    table_off = pe.sections[0].get_file_offset()
    table_end = pe.sections[-1].get_file_offset() + pe.sections[-1].sizeof()
    out = [
        {"key": "dos", "kind": "header", "start": 0, "end": 0x40, "fields": fields(pe.DOS_HEADER)},
        {"key": "stub", "kind": "header", "start": 0x40, "end": e_lfanew, "text": data[0x4E:0x76].decode("latin-1")},
        {"key": "sig", "kind": "header", "start": e_lfanew, "end": e_lfanew + 4},
        {"key": "coff", "kind": "header", "start": e_lfanew + 4, "end": opt_off, "fields": fields(pe.FILE_HEADER)},
        {"key": "opt", "kind": "header", "start": opt_off, "end": dirs_off,
         "fields": [f for f in fields(pe.OPTIONAL_HEADER) if f[2] < dirs_off]},
        {"key": "dirs", "kind": "header", "start": dirs_off, "end": table_off,
         "fields": [[f"{d.name.replace('IMAGE_DIRECTORY_ENTRY_', '')}", f"RVA 0x{d.VirtualAddress:X} · {d.Size} B", d.get_file_offset(), 8]
                    for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY if d.VirtualAddress or d.Size]},
        {"key": "table", "kind": "header", "start": table_off, "end": table_end,
         "fields": [[s.Name.rstrip(b"\0").decode(), f"raw 0x{s.PointerToRawData:X}+0x{s.SizeOfRawData:X} · flags 0x{s.Characteristics:08X}", s.get_file_offset(), s.sizeof()] for s in pe.sections]},
        {"key": "pad", "kind": "padding", "start": table_end, "end": pe.OPTIONAL_HEADER.SizeOfHeaders},
    ]
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode()
        out.append({"key": name, "kind": "section", "start": s.PointerToRawData, "end": s.PointerToRawData + s.SizeOfRawData,
                    "flags": {"read": bool(s.Characteristics & 0x40000000), "write": bool(s.Characteristics & 0x80000000),
                              "execute": bool(s.Characteristics & 0x20000000)},
                    "entropy": round(shannon_entropy(s.get_data()), 3)})
    overlay_at = pe.get_overlay_data_start_offset()
    if overlay_at:
        out.append({"key": "overlay", "kind": "overlay", "start": overlay_at, "end": len(data),
                    "entropy": round(shannon_entropy(data[overlay_at:]), 3)})
    for r in out:
        r.setdefault("entropy", round(shannon_entropy(data[r["start"]:r["end"]]), 3) if r["end"] > r["start"] else 0.0)
    imports = [{"dll": e.dll.decode(), "names": [i.name.decode() for i in e.imports], "iat": [i.address - pe.OPTIONAL_HEADER.ImageBase for i in e.imports]}
               for e in pe.DIRECTORY_ENTRY_IMPORT]
    meta = {"entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint, "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "entry_offset": pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "imports": imports,
            "code_hex": data[0x200:0x209].hex(" ")}
    return out, meta


def trajectory(data: bytes, window: int = 256, step: int = 64) -> dict:
    offsets = list(range(0, max(1, len(data) - window + 1), step))
    return {"window": window, "step": step, "offsets": offsets,
            "values": [round(shannon_entropy(data[o:o + window]), 3) for o in offsets]}


def scan(data: bytes, name: str) -> dict:
    r = analyze_upload(data, name)
    pe = r.get("pe_analysis") or {}
    ca = r.get("content_analysis") or {}
    fs = r.get("feature_summary") or {}
    return {
        "name": name,
        "combined_score": r.get("combined_score"), "heuristic_score": r.get("heuristic_score"),
        "classification": r.get("classification"),
        "evidence": [{k: e.get(k) for k in ("category", "severity", "evidence", "explanation", "contribution")} for e in r.get("evidence", [])],
        "engine_status": r.get("engine_status"), "model_status": r.get("model_status"),
        "yara_matches": len(r.get("yara_matches") or []),
        "mitre": r.get("mitre_techniques"),
        "features": {k: fs.get(k) for k in ("file_size", "entropy", "extension_category", "is_executable", "magic_mismatch",
                                            "double_extension", "import_count", "string_count", "executable_section_count")},
        "pe": {k: pe.get(k) for k in ("risk_score", "findings", "import_names", "section_count", "is_managed", "header_summary")},
        "cfg": {k: (pe.get("cfg_topology") or {}).get(k) for k in ("status", "basic_block_count", "edge_count", "cyclomatic_complexity",
                                                                   "instruction_count", "detected_patterns", "evidence_patterns", "architecture")},
        "content": {k: ca.get(k) for k in ("file_type", "score", "classification", "evidence_agreement", "findings")},
        "summary": r.get("detection_summary"),
    }


def url_results() -> list[dict]:
    out = []
    for url in URLS:
        r = analyze_url_intel(url)
        out.append({k: r.get(k) for k in ("url", "scheme", "host", "unicode_host", "registrable_domain", "impersonated_brand",
                                          "score", "classification", "evidence_agreement", "findings")})
    return out


# ---------------------------------------------------------------------------------- tool registry
def tool_catalog(workspace: Path) -> dict | None:
    tools = workspace / "Tools"
    if not (tools / "registry.py").is_file():
        return None
    sys.path.insert(0, str(workspace))
    from Tools.registry import ToolRegistry  # noqa: E402

    config = json.loads((tools / "registry.json").read_text(encoding="utf-8"))
    categories = sorted(p.name for p in tools.iterdir() if p.is_dir() and any(p.glob("*.py"))
                        and not p.name.startswith(("_", "tests")) and p.name not in ("detection", "maintenance", "security_toolkit"))
    schemas: dict[str, dict] = {}

    def pack(record) -> dict:
        d = record.as_dict()
        m = d.pop("metadata") or {}
        out_schema = m.pop("output_schema", None)
        if out_schema is not None:
            key = hashlib.sha256(json.dumps(out_schema, sort_keys=True).encode()).hexdigest()[:12]
            schemas.setdefault(key, out_schema)
            m["output_schema_ref"] = key
        return {**d, **m}

    real = [pack(r) for r in ToolRegistry(tools).discover()]
    wide = [pack(r) for r in ToolRegistry(tools, approved_directories=categories).discover()]
    return {
        "registry_json": {"approved_directories": config.get("approved_directories", []),
                          "trusted_tools": len(config.get("trusted_tools", {}))},
        "categories": categories,
        "discovery_real": real,
        "discovery_all_categories": wide,
        "output_schemas": schemas,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", type=Path, default=DEFAULT_TOOLS, help="CyberScan workspace that contains Tools/")
    args = ap.parse_args()

    data = build_sample()
    regs, meta = regions(data)
    lab = {
        "generated_by": "web_v/make_lab_data.py",
        "generated_on": date.today().isoformat(),
        "sample": {
            "name": SAMPLE_NAME, "size": len(data), "b64": base64.b64encode(data).decode(),
            "sha256": hashlib.sha256(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(), "sniffed_type": sniff_type(data),
            "entropy": round(shannon_entropy(data), 3), "regions": regs, **meta,
            "trajectory": trajectory(data),
        },
        "scan": scan(data, SAMPLE_NAME),
        "scan_honest": scan(data, HONEST_NAME),
        "correlated": {label: group for label, group in CORRELATED_EVIDENCE.items()},
        "urls": url_results(),
    }
    STATIC.mkdir(parents=True, exist_ok=True)
    (STATIC / "lab.json").write_text(json.dumps(lab, ensure_ascii=False, separators=(",", ":"), default=str), encoding="utf-8")
    catalog = tool_catalog(args.tools)
    if catalog:
        (STATIC / "lab-tools.json").write_text(json.dumps(catalog, ensure_ascii=False, separators=(",", ":"), default=str), encoding="utf-8")
    s = lab["scan"]
    print(f"sample {len(data)} B sha256 {lab['sample']['sha256'][:16]}… scan {s['combined_score']} {s['classification']}; "
          f"honest name {lab['scan_honest']['combined_score']} {lab['scan_honest']['classification']}; "
          f"tools: {len(catalog['discovery_all_categories']) if catalog else 'not found'}")


if __name__ == "__main__":
    main()
