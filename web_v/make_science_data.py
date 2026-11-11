"""Precompute the data behind the landing page's "Science behind CyberScan" section.

Every number in static/data/science.json comes from running CyberScan's own engines
(core.nextgen_engine, core.deep_embedding, core.mitre_mapper, core.risk_engine) on small
synthetic inputs built here. No real program and no malware is used: the "code" samples are
two hand-assembled x86-32 functions of a few dozen bytes each, and the "encrypted" region is
deterministic pseudo-random bytes (BLAKE2b in counter mode).

    python web_v/make_science_data.py

Needs capstone (the CFG samples) and numpy. Re-run after changing an engine; the page states
that its figures were produced by this script.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.deep_embedding import HighDimensionalEmbedding  # noqa: E402
from core.nextgen_engine import NextGenCyberEngine  # noqa: E402
from core.risk_engine import classify_risk  # noqa: E402
from ml.feature_schema import LATENT_CHANNEL_DIMENSION  # noqa: E402

OUT = Path(__file__).resolve().parent / "static" / "data" / "science.json"

# ---- synthetic inputs ------------------------------------------------------------------------

# An ordinary function: count the bytes of a buffer above 0x7F (cdecl, x86-32).
ORDINARY = bytes.fromhex(
    "55"        # push ebp
    "89e5"      # mov ebp, esp
    "8b4d08"    # mov ecx, [ebp+8]      buffer
    "8b550c"    # mov edx, [ebp+0xc]    length
    "31c0"      # xor eax, eax          count = 0 (how compilers zero a register)
    "85d2"      # test edx, edx
    "740a"      # je done
    "80397f"    # loop: cmp byte ptr [ecx], 0x7f
    "7601"      # jbe skip
    "40"        # inc eax
    "41"        # skip: inc ecx
    "4a"        # dec edx
    "75f6"      # jne loop
    "5d"        # done: pop ebp
    "c3"        # ret
)

# The shape of an in-place XOR loop: buffer[i] ^= key for i < length.
XOR_LOOP = bytes.fromhex(
    "55"        # push ebp
    "89e5"      # mov ebp, esp
    "56"        # push esi
    "8b7508"    # mov esi, [ebp+8]      buffer
    "8b550c"    # mov edx, [ebp+0xc]    length
    "8a4510"    # mov al, [ebp+0x10]    key
    "31c9"      # xor ecx, ecx          i = 0
    "85d2"      # test edx, edx
    "7408"      # je done
    "30040e"    # loop: xor byte ptr [esi+ecx], al   <- writes into memory
    "41"        # inc ecx
    "39d1"      # cmp ecx, edx
    "72f8"      # jb loop
    "5e"        # done: pop esi
    "5d"        # pop ebp
    "c3"        # ret
)

TEXT_A = (
    "Static analysis reads a file without running it. The scanner measures how the bytes are "
    "distributed, where the structure changes, and which instructions the code would execute. "
) * 24
TEXT_B = (
    "A program's header tells the operating system where its code and data live. Sections with "
    "unusual permissions or unusual byte statistics deserve a closer look by a human reviewer. "
) * 24


def pseudo_random(size: int, seed: bytes) -> bytes:
    """Deterministic bytes that look like ciphertext or compressed data (~8 bits/byte)."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.blake2b(seed + counter.to_bytes(8, "little"), digest_size=64).digest()
        counter += 1
    return bytes(out[:size])


def structured_header(size: int) -> bytes:
    """A low-entropy, table-like block: mostly zeros with a few small fields."""
    block = bytearray(size)
    block[0:2] = b"CS"
    for i in range(16, size, 32):
        block[i:i + 4] = (i // 32).to_bytes(4, "little")
    return bytes(block)


def code_like(size: int) -> bytes:
    """The two sample functions repeated with int3 padding, as a linker would lay them out."""
    unit = ORDINARY + b"\xcc" * 5 + XOR_LOOP + b"\xcc" * 2
    return (unit * (size // len(unit) + 1))[:size]


REGIONS = [
    ("header", "Structured header", "Table-like fields, mostly zeros", structured_header(2048)),
    ("code", "Machine code", "Two small x86 functions, repeated", code_like(4096)),
    ("text", "Readable text", "English prose (ASCII)", TEXT_A.encode()[:4096]),
    ("random", "Encrypted-looking", "Pseudo-random bytes: what ciphertext or compressed data looks like", pseudo_random(4096, b"demo")),
    ("padding", "Zero padding", "Alignment filler", bytes(2048)),
]


# ---- helpers ---------------------------------------------------------------------------------

def r(x: float, n: int = 3) -> float:
    return round(float(x), n)


def histogram(data: bytes) -> list[int]:
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return counts


def shannon(data: bytes) -> float:
    n = len(data)
    return math.log2(n) - math.fsum(c * math.log2(c) for c in histogram(data) if c) / n if n else 0.0


def cfg_sample(name: str, label: str, code: bytes) -> dict:
    """The engine's CFG metrics, plus per-block disassembly partitioned the same way."""
    from capstone import CS_ARCH_X86, CS_MODE_32, Cs

    cfg = NextGenCyberEngine.extract_cfg_topology(code, "x86-32")
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(code, 0))
    # The engine's leader rule: first instruction, any branch target, anything after a non-"normal" instruction.
    decoded = NextGenCyberEngine._capstone_instructions(code, "x86-32")[0]
    addresses = {ins[0] for ins in decoded}
    leaders = {decoded[0][0]}
    for i, (addr, size, _, kind, target) in enumerate(decoded):
        if target in addresses:
            leaders.add(target)
        if i + 1 < len(decoded) and (addr + size != decoded[i + 1][0] or kind != "normal"):
            leaders.add(decoded[i + 1][0])
    blocks: list[list] = []
    for ins in instructions:
        if not blocks or ins.address in leaders:
            blocks.append([])
        blocks[-1].append({"addr": f"0x{ins.address:02X}", "asm": f"{ins.mnemonic} {ins.op_str}".strip(),
                           "bytes": ins.bytes.hex(" ")})
    assert len(blocks) == cfg["basic_block_count"], (name, len(blocks), cfg["basic_block_count"])
    adjacency = {int(k): v for k, v in cfg["adjacency"].items()}
    edges = []
    for source, targets in adjacency.items():
        last = blocks[source][-1]
        end = int(last["addr"], 16) + len(last["bytes"].split())
        for target in targets:
            if target <= source:
                kind = "back"      # loops: the edge goes to an earlier (or the same) block
            elif int(blocks[target][0]["addr"], 16) == end:
                kind = "fall"      # execution continues into the next block
            else:
                kind = "jump"      # a branch taken to a later block
            edges.append({"from": source, "to": target, "kind": kind})
    return {
        "id": name,
        "label": label,
        "hex": code.hex(" "),
        "blocks": blocks,
        "edges": edges,
        "metrics": {
            "instructions": cfg["instruction_count"],
            "blocks": cfg["basic_block_count"],
            "edges": cfg["edge_count"],
            "components": 1,
            "cyclomatic": cfg["cyclomatic_complexity"],
            "density": r(cfg["graph_density"], 4),
            "back_edges": cfg["back_edge_count"],
        },
        "descriptive_patterns": cfg["detected_patterns"],
        "evidence_patterns": cfg["evidence_patterns"],
        "architecture": cfg["architecture"],
    }


def quantize(vector) -> tuple[str, float]:
    """int8 quantization of a unit vector for transport; the page only draws it."""
    peak = max(abs(v) for v in vector) or 1.0
    q = bytes(((max(-127, min(127, round(v / peak * 127)))) & 0xFF) for v in vector)
    return base64.b64encode(q).decode(), peak


# ---- build -----------------------------------------------------------------------------------

def main() -> None:
    blob = b"".join(region[3] for region in REGIONS)
    topo = NextGenCyberEngine.analyze_entropy_topography(blob)
    offsets, cursor = [], 0
    for key, label, desc, data in REGIONS:
        offsets.append({"key": key, "label": label, "desc": desc, "start": cursor, "end": cursor + len(data),
                        "entropy_whole": r(shannon(data)), "histogram": histogram(data)})
        cursor += len(data)
    # The engine's own whole-region entropy must agree with this script's formula.
    from core.entropy import shannon_entropy
    for region, (_, _, _, data) in zip(offsets, REGIONS):
        assert abs(shannon_entropy(data) - region["entropy_whole"]) < 0.002

    ent = topo
    # The whole product, as the website runs it, on the same harmless file (OSINT off, no AI).
    from ui.scan_service import ScanService
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "demo_sample.bin"
        path.write_bytes(blob)
        result, nextgen, _, prediction, intelligence, _ = ScanService().analyze(
            str(path), "File", {"osint_enabled": False, "ai_summary_enabled": False})
    scan_ent, scan_cfg = nextgen["entropy_topography"], nextgen["cfg_topology"]
    components = {
        "entropy_level": (scan_ent["mean_entropy"] / 8.0) * 20.0 + (scan_ent["peak_entropy"] / 8.0) * 15.0,
        "discontinuities": min(len(scan_ent["anomalies"]) / 3.0, 1.0) * 20.0,
        "gradient_spread": min(math.sqrt(scan_ent["gradient_variance"]) / 4.0, 1.0) * 10.0,
        "cfg_complexity": min(scan_cfg["cyclomatic_complexity"] / 20.0, 1.0) * 15.0,
        "structural_patterns": min(len(scan_cfg["detected_patterns"]) / 3.0, 1.0) * 20.0,
    }
    assert abs(sum(components.values()) - nextgen["composite_innovation_score"]) < 0.01
    findings = [{"category": f.category, "severity": f.severity, "evidence": f.evidence,
                 "explanation": f.explanation, "contribution": f.contribution} for f in result.evidence]
    assert result.combined_score == max([f["contribution"] for f in findings] + [0])  # weights 1/0: the floor rules

    embedder = HighDimensionalEmbedding()
    samples = [
        ("text_a", "English text A", TEXT_A.encode()[:4096]),
        ("text_b", "English text B", TEXT_B.encode()[:4096]),
        ("code_a", "Machine code", code_like(4096)),
        ("rand_a", "Pseudo-random A", pseudo_random(4096, b"seed-a")),
        ("rand_b", "Pseudo-random B", pseudo_random(4096, b"seed-b")),
        ("zeros", "Zero padding", bytes(4096)),
    ]
    vectors, embed_out = [], []
    for key, label, data in samples:
        v = embedder.embed_bytes(data)
        vectors.append(v)
        b64, peak = quantize(v)
        channel_nonzero = [sum(1 for x in v[c * LATENT_CHANNEL_DIMENSION:(c + 1) * LATENT_CHANNEL_DIMENSION] if x) for c in range(4)]
        embed_out.append({"id": key, "label": label, "bytes": len(data), "q": b64, "peak": r(peak, 5),
                          "nonzero": channel_nonzero, "norm": r(math.sqrt(math.fsum(x * x for x in v)), 6)})
    similarity = [[r(math.fsum(a * b for a, b in zip(u, w)), 3) for w in vectors] for u in vectors]

    document = {
        "generated_by": "web_v/make_science_data.py",
        "entropy": {
            "file_bytes": len(blob),
            "window": ent["window_size"],
            "step": ent["step_size"],
            "trajectory": [r(x) for x in ent["trajectory"]],
            "offsets": ent["window_offsets"],
            "anomalies": [{"start": a["offset_start"], "end": a["offset_end"], "delta": r(a["delta"]), "severity": a["severity"]}
                          for a in ent["anomalies"]],
            "mean": r(ent["mean_entropy"]),
            "peak": r(ent["peak_entropy"]),
            "gradient_variance": r(ent["gradient_variance"]),
            "regions": offsets,
        },
        "cfg": [cfg_sample("ordinary", "Ordinary loop", ORDINARY), cfg_sample("xorloop", "In-place XOR loop", XOR_LOOP)],
        "embedding": {"dimension": embedder.DIMENSION, "channel": LATENT_CHANNEL_DIMENSION, "samples": embed_out,
                      "similarity": similarity},
        "scan_topography": {
            "window": scan_ent["window_size"],
            "step": scan_ent["step_size"],
            "trajectory": [r(x) for x in scan_ent["trajectory"]],
            "offsets": scan_ent["window_offsets"],
            "anomalies": [{"start": a["offset_start"], "end": a["offset_end"], "delta": r(a["delta"]), "severity": a["severity"]}
                          for a in scan_ent["anomalies"]],
            "mean": r(scan_ent["mean_entropy"]),
            "peak": r(scan_ent["peak_entropy"]),
        },
        "assessment": {
            "file": "demo_sample.bin",
            "findings": findings,
            "combined_score": result.combined_score,
            "classification": result.classification,
            "band_rule": classify_risk(result.combined_score),
            "mitre": result.mitre_techniques,
            "composite": nextgen["composite_innovation_score"],
            "components": {k: r(v, 2) for k, v in components.items()},
            "storyline": nextgen["forensic_storyboard"],
            "engines": {k: v for k, v in result.engine_status.items() if k in ("PE", "ML", "OSINT", "Dissonance", "Surprise map")},
            "classifier": prediction.get("status"),
            "osint": intelligence.get("status"),
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")
    print("verdict", result.combined_score, result.classification, findings)
    print("composite", nextgen["composite_innovation_score"], components, result.mitre_techniques)
    for c in document["cfg"]:
        print(c["id"], c["metrics"], c["descriptive_patterns"], c["evidence_patterns"], c["edges"])
    print("similarity", similarity)


if __name__ == "__main__":
    main()
