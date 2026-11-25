"""Measure the CyberScan detection engine and write the numbers the /tests page shows.

    .venv/Scripts/python.exe tools/bench_engine.py [--limit 400] [--out web_v/static/data/bench.json]

What it measures, honestly:
  * false positives: the engine (the same ScanService the website uses, threat-intel lookups off)
    runs over a benign corpus built only from files on this machine that are known not to be
    malware: this repository's own website files and the third-party packages installed in the
    project's virtual environment (.venv). That includes real Windows PE binaries (.pyd/.dll from
    well-known packages such as numpy, PySide6 and Pillow). Windows system files are NOT used.
  * synthetic samples: inert files built from the test fixtures in tests/ (tests/repair_fixtures.py
    and the payload strings the unit tests use). They contain the *shapes* of attacks (an
    auto-running PDF script, an encoded PowerShell line, a macro that calls Shell) but nothing runs.
  * speed: wall time per file on this computer.

What it does NOT measure: detection of real, live malware. No malware, no EICAR string and no
downloaded sample is used, so there is no malware detection rate here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

FLAGGED = {"SUSPICIOUS", "REVIEW"}
MAX_SIZE = 4 * 1024 * 1024      # the public website's upload limit


def benign_corpus(limit: int, seed: int = 1430) -> list[tuple[str, Path]]:
    """(group, path) pairs, a fixed random sample per group so runs are comparable."""
    venv = ROOT / ".venv" / "Lib" / "site-packages"
    static = ROOT / "web_v" / "static"
    groups: dict[str, list[Path]] = {
        "PE binaries (.pyd/.dll from .venv packages)": [p for ext in ("*.pyd", "*.dll") for p in venv.rglob(ext)],
        "Python source (.venv packages)": list(venv.rglob("*.py")),
        "Data and text (.json/.txt/.md/.toml/.cfg)": [p for ext in ("*.json", "*.txt", "*.md", "*.toml", "*.cfg")
                                                       for p in (*venv.rglob(ext), *ROOT.glob(ext))],
        "Website code (.js/.css/.html)": [p for ext in ("*.js", "*.css", "*.html") for p in static.rglob(ext)
                                          if "pyodide" not in p.parts and "vendor" not in p.parts],
        "Images, fonts and audio": [p for ext in ("*.png", "*.jpg", "*.webp", "*.ico", "*.woff2", "*.mp3", "*.svg")
                                    for p in static.rglob(ext) if "pyodide" not in p.parts],
        "Archives and documents (.zip/.whl/.pdf)": [p for ext in ("*.zip", "*.pdf") for p in (*venv.rglob(ext), *ROOT.glob(f"docs/**/{ext}"))],
    }
    rng = random.Random(seed)
    per = max(1, limit // len(groups))
    out: list[tuple[str, Path]] = []
    for name, files in groups.items():
        files = sorted({p for p in files if p.is_file() and 0 < p.stat().st_size <= MAX_SIZE})
        rng.shuffle(files)
        out += [(name, p) for p in files[:per]]
    return out


def synthetic_samples() -> list[tuple[str, str, str, bytes]]:
    """(name, expected, file name, bytes). expected: 'flag' (should be REVIEW/SUSPICIOUS) or 'clean'."""
    import repair_fixtures as fx  # tests/repair_fixtures.py: inert, byte-built files

    module = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  Shell \"calc.exe\"\r\nEnd Sub\r\n" * 60
    samples: list[tuple[str, str, bytes, str]] = [
        ("PDF that runs a script when opened (/OpenAction + /JavaScript)", "flag", fx.build_pdf()[0], ".pdf"),
        ("Text with an encoded PowerShell command", "flag", b"powershell -nop -w hidden -enc SQBFAFgA\r\ncmd.exe /c vssadmin delete shadows /all /quiet\r\n", ".txt"),
        ("Program with a hidden encoded PowerShell string", "flag", fx.build_pe(overlay=b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00")[0], ".exe"),
        ("Document named .pdf that is really a program", "flag", fx.build_pe()[0], ".pdf"),
        ("Program with a large high-entropy appended block", "flag", fx.build_pe(overlay=random.Random(7).randbytes(96 * 1024))[0], ".exe"),
        ("Office macro text with AutoOpen + Shell", "flag", module, ".bas"),
        ("ZIP with data hidden before the archive", "flag", fx.build_zip(prefix=fx.build_pe()[0])[0], ".zip"),
        ("Clean minimal PE (no overlay)", "clean", fx.build_pe()[0], ".exe"),
        ("Clean PNG", "clean", fx.build_png()[0], ".png"),
        ("Clean JPEG", "clean", fx.build_jpeg()[0], ".jpg"),
        ("Clean GIF", "clean", fx.build_gif()[0], ".gif"),
        ("Clean OOXML document", "clean", fx.build_ooxml()[0], ".docx"),
        ("Clean ZIP", "clean", fx.build_zip()[0], ".zip"),
        ("Plain English text", "clean", b"Meeting notes: send the quarterly figures to the team on Monday.\n" * 20, ".txt"),
    ]
    return [(name, expected, f"sample-{i:02d}{ext}", data) for i, (name, expected, data, ext) in enumerate(samples)]


def engine_version() -> str:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%h %ad", "--date=short"],
                              capture_output=True, text=True, timeout=10).stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=420)
    ap.add_argument("--out", default=str(ROOT / "web_v" / "static" / "data" / "bench.json"))
    args = ap.parse_args()

    from config import DEFAULT_SETTINGS
    from ui.scan_service import ScanService

    settings = {**DEFAULT_SETTINGS, "osint_enabled": False, "analysis_timeout": 60.0}
    service = ScanService()

    reasons: dict[str, int] = {}

    def scan(path: Path) -> tuple[str, int, float]:
        t0 = time.perf_counter()
        result, *_ = service.analyze(str(path), "File", settings)
        if result.classification in FLAGGED and result.evidence:
            top = max(result.evidence, key=lambda f: f.contribution)
            reasons[top.evidence[:90]] = reasons.get(top.evidence[:90], 0) + 1
        return result.classification, int(result.combined_score), time.perf_counter() - t0

    corpus = benign_corpus(args.limit)
    groups: dict[str, dict] = {}
    times: list[float] = []
    flagged_files: list[dict] = []
    errors = 0
    for n, (group, path) in enumerate(corpus, 1):
        g = groups.setdefault(group, {"files": 0, "bytes": 0, "suspicious": 0, "review": 0, "clean": 0, "errors": 0})
        try:
            cls, score, secs = scan(path)
        except Exception as exc:  # noqa: BLE001 - a crash is a result too
            g["errors"] += 1
            errors += 1
            print(f"  error {path.name}: {exc}", file=sys.stderr)
            continue
        g["files"] += 1
        g["bytes"] += path.stat().st_size
        times.append(secs)
        key = {"SUSPICIOUS": "suspicious", "REVIEW": "review"}.get(cls, "clean")
        g[key] += 1
        if cls in FLAGGED:
            flagged_files.append({"group": group, "file": path.name, "type": path.suffix.lower(), "classification": cls, "score": score})
        if n % 25 == 0:
            print(f"  {n}/{len(corpus)} scanned", file=sys.stderr)

    total = sum(g["files"] for g in groups.values())
    suspicious = sum(g["suspicious"] for g in groups.values())
    review = sum(g["review"] for g in groups.values())

    # Synthetic samples are checked in memory by the same static engine the scan service calls
    # (core.scanner.scan_target with the file's bytes): written to disk on Windows, the byte-built
    # test programs are quarantined by Microsoft Defender before CyberScan can read them.
    from core.scanner import scan_target

    synth = []
    for name, expected, filename, data in synthetic_samples():
        result = scan_target(filename, is_file=True, settings=settings, file_data=data)
        cls, score = result.classification, int(result.combined_score)
        got = "flag" if cls in FLAGGED else "clean"
        synth.append({"name": name, "expected": expected, "classification": cls, "score": score, "ok": got == expected})

    flag_expected = [s for s in synth if s["expected"] == "flag" and s["ok"] is not None]
    clean_expected = [s for s in synth if s["expected"] == "clean" and s["ok"] is not None]
    out = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "engine": engine_version(),
        "machine": f"{platform.system()} {platform.release()}, Python {platform.python_version()}, {os.cpu_count()} CPU threads",
        "settings": "Website defaults; online threat-intelligence lookups off; 60 s time limit per file",
        "benign": {
            "files": total, "bytes": sum(g["bytes"] for g in groups.values()), "errors": errors,
            "suspicious": suspicious, "review": review,
            "fp_suspicious_rate": round(suspicious / total, 4) if total else None,
            "fp_any_rate": round((suspicious + review) / total, 4) if total else None,
            "groups": groups,
            "flagged": sorted(flagged_files, key=lambda f: -f["score"])[:40],
            "top_reasons": sorted(([k, v] for k, v in reasons.items()), key=lambda kv: -kv[1])[:8],
        },
        "synthetic": {
            "samples": synth,
            "flagged_of_expected": [sum(s["ok"] for s in flag_expected), len(flag_expected)],
            "clean_of_expected": [sum(s["ok"] for s in clean_expected), len(clean_expected)],
        },
        "speed": {
            "median_s": round(statistics.median(times), 3) if times else None,
            "p95_s": round(sorted(times)[int(len(times) * 0.95) - 1], 3) if len(times) > 20 else None,
            "max_s": round(max(times), 3) if times else None,
        },
        "corpus_digest": hashlib.sha256("\n".join(sorted(p.name + str(p.stat().st_size) for _, p in corpus)).encode()).hexdigest()[:16],
        "not_measured": [
            "Detection of real, live malware (no malware or EICAR test file was used).",
            "Files larger than 4 MB (the website's upload limit).",
            "Online threat-intelligence lookups (they were switched off for repeatability).",
        ],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("engine", "speed")}, indent=1))
    print(f"benign: {total} files, {suspicious} suspicious, {review} review; synthetic flagged "
          f"{out['synthetic']['flagged_of_expected']}, clean {out['synthetic']['clean_of_expected']} -> {args.out}")


if __name__ == "__main__":
    main()
