"""Detection, repair and security evaluation of CyberScan.

Everything is static: no sample is ever executed, opened by another
program, passed to a shell or a loader (the project's hard safety rules).
Malicious-side samples are only (a) the EICAR test string, (b) the
project's inert mock samples, and (c) inert indicator samples generated
here: random bytes or placeholder text carrying *fragments* of known
indicators, never working code. Real malware is not used and is not
available (the EMBER2024/SOREL downloads are paused).

Writes reports/evaluation/results.json and a log.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import random
import re
import struct
import sys
import tempfile
import time
import traceback
import zipfile
import zlib
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "reports" / "evaluation"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.chdir(ROOT)

RESULTS: dict = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "sections": {}}
LOG = []


def log(text: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {text}"
    LOG.append(line)
    print(line, flush=True)


def save() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    RESULTS["log"] = LOG[-400:]
    (OUT / "results.json").write_text(json.dumps(RESULTS, indent=1, ensure_ascii=False, default=str), encoding="utf-8")


def memory() -> dict:
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32")
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    kernel.K32GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
    mb = 1024 * 1024
    return {"working_mb": round(counters.WorkingSetSize / mb), "peak_working_mb": round(counters.PeakWorkingSetSize / mb),
            "commit_mb": round(counters.PagefileUsage / mb), "peak_commit_mb": round(counters.PeakPagefileUsage / mb)}


# -- metrics ------------------------------------------------------------------------------------


def confusion(labels, predictions) -> dict:
    tp = sum(1 for y, p in zip(labels, predictions) if y and p)
    tn = sum(1 for y, p in zip(labels, predictions) if not y and not p)
    fp = sum(1 for y, p in zip(labels, predictions) if not y and p)
    fn = sum(1 for y, p in zip(labels, predictions) if y and not p)
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall and not math.isnan(precision + recall) else float("nan")
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "fpr": fp / (fp + tn) if fp + tn else float("nan"), "fnr": fn / (fn + tp) if fn + tp else float("nan"),
            "precision": precision, "recall": recall, "f1": f1,
            "accuracy": (tp + tn) / max(1, tp + tn + fp + fn), "n": tp + tn + fp + fn}


def roc_auc(labels, scores) -> float:
    """Probability a random positive outscores a random negative (ties count half)."""
    positives = [s for y, s in zip(labels, scores) if y]
    negatives = [s for y, s in zip(labels, scores) if not y]
    if not positives or not negatives:
        return float("nan")
    wins = 0.0
    for p in positives:
        for n in negatives:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(positives) * len(negatives))


def wilson(successes: int, total: int) -> list[float]:
    """95% Wilson interval for a rate."""
    if total == 0:
        return [float("nan"), float("nan")]
    z, phat = 1.96, successes / total
    centre = (phat + z * z / (2 * total)) / (1 + z * z / total)
    half = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


# -- samples --------------------------------------------------------------------------------------

BENIGN_EXT = {".pdf", ".docx", ".xlsx", ".pptx", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".txt", ".csv", ".json",
              ".html", ".py", ".md", ".exe", ".dll", ".mp3", ".mp4", ".doc", ".xls", ".rtf", ".svg", ".xml"}


def collect_benign(limit: int, seed: int = 7) -> list[Path]:
    """Real files from this machine: the user's folders, Windows' own programs, Python's library."""
    rng = random.Random(seed)
    roots = [Path.home() / name for name in ("Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos")]
    pool: dict[str, list[Path]] = defaultdict(list)
    for root in roots:
        for folder, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "__pycache__", "dist", "AppData", "site-packages"}]
            for name in names:
                path = Path(folder) / name
                if path.suffix.lower() in BENIGN_EXT:
                    try:
                        if 0 < path.stat().st_size <= 20 * 1024 * 1024:
                            pool[path.suffix.lower()].append(path)
                    except OSError:
                        pass
            if sum(len(v) for v in pool.values()) > 6000:
                break
    system = Path(r"C:\Windows\System32")
    for name in sorted(os.listdir(system)):
        path = system / name
        if path.suffix.lower() in {".exe", ".dll"} and path.is_file():
            try:
                if 0 < path.stat().st_size <= 8 * 1024 * 1024:
                    pool["sys" + path.suffix.lower()].append(path)
            except OSError:
                pass
    for path in (Path(sys.base_prefix) / "Lib").glob("*.py"):
        pool["lib.py"].append(path)
    chosen: list[Path] = []
    groups = sorted(pool)
    per = max(4, limit // max(1, len(groups)))
    for group in groups:
        items = pool[group]
        rng.shuffle(items)
        chosen += items[:per]
    rng.shuffle(chosen)
    return chosen[:limit]


INDICATORS = [
    b"powershell -nop -w hidden -enc SQBFAFgA",
    b"cmd.exe /c vssadmin delete shadows /all /quiet",
    b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00",
    b"IEX (New-Object Net.WebClient).DownloadString(",
    b"certutil -urlcache -split -f http://",
    b"bcdedit /set {default} recoveryenabled No",
    b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"schtasks /create /sc minute /tn",
    b"mshta vbscript:Execute(",
    b"wmic shadowcopy delete",
]


def mutate_indicator(fragment: bytes, how: str) -> bytes:
    """Ways an attacker hides the same intent (all still inert fragments)."""
    text = fragment.decode("latin-1")
    if how == "utf16":
        return text.encode("utf-16-le")
    if how == "base64":
        return base64.b64encode(fragment)
    if how == "spaced":
        return " ".join(text).encode("latin-1")
    if how == "concat":
        middle = len(text) // 2
        return f'"{text[:middle]}" + "{text[middle:]}"'.encode("latin-1")
    if how == "caret":  # cmd's escape character between letters
        return "^".join(text).encode("latin-1")
    if how == "case":
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(text)).encode("latin-1")
    return fragment


def make_indicator_samples(folder: Path, rng: random.Random, count: int) -> list[tuple[Path, str, list[str]]]:
    """Inert samples: placeholder text or random bytes with 1-3 indicator fragments, in varied containers."""
    out = []
    containers = ("text_ps1", "text_bat", "text_txt", "random_bin", "pe_like", "double_ext", "rlo_name")
    for index in range(count):
        kind = containers[index % len(containers)]
        fragments = rng.sample(INDICATORS, rng.randint(1, 3))
        filler = b"Lorem ipsum placeholder text for an inert test sample.\r\n" * rng.randint(2, 40)
        body = filler + b"\r\n".join(fragments) + b"\r\n" + filler
        if kind == "random_bin":
            body = os.urandom(rng.randint(2000, 40000)) + b"\x00" + b"\x00".join(fragments) + b"\x00" + os.urandom(2000)
            name = f"blob_{index}.bin"
        elif kind == "pe_like":
            body = b"MZ" + bytes(200) + b"\x00".join(fragments) + os.urandom(rng.randint(1000, 8000))
            name = f"setup_{index}.exe"
        elif kind == "double_ext":
            name = f"invoice_{index}.pdf.exe"
            body = b"MZ" + bytes(100) + body
        elif kind == "rlo_name":
            name = f"photo_{index}\u202egpj.exe"
            body = b"MZ" + bytes(100) + body
        else:
            name = f"script_{index}." + {"text_ps1": "ps1", "text_bat": "bat", "text_txt": "txt"}[kind]
        path = folder / name
        path.write_bytes(body)
        out.append((path, kind, [f[:24].decode("latin-1") for f in fragments]))
    return out


# -- main -----------------------------------------------------------------------------------------


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cs_eval_"))
    log(f"work folder {work}")
    rng = random.Random(2026)
    np_random = None
    import numpy as np

    from config import DEFAULT_SETTINGS
    from ui.scan_service import ScanService

    service = ScanService()
    settings = dict(DEFAULT_SETTINGS)
    settings["osint_enabled"] = False
    crashes: list[dict] = []

    def scan(path: Path | str, mode: str = "File") -> dict:
        started, cpu = time.perf_counter(), time.process_time()
        try:
            result = service.analyze(str(path), mode, settings)[0]
            return {"ok": True, "score": float(result.combined_score), "class": result.classification,
                    "evidence": [f"{e.category}: {e.evidence[:70]}" for e in result.evidence][:12], "seconds": time.perf_counter() - started,
                    "cpu": time.process_time() - cpu, "yara": [m.get("rule") for m in result.yara_matches][:6]}
        except Exception as exc:  # noqa: BLE001 - every exception is a measured outcome
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200], "seconds": time.perf_counter() - started,
                    "trace": traceback.format_exc(limit=3)[-600:]}

    # ============================================================== 1. detection (scanner)
    section = RESULTS["sections"]["detection"] = {}
    benign = collect_benign(260)
    log(f"benign files: {len(benign)} ({Counter(p.suffix.lower() for p in benign).most_common(12)})")
    malicious_dir = work / "malicious"
    malicious_dir.mkdir()
    positives: list[tuple[Path, str]] = []
    for name in ("virus.txt", "eicar_com.zip", "test_mock_malware.bin"):
        positives.append((ROOT / "mlware" / name, "signature" if "eicar" in name or name == "virus.txt" else "mock"))
    for path in sorted((ROOT / "data" / "datasets" / "synthetic_integration").glob("*.bin")):
        if path.name.startswith(("malware", "suspicious")):
            positives.append((path, "synthetic_" + path.name.split("_")[0]))
    for path, kind, _fragments in make_indicator_samples(malicious_dir, rng, 70):
        positives.append((path, "heuristic_" + kind))
    synthetic_clean = sorted((ROOT / "data" / "datasets" / "synthetic_integration").glob("clean_*.bin"))

    rows = []
    for index, path in enumerate(benign):
        outcome = scan(path)
        rows.append({"path": str(path), "label": 0, "group": "benign_" + path.suffix.lower(), **outcome})
        if index % 40 == 0:
            log(f"benign {index}/{len(benign)}")
    for path in synthetic_clean:
        rows.append({"path": str(path), "label": 0, "group": "synthetic_clean", **scan(path)})
    for path, group in positives:
        rows.append({"path": str(path), "label": 1, "group": group, **scan(path)})
    log("detection scans done")
    ok_rows = [r for r in rows if r["ok"]]
    crashes += [{"where": "scan", "path": r["path"], "error": r["error"]} for r in rows if not r["ok"]]
    labels = [r["label"] for r in ok_rows]
    scores = [r["score"] for r in ok_rows]
    section["sets"] = {"benign_real": len(benign), "benign_synthetic": len(synthetic_clean), "positive": len(positives),
                       "positive_by_group": Counter(g for _p, g in positives)}
    section["any_warning"] = confusion(labels, [s > 0 for s in scores])
    section["strong_warning"] = confusion(labels, [s >= 50 for s in scores])
    section["roc_auc"] = roc_auc(labels, scores)
    section["fpr_any_ci"] = wilson(section["any_warning"]["fp"], section["any_warning"]["fp"] + section["any_warning"]["tn"])
    section["recall_any_ci"] = wilson(section["any_warning"]["tp"], section["any_warning"]["tp"] + section["any_warning"]["fn"])
    by_group = defaultdict(lambda: {"n": 0, "flagged_any": 0, "flagged_strong": 0, "mean_score": 0.0})
    for row in ok_rows:
        g = by_group[row["group"]]
        g["n"] += 1
        g["flagged_any"] += row["score"] > 0
        g["flagged_strong"] += row["score"] >= 50
        g["mean_score"] += row["score"]
    for g in by_group.values():
        g["mean_score"] = round(g["mean_score"] / max(1, g["n"]), 1)
    section["by_group"] = dict(sorted(by_group.items()))
    section["false_positives"] = [{"path": r["path"], "score": r["score"], "evidence": r["evidence"][:4]} for r in ok_rows
                                  if not r["label"] and r["score"] > 0][:60]
    section["false_negatives"] = [{"path": r["path"], "group": r["group"], "score": r["score"]} for r in ok_rows
                                  if r["label"] and r["score"] <= 0]
    signature = [r for r in ok_rows if r["group"] == "signature"]
    section["signature_detection"] = [{"path": Path(r["path"]).name, "score": r["score"], "yara": r.get("yara"), "evidence": r["evidence"][:4]} for r in signature]
    times = [r["seconds"] for r in ok_rows]
    section["scan_seconds"] = {"median": float(np.median(times)), "p95": float(np.percentile(times, 95)), "max": max(times)}
    RESULTS["sections"]["detection_rows"] = [{k: r.get(k) for k in ("path", "label", "group", "ok", "score", "class", "seconds", "error")} for r in rows]
    save()

    # ============================================================== 2. zero-day proxy and adversarial robustness
    section = RESULTS["sections"]["adversarial"] = {}
    adv_dir = work / "adversarial"
    adv_dir.mkdir()
    base_hits = 0
    variants = defaultdict(lambda: {"n": 0, "detected": 0})
    for index, fragment in enumerate(INDICATORS):
        filler = b"Placeholder text of an inert test sample.\r\n" * 12
        original = adv_dir / f"plain_{index}.txt"
        original.write_bytes(filler + fragment + b"\r\n" + filler)
        outcome = scan(original)
        detected = outcome.get("ok") and outcome["score"] > 0
        base_hits += bool(detected)
        variants["original"]["n"] += 1
        variants["original"]["detected"] += bool(detected)
        for how in ("utf16", "base64", "spaced", "concat", "caret", "case"):
            path = adv_dir / f"{how}_{index}.txt"
            path.write_bytes(filler + mutate_indicator(fragment, how) + b"\r\n" + filler)
            outcome = scan(path)
            variants[how]["n"] += 1
            variants[how]["detected"] += bool(outcome.get("ok") and outcome["score"] > 0)
        # Entropy padding: the same fragment buried in 2 MB of zeros, or in random bytes.
        for how, pad in (("zero_padding", bytes(2 * 1024 * 1024)), ("random_padding", os.urandom(512 * 1024))):
            path = adv_dir / f"{how}_{index}.bin"
            path.write_bytes(pad + fragment + pad)
            outcome = scan(path)
            variants[how]["n"] += 1
            variants[how]["detected"] += bool(outcome.get("ok") and outcome["score"] > 0)
    section["variants"] = {k: {**v, "rate": round(v["detected"] / max(1, v["n"]), 3)} for k, v in variants.items()}
    log("adversarial done")
    save()

    # ============================================================== 3. repair engine
    from repair_engine.analyze import analyze as repair_analyze, repair as repair_apply
    from repair_engine.parsers import parse
    from repair_engine.synth.injector import FAMILIES, inject

    section = RESULTS["sections"]["repair"] = {}
    eligible = [p for p in benign if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx", ".pptx", ".zip", ".exe", ".dll"}]
    pairs, clean_reports = [], []
    families = ["append_after_end", "pdf_javascript", "pdf_embedded_file", "ooxml_vba_part", "ooxml_embedded_object"]
    for index, path in enumerate(eligible[:180]):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        name = path.name
        try:
            before = repair_analyze(data, name)
        except Exception as exc:  # noqa: BLE001
            crashes.append({"where": "repair.analyze clean", "path": str(path), "error": repr(exc)[:200]})
            continue
        clean_reports.append({"path": str(path), "format": before.format, "findings": [f.key for f in before.findings],
                              "repairable": sum(f.repairable for f in before.findings),
                              "recommended": [f.key for f in before.findings if f.recommended]})
        for family in rng.sample(families, len(families)):
            injection = inject(data, name, family, rng.randrange(1 << 30))
            if injection is None or injection.content_kind == "zeros":
                continue
            try:
                report = repair_analyze(injection.modified, name)
            except Exception as exc:  # noqa: BLE001
                crashes.append({"where": "repair.analyze injected", "path": str(path), "error": repr(exc)[:200]})
                break
            new = [f for f in report.findings if f.key not in {g for g in clean_reports[-1]["findings"]}]
            found = [f for f in new if f.start is not None and any(f.start < end and (f.end or f.start) > start for start, end, _ in injection.regions)]
            chosen = [f for f in report.findings if f.repairable and f.recommended] or [f for f in new if f.repairable]
            started = time.perf_counter()
            result = repair_apply(injection.modified, name, chosen) if chosen else None
            elapsed = time.perf_counter() - started
            repaired = result.repaired if result is not None and result.ok else None
            pair = {"path": str(path), "format": report.format, "family": family, "content": injection.content_kind,
                    "detected": bool(new), "located": bool(found), "repairable": bool(chosen), "repair_seconds": round(elapsed, 3),
                    "repaired": repaired is not None, "byte_identical": repaired == data if repaired is not None else False,
                    "sha_match": (hashlib.sha256(repaired).hexdigest() == hashlib.sha256(data).hexdigest()) if repaired is not None else False,
                    "validation": (result.validation.checks if result is not None and result.validation else None),
                    "after_findings": (result.after if result is not None else None), "score": max([{"high": 3, "medium": 2, "low": 1}.get(f.severity, 0) for f in new] or [0])}
            if repaired is not None:
                pair.update(_functional(data, repaired, path.suffix.lower()))
                try:
                    rescan = repair_analyze(repaired, result.name)
                    pair["prsv_findings"] = len(rescan.findings)
                    pair["prsv_same_as_clean"] = sorted(f.key for f in rescan.findings) == sorted(clean_reports[-1]["findings"])
                except Exception as exc:  # noqa: BLE001
                    crashes.append({"where": "prsv", "path": str(path), "error": repr(exc)[:200]})
            pairs.append(pair)
            break  # one family per file keeps the set balanced
        if index % 40 == 0:
            log(f"repair {index}/{len(eligible[:180])}")
    labels = [0] * len(clean_reports) + [1] * len(pairs)
    preds = [bool(c["repairable"]) for c in clean_reports] + [p["detected"] for p in pairs]
    scores_r = [max([0] + [1 for _ in c["findings"]]) for c in clean_reports] + [p["score"] for p in pairs]
    section["detection_on_tampering"] = confusion(labels, preds)
    section["detection_on_tampering"]["note"] = "positive = a finding the injection caused; on clean files, positive = any repairable finding"
    section["roc_auc"] = roc_auc(labels, scores_r)
    section["preselected_on_clean"] = sum(1 for c in clean_reports if c["recommended"])
    section["clean_files"] = len(clean_reports)
    section["clean_findings_by_kind"] = Counter(k.split("@")[0] for c in clean_reports for k in c["findings"])
    section["pairs"] = len(pairs)
    section["by_family"] = {}
    for family in families:
        chosen = [p for p in pairs if p["family"] == family]
        if chosen:
            section["by_family"][family] = {
                "n": len(chosen), "detected": sum(p["detected"] for p in chosen), "located": sum(p["located"] for p in chosen),
                "repaired": sum(p["repaired"] for p in chosen), "byte_identical": sum(p["byte_identical"] for p in chosen)}
    repaired = [p for p in pairs if p["repaired"]]
    section["repair_integrity"] = {
        "repaired": len(repaired), "of_detected": sum(p["detected"] for p in pairs),
        "byte_identical": sum(p["byte_identical"] for p in repaired), "sha_match": sum(p["sha_match"] for p in repaired),
        "validation_passed": sum(1 for p in repaired if p["validation"] and all(str(v).startswith("ok") for k, v in p["validation"].items() if k != "scores")),
        "prsv_clean": sum(1 for p in repaired if p.get("prsv_same_as_clean")),
        "functional_ok": sum(1 for p in repaired if p.get("functional") is True),
        "functional_checked": sum(1 for p in repaired if p.get("functional") is not None),
        "metadata_ok": sum(1 for p in repaired if p.get("metadata") is True),
        "content_ok": sum(1 for p in repaired if p.get("content") is True),
        "median_seconds": float(np.median([p["repair_seconds"] for p in repaired])) if repaired else None,
    }
    section["failures"] = [p for p in pairs if p["detected"] and not p["byte_identical"]][:20]
    RESULTS["sections"]["repair_pairs"] = pairs
    log("repair done")
    save()

    # ============================================================== 4. robustness: corrupted, malformed, fuzz
    section = RESULTS["sections"]["robustness"] = {}
    seeds = [p for p in eligible if p.stat().st_size < 3 * 1024 * 1024][:60]
    cases = Counter()
    parser_crashes, slow = [], []
    for round_ in range(3000):
        source = seeds[round_ % len(seeds)].read_bytes()
        how = ("truncate", "bitflip", "byteblock", "splice", "header_zero", "length_bomb")[round_ % 6]
        data = bytearray(source)
        if how == "truncate":
            data = data[: rng.randrange(1, max(2, len(data)))]
        elif how == "bitflip":
            for _ in range(rng.randint(1, 40)):
                i = rng.randrange(len(data))
                data[i] ^= 1 << rng.randrange(8)
        elif how == "byteblock":
            i = rng.randrange(len(data))
            data[i:i + 64] = os.urandom(64)
        elif how == "splice":
            other = seeds[rng.randrange(len(seeds))].read_bytes()
            cut = rng.randrange(len(data))
            data = data[:cut] + other[rng.randrange(len(other)):]
        elif how == "header_zero":
            data[: min(64, len(data))] = bytes(min(64, len(data)))
        else:  # big length fields where formats keep them
            for i in range(min(len(data) - 4, 400), 0, -97):
                struct.pack_into("<I", data, i, 0xFFFFFFF0)
        cases[how] += 1
        started = time.perf_counter()
        try:
            parse(bytes(data), seeds[round_ % len(seeds)].name)
            repair_analyze(bytes(data), seeds[round_ % len(seeds)].name)
        except Exception as exc:  # noqa: BLE001
            parser_crashes.append({"how": how, "source": seeds[round_ % len(seeds)].name, "error": f"{type(exc).__name__}: {exc}"[:200]})
        took = time.perf_counter() - started
        if took > 2.0:
            slow.append({"how": how, "source": seeds[round_ % len(seeds)].name, "seconds": round(took, 2)})
    section["parser_fuzz"] = {"cases": sum(cases.values()), "by_mutation": cases, "crashes": len(parser_crashes),
                              "crash_examples": parser_crashes[:10], "slow_over_2s": slow[:10]}
    log(f"parser fuzz: {len(parser_crashes)} crashes in {sum(cases.values())}")
    # The whole scanner on corrupted and malformed files.
    fuzz_dir = work / "fuzz"
    fuzz_dir.mkdir()
    scanner_cases = []
    for index in range(150):
        source = seeds[index % len(seeds)]
        data = bytearray(source.read_bytes())
        for _ in range(rng.randint(1, 60)):
            i = rng.randrange(len(data))
            data[i] = rng.randrange(256)
        if index % 3 == 0:
            data = data[: rng.randrange(1, len(data))]
        target = fuzz_dir / f"fuzz_{index}{source.suffix}"
        target.write_bytes(bytes(data))
        outcome = scan(target)
        scanner_cases.append({"source": source.name, "ok": outcome["ok"], "seconds": round(outcome["seconds"], 2),
                              "error": outcome.get("error")})
    malformed = _malformed_samples(work / "malformed")
    for name, path in malformed:
        outcome = scan(path)
        scanner_cases.append({"source": name, "ok": outcome["ok"], "seconds": round(outcome["seconds"], 2), "error": outcome.get("error"),
                              "score": outcome.get("score"), "evidence": outcome.get("evidence", [])[:3], "malformed": True})
    section["scanner_fuzz"] = {"cases": len(scanner_cases), "errors": sum(1 for c in scanner_cases if not c["ok"]),
                               "error_examples": [c for c in scanner_cases if not c["ok"]][:10],
                               "max_seconds": max(c["seconds"] for c in scanner_cases),
                               "malformed": [c for c in scanner_cases if c.get("malformed")]}
    crashes += [{"where": "scanner fuzz", **c} for c in scanner_cases if not c["ok"]]
    log("scanner fuzz done")
    save()

    # ============================================================== 5. format confusion and file-type validation
    section = RESULTS["sections"]["formats"] = {}
    confusion_cases = _polyglots(work / "polyglot")
    results = []
    for name, path, expectation in confusion_cases:
        outcome = scan(path)
        regions = parse(path.read_bytes(), path.name)
        results.append({"case": name, "expect": expectation, "scanner_score": outcome.get("score"), "scanner_evidence": outcome.get("evidence", [])[:4],
                        "parser_format": regions.format, "parser_mismatch": bool(regions.of_kind("magic_mismatch")),
                        "after_eof": bool(regions.of_kind("after_eof"))})
    section["format_confusion"] = results
    # File type validation: does the parser's format agree with the extension on real files?
    agree = Counter()
    mismatches = []
    expected = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".pdf": "pdf", ".zip": "zip", ".docx": "ooxml",
                ".xlsx": "ooxml", ".pptx": "ooxml", ".exe": "pe", ".dll": "pe", ".doc": "ole", ".xls": "ole"}
    for path in benign:
        want = expected.get(path.suffix.lower())
        if want is None:
            continue
        try:
            got = parse(path.read_bytes(), path.name).format
        except Exception as exc:  # noqa: BLE001
            got = f"error {type(exc).__name__}"
        agree[got == want] += 1
        if got != want:
            mismatches.append({"path": path.name, "extension": path.suffix, "detected": got})
    section["file_type_validation"] = {"checked": sum(agree.values()), "agree": agree[True], "mismatches": mismatches[:20]}
    log("formats done")
    save()

    # ============================================================== 6. archives, large files, resources
    section = RESULTS["sections"]["resources"] = {}
    archive_dir = work / "archives"
    archive_dir.mkdir()
    archive_cases = _archives(archive_dir)
    archive_results = []
    for name, path in archive_cases:
        before = memory()
        outcome = scan(path)
        after = memory()
        archive_results.append({"case": name, "size_kb": round(path.stat().st_size / 1024, 1), "ok": outcome["ok"],
                                "seconds": round(outcome["seconds"], 2), "score": outcome.get("score"),
                                "evidence": outcome.get("evidence", [])[:4], "error": outcome.get("error"),
                                "peak_commit_mb": after["peak_commit_mb"], "commit_growth_mb": after["commit_mb"] - before["commit_mb"]})
    section["archives"] = archive_results
    log("archives done")
    large = []
    for size_mb in (49, 51, 200):
        path = work / f"large_{size_mb}.bin"
        with open(path, "wb") as handle:
            handle.seek(size_mb * 1024 * 1024 - 1)
            handle.write(b"\0")
        before = memory()
        outcome = scan(path)
        large.append({"size_mb": size_mb, "ok": outcome["ok"], "seconds": round(outcome["seconds"], 2),
                      "cpu_seconds": round(outcome.get("cpu", 0), 2), "error": outcome.get("error"),
                      "peak_commit_mb": memory()["peak_commit_mb"], "commit_before_mb": before["commit_mb"]})
        path.unlink()
    section["large_files"] = large
    cpu = [r.get("cpu", 0) for r in rows if r.get("ok")]
    section["per_scan_cpu_seconds"] = {"median": float(np.median(cpu)), "p95": float(np.percentile(cpu, 95))}
    section["memory_now"] = memory()
    log("large files done")
    save()

    # ============================================================== 7. paths, isolation, execution audit
    section = RESULTS["sections"]["isolation"] = {}
    paths = []
    long_dir = work / ("d" * 120) / ("e" * 120)
    try:
        os.makedirs("\\\\?\\" + str(long_dir), exist_ok=True)
        long_file = "\\\\?\\" + str(long_dir / "long_path_file.txt")
        with open(long_file, "wb") as handle:
            handle.write(b"hello")
    except OSError as exc:
        long_file = None
        log(f"long path not created: {exc}")
    for label, target in (("device NUL", "NUL"), ("device CON", "CON"), ("raw disk", r"\\.\PhysicalDrive0"),
                          ("directory", str(work)), ("missing", str(work / "nope.bin")),
                          ("long path (>260)", long_file or ""), ("path traversal", str(work / ".." / ".." / "Windows" / "win.ini"))):
        if not target:
            continue
        outcome = scan(target)
        paths.append({"case": label, "ok": outcome["ok"], "seconds": round(outcome["seconds"], 2), "error": outcome.get("error"),
                      "score": outcome.get("score")})
    section["path_inputs"] = paths
    section["quarantine"] = _quarantine_round_trip(work)
    section["execution_audit"] = _execution_audit()
    log("isolation done")
    save()

    # ============================================================== 8. the learning model
    RESULTS["sections"]["model"] = _model_tests(benign, rng)
    log("model done")
    RESULTS["sections"]["crashes"] = {"count": len(crashes), "examples": crashes[:25]}
    RESULTS["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save()
    log("finished")


# -- helpers --------------------------------------------------------------------------------------


def _functional(original: bytes, repaired: bytes, suffix: str) -> dict:
    """Does the repaired file still work as its kind, with the same content and metadata?"""
    out = {"functional": None, "content": None, "metadata": None}
    try:
        if suffix in {".png", ".jpg", ".jpeg", ".gif"}:
            from PySide6.QtGui import QImage

            a, b = QImage.fromData(original), QImage.fromData(repaired)
            out["functional"] = not b.isNull()
            out["content"] = (not a.isNull()) and a == b
            out["metadata"] = (a.width(), a.height()) == (b.width(), b.height())
        elif suffix in {".docx", ".xlsx", ".pptx", ".zip"}:
            with zipfile.ZipFile(io.BytesIO(original)) as one, zipfile.ZipFile(io.BytesIO(repaired)) as two:
                out["functional"] = two.testzip() is None
                names = sorted(n for n in one.namelist())
                out["content"] = names == sorted(two.namelist()) and all(one.read(n) == two.read(n) for n in names)
                out["metadata"] = all(one.getinfo(n).date_time == two.getinfo(n).date_time for n in names if n in two.namelist())
        elif suffix == ".pdf":
            from repair_engine.parsers import parse

            a, b = parse(original, "a.pdf"), parse(repaired, "a.pdf")
            out["functional"] = b.format == "pdf" and not b.errors
            out["content"] = len(a.of_kind("pdf_object")) == len(b.of_kind("pdf_object"))
            out["metadata"] = repaired[:8] == original[:8]
        elif suffix in {".exe", ".dll"}:
            from repair_engine import pe_layout

            pe_layout.read(repaired)
            out["functional"] = True
            out["content"] = repaired == original
            out["metadata"] = repaired[:0x400] == original[:0x400]
    except Exception as exc:  # noqa: BLE001
        out["functional"] = False
        out["error"] = repr(exc)[:160]
    return out


def _malformed_samples(folder: Path) -> list[tuple[str, Path]]:
    folder.mkdir()
    cases = []

    def put(name, data):
        path = folder / name
        path.write_bytes(data)
        cases.append((name, path))

    pe = bytearray(b"MZ" + bytes(0x3E))
    struct.pack_into("<I", pe, 0x3C, 0xFFFFFFF0)  # e_lfanew far outside the file
    put("pe_bad_lfanew.exe", bytes(pe) + bytes(200))
    pe2 = bytearray(b"MZ" + bytes(0x3E) + b"PE\0\0" + bytes(20))
    struct.pack_into("<I", pe2, 0x3C, 0x40)
    struct.pack_into("<H", pe2, 0x46, 0xFFFF)  # 65535 sections declared
    put("pe_65535_sections.exe", bytes(pe2) + bytes(400))
    put("zip_bad_central_dir.zip", b"PK\x03\x04" + bytes(26) + b"PK\x05\x06" + bytes(8) + struct.pack("<IIH", 0xFFFFFFFF, 0xFFFFFFF0, 0))
    put("pdf_garbage_xref.pdf", b"%PDF-1.7\n1 0 obj << /Length 999999999 >> stream\n" + os.urandom(2000) + b"\nxref\nGARBAGE\ntrailer << /Root 99 0 R >>\nstartxref\n-5\n%%EOF")
    put("png_bad_crc.png", b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 100000, 100000, 8, 6, 0, 0, 0) + b"BADC")
    put("gif_zero_size.gif", b"GIF89a" + bytes(7))
    put("ole_truncated.doc", bytes.fromhex("D0CF11E0A1B11AE1") + bytes(100))
    put("deep_pdf_nesting.pdf", b"%PDF-1.4\n1 0 obj " + b"<<" * 5000 + b">>" * 5000 + b" endobj\n%%EOF")
    return cases


def _polyglots(folder: Path) -> list[tuple[str, Path, str]]:
    folder.mkdir()
    from repair_fixtures import build_png, build_zip
    from test_repair_engine_synth import simple_pdf

    png = build_png()[0]
    archive, _ = build_zip(members={"readme.txt": b"inert placeholder text " * 20})
    pdf = simple_pdf()
    cases = []

    def put(name, data, expect):
        path = folder / name
        path.write_bytes(data)
        cases.append((name, path, expect))

    put("png_plus_zip.png", png + archive, "data after the picture's end, an archive")
    put("pdf_plus_zip.pdf", pdf + archive, "data after the PDF's end, an archive")
    put("zip_named_jpg.jpg", archive, "content is a zip, name says jpg")
    put("pe_named_pdf.pdf", b"MZ" + bytes(200) + b"This program cannot be run in DOS mode." + bytes(300), "content is a program, name says pdf")
    put("pdf_with_pe_prefix.pdf", b"MZ" + bytes(60) + pdf, "starts as a program, holds a PDF")
    put("html_named_png.png", b"<html><body><script>/* inert placeholder */</script></body></html>", "content is HTML, name says png")
    return cases


def _archives(folder: Path) -> list[tuple[str, Path]]:
    cases = []

    def put(name, writer):
        path = folder / name
        writer(path)
        cases.append((name, path))

    def zip_slip(path):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("../../../../Windows/Temp/evil.txt", "inert placeholder")
            z.writestr("C:/absolute/path.txt", "inert placeholder")
            z.writestr("normal.txt", "inert placeholder")

    def bomb(path):
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("zeros.bin", bytes(300 * 1024 * 1024))  # 300 MB of zeros, about 0.3 MB packed

    def nested(path):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("deep.txt", "inert placeholder " * 10)
        payload = inner.getvalue()
        for level in range(12):
            box = io.BytesIO()
            with zipfile.ZipFile(box, "w") as z:
                z.writestr(f"level_{level}.zip", payload)
            payload = box.getvalue()
        path.write_bytes(payload)

    def many(path):
        with zipfile.ZipFile(path, "w") as z:
            for i in range(20000):
                z.writestr(f"f/{i}.txt", "x")

    def encrypted(path):
        local = b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0x01, 0, 0, 0, 0, 5, 5, 8, 0) + b"secret.x" + b"\x01\x02\x03\x04\x05"
        central = b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0x01, 0, 0, 0, 0, 5, 5, 8, 0, 0, 0, 0, 0, 0) + b"secret.x"
        end = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(central), len(local), 0)
        path.write_bytes(local + central + end)

    def exe_inside(path):
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("invoice.pdf.exe", b"MZ" + bytes(200) + b"powershell -nop -w hidden -enc SQBFAFgA")
            z.writestr("readme.txt", "inert placeholder")

    for name, writer in (("zip_slip.zip", zip_slip), ("zip_bomb_300mb.zip", bomb), ("nested_12_levels.zip", nested),
                         ("20000_entries.zip", many), ("encrypted_entry.zip", encrypted), ("disguised_exe_inside.zip", exe_inside)):
        put(name, writer)
    return cases


def _quarantine_round_trip(work: Path) -> dict:
    from ui import vault

    data_dir = work / "vault_data"
    data_dir.mkdir()
    sample = work / "to_isolate.exe"
    content = b"MZ" + bytes(100) + b"powershell -nop -w hidden -enc SQBFAFgA" + os.urandom(500)
    sample.write_bytes(content)
    out: dict = {}
    try:
        sealed = Path(vault.quarantine(str(sample), data_dir, data_dir / "quarantine"))
        stored = sealed.read_bytes()
        out["original_removed"] = not sample.exists()
        out["sealed_extension"] = sealed.suffix
        out["plaintext_absent"] = content[:200] not in stored and b"powershell" not in stored
        out["sealed_is_not_a_program"] = stored[:2] != b"MZ"
        restored = vault.restore(str(sealed), str(sample), data_dir)
        out["restored_identical"] = Path(restored).read_bytes() == content
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]
    return out


def _execution_audit() -> dict:
    """Static audit: where the code could start a process or evaluate code."""
    pattern = re.compile(r"\b(subprocess\.|os\.system\(|os\.startfile\(|os\.exec\w*\(|os\.spawn\w*\(|QProcess|ShellExecute|eval\(|exec\()")
    hits = []
    for folder in ("core", "ui", "repair_engine", "ml", "monitoring", "reports"):
        for path in (ROOT / folder).rglob("*.py"):
            if "harness" in path.parts or "__pycache__" in path.parts:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if pattern.search(line) and not line.strip().startswith("#"):
                    hits.append({"file": str(path.relative_to(ROOT)), "line": number, "code": line.strip()[:140]})
    return {"sites": hits}


def _model_tests(benign: list[Path], rng: random.Random) -> dict:
    import numpy as np

    out: dict = {}
    try:
        from ml.structural_classifier import StructuralClassifier
    except Exception as exc:  # noqa: BLE001
        return {"error": repr(exc)}
    model = StructuralClassifier(ROOT / "data" / "models" / "structural_classifier_4096.json")
    out["ready"] = model.is_ready
    folder = ROOT / "data" / "datasets" / "synthetic_integration"
    synth = sorted(folder.glob("*.bin"))
    labels = [p.name.split("_")[0] for p in synth]
    X = np.stack([model.embed_file(p) for p in synth])
    out["synthetic"] = {"n": len(synth), "classes": Counter(labels)}
    # Leakage: one feature, one split.
    feature = 3025
    values = X[:, feature]
    separable = {}
    for cls in sorted(set(labels)):
        inside = values[[i for i, l in enumerate(labels) if l == cls]]
        outside = values[[i for i, l in enumerate(labels) if l != cls]]
        separable[cls] = bool(inside.size and outside.size and (inside.min() > outside.max() or inside.max() < outside.min()))
    out["leakage_single_feature"] = {"feature": feature, "class_alone_separable": separable}
    duplicates = 0
    for i in range(len(X)):
        for j in range(i + 1, len(X)):
            if labels[i] != labels[j] and np.allclose(X[i], X[j], atol=1e-6):
                duplicates += 1
    out["leakage_cross_class_duplicates"] = duplicates
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import GroupKFold, StratifiedKFold, cross_val_score
        from sklearn.tree import DecisionTreeClassifier

        y = np.array(labels)
        groups = np.array([p.name.split("_")[0] + "_" + p.stem.split("_")[1][:1] for p in synth])
        folds = min(5, Counter(labels).most_common()[-1][1])
        strat = cross_val_score(RandomForestClassifier(n_estimators=200, random_state=0), X, y, cv=StratifiedKFold(folds, shuffle=True, random_state=0), scoring="f1_macro")
        stump = cross_val_score(DecisionTreeClassifier(max_depth=3, random_state=0), X[:, [feature]], y, cv=StratifiedKFold(folds, shuffle=True, random_state=0), scoring="f1_macro")
        grouped = cross_val_score(RandomForestClassifier(n_estimators=200, random_state=0), X, y, cv=GroupKFold(min(5, len(set(groups)))), groups=groups, scoring="f1_macro")
        out["cross_validation"] = {"folds": folds, "stratified_f1_macro": [round(float(v), 3) for v in strat],
                                   "single_feature_tree_f1_macro": [round(float(v), 3) for v in stump],
                                   "group_kfold_f1_macro": [round(float(v), 3) for v in grouped]}
    except Exception as exc:  # noqa: BLE001
        out["cross_validation"] = {"error": repr(exc)[:200]}
    # Out of distribution: real, benign files the model never saw.
    real = [p for p in benign if p.stat().st_size < 10 * 1024 * 1024][:150]
    R = np.stack([model.embed_file(p) for p in real])
    if model.is_ready:
        predicted = model.predict(R)
        names = predicted.get("label") or []
        names = [names] if isinstance(names, str) else list(names)
        out["ood_real_benign"] = {"n": len(real), "predicted": Counter(str(n) for n in names)}
        synth_pred = model.predict(X)
        names_s = synth_pred.get("label") or []
        names_s = [names_s] if isinstance(names_s, str) else list(names_s)
        out["in_distribution_accuracy"] = round(sum(1 for a, b in zip(names_s, labels) if str(a) == b) / len(labels), 3)
        try:
            proba_real = model.predict_proba(R)
            proba_synth = model.predict_proba(X)
            out["drift"] = _drift(proba_synth.max(axis=1), proba_real.max(axis=1))
        except Exception as exc:  # noqa: BLE001
            out["drift"] = {"error": repr(exc)[:200]}
    # Feature drift: how far real files sit from the training data.
    centre = X.mean(axis=0)
    out["embedding_distance"] = {"synthetic_to_centre_median": round(float(np.median(np.linalg.norm(X - centre, axis=1))), 3),
                                 "real_to_centre_median": round(float(np.median(np.linalg.norm(R - centre, axis=1))), 3)}
    return out


def _drift(expected, actual, bins: int = 10) -> dict:
    import numpy as np

    edges = np.linspace(0.0, 1.0, bins + 1)
    e, _ = np.histogram(expected, edges)
    a, _ = np.histogram(actual, edges)
    e = (e + 0.5) / (e.sum() + 0.5 * bins)
    a = (a + 0.5) / (a.sum() + 0.5 * bins)
    psi = float(np.sum((a - e) * np.log(a / e)))
    return {"psi_confidence": round(psi, 3), "synthetic_confidence_median": round(float(np.median(expected)), 3),
            "real_confidence_median": round(float(np.median(actual)), 3)}


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        LOG.append(traceback.format_exc())
        save()
        raise
