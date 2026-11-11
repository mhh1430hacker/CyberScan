"""OSINT + HTTP API benchmarks, kept separate so they finish in one bounded run.

Network figures depend on this machine's connection; the report says so.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "web_v")]

QA = Path(__file__).resolve().parent
FIX = QA / "artifacts" / "fixtures"


def stats(vals):
    s = sorted(vals)
    def p(q):
        if len(s) == 1:
            return s[0]
        k = (len(s) - 1) * q
        lo, hi = int(k), min(int(k) + 1, len(s) - 1)
        return s[lo] + (s[hi] - s[lo]) * (k - lo)
    return {"n": len(s), "median_ms": round(p(.5), 1), "p95_ms": round(p(.95), 1),
            "min_ms": round(s[0], 1), "max_ms": round(s[-1], 1)}


def osint() -> dict:
    import asyncio
    from core.global_intelligence import GlobalIntelligenceEngine

    out = {}
    for label, indicator in (("sha256_unknown", "a" * 64), ("domain", "example.com"),
                             ("url", "https://example.com/login"), ("invalid", "not an indicator")):
        wall, reported, status = [], [], None
        for _ in range(3):
            GlobalIntelligenceEngine._shared_cache.clear()
            t = time.perf_counter()
            res = asyncio.run(GlobalIntelligenceEngine().query_indicator(indicator))
            wall.append((time.perf_counter() - t) * 1000)
            reported.append(res.get("elapsed_ms"))
            status = res
        out[label] = {"wall": stats(wall), "self_reported_elapsed_ms": reported,
                      "status": status.get("status"),
                      "feeds": {k: v.get("status") for k, v in (status.get("feeds") or {}).items()}}
        print(f"  {label:<15} wall median {out[label]['wall']['median_ms']:>8.1f} ms  "
              f"p95 {out[label]['wall']['p95_ms']:>8.1f} ms  status={out[label]['status']}", flush=True)

    GlobalIntelligenceEngine._shared_cache.clear()
    asyncio.run(GlobalIntelligenceEngine().query_indicator("example.com"))
    hits = []
    for _ in range(10):
        t = time.perf_counter()
        asyncio.run(GlobalIntelligenceEngine().query_indicator("example.com"))
        hits.append((time.perf_counter() - t) * 1000)
    out["cache_hit"] = stats(hits)
    print(f"  {'cache_hit':<15} wall median {out['cache_hit']['median_ms']:>8.1f} ms", flush=True)

    async def fake_feed(*_a, **_k):
        await asyncio.sleep(0.01)
        return GlobalIntelligenceEngine._feed_result("no_match")

    with mock.patch.object(GlobalIntelligenceEngine, "_query_threatfox", side_effect=fake_feed), \
         mock.patch.object(GlobalIntelligenceEngine, "_query_urlhaus", side_effect=fake_feed), \
         mock.patch.object(GlobalIntelligenceEngine, "_query_otx", side_effect=fake_feed):
        sim = []
        for _ in range(10):
            GlobalIntelligenceEngine._shared_cache.clear()
            t = time.perf_counter()
            asyncio.run(GlobalIntelligenceEngine().query_indicator("b" * 64))
            sim.append((time.perf_counter() - t) * 1000)
    out["simulated_responsive_feeds_NOT_REAL"] = stats(sim)
    print(f"  {'simulated(10ms)':<15} wall median {out['simulated_responsive_feeds_NOT_REAL']['median_ms']:>8.1f} ms (mocked)", flush=True)
    return out


def http() -> dict:
    import http.client
    import threading
    from server import create_server, cleanup

    server, app = create_server(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = app.token
    base = {"Host": f"127.0.0.1:{port}", "X-CyberScan-Token": token}
    out = {}

    def req(method, path, body=None, extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        h = dict(base, **(extra or {}))
        payload = b""
        if body is not None:
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=h)
        r = conn.getresponse()
        data = r.read()
        status = r.status
        conn.close()
        return status, data

    try:
        for asset in ("/", "/app.html", "/styles.css", "/app.js"):
            samples, size = [], 0
            for _ in range(5):
                t = time.perf_counter()
                status, data = req("GET", asset)
                samples.append((time.perf_counter() - t) * 1000)
                size = len(data)
            out[f"GET {asset}"] = {**stats(samples), "status": status, "bytes": size}
            print(f"  GET {asset:<20} median {stats(samples)['median_ms']:>8.1f} ms  {size:>8} B", flush=True)

        for size, reps in ((64 * 1024, 5), (1024 * 1024, 3), (4 * 1024 * 1024, 2)):
            name = f"upload_{size // 1024}KiB_e2e"
            blob = (FIX / f"random_{size}.bin").read_bytes()
            samples = []
            for _ in range(reps):
                t = time.perf_counter()
                status, data = req("POST", "/api/scan/file", blob,
                                   {"X-Filename": "u.bin", "Content-Type": "application/octet-stream"})
                job = json.loads(data)["id"]
                while True:
                    st, d = req("GET", f"/api/scan/{job}")
                    if json.loads(d)["status"] != "running":
                        break
                    time.sleep(0.01)
                samples.append((time.perf_counter() - t) * 1000)
            out[name] = {**stats(samples), "status": status}
            print(f"  POST {name:<20} median {stats(samples)['median_ms']:>8.1f} ms", flush=True)

        samples = []
        for _ in range(5):
            t = time.perf_counter()
            status, data = req("POST", "/api/scan", {"mode": "text", "value": "hello world " * 500})
            job = json.loads(data)["id"]
            while True:
                st, d = req("GET", f"/api/scan/{job}")
                if json.loads(d)["status"] != "running":
                    break
                time.sleep(0.01)
            samples.append((time.perf_counter() - t) * 1000)
        out["text_scan_e2e"] = {**stats(samples), "status": status}
        print(f"  POST text_scan_e2e         median {stats(samples)['median_ms']:>8.1f} ms", flush=True)

        for ep in ("/api/settings", "/api/history", "/api/stats", "/api/protection"):
            samples = []
            for _ in range(5):
                t = time.perf_counter()
                status, data = req("GET", ep)
                samples.append((time.perf_counter() - t) * 1000)
            out[f"GET {ep}"] = {**stats(samples), "status": status}
            print(f"  GET {ep:<24} median {stats(samples)['median_ms']:>8.1f} ms", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        cleanup(app)
    return out


def concurrency() -> dict:
    from concurrent.futures import ThreadPoolExecutor
    from config import DEFAULT_SETTINGS
    from ui.scan_service import ScanService

    svc = ScanService()
    path = str(FIX / "random_1048576.bin")
    settings = dict(DEFAULT_SETTINGS)
    out = {}

    def run(n_workers, n_scans):
        t = time.perf_counter()
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            list(pool.map(lambda _: svc.analyze(path, "File", settings), range(n_scans)))
        wall = (time.perf_counter() - t) * 1000
        return {"workers": n_workers, "scans": n_scans, "wall_ms": round(wall, 1),
                "per_scan_ms": round(wall / n_scans, 1), "throughput_scans_s": round(n_scans / (wall / 1000), 2)}

    out["sequential"] = run(1, 8)
    print(f"  sequential 8 scans          {out['sequential']['wall_ms']:>8.1f} ms", flush=True)
    for w in (2, 4, 8):
        out[f"pool_{w}"] = run(w, 8)
        speed = out["sequential"]["wall_ms"] / out[f"pool_{w}"]["wall_ms"]
        print(f"  {w} workers, 8 scans        {out[f'pool_{w}']['wall_ms']:>8.1f} ms   speedup {speed:.2f}x", flush=True)
    return out


if __name__ == "__main__":
    report = {}
    print("== OSINT correlation ==", flush=True)
    report["osint"] = osint()
    print("== HTTP API (localhost) ==", flush=True)
    report["http"] = http()
    print("== concurrency ==", flush=True)
    report["concurrency"] = concurrency()
    (QA / "artifacts" / "benchmark_network.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("wrote qa/artifacts/benchmark_network.json")
