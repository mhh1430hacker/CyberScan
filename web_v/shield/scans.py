"""Virus scans and the Smart Scan.

    quick     the places malware lands and starts from: Downloads, Desktop, Temp, the
              Startup folders, every program that is running now and every startup item
    full      every fixed drive
    targeted  the folders or files you choose
    usb       removable drives
    smart     quick virus scan + Windows security settings + startup items + network
              + browser add-ons, with one list of everything worth fixing
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import core, engine, system, vault, winutil


def _quick_roots() -> list[Path]:
    kf = winutil.known_folder
    roots = [kf("downloads"), kf("desktop"), kf("temp"), kf("startup"), kf("common_startup")]
    return [r for r in roots if r.exists()]


def _shallow_roots() -> list[Path]:
    """Where droppers hide programs (AppData\\<random>\\x.exe, ProgramData): only the
    top two levels, so app caches with thousands of files are not walked."""
    kf = winutil.known_folder
    return [p for p in (kf("appdata"), kf("localappdata"), Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")),
                        Path(os.environ.get("PUBLIC", r"C:\Users\Public"))) if p.is_dir()]


def _quick_files(exclusions: list[str], stop) -> Any:
    for p in engine.walk(_quick_roots(), exclusions, stop=stop):
        yield p
    for p in engine.walk(_shallow_roots(), exclusions, stop=stop, max_depth=1):
        if p.suffix.casefold() in engine.CODE_EXT - {".html", ".htm", ".svg", ".xhtml", ".pdf", ".docx", ".xlsx", ".pptx", ".zip", ".gz", ".tar"}:
            yield p


def _process_and_startup_files() -> list[Path]:
    paths = {p["path"] for p in system.processes() if p.get("path")}
    paths |= {i["path"] for i in system.autoruns() if i.get("path")}
    return [Path(p) for p in paths if p and Path(p).is_file()]


def _scan_files(job: core.Job, files_iter, options: dict[str, Any], auto_quarantine: bool, source: str,
                estimate: int | None = None) -> dict[str, Any]:
    counts = {"files": 0, "deep": 0, "threats": 0, "review": 0, "skipped": 0, "errors": 0, "quarantined": 0}
    job.counts = counts
    started = time.time()

    def handle(path: Path) -> tuple[Path, dict[str, Any]]:
        return path, engine.inspect(path, options)

    with ThreadPoolExecutor(max_workers=max(2, min(6, (os.cpu_count() or 4) // 2))) as pool:
        pending = []
        for path in files_iter:
            if job.cancel:
                break
            pending.append(pool.submit(handle, path))
            if len(pending) >= 64:
                _drain(job, pending, counts, auto_quarantine, source)
                pending = []
            if estimate:
                job.progress = min(0.97, counts["files"] / max(estimate, 1))
        _drain(job, pending, counts, auto_quarantine, source)
    engine.flush_cache()
    counts["seconds"] = int(time.time() - started)
    return counts


def _drain(job: core.Job, futures, counts, auto_quarantine: bool, source: str) -> None:
    for future in futures:
        try:
            path, verdict = future.result()
        except Exception:  # noqa: BLE001
            counts["errors"] += 1
            continue
        counts["files"] += 1
        status = verdict.get("status")
        if verdict.get("deep"):
            counts["deep"] += 1
        if status == "skipped":
            counts["skipped"] += 1
        elif status == "error":
            counts["errors"] += 1
        if counts["files"] % 25 == 0:
            job.detail = str(path)
        if status in ("threat", "review"):
            counts["threats" if status == "threat" else "review"] += 1
            item = {"path": str(path), "status": status, "name": verdict.get("name", ""), "score": verdict.get("score", 0),
                    "reasons": verdict.get("reasons", []), "sha256": verdict.get("sha256", ""), "action": "none"}
            if status == "threat" and auto_quarantine:
                try:
                    sealed = vault.seal(path, "; ".join(item["reasons"])[:400], item["name"], source, item["sha256"])
                    item["action"] = "quarantined"
                    item["vault_id"] = sealed["id"]
                    counts["quarantined"] += 1
                except Exception as exc:  # noqa: BLE001
                    item["action"] = f"failed: {type(exc).__name__}"
            job.items.append(item)
            core.EVENTS.add(source, "high" if status == "threat" else "medium", "threat_found" if status == "threat" else "review_found",
                            str(path), name=item["name"], action=item["action"])


def _estimate(roots: list[Path], exclusions: list[str], limit: int = 400000) -> int:
    n = 0
    for _ in engine.walk(roots, exclusions):
        n += 1
        if n >= limit:
            break
    return n


def virus_scan(kind: str, targets: list[str] | None = None) -> core.Job:
    if core.running("virus_scan"):
        raise RuntimeError("A scan is already running.")
    config = core.load_config()
    options = dict(config["virus_scan"])
    exclusions = core.exclusions(config)
    auto_q = bool(options.get("auto_quarantine"))

    def work(job: core.Job) -> dict[str, Any]:
        job.detail = "preparing"
        if kind == "quick":
            extra = _process_and_startup_files()
            items = list(dict.fromkeys([*extra, *_quick_files(exclusions, lambda: job.cancel)]))
            counts = _scan_files(job, iter(items), options, auto_q, "virus_scan", len(items))
            core.EVENTS.add("virus_scan", "info", "scan_done", kind, counts=counts)
            return {"kind": kind, "counts": counts, "roots": [str(r) for r in _quick_roots()]}
        if kind == "full":
            roots, extra = winutil.drives("fixed"), []
        elif kind == "usb":
            roots, extra = winutil.drives("removable"), []
            if not roots:
                return {"kind": kind, "counts": {"files": 0}, "message": "no_usb"}
        else:
            roots = [Path(t) for t in (targets or []) if t and Path(t).exists()]
            extra = []
            if not roots:
                raise ValueError("Choose a folder or file that exists.")
        job.detail = "counting"
        estimate = None if kind == "full" else _estimate(roots, exclusions) + len(extra)

        def files():
            seen = set()
            for p in extra:
                seen.add(str(p).casefold())
                yield p
            for p in engine.walk(roots, exclusions, stop=lambda: job.cancel):
                if str(p).casefold() not in seen:
                    yield p

        counts = _scan_files(job, files(), options, auto_q, "virus_scan", estimate)
        if kind == "full" and not job.cancel:
            job.progress = 1.0
        core.EVENTS.add("virus_scan", "info", "scan_done", kind, counts=counts)
        return {"kind": kind, "counts": counts, "roots": [str(r) for r in roots]}

    return core.start_job("virus_scan", work)


# ---------------------------------------------------------------- smart scan
SMART_STEPS = ("viruses", "system", "startup", "network", "browser")


def smart_scan() -> core.Job:
    if core.running("smart_scan"):
        raise RuntimeError("A Smart Scan is already running.")
    config = core.load_config()
    options = dict(config["virus_scan"])
    exclusions = core.exclusions(config)

    def work(job: core.Job) -> dict[str, Any]:
        from . import network, privacy  # noqa: PLC0415

        report: dict[str, Any] = {"steps": {}, "issues": 0}

        def step(index: int, name: str) -> None:
            job.detail = name
            job.progress = index / len(SMART_STEPS)

        step(0, "viruses")
        files = list(dict.fromkeys([*_process_and_startup_files(), *_quick_files(exclusions, lambda: job.cancel)]))
        counts = _scan_files(job, iter(files), options, bool(options.get("auto_quarantine")), "smart_scan", None)
        report["steps"]["viruses"] = {"counts": counts, "items": job.items[:100], "issues": counts["threats"] + counts["review"]}
        if job.cancel:
            return report

        step(1, "system")
        checks = system.security_checks()
        report["steps"]["system"] = {"checks": checks, "issues": sum(1 for c in checks if c["status"] in ("bad", "warn"))}
        if job.cancel:
            return report

        step(2, "startup")
        runs = system.assess_autoruns(system.autoruns())
        report["steps"]["startup"] = {"items": runs, "issues": sum(1 for r in runs if r["risk"] != "ok")}
        if job.cancel:
            return report

        step(3, "network")
        try:
            wifi = network.wifi_status()
            dns = network.dns_check(quick=True)
            issues = (1 if wifi.get("risk") in ("bad", "warn") else 0) + (1 if dns.get("status") in ("bad", "warn") else 0)
            report["steps"]["network"] = {"wifi": wifi, "dns": dns, "issues": issues}
        except Exception as exc:  # noqa: BLE001
            report["steps"]["network"] = {"error": str(exc), "issues": 0}

        step(4, "browser")
        try:
            exts = privacy.browser_extensions()
            risky = [e for e in exts if e["risk"] != "ok"]
            report["steps"]["browser"] = {"items": risky[:60], "total": len(exts), "issues": len([e for e in risky if e["risk"] == "bad"])}
        except Exception as exc:  # noqa: BLE001
            report["steps"]["browser"] = {"error": str(exc), "issues": 0}

        report["issues"] = sum(int(s.get("issues", 0)) for s in report["steps"].values())
        cfg = core.load_config()
        cfg["smart_scan"]["last_run"] = int(time.time())
        cfg["smart_scan"]["last_summary"] = {k: int(v.get("issues", 0)) for k, v in report["steps"].items()}
        core.save_config(cfg)
        core.EVENTS.add("smart_scan", "high" if report["issues"] else "info", "smart_done", str(report["issues"]),
                        issues=report["issues"])
        return report

    return core.start_job("smart_scan", work)


def due(config: dict[str, Any], now: float | None = None) -> bool:
    """Is a scheduled Smart Scan due? 'auto' means once a week, at a quiet moment."""
    now = now or time.time()
    s = config["smart_scan"]
    last = float(s.get("last_run") or 0)
    schedule = s.get("schedule", "auto")
    if schedule == "off":
        return False
    period = {"auto": 7, "daily": 1, "weekly": 7, "monthly": 30}[schedule] * 86400
    if now - last < period - 600:
        return False
    if schedule == "auto":
        return True
    local = time.localtime(now)
    hour, minute = (int(x) for x in s.get("time", "12:00").split(":"))
    if (local.tm_hour, local.tm_min) < (hour, minute):
        return False
    if schedule == "weekly" and local.tm_wday != int(s.get("day", 0)) % 7:
        return False
    if schedule == "monthly" and local.tm_mday != max(1, min(28, int(s.get("day", 1)))):
        return False
    return True
