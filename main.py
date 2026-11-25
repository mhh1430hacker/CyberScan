from __future__ import annotations

import sys


def self_test(report_path: str | None) -> int:
    """`CyberScan.exe --self-test [report.json]`: loads every engine the packaged app needs and
    scans two small samples, without opening a window. Used after a build to prove that nothing
    the app imports was left out of the bundle (build.spec excludes). Exit code 0 = all good."""
    import json
    import os
    import tempfile
    import traceback

    checks: dict[str, str] = {}

    def run(name, fn):
        try:
            value = fn()
            checks[name] = "ok" + (f": {value}" if value else "")
        except Exception:  # noqa: BLE001
            checks[name] = "FAIL: " + traceback.format_exc(limit=3).strip().splitlines()[-1]

    def qt():
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        import ui.qt_app  # noqa: F401 - the whole window module and everything it imports
        QApplication.instance() or QApplication([])
        return ""

    def modules():
        import importlib
        for name in ("yara", "pefile", "capstone", "olefile", "pypdf", "aiohttp", "cryptography", "PIL", "zxingcpp",
                     "numpy", "sklearn.ensemble", "ml.model_runtime", "repair_engine.analyze",
                     "repair_engine.parsers", "monitoring.downloads_monitor", "reports.exporter", "ui.updater"):
            importlib.import_module(name)
        return ""

    def scan(content: bytes, name: str):
        from config import DEFAULT_SETTINGS
        from core.file_analyzer import analyze_file
        folder = tempfile.mkdtemp(prefix="cyberscan-selftest-")
        path = os.path.join(folder, name)
        with open(path, "wb") as handle:
            handle.write(content)
        result = analyze_file(path, dict(DEFAULT_SETTINGS))
        return getattr(result, "classification", None) or getattr(result, "verdict", "") or type(result).__name__

    def sklearn_fit():
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        import numpy as np
        x = np.random.default_rng(0).random((40, 4))
        RandomForestClassifier(n_estimators=3).fit(x, (x[:, 0] > .5).astype(int))
        IsolationForest(n_estimators=5).fit(x)
        return ""

    def worker_process():
        # the app scans in a separate, spawned process (ui/scan_process.py): prove it starts frozen
        from config import DEFAULT_SETTINGS
        from ui import scan_process
        settings = dict(DEFAULT_SETTINGS, osint_enabled=False)
        try:
            _scan_id, future = scan_process.HOST.submit("hello from the self-test", "Text", settings)
            result = future.result(timeout=180)
        finally:
            scan_process.HOST.shutdown()
        first = result[0] if isinstance(result, tuple) else result
        return getattr(first, "classification", "") or type(first).__name__

    run("qt_window_module", qt)
    run("scan_worker_process", worker_process)
    run("engine_modules", modules)
    run("sklearn", sklearn_fit)
    run("scan_text_file", lambda: scan(b"hello world\n" * 50, "note.txt"))
    run("scan_fake_exe", lambda: scan(b"MZ" + b"\0" * 58 + b"\x80\0\0\0" + b"\0" * 200, "invoice.pdf.exe"))
    ok = all(v.startswith("ok") for v in checks.values())
    text = json.dumps({"ok": ok, "checks": checks}, indent=1)
    if report_path:
        with open(report_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    elif sys.stdout:
        print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        import multiprocessing

        multiprocessing.freeze_support()
        index = sys.argv.index("--self-test")
        sys.exit(self_test(sys.argv[index + 1] if len(sys.argv) > index + 1 else None))
    from ui.qt_app import main

    main()
