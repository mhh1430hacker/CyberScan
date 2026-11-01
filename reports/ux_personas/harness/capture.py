"""Drive the real CyberScan window through every state and screenshot it.

Windows platform plugin with WA_DontShowOnScreen (real fonts and rendering,
nothing pops up). All data paths point at a temp folder; message boxes are
recorded, not shown. Nothing in data/ or the user's settings is touched.

Usage: python reports/ux_personas/harness/capture.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "reports" / "ux_personas" / os.environ.get("SHOTS", "screens")
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ["CYBERSCAN_REDUCE_MOTION"] = "0"
os.environ.setdefault("CYBERSCAN_SCAN_IN_PROCESS", "1")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

app = QApplication.instance() or QApplication([])
import ui.ai_summary as ai_summary  # noqa: E402
import ui.qt_app as qa  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="cs_ux_"))
(TMP / "data").mkdir()
qa.DATA_DIR = TMP / "data"
qa.REPORT_DIR = TMP / "reports"
qa.ensure_directories = lambda: None
ai_summary.OLLAMA_URL = "http://127.0.0.1:9"
DIALOGS: list[dict] = []


def _box(kind):
    def box(_parent, title, text, *args, **kwargs):
        DIALOGS.append({"kind": kind, "title": title, "text": text})
        return QMessageBox.StandardButton.Yes if kind == "question" else QMessageBox.StandardButton.Ok
    return staticmethod(box)


for name in ("critical", "warning", "information", "question"):
    setattr(QMessageBox, name, _box(name))

SAMPLES = TMP / "samples"
SAMPLES.mkdir()
(SAMPLES / "Q3 budget notes.txt").write_text("Budget review for the third quarter.\n" * 80, encoding="utf-8")
(SAMPLES / "invoice_2026.pdf.exe").write_bytes(b"MZ" + bytes(4000) + os.urandom(30000) + b"powershell -nop -w hidden -enc SQBFAFgA" + bytes(2000))
(SAMPLES / "holiday-photo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(40_000))
(SAMPLES / "empty.dat").write_bytes(b"")
(SAMPLES / "تقرير الربع الثالث.txt").write_text("مراجعة الميزانية.\n" * 60, encoding="utf-8")

LOG: list[dict] = []


def pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)


def wait(predicate, timeout=60.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def shot(window, name: str, full: bool = False) -> None:
    pump(0.25)
    window.grab().save(str(OUT / f"{name}.png"))
    if full:
        content = window.scroll.widget()
        content.grab().save(str(OUT / f"{name}__full.png"))
    LOG.append({"shot": name, "view": window.view, "size": [window.width(), window.height()]})


def scan(window, target: str, *, until="result", timeout=90.0) -> float:
    window.lens.set_target(target)
    started = time.perf_counter()
    window.lens.scan_button.click()
    wait(lambda: window.view == until or window.journey.phase in {"failed", "cancelled"}, timeout)
    pump(0.6)
    return time.perf_counter() - started


def make_window(width=1440, height=900):
    window = qa.CyberScanApp()
    window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    window.resize(width, height)
    window.show()
    pump(1.0)
    return window


def run() -> None:
    t0 = time.perf_counter()
    window = make_window()
    LOG.append({"startup_seconds": round(time.perf_counter() - t0, 2)})
    shot(window, "01_home_empty")

    window.lens.set_target(str(SAMPLES / "invoice_2026.pdf.exe"))
    shot(window, "02_home_target_typed")
    window.lens.set_target("")
    window.lens.scan_button.click()
    shot(window, "03_error_empty")
    window.lens.set_target(r"C:\nowhere\missing-file.docx")
    window.lens.scan_button.click()
    shot(window, "04_error_missing_file")
    window.lens.set_target("htp:/bad link")
    window.lens.scan_button.click()
    shot(window, "05_input_weird_text")
    wait(lambda: window.view == "result", 60)
    pump(0.5)
    shot(window, "06_result_weird_text", full=True)
    window.new_scan()
    pump(0.5)

    # Journey stages on the suspicious file.
    window.lens.set_target(str(SAMPLES / "invoice_2026.pdf.exe"))
    started = time.perf_counter()
    window.lens.scan_button.click()
    pump(0.4)
    shot(window, "10_journey_start")
    pump(1.6)
    shot(window, "11_journey_scanning")
    wait(lambda: window.sonar.phase == "echo", 60)
    pump(0.8)
    shot(window, "12_journey_echo")
    wait(lambda: window.sonar.phase == "flag", 20)
    pump(0.9)
    shot(window, "13_journey_flag")
    wait(lambda: window.view == "result", 60)
    LOG.append({"suspicious_scan_seconds": round(time.perf_counter() - started, 2)})
    pump(1.2)
    shot(window, "20_result_suspicious", full=True)
    panel = window.result_panel
    panel.why_button.click()
    pump(1.0)
    shot(window, "21_result_details_open", full=True)
    panel.advanced_button.click()
    pump(1.0)
    shot(window, "22_result_advanced_open", full=True)
    window.scroll.ensureWidgetVisible(panel.inside_card, 0, 20)
    shot(window, "23_result_inside_cube")

    window.new_scan()
    pump(0.5)
    LOG.append({"benign_scan_seconds": round(scan(window, str(SAMPLES / "Q3 budget notes.txt")), 2)})
    shot(window, "24_result_benign_text", full=True)
    window.new_scan()
    LOG.append({"url_scan_seconds": round(scan(window, "https://login-microsoft.secure-verify.example.com/account?id=1"), 2)})
    shot(window, "25_result_url", full=True)
    window.new_scan()
    LOG.append({"hash_scan_seconds": round(scan(window, "44d88612fea8a8f36de82e1278abb02f"), 2)})
    shot(window, "26_result_hash", full=True)
    window.new_scan()
    LOG.append({"empty_scan_seconds": round(scan(window, str(SAMPLES / "empty.dat")), 2)})
    shot(window, "27_result_empty_file", full=True)
    window.new_scan()
    scan(window, str(SAMPLES / "holiday-photo.png"))
    shot(window, "28_result_image", full=True)

    window.new_scan()
    pump(0.5)
    shot(window, "30_home_with_history")
    try:
        window.rail.search.setText("invoice")
        pump(0.5)
        shot(window, "31_history_search")
        window.rail.search.setText("")
    except AttributeError:
        LOG.append({"note": "history search field not found"})

    # Cancel mid-journey.
    window.lens.set_target(str(SAMPLES / "invoice_2026.pdf.exe"))
    window.lens.scan_button.click()
    pump(1.2)
    window.stop_button.click()
    pump(0.8)
    shot(window, "32_journey_cancelled")
    window.new_scan()

    window.open_settings()
    pump(0.8)
    shot(window, "40_settings_sheet")
    window.close_settings()
    pump(0.5)

    window.set_mode("repair")
    pump(1.2)
    shot(window, "41_repair_mode")
    window.set_mode("scan")
    pump(0.6)

    window.toggle_language()
    pump(0.8)
    shot(window, "50_ar_home")
    scan(window, str(SAMPLES / "invoice_2026.pdf.exe"))
    shot(window, "51_ar_result", full=True)
    window.result_panel.why_button.click()
    pump(1.0)
    shot(window, "52_ar_details", full=True)
    window.new_scan()
    scan(window, str(SAMPLES / "تقرير الربع الثالث.txt"))
    shot(window, "53_ar_result_arabic_name", full=True)
    window.set_mode("repair")
    pump(1.0)
    shot(window, "54_ar_repair")
    window.set_mode("scan")
    window.toggle_language()
    pump(0.5)
    window.close()

    small = make_window(900, 620)
    shot(small, "60_small_home")
    scan(small, str(SAMPLES / "invoice_2026.pdf.exe"))
    shot(small, "61_small_result")
    small.close()

    big = make_window(1920, 1080)
    shot(big, "62_wide_home")
    big.close()

    large = make_window()
    try:
        large.settings["large_text"] = True
        large._apply_text_scale()
    except Exception as exc:  # noqa: BLE001
        LOG.append({"large_text_error": repr(exc)})
    pump(0.6)
    shot(large, "63_large_text_home")
    scan(large, str(SAMPLES / "invoice_2026.pdf.exe"))
    shot(large, "64_large_text_result", full=True)
    large.close()


if __name__ == "__main__":
    try:
        run()
    finally:
        (OUT.parent / "capture_log.json").write_text(json.dumps({"log": LOG, "dialogs": DIALOGS}, ensure_ascii=False, indent=2), encoding="utf-8")
        from ui import scan_process

        scan_process.HOST.shutdown()
