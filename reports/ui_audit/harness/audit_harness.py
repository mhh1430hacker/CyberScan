"""Read-only UI audit harness for CyberScan.

Runs the real CyberScanApp on the Windows platform plugin with
WA_DontShowOnScreen, redirects every persistent path to a temp folder,
records message boxes instead of showing them, captures screenshots and
measurements. Never touches data/ or the user's settings.
"""
from __future__ import annotations

import copy
import ctypes
import ctypes.wintypes as wt
import json
import os
import random
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(r"C:\Users\mahdi\Desktop\dist")
OUT = ROOT / "reports" / "ui_audit"
SHOTS = OUT / "screens"
LOGS = OUT / "logs"
SHOTS.mkdir(parents=True, exist_ok=True)
LOGS.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ["CYBERSCAN_REDUCE_MOTION"] = "0"

SCRATCH = Path(__file__).resolve().parent
TMP = Path(tempfile.mkdtemp(prefix="cs_audit_", dir=SCRATCH))
(TMP / "data").mkdir()
(TMP / "reports").mkdir()
SAMPLES = TMP / "samples"
SAMPLES.mkdir()

from PySide6.QtCore import QEventLoop, QObject, Qt, QTimer, qInstallMessageHandler  # noqa: E402
from PySide6.QtGui import QColor, QPixmap  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QAbstractButton, QApplication, QLabel, QLineEdit, QListWidget, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QTabWidget, QWidget,
)

QT_MESSAGES: list[dict] = []


def _qt_handler(mode, context, message):
    QT_MESSAGES.append({"t": round(time.perf_counter(), 3), "mode": str(mode), "msg": message})


qInstallMessageHandler(_qt_handler)
EXCEPTIONS: list[str] = []
_orig_hook = sys.excepthook


def _hook(etype, value, tb):
    EXCEPTIONS.append("".join(traceback.format_exception(etype, value, tb)))


sys.excepthook = _hook

T_IMPORT0 = time.perf_counter()
app = QApplication.instance() or QApplication([])
import ui.qt_app as qa  # noqa: E402
import ui.home as home  # noqa: E402
from ui.design_system import TOKENS  # noqa: E402
T_IMPORT1 = time.perf_counter()

qa.DATA_DIR = TMP / "data"
qa.REPORT_DIR = TMP / "reports"
qa.ensure_directories = lambda: None

DIALOGS: list[dict] = []


def _fake_box(kind, ret=None):
    def box(parent, title, text, *args, **kwargs):
        DIALOGS.append({"kind": kind, "title": title, "text": text, "t": round(time.perf_counter(), 3)})
        return ret if ret is not None else QMessageBox.StandardButton.Ok
    return box


qa.QMessageBox.critical = staticmethod(_fake_box("critical"))
qa.QMessageBox.information = staticmethod(_fake_box("information"))
qa.QMessageBox.warning = staticmethod(_fake_box("warning"))
qa.QMessageBox.question = staticmethod(_fake_box("question", QMessageBox.StandardButton.Yes))
qa.QFileDialog.getOpenFileName = staticmethod(lambda *a, **k: ("", ""))
qa.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: ("", ""))

# --- instrumentation of real scan events -----------------------------------
TIMELINE: list[tuple] = []
HOLD = {"event": None, "stage": None}
_orig_analyze = qa.ScanService.analyze


def _analyze(self, candidate, mode, settings, progress=None):
    def prog(index, state, detail):
        TIMELINE.append(("emit", time.perf_counter(), index, state))
        if progress:
            progress(index, state, detail)
        if HOLD["event"] is not None and HOLD["stage"] == index and state == "running":
            HOLD["event"].wait(30)
    TIMELINE.append(("analyze_start", time.perf_counter()))
    try:
        return _orig_analyze(self, candidate, mode, settings, prog)
    finally:
        TIMELINE.append(("analyze_return", time.perf_counter()))


qa.ScanService.analyze = _analyze

# --- helpers ----------------------------------------------------------------
RESULTS: dict = {"facts": {}, "measurements": {}, "layout": {}, "text": {}, "keyboard": {}, "errors": []}


def settle(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_until(pred, timeout_ms=30000, step=10) -> bool:
    start = time.perf_counter()
    while (time.perf_counter() - start) * 1000 < timeout_ms:
        if pred():
            return True
        settle(step)
    return pred()


def shot(name: str, widget: QWidget | None = None) -> str:
    w = widget or win
    pm = w.grab()
    path = SHOTS / f"{name}.png"
    pm.save(str(path))
    return str(path.relative_to(ROOT))


def full_shot(name: str) -> str:
    scroll = win.pages.currentWidget()
    inner = scroll.widget() if isinstance(scroll, QScrollArea) else scroll
    pm = QPixmap(inner.size())
    pm.fill(QColor(TOKENS["bg"]))
    inner.render(pm)
    path = SHOTS / f"{name}.png"
    pm.save(str(path))
    return str(path.relative_to(ROOT))


class PMC(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def memory_mb() -> dict:
    counters = PMC()
    counters.cb = ctypes.sizeof(PMC)
    k32 = ctypes.WinDLL("kernel32")
    k32.GetCurrentProcess.restype = wt.HANDLE
    psapi = ctypes.WinDLL("psapi")
    psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.POINTER(PMC), wt.DWORD]
    psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
    return {"working_set_mb": round(counters.WorkingSetSize / 2**20, 1),
            "private_mb": round(counters.PagefileUsage / 2**20, 1)}


def cpu_share(seconds: float) -> float:
    """Process CPU time / wall time over a window of the real event loop (1.0 = one core)."""
    c0, w0 = time.process_time(), time.perf_counter()
    settle(int(seconds * 1000))
    return round((time.process_time() - c0) / (time.perf_counter() - w0), 3)


def active_timers() -> dict:
    from PySide6.QtCore import QAbstractAnimation
    timers = [t for t in win.findChildren(QTimer) if t.isActive()]
    owners = []
    for timer in timers:
        parent = timer.parent()
        owners.append(f"{type(parent).__name__}:{timer.interval()}ms")
    anims = [a for a in win.findChildren(QAbstractAnimation) if a.state() == QAbstractAnimation.State.Running]
    return {"active_qtimers": len(timers), "owners": sorted(owners), "running_animations": len(anims)}


def visible(widget) -> bool:
    return widget.isVisibleTo(win) and widget.isVisible()


ALLOWED_LATIN = {"YARA", "MITRE", "ATT", "CK", "PE", "SHA", "URL", "URLs", "IP", "IPs", "OSINT", "CYBERSCAN",
                 "CyberScan", "JSON", "Ctrl", "API", "KEY", "URLHAUS", "OTX", "THREATFOX", "ThreatFox",
                 "URLhaus", "AlienVault", "MZ", "D", "KB", "MB", "GB", "TXT", "EXE", "PDF", "BIN", "CFG"}


def texts_of(root: QWidget) -> list[tuple[str, str]]:
    out = []
    for w in root.findChildren(QWidget):
        if not visible(w):
            continue
        name = type(w).__name__
        if isinstance(w, QLabel) and w.text():
            out.append((name, w.text()))
        elif isinstance(w, QAbstractButton) and w.text():
            out.append((name, w.text()))
        if isinstance(w, QLineEdit) and w.placeholderText():
            out.append((name + ".placeholder", w.placeholderText()))
        if isinstance(w, QPlainTextEdit):
            if w.toPlainText():
                out.append((name, w.toPlainText()[:300]))
            elif w.placeholderText():
                out.append((name + ".placeholder", w.placeholderText()))
        if isinstance(w, QTabWidget):
            for i in range(w.count()):
                out.append(("QTab", w.tabText(i)))
        if isinstance(w, QListWidget):
            for i in range(min(w.count(), 5)):
                out.append(("QListItem", w.item(i).text()))
        if w.toolTip():
            out.append((name + ".tooltip", w.toolTip()))
        if w.accessibleName():
            out.append((name + ".accessibleName", w.accessibleName()))
    return out


def latin_leaks(pairs) -> list[tuple[str, str]]:
    import re
    leaks = []
    for kind, text in pairs:
        cleaned = re.sub(r"[A-Za-z]:[\\/][^\s]*|https?://\S+|\S+\.\w{2,4}\b|[0-9a-fA-F]{16,}", " ", text)
        words = [w for w in re.findall(r"[A-Za-z][A-Za-z'&-]{2,}", cleaned) if w not in ALLOWED_LATIN]
        if words:
            leaks.append((kind, text[:160]))
    return leaks


def layout_issues(root: QWidget) -> dict:
    clipped = []
    for w in root.findChildren(QWidget):
        if not visible(w) or w.width() <= 0:
            continue
        if isinstance(w, home.ElidedLabel):
            continue
        if isinstance(w, QLabel) and w.text() and not w.wordWrap() and "<" not in w.text():
            need = w.sizeHint().width()
            if need > w.width() + 2:
                clipped.append({"type": "QLabel", "text": w.text()[:80], "need": need, "have": w.width()})
        elif isinstance(w, QPushButton) and w.text():
            need = w.sizeHint().width()
            if need > w.width() + 2:
                clipped.append({"type": type(w).__name__, "text": w.text()[:80], "need": need, "have": w.width()})
    hscroll = []
    for area in root.findChildren(QScrollArea):
        if visible(area) and area.horizontalScrollBar().maximum() > 0:
            hscroll.append({"area": area.objectName() or "scroll", "overflow_px": area.horizontalScrollBar().maximum()})
    outside = []
    win_rect = win.rect()
    for w in root.findChildren(QWidget):
        if visible(w) and w.width() > 0 and not isinstance(w.parentWidget(), QScrollArea):
            top_left = w.mapTo(win, w.rect().topLeft())
            if top_left.x() + w.width() > win_rect.width() + 1 and w.parentWidget() and w.parentWidget().width() < w.width():
                outside.append({"type": type(w).__name__, "name": w.objectName(), "right": top_left.x() + w.width()})
    return {"clipped": clipped, "horizontal_scroll": hscroll, "beyond_window": outside[:10]}


TOGGLE_ERRORS = []


def _safe_toggle():
    try:
        win.toggle_language()
    except Exception as exc:
        TOGGLE_ERRORS.append(f"{type(exc).__name__}: {exc}")


def run_real_scan(target: str, mode: str = "File", *, label: str, capture_every: list[int] | None = None,
                  heartbeat: bool = False) -> dict:
    """Drive a scan exactly as a user would: type the target, press Analyze."""
    TIMELINE.clear()
    samples: list[tuple] = []
    gaps: list[float] = []
    last = [time.perf_counter()]

    def sample():
        now = time.perf_counter()
        gaps.append(now - last[0])
        last[0] = now
        samples.append((now, win.journey.phase, tuple(win.journey.stage_states), win.results_panel.isVisible(),
                        None if win.journey._packet_x is None else round(win.journey._packet_x, 1)))

    sampler = QTimer()
    sampler.setInterval(5 if heartbeat else 10)
    sampler.timeout.connect(sample)
    concluded_at = []
    win.journey.concluded.connect(lambda: concluded_at.append(time.perf_counter()))
    win._choose_mode_without_dialog(mode)
    win.selected_path = None
    win.target_entry.setText(target)
    sampler.start()
    t_click = time.perf_counter()
    win.analyze_button.click()
    done = wait_until(lambda: win.worker is None and (
        win.results_panel.isVisible() or win.journey.phase in {"failed", "cancelled"}), 40000)
    settle(400)
    sampler.stop()
    emits = [e for e in TIMELINE if e[0] == "emit"]
    ret = [e[1] for e in TIMELINE if e[0] == "analyze_return"]
    # lag between a worker emit and the journey showing that state
    lags = []
    for _kind, t_emit, index, state in emits:
        for s in samples:
            if s[0] >= t_emit and s[2][index] == state:
                lags.append(round((s[0] - t_emit) * 1000, 1))
                break
    reveal = next((s[0] for s in samples if s[3]), None)
    return {
        "label": label, "completed": done, "classification": getattr(win.last_payload[0], "classification", None) if win.last_payload else None,
        "journey_phase_end": win.journey.phase,
        "click_to_engine_return_ms": round((ret[-1] - t_click) * 1000, 1) if ret else None,
        "engine_return_to_results_visible_ms": round((reveal - ret[-1]) * 1000, 1) if reveal and ret else None,
        "engine_return_to_concluded_ms": round((concluded_at[-1] - ret[-1]) * 1000, 1) if concluded_at and ret else None,
        "emit_to_display_lag_ms": lags,
        "stage_emits": [(e[2], e[3], round((e[1] - t_click) * 1000, 1)) for e in emits],
        "max_event_loop_gap_ms": round(max(gaps) * 1000, 1) if gaps else None,
        "event_loop_gaps_over_100ms": sum(1 for g in gaps if g > 0.1),
        "samples": len(samples),
    }


def make_samples() -> dict:
    s = {}
    (SAMPLES / "meeting_notes.txt").write_text(
        "Agenda for Thursday.\nReview the quarterly budget and the hiring plan.\nNo action items yet.\n" * 20,
        encoding="utf-8")
    s["benign_text"] = SAMPLES / "meeting_notes.txt"
    body = bytearray(b"MZ" + b"\x90" * 58 + (128).to_bytes(4, "little") + b"\x00" * 64)
    body += b"This program cannot be run in DOS mode.\r\n" + b"\x00" * 200
    body += (b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00GetProcAddress\x00LoadLibraryA\x00"
             b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00"
             b"http://198.51.100.7/stage2.bin\x00HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00")
    body += bytes(random.Random(7).getrandbits(8) for _ in range(60000))
    (SAMPLES / "invoice.pdf.exe").write_bytes(bytes(body))
    s["synthetic_pe_like"] = SAMPLES / "invoice.pdf.exe"
    rnd = random.Random(11)
    (SAMPLES / "archive_blob.bin").write_bytes(bytes(rnd.getrandbits(8) for _ in range(400_000)))
    s["random_blob"] = SAMPLES / "archive_blob.bin"
    (SAMPLES / "large_random.bin").write_bytes(os.urandom(12 * 2**20))
    s["large_random"] = SAMPLES / "large_random.bin"
    long_name = "Quarterly_financial_reconciliation_statement_for_the_regional_operations_division_" \
                "final_reviewed_version_with_appendices_and_signatures_2026-10-29_copy(3).pdf.exe"
    (SAMPLES / long_name).write_bytes(bytes(body))
    s["long_name"] = SAMPLES / long_name
    arabic = "تقرير_الربع_الثالث_للحسابات_النهائية.pdf.exe"
    (SAMPLES / arabic).write_bytes(bytes(body))
    s["arabic_name"] = SAMPLES / arabic
    mixed = "Invoice فاتورة 2026 (final نهائي).docx"
    (SAMPLES / mixed).write_bytes(b"PK\x03\x04" + b"\x00" * 400)
    s["mixed_name"] = SAMPLES / mixed
    deep = SAMPLES
    for part in ("Projects", "Customer_Engagements_2026", "Regional_Office_Middle_East", "Incoming_Attachments",
                 "Unsorted_From_Email_Gateway", "Quarantine_Review_Pending"):
        deep = deep / part
    deep.mkdir(parents=True)
    (deep / "statement.txt").write_text("Plain statement text.\n", encoding="utf-8")
    s["deep_path"] = deep / "statement.txt"
    (SAMPLES / "empty.bin").write_bytes(b"")
    s["empty"] = SAMPLES / "empty.bin"
    return s


def record_history(count: int) -> list[dict]:
    kinds = ["SUSPICIOUS", "REVIEW", "NO_INDICATORS_OBSERVED"]
    out = []
    for i in range(count):
        out.append({"id": f"h{i}", "timestamp": f"2026-10-{(i % 28) + 1:02d}T10:{i % 60:02d}:00+03:00",
                    "target": str(SAMPLES / f"sample_{i}.bin"), "classification": kinds[i % 3],
                    "score": (i * 7) % 100, "sha256": f"{i:064x}", "report_path": f"reports/history/h{i}.json"})
    return out


# =============================================================================
LANG0 = os.environ.get("AUDIT_LANG", "en")
if LANG0 == "ar":
    (TMP / "data" / "ui_settings.json").write_text(json.dumps({"ui_language": "ar"}), encoding="utf-8")
t0 = time.perf_counter()
win = qa.CyberScanApp()
win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
t_construct = time.perf_counter()
win.resize(1440, 900)
win.show()
settle(50)
t_shown = time.perf_counter()
settle(600)
RESULTS["measurements"]["startup"] = {
    "import_qt_app_ms": round((T_IMPORT1 - T_IMPORT0) * 1000, 1),
    "construct_window_ms": round((t_construct - t0) * 1000, 1),
    "construct_to_first_events_ms": round((t_shown - t_construct) * 1000, 1),
    "note": "in-process; excludes Python interpreter start. See startup_subprocess for cold runs.",
}
RESULTS["measurements"]["memory_after_start"] = memory_mb()
RESULTS["facts"]["window_title"] = win.windowTitle()
RESULTS["facts"]["minimum_size"] = [win.minimumWidth(), win.minimumHeight()]
RESULTS["facts"]["reduced_motion_effective"] = home.prefers_reduced_motion()

SAMPLE = make_samples()
STEPS: list[tuple[str, callable]] = []


def step(name):
    def deco(fn):
        STEPS.append((name, fn))
        return fn
    return deco


@step("idle_and_cpu")
def _idle():
    win._show_page("analysis")
    settle(400)
    shot("01_idle_empty_en_1440")
    RESULTS["layout"]["idle_en_1440"] = layout_issues(win)
    RESULTS["measurements"]["timers_idle_analysis"] = active_timers()
    RESULTS["measurements"]["cpu_idle_analysis_page_5s"] = cpu_share(5)
    win._show_page("settings")
    settle(300)
    RESULTS["measurements"]["timers_idle_settings"] = active_timers()
    RESULTS["measurements"]["cpu_idle_settings_page_5s"] = cpu_share(5)
    win.showMinimized()
    settle(300)
    RESULTS["measurements"]["timers_minimized"] = active_timers()
    RESULTS["measurements"]["cpu_minimized_5s"] = cpu_share(5)
    win.showNormal()
    win.resize(1440, 900)
    win._show_page("analysis")
    settle(400)


@step("idle_variants")
def _idle_variants():
    win.scan_history = record_history(3)
    win.refresh_history()
    settle(200)
    shot("02_idle_history_en_1440")
    win._set_drop_armed(True)
    settle(100)
    shot("03_drop_armed_en")
    win._set_drop_armed(False)
    win.mode_segment.buttons["URL"].click()
    settle(100)
    shot("04_mode_url_en")
    win.mode_segment.buttons["Indicator / text"].click() if "Indicator / text" in win.mode_segment.buttons else None
    settle(100)
    shot("05_mode_indicator_en")
    win._choose_mode_without_dialog("File")
    win.target_entry.setText("")
    win.analyze_button.click()
    settle(150)
    shot("06_error_empty_target_en")
    RESULTS["facts"]["empty_target_banner"] = [win.status_banner.isVisible()]
    win.target_entry.setText(r"C:\does\not\exist\file.bin")
    win.analyze_button.click()
    settle(150)
    shot("07_error_file_not_found_en")
    win._choose_mode_without_dialog("URL")
    win.target_entry.setText("example dot com")
    win.analyze_button.click()
    settle(150)
    shot("08_error_bad_url_en")
    win._choose_mode_without_dialog("File")
    win.target_entry.setText(str(SAMPLE["long_name"]))
    win.selected_file_label.setText(str(SAMPLE["long_name"]))
    settle(150)
    shot("09_long_filename_selected_en")
    RESULTS["layout"]["long_filename_selected_en"] = layout_issues(win)
    win.target_entry.setText("")


@step("scan_real_variants")
def _scans():
    runs = RESULTS["measurements"].setdefault("real_scans", [])
    run = run_real_scan(str(SAMPLE["benign_text"]), label="benign_text")
    runs.append(run)
    shot("10_result_benign_viewport_en")
    full_shot("10b_result_benign_full_en")
    RESULTS["payload_benign"] = True
    globals()["PAYLOAD_LOW"] = copy.deepcopy(win.last_payload)
    RESULTS["text"]["result_benign_en"] = texts_of(win.results_panel)
    win.new_scan_button.click()
    settle(300)
    shot("11_after_new_scan_en")

    run = run_real_scan(str(SAMPLE["synthetic_pe_like"]), label="synthetic_pe_like")
    runs.append(run)
    shot("12_result_pe_like_viewport_en")
    full_shot("12b_result_pe_like_full_en")
    globals()["PAYLOAD_PE"] = copy.deepcopy(win.last_payload)
    RESULTS["text"]["result_pe_en"] = texts_of(win.results_panel)
    RESULTS["layout"]["result_pe_en_1440"] = layout_issues(win)
    win.details_button.click()
    settle(300)
    full_shot("13_result_pe_technical_open_en")
    win.details_button.click()
    win.new_scan_button.click()

    run = run_real_scan(str(SAMPLE["random_blob"]), label="random_blob")
    runs.append(run)
    full_shot("14_result_random_blob_full_en")
    win.new_scan_button.click()

    run = run_real_scan("http://198.51.100.7/secure-login.php?account=verify&redirect=//paypa1.example", "URL",
                        label="url")
    runs.append(run)
    full_shot("15_result_url_full_en")
    win.new_scan_button.click()

    run = run_real_scan("44d88612fea8a8f36de82e1278abb02f", "Indicator / text", label="indicator_hash")
    runs.append(run)
    full_shot("16_result_indicator_full_en")
    win.new_scan_button.click()

    run = run_real_scan(str(SAMPLE["empty"]), label="empty_file")
    runs.append(run)
    full_shot("17_result_empty_file_full_en")
    win.new_scan_button.click()

    run = run_real_scan(str(SAMPLE["large_random"]), label="large_random_12MB", heartbeat=True)
    runs.append(run)
    win.new_scan_button.click()

    for key in ("long_name", "arabic_name", "mixed_name", "deep_path"):
        run = run_real_scan(str(SAMPLE[key]), label=key)
        runs.append(run)
        full_shot(f"18_result_{key}_full_en")
        RESULTS["layout"][f"result_{key}_en"] = layout_issues(win)
        win.new_scan_button.click()
    settle(200)


@step("journey_frames")
def _journey_frames():
    # Hold the engine inside stage 1 to capture mid-journey frames and to
    # check whether anything advances while the engine is stalled.
    HOLD["event"] = threading.Event()
    HOLD["stage"] = 1
    win._choose_mode_without_dialog("File")
    win.target_entry.setText(str(SAMPLE["synthetic_pe_like"]))
    t = time.perf_counter()
    win.analyze_button.click()
    settle(120)
    shot("20_journey_entering_en")
    wait_until(lambda: win.journey.stage_states[1] == "running", 10000)
    settle(900)
    shot("21_journey_stage2_running_en")
    states_before = tuple(win.journey.stage_states)
    packet_before = win.journey._packet_x
    timers_running = active_timers()
    cpu = cpu_share(3)
    settle(2000)
    RESULTS["measurements"]["stalled_engine_check"] = {
        "states_before": states_before, "states_after_5s": tuple(win.journey.stage_states),
        "packet_x_before": packet_before, "packet_x_after": win.journey._packet_x,
        "caption": win.journey_caption.text(), "status": win.journey_status.text(),
        "pill": win.connection_status.text(),
    }
    RESULTS["measurements"]["timers_during_journey"] = timers_running
    RESULTS["measurements"]["cpu_during_journey_3s"] = cpu
    RESULTS["measurements"]["memory_during_journey"] = memory_mb()
    # close while running -> refused
    DIALOGS.clear()
    win.close()
    settle(100)
    RESULTS["facts"]["close_during_scan"] = {"window_still_visible": win.isVisible(), "dialogs": list(DIALOGS)}
    # cancel
    win.cancel_button.click()
    settle(300)
    shot("22_journey_cancelled_en")
    RESULTS["facts"]["after_cancel"] = {
        "caption": win.journey_caption.text(), "banner_visible": win.status_banner.isVisible(),
        "banner_title": win.status_banner.title.text() if hasattr(win.status_banner, "title") else None,
        "pill": win.connection_status.text(), "analyze_enabled": win.analyze_button.isEnabled(),
        "abandoned": len(win._abandoned_workers),
    }
    DIALOGS.clear()
    win.close()
    settle(100)
    RESULTS["facts"]["close_after_cancel_while_thread_alive"] = {"window_still_visible": win.isVisible(), "dialogs": list(DIALOGS)}
    HOLD["event"].set()
    wait_until(lambda: not any(w.isRunning() for w in win._abandoned_workers), 20000)
    settle(300)
    HOLD["event"] = None
    if not win.isVisible():
        win.show()
        settle(200)
    RESULTS["facts"]["history_count_after_cancel"] = len(win.scan_history)
    win.new_scan_button.click() if win.new_scan_button.isVisible() else win.journey_new_scan_button.click()
    settle(200)


@step("evidence_and_failure")
def _evidence():
    # capture the evidence/concluding frames of a real scan
    TIMELINE.clear()
    win._choose_mode_without_dialog("File")
    win.target_entry.setText(str(SAMPLE["synthetic_pe_like"]))
    win.analyze_button.click()
    wait_until(lambda: win.journey.phase in {"evidence", "concluding"}, 20000, 5)
    settle(150)
    shot("23_journey_evidence_en")
    wait_until(lambda: win.results_panel.isVisible(), 10000)
    settle(80)
    shot("24_journey_concluded_results_en")
    win.new_scan_button.click()
    settle(200)
    # real failure: file larger than the in-memory size limit (not persisted)
    saved = dict(win.settings)
    win.settings["maximum_file_size"] = 16
    DIALOGS.clear()
    run = run_real_scan(str(SAMPLE["benign_text"]), label="failure_size_limit")
    RESULTS["measurements"].setdefault("real_scans", []).append(run)
    shot("25_failure_en")
    RESULTS["facts"]["failure"] = {
        "dialogs": list(DIALOGS), "journey_states": list(win.journey.stage_states),
        "caption": win.journey_caption.text(), "pill": win.connection_status.text(),
        "banner_visible": win.status_banner.isVisible(),
        "history_count": len(win.scan_history),
    }
    win.settings.clear()
    win.settings.update(saved)
    win.journey_new_scan_button.click()
    settle(200)


@step("synthetic_verdicts")
def _synthetic():
    """Verdict classes the engine cannot be pushed into with inert inputs."""
    result, nextgen, vector, prediction, intelligence, raw = copy.deepcopy(PAYLOAD_LOW)
    result.engine_status = dict(result.engine_status)
    key = next((k for k in result.engine_status if "entropy" in k.lower()), None) or next(iter(result.engine_status))
    result.engine_status[key] = "failed: synthetic audit fault"
    win._start_journey(result.target, "File")
    win._scan_completed((result, nextgen, vector, prediction, intelligence, raw))
    wait_until(lambda: win.results_panel.isVisible(), 8000)
    settle(300)
    full_shot("30_result_inconclusive_SYNTHETIC_full_en")
    RESULTS["text"]["result_inconclusive_en"] = texts_of(win.results_panel)
    win.new_scan_button.click()
    settle(200)
    result, nextgen, vector, prediction, intelligence, raw = copy.deepcopy(PAYLOAD_PE)
    result.classification = "SOMETHING_NEW"
    win._start_journey(result.target, "File")
    win._scan_completed((result, nextgen, vector, prediction, intelligence, raw))
    wait_until(lambda: win.results_panel.isVisible(), 8000)
    settle(300)
    full_shot("31_result_unrecognized_SYNTHETIC_full_en")
    win.new_scan_button.click()
    settle(200)


@step("pages_en")
def _pages():
    win.scan_history = record_history(3)
    win.refresh_history()
    for name in ("history", "yara", "mitre", "model", "logs", "settings", "about"):
        win._show_page(name)
        settle(320)
        shot(f"40_page_{name}_en")
        RESULTS["layout"][f"page_{name}_en"] = layout_issues(win)
        RESULTS["text"][f"page_{name}_en"] = texts_of(win.pages.currentWidget())
    win._show_page("history")
    if win.history_list.count():
        win.history_list.setCurrentRow(0)
    settle(200)
    shot("41_history_selected_en")
    win.scan_history = []
    win.refresh_history()
    settle(150)
    shot("42_history_empty_en")
    t = time.perf_counter()
    win.scan_history = record_history(500)
    win.refresh_history()
    settle(50)
    RESULTS["measurements"]["history_500_refresh_ms"] = round((time.perf_counter() - t) * 1000, 1)
    shot("43_history_500_en")
    win._show_page("analysis")
    settle(300)
    shot("44_home_with_500_history_en")
    t = time.perf_counter()
    for i in range(300):
        win._show_page(("analysis", "history", "settings", "yara", "logs")[i % 5])
        app.processEvents()
    RESULTS["measurements"]["rapid_page_switch_300_ms"] = round((time.perf_counter() - t) * 1000, 1)
    win._show_page("analysis")
    settle(300)
    RESULTS["facts"]["page_opacity_after_rapid_switch"] = round(win._page_effect.opacity(), 2)
    win.scan_history = record_history(3)
    win.refresh_history()


@step("arabic")
def _arabic():
    _safe_toggle()
    settle(400)
    shot("50_idle_ar_1440")
    RESULTS["layout"]["idle_ar_1440"] = layout_issues(win)
    RESULTS["text"]["idle_ar"] = texts_of(win)
    run = run_real_scan(str(SAMPLE["synthetic_pe_like"]), label="pe_like_ar")
    RESULTS["measurements"].setdefault("real_scans", []).append(run)
    shot("51_result_pe_viewport_ar")
    full_shot("51b_result_pe_full_ar")
    RESULTS["text"]["result_pe_ar"] = texts_of(win.results_panel)
    RESULTS["layout"]["result_pe_ar"] = layout_issues(win)
    win.details_button.click()
    settle(300)
    full_shot("52_result_pe_technical_open_ar")
    RESULTS["text"]["technical_ar"] = texts_of(win.results_panel)
    win.details_button.click()
    win.new_scan_button.click()
    run = run_real_scan(str(SAMPLE["arabic_name"]), label="arabic_name_ar")
    RESULTS["measurements"]["real_scans"].append(run)
    full_shot("53_result_arabic_name_full_ar")
    win.new_scan_button.click()
    run = run_real_scan(str(SAMPLE["mixed_name"]), label="mixed_name_ar")
    RESULTS["measurements"]["real_scans"].append(run)
    full_shot("54_result_mixed_name_full_ar")
    win.new_scan_button.click()
    saved = dict(win.settings)
    win.settings["maximum_file_size"] = 16
    DIALOGS.clear()
    run_real_scan(str(SAMPLE["benign_text"]), label="failure_ar")
    shot("55_failure_ar")
    RESULTS["facts"]["failure_ar_dialogs"] = list(DIALOGS)
    win.settings.clear()
    win.settings.update(saved)
    win.journey_new_scan_button.click()
    for name in ("history", "yara", "mitre", "model", "logs", "settings", "about"):
        win._show_page(name)
        settle(320)
        shot(f"56_page_{name}_ar")
        RESULTS["layout"][f"page_{name}_ar"] = layout_issues(win)
        RESULTS["text"][f"page_{name}_ar"] = texts_of(win.pages.currentWidget())
    win._show_page("analysis")
    settle(200)
    all_ar = []
    for key, pairs in RESULTS["text"].items():
        if key.endswith("_ar") or key == "idle_ar" or key == "technical_ar":
            all_ar.extend((key, kind, text) for kind, text in latin_leaks(pairs))
    RESULTS["text"]["arabic_latin_leaks"] = all_ar
    _safe_toggle()
    settle(300)


@step("widths")
def _widths():
    out = {}
    for lang in ("en", "ar"):
        if lang == "ar":
            _safe_toggle()
            settle(300)
        for width in (880, 960, 1000, 1080, 1200, 1440, 1920):
            win.resize(width, 760 if width < 1100 else 900)
            win._apply_layout_mode()
            settle(250)
            issues = layout_issues(win)
            out[f"{lang}_{width}_idle"] = issues
            if width in (880, 1920):
                shot(f"60_idle_{lang}_{width}")
        win.resize(880, 600)
        win._apply_layout_mode()
        settle(250)
        shot(f"61_idle_{lang}_880x600_minimum")
        out[f"{lang}_880x600_idle"] = layout_issues(win)
        win.target_entry.setText(str(SAMPLE["synthetic_pe_like"]))
        run_real_scan(str(SAMPLE["synthetic_pe_like"]), label=f"pe_like_{lang}_880")
        shot(f"62_result_{lang}_880x600_viewport")
        full_shot(f"62b_result_{lang}_880_full")
        out[f"{lang}_880_result"] = layout_issues(win)
        win.new_scan_button.click()
        settle(200)
        # continuous resize
        t = time.perf_counter()
        frames = 0
        for width in list(range(880, 1900, 20)) + list(range(1900, 880, -20)):
            win.resize(width, 820)
            app.processEvents()
            frames += 1
        out[f"{lang}_continuous_resize"] = {"steps": frames, "total_ms": round((time.perf_counter() - t) * 1000, 1)}
        settle(300)
        if lang == "ar":
            _safe_toggle()
            settle(300)
    win.resize(1440, 900)
    win._apply_layout_mode()
    settle(300)
    RESULTS["layout"]["widths"] = out


@step("large_text")
def _large_text():
    win.settings["large_text"] = True
    win._apply_text_scale()
    settle(300)
    shot("70_idle_large_text_en_1440")
    RESULTS["layout"]["large_text_idle_1440"] = layout_issues(win)
    win.resize(1000, 760)
    win._apply_layout_mode()
    settle(300)
    shot("71_idle_large_text_en_1000")
    RESULTS["layout"]["large_text_idle_1000"] = layout_issues(win)
    run_real_scan(str(SAMPLE["synthetic_pe_like"]), label="large_text_1000")
    full_shot("72_result_large_text_1000_full")
    RESULTS["layout"]["large_text_result_1000"] = layout_issues(win)
    win.new_scan_button.click()
    win.settings["large_text"] = False
    win._apply_text_scale()
    win.resize(1440, 900)
    win._apply_layout_mode()
    settle(300)


@step("keyboard_a11y")
def _keyboard():
    from PySide6.QtWidgets import QWidget as W
    win._show_page("analysis")
    settle(200)

    def chain(page_root: W):
        seq = []
        start = win
        w = start.nextInFocusChain()
        seen = 0
        while w is not start and seen < 600:
            seen += 1
            if visible(w) and w.isEnabled() and (w.focusPolicy().value & Qt.FocusPolicy.TabFocus.value):
                label = ""
                if isinstance(w, QAbstractButton):
                    label = w.text() or w.accessibleName() or w.toolTip()
                elif isinstance(w, QLineEdit):
                    label = w.placeholderText()
                else:
                    label = w.accessibleName()
                seq.append({"class": type(w).__name__, "name": w.objectName(), "label": (label or "")[:60],
                            "x": w.mapTo(win, w.rect().topLeft()).x(), "y": w.mapTo(win, w.rect().topLeft()).y()})
            w = w.nextInFocusChain()
        return seq

    RESULTS["keyboard"]["idle_chain"] = chain(win)
    unreachable = []
    unnamed = []
    for w in win.findChildren(QAbstractButton):
        if not visible(w):
            continue
        if not (w.focusPolicy().value & Qt.FocusPolicy.TabFocus.value):
            unreachable.append({"class": type(w).__name__, "text": w.text()[:40], "tooltip": w.toolTip()[:40]})
        if not (w.text().strip() or w.accessibleName().strip()):
            unnamed.append({"class": type(w).__name__, "tooltip": w.toolTip()[:60], "name": w.objectName()})
    RESULTS["keyboard"]["idle_buttons_not_tab_reachable"] = unreachable
    RESULTS["keyboard"]["idle_buttons_without_text_or_accessible_name"] = unnamed
    run_real_scan(str(SAMPLE["synthetic_pe_like"]), label="keyboard_result")
    RESULTS["keyboard"]["result_chain"] = chain(win)
    painted = {}
    for attr in ("journey", "verdict_badge", "risk_gauge", "category_donut", "category_bars", "file_card",
                 "scan_core", "stage_track"):
        w = getattr(win, attr, None)
        if w is not None:
            painted[attr] = {"accessibleName": w.accessibleName(), "accessibleDescription": w.accessibleDescription()[:120]}
    RESULTS["keyboard"]["painted_widget_accessibility_en"] = painted
    _safe_toggle()
    settle(300)
    painted_ar = {}
    for attr in ("journey", "verdict_badge", "risk_gauge", "category_donut", "scan_core"):
        w = getattr(win, attr, None)
        if w is not None:
            painted_ar[attr] = {"accessibleName": w.accessibleName(), "accessibleDescription": w.accessibleDescription()[:120]}
    RESULTS["keyboard"]["painted_widget_accessibility_ar"] = painted_ar
    _safe_toggle()
    win.new_scan_button.click()
    settle(200)
    # Focus ring visibility: render the primary button with and without focus.
    win.activateWindow()
    settle(100)
    btn = win.analyze_button
    plain = btn.grab().toImage()
    btn.setFocus(Qt.FocusReason.TabFocusReason)
    settle(150)
    focused = btn.grab().toImage()
    diff = 0
    if plain.size() == focused.size():
        for y in range(0, plain.height(), 2):
            for x in range(0, plain.width(), 2):
                if plain.pixel(x, y) != focused.pixel(x, y):
                    diff += 1
    RESULTS["keyboard"]["focus_ring_probe"] = {"has_focus": btn.hasFocus(), "changed_pixels_sampled": diff,
                                               "active_window": QApplication.activeWindow() is win}
    btn.grab().save(str(SHOTS / "80_analyze_button_focused.png"))


@step("consecutive_and_close")
def _consecutive():
    reps = []
    for i in range(5):
        before = len(win.scan_history)
        r = run_real_scan(str(SAMPLE["benign_text"] if i % 2 else SAMPLE["synthetic_pe_like"]), label=f"seq_{i}")
        reps.append({"history_delta": len(win.scan_history) - before, "phase": r["journey_phase_end"],
                     "click_to_results_ms": r["click_to_engine_return_ms"], "reveal_ms": r["engine_return_to_results_visible_ms"],
                     "first_states_seen": r["stage_emits"][:1]})
        win.new_scan_button.click()
        settle(150)
    RESULTS["measurements"]["consecutive_scans"] = reps
    RESULTS["measurements"]["timers_after_consecutive"] = active_timers()
    RESULTS["measurements"]["memory_after_all_scans"] = memory_mb()
    # close while the journey is animating
    HOLD["event"] = threading.Event()
    HOLD["stage"] = 2
    win._choose_mode_without_dialog("File")
    win.target_entry.setText(str(SAMPLE["benign_text"]))
    win.analyze_button.click()
    wait_until(lambda: win.journey.stage_states[2] == "running", 10000)
    HOLD["event"].set()
    wait_until(lambda: win.worker is None, 10000)
    win.close()
    settle(200)
    RESULTS["measurements"]["timers_after_close"] = active_timers()
    RESULTS["facts"]["closed_during_conclusion"] = {"visible": win.isVisible(), "journey_animating": win.journey.animating,
                                                   "scan_core_animating": win.scan_core.animating}
    HOLD["event"] = None



@step("repro")
def _repro():
    out = {}
    QT_MESSAGES.clear()
    r = run_real_scan(str(SAMPLE["benign_text"]), label="repro_no_findings")
    settle(8000)
    out["no_findings"] = {"phase_after_8s_more": win.journey.phase, "results_visible": win.results_panel.isVisible(),
                          "classification": r["classification"], "markers": len(win.journey.markers),
                          "pill": win.connection_status.text(), "caption": win.journey_caption.text(),
                          "new_scan_button_visible": win.journey_new_scan_button.isVisible()}
    shot("90_REPRO_no_findings_after_8s")
    win.journey_new_scan_button.click()
    settle(200)
    out["text_bindings_before"] = len(win._text_bindings)
    run_real_scan(str(SAMPLE["mixed_name"]), label="repro_a")
    win.new_scan_button.click()
    run_real_scan(str(SAMPLE["mixed_name"]), label="repro_b")
    out["text_bindings_after_2_scans"] = len(win._text_bindings)
    from shiboken6 import isValid
    out["dead_bindings"] = sum(1 for w, _src in win._text_bindings if not isValid(w))
    try:
        n_err = len(TOGGLE_ERRORS)
        _safe_toggle()
        out["toggle"] = TOGGLE_ERRORS[-1] if len(TOGGLE_ERRORS) > n_err else "ok"
    except Exception as exc:
        out["toggle"] = f"{type(exc).__name__}: {exc}"
    settle(300)
    out["after_toggle"] = {"language": win.language, "direction_rtl": win.layoutDirection() == Qt.LayoutDirection.RightToLeft,
                           "hero_title": win.hero_title.text(), "page_title": win.page_title.text(),
                           "language_button": win.language_button.text()}
    shot("91_REPRO_after_failed_language_toggle")
    full_shot("91b_REPRO_after_failed_language_toggle_full")
    RESULTS["facts"]["repro"] = out


@step("paint_cost")
def _paint_cost():
    from ui.qt_widgets import AnimatedBackground
    from ui.home import ScanCore
    from ui.journey import JourneyScene
    stats = {}

    def wrap(cls):
        orig = cls.paintEvent

        def timed(self, event):
            t = time.perf_counter()
            orig(self, event)
            entry = stats.setdefault(cls.__name__, [0, 0.0])
            entry[0] += 1
            entry[1] += time.perf_counter() - t
        cls.paintEvent = timed

    for cls in (AnimatedBackground, ScanCore, JourneyScene):
        wrap(cls)

    def summary(cpu):
        return {"cpu": cpu, "per_class": {k: {"paints": v[0], "ms_total": round(v[1] * 1000, 1),
                                              "ms_avg": round(v[1] * 1000 / max(1, v[0]), 2)} for k, v in stats.items()}}

    win._show_page("analysis")
    win.resize(1440, 900)
    settle(500)
    stats.clear()
    RESULTS["measurements"]["paint_cost_idle_4s"] = summary(cpu_share(4))
    win._show_page("settings")
    settle(400)
    stats.clear()
    RESULTS["measurements"]["paint_cost_settings_4s"] = summary(cpu_share(4))
    win._show_page("analysis")
    HOLD["event"] = threading.Event()
    HOLD["stage"] = 1
    win._choose_mode_without_dialog("File")
    win.target_entry.setText(str(SAMPLE["benign_text"]))
    win.analyze_button.click()
    wait_until(lambda: win.journey.stage_states[1] == "running", 10000)
    settle(800)
    stats.clear()
    RESULTS["measurements"]["paint_cost_journey_4s"] = summary(cpu_share(4))
    HOLD["event"].set()
    wait_until(lambda: win.worker is None, 10000)
    HOLD["event"] = None
    settle(1500)
    win.journey_new_scan_button.click()
    settle(200)


@step("painter_warnings")
def _painter_warnings():
    win._show_page("analysis")
    settle(400)
    QT_MESSAGES.clear()
    settle(3000)
    no_grab = len(QT_MESSAGES)
    win._show_page("settings")
    settle(400)
    win._show_page("analysis")
    settle(400)
    after_switch = len(QT_MESSAGES)
    QT_MESSAGES.clear()
    shot("zz_probe")
    with_grab = len(QT_MESSAGES)
    QT_MESSAGES.clear()
    win.analyze_button.grab()
    leaf_grab = len(QT_MESSAGES)
    RESULTS["facts"]["painter_warnings"] = {"idle_3s_no_grab": no_grab, "two_page_switches": after_switch - no_grab,
                                            "one_window_grab": with_grab, "one_leaf_grab": leaf_grab,
                                            "sample": [m["msg"] for m in QT_MESSAGES[:3]]}
    (SHOTS / "zz_probe.png").unlink(missing_ok=True)


@step("memory")
def _memory():
    m0 = memory_mb()
    for i in range(8):
        run_real_scan(str(SAMPLE["mixed_name"] if i % 2 else SAMPLE["random_blob"]), label=f"mem_{i}")
        if win.new_scan_button.isVisible():
            win.new_scan_button.click()
        else:
            win.journey_new_scan_button.click()
        settle(100)
    RESULTS["measurements"]["memory_series"] = {"before": m0, "after_8_scans": memory_mb(),
                                                "text_bindings": len(win._text_bindings)}


@step("lang_pass")
def _lang_pass():
    """One language for the whole process (chosen at start); no toggling."""
    lang = LANG0
    win._show_page("analysis")
    win.scan_history = record_history(3)
    win.refresh_history()
    settle(400)
    shot(f"A{lang}_01_idle_1440")
    RESULTS["layout"][f"{lang}_idle_1440"] = layout_issues(win)
    RESULTS["text"][f"{lang}_idle"] = texts_of(win)
    win._choose_mode_without_dialog("File")
    win.target_entry.setText("")
    win.analyze_button.click()
    settle(150)
    shot(f"A{lang}_02_error_empty")
    for key, label in (("synthetic_pe_like", "pe"), ("random_blob", "blob"), ("arabic_name", "arname"), ("mixed_name", "mixed")):
        run_real_scan(str(SAMPLE[key]), label=f"{lang}_{label}")
        shot(f"A{lang}_10_result_{label}_viewport")
        full_shot(f"A{lang}_11_result_{label}_full")
        RESULTS["text"][f"{lang}_result_{label}"] = texts_of(win.results_panel)
        RESULTS["layout"][f"{lang}_result_{label}"] = layout_issues(win)
        if label == "pe":
            win.details_button.click()
            settle(300)
            full_shot(f"A{lang}_12_result_pe_technical")
            RESULTS["text"][f"{lang}_technical"] = texts_of(win.results_panel)
            win.details_button.click()
        win.new_scan_button.click()
        settle(150)
    saved = dict(win.settings)
    win.settings["maximum_file_size"] = 16
    DIALOGS.clear()
    run_real_scan(str(SAMPLE["benign_text"]), label=f"{lang}_failure")
    shot(f"A{lang}_20_failure")
    RESULTS["facts"][f"{lang}_failure_dialogs"] = list(DIALOGS)
    win.settings.clear()
    win.settings.update(saved)
    win.journey_new_scan_button.click()
    HOLD["event"] = threading.Event()
    HOLD["stage"] = 1
    win.target_entry.setText(str(SAMPLE["random_blob"]))
    win.analyze_button.click()
    wait_until(lambda: win.journey.stage_states[1] == "running", 10000)
    settle(800)
    shot(f"A{lang}_21_journey_running")
    win.cancel_button.click()
    settle(300)
    shot(f"A{lang}_22_cancelled")
    HOLD["event"].set()
    wait_until(lambda: not any(w.isRunning() for w in win._abandoned_workers), 20000)
    HOLD["event"] = None
    win.journey_new_scan_button.click()
    for name in ("history", "yara", "mitre", "model", "logs", "settings", "about"):
        win._show_page(name)
        settle(320)
        shot(f"A{lang}_30_page_{name}")
        RESULTS["layout"][f"{lang}_page_{name}"] = layout_issues(win)
        RESULTS["text"][f"{lang}_page_{name}"] = texts_of(win.pages.currentWidget())
    win._show_page("history")
    win.history_list.setCurrentRow(0)
    settle(200)
    shot(f"A{lang}_31_history_selected")
    RESULTS["text"][f"{lang}_history_details"] = [("details", win.history_details.toPlainText()[:600])]
    win._show_page("analysis")
    settle(200)
    if lang == "ar":
        leaks = []
        for key, pairs in RESULTS["text"].items():
            leaks.extend((key, kind, text) for kind, text in latin_leaks(pairs))
        RESULTS["text"]["arabic_latin_leaks"] = leaks
    out = {}
    for width in (880, 960, 1000, 1080, 1200, 1440, 1920):
        win.resize(width, 760 if width < 1100 else 900)
        win._apply_layout_mode()
        settle(250)
        out[f"idle_{width}"] = layout_issues(win)
        if width in (880, 1000, 1920):
            shot(f"A{lang}_40_idle_{width}")
    win.resize(880, 600)
    win._apply_layout_mode()
    settle(250)
    shot(f"A{lang}_41_idle_880x600")
    out["idle_880x600"] = layout_issues(win)
    run_real_scan(str(SAMPLE["synthetic_pe_like"]), label=f"{lang}_880")
    shot(f"A{lang}_42_result_880x600_viewport")
    full_shot(f"A{lang}_43_result_880_full")
    out["result_880"] = layout_issues(win)
    win.new_scan_button.click()
    t = time.perf_counter()
    n = 0
    for width in list(range(880, 1900, 20)) + list(range(1900, 880, -20)):
        win.resize(width, 820)
        app.processEvents()
        n += 1
    out["continuous_resize"] = {"steps": n, "total_ms": round((time.perf_counter() - t) * 1000, 1)}
    win.resize(1440, 900)
    win._apply_layout_mode()
    settle(300)
    RESULTS["layout"][f"{lang}_widths"] = out
    win.settings["large_text"] = True
    win._apply_text_scale()
    win.resize(1000, 760)
    win._apply_layout_mode()
    settle(300)
    shot(f"A{lang}_50_large_text_1000")
    RESULTS["layout"][f"{lang}_large_text_1000"] = layout_issues(win)
    run_real_scan(str(SAMPLE["synthetic_pe_like"]), label=f"{lang}_large")
    full_shot(f"A{lang}_51_large_text_result_1000")
    RESULTS["layout"][f"{lang}_large_text_result"] = layout_issues(win)
    win.new_scan_button.click()
    win.settings["large_text"] = False
    win._apply_text_scale()
    win.resize(1440, 900)
    win._apply_layout_mode()
    settle(300)


ONLY = [x for x in os.environ.get("AUDIT_STEPS", "").split(",") if x]
if ONLY:
    STEPS[:] = [(n, f) for n, f in STEPS if n in ONLY]
    RESULTS_FILE = LOGS / f"harness_results_{os.environ.get('AUDIT_TAG', 'supp')}.json"
else:
    RESULTS_FILE = LOGS / "harness_results.json"
for name, fn in STEPS:
    try:
        fn()
    except Exception:
        RESULTS["errors"].append({"step": name, "trace": traceback.format_exc()})
    if not win.isVisible() and name != "consecutive_and_close":
        win.show()
        settle(150)

RESULTS["qt_messages"] = QT_MESSAGES
RESULTS["uncaught_exceptions"] = EXCEPTIONS
RESULTS["dialogs_remaining"] = DIALOGS
RESULTS["temp_dir"] = str(TMP)
RESULTS["toggle_errors"] = TOGGLE_ERRORS
RESULTS_FILE.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
print("steps", [s for s, _ in STEPS])
print("errors", len(RESULTS["errors"]), "qt_messages", len(QT_MESSAGES), "exceptions", len(EXCEPTIONS))
