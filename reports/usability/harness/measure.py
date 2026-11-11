"""Usability evaluation harness: measures the real CyberScan window.

Runs the real app (Windows platform, not shown on screen), with every
persistent path redirected to a temporary folder. Collects:

* screenshots of every screen, in English and Arabic, at three sizes;
* text contrast measured from rendered pixels (WCAG 1.4.3 / 1.4.11);
* click-target sizes (WCAG 2.5.8), accessible names (4.1.2);
* the keyboard tab order on each screen, and whether focus is visible (2.4.7, 2.4.11);
* timed tasks, counting user actions;
* stress cases, with the longest UI freeze measured by a 10 ms heartbeat.

Writes ``reports/usability/data.json`` and ``reports/usability/screens/``.
Never touches the user's data or settings.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "reports" / "usability"
SHOTS = OUT / "screens"
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ["CYBERSCAN_REDUCE_MOTION"] = "0"

SUSPICIOUS = (
    b"MZ" + b"\x00" * 200
    + b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00"
    + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00"
)


def main() -> None:
    SHOTS.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cs_usability_"))
    (tmp / "data").mkdir()
    (tmp / "reports").mkdir()
    samples = tmp / "samples"
    samples.mkdir()

    import numpy as np
    from PySide6.QtCore import QEvent, QEventLoop, QObject, QPoint, Qt, QTimer
    from PySide6.QtGui import QKeyEvent
    from PySide6.QtWidgets import (QAbstractButton, QApplication, QCheckBox, QLabel, QLineEdit, QMessageBox,
                                   QPlainTextEdit, QPushButton, QTabBar, QWidget)

    app = QApplication([])
    import ui.qt_app as qa

    qa.DATA_DIR, qa.REPORT_DIR = tmp / "data", tmp / "reports"
    qa.ensure_directories = lambda: None
    boxes: list[tuple[str, str, str]] = []

    def fake_box(kind, answer=None):
        def box(_parent, title, text, *args, **kwargs):
            boxes.append((kind, title, text))
            return answer if answer is not None else QMessageBox.StandardButton.Ok
        return staticmethod(box)

    for kind in ("critical", "warning", "information"):
        setattr(qa.QMessageBox, kind, fake_box(kind))
    qa.QMessageBox.question = fake_box("question", QMessageBox.StandardButton.Yes)

    # -- helpers ------------------------------------------------------------------------------
    def settle(ms: int) -> None:
        loop = QEventLoop()
        QTimer.singleShot(ms, loop.quit)
        loop.exec()

    def until(predicate, seconds: float = 60.0) -> bool:
        end = time.time() + seconds
        while time.time() < end:
            if predicate():
                return True
            settle(25)
        return False

    class Heartbeat(QObject):
        """The longest gap between 10 ms ticks: how long the UI froze."""

        def __init__(self):
            super().__init__()
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.tick)
            self.last = time.perf_counter()
            self.worst = 0.0

        def start(self):
            self.last, self.worst = time.perf_counter(), 0.0
            self.timer.start(10)

        def tick(self):
            now = time.perf_counter()
            self.worst = max(self.worst, now - self.last)
            self.last = now

        def stop(self) -> float:
            self.tick()
            self.timer.stop()
            return round(self.worst * 1000)

    heart = Heartbeat()

    def press(widget, key, text="", modifiers=Qt.KeyboardModifier.NoModifier):
        QApplication.sendEvent(widget, QKeyEvent(QKeyEvent.Type.KeyPress, key, modifiers, text))
        QApplication.sendEvent(widget, QKeyEvent(QKeyEvent.Type.KeyRelease, key, modifiers, text))

    def shot(name: str) -> str:
        path = SHOTS / f"{name}.png"
        w.grab().save(str(path))
        return path.name

    def luminance(rgb) -> np.ndarray:
        c = np.asarray(rgb, dtype=np.float64) / 255.0
        c = np.where(c <= 0.03928, c / 12.92, ((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * c[..., 0] + 0.7152 * c[..., 1] + 0.0722 * c[..., 2]

    def ratio(a, b) -> float:
        la, lb = float(luminance(a)), float(luminance(b))
        hi, lo = max(la, lb), min(la, lb)
        return (hi + 0.05) / (lo + 0.05)

    def visible(widget) -> bool:
        return widget.isVisibleTo(w) and widget.width() > 0 and widget.height() > 0 and widget.window() is w

    def text_of(widget) -> str:
        if isinstance(widget, QLineEdit):
            return widget.text() or widget.placeholderText()
        return widget.text() if hasattr(widget, "text") else ""

    def front_root():
        """What the user actually sees: an open panel covers the screen beneath it."""
        for overlay in (getattr(w, "observatory", None), w.sheet):
            if overlay is not None and overlay.isVisible():
                return overlay
        return w

    def calm(limit: float = 2.0) -> None:
        """Wait until no fade is in progress (fade_in removes its effect when done)."""
        end = time.time() + limit
        while time.time() < end and any(x.graphicsEffect() is not None for x in w.findChildren(QWidget) if x.isVisible()):
            settle(40)

    def measure_contrast(screen: str) -> list[dict]:
        """Text contrast from rendered pixels: the most common colour is the background,
        the strongest 2% of pixels against it are the text."""
        image = w.grab().toImage().convertToFormat(w.grab().toImage().Format.Format_RGB888)
        width, height = image.width(), image.height()
        ratio_px = image.width() / max(1, w.width())
        buffer = np.frombuffer(image.constBits(), dtype=np.uint8, count=image.sizeInBytes()).reshape(height, image.bytesPerLine())
        pixels = buffer[:, : width * 3].reshape(height, width, 3)
        rows = []
        root = front_root()
        for widget in root.findChildren(QWidget):
            if not isinstance(widget, (QLabel, QAbstractButton, QLineEdit)) or not visible(widget):
                continue
            seen_part = widget.visibleRegion().boundingRect()
            if seen_part.isEmpty():
                continue
            text = text_of(widget).strip()
            if not text or (isinstance(widget, QLabel) and widget.pixmap() is not None and not widget.pixmap().isNull()):
                continue
            top_left = widget.mapTo(w, seen_part.topLeft())
            x0, y0 = int(top_left.x() * ratio_px), int(top_left.y() * ratio_px)
            x1, y1 = min(width, x0 + int(seen_part.width() * ratio_px)), min(height, y0 + int(seen_part.height() * ratio_px))
            if x1 - x0 < 4 or y1 - y0 < 4 or x0 < 0 or y0 < 0:
                continue
            crop = pixels[y0:y1, x0:x1].reshape(-1, 3)
            quant = (crop // 8).astype(np.int64)
            keys = quant[:, 0] * 1024 + quant[:, 1] * 32 + quant[:, 2]
            mode = np.bincount(keys).argmax()
            background = crop[keys == mode].mean(axis=0)
            lb = luminance(background)
            lum = luminance(crop)
            contrast = (np.maximum(lum, lb) + 0.05) / (np.minimum(lum, lb) + 0.05)
            fg_contrast = float(np.percentile(contrast, 98))
            if fg_contrast < 1.15:
                continue  # nothing drawn (an empty or covered label)
            font = widget.font()
            px = font.pixelSize() if font.pixelSize() > 0 else font.pointSizeF() * 96 / 72
            large = px >= 24 or (px >= 18.66 and font.weight() >= 600)
            rows.append({
                "screen": screen, "widget": type(widget).__name__, "name": widget.objectName(), "text": text[:70],
                "px": round(px, 1), "large": large, "contrast": round(fg_contrast, 2),
                "pass": fg_contrast >= (3.0 if large else 4.5), "enabled": widget.isEnabled(),
            })
        return rows

    def controls(screen: str) -> list[dict]:
        rows = []
        for widget in front_root().findChildren(QWidget):
            if not isinstance(widget, (QAbstractButton, QLineEdit, QCheckBox, QTabBar)) or not visible(widget):
                continue
            if widget.visibleRegion().isEmpty():
                continue
            name = widget.accessibleName() or text_of(widget) or widget.toolTip()
            rows.append({
                "screen": screen, "widget": type(widget).__name__, "name": (name or "")[:60], "object": widget.objectName(),
                "w": widget.width(), "h": widget.height(), "target_ok": min(widget.width(), widget.height()) >= 24,
                "named": bool((name or "").strip()), "tab": bool(widget.focusPolicy() & Qt.FocusPolicy.TabFocus),
                "enabled": widget.isEnabled(),
            })
        return rows

    def tab_chain(screen: str, steps: int = 40) -> dict:
        """Press Tab from the top; record what receives focus and whether focus shows."""
        w.activateWindow()
        w.setFocus()
        order, invisible_focus, seen = [], [], set()
        for _ in range(steps):
            before = QApplication.focusWidget()
            w.focusNextChild()
            settle(20)
            focus = QApplication.focusWidget()
            if focus is None or focus is before:
                break
            key = id(focus)
            label = (focus.accessibleName() or text_of(focus) or focus.objectName() or type(focus).__name__)[:40]
            if key in seen:
                break
            seen.add(key)
            shown = visible(focus)
            order.append({"widget": type(focus).__name__, "label": label, "visible": shown})
            if not shown:
                invisible_focus.append(label)
            else:
                # Is focus drawn? Compare the widget focused with the same widget after focus leaves.
                focused = focus.grab().toImage()
                w.setFocus()
                settle(10)
                plain = focus.grab().toImage()
                focus.setFocus()
                settle(10)
                order[-1]["focus_drawn"] = focused != plain
        return {"screen": screen, "order": order, "invisible_focus": invisible_focus,
                "undrawn": [o["label"] for o in order if o.get("visible") and not o.get("focus_drawn")]}

    data: dict = {"contrast": [], "controls": [], "tabs": [], "tasks": [], "stress": [], "errors": [], "screens": [], "log": []}

    def rss_mb() -> int:
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD), ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        kernel = ctypes.WinDLL("kernel32")
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        kernel.K32GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        return round(counters.PagefileUsage / 1024 / 1024)

    def log(text: str) -> None:
        text = f"[{rss_mb()} MB] {text}"
        data["log"].append(text)
        print(text, flush=True)

    def record_task(name, actions, seconds, success, notes="", freeze=None):
        data["tasks"].append({"task": name, "actions": actions, "seconds": round(seconds, 2), "success": success,
                              "notes": notes, "worst_freeze_ms": freeze})
        log(f"task {name}: {'OK' if success else 'FAIL'} {actions} actions {seconds:.2f}s freeze {freeze}ms {notes}")

    # -- samples ------------------------------------------------------------------------------
    notes = samples / "meeting_notes.txt"
    notes.write_text("Agenda for Thursday.\n" * 40, encoding="utf-8")
    risky = samples / "invoice.pdf.exe"
    risky.write_bytes(SUSPICIOUS)
    import repair_engine  # noqa: F401
    sys.path.insert(0, str(ROOT / "tests"))
    from repair_fixtures import build_png

    photo = samples / "beach.png"
    photo.write_bytes(build_png()[0] + b"MZ" + bytes(range(256)) * 40)
    empty = samples / "empty.bin"
    empty.write_bytes(b"")
    big = samples / "big_archive.bin"
    big.write_bytes(os.urandom(48 * 1024 * 1024))
    long_name = samples / ("quarterly_financial_statement_" * 6 + ".pdf")
    long_name.write_bytes(b"%PDF-1.4\n%%EOF\n")
    rlo = samples / ("photo_\u202egnp.exe")
    rlo.write_bytes(b"not really a program")

    # -- the window -------------------------------------------------------------------------
    w = qa.CyberScanApp()
    w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    w.resize(1440, 900)
    w.show()
    settle(1500)

    def scan(target: str, seconds: float = 90) -> tuple[bool, float, int]:
        w.set_mode("scan")
        w.new_scan()
        settle(400)
        assert w.view == "lens", w.view
        heart.start()
        started = time.perf_counter()
        w.lens.set_target(target)
        w.lens.scan_button.click()
        ok = until(lambda: w.view == "result" or w.journey.phase in {"failed", "cancelled"} or bool(w.lens.error.isVisible()), seconds)
        elapsed = time.perf_counter() - started
        return ok and w.view == "result", elapsed, heart.stop()

    def capture(screen: str, language: str) -> None:
        name = f"{screen}_{language}"
        calm()
        log(f"capture {name}")
        data["screens"].append(shot(name))
        data["contrast"] += measure_contrast(name)
        data["controls"] += controls(name)

    # -- screens, both languages -------------------------------------------------------------
    for language in ("en", "ar"):
        if w.language != language:
            w.toggle_language()
            settle(600)
        w.new_scan() if hasattr(w, "new_scan") else None
        settle(900)
        capture("home", language)
        data["tabs"].append(tab_chain(f"home_{language}"))
        w.lens.set_target(str(risky))
        w.lens.scan_button.click()
        settle(700)
        capture("journey", language)
        until(lambda: w.view == "result", 60)
        settle(2500)
        capture("result_risky", language)
        data["tabs"].append(tab_chain(f"result_{language}"))
        w.result_panel.why_button.click()
        settle(700)
        capture("result_details", language)
        w.open_settings()
        settle(700)
        capture("settings", language)
        data["tabs"].append(tab_chain(f"settings_{language}"))
        w.close_settings()
        settle(400)
        ok, _, _ = scan(str(photo))
        until(lambda: w.result_panel.repair_button.isVisible(), 20)
        settle(1500)
        capture("result_repairable", language)
        w.repair_current()
        if w._transition is not None:
            w._transition.finish()
        settle(2500)
        capture("repair_review", language)
        data["tabs"].append(tab_chain(f"repair_{language}"))
        w.set_mode("scan")
        settle(500)

    if w.language != "en":
        w.toggle_language()
        settle(500)

    # -- tasks ---------------------------------------------------------------------------------
    # T1: scan a file with the keyboard only (focus the field, type, Enter).
    w.new_scan() if hasattr(w, "new_scan") else None
    settle(600)
    started = time.perf_counter()
    heart.start()
    press(w, Qt.Key.Key_L, "", Qt.KeyboardModifier.ControlModifier)
    w.lens.field.setText(str(notes))
    press(w.lens.field, Qt.Key.Key_Return, "\r")
    done = until(lambda: w.view == "result", 60)
    record_task("Check a file (keyboard only)", 3, time.perf_counter() - started, done,
                "Ctrl+L, paste, Enter", heart.stop())
    verdict = w.result_panel.headline.text() if hasattr(w.result_panel, "headline") else ""
    data["verdict_notes"] = verdict

    # T2: understand why a risky file was flagged.
    ok, secs, freeze = scan(str(risky))
    started = time.perf_counter()
    w.result_panel.why_button.click()
    settle(400)
    reasons = [lbl.text() for lbl in w.result_panel.findChildren(QLabel) if visible(lbl) and lbl.text().lstrip().startswith("•")]
    record_task("Understand why a file was flagged", 1, time.perf_counter() - started + secs, ok and bool(reasons),
                f"{len(reasons)} reasons visible: " + " | ".join(r[:40] for r in reasons[:3]), freeze)

    # T3: quarantine the risky file.
    started = time.perf_counter()
    q_visible = w.result_panel.quarantine_button.isVisible()
    w.result_panel.quarantine_button.click()
    settle(800)
    record_task("Move a risky file to quarantine", 2, time.perf_counter() - started, q_visible and not risky.exists(),
                "button + confirmation" + ("" if q_visible else " (button not shown)"))

    # T4: repair a file straight from its result.
    ok, secs, freeze = scan(str(photo))
    until(lambda: w.result_panel.repair_button.isVisible(), 20)
    started = time.perf_counter()
    heart.start()
    w.result_panel.repair_button.click()
    until(lambda: w._transition is None, 6)
    w.repair_view.repair_button.click()
    until(lambda: w.repair_view.output is not None or w.repair_view.outcome.isVisible(), 30)
    w.repair_view.wait()
    out = w.repair_view.output
    record_task("Repair a file from its result", 2, time.perf_counter() - started, out is not None and out.exists(),
                f"copy: {out.name if out else '-'}; transition {2.15}s included", heart.stop())
    w.set_mode("scan")
    settle(400)

    # T5: check a link.
    ok, secs, freeze = scan("https://paypa1-secure-login.example.com/verify")
    record_task("Check a link", 2, secs, ok, w.result_panel.headline.text() if ok else w.lens.error.text(), freeze)

    # T6: switch language and back.
    started = time.perf_counter()
    heart.start()
    w.toggle_language()
    settle(50)
    w.toggle_language()
    settle(50)
    record_task("Switch language and back", 2, time.perf_counter() - started, w.language == "en", "", heart.stop())

    # T7: find an earlier scan by name.
    started = time.perf_counter()
    w.rail.search.setText("meeting")
    settle(300)
    cards = [c for c in w.rail.cards if visible(c)]
    found = bool(cards)
    if found:
        cards[0].click()
        settle(800)
    record_task("Find and reopen an earlier scan", 2, time.perf_counter() - started, found and w.view == "result",
                f"{len(cards)} matching")
    w.rail.search.setText("")

    # T8: export a report.
    started = time.perf_counter()
    exported = False
    try:
        target = tmp / "report.txt"
        qa.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (str(target), "Text report (*.txt)"))
        w.export_current_report()
        settle(500)
        exported = target.exists() and target.stat().st_size > 0
    except Exception as exc:  # noqa: BLE001
        log(f"export raised {exc!r}")
    record_task("Export a report", 2, time.perf_counter() - started, exported, "save dialog stubbed")

    # T9: open the file's galaxy.
    started = time.perf_counter()
    heart.start()
    w.open_galaxy()
    formed = until(lambda: w.observatory is not None and w.observatory.ready, 60)
    settle(2600)
    calm()
    data["screens"].append(shot("observatory_en"))
    data["contrast"] += measure_contrast("observatory_en")
    data["controls"] += controls("observatory_en")
    record_task("See the file's galaxy", 1, time.perf_counter() - started, formed, "", heart.stop())
    if w.observatory is not None:
        w.observatory.close_observatory()
    settle(300)

    # -- stress ---------------------------------------------------------------------------------
    def stress(name, action, check, note=""):
        boxes.clear()
        heart.start()
        started = time.perf_counter()
        error = ""
        try:
            action()
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        elapsed = time.perf_counter() - started
        freeze = heart.stop()
        try:
            outcome = check()
        except Exception as exc:  # noqa: BLE001
            outcome = f"check failed: {exc}"
        message = w.lens.error.text() if w.lens.error.isVisible() else ""
        data["stress"].append({"case": name, "seconds": round(elapsed, 2), "worst_freeze_ms": freeze, "outcome": outcome,
                               "exception": error, "message": message, "dialogs": [b[1] + ": " + b[2][:120] for b in boxes], "note": note})
        log(f"stress {name}: {outcome} freeze {freeze}ms {message[:80]} {error}")

    def home():
        w.set_mode("scan")
        w.new_scan()
        settle(300)

    def submit(text):
        home()
        w.lens.set_target(text)
        w.lens.scan_button.click()
        settle(600)

    stress("Empty input + Scan", lambda: submit(""), lambda: "error shown" if w.lens.error.isVisible() else f"view={w.view}")
    stress("Path that doesn't exist", lambda: submit(r"C:\nope\missing_file.docx"),
           lambda: "error shown" if w.lens.error.isVisible() else f"view={w.view}")
    stress("A folder instead of a file", lambda: submit(str(samples)), lambda: f"view={w.view} phase={w.journey.phase}")
    stress("Empty (0-byte) file", lambda: (submit(str(empty)), until(lambda: w.view == "result" or w.journey.phase == "failed", 60)),
           lambda: f"view={w.view} headline={getattr(w.result_panel, 'headline').text()[:50]}")
    stress("48 MB random file", lambda: (submit(str(big)), until(lambda: w.view == "result" or w.journey.phase == "failed", 240)),
           lambda: f"view={w.view} headline={w.result_panel.headline.text()[:50]}")
    stress("180-character file name", lambda: (submit(str(long_name)), until(lambda: w.view == "result", 60)),
           lambda: f"view={w.view}; horizontal scroll={w.scroll.horizontalScrollBar().maximum() > 0}")
    stress("Name with a hidden right-to-left character", lambda: (home(), w.lens.set_target(str(rlo)), settle(400)),
           lambda: "warning before scan: " + (w.lens.preview_warning.text()[:70] if w.lens.preview_warning.isVisible() else "none"))
    stress("Scan clicked 10 times quickly", lambda: (home(), w.lens.set_target(str(notes)),
                                                       [w.lens.scan_button.click() for _ in range(10)],
                                                       until(lambda: w.view == "result", 60)),
           lambda: f"view={w.view}; history items={len(w.rail.items)}")
    stress("Language switched 20 times quickly", lambda: [w.toggle_language() for _ in range(20)],
           lambda: f"language={w.language}; stray windows=" + str(sum(1 for t in QApplication.topLevelWidgets() if t.isVisible() and t is not w)))
    stress("Mode switched 20 times quickly", lambda: [w.set_mode("repair" if i % 2 == 0 else "scan") for i in range(20)],
           lambda: f"mode={w.app_mode} view={w.view}")

    def cancel_midway():
        home()
        w.lens.set_target(str(big))
        w.lens.scan_button.click()
        settle(250)
        w.cancel_scan()
        settle(300)

    stress("Cancel a scan midway", cancel_midway, lambda: f"phase={w.journey.phase}; other button={w.other_button.isVisible()}")
    until(lambda: not w._abandoned_workers or not any(t.isRunning() for t in w._abandoned_workers), 120)

    def many_history():
        items = list(w.rail.items)
        template = items[0] if items else None
        if template is None:
            return
        from dataclasses import replace

        fake = [replace(template, record_id=f"r{i}", name=f"report_{i}.pdf", search_text=f"report_{i}.pdf") for i in range(400)]
        w.rail.set_items(fake, [(400, "ok")])
        settle(200)
        w.rail.search.setText("report_39")
        settle(200)

    stress("400 scans in the history, then search", many_history, lambda: f"cards shown={len(w.rail.cards)}")
    w.rail.search.setText("")

    def sizes():
        for width, height in ((800, 560), (1024, 700), (2560, 1440)):
            w.resize(width, height)
            settle(500)
            data["screens"].append(shot(f"size_{width}x{height}"))
            data["contrast"] += []
        w.resize(1440, 900)
        settle(300)

    stress("Window resized 800x560 / 1024x700 / 2560x1440", sizes,
           lambda: f"horizontal scroll at end={w.scroll.horizontalScrollBar().maximum() > 0}")

    def large_text():
        w.open_settings()
        settle(300)
        sheet = w.sheet
        checks = getattr(sheet, "checks", {})
        key = "large_text" if "large_text" in checks else None
        if key:
            checks[key].setChecked(True)
            sheet.save_button.click()
        else:
            w.close_settings()
        settle(600)
        home()
        settle(400)
        calm()
        data["screens"].append(shot("large_text_home"))
        data["contrast"] += measure_contrast("large_text_home")
        ok, _, _ = scan(str(risky))
        settle(1500)
        data["screens"].append(shot("large_text_result"))
        return key

    stress("Large text on", large_text, lambda: f"horizontal scroll={w.scroll.horizontalScrollBar().maximum() > 0}")

    # -- idle cost ----------------------------------------------------------------------------
    home()
    settle(2000)
    cpu_start, wall_start = time.process_time(), time.perf_counter()
    settle(4000)
    data["idle_cpu_percent"] = round(100 * (time.process_time() - cpu_start) / (time.perf_counter() - wall_start), 1)
    data["dialogs_seen"] = [b[0] + " · " + b[1] for b in boxes]
    (OUT / "data.json").write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    log("done")
    w.close()


if __name__ == "__main__":
    main()
