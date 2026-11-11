"""Scroll-pass captures of a real result, and cold-start timing (run separately)."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

T0 = time.perf_counter()
ROOT = Path(r"C:\Users\mahdi\Desktop\dist")
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
MODE = sys.argv[1]
TMP = Path(tempfile.mkdtemp(prefix="cs_scroll_", dir=Path(__file__).parent))
(TMP / "data").mkdir()
(TMP / "reports").mkdir()

from PySide6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication([])
T_QT = time.perf_counter()
import ui.qt_app as qa  # noqa: E402
T_IMPORT = time.perf_counter()
qa.DATA_DIR = TMP / "data"
qa.REPORT_DIR = TMP / "reports"
qa.ensure_directories = lambda: None
qa.QMessageBox.critical = staticmethod(lambda *a, **k: None)


def settle(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


win = qa.CyberScanApp()
win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
win.resize(1440, 900)
win.show()
app.processEvents()
T_SHOWN = time.perf_counter()

if MODE == "start":
    print(json.dumps({"python_to_qapp_ms": round((T_QT - T0) * 1000), "import_qt_app_ms": round((T_IMPORT - T_QT) * 1000),
                      "construct_and_show_ms": round((T_SHOWN - T_IMPORT) * 1000), "total_ms": round((T_SHOWN - T0) * 1000)}))
    sys.exit(0)

lang = MODE.split("_")[1]
if lang == "ar":
    win.toggle_language()
sample = TMP / "invoice.pdf.exe"
sample.write_bytes(b"MZ" + b"\x00" * 200 + b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00")
win.target_entry.setText(str(sample))
win.analyze_button.click()
start = time.perf_counter()
while not win.results_panel.isVisible() and time.perf_counter() - start < 40:
    settle(50)
settle(1500)
scroll = win.pages.currentWidget()
bar = scroll.verticalScrollBar()
out = ROOT / "reports" / "ui_audit" / "screens"
positions = []
value = 0
index = 0
while True:
    bar.setValue(value)
    settle(250)
    win.grab().save(str(out / f"S{lang}_{index:02d}_scroll_{bar.value()}.png"))
    positions.append(bar.value())
    if bar.value() >= bar.maximum():
        break
    value += int(bar.pageStep() * 0.85)
    index += 1
win.details_button.click()
settle(400)
win.grab().save(str(out / f"S{lang}_90_technical_opened.png"))
print(json.dumps({"lang": lang, "positions": positions, "max": bar.maximum(), "results_visible": win.results_panel.isVisible()}))
