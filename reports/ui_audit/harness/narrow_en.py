"""Clean English 880x600 pass: idle and result, with overflow measurement."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(r"C:\Users\mahdi\Desktop\dist")
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
TMP = Path(tempfile.mkdtemp(prefix="cs_narrow_", dir=Path(__file__).parent))
(TMP / "data").mkdir()
(TMP / "reports").mkdir()
from PySide6.QtCore import QEventLoop, Qt, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication([])
import ui.qt_app as qa  # noqa: E402

qa.DATA_DIR = TMP / "data"
qa.REPORT_DIR = TMP / "reports"
qa.ensure_directories = lambda: None


def settle(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


win = qa.CyberScanApp()
win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
win.resize(880, 600)
win.show()
settle(600)
win._apply_layout_mode()
settle(300)
out = ROOT / "reports" / "ui_audit" / "screens"
scroll = win.pages.currentWidget()
facts = {"idle_hscroll": scroll.horizontalScrollBar().maximum()}
win.grab().save(str(out / "N_en_880x600_idle.png"))
sample = TMP / "invoice.pdf.exe"
sample.write_bytes(b"MZ" + b"\x00" * 200 + b"powershell -nop -w hidden -enc SQBFAFgA\x00cmd.exe /c vssadmin delete shadows /all /quiet\x00VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00")
win.target_entry.setText(str(sample))
win.analyze_button.click()
start = time.perf_counter()
while not win.results_panel.isVisible() and time.perf_counter() - start < 40:
    settle(50)
settle(1500)
facts["result_hscroll"] = scroll.horizontalScrollBar().maximum()
win.grab().save(str(out / "N_en_880x600_result_top.png"))
bar = scroll.verticalScrollBar()
bar.setValue(int(bar.maximum() * 0.45))
settle(300)
win.grab().save(str(out / "N_en_880x600_result_mid.png"))
widest = sorted(((w.width(), type(w).__name__, w.objectName()) for w in scroll.widget().findChildren(type(win.results_panel)) if w.isVisible()), reverse=True)[:3]
facts["viewport_width"] = scroll.viewport().width()
facts["content_width"] = scroll.widget().width()
facts["results_panel_min_width"] = win.results_panel.minimumSizeHint().width()
print(json.dumps(facts))
