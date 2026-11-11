"""Hacker persona probe: an RTLO-spoofed program name. Read-only, temp data."""
import os, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT)); os.chdir(ROOT)
os.environ["CYBERSCAN_REDUCE_MOTION"] = os.environ.get("RM", "1")
os.environ["CYBERSCAN_SCAN_IN_PROCESS"] = "0"  # no worker process: this probe has no __main__ guard
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox
app = QApplication([])
import ui.qt_app as qa, ui.ai_summary as ai
tmp = Path(tempfile.mkdtemp(prefix="cs_rtlo_")); (tmp/"data").mkdir()
qa.DATA_DIR = tmp/"data"; qa.REPORT_DIR = tmp/"reports"; qa.ensure_directories = lambda: None; ai.OLLAMA_URL = "http://127.0.0.1:9"
for n in ("critical","warning","information","question"): setattr(QMessageBox, n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
name = "holiday‮gnp.exe"
p = tmp / name
p.write_bytes(b"Just a harmless text line. " * 50 if os.environ.get("RTLO_TEXT") else b"MZ" + bytes(3000) + os.urandom(5000))
w = qa.CyberScanApp(); w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True); w.resize(1440, 900); w.show()
def pump(s):
    e = time.monotonic() + s
    while time.monotonic() < e: app.processEvents(); time.sleep(0.01)
pump(1)
w.lens.set_target(str(p)); pump(0.5)
out = ROOT / "reports" / "ux_personas" / os.environ.get("SHOTS", "screens")
w.grab().save(str(out / "70_rtlo_input.png"))
w.lens.scan_button.click()
end = time.monotonic() + 120
while time.monotonic() < end and w.view != "result": app.processEvents(); time.sleep(0.01)
pump(1.0)
w.grab().save(str(out / "71_rtlo_result.png"))
w.result_panel.why_button.click(); pump(0.8)
w.scroll.widget().grab().save(str(out / "72_rtlo_details_full.png"))
print("view", w.view, "phase", w.journey.phase, "failure:", getattr(w, "_failure", None), "tech:", w.technical_text.toPlainText()[:400] if hasattr(w.technical_text, "toPlainText") else w.technical_text.text()[:400]); r = (w._current or {}).get("result")
print("classification", getattr(r, "classification", None))
from ui import scan_process; scan_process.HOST.shutdown()
