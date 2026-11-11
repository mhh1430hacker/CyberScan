"""Render the rail brand, the app icon sizes and the window title in both languages."""
import os, sys, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT)); os.chdir(ROOT)
os.environ["CYBERSCAN_SCAN_IN_PROCESS"] = "0"
from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QPixmap, QColor
from PySide6.QtWidgets import QApplication
app = QApplication([])
import ui.qt_app as qa, ui.ai_summary as ai
from ui.brand import app_pixmap, ICON_SIZES
tmp = Path(tempfile.mkdtemp(prefix="cs_brand_")); (tmp / "data").mkdir()
qa.DATA_DIR = tmp / "data"; qa.REPORT_DIR = tmp / "reports"; qa.ensure_directories = lambda: None; ai.OLLAMA_URL = "http://127.0.0.1:9"
out = ROOT / "reports" / "ux_personas" / "screens_after"
out.mkdir(parents=True, exist_ok=True)
sheet = QPixmap(sum(ICON_SIZES) + 12 * len(ICON_SIZES) + 12, 280)
sheet.fill(QColor("#ffffff"))
p = QPainter(sheet); x = 12
for size in ICON_SIZES:
    p.drawPixmap(x, 12, app_pixmap(size)); x += size + 12
p.end(); sheet.save(str(out / "80_app_icon_sizes.png"))
w = qa.CyberScanApp(); w.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True); w.resize(1440, 900); w.show()
def pump(s):
    e = time.monotonic() + s
    while time.monotonic() < e: app.processEvents(); time.sleep(0.01)
pump(1)
w.grab().save(str(out / "81_brand_en.png")); print("title en:", w.windowTitle())
w.toggle_language(); pump(0.8)
w.grab().save(str(out / "82_brand_ar.png")); print("title ar:", w.windowTitle())
