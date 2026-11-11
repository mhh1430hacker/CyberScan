import os, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
os.environ["CYBERSCAN_SCAN_IN_PROCESS"] = "1"
from PySide6.QtWidgets import QApplication


def main():
    app = QApplication([])
    import ui.qt_app as qa
    from ui import scan_process
    d = Path(tempfile.mkdtemp(prefix="cs_rtlo3_"))
    for name in ["plain_holiday.txt", "holiday‮gnp.txt", "holiday‮gnp.exe"]:
        p = d / name
        p.write_bytes(b"Just a harmless text line. " * 50)
        w = qa.ScanWorker(str(p), "File", {"osint_enabled": False})
        got = []
        w.completed.connect(lambda payload: got.append(("ok", payload[0].classification)))
        w.failed.connect(lambda m: got.append(("failed", m[:200])))
        t = time.time()
        w.start()
        while not got and time.time() - t < 60:
            app.processEvents()
            time.sleep(0.01)
        print(repr(name), got or "NO RESULT after 60s", round(time.time() - t, 1), flush=True)
        w.wait(2000)
    scan_process.HOST.shutdown()


if __name__ == "__main__":
    main()
