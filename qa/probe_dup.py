import sys, json
sys.path[:0] = [r"C:\Users\mahdi\Desktop\dist", r"C:\Users\mahdi\Desktop\dist\web_v"]
from core.scanner import scan_target
from ui.scan_service import ScanService
from config import DEFAULT_SETTINGS
s = dict(DEFAULT_SETTINGS)
path = r"C:\Users\mahdi\Desktop\dist\qa\artifacts\fixtures\random_1024.bin"
w = scan_target(path, is_file=True, settings=s)
print("native scan_target  :", w.target, "|", w.classification, "| engine_status keys:", sorted(w.engine_status)[:6])
r = ScanService().analyze(path, "File", s)
sr = r[0]
print("service wrapper     :", sr.target, "|", sr.classification, "|", (sr.nextgen_analysis or {}).get("input_profile"))
print("wrapper target == native target:", sr.target == w.target)
print("wrapper has entropy/PE from native:", bool((sr.nextgen_analysis or {}).get("entropy_topography")))
