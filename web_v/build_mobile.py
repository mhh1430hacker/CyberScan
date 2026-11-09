"""Build the engine bundle for CyberScan Mobile (on-device scanning).

    .venv\\Scripts\\python.exe web_v\\build_mobile.py            # from the last commit
    .venv\\Scripts\\python.exe web_v\\build_mobile.py --worktree # from the files on disk

Writes web_v/static/m/engine.zip: the engine, the shared presentation code,
the web server's result format, pefile (pure Python, MIT licence), a pure-Python
YARA reader (web_v/yara_lite.py, packed as `yara`) and two
tiny stand-ins for scikit-learn (only needed for training, never on a phone).
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "web_v" / "static" / "m" / "engine.zip"

FILES = [
    "config.py",
    "reports/__init__.py", "reports/exporter.py", "reports/report_generator.py",
    "ui/__init__.py", "ui/ai_summary.py", "ui/copy.py", "ui/file_kind.py", "ui/finding_text.py",
    "ui/link_hints.py", "ui/names.py", "ui/persistence.py", "ui/plain_language.py", "ui/result_view.py",
    "ui/scan_service.py", "ui/secrets.py", "ui/structure.py", "ui/vault.py",
    "ml/__init__.py", "ml/model_runtime.py", "ml/structural_classifier.py", "ml/forest_format.py",
    "ml/forest_export.py", "ml/conformal.py", "ml/counterfactual.py", "ml/feature_schema.py", "ml/pe_layout.py",
    "monitoring/__init__.py", "monitoring/downloads_monitor.py",
    "web_v/server.py", "web_v/services.py", "web_v/mobile_bridge.py",
    "web_v/assistant.py", "web_v/assistant_knowledge.md",
]
TREES = ["core", "repair_engine/executor", "repair_engine/parsers", "repair_engine/blind", "rules"]
TREE_FILES = ["repair_engine/__init__.py", "repair_engine/analyze.py", "repair_engine/regions.py",
              "repair_engine/validator.py", "repair_engine/pe_layout.py"]

SKLEARN_STUB = '''class {name}:
    """Stand-in: training isn't available on a phone, and scanning never needs it."""
    def __init__(self, *args, **kwargs):
        raise RuntimeError("training is not available on this device")
'''


def from_git(ref: str, path: str) -> bytes | None:
    done = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=ROOT, capture_output=True)
    return done.stdout if done.returncode == 0 else None


def list_tree(ref: str | None, tree: str) -> list[str]:
    if ref:
        done = subprocess.run(["git", "ls-tree", "-r", "--name-only", ref, tree], cwd=ROOT, capture_output=True, text=True)
        return [p for p in done.stdout.splitlines() if p.endswith((".py", ".yar", ".yara"))]
    return [p.relative_to(ROOT).as_posix() for p in (ROOT / tree).rglob("*") if p.suffix in {".py", ".yar", ".yara"}]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", action="store_true", help="use the files on disk instead of the last commit")
    parser.add_argument("--ref", default="HEAD")
    args = parser.parse_args()
    ref = None if args.worktree else args.ref

    paths = list(FILES) + list(TREE_FILES)
    for tree in TREES:
        paths += list_tree(ref, tree)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in sorted(set(paths)):
            # the engine comes from the commit; the web edition's own files from disk
            data = from_git(ref, rel) if ref and not rel.startswith("web_v/") else (ROOT / rel).read_bytes()
            if data is None:
                sys.exit(f"missing in {ref}: {rel}")
            z.writestr(rel, data)
        # pefile is pure Python: take it from this project's environment
        import pefile  # noqa: PLC0415
        import ordlookup  # noqa: PLC0415
        z.writestr("pefile.py", Path(pefile.__file__).read_bytes())
        for f in Path(ordlookup.__file__).parent.glob("*.py"):
            z.writestr(f"ordlookup/{f.name}", f.read_bytes())
        dist = Path(pefile.__file__).parent / f"pefile-{pefile.__version__}.dist-info"
        lic = next((p for p in dist.glob("**/LICENSE*")), None) if dist.exists() else None
        if lic:
            z.writestr("pefile-LICENSE.txt", lic.read_bytes())
        # yara-python is C; the phone gets a pure-Python reader for the same rules
        z.writestr("yara.py", (ROOT / "web_v" / "yara_lite.py").read_bytes())
        z.writestr("sklearn/__init__.py", "")
        z.writestr("sklearn/ensemble.py", SKLEARN_STUB.format(name="RandomForestClassifier"))
        z.writestr("sklearn/preprocessing.py", SKLEARN_STUB.format(name="LabelEncoder"))
        z.writestr("BUILD.json", json.dumps({"source": ref or "worktree", "files": len(paths) + 5}))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(buf.getvalue())
    digest = hashlib.sha256(buf.getvalue()).hexdigest()[:12]
    (OUT.parent / "engine.version").write_text(digest)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(buf.getvalue()) / 1024:.0f} KB, {digest})")


if __name__ == "__main__":
    main()
