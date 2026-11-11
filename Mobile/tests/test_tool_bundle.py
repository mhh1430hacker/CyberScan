from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]


def test_engine_bundle_contains_shared_tool_runtime() -> None:
    archive_path = ROOT / "Mobile" / "static" / "m" / "engine.zip"
    expected = {
        "Tools/registry.py",
        "Tools/registry.json",
        "Tools/file_analysis/file_inspection.py",
        "Tools/detection/service.py",
        "detection/__init__.py",
        "web_v/mobile_bridge.py",
    }

    with ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        assert expected <= names
        assert archive.read("web_v/mobile_bridge.py") == (ROOT / "Mobile" / "mobile_bridge.py").read_bytes()
        assert b"Tools" in archive.read("detection/__init__.py")


def test_mobile_worker_exposes_shared_tool_messages() -> None:
    worker = (ROOT / "Mobile" / "static" / "m" / "engine-worker.js").read_text(encoding="utf-8")

    assert 'msg.type === "tools-list"' in worker
    assert 'msg.type === "tool-run"' in worker
