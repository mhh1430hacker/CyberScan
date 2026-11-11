from __future__ import annotations

import json
from pathlib import Path

from core.file_analyzer import analyze_file
from monitoring.downloads_monitor import DownloadMonitor
from reports.exporter import export_report
from reports.report_generator import generate_report


def test_report_prints_real_sha256_not_the_target_path(tmp_path):
    sample = tmp_path / "a.txt"
    sample.write_bytes(b"abc")
    report = generate_report(analyze_file(str(sample)))
    assert "SHA-256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in report
    assert "File integrity verification:" in report


def test_json_export_contains_full_result(tmp_path):
    sample = tmp_path / "a.txt"
    sample.write_bytes(b"powershell -enc AAAA")
    output = tmp_path / "out.json"
    export_report(analyze_file(str(sample)), output, "json")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["sha256"] and payload["mitre_techniques"] and payload["feature_summary"]
    assert payload["integrity_report"]["status"] == "verification_incomplete"


def test_monitor_ignores_existing_and_temporary_files_and_waits_for_stable_size(tmp_path):
    (tmp_path / "old.txt").write_text("already here")
    seen: list[str] = []
    monitor = DownloadMonitor(str(tmp_path), callback=seen.append, poll_interval=0.01)
    monitor._seen = {path.name for path in tmp_path.iterdir()}  # same baseline start() records

    (tmp_path / "movie.mp4.crdownload").write_text("partial")
    (tmp_path / "new.txt").write_text("fresh")
    assert monitor.poll_once() == []  # first sighting: size not yet confirmed stable
    reported = monitor.poll_once()
    assert [Path(path).name for path in reported] == ["new.txt"]
    assert seen == reported
    assert monitor.poll_once() == []  # reported only once


def test_monitor_survives_callback_errors_and_can_restart(tmp_path):
    def broken(_path):
        raise RuntimeError("boom")

    monitor = DownloadMonitor(str(tmp_path), callback=broken, poll_interval=0.01)
    monitor.start()
    monitor.stop()
    assert not monitor.is_running()
    monitor.start()
    assert monitor.is_running()
    monitor.stop()
