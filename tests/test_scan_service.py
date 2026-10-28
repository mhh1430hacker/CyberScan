from config import DEFAULT_SETTINGS
from ui.scan_service import ScanService, looks_like_text


def test_scan_service_returns_live_structural_evidence(tmp_path):
    sample = tmp_path / "ordinary-note.txt"
    sample.write_text("A harmless laboratory note for static inspection.", encoding="utf-8")
    progress = []
    settings = DEFAULT_SETTINGS.copy()
    settings["osint_enabled"] = False

    result, nextgen, vector, prediction, intelligence, raw_data = ScanService().analyze(
        str(sample),
        "File",
        settings,
        lambda index, state, detail: progress.append((index, state, detail)),
    )

    assert result.target == str(sample)
    assert result.feature_summary["sha256"]
    assert len(vector) == 4096
    assert prediction["status"] in {"classified", "untrained"}
    assert nextgen["input_profile"] == "text-content"
    assert intelligence["status"] == "disabled"
    assert raw_data == sample.read_bytes()
    assert [index for index, state, _ in progress if state == "complete"] == [0, 1, 2, 3]


def test_looks_like_text_checks_actual_byte_content():
    assert looks_like_text(b"a readable indicator")
    assert not looks_like_text(b"MZ\x00\x01binary")
