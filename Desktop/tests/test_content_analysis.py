from __future__ import annotations

import lzma

from core.file_analyzer import analyze_file
from core.heuristic_engine import evaluate_heuristics
from core.magic_bytes import detect_magic_issue
from core.mitre_mapper import map_findings_to_mitre
from core.scanner import scan_target


def test_file_content_is_scanned_not_just_its_hash(tmp_path):
    sample = tmp_path / "note.txt"
    sample.write_bytes(b"powershell -enc ZgBpAGcA")
    result = analyze_file(str(sample))
    assert any(item.evidence == "Encoded PowerShell execution" for item in result.evidence)
    assert result.classification == "SUSPICIOUS"


def test_plain_text_with_email_address_is_not_flagged(tmp_path):
    sample = tmp_path / "note.txt"
    sample.write_bytes(b"Contact bob@example.com about the report.")
    result = analyze_file(str(sample))
    assert result.heuristic_score == 0
    assert result.classification == "SAFE"


def test_random_binary_does_not_trigger_prose_rules(tmp_path):
    sample = tmp_path / "blob.dat"
    sample.write_bytes(bytes(range(256)) * 8)
    result = analyze_file(str(sample))
    assert not any(item.evidence == "Unusual capitalization pattern" for item in result.evidence)


def test_scan_result_carries_the_file_sha256(tmp_path):
    sample = tmp_path / "a.txt"
    sample.write_bytes(b"abc")
    result = analyze_file(str(sample))
    assert result.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_disabling_heuristics_and_ml_is_honoured(tmp_path):
    sample = tmp_path / "note.txt"
    sample.write_bytes(b"powershell -enc ZgBpAGcA")
    result = analyze_file(str(sample), {"heuristic_rules": False, "ml_analysis": False})
    assert not any(item.category == "heuristic" for item in result.evidence)
    assert "disabled" in result.model_status


def test_oversized_file_is_rejected(tmp_path):
    sample = tmp_path / "big.bin"
    sample.write_bytes(b"x" * 100)
    try:
        analyze_file(str(sample), {"maximum_file_size": 10})
    except ValueError as exc:
        assert "maximum file size" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_integrity_verifier_failure_does_not_abort_file_analysis(tmp_path, monkeypatch):
    sample = tmp_path / "note.txt"
    sample.write_bytes(b"ordinary text")

    def broken_verifier(*_args, **_kwargs):
        raise lzma.LZMAError("malformed archive stream")

    monkeypatch.setattr("core.file_analyzer.verify_file_integrity", broken_verifier)

    result = analyze_file(
        str(sample),
        {"heuristic_rules": False, "ml_analysis": False},
    )

    assert result.sha256
    assert result.integrity_report is not None
    assert result.integrity_report["status"] == "verification_incomplete"
    assert "LZMAError" in result.integrity_report["checks"][0]["detail"]


def test_heuristic_word_boundaries_avoid_false_positives():
    assert evaluate_heuristics("powershell -exec bypass")["score"] == 0
    assert evaluate_heuristics("Get-Index ")["score"] == 0
    assert evaluate_heuristics("http://user@evil.example/x")["score"] > 0


def test_url_and_text_targets_now_report_evidence():
    result = scan_target("powershell -enc AAAA")
    assert result.evidence and result.evidence[0].explanation
    url_result = scan_target("http://1.2.3.4/payload")
    assert any(item.evidence == "Direct IPv4 URL host" for item in url_result.evidence)


def test_new_container_signatures_are_checked():
    assert detect_magic_issue(b"PK\x03\x04", ".docx")["mismatch"] is False
    assert detect_magic_issue(b"hello", ".docx")["mismatch"] is True
    assert detect_magic_issue(b"\x1f\x8b\x08", ".gz")["mismatch"] is False


def test_mitre_mapping_has_no_reverse_substring_matches():
    assert map_findings_to_mitre(["process"])[0]["id"] == "N/A"
    ids = {item["id"] for item in map_findings_to_mitre(["IsDebuggerPresent", "Double extension"])}
    assert ids == {"T1622", "T1036.007"}
