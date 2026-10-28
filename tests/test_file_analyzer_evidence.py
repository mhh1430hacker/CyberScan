from core.file_analyzer import analyze_file

EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_structural_finding_cannot_be_reported_as_safe(tmp_path):
    sample = tmp_path / "spoofed.txt"
    sample.write_bytes(b"MZ" + b"\x00" * 64)

    result = analyze_file(str(sample))

    assert any(item.evidence == "Header mismatch" for item in result.evidence)
    assert result.heuristic_score >= 25
    assert result.classification != "SAFE"


def test_eicar_test_marker_is_recorded_as_benign_test_evidence(tmp_path):
    sample = tmp_path / "eicar.txt"
    sample.write_bytes(EICAR_TEST_SIGNATURE)

    result = analyze_file(str(sample))

    assert any(item.category == "test_marker" for item in result.evidence)
    assert result.heuristic_score == 0
    assert result.classification == "NO_INDICATORS_OBSERVED"
