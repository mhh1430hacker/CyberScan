from core.magic_bytes import detect_magic_issue


def test_magic_mismatch_detected_for_mz_file_with_txt_extension():
    result = detect_magic_issue(b"MZ", ".txt")
    assert result["mismatch"] is True
    assert result["severity"] == "high"
