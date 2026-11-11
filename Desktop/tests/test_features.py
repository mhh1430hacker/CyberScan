from core.feature_extractor import extract_features_from_bytes


def test_extract_features_has_expected_keys():
    features = extract_features_from_bytes(b"MZ\x00\x00" + b"\x00" * 100, file_name="test.txt")
    assert "file_size" in features
    assert "entropy" in features
    assert "double_extension" in features
    assert "magic_mismatch" in features
