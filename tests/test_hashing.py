from core.hashing import compute_sha256, is_valid_sha256


def test_compute_sha256_known_value():
    assert compute_sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_is_valid_sha256_accepts_valid_hash():
    assert is_valid_sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") is True
    assert is_valid_sha256("not-a-valid-hash") is False
