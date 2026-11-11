from core.entropy import shannon_entropy


def test_entropy_zero_for_uniform_data():
    data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert shannon_entropy(data) == 0.0


def test_entropy_high_for_random_data():
    data = bytes(range(256)) * 2
    assert shannon_entropy(data) > 7.0
