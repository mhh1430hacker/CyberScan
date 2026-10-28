import mmap

from core.entropy import shannon_entropy
from core.entropy import entropy_topography


def test_entropy_zero_for_uniform_data():
    data = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    assert shannon_entropy(data) == 0.0


def test_entropy_high_for_random_data():
    data = bytes(range(256)) * 2
    assert shannon_entropy(data) > 7.0


def test_topography_marks_a_low_to_high_entropy_boundary():
    data = b"\x00" * 4096 + bytes(range(256)) * 16
    result = entropy_topography(data, window_size=4096, step_size=4096)

    assert result["trajectory"][0] == 0.0
    assert result["peak_entropy"] == 8.0
    assert result["anomalies"][0]["high_entropy_boundary"] is True


def test_entropy_functions_accept_a_read_only_memory_map(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(bytes(range(256)) * 32)

    with sample.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            assert shannon_entropy(mapped) == 8.0
            assert entropy_topography(mapped, window_size=1024, step_size=512)["peak_entropy"] == 8.0
