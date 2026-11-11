import hashlib

from no_reference_assessment import assess_without_reference


def test_valid_but_unverified_json_is_not_repaired(tmp_path):
    candidate = tmp_path / "candidate.json"
    original = b'{"mode":"unexpected","retries":99}\n'
    candidate.write_bytes(original)

    result = assess_without_reference(candidate)

    assert result.valid_json_object is True
    assert result.automatic_repair_authorized is False
    assert result.status == "manual_review_required"
    assert candidate.read_bytes() == original
    assert result.sha256 == hashlib.sha256(original).hexdigest()


def test_malformed_json_is_refused_without_modifying_input(tmp_path):
    candidate = tmp_path / "damaged.json"
    original = b'{"mode": "safe", "retries":'
    candidate.write_bytes(original)

    result = assess_without_reference(candidate)

    assert result.valid_json_object is False
    assert result.automatic_repair_authorized is False
    assert result.status == "repair_refused"
    assert candidate.read_bytes() == original


def test_valid_json_array_is_not_accepted_as_configuration_object(tmp_path):
    candidate = tmp_path / "array.json"
    original = b'["value"]'
    candidate.write_bytes(original)

    result = assess_without_reference(candidate)

    assert result.valid_json_object is False
    assert result.automatic_repair_authorized is False
    assert candidate.read_bytes() == original


def test_missing_candidate_is_reported(tmp_path):
    candidate = tmp_path / "missing.json"

    try:
        assess_without_reference(candidate)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Missing candidate must be reported.")
