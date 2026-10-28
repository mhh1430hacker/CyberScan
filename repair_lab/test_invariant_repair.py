import json
from pathlib import Path

from invariant_repair import repair_component


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "invariant_repair"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_threat_is_suppressed_and_legitimate_behaviors_are_preserved():
    original = _load("threat.json")
    result = repair_component(original, _load("contract.json"))

    assert result.status == "repaired"
    assert result.verification_passed is True
    assert result.edit_count == 1
    assert len(original["actions"]) == 7
    assert len(result.component["actions"]) == 7
    assert result.component["actions"][4]["value"] is True
    assert original["actions"][4]["value"] is False


def test_clean_component_receives_no_intervention():
    component = _load("clean.json")

    result = repair_component(component, _load("contract.json"))

    assert result.status == "unchanged"
    assert result.edit_count == 0
    assert result.component == component


def test_legitimate_change_that_looks_like_a_mutation_is_preserved():
    component = _load("legitimate_change.json")

    result = repair_component(component, _load("contract.json"))

    assert result.status == "unchanged"
    assert result.component["actions"][0]["value"] == "light"


def test_mixed_threat_and_legitimate_change_are_separated():
    component = _load("mixed.json")

    result = repair_component(component, _load("contract.json"))

    assert result.status == "repaired"
    assert result.component["actions"][0]["value"] == "light"
    assert result.component["actions"][4]["value"] is True
    assert result.component["actions"][-1]["value"] == "high_contrast"
    assert result.verification_passed is True


def test_held_out_verification_failure_is_not_reported_as_repair():
    result = repair_component(_load("verification_failure.json"), _load("contract.json"))

    assert result.status == "verification_failed"
    assert result.verification_passed is False
    assert result.component == _load("verification_failure.json")


def test_ambiguous_repair_is_refused():
    result = repair_component(_load("ambiguous.json"), _load("ambiguous_contract.json"))

    assert result.status == "ambiguous"
    assert result.minimal_solution_count >= 2
    assert result.behavior_class_count == 2
    assert result.verification_passed is False


def test_search_bound_failure_does_not_claim_repair():
    result = repair_component(_load("bounded_failure.json"), _load("contract.json"))

    assert result.status == "refused"
    assert result.verification_passed is False
    assert result.component == _load("bounded_failure.json")


def test_repair_is_reproducible_for_identical_inputs():
    component = _load("mixed.json")
    contract = _load("contract.json")

    first = repair_component(component, contract)
    second = repair_component(component, contract)

    assert first == second
