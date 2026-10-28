from __future__ import annotations

import json
from pathlib import Path

from invariant_repair import repair_component, verify_component


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "invariant_repair"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _case_result(component: dict, contract: dict, command: str) -> tuple[dict, bool]:
    state = dict(contract["initial_state"])
    bad_effect = False
    for action in component["actions"]:
        if action["when"] in (command, "*"):
            state[action["key"]] = action["value"]
            bad_effect |= any(
                effect["key"] == action["key"] and effect["value"] == action["value"]
                for effect in contract["forbidden_effects"]
            )
    return state, bad_effect


def _all_declared_cases_pass(component: dict, contract: dict) -> bool:
    result = repair_component(component, contract)
    return result.status == "unchanged"


def main() -> None:
    contract = _load("contract.json")
    report: dict[str, object] = {"mechanism": {}, "baselines": {}, "variants": {}}

    for fixture, label in (("threat.json", "threat"), ("mixed.json", "mixed")):
        source = _load(fixture)
        repaired = repair_component(source, contract)
        report["mechanism"][label] = {
            "status": repaired.status,
            "edit_count": repaired.edit_count,
            "minimal_training_solutions": repaired.minimal_solution_count,
            "behavior_classes": repaired.behavior_class_count,
            "verification_passed": repaired.verification_passed,
            "forbidden_effect_after_repair": _case_result(
                repaired.component, contract, "startup"
            )[1],
            "all_declared_cases_pass_after_repair": _all_declared_cases_pass(
                repaired.component, contract
            ),
            "declared_cases_checked": len(contract["cases"]) + len(contract["verification_cases"]),
        }
        naive = {**source, "actions": source["actions"][:-1]}
        report["baselines"][f"delete_last_{label}"] = {
            "forbidden_effect_remains": _case_result(naive, contract, "startup")[1],
            "high_contrast_behavior_preserved": _case_result(
                naive, contract, "set_theme_high_contrast"
            )[0]["theme"]
            == "high_contrast",
        }
        report["baselines"][f"no_intervention_{label}"] = {
            "forbidden_effect_occurs": _case_result(source, contract, "startup")[1]
        }

    for fixture, label in (
        ("clean.json", "clean"),
        ("legitimate_change.json", "legitimate_change"),
        ("ambiguous.json", "ambiguous"),
        ("bounded_failure.json", "bounded_failure"),
        ("verification_failure.json", "verification_failure"),
    ):
        result = repair_component(
            _load(fixture),
            _load("ambiguous_contract.json") if label == "ambiguous" else contract,
        )
        report["variants"][label] = {
            "status": result.status,
            "edit_count": result.edit_count,
            "verification_passed": result.verification_passed,
        }

    report["baselines"]["reject_entire_component"] = {
        "threat_suppressed": True,
        "legitimate_behaviors_available": 0,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
