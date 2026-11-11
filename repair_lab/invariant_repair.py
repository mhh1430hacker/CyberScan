from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RepairResult:
    status: str
    component: dict[str, Any]
    reason: str
    edit_count: int
    minimal_solution_count: int
    behavior_class_count: int
    states_examined: int
    verification_passed: bool
    component_sha256: str


def _json_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(component: dict[str, Any]) -> str:
    return hashlib.sha256(_json_key(component).encode("utf-8")).hexdigest()


def _validate_inputs(
    component: dict[str, Any], contract: dict[str, Any], max_edits: int, max_states: int
) -> None:
    if not isinstance(component, dict) or not isinstance(component.get("actions"), list):
        raise ValueError("Component must be an object containing an actions list.")
    if len(component["actions"]) > 16:
        raise ValueError("Prototype accepts at most 16 actions.")
    for action in component["actions"]:
        if (
            not isinstance(action, dict)
            or action.get("op") != "set"
            or not isinstance(action.get("when"), str)
            or not action["when"]
            or not isinstance(action.get("key"), str)
            or "value" not in action
        ):
            raise ValueError("Each action must be a set operation with when, key, and value.")

    fields = contract.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise ValueError("Contract must define field value domains.")
    if not isinstance(contract.get("initial_state"), dict):
        raise ValueError("Contract must define an initial_state object.")
    for key, value in contract["initial_state"].items():
        if key not in fields or value not in fields[key]:
            raise ValueError(f"Initial value for {key!r} is outside its declared domain.")
    for action in component["actions"]:
        if action["key"] not in fields:
            raise ValueError(f"Action writes undeclared field {action['key']!r}.")

    for name in ("cases", "verification_cases", "forbidden_effects"):
        if not isinstance(contract.get(name), list):
            raise ValueError(f"Contract must define {name} as a list.")
    for case in contract["cases"] + contract["verification_cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("command"), str):
            raise ValueError("Every contract case must name a command.")
        if not isinstance(case.get("expected"), dict):
            raise ValueError("Every contract case must declare expected outputs.")
        for key, expectation in case["expected"].items():
            if key not in fields:
                raise ValueError(f"Expected output uses undeclared field {key!r}.")
            allowed = expectation.get("one_of") if isinstance(expectation, dict) else [expectation]
            if not isinstance(allowed, list) or not allowed or any(value not in fields[key] for value in allowed):
                raise ValueError(f"Expected output for {key!r} is outside its declared domain.")
    for effect in contract["forbidden_effects"]:
        if not isinstance(effect, dict) or effect.get("key") not in fields or "value" not in effect:
            raise ValueError("Forbidden effects must specify a declared key and value.")
    if max_edits < 0 or max_states < 1:
        raise ValueError("Search bounds must be non-negative edits and at least one state.")


def _run_case(
    actions: list[dict[str, Any]], contract: dict[str, Any], case: dict[str, Any]
) -> tuple[dict[str, Any], list[tuple[str, Any]], list[str]]:
    state = dict(contract["initial_state"])
    initial = case.get("initial_state", {})
    if not isinstance(initial, dict):
        return state, [], ["case initial_state must be an object"]
    for key, value in initial.items():
        if key not in contract["fields"] or value not in contract["fields"][key]:
            return state, [], [f"invalid case initial value for {key!r}"]
        state[key] = value

    writes: list[tuple[str, Any]] = []
    failures: list[str] = []
    for action in actions:
        if action["when"] not in (case["command"], "*"):
            continue
        key, value = action["key"], action["value"]
        writes.append((key, value))
        if value not in contract["fields"][key]:
            failures.append(f"write outside declared domain: {key}={value!r}")
        state[key] = value

    for effect in contract["forbidden_effects"]:
        if (effect["key"], effect["value"]) in writes:
            failures.append(f"forbidden effect observed: {effect['key']}={effect['value']!r}")
    for key, expectation in case["expected"].items():
        if isinstance(expectation, dict):
            matches = state.get(key) in expectation["one_of"]
        else:
            matches = state.get(key) == expectation
        if not matches:
            failures.append(f"contract output mismatch: {key}={state.get(key)!r}")
    return state, writes, failures


def _passes(
    actions: list[dict[str, Any]], contract: dict[str, Any], cases: list[dict[str, Any]]
) -> bool:
    return all(not _run_case(actions, contract, case)[2] for case in cases)


def verify_component(
    component: dict[str, Any], contract: dict[str, Any]
) -> tuple[bool, tuple[str, ...]]:
    """Verify against held-out cases, separate from the search's training cases."""
    failures: list[str] = []
    for case in contract["verification_cases"]:
        _, _, case_failures = _run_case(component["actions"], contract, case)
        failures.extend(f"{case['command']}: {failure}" for failure in case_failures)
    return not failures, tuple(failures)


def _behavior_signature(
    actions: list[dict[str, Any]], contract: dict[str, Any]
) -> str:
    states = [
        _run_case(actions, contract, case)[0]
        for case in contract["cases"] + contract["verification_cases"]
    ]
    return _json_key(states)


def _neighbors(
    actions: list[dict[str, Any]], fields: dict[str, list[Any]]
) -> list[list[dict[str, Any]]]:
    results: list[list[dict[str, Any]]] = []
    for index, action in enumerate(actions):
        removed = [dict(item) for item in actions]
        del removed[index]
        results.append(removed)
        for replacement in fields[action["key"]]:
            if replacement == action["value"]:
                continue
            changed = [dict(item) for item in actions]
            changed[index] = {**action, "value": replacement}
            results.append(changed)
    return results


def repair_component(
    component: dict[str, Any],
    contract: dict[str, Any],
    *,
    max_edits: int = 2,
    max_states: int = 5000,
) -> RepairResult:
    _validate_inputs(component, contract, max_edits, max_states)
    original = json.loads(_json_key(component))
    original_hash = _digest(original)
    training_cases = contract["cases"]
    all_cases = training_cases + contract["verification_cases"]
    original_passes = _passes(original["actions"], contract, all_cases)
    if original_passes:
        return RepairResult(
            "unchanged",
            original,
            "All declared behaviors and invariants already pass; no intervention made.",
            0,
            1,
            1,
            1,
            True,
            original_hash,
        )

    queue: deque[tuple[list[dict[str, Any]], int]] = deque([(original["actions"], 0)])
    visited = {_json_key(original["actions"])}
    states_examined = 1

    for edit_count in range(1, max_edits + 1):
        level_candidates: dict[str, list[dict[str, Any]]] = {}
        while queue and queue[0][1] == edit_count - 1:
            actions, _ = queue.popleft()
            for neighbor in _neighbors(actions, contract["fields"]):
                key = _json_key(neighbor)
                if key in visited:
                    continue
                visited.add(key)
                states_examined += 1
                if states_examined > max_states:
                    return RepairResult(
                        "refused",
                        original,
                        "Search state limit reached before a repair could be established.",
                        0,
                        0,
                        0,
                        states_examined,
                        False,
                        original_hash,
                    )
                if _passes(neighbor, contract, training_cases):
                    level_candidates[key] = neighbor
                else:
                    queue.append((neighbor, edit_count))

        if level_candidates:
            behavior_groups: dict[str, list[list[dict[str, Any]]]] = {}
            for candidate_actions in level_candidates.values():
                signature = _behavior_signature(candidate_actions, contract)
                behavior_groups.setdefault(signature, []).append(candidate_actions)
            if len(behavior_groups) != 1:
                return RepairResult(
                    "ambiguous",
                    original,
                    "Multiple equally minimal repairs satisfy training cases but produce different declared behaviors.",
                    edit_count,
                    len(level_candidates),
                    len(behavior_groups),
                    states_examined,
                    False,
                    original_hash,
                )

            equivalent_candidates = next(iter(behavior_groups.values()))
            selected_actions = min(
                equivalent_candidates,
                key=lambda candidate: (-len(candidate), _json_key(candidate)),
            )
            candidate_component = {**original, "actions": selected_actions}
            verified, verification_failures = verify_component(candidate_component, contract)
            if not verified:
                return RepairResult(
                    "verification_failed",
                    original,
                    "The selected repair failed held-out verification: " + "; ".join(verification_failures),
                    edit_count,
                    len(level_candidates),
                    len(behavior_groups),
                    states_examined,
                    False,
                    original_hash,
                )
            return RepairResult(
                "repaired",
                candidate_component,
                "Minimal repair passed declared training constraints and held-out verification.",
                edit_count,
                len(level_candidates),
                len(behavior_groups),
                states_examined,
                True,
                _digest(candidate_component),
            )

    return RepairResult(
        "refused",
        original,
        f"No verified repair found within the {max_edits}-edit search bound.",
        0,
        0,
        0,
        states_examined,
        False,
        original_hash,
    )
