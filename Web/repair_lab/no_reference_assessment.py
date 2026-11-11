from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Assessment:
    sha256: str
    valid_json_object: bool
    automatic_repair_authorized: bool
    status: str
    reason: str


def assess_without_reference(candidate_path: str | Path) -> Assessment:
    candidate = Path(candidate_path)
    if not candidate.is_file():
        raise FileNotFoundError(f"Candidate file is missing: {candidate}")

    contents = candidate.read_bytes()
    digest = hashlib.sha256(contents).hexdigest()
    try:
        parsed = json.loads(contents.decode("utf-8"))
        valid_object = isinstance(parsed, dict)
    except (UnicodeDecodeError, json.JSONDecodeError):
        valid_object = False

    if valid_object:
        return Assessment(
            sha256=digest,
            valid_json_object=True,
            automatic_repair_authorized=False,
            status="manual_review_required",
            reason=(
                "Valid JSON syntax does not establish that values are legitimate; "
                "no trusted source is available for comparison or restoration."
            ),
        )

    return Assessment(
        sha256=digest,
        valid_json_object=False,
        automatic_repair_authorized=False,
        status="repair_refused",
        reason=(
            "The file is not a valid UTF-8 JSON object, and its intended contents "
            "cannot be established without a trusted source."
        ),
    )
