"""Approved-contract adapter for CyberScan's existing bounded content inspector."""
from __future__ import annotations

import base64
import binascii
import sys
from pathlib import Path

_TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(_TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TOOLS_ROOT))

TOOL_ID = "cyberscan.file.inspection"
NAME = "File content inspection"
DESCRIPTION = "Inspect an uploaded file in memory using CyberScan's existing bounded static analyzer."
CATEGORY = "file-analysis"
VERSION = "1.0.0"
INPUT_SCHEMA = {
    "type": "object",
    "required": ["file_name", "data_base64"],
    "properties": {
        "file_name": {"type": "string", "minLength": 1, "maxLength": 255},
        "data_base64": {"type": "string", "minLength": 4, "maxLength": 70_000_000},
    },
    "additionalProperties": False,
}
OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["status", "result", "error"],
    "properties": {
        "status": {"type": "string", "enum": ["ok", "rejected", "busy", "timeout", "error"]},
        "result": {"type": ["object", "null"]},
        "error": {"type": ["object", "null"]},
    },
    "additionalProperties": False,
}
PRIVACY = {
    "data_handling": "File bytes are decoded in memory and are not written to disk by this adapter.",
    "external_services": "No external service is contacted.",
}
PROCESSING = {
    "network": False,
    "filesystem": False,
    "executes_files": False,
}
MAX_FILE_BYTES = 50 * 1024 * 1024


def run(input_data, options=None):
    """Inspect base64-encoded bytes through the existing bounded ScanService."""
    del options
    encoded = input_data["data_base64"]
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("data_base64 must contain valid base64.") from exc
    if not data:
        raise ValueError("The uploaded file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f"The file exceeds the {MAX_FILE_BYTES}-byte limit.")

    from detection.engine import safe_file_name
    from detection.service import default_service

    envelope = default_service().inspect_upload(data, safe_file_name(input_data["file_name"]))
    return {
        "status": envelope["status"],
        "result": envelope.get("result"),
        "error": envelope.get("error"),
    }
