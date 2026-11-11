from pathlib import Path
import hashlib
import sys

_TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(_TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TOOLS_ROOT))
_RUNTIME_SHA256 = "0d654a81d0e147373c84e722a8d9f0b1eaddd84e418b7a452c416d133424757b"
_RUNTIME_PATH = _TOOLS_ROOT / "tool_runtime.py"
if hashlib.sha256(_RUNTIME_PATH.read_bytes()).hexdigest() != _RUNTIME_SHA256:
    raise ImportError("CyberScan tool runtime hash does not match the reviewed version.")
from tool_runtime import run_tool

TOOL_ID = "cyberscan.website.technology_fingerprinter"
NAME = "Website Technology Fingerprinter"
DESCRIPTION = "Passively identify selected technology signatures in user-supplied markup and response headers."
CATEGORY = "website-security"
VERSION = "1.0.0"
SOURCE = "Local signatures applied to supplied content only."
LICENSE = "UNSPECIFIED: no applicable repository license declaration."
EXECUTION_MODE = "local"
TIMEOUT_SECONDS = 10
INPUT_SCHEMA = {"type": "object", "required": [], "properties": {"html": {"type": "string", "maxLength": 200000}, "headers": {"type": "object"}}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "required": ["tool_id", "status", "classification", "risk_score", "findings", "evidence", "metadata"], "properties": {"tool_id": {"type": "string"}, "status": {"type": "string", "enum": ["success", "partial", "error"]}, "classification": {"type": "string", "enum": ["clean", "suspicious", "unknown"]}, "risk_score": {"type": "integer"}, "findings": {"type": "array", "items": {"type": "object"}}, "evidence": {"type": "array"}, "metadata": {"type": "object", "required": ["version", "execution_mode", "execution_time_ms", "source", "license", "timeout_seconds"], "properties": {"version": {"type": "string"}, "execution_mode": {"type": "string"}, "execution_time_ms": {"type": "integer"}, "source": {"type": "string"}, "license": {"type": "string"}, "timeout_seconds": {"type": "integer"}}}}, "additionalProperties": False}
PRIVACY = {"data_handling": "Supplied markup and headers are analyzed in memory.", "external_services": "No site is crawled or contacted."}
PROCESSING = {"network": False, "filesystem": False, "executes_files": False}


def run(input_data, options=None):
    return run_tool(TOOL_ID, input_data, options, version=VERSION, source=SOURCE, license_info=LICENSE, timeout_seconds=TIMEOUT_SECONDS)
