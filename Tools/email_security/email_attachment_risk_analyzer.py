from pathlib import Path
import hashlib
import sys

_TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(_TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TOOLS_ROOT))
_RUNTIME_SHA256 = "797b6402901e2a5a38633e9477e77c272171fa469eab121ce87bf44b20b409c8"
_RUNTIME_PATH = _TOOLS_ROOT / "tool_runtime.py"
if hashlib.sha256(_RUNTIME_PATH.read_bytes()).hexdigest() != _RUNTIME_SHA256:
    raise ImportError("CyberScan tool runtime hash does not match the reviewed version.")
from tool_runtime import run_tool

TOOL_ID = "cyberscan.email.email_attachment_risk_analyzer"
NAME = "Email Attachment Risk Analyzer"
DESCRIPTION = "Assess attachment filenames and declared content types for executable and misleading extension risks."
CATEGORY = "email-security"
VERSION = "1.0.0"
SOURCE = "Local attachment metadata heuristics."
LICENSE = "UNSPECIFIED: no applicable repository license declaration."
EXECUTION_MODE = "local"
TIMEOUT_SECONDS = 10
INPUT_SCHEMA = {"type": "object", "required": ["attachments"], "properties": {"attachments": {"type": "array", "maxItems": 100, "items": {"type": "object", "required": ["file_name"], "properties": {"file_name": {"type": "string", "maxLength": 255}, "content_type": {"type": "string", "maxLength": 150}}, "additionalProperties": False}}}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "required": ["tool_id", "status", "classification", "risk_score", "findings", "evidence", "metadata"], "properties": {"tool_id": {"type": "string"}, "status": {"type": "string", "enum": ["success", "partial", "error"]}, "classification": {"type": "string", "enum": ["clean", "suspicious", "unknown"]}, "risk_score": {"type": "integer"}, "findings": {"type": "array", "items": {"type": "object"}}, "evidence": {"type": "array"}, "metadata": {"type": "object", "required": ["version", "execution_mode", "execution_time_ms", "source", "license", "timeout_seconds"], "properties": {"version": {"type": "string"}, "execution_mode": {"type": "string"}, "execution_time_ms": {"type": "integer"}, "source": {"type": "string"}, "license": {"type": "string"}, "timeout_seconds": {"type": "integer"}}}}, "additionalProperties": False}
PRIVACY = {"data_handling": "Attachment names and declared media types are analyzed in memory; files are not opened.", "external_services": "None."}
PROCESSING = {"network": False, "filesystem": False, "executes_files": False}


def run(input_data, options=None):
    return run_tool(TOOL_ID, input_data, options, version=VERSION, source=SOURCE, license_info=LICENSE, timeout_seconds=TIMEOUT_SECONDS)
