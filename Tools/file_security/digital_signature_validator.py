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

TOOL_ID = "cyberscan.file.digital_signature_validator"
NAME = "Digital Signature Validator"
DESCRIPTION = "Verify a detached signature against a supplied public key; does not establish certificate trust."
CATEGORY = "file-security"
VERSION = "1.0.0"
SOURCE = "Local cryptography implementation; detached signatures only."
LICENSE = "UNSPECIFIED: no applicable repository license declaration."
EXECUTION_MODE = "local"
TIMEOUT_SECONDS = 10
INPUT_SCHEMA = {"type": "object", "required": ["file_base64", "signature_base64", "public_key_pem", "algorithm"], "properties": {"file_base64": {"type": "string", "minLength": 4, "maxLength": 70000000}, "signature_base64": {"type": "string", "minLength": 4, "maxLength": 1000000}, "public_key_pem": {"type": "string", "minLength": 32, "maxLength": 100000}, "algorithm": {"type": "string", "enum": ["rsa-pkcs1v15-sha256", "ecdsa-sha256", "ed25519"]}}, "additionalProperties": False}
OUTPUT_SCHEMA = {"type": "object", "required": ["tool_id", "status", "classification", "risk_score", "findings", "evidence", "metadata"], "properties": {"tool_id": {"type": "string"}, "status": {"type": "string", "enum": ["success", "partial", "error"]}, "classification": {"type": "string", "enum": ["clean", "suspicious", "unknown"]}, "risk_score": {"type": "integer"}, "findings": {"type": "array", "items": {"type": "object"}}, "evidence": {"type": "array"}, "metadata": {"type": "object", "required": ["version", "execution_mode", "execution_time_ms", "source", "license", "timeout_seconds"], "properties": {"version": {"type": "string"}, "execution_mode": {"type": "string"}, "execution_time_ms": {"type": "integer"}, "source": {"type": "string"}, "license": {"type": "string"}, "timeout_seconds": {"type": "integer"}}}}, "additionalProperties": False}
PRIVACY = {"data_handling": "File, signature, and public-key bytes are processed in memory.", "external_services": "None; trust-chain validation is not performed."}
PROCESSING = {"network": False, "filesystem": False, "executes_files": False}


def run(input_data, options=None):
    return run_tool(TOOL_ID, input_data, options, version=VERSION, source=SOURCE, license_info=LICENSE, timeout_seconds=TIMEOUT_SECONDS)
