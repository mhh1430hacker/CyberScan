# CyberScan Local AI Architecture

## Model and AWS constraints

The optional model is `Qwen3-4B Q4_K_M`, served locally through
`llama-cpp-python` (llama.cpp). Its catalog pins the Hugging Face repository
revision, artifact size (2,497,280,640 bytes), SHA-256, and Apache-2.0
license. The model file is about 2.33 GiB, leaving room under the requested
5 GiB model-storage budget for metadata and partial-install headroom. It is
not included in this repository and is never downloaded automatically.

The model's publisher claims support for 100+ languages and dialects. This is
not an independent quality guarantee. `langdetect` can identify languages
from its installed profiles, but language detection does not certify model
generation quality. The 50+ language fixture is only a detection evaluation;
unsupported detector profiles are excluded. English and Arabic generation,
AWS performance, RAM fit, and GPU support have not been verified.

The AWS instance type, RAM, GPU, and storage layout are not specified.
Therefore this architecture does not claim that the model will fit or perform
adequately on a particular instance. Inference defaults to CPU; GPU offload
is opt-in and requires a compatible `llama-cpp-python` build. The model
manager reports fallback when requested GPU support is unavailable.

## Model management

- `model_catalog.json` is the allowlist for model IDs and pinned artifacts.
- `LocalModelManager` downloads only the catalog-selected artifact and only
  after explicit confirmation. It checks size and SHA-256 before atomically
  placing the model. Existing or partial files are not silently overwritten.
- Install the optional runtime with `pip install -r AI/requirements-inference.txt`.
  CPU/GPU build compatibility must be selected for the target AWS image.
- Check state with `python -m AI.cli status`; install with
  `python -m AI.cli install --confirm`. The download is approximately 2.5 GB.
- Set `CYBERSCAN_AI_MODEL_DIR` to choose a model-storage location. Otherwise,
  the manager uses the platform's user data directory.
- Context, thread count, and generation lengths are bounded. No cloud
  inference endpoint or arbitrary model host is used.

## Agent and tool boundaries

- `LocalAIAgent.chat()` only generates text; it cannot call tools.
- `ToolPlanner` uses the current `Tools/registry.py` catalog. It proposes
  approved tools but does not execute them. Caller-provided inputs are
  schema-validated and are never invented by the model.
- `LocalAIAgent.execute()` requires explicit confirmation of exactly the
  displayed tool IDs, validates the caller principal, consumes plans once,
  checks cancellation, and rechecks Registry availability and source hashes.
- Tool discovery is read-only. This AI package does not modify
  `Tools/registry.json` or enable categories.
- The Registry executes approved Python in the host process. Hash approval is
  source-integrity verification and execution authorization, not sandboxing.
  `PROCESSING` flags are declarations, not enforced restrictions. Only
  reviewed, locally trusted tools should be approved.
- Tool results and provenance are preserved individually; risk values are not
  averaged or represented as a new detection verdict.
- Optional conversation history uses principal-scoped local SQLite storage.
  The caller chooses what text/results are stored; there is no telemetry or
  synchronization.

## Integration boundary

The platform-neutral API is exposed through `AI.agent.LocalAIAgent`. No
website UI, network-facing AI service, Desktop UI, Mobile UI, or change to the
frozen detection engine is included. Web, Desktop, Mobile, and future AI
clients must continue to use the shared Tool Registry rather than duplicate
tool implementations.

## Validation status and non-goals

Unit tests cover dynamic Registry discovery, schema validation, planning,
confirmation, source-hash changes, cancellation, conversation separation,
language detection, and mocked model installation/loading. They do not prove
real-model inference or AWS deployment compatibility. Do not download the
multi-gigabyte model merely to run unit tests.

No model is installed or bundled; no UI or AWS deployment is configured.
Model-generated language quality, resource consumption, GPU behavior,
production authorization identity, and in-process tool isolation remain
unverified. Do not treat successful model loading as a security boundary or
as evidence that AI output is accurate.
