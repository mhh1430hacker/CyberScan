# CyberScan AI foundation

This package provides an optional, local-only assistant backed by the shared
CyberScan Tool Registry. It uses a separately installed, checksum-pinned
Qwen3-4B Q4_K_M GGUF model through llama.cpp; it does not use or require any
cached Ollama model. The model artifact is about 2.5 GB and stays within the
5 GB model-storage budget. Model weights are not bundled or downloaded unless
an operator explicitly confirms installation.

## Optional setup

Install the inference runtime in the target environment:

```sh
python -m pip install -r AI/requirements-inference.txt
python -m AI.cli status
python -m AI.cli install --confirm
```

Choose a CPU or GPU-compatible `llama-cpp-python` build for the AWS operating
system and hardware. GPU acceleration is opt-in. AWS RAM/GPU compatibility
cannot be confirmed until the instance type is known. Configure model storage
with `CYBERSCAN_AI_MODEL_DIR`; otherwise a platform-specific user data
directory is used.

Language detection is optional and separate from model language quality:

```powershell
python -m pip install -r AI/requirements-language.txt
```

## Integration and safety

`AI.agent.LocalAIAgent` exposes chat, tool discovery, plan preparation,
confirmation-gated execution, and conversation deletion. Chat has no tool
access. Planning is not execution; execution requires confirmation of the
exact displayed tool IDs and rechecks current Registry status and source
hashes. The AI package does not alter the Registry allowlist.

The Registry runs approved tools in-process. Hash approval is not sandboxing,
and tool `PROCESSING` metadata is descriptive rather than enforced. Approve
only reviewed tools. See [ARCHITECTURE.md](./ARCHITECTURE.md) for boundaries,
limitations, and AWS assumptions.

The tests do not download model weights. They exercise the architecture and
mock model runtime/download behavior. Real Qwen inference, AWS performance,
GPU operation, and multilingual generation remain unverified. No website,
Desktop, or Mobile AI UI is included.
