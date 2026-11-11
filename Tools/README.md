# CyberScan Tools

`Tools/` is the platform-neutral catalog and execution boundary. Applications
use `Tools.registry.ToolRegistry`; individual tool modules do not
depend on Web, Desktop, Mobile, or AI user interfaces.

## Tool contract

Place a tool module directly inside an approved category directory, for example
`Tools/file_analysis/my_tool.py`. It must define the following top-level
literal values (discovery parses these with Python's AST and does not import the
module):

```python
TOOL_ID = "vendor.unique-tool"
NAME = "Readable name"
DESCRIPTION = "What the tool does and what it does not do."
CATEGORY = "file-analysis"
VERSION = "1.0.0"
INPUT_SCHEMA = {"type": "object", "required": [], "properties": {}}
OUTPUT_SCHEMA = {"type": "object", "properties": {}}
PRIVACY = {"data_handling": "How input is handled.", "external_services": "Whether data leaves the device."}
PROCESSING = {"network": False, "filesystem": False, "executes_files": False}

def run(input_data, options=None):
    raise NotImplementedError
```

This is a contract sketch, not a runnable tool; a real module must implement
its analysis before it can be approved.

`run` receives validated data and returns a JSON-compatible object validated
against `OUTPUT_SCHEMA`. The top-level output schema must be an object because
the current execution API accepts only object results; nested properties and
input schemas support object, array, string, integer, number, boolean and null,
including required object properties, enumerations, and bounded strings/arrays.
The tool contract forbids executing uploaded files, but this is not enforced by
the registry. Tools that need external services or file writes should declare
those operations and apply their own limits; the declarations themselves do not
enforce those limits.

## Discovery, trust and execution

`Tools/registry.json` is the central allowlist for discoverable category
directories and explicit source-hash approvals. Discovery reads only direct
`.py` files in those directories, parses literal metadata and the `run`
signature, detects duplicate IDs, and reports each module as `invalid`,
`disabled` or `available`. Discovery never imports or evaluates a tool module.

New modules remain disabled until an authorized maintainer reviews them and
approves the discovered SHA-256 using `ToolRegistry.approve(tool_id, hash)`.
The registry binds approval to the exact source bytes; any edit disables that
approval. Approval grants permission to run Python in-process, so only reviewed
code should be approved. This is a source-integrity and trust gate, not a
sandbox: approved code runs with the application's process permissions.

`PRIVACY` and `PROCESSING` are descriptive declarations. Discovery validates
their shape, but the registry does not enforce network, filesystem, file
execution, time, or memory restrictions. The `run` contract forbids executing
uploaded files, but the registry cannot technically prevent a tool from doing
so. Review the tool implementation and its imported dependencies before
approval; do not approve untrusted third-party code. The registry reports
import failures and tool exceptions as structured execution results instead of
terminating discovery or the caller, but this does not contain side effects or
stop a hung tool.

```python
from Tools.registry import ToolRegistry

registry = ToolRegistry()
for tool in registry.discover():
    print(tool.as_dict())

result = registry.execute("cyberscan.file.inspection", {
    "file_name": "sample.pdf",
    "data_base64": "...",
})
```

The included `file_analysis/file_inspection.py` is an adapter to the existing
bounded Sentinel `ScanService`; it does not reimplement detection and remains
disabled until explicitly approved.

The first 50 offline security-tool modules, their input formats, known limits,
and integration requirements are listed in
[SECURITY_TOOLS.md](./SECURITY_TOOLS.md). Their five category directories are
not yet part of the default `registry.json` allowlist, and none of their source
hashes is trusted by default. Per-tool timeout values are descriptive only:
the current in-process execution API does not enforce them.

## Application access

- **Web and Desktop** can import `ToolRegistry` and use the same discovery,
  schema-validation and approved execution API. Existing interfaces are not
  replaced by this structural migration.
- **Mobile** bundles the same `Tools/` sources into its on-device engine and
  exposes `tools-list` and `tool-run` messages through its existing worker
  bridge. Discovery never imports tool modules. A tool stays disabled there
  unless its exact source hash has been trusted in `registry.json`.
  The first 50 modules also pin and check `tool_runtime.py` before importing
  the helper, so the wrapper's approved hash binds that shared implementation.
- **AI** defines future protocols for discovery, permission checks and
  execution in `AI/contracts.py`; no agent or automatic permission grant is
  implemented.

## Detection engine ownership

The frozen Sentinel engine's sole canonical source is `Tools/detection/`.
`Web/detection/` and `Desktop/detection/` are import-path compatibility shims;
they contain no engine implementation. The engine source is compared against
the recorded SHA-256 baseline during migration and is not modified here.
