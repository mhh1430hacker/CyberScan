# CyberScan NextGen — Independent Scientific Research & Validation Audit

**Date:** 2026-11-09  
**Scope:** Six core technical claims evaluated against source code implementation  
**Method:** Read-only code inspection; every finding cited with `path:line` references  
**Constraint:** Zero file modifications (`No files were changed`)

---

## Executive Summary

| Claim | Verdict | Key Evidence |
|-------|---------|--------------|
| 1. Information-Theoretic vs. Thermodynamic Entropy | **Misleading terminology** — only Shannon entropy implemented | `core/entropy.py:98-99`, `core/nextgen_engine.py:98` |
| 2. Control Flow Graph (CFG) Disassembly | **Partial implementation** — linear-sweep x86 only, bounded, fallback to byte patterns | `core/nextgen_engine.py:161-347`, `core/nextgen_engine.py:302-327` |
| 3. 4096-Dimensional Latent Vector Embeddings | **Accurate** — deterministic 4×1024 channel encoding, not a neural net | `ml/feature_schema.py:1-8`, `core/deep_embedding.py:14-275`, `ml/structural_classifier.py:65-74` |
| 4. Asynchronous OSINT Correlation | **Accurate** — concurrent aiohttp feeds with caching, timeouts, opt-in | `core/global_intelligence.py:20-35`, `core/global_intelligence.py:276-343` |
| 5. Zero-Execution Security Bounds | **Accurate** — explicit bounds on file size, timeout, disassembly, strings, ZIP | `config.py:15-17`, `core/nextgen_engine.py:305`, `README.md:94-101` |
| 6. Performance/Validation Benchmarks | **Honest disclosure** — no validated accuracy claims, synthetic data only, ML weight=0 default | `README.md:183-190`, `core/risk_engine.py:10-26`, `ml/structural_classifier.py:114-116` |

---

## Claim-by-Claim Validation

### 1. Information-Theoretic vs. Thermodynamic Entropy

**Project language:** "entropy estimation", "entropy topography", "high-entropy regions"  
**Implementation:** Pure Shannon (information-theoretic) entropy

**Code Evidence:**

```python
# core/entropy.py:98-99
length = end - offset
entropy = math.log2(length) - weighted_counts / length if length else 0.0

# core/nextgen_engine.py:98
entropy = math.log2(length) - weighted_counts / length if length else 0.0
```

**Formula implemented:**  
`H = log₂(N) - (1/N) × Σ countᵢ × log₂(countᵢ)` — standard Shannon entropy for byte distribution in a sliding window.

**Findings:**
- No Boltzmann/Gibbs thermodynamic entropy anywhere in codebase
- Entropy bounded to `[0.0, 8.0]` bits/byte (`core/entropy.py:104`, `core/nextgen_engine.py:99`)
- Window size default 4096 bytes, step = window/4 (`core/entropy.py:175-179`)
- Gradient-based anomaly detection on entropy trajectory (`core/entropy.py:137-158`)

**Verdict:** The term "entropy" is used correctly in the information-theoretic sense, but documentation never clarifies this is **not** thermodynamic entropy. For a security tool this distinction matters: high Shannon entropy ≈ encryption/compression, not "disorder" in the physics sense.

---

### 2. Control Flow Graph (CFG) Disassembly

**Project language:** "CFG topology", "code-graph topology", "basic blocks", "cyclomatic complexity"

**Code Evidence:**

```python
# core/nextgen_engine.py:161-168
def _capstone_instructions(
    data: bytes, architecture_hint: str | None = None
) -> tuple[list[tuple[int, int, str, str, int | None]], str, list[str]] | None:
    """Linear-sweep decode; returns (instructions, architecture, operand texts).
```

```python
# core/nextgen_engine.py:302-327
@classmethod
def extract_cfg_topology(cls, data: bytes, architecture_hint: str | None = None) -> dict[str, Any]:
    data = data[:cls.MAX_DISASSEMBLY_BYTES]  # 256 KiB hard limit
    ...
    decoded = cls._capstone_instructions(data, architecture_hint)
    if decoded is None:
        patterns = cls._raw_byte_patterns(data)  # fallback
        return {..., "disassembly_available": False, ...}
```

**Implementation details:**
- **Architecture:** x86-32 and x86-64 only (`core/nextgen_engine.py:185-186`)
- **Decoder:** Linear sweep via Capstone — not recursive traversal, no data-flow analysis
- **Bounds:** `MAX_DISASSEMBLY_BYTES = 256 * 1024` (`core/nextgen_engine.py:19` implied by usage at line 305)
- **Graph construction:** Basic blocks from leaders (entry, jump targets, call/ret followers) (`core/nextgen_engine.py:349-380`)
- **Metrics computed:** basic_block_count, cyclomatic_complexity, graph_density, back_edge_count, back_edge_density, adjacency list
- **Fallback:** Raw byte pattern frequency when Capstone unavailable (`core/nextgen_engine.py:144-160`, `core/nextgen_engine.py:311-312`)

**Limitations acknowledged in README:**  
"CFG measurements are static decoder heuristics and may be incomplete or misleading for obfuscated, packed, mixed-architecture, or non-code bytes." (`README.md:189-190`)

**Verdict:** CFG extraction is real but limited: linear-sweep only, x86 only, 256 KB cap, no symbolic execution, no deobfuscation. The fallback to raw byte patterns when disassembly fails is a pragmatic engineering choice but means "CFG topology" channel in the embedding may contain zero code-graph signal for packed binaries.

---

### 3. 4096-Dimensional Latent Vector Embeddings

**Project language:** "deterministic 4096-coordinate representation has four 1024-coordinate channels"

**Code Evidence:**

```python
# ml/feature_schema.py:1-8
LATENT_CHANNEL_DIMENSION = 1024
LATENT_DIMENSION = LATENT_CHANNEL_DIMENSION * 4
LATENT_CHANNELS = (
    "byte_opcode_histogram",
    "entropy_topography",
    "cfg_graph_topology",
    "pe_headers_sections_imports",
)
```

```python
# core/deep_embedding.py:14-16
class HighDimensionalEmbedding:
    """Deterministic, non-lossless feature encoding of file bytes into 4096 dimensions."""
```

```python
# core/deep_embedding.py:265-272
vector: list[float] = []
for channel in channels:
    channel_norm = math.sqrt(math.fsum(value * value for value in channel))
    if channel_norm:
        vector.extend(value / channel_norm for value in channel)
    else:
        vector.extend(channel)
return self._normalize(vector)
```

**Channel construction (core/deep_embedding.py):**
- **Channel 0 (byte_opcode_histogram):** Byte 1-grams (256), 2-grams (hashed to 512), opcode frequencies, printable ratio, MZ/PE sigs
- **Channel 1 (entropy_topography):** Mean, peak, variance, gradient stats, anomaly count/severity, resampled trajectory → 1024
- **Channel 2 (cfg_graph_topology):** Node degrees (512 slots), edges (hashed to 496), patterns, architecture → 1024
- **Channel 3 (pe_headers_sections_imports):** PE header fields, section metadata, imports, API names → 1024

**Feature hashing:** Blake2b with per-channel salt (`core/deep_embedding.py:68-74`) — deterministic but collision-prone by design.

**Normalization:** Per-channel L2 normalization, then global L2 (`core/deep_embedding.py:265-272`, `core/deep_embedding.py:32-48`)

**Classifier consumption:** `ml/structural_classifier.py:65-74` — `HighDimensionalEmbedding().embed_bytes(data)` → `np.float32[4096]`

**Verdict:** **Accurate.** The 4096-D vector is a deterministic, hand-engineered feature encoding (not learned, not a neural net). Four 1024-D channels as documented. Collisions via hashing are expected and documented as "non-lossless".

---

### 4. Asynchronous OSINT Correlation

**Project language:** "Public-feed lookups", "ThreatFox", "URLhaus", "AlienVault OTX", "concurrently", "cached in-process for five minutes"

**Code Evidence:**

```python
# core/global_intelligence.py:20-35
class GlobalIntelligenceEngine:
    def __init__(
        self,
        *,
        timeout_seconds: float = 8.0,
        otx_timeout_seconds: float = 8.0,
        cache_ttl_seconds: float = 300.0,
        max_cache_entries: int = 1000,
        ...
    ):
```

```python
# core/global_intelligence.py:276-343
async def query_indicator(self, indicator: str) -> dict[str, Any]:
    ...
    tasks = {
        "ThreatFox": asyncio.create_task(self._query_threatfox(session, value)),
        "URLhaus": asyncio.create_task(self._query_urlhaus(session, value, indicator_type)),
        "AlienVault OTX": asyncio.create_task(self._query_otx(session, value, indicator_type)),
    }
    done, pending = await asyncio.wait(tuple(tasks.values()), timeout=self.total_timeout_seconds)
    ...
```

**Feed endpoints (core/global_intelligence.py:44-53):**
- ThreatFox: `https://threatfox-api.abuse.ch/api/v1/`
- URLhaus: `https://urlhaus-api.abuse.ch/v1/` (payload + host)
- AlienVault OTX: `https://otx.alienvault.com/api/v1/`

**Indicator types supported (core/global_intelligence.py:66-87):** SHA256, SHA1, MD5, IPv4, IPv6, URL, domain

**Caching:** Thread-safe in-memory LRU with 5-min TTL, 1000-entry cap (`core/global_intelligence.py:296-360`)

**Opt-in enforcement:** `README.md:49-53` — "Public-feed lookups are disabled by default. When explicitly enabled in Settings..."

**Verdict:** **Accurate.** True async concurrency via `aiohttp` + `asyncio.wait`, bounded timeouts, caching, clear "correlation not proof" interpretation (`core/global_intelligence.py:392`).

---

### 5. Zero-Execution Security Bounds

**Project language:** "The target is analyzed statically and is never executed" (`README.md:16`), "bounded sliding-window entropy", "limiting string extraction and disassembly work"

**Code Evidence:**

```python
# config.py:15-17
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB
ANALYSIS_TIMEOUT_SECONDS = 15.0
MAX_STRING_SCAN_SIZE = 200_000
```

```python
# core/nextgen_engine.py:305
data = data[:cls.MAX_DISASSEMBLY_BYTES]  # 256 KiB disassembly cap
```

```python
# core/entropy.py:175-179
def entropy_for_window(
    data: bytes | bytearray | memoryview,
    window_size: int = 4096,
    step_size: int | None = None,
) -> list[float]:
```

```python
# core/heuristic_engine.py:137-139
MAX_TAIL_STRING_CHARACTERS = 2_000_000
CHUNK_CHARACTERS = 1024
CHUNK_OVERLAP = 256
```

**ZIP inspection bounds (README.md:94-101):**
- 50 MiB input limit
- 1,000 total entries max
- 16 MiB per member
- 64 MiB total decompressed
- 2 nested levels max
- No member scanning for malware

**Entropy bounds:** Output clamped to `[0.0, 8.0]` (`core/entropy.py:104`, `core/nextgen_engine.py:99`)

**Verdict:** **Accurate.** Every analytical path has explicit, configurable bounds. No code execution, no dynamic analysis, no sandbox. The 15-second analysis timeout (`config.py:16`) applies to the full pipeline.

---

### 6. Performance/Validation Benchmarks

**Project language:** "no validated evidence supporting a 98% detection accuracy, zero false positives, or a competition-grade malware detection rate"

**Code Evidence:**

```markdown
# README.md:183-190
CyberScan has no validated evidence supporting a 98% detection accuracy,
zero false positives, or a competition-grade malware detection rate. Such
figures require an independently labeled dataset, a held-out evaluation, and
reported class-specific metrics. The risk score is an explainable indicator,
not a confidence percentage or calibrated probability.
```

```python
# core/risk_engine.py:10-26
def combine_scores(heuristic_score: float, ml_score: float | None, 
                   heuristic_weight: float = 1.0, ml_weight: float = 0.0) -> float:
    ...
    if ml_score is None:
        return clamp(heuristic_score)
    ...
```

```python
# ml/structural_classifier.py:114-116
def embed_bytes(self, data: bytes) -> np.ndarray:
    """Extract 4096-dim embedding from raw bytes."""
    return _extract_features_from_bytes(data)
```

**Training/evaluation (README.md:243-256):**
- Synthetic dataset: 30 samples (10 per class) — explicitly labeled synthetic
- Metrics reported: accuracy, balanced accuracy, macro-F1, confusion matrix, per-class, ROC-AUC, Brier/ECE
- Group-aware split to prevent leakage
- **Caveat:** "Brier/ECE are computed from raw uncalibrated Random Forest scores and do not make them calibrated probabilities. These metrics are not a malware-coverage claim."

**Default weights:** `heuristic_weight=1.0, ml_weight=0.0` (`core/risk_engine.py:37-49`) — ML score reported separately, not fused by default

**Verdict:** **Honest and scientifically responsible.** No inflated claims. Explicit about: synthetic data only, uncalibrated scores, default ML weight zero, need for independent holdout evaluation.

---

## Scientific Rigor Assessment

| Dimension | Rating | Notes |
|-----------|--------|-------|
| **Terminology precision** | ⚠️ Mixed | "Entropy" used without Shannon qualifier; "latent vector" suggests learned representation but is hand-engineered |
| **Scope honesty** | ✅ Excellent | README explicitly disclaims detection rates, calibration, zero-day coverage |
| **Reproducibility** | ✅ Good | Deterministic embeddings, fixed seeds, synthetic dataset generator included |
| **Boundary conditions** | ✅ Excellent | Every code path has explicit bounds (size, time, depth, count) |
| **Statistical validity** | ⚠️ Limited | No real malware evaluation set; synthetic data only; ML uncalibrated; default ML weight=0 |
| **Adversarial robustness** | ❌ Not claimed | Linear-sweep CFG, no deobfuscation, no packing detection — acknowledged in README |
| **Operational safety** | ✅ Excellent | Zero-execution, opt-in OSINT, dry-run quarantine, explicit "not a replacement for commercial EDR" |

---

## Claim vs. Implementation Gap Analysis

| Claim Phrase | Implementation Reality | Gap |
|--------------|------------------------|-----|
| "entropy topography" | Shannon sliding-window entropy trajectory | None — correct infotheory term |
| "CFG topology" | Linear-sweep x86 basic blocks + cyclomatic complexity | "CFG" overstates: no recursive descent, no data flow, 256KB cap |
| "4096-dimensional latent vector" | 4×1024 deterministic feature channels with hashing | "Latent" suggests learned; actually hand-engineered + feature hashing |
| "Asynchronous OSINT correlation" | `asyncio.wait` on 3 aiohttp feeds with cache | Accurate |
| "Zero-execution security bounds" | Hard limits on every analytical dimension | Accurate |
| "Performance benchmarks" | Synthetic 30-sample eval, uncalibrated, ML off by default | Honest disclosure — no gap, but no production validation either |

---

## Conclusions

1. **No scientific fraud detected.** All six claims are either accurately implemented or honestly caveated in documentation.

2. **Terminology inflation in two areas:**
   - "Latent vector" → hand-engineered feature hash (industry commonly misuses "latent")
   - "CFG topology" → linear-sweep basic-block graph (standard limitation, but worth clarifying)

3. **Security bounds are engineering-grade.** Every analytical component has configurable, documented limits. The 15-second timeout and 50 MiB file cap make this suitable for triage, not deep analysis.

4. **ML component is research-grade only.** Synthetic data, uncalibrated scores, default weight zero. Not production-ready for detection decisions.

5. **OSINT is properly scoped.** Opt-in, cached, timeout-bounded, correlation-only interpretation.

6. **Overall:** A well-engineered **static analysis research prototype** with excellent boundary discipline and honest documentation. Suitable for educational use, triage assistance, and feature research. Not a detection engine.

---

## References (Code Citations)

- `config.py:15-17` — Global bounds
- `core/entropy.py:98-104, 137-170, 173-180` — Shannon entropy implementation
- `core/nextgen_engine.py:19-20, 161-380, 302-327` — CFG extraction, bounds, fallback
- `core/deep_embedding.py:14-275` — 4096-D embedding construction
- `ml/feature_schema.py:1-8` — Latent dimension constants
- `ml/structural_classifier.py:65-74, 114-116` — Embedding consumption
- `core/global_intelligence.py:20-35, 66-87, 276-343, 392` — Async OSINT
- `core/heuristic_engine.py:137-139, 142-177` — String extraction bounds
- `core/risk_engine.py:10-26, 37-55` — Score fusion, default weights
- `README.md:16, 41-44, 49-53, 94-101, 183-190, 243-256` — Documentation claims & caveats

---

*Report generated by read-only code inspection. No files modified.*