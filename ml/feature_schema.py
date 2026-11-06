LATENT_CHANNEL_DIMENSION = 1024
LATENT_DIMENSION = LATENT_CHANNEL_DIMENSION * 4
LATENT_CHANNELS = (
    "byte_opcode_histogram",
    "entropy_topography",
    "cfg_graph_topology",
    "pe_headers_sections_imports",
)

MODEL_CLASS_ORDER = ("clean", "suspicious", "malware")

# Feature schema version for tracking and compatibility
FEATURE_SCHEMA_VERSION = "cyberscan-4096-v1"

# Mapping of channel index to feature name for reconstruction
CHANNEL_NAMES = {
    0: "byte_opcode_histogram",
    1: "entropy_topography",
    2: "cfg_graph_topology",
    3: "pe_headers_sections_imports",
}

# Number of channels (4) - kept for compatibility with existing code
NUM_CHANNELS = len(LATENT_CHANNELS)
