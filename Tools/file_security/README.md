# File Security Tools

These tools analyze user-supplied content in memory. They do not execute
uploaded files, extract archive members, or contact external services.
See [the full 50-tool inventory](../SECURITY_TOOLS.md) for limitations,
dependency status, licensing, and Registry integration.

| Tool module | Input |
|---|---|
| `file_hash_analyzer.py` | Base64 file bytes; optional filename |
| `digital_signature_validator.py` | File bytes, detached signature, PEM public key, and supported algorithm |
| `file_type_mismatch_detector.py` | Filename and base64 file bytes |
| `entropy_analyzer.py` | Base64 file bytes |
| `pe_structure_analyzer.py` | Base64 PE bytes |
| `digital_certificate_inspector.py` | PEM or base64 DER X.509 certificate |
| `embedded_payload_detector.py` | Base64 file bytes |
| `archive_security_analyzer.py` | Base64 archive bytes; bounded ZIP inspection |
| `macro_security_analyzer.py` | Base64 document bytes |
| `pdf_active_content_analyzer.py` | Base64 PDF bytes |

Archive paths, compression ratios, signatures, and entropy are review
indicators—not proof of compromise. ZIP inspection caps the central directory
at 8 MiB and 10,000 entries; ZIP64, RAR/7z, nested archive traversal, and
extraction are not supported.
