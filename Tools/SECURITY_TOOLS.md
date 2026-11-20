# First 50 Security Tools

These are platform-neutral, local analyzers. They do not execute uploaded files
or initiate HTTP, DNS, WHOIS, RDAP, or TLS requests. Network-derived checks
accept user-supplied records or observations and identify that limitation in
their results.

Each module contains literal Registry metadata, a JSON input/output schema, a
`run(input_data, options=None)` entry point, `SOURCE`, `VERSION`, `LICENSE`,
`EXECUTION_MODE`, and `TIMEOUT_SECONDS`. All outputs use the common envelope:
`tool_id`, `status`, `classification`, `risk_score`, `findings`, `evidence`,
and `metadata`. The output metadata explicitly says `timeout_enforced: false`:
the Registry runs approved code in-process and does not enforce per-tool
timeouts. `PROCESSING` flags and timeout values are declarations, not security
controls.

## Inventory

| # | Tool | State and scope |
|---:|---|---|
| 1 | File Hash Analyzer | Implemented; local MD5/SHA-1/SHA-256/SHA-512 calculations. |
| 2 | Digital Signature Validator | Implemented; detached RSA-PKCS#1 v1.5/SHA-256, ECDSA/SHA-256, and Ed25519 verification. No signer trust-chain validation. |
| 3 | File Type Mismatch Detector | Implemented; compares a bounded set of extensions and detected signatures. |
| 4 | Entropy Analyzer | Implemented; entropy is a heuristic and cannot distinguish compression from encryption. |
| 5 | PE Structure Analyzer | Implemented; static PE parsing; uses `pefile` when installed and the Sentinel analyzer otherwise. |
| 6 | Digital Certificate Inspector | Implemented; X.509 metadata and validity dates. No revocation or trust verification. |
| 7 | Embedded Payload Detector | Partial; secondary-signature and Sentinel indicator heuristics, no extraction. |
| 8 | Archive Security Analyzer | Partial; bounded ZIP metadata only. RAR/7z, nested archives, and extraction are unsupported. |
| 9 | Macro Security Analyzer | Partial; identifies selected OOXML macro entries and Sentinel indicators; does not execute macros or fully inspect every Office format. |
| 10 | PDF Active Content Analyzer | Partial; token-based active-content inspection, not a complete PDF parser. |
| 11 | YARA Rule Scanner | Partial; requires optional `yara-python`. When unavailable, reports partial/unavailable and does not claim a scan. |
| 12 | Suspicious API Detector | Partial; searches selected printable API names; string presence does not prove a call. |
| 13 | Packer Indicator Detector | Partial; PE section-name and entropy heuristics. |
| 14 | Executable Section Analyzer | Implemented; static PE section/permission summary; no binary execution. |
| 15 | Script Obfuscation Detector | Partial; selected encoding and dynamic-evaluation patterns. |
| 16 | Malware Indicator Analyzer | Implemented as an adapter to the frozen Sentinel `inspect_content` analyzer. |
| 17 | Persistence Indicator Detector | Partial; selected persistence paths and command strings. |
| 18 | Ransomware Indicator Detector | Partial; selected ransom-note and backup-deletion strings. |
| 19 | Shellcode Pattern Detector | Partial; limited byte signatures with heuristic findings. |
| 20 | Malware Similarity Analyzer | Implemented as exact hashes plus sampled byte-shingle similarity; no family attribution. |
| 21 | URL Reputation Analyzer | Partial; offline URL heuristics only. Reputation data source is explicitly `none`. |
| 22 | Phishing URL Detector | Implemented as local Sentinel URL heuristics; not a reputation-feed verdict. |
| 23 | Domain Reputation Analyzer | Partial; offline URL heuristics only. No live reputation result. |
| 24 | Homograph Attack Detector | Implemented using Sentinel's IDN and brand-impersonation heuristics. |
| 25 | Redirect Chain Analyzer | Partial; analyzes supplied observed hops and never follows redirects. |
| 26 | URL Shortener Analyzer | Partial; checks a fixed local list and does not resolve short links. |
| 27 | DNS Record Analyzer | Partial; analyzes supplied record strings only; does not query DNS. |
| 28 | SSL Certificate Inspector | Partial; inspects a supplied certificate; does not establish a TLS connection or check revocation. |
| 29 | Domain Expiration Checker | Partial; evaluates a supplied timestamp; does not query WHOIS/RDAP or a registrar. |
| 30 | Suspicious Subdomain Detector | Partial; lexical checks on a supplied hostname, not a threat-intelligence verdict. |
| 31 | HTTP Security Headers Analyzer | Implemented for user-supplied response headers; no site request. |
| 32 | Content Security Policy Analyzer | Implemented for supplied CSP text; policy review is heuristic. |
| 33 | CORS Configuration Analyzer | Implemented for supplied Access-Control response headers. |
| 34 | Cookie Security Analyzer | Implemented for supplied Set-Cookie values. |
| 35 | HTTPS Configuration Checker | Partial; URL scheme and supplied HSTS only, no connection check. |
| 36 | Mixed Content Detector | Partial; searches supplied markup for HTTP resource references. |
| 37 | TLS Configuration Analyzer | Partial; reviews supplied protocol/cipher names, no live handshake. |
| 38 | security.txt Validator | Partial; checks field presence and ISO-8601 expiry, not a complete standards validator. |
| 39 | Server Configuration Analyzer | Partial; identifies technology-disclosure headers and a narrow set of legacy banners. |
| 40 | Website Technology Fingerprinter | Partial; local signatures applied only to user-supplied markup and headers. |
| 41 | Email Header Analyzer | Implemented; parses selected headers and compares visible From/Return-Path domains. |
| 42 | SPF Validator | Partial; syntax and approximate DNS-lookup counting only; no DNS or sender-IP evaluation. |
| 43 | DKIM Validator | Partial; checks supplied signature/key metadata only. Cryptographic DKIM verification is not implemented. |
| 44 | DMARC Validator | Partial; validates supplied tags and policy syntax only; no DNS lookup or policy evaluation. |
| 45 | Email Spoofing Detector | Implemented as an adapter to the frozen Sentinel message analyzer. |
| 46 | Sender Identity Analyzer | Implemented; parses From/Reply-To identity fields; does not authenticate the sender. |
| 47 | Email Phishing Detector | Implemented as an adapter to frozen Sentinel message and URL heuristics. |
| 48 | Email URL Extractor | Implemented; extracts and locally analyzes URLs without opening them. |
| 49 | Email Attachment Risk Analyzer | Partial; checks filenames and declared media types only; does not read attachment bytes. |
| 50 | Display Name Impersonation Detector | Partial; compares a supplied brand list to visible display name/domain text. |

Summary: **50 modules implemented**, with **20 scope-limited implementations**
and **30 partial/heuristic implementations** as described above. No tool
requires an external service by design; tools that need remote context accept
user-supplied evidence and state that no live query was made. There are no
wholly unimplemented modules.

### Dependencies and licensing

The selected development environment already provides `cryptography` and
`pefile`. `yara-python` is optional and was unavailable in the test path; the
scanner reports that condition rather than returning a fabricated clean
verdict. No dependency manifest was changed. Tool modules truthfully declare
`LICENSE = "UNSPECIFIED: no applicable repository license declaration."`:
the repository has no applicable license file, so these declarations are not
license grants. A maintainer/legal owner must establish the project license
before distribution.

### Registry integration

The current [registry.json](./registry.json) still allowlists only
`file_analysis`. A coordination request to Sentinel to add the five category
directories was appended to `../collaboration/DISCUSSION.md`; no confirmation has
been received in this task. Therefore these modules are discoverable in the
focused test configuration, but **not in the default application registry**.
The Registry must be configured to allowlist:

- `file_security`
- `malware_analysis`
- `url_domain_security`
- `website_security`
- `email_security`

Allowlisting a directory does not approve any tool. Each discovered module
must remain disabled until a maintainer separately reviews and approves its
source hash. Every entry point pins and checks the shared
`Tools/tool_runtime.py` SHA-256 before importing it, so the approved wrapper
also binds that shared implementation. Review all other imported dependencies
as well; their code is not transitively bound by the Registry's source hash.

### Focused test

From the project root:

```powershell
pytest Tools\tests\test_first_50_tools.py Tools\tests\test_tool_registry.py -q
```

The test uses an in-memory/test-only Registry allowlist and hashes; it does not
modify `registry.json` or approve tools for normal application use. The 50
parameterized cases each exercise a benign/control and an indicator-bearing
input where relevant (100 tool executions); hash and similarity tests compare
distinct and matching inputs. Additional checks cover archive limits, the
default allowlist, invalid input, and runtime integrity. The existing Registry
regression cases run in the same command. Latest result: **62 passed**. The
tests do not contact external services or execute samples.
