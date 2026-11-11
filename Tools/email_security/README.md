# Email Security Tools

Email analysis is local and based on supplied message content, records, or
attachment metadata. It does not access mailboxes, DNS, or external reputation
services, and it does not open attachment files.
See [the full 50-tool inventory](../SECURITY_TOOLS.md) for limitations,
licensing, and Registry integration.

| Tool module | Input |
|---|---|
| `email_header_analyzer.py` | Header/message text |
| `spf_validator.py` | Supplied SPF record |
| `dkim_validator.py` | Supplied DKIM-Signature and public-key record |
| `dmarc_validator.py` | Supplied DMARC record |
| `email_spoofing_detector.py` | Message text; Sentinel's frozen local analyzer |
| `sender_identity_analyzer.py` | Message header text |
| `email_phishing_detector.py` | Message text; Sentinel's frozen local analyzer |
| `email_url_extractor.py` | Message text |
| `email_attachment_risk_analyzer.py` | Attachment filenames and declared media types |
| `display_name_impersonation_detector.py` | Message text and an explicit brand list |

SPF and DMARC are syntax-only. DKIM does not perform canonicalization or
cryptographic verification; all three report that DNS/evaluation work was not
performed.
