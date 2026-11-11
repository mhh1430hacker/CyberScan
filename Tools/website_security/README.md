# Website Security Tools

Website checks operate only on user-supplied headers, configuration values,
markup, or TLS metadata. They do not crawl, scan, or contact a target.
See [the full 50-tool inventory](../SECURITY_TOOLS.md) for limitations,
licensing, and Registry integration.

| Tool module | Input |
|---|---|
| `http_security_headers_analyzer.py` | Response header object |
| `content_security_policy_analyzer.py` | CSP header text |
| `cors_configuration_analyzer.py` | Response header object |
| `cookie_security_analyzer.py` | Set-Cookie values |
| `https_configuration_checker.py` | URL and optional supplied HSTS value |
| `mixed_content_detector.py` | Markup text |
| `tls_configuration_analyzer.py` | Supplied TLS protocol and cipher names |
| `security_txt_validator.py` | security.txt text |
| `server_configuration_analyzer.py` | Response header object |
| `website_technology_fingerprinter.py` | Optional HTML and response headers |
