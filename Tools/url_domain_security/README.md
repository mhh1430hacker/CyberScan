# URL and Domain Security Tools

These tools are offline and input-driven. They do not resolve DNS, fetch web
pages, follow redirects, query registrars, or consult reputation services.
See [the full 50-tool inventory](../SECURITY_TOOLS.md) for limitations,
licensing, and Registry integration.

| Tool module | Input |
|---|---|
| `url_reputation_analyzer.py` | URL; local heuristics only |
| `phishing_url_detector.py` | URL; local phishing heuristics |
| `domain_reputation_analyzer.py` | Domain; local heuristics only |
| `homograph_attack_detector.py` | URL |
| `redirect_chain_analyzer.py` | User-observed redirect URL list |
| `url_shortener_analyzer.py` | URL; checks a local shortener list |
| `dns_record_analyzer.py` | Domain and supplied DNS record strings |
| `ssl_certificate_inspector.py` | Supplied X.509 certificate |
| `domain_expiration_checker.py` | Domain and supplied ISO-8601 expiration timestamp |
| `suspicious_subdomain_detector.py` | Hostname |

Reputation, DNS, redirect, TLS, and expiration conclusions are unavailable
unless the corresponding external evidence is explicitly supplied; the tools
label those limitations and do not invent live results.
