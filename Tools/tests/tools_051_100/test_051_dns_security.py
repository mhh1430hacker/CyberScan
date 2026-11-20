"""Tool 051 - DNS Security Analyzer."""
from conftest import ids

TOOL = "cyberscan.network.dns-security"
GOOD = {
    "example.org": {"TXT": ["v=spf1 include:_spf.example.net -all"], "MX": ["10 mx1.example.org.", "20 mx2.example.org."],
                    "NS": ["ns1.example.net.", "ns2.example.net."], "CAA": ['0 issue "letsencrypt.org"'],
                    "DNSKEY": ["257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="]},
    "_dmarc.example.org": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.org"]},
}


def test_well_configured_domain_is_clean(run):
    result = run(TOOL, {"domain": "example.org", "records": GOOD})
    assert result["status"] == "success" and result["classification"] == "clean", result["findings"]


def test_weak_mail_authentication_is_flagged(run):
    records = {"example.com": {"TXT": ["v=spf1 a mx +all"], "MX": ["10 192.0.2.1."], "NS": ["ns1.example.com."], "CAA": []},
               "_dmarc.example.com": {"TXT": []}}
    result = run(TOOL, {"domain": "example.com", "records": records})
    found = ids(result)
    assert {"spf.pass-all", "dmarc.missing", "mx.ip-literal", "ns.single", "caa.missing"} <= found
    assert result["classification"] == "suspicious"
    assert all(f["assurance"] == "verified_condition" for f in result["findings"] if f["id"] == "spf.pass-all")


def test_spf_lookup_limit_and_multiple_records(run):
    many = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all"
    records = {"example.com": {"TXT": [many, "v=spf1 -all"]}, "_dmarc.example.com": {"TXT": ["v=DMARC1; p=none"]}}
    found = ids(run(TOOL, {"domain": "example.com", "records": records}))
    assert {"spf.too-many-lookups", "spf.multiple", "dmarc.monitor-only", "dmarc.no-reports"} <= found


def test_unsupplied_owner_is_unknown_not_missing(run):
    result = run(TOOL, {"domain": "example.com", "records": {"example.com": {"TXT": ["v=spf1 -all"]}}})
    assert "dmarc.missing" not in ids(result)
    assert any("_dmarc.example.com" in limit for limit in result["limitations"])


def test_weak_dkim_key_detected(run):
    # 512-bit RSA public key (SubjectPublicKeyInfo, DER) - test data only
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import base64
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    records = {"example.com": {"TXT": ["v=spf1 -all"]}, "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:a@example.com"]},
               "s1._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"]}}
    result = run(TOOL, {"domain": "example.com", "records": records, "dkim_selectors": ["s1"]})
    assert "dkim.short-key" in ids(result)


def test_live_mode_uses_lookup_and_reports_failures(run, monkeypatch):
    import security_toolkit.dnsutil as dnsutil

    answers = {("example.com", "TXT"): ["v=spf1 ?all"], ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine; pct=50; rua=mailto:x@example.com"],
               ("example.com", "MX"): ["10 mx.example.com."], ("example.com", "NS"): ["a.ns.", "b.ns."], ("example.com", "CAA"): []}

    def fake_lookup(name, rtype, *, timeout, nameserver=None):
        if rtype == "DNSKEY":
            raise dnsutil.LookupFailed("timeout")
        return answers.get((name, rtype), [])

    monkeypatch.setattr(dnsutil, "lookup", fake_lookup)
    result = run(TOOL, {"domain": "Example.COM", "resolve": True})
    assert result["status"] == "partial"  # DNSKEY lookup failed
    assert {"spf.neutral-all", "dmarc.partial-pct", "caa.missing"} <= ids(result)
    assert result["metadata"]["execution_mode"] == "network-passive"


def test_invalid_inputs_are_rejected(run, registry):
    assert run(TOOL, {"domain": "not a domain", "records": GOOD})["status"] == "invalid_input"
    assert run(TOOL, {"domain": "example.org"})["status"] == "invalid_input"  # neither records nor resolve
    assert registry.execute(TOOL, {"domain": "example.org", "unknown": 1}).status == "invalid_input"
