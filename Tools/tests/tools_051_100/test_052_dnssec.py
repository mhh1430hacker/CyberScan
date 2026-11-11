"""Tool 052 - DNSSEC Validator, against a zone signed in the test with real keys."""
import time

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import ids

TOOL = "cyberscan.network.dnssec-validator"
ZONE = dns.name.from_text("example.test.")
NOW = int(time.time())


def _signed_zone(*, tamper=False, expire_in=30 * 86400):
    key = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(key.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256, flags=257)
    keyset = dns.rrset.from_rdata(ZONE, 3600, dnskey)
    soa = dns.rrset.from_text(ZONE, 3600, "IN", "SOA", "ns1.example.test. admin.example.test. 1 7200 3600 1209600 300")
    a = dns.rrset.from_text(ZONE, 300, "IN", "A", "192.0.2.10")
    sigs = []
    for rrset in (keyset, soa, a):
        sig = dns.dnssec.sign(rrset, key, ZONE, dnskey, inception=NOW - 3600, expiration=NOW + expire_in)
        sigs.append(dns.rrset.from_rdata(ZONE, rrset.ttl, sig))
    if tamper:
        a = dns.rrset.from_text(ZONE, 300, "IN", "A", "198.51.100.66")  # answer changed after signing
    text = "\n".join(r.to_text() for r in (keyset, soa, a, *sigs))
    ds = dns.dnssec.make_ds(ZONE, dnskey, "SHA256").to_text()
    return text, ds


def test_valid_signed_zone_validates(run):
    text, ds = _signed_zone()
    result = run(TOOL, {"zone": "example.test", "zone_text": text, "ds_records": [ds], "now": NOW})
    assert result["classification"] == "clean", result["findings"]
    assert {"A", "DNSKEY", "SOA"} <= set(result["artifacts"]["validated_rrsets"])


def test_tampered_rrset_is_bogus(run):
    text, ds = _signed_zone(tamper=True)
    result = run(TOOL, {"zone": "example.test", "zone_text": text, "ds_records": [ds], "now": NOW})
    assert "dnssec.bogus.A" in ids(result) and result["classification"] == "review"


def test_ds_mismatch_and_sha1_digest(run):
    text, _ = _signed_zone()
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = dns.dnssec.make_dnskey(other_key.public_key(), dns.dnssec.Algorithm.ECDSAP256SHA256, flags=257)
    wrong_ds = dns.dnssec.make_ds(ZONE, other, "SHA1", policy=dns.dnssec.allow_all_policy).to_text()
    found = ids(run(TOOL, {"zone": "example.test", "zone_text": text, "ds_records": [wrong_ds], "now": NOW}))
    assert "dnssec.ds-mismatch" in found
    assert any(f.startswith("dnssec.ds-sha1") for f in found)


def test_expiring_signatures(run):
    text, ds = _signed_zone(expire_in=2 * 86400)
    found = ids(run(TOOL, {"zone": "example.test", "zone_text": text, "ds_records": [ds], "now": NOW}))
    assert {"dnssec.expiring.A", "dnssec.expiring.SOA"} <= found


def test_unsigned_zone_and_bad_input(run):
    unsigned = "example.test. 300 IN A 192.0.2.1"
    assert "dnssec.unsigned" in ids(run(TOOL, {"zone": "example.test", "zone_text": unsigned}))
    assert run(TOOL, {"zone": "example.test", "zone_text": "this is not a zone {"})["status"] == "invalid_input"
    assert run(TOOL, {"zone": "example.test"})["status"] == "invalid_input"


def test_live_mode_with_injected_resolver(run, monkeypatch):
    import dns.zone
    import security_toolkit.dnsutil as dnsutil

    text, ds = _signed_zone()
    node = dns.zone.from_text(text, origin=ZONE, relativize=False, check_origin=False).nodes[ZONE]

    def fake_fetch(name, rtype, *, nameserver, timeout):
        rdtype = dns.rdatatype.from_text(rtype)
        to = lambda rds: dns.rrset.from_rdata_list(ZONE, rds.ttl, list(rds)) if rds else None
        return to(node.get_rdataset(dns.rdataclass.IN, rdtype)), to(node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.RRSIG, rdtype))

    monkeypatch.setattr(dnsutil, "fetch_rrsets", fake_fetch)
    result = run(TOOL, {"zone": "example.test", "resolve": True, "ds_records": [ds], "now": NOW})
    assert result["status"] == "success" and result["metadata"]["execution_mode"] == "network-passive"
    assert {"DNSKEY", "SOA"} <= set(result["artifacts"]["validated_rrsets"])


def test_live_failure_is_partial_not_error(run, monkeypatch):
    import security_toolkit.dnsutil as dnsutil

    def boom(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr(dnsutil, "fetch_rrsets", boom)
    result = run(TOOL, {"zone": "example.test", "resolve": True})
    assert result["status"] == "partial" and result["classification"] == "unknown"
    assert "dnssec.unsigned" not in ids(result)  # a failed lookup is unknown, not "unsigned"
