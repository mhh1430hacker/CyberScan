"""Tools 053-060 (network security): benign and risky fixtures for each tool."""
import datetime as dt
import json
import socket
import struct
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from conftest import b64, ids, no_secret_leak

# ---- 053 network configuration ---------------------------------------------------------------
CFG = "cyberscan.network.config-analyzer"
HARDENED_SSHD = """Port 22
ListenAddress 10.0.0.5
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256
"""
WEAK_SSHD = """PermitRootLogin yes
PermitEmptyPasswords yes
Ciphers aes128-cbc,3des-cbc,aes256-ctr
MACs hmac-md5,hmac-sha2-256
MaxAuthTries 20
X11Forwarding yes
"""
IOS = """hostname edge1
enable password Cisco123
username admin privilege 15 password 7 0822455D0A16
snmp-server community public RO
snmp-server community s3cr3tRW RW
ip http server
line vty 0 4
 password letmein
 login
 transport input telnet ssh
"""


def test_053_hardened_sshd_is_clean(run):
    result = run(CFG, {"content": HARDENED_SSHD})
    assert result["classification"] == "clean" and result["metadata"]["input_kind"] == "sshd"


def test_053_weak_sshd(run):
    found = ids(run(CFG, {"content": WEAK_SSHD}))
    assert {"sshd.root-login", "sshd.empty-passwords", "sshd.weak-ciphers", "sshd.weak-macs", "sshd.password-auth",
            "sshd.maxauthtries", "sshd.x11forwarding"} <= found


def test_053_ios_device_and_secret_masking(run):
    result = run(CFG, {"content": IOS})
    assert {"ios.enable-password", "ios.type7-password", "ios.snmp-community", "ios.http-server", "ios.telnet",
            "ios.vty-no-acl", "ios.no-remote-logging", "ios.no-password-encryption"} <= ids(result)
    no_secret_leak(result, "Cisco123", "s3cr3tRW")
    assert result["classification"] == "suspicious"


def test_053_unknown_format(run):
    assert run(CFG, {"content": "just some notes"})["status"] == "unsupported"


# ---- 054 ip reputation -----------------------------------------------------------------------
IPR = "cyberscan.network.ip-reputation"
DROP = "; Spamhaus-style DROP list (test data)\n198.51.100.0/24 ; SBL0001\n2001:db8:bad::/48 ; SBL0002\n"


def test_054_classification_without_lists_makes_no_reputation_claim(run):
    result = run(IPR, {"ips": ["10.1.2.3", "8.8.8.8", "240.0.0.1", "not-an-ip"]})
    assert result["artifacts"]["classification_by_address"]["10.1.2.3"].startswith("private")
    assert result["artifacts"]["classification_by_address"]["8.8.8.8"] == "global unicast"
    assert "ip.bogon" in ids(result)
    assert any("no built-in reputation" in l for l in result["limitations"])


def test_054_supplied_blocklist_matches_and_allowlist(run):
    text = "connection from 198.51.100.7 port 4444; later 2001:db8:bad::5 and 203.0.113.9"
    result = run(IPR, {"content": text, "blocklists": [{"name": "DROP", "entries": DROP}],
                       "allowlist": ["203.0.113.0/24"]})
    listed = [f for f in result["findings"] if f["id"].startswith("ip.listed")]
    # 198.51.100.0/24 and 2001:db8::/32 are documentation ranges: classified special-purpose, never "listed"
    assert listed == [] and result["artifacts"]["summary"]["special_purpose"] == 3
    real = run(IPR, {"ips": ["45.9.20.1"], "blocklists": [{"name": "DROP", "entries": "45.9.20.0/22 ; SBL9"}]})
    assert [f["id"] for f in real["findings"]] == ["ip.listed.drop"] and real["findings"][0]["severity"] == "high"


def test_054_rejects_empty_and_bad_lists(run):
    assert run(IPR, {"ips": ["nope"]})["status"] == "invalid_input"
    assert run(IPR, {"ips": ["1.1.1.1"], "blocklists": [{"name": "x", "entries": "garbage"}]})["status"] == "invalid_input"


# ---- 055 service exposure --------------------------------------------------------------------
EXP = "cyberscan.network.service-exposure"
NETSTAT = """
Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1000
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1100
  TCP    127.0.0.1:6379         0.0.0.0:0              LISTENING       1200
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    10.0.0.5:52000         93.184.216.34:443      ESTABLISHED     900
"""
SS = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:27017 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"


def test_055_listing_mode(run):
    result = run(EXP, {"listening": NETSTAT})
    found = ids(result)
    assert {"listen.3389", "listen.445", "listen.135"} <= found
    assert "listen.6379" not in found  # loopback-only Redis is fine
    assert result["metadata"]["execution_mode"] == "local"
    assert "listen.27017" in ids(run(EXP, {"listening": SS}))


def test_055_probe_requires_authorization_and_refuses_public(run):
    assert run(EXP, {"targets": ["127.0.0.1"], "ports": [1]})["status"] == "invalid_input"
    assert run(EXP, {"targets": ["8.8.8.8"], "ports": [53], "authorization_confirmed": True})["status"] == "invalid_input"


def test_055_probe_against_local_listener(run):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    stop = threading.Event()

    def accept():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                pass
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        closed = port + 1 if port < 65535 else port - 1
        result = run(EXP, {"targets": ["127.0.0.1"], "ports": [port, closed], "authorization_confirmed": True, "connect_timeout": 0.5})
    finally:
        stop.set()
        server.close()
    probe = result["artifacts"]["probe"][0]
    assert probe["open"] == [port]
    assert result["metadata"]["execution_mode"] == "network-active-authorized"


# ---- 056 traffic metadata --------------------------------------------------------------------
TMA = "cyberscan.network.traffic-metadata"


def _ipv4_tcp(src, dst, sport, dport, flags):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 1024, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def _ipv4_dns(src, dst, name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + q
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + udp


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in frames:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    return out


def test_056_port_scan_cleartext_and_tunnel(run):
    frames = [(1000 + i * 0.01, _ipv4_tcp("10.0.0.9", "10.0.0.20", 40000 + i, p, 0x02)) for i, p in enumerate(range(20, 60))]
    frames += [(2000, _ipv4_tcp("10.0.0.9", "10.0.0.30", 50000, 23, 0x18))]
    import hashlib
    frames += [(3000 + i, _ipv4_dns("10.0.0.9", "10.0.0.53", hashlib.sha256(str(i).encode()).hexdigest()[:44] + ".exfil.example"))
               for i in range(40)]
    result = run(TMA, {"data_base64": b64(_pcap(frames))})
    assert {"scan.ports", "cleartext.telnet", "dns.tunnel"} <= ids(result)
    assert result["artifacts"]["packets"] == len(frames) and result["metadata"]["input_kind"] == "pcap"


def test_056_benign_capture_and_pcapng(run):
    frame = _ipv4_tcp("10.0.0.9", "93.184.216.34", 50001, 443, 0x10)
    result = run(TMA, {"data_base64": b64(_pcap([(1, frame)]))})
    assert result["classification"] == "clean"
    shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
    idb = struct.pack("<IIHHI", 1, 20, 1, 0, 65535) + struct.pack("<I", 20)
    body = struct.pack("<IIIII", 0, 0, 1000000, len(frame), len(frame)) + frame + b"\x00" * (-len(frame) % 4)
    epb = struct.pack("<II", 6, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
    ng = run(TMA, {"data_base64": b64(shb + idb + epb)})
    assert ng["metadata"]["input_kind"] == "pcapng" and ng["artifacts"]["decoded"] == 1


def test_056_not_a_capture(run):
    assert run(TMA, {"data_base64": b64(b"GIF89a....")})["status"] == "unsupported"
    assert run(TMA, {"data_base64": "%%%%"})["status"] == "invalid_input"


# ---- 057 certificate chain -------------------------------------------------------------------
CERT = "cyberscan.network.certificate-chain"
NOW = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)


def _cert(subject, issuer_name, key, signer, *, ca, days=365, san=None, hash_alg=None, start=None):
    """Certificates with the extensions a real CA issues (SKI/AKI), so RFC 5280 profile checks pass."""
    start = start or NOW - dt.timedelta(days=10)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san or []]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(signer, hash_alg or hashes.SHA256())


@pytest.fixture(scope="module")
def pki():
    root_key, int_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Test Root", "Test Root", root_key, root_key, ca=True, days=3650, start=NOW - dt.timedelta(days=100))
    inter = _cert("Test Intermediate", "Test Root", int_key, root_key, ca=True, days=1000)
    leaf = _cert("www.example.test", "Test Intermediate", leaf_key, int_key, ca=False, days=90, san=["www.example.test"])
    pem = lambda *c: "".join(x.public_bytes(serialization.Encoding.PEM).decode() for x in c)
    return {"root": root, "inter": inter, "leaf": leaf, "pem": pem, "leaf_key": leaf_key, "int_key": int_key}


def test_057_valid_chain_to_supplied_root(run, pki):
    pem = pki["pem"]
    result = run(CERT, {"pem_chain": pem(pki["leaf"], pki["inter"]), "trusted_roots_pem": pem(pki["root"]),
                        "hostname": "www.example.test", "now": int(NOW.timestamp())})
    assert result["classification"] == "clean", result["findings"]
    assert result["artifacts"]["trusted_path"][-1] == "CN=Test Root"


def test_057_wrong_host_wrong_order_expired(run, pki):
    pem = pki["pem"]
    roots = pem(pki["root"])
    wrong_host = run(CERT, {"pem_chain": pem(pki["leaf"], pki["inter"]), "trusted_roots_pem": roots,
                            "hostname": "evil.example.test", "now": int(NOW.timestamp())})
    assert {"chain.hostname-mismatch"} & ids(wrong_host) or {"chain.untrusted"} & ids(wrong_host)
    swapped = run(CERT, {"pem_chain": pem(pki["inter"], pki["leaf"]), "trusted_roots_pem": roots, "now": int(NOW.timestamp())})
    assert any(f.startswith("chain.broken-link") for f in ids(swapped))
    later = int((NOW + dt.timedelta(days=200)).timestamp())
    expired = run(CERT, {"pem_chain": pem(pki["leaf"], pki["inter"]), "trusted_roots_pem": roots, "now": later})
    assert "cert.expired.0" in ids(expired)


# Fixed test certificates made with OpenSSL 3.2 (cryptography >= 47 refuses to sign with SHA-1).
# Public certificates only; the private keys were discarded. Not real hosts.
SELF_SIGNED_RSA1024_SHA1 = """-----BEGIN CERTIFICATE-----
MIICKDCCAZGgAwIBAgICEjQwDQYJKoZIhvcNAQEFBQAwHjEcMBoGA1UEAwwTbGVn
YWN5LmV4YW1wbGUudGVzdDAgFw0yNjExMTAxODIxMDRaGA8yMTI2MTAxNzE4MjEw
NFowHjEcMBoGA1UEAwwTbGVnYWN5LmV4YW1wbGUudGVzdDCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEAsgH3xrCrxOXaecjdWi3vGsulAhH6LV8QyRuS7Uj30liH
4JB53R7ixH7lCzlr7ciz4fPSkRtvJXrzbG4Gph3tAyagXwp8+KDDZaTa2wVW7AzO
Wm2je5H0DruSlceuPmVSHvt2BESmgLoAK1y3qDHhkbzzBgV2GI7kIFi1pyf0xnsC
AwEAAaNzMHEwHQYDVR0OBBYEFHzctJVgg7brYXj+9LA5GeThY9GzMB8GA1UdIwQY
MBaAFHzctJVgg7brYXj+9LA5GeThY9GzMA8GA1UdEwEB/wQFMAMBAf8wHgYDVR0R
BBcwFYITbGVnYWN5LmV4YW1wbGUudGVzdDANBgkqhkiG9w0BAQUFAAOBgQA2LQ+Y
s0+dwQDxIgUkz2RpCHR/o1YP+KmwkGijTuo4cde2QtsIO36C8I2h4ICXSDzVLtr1
bnRWEGmIHCazt0DoVVEuuP27SI2he5u76Z2iX+uHEkU74h0QvWyHA8VJFcLz77NS
rF+H5LtxAjTZek8WvjlPqNHW4YLdU/sS/2JlSA==
-----END CERTIFICATE-----"""
SHA1_SIGNED_LEAF = """-----BEGIN CERTIFICATE-----
MIICWjCCAgKgAwIBAgIBAjAJBgcqhkjOPQQBMBkxFzAVBgNVBAMMDkxlZ2FjeSBU
ZXN0IENBMCAXDTI2MTExMDE4MjE0MFoYDzIxMjYxMDE3MTgyMTQwWjAbMRkwFwYD
VQQDDBBvbGQuZXhhbXBsZS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA3/4Xhba+GVPrvPlz1t79qCv4ZGtX1JsGCSB943xpKpy/flkUxPjXMqI2
+HpTaqSVDGOM8SzpRIyvGTZqDPtderD6v4qZDZ822EBb11xYbRKma/suVfJKrJ+G
mPZSjGwmzAyxWxagxvcu2Iq2VS/VwcMY7fi0AzoYuzZwqOghJpby8v0Kp2Ar8LLh
NeMEGnxsEdxOdkDpO3autUYuLC9lKmpzPT5npaBLCVvzEAhhtOWeYYphIVN/md3k
A178MkLa/baX4chMfNi5Yuav44u96xdzeNdoRPezLlq1DLXMhlE5ScW0RDM328cd
MPn5nAsm5ALEWaR5vlsSDS1UbJhXIQIDAQABo20wazAbBgNVHREEFDASghBvbGQu
ZXhhbXBsZS50ZXN0MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFKyuoGlehSNxUs02
66jJo+8efE5mMB8GA1UdIwQYMBaAFM1pa3GVAvQgJ6gKaGUV9ss+RbuoMAkGByqG
SM49BAEDRwAwRAIgaDWMk+GeTrQFpLWdhfLY7Zg1rzAecNyC7N5nSYnuwCECIGG/
ist1kT+/ilRhBCzSVdo/GZTeB5aSNqg0RLVwY7s0
-----END CERTIFICATE-----"""
LEGACY_CA = """-----BEGIN CERTIFICATE-----
MIIBdzCCARygAwIBAgIBATAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA5MZWdhY3kg
VGVzdCBDQTAgFw0yNjExMTAxODIxMzlaGA8yMTI2MTAxNzE4MjEzOVowGTEXMBUG
A1UEAwwOTGVnYWN5IFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQa
SmpnS6TFpiCkrQWsc94oSpnCJaVNn2RRnwwZDqY7e/pftW+gs4V7US5xKb0YC1D0
LM+jRqri2jWfkbKY3KbWo1MwUTAdBgNVHQ4EFgQUzWlrcZUC9CAnqApoZRX2yz5F
u6gwHwYDVR0jBBgwFoAUzWlrcZUC9CAnqApoZRX2yz5Fu6gwDwYDVR0TAQH/BAUw
AwEB/zAKBggqhkjOPQQDAgNJADBGAiEA/Jqo5yDcljtLhOyyCyVidRUHXz0u/OTS
FVn/KxoYIcsCIQD3AQ2xV/e526oEm7ZbVcxRJ+fnqe/8bsucye2UUWxqJw==
-----END CERTIFICATE-----"""


def test_057_weak_key_and_self_signed(run):
    result = run(CERT, {"pem_chain": SELF_SIGNED_RSA1024_SHA1, "hostname": "legacy.example.test", "now": int(NOW.timestamp())})
    assert {"cert.weak-rsa.0", "cert.self-signed", "chain.untrusted"} <= ids(result)
    assert result["classification"] == "suspicious"


def test_057_sha1_signature_on_leaf(run):
    result = run(CERT, {"pem_chain": SHA1_SIGNED_LEAF + "\n" + LEGACY_CA, "trusted_roots_pem": LEGACY_CA,
                        "hostname": "old.example.test", "now": int(NOW.timestamp())})
    assert "cert.weak-signature.0" in ids(result)
    assert "cert.weak-signature.1" not in ids(result)  # the root's own (SHA-256) self-signature is irrelevant anyway


def test_057_live_handshake_via_toolkit(run, pki, monkeypatch):
    import security_toolkit.httputil as httputil
    ders = [c.public_bytes(serialization.Encoding.DER) for c in (pki["leaf"], pki["inter"])]
    monkeypatch.setattr(httputil, "fetch_tls_chain", lambda host, port, timeout: ders)
    result = run(CERT, {"host": "www.example.test", "trusted_roots_pem": pki["pem"](pki["root"]), "now": int(NOW.timestamp())})
    assert result["metadata"]["input_kind"] == "tls-handshake" and result["classification"] == "clean"
    assert run(CERT, {"pem_chain": "not pem"})["status"] == "invalid_input"


# ---- 058 HSTS --------------------------------------------------------------------------------
HSTS = "cyberscan.network.hsts"


def test_058_good_and_missing_headers(run):
    good = run(HSTS, {"headers": "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"})
    assert good["classification"] == "clean" and "hsts.preload-ready" in ids(good)
    assert "hsts.missing" in ids(run(HSTS, {"headers": "HTTP/1.1 200 OK\nContent-Type: text/html\n"}))


def test_058_weak_policies(run):
    found = ids(run(HSTS, {"headers": "Strict-Transport-Security: max-age=86400; preload\nStrict-Transport-Security: max-age=1"}))
    assert {"hsts.short-max-age", "hsts.no-subdomains", "hsts.preload-not-eligible", "hsts.duplicate"} <= found
    assert "hsts.disabled" in ids(run(HSTS, {"headers": "Strict-Transport-Security: max-age=0"}))
    assert "hsts.no-max-age" in ids(run(HSTS, {"headers": "Strict-Transport-Security: includeSubDomains"}))
    assert "hsts.over-http" in ids(run(HSTS, {"headers": "Strict-Transport-Security: max-age=31536000", "scheme": "http"}))


def test_058_live_url_with_redirect_check(run, monkeypatch):
    import security_toolkit.httputil as httputil

    def fake_fetch(url, *, method="GET", timeout=10.0, max_body=0):
        if url.startswith("https://"):
            return httputil.Response(url, 200, [("Strict-Transport-Security", "max-age=31536000; includeSubDomains")])
        return httputil.Response(url, 200, [("Content-Type", "text/html")])
    monkeypatch.setattr(httputil, "fetch", fake_fetch)
    result = run(HSTS, {"url": "https://www.example.test/", "check_http_redirect": True})
    assert ids(result) == {"hsts.no-https-redirect"}
    assert run(HSTS, {"url": "ftp://x"})["status"] == "invalid_input"


# ---- 059 MTA-STS -----------------------------------------------------------------------------
STS = "cyberscan.network.mta-sts"
POLICY = "version: STSv1\nmode: enforce\nmx: mx1.example.test\nmx: *.backup.example.test\nmax_age: 604800\n"
RECORDS = {"_mta-sts.example.test": {"TXT": ["v=STSv1; id=20260601"]},
           "_smtp._tls.example.test": {"TXT": ["v=TLSRPTv1; rua=mailto:tls@example.test"]},
           "example.test": {"MX": ["10 mx1.example.test.", "20 a.backup.example.test."]}}


def test_059_valid_policy(run):
    result = run(STS, {"domain": "example.test", "records": RECORDS, "policy_text": POLICY})
    assert result["classification"] == "clean", result["findings"]


def test_059_problems(run):
    records = json.loads(json.dumps(RECORDS))
    records["example.test"]["MX"].append("30 mail.other.test.")
    records["_smtp._tls.example.test"]["TXT"] = []
    policy = "version: STSv1\nmode: testing\nmx: mx1.example.test\nmx: *.backup.example.test\nmax_age: 3600\n"
    found = ids(run(STS, {"domain": "example.test", "records": records, "policy_text": policy}))
    assert {"mtasts.mx-mismatch", "mtasts.testing", "mtasts.max-age-short", "tlsrpt.missing"} <= found
    # '*.backup.example.test' must not match two labels deep
    deep = json.loads(json.dumps(RECORDS))
    deep["example.test"]["MX"] = ["10 a.b.backup.example.test."]
    assert "mtasts.mx-mismatch" in ids(run(STS, {"domain": "example.test", "records": deep, "policy_text": POLICY}))


def test_059_fetch_policy_errors(run, monkeypatch):
    import security_toolkit.httputil as httputil
    monkeypatch.setattr(httputil, "fetch", lambda url, **k: httputil.Response(url, 404, []))
    assert "mtasts.policy-http-error" in ids(run(STS, {"domain": "example.test", "records": RECORDS, "fetch_policy": True}))
    monkeypatch.setattr(httputil, "fetch", lambda url, **k: httputil.Response(url, 200, [("Content-Type", "text/html")], POLICY.encode()))
    assert "mtasts.content-type" in ids(run(STS, {"domain": "example.test", "records": RECORDS, "fetch_policy": True}))


# ---- 060 network anomaly ---------------------------------------------------------------------
ANOM = "cyberscan.network.anomaly-analyzer"


def _baseline():
    return [{"ts": i * 37 % 3600, "src": f"10.0.0.{10 + i % 20}", "dst": "93.184.216.34", "dport": 443,
             "bytes_out": 2000 + (i * 97) % 500} for i in range(200)]


def test_060_quiet_network_is_clean(run):
    result = run(ANOM, {"flows": _baseline()})
    assert result["classification"] == "clean", result["findings"]


def test_060_beacon_exfil_and_sweep(run):
    flows = _baseline()
    flows += [{"ts": 1000 + i * 60, "src": "10.0.0.99", "dst": "203.0.113.50", "dport": 8443, "bytes_out": 300} for i in range(20)]
    flows += [{"ts": 5000, "src": "10.0.0.15", "dst": "198.51.100.9", "dport": 443, "bytes_out": 300 * 1024 * 1024}]
    flows += [{"ts": 6000, "src": "10.0.0.66", "dst": f"10.0.1.{i}", "dport": 445, "conn_state": "S0"} for i in range(60)]
    found = ids(run(ANOM, {"flows": flows}))
    assert {"beacon.periodic", "volume.large-egress", "volume.outlier", "scan.hosts"} <= found


def test_060_csv_and_zeek_inputs(run):
    csv_text = "ts,src,dst,dport,bytes_out\n" + "\n".join(f"{i},10.0.0.1,10.0.0.2,21,10" for i in range(3))
    assert "cleartext.ftp" in ids(run(ANOM, {"content": csv_text}))
    zeek = ("#separator \\x09\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_bytes\tresp_bytes\tconn_state\n"
            "1.0\t10.0.0.1\t5000\t10.0.0.2\t23\ttcp\t10\t20\tSF\n")
    result = run(ANOM, {"content": zeek})
    assert result["metadata"]["input_kind"] == "zeek" and "cleartext.telnet" in ids(result)
    assert run(ANOM, {"content": "[1, 2]"})["status"] == "invalid_input"
