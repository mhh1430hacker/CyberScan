"""Authenticode facts for the EMBER2024 feature vector, read with a small DER reader.

EMBER2024's feature extractor (thrember, Apache-2.0) reads the embedded Authenticode
signature with ``signify`` (MIT), which needs asn1crypto/oscrypto/certvalidator. Those are not
on the website's Lambda package or in the phone's Pyodide bundle, so this module reproduces
the few facts the model uses, following signify 0.7's parsing rules:

* the certificate table is located and walked exactly as ``signify.authenticode.SignedPEFile``
  does (``get_authenticode_omit_sections`` / ``_parse_cert_table``); a problem there is
  silent (signify's ``ignore_parse_errors=True``);
* each WIN_CERT_TYPE_PKCS_SIGNED_DATA entry is parsed with the same structural checks
  (one digest algorithm from md5/sha1/sha256/sha384/sha512, SpcIndirectDataContent with
  SpcPeImageData, exactly one SignerInfo, no CRLs, at most one opus info / timestamp /
  countersignature, nested signatures that are SignedData) â€” a failure raises
  :class:`SignatureParseError`, which the caller turns into ``parse_error = 1``;
* nested signatures (1.3.6.1.4.1.311.2.4.1) are yielded after their parent, depth first.

Nothing is verified (no hashes, no chains, no clock): these are file facts, not trust.
Names are compared as DER bytes (signify compares parsed RDN tuples; equal DER gives equal
tuples, and the reverse differs only for names that use different string encodings).
"""
from __future__ import annotations

import calendar
import re
import struct
from dataclasses import dataclass, field

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
OID_SPC_PE_IMAGE_DATA = "1.3.6.1.4.1.311.2.1.15"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_COUNTER_SIGNATURE = "1.2.840.113549.1.9.6"
OID_SPC_STATEMENT_TYPE = "1.3.6.1.4.1.311.2.1.11"
OID_SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_MS_TIMESTAMP_TOKEN = "1.3.6.1.4.1.311.3.3.1"
ACCEPTED_DIGESTS = {
    "1.2.840.113549.2.5",        # md5
    "1.3.14.3.2.26",             # sha1
    "2.16.840.1.101.3.4.2.1",    # sha256
    "2.16.840.1.101.3.4.2.2",    # sha384
    "2.16.840.1.101.3.4.2.3",    # sha512
}
MAX_DEPTH = 96        # nesting of DER structures (nested signatures go deep)
MAX_NESTED = 16       # nested signatures followed


class SignatureParseError(ValueError):
    """The signature is there but does not parse the way signify expects."""


# ------------------------------------------------------------------ a minimal DER/BER reader
@dataclass
class Node:
    cls: int            # 0 universal, 1 application, 2 context, 3 private
    constructed: bool
    tag: int
    raw: bytes          # the whole TLV
    body: bytes         # the contents
    children: list["Node"] = field(default_factory=list)


def _read(buf: bytes, pos: int, end: int, depth: int) -> tuple[Node, int]:
    if depth > MAX_DEPTH:
        raise SignatureParseError("structure nested too deeply")
    if pos + 2 > end:
        raise SignatureParseError("truncated")
    first = buf[pos]
    cls, constructed, tag = first >> 6, bool(first & 0x20), first & 0x1F
    p = pos + 1
    if tag == 0x1F:
        tag = 0
        while True:
            if p >= end:
                raise SignatureParseError("truncated tag")
            byte = buf[p]
            p += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
    if p >= end:
        raise SignatureParseError("truncated length")
    length = buf[p]
    p += 1
    if length == 0x80:                       # BER indefinite length: children up to 00 00
        if not constructed:
            raise SignatureParseError("indefinite primitive")
        children, q = [], p
        while True:
            if q + 2 > end:
                raise SignatureParseError("unterminated indefinite length")
            if buf[q] == 0 and buf[q + 1] == 0:
                break
            child, q = _read(buf, q, end, depth + 1)
            children.append(child)
        node = Node(cls, constructed, tag, buf[pos:q + 2], buf[p:q], children)
        return node, q + 2
    if length & 0x80:
        count = length & 0x7F
        if count > 4 or p + count > end:
            raise SignatureParseError("bad length")
        length = int.from_bytes(buf[p:p + count], "big")
        p += count
    if p + length > end:
        raise SignatureParseError("length beyond data")
    node = Node(cls, constructed, tag, buf[pos:p + length], buf[p:p + length])
    if constructed:
        q = p
        while q < p + length:
            child, q = _read(buf, q, p + length, depth + 1)
            node.children.append(child)
    return node, p + length


def parse_der(data: bytes) -> Node:
    node, _ = _read(data, 0, len(data), 0)
    return node


def _oid(node: Node) -> str:
    if node.cls != 0 or node.tag != 6 or not node.body:
        raise SignatureParseError("expected an OID")
    body = node.body
    parts, value = [], 0
    for byte in body:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    first = parts[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(x) for x in head + parts[1:])


def _universal(node: Node, tag: int) -> bool:
    return node.cls == 0 and node.tag == tag


def _seq(node: Node, what: str) -> list[Node]:
    if not (_universal(node, 16) and node.constructed):
        raise SignatureParseError(f"{what}: expected a SEQUENCE")
    return node.children


_UTC_TIME = re.compile(rb"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?()(Z|[+-]\d{4})?$")
_GENERALIZED_TIME = re.compile(rb"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?(Z|[+-]\d{4})?$")


def _time(node: Node) -> float:
    """UTCTime / GeneralizedTime as a POSIX timestamp (what datetime.timestamp() gives)."""
    if node.cls != 0 or node.tag not in (23, 24):
        raise SignatureParseError("bad time")
    match = (_UTC_TIME if node.tag == 23 else _GENERALIZED_TIME).match(node.body)
    if not match:
        raise SignatureParseError("bad time")
    year = int(match.group(1))
    if node.tag == 23:
        year += 2000 if year < 50 else 1900
    seconds = calendar.timegm((year, int(match.group(2)), int(match.group(3)), int(match.group(4)),
                               int(match.group(5)), int(match.group(6) or 0)))
    zone = match.group(8) or b"Z"
    if zone != b"Z":
        sign = 1 if zone[:1] == b"+" else -1
        seconds -= sign * (int(zone[1:3]) * 3600 + int(zone[3:5]) * 60)
    fraction = match.group(7)
    if fraction:
        micro = int((fraction + b"000000")[:6])   # datetime keeps microseconds
        return seconds + micro / 1_000_000
    return float(seconds)


# ------------------------------------------------------------------ CMS / Authenticode structures
@dataclass
class SignedFacts:
    certificates: list[tuple[bytes, bytes]]     # (issuer DER, subject DER) per certificate, in order
    program_name_present: bool
    countersigner_time: float | None             # None: no countersigner
    has_countersigner: bool
    nested: list["SignedFacts"]


def _content_info(node: Node) -> tuple[str, Node | None]:
    parts = _seq(node, "ContentInfo")
    if not parts:
        raise SignatureParseError("empty ContentInfo")
    content = None
    if len(parts) > 1:
        explicit = parts[1]
        if explicit.cls != 2 or explicit.tag != 0 or not explicit.children:
            raise SignatureParseError("ContentInfo content")
        content = explicit.children[0]
    return _oid(parts[0]), content


def _digest_ok(algorithm: Node, where: str) -> None:
    parts = _seq(algorithm, where)
    if not parts or _oid(parts[0]) not in ACCEPTED_DIGESTS:
        raise SignatureParseError(f"{where}: unsupported digest")
    if len(parts) > 1 and not _universal(parts[1], 5):      # parameters other than NULL
        raise SignatureParseError(f"{where}: unexpected parameters")


def _attributes(node: Node | None) -> dict[str, list[Node]]:
    if node is None:
        return {}
    result: dict[str, list[Node]] = {}
    for attr in node.children:
        parts = _seq(attr, "Attribute")
        if len(parts) < 2 or not (_universal(parts[1], 17) and parts[1].constructed):
            raise SignatureParseError("Attribute values")
        result[_oid(parts[0])] = list(parts[1].children)      # duplicates: the last one wins (as signify)
    return result


@dataclass
class _Signer:
    signed: dict[str, list[Node]]
    unsigned: dict[str, list[Node]]


def _signer_info(node: Node, required: tuple[str, ...]) -> _Signer:
    parts = _seq(node, "SignerInfo")
    if len(parts) < 5:
        raise SignatureParseError("SignerInfo too short")
    sid = parts[1]
    if not _universal(sid, 16):                 # [0] subjectKeyIdentifier is refused by signify
        raise SignatureParseError("SignerInfo.sid is not IssuerAndSerialNumber")
    rest = parts[2:]
    _digest_ok(rest[0], "SignerInfo.digestAlgorithm")
    signed_node = unsigned_node = None
    index = 1
    if index < len(rest) and rest[index].cls == 2 and rest[index].tag == 0:
        signed_node = rest[index]
        index += 1
    index += 2                                  # signatureAlgorithm, signature
    if index < len(rest) and rest[index].cls == 2 and rest[index].tag == 1:
        unsigned_node = rest[index]
    signed, unsigned = _attributes(signed_node), _attributes(unsigned_node)
    if not all(oid in signed for oid in required):
        raise SignatureParseError("required authenticated attributes missing")
    for oid in (OID_MESSAGE_DIGEST, OID_CONTENT_TYPE, OID_SIGNING_TIME):
        if oid in signed and len(signed[oid]) != 1:
            raise SignatureParseError("attribute must have exactly one value")
    if OID_COUNTER_SIGNATURE in unsigned and len(unsigned[OID_COUNTER_SIGNATURE]) != 1:
        raise SignatureParseError("one countersignature expected")
    return _Signer(signed, unsigned)


def _signed_data(node: Node, expected_content: str) -> tuple[list[Node], Node, list[_Signer], Node | None, bool]:
    """(certificate nodes, encapsulated content, signer infos, crls?, ...)"""
    parts = _seq(node, "SignedData")
    if len(parts) < 4:
        raise SignatureParseError("SignedData too short")
    digests = parts[1]
    if not (_universal(digests, 17) and len(digests.children) == 1):
        raise SignatureParseError("SignedData.digestAlgorithms must contain exactly 1 algorithm")
    _digest_ok(digests.children[0], "SignedData.digestAlgorithm")
    content_type, content = _content_info(parts[2])
    if content_type != expected_content:
        raise SignatureParseError(f"SignedData content {content_type}, expected {expected_content}")
    certificates: list[Node] = []
    crls = None
    signer_set = None
    for item in parts[3:]:
        if item.cls == 2 and item.tag == 0:
            certificates = [c for c in item.children if _universal(c, 16)]
        elif item.cls == 2 and item.tag == 1:
            crls = item
        elif _universal(item, 17):
            signer_set = item
    if signer_set is None:
        raise SignatureParseError("SignedData.signerInfos missing")
    if content is not None and content.cls == 0 and content.tag == 4 and not content.children:
        try:   # an OCTET STRING wrapping the TSTInfo (RFC 3161)
            content = parse_der(content.body)
        except SignatureParseError:
            pass
    return certificates, content, list(signer_set.children), crls, True


def _names(cert: Node) -> tuple[bytes, bytes]:
    parts = _seq(cert, "Certificate")
    tbs = _seq(parts[0], "TBSCertificate")
    index = 1 if tbs and tbs[0].cls == 2 and tbs[0].tag == 0 else 0     # optional [0] version
    if len(tbs) < index + 5:
        raise SignatureParseError("TBSCertificate too short")
    issuer, subject = tbs[index + 2], tbs[index + 4]
    return issuer.raw, subject.raw


def _countersigner_time_pkcs9(node: Node) -> float:
    signer = _signer_info(node, (OID_CONTENT_TYPE, OID_SIGNING_TIME, OID_MESSAGE_DIGEST))
    return _time(signer.signed[OID_SIGNING_TIME][0])


def _rfc3161_time(content_info: Node) -> float:
    content_type, content = _content_info(content_info)
    if content_type != OID_SIGNED_DATA or content is None:
        raise SignatureParseError("RFC-3161 Timestamp does not contain SignedData structure")
    certificates, tst, signers, _crls, _ = _signed_data(content, OID_TST_INFO)
    for cert in certificates:
        _names(cert)
    for signer in signers:
        _signer_info(signer, (OID_CONTENT_TYPE, OID_MESSAGE_DIGEST))
    if tst is None:
        raise SignatureParseError("TSTInfo missing")
    fields = _seq(tst, "TSTInfo")
    if len(fields) < 5 or not _universal(fields[0], 2) or int.from_bytes(fields[0].body, "big") != 1:
        raise SignatureParseError("TSTInfo.version must be v1")
    imprint = _seq(fields[2], "MessageImprint")
    _digest_ok(imprint[0], "TSTInfo.messageImprint.hashAlgorithm")
    if len(signers) != 1:
        raise SignatureParseError("RFC3161 SignedData.signerInfos must contain exactly 1 signer")
    return _time(fields[4])


def authenticode_signed_data(node: Node, depth: int = 0) -> SignedFacts:
    """One Authenticode SignedData (the content of a ContentInfo), with its nested ones."""
    if depth > MAX_NESTED:
        raise SignatureParseError("too many nested signatures")
    certificates, content, signers, crls, _ = _signed_data(node, OID_SPC_INDIRECT_DATA)
    names = [_names(cert) for cert in certificates]
    if len(signers) != 1:
        raise SignatureParseError("SignedData.signerInfos must contain exactly 1 signer")
    signer = _signer_info(signers[0], (OID_CONTENT_TYPE, OID_MESSAGE_DIGEST))
    if OID_CONTENT_TYPE in signer.signed and _oid(signer.signed[OID_CONTENT_TYPE][0]) != OID_SPC_INDIRECT_DATA:
        raise SignatureParseError("unexpected SignerInfo content type")
    if OID_SPC_STATEMENT_TYPE in signer.signed and len(signer.signed[OID_SPC_STATEMENT_TYPE]) != 1:
        raise SignatureParseError("one SpcStatementType expected")
    has_countersigner, when = False, None
    if OID_COUNTER_SIGNATURE in signer.unsigned:
        has_countersigner = True
        when = _countersigner_time_pkcs9(signer.unsigned[OID_COUNTER_SIGNATURE][0])
    program_name = False
    if OID_SPC_SP_OPUS_INFO in signer.signed:
        values = signer.signed[OID_SPC_SP_OPUS_INFO]
        if len(values) != 1:
            raise SignatureParseError("one SpcSpOpusInfo expected")
        opus = _seq(values[0], "SpcSpOpusInfo")
        program_name = any(item.cls == 2 and item.tag == 0 for item in opus)
    nested = []
    for value in signer.unsigned.get(OID_NESTED_SIGNATURE, []):
        content_type, inner = _content_info(value)
        if content_type != OID_SIGNED_DATA or inner is None:
            raise SignatureParseError("Nested signature is not a SignedData structure")
        nested.append(authenticode_signed_data(inner, depth + 1))
    if OID_COUNTER_SIGNATURE in signer.unsigned and OID_MS_TIMESTAMP_TOKEN in signer.unsigned:
        raise SignatureParseError("Countersignature and RFC-3161 timestamp both present")
    if OID_MS_TIMESTAMP_TOKEN in signer.unsigned:
        tokens = signer.unsigned[OID_MS_TIMESTAMP_TOKEN]
        if len(tokens) != 1:
            raise SignatureParseError("one RFC-3161 timestamp expected")
        has_countersigner, when = True, _rfc3161_time(tokens[0])
    # SpcIndirectDataContent.data.type must be SpcPeImageData
    if content is None:
        raise SignatureParseError("SpcIndirectDataContent missing")
    spc = _seq(content, "SpcIndirectDataContent")
    if not spc or _oid(_seq(spc[0], "SpcAttributeTypeAndOptionalValue")[0]) != OID_SPC_PE_IMAGE_DATA:
        raise SignatureParseError("SpcInfo does not contain SpcPeImageData")
    if crls is not None and crls.children:
        raise SignatureParseError("SignedData.crls is present")
    return SignedFacts(names, program_name, when, has_countersigner, nested)


# ------------------------------------------------------------------ the PE certificate table
def _cert_table(data: bytes) -> tuple[int, int] | None:
    """(offset, size) of the certificate table, by signify's rules; None when there is none."""
    length = len(data)
    if data[:2] != b"MZ" or length < 0x40:
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset >= length or data[pe_offset:pe_offset + 4] != b"PE\0\0" or pe_offset + 22 > length:
        return None
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    if optional_size + optional_offset > length or optional_size < 68:
        return None
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        rva_base, cert_base = optional_offset + 92, optional_offset + 128
    elif magic == 0x20B:
        rva_base, cert_base = optional_offset + 108, optional_offset + 144
    else:
        return None
    if optional_offset + optional_size < rva_base + 4:
        return None
    if struct.unpack_from("<I", data, rva_base)[0] < 5:
        return None
    if optional_offset + optional_size < cert_base + 8:
        return None
    address, size = struct.unpack_from("<II", data, cert_base)
    if not size or address < optional_size + optional_offset or address + size > length:
        return None
    return address, size


def iter_signed(data: bytes):
    """SignedFacts for every signature in the file, nested ones after their parent.

    Raises SignatureParseError for a signature that is present but malformed (signify's
    AuthenticodeParseError / ParseError); problems with the table itself end silently."""
    table = _cert_table(data)
    if table is None:
        return
    position, end = table[0], table[0] + table[1]
    found = False
    while position < end:
        if position + 8 > len(data):
            return
        length, revision, kind = struct.unpack_from("<IHH", data, position)
        if length <= 8 or position + length > end:
            return
        if revision != 0x200:
            return
        if kind == 2:
            content_type, content = _content_info(parse_der(data[position + 8:position + length]))
            if content_type != OID_SIGNED_DATA or content is None:
                raise SignatureParseError("ContentInfo does not contain SignedData")
            stack = [authenticode_signed_data(content)]
            while stack:
                facts = stack.pop(0)
                yield facts
                stack[0:0] = facts.nested
            found = True
        position += length + (8 - length % 8) % 8
    if not found:
        return


def signature_features(data: bytes, pe_timestamp: int) -> dict:
    """The raw ``authenticode`` object of EMBER2024's AuthenticodeSignature feature."""
    raw = {"num_certs": 0, "self_signed": 0, "empty_program_name": 0, "no_countersigner": 0,
           "parse_error": 0, "chain_max_depth": 0, "latest_signing_time": 0, "signing_time_diff": 0}
    try:
        for facts in iter_signed(data):
            raw["num_certs"] += 1
            if not facts.program_name_present:
                raw["empty_program_name"] = 1
            if facts.has_countersigner and facts.countersigner_time is not None:
                if facts.countersigner_time >= raw["latest_signing_time"]:
                    raw["latest_signing_time"] = facts.countersigner_time
                raw["signing_time_diff"] = facts.countersigner_time - pe_timestamp
            else:
                raw["no_countersigner"] = 1
            if len(facts.certificates) > raw["chain_max_depth"]:
                raw["chain_max_depth"] = len(facts.certificates)
            for issuer, subject in facts.certificates[:-1]:
                if issuer == subject:
                    raw["self_signed"] = 1
    except (SignatureParseError, IndexError, ValueError, struct.error):
        raw["parse_error"] = 1
    return raw
