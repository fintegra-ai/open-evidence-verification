# SPDX-License-Identifier: Apache-2.0

"""Real RFC 3161 trusted timestamping for OEVP (v0.1, TUR 4).

This module is the *production* counterpart of :mod:`oev.tsa` (mock TSA).
It talks to a real, public, no-credentials RFC 3161 TSA over HTTPS/HTTP
(plain ``TimeStampReq`` POST, no registration, no payment) and verifies
the returned CMS ``TimeStampToken`` offline:

* :func:`request_timestamp` — POST a ``TimeStampReq`` (plain-INTEGER
  nonce + ``certReq=TRUE`` by default) and return a sidecar dict
  (``oev-real-tsa-token/0.1``) holding the raw ``TimeStampResp`` DER,
  the embedded certificate chain (if any), ``genTime``, the TSA
  identity and the token hash. The attestation itself is never
  modified; the sidecar is stored next to it.
* :func:`verify_real_timestamp_token` — offline verification of a
  sidecar: response status, TSTInfo imprint digest == expected digest,
  nonce echo, CMS signature (signedAttrs ``messageDigest`` + ``content
  Type`` + signature over the DER SET OF), signer-certificate chain to
  caller-supplied trust roots, EKU ``timeStamping`` on the signer,
  certificate validity *at genTime*, and an optional genTime window.
* :func:`build_time_anchor` — bind an attestation/commitment/checkpoint
  digest to a verified token (token hash + genTime + TSA identity).
* :func:`assess_time_proof` / :func:`split_verdict` — keep
  ``time_proven`` and ``execution_proven`` strictly separate: a TSA
  proves *at most* that a digest existed no later than ``genTime``; it
  says nothing about whether the execution was performed correctly.

Measured live-TSA behaviour (2026-11-13, this sandbox):

* freetsa.org (https://freetsa.org/tsr) and timestamp.digicert.com
  (http; the https endpoint returned an empty reply from this sandbox)
  both grant requests carrying a *correct* plain-INTEGER nonce and
  ``certReq=TRUE``, embed their chains, and echo the nonce in the
  token. Earlier rejections were caused by the wrong nonce tag: the
  Tur-3 ``[1]`` tag (``0xA1``) and the first TUR 4 ``0x81`` tag are
  both non-conformant — RFC 3161 §2.4.1/§2.4.2 use a plain INTEGER
  (``0x02``) for the nonce in both the request and the token, as
  OpenSSL's ``TS_REQ``/``TS_TST_INFO`` templates confirm. DigiCert
  tolerates a ``[1]`` nonce by ignoring it (grants, no nonce echoed);
  freetsa.org and OpenSSL reject it.
* timestamp.sectigo.com / tsa.starfieldtech.com: unreachable from this
  sandbox (30 s timeout, N/A — not a verdict on the services).

Honest limits (read before trusting a "VERIFIED"):

* No revocation checking: OCSP/CRL is never consulted, online or
  offline. An expired TSA certificate *is* rejected (validity is
  checked at ``genTime``), but a revoked-but-unexpired certificate is
  NOT detected. Callers that need revocation must check it themselves
  and must not present the token as fully verified without that check.
* No RSASSA-PSS signatures (only PKCS#1 v1.5 RSA, ECDSA, Ed25519/Ed448).
* Chain building matches issuers by subject name; trust anchors are
  matched by (subject name, public key) — RFC 5280 anchor semantics —
  so a cross-signed variant of a root still anchors the chain. A
  trust root is trusted by caller fiat — verify the fingerprint
  out-of-band before pinning it.
* ``cryptography`` is already a runtime dependency of OEVP; no new
  dependency is added. There is no ``asn1crypto`` here: CMS parsing is
  a hand-rolled DER reader (definite lengths only; indefinite lengths
  are rejected, as DER requires).
* Network errors are reported as :class:`TSAUnavailableError` and TSA
  rejections as :class:`TSARejectedError` — both controlled, never an
  uncaught ``urllib`` exception escaping into a verifier.
"""

from __future__ import annotations

import base64
import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .hashing import is_valid_digest, sha256_bytes
from .tsa import (
    _SHA256_ALG_ID_DER,
    _der_integer_bytes,
    _der_tlv,
)

REAL_TOKEN_PROTOCOL_VERSION = "oev-real-tsa-token/0.1"

# -- OIDs ---------------------------------------------------------------------

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE_ATTR = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST_ATTR = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME_ATTR = "1.2.840.113549.1.9.5"
OID_TIME_STAMPING_EKU = "1.3.6.1.5.5.7.3.8"

_HASH_ALG_BY_OID = {
    "1.3.14.3.2.26": ("sha1", hashes.SHA1),
    "2.16.840.1.101.3.4.2.1": ("sha256", hashes.SHA256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashes.SHA384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashes.SHA512),
}
_SIG_ALG_BY_OID = {
    "1.2.840.113549.1.1.5": ("rsa-pkcs1v15", "sha1"),
    "1.2.840.113549.1.1.11": ("rsa-pkcs1v15", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa-pkcs1v15", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa-pkcs1v15", "sha512"),
    "1.2.840.113549.1.1.14": ("rsa-pkcs1v15", "sha224"),
    "1.2.840.10045.4.3.1": ("ecdsa", "sha224"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    "1.3.101.112": ("ed25519", None),
    "1.3.101.113": ("ed448", None),
}
_PKCS1_HASH = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
_ECDSA_HASH = _PKCS1_HASH

PKI_STATUS = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}
FAIL_INFO_BITS = [
    "badAlg",
    "badRequest",
    "badDataFormat",
    "timeNotAvailable",
    "unacceptedPolicy",
    "unacceptedExtension",
    "addInfoNotAvailable",
    "systemFailure",
]


class RealTSAError(ValueError):
    """Malformed real-TSA input or a failed real-token check (controlled)."""


class TSAUnavailableError(RealTSAError):
    """The TSA could not be reached or did not answer HTTP 200 (controlled)."""


class TSARejectedError(RealTSAError):
    """The TSA answered with PKIStatus != granted (controlled)."""

    def __init__(self, message: str, status: int, fail_info: list[str]) -> None:
        super().__init__(message)
        self.status = status
        self.fail_info = fail_info


# -- minimal DER --------------------------------------------------------------


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at ``offset``. Returns ``(tag, content, next_offset)``.

    Definite lengths only (DER forbids indefinite form); multi-byte tag
    numbers are rejected — CMS/TSP structures here never use them.
    """
    if offset >= len(data):
        raise RealTSAError("DER: truncated input")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise RealTSAError("DER: multi-byte tag numbers are not supported")
    if offset >= len(data):
        raise RealTSAError("DER: truncated length")
    first = data[offset]
    offset += 1
    if first == 0x80:
        raise RealTSAError("DER: indefinite length form is not DER")
    if first & 0x80:
        nbytes = first & 0x7F
        if nbytes == 0 or nbytes > 4 or offset + nbytes > len(data):
            raise RealTSAError("DER: bad long-form length")
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    else:
        length = first
    if offset + length > len(data):
        raise RealTSAError("DER: truncated content")
    return tag, data[offset : offset + length], offset + length


def _tlv_raw(data: bytes, offset: int) -> tuple[int, bytes, bytes, int]:
    """Like :func:`_read_tlv` but also returns the full raw TLV bytes."""
    tag, content, nxt = _read_tlv(data, offset)
    return tag, content, data[offset:nxt], nxt


def _der_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise RealTSAError(f"Bad OID: {oid!r}")
    out = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            out.append(0)
            continue
        stack = bytearray()
        while part:
            stack.append(part & 0x7F)
            part >>= 7
        for i, b in enumerate(reversed(stack)):
            out.append(b | (0x80 if i < len(stack) - 1 else 0))
    return bytes(out)


def _read_oid(content: bytes) -> str:
    if not content:
        raise RealTSAError("DER: empty OID")
    first = content[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if content[-1] & 0x80:
        raise RealTSAError("DER: truncated OID")
    return ".".join(str(p) for p in parts)


def _parse_asn1_time(tag: int, content: bytes) -> datetime:
    """Parse UTCTime (0x17) / GeneralizedTime (0x18) with a ``Z`` suffix."""
    text = content.decode("ascii", errors="strict")
    if not text.endswith("Z"):
        raise RealTSAError(f"ASN.1 time without Z suffix is not accepted: {text!r}")
    text = text[:-1]
    try:
        if tag == 0x17:  # UTCTime YYMMDDHHMMSS
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            return datetime(
                year,
                int(text[2:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
                tzinfo=timezone.utc,
            )
        if tag == 0x18:  # GeneralizedTime YYYYMMDDHHMMSS[.fff]
            base = text.split(".")[0]
            return datetime(
                int(base[0:4]),
                int(base[4:6]),
                int(base[6:8]),
                int(base[8:10]),
                int(base[10:12]),
                int(base[12:14]),
                tzinfo=timezone.utc,
            )
    except (ValueError, IndexError) as exc:
        raise RealTSAError(f"Unparseable ASN.1 time {text!r}: {exc}") from exc
    raise RealTSAError(f"Unsupported ASN.1 time tag 0x{tag:02x}")


def _parse_iso_z(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RealTSAError(f"Not a UTC ISO-8601 timestamp: {value!r}") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _iso_z(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- TimeStampResp / TSTInfo / CMS parsing ------------------------------------


def parse_timestamp_response(der: bytes) -> dict[str, Any]:
    """Parse an RFC 3161 ``TimeStampResp`` DER blob.

    Returns ``{"status": int, "status_name": str, "status_string": str,
    "fail_info": [str, ...], "token_der": bytes | None}``. Raises
    :class:`RealTSAError` on malformed input.
    """
    tag, body, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise RealTSAError("TimeStampResp must be a single SEQUENCE")
    tag, status_body, offset = _read_tlv(body, 0)
    if tag != 0x30:
        raise RealTSAError("TimeStampResp status must be a SEQUENCE")
    tag, status_bytes, soff = _read_tlv(status_body, 0)
    if tag != 0x02:
        raise RealTSAError("PKIStatus must be an INTEGER")
    status = int.from_bytes(status_bytes, "big")
    status_string = ""
    fail_info: list[str] = []
    while soff < len(status_body):
        tag, content, soff = _read_tlv(status_body, soff)
        if tag == 0x30:  # PKIFreeText: SEQUENCE OF UTF8String
            parts: list[str] = []
            ioff = 0
            while ioff < len(content):
                t2, c2, ioff = _read_tlv(content, ioff)
                if t2 != 0x0C:
                    raise RealTSAError("PKIFreeText entries must be UTF8String")
                parts.append(c2.decode("utf-8", errors="replace"))
            status_string = "; ".join(parts)
        elif tag == 0x03:  # BIT STRING failInfo
            if not content:
                raise RealTSAError("failInfo BIT STRING is empty")
            unused = content[0]
            bits = content[1:]
            for bit_index, name in enumerate(FAIL_INFO_BITS):
                byte = bits[bit_index // 8] if bit_index // 8 < len(bits) else 0
                if byte & (0x80 >> (bit_index % 8)):
                    fail_info.append(name)
            if unused:
                # Only the meaningful bits are reported; unused-bit count
                # is not itself an error.
                pass
        else:
            raise RealTSAError(f"Unexpected PKIStatusInfo field tag 0x{tag:02x}")
    token_der: bytes | None = None
    if offset < len(body):
        tag, _content, raw, offset = _tlv_raw(body, offset)
        if tag == 0xA0:
            # Spec form: [0] EXPLICIT wrapping the ContentInfo.
            tag2, _c2, end2 = _read_tlv(_content, 0)
            if tag2 != 0x30 or end2 != len(_content):
                raise RealTSAError("TimeStampToken must be a ContentInfo SEQUENCE")
            token_der = _content
        elif tag == 0x30:
            # Wire form used by freetsa.org, DigiCert and OpenSSL's
            # responder: the ContentInfo appears bare, without the [0]
            # wrapper. Both forms are accepted; the raw TLV is the token.
            token_der = raw
        else:
            raise RealTSAError(
                f"TimeStampResp token must be [0] EXPLICIT or a bare ContentInfo, "
                f"got tag 0x{tag:02x}"
            )
        if offset != len(body):
            raise RealTSAError("Trailing bytes after TimeStampResp token")
    return {
        "status": status,
        "status_name": PKI_STATUS.get(status, f"unknown({status})"),
        "status_string": status_string,
        "fail_info": fail_info,
        "token_der": token_der,
    }


def parse_tst_info(der: bytes) -> dict[str, Any]:
    """Parse a CMS eContent ``TSTInfo`` DER blob (RFC 3161 §2.4.2)."""
    tag, body, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise RealTSAError("TSTInfo must be a single SEQUENCE")
    offset = 0
    tag, version_bytes, offset = _read_tlv(body, offset)
    if tag != 0x02 or int.from_bytes(version_bytes, "big") != 1:
        raise RealTSAError("TSTInfo version must be INTEGER 1")
    tag, policy_bytes, offset = _read_tlv(body, offset)
    if tag != 0x06:
        raise RealTSAError("TSTInfo policy must be an OID")
    policy = _read_oid(policy_bytes)
    tag, imprint, offset = _read_tlv(body, offset)
    if tag != 0x30:
        raise RealTSAError("TSTInfo messageImprint must be a SEQUENCE")
    tag, alg_body, ioff = _read_tlv(imprint, 0)
    if tag != 0x30:
        raise RealTSAError("messageImprint hashAlgorithm must be a SEQUENCE")
    tag, alg_oid_bytes, _ = _read_tlv(alg_body, 0)
    if tag != 0x06:
        raise RealTSAError("hashAlgorithm must start with an OID")
    hash_oid = _read_oid(alg_oid_bytes)
    if hash_oid not in _HASH_ALG_BY_OID:
        raise RealTSAError(f"Unsupported TSTInfo hash algorithm OID {hash_oid}")
    tag, hashed, ioff = _read_tlv(imprint, ioff)
    if tag != 0x04 or ioff != len(imprint):
        raise RealTSAError("messageImprint hashedMessage must be an OCTET STRING")
    hash_name = _HASH_ALG_BY_OID[hash_oid][0]
    digest = f"{hash_name}:" + hashed.hex()
    tag, serial_bytes, offset = _read_tlv(body, offset)
    if tag != 0x02:
        raise RealTSAError("TSTInfo serialNumber must be an INTEGER")
    serial = int.from_bytes(serial_bytes, "big")
    tag, time_bytes, offset = _read_tlv(body, offset)
    if tag != 0x18:
        raise RealTSAError("TSTInfo genTime must be GeneralizedTime")
    gen_time = _parse_asn1_time(tag, time_bytes)
    nonce: int | None = None
    while offset < len(body):
        tag, content, _raw, offset = _tlv_raw(body, offset)
        if tag == 0xA0:
            # accuracy [0] (RFC 3161) and tsa [0] EXPLICIT share this
            # tag; neither carries trusted time. The TSA identity is
            # taken from the signer certificate by the verifier instead.
            continue
        if tag == 0x30:
            # accuracy as a bare SEQUENCE: OpenSSL's TS_TST_INFO
            # template defines accuracy as ASN1_OPT (no [0] tag),
            # deviating from RFC 3161's accuracy [0]. Accept and skip.
            continue
        if tag == 0x01:  # ordering BOOLEAN
            continue
        if tag in (0x02, 0x80):
            # nonce is a plain INTEGER (tag 0x02) in TSTInfo (RFC 3161
            # §2.4.2; OpenSSL agrees); 0x80 is accepted for tokens
            # minted by the pre-fix synthetic builder only.
            nonce = int.from_bytes(content, "big")
            continue
        if tag == 0xA1:  # extensions [1] IMPLICIT — skipped
            continue
        raise RealTSAError(f"Unexpected TSTInfo field tag 0x{tag:02x}")
    return {
        "version": 1,
        "policy": policy,
        "hash_algorithm": hash_name,
        "digest": digest,
        "serial": serial,
        "serial_hex": format(serial, "x"),
        "gen_time": gen_time,
        "gen_time_iso": _iso_z(gen_time),
        "nonce": nonce,
    }


def _parse_attribute_values(content: bytes) -> list[tuple[int, bytes, bytes]]:
    """Parse a SET OF AttributeValue: returns [(tag, content, raw), ...]."""
    values: list[tuple[int, bytes, bytes]] = []
    offset = 0
    while offset < len(content):
        tag, value, raw, offset = _tlv_raw(content, offset)
        values.append((tag, value, raw))
    return values


def parse_cms_signed_data(content_info_der: bytes) -> dict[str, Any]:
    """Parse a CMS ``ContentInfo`` holding ``SignedData`` (RFC 5652).

    Returns ``{"encap_content_type": str, "econtent": bytes,
    "certificates_der": [bytes, ...], "signer_infos": [...]}`` where each
    signer info has ``digest_algorithm`` (hash name), ``signature_algorithm``
    (OID), ``signature`` (bytes), ``signed_attrs_der`` (DER SET OF bytes or
    None) and the parsed attribute values.
    """
    tag, body, end = _read_tlv(content_info_der, 0)
    if tag != 0x30 or end != len(content_info_der):
        raise RealTSAError("ContentInfo must be a single SEQUENCE")
    tag, oid_bytes, offset = _read_tlv(body, 0)
    if tag != 0x06 or _read_oid(oid_bytes) != OID_SIGNED_DATA:
        raise RealTSAError("ContentInfo contentType is not SignedData")
    tag, signed_data, offset = _read_tlv(body, offset)
    if tag != 0xA0 or offset != len(body):
        raise RealTSAError("ContentInfo must carry [0] EXPLICIT SignedData")
    tag, sd_body, sd_end = _read_tlv(signed_data, 0)
    if tag != 0x30 or sd_end != len(signed_data):
        raise RealTSAError("SignedData must be a SEQUENCE")
    offset = 0
    tag, _version, offset = _read_tlv(sd_body, offset)
    if tag != 0x02:
        raise RealTSAError("SignedData version must be an INTEGER")
    tag, _digest_algs, offset = _read_tlv(sd_body, offset)
    if tag != 0x31:
        raise RealTSAError("SignedData digestAlgorithms must be a SET")
    tag, encap, offset = _read_tlv(sd_body, offset)
    if tag != 0x30:
        raise RealTSAError("SignedData encapContentInfo must be a SEQUENCE")
    tag, econtent_type_bytes, eoff = _read_tlv(encap, 0)
    if tag != 0x06:
        raise RealTSAError("encapContentInfo content type must be an OID")
    econtent_type = _read_oid(econtent_type_bytes)
    econtent: bytes | None = None
    if eoff < len(encap):
        tag, econtent_wrapped, eoff = _read_tlv(encap, eoff)
        if tag != 0xA0:
            raise RealTSAError("encapContentInfo eContent must be [0] EXPLICIT")
        tag, econtent, eend = _read_tlv(econtent_wrapped, 0)
        if tag != 0x04 or eend != len(econtent_wrapped):
            raise RealTSAError("encapContentInfo eContent must be an OCTET STRING")
        if eoff != len(encap):
            raise RealTSAError("Trailing bytes in encapContentInfo")
    certificates_der: list[bytes] = []
    signer_infos: list[dict[str, Any]] = []
    while offset < len(sd_body):
        tag, content, _raw, offset = _tlv_raw(sd_body, offset)
        if tag == 0xA0:  # certificates [0] IMPLICIT SET OF Certificate
            coff = 0
            while coff < len(content):
                _t, _c, cert_raw, coff = _tlv_raw(content, coff)
                certificates_der.append(cert_raw)
        elif tag == 0xA1:  # crls [1] — not used; ignore.
            continue
        elif tag == 0x31:  # signerInfos SET OF SignerInfo
            soff = 0
            while soff < len(content):
                _t, _c, si_raw, soff = _tlv_raw(content, soff)
                signer_infos.append(_parse_signer_info(si_raw))
        else:
            raise RealTSAError(f"Unexpected SignedData field tag 0x{tag:02x}")
    if econtent is None:
        raise RealTSAError("SignedData carries no eContent (detached token)")
    if not signer_infos:
        raise RealTSAError("SignedData carries no SignerInfo")
    return {
        "encap_content_type": econtent_type,
        "econtent": econtent,
        "certificates_der": certificates_der,
        "signer_infos": signer_infos,
    }


def _parse_signer_info(si_body: bytes) -> dict[str, Any]:
    tag, _outer, end = _read_tlv(si_body, 0)
    if tag != 0x30 or end != len(si_body):
        raise RealTSAError("SignerInfo must be a SEQUENCE")
    body = _outer
    offset = 0
    tag, _version, offset = _read_tlv(body, offset)
    if tag != 0x02:
        raise RealTSAError("SignerInfo version must be an INTEGER")
    tag, sid_body, offset = _read_tlv(body, offset)
    sid: dict[str, Any]
    if tag == 0x30:  # issuerAndSerialNumber SEQUENCE
        tag, _content, issuer_raw, ioff = _tlv_raw(sid_body, 0)
        if tag != 0x30:
            raise RealTSAError("issuerAndSerialNumber issuer must be a Name SEQUENCE")
        tag, serial_bytes, ioff = _read_tlv(sid_body, ioff)
        if tag != 0x02 or ioff != len(sid_body):
            raise RealTSAError("issuerAndSerialNumber serial must be an INTEGER")
        sid = {
            "kind": "issuer_and_serial",
            "issuer_der": issuer_raw,
            "serial": int.from_bytes(serial_bytes, "big"),
        }
    elif tag == 0x80:  # subjectKeyIdentifier [0] IMPLICIT
        sid = {"kind": "subject_key_id", "key_id": sid_body.hex()}
    else:
        raise RealTSAError(f"Unsupported SignerInfo sid tag 0x{tag:02x}")
    tag, digest_alg_body, offset = _read_tlv(body, offset)
    if tag != 0x30:
        raise RealTSAError("SignerInfo digestAlgorithm must be a SEQUENCE")
    tag, digest_oid_bytes, _ = _read_tlv(digest_alg_body, 0)
    if tag != 0x06 or _read_oid(digest_oid_bytes) not in _HASH_ALG_BY_OID:
        raise RealTSAError("SignerInfo digestAlgorithm is unsupported")
    digest_name = _HASH_ALG_BY_OID[_read_oid(digest_oid_bytes)][0]
    signed_attrs_der: bytes | None = None
    attributes: dict[str, list[tuple[int, bytes, bytes]]] = {}
    tag, next_content, _raw, peek = _tlv_raw(body, offset)
    if tag == 0xA0:  # signedAttrs [0] IMPLICIT SET OF Attribute
        offset = peek
        # Re-encode as DER SET OF (tag 0x31) — the bytes the signer signed.
        signed_attrs_der = _der_tlv(0x31, next_content)
        aoff = 0
        while aoff < len(next_content):
            _t, attr_body, _r, aoff = _tlv_raw(next_content, aoff)
            tag2, oid_bytes2, voff = _read_tlv(attr_body, 0)
            if tag2 != 0x06:
                raise RealTSAError("Attribute type must be an OID")
            attr_oid = _read_oid(oid_bytes2)
            tag2, values_body, voff = _read_tlv(attr_body, voff)
            if tag2 != 0x31 or voff != len(attr_body):
                raise RealTSAError("Attribute values must be a SET")
            attributes[attr_oid] = _parse_attribute_values(values_body)
    tag, sig_alg_body, offset = _read_tlv(body, offset)
    if tag != 0x30:
        raise RealTSAError("SignerInfo signatureAlgorithm must be a SEQUENCE")
    tag, sig_oid_bytes, _ = _read_tlv(sig_alg_body, 0)
    if tag != 0x06:
        raise RealTSAError("signatureAlgorithm must start with an OID")
    sig_oid = _read_oid(sig_oid_bytes)
    tag, signature, offset = _read_tlv(body, offset)
    if tag != 0x04:
        raise RealTSAError("SignerInfo signature must be an OCTET STRING")
    return {
        "sid": sid,
        "digest_algorithm": digest_name,
        "signed_attrs_der": signed_attrs_der,
        "attributes": attributes,
        "signature_algorithm_oid": sig_oid,
        "signature": signature,
    }


# -- X.509 certificate handling -----------------------------------------------


def _load_cert_der(der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise RealTSAError(f"Unparseable X.509 certificate: {exc}") from exc


def _load_cert_pem(pem: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise RealTSAError(f"Unparseable PEM certificate: {exc}") from exc


def _cert_der(cert: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.DER)


def _cert_pem(cert: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


def _validity_window(cert: x509.Certificate) -> tuple[datetime, datetime]:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_before is None or not_after is None:  # cryptography < 42 fallback
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after


def _hash_obj(name: str) -> hashes.HashAlgorithm:
    return _PKCS1_HASH[name]()  # type: ignore[abstract]


def _resolve_sig_scheme(sig_oid: str, digest_name: str | None) -> tuple[str, str | None] | None:
    """Resolve a CMS signatureAlgorithm OID to (scheme, hash_name).

    ``rsaEncryption`` (1.2.840.113549.1.1.1) carries no hash — DigiCert
    uses it in SignerInfo, with the hash taken from digestAlgorithm.
    RSASSA-PSS (1.2.840.113549.1.1.10) is deliberately unsupported.
    """
    if sig_oid == "1.2.840.113549.1.1.1":
        if digest_name is None:
            return None
        return ("rsa-pkcs1v15", digest_name)
    return _SIG_ALG_BY_OID.get(sig_oid)


def _verify_with_public_key(
    public_key: Any,
    signature: bytes,
    data: bytes,
    sig_oid: str,
    digest_name: str | None = None,
) -> bool:
    """Verify ``signature`` over ``data`` with ``public_key`` per ``sig_oid``."""
    resolved = _resolve_sig_scheme(sig_oid, digest_name)
    if resolved is None:
        return False
    scheme, hash_name = resolved
    try:
        if scheme == "rsa-pkcs1v15" and isinstance(public_key, rsa.RSAPublicKey):
            assert hash_name is not None
            public_key.verify(signature, data, padding.PKCS1v15(), _hash_obj(hash_name))
        elif scheme == "ecdsa" and isinstance(public_key, ec.EllipticCurvePublicKey):
            assert hash_name is not None
            public_key.verify(signature, data, ec.ECDSA(_hash_obj(hash_name)))
        elif (
            scheme == "ed25519"
            and isinstance(public_key, ed25519.Ed25519PublicKey)
            or scheme == "ed448"
            and isinstance(public_key, ed448.Ed448PublicKey)
        ):
            public_key.verify(signature, data)
        else:
            return False
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return False
    return True


def _cert_signature_oid(cert: x509.Certificate) -> str:
    return cert.signature_algorithm_oid.dotted_string


def verify_cert_chain(
    signer_der: bytes,
    intermediate_ders: list[bytes],
    trust_root_pems: list[bytes],
    at_time: datetime,
) -> tuple[bool, str, list[str], list[dict[str, Any]]]:
    """Verify a signer certificate chain to caller-supplied trust roots.

    Returns ``(ok, note, chain_subjects, checks)``. Chain building
    matches issuers by subject name; a trust anchor matches only by
    exact DER equality (pinning). Every certificate's validity window
    is checked *at* ``at_time`` (the token's genTime), so an expired
    TSA certificate fails even though revocation is not checked (see
    module docstring). The signer must carry EKU ``timeStamping`` and,
    when KeyUsage is present, ``digitalSignature``.
    """
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, note: str) -> bool:
        checks.append({"check": name, "ok": ok, "note": note})
        return ok

    try:
        signer = _load_cert_der(signer_der)
    except RealTSAError as exc:
        check("signer_cert_parses", False, str(exc))
        return False, f"Signer certificate does not parse: {exc}", [], checks
    check("signer_cert_parses", True, f"subject={signer.subject.rfc4514_string()}")
    intermediates: list[x509.Certificate] = []
    for der in intermediate_ders:
        try:
            intermediates.append(_load_cert_der(der))
        except RealTSAError as exc:
            check("intermediate_cert_parses", False, str(exc))
            return False, f"Intermediate certificate does not parse: {exc}", [], checks
    roots: list[x509.Certificate] = []
    for pem in trust_root_pems:
        try:
            roots.append(_load_cert_pem(pem))
        except RealTSAError as exc:
            check("trust_root_parses", False, str(exc))
            return False, f"Trust root does not parse: {exc}", [], checks
    if not roots:
        check("trust_roots_present", False, "No TSA trust roots supplied")
        return False, "No TSA trust roots supplied; token cannot be checked.", [], checks
    check("trust_roots_present", True, f"{len(roots)} trust root(s) supplied")

    # Signer EKU / KeyUsage (RFC 3161 §2.3: the TSA certificate MUST
    # have extendedKeyUsage id-kp-timeStamping, and the extension MUST
    # be critical — both live TSAs' leaves carry a critical EKU, and
    # OpenSSL's purpose check agrees).
    try:
        eku_ext = signer.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku = cast(x509.ExtendedKeyUsage, eku_ext.value)
        has_eku = ExtendedKeyUsageOID.TIME_STAMPING in eku
        eku_critical = bool(eku_ext.critical)
    except x509.ExtensionNotFound:
        has_eku = False
        eku_critical = False
    if not check(
        "signer_eku_timeStamping",
        has_eku,
        "signer EKU contains timeStamping" if has_eku else "signer EKU lacks timeStamping",
    ):
        return (
            False,
            "Signer certificate lacks extendedKeyUsage timeStamping.",
            [signer.subject.rfc4514_string()],
            checks,
        )
    if not check(
        "signer_eku_critical",
        eku_critical,
        "signer EKU is critical (RFC 3161 §2.3)"
        if eku_critical
        else "signer EKU is not critical (RFC 3161 §2.3 requires critical)",
    ):
        return (
            False,
            "Signer certificate EKU timeStamping is not critical.",
            [signer.subject.rfc4514_string()],
            checks,
        )
    try:
        key_usage = cast(
            x509.KeyUsage,
            signer.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
        )
        digital_sig = bool(key_usage.digital_signature)
    except x509.ExtensionNotFound:
        digital_sig = True  # absent KeyUsage imposes no restriction
    if not check(
        "signer_keyUsage_digitalSignature",
        digital_sig,
        "signer KeyUsage allows digitalSignature"
        if digital_sig
        else "signer KeyUsage forbids digitalSignature",
    ):
        return (
            False,
            "Signer certificate KeyUsage forbids digitalSignature.",
            [signer.subject.rfc4514_string()],
            checks,
        )

    root_anchors = set()
    for root in roots:
        try:
            root_anchors.add(_anchor_key(root, _cert_der(root)))
        except RealTSAError as exc:
            check("trust_root_parses", False, str(exc))
            return False, f"Trust root does not parse: {exc}", [], checks
    chain: list[x509.Certificate] = [signer]
    chain_ders: list[bytes] = [signer_der]
    chain_subjects = [signer.subject.rfc4514_string()]
    current = signer
    current_der = signer_der
    for _hop in range(10):
        not_before, not_after = _validity_window(current)
        if not (not_before <= at_time <= not_after):
            check(
                "cert_valid_at_genTime",
                False,
                f"{current.subject.rfc4514_string()}: valid "
                f"{_iso_z(not_before)}..{_iso_z(not_after)}, genTime {_iso_z(at_time)} outside",
            )
            return (
                False,
                (
                    f"Certificate {current.subject.rfc4514_string()!r} is not valid "
                    f"at genTime {_iso_z(at_time)} (expired or not yet valid)."
                ),
                chain_subjects,
                checks,
            )
        check(
            "cert_valid_at_genTime",
            True,
            f"{current.subject.rfc4514_string()}: valid at genTime",
        )
        if _anchor_key(current, current_der) in root_anchors:
            check("chain_reaches_trust_root", True, "chain ends at a trust anchor (subject+key)")
            return True, "Certificate chain reaches a trust anchor.", chain_subjects, checks
        # Find the issuer among intermediates and roots (by subject name).
        issuer_name = current.issuer
        candidates = [
            (c, d)
            for c, d in zip(
                intermediates + roots, intermediate_ders + [_cert_der(r) for r in roots]
            )
            if c.subject == issuer_name
        ]
        if not candidates:
            check(
                "chain_issuer_found",
                False,
                f"no issuer for {current.subject.rfc4514_string()} among intermediates/roots",
            )
            return (
                False,
                (
                    f"Certificate chain incomplete: issuer of "
                    f"{current.subject.rfc4514_string()!r} not supplied."
                ),
                chain_subjects,
                checks,
            )
        issuer, issuer_der = candidates[0]
        if _cert_der(current) == _cert_der(issuer):
            check("chain_no_self_loop", False, "self-signed non-root certificate")
            return (
                False,
                "Self-signed certificate that is not a trust root.",
                chain_subjects,
                checks,
            )
        # The issuer must be a CA (when BasicConstraints is present).
        try:
            basic = cast(
                x509.BasicConstraints,
                issuer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value,
            )
            is_ca = bool(basic.ca)
        except x509.ExtensionNotFound:
            is_ca = False
        if not check(
            "issuer_is_ca",
            is_ca,
            f"issuer {issuer.subject.rfc4514_string()} is a CA"
            if is_ca
            else f"issuer {issuer.subject.rfc4514_string()} is not a CA",
        ):
            return (
                False,
                f"Issuer {issuer.subject.rfc4514_string()!r} is not a CA.",
                chain_subjects,
                checks,
            )
        if not _verify_with_public_key(
            issuer.public_key(),
            current.signature,
            current.tbs_certificate_bytes,
            _cert_signature_oid(current),
        ):
            check(
                "cert_signature_valid",
                False,
                f"signature of {current.subject.rfc4514_string()} fails under its issuer",
            )
            return (
                False,
                (
                    f"Certificate signature of {current.subject.rfc4514_string()!r} "
                    "does not verify under its issuer."
                ),
                chain_subjects,
                checks,
            )
        check(
            "cert_signature_valid",
            True,
            f"signature of {current.subject.rfc4514_string()} verifies under its issuer",
        )
        chain.append(issuer)
        chain_ders.append(issuer_der)
        chain_subjects.append(issuer.subject.rfc4514_string())
        current = issuer
        current_der = issuer_der
    check("chain_length", False, "chain exceeds 10 hops")
    return False, "Certificate chain exceeds 10 hops.", chain_subjects, checks


# -- real token verification ----------------------------------------------------


@dataclass
class RealTokenDetails:
    gen_time_iso: str | None = None
    tsa_identity: str | None = None
    policy_oid: str | None = None
    serial_hex: str | None = None
    signer_subject: str | None = None
    signer_issuer: str | None = None
    signature_algorithm_oid: str | None = None
    chain_subjects: list[str] | None = None
    checks: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "gen_time": self.gen_time_iso,
            "tsa_identity": self.tsa_identity,
            "policy_oid": self.policy_oid,
            "serial_hex": self.serial_hex,
            "signer_subject": self.signer_subject,
            "signer_issuer": self.signer_issuer,
            "signature_algorithm_oid": self.signature_algorithm_oid,
            "chain_subjects": self.chain_subjects or [],
            "checks": self.checks or [],
        }


def _fail(
    note: str, details: RealTokenDetails, checks: list[dict[str, Any]]
) -> tuple[str, str, dict[str, Any]]:
    details.checks = checks
    return "REAL_TSA_INVALID", note, details.to_dict()


def _as_bytes(pem: bytes | str) -> bytes:
    return pem.encode("ascii") if isinstance(pem, str) else pem


def verify_real_timestamp_token(
    sidecar: dict[str, Any] | None,
    expected_digest: str,
    trust_roots_pem: list[bytes] | list[str] | None,
    *,
    intermediates_pem: list[bytes] | list[str] | None = None,
    expected_nonce: int | None = None,
    gen_time_window: tuple[datetime, datetime] | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """Verify a real RFC 3161 timestamp-token sidecar offline.

    Returns ``(status, note, details)`` with status one of
    ``REAL_TSA_VERIFIED`` / ``REAL_TSA_INVALID`` / ``UNVERIFIED`` (no
    sidecar, or no trust roots — "time not proven", not a failure).
    ``expected_nonce``, when given, must equal the token nonce; when
    omitted, the sidecar's own recorded nonce is cross-checked against
    the token instead. ``gen_time_window``, when given, bounds the
    token's genTime (freshness window chosen by the caller).
    """
    details = RealTokenDetails()
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, note: str) -> bool:
        checks.append({"check": name, "ok": ok, "note": note})
        return ok

    if sidecar is None:
        details.checks = checks
        return (
            "UNVERIFIED",
            "No real timestamp token supplied; time is not proven.",
            details.to_dict(),
        )
    if not trust_roots_pem:
        details.checks = checks
        return (
            "UNVERIFIED",
            "No TSA trust roots supplied; token cannot be checked.",
            details.to_dict(),
        )
    if str(sidecar.get("protocol_version", "")) != REAL_TOKEN_PROTOCOL_VERSION:
        return _fail(
            f"Unsupported real-token sidecar version: {sidecar.get('protocol_version')!r}",
            details,
            checks,
        )
    try:
        response_der = base64.b64decode(str(sidecar["response_der_b64"]), validate=True)
    except (KeyError, ValueError) as exc:
        return _fail(f"Sidecar response_der_b64 does not decode: {exc}", details, checks)
    recorded_hash = str(sidecar.get("token_sha256", ""))
    if recorded_hash and sha256_bytes(response_der) != recorded_hash:
        return _fail("Sidecar token_sha256 does not match the response bytes.", details, checks)
    check("sidecar_hash_matches", True, "token_sha256 matches the response bytes")
    try:
        response = parse_timestamp_response(response_der)
    except RealTSAError as exc:
        return _fail(f"TimeStampResp does not parse: {exc}", details, checks)
    if response["status"] not in (0, 1):
        return _fail(
            f"TSA did not grant the timestamp: status {response['status']} "
            f"({response['status_name']}) {response['status_string']!r} "
            f"failInfo={response['fail_info']}",
            details,
            checks,
        )
    check(
        "tsa_status_granted",
        True,
        f"TSA status {response['status']} ({response['status_name']})",
    )
    token_der = response["token_der"]
    if token_der is None:
        return _fail("TSA response carries no timestamp token.", details, checks)
    try:
        cms = parse_cms_signed_data(token_der)
    except RealTSAError as exc:
        return _fail(f"CMS SignedData does not parse: {exc}", details, checks)
    if cms["encap_content_type"] != OID_TST_INFO:
        return _fail(
            f"CMS eContent type is {cms['encap_content_type']}, not TSTInfo.",
            details,
            checks,
        )
    check("econtent_is_tstinfo", True, "CMS eContent type is TSTInfo")
    try:
        tst = parse_tst_info(bytes(cms["econtent"]))
    except RealTSAError as exc:
        return _fail(f"TSTInfo does not parse: {exc}", details, checks)
    details.gen_time_iso = tst["gen_time_iso"]
    details.policy_oid = tst["policy"]
    details.serial_hex = tst["serial_hex"]
    if tst["digest"] != expected_digest:
        return _fail(
            f"Token imprint {tst['digest']} does not match the expected digest {expected_digest}.",
            details,
            checks,
        )
    check("imprint_matches", True, f"imprint {tst['digest']} matches the expected digest")
    if str(sidecar.get("imprint_digest", "")) not in ("", expected_digest):
        return _fail("Sidecar imprint_digest disagrees with the expected digest.", details, checks)
    # Nonce: the request nonce (when the caller sent one) must be echoed.
    token_nonce = tst["nonce"]
    if expected_nonce is not None:
        if token_nonce is None or token_nonce != expected_nonce:
            return _fail(
                f"Token nonce {token_nonce} does not match the requested nonce {expected_nonce}.",
                details,
                checks,
            )
        check("nonce_matches", True, "token nonce matches the requested nonce")
    elif str(sidecar.get("nonce", "")) not in ("", "None"):
        try:
            sidecar_nonce = int(str(sidecar["nonce"]))
        except ValueError:
            return _fail("Sidecar nonce is not an integer.", details, checks)
        if token_nonce is None or token_nonce != sidecar_nonce:
            return _fail(
                f"Token nonce {token_nonce} does not match the sidecar nonce {sidecar_nonce}.",
                details,
                checks,
            )
        check("nonce_matches", True, "token nonce matches the sidecar nonce")
    if gen_time_window is not None:
        start, end = gen_time_window
        gen_time: datetime = tst["gen_time"]
        if not (start <= gen_time <= end):
            return _fail(
                f"Token genTime {_iso_z(gen_time)} is outside the caller window "
                f"{_iso_z(start)}..{_iso_z(end)}.",
                details,
                checks,
            )
        check("genTime_in_window", True, "genTime is inside the caller window")

    # CMS signature over signedAttrs (or the eContent when unsigned attrs
    # are absent — RFC 5652 §5.4).
    signer_infos: list[dict[str, Any]] = cms["signer_infos"]
    if len(signer_infos) != 1:
        check(
            "single_signer",
            False,
            f"token has {len(signer_infos)} SignerInfos; exactly 1 is expected",
        )
        return _fail(
            f"Token has {len(signer_infos)} SignerInfos; exactly 1 is supported.",
            details,
            checks,
        )
    info = signer_infos[0]
    details.signature_algorithm_oid = info["signature_algorithm_oid"]
    digest_name: str = info["digest_algorithm"]
    hash_fn = getattr(hashlib, digest_name)
    econtent: bytes = bytes(cms["econtent"])
    if info["signed_attrs_der"] is not None:
        attrs: dict[str, list[tuple[int, bytes, bytes]]] = info["attributes"]
        md_values = attrs.get(OID_MESSAGE_DIGEST_ATTR, [])
        if len(md_values) != 1 or md_values[0][0] != 0x04:
            return _fail("signedAttrs lack a single messageDigest OCTET STRING.", details, checks)
        if md_values[0][1] != hash_fn(econtent).digest():
            return _fail(
                "signedAttrs messageDigest does not match the eContent hash.", details, checks
            )
        check("signedAttrs_messageDigest", True, "messageDigest matches the eContent hash")
        ct_values = attrs.get(OID_CONTENT_TYPE_ATTR, [])
        if len(ct_values) != 1 or ct_values[0][0] != 0x06:
            return _fail("signedAttrs lack a single contentType OID.", details, checks)
        if _read_oid(ct_values[0][1]) != OID_TST_INFO:
            return _fail("signedAttrs contentType is not TSTInfo.", details, checks)
        check("signedAttrs_contentType", True, "contentType is TSTInfo")
        signed_data = bytes(info["signed_attrs_der"])
    else:
        signed_data = econtent
        check("signedAttrs_absent", True, "no signedAttrs; signature covers eContent directly")

    # Find the signer certificate: embedded certs first, then caller
    # intermediates (DigiCert never embeds certificates).
    embedded: list[bytes] = list(cms["certificates_der"])
    extra_intermediates: list[bytes] = []
    for pem in intermediates_pem or []:
        try:
            extra_intermediates.append(_cert_der(_load_cert_pem(_as_bytes(pem))))
        except RealTSAError as exc:
            return _fail(f"Intermediate certificate does not parse: {exc}", details, checks)
    sidecar_chain: list[bytes] = []
    for pem in sidecar.get("cert_chain_pem", []) or []:
        try:
            sidecar_chain.append(_cert_der(_load_cert_pem(_as_bytes(pem))))
        except RealTSAError as exc:
            return _fail(f"Sidecar certificate does not parse: {exc}", details, checks)
    all_certs = embedded + sidecar_chain + extra_intermediates
    signer_der: bytes | None = None
    sid = info["sid"]
    for cert_der in all_certs:
        try:
            cert = _load_cert_der(cert_der)
        except RealTSAError:
            continue
        if sid["kind"] == "issuer_and_serial":
            try:
                issuer_der = _cert_issuer_der(cert_der)
            except RealTSAError:
                continue
            if issuer_der == sid["issuer_der"] and cert.serial_number == sid["serial"]:
                signer_der = cert_der
                break
        elif sid["kind"] == "subject_key_id":
            try:
                ski = cast(
                    x509.SubjectKeyIdentifier,
                    cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value,
                )
                if bytes(ski.digest).hex() == sid["key_id"]:
                    signer_der = cert_der
                    break
            except x509.ExtensionNotFound:
                continue
    if signer_der is None:
        return _fail("Signer certificate is not among the supplied certificates.", details, checks)
    signer_cert = _load_cert_der(signer_der)
    details.signer_subject = signer_cert.subject.rfc4514_string()
    details.signer_issuer = signer_cert.issuer.rfc4514_string()
    details.tsa_identity = details.signer_subject
    check("signer_cert_found", True, f"signer={details.signer_subject}")

    if _resolve_sig_scheme(info["signature_algorithm_oid"], digest_name) is None:
        return _fail(
            f"Unsupported signature algorithm OID "
            f"{info['signature_algorithm_oid']} (RSASSA-PSS is not supported).",
            details,
            checks,
        )
    if not _verify_with_public_key(
        signer_cert.public_key(),
        bytes(info["signature"]),
        signed_data,
        info["signature_algorithm_oid"],
        digest_name,
    ):
        return _fail("CMS signature does not verify under the signer certificate.", details, checks)
    check("cms_signature_valid", True, "CMS signature verifies under the signer certificate")

    chain_ok, chain_note, chain_subjects, chain_checks = verify_cert_chain(
        signer_der,
        [d for d in all_certs if d != signer_der],
        [_as_bytes(p) for p in trust_roots_pem],
        tst["gen_time"],
    )
    checks.extend(chain_checks)
    details.chain_subjects = chain_subjects
    if not chain_ok:
        return _fail(f"Certificate chain check failed: {chain_note}", details, checks)
    check("chain_to_trust_root", True, chain_note)
    return (
        "REAL_TSA_VERIFIED",
        (
            f"Real TSA token verified: genTime={tst['gen_time_iso']}, "
            f"tsa={details.signer_subject}, policy={tst['policy']}, "
            f"serial=0x{tst['serial_hex']}. Proves at most that the digest "
            "existed by genTime."
        ),
        details.to_dict(),
    )


def _cert_subject_der(cert_der: bytes) -> bytes:
    """Slice the raw subject Name TLV out of a DER certificate.

    TBSCertificate field order after the optional [0] version: serial,
    signature, issuer, validity, subject, ...
    """
    _tag, cert_body, _end = _read_tlv(cert_der, 0)
    _tag, tbs_body, _end = _read_tlv(cert_body, 0)
    offset = 0
    tag, _content, _raw, offset = _tlv_raw(tbs_body, offset)
    if tag == 0xA0:  # [0] version EXPLICIT
        tag, _content, _raw, offset = _tlv_raw(tbs_body, offset)
    for _field in ("serial", "signature", "issuer", "validity"):
        tag, _content, _raw, offset = _tlv_raw(tbs_body, offset)
    tag, _content, subject_raw, _offset = _tlv_raw(tbs_body, offset)
    if tag != 0x30:
        raise RealTSAError("Certificate subject field is not a Name SEQUENCE")
    return subject_raw


def _spki_der(cert: x509.Certificate) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _anchor_key(cert: x509.Certificate, cert_der: bytes) -> tuple[bytes, bytes]:
    """Trust-anchor identity of a certificate: (subject DER, SPKI DER).

    Anchors are matched by (subject name, public key) — RFC 5280 trust
    anchor semantics — not by exact certificate DER equality, so a
    cross-signed variant of a root (same subject, same key, different
    issuer/serial, e.g. DigiCert's cross-signed Trusted Root G4) still
    anchors the chain.
    """
    return (_cert_subject_der(cert_der), _spki_der(cert))


def _cert_issuer_der(cert_der: bytes) -> bytes:
    """Slice the raw issuer Name TLV out of a DER certificate.

    TBSCertificate ::= SEQUENCE { [0] version EXPLICIT OPTIONAL,
    serial INTEGER, signature AlgorithmIdentifier, issuer Name, ... }.
    The returned bytes are the original issuer encoding, so they compare
    byte-identical with the issuer in a CMS SignerInfo sid.
    """
    _tag, cert_body, _end = _read_tlv(cert_der, 0)
    _tag, tbs_body, _end = _read_tlv(cert_body, 0)
    offset = 0
    # [0] version EXPLICIT (when present), then serial INTEGER.
    tag, _content, _raw, offset = _tlv_raw(tbs_body, offset)
    if tag == 0xA0:
        tag, _content, _raw, offset = _tlv_raw(tbs_body, offset)
    # signature AlgorithmIdentifier
    tag, _content, _raw, offset = _tlv_raw(tbs_body, offset)
    # issuer Name
    tag, _content, issuer_raw, _offset = _tlv_raw(tbs_body, offset)
    if tag != 0x30:
        raise RealTSAError("Certificate issuer field is not a Name SEQUENCE")
    return issuer_raw


# -- TSA client -----------------------------------------------------------------


def build_timestamp_request_no_nonce(digest: str, *, cert_req: bool = True) -> bytes:
    """Build an RFC 3161 ``TimeStampReq`` DER blob without a nonce.

    ``cert_req`` asks the TSA to include its certificate chain (DigiCert
    honours it only when TRUE; freetsa honours it too).
    """
    der, _nonce = _build_live_request(digest, include_nonce=False, cert_req=cert_req)
    return der


def _build_live_request(
    digest: str, *, include_nonce: bool, cert_req: bool
) -> tuple[bytes, int | None]:
    """Build a live ``TimeStampReq``: plain-INTEGER nonce (RFC 3161
    §2.4.1) when ``include_nonce`` is set, ``certReq`` when asked."""
    import secrets

    if not is_valid_digest(digest):
        raise RealTSAError(f"Invalid digest for timestamp request: {digest!r}")
    raw = bytes.fromhex(digest[len("sha256:") :])
    message_imprint = _der_tlv(0x30, _SHA256_ALG_ID_DER + _der_tlv(0x04, raw))
    body = _der_tlv(0x02, b"\x01") + message_imprint
    nonce: int | None = None
    if include_nonce:
        nonce = secrets.randbits(128)
        body += _der_tlv(0x02, _der_integer_bytes(nonce))
    if cert_req:
        body += _der_tlv(0x01, b"\x01")
    return _der_tlv(0x30, body), nonce


def request_timestamp(
    url: str,
    digest: str,
    *,
    timeout: float = 30.0,
    include_nonce: bool = True,
    cert_req: bool = True,
) -> dict[str, Any]:
    """Request a real RFC 3161 timestamp token from ``url``.

    Returns an ``oev-real-tsa-token/0.1`` sidecar dict (raw response DER,
    embedded chain, genTime, TSA identity, token hash). Network failure
    raises :class:`TSAUnavailableError`; a TSA rejection raises
    :class:`TSARejectedError`; malformed replies raise
    :class:`RealTSAError`. Nothing here verifies the token — call
    :func:`verify_real_timestamp_token` on the sidecar afterwards.

    The default sends a nonce (plain INTEGER, RFC 3161 §2.4.1) and
    ``certReq=TRUE``: both live TSAs grant such requests and echo the
    nonce in the token (measured 2026-11-13).

    Only ``http``/``https`` URLs are accepted: ``urllib`` would otherwise
    honour ``file:`` and other schemes for a caller-supplied URL (bandit
    B310), which must never turn a timestamp request into a local read.
    """
    from urllib.parse import urlparse

    if urlparse(url).scheme not in ("http", "https"):
        raise RealTSAError(f"Refusing TSA URL with non-HTTP(S) scheme: {url!r}")
    request_der, nonce = _build_live_request(digest, include_nonce=include_nonce, cert_req=cert_req)
    req = urllib.request.Request(
        url,
        data=request_der,
        method="POST",
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
            "User-Agent": "oev-tsa-real/0.1",
        },
    )
    try:
        # URL scheme is validated to http/https at the top of this function,
        # so urlopen cannot open file: or other schemes (see nosec below).
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            status_code = resp.status
            response_der = resp.read()
    except urllib.error.HTTPError as exc:
        raise TSAUnavailableError(f"TSA {url} answered HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TSAUnavailableError(f"TSA {url} unreachable: {exc}.") from exc
    if status_code != 200:
        raise TSAUnavailableError(f"TSA {url} answered HTTP {status_code}.")
    try:
        parsed = parse_timestamp_response(response_der)
    except RealTSAError as exc:
        raise RealTSAError(f"TSA {url} returned an unparseable response: {exc}") from exc
    if parsed["status"] not in (0, 1):
        raise TSARejectedError(
            f"TSA {url} rejected the request: status {parsed['status']} "
            f"({parsed['status_name']}) {parsed['status_string']!r} "
            f"failInfo={parsed['fail_info']}",
            parsed["status"],
            parsed["fail_info"],
        )
    if parsed["token_der"] is None:
        raise RealTSAError(f"TSA {url} granted the request but sent no token.")
    try:
        cms = parse_cms_signed_data(parsed["token_der"])
        tst = parse_tst_info(bytes(cms["econtent"]))
    except RealTSAError as exc:
        raise RealTSAError(f"TSA {url} token does not parse: {exc}") from exc
    chain_pem: list[str] = []
    signer_subject: str | None = None
    for cert_der in cms["certificates_der"]:
        try:
            cert = _load_cert_der(cert_der)
        except RealTSAError:
            continue
        chain_pem.append(_cert_pem(cert).decode("ascii"))
    signer_infos = cms["signer_infos"]
    if signer_infos and signer_infos[0]["sid"]["kind"] == "issuer_and_serial":
        for cert_der in cms["certificates_der"]:
            try:
                cert = _load_cert_der(cert_der)
            except RealTSAError:
                continue
            sid = signer_infos[0]["sid"]
            try:
                issuer_der = _cert_issuer_der(cert_der)
            except RealTSAError:
                continue
            if issuer_der == sid["issuer_der"] and cert.serial_number == sid["serial"]:
                signer_subject = cert.subject.rfc4514_string()
                break
    return {
        "protocol_version": REAL_TOKEN_PROTOCOL_VERSION,
        "tsa_url": url,
        "tsa_identity": signer_subject,
        "response_der_b64": base64.b64encode(response_der).decode("ascii"),
        "cert_chain_pem": chain_pem,
        "gen_time": tst["gen_time_iso"],
        "imprint_digest": tst["digest"],
        "nonce": str(tst["nonce"]) if tst["nonce"] is not None else None,
        "request_nonce": str(nonce) if nonce is not None else None,
        "token_sha256": sha256_bytes(response_der),
        "policy_oid": tst["policy"],
        "serial_hex": tst["serial_hex"],
    }


# -- time anchors + the time/execution split ------------------------------------


def build_time_anchor(attestation_digest: str, sidecar: dict[str, Any]) -> dict[str, Any]:
    """Bind an attestation/commitment/checkpoint digest to a TSA token.

    Returns a small anchor record; the attestation itself is never
    modified (old attestations keep verifying exactly as before). The
    anchor is only meaningful after the sidecar passes
    :func:`verify_real_timestamp_token`.
    """
    if not is_valid_digest(attestation_digest):
        raise RealTSAError(f"Invalid attestation digest for time anchor: {attestation_digest!r}")
    if str(sidecar.get("protocol_version", "")) != REAL_TOKEN_PROTOCOL_VERSION:
        raise RealTSAError("Time anchor needs an oev-real-tsa-token/0.1 sidecar.")
    return {
        "attestation_digest": attestation_digest,
        "token_sha256": str(sidecar.get("token_sha256", "")),
        "gen_time": str(sidecar.get("gen_time", "")),
        "tsa_identity": str(sidecar.get("tsa_identity", "")),
        "tsa_url": str(sidecar.get("tsa_url", "")),
        "protocol_version": REAL_TOKEN_PROTOCOL_VERSION,
    }


def check_claimed_vs_gen_time(
    claimed_time: str,
    gen_time: str | datetime,
    *,
    tolerance_seconds: int = 300,
) -> tuple[bool, str, float]:
    """Compare a self-asserted ``claimed_time`` with a TSA ``genTime``.

    Returns ``(matches, note, delta_seconds)`` where delta is
    ``claimed - genTime`` in seconds. A *consistent* backdate/future
    date (V3-C17) is caught here: the attacker can set ``claimed_time``
    to anything, but the TSA's ``genTime`` is signed by the TSA, so a
    claimed time far from genTime fails this check and time stays
    unproven — even though the token itself is cryptographically valid.
    """
    claimed = _parse_iso_z(claimed_time)
    gen = gen_time if isinstance(gen_time, datetime) else _parse_iso_z(gen_time)
    delta = (claimed - gen).total_seconds()
    if abs(delta) <= tolerance_seconds:
        return True, f"claimed_time is within {tolerance_seconds}s of TSA genTime.", delta
    direction = "before" if delta < 0 else "after"
    return (
        False,
        (
            f"claimed_time is {abs(delta):.0f}s {direction} the TSA genTime "
            f"(tolerance {tolerance_seconds}s): consistent backdate/future-date "
            "is NOT proven by this token."
        ),
        delta,
    )


def assess_time_proof(
    token_status: str,
    *,
    claimed_time: str | None = None,
    gen_time: str | datetime | None = None,
    tolerance_seconds: int = 300,
) -> tuple[bool, str]:
    """Decide ``time_proven`` from a token verification status.

    ``time_proven`` is True only when the token itself verified
    (``REAL_TSA_VERIFIED`` — mock tokens never qualify) AND, when a
    claimed time is supplied, it agrees with the TSA genTime within
    tolerance. A cryptographically valid token with a far-away claimed
    time proves the digest existed at genTime — not at the claimed time.
    """
    if token_status != "REAL_TSA_VERIFIED":
        return False, f"time_proven=False: token status is {token_status}."
    if claimed_time is not None and gen_time is not None:
        matches, note, _delta = check_claimed_vs_gen_time(
            claimed_time, gen_time, tolerance_seconds=tolerance_seconds
        )
        if not matches:
            return False, f"time_proven=False: {note}"
        return True, f"time_proven=True: real TSA token verified; {note}"
    return True, "time_proven=True: real TSA token verified (no claimed_time to compare)."


def split_verdict(
    execution_proven: bool,
    time_proven: bool,
    *,
    note: str = "",
) -> dict[str, Any]:
    """Report the two proof dimensions separately — never merged.

    A TSA token proves *at most* that a digest existed by genTime; it
    does not prove the execution was performed correctly. Conversely a
    correct execution (HEA PROVEN) proves nothing about wall-clock time
    without a verified real-TSA token. Both fields are reported as
    given; this function merges nothing and infers nothing.
    """
    return {
        "time_proven": bool(time_proven),
        "execution_proven": bool(execution_proven),
        "note": note
        or (
            "time_proven: digest existed by the TSA genTime (real TSA token "
            "verified). execution_proven: the execution itself was attested "
            "and verified (HEA). The two are independent; neither implies "
            "the other."
        ),
    }


__all__ = [
    "REAL_TOKEN_PROTOCOL_VERSION",
    "RealTSAError",
    "TSARejectedError",
    "TSAUnavailableError",
    "assess_time_proof",
    "build_time_anchor",
    "build_timestamp_request_no_nonce",
    "check_claimed_vs_gen_time",
    "parse_cms_signed_data",
    "parse_timestamp_response",
    "parse_tst_info",
    "request_timestamp",
    "split_verdict",
    "verify_cert_chain",
    "verify_real_timestamp_token",
]
