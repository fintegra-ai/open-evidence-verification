# SPDX-License-Identifier: Apache-2.0

"""Real RFC 3161 TSA tests (TUR 4, worker B).

Everything here is synthetic and offline EXCEPT ``test_live_freetsa_*``,
``test_live_digicert_*`` and ``test_live_sectigo_*``, which are gated on
``OEVP_LIVE_TSA=1`` and skip (with the reason recorded) when the network
is unavailable.

The synthetic CMS tokens are built by an *independent* DER encoder in
this file — not by re-using the verifier's own parser — so a builder
bug and a verifier bug cannot cancel out. The builder is also imported
by ``benchmarks/c17_experiment.py`` (same pattern as C18 importing from
``test_domain_profiles``).

Live-TSA facts established 2026-11-13 (see docs/TSA_V4.md):
* freetsa.org grants requests and embeds its chain; a full offline
  verification (signature + chain to the pinned Root CA) passes.
* http://tsa.starfieldtech.com is unreachable from this sandbox
  (connection closed without a response; N/A, not a verdict on the
  service).
* timestamp.sectigo.com grants requests and, with ``certReq=TRUE``,
  embeds its chain (Signer R37 → CA R41 → Root R46, leaf critical EKU,
  SHA-384 signer digest, RSA signature) and echoes the nonce — verified
  ``REAL_TSA_VERIFIED`` against the embedded Root R46 pinned as the
  anchor (the embedded R46 is itself issued by the USERTrust RSA CA,
  so a purist would fetch that root out-of-band; pinning the embedded
  root is the documented caller-fiat choice).
* timestamp.digicert.com grants requests; with ``certReq=TRUE`` it
  embeds the full chain (2026 responder leaf → 2025 intermediate →
  cross-signed Trusted Root G4) and verifies against the self-signed
  Trusted Root G4 from DigiCert's public repository — anchor matching
  is by (subject, public key), which is what makes the cross-signed
  root anchor the chain. Without ``certReq`` it embeds no certificates.
* Both live TSAs grant correct plain-INTEGER nonce requests and echo
  the nonce in the token — live nonce verification works. (The earlier
  rejections were caused by the non-conformant ``[1]`` nonce tag, not
  by the nonce itself.)
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from oev.hashing import sha256_bytes
from oev.tsa import build_timestamp_request, parse_timestamp_request
from oev.tsa_real import (
    REAL_TOKEN_PROTOCOL_VERSION,
    RealTSAError,
    TSARejectedError,
    TSAUnavailableError,
    assess_time_proof,
    build_time_anchor,
    build_timestamp_request_no_nonce,
    check_claimed_vs_gen_time,
    parse_cms_signed_data,
    parse_timestamp_response,
    parse_tst_info,
    request_timestamp,
    split_verdict,
    verify_real_timestamp_token,
)

DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32
GEN_TIME = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
TEST_POLICY = "1.2.3.4.1"


# ---------------------------------------------------------------------------
# Independent DER encoder (test-side; does not import oev.tsa_real internals)
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value: int) -> bytes:
    if value == 0:
        return _tlv(0x02, b"\x00")
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


def _der_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
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
    return _tlv(0x06, bytes(out))


def _der_seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def _der_set(*parts: bytes) -> bytes:
    return _tlv(0x31, b"".join(sorted(parts)))


def _der_octet(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _der_null() -> bytes:
    return b"\x05\x00"


def _der_gentime(moment: datetime) -> bytes:
    return _tlv(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _der_utctime(moment: datetime) -> bytes:
    return _tlv(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        nbytes = first & 0x7F
        length = int.from_bytes(data[offset : offset + nbytes], "big")
        offset += nbytes
    else:
        length = first
    return tag, data[offset : offset + length], offset + length


# ---------------------------------------------------------------------------
# Synthetic TSA: CA + leaf certificates, TSTInfo, CMS, TimeStampResp
# ---------------------------------------------------------------------------


def make_test_ca(
    *,
    key_type: str = "ec",
    not_before: datetime = GEN_TIME - timedelta(days=1),
    not_after: datetime = GEN_TIME + timedelta(days=365),
) -> tuple[x509.Certificate, Any]:
    if key_type == "rsa":
        key: Any = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Root CA")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x1001)
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_test_tsa_leaf(
    ca_cert: x509.Certificate,
    ca_key: Any,
    *,
    key_type: str = "ec",
    not_before: datetime = GEN_TIME - timedelta(days=1),
    not_after: datetime = GEN_TIME + timedelta(days=365),
    with_eku: bool = True,
    eku_critical: bool = True,
    serial: int = 0x2002,
) -> tuple[x509.Certificate, Any]:
    if key_type == "rsa":
        key: Any = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA Signer")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if with_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=eku_critical,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, key


def _cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def build_tst_info(
    *,
    digest: str,
    gen_time: datetime = GEN_TIME,
    nonce: int | None = None,
    serial: int = 0xABCDEF,
    policy: str = TEST_POLICY,
    accuracy: bool = False,
    extensions: bool = False,
) -> bytes:
    raw = bytes.fromhex(digest[len("sha256:") :])
    alg = _der_seq(_der_oid("2.16.840.1.101.3.4.2.1"), _der_null())
    imprint = _der_seq(alg, _der_octet(raw))
    parts: list[bytes] = [
        _der_int(1),
        _der_oid(policy),
        imprint,
        _der_int(serial),
        _der_gentime(gen_time),
    ]
    if accuracy:
        # OpenSSL form: accuracy as a bare SEQUENCE (its TS_TST_INFO
        # template drops the RFC 3161 [0] tag).
        parts.append(_der_seq(_der_int(1)))
    if nonce is not None:
        parts.append(_der_int(nonce))  # plain INTEGER (RFC 3161 §2.4.2)
    if extensions:
        parts.append(_tlv(0xA1, b""))  # extensions [1] (empty)
    return _der_seq(*parts)


def build_timestamp_response(
    *,
    digest: str = DIGEST,
    gen_time: datetime = GEN_TIME,
    nonce: int | None = None,
    signer_cert: x509.Certificate,
    signer_key: Any,
    ca_cert: x509.Certificate | None = None,
    include_certs: bool = True,
    key_type: str = "ec",
    status: int = 0,
    status_string: str = "",
    fail_info: list[str] | None = None,
    sign_with: Any = None,
    message_digest_override: bytes | None = None,
    wrap_token: bool = False,
    serial: int = 0xABCDEF,
    accuracy: bool = False,
    extensions: bool = False,
) -> bytes:
    """Build a full TimeStampResp DER with a synthetic CMS token.

    ``sign_with`` signs with a different key than the certificate
    (wrong-signature attack); ``message_digest_override`` makes the
    signedAttrs messageDigest disagree with the eContent hash.
    """
    status_body = _der_int(status)
    if status_string:
        status_body += _der_seq(_tlv(0x0C, status_string.encode()))
    if fail_info:
        bits = {
            "badAlg": 0,
            "badRequest": 1,
            "badDataFormat": 2,
            "timeNotAvailable": 3,
            "unacceptedPolicy": 4,
            "unacceptedExtension": 5,
            "addInfoNotAvailable": 6,
            "systemFailure": 7,
        }
        value = 0
        for name in fail_info:
            value |= 0x80 >> bits[name]
        status_body += _tlv(0x03, b"\x00" + bytes([value]))
    status_seq = _der_seq(status_body)
    if status != 0:
        return _der_seq(status_seq)
    tst = build_tst_info(
        digest=digest,
        gen_time=gen_time,
        nonce=nonce,
        serial=serial,
        accuracy=accuracy,
        extensions=extensions,
    )
    econtent = tst
    md = message_digest_override or hashlib.sha256(econtent).digest()
    attr_content_type = _der_seq(
        _der_oid("1.2.840.113549.1.9.3"),
        _der_set(_der_oid("1.2.840.113549.1.9.16.1.4")),
    )
    attr_signing_time = _der_seq(
        _der_oid("1.2.840.113549.1.9.5"),
        _der_set(_der_utctime(gen_time)),
    )
    attr_message_digest = _der_seq(
        _der_oid("1.2.840.113549.1.9.4"),
        _der_set(_der_octet(md)),
    )
    signed_attrs_content = b"".join(
        sorted([attr_content_type, attr_signing_time, attr_message_digest])
    )
    signed_attrs_der = _der_set(attr_content_type, attr_signing_time, attr_message_digest)
    signing_key = sign_with if sign_with is not None else signer_key
    if key_type == "rsa":
        signature = signing_key.sign(signed_attrs_der, padding.PKCS1v15(), hashes.SHA256())
        sig_alg = _der_seq(_der_oid("1.2.840.113549.1.1.11"), _der_null())
    else:
        signature = signing_key.sign(signed_attrs_der, ec.ECDSA(hashes.SHA256()))
        sig_alg = _der_seq(_der_oid("1.2.840.10045.4.3.2"))
    issuer_der = signer_cert.issuer.public_bytes()
    # issuer Name DER: public_bytes() returns the full Name TLV already.
    sid = _der_seq(issuer_der, _der_int(signer_cert.serial_number))
    digest_alg = _der_seq(_der_oid("2.16.840.1.101.3.4.2.1"), _der_null())
    signer_info = _der_seq(
        _der_int(1),
        sid,
        digest_alg,
        _tlv(0xA0, signed_attrs_content),
        sig_alg,
        _der_octet(signature),
    )
    encap = _der_seq(
        _der_oid("1.2.840.113549.1.9.16.1.4"),
        _tlv(0xA0, _der_octet(econtent)),
    )
    signed_data_body = _der_int(3) + _der_set(digest_alg) + encap
    if include_certs:
        certs = _cert_der(signer_cert)
        if ca_cert is not None:
            certs += _cert_der(ca_cert)
        signed_data_body += _tlv(0xA0, certs)
    signed_data_body += _der_set(signer_info)
    signed_data = _der_seq(signed_data_body)
    content_info = _der_seq(
        _der_oid("1.2.840.113549.1.7.2"),
        _tlv(0xA0, signed_data),
    )
    if wrap_token:
        token = _tlv(0xA0, content_info)
    else:
        token = content_info
    return _der_seq(status_seq, token)


def build_sidecar(
    response_der: bytes,
    *,
    tsa_url: str = "https://tsa.example.invalid/tsr",
    gen_time: datetime = GEN_TIME,
    digest: str = DIGEST,
    nonce: int | None = None,
    chain_pem: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "protocol_version": REAL_TOKEN_PROTOCOL_VERSION,
        "tsa_url": tsa_url,
        "tsa_identity": None,
        "response_der_b64": base64.b64encode(response_der).decode("ascii"),
        "cert_chain_pem": chain_pem or [],
        "gen_time": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "imprint_digest": digest,
        "nonce": str(nonce) if nonce is not None else None,
        "token_sha256": sha256_bytes(response_der),
    }


def _synthetic_setup(
    *,
    key_type: str = "ec",
    leaf_not_before: datetime | None = None,
    leaf_not_after: datetime | None = None,
    with_eku: bool = True,
    eku_critical: bool = True,
) -> tuple[x509.Certificate, Any, x509.Certificate, Any]:
    ca_cert, ca_key = make_test_ca(key_type=key_type)
    leaf_cert, leaf_key = make_test_tsa_leaf(
        ca_cert,
        ca_key,
        key_type=key_type,
        not_before=leaf_not_before or GEN_TIME - timedelta(days=1),
        not_after=leaf_not_after or GEN_TIME + timedelta(days=365),
        with_eku=with_eku,
        eku_critical=eku_critical,
    )
    return ca_cert, ca_key, leaf_cert, leaf_key


def _verified_sidecar(
    *,
    key_type: str = "ec",
    digest: str = DIGEST,
    nonce: int | None = None,
    **kwargs: Any,
) -> tuple[dict[str, Any], bytes, x509.Certificate]:
    ca_cert, _ca_key, leaf_cert, leaf_key = _synthetic_setup(key_type=key_type, **kwargs)
    response = build_timestamp_response(
        digest=digest,
        nonce=nonce,
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        key_type=key_type,
    )
    sidecar = build_sidecar(
        response,
        digest=digest,
        nonce=nonce,
        chain_pem=[_cert_pem(leaf_cert).decode(), _cert_pem(ca_cert).decode()],
    )
    return sidecar, _cert_pem(ca_cert), leaf_cert


# ---------------------------------------------------------------------------
# Nonce tag regression (TUR 4): 0x81 is correct, 0xA1 is legacy-accepted
# ---------------------------------------------------------------------------


def test_nonce_tag_is_plain_integer_0x02() -> None:
    # RFC 3161 §2.4.1: the nonce is a plain INTEGER (tag 0x02) — no
    # [1] tag. (Tur 3 claimed [1] IMPLICIT; the first TUR 4 attempt
    # used 0x81. Both are wrong; OpenSSL's TS_REQ template is
    # ASN1_OPT(nonce, ASN1_INTEGER) and its responder rejects [1].)
    der, nonce = build_timestamp_request(DIGEST)
    # Walk the request: SEQ{ version, imprint, nonce, certReq }.
    _tag, body, _end = _read_tlv(der, 0)
    _tag, _v, off = _read_tlv(body, 0)
    _tag, _imprint, off = _read_tlv(body, off)
    tag, _content, _off = _read_tlv(body, off)
    assert tag == 0x02, f"nonce tag must be plain INTEGER 0x02, got 0x{tag:02x}"
    parsed = parse_timestamp_request(der)
    assert parsed["nonce"] == nonce


def test_legacy_0xa1_nonce_still_parses() -> None:
    der, nonce = build_timestamp_request(DIGEST)
    # Rebuild the same request with the legacy constructed tag.
    _tag, body, _end = _read_tlv(der, 0)
    _tag, version, off = _read_tlv(body, 0)
    _tag, imprint, off = _read_tlv(body, off)
    _tag, nonce_content, off = _read_tlv(body, off)
    _tag, cert_req, _off = _read_tlv(body, off)
    legacy_body = (
        _tlv(0x02, version) + _tlv(0x30, imprint) + _tlv(0xA1, nonce_content) + _tlv(0x01, cert_req)
    )
    legacy = _tlv(0x30, legacy_body)
    parsed = parse_timestamp_request(legacy)
    assert parsed["nonce"] == nonce


def test_legacy_0x81_nonce_still_parses() -> None:
    der, nonce = build_timestamp_request(DIGEST)
    _tag, body, _end = _read_tlv(der, 0)
    _tag, version, off = _read_tlv(body, 0)
    _tag, imprint, off = _read_tlv(body, off)
    _tag, nonce_content, off = _read_tlv(body, off)
    _tag, cert_req, _off = _read_tlv(body, off)
    legacy_body = (
        _tlv(0x02, version) + _tlv(0x30, imprint) + _tlv(0x81, nonce_content) + _tlv(0x01, cert_req)
    )
    parsed = parse_timestamp_request(_tlv(0x30, legacy_body))
    assert parsed["nonce"] == nonce


def test_no_nonce_request_shape() -> None:
    der = build_timestamp_request_no_nonce(DIGEST, cert_req=True)
    _tag, body, end = _read_tlv(der, 0)
    assert end == len(der)
    _tag, version, off = _read_tlv(body, 0)
    assert version == b"\x01"
    _tag, imprint, off = _read_tlv(body, off)
    _tag, _alg, ioff = _read_tlv(imprint, 0)
    _tag, hashed, _ioff = _read_tlv(imprint, ioff)
    assert "sha256:" + hashed.hex() == DIGEST
    tag, cert_req, off = _read_tlv(body, off)
    assert tag == 0x01 and cert_req == b"\x01"
    assert off == len(body)  # no nonce field at all


# ---------------------------------------------------------------------------
# Response / TSTInfo / CMS parsing
# ---------------------------------------------------------------------------


def test_parse_rejection_response() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    der = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        status=2,
        status_string="Bad request format or system error.",
        fail_info=["unacceptedExtension"],
    )
    parsed = parse_timestamp_response(der)
    assert parsed["status"] == 2
    assert parsed["status_name"] == "rejection"
    assert "Bad request format" in parsed["status_string"]
    assert parsed["fail_info"] == ["unacceptedExtension"]
    assert parsed["token_der"] is None


def test_parse_wrapped_token_form() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    der = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        wrap_token=True,
    )
    parsed = parse_timestamp_response(der)
    assert parsed["status"] == 0
    assert parsed["token_der"] is not None
    tst = parse_tst_info(bytes(parse_cms_signed_data(parsed["token_der"])["econtent"]))
    assert tst["digest"] == DIGEST
    assert tst["gen_time_iso"] == "2026-11-13T12:00:00Z"


def test_parse_tst_info_openssl_accuracy_form() -> None:
    # OpenSSL emits accuracy as a bare SEQUENCE (no [0] tag) and may
    # append extensions [1]; a conformant parser must accept both.
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    response = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        nonce=777,
        accuracy=True,
        extensions=True,
    )
    parsed = parse_timestamp_response(response)
    tst = parse_tst_info(bytes(parse_cms_signed_data(parsed["token_der"])["econtent"]))
    assert tst["nonce"] == 777
    assert tst["gen_time_iso"] == "2026-11-13T12:00:00Z"
    sidecar = build_sidecar(
        response,
        nonce=777,
        chain_pem=[_cert_pem(leaf_cert).decode(), _cert_pem(ca_cert).decode()],
    )
    status, note, _d = verify_real_timestamp_token(
        sidecar, DIGEST, [_cert_pem(ca_cert)], expected_nonce=777
    )
    assert status == "REAL_TSA_VERIFIED", note


def test_parse_tst_info_fields() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    der = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        nonce=123456789,
        serial=0x1234,
    )
    parsed = parse_timestamp_response(der)
    cms = parse_cms_signed_data(parsed["token_der"])
    assert cms["encap_content_type"] == "1.2.840.113549.1.9.16.1.4"
    assert len(cms["certificates_der"]) == 2
    tst = parse_tst_info(bytes(cms["econtent"]))
    assert tst["digest"] == DIGEST
    assert tst["nonce"] == 123456789
    assert tst["serial_hex"] == "1234"
    assert tst["policy"] == TEST_POLICY


def test_malformed_response_is_controlled() -> None:
    with pytest.raises(RealTSAError):
        parse_timestamp_response(b"\x30\x03\x02\x01\x00garbage")
    with pytest.raises(RealTSAError):
        parse_tst_info(b"\x30\x00")


# ---------------------------------------------------------------------------
# Verification: valid tokens (EC + RSA)
# ---------------------------------------------------------------------------


def test_synthetic_token_verifies_ec() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(key_type="ec")
    status, note, details = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_VERIFIED", note
    assert details["gen_time"] == "2026-11-13T12:00:00Z"
    assert "Test TSA Signer" in (details["tsa_identity"] or "")
    assert len(details["chain_subjects"]) == 2


def test_synthetic_token_verifies_rsa() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(key_type="rsa")
    status, note, _details = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_VERIFIED", note


def test_synthetic_token_verifies_with_nonce() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(key_type="ec", nonce=987654321)
    status, note, _d = verify_real_timestamp_token(
        sidecar, DIGEST, [ca_pem], expected_nonce=987654321
    )
    assert status == "REAL_TSA_VERIFIED", note


def test_token_without_embedded_certs_uses_intermediates() -> None:
    # DigiCert shape: no certs in the token; signer + CA supplied out-of-band.
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    response = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        include_certs=False,
    )
    sidecar = build_sidecar(response)
    status, note, _d = verify_real_timestamp_token(
        sidecar,
        DIGEST,
        [_cert_pem(ca_cert)],
        intermediates_pem=[_cert_pem(leaf_cert)],
    )
    assert status == "REAL_TSA_VERIFIED", note


# ---------------------------------------------------------------------------
# Verification: attacks
# ---------------------------------------------------------------------------


def test_imprint_mismatch_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar()
    status, note, _d = verify_real_timestamp_token(sidecar, OTHER_DIGEST, [ca_pem])
    assert status == "REAL_TSA_INVALID"
    assert "imprint" in note


def test_nonce_mismatch_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(nonce=111)
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem], expected_nonce=222)
    assert status == "REAL_TSA_INVALID"
    assert "nonce" in note


def test_wrong_signature_invalid() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    _other_ca, other_key, _ol, _ok = _synthetic_setup()
    response = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        sign_with=other_key,
    )
    sidecar = build_sidecar(response)
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [_cert_pem(ca_cert)])
    assert status == "REAL_TSA_INVALID"
    assert "signature" in note


def test_tampered_message_digest_attr_invalid() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    response = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        message_digest_override=hashlib.sha256(b"different content").digest(),
    )
    sidecar = build_sidecar(response)
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [_cert_pem(ca_cert)])
    assert status == "REAL_TSA_INVALID"
    assert "messageDigest" in note


def test_expired_tsa_cert_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(leaf_not_after=GEN_TIME - timedelta(days=1))
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_INVALID"
    assert "not valid at genTime" in note


def test_not_yet_valid_tsa_cert_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(leaf_not_before=GEN_TIME + timedelta(days=1))
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_INVALID"
    assert "not valid at genTime" in note


def test_missing_eku_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(with_eku=False)
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_INVALID"
    assert "timeStamping" in note


def test_non_critical_eku_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar(eku_critical=False)
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_INVALID"
    assert "not critical" in note


def test_untrusted_root_invalid() -> None:
    sidecar, _ca_pem, _leaf = _verified_sidecar()
    other_ca, _ok = make_test_ca()
    status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [_cert_pem(other_ca)])
    assert status == "REAL_TSA_INVALID"
    assert "chain" in note


def test_tampered_sidecar_hash_invalid() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar()
    sidecar["token_sha256"] = "sha256:" + "00" * 32
    status, _note, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem])
    assert status == "REAL_TSA_INVALID"


def test_no_sidecar_is_unverified_not_failed() -> None:
    _sidecar, ca_pem, _leaf = _verified_sidecar()
    status, note, _d = verify_real_timestamp_token(None, DIGEST, [ca_pem])
    assert status == "UNVERIFIED"
    assert "not proven" in note


def test_no_trust_roots_is_unverified() -> None:
    sidecar, _ca_pem, _leaf = _verified_sidecar()
    status, _note, _d = verify_real_timestamp_token(sidecar, DIGEST, [])
    assert status == "UNVERIFIED"


def test_gen_time_window_enforced() -> None:
    sidecar, ca_pem, _leaf = _verified_sidecar()
    window = (
        datetime(2026, 11, 13, 11, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 11, 13, 13, 0, 0, tzinfo=timezone.utc),
    )
    status, _n, _d = verify_real_timestamp_token(sidecar, DIGEST, [ca_pem], gen_time_window=window)
    assert status == "REAL_TSA_VERIFIED"
    old_window = (
        datetime(2026, 11, 12, 0, 0, 0, tzinfo=timezone.utc),
        datetime(2026, 11, 12, 23, 59, 59, tzinfo=timezone.utc),
    )
    status, note, _d = verify_real_timestamp_token(
        sidecar, DIGEST, [ca_pem], gen_time_window=old_window
    )
    assert status == "REAL_TSA_INVALID"
    assert "outside the caller window" in note


# ---------------------------------------------------------------------------
# Time anchor + the time/execution split (V3-C17 core)
# ---------------------------------------------------------------------------


def test_claimed_vs_gen_time_backdate_and_future() -> None:
    matches, _note, delta = check_claimed_vs_gen_time("2020-01-01T00:00:00Z", GEN_TIME)
    assert matches is False
    assert delta < 0
    matches, _note, delta = check_claimed_vs_gen_time("2030-01-01T00:00:00Z", GEN_TIME)
    assert matches is False
    assert delta > 0
    matches, _note, delta = check_claimed_vs_gen_time("2026-11-13T12:02:00Z", GEN_TIME)
    assert matches is True
    assert abs(delta - 120.0) < 1e-6
    # Exactly at the tolerance boundary still matches.
    matches, _note, _d = check_claimed_vs_gen_time(
        "2026-11-13T12:05:00Z", GEN_TIME, tolerance_seconds=300
    )
    assert matches is True


def test_assess_time_proof_mock_never_proves() -> None:
    proven, _note = assess_time_proof("TSA_VERIFIED")  # mock status
    assert proven is False
    proven, _note = assess_time_proof("UNVERIFIED")
    assert proven is False
    proven, _note = assess_time_proof("REAL_TSA_INVALID")
    assert proven is False


def test_assess_time_proof_real_token_with_claimed_time() -> None:
    proven, _note = assess_time_proof(
        "REAL_TSA_VERIFIED",
        claimed_time="2026-11-13T12:01:00Z",
        gen_time=GEN_TIME,
    )
    assert proven is True
    # Consistent backdate: genuine token, claimed time years earlier.
    proven, note = assess_time_proof(
        "REAL_TSA_VERIFIED",
        claimed_time="2020-01-01T00:00:00Z",
        gen_time=GEN_TIME,
    )
    assert proven is False
    assert "backdate" in note


def test_split_verdict_keeps_dimensions_separate() -> None:
    both = split_verdict(True, True)
    assert both["execution_proven"] is True and both["time_proven"] is True
    exec_only = split_verdict(True, False)
    assert exec_only["execution_proven"] is True and exec_only["time_proven"] is False
    time_only = split_verdict(False, True)
    assert time_only["execution_proven"] is False and time_only["time_proven"] is True
    neither = split_verdict(False, False)
    assert neither["execution_proven"] is False and neither["time_proven"] is False


def test_time_anchor_does_not_modify_attestation() -> None:
    sidecar, _ca_pem, _leaf = _verified_sidecar()
    attestation = {"check_id": "archive_safety", "result": "PASS", "digest": DIGEST}
    before = dict(attestation)
    anchor = build_time_anchor(DIGEST, sidecar)
    assert attestation == before  # untouched
    assert anchor["attestation_digest"] == DIGEST
    assert anchor["token_sha256"] == sidecar["token_sha256"]
    assert anchor["gen_time"] == "2026-11-13T12:00:00Z"
    assert anchor["protocol_version"] == REAL_TOKEN_PROTOCOL_VERSION


def test_time_anchor_rejects_mock_sidecar() -> None:
    with pytest.raises(RealTSAError):
        build_time_anchor(DIGEST, {"protocol_version": "oev-tsa-token/0.1"})


# ---------------------------------------------------------------------------
# Client: local HTTP server (offline) + controlled failures
# ---------------------------------------------------------------------------


def _serve(response_der: bytes, http_status: int = 200):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(http_status)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(response_der)))
            self.end_headers()
            self.wfile.write(response_der)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/tsr"


def test_client_against_local_server() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    response = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
    )
    server, url = _serve(response)
    try:
        sidecar = request_timestamp(url, DIGEST, timeout=10.0)
        assert sidecar["protocol_version"] == REAL_TOKEN_PROTOCOL_VERSION
        assert sidecar["gen_time"] == "2026-11-13T12:00:00Z"
        assert sidecar["imprint_digest"] == DIGEST
        assert len(sidecar["cert_chain_pem"]) == 2
        status, note, _d = verify_real_timestamp_token(sidecar, DIGEST, [_cert_pem(ca_cert)])
        assert status == "REAL_TSA_VERIFIED", note
    finally:
        server.shutdown()
        server.server_close()


def test_client_rejection_is_controlled() -> None:
    ca_cert, _ck, leaf_cert, leaf_key = _synthetic_setup()
    response = build_timestamp_response(
        signer_cert=leaf_cert,
        signer_key=leaf_key,
        ca_cert=ca_cert,
        status=2,
        status_string="Bad request format or system error.",
        fail_info=["badRequest"],
    )
    server, url = _serve(response)
    try:
        with pytest.raises(TSARejectedError) as excinfo:
            request_timestamp(url, DIGEST, timeout=10.0)
        assert excinfo.value.status == 2
        assert excinfo.value.fail_info == ["badRequest"]
    finally:
        server.shutdown()
        server.server_close()


def test_client_http_error_is_controlled() -> None:
    server, url = _serve(b"not a timestamp response", http_status=500)
    try:
        with pytest.raises(TSAUnavailableError):
            request_timestamp(url, DIGEST, timeout=10.0)
    finally:
        server.shutdown()
        server.server_close()


def test_client_unreachable_is_controlled() -> None:
    # Port 1 on loopback: connection refused, no network needed.
    with pytest.raises(TSAUnavailableError):
        request_timestamp("http://127.0.0.1:1/tsr", DIGEST, timeout=5.0)


def test_client_sends_nonce_request_by_default() -> None:
    seen: dict[str, bytes] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            seen["body"] = self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"\x30\x00")

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(RealTSAError):
            request_timestamp(
                f"http://127.0.0.1:{server.server_address[1]}/tsr", DIGEST, timeout=10.0
            )
    finally:
        server.shutdown()
        server.server_close()
    # Default request: version, messageImprint, plain-INTEGER nonce
    # (0x02), certReq TRUE. Both live TSAs grant this and echo the nonce.
    body = seen["body"]
    _tag, content, _end = _read_tlv(body, 0)
    _tag, _version, off = _read_tlv(content, 0)
    _tag, _imprint, off = _read_tlv(content, off)
    tag, _nonce, off = _read_tlv(content, off)
    assert tag == 0x02, f"nonce must be a plain INTEGER (0x02), got 0x{tag:02x}"
    tag, cert_req, off = _read_tlv(content, off)
    assert tag == 0x01 and cert_req == b"\x01"
    assert off == len(content)


# ---------------------------------------------------------------------------
# Live TSAs (gated; skip with reason when unavailable)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("OEVP_LIVE_TSA") != "1",
    reason="live TSA test: run with OEVP_LIVE_TSA=1 (needs network)",
)
def test_live_freetsa_full_verification() -> None:
    try:
        sidecar = request_timestamp("https://freetsa.org/tsr", DIGEST, timeout=30.0)
    except TSAUnavailableError as exc:
        pytest.skip(f"freetsa unreachable: {exc}")
    assert sidecar["gen_time"] is not None
    assert len(sidecar["cert_chain_pem"]) == 2
    assert sidecar["nonce"] is not None  # freetsa echoes the nonce
    assert sidecar["nonce"] == sidecar["request_nonce"]
    root_pem = sidecar["cert_chain_pem"][1].encode()
    status, note, details = verify_real_timestamp_token(
        sidecar, DIGEST, [root_pem], expected_nonce=int(sidecar["request_nonce"])
    )
    assert status == "REAL_TSA_VERIFIED", note
    assert details["gen_time"] is not None
    proven, _n = assess_time_proof(
        status, claimed_time=details["gen_time"], gen_time=details["gen_time"]
    )
    assert proven is True


@pytest.mark.skipif(
    os.environ.get("OEVP_LIVE_TSA") != "1",
    reason="live TSA test: run with OEVP_LIVE_TSA=1 (needs network)",
)
def test_live_digicert_full_verification() -> None:
    # DigiCert grants the token; with certReq=TRUE it embeds the full
    # chain (2026 responder leaf -> 2025 intermediate -> cross-signed
    # Trusted Root G4). The self-signed Trusted Root G4 comes from
    # DigiCert's public repository (cacerts.digicert.com); the chain
    # anchors on it by (subject, public key) — the embedded root is
    # the cross-signed variant of the same key.
    try:
        sidecar = request_timestamp("http://timestamp.digicert.com", DIGEST, timeout=30.0)
    except TSAUnavailableError as exc:
        pytest.skip(f"digicert unreachable: {exc}")
    parsed = parse_timestamp_response(base64.b64decode(sidecar["response_der_b64"]))
    assert parsed["status"] == 0
    cms = parse_cms_signed_data(parsed["token_der"])
    tst = parse_tst_info(bytes(cms["econtent"]))
    assert tst["digest"] == DIGEST
    assert tst["nonce"] is not None  # DigiCert echoes the nonce too
    assert str(tst["nonce"]) == sidecar["request_nonce"]
    assert len(cms["certificates_der"]) == 3  # leaf + 2025 CA + G4
    import urllib.request

    try:
        with urllib.request.urlopen(
            "https://cacerts.digicert.com/DigiCertTrustedRootG4.crt",
            timeout=30,
        ) as resp:
            g4_der = resp.read()
    except Exception as exc:  # noqa: BLE001 - network is best-effort here
        pytest.skip(f"DigiCert root download failed: {exc}")
    g4_pem = x509.load_der_x509_certificate(g4_der).public_bytes(serialization.Encoding.PEM)
    status, note, details = verify_real_timestamp_token(
        sidecar, DIGEST, [g4_pem], expected_nonce=int(sidecar["request_nonce"])
    )
    assert status == "REAL_TSA_VERIFIED", note
    assert len(details["chain_subjects"]) == 3
    proven, _n = assess_time_proof(
        status, claimed_time=details["gen_time"], gen_time=details["gen_time"]
    )
    assert proven is True


@pytest.mark.skipif(
    os.environ.get("OEVP_LIVE_TSA") != "1",
    reason="live TSA test: run with OEVP_LIVE_TSA=1 (needs network)",
)
def test_live_sectigo_full_verification() -> None:
    # Sectigo grants the token; with certReq=TRUE it embeds its chain
    # (Signer R37 -> CA R41 -> Root R46; SHA-384 signer digest, RSA
    # signature). The embedded Root R46 is itself issued by the
    # USERTrust RSA CA, so the test pins the embedded R46 as the anchor
    # — the documented caller-fiat choice (see module docstring).
    try:
        sidecar = request_timestamp("https://timestamp.sectigo.com", DIGEST, timeout=30.0)
    except TSAUnavailableError as exc:
        pytest.skip(f"sectigo unreachable: {exc}")
    parsed = parse_timestamp_response(base64.b64decode(sidecar["response_der_b64"]))
    assert parsed["status"] == 0
    cms = parse_cms_signed_data(parsed["token_der"])
    tst = parse_tst_info(bytes(cms["econtent"]))
    assert tst["digest"] == DIGEST
    assert tst["nonce"] is not None  # Sectigo echoes the nonce too
    assert str(tst["nonce"]) == sidecar["request_nonce"]
    assert len(cms["certificates_der"]) == 3  # signer + CA R41 + Root R46
    root_pem = sidecar["cert_chain_pem"][-1].encode()
    status, note, details = verify_real_timestamp_token(
        sidecar, DIGEST, [root_pem], expected_nonce=int(sidecar["request_nonce"])
    )
    assert status == "REAL_TSA_VERIFIED", note
    assert "Sectigo Public Time Stamping Signer R37" in details["chain_subjects"][0]
    assert len(details["chain_subjects"]) == 3
    proven, _n = assess_time_proof(
        status, claimed_time=details["gen_time"], gen_time=details["gen_time"]
    )
    assert proven is True
