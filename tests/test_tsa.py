# SPDX-License-Identifier: Apache-2.0

"""TSA module tests: RFC 3161 request encoding + mock TSA tokens.

No network is used anywhere: the mock TSA signs locally, and the
tests assert the module never imports ``socket``/``http``.
"""

from __future__ import annotations

import base64
import sys

import pytest

from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore
from oev.tsa import (
    MockTSA,
    build_timestamp_request,
    parse_timestamp_request,
    verify_timestamp_token,
)

DIGEST = "sha256:" + "ab" * 32


def test_tsa_request_der_roundtrip() -> None:
    der, nonce = build_timestamp_request(DIGEST)
    parsed = parse_timestamp_request(der)
    assert parsed["version"] == 1
    assert parsed["hash_algorithm"] == "sha256"
    assert parsed["digest"] == DIGEST
    assert parsed["nonce"] == nonce
    assert parsed["cert_req"] is False


def test_tsa_request_nonce_is_fresh() -> None:
    _, nonce1 = build_timestamp_request(DIGEST)
    _, nonce2 = build_timestamp_request(DIGEST)
    assert nonce1 != nonce2


def test_tsa_request_rejects_bad_digest() -> None:
    with pytest.raises(ValueError):
        build_timestamp_request("not-a-digest")


def test_tsa_request_parser_rejects_truncation_and_wrong_hash() -> None:
    der, _nonce = build_timestamp_request(DIGEST)
    with pytest.raises(ValueError):
        parse_timestamp_request(der[:-1])
    with pytest.raises(ValueError):
        parse_timestamp_request(der + b"\x00")
    # Flip the hash-algorithm OID byte inside the request: must be rejected.
    tampered = bytearray(der)
    tampered[12] ^= 0x01
    with pytest.raises(ValueError):
        parse_timestamp_request(bytes(tampered))


def test_tsa_module_imports_no_network() -> None:
    import oev.tsa as tsa_mod

    assert "socket" not in sys.modules or sys.modules["socket"] is not None
    source = (tsa_mod.__file__ or "").replace(".pyc", ".py")
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    assert "import socket" not in text
    assert "import http" not in text
    assert "urllib" not in text
    assert "import requests" not in text
    assert "requests.get" not in text


def _tsa_pair() -> tuple[MockTSA, TrustStore]:
    priv, pub = generate_ed25519_keypair()
    tsa = MockTSA(priv, key_id="tsa-mock-1")
    store = TrustStore.from_list([{"key_id": "tsa-mock-1", "public_key_pem": pub.decode()}])
    return tsa, store


def test_mock_tsa_token_verifies() -> None:
    tsa, store = _tsa_pair()
    stamped = tsa.timestamp(DIGEST, gen_time="2026-11-13T10:00:00Z")
    assert stamped["token"]["tsa_gen_time"] == "2026-11-13T10:00:00Z"
    assert stamped["token"]["tsa_policy"] == "mock-tsa/0.1"
    assert stamped["token"]["imprint_digest"] == DIGEST
    status, note = verify_timestamp_token(stamped["envelope"], DIGEST, store)
    assert status == "TSA_VERIFIED"
    assert "mock TSA" in note


def test_mock_tsa_token_wrong_digest_invalid() -> None:
    tsa, store = _tsa_pair()
    stamped = tsa.timestamp(DIGEST, gen_time="2026-11-13T10:00:00Z")
    status, _note = verify_timestamp_token(stamped["envelope"], "sha256:" + "cd" * 32, store)
    assert status == "TSA_INVALID"


def test_mock_tsa_token_untrusted_key_invalid() -> None:
    tsa, _store = _tsa_pair()
    stamped = tsa.timestamp(DIGEST, gen_time="2026-11-13T10:00:00Z")
    _priv, other_pub = generate_ed25519_keypair()
    other_store = TrustStore.from_list(
        [{"key_id": "tsa-other-1", "public_key_pem": other_pub.decode()}]
    )
    status, _note = verify_timestamp_token(stamped["envelope"], DIGEST, other_store)
    assert status == "TSA_INVALID"


def test_mock_tsa_token_tampered_request_invalid() -> None:
    """Request/token cross-check: even a correctly-signed token fails
    when its embedded RFC 3161 request carries a different digest."""
    from oev.canonical import canonicalize_json
    from oev.dsse import build_dsse_envelope, compute_pae
    from oev.signing import load_ed25519_private_key

    tsa, store = _tsa_pair()
    stamped = tsa.timestamp(DIGEST, gen_time="2026-11-13T10:00:00Z")
    token = dict(stamped["token"])
    other_der, _nonce = build_timestamp_request("sha256:" + "12" * 32)
    token["request_der_b64"] = base64.b64encode(other_der).decode("ascii")
    # Re-sign with the TSA key itself (attacker holds the TSA key in
    # this scenario): the signature is valid, so only the cross-check
    # can catch the tampering.
    key = load_ed25519_private_key(tsa._private_key_pem)
    payload_bytes = canonicalize_json(token)
    sig = key.sign(compute_pae("application/vnd.oev.timestamp-token+json", payload_bytes))
    envelope = build_dsse_envelope(
        payload_type="application/vnd.oev.timestamp-token+json",
        payload_bytes=payload_bytes,
        signatures=[{"sig": base64.b64encode(sig).decode("ascii"), "keyid": "tsa-mock-1"}],
    )
    status, _note = verify_timestamp_token(envelope, DIGEST, store)
    assert status == "TSA_INVALID"


def test_no_token_is_unverified_not_failed() -> None:
    _tsa, store = _tsa_pair()
    status, note = verify_timestamp_token(None, DIGEST, store)
    assert status == "UNVERIFIED"
    assert "not proven" in note


def test_no_tsa_trust_store_is_unverified() -> None:
    tsa, _store = _tsa_pair()
    stamped = tsa.timestamp(DIGEST, gen_time="2026-11-13T10:00:00Z")
    status, _note = verify_timestamp_token(stamped["envelope"], DIGEST, None)
    assert status == "UNVERIFIED"
