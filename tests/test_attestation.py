# SPDX-License-Identifier: Apache-2.0

"""Tests for per-check attestations (HEA design §3, §9.1, §9.2)."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from oev.attestation import (
    ATTESTATION_PAYLOAD_TYPE,
    KNOWN_TEST_KEY_DIGESTS,
    compute_attestation_digest,
    compute_attestation_id,
    evaluate_attestation_signature,
    parse_attestation_envelope,
    sign_attestation_dsse,
    validate_attestation_payload,
)
from oev.canonical import canonicalize_json
from oev.dsse import build_dsse_envelope, compute_pae
from oev.hashing import sha256_bytes
from oev.revocation import RevocationEntry, RevocationList
from oev.signing import generate_ed25519_keypair, load_ed25519_private_key
from oev.trust import TrustStore
from oev.witness import build_attestation_payload
from tests.hea_helpers import CLAIMED_TIME, NOT_AFTER, NOT_BEFORE, make_keypair

LIMITATIONS = [
    {"code": "WITNESS_LOCAL_ONLY", "description": "local witness", "material": True},
]


def _payload(**overrides: Any) -> dict[str, Any]:
    payload = build_attestation_payload(
        execution_id="exec_" + "a" * 32,
        commitment_digest="sha256:" + "b" * 64,
        bundle_digest="sha256:" + "c" * 64,
        profile_digest="sha256:" + "d" * 64,
        code_version={
            "engine": "oev 0.2.3",
            "adapter": "oept 0.1.3",
            "code_digest": "sha256:" + "e" * 64,
        },
        check_id="archive_safety",
        result_status="PASS",
        result_detail="ok",
        result_duration_ms=4,
        execution_status="COMPLETED",
        log_anchor={"log_id": "hea-log-001", "leaf_index": 1, "leaf_hash": "sha256:" + "f" * 64},
        claimed_time=CLAIMED_TIME,
        witness_key_id="wit-1",
        limitations=LIMITATIONS,
    )
    payload.update(overrides)
    return payload


def _witness_store(key_id: str = "wit-1") -> tuple[TrustStore, bytes]:
    priv, _pub, entry = make_keypair(role="witness")
    entry["key_id"] = key_id
    return TrustStore.from_list([entry]), priv


def _sign(payload: dict[str, Any], priv: bytes, key_id: str = "wit-1") -> dict[str, Any]:
    return sign_attestation_dsse(payload, priv, key_id)


def test_valid_attestation_signs_and_verifies_trusted() -> None:
    store, priv = _witness_store()
    envelope = _sign(_payload(), priv)
    payload, evaluation = evaluate_attestation_signature(envelope, store)
    assert payload is not None
    assert evaluation.crypto_valid is True
    assert evaluation.trusted_key_id == "wit-1"
    assert evaluation.reason == ""


def test_attestation_id_is_deterministic_and_per_check() -> None:
    assert compute_attestation_id("exec_" + "a" * 32, "c1") == compute_attestation_id(
        "exec_" + "a" * 32, "c1"
    )
    assert compute_attestation_id("exec_" + "a" * 32, "c1") != compute_attestation_id(
        "exec_" + "a" * 32, "c2"
    )
    assert compute_attestation_id("exec_" + "a" * 32, "c1") != compute_attestation_id(
        "exec_" + "b" * 32, "c1"
    )


def test_empty_limitations_rejected() -> None:
    payload = _payload(limitations=[])
    with pytest.raises(ValueError, match="limitations"):
        validate_attestation_payload(payload)


def test_missing_limitations_rejected() -> None:
    payload = _payload()
    del payload["limitations"]
    with pytest.raises(ValueError):
        validate_attestation_payload(payload)


def test_wrong_payload_type_rejected() -> None:
    _store, priv = _witness_store()
    envelope = _sign(_payload(), priv)
    envelope["payloadType"] = "application/vnd.oev.verification-receipt+json"
    with pytest.raises(ValueError):
        parse_attestation_envelope(envelope)


def test_multi_signature_envelope_accepts_any_trusted_witness() -> None:
    store, priv1 = _witness_store()
    priv2, _pub2, entry2 = make_keypair(role="witness")
    entry2["key_id"] = "wit-2"
    store = TrustStore.from_list(
        [
            {
                "key_id": "wit-1",
                "public_key_pem": store.keys[0].public_key_pem.decode(),
                "role": "witness",
                "not_before": NOT_BEFORE,
                "not_after": NOT_AFTER,
            },
            entry2,
        ]
    )
    payload = _payload()
    payload_bytes = canonicalize_json(payload)
    key1 = load_ed25519_private_key(priv1)
    key2 = load_ed25519_private_key(priv2)
    sigs = [
        {
            "sig": base64.b64encode(
                key1.sign(compute_pae(ATTESTATION_PAYLOAD_TYPE, payload_bytes))
            ).decode(),
            "keyid": "wit-1",
        },
        {
            "sig": base64.b64encode(
                key2.sign(compute_pae(ATTESTATION_PAYLOAD_TYPE, payload_bytes))
            ).decode(),
            "keyid": "wit-2",
        },
    ]
    envelope = build_dsse_envelope(ATTESTATION_PAYLOAD_TYPE, payload_bytes, sigs)
    _payload_out, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.crypto_valid is True
    assert evaluation.reason == ""


def test_receipt_signer_role_cannot_attest() -> None:
    priv, _pub, entry = make_keypair(role="receipt-signer")
    entry["key_id"] = "wit-1"
    store = TrustStore.from_list([entry])
    envelope = _sign(_payload(), priv)
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "WITNESS_UNAUTHORIZED"


def test_roleless_key_cannot_attest() -> None:
    priv, _pub, entry = make_keypair(role=None)
    entry["key_id"] = "wit-1"
    store = TrustStore.from_list([entry])
    envelope = _sign(_payload(), priv)
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "WITNESS_UNAUTHORIZED"


def test_witness_key_without_expiry_rejected() -> None:
    priv, _pub, entry = make_keypair(role="witness")
    del entry["not_after"]
    entry["key_id"] = "wit-1"
    store = TrustStore.from_list([entry])
    envelope = _sign(_payload(), priv)
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "WITNESS_KEY_EXPIRED"


def test_expired_witness_key_rejected() -> None:
    priv, _pub, entry = make_keypair(role="witness")
    entry["key_id"] = "wit-1"
    entry["not_after"] = "2026-01-02T00:00:00Z"  # before CLAIMED_TIME 2026-11-13
    store = TrustStore.from_list([entry])
    envelope = _sign(_payload(), priv)
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "WITNESS_KEY_EXPIRED"


def test_revoked_flag_in_store_rejected() -> None:
    priv, _pub, entry = make_keypair(role="witness")
    entry["key_id"] = "wit-1"
    entry["revoked"] = True
    store = TrustStore.from_list([entry])
    envelope = _sign(_payload(), priv)
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "WITNESS_KEY_REVOKED"


def test_revocation_list_rejected() -> None:
    store, priv = _witness_store()
    envelope = _sign(_payload(), priv)
    revocation = RevocationList(
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        entries=[
            RevocationEntry(
                key_id="wit-1", reason="key-compromise", revoked_at_claimed=CLAIMED_TIME
            )
        ],
    )
    _p, evaluation = evaluate_attestation_signature(envelope, store, revocation)
    assert evaluation.reason == "WITNESS_KEY_REVOKED"


def test_unknown_key_signature_is_untrusted() -> None:
    store, _priv = _witness_store()
    other_priv, _other_pub = generate_ed25519_keypair()
    # Payload names the unknown key too, so no caller-trusted key is hinted.
    payload = _payload()
    payload["witness"] = dict(payload["witness"])
    payload["witness"]["witness_key_id"] = "attacker"
    envelope = _sign(payload, other_priv, key_id="attacker")
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "SIGNATURE_UNTRUSTED"


def test_signature_by_other_key_under_trusted_key_id_is_invalid() -> None:
    # Same bytes signed by another key, but the payload claims wit-1: the
    # signature fails under the claimed trusted key -> SIGNATURE_INVALID.
    store, _priv = _witness_store()
    other_priv, _other_pub = generate_ed25519_keypair()
    envelope = _sign(_payload(), other_priv, key_id="wit-1")
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "SIGNATURE_INVALID"


def test_tampered_payload_after_signing_is_signature_invalid() -> None:
    store, priv = _witness_store()
    envelope = _sign(_payload(), priv)
    raw = base64.b64decode(envelope["payload"].encode())
    tampered = bytearray(raw)
    tampered[-10] = ord("X") if tampered[-10] != ord("X") else ord("Y")
    envelope["payload"] = base64.b64encode(bytes(tampered)).decode()
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    # Either the payload no longer parses (MALFORMED) or the signature fails
    # under the hinted trusted key (SIGNATURE_INVALID); both are fail-closed.
    assert evaluation.reason.split(":")[0] in ("MALFORMED_ATTESTATION", "SIGNATURE_INVALID")


def test_no_trust_store_is_untrusted() -> None:
    _store, priv = _witness_store()
    envelope = _sign(_payload(), priv)
    _p, evaluation = evaluate_attestation_signature(envelope, None)
    assert evaluation.reason == "SIGNATURE_UNTRUSTED"


def test_not_run_requires_interrupted_execution_status() -> None:
    payload = _payload(result={"status": "NOT_RUN", "detail": "", "duration_ms": 0})
    with pytest.raises(ValueError, match="NOT_RUN"):
        validate_attestation_payload(payload)


def test_detail_over_1kib_rejected() -> None:
    payload = _payload()
    payload["result"] = {"status": "PASS", "detail": "x" * 1025, "duration_ms": 0}
    with pytest.raises(ValueError, match="detail"):
        validate_attestation_payload(payload)


def test_witness_key_id_mismatch_rejected() -> None:
    store, priv = _witness_store()
    payload = _payload()
    payload["witness"] = dict(payload["witness"])
    payload["witness"]["witness_key_id"] = "wit-2"
    envelope = _sign(payload, priv, key_id="wit-1")
    _p, evaluation = evaluate_attestation_signature(envelope, store)
    assert evaluation.reason == "WITNESS_UNAUTHORIZED"


def test_known_test_key_digest_is_blocklisted() -> None:
    # The committed OEPT test-only public key digest is a fixed, public value.
    assert (
        "sha256:7b62577c0ed2710b0d171aa4bdb96834ccacdd91e73ab115f73b38130369656b"
        in KNOWN_TEST_KEY_DIGESTS
    )


def test_signing_with_blocklisted_key_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    import oev.attestation as attestation_mod

    priv, _pub, _entry = make_keypair(role="witness")
    from cryptography.hazmat.primitives import serialization

    public_pem = (
        load_ed25519_private_key(priv)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(
        attestation_mod, "KNOWN_TEST_KEY_DIGESTS", frozenset({sha256_bytes(public_pem)})
    )
    with pytest.raises(ValueError, match="test-only key"):
        _sign(_payload(), priv)


def test_attestation_digest_is_stable() -> None:
    payload = _payload()
    assert compute_attestation_digest(payload) == compute_attestation_digest(payload)


def test_unsupported_attestation_version_rejected_by_model() -> None:
    payload = _payload(protocol_version="oev-attestation/9.9")
    # Schema enum rejects the version before the model check runs; either
    # way the payload is refused as a ValueError.
    with pytest.raises(ValueError):
        validate_attestation_payload(payload)
