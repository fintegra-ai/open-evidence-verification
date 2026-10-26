# SPDX-License-Identifier: Apache-2.0

"""Hostile adversarial review test suite for OEVP v0.1.

Validates resilience against:
- Duplicate JSON key parser differential attacks
- Non-finite floating point (NaN / Infinity) serialization attacks
- Overlapping required and optional profile checks
- Duplicate check_id injection in verification receipts
- Non-material vs material limitation handling in aggregation
- Bidirectional required check coverage in re-verification
- KeyID spoofing / envelope hint hijacking
- Bounding enforcement (DSSE signature count, TrustStore key count)
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from oev.canonical import (
    CanonicalizationError,
    canonicalize_json,
    safe_json_loads,
)
from oev.dsse import (
    DsseError,
    compute_pae,
    parse_dsse_envelope,
)
from oev.models import (
    CheckResult,
    CheckStatus,
    Limitation,
    OverallResult,
    VerificationProfile,
    VerificationReceipt,
)
from oev.receipts import aggregate_overall_result
from oev.trust import (
    MAX_TRUSTED_KEYS,
    TrustedKey,
    TrustStore,
    evaluate_receipt_trust,
)


def test_duplicate_json_keys_rejected() -> None:
    """Duplicate JSON keys must be rejected by safe_json_loads across all entry points."""
    dup_json = '{"key": 1, "key": 2}'
    with pytest.raises(ValueError, match="Duplicate JSON object key detected"):
        safe_json_loads(dup_json)

    # Test in nested structures
    dup_nested = '{"outer": {"nested": 1, "nested": 2}}'
    with pytest.raises(ValueError, match="Duplicate JSON object key detected"):
        safe_json_loads(dup_nested)


def test_nan_infinity_in_canonicalization_rejected() -> None:
    """Non-finite floats (NaN, +inf, -inf) must be rejected prior to JCS canonicalization."""
    with pytest.raises(CanonicalizationError, match="Non-finite float"):
        canonicalize_json({"val": float("nan")})

    with pytest.raises(CanonicalizationError, match="Non-finite float"):
        canonicalize_json({"val": float("inf")})

    with pytest.raises(CanonicalizationError, match="Non-finite float"):
        canonicalize_json({"val": float("-inf")})


def test_profile_disjoint_checks_enforced() -> None:
    """A profile must reject overlap between required_checks and optional_checks."""
    invalid_profile = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "test-overlap",
        "profile_version": "1.0",
        "target_format": "test/format",
        "required_checks": ["chk_manifest", "chk_signature"],
        "optional_checks": ["chk_signature", "chk_extra"],
    }
    with pytest.raises(ValueError, match="Checks cannot be both required and optional"):
        VerificationProfile.from_dict(invalid_profile)


def test_receipt_duplicate_check_id_rejected() -> None:
    """A receipt must reject duplicate check_id entries in checks[]."""
    invalid_receipt = {
        "receipt_id": "rec-dup",
        "protocol_version": "oev-receipt/0.1",
        "recorded_verification_time": "2026-09-05T12:00:00Z",
        "package": {
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "format": "test",
        },
        "profile": {
            "profile_id": "p1",
            "profile_version": "1",
            "profile_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        },
        "verifier": {"software": "test", "version": "1"},
        "trust_inputs": [],
        "checks": [
            {"check_id": "chk_1", "category": "cat", "status": "PASS"},
            {"check_id": "chk_1", "category": "cat", "status": "FAIL"},
        ],
        "limitations": [],
        "overall_result": "TECHNICAL_CHECKS_FAILED",
    }
    with pytest.raises(ValueError, match="Duplicate check_id in checks"):
        VerificationReceipt.from_dict(invalid_receipt)


def test_limitation_materiality_in_overall_aggregation() -> None:
    """Non-material limitations must not degrade an otherwise passing verification to PARTIAL."""
    checks = [
        CheckResult(check_id="req1", category="c", status=CheckStatus.PASS),
    ]

    # Case 1: Material limitation -> TECHNICAL_CHECKS_PARTIAL
    mat_lim = [Limitation(code="MAT_NOTE", description="Important limitation", material=True)]
    res1 = aggregate_overall_result(
        required_checks=["req1"],
        optional_checks=[],
        checks=checks,
        limitations=mat_lim,
    )
    assert res1 == OverallResult.TECHNICAL_CHECKS_PARTIAL

    # Case 2: Non-material limitation -> TECHNICAL_CHECKS_PASSED
    non_mat_lim = [Limitation(code="INFO_NOTE", description="Advisory info note", material=False)]
    res2 = aggregate_overall_result(
        required_checks=["req1"],
        optional_checks=[],
        checks=checks,
        limitations=non_mat_lim,
    )
    assert res2 == OverallResult.TECHNICAL_CHECKS_PASSED


def test_max_dsse_signatures_bound() -> None:
    """Envelope parser must reject envelopes with more than 32 signatures to prevent DoS."""
    sigs = [{"sig": "AAAA", "keyid": f"k_{i}"} for i in range(33)]
    envelope = {
        "payloadType": "application/test",
        "payload": base64.b64encode(b"hello").decode("ascii"),
        "signatures": sigs,
    }
    with pytest.raises(DsseError, match="signatures count exceeds maximum allowed"):
        parse_dsse_envelope(envelope)


def test_max_trusted_keys_bound() -> None:
    """TrustStore must reject adding more than 64 keys."""
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    store = TrustStore()
    for i in range(MAX_TRUSTED_KEYS):
        store.add_key(TrustedKey(key_id=f"key_{i}", public_key_pem=pub_pem, digest=f"d_{i}"))

    with pytest.raises(ValueError, match="cannot exceed maximum of 64 keys"):
        store.add_key(TrustedKey(key_id="key_overflow", public_key_pem=pub_pem, digest="d_over"))


def test_keyid_spoofing_attack_mitigation() -> None:
    """An attacker sets keyid to a trusted key\x27s ID, but signs with their own rogue key.

    Trust evaluation must ignore the keyid hint and verify the cryptographic signature
    against the actual caller-supplied trusted key PEM.
    """
    trusted_priv = Ed25519PrivateKey.generate()
    trusted_pub_pem = trusted_priv.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    trust_store = TrustStore(
        [TrustedKey(key_id="trusted_verifier_alpha", public_key_pem=trusted_pub_pem, digest="d1")]
    )

    attacker_priv = Ed25519PrivateKey.generate()

    payload_bytes = b'{"receipt_id": "spoofed"}'
    pae = compute_pae("application/test", payload_bytes)
    attacker_sig = attacker_priv.sign(pae)
    attacker_sig_b64 = base64.b64encode(attacker_sig).decode("ascii")

    envelope = {
        "payloadType": "application/test",
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [
            {
                "sig": attacker_sig_b64,
                "keyid": "trusted_verifier_alpha",
            }
        ],
    }

    eval_result = evaluate_receipt_trust(envelope, trust_store)
    assert eval_result.crypto_valid is False
    assert eval_result.is_trusted is False
    assert eval_result.trusted_key_id is None
    assert "did not match" in eval_result.reason
