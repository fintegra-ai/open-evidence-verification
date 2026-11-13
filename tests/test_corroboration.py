# SPDX-License-Identifier: Apache-2.0

"""Tests for the independent-evidence corroboration layer (V3-C18).

All inputs are synthetic / generated; no real personal or financial
data. Keys are deterministic Ed25519 test keys derived from
SHA-256("c18-test-key:<seed>:<role>") — test keys only, never used
outside this file.

The tests assert the two-dimensional contract: the technical dimension
(the existing domain engines, unchanged) and the source-trust
dimension (``oev.corroboration``) are reported separately, and a
staged consistent lie is TECHNICAL_PASS + SOURCE_UNCORROBORATED when
no independent source exists, and SOURCE_MISMATCH when a trusted
independent source disagrees.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oev.corroboration import (
    REASON_CLAIMS_DIGEST_MISMATCH,
    REASON_CONTENT_DIGEST_MISMATCH,
    REASON_KEY_REVOKED,
    REASON_SELF_KEY,
    REASON_SIGNATURE_INVALID,
    REASON_TRUST_ROOT_UNKNOWN,
    CorroborationRecord,
    SourceTrust,
    build_corroboration_record,
    claims_digest,
    compare_claims,
    evaluate_profile_with_corroboration,
    sign_corroboration_dsse,
    verify_corroboration,
)
from oev.domain.ai_eval import AI_CHECK_IDS
from oev.domain.dataset import DATASET_CHECK_IDS
from oev.domain.financial import FINANCIAL_CHECK_IDS
from oev.hashing import sha256_bytes
from oev.models import VerificationProfile
from oev.schemas import validate_document
from oev.trust import TrustedKey, TrustStore
from tests.test_domain_profiles import ai_members, ds_members, fin_members


def _derive_key(seed: int, role: str) -> tuple[bytes, bytes]:
    """Deterministic Ed25519 keypair (private_pem, public_pem). Test keys only."""
    raw = hashlib.sha256(f"c18-test-key:{seed}:{role}".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return (
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _trusted_key(seed: int, role: str, **kw) -> tuple[TrustedKey, bytes, bytes]:
    priv, pub = _derive_key(seed, role)
    kw.setdefault("not_before", "2026-01-01T00:00:00Z")
    kw.setdefault("not_after", "2030-01-01T00:00:00Z")
    key = TrustedKey(
        key_id=f"c18-{role}-{seed}",
        public_key_pem=pub,
        digest=sha256_bytes(pub),
        **kw,
    )
    return key, priv, pub


def _j(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True).encode()


def _doc(members: dict[str, bytes], path: str) -> dict:
    return json.loads(members[path].decode())


def _profile(domain: str, check_ids: list[str]) -> VerificationProfile:
    return VerificationProfile(
        profile_id=f"{domain}-verify",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=list(check_ids),
        parameters={"domain": domain},
    )


FIN_PROFILE = _profile("financial-evidence", list(FINANCIAL_CHECK_IDS))
DS_PROFILE = _profile("dataset-release", list(DATASET_CHECK_IDS))
AI_PROFILE = _profile(
    "ai-model-eval",
    list(AI_CHECK_IDS),
)


def _source_setup(seed: int = 7):
    """Return (trust_roots, producer_ids, producer_digests, source_priv, source_key)."""
    source_key, source_priv, _ = _trusted_key(seed, "source")
    roots = {"c18-root": TrustStore([source_key])}
    return roots, source_priv, source_key


def _fin_source_record(seed: int = 7, amount: int = 123456) -> dict:
    roots, source_priv, _ = _source_setup(seed)
    record = build_corroboration_record(
        "synth-erp-system-01",
        "c18-source-7",
        "c18-root",
        {
            "amount_minor": amount,
            "invoice_no": "SYNTH-INV-0001",
            "seller_id": "SYNTH-SELLER-01",
            "buyer_id": "SYNTH-BUYER-01",
            "currency": "XXX",
        },
        issued_at="2026-11-13T00:00:00Z",
    )
    return {
        "envelope": sign_corroboration_dsse(record, source_priv, "c18-source-7"),
        "roots": roots,
        "record": record,
    }


# ---------------------------------------------------------------------------
# Record construction / digest binding
# ---------------------------------------------------------------------------


def test_claims_digest_is_jcs_deterministic() -> None:
    a = claims_digest({"b": 2, "a": 1})
    b = claims_digest({"a": 1, "b": 2})
    assert a == b
    assert a.startswith("sha256:")
    assert claims_digest({"a": 1}) != claims_digest({"a": 2})


def test_record_round_trip_and_schema_validation() -> None:
    record = build_corroboration_record(
        "synth-erp-system-01",
        "c18-source-7",
        "c18-root",
        {"amount_minor": 123456},
        issued_at="2026-11-13T00:00:00Z",
        timestamp_ref={"reference": "synth-tsa-token-1"},
    )
    doc = record.to_dict()
    validate_document(doc, "corroboration-0.1.schema.json")
    assert CorroborationRecord.from_dict(doc) == record
    assert record.content_digest == claims_digest({"amount_minor": 123456})


def test_record_with_wrong_protocol_version_is_rejected() -> None:
    with pytest.raises(ValueError, match="protocol version"):
        CorroborationRecord.from_dict(
            {
                "protocol_version": "oev-corroboration/9.9",
                "source_id": "s",
                "source_key_id": "k",
                "trust_root_id": "r",
                "content_digest": "sha256:" + "0" * 64,
                "claims": {},
            }
        )


def test_schema_rejects_missing_source_id() -> None:
    with pytest.raises(Exception, match="corroboration-0.1.schema.json"):
        validate_document(
            {
                "protocol_version": "oev-corroboration/0.1",
                "source_key_id": "k",
                "trust_root_id": "r",
                "content_digest": "sha256:" + "0" * 64,
                "claims": {},
            },
            "corroboration-0.1.schema.json",
        )


# ---------------------------------------------------------------------------
# verify_corroboration: the five outcomes
# ---------------------------------------------------------------------------


def test_valid_independent_record_is_corroborated() -> None:
    setup = _fin_source_record()
    result = verify_corroboration(setup["envelope"], setup["roots"])
    assert result.outcome == SourceTrust.CORROBORATED
    assert result.reason == "OK"
    assert result.matched_key_id == "c18-source-7"
    assert result.record is not None and result.record.claims["amount_minor"] == 123456


def test_no_record_is_explicitly_uncorroborated() -> None:
    result = verify_corroboration(None, {})
    assert result.outcome == SourceTrust.SOURCE_UNCORROBORATED
    assert result.reason == "NO_RECORD"


def test_forged_signature_is_rejected() -> None:
    setup = _fin_source_record()
    envelope = json.loads(json.dumps(setup["envelope"]))
    sig = envelope["signatures"][0]["sig"]
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode()
    result = verify_corroboration(envelope, setup["roots"])
    assert result.outcome == SourceTrust.SOURCE_REJECTED
    assert result.reason == REASON_SIGNATURE_INVALID


def test_signature_by_key_outside_the_root_is_rejected() -> None:
    outsider_priv, _ = _derive_key(7, "outsider")
    record = build_corroboration_record(
        "synth-erp-system-01", "c18-outsider-7", "c18-root", {"amount_minor": 123456}
    )
    envelope = sign_corroboration_dsse(record, outsider_priv, "c18-outsider-7")
    roots, _, _ = _source_setup()
    result = verify_corroboration(envelope, roots)
    assert result.outcome == SourceTrust.SOURCE_REJECTED
    assert result.reason == REASON_SIGNATURE_INVALID


def test_unknown_trust_root_is_rejected() -> None:
    setup = _fin_source_record()
    result = verify_corroboration(setup["envelope"], {"other-root": setup["roots"]["c18-root"]})
    assert result.outcome == SourceTrust.SOURCE_REJECTED
    assert result.reason == REASON_TRUST_ROOT_UNKNOWN


def test_malformed_envelope_is_a_controlled_rejection() -> None:
    roots, _, _ = _source_setup()
    assert verify_corroboration({"payload": "!!!not-base64!!!"}, roots).outcome == (
        SourceTrust.SOURCE_REJECTED
    )
    assert verify_corroboration("not-a-dict", roots).outcome == SourceTrust.SOURCE_REJECTED  # type: ignore[arg-type]


def test_record_whose_digest_does_not_bind_its_claims_is_rejected() -> None:
    roots, source_priv, _ = _source_setup()
    record = build_corroboration_record(
        "synth-erp-system-01", "c18-source-7", "c18-root", {"amount_minor": 123456}
    )
    tampered = CorroborationRecord(
        source_id=record.source_id,
        source_key_id=record.source_key_id,
        trust_root_id=record.trust_root_id,
        # Correctly signed, but the digest no longer matches the claims.
        content_digest="sha256:" + "0" * 64,
        claims=record.claims,
    )
    envelope = sign_corroboration_dsse(tampered, source_priv, "c18-source-7")
    result = verify_corroboration(envelope, roots)
    assert result.outcome == SourceTrust.SOURCE_REJECTED
    assert result.reason == REASON_CLAIMS_DIGEST_MISMATCH


def test_expected_digest_mismatch_is_mismatch_not_rejection() -> None:
    setup = _fin_source_record()
    expected = claims_digest({"amount_minor": 999999})
    result = verify_corroboration(
        setup["envelope"], setup["roots"], expected_content_digest=expected
    )
    assert result.outcome == SourceTrust.SOURCE_MISMATCH
    assert result.reason == REASON_CONTENT_DIGEST_MISMATCH


def test_expected_digest_match_still_corroborates() -> None:
    setup = _fin_source_record()
    result = verify_corroboration(
        setup["envelope"],
        setup["roots"],
        expected_content_digest=claims_digest(setup["record"].claims),
    )
    assert result.outcome == SourceTrust.CORROBORATED


def test_revoked_source_key_is_rejected() -> None:
    revoked_key, revoked_priv, _ = _trusted_key(7, "source-revoked", revoked=True)
    roots = {"c18-root": TrustStore([revoked_key])}
    record = build_corroboration_record(
        "synth-erp-system-01",
        "c18-source-revoked-7",
        "c18-root",
        {"amount_minor": 123456},
    )
    envelope = sign_corroboration_dsse(record, revoked_priv, "c18-source-revoked-7")
    result = verify_corroboration(envelope, roots)
    assert result.outcome == SourceTrust.SOURCE_REJECTED
    assert result.reason == REASON_KEY_REVOKED


def test_expired_source_key_at_issued_at_is_rejected() -> None:
    key, priv, _ = _trusted_key(
        7,
        "source-short",
        not_before="2026-01-01T00:00:00Z",
        not_after="2026-06-01T00:00:00Z",
    )
    roots = {"c18-root": TrustStore([key])}
    record = build_corroboration_record(
        "synth-erp-system-01",
        "c18-source-short-7",
        "c18-root",
        {"amount_minor": 123456},
        issued_at="2026-11-13T00:00:00Z",
    )
    envelope = sign_corroboration_dsse(record, priv, "c18-source-short-7")
    result = verify_corroboration(envelope, roots)
    assert result.outcome == SourceTrust.SOURCE_REJECTED
    assert result.reason == "KEY_EXPIRED"


# ---------------------------------------------------------------------------
# Independence: producer / witness keys are not independent sources
# ---------------------------------------------------------------------------


def test_producer_key_as_source_is_self_corroboration() -> None:
    producer_key, producer_priv, producer_pub = _trusted_key(7, "producer")
    roots = {"c18-root": TrustStore([producer_key])}
    record = build_corroboration_record(
        "synth-erp-system-01", "c18-producer-7", "c18-root", {"amount_minor": 123456}
    )
    envelope = sign_corroboration_dsse(record, producer_priv, "c18-producer-7")
    result = verify_corroboration(
        envelope,
        roots,
        producer_key_ids={"c18-producer-7"},
        producer_key_digests={sha256_bytes(producer_pub)},
    )
    assert result.outcome == SourceTrust.SELF_CORROBORATION
    assert result.reason == REASON_SELF_KEY


def test_producer_key_detected_by_digest_even_with_renamed_key_id() -> None:
    # The attacker re-registers the producer key under a fresh key id in a
    # "foreign" root. Key-id matching misses it; public-key digest matching
    # must still catch it.
    producer_key, producer_priv, producer_pub = _trusted_key(7, "producer")
    alias = TrustedKey(
        key_id="c18-foreign-erp-7",
        public_key_pem=producer_pub,
        digest=sha256_bytes(producer_pub),
        not_before="2026-01-01T00:00:00Z",
        not_after="2030-01-01T00:00:00Z",
    )
    assert producer_key.key_id != alias.key_id
    roots = {"c18-root": TrustStore([alias])}
    record = build_corroboration_record(
        "synth-erp-system-01", "c18-foreign-erp-7", "c18-root", {"amount_minor": 123456}
    )
    envelope = sign_corroboration_dsse(record, producer_priv, "c18-foreign-erp-7")
    result = verify_corroboration(
        envelope, roots, producer_key_digests={sha256_bytes(producer_pub)}
    )
    assert result.outcome == SourceTrust.SELF_CORROBORATION


def test_keyid_hint_is_ignored_for_trust() -> None:
    # Envelope keyid claims the trusted source key, but the signature was
    # made with the producer key (which is also in the root here). Trust
    # follows the key that cryptographically verified — the producer key —
    # so the outcome is SELF_CORROBORATION, never CORROBORATED.
    source_key, _, _ = _trusted_key(7, "source")
    producer_key, producer_priv, producer_pub = _trusted_key(7, "producer")
    roots = {"c18-root": TrustStore([source_key, producer_key])}
    record = build_corroboration_record(
        "synth-erp-system-01", "c18-source-7", "c18-root", {"amount_minor": 123456}
    )
    envelope = sign_corroboration_dsse(record, producer_priv, "c18-source-7")
    result = verify_corroboration(
        envelope, roots, producer_key_digests={sha256_bytes(producer_pub)}
    )
    assert result.outcome == SourceTrust.SELF_CORROBORATION
    assert result.matched_key_id == "c18-producer-7"


def test_witness_key_as_source_is_self_corroboration() -> None:
    witness_key, witness_priv, witness_pub = _trusted_key(7, "witness")
    roots = {"c18-root": TrustStore([witness_key])}
    record = build_corroboration_record(
        "synth-erp-system-01", "c18-witness-7", "c18-root", {"amount_minor": 123456}
    )
    envelope = sign_corroboration_dsse(record, witness_priv, "c18-witness-7")
    result = verify_corroboration(envelope, roots, producer_key_digests={sha256_bytes(witness_pub)})
    assert result.outcome == SourceTrust.SELF_CORROBORATION


# ---------------------------------------------------------------------------
# Two-dimensional wrapper: financial
# ---------------------------------------------------------------------------


def test_fin_valid_with_true_source_is_corroborated() -> None:
    setup = _fin_source_record()
    result = evaluate_profile_with_corroboration(
        fin_members(), FIN_PROFILE, [setup["envelope"]], setup["roots"]
    )
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.CORROBORATED
    assert result.comparison == "AGREE"
    assert result.mismatches == []


def test_fin_staged_lie_without_source_is_uncorroborated_not_pass() -> None:
    members = fin_members()
    for path in (
        "domain/financial/invoice.json",
        "domain/financial/erp_record.json",
        "domain/financial/payment.json",
    ):
        doc = _doc(members, path)
        doc["amount_minor"] = 999999
        members[path] = _j(doc)
    result = evaluate_profile_with_corroboration(members, FIN_PROFILE, [], {})
    # The honest Tur-3 miss, now explicit: technical PASS, source uncorroborated.
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.SOURCE_UNCORROBORATED
    assert result.comparison == "NOT_COMPARED"


def test_fin_staged_lie_with_true_source_is_mismatch() -> None:
    members = fin_members()
    for path in (
        "domain/financial/invoice.json",
        "domain/financial/erp_record.json",
        "domain/financial/payment.json",
    ):
        doc = _doc(members, path)
        doc["amount_minor"] = 999999
        members[path] = _j(doc)
    setup = _fin_source_record(amount=123456)  # the true amount
    result = evaluate_profile_with_corroboration(
        members, FIN_PROFILE, [setup["envelope"]], setup["roots"]
    )
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.SOURCE_MISMATCH
    assert result.comparison == "MISMATCH"
    assert any("amount_minor" in m for m in result.mismatches)


def test_fin_internal_mismatch_keeps_technical_fail_and_source_dimensions_separate() -> None:
    members = fin_members()
    erp = _doc(members, "domain/financial/erp_record.json")
    erp["amount_minor"] = 123457
    members["domain/financial/erp_record.json"] = _j(erp)
    result = evaluate_profile_with_corroboration(members, FIN_PROFILE, [], {})
    assert result.technical_summary == "TECHNICAL_FAIL"
    assert result.source_trust == SourceTrust.SOURCE_UNCORROBORATED


def test_fin_producer_key_source_is_self_even_when_claims_would_mismatch() -> None:
    members = fin_members()
    for path in (
        "domain/financial/invoice.json",
        "domain/financial/erp_record.json",
        "domain/financial/payment.json",
    ):
        doc = _doc(members, path)
        doc["amount_minor"] = 999999
        members[path] = _j(doc)
    producer_key, producer_priv, producer_pub = _trusted_key(7, "producer")
    roots = {"c18-root": TrustStore([producer_key])}
    record = build_corroboration_record(
        "synth-erp-system-01",
        "c18-producer-7",
        "c18-root",
        {
            "amount_minor": 123456,
            "invoice_no": "SYNTH-INV-0001",
            "seller_id": "SYNTH-SELLER-01",
            "buyer_id": "SYNTH-BUYER-01",
            "currency": "XXX",
        },
    )
    envelope = sign_corroboration_dsse(record, producer_priv, "c18-producer-7")
    result = evaluate_profile_with_corroboration(
        members,
        FIN_PROFILE,
        [envelope],
        roots,
        producer_key_digests={sha256_bytes(producer_pub)},
    )
    # Independence is checked before comparison: no mismatch verdict is
    # drawn from a non-independent record.
    assert result.source_trust == SourceTrust.SELF_CORROBORATION
    assert result.comparison == "NOT_COMPARED"


def test_fin_forged_source_signature_is_rejected_not_mismatch() -> None:
    setup = _fin_source_record()
    envelope = json.loads(json.dumps(setup["envelope"]))
    sig = envelope["signatures"][0]["sig"]
    raw = bytearray(base64.b64decode(sig))
    raw[-1] ^= 0x01
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode()
    result = evaluate_profile_with_corroboration(
        fin_members(), FIN_PROFILE, [envelope], setup["roots"]
    )
    assert result.source_trust == SourceTrust.SOURCE_REJECTED
    assert result.comparison == "NOT_COMPARED"


def test_fin_self_plus_genuine_records_aggregate_to_corroborated() -> None:
    producer_key, producer_priv, producer_pub = _trusted_key(7, "producer")
    source_key, source_priv, _ = _trusted_key(7, "source")
    roots = {"c18-root": TrustStore([producer_key, source_key])}
    self_record = build_corroboration_record(
        "synth-erp-system-01", "c18-producer-7", "c18-root", {"amount_minor": 1}
    )
    true_record = build_corroboration_record(
        "synth-erp-system-01",
        "c18-source-7",
        "c18-root",
        {
            "amount_minor": 123456,
            "invoice_no": "SYNTH-INV-0001",
            "seller_id": "SYNTH-SELLER-01",
            "buyer_id": "SYNTH-BUYER-01",
            "currency": "XXX",
        },
    )
    envelopes = [
        sign_corroboration_dsse(self_record, producer_priv, "c18-producer-7"),
        sign_corroboration_dsse(true_record, source_priv, "c18-source-7"),
    ]
    result = evaluate_profile_with_corroboration(
        fin_members(),
        FIN_PROFILE,
        envelopes,
        roots,
        producer_key_digests={sha256_bytes(producer_pub)},
    )
    assert result.source_trust == SourceTrust.CORROBORATED
    assert len(result.verifications) == 2
    assert {v.outcome for v in result.verifications} == {
        SourceTrust.SELF_CORROBORATION,
        SourceTrust.CORROBORATED,
    }


# ---------------------------------------------------------------------------
# Two-dimensional wrapper: dataset
# ---------------------------------------------------------------------------


def _ds_source_setup(seed: int = 7, sha: str | None = None):
    from tests.test_domain_profiles import DATA_CSV

    roots, source_priv, _ = _source_setup(seed)
    digest = sha if sha is not None else hashlib.sha256(DATA_CSV).hexdigest()
    record = build_corroboration_record(
        "synth-dataset-registry-01",
        "c18-source-7",
        "c18-root",
        {"sha256": digest, "rows_declared": 4, "dataset_id": "SYNTH-DS-0001", "version": "1.2.0"},
    )
    return {
        "envelope": sign_corroboration_dsse(record, source_priv, "c18-source-7"),
        "roots": roots,
    }


def test_ds_valid_with_true_source_is_corroborated() -> None:
    setup = _ds_source_setup()
    result = evaluate_profile_with_corroboration(
        ds_members(), DS_PROFILE, [setup["envelope"]], setup["roots"]
    )
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.CORROBORATED
    assert result.comparison == "AGREE"


def test_ds_staged_lie_with_true_source_is_mismatch() -> None:
    from tests.test_domain_profiles import DATA_CSV

    members = ds_members()
    # Falsify the data consistently: change one cell, recompute the
    # manifest checksum, so every bundle-internal check still passes.
    falsified = b"synth_a,synth_b,synth_c\n2,2.5,alpha\n2,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"
    assert falsified != DATA_CSV
    members["domain/dataset/data.csv"] = falsified
    man = _doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(falsified).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    setup = _ds_source_setup()  # source attests the ORIGINAL data checksum
    result = evaluate_profile_with_corroboration(
        members, DS_PROFILE, [setup["envelope"]], setup["roots"]
    )
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.SOURCE_MISMATCH
    assert any("sha256" in m for m in result.mismatches)


def test_ds_staged_lie_without_source_is_uncorroborated() -> None:
    members = ds_members()
    falsified = b"synth_a,synth_b,synth_c\n2,2.5,alpha\n2,3.5,beta\n3,4.5,gamma\n4,5.5,delta\n"
    members["domain/dataset/data.csv"] = falsified
    man = _doc(members, "domain/dataset/manifest.json")
    man["sha256"] = hashlib.sha256(falsified).hexdigest()
    members["domain/dataset/manifest.json"] = _j(man)
    result = evaluate_profile_with_corroboration(members, DS_PROFILE, [], {})
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.SOURCE_UNCORROBORATED


# ---------------------------------------------------------------------------
# Two-dimensional wrapper: ai-eval
# ---------------------------------------------------------------------------


def _expected_metrics(pairs):
    mae = sum(abs(t - p) for t, p in pairs) / len(pairs)
    rmse = math.sqrt(sum((t - p) ** 2 for t, p in pairs) / len(pairs))
    mean = sum(t for t, _ in pairs) / len(pairs)
    ss_tot = sum((t - mean) ** 2 for t, _ in pairs)
    r2 = 1.0 - sum((t - p) ** 2 for t, p in pairs) / ss_tot
    return mae, rmse, r2


def _ai_source_setup(seed: int = 7, mae=None, rmse=None, r2=None):
    from tests.test_domain_profiles import PAIRS

    roots, source_priv, _ = _source_setup(seed)
    m, r, r2v = _expected_metrics(PAIRS)
    record = build_corroboration_record(
        "synth-eval-harness-01",
        "c18-source-7",
        "c18-root",
        {
            "mae": mae if mae is not None else m,
            "rmse": rmse if rmse is not None else r,
            "r2": r2 if r2 is not None else r2v,
        },
    )
    return {
        "envelope": sign_corroboration_dsse(record, source_priv, "c18-source-7"),
        "roots": roots,
    }


def test_ai_valid_with_true_source_is_corroborated() -> None:
    setup = _ai_source_setup()
    result = evaluate_profile_with_corroboration(
        ai_members(), AI_PROFILE, [setup["envelope"]], setup["roots"]
    )
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.CORROBORATED
    assert result.comparison == "AGREE"


def test_ai_staged_lie_with_true_source_is_mismatch() -> None:
    # Falsify predictions consistently: new predictions, reported metrics
    # recomputed to match them, input hash updated — bundle-internal
    # checks pass, but the independent harness attests the true metrics.
    fake_pairs = [(1.0, 1.4), (2.0, 2.4), (3.0, 3.4), (4.0, 4.4), (5.0, 5.4)]
    fake_csv = b"y_true,y_pred\n" + b"\n".join(f"{t},{p}".encode() for t, p in fake_pairs) + b"\n"
    members = ai_members()
    members["domain/ai-eval/predictions.csv"] = fake_csv
    mae, rmse, r2 = _expected_metrics(fake_pairs)
    ev = _doc(members, "domain/ai-eval/eval.json")
    ev["reported"] = {"mae": mae, "rmse": rmse, "r2": r2}
    ev["input_sha256"] = hashlib.sha256(fake_csv).hexdigest()
    members["domain/ai-eval/eval.json"] = _j(ev)
    setup = _ai_source_setup()  # source attests the ORIGINAL metrics
    result = evaluate_profile_with_corroboration(
        members, AI_PROFILE, [setup["envelope"]], setup["roots"]
    )
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.SOURCE_MISMATCH
    assert any("mae" in m for m in result.mismatches)


def test_ai_staged_lie_without_source_is_uncorroborated() -> None:
    fake_pairs = [(1.0, 1.4), (2.0, 2.4), (3.0, 3.4), (4.0, 4.4), (5.0, 5.4)]
    fake_csv = b"y_true,y_pred\n" + b"\n".join(f"{t},{p}".encode() for t, p in fake_pairs) + b"\n"
    members = ai_members()
    members["domain/ai-eval/predictions.csv"] = fake_csv
    mae, rmse, r2 = _expected_metrics(fake_pairs)
    ev = _doc(members, "domain/ai-eval/eval.json")
    ev["reported"] = {"mae": mae, "rmse": rmse, "r2": r2}
    ev["input_sha256"] = hashlib.sha256(fake_csv).hexdigest()
    members["domain/ai-eval/eval.json"] = _j(ev)
    result = evaluate_profile_with_corroboration(members, AI_PROFILE, [], {})
    assert result.technical_summary == "TECHNICAL_PASS"
    assert result.source_trust == SourceTrust.SOURCE_UNCORROBORATED


# ---------------------------------------------------------------------------
# compare_claims edge cases + serialisation
# ---------------------------------------------------------------------------


def test_compare_claims_with_no_comparable_field_is_not_compared() -> None:
    comp, mism, _ = compare_claims("financial", fin_members(), {"unrelated": 1})
    assert comp == "NOT_COMPARED"
    assert mism == []


def test_compare_claims_unknown_domain_is_not_compared() -> None:
    comp, _, _ = compare_claims("unknown", fin_members(), {"amount_minor": 1})
    assert comp == "NOT_COMPARED"


def test_wrapper_result_serialises_to_json() -> None:
    setup = _fin_source_record()
    result = evaluate_profile_with_corroboration(
        fin_members(), FIN_PROFILE, [setup["envelope"]], setup["roots"]
    )
    doc = result.to_dict()
    json.dumps(doc)  # must be JSON-serialisable
    assert doc["source_trust"] == "CORROBORATED"
    assert doc["technical_summary"] == "TECHNICAL_PASS"
    assert doc["verifications"][0]["matched_key_id"] == "c18-source-7"
