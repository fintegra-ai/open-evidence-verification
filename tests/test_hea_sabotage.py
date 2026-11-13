# SPDX-License-Identifier: Apache-2.0

"""Sabotage scenarios (HEA design §8): replay, fake PASS, tampered receipt,
missing steps, different code, fake time, witness compromise, log attacks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from oev.canonical import canonicalize_json
from oev.hea_verifier import verify_historical_execution
from oev.models import CheckResult, CheckStatus, OverallResult, VerificationReceipt
from oev.receipts import finalize_receipt
from oev.revocation import RevocationEntry, RevocationList
from oev.witness import build_attestation_payload
from tests.hea_helpers import (
    CLAIMED_TIME,
    build_valid_hea,
    hea_inputs,
    make_keypair,
    make_profile,
)

def test_extra_attestation_for_check_absent_from_receipt(tmp_path: Path) -> None:
    # The receipt drops an executed check (re-finalised, so its digest is
    # valid) while the attestation and the log event for it are still
    # supplied: the attestation is extra from the receipt's point of view
    # and must not be silently swallowed — RESULT_CONFLICT.
    bundle = build_valid_hea(tmp_path)
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    receipt_dict["checks"] = [
        c for c in receipt_dict["checks"] if c["check_id"] != "manifest_structure"
    ]
    receipt_dict["execution_attestations"] = [
        a for a in receipt_dict["execution_attestations"] if a["check_id"] != "manifest_structure"
    ]
    receipt = finalize_receipt(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=receipt))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "RESULT_CONFLICT"

def test_forged_extra_attestation_is_not_silently_accepted(tmp_path: Path) -> None:
    # An attacker signs an attestation for a check that was never executed
    # (directly with the witness key, bypassing the witness cross-check)
    # and anchors it at another check's log leaf. The verifier rejects
    # the submission instead of ignoring the extra envelope.
    from oev.attestation import sign_attestation_dsse

    bundle = build_valid_hea(tmp_path)
    payload = build_attestation_payload(
        execution_id=bundle["execution_id"],
        commitment_digest=bundle["commitment_digest"],
        bundle_digest=bundle["receipt"].package.digest,
        profile_digest=bundle["receipt"].profile.profile_digest,
        code_version={
            "engine": "oev 0.2.3-test",
            "adapter": "oept 0.1.3-test",
            "code_digest": bundle["code_digest"],
        },
        check_id="ghost_check",
        result_status="PASS",
        result_detail="",
        result_duration_ms=0,
        execution_status="COMPLETED",
        log_anchor={
            "log_id": "hea-log-001",
            "leaf_index": 1,  # archive_safety's CHECK_COMPLETED leaf
            "leaf_hash": bundle["log_events"][1].leaf_hash(),
        },
        claimed_time=CLAIMED_TIME,
        witness_key_id="wit-1",
    )
    forged = sign_attestation_dsse(payload, bundle["witness_private"], "wit-1")
    result = verify_historical_execution(
        hea_inputs(bundle, attestations=bundle["attestation_envelopes"] + [forged])
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "LOG_ANCHOR_INVALID"

def test_replay_attestation_to_another_package_fails(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, package_bytes=b"a completely different package")
    )
    assert result.reason == "BUNDLE_DIGEST_MISMATCH"

def test_fake_pass_receipt_without_witness_is_unproven(tmp_path: Path) -> None:
    # A producer that writes PASS and signs a receipt itself, with no
    # witness involvement, produces NO_ATTESTATION — never PROVEN.
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(hea_inputs(bundle, attestations=[]))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "NO_ATTESTATION"

def test_tampered_receipt_fail_to_pass_without_redigest(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt_dict = bundle["receipt"].to_dict(include_digest=True)
    receipt_dict["checks"][0]["status"] = "FAIL"
    receipt_dict["overall_result"] = "TECHNICAL_CHECKS_FAILED"
    tampered = VerificationReceipt.from_dict(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=tampered))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"

def test_tampered_receipt_fail_to_pass_with_redigest_conflicts_attestation(tmp_path: Path) -> None:
    # Attacker rewrites the receipt AND recomputes its digest (they hold no
    # witness key, so the attestation still says what the witness saw).
    bundle = build_valid_hea(tmp_path)
    checks = [
        CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.FAIL),
        CheckResult(check_id="manifest_structure", category="structure", status=CheckStatus.PASS),
    ]
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    receipt_dict["checks"] = [c.to_dict() for c in checks]
    receipt_dict["overall_result"] = "TECHNICAL_CHECKS_FAILED"
    receipt = finalize_receipt(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=receipt))
    assert result.reason == "RESULT_CONFLICT"

def test_missing_step_is_detected_not_silently_passed(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    receipt_dict["checks"].append(
        {"check_id": "ghost_check", "category": "safety", "status": "PASS", "duration_ms": 0}
    )
    receipt = finalize_receipt(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=receipt))
    assert result.reason == "MISSING_EXECUTION_STEP"

def test_different_code_execution_is_detected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, expected_code_digest="sha256:" + "5" * 64)
    )
    assert result.reason == "CODE_DIGEST_MISMATCH"

def test_backdated_claimed_time_does_not_change_the_verdict(tmp_path: Path) -> None:
    # hea-10: fake time — the whole bundle is built with claimed_time a year
    # in the past, consistently, with a witness key valid across the
    # interval. The verdict stays PROVEN (claimed_time is never used for
    # ordering), but the output still says time is not proven. This is the
    # documented v0.1 limit: backdating is NOT prevented, only neutralised.
    bundle = build_valid_hea(
        tmp_path,
        claimed_time="2025-11-13T07:20:00Z",
        key_not_before="2025-01-01T00:00:00Z",
    )
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert result.time_not_proven is True

def test_rewritten_attestation_breaks_receipt_binding(tmp_path: Path) -> None:
    # Re-signing an attestation (e.g. with a different claimed_time) after
    # the receipt was finalised breaks the receipt's attestation-digest
    # binding: fail-closed, RESULT_CONFLICT.
    bundle = build_valid_hea(tmp_path)
    service = bundle["service"]
    check = bundle["checks"][0]
    payload = build_attestation_payload(
        execution_id=bundle["execution_id"],
        commitment_digest=bundle["commitment_digest"],
        bundle_digest=bundle["receipt"].package.digest,
        profile_digest=bundle["receipt"].profile.profile_digest,
        code_version={
            "engine": "oev 0.2.3-test",
            "adapter": "oept 0.1.3-test",
            "code_digest": bundle["code_digest"],
        },
        check_id=check.check_id,
        result_status="PASS",
        result_detail="",
        result_duration_ms=0,
        execution_status="COMPLETED",
        log_anchor={
            "log_id": "hea-log-001",
            "leaf_index": 1,
            "leaf_hash": bundle["log_events"][1].leaf_hash(),
        },
        claimed_time="2025-11-13T07:20:00Z",
        witness_key_id="wit-1",
    )
    rewritten = service.attest(payload)
    envelopes = [rewritten, bundle["attestation_envelopes"][1]]
    result = verify_historical_execution(hea_inputs(bundle, attestations=envelopes))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason in ("RESULT_CONFLICT", "WITNESS_UNAUTHORIZED")

def test_witness_compromise_after_revocation_is_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    revocation = RevocationList(
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        entries=[
            RevocationEntry(
                key_id="wit-1", reason="key-compromise", revoked_at_claimed=CLAIMED_TIME
            )
        ],
    )
    result = verify_historical_execution(hea_inputs(bundle, revocation_list=revocation))
    assert result.reason == "WITNESS_KEY_REVOKED"

def test_log_middle_deletion_is_detected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    events = list(bundle["log_events"])
    del events[1]
    result = verify_historical_execution(hea_inputs(bundle, log_events=events))
    assert result.reason in ("LOG_GAP", "LOG_ANCHOR_INVALID")

def test_log_fork_same_seq_different_leaf_is_detected(tmp_path: Path) -> None:
    # Attacker rewrites one event's content but keeps seq numbers: the
    # checkpoint Merkle root no longer matches.
    bundle = build_valid_hea(tmp_path)
    events = list(bundle["log_events"])
    from oev.execution_log import LogEvent

    forked = LogEvent(
        log_id=events[1].log_id,
        seq=events[1].seq,
        event_type=events[1].event_type,
        execution_id=events[1].execution_id,
        check_id=events[1].check_id,
        event_digest="sha256:" + "7" * 64,
        prev_hash=events[1].prev_hash,
        claimed_time=events[1].claimed_time,
    )
    events[1] = forked
    result = verify_historical_execution(hea_inputs(bundle, log_events=events))
    assert result.reason in ("LOG_ANCHOR_INVALID", "LOG_GAP")

def test_profile_selection_manipulation_is_detected(tmp_path: Path) -> None:
    # Attacker swaps the profile file for a laxer one with the same id:
    # the profile digest no longer matches receipt + attestation.
    from tests.hea_helpers import make_profile

    bundle = build_valid_hea(tmp_path)
    lax = make_profile(required=["archive_safety"])
    lax = make_profile(required=["archive_safety", "manifest_structure"])
    # Same required list but different parameters -> different digest.
    lax_dict = lax.to_dict()
    lax_dict["parameters"] = {"lax": True}
    from oev.models import VerificationProfile

    lax = VerificationProfile.from_dict(lax_dict)
    result = verify_historical_execution(hea_inputs(bundle, profile=lax))
    assert result.reason == "PROFILE_DIGEST_MISMATCH"

def _resign_first_attestation(
    bundle: dict[str, Any], priv: bytes, key_id: str
) -> list[dict[str, Any]]:
    """Re-sign the first check's attestation payload with another key."""
    from oev.attestation import parse_attestation_envelope, sign_attestation_dsse

    payload = parse_attestation_envelope(bundle["attestation_envelopes"][0])
    payload["witness"] = dict(payload["witness"])
    payload["witness"]["witness_key_id"] = key_id
    return [sign_attestation_dsse(payload, priv, key_id), bundle["attestation_envelopes"][1]]

def test_receipt_key_used_as_witness_is_role_confusion(tmp_path: Path) -> None:
    # The attestation is cryptographically valid under a key the caller
    # trusts — but that key's role is receipt-signer, not witness.
    from oev.trust import TrustStore

    bundle = build_valid_hea(tmp_path)
    priv, _pub, entry = make_keypair(role="receipt-signer")
    entry["key_id"] = "rec-1"
    envelopes = _resign_first_attestation(bundle, priv, "rec-1")
    # The store keeps the real witness key (commitment still verifies)
    # AND the wrong-role key (the re-signed attestation verifies under it).
    wit_entry = {
        "key_id": "wit-1",
        "public_key_pem": bundle["witness_store"].keys[0].public_key_pem.decode(),
        "role": "witness",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-12-31T23:59:59Z",
    }
    store = TrustStore.from_list([wit_entry, entry])
    result = verify_historical_execution(
        hea_inputs(bundle, attestations=envelopes, witness_trust_store=store)
    )
    assert result.reason == "WITNESS_UNAUTHORIZED"

def test_checkpoint_key_used_as_witness_is_rejected(tmp_path: Path) -> None:
    # Same role confusion, with the checkpoint-signer key instead.
    from oev.trust import TrustStore

    bundle = build_valid_hea(tmp_path)
    entry = {
        "key_id": "cp-1",
        "public_key_pem": bundle["checkpoint_store"].keys[0].public_key_pem.decode(),
        "role": "checkpoint-signer",
        "not_after": "2027-12-31T23:59:59Z",
    }
    envelopes = _resign_first_attestation(bundle, bundle["checkpoint_private"], "cp-1")
    wit_entry = {
        "key_id": "wit-1",
        "public_key_pem": bundle["witness_store"].keys[0].public_key_pem.decode(),
        "role": "witness",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-12-31T23:59:59Z",
    }
    store = TrustStore.from_list([wit_entry, entry])
    result = verify_historical_execution(
        hea_inputs(bundle, attestations=envelopes, witness_trust_store=store)
    )
    assert result.reason == "WITNESS_UNAUTHORIZED"

def test_equivocation_two_results_same_check(tmp_path: Path) -> None:
    # Same execution, same check, two different signed results submitted
    # together: the verifier refuses the submission (RESULT_CONFLICT).
    bundle = build_valid_hea(tmp_path)
    service = bundle["service"]
    check = bundle["checks"][0]
    payload = build_attestation_payload(
        execution_id=bundle["execution_id"],
        commitment_digest=bundle["commitment_digest"],
        bundle_digest=bundle["receipt"].package.digest,
        profile_digest=bundle["receipt"].profile.profile_digest,
        code_version={
            "engine": "oev 0.2.3-test",
            "adapter": "oept 0.1.3-test",
            "code_digest": bundle["code_digest"],
        },
        check_id=check.check_id,
        result_status="FAIL",
        result_detail="second opinion",
        result_duration_ms=0,
        execution_status="COMPLETED",
        log_anchor={
            "log_id": "hea-log-001",
            "leaf_index": 1,
            "leaf_hash": bundle["log_events"][1].leaf_hash(),
        },
        claimed_time=CLAIMED_TIME,
        witness_key_id="wit-1",
    )
    second = service.attest(payload)
    envelopes = bundle["attestation_envelopes"] + [second]
    result = verify_historical_execution(hea_inputs(bundle, attestations=envelopes))
    assert result.reason == "RESULT_CONFLICT"

def test_commitment_signed_by_non_witness_key_rejected(tmp_path: Path) -> None:
    from oev.execution import build_commitment_envelope, compute_execution_id

    bundle = build_valid_hea(tmp_path)
    other_priv, _pub, _entry = make_keypair(role="receipt-signer")
    envelope = build_commitment_envelope(
        bundle["prebinding"],
        compute_execution_id(bundle["prebinding"]),
        CLAIMED_TIME,
        other_priv,
        "rec-1",
    )
    result = verify_historical_execution(hea_inputs(bundle, commitment_envelope=envelope))
    assert result.reason in ("WITNESS_UNAUTHORIZED", "SIGNATURE_UNTRUSTED", "SIGNATURE_INVALID")

def test_receipt_digest_binding_survives_json_roundtrip(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt_json = json.loads(canonicalize_json(bundle["receipt"].to_dict()).decode())
    receipt = VerificationReceipt.from_dict(receipt_json)
    result = verify_historical_execution(hea_inputs(bundle, receipt=receipt))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"

def test_log_anchor_pointing_at_wrong_leaf_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    service = bundle["service"]
    check = bundle["checks"][0]
    payload = build_attestation_payload(
        execution_id=bundle["execution_id"],
        commitment_digest=bundle["commitment_digest"],
        bundle_digest=bundle["receipt"].package.digest,
        profile_digest=bundle["receipt"].profile.profile_digest,
        code_version={
            "engine": "oev 0.2.3-test",
            "adapter": "oept 0.1.3-test",
            "code_digest": bundle["code_digest"],
        },
        check_id=check.check_id,
        result_status="PASS",
        result_detail="",
        result_duration_ms=0,
        execution_status="COMPLETED",
        log_anchor={
            "log_id": "hea-log-001",
            "leaf_index": 2,  # the OTHER check's leaf
            "leaf_hash": bundle["log_events"][2].leaf_hash(),
        },
        claimed_time=CLAIMED_TIME,
        witness_key_id="wit-1",
    )
    # The witness itself refuses: its log says leaf 2 is not this check.
    with pytest.raises(ValueError, match="log_anchor"):
        service.attest(payload)

def test_overall_failed_execution_is_proven_not_hidden(tmp_path: Path) -> None:
    checks = [
        CheckResult(
            check_id="archive_safety", category="safety", status=CheckStatus.FAIL, detail="bad"
        ),
        CheckResult(check_id="manifest_structure", category="structure", status=CheckStatus.PASS),
    ]
    bundle = build_valid_hea(tmp_path, checks=checks, overall=OverallResult.TECHNICAL_CHECKS_FAILED)
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert bundle["receipt"].overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
