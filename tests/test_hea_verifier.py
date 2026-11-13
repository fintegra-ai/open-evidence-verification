# SPDX-License-Identifier: Apache-2.0

"""Tests for the offline HEA verifier (HEA design §6, §7)."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from oev.canonical import canonicalize_json
from oev.dsse import build_dsse_envelope, compute_pae
from oev.execution_log import LogCompleteness, sign_completeness_dsse
from oev.hea_verifier import assess_disproven, verify_historical_execution
from oev.models import CheckResult, CheckStatus, OverallResult
from oev.receipts import finalize_receipt
from oev.signing import load_ed25519_private_key
from oev.trust import TrustStore
from oev.witness import build_attestation_payload
from tests.hea_helpers import (
    CLAIMED_TIME,
    build_valid_hea,
    hea_inputs,
    make_keypair,
    make_profile,
)


def test_valid_bundle_is_proven_with_time_not_proven(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert result.reason == ""
    assert result.time_not_proven is True
    assert result.witness_mode == "local-process"
    assert result.execution_id == bundle["execution_id"]
    assert len(result.limitations) == 4  # 2 limitations x 2 attestations
    assert all(entry["hea_result"] == "HISTORICAL_EXECUTION_PROVEN" for entry in result.per_check)
    assert any("not proven" in note.lower() for note in result.notes)


def test_no_attestation_is_unproven_not_invalid(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(hea_inputs(bundle, attestations=[]))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "NO_ATTESTATION"


def test_no_commitment_is_no_prebinding(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, commitment_envelope=None, prebinding=None)
    )
    assert result.reason == "NO_PREBINDING"


def test_commitment_only_without_prebinding_is_no_prebinding(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(hea_inputs(bundle, prebinding=None))
    assert result.reason == "NO_PREBINDING"


def test_wrong_package_bytes_is_bundle_mismatch(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(hea_inputs(bundle, package_bytes=b"different bytes"))
    assert result.reason == "BUNDLE_DIGEST_MISMATCH"


def test_profile_swap_is_profile_mismatch(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    other = make_profile(required=["archive_safety"])
    result = verify_historical_execution(hea_inputs(bundle, profile=other))
    assert result.reason == "PROFILE_DIGEST_MISMATCH"


def test_wrong_expected_code_digest(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, expected_code_digest="sha256:" + "0" * 64)
    )
    assert result.reason == "CODE_DIGEST_MISMATCH"


def test_attestation_result_conflict_with_receipt(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    service = bundle["service"]
    # Re-sign the first check's attestation with FAIL while the receipt says PASS.
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
        result_detail="forged",
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
    forged = service.attest(payload)
    envelopes = [forged, bundle["attestation_envelopes"][1]]
    result = verify_historical_execution(hea_inputs(bundle, attestations=envelopes))
    assert result.reason == "RESULT_CONFLICT"


def test_tampered_receipt_self_digest_is_conflict(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt_dict = bundle["receipt"].to_dict(include_digest=True)
    receipt_dict["checks"][0]["status"] = "FAIL"  # digest no longer matches
    from oev.models import VerificationReceipt

    tampered = VerificationReceipt.from_dict(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=tampered))
    assert result.reason == "RESULT_CONFLICT"


def test_receipt_attestation_digest_mismatch_is_conflict(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    receipt_dict["execution_attestations"][0]["attestation_digest"] = "sha256:" + "0" * 64
    receipt = finalize_receipt(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=receipt))
    assert result.reason == "RESULT_CONFLICT"


def test_unsupported_attestation_version(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    payload = {
        "protocol_version": "oev-attestation/9.9",
        "attestation_id": "att_" + "0" * 16,
        "execution_id": bundle["execution_id"],
    }
    payload_bytes = canonicalize_json(payload)
    key = load_ed25519_private_key(bundle["witness_private"])
    sig = base64.b64encode(
        key.sign(compute_pae("application/vnd.oev.execution-attestation+json", payload_bytes))
    ).decode()
    envelope = build_dsse_envelope(
        "application/vnd.oev.execution-attestation+json",
        payload_bytes,
        [{"sig": sig, "keyid": "wit-1"}],
    )
    result = verify_historical_execution(hea_inputs(bundle, attestations=[envelope]))
    assert result.reason == "UNSUPPORTED_PROTOCOL_VERSION"


def test_missing_checkpoint_is_log_anchor_invalid(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(hea_inputs(bundle, checkpoint_envelope=None))
    assert result.reason == "LOG_ANCHOR_INVALID"


def test_checkpoint_signed_by_unknown_key_is_log_anchor_invalid(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    from oev.execution_log import build_checkpoint, sign_checkpoint_dsse

    checkpoint = build_checkpoint(bundle["log_events"], "hea-log-001", CLAIMED_TIME)
    other_priv, _pub, _entry = make_keypair(role="checkpoint-signer")
    envelope = sign_checkpoint_dsse(checkpoint, other_priv, "cp-9")
    result = verify_historical_execution(hea_inputs(bundle, checkpoint_envelope=envelope))
    assert result.reason == "LOG_ANCHOR_INVALID"


def test_log_gap_is_detected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    events = list(bundle["log_events"])
    del events[2]  # remove a middle CHECK_COMPLETED event
    result = verify_historical_execution(hea_inputs(bundle, log_events=events))
    assert result.reason in ("LOG_GAP", "LOG_ANCHOR_INVALID")


def test_missing_execution_step_when_check_has_no_log_event(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    # Add a third PASS check to the receipt (re-finalised) with no log event
    # and no attestation: the execution step is missing.
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    receipt_dict["checks"].append(
        {"check_id": "ghost_check", "category": "safety", "status": "PASS", "duration_ms": 0}
    )
    receipt = finalize_receipt(receipt_dict)
    result = verify_historical_execution(hea_inputs(bundle, receipt=receipt))
    assert result.reason == "MISSING_EXECUTION_STEP"


def test_not_run_check_is_hea_not_applicable(tmp_path: Path) -> None:
    checks = [
        CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
        CheckResult(
            check_id="manifest_structure", category="structure", status=CheckStatus.NOT_RUN
        ),
    ]
    bundle = build_valid_hea(tmp_path, checks=checks, overall=OverallResult.PROFILE_UNSATISFIED)
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    by_id = {entry["check_id"]: entry for entry in result.per_check}
    assert by_id["manifest_structure"]["hea_result"] == "HEA_NOT_APPLICABLE"
    assert by_id["archive_safety"]["hea_result"] == "HISTORICAL_EXECUTION_PROVEN"


def test_failed_check_execution_can_still_be_proven(tmp_path: Path) -> None:
    # HEA proves execution, not success: a proven FAIL is still PROVEN.
    checks = [
        CheckResult(
            check_id="archive_safety", category="safety", status=CheckStatus.FAIL, detail="bad"
        ),
        CheckResult(check_id="manifest_structure", category="structure", status=CheckStatus.PASS),
    ]
    bundle = build_valid_hea(tmp_path, checks=checks, overall=OverallResult.TECHNICAL_CHECKS_FAILED)
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_revoked_witness_key_is_rejected(tmp_path: Path) -> None:
    from oev.revocation import RevocationEntry, RevocationList

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


def test_expired_witness_key_is_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    wit_entry = {
        "key_id": "wit-1",
        "public_key_pem": bundle["witness_store"].keys[0].public_key_pem.decode(),
        "role": "witness",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2026-01-02T00:00:00Z",  # expired long before CLAIMED_TIME
    }
    store = TrustStore.from_list([wit_entry])
    result = verify_historical_execution(hea_inputs(bundle, witness_trust_store=store))
    assert result.reason == "WITNESS_KEY_EXPIRED"


def test_witness_authorization_for_other_profile_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    auth = {"wit-1": {"profiles": ["some-other-profile"], "formats": []}}
    result = verify_historical_execution(hea_inputs(bundle, witness_authorization=auth))
    assert result.reason == "WITNESS_UNAUTHORIZED"


def test_witness_authorization_for_this_profile_passes(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    auth = {"wit-1": {"profiles": ["strict-conformance-profile"], "formats": []}}
    result = verify_historical_execution(hea_inputs(bundle, witness_authorization=auth))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_disproven_when_complete_log_has_no_execution_started(tmp_path: Path) -> None:
    from oev.execution_log import build_checkpoint, sign_checkpoint_dsse

    bundle = build_valid_hea(tmp_path)
    events = bundle["log_events"]
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    checkpoint_envelope = sign_checkpoint_dsse(checkpoint, bundle["checkpoint_private"], "cp-1")
    statement = LogCompleteness(
        log_id="hea-log-001",
        through_seq=checkpoint.checkpoint_seq,
        checkpoint_digest=checkpoint.checkpoint_digest(),
        claimed_time=CLAIMED_TIME,
    )
    completeness = sign_completeness_dsse(statement, bundle["checkpoint_private"], "cp-1")
    is_disproven, _note = assess_disproven(
        events,
        checkpoint_envelope,
        completeness,
        "exec_" + "f" * 32,  # never executed
        bundle["checkpoint_store"],
        bundle["checkpoint_store"],
    )
    assert is_disproven


def test_disproven_requires_completeness_statement(tmp_path: Path) -> None:
    from oev.execution_log import build_checkpoint, sign_checkpoint_dsse

    bundle = build_valid_hea(tmp_path)
    events = bundle["log_events"]
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    checkpoint_envelope = sign_checkpoint_dsse(checkpoint, bundle["checkpoint_private"], "cp-1")
    is_disproven, note = assess_disproven(
        events,
        checkpoint_envelope,
        None,  # no completeness statement
        "exec_" + "f" * 32,
        bundle["checkpoint_store"],
        bundle["checkpoint_store"],
    )
    assert not is_disproven
    assert "completeness" in note


def test_disproven_rejected_when_execution_started_exists(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    service = bundle["service"]
    from oev.execution_log import LogCheckpoint

    checkpoint = LogCheckpoint.from_dict(
        json.loads(base64.b64decode(bundle["checkpoint_envelope"]["payload"].encode()))
    )
    result = service.completeness(checkpoint, CLAIMED_TIME)
    is_disproven, _note = assess_disproven(
        bundle["log_events"],
        bundle["checkpoint_envelope"],
        result["envelope"],
        bundle["execution_id"],  # this one DID execute
        bundle["checkpoint_store"],
        bundle["checkpoint_store"],
    )
    assert not is_disproven


def test_verifier_uses_no_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = build_valid_hea(tmp_path)

    def _blocked(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network use attempted")

    monkeypatch.setattr(socket, "socket", _blocked)
    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_reverification_dimension_stays_separate(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, reverification_result="CANNOT_REPRODUCE")
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert result.reverification_result == "CANNOT_REPRODUCE"


def test_too_many_attestations_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    many = bundle["attestation_envelopes"] * 600  # 1200 > MAX 1024
    result = verify_historical_execution(hea_inputs(bundle, attestations=many))
    assert result.reason == "MALFORMED_ATTESTATION"


def test_duplicate_check_attestations_are_equivocation(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    envelopes = bundle["attestation_envelopes"] + [bundle["attestation_envelopes"][0]]
    result = verify_historical_execution(hea_inputs(bundle, attestations=envelopes))
    assert result.reason == "RESULT_CONFLICT"
