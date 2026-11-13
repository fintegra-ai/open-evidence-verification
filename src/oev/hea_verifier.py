# SPDX-License-Identifier: Apache-2.0

"""Independent offline HEA verifier (HEA design §6).

Import-closure rule (§6.3): this module imports only protocol-core
modules — ``canonical``, ``hashing``, ``dsse``, ``trust``, ``schemas``,
``execution``, ``attestation``, ``execution_log``, ``revocation``,
``models``, ``receipts``, ``profiles``, ``signing``. It never imports
``engine``, ``adapters``, ``replay``, ``cli``, ``inspect``,
``decision_pack`` or ``pack_verifier`` (enforced by
``tests/test_hea_verifier_independence.py``). The reproducibility
dimension (MATCH/MISMATCH/CANNOT_REPRODUCE) is supplied by the caller —
this verifier does not re-execute checks; it verifies historical
execution only (§7.4: the two dimensions stay separate, never one score).

Verification order is normative (§6.2): cheap and foundational checks
first; any step fails closed with HISTORICAL_EXECUTION_UNPROVEN plus
exactly one HeaReason code. There is no silent UNPROVEN.

Deviation note (recorded, not hidden): §6 step 2 names a
``RECEIPT_INVALID`` reason, but the normative §7.3 code list has no such
code. A receipt whose self-digest fails is reported as
``RESULT_CONFLICT`` ("receipt self-digest invalid") — the attestation↔
receipt binding cannot be established. See docs/PROTOCOL_SECURITY_REVIEW.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .attestation import (
    ATTESTATION_PROTOCOL_VERSION,
    compute_attestation_digest,
    evaluate_attestation_signature,
    parse_attestation_envelope,
    validate_attestation_payload,
)
from .dsse import DsseError, parse_dsse_envelope
from .execution import (
    compute_execution_id,
    is_valid_execution_id,
    parse_commitment_envelope,
)
from .execution_log import (
    LogEvent,
    events_from_jsonl,
    merkle_root,
    verify_checkpoint_signature,
    verify_completeness_signature,
    verify_event_chain,
    verify_merkle_inclusion_proof,
)
from .hashing import sha256_bytes
from .models import (
    CHECK_STATUS_EXECUTED,
    CheckStatus,
    HistoricalExecutionResult,
    VerificationProfile,
    VerificationReceipt,
)
from .profiles import compute_profile_digest
from .receipts import verify_receipt_digest
from .revocation import RevocationList
from .signing import verify_dsse_signature_with_key
from .trust import TrustStore

MAX_ATTESTATIONS: int = 1024


@dataclass
class HeaVerificationInputs:
    """All inputs to the offline HEA verifier (§6.1). No network is used."""

    package_bytes: bytes
    receipt: VerificationReceipt | dict[str, Any]
    profile: VerificationProfile | dict[str, Any]
    attestations: list[dict[str, Any]]  # DSSE envelopes, one per check
    commitment_envelope: dict[str, Any] | None = None
    prebinding: dict[str, Any] | None = None
    log_events: list[LogEvent] | None = None
    log_jsonl: bytes | None = None
    checkpoint_envelope: dict[str, Any] | None = None
    inclusion_proofs: dict[str, list[dict[str, str]]] | None = None
    witness_trust_store: TrustStore | None = None
    checkpoint_trust_store: TrustStore | None = None
    revocation_list: RevocationList | None = None
    expected_code_digest: str | None = None
    witness_authorization: dict[str, dict[str, list[str]]] | None = None
    reverification_result: str | None = None
    # DISPROVEN inputs (design §7.2): only consulted when no attestation
    # exists for the execution.
    completeness_envelope: dict[str, Any] | None = None
    log_operator_trust_store: TrustStore | None = None
    claimed_execution_id: str | None = None


@dataclass
class HeaVerificationResult:
    """Offline HEA verdict: historical-execution dimension only (§7.4)."""

    historical_execution: str
    reason: str
    notes: list[str] = field(default_factory=list)
    per_check: list[dict[str, Any]] = field(default_factory=list)
    witness_mode: str | None = None
    limitations: list[dict[str, Any]] = field(default_factory=list)
    time_not_proven: bool = True
    execution_id: str | None = None
    receipt_digest: str = ""
    reverification_result: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "historical_execution": self.historical_execution,
            "reason": self.reason,
            "notes": list(self.notes),
            "per_check": [dict(c) for c in self.per_check],
            "witness_mode": self.witness_mode,
            "limitations": [dict(lim) for lim in self.limitations],
            "time_not_proven": self.time_not_proven,
            "execution_id": self.execution_id,
            "receipt_digest": self.receipt_digest,
            "reverification_result": self.reverification_result,
        }


def _unproven(
    reason: str,
    notes: list[str],
    receipt: VerificationReceipt,
    per_check: list[dict[str, Any]] | None = None,
    execution_id: str | None = None,
    witness_mode: str | None = None,
    limitations: list[dict[str, Any]] | None = None,
    reverification_result: str | None = None,
) -> HeaVerificationResult:
    return HeaVerificationResult(
        historical_execution=HistoricalExecutionResult.UNPROVEN.value,
        reason=reason,
        notes=notes,
        per_check=per_check or [],
        witness_mode=witness_mode,
        limitations=limitations or [],
        time_not_proven=True,
        execution_id=execution_id,
        receipt_digest=receipt.receipt_digest,
        reverification_result=reverification_result,
    )


def _verify_commitment_signature(
    envelope: dict[str, Any],
    witness_trust_store: TrustStore | None,
    revocation_list: RevocationList | None,
    claimed_time: str,
) -> str:
    """Verify a commitment DSSE signature. Returns ``""`` or a HeaReason code."""
    if witness_trust_store is None or len(witness_trust_store.keys) == 0:
        return "SIGNATURE_UNTRUSTED"
    try:
        _pt, _pb, signatures = parse_dsse_envelope(envelope)
    except DsseError:
        return "MALFORMED_ATTESTATION"
    hinted = {s.get("keyid", "") for s in signatures}
    candidate_exists = any(k.key_id in hinted for k in witness_trust_store.keys)
    for trusted_key in witness_trust_store.keys:
        if not verify_dsse_signature_with_key(envelope, trusted_key.public_key_pem):
            continue
        if revocation_list is not None and revocation_list.is_revoked(trusted_key.key_id):
            return "WITNESS_KEY_REVOKED"
        if trusted_key.revoked:
            return "WITNESS_KEY_REVOKED"
        if trusted_key.role != "witness":
            return "WITNESS_UNAUTHORIZED"
        if trusted_key.not_after is None:
            return "WITNESS_KEY_EXPIRED"
        state = trusted_key.key_state_at(claimed_time)
        if state == "expired":
            return "WITNESS_KEY_EXPIRED"
        return ""
    return "SIGNATURE_INVALID" if candidate_exists else "SIGNATURE_UNTRUSTED"


def assess_disproven(
    log_events: list[LogEvent],
    checkpoint_envelope: dict[str, Any] | None,
    completeness_envelope: dict[str, Any] | None,
    execution_id: str,
    checkpoint_trust_store: TrustStore | None,
    log_operator_trust_store: TrustStore | None,
) -> tuple[bool, str]:
    """DISPROVEN assessment (design §7.2): all three conditions must hold.

    1. A complete, signed log covers the claimed interval (gapless chain
       + valid signed checkpoint).
    2. No EXECUTION_STARTED event for ``execution_id`` exists in the log.
    3. Log completeness is backed by the operator's signed statement (or
       an external transparency-log anchor — not implemented in v0.1).

    Returns ``(is_disproven, note)``. Anything short of all three yields
    ``(False, note)`` — the default stays UNPROVEN, never DISPROVEN.
    """
    if checkpoint_envelope is None:
        return False, "no signed checkpoint: log completeness cannot be established"
    checkpoint, checkpoint_reason = verify_checkpoint_signature(
        checkpoint_envelope, checkpoint_trust_store
    )
    if checkpoint is None or checkpoint_reason:
        return False, f"checkpoint signature invalid ({checkpoint_reason or 'unparseable'})"
    ok, chain_note = verify_event_chain(log_events)
    if not ok:
        return False, f"log chain invalid: {chain_note}"
    if len(log_events) != checkpoint.leaf_count:
        return False, "log event count does not match checkpoint leaf_count"
    leaves = [e.leaf_hash() for e in log_events]
    if merkle_root(leaves) != checkpoint.merkle_root:
        return False, "log Merkle root does not match checkpoint"
    if completeness_envelope is None:
        return False, "no log completeness statement: absence may mean deletion, not non-execution"
    statement, completeness_ok = verify_completeness_signature(
        completeness_envelope, log_operator_trust_store
    )
    if statement is None or not completeness_ok:
        return False, "log completeness statement missing or untrusted"
    if statement.through_seq < checkpoint.checkpoint_seq:
        return False, "completeness statement does not cover the checkpoint interval"
    if statement.checkpoint_digest != checkpoint.checkpoint_digest():
        return False, "completeness statement does not match the checkpoint"
    for event in log_events:
        if event.execution_id == execution_id and event.event_type == "EXECUTION_STARTED":
            return False, "EXECUTION_STARTED exists for this execution_id; not disproven"
    return True, "complete signed log contains no EXECUTION_STARTED for this execution_id"


def verify_historical_execution(inputs: HeaVerificationInputs) -> HeaVerificationResult:
    """Run the §6 offline verification sequence. Never touches the network."""
    receipt = (
        inputs.receipt
        if isinstance(inputs.receipt, VerificationReceipt)
        else VerificationReceipt.from_dict(dict(inputs.receipt))
    )
    profile = (
        inputs.profile
        if isinstance(inputs.profile, VerificationProfile)
        else VerificationProfile.from_dict(dict(inputs.profile))
    )
    notes: list[str] = [
        "Time is NOT proven: claimed_time fields are self-asserted; ordering comes from log sequence only (HEA design §9.4). Backdating is not prevented in v0.1.",
    ]
    if inputs.revocation_list is None:
        notes.append(
            "No revocation list supplied; revocation status unknown (fail-explicit, §9.1)."
        )
    if inputs.expected_code_digest is None:
        notes.append("No expected code digest supplied; code identity not independently checked.")
    if inputs.witness_authorization is None:
        notes.append("No witness authorisation supplied; authorisation not checked.")

    per_check: list[dict[str, Any]] = []
    for check in receipt.checks:
        status = str(check.status.value if isinstance(check.status, CheckStatus) else check.status)
        if status == "NOT_RUN":
            per_check.append(
                {
                    "check_id": check.check_id,
                    "hea_result": HistoricalExecutionResult.NOT_APPLICABLE.value,
                    "reason": "",
                    "note": "Check never ran; no attestation is expected (HEA_NOT_APPLICABLE).",
                }
            )
        else:
            per_check.append(
                {"check_id": check.check_id, "hea_result": "", "reason": "", "note": ""}
            )

    def _fail(reason: str, note: str) -> HeaVerificationResult:
        notes.append(note)
        for entry in per_check:
            if not entry["hea_result"]:
                entry["hea_result"] = HistoricalExecutionResult.UNPROVEN.value
                entry["reason"] = reason
        return _unproven(
            reason,
            notes,
            receipt,
            per_check=per_check,
            execution_id=inputs.claimed_execution_id,
            reverification_result=inputs.reverification_result,
        )

    # ---- Step 0: attestation presence -------------------------------------
    if len(inputs.attestations) > MAX_ATTESTATIONS:
        return _fail(
            "MALFORMED_ATTESTATION",
            f"Attestation count exceeds the {MAX_ATTESTATIONS} limit.",
        )
    if not inputs.attestations:
        # DISPROVEN is the only alternative to UNPROVEN here, and only
        # under the three §7.2 conditions.
        if inputs.claimed_execution_id and inputs.log_events is not None:
            is_disproven, dis_note = assess_disproven(
                inputs.log_events,
                inputs.checkpoint_envelope,
                inputs.completeness_envelope,
                inputs.claimed_execution_id,
                inputs.checkpoint_trust_store,
                inputs.log_operator_trust_store,
            )
            notes.append(f"DISPROVEN assessment: {dis_note}")
            if is_disproven:
                for entry in per_check:
                    if not entry["hea_result"]:
                        entry["hea_result"] = HistoricalExecutionResult.DISPROVEN.value
                return HeaVerificationResult(
                    historical_execution=HistoricalExecutionResult.DISPROVEN.value,
                    reason="",
                    notes=notes,
                    per_check=per_check,
                    time_not_proven=True,
                    execution_id=inputs.claimed_execution_id,
                    receipt_digest=receipt.receipt_digest,
                    reverification_result=inputs.reverification_result,
                )
        return _fail(
            "NO_ATTESTATION",
            "No attestation is bound to this receipt (pre-HEA receipt or lost attestation). "
            "This does not invalidate the receipt itself.",
        )

    # ---- Step 1: schema / canonical form ----------------------------------
    parsed_attestations: list[dict[str, Any]] = []
    for index, envelope in enumerate(inputs.attestations):
        if not isinstance(envelope, dict):
            return _fail("MALFORMED_ATTESTATION", f"Attestation #{index} is not a JSON object.")
        try:
            payload = parse_attestation_envelope(envelope)
        except (DsseError, ValueError) as exc:
            return _fail("MALFORMED_ATTESTATION", f"Attestation #{index} envelope invalid: {exc}")
        version = str(payload.get("protocol_version", ""))
        if version != ATTESTATION_PROTOCOL_VERSION:
            return _fail(
                "UNSUPPORTED_PROTOCOL_VERSION",
                f"Attestation #{index} protocol version not supported: {version!r}",
            )
        try:
            validate_attestation_payload(payload)
        except ValueError as exc:
            return _fail("MALFORMED_ATTESTATION", f"Attestation #{index} invalid: {exc}")
        parsed_attestations.append(payload)

    execution_id = str(parsed_attestations[0]["execution_id"])
    if any(str(p["execution_id"]) != execution_id for p in parsed_attestations):
        return _fail(
            "RESULT_CONFLICT",
            "Attestations disagree on execution_id; they do not describe one execution.",
        )
    attested_check_ids = [str(p["check_id"]) for p in parsed_attestations]
    if len(set(attested_check_ids)) != len(attested_check_ids):
        return _fail(
            "RESULT_CONFLICT",
            "Two attestations cover the same check_id with possibly different "
            "results (equivocation within one submission).",
        )
    if not is_valid_execution_id(execution_id):
        return _fail("MALFORMED_ATTESTATION", f"execution_id has invalid form: {execution_id!r}")
    witness_mode = str(parsed_attestations[0]["witness"]["witness_mode"])
    if any(str(p["witness"]["witness_mode"]) != witness_mode for p in parsed_attestations):
        return _fail("RESULT_CONFLICT", "Attestations disagree on witness_mode for one execution.")
    limitations: list[dict[str, Any]] = []
    for payload in parsed_attestations:
        limitations.extend(dict(lim) for lim in payload.get("limitations", []))

    # ---- Step 2: receipt binding ------------------------------------------
    digest_ok, _declared, _recomputed = verify_receipt_digest(receipt)
    if not digest_ok:
        return _fail(
            "RESULT_CONFLICT",
            "Receipt self-digest verification failed (tampered receipt); "
            "recorded digests and check statuses are untrusted.",
        )
    actual_package_digest = sha256_bytes(inputs.package_bytes)
    if actual_package_digest != receipt.package.digest:
        return _fail(
            "BUNDLE_DIGEST_MISMATCH",
            f"Package bytes hash to {actual_package_digest}, receipt records {receipt.package.digest}.",
        )
    actual_profile_digest = compute_profile_digest(profile)
    if actual_profile_digest != receipt.profile.profile_digest:
        return _fail(
            "PROFILE_DIGEST_MISMATCH",
            f"Supplied profile hashes to {actual_profile_digest}, receipt records {receipt.profile.profile_digest}.",
        )

    # ---- Step 3: pre-binding ----------------------------------------------
    if inputs.commitment_envelope is None or inputs.prebinding is None:
        return _fail(
            "NO_PREBINDING",
            "No execution commitment / pre-binding supplied; a later-invented "
            "execution_id cannot enter the chain.",
        )
    try:
        commitment = parse_commitment_envelope(inputs.commitment_envelope)
    except (DsseError, ValueError) as exc:
        return _fail("NO_PREBINDING", f"Commitment envelope invalid: {exc}")
    try:
        recomputed_id = compute_execution_id(dict(inputs.prebinding))
    except ValueError as exc:
        return _fail("NO_PREBINDING", f"Pre-binding structure invalid: {exc}")
    if recomputed_id != execution_id or commitment.execution_id != execution_id:
        return _fail(
            "NO_PREBINDING",
            "Execution ID cannot be recomputed from the pre-binding structure "
            "(commitment + nonce + inputs).",
        )
    prebinding = dict(inputs.prebinding)
    if str(prebinding.get("bundle_digest")) != actual_package_digest:
        return _fail(
            "BUNDLE_DIGEST_MISMATCH", "Pre-binding bundle_digest does not match the package."
        )
    if str(prebinding.get("profile_digest")) != actual_profile_digest:
        return _fail(
            "PROFILE_DIGEST_MISMATCH", "Pre-binding profile_digest does not match the profile."
        )
    if str(commitment.bundle_digest) != actual_package_digest:
        return _fail(
            "BUNDLE_DIGEST_MISMATCH", "Commitment bundle_digest does not match the package."
        )
    if str(commitment.profile_digest) != actual_profile_digest:
        return _fail(
            "PROFILE_DIGEST_MISMATCH", "Commitment profile_digest does not match the profile."
        )
    if list(prebinding.get("check_ids", [])) != list(commitment.check_ids):
        return _fail("NO_PREBINDING", "Pre-binding check_ids disagree with the commitment.")
    commitment_reason = _verify_commitment_signature(
        inputs.commitment_envelope,
        inputs.witness_trust_store,
        inputs.revocation_list,
        commitment.issued_at_claimed,
    )
    if commitment_reason:
        return _fail(
            commitment_reason,
            f"Commitment signature verification failed: {commitment_reason}.",
        )
    attestation_code_digest = str(parsed_attestations[0]["code_version"].get("code_digest", ""))
    if any(
        str(p["code_version"].get("code_digest", "")) != attestation_code_digest
        for p in parsed_attestations
    ):
        return _fail("CODE_DIGEST_MISMATCH", "Attestations disagree on code_digest.")
    if str(commitment.code_version.get("code_digest", "")) != attestation_code_digest:
        return _fail(
            "CODE_DIGEST_MISMATCH", "Commitment code_digest disagrees with the attestations."
        )
    if (
        inputs.expected_code_digest is not None
        and attestation_code_digest != inputs.expected_code_digest
    ):
        return _fail(
            "CODE_DIGEST_MISMATCH",
            f"Attested code digest {attestation_code_digest} != expected {inputs.expected_code_digest}.",
        )
    # ---- Step 4: witness signatures ---------------------------------------
    for payload, envelope in zip(parsed_attestations, inputs.attestations):
        _payload, evaluation = evaluate_attestation_signature(
            envelope, inputs.witness_trust_store, inputs.revocation_list
        )
        if evaluation.reason:
            return _fail(
                evaluation.reason.split(":")[0],
                f"Attestation for check {payload['check_id']!r} failed signature "
                f"verification: {evaluation.reason}.",
            )
        if inputs.witness_authorization is not None:
            auth = inputs.witness_authorization.get(evaluation.trusted_key_id or "")
            if auth is None:
                return _fail(
                    "WITNESS_UNAUTHORIZED",
                    f"Witness key {evaluation.trusted_key_id!r} has no authorisation record.",
                )
            allowed_profiles = auth.get("profiles", [])
            if allowed_profiles and profile.profile_id not in allowed_profiles:
                return _fail(
                    "WITNESS_UNAUTHORIZED",
                    f"Witness key {evaluation.trusted_key_id!r} is not authorised "
                    f"for profile {profile.profile_id!r}.",
                )

    # ---- Step 5: log binding ----------------------------------------------
    log_events: list[LogEvent] = []
    if inputs.log_events is not None:
        log_events = list(inputs.log_events)
    elif inputs.log_jsonl is not None:
        try:
            log_events = events_from_jsonl(inputs.log_jsonl)
        except ValueError as exc:
            return _fail("LOG_GAP", f"Log file cannot be parsed: {exc}")
    if inputs.checkpoint_envelope is None:
        return _fail(
            "LOG_ANCHOR_INVALID",
            "No signed checkpoint supplied; a log anchor cannot be verified without one.",
        )
    checkpoint, checkpoint_reason = verify_checkpoint_signature(
        inputs.checkpoint_envelope, inputs.checkpoint_trust_store
    )
    if checkpoint is None or checkpoint_reason:
        return _fail(
            "LOG_ANCHOR_INVALID",
            f"Checkpoint signature invalid or untrusted: {checkpoint_reason or 'unparseable'}.",
        )
    chain_ok, chain_note = verify_event_chain(log_events)
    if not chain_ok:
        reason = "LOG_GAP" if "seq gap" in chain_note else "LOG_ANCHOR_INVALID"
        return _fail(reason, f"Log chain verification failed: {chain_note}.")
    if len(log_events) != checkpoint.leaf_count:
        return _fail(
            "LOG_ANCHOR_INVALID",
            f"Log has {len(log_events)} events but checkpoint covers {checkpoint.leaf_count}.",
        )
    leaves = [e.leaf_hash() for e in log_events]
    if merkle_root(leaves) != checkpoint.merkle_root:
        return _fail("LOG_ANCHOR_INVALID", "Log Merkle root does not match the signed checkpoint.")
    started = [
        e
        for e in log_events
        if e.execution_id == execution_id and e.event_type == "EXECUTION_STARTED"
    ]
    if not started:
        return _fail(
            "MISSING_EXECUTION_STEP",
            "No EXECUTION_STARTED event for this execution_id in the log.",
        )
    completed = [
        e
        for e in log_events
        if e.execution_id == execution_id
        and e.event_type in ("EXECUTION_COMPLETED", "EXECUTION_FAILED")
    ]
    if not completed:
        return _fail(
            "MISSING_EXECUTION_STEP",
            "No EXECUTION_COMPLETED / EXECUTION_FAILED event for this execution_id in the log.",
        )
    logged_checks = {
        str(e.check_id)
        for e in log_events
        if e.execution_id == execution_id and e.event_type == "CHECK_COMPLETED"
    }
    required = set(profile.required_checks) | set(profile.optional_checks)
    receipt_check_ids = {c.check_id for c in receipt.checks}
    missing_in_receipt = sorted(required - receipt_check_ids)
    missing_in_log = sorted(
        c.check_id
        for c in receipt.checks
        if str(c.status.value if isinstance(c.status, CheckStatus) else c.status)
        in CHECK_STATUS_EXECUTED
        and c.check_id not in logged_checks
    )
    if missing_in_log:
        return _fail(
            "MISSING_EXECUTION_STEP",
            f"Checks attested in the receipt have no CHECK_COMPLETED log event: {missing_in_log}.",
        )
    if missing_in_receipt:
        notes.append(
            "Profile checks missing from the receipt (profile unsatisfied, not a "
            f"log gap): {missing_in_receipt}. The receipt itself is incomplete."
        )
        # Missing-from-receipt is a receipt defect, not a log defect; the
        # execution of the checks that ARE present can still be proven.
    for payload in parsed_attestations:
        anchor = dict(payload.get("log_anchor", {}))
        leaf_index = int(anchor.get("leaf_index", -1))
        leaf_hash = str(anchor.get("leaf_hash", ""))
        if leaf_index < 0 or leaf_index >= len(log_events):
            return _fail(
                "LOG_ANCHOR_INVALID",
                f"Attestation for {payload['check_id']!r} has an out-of-range log_anchor.",
            )
        event = log_events[leaf_index]
        if event.leaf_hash() != leaf_hash or event.execution_id != execution_id:
            return _fail(
                "LOG_ANCHOR_INVALID",
                f"Attestation for {payload['check_id']!r} does not anchor to the log leaf it claims.",
            )
        if event.check_id != payload["check_id"] or event.event_type != "CHECK_COMPLETED":
            return _fail(
                "LOG_ANCHOR_INVALID",
                f"Log leaf for {payload['check_id']!r} is not its CHECK_COMPLETED event.",
            )
        if inputs.inclusion_proofs is not None:
            proof = inputs.inclusion_proofs.get(str(payload["check_id"]))
            if proof is not None and not verify_merkle_inclusion_proof(
                leaf_hash, leaf_index, proof, checkpoint.merkle_root
            ):
                return _fail(
                    "LOG_ANCHOR_INVALID",
                    f"Merkle inclusion proof for {payload['check_id']!r} fails against the checkpoint.",
                )
        anchor_checkpoint = str(anchor.get("checkpoint_digest", ""))
        if anchor_checkpoint and anchor_checkpoint != checkpoint.checkpoint_digest():
            return _fail(
                "LOG_ANCHOR_INVALID",
                f"Attestation for {payload['check_id']!r} anchors to a different checkpoint.",
            )
        commitment_digest = str(payload.get("execution_commitment_digest", ""))
        if commitment_digest != commitment.commitment_digest():
            return _fail(
                "NO_PREBINDING",
                f"Attestation for {payload['check_id']!r} binds a different commitment digest.",
            )
        if str(payload.get("bundle_digest")) != actual_package_digest:
            return _fail(
                "BUNDLE_DIGEST_MISMATCH",
                f"Attestation for {payload['check_id']!r} binds a different bundle digest.",
            )
        if str(payload.get("profile_digest")) != actual_profile_digest:
            return _fail(
                "PROFILE_DIGEST_MISMATCH",
                f"Attestation for {payload['check_id']!r} binds a different profile digest.",
            )

    # ---- Step 6: result comparison ----------------------------------------
    receipt_by_id = {c.check_id: c for c in receipt.checks}
    attestation_by_id = {str(p["check_id"]): p for p in parsed_attestations}
    # H2 coverage (design §3.1 "one attestation per check", §7.3
    # NO_ATTESTATION): every check the receipt records as executed must
    # have a supplied attestation. The loop below is supplied-driven, so
    # without this check a dropped attestation is invisible: the log
    # still contains every CHECK_COMPLETED event and the remaining
    # attestations still verify. NOT_RUN checks never ran, so no
    # attestation is expected for them (HEA_NOT_APPLICABLE, set above);
    # pre-HEA receipts with no attestations at all are already handled
    # by Step 0. Placed here (after Step 5) deliberately, so the existing
    # reason precedence is preserved: a receipt check with no log event
    # still reports MISSING_EXECUTION_STEP, and signature / commitment /
    # log failures still report before a coverage failure.
    executed_check_ids = {
        c.check_id
        for c in receipt.checks
        if str(c.status.value if isinstance(c.status, CheckStatus) else c.status)
        in CHECK_STATUS_EXECUTED
    }
    missing_attestations = sorted(executed_check_ids - set(attestation_by_id))
    if missing_attestations:
        return _fail(
            "NO_ATTESTATION",
            f"Executed checks have no supplied attestation: {missing_attestations}. "
            "A partial attestation set cannot prove the execution.",
        )
    for check_id, payload in attestation_by_id.items():
        recorded = receipt_by_id.get(check_id)
        if recorded is None:
            return _fail(
                "RESULT_CONFLICT",
                f"Attestation covers check {check_id!r} which the receipt does not record.",
            )
        recorded_status = str(
            recorded.status.value if isinstance(recorded.status, CheckStatus) else recorded.status
        )
        if str(payload["result"]["status"]) != recorded_status:
            return _fail(
                "RESULT_CONFLICT",
                f"Attestation result for {check_id!r} is {payload['result']['status']!r} "
                f"but the receipt records {recorded_status!r}. Neither corrects the other.",
            )
    if receipt.execution_attestations:
        bound = {a["check_id"]: a["attestation_digest"] for a in receipt.execution_attestations}
        for check_id, payload in attestation_by_id.items():
            expected_digest = bound.get(check_id)
            if expected_digest is None:
                return _fail(
                    "RESULT_CONFLICT",
                    f"Receipt does not bind an attestation for check {check_id!r}.",
                )
            if compute_attestation_digest(payload) != expected_digest:
                return _fail(
                    "RESULT_CONFLICT",
                    f"Receipt attestation digest for {check_id!r} does not match the attestation.",
                )
    for payload in parsed_attestations:
        receipt_digest_in_att = payload.get("receipt_digest")
        if receipt_digest_in_att and receipt_digest_in_att != receipt.receipt_digest:
            return _fail(
                "RESULT_CONFLICT",
                f"Attestation for {payload['check_id']!r} binds receipt digest "
                f"{receipt_digest_in_att!r}, receipt is {receipt.receipt_digest!r}.",
            )

    # ---- Step 7: time (limited) -------------------------------------------
    # v0.1 has no trusted-timestamp tokens: claimed_time is never used for
    # ordering or expiry beyond the approximate key-state check in step 4.
    # The "time not proven" note was added at the start.

    # ---- Step 8: output ----------------------------------------------------
    for entry in per_check:
        if not entry["hea_result"]:
            entry["hea_result"] = HistoricalExecutionResult.PROVEN.value
            entry["reason"] = ""
            entry["note"] = (
                "Pre-binding + witness signature + log anchor + receipt binding verified offline."
            )
    return HeaVerificationResult(
        historical_execution=HistoricalExecutionResult.PROVEN.value,
        reason="",
        notes=notes,
        per_check=per_check,
        witness_mode=witness_mode,
        limitations=limitations,
        time_not_proven=True,
        execution_id=execution_id,
        receipt_digest=receipt.receipt_digest,
        reverification_result=inputs.reverification_result,
    )
