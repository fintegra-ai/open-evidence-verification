# SPDX-License-Identifier: Apache-2.0

"""DISPROVEN end-to-end for Model B2 (round 4, worker D).

Round 3 had the DISPROVEN *vector* (a complete signed log with no
``EXECUTION_STARTED`` for the claimed id) but no production path that
emits the three conditions together. This module is that path, on top
of the B2 run artifacts:

1. **Complete signed log** — the B2 execution log + signed checkpoint
   (``checkpoint.dsse.json``), verified exactly as the HEA verifier
   does (chain + Merkle root + checkpoint signature).
2. **No event for the claimed execution** — no ``EXECUTION_STARTED``
   (for an execution id) or no ``CHECK_COMPLETED`` (for one check)
   in that log.
3. **Signed completeness** — the log operator's completeness
   statement (``log-completeness.dsse.json``) **and** the B2 execution
   completeness statement (``b2-completeness.dsse.json``), both
   DSSE-signed and bound to the checkpoint.

Outcomes (fail-explicit, three-valued):
* ``DISPROVEN`` — all three conditions hold; the check/execution
  demonstrably never ran (within the log's coverage).
* ``UNPROVEN`` — a condition is *absent* (no statement, no
  checkpoint, no log): absence of evidence, not evidence of absence.
  This is the default and must never be upgraded silently.
* ``REJECTED`` — a condition is *present but inconsistent* (forged
  signature, tampered list, log contradicts the statement, checkpoint
  mismatch). A rejected statement is worse than a missing one: it is
  evidence of tampering, so it gets its own outcome instead of being
  folded into UNPROVEN.

``assess_b2_disproven`` answers the execution-level question through
the unchanged HEA verifier (``assess_disproven``); the per-check
question is answered by :func:`verify_disproven_check`, which adds
the B2 execution-completeness statement to the same three conditions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .b2_completeness import verify_execution_completeness
from .canonical import safe_json_loads
from .dsse import parse_dsse_envelope
from .execution_log import (
    LogEvent,
    events_from_jsonl,
    merkle_root,
    verify_checkpoint_signature,
    verify_event_chain,
)
from .hea_verifier import HeaVerificationInputs, verify_historical_execution
from .models import VerificationProfile, VerificationReceipt
from .trust import TrustStore

B2_OUT_FILES = {
    "receipt": "receipt.json",
    "manifest": "b2-manifest.json",
    "log": "execution-log.jsonl",
    "checkpoint": "checkpoint.dsse.json",
    "log_completeness": "log-completeness.dsse.json",
    "execution_completeness": "b2-completeness.dsse.json",
    "prebinding": "prebinding.json",
    "commitment": "commitment.dsse.json",
}


def load_b2_artifacts(out_dir: str | Path) -> dict[str, Any]:
    """Load a B2 run's artifacts from its output directory.

    Missing optional files (log-completeness, execution-completeness)
    are reported as ``None`` rather than raising — their absence is a
    meaningful DISPROVEN outcome (UNPROVEN), not a load error. Missing
    *required* files (receipt, log, checkpoint) raise ValueError.
    """
    out_dir = Path(out_dir)
    artifacts: dict[str, Any] = {"out_dir": str(out_dir)}

    def _read_json(name: str) -> dict[str, Any]:
        data = safe_json_loads((out_dir / name).read_bytes())
        if not isinstance(data, dict):
            raise ValueError(f"B2 artifact {name} is not a JSON object")  # noqa: TRY004
        return data

    receipt_data = _read_json(B2_OUT_FILES["receipt"])
    if "payload" in receipt_data:
        _pt, payload_bytes, _sigs = parse_dsse_envelope(receipt_data)
        receipt_data = safe_json_loads(payload_bytes.decode("utf-8"))
    artifacts["receipt"] = VerificationReceipt.from_dict(dict(receipt_data))
    artifacts["manifest"] = _read_json(B2_OUT_FILES["manifest"])
    log_bytes = (out_dir / B2_OUT_FILES["log"]).read_bytes()
    artifacts["log_events"] = events_from_jsonl(log_bytes)
    artifacts["log_bytes"] = log_bytes
    artifacts["checkpoint_envelope"] = _read_json(B2_OUT_FILES["checkpoint"])
    for key in ("log_completeness", "execution_completeness"):
        path = out_dir / B2_OUT_FILES[key]
        artifacts[f"{key}_envelope"] = _read_json(B2_OUT_FILES[key]) if path.is_file() else None
    return artifacts


def assess_b2_disproven(
    out_dir: str | Path,
    claimed_execution_id: str,
    *,
    package_bytes: bytes,
    profile: VerificationProfile | dict[str, Any],
    witness_trust_store: TrustStore | None = None,
    checkpoint_trust_store: TrustStore | None = None,
    log_operator_trust_store: TrustStore | None = None,
) -> dict[str, Any]:
    """Execution-level DISPROVEN assessment for a B2 run's artifacts.

    Builds the verifier inputs with **no attestations** and asks the
    unchanged HEA verifier. Returns ``{"historical_execution",
    "reason", "notes"}`` where ``historical_execution`` is
    ``HISTORICAL_EXECUTION_DISPROVEN`` only when all three §7.2
    conditions hold, else ``HISTORICAL_EXECUTION_UNPROVEN``.
    """
    artifacts = load_b2_artifacts(out_dir)
    receipt = artifacts["receipt"]
    inputs = HeaVerificationInputs(
        package_bytes=package_bytes,
        receipt=receipt,
        profile=profile,
        attestations=[],
        claimed_execution_id=claimed_execution_id,
        log_events=list(artifacts["log_events"]),
        checkpoint_envelope=artifacts["checkpoint_envelope"],
        completeness_envelope=artifacts["log_completeness_envelope"],
        witness_trust_store=witness_trust_store,
        checkpoint_trust_store=checkpoint_trust_store,
        log_operator_trust_store=log_operator_trust_store,
    )
    result = verify_historical_execution(inputs)
    return {
        "historical_execution": result.historical_execution,
        "reason": result.reason,
        "notes": list(result.notes),
        "execution_id": claimed_execution_id,
    }


def verify_disproven_check(
    *,
    check_id: str,
    execution_id: str,
    log_events: list[LogEvent],
    checkpoint_envelope: dict[str, Any] | None,
    checkpoint_trust_store: TrustStore | None,
    execution_completeness_envelope: dict[str, Any] | None,
    log_operator_trust_store: TrustStore | None,
    profile_check_ids: list[str] | None = None,
    expected_code_digest: str | None = None,
) -> tuple[str, str]:
    """Per-check DISPROVEN: did ``check_id`` demonstrably never run?

    Returns ``(outcome, note)`` with outcome one of ``DISPROVEN`` /
    ``UNPROVEN`` / ``REJECTED``:

    * ``UNPROVEN`` — the execution-completeness statement is absent
      (or there is no checkpoint at all): nothing to assess.
    * ``REJECTED`` — the statement is present but fails verification
      (bad signature, wrong binding, bucket partition broken), or the
      log/checkpoint are inconsistent, or the log *contradicts* the
      statement (a CHECK_COMPLETED exists for this check while the
      statement claims it never ran).
    * ``DISPROVEN`` — the statement verifies, is bound to this
      checkpoint, lists the check as ``not_run`` (or ``skipped``), and
      the complete signed log contains no CHECK_COMPLETED for it.
    """
    if execution_completeness_envelope is None:
        return (
            "UNPROVEN",
            "no execution completeness statement: absence may mean loss, not non-execution",
        )
    if checkpoint_envelope is None:
        return "UNPROVEN", "no signed checkpoint: log completeness cannot be established"
    checkpoint, checkpoint_reason = verify_checkpoint_signature(
        checkpoint_envelope, checkpoint_trust_store
    )
    if checkpoint is None or checkpoint_reason:
        return "REJECTED", f"checkpoint signature invalid ({checkpoint_reason or 'unparseable'})"
    ok, chain_note = verify_event_chain(log_events)
    if not ok:
        return "REJECTED", f"log chain invalid: {chain_note}"
    if len(log_events) != checkpoint.leaf_count:
        return "REJECTED", "log event count does not match checkpoint leaf_count"
    leaves = [e.leaf_hash() for e in log_events]
    if merkle_root(leaves) != checkpoint.merkle_root:
        return "REJECTED", "log Merkle root does not match checkpoint"
    statement, stmt_ok, stmt_note = verify_execution_completeness(
        execution_completeness_envelope,
        log_operator_trust_store,
        expected_checkpoint_digest=checkpoint.checkpoint_digest(),
        expected_code_digest=expected_code_digest,
        expected_execution_id=execution_id,
        profile_check_ids=profile_check_ids,
    )
    if not stmt_ok:
        return "REJECTED", f"execution completeness statement rejected: {stmt_note}"
    assert statement is not None
    status = statement.status_of(check_id)
    if status == "executed":
        return (
            "REJECTED",
            f"statement lists {check_id!r} as executed, but the claim is that it never ran",
        )
    if status is None:
        return (
            "REJECTED",
            f"statement does not list {check_id!r} at all (incomplete statement)",
        )
    # status is "not_run" or "skipped": the log must agree.
    for event in log_events:
        if (
            event.execution_id == execution_id
            and event.event_type == "CHECK_COMPLETED"
            and event.check_id == check_id
        ):
            return (
                "REJECTED",
                f"log contradicts the statement: CHECK_COMPLETED exists for {check_id!r}",
            )
    return (
        "DISPROVEN",
        (
            f"complete signed log + verified completeness statement list {check_id!r} "
            f"as {status}; no CHECK_COMPLETED event for it"
        ),
    )


def disprove_check_from_b2_run(
    out_dir: str | Path,
    check_id: str,
    *,
    checkpoint_trust_store: TrustStore | None,
    log_operator_trust_store: TrustStore | None,
    profile: VerificationProfile | dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Convenience wrapper: per-check DISPROVEN straight from a B2 out dir."""
    artifacts = load_b2_artifacts(out_dir)
    manifest = artifacts["manifest"]
    profile_obj = profile
    if profile_obj is None:
        # Profile check ids from the manifest's attested + receipt checks
        # are not the full profile; fall back to no partition check.
        profile_ids: list[str] | None = None
    else:
        prof = (
            profile_obj
            if isinstance(profile_obj, VerificationProfile)
            else VerificationProfile.from_dict(dict(profile_obj))
        )
        profile_ids = list(dict.fromkeys(prof.required_checks + prof.optional_checks))
    return verify_disproven_check(
        check_id=check_id,
        execution_id=str(manifest["execution_id"]),
        log_events=list(artifacts["log_events"]),
        checkpoint_envelope=artifacts["checkpoint_envelope"],
        checkpoint_trust_store=checkpoint_trust_store,
        execution_completeness_envelope=artifacts["execution_completeness_envelope"],
        log_operator_trust_store=log_operator_trust_store,
        profile_check_ids=profile_ids,
        expected_code_digest=str(manifest.get("code_digest") or ""),
    )


__all__ = [
    "B2_OUT_FILES",
    "assess_b2_disproven",
    "disprove_check_from_b2_run",
    "load_b2_artifacts",
    "verify_disproven_check",
]
