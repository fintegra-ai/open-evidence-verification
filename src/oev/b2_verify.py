# SPDX-License-Identifier: Apache-2.0

"""Model B2 verification wrapper (offline).

Runs the existing HEA verifier (``hea_verifier.py`` — unchanged, so
Model A attestations keep verifying exactly as before) and then adds
the B2-specific checks the base verifier does not make:

1. **Witness mode.** Every attestation AND the pre-binding execution
   context must say ``separate-machine``. A Model A bundle verifies
   under HEA (PROVEN) but is NOT a B2 proof — the wrapper reports
   ``b2_ok: False`` with reason ``NOT_B2_WITNESS_MODE`` for it.
2. **Authorisation.** When a witness-authorisation document is
   supplied, it is validated and converted to the verifier's
   ``witness_authorization`` input; the verifier then enforces the
   profile allow-list (``WITNESS_UNAUTHORIZED``).
3. **Timestamp status.** For each attested check, an optional TSA
   token sidecar is verified with :func:`oev.tsa.verify_timestamp_token`
   against caller-supplied TSA trust roots. Status per check:
   ``TSA_VERIFIED`` / ``TSA_INVALID`` / ``UNVERIFIED`` (no token).
   ``UNVERIFIED`` is the honest default — it never fails the HEA
   verdict, and it never claims proven time. ``TSA_INVALID`` likewise
   does not change the HEA verdict (the token is not part of the
   attestation); it is reported so callers do not mistake a broken
   token for proven time.

The wrapper never touches the network. It imports ``engine`` only
through ``b2_witness`` (re-execution lives there); this module itself
imports only the verifier, the attestation digest helper, the TSA
module and the B2 authorisation schema.
"""

from __future__ import annotations

from typing import Any

from .attestation import compute_attestation_digest, parse_attestation_envelope
from .b2_witness import B2_WITNESS_MODE, to_verifier_authorization, validate_witness_authorization
from .execution_log import parse_checkpoint_envelope
from .hea_verifier import HeaVerificationInputs, HeaVerificationResult, verify_historical_execution
from .tsa import verify_timestamp_token


def verify_b2_execution(
    inputs: HeaVerificationInputs,
    timestamp_token_envelopes: dict[str, dict[str, Any]] | None = None,
    tsa_trust_store: Any | None = None,
    witness_authorization: dict[str, Any] | None = None,
    expected_code_digest_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify a B2 execution offline. Returns a plain-dict report.

    Keys: ``historical_execution`` (HEA verdict), ``reason``,
    ``b2_ok`` (bool — all B2-specific checks passed),
    ``b2_reason`` ("" when b2_ok), ``witness_mode``,
    ``timestamp_status`` (per check_id), ``time_proven`` (bool —
    True only when every attested check has a TSA_VERIFIED token from
    a *non-mock* TSA; the mock TSA never yields ``time_proven``),
    ``hea_result`` (the full ``HeaVerificationResult.to_dict()``).
    """
    if expected_code_digest_document is not None:
        inputs = HeaVerificationInputs(
            **{**inputs.__dict__, "expected_code_digest_document": expected_code_digest_document}
        )
    if witness_authorization is not None:
        valid_auth = validate_witness_authorization(witness_authorization)
        inputs = HeaVerificationInputs(
            **{**inputs.__dict__, "witness_authorization": to_verifier_authorization(valid_auth)}
        )
    hea: HeaVerificationResult = verify_historical_execution(inputs)

    report: dict[str, Any] = {
        "historical_execution": hea.historical_execution,
        "reason": hea.reason,
        "b2_ok": False,
        "b2_reason": "",
        "witness_mode": hea.witness_mode,
        "timestamp_status": {},
        "time_proven": False,
        "hea_result": hea.to_dict(),
    }

    # B2 check 1 — witness mode must be separate-machine everywhere.
    if hea.historical_execution != "HISTORICAL_EXECUTION_PROVEN":
        report["b2_reason"] = f"HEA verdict is not PROVEN ({hea.reason})"
        return report
    if hea.witness_mode != B2_WITNESS_MODE:
        report["b2_reason"] = (
            f"NOT_B2_WITNESS_MODE: attestations use witness_mode "
            f"{hea.witness_mode!r}, not 'separate-machine'"
        )
        return report
    prebinding = inputs.prebinding or {}
    context = dict(prebinding.get("execution_context", {}))
    if context.get("witness_mode") != B2_WITNESS_MODE:
        report["b2_reason"] = (
            "NOT_B2_WITNESS_MODE: pre-binding execution_context witness_mode is not "
            "'separate-machine'"
        )
        return report

    # B2 check 2 — timestamp tokens (sidecars, optional).
    token_envelopes = timestamp_token_envelopes or {}
    statuses: dict[str, str] = {}
    notes: list[str] = []
    for envelope in inputs.attestations:
        try:
            payload = parse_attestation_envelope(envelope)
        except ValueError:
            continue
        check_id = str(payload["check_id"])
        digest = compute_attestation_digest(payload)
        status, note = verify_timestamp_token(
            token_envelopes.get(check_id), digest, tsa_trust_store
        )
        statuses[check_id] = status
        notes.append(f"{check_id}: {status} — {note}")
    report["timestamp_status"] = statuses
    report["timestamp_notes"] = notes
    # Mock-TSA tokens verify as mock tokens; they never yield proven time.
    report["time_proven"] = (
        bool(statuses)
        and all(s == "TSA_VERIFIED" for s in statuses.values())
        and not any("mock TSA" in n for n in notes)
    )

    report["b2_ok"] = True
    return report
