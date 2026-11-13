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
from .b2_completeness import verify_execution_completeness
from .b2_signed_auth import verify_signed_witness_authorization
from .b2_witness import B2_WITNESS_MODE, to_verifier_authorization, validate_witness_authorization
from .execution_log import parse_checkpoint_envelope
from .hea_verifier import HeaVerificationInputs, HeaVerificationResult, verify_historical_execution
from .tsa import verify_timestamp_token


def _b2_report(
    *,
    hea: HeaVerificationResult | None,
    b2_ok: bool,
    b2_reason: str,
    authorization_status: str,
    completeness_status: str,
) -> dict[str, Any]:
    """Build a B2 report before (or without) a HEA verdict."""
    return {
        "historical_execution": hea.historical_execution
        if hea is not None
        else "HISTORICAL_EXECUTION_UNPROVEN",
        "reason": hea.reason if hea is not None else b2_reason,
        "b2_ok": b2_ok,
        "b2_reason": b2_reason,
        "witness_mode": hea.witness_mode if hea is not None else None,
        "timestamp_status": {},
        "time_proven": False,
        "hea_result": hea.to_dict() if hea is not None else None,
        "authorization_status": authorization_status,
        "completeness_status": completeness_status,
    }


def verify_b2_execution(
    inputs: HeaVerificationInputs,
    timestamp_token_envelopes: dict[str, dict[str, Any]] | None = None,
    tsa_trust_store: Any | None = None,
    witness_authorization: dict[str, Any] | None = None,
    signed_witness_authorization: dict[str, Any] | None = None,
    authorization_issuer_trust_store: Any | None = None,
    require_signed_authorization: bool = False,
    execution_completeness_envelope: dict[str, Any] | None = None,
    log_operator_trust_store: Any | None = None,
    expected_code_digest_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify a B2 execution offline. Returns a plain-dict report.

    Keys: ``historical_execution`` (HEA verdict), ``reason``,
    ``b2_ok`` (bool — all B2-specific checks passed),
    ``b2_reason`` ("" when b2_ok), ``witness_mode``,
    ``timestamp_status`` (per check_id), ``time_proven`` (bool —
    True only when every attested check has a TSA_VERIFIED token from
    a *non-mock* TSA; the mock TSA never yields ``time_proven``),
    ``hea_result`` (the full ``HeaVerificationResult.to_dict()``),
    plus round-4 keys: ``authorization_status`` (signed / unsigned /
    rejected / missing-required), ``completeness_status`` (verified /
    rejected / absent / not-supplied).
    """
    authorization_status = "not-supplied"
    if signed_witness_authorization is not None:
        auth, auth_ok, auth_note = verify_signed_witness_authorization(
            signed_witness_authorization, authorization_issuer_trust_store
        )
        if not auth_ok or auth is None:
            return _b2_report(
                hea=None,
                b2_ok=False,
                b2_reason=f"SIGNED_AUTHORIZATION_REJECTED: {auth_note}",
                authorization_status=f"rejected: {auth_note}",
                completeness_status="not-supplied",
            )
        authorization_status = "signed-verified"
        # The verified document enforces the full semantics (profiles,
        # checks, window, revocation) in the HEA verifier's Step 4.
        inputs = HeaVerificationInputs(
            **{
                **inputs.__dict__,
                "witness_authorization_document": {
                    "protocol_version": "oev-witness-authorization/0.1",
                    "witness_key_id": auth.witness_key_id,
                    "issuer_key_id": auth.issuer_key_id,
                    "authorized_profiles": list(auth.authorized_profiles),
                    "valid_from_claimed": auth.valid_from_claimed,
                    "valid_until_claimed": auth.valid_until_claimed,
                    **(
                        {"authorized_checks": list(auth.authorized_checks)}
                        if auth.authorized_checks is not None
                        else {}
                    ),
                    **(
                        {"witness_public_key_digest": auth.witness_public_key_digest}
                        if auth.witness_public_key_digest is not None
                        else {}
                    ),
                    "revoked": auth.revoked,
                    **(
                        {"revocation_reason": auth.revocation_reason}
                        if auth.revocation_reason is not None
                        else {}
                    ),
                    **({"scope_note": auth.scope_note} if auth.scope_note else {}),
                },
            }
        )
    elif require_signed_authorization:
        return _b2_report(
            hea=None,
            b2_ok=False,
            b2_reason="UNSIGNED_AUTHORIZATION_REJECTED: this B2 deployment "
            "requires a signed witness authorisation",
            authorization_status="missing-required",
            completeness_status="not-supplied",
        )
    elif witness_authorization is not None:
        authorization_status = "unsigned (legacy path; signed authorisation not required)"
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
        "authorization_status": authorization_status,
        "completeness_status": "not-supplied",
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

    # B2 check 3 — execution completeness statement (round 4, optional
    # input). When supplied it must verify and its ``executed`` list
    # must equal the attested checks; a rejected statement fails B2
    # (the run's completeness claim cannot be trusted). When absent the
    # run still verifies — the statement is a DISPROVEN input, not a
    # PROVEN precondition — and the report says so.
    if execution_completeness_envelope is not None:
        attested_ids = [
            str(parse_attestation_envelope(e)["check_id"])
            for e in inputs.attestations
            if isinstance(e, dict)
        ]
        checkpoint_digest = None
        try:
            if inputs.checkpoint_envelope is not None:
                checkpoint_digest = parse_checkpoint_envelope(
                    inputs.checkpoint_envelope
                ).checkpoint_digest()
        except ValueError:
            checkpoint_digest = None
        profile_ids = list(
            dict.fromkeys(
                list(inputs.profile.required_checks) + list(inputs.profile.optional_checks)
                if not isinstance(inputs.profile, dict)
                else []
            )
        )
        _stmt, stmt_ok, stmt_note = verify_execution_completeness(
            execution_completeness_envelope,
            log_operator_trust_store,
            expected_checkpoint_digest=checkpoint_digest,
            expected_execution_id=hea.execution_id,
            profile_check_ids=profile_ids or None,
            attested_check_ids=attested_ids,
        )
        report["completeness_status"] = f"{'verified' if stmt_ok else 'rejected'}: {stmt_note}"
        if not stmt_ok:
            report["b2_reason"] = f"COMPLETENESS_REJECTED: {stmt_note}"
            return report
    else:
        report["completeness_status"] = (
            "absent: no execution completeness statement supplied "
            "(DISPROVEN path unavailable for this bundle)"
        )
    report["b2_ok"] = True
    return report
