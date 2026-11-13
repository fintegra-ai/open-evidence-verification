# SPDX-License-Identifier: Apache-2.0

"""Signed execution completeness statements for Model B2 (round 4, worker D).

After a B2 run the witness signs a statement that lists, for one
execution, **every** profile check exactly once in one of three buckets:

* ``executed`` — the check ran and has an attestation;
* ``not_run`` — the check never ran (recorded NOT_RUN in the receipt);
* ``skipped`` — the profile requires the check but the receipt does not
  record it at all (a receipt defect, not a log gap).

The statement is bound to the execution's checkpoint digest, the
code digest that ran, and the execution id, and is DSSE-signed by the
log operator (checkpoint-signer) key — the same key that signs the
checkpoint, never the witness attestation key (role separation, §9.2).

Why this exists: a bare "no attestation for check X" proves nothing
(the attestation may simply be lost). The completeness statement is
what turns absence into evidence — together with the signed log and
the checkpoint it is one of the three DISPROVEN conditions
(``hea_verifier.assess_disproven``; see ``b2_disproven``).

Verification is fail-explicit: ``verify_execution_completeness``
returns ``(statement|None, ok, note)`` and never raises for a bad
statement. A forged, tampered or mis-bound statement is ``ok=False``
with a note naming the failure — the caller must treat that as a
rejected statement, never as "no statement".
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize_json, safe_json_loads
from .dsse import build_dsse_envelope, compute_pae, parse_dsse_envelope
from .models import CHECK_STATUS_EXECUTED
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .trust import TrustStore

B2_COMPLETENESS_PROTOCOL_VERSION = "oev-b2-completeness/0.1"
B2_COMPLETENESS_PAYLOAD_TYPE = "application/vnd.oev.b2-completeness+json"


@dataclass(frozen=True)
class ExecutionCompletenessStatement:
    """One signed per-execution completeness statement (v0.1)."""

    execution_id: str
    checkpoint_digest: str
    code_digest: str
    witness_key_id: str
    executed: tuple[str, ...]
    not_run: tuple[str, ...]
    skipped: tuple[str, ...]
    claimed_time: str
    policy_digest: str | None = None
    protocol_version: str = B2_COMPLETENESS_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "execution_id": self.execution_id,
            "checkpoint_digest": self.checkpoint_digest,
            "code_digest": self.code_digest,
            "witness_key_id": self.witness_key_id,
            "executed": sorted(self.executed),
            "not_run": sorted(self.not_run),
            "skipped": sorted(self.skipped),
            "claimed_time": self.claimed_time,
        }
        if self.policy_digest is not None:
            d["policy_digest"] = self.policy_digest
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionCompletenessStatement:
        if str(data.get("protocol_version", "")) != B2_COMPLETENESS_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported completeness protocol version: {data.get('protocol_version')!r}"
            )
        return cls(
            execution_id=str(data["execution_id"]),
            checkpoint_digest=str(data["checkpoint_digest"]),
            code_digest=str(data["code_digest"]),
            witness_key_id=str(data["witness_key_id"]),
            executed=tuple(str(c) for c in data.get("executed", [])),
            not_run=tuple(str(c) for c in data.get("not_run", [])),
            skipped=tuple(str(c) for c in data.get("skipped", [])),
            claimed_time=str(data["claimed_time"]),
            policy_digest=(str(data["policy_digest"]) if data.get("policy_digest") else None),
        )

    def all_checks(self) -> set[str]:
        return set(self.executed) | set(self.not_run) | set(self.skipped)

    def status_of(self, check_id: str) -> str | None:
        """``"executed"`` / ``"not_run"`` / ``"skipped"`` / None (unlisted)."""
        if check_id in self.executed:
            return "executed"
        if check_id in self.not_run:
            return "not_run"
        if check_id in self.skipped:
            return "skipped"
        return None


def build_execution_completeness(
    *,
    execution_id: str,
    checkpoint_digest: str,
    code_digest: str,
    witness_key_id: str,
    receipt_checks: list[dict[str, Any]],
    profile_check_ids: list[str],
    claimed_time: str,
    policy_digest: str | None = None,
) -> ExecutionCompletenessStatement:
    """Build the statement from a finished receipt + profile.

    Every profile check lands in exactly one bucket; a receipt check
    outside the profile is refused (it cannot be honestly bucketed).
    """
    executed: list[str] = []
    not_run: list[str] = []
    seen: set[str] = set()
    for check in receipt_checks:
        check_id = str(check["check_id"])
        if check_id in seen:
            raise ValueError(f"Duplicate check in receipt: {check_id!r}")
        seen.add(check_id)
        status = str(check.get("status", ""))
        if status in CHECK_STATUS_EXECUTED:
            executed.append(check_id)
        elif status == "NOT_RUN":
            not_run.append(check_id)
        else:
            raise ValueError(f"Unknown check status for completeness: {status!r}")
    unknown = sorted(seen - set(profile_check_ids))
    if unknown:
        raise ValueError(f"Receipt records checks outside the profile: {unknown}")
    skipped = sorted(set(profile_check_ids) - seen)
    return ExecutionCompletenessStatement(
        execution_id=execution_id,
        checkpoint_digest=checkpoint_digest,
        code_digest=code_digest,
        witness_key_id=witness_key_id,
        executed=tuple(sorted(executed)),
        not_run=tuple(sorted(not_run)),
        skipped=tuple(skipped),
        claimed_time=claimed_time,
        policy_digest=policy_digest,
    )


def sign_execution_completeness(
    statement: ExecutionCompletenessStatement | dict[str, Any],
    private_key_pem: bytes,
    key_id: str = "",
) -> dict[str, Any]:
    """DSSE-sign a completeness statement with the log-operator key."""
    payload = (
        statement.to_dict()
        if isinstance(statement, ExecutionCompletenessStatement)
        else dict(statement)
    )
    # Structural validation before signing: never sign a malformed statement.
    ExecutionCompletenessStatement.from_dict(payload)
    payload_bytes = canonicalize_json(payload)
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(B2_COMPLETENESS_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
    if key_id:
        sig_entry["keyid"] = key_id
    return build_dsse_envelope(
        payload_type=B2_COMPLETENESS_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_execution_completeness(
    envelope: dict[str, Any] | None,
    operator_trust_store: TrustStore | None,
    *,
    expected_checkpoint_digest: str | None = None,
    expected_code_digest: str | None = None,
    expected_execution_id: str | None = None,
    expected_witness_key_id: str | None = None,
    profile_check_ids: list[str] | None = None,
    attested_check_ids: list[str] | None = None,
) -> tuple[ExecutionCompletenessStatement | None, bool, str]:
    """Verify a signed completeness statement against its bindings.

    Checks, in order: envelope shape, payload type, statement shape,
    signature against the operator trust store, checkpoint / code /
    execution / witness bindings, bucket partition of the profile
    checks, and (when supplied) that ``executed`` equals the attested
    check ids. Returns ``(statement|None, ok, note)``.
    """
    if envelope is None:
        return None, False, "no execution completeness statement supplied"
    try:
        payload_type, payload_bytes, signatures = parse_dsse_envelope(envelope)
    except ValueError as exc:
        return None, False, f"completeness envelope malformed: {exc}"
    if payload_type != B2_COMPLETENESS_PAYLOAD_TYPE:
        return None, False, f"unexpected completeness payloadType: {payload_type!r}"
    try:
        data = safe_json_loads(payload_bytes.decode("utf-8"))
    except ValueError as exc:
        return None, False, f"completeness payload is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, False, "completeness payload is not a JSON object"
    try:
        statement = ExecutionCompletenessStatement.from_dict(data)
    except (ValueError, KeyError, TypeError) as exc:
        return None, False, f"completeness statement invalid: {exc}"
    if operator_trust_store is None or len(operator_trust_store.keys) == 0:
        return statement, False, "no log-operator trust roots supplied"
    pae = compute_pae(payload_type, payload_bytes)
    trusted = False
    for trusted_key in operator_trust_store.keys:
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
        except ValueError:
            continue
        for sig_entry in signatures:
            try:
                public_key.verify(
                    base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                )
                trusted = True
                break
            except (InvalidSignature, ValueError):
                continue
        if trusted:
            break
    if not trusted:
        return statement, False, "completeness statement signature is not trusted"
    if expected_checkpoint_digest is not None and (
        statement.checkpoint_digest != expected_checkpoint_digest
    ):
        return statement, False, "completeness statement binds a different checkpoint digest"
    if expected_code_digest is not None and statement.code_digest != expected_code_digest:
        return statement, False, "completeness statement binds a different code digest"
    if expected_execution_id is not None and statement.execution_id != expected_execution_id:
        return statement, False, "completeness statement binds a different execution_id"
    if expected_witness_key_id is not None and (
        statement.witness_key_id != expected_witness_key_id
    ):
        return statement, False, "completeness statement binds a different witness_key_id"
    buckets = [statement.executed, statement.not_run, statement.skipped]
    flat = [c for bucket in buckets for c in bucket]
    if len(set(flat)) != len(flat):
        return statement, False, "completeness statement lists a check in two buckets"
    if profile_check_ids is not None and set(flat) != set(profile_check_ids):
        return (
            statement,
            False,
            (
                "completeness statement does not partition the profile checks: "
                f"missing={sorted(set(profile_check_ids) - set(flat))}, "
                f"extra={sorted(set(flat) - set(profile_check_ids))}"
            ),
        )
    if attested_check_ids is not None and set(statement.executed) != set(attested_check_ids):
        return (
            statement,
            False,
            "completeness statement 'executed' list does not match the attested checks",
        )
    return statement, True, "execution completeness statement verified"


__all__ = [
    "B2_COMPLETENESS_PAYLOAD_TYPE",
    "B2_COMPLETENESS_PROTOCOL_VERSION",
    "ExecutionCompletenessStatement",
    "build_execution_completeness",
    "sign_execution_completeness",
    "verify_execution_completeness",
]
