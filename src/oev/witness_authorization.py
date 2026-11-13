# SPDX-License-Identifier: Apache-2.0

"""Witness authorisation documents (oev-witness-authorization/0.1, HEA §9.2).

Round 3 (P0): the authorisation record is no longer an untyped dict.
A document names one witness key, the operator that issued it
(``issuer_key_id``), the profiles and (optionally) checks the key may
attest, a validity window in claimed time, and a revocation flag. The
offline verifier enforces it in Step 4; a missing or mismatched
authorisation fails closed as ``HISTORICAL_EXECUTION_UNPROVEN`` with
reason ``WITNESS_UNAUTHORIZED``.

Semantics (fail-closed throughout):
- ``authorized_profiles`` is required and an empty list authorises NO
  profile. (The legacy in-code dict keeps its old rule — an absent or
  empty ``profiles`` list means "no profile restriction" — only for
  backwards compatibility with callers that already pass that shape.)
- ``authorized_checks`` absent means no check restriction; present and
  empty authorises no check; present and non-empty requires membership.
- ``claimed_time`` of the attestation must fall inside
  [``valid_from_claimed``, ``valid_until_claimed``] (claimed time is
  self-asserted, so the window is an operator policy check, not a
  proof of wall-clock validity — same caveat as key expiry, §9.4).
- ``revoked: true`` authorises nothing, whatever else the document says.
- The document itself is not signed in v0.1: it is caller-supplied
  trust input, like the trust stores. A signed authorisation envelope
  is future work; until then the caller must obtain the document over
  a trusted channel, and the verifier records that caveat in its notes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .schemas import validate_document
from .trust import parse_hea_timestamp

WITNESS_AUTHORIZATION_PROTOCOL_VERSION = "oev-witness-authorization/0.1"
WITNESS_AUTHORIZATION_SCHEMA_NAME = "witness-authorization-0.1.schema.json"


@dataclass(frozen=True)
class WitnessAuthorization:
    """One parsed, validated witness-authorisation document."""

    witness_key_id: str
    issuer_key_id: str
    authorized_profiles: tuple[str, ...]
    valid_from_claimed: str
    valid_until_claimed: str
    authorized_checks: tuple[str, ...] | None = None
    witness_public_key_digest: str | None = None
    revoked: bool = False
    revocation_reason: str | None = None
    scope_note: str | None = None


def load_witness_authorization_document(doc: dict[str, Any]) -> WitnessAuthorization:
    """Validate a witness-authorisation document and parse it. Raises ValueError."""
    if not isinstance(doc, dict):
        raise ValueError("Witness authorisation document must be a JSON object")  # noqa: TRY004 — callers catch ValueError for malformed documents.
    validate_document(doc, WITNESS_AUTHORIZATION_SCHEMA_NAME)
    if str(doc.get("protocol_version", "")) != WITNESS_AUTHORIZATION_PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported witness authorisation protocol version: {doc.get('protocol_version')!r}"
        )
    try:
        valid_from = parse_hea_timestamp(str(doc["valid_from_claimed"]))
        valid_until = parse_hea_timestamp(str(doc["valid_until_claimed"]))
    except ValueError as exc:
        raise ValueError(f"Witness authorisation validity window is malformed: {exc}") from exc
    if valid_from > valid_until:
        raise ValueError("Witness authorisation valid_from_claimed is after valid_until_claimed")
    checks = doc.get("authorized_checks")
    return WitnessAuthorization(
        witness_key_id=str(doc["witness_key_id"]),
        issuer_key_id=str(doc["issuer_key_id"]),
        authorized_profiles=tuple(str(p) for p in doc["authorized_profiles"]),
        valid_from_claimed=str(doc["valid_from_claimed"]),
        valid_until_claimed=str(doc["valid_until_claimed"]),
        authorized_checks=tuple(str(c) for c in checks) if checks is not None else None,
        witness_public_key_digest=(
            str(doc["witness_public_key_digest"]) if doc.get("witness_public_key_digest") else None
        ),
        revoked=bool(doc.get("revoked", False)),
        revocation_reason=(str(doc["revocation_reason"]) if doc.get("revocation_reason") else None),
        scope_note=str(doc["scope_note"]) if doc.get("scope_note") else None,
    )


def check_witness_authorization(
    auth: WitnessAuthorization,
    *,
    key_id: str,
    profile_id: str,
    check_id: str,
    claimed_time: str,
) -> str:
    """Return ``""`` when the authorisation covers this attestation, else a note.

    The note names the failed condition; the caller maps any non-empty
    note to ``WITNESS_UNAUTHORIZED``. Never raises for a mismatched
    document — only for a malformed ``claimed_time``, which the
    verifier's Step 1 already rejects before this point.
    """
    if auth.witness_key_id != key_id:
        return f"Authorisation document is for witness key {auth.witness_key_id!r}, not {key_id!r}."
    if auth.revoked:
        reason = auth.revocation_reason or "no reason recorded"
        return f"Witness key {key_id!r} authorisation is revoked ({reason})."
    if profile_id not in auth.authorized_profiles:
        return (
            f"Witness key {key_id!r} is not authorised for profile {profile_id!r} "
            f"(authorised: {sorted(auth.authorized_profiles)})."
        )
    if auth.authorized_checks is not None and check_id not in auth.authorized_checks:
        return (
            f"Witness key {key_id!r} is not authorised for check {check_id!r} "
            f"(authorised: {sorted(auth.authorized_checks)})."
        )
    moment = parse_hea_timestamp(claimed_time)
    if moment < parse_hea_timestamp(auth.valid_from_claimed):
        return (
            f"Attestation claimed_time {claimed_time} is before the authorisation "
            f"validity window (from {auth.valid_from_claimed})."
        )
    if moment > parse_hea_timestamp(auth.valid_until_claimed):
        return (
            f"Attestation claimed_time {claimed_time} is after the authorisation "
            f"validity window (until {auth.valid_until_claimed})."
        )
    return ""


def authorization_to_legacy_dict(auth: WitnessAuthorization) -> dict[str, dict[str, list[str]]]:
    """Project a document onto the legacy ``{key_id: {"profiles": [...]}}`` shape.

    Used only by callers that still feed the legacy path; the document
    path in the verifier enforces the full semantics above.
    """
    return {auth.witness_key_id: {"profiles": list(auth.authorized_profiles)}}
