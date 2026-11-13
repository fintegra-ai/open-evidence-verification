# SPDX-License-Identifier: Apache-2.0

"""Signed revocation lists for HEA witness / checkpoint keys (oev-revocation/0.1).

A revocation list is a DSSE-signed JSON document (HEA design §9.1)::

    {
      "protocol_version": "oev-revocation/0.1",
      "issuer_key_id": "<signer key id>",
      "issued_at_claimed": "2026-11-13T07:20:00Z",
      "entries": [
        {"key_id": "<revoked key>", "reason": "key-compromise", "revoked_at_claimed": "..."}
      ]
    }

Semantics (fail-explicit, not fail-open):
- A revocation list is only honoured when its DSSE signature verifies
  against a caller-supplied revocation-authority trust store. An unsigned
  or untrusted list is ignored, and the verifier records
  "revocation status unknown" in its notes instead of claiming "not revoked".
- Revocation is retroactive in effect for verification purposes: once a key
  is listed, attestations signed with it are rejected with
  ``WITNESS_KEY_REVOKED`` regardless of their claimed time. (Key state at
  signing time cannot be established reliably because claimed time is
  untrusted; see HEA design §9.1/§9.4.)
- The list itself carries only claimed times; it is not a trusted timestamp.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize_json, safe_json_loads
from .dsse import (
    DsseError,
    build_dsse_envelope,
    compute_pae,
    parse_dsse_envelope,
)
from .schemas import validate_document
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .trust import TrustStore, parse_hea_timestamp

REVOCATION_PROTOCOL_VERSION = "oev-revocation/0.1"
REVOCATION_PAYLOAD_TYPE = "application/vnd.oev.revocation-list+json"
REVOCATION_SCHEMA_NAME = "revocation-list-0.1.schema.json"

MAX_REVOCATION_ENTRIES: int = 1024


@dataclass(frozen=True)
class RevocationEntry:
    """One revoked key."""

    key_id: str
    reason: str
    revoked_at_claimed: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "reason": self.reason,
            "revoked_at_claimed": self.revoked_at_claimed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RevocationEntry:
        parse_hea_timestamp(str(data["revoked_at_claimed"]))
        return cls(
            key_id=str(data["key_id"]),
            reason=str(data["reason"]),
            revoked_at_claimed=str(data["revoked_at_claimed"]),
        )


@dataclass(frozen=True)
class RevocationList:
    """A signed list of revoked key ids (oev-revocation/0.1)."""

    issuer_key_id: str
    issued_at_claimed: str
    entries: list[RevocationEntry] = field(default_factory=list)
    protocol_version: str = REVOCATION_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "issuer_key_id": self.issuer_key_id,
            "issued_at_claimed": self.issued_at_claimed,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RevocationList:
        if str(data.get("protocol_version", "")) != REVOCATION_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported revocation protocol version: {data.get('protocol_version')!r}"
            )
        parse_hea_timestamp(str(data["issued_at_claimed"]))
        entries = [RevocationEntry.from_dict(e) for e in data.get("entries", [])]
        if len(entries) > MAX_REVOCATION_ENTRIES:
            raise ValueError(f"Revocation list exceeds {MAX_REVOCATION_ENTRIES} entries")
        seen: set[str] = set()
        for entry in entries:
            if entry.key_id in seen:
                raise ValueError(f"Duplicate key_id in revocation list: {entry.key_id!r}")
            seen.add(entry.key_id)
        return cls(
            issuer_key_id=str(data["issuer_key_id"]),
            issued_at_claimed=str(data["issued_at_claimed"]),
            entries=entries,
        )

    def is_revoked(self, key_id: str) -> bool:
        return any(e.key_id == key_id for e in self.entries)

    def revoked_key_ids(self) -> set[str]:
        return {e.key_id for e in self.entries}


def build_revocation_list(
    entries: list[RevocationEntry],
    issuer_key_id: str,
    issued_at_claimed: str,
    private_key_pem: bytes,
) -> dict[str, Any]:
    """Build and DSSE-sign a revocation list. Returns the DSSE envelope."""
    revocation = RevocationList(
        issuer_key_id=issuer_key_id,
        issued_at_claimed=issued_at_claimed,
        entries=list(entries),
    )
    payload = revocation.to_dict()
    validate_document(payload, REVOCATION_SCHEMA_NAME)
    payload_bytes = canonicalize_json(payload)
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(REVOCATION_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {
        "sig": base64.b64encode(raw_sig).decode("ascii"),
        "keyid": issuer_key_id,
    }
    return build_dsse_envelope(
        payload_type=REVOCATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_revocation_list(
    envelope: dict[str, Any],
    authority_trust_store: TrustStore | None,
) -> tuple[RevocationList | None, str]:
    """Verify a DSSE revocation list against caller-supplied authority keys.

    Returns ``(revocation_list_or_None, note)``. A ``None`` list means the
    input was absent, malformed, or untrusted — the caller must treat
    revocation status as UNKNOWN, never as "not revoked".
    """
    if envelope is None:
        return None, "no revocation list supplied; revocation status unknown"
    try:
        payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    except DsseError as exc:
        return None, f"revocation list envelope malformed: {exc}"
    if payload_type != REVOCATION_PAYLOAD_TYPE:
        return None, f"revocation list has unexpected payloadType: {payload_type!r}"
    try:
        data = safe_json_loads(payload_bytes.decode("utf-8"))
    except ValueError as exc:
        return None, f"revocation list payload is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "revocation list payload is not a JSON object"
    try:
        validate_document(data, REVOCATION_SCHEMA_NAME)
        revocation = RevocationList.from_dict(data)
    except (ValueError, KeyError, TypeError) as exc:
        return None, f"revocation list failed validation: {exc}"
    if authority_trust_store is None or len(authority_trust_store.keys) == 0:
        return None, "no revocation-authority trust roots supplied; revocation status unknown"
    matched = False
    for trusted_key in authority_trust_store.keys:
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
            pae = compute_pae(payload_type, payload_bytes)
            for sig_entry in _sigs:
                try:
                    public_key.verify(
                        base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                    )
                    matched = True
                    break
                except (InvalidSignature, ValueError):
                    continue
            if matched:
                break
        except ValueError:
            continue
    if not matched:
        return None, "revocation list signature is not trusted by caller"
    return revocation, f"revocation list verified ({len(revocation.entries)} entries)"
