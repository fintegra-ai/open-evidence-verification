# SPDX-License-Identifier: Apache-2.0

"""Caller-supplied trust roots and trust evaluation for OEVP.

NON-NEGOTIABLE TRUST INVARIANTS:
1. DSSE keyid is strictly an unauthenticated hint. It must never be trusted.
2. Embedded keys inside packages, metadata, or envelopes are identifiers only;
   they NEVER bootstrap their own trust.
3. Cryptographic signature validity (SIGNATURE_CRYPTO_VALID) is distinct from
   caller trust (SIGNER_TRUSTED_BY_CALLER).
4. Trust roots are ALWAYS supplied explicitly by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import safe_json_loads
from .fileio import read_bounded_file
from .hashing import sha256_bytes
from .signing import (
    load_ed25519_public_key,
    verify_dsse_signature_with_key,
)

MAX_TRUSTED_KEYS: int = 64
MAX_KEYID_LENGTH: int = 256

#: Roles a trusted key may hold. A key signs only objects of its own role
#: (HEA design §9.2). ``role`` is optional for backwards compatibility:
#: a key without a role may sign receipts (the pre-HEA behaviour) but is
#: never authorised as a witness or checkpoint signer.
KEY_ROLES: frozenset[str] = frozenset(
    {"receipt-signer", "witness", "checkpoint-signer", "code-signer"}
)

#: Strict ISO-8601 UTC form used by ``not_before`` / ``not_after``.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_hea_timestamp(value: str) -> datetime:
    """Parse a strict ``YYYY-MM-DDTHH:MM:SSZ`` timestamp (claimed time)."""
    try:
        parsed = datetime.strptime(value, _TIMESTAMP_FORMAT)
    except ValueError as exc:
        raise ValueError(
            f"Invalid HEA timestamp (expected YYYY-MM-DDTHH:MM:SSZ): {value!r}"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class TrustedKey:
    """A caller-supplied trusted public key.

    HEA extension (oev-attestation/0.1): the optional fields carry the key
    lifecycle. Absence of a field means "unknown", never "unbounded":
    a witness key MUST carry ``not_after`` (HEA design §9.1); receipt
    keys keep the fields optional for backwards compatibility.
    """

    key_id: str
    public_key_pem: bytes
    digest: str
    not_before: str | None = None
    not_after: str | None = None
    revoked: bool = False
    role: str | None = None
    successor_key_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustedKey:
        key_id = str(data["key_id"]).strip()
        if not key_id:
            raise ValueError("Trusted key 'key_id' cannot be empty")
        if len(key_id) > MAX_KEYID_LENGTH:
            raise ValueError(f"Trusted key 'key_id' exceeds maximum length ({MAX_KEYID_LENGTH})")
        pem = data["public_key_pem"]
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem)
        # Validate that it is a valid Ed25519 public key
        load_ed25519_public_key(pem_bytes)
        digest = sha256_bytes(pem_bytes)
        not_before = data.get("not_before")
        not_after = data.get("not_after")
        if not_before is not None:
            parse_hea_timestamp(str(not_before))
        if not_after is not None:
            parse_hea_timestamp(str(not_after))
        if (
            not_before is not None
            and not_after is not None
            and parse_hea_timestamp(str(not_before)) > parse_hea_timestamp(str(not_after))
        ):
            raise ValueError("Trusted key 'not_before' is after 'not_after'")
        role = data.get("role")
        if role is not None and str(role) not in KEY_ROLES:
            raise ValueError(f"Trusted key 'role' is not a known HEA role: {role!r}")
        successor = data.get("successor_key_id")
        if successor is not None and (
            not str(successor).strip() or len(str(successor)) > MAX_KEYID_LENGTH
        ):
            raise ValueError("Trusted key 'successor_key_id' is invalid")
        return cls(
            key_id=key_id,
            public_key_pem=pem_bytes,
            digest=digest,
            not_before=str(not_before) if not_before is not None else None,
            not_after=str(not_after) if not_after is not None else None,
            revoked=bool(data.get("revoked", False)),
            role=str(role) if role is not None else None,
            successor_key_id=str(successor) if successor is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem.decode("utf-8"),
        }
        if self.not_before is not None:
            d["not_before"] = self.not_before
        if self.not_after is not None:
            d["not_after"] = self.not_after
        if self.revoked:
            d["revoked"] = True
        if self.role is not None:
            d["role"] = self.role
        if self.successor_key_id is not None:
            d["successor_key_id"] = self.successor_key_id
        return d

    def key_state_at(self, claimed_time: str) -> str:
        """Return the key state at a claimed time: ``valid``/``expired``/``not_yet_valid``/``revoked``.

        The time is *claimed* (HEA design §9.4): expiry enforcement is
        therefore approximate, never a proof of wall-clock validity.
        Revocation is time-independent: a revoked key is revoked.
        """
        if self.revoked:
            return "revoked"
        moment = parse_hea_timestamp(claimed_time)
        if self.not_before is not None and moment < parse_hea_timestamp(self.not_before):
            return "not_yet_valid"
        if self.not_after is not None and moment > parse_hea_timestamp(self.not_after):
            return "expired"
        return "valid"

    def is_authorized_for(self, required_role: str) -> bool:
        """Role check (HEA design §9.2).

        A key with no recorded role keeps the pre-HEA behaviour: it may
        sign receipts only. Witness and checkpoint signing always require
        an explicit matching role.
        """
        if required_role == "receipt-signer":
            return self.role is None or self.role == "receipt-signer"
        return self.role == required_role


class TrustStore:
    """Container for caller-supplied trust roots."""

    def __init__(self, keys: list[TrustedKey] | None = None) -> None:
        self._keys: list[TrustedKey] = []
        self._key_ids: set[str] = set()
        if keys:
            for k in keys:
                self.add_key(k)

    def add_key(self, key: TrustedKey) -> None:
        if len(self._keys) >= MAX_TRUSTED_KEYS:
            raise ValueError(f"TrustStore cannot exceed maximum of {MAX_TRUSTED_KEYS} keys")
        if key.key_id in self._key_ids:
            raise ValueError(f"Duplicate trusted key ID '{key.key_id}' in trust store")
        self._keys.append(key)
        self._key_ids.add(key.key_id)

    @property
    def keys(self) -> list[TrustedKey]:
        return list(self._keys)

    def get_key_by_id(self, key_id: str) -> TrustedKey | None:
        for k in self._keys:
            if k.key_id == key_id:
                return k
        return None

    @classmethod
    def from_file(cls, path: str | Path) -> TrustStore:
        content = read_bounded_file(path)
        data = safe_json_loads(content)
        if not isinstance(data, list):
            raise TypeError("Trust file must be a JSON array of key objects")
        keys = [TrustedKey.from_dict(entry) for entry in data]
        return cls(keys)

    @classmethod
    def from_list(cls, key_dicts: list[dict[str, Any]]) -> TrustStore:
        keys = [TrustedKey.from_dict(entry) for entry in key_dicts]
        return cls(keys)


@dataclass(frozen=True)
class TrustEvaluationResult:
    """Result of evaluating a DSSE envelope against caller trust roots."""

    crypto_valid: bool
    is_trusted: bool
    trusted_key_id: str | None
    reason: str


def evaluate_receipt_trust(
    envelope: dict[str, Any],
    trust_store: TrustStore | None,
) -> TrustEvaluationResult:
    """Evaluate DSSE envelope signatures against caller-supplied verifier trust keys.

    If trust_store is None or empty:
      The receipt CANNOT be trusted, regardless of what keys are in the envelope.
    """
    if trust_store is None or len(trust_store.keys) == 0:
        return TrustEvaluationResult(
            crypto_valid=False,
            is_trusted=False,
            trusted_key_id=None,
            reason="No verifier trust roots supplied by caller (UNVERIFIED_SIGNER)",
        )

    for trusted_key in trust_store.keys:
        if verify_dsse_signature_with_key(envelope, trusted_key.public_key_pem):
            return TrustEvaluationResult(
                crypto_valid=True,
                is_trusted=True,
                trusted_key_id=trusted_key.key_id,
                reason=f"Signature cryptographically verified against trusted key '{trusted_key.key_id}'",
            )

    return TrustEvaluationResult(
        crypto_valid=False,
        is_trusted=False,
        trusted_key_id=None,
        reason="Signature did not match any caller-supplied trusted verifier key",
    )
