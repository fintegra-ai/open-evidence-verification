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
from pathlib import Path
from typing import Any

from .canonical import safe_json_loads
from .hashing import sha256_bytes
from .signing import (
    load_ed25519_public_key,
    verify_dsse_signature_with_key,
)

MAX_TRUSTED_KEYS: int = 64
MAX_KEYID_LENGTH: int = 256


@dataclass(frozen=True)
class TrustedKey:
    """A caller-supplied trusted public key."""

    key_id: str
    public_key_pem: bytes
    digest: str

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
        return cls(key_id=key_id, public_key_pem=pem_bytes, digest=digest)


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
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
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
