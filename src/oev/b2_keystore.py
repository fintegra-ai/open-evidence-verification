# SPDX-License-Identifier: Apache-2.0

"""Separate keystores for Model B2 (round 4, worker D).

A B2 witness must not share key custody with the producer: the witness
private key lives in a *different directory* from the producer key, with
different filesystem permissions, and is loaded through a *different
code path* (the witness worker / mTLS server reads only its own
keystore; the producer process never opens it).

Layout per keystore root (all under one role directory)::

    <root>/
      keys/        0o700 — private keys 0o600, public keys 0o644
      tls/         0o700 — mTLS test certificates (see ``b2_mtls``)
      meta/        0o700 — rotation-chain records (JSON, world-readable? no: 0o600)

Rules enforced here, not by convention:
* ``key_id`` is restricted to ``[A-Za-z0-9_-]+`` (no path traversal);
* every load resolves inside the keystore's own ``keys/`` directory;
* a keystore records its role (``witness`` / ``producer`` /
  ``checkpoint-signer``) and refuses to load a key whose recorded role
  does not match the keystore role;
* key rotation is an explicit, signed chain: each rotation record is
  DSSE-signed by the OLD key (proof of possession) and binds the old
  and new public-key digests, so a verifier can walk old -> new.

Honest limits: filesystem permissions are a same-host control only.
On a shared host a root-level attacker (or the producer, if it runs as
the same user) can still read the keystore. Separate keystores raise
the bar from "one accidental read" to "a host-level compromise"; they
are NOT independent-host custody. Rotation does not retroactively
invalidate attestations signed by the old key — those stay valid until
the old key is revoked (see ``oev.revocation``).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .canonical import canonicalize_json
from .dsse import build_dsse_envelope, compute_pae, parse_dsse_envelope
from .hashing import sha256_bytes
from .signing import (
    generate_ed25519_keypair,
    load_ed25519_private_key,
    load_ed25519_public_key,
)

KEYSTORE_ROLES: frozenset[str] = frozenset({"witness", "producer", "checkpoint-signer"})
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

ROTATION_PROTOCOL_VERSION = "oev-key-rotation/0.1"
ROTATION_PAYLOAD_TYPE = "application/vnd.oev.key-rotation+json"


def _check_key_id(key_id: str) -> str:
    if not _KEY_ID_RE.match(key_id):
        raise ValueError(f"Invalid key_id (path traversal / bad characters): {key_id!r}")
    return key_id


def _public_pem_of_private(private_key_pem: bytes) -> bytes:
    return (
        load_ed25519_private_key(private_key_pem)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


@dataclass
class Keystore:
    """One role's key directory (witness, producer or checkpoint-signer)."""

    root: Path
    role: str

    def __post_init__(self) -> None:
        if self.role not in KEYSTORE_ROLES:
            raise ValueError(f"Unknown keystore role: {self.role!r}")
        self.root = Path(self.root)
        self.keys_dir = self.root / "keys"
        self.tls_dir = self.root / "tls"
        self.meta_dir = self.root / "meta"

    def create(self) -> Keystore:
        """Create the directories with 0o700 (no group/other access)."""
        for d in (self.root, self.keys_dir, self.tls_dir, self.meta_dir):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)
        (self.root / "meta" / "role.json").write_bytes(
            canonicalize_json({"role": self.role, "keystore": "oev-b2-keystore/0.1"})
        )
        (self.root / "meta" / "role.json").chmod(0o600)
        return self

    @classmethod
    def open(cls, root: str | Path, role: str) -> Keystore:
        """Open an existing keystore, refusing a role mismatch."""
        ks = cls(Path(root), role)
        role_file = ks.root / "meta" / "role.json"
        if not role_file.is_file():
            raise ValueError(f"Not a keystore (no meta/role.json): {ks.root}")
        recorded = json.loads(role_file.read_bytes().decode("utf-8"))
        if str(recorded.get("role", "")) != role:
            raise ValueError(
                f"Keystore role mismatch: directory records {recorded.get('role')!r}, "
                f"caller asked for {role!r} — a witness keystore must not be "
                "opened as a producer keystore"
            )
        return ks

    # -- keys ---------------------------------------------------------------
    def _private_path(self, key_id: str) -> Path:
        return self.keys_dir / f"{_check_key_id(key_id)}.key.pem"

    def _public_path(self, key_id: str) -> Path:
        return self.keys_dir / f"{_check_key_id(key_id)}.pub.pem"

    def generate_keypair(self, key_id: str) -> tuple[bytes, bytes]:
        """Generate + store a fresh Ed25519 keypair (private file 0o600)."""
        _check_key_id(key_id)
        if self._private_path(key_id).exists():
            raise ValueError(f"Key already exists in this keystore: {key_id!r}")
        priv, pub = generate_ed25519_keypair()
        self.store_keypair(key_id, priv, pub)
        return priv, pub

    def store_keypair(self, key_id: str, private_key_pem: bytes, public_key_pem: bytes) -> None:
        """Store a keypair, verifying the public half belongs to the private half."""
        _check_key_id(key_id)
        derived = _public_pem_of_private(private_key_pem)
        if sha256_bytes(derived) != sha256_bytes(public_key_pem):
            raise ValueError("Public key does not belong to the private key")
        priv_path = self._private_path(key_id)
        pub_path = self._public_path(key_id)
        priv_path.write_bytes(private_key_pem)
        priv_path.chmod(0o600)
        pub_path.write_bytes(public_key_pem)
        pub_path.chmod(0o644)

    def load_private_key(self, key_id: str) -> bytes:
        """Load a private key — only from this keystore's own keys/ dir."""
        path = self._private_path(_check_key_id(key_id))
        resolved = path.resolve()
        if resolved.parent != self.keys_dir.resolve():
            raise ValueError(f"Key path escapes the keystore: {key_id!r}")
        if not resolved.is_file():
            raise ValueError(f"No such key in this keystore: {key_id!r}")
        return resolved.read_bytes()

    def load_public_key(self, key_id: str) -> bytes:
        path = self._public_path(_check_key_id(key_id))
        if not path.is_file():
            raise ValueError(f"No such key in this keystore: {key_id!r}")
        return path.read_bytes()

    def list_key_ids(self) -> list[str]:
        return sorted(p.name[: -len(".key.pem")] for p in self.keys_dir.glob("*.key.pem"))

    def permissions_report(self) -> dict[str, Any]:
        """Report the actual on-disk modes (for tests / deployment checks)."""
        import stat

        def _mode(p: Path) -> str:
            return oct(stat.S_IMODE(p.stat().st_mode))

        report: dict[str, Any] = {
            "root": _mode(self.root),
            "keys_dir": _mode(self.keys_dir),
            "keys": {},
        }
        for key_id in self.list_key_ids():
            report["keys"][key_id] = {
                "private": _mode(self._private_path(key_id)),
                "public": _mode(self._public_path(key_id)),
            }
        return report


# -- key rotation ------------------------------------------------------------


def build_rotation_record(
    old_private_key_pem: bytes,
    old_key_id: str,
    new_public_key_pem: bytes,
    new_key_id: str,
    rotated_at_claimed: str,
) -> dict[str, Any]:
    """Build a rotation record, DSSE-signed by the OLD key.

    The old key's signature proves the rotation was authorised by the
    holder of the key being replaced (not by someone who merely knows
    the new public key). The record binds both public-key digests.
    """
    old_public_pem = _public_pem_of_private(old_private_key_pem)
    record: dict[str, Any] = {
        "protocol_version": ROTATION_PROTOCOL_VERSION,
        "old_key_id": _check_key_id(old_key_id),
        "old_key_digest": sha256_bytes(old_public_pem),
        "new_key_id": _check_key_id(new_key_id),
        "new_key_digest": sha256_bytes(new_public_key_pem),
        "rotated_at_claimed": rotated_at_claimed,
    }
    payload_bytes = canonicalize_json(record)
    private_key = load_ed25519_private_key(old_private_key_pem)
    raw_sig = private_key.sign(compute_pae(ROTATION_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {
        "sig": base64.b64encode(raw_sig).decode("ascii"),
        "keyid": old_key_id,
    }
    return build_dsse_envelope(
        payload_type=ROTATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_rotation_record(
    envelope: dict[str, Any],
    old_public_key_pem: bytes,
    expected_new_public_key_pem: bytes | None = None,
) -> tuple[dict[str, Any] | None, bool, str]:
    """Verify one rotation record. Returns ``(record|None, ok, note)``.

    ``ok`` is False (not an exception) for a bad signature, a digest
    mismatch, or a malformed envelope — callers must treat that as a
    failed rotation, never as "rotation unknown, proceed anyway".
    """
    try:
        payload_type, payload_bytes, signatures = parse_dsse_envelope(envelope)
    except ValueError as exc:
        return None, False, f"rotation record envelope malformed: {exc}"
    if payload_type != ROTATION_PAYLOAD_TYPE:
        return None, False, f"unexpected rotation payloadType: {payload_type!r}"
    try:
        record = json.loads(payload_bytes.decode("utf-8"))
    except ValueError as exc:
        return None, False, f"rotation record payload is not valid JSON: {exc}"
    if not isinstance(record, dict):
        return None, False, "rotation record payload is not a JSON object"
    if str(record.get("protocol_version", "")) != ROTATION_PROTOCOL_VERSION:
        return None, False, "unsupported rotation protocol version"
    try:
        public_key = load_ed25519_public_key(old_public_key_pem)
    except ValueError as exc:
        return None, False, f"old public key unloadable: {exc}"
    if sha256_bytes(old_public_key_pem) != str(record.get("old_key_digest", "")):
        return None, False, "rotation record old_key_digest does not match the old public key"
    if expected_new_public_key_pem is not None and sha256_bytes(expected_new_public_key_pem) != str(
        record.get("new_key_digest", "")
    ):
        return None, False, "rotation record new_key_digest does not match the new public key"
    pae = compute_pae(payload_type, payload_bytes)
    for sig_entry in signatures:
        try:
            public_key.verify(
                base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
            )
            return record, True, "rotation record verified (signed by the old key)"
        except (InvalidSignature, ValueError):
            continue
    return None, False, "rotation record signature does not verify against the old key"


def verify_rotation_chain(
    envelopes: list[dict[str, Any]],
    first_old_public_key_pem: bytes,
    keystore: Keystore | None = None,
) -> tuple[bool, str]:
    """Verify a chain old -> new -> newer ... Each link's ``new_key_id``
    must equal the next link's ``old_key_id`` and the digests must line
    up with the keystore contents when a keystore is supplied."""
    current_pub = first_old_public_key_pem
    for index, envelope in enumerate(envelopes):
        record, ok, note = verify_rotation_record(envelope, current_pub)
        if not ok:
            return False, f"rotation link {index} invalid: {note}"
        if record is None:
            return False, f"rotation link {index} has no record"
        if keystore is not None:
            try:
                new_pub = keystore.load_public_key(str(record["new_key_id"]))
            except ValueError as exc:
                return False, f"rotation link {index}: new key not in keystore: {exc}"
            if sha256_bytes(new_pub) != str(record["new_key_digest"]):
                return False, f"rotation link {index}: new key digest mismatch in keystore"
            current_pub = new_pub
        else:
            # Without a keystore we can only check the id linkage.
            if index + 1 < len(envelopes):
                nxt = envelopes[index + 1]
                try:
                    _pt, nxt_bytes, _s = parse_dsse_envelope(nxt)
                    nxt_record = json.loads(nxt_bytes.decode("utf-8"))
                except ValueError as exc:
                    return False, f"rotation link {index + 1} unparseable: {exc}"
                if str(nxt_record.get("old_key_id")) != str(record["new_key_id"]):
                    return False, (
                        f"rotation chain break between links {index} and {index + 1}: "
                        "new_key_id != next old_key_id"
                    )
    return True, f"rotation chain verified ({len(envelopes)} link(s))"


__all__ = [
    "KEYSTORE_ROLES",
    "ROTATION_PAYLOAD_TYPE",
    "ROTATION_PROTOCOL_VERSION",
    "Keystore",
    "build_rotation_record",
    "verify_rotation_chain",
    "verify_rotation_record",
]
