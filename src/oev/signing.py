"""Ed25519 cryptographic signing and verification for DSSE receipt envelopes.

Security model:
- Ed25519 signatures are computed over the DSSE PAE representation.
- The signed payload is the JCS-canonicalized JSON bytes of the VerificationReceipt.
- Signing asserts that an identified verifier executed the recorded appraisal.
- Trust is never derived from embedded keys or envelope keyid hints; caller must provide
  accepted verifier trust roots.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize_json
from .dsse import (
    DEFAULT_PAYLOAD_TYPE,
    build_dsse_envelope,
    compute_pae,
    parse_dsse_envelope,
)
from .models import VerificationReceipt


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair. Returns (private_key_pem, public_key_pem)."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_ed25519_private_key(pem_bytes: bytes) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes."""
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"Key is not Ed25519, got {type(key).__name__}")
        return key
    except Exception as exc:
        raise ValueError(f"Failed to load Ed25519 private key: {exc}") from exc


def load_ed25519_public_key(pem_bytes: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes."""
    try:
        key = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError(f"Key is not Ed25519, got {type(key).__name__}")
        return key
    except Exception as exc:
        raise ValueError(f"Failed to load Ed25519 public key: {exc}") from exc


def sign_receipt_dsse(
    receipt: VerificationReceipt | dict[str, Any],
    private_key_pem: bytes,
    key_id: str = "",
    payload_type: str = DEFAULT_PAYLOAD_TYPE,
) -> dict[str, Any]:
    """Canonicalize receipt, compute DSSE PAE, sign with Ed25519, and return DSSE envelope."""
    receipt_dict = (
        receipt.to_dict(include_digest=True)
        if isinstance(receipt, VerificationReceipt)
        else dict(receipt)
    )
    payload_bytes = canonicalize_json(receipt_dict)

    private_key = load_ed25519_private_key(private_key_pem)
    pae_bytes = compute_pae(payload_type, payload_bytes)
    raw_sig = private_key.sign(pae_bytes)

    sig_entry = {
        "sig": base64.b64encode(raw_sig).decode("ascii"),
    }
    if key_id:
        sig_entry["keyid"] = key_id

    return build_dsse_envelope(
        payload_type=payload_type,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_dsse_signature_with_key(
    envelope: dict[str, Any],
    public_key_pem: bytes,
) -> bool:
    """Check if any signature in the DSSE envelope verifies against the provided public key."""
    payload_type, payload_bytes, signatures = parse_dsse_envelope(envelope)
    pae_bytes = compute_pae(payload_type, payload_bytes)
    public_key = load_ed25519_public_key(public_key_pem)

    for sig_entry in signatures:
        try:
            raw_sig = base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True)
            public_key.verify(raw_sig, pae_bytes)
            return True
        except (InvalidSignature, ValueError):
            continue

    return False
