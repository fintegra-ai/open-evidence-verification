"""Implementation of the Dead Simple Signing Envelope (DSSE v1 specification).

DSSE is maintained in the Secure Systems Lab / in-toto ecosystem.
Specification reference: DSSE v1 specification (https://github.com/secure-systems-lab/dsse).
NOTE: DSSE is NOT RFC 9162 (RFC 9162 is Certificate Transparency Version 2.0).

DSSE security relies on Pre-Authentication Encoding (PAE) to bind the payloadType
and payload bytes unambiguously without relying on complex canonicalization schemes
for signature verification. In OEVP, JCS is used for deterministic content identity
prior to DSSE wrapping; DSSE authenticates the exact payload bytes through PAE.
"""

from __future__ import annotations

import base64
from typing import Any

DEFAULT_PAYLOAD_TYPE = "application/vnd.oev.verification-receipt+json"


class DsseError(ValueError):
    """Raised when a DSSE envelope is malformed or invalid."""


def compute_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """Compute DSSE v1 Pre-Authentication Encoding (PAE).

    PAE(payloadType, payload) =
        "DSSEv1 " + Length(payloadType) + " " + payloadType + " " + Length(payload) + " " + payload
    where Length(s) is the ASCII decimal representation of the byte length of s.
    """
    type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload_bytes)).encode("ascii")
        + b" "
        + payload_bytes
    )


def build_dsse_envelope(
    payload_type: str,
    payload_bytes: bytes,
    signatures: list[dict[str, str]],
) -> dict[str, Any]:
    """Construct a standard DSSE v1 envelope dictionary."""
    encoded_payload = base64.b64encode(payload_bytes).decode("ascii")
    return {
        "payloadType": payload_type,
        "payload": encoded_payload,
        "signatures": signatures,
    }


def parse_dsse_envelope(envelope: dict[str, Any]) -> tuple[str, bytes, list[dict[str, str]]]:
    """Parse and validate structure of a DSSE v1 envelope.

    Returns (payload_type, decoded_payload_bytes, signatures).
    """
    if not isinstance(envelope, dict):
        raise DsseError(f"Envelope must be a JSON object, got {type(envelope).__name__}")

    payload_type = envelope.get("payloadType")
    if not isinstance(payload_type, str) or not payload_type:
        raise DsseError("Envelope missing or invalid 'payloadType' string")

    payload_b64 = envelope.get("payload")
    if not isinstance(payload_b64, str):
        raise DsseError("Envelope missing or invalid 'payload' base64 string")

    try:
        payload_bytes = base64.b64decode(payload_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise DsseError(f"Envelope 'payload' contains invalid Base64 data: {exc}") from exc

    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or len(sigs) == 0:
        raise DsseError("Envelope 'signatures' must be a non-empty array")

    parsed_sigs: list[dict[str, str]] = []
    for idx, sig_entry in enumerate(sigs):
        if not isinstance(sig_entry, dict):
            raise DsseError(f"Signature entry #{idx} is not an object")
        sig_b64 = sig_entry.get("sig")
        if not isinstance(sig_b64, str) or not sig_b64:
            raise DsseError(f"Signature entry #{idx} missing 'sig' base64 string")
        key_id = sig_entry.get("keyid")
        if key_id is not None and not isinstance(key_id, str):
            raise DsseError(f"Signature entry #{idx} 'keyid' must be a string or omitted")

        parsed_sigs.append(
            {
                "sig": sig_b64,
                "keyid": key_id or "",
            }
        )

    return (payload_type, payload_bytes, parsed_sigs)
