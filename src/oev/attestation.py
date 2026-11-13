# SPDX-License-Identifier: Apache-2.0

"""Per-check execution attestations (oev-attestation/0.1).

HEA design §3. One attestation covers exactly one check: putting a whole
check vector into one attestation would hide partial forgery. The witness
signs a JCS-canonical payload inside a DSSE v1 envelope with
``payloadType: application/vnd.oev.execution-attestation+json``.

Rules enforced here:
- ``limitations`` is mandatory and non-empty: every witness model has a
  limit, and a witness that writes none is not trustworthy.
- ``claimed_time`` is self-asserted by name: it is never used for ordering
  or expiry decisions beyond the approximate key-state check (§9.4).
- ``detail`` is capped at 1 KiB and must not carry sensitive content (§9.5).
- The committed OEPT test-only key (``conformance/test-only-keys/``) is
  block-listed by public-key digest: an attestation signed with it is
  rejected with ``SIGNATURE_UNTRUSTED`` even if a caller trusted it by
  mistake (defence in depth; design §9.1).
- A witness key MUST carry ``not_after`` (design §9.1); a witness key
  without an expiry is rejected with ``WITNESS_KEY_EXPIRED`` treatment
  (reported as unauthorised-for-witness-role).

Two-way binding note (design §5.2, circularity resolution): attestations
are produced *before* the receipt exists, so ``receipt_digest`` is absent
from them; the receipt instead binds the attestations through its
``execution_attestations[]`` field, which is inside the receipt digest.
When a receipt digest IS present in an attestation, the verifier checks it
against the receipt; when absent, the receipt-to-attestation binding is
the authoritative link.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .canonical import canonicalize_json, safe_json_loads
from .dsse import DsseError, build_dsse_envelope, compute_pae, parse_dsse_envelope
from .hashing import is_valid_digest, sha256_bytes
from .revocation import RevocationList
from .schemas import validate_document
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .trust import TrustStore

ATTESTATION_PROTOCOL_VERSION = "oev-attestation/0.1"
ATTESTATION_PAYLOAD_TYPE = "application/vnd.oev.execution-attestation+json"
ATTESTATION_SCHEMA_NAME = "execution-attestation-0.1.schema.json"

MAX_DETAIL_CHARS = 1024
WITNESS_MODES: frozenset[str] = frozenset({"local-process", "separate-machine", "tee"})
EXECUTION_STATUSES: frozenset[str] = frozenset({"COMPLETED", "FAILED", "INTERRUPTED"})
CHECK_STATUSES: frozenset[str] = frozenset(
    {"PASS", "FAIL", "NOT_RUN", "NOT_APPLICABLE", "UNVERIFIED", "UNSUPPORTED"}
)

#: SHA-256 digests (``sha256:<hex>`` over the PEM bytes) of public keys that
#: must never sign an attestation. The OEPT committed test-only conformance
#: key is public by definition; its public PEM hashes to this value.
KNOWN_TEST_KEY_DIGESTS: frozenset[str] = frozenset(
    {
        # OEPT conformance/test-only-keys/conformance-test-only-signing.pub
        "sha256:7b62577c0ed2710b0d171aa4bdb96834ccacdd91e73ab115f73b38130369656b",
    }
)


def compute_attestation_id(execution_id: str, check_id: str) -> str:
    """``att_<first 16 hex of SHA-256(execution_id + ':' + check_id)>``.

    The design names the attestation id after the execution id; the check
    id is folded in so that one execution's per-check attestations stay
    distinct (design §3.1 requires one attestation per check).
    """
    digest = sha256_bytes(f"{execution_id}:{check_id}".encode())
    return "att_" + digest[len("sha256:") : len("sha256:") + 16]


def compute_attestation_digest(payload: dict[str, Any]) -> str:
    """SHA-256 (JCS) of an attestation payload — what the receipt binds."""
    return sha256_bytes(canonicalize_json(payload))


@dataclass(frozen=True)
class Attestation:
    """A witness-signed claim about one check of one execution (§3.1)."""

    attestation_id: str
    execution_id: str
    execution_commitment_digest: str
    bundle_digest: str
    profile_digest: str
    code_version: dict[str, Any]
    check_id: str
    inputs_digest: str
    execution_status: str
    result_status: str
    result_detail: str
    result_duration_ms: int
    witness_mode: str
    witness_key_id: str
    witness_software: str
    log_anchor: dict[str, Any]
    claimed_time: str
    limitations: list[dict[str, Any]] = field(default_factory=list)
    receipt_digest: str | None = None
    tee_measurement: str | None = None
    protocol_version: str = ATTESTATION_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "attestation_id": self.attestation_id,
            "execution_id": self.execution_id,
            "execution_commitment_digest": self.execution_commitment_digest,
            "bundle_digest": self.bundle_digest,
            "profile_digest": self.profile_digest,
            "code_version": dict(self.code_version),
            "check_id": self.check_id,
            "inputs_digest": self.inputs_digest,
            "execution_status": self.execution_status,
            "result": {
                "status": self.result_status,
                "detail": self.result_detail,
                "duration_ms": self.result_duration_ms,
            },
            "witness": {
                "witness_mode": self.witness_mode,
                "witness_key_id": self.witness_key_id,
                "witness_software": self.witness_software,
            },
            "log_anchor": dict(self.log_anchor),
            "claimed_time": self.claimed_time,
            "limitations": [dict(lim) for lim in self.limitations],
        }
        if self.tee_measurement is not None:
            d["witness"]["tee_measurement"] = self.tee_measurement
        if self.receipt_digest is not None:
            d["receipt_digest"] = self.receipt_digest
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Attestation:
        if str(data.get("protocol_version", "")) != ATTESTATION_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported attestation protocol version: {data.get('protocol_version')!r}"
            )
        result = data["result"]
        witness = data["witness"]
        limitations = data.get("limitations", [])
        if not isinstance(limitations, list) or len(limitations) == 0:
            raise ValueError("Attestation 'limitations' is mandatory and must be non-empty")
        return cls(
            attestation_id=str(data["attestation_id"]),
            execution_id=str(data["execution_id"]),
            execution_commitment_digest=str(data["execution_commitment_digest"]),
            bundle_digest=str(data["bundle_digest"]),
            profile_digest=str(data["profile_digest"]),
            code_version=dict(data["code_version"]),
            check_id=str(data["check_id"]),
            inputs_digest=str(data["inputs_digest"]),
            execution_status=str(data["execution_status"]),
            result_status=str(result["status"]),
            result_detail=str(result.get("detail", "")),
            result_duration_ms=int(result.get("duration_ms", 0)),
            witness_mode=str(witness["witness_mode"]),
            witness_key_id=str(witness["witness_key_id"]),
            witness_software=str(witness["witness_software"]),
            log_anchor=dict(data["log_anchor"]),
            claimed_time=str(data["claimed_time"]),
            limitations=[dict(lim) for lim in limitations],
            receipt_digest=str(data["receipt_digest"]) if data.get("receipt_digest") else None,
            tee_measurement=str(witness["tee_measurement"])
            if witness.get("tee_measurement")
            else None,
        )


def validate_attestation_payload(payload: dict[str, Any]) -> None:
    """Validate an attestation payload dict (schema + HEA rules). Raises ValueError."""
    validate_document(payload, ATTESTATION_SCHEMA_NAME)
    attestation = Attestation.from_dict(payload)  # structural + limitations check
    if attestation.witness_mode not in WITNESS_MODES:
        raise ValueError(f"Unknown witness_mode: {attestation.witness_mode!r}")
    if attestation.execution_status not in EXECUTION_STATUSES:
        raise ValueError(f"Unknown execution_status: {attestation.execution_status!r}")
    if attestation.result_status not in CHECK_STATUSES:
        raise ValueError(f"Unknown result status: {attestation.result_status!r}")
    if len(attestation.result_detail) > MAX_DETAIL_CHARS:
        raise ValueError(f"Attestation result detail exceeds {MAX_DETAIL_CHARS} characters")
    if not is_valid_digest(attestation.bundle_digest):
        raise ValueError("Attestation bundle_digest is malformed")
    if not is_valid_digest(attestation.profile_digest):
        raise ValueError("Attestation profile_digest is malformed")
    if not is_valid_digest(attestation.execution_commitment_digest):
        raise ValueError("Attestation execution_commitment_digest is malformed")
    if not is_valid_digest(attestation.inputs_digest):
        raise ValueError("Attestation inputs_digest is malformed")
    if attestation.receipt_digest is not None and not is_valid_digest(attestation.receipt_digest):
        raise ValueError("Attestation receipt_digest is malformed")
    if attestation.result_status == "NOT_RUN" and attestation.execution_status != "INTERRUPTED":
        # A check that never ran inside a completed execution is a producer
        # error, not a witnessable outcome; the witness must not attest it
        # as a completed result. (NOT_RUN inside INTERRUPTED is legitimate.)
        raise ValueError("NOT_RUN result requires execution_status INTERRUPTED")
    expected_id = compute_attestation_id(attestation.execution_id, attestation.check_id)
    if attestation.attestation_id != expected_id:
        raise ValueError(
            f"attestation_id mismatch: {attestation.attestation_id!r} != {expected_id!r}"
        )


def sign_attestation_dsse(
    payload: dict[str, Any],
    private_key_pem: bytes,
    key_id: str = "",
) -> dict[str, Any]:
    """Validate and DSSE-sign an attestation payload. Returns the envelope."""
    validate_attestation_payload(payload)
    # Defence in depth: never sign with the committed test-only key.
    private_key = load_ed25519_private_key(private_key_pem)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sha256_bytes(public_pem) in KNOWN_TEST_KEY_DIGESTS:
        raise ValueError("Refusing to sign an attestation with the committed test-only key")
    payload_bytes = canonicalize_json(payload)
    raw_sig = private_key.sign(compute_pae(ATTESTATION_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
    if key_id:
        sig_entry["keyid"] = key_id
    return build_dsse_envelope(
        payload_type=ATTESTATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


@dataclass(frozen=True)
class AttestationSignatureEvaluation:
    """Outcome of the signature-level check of one attestation (§3.4)."""

    crypto_valid: bool
    trusted_key_id: str | None
    reason: str  # "" on success, else a HeaReason code


def parse_attestation_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Parse a DSSE attestation envelope into its payload dict (no trust check)."""
    payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    if payload_type != ATTESTATION_PAYLOAD_TYPE:
        raise DsseError(
            f"Unexpected DSSE payloadType for an execution attestation: {payload_type!r}"
        )
    data = safe_json_loads(payload_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise DsseError("Attestation payload is not a JSON object")
    return data


def evaluate_attestation_signature(
    envelope: dict[str, Any],
    witness_trust_store: TrustStore | None,
    revocation_list: RevocationList | None = None,
) -> tuple[dict[str, Any] | None, AttestationSignatureEvaluation]:
    """Signature-level verification of an attestation (§3.4 steps 1–5).

    Returns ``(payload_or_None, evaluation)``. ``payload`` is returned only
    when the payload parses; trust failures still return the payload so the
    caller can report which attestation failed.
    """
    try:
        payload = parse_attestation_envelope(envelope)
    except (DsseError, ValueError) as exc:
        return None, AttestationSignatureEvaluation(
            crypto_valid=False, trusted_key_id=None, reason=f"MALFORMED_ATTESTATION: {exc}"
        )
    try:
        validate_attestation_payload(payload)
    except ValueError as exc:
        return payload, AttestationSignatureEvaluation(
            crypto_valid=False, trusted_key_id=None, reason=f"MALFORMED_ATTESTATION: {exc}"
        )
    if witness_trust_store is None or len(witness_trust_store.keys) == 0:
        return payload, AttestationSignatureEvaluation(
            crypto_valid=False, trusted_key_id=None, reason="SIGNATURE_UNTRUSTED"
        )
    attestation = Attestation.from_dict(payload)
    _payload_type, payload_bytes, signatures = parse_dsse_envelope(envelope)
    pae = compute_pae(ATTESTATION_PAYLOAD_TYPE, payload_bytes)
    hinted_key_ids = {s.get("keyid", "") for s in signatures} | {attestation.witness_key_id}
    candidate_exists = any(k.key_id in hinted_key_ids for k in witness_trust_store.keys)
    for trusted_key in witness_trust_store.keys:
        if sha256_bytes(trusted_key.public_key_pem) in KNOWN_TEST_KEY_DIGESTS:
            continue  # committed test key can never authenticate an attestation
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
        except ValueError:
            continue
        crypto_ok = False
        for sig_entry in signatures:
            try:
                public_key.verify(
                    base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                )
                crypto_ok = True
                break
            except (InvalidSignature, ValueError):
                continue
        if not crypto_ok:
            continue
        # Cryptographically valid under a caller-trusted key: now the HEA rules.
        if revocation_list is not None and revocation_list.is_revoked(trusted_key.key_id):
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_KEY_REVOKED"
            )
        if trusted_key.revoked:
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_KEY_REVOKED"
            )
        if trusted_key.role != "witness":
            # Includes role=None: pre-HEA keys without a role may sign
            # receipts only, never attestations (design §9.2).
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_UNAUTHORIZED"
            )
        if trusted_key.not_after is None:
            # Witness keys MUST carry an expiry (design §9.1).
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_KEY_EXPIRED"
            )
        state = str(trusted_key.key_state_at(attestation.claimed_time))
        if state == "expired":
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_KEY_EXPIRED"
            )
        if state == "not_yet_valid":
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_UNAUTHORIZED"
            )
        if trusted_key.key_id != attestation.witness_key_id:
            return payload, AttestationSignatureEvaluation(
                crypto_valid=True, trusted_key_id=trusted_key.key_id, reason="WITNESS_UNAUTHORIZED"
            )
        return payload, AttestationSignatureEvaluation(
            crypto_valid=True, trusted_key_id=trusted_key.key_id, reason=""
        )
    # No trusted key verified the signature. If the envelope names a
    # caller-trusted key (keyid hint or payload witness_key_id) yet the
    # signature fails under it, the signature itself is invalid; otherwise
    # the signer is simply untrusted.
    reason = "SIGNATURE_INVALID" if candidate_exists else "SIGNATURE_UNTRUSTED"
    return payload, AttestationSignatureEvaluation(
        crypto_valid=False, trusted_key_id=None, reason=reason
    )
