# SPDX-License-Identifier: Apache-2.0

"""Pre-binding: Execution ID derivation and execution commitments (oev-execution/0.1).

HEA design §1. An Execution ID is content-derived, never a random UUID::

    execution_id = "exec_" + hex(SHA-256(JCS(pre-binding structure)))[:32]

The pre-binding structure binds bundle digest, profile digest, code digest,
check list, input digests, trust-inputs digest, a fresh 128-bit nonce and the
execution context. The witness issues a signed execution commitment *before*
execution starts; an attestation without a verifiable commitment is rejected
with ``NO_PREBINDING``.

Code digest scope (design Ek B, open question 1 — decided here and
documented in spec/execution-attestation-spec.md): the digest covers the
``oev`` package Python sources (engine, adapters, profiles, canonical,
DSSE, signing, trust, models, receipts, reverify, and the HEA modules
themselves) plus the running Python version. Third-party dependencies are
excluded. The digest is a *build identity*, not a proof of code correctness.
"""

from __future__ import annotations

import base64
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonicalize_json, safe_json_loads
from .dsse import DsseError, build_dsse_envelope, parse_dsse_envelope
from .hashing import is_valid_digest, sha256_bytes
from .schemas import validate_document
from .signing import load_ed25519_private_key
from .trust import parse_hea_timestamp

EXECUTION_PROTOCOL_VERSION = "oev-execution/0.1"
COMMITMENT_PAYLOAD_TYPE = "application/vnd.oev.execution-commitment+json"
COMMITMENT_SCHEMA_NAME = "execution-commitment-0.1.schema.json"

EXECUTION_ID_PREFIX = "exec_"
EXECUTION_ID_HEX_LENGTH = 32


def generate_nonce() -> str:
    """Generate a fresh 128-bit cryptographically random nonce (base64url, no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def is_valid_execution_id(execution_id: str) -> bool:
    """Check the ``exec_<32 lowercase hex>`` form (format only, not content)."""
    if not isinstance(execution_id, str) or not execution_id.startswith(EXECUTION_ID_PREFIX):
        return False
    suffix = execution_id[len(EXECUTION_ID_PREFIX) :]
    return len(suffix) == EXECUTION_ID_HEX_LENGTH and all(c in "0123456789abcdef" for c in suffix)


def build_prebinding(
    bundle_digest: str,
    bundle_format: str,
    profile_id: str,
    profile_version: str,
    profile_digest: str,
    code_version: dict[str, Any],
    check_ids: list[str],
    input_digests: dict[str, str] | None = None,
    trust_inputs_digest: str | None = None,
    nonce: str | None = None,
    witness_mode: str = "local-process",
    witness_key_id: str = "",
) -> dict[str, Any]:
    """Build the pre-binding structure (§1.2). Raises ValueError on bad inputs."""
    if not is_valid_digest(bundle_digest):
        raise ValueError(f"Invalid bundle_digest: {bundle_digest!r}")
    if not is_valid_digest(profile_digest):
        raise ValueError(f"Invalid profile_digest: {profile_digest!r}")
    code_digest = str(code_version.get("code_digest", ""))
    if not is_valid_digest(code_digest):
        raise ValueError(f"Invalid code_digest in code_version: {code_digest!r}")
    if not check_ids:
        raise ValueError("Pre-binding requires a non-empty check_ids list")
    if len(set(check_ids)) != len(check_ids):
        raise ValueError("Pre-binding check_ids must be unique")
    if len(check_ids) > 10_000:
        raise ValueError("Pre-binding check_ids exceed the 10 000 limit")
    digests = dict(input_digests or {})
    for name, digest in digests.items():
        if not is_valid_digest(digest):
            raise ValueError(f"Invalid input digest for {name!r}: {digest!r}")
    if trust_inputs_digest is not None and not is_valid_digest(trust_inputs_digest):
        raise ValueError(f"Invalid trust_inputs_digest: {trust_inputs_digest!r}")
    if witness_mode not in ("local-process", "separate-machine", "tee"):
        raise ValueError(f"Unknown witness_mode: {witness_mode!r}")
    return {
        "protocol_version": EXECUTION_PROTOCOL_VERSION,
        "bundle_digest": bundle_digest,
        "bundle_format": bundle_format,
        "profile_id": profile_id,
        "profile_version": profile_version,
        "profile_digest": profile_digest,
        "code_version": dict(code_version),
        "check_ids": sorted(check_ids),
        "input_digests": digests,
        "trust_inputs_digest": trust_inputs_digest or sha256_bytes(canonicalize_json([])),
        "nonce": nonce or generate_nonce(),
        "execution_context": {
            "witness_mode": witness_mode,
            "witness_key_id": witness_key_id,
        },
    }


def compute_execution_id(prebinding: dict[str, Any]) -> str:
    """Derive the Execution ID from a pre-binding structure (JCS + SHA-256)."""
    if str(prebinding.get("protocol_version", "")) != EXECUTION_PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported execution protocol version: {prebinding.get('protocol_version')!r}"
        )
    digest = sha256_bytes(canonicalize_json(prebinding))
    return EXECUTION_ID_PREFIX + digest[len("sha256:") : len("sha256:") + EXECUTION_ID_HEX_LENGTH]


def compute_trust_inputs_digest(trust_inputs: list[dict[str, Any]]) -> str:
    """Digest of the caller trust-input list (JCS over sorted entries)."""
    normalised = sorted(
        (
            {
                "trust_id": str(t.get("trust_id", "")),
                "type": str(t.get("type", "")),
                "digest": str(t.get("digest", "")),
            }
            for t in trust_inputs
        ),
        key=lambda t: t["trust_id"],
    )
    return sha256_bytes(canonicalize_json(normalised))


@dataclass(frozen=True)
class ExecutionCommitment:
    """A witness-signed pre-execution commitment (oev-execution/0.1)."""

    execution_id: str
    nonce: str
    bundle_digest: str
    profile_digest: str
    code_version: dict[str, Any]
    check_ids: list[str]
    input_digests: dict[str, str]
    issued_at_claimed: str
    protocol_version: str = EXECUTION_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "execution_id": self.execution_id,
            "nonce": self.nonce,
            "bundle_digest": self.bundle_digest,
            "profile_digest": self.profile_digest,
            "code_version": dict(self.code_version),
            "check_ids": list(self.check_ids),
            "input_digests": dict(self.input_digests),
            "issued_at_claimed": self.issued_at_claimed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionCommitment:
        if str(data.get("protocol_version", "")) != EXECUTION_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported execution protocol version: {data.get('protocol_version')!r}"
            )
        return cls(
            execution_id=str(data["execution_id"]),
            nonce=str(data["nonce"]),
            bundle_digest=str(data["bundle_digest"]),
            profile_digest=str(data["profile_digest"]),
            code_version=dict(data["code_version"]),
            check_ids=[str(c) for c in data["check_ids"]],
            input_digests={str(k): str(v) for k, v in dict(data.get("input_digests", {})).items()},
            issued_at_claimed=str(data["issued_at_claimed"]),
        )

    def commitment_digest(self) -> str:
        """SHA-256 (JCS) of the commitment payload — the digest the log and attestations bind."""
        return sha256_bytes(canonicalize_json(self.to_dict()))


def build_commitment_envelope(
    prebinding: dict[str, Any],
    execution_id: str,
    issued_at_claimed: str,
    private_key_pem: bytes,
    key_id: str = "",
) -> dict[str, Any]:
    """Sign a commitment payload as a DSSE envelope. Returns the envelope."""
    from .dsse import compute_pae

    commitment = ExecutionCommitment(
        execution_id=execution_id,
        nonce=str(prebinding["nonce"]),
        bundle_digest=str(prebinding["bundle_digest"]),
        profile_digest=str(prebinding["profile_digest"]),
        code_version=dict(prebinding["code_version"]),
        check_ids=[str(c) for c in prebinding["check_ids"]],
        input_digests={
            str(k): str(v) for k, v in dict(prebinding.get("input_digests", {})).items()
        },
        issued_at_claimed=issued_at_claimed,
    )
    payload = commitment.to_dict()
    validate_document(payload, COMMITMENT_SCHEMA_NAME)
    # Semantic timestamp check (round 3, P0): the schema pattern rejects
    # the wrong shape; this rejects impossible dates the pattern cannot
    # see. A commitment must never be signed with a malformed issue time.
    parse_hea_timestamp(issued_at_claimed)
    payload_bytes = canonicalize_json(payload)
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(COMMITMENT_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {
        "sig": base64.b64encode(raw_sig).decode("ascii"),
    }
    if key_id:
        sig_entry["keyid"] = key_id
    return build_dsse_envelope(
        payload_type=COMMITMENT_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def parse_commitment_envelope(envelope: dict[str, Any]) -> ExecutionCommitment:
    """Parse a DSSE commitment envelope and return the commitment payload."""
    payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    if payload_type != COMMITMENT_PAYLOAD_TYPE:
        raise DsseError(
            f"Unexpected DSSE payloadType for an execution commitment: {payload_type!r}"
        )
    data = safe_json_loads(payload_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise DsseError("Commitment payload is not a JSON object")
    validate_document(data, COMMITMENT_SCHEMA_NAME)
    commitment = ExecutionCommitment.from_dict(data)
    # Semantic timestamp check (round 3, P0): a malformed
    # ``issued_at_claimed`` previously crashed the verifier in
    # ``key_state_at``; fail here as a controlled ValueError instead.
    parse_hea_timestamp(commitment.issued_at_claimed)
    return commitment


def compute_code_digest(package_dir: str | Path | None = None) -> str:
    """Digest of the running ``oev`` package sources + Python version.

    Scope (decided per design Ek B Q1): every ``.py`` file under the
    installed ``oev`` package directory (sorted relative paths with their
    SHA-256 digests) plus the interpreter version. Third-party
    dependencies are excluded. Two installs with identical ``oev`` sources
    and the same Python version produce the same digest.
    """
    import oev

    base = Path(package_dir) if package_dir is not None else Path(str(oev.__file__)).parent
    files: dict[str, str] = {}
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(base).as_posix()
        files[rel] = sha256_bytes(path.read_bytes())
    record = {
        "python_version": sys.version.split()[0],
        "package": "oev",
        "files": files,
    }
    return sha256_bytes(canonicalize_json(record))


def build_code_version(
    engine: str,
    adapter: str,
    package_dir: str | Path | None = None,
    *,
    policy_digest: str | None = None,
    dependencies: list[dict[str, Any]] | None = None,
    include_environment: bool = False,
) -> dict[str, Any]:
    """Build the human-readable + digest ``code_version`` record for pre-binding.

    Round 3 (P0): producers may additionally record ``policy_digest``,
    ``dependencies`` and the ``environment`` record (see
    ``oev.code_digest``). They are optional and off by default, so
    existing callers keep the exact ``{engine, adapter, code_digest}``
    record; the verifier compares the extra fields only when the caller
    supplies an expected code-digest document.
    """
    record: dict[str, Any] = {
        "engine": engine,
        "adapter": adapter,
        "code_digest": compute_code_digest(package_dir),
    }
    if policy_digest is not None:
        record["policy_digest"] = policy_digest
    if dependencies is not None:
        record["dependencies"] = [dict(d) for d in dependencies]
    if include_environment:
        from .code_digest import build_environment_record

        record["environment"] = build_environment_record()
    return record
