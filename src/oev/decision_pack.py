# SPDX-License-Identifier: Apache-2.0

"""Decision Evidence Pack construction, manifest signing, and legacy verify API.

Determinism contract:
- Every JSON pack member and the manifest are stored as RFC 8785 (JCS) canonical
  UTF-8 bytes with no trailing newline; digests are computed over those bytes.
- Artifact members are hashed over their raw stored bytes (no canonicalization).
- Manifest members are recorded in stable, lexicographically sorted path order.
- pack_digest = sha256(JCS(manifest body without 'pack_digest')) — the same
  self-digest recursion rule used by verification receipts.

Integrity boundary: verification asserts technical integrity only. It never
asserts factual truth, commercial truth, legal validity, compliance approval,
or fraud detection, and it never re-executes recorded rules.

All verification logic lives in :mod:`oev.pack_verifier` — the independent,
offline verifier module. This builder module depends on the verifier, never
the reverse.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization

from oev.canonical import canonicalize_json, safe_json_loads
from oev.decision_models import (
    ARTIFACTS_DIR_PREFIX,
    CANONICALIZATION_JCS,
    CANONICALIZATION_RAW,
    CORE_MEMBER_ROLES,
    DECISION_PACK_PROTOCOL_VERSION,
    DSSE_ENVELOPE_MEMBER_PATH,
    MANIFEST_MEMBER_PATH,
    MANIFEST_PAYLOAD_TYPE,
    ROLE_TO_SCHEMA,
    PackManifest,
    PackMember,
    PackVerificationResult,
)
from oev.dsse import compute_pae
from oev.hashing import sha256_bytes
from oev.pack_verifier import (
    MANIFEST_SCHEMA_NAME,
    PackSignatureState,
    compute_manifest_self_digest,
    verify_pack_offline,
)
from oev.schemas import validate_document
from oev.signing import load_ed25519_private_key
from oev.trust import TrustStore

MEDIA_TYPE_BY_SUFFIX: dict[str, str] = {
    ".csv": "text/csv",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".xml": "application/xml",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}

MAX_ARTIFACT_BYTES: int = 64 * 1024 * 1024


class DecisionPackError(ValueError):
    """Raised when a decision pack cannot be built or is structurally invalid."""


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_member_bytes(obj: Any) -> bytes:
    """Return the canonical JCS bytes used for storage and hashing of a JSON member."""
    return canonicalize_json(obj)


def compute_rule_digest(rule: dict[str, Any]) -> str:
    """Content-address a rule definition (rules-as-data) via JCS canonical bytes."""
    return sha256_bytes(canonicalize_json(rule))


def compute_pack_digest(manifest: dict[str, Any] | PackManifest) -> str:
    """Compute the manifest self-digest: sha256 over JCS body WITHOUT pack_digest."""
    d = (
        manifest.to_dict(include_digest=False)
        if isinstance(manifest, PackManifest)
        else dict(manifest)
    )
    d.pop("pack_digest", None)
    return compute_manifest_self_digest(d)


def artifact_media_type(path: str) -> str:
    """Deterministic media-type mapping for artifact members."""
    suffix = PurePosixPath(path).suffix.lower()
    return MEDIA_TYPE_BY_SUFFIX.get(suffix, "application/octet-stream")


@dataclass(frozen=True)
class MemberInput:
    """Prepared bytes for one pack member awaiting manifest coverage."""

    path: str
    role: str
    media_type: str
    canonicalization: str
    body: bytes


def build_manifest(
    pack_id: str,
    case_id: str,
    created_at: str,
    member_inputs: list[MemberInput],
    creator_software: str | None = None,
    creator_version: str | None = None,
) -> PackManifest:
    """Build and schema-validate a manifest from prepared member bytes.

    Members are recorded in stable, lexicographically sorted path order.
    """
    if not pack_id or not case_id:
        raise DecisionPackError("pack_id and case_id must be non-empty")
    if not member_inputs:
        raise DecisionPackError("A pack requires at least the seven core members")

    paths = [m.path for m in member_inputs]
    if len(set(paths)) != len(paths):
        raise DecisionPackError("Duplicate member paths in pack input")

    members = [
        PackMember(
            path=m.path,
            role=m.role,
            media_type=m.media_type,
            canonicalization=m.canonicalization,
            size_bytes=len(m.body),
            sha256=sha256_bytes(m.body),
        )
        for m in sorted(member_inputs, key=lambda m: m.path)
    ]

    manifest = PackManifest(
        pack_id=pack_id,
        case_id=case_id,
        created_at=created_at,
        members=members,
        creator_software=creator_software,
        creator_version=creator_version,
    )
    digest = compute_pack_digest(manifest)
    validated = PackManifest(
        pack_id=manifest.pack_id,
        case_id=manifest.case_id,
        created_at=manifest.created_at,
        members=manifest.members,
        creator_software=manifest.creator_software,
        creator_version=manifest.creator_version,
        pack_digest=digest,
    )
    validate_document(validated.to_dict(include_digest=True), MANIFEST_SCHEMA_NAME)
    return validated


def _validate_member_path(path: str, role: str) -> None:
    """Enforce structural path rules beyond the JSON Schema pattern."""
    if path in (MANIFEST_MEMBER_PATH, DSSE_ENVELOPE_MEMBER_PATH):
        raise DecisionPackError(f"'{path}' must never be listed as a pack member")
    if path.startswith("/") or "\\" in path or ".." in path.split("/"):
        raise DecisionPackError(f"Unsafe member path: {path!r}")
    if path.endswith("/"):
        raise DecisionPackError(f"Member path must not end with '/': {path!r}")
    if role == "artifact":
        if not path.startswith(ARTIFACTS_DIR_PREFIX):
            raise DecisionPackError(
                f"Artifact members must live under '{ARTIFACTS_DIR_PREFIX}': {path}"
            )
    else:
        expected = CORE_MEMBER_ROLES.get(role)
        if expected is None:
            raise DecisionPackError(f"Unknown member role: {role!r}")
        if path != expected:
            raise DecisionPackError(f"Role '{role}' must use path '{expected}', got '{path}'")


def write_pack(out_dir: Path, manifest: PackManifest, bodies: dict[str, bytes]) -> None:
    """Write canonical member bytes and the canonical manifest into out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for member in manifest.members:
        body = bodies.get(member.path)
        if body is None:
            raise DecisionPackError(f"Missing prepared body for member '{member.path}'")
        target = out_dir / member.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (out_dir / MANIFEST_MEMBER_PATH).write_bytes(canonicalize_json(manifest.to_dict(True)))


def _load_core_member(src_dir: Path, role: str) -> tuple[Any, bytes]:
    """Read, parse, and schema-validate one core JSON member from a source directory."""
    path = src_dir / CORE_MEMBER_ROLES[role]
    if not path.is_file():
        raise DecisionPackError(f"Missing core member file: {path}")
    try:
        data = safe_json_loads(path.read_bytes())
    except ValueError as exc:
        raise DecisionPackError(
            f"Core member '{CORE_MEMBER_ROLES[role]}' is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise DecisionPackError(f"Core member '{CORE_MEMBER_ROLES[role]}' must be a JSON object")
    if data.get("protocol_version") != DECISION_PACK_PROTOCOL_VERSION:
        raise DecisionPackError(
            f"Core member '{CORE_MEMBER_ROLES[role]}' must declare "
            f"protocol_version {DECISION_PACK_PROTOCOL_VERSION}"
        )
    validate_document(data, ROLE_TO_SCHEMA[role])
    return data, canonicalize_json(data)


def collect_source_members(src_dir: Path) -> tuple[str, list[MemberInput]]:
    """Collect and canonicalize all members from a source directory.

    Returns (case_id, member_inputs). The source directory must contain exactly
    the seven core members plus (optionally) an artifacts/ subtree.
    """
    src_dir = Path(src_dir)
    if not src_dir.is_dir():
        raise DecisionPackError(f"Source directory not found: {src_dir}")

    core_docs: dict[str, Any] = {}
    inputs: list[MemberInput] = []
    case_id = ""
    for role in CORE_MEMBER_ROLES:
        data, canonical = _load_core_member(src_dir, role)
        core_docs[role] = data
        if role == "case":
            case_id = str(data["case_id"])
        elif str(data.get("case_id", "")) != case_id:
            raise DecisionPackError(
                f"Member '{CORE_MEMBER_ROLES[role]}' case_id does not match case.json"
            )
        inputs.append(
            MemberInput(
                path=CORE_MEMBER_ROLES[role],
                role=role,
                media_type="application/json",
                canonicalization=CANONICALIZATION_JCS,
                body=canonical,
            )
        )

    artifacts_root = src_dir / "artifacts"
    if artifacts_root.is_dir():
        for file_path in sorted(p for p in artifacts_root.rglob("*") if p.is_file()):
            rel = file_path.relative_to(src_dir).as_posix()
            body = file_path.read_bytes()
            if len(body) > MAX_ARTIFACT_BYTES:
                raise DecisionPackError(
                    f"Artifact '{rel}' exceeds maximum size ({len(body)} > {MAX_ARTIFACT_BYTES})"
                )
            inputs.append(
                MemberInput(
                    path=rel,
                    role="artifact",
                    media_type=artifact_media_type(rel),
                    canonicalization=CANONICALIZATION_RAW,
                    body=body,
                )
            )

    for member_input in inputs:
        _validate_member_path(member_input.path, member_input.role)
    return case_id, inputs


def build_pack(
    src_dir: str | Path,
    out_dir: str | Path,
    pack_id: str,
    created_at: str | None = None,
    creator_software: str | None = None,
    creator_version: str | None = None,
) -> PackManifest:
    """Build a complete decision evidence pack from a source directory."""
    case_id, member_inputs = collect_source_members(Path(src_dir))
    manifest = build_manifest(
        pack_id=pack_id,
        case_id=case_id,
        created_at=created_at or utc_now_iso(),
        member_inputs=member_inputs,
        creator_software=creator_software,
        creator_version=creator_version,
    )
    write_pack(Path(out_dir), manifest, {m.path: m.body for m in member_inputs})
    return manifest


def load_manifest(source: str | Path | dict[str, Any]) -> PackManifest:
    """Load and schema-validate a manifest from file path or dictionary."""
    if isinstance(source, (str, Path)):
        raw = Path(source).read_bytes()
        data = safe_json_loads(raw)
    elif isinstance(source, dict):
        data = source
    else:
        raise TypeError(f"Expected path or dict for manifest, got {type(source).__name__}")
    if not isinstance(data, dict):
        raise DecisionPackError("Manifest must be a JSON object")
    validate_document(data, MANIFEST_SCHEMA_NAME)
    return PackManifest.from_dict(data)


def verify_pack(
    pack_dir: str | Path,
    trust_store: TrustStore | None = None,
) -> PackVerificationResult:
    """Verify pack integrity via the independent offline verifier.

    Kept as the stable pre-0.2 API shape; the implementation is a thin adapter
    over :func:`oev.pack_verifier.verify_pack_offline`, which owns all
    verification logic and the honest three-way signature state.
    """
    outcome = verify_pack_offline(pack_dir, trust_store=trust_store)
    listed_paths = [m.path for m in outcome.member_results]
    reasons = [
        f"{c.check_id}: {c.note}"
        for c in outcome.checks
        if c.status in ("FAIL", "UNVERIFIED") and c.note
    ]
    return PackVerificationResult(
        pack_path=outcome.pack_path,
        overall=outcome.overall,
        manifest_schema_valid=outcome.check_status("manifest_schema") == "PASS",
        manifest_canonical=outcome.check_status("manifest_canonical") == "PASS",
        pack_digest_valid=outcome.pack_digest_valid,
        declared_pack_digest=outcome.declared_pack_digest,
        recomputed_pack_digest=outcome.recomputed_pack_digest,
        member_order_stable=listed_paths == sorted(listed_paths)
        and len(set(listed_paths)) == len(listed_paths),
        member_results=list(outcome.member_results),
        extra_files=list(outcome.extra_files),
        structure_errors=list(outcome.structure_errors),
        is_signed=outcome.signature_state != PackSignatureState.SIGNATURE_NOT_PRESENT.value,
        signature_crypto_valid=outcome.signature_crypto_valid,
        is_trusted_signer=outcome.is_trusted_signer,
        trusted_signer_key_id=outcome.trusted_signer_key_id,
        signer_note=outcome.signer_note,
        signature_state=outcome.signature_state,
        reasons=reasons,
    )


def sign_pack_manifest(
    pack_dir: str | Path,
    private_key_pem: bytes,
    key_id: str = "",
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Sign the canonical manifest bytes of a pack with DSSE v1 / Ed25519.

    The DSSE payload is the exact manifest.json bytes; the envelope is written
    as manifest.dsse.json (inside the pack directory by default). The envelope
    is not itself a pack member and is never covered by the manifest.

    The signer's public key is embedded in the signature entry as an
    unauthenticated hint (``public_key_pem``) so that any third party can
    verify the signature math offline without trust roots. Trust still always
    requires caller-supplied roots.
    """
    pack_dir = Path(pack_dir)
    manifest_bytes = (pack_dir / MANIFEST_MEMBER_PATH).read_bytes()
    parsed = safe_json_loads(manifest_bytes)
    if canonicalize_json(parsed) != manifest_bytes:
        raise DecisionPackError(
            "Refusing to sign: manifest.json is not canonical JCS encoding. Rebuild the pack first."
        )

    private_key = load_ed25519_private_key(private_key_pem)
    pae_bytes = compute_pae(MANIFEST_PAYLOAD_TYPE, manifest_bytes)
    raw_sig = private_key.sign(pae_bytes)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    sig_entry: dict[str, str] = {
        "sig": base64.b64encode(raw_sig).decode("ascii"),
        "public_key_pem": public_pem,
    }
    if key_id:
        sig_entry["keyid"] = key_id

    envelope: dict[str, Any] = {
        "payloadType": MANIFEST_PAYLOAD_TYPE,
        "payload": base64.b64encode(manifest_bytes).decode("ascii"),
        "signatures": [sig_entry],
    }

    target = Path(out_path) if out_path is not None else pack_dir / DSSE_ENVELOPE_MEMBER_PATH
    target.write_bytes(canonicalize_json(envelope))
    return envelope
