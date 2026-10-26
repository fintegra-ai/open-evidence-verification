# SPDX-License-Identifier: Apache-2.0

"""Offline verifier and portable verification receipt for Decision Evidence Packs.

INDEPENDENCE CONTRACT (mechanically tested in tests/test_independence.py):
This module is the self-contained offline verifier for decision evidence packs.
It imports ONLY protocol-core primitives: canonicalization, hashing, DSSE
parsing, Ed25519 signing primitives, caller-supplied trust stores, schema
validation, and the pack vocabularies/models. It MUST NOT import application
layers (``oev.engine``, ``oev.receipts``, ``oev.profiles``, ``oev.inspect``,
``oev.reverify``, ``oev.adapters``, ``oev.cli``) or the pack builder
(``oev.decision_pack``). The pack builder depends on this module, never the
reverse.

HONEST THREE-WAY SIGNATURE VOCABULARY (non-negotiable):

- ``SIGNATURE_NOT_PRESENT``: the pack directory contains no
  ``manifest.dsse.json`` envelope. An unsigned pack is never invalid because
  of that; its integrity stands on the manifest and member digests alone.
- ``SIGNATURE_VALID``: an envelope is present, its payload is bound to the
  exact stored manifest bytes, and at least one Ed25519 signature verifies
  over the DSSE PAE against key material available to this verification run
  (caller-supplied trust roots, or the unauthenticated embedded public-key
  hint that ``oev pack sign`` writes).
- ``SIGNATURE_INVALID``: an envelope is present but was NOT established as
  valid — malformed structure, wrong payload type, payload/manifest binding
  failure, signature verification failure, or no key material was available
  to verify it. This is a fail-closed verdict meaning "do not rely on this
  signature as verified"; the accompanying note states which case applies.
  It is never emitted for an unsigned pack, and it never upgrades or
  downgrades pack integrity by itself.

Whether the verifying key matches a caller-supplied trust root
(``is_trusted_signer``) is reported separately and is orthogonal to the
signature state: an embedded-key-verified signature is SIGNATURE_VALID even
when the signer is untrusted, and trust never rescues a broken envelope.
When an envelope is present but no key material exists at all, the
``manifest_signature`` check is recorded as ``UNVERIFIED`` (not ``FAIL``),
because verification could not even be attempted.

INTEGRITY BOUNDARY: verification asserts technical integrity only — members
present, byte-identical to their manifest digests, canonically encoded,
internally consistent, and (optionally) signature math correct. It never
asserts factual truth, commercial truth, legal validity, compliance approval,
or fraud detection, and it never re-executes recorded rules.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from oev import __version__
from oev.canonical import canonicalize_json, safe_json_loads
from oev.decision_models import (
    CORE_MEMBER_ROLES,
    DSSE_ENVELOPE_MEMBER_PATH,
    MANIFEST_MEMBER_PATH,
    MANIFEST_PAYLOAD_TYPE,
    MemberVerification,
    PackManifest,
    PackMember,
)
from oev.dsse import compute_pae, parse_dsse_envelope
from oev.hashing import sha256_bytes
from oev.schemas import validate_document
from oev.signing import load_ed25519_public_key
from oev.trust import TrustStore

PACK_RECEIPT_PROTOCOL_VERSION = "oev-pack-receipt/0.1"
PACK_RECEIPT_PAYLOAD_TYPE = "application/vnd.oev.pack-verification-receipt+json"
PACK_RECEIPT_SCHEMA_NAME = "pack-verification-receipt.schema.json"

MANIFEST_SCHEMA_NAME = "decision-pack-manifest.schema.json"

# Unauthenticated DSSE signature-entry extension written by `oev pack sign`
# and `sign_pack_receipt`: the signer's SPKI PEM, enabling pure crypto
# verification offline. Embedded keys NEVER bootstrap trust.
EMBEDDED_PUBLIC_KEY_HINT = "public_key_pem"

MAX_EMBEDDED_KEY_LENGTH = 4096


class PackSignatureState(str, Enum):
    """Honest three-way signature state; see module docstring for semantics."""

    SIGNATURE_NOT_PRESENT = "SIGNATURE_NOT_PRESENT"
    SIGNATURE_VALID = "SIGNATURE_VALID"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"


# Check-status tokens. Values mirror the oev-receipt/0.1 check vocabulary so
# the whole protocol shares one honest status language.
CHECK_PASS = "PASS"
CHECK_FAIL = "FAIL"
CHECK_NOT_RUN = "NOT_RUN"
CHECK_NOT_APPLICABLE = "NOT_APPLICABLE"
CHECK_UNVERIFIED = "UNVERIFIED"

CHECK_PACK_PRESENT = "pack_present"
CHECK_MANIFEST_SCHEMA = "manifest_schema"
CHECK_MANIFEST_CANONICAL = "manifest_canonical"
CHECK_PACK_DIGEST = "pack_digest"
CHECK_MEMBER_COVERAGE = "member_coverage"
CHECK_SNAPSHOT_MEMBERSHIP = "snapshot_membership"
CHECK_MEMBER_HASHES = "member_hashes"
CHECK_CROSS_REFERENCES = "cross_references"
CHECK_MANIFEST_SIGNATURE = "manifest_signature"

PACK_CHECK_IDS: tuple[str, ...] = (
    CHECK_PACK_PRESENT,
    CHECK_MANIFEST_SCHEMA,
    CHECK_MANIFEST_CANONICAL,
    CHECK_PACK_DIGEST,
    CHECK_MEMBER_COVERAGE,
    CHECK_SNAPSHOT_MEMBERSHIP,
    CHECK_MEMBER_HASHES,
    CHECK_CROSS_REFERENCES,
    CHECK_MANIFEST_SIGNATURE,
)

INTEGRITY_CHECK_IDS: tuple[str, ...] = (
    CHECK_PACK_PRESENT,
    CHECK_MANIFEST_SCHEMA,
    CHECK_MANIFEST_CANONICAL,
    CHECK_PACK_DIGEST,
    CHECK_MEMBER_COVERAGE,
    CHECK_SNAPSHOT_MEMBERSHIP,
    CHECK_MEMBER_HASHES,
    CHECK_CROSS_REFERENCES,
)

OVERALL_PACK_VALID = "PACK_VALID"
OVERALL_PACK_INVALID = "PACK_INVALID"

OVERALL_RECEIPT_VALID = "RECEIPT_VALID"
OVERALL_RECEIPT_INVALID = "RECEIPT_INVALID"

PACK_BINDING_MATCH = "PACK_BINDING_MATCH"
PACK_BINDING_MISMATCH = "PACK_BINDING_MISMATCH"
PACK_BINDING_NOT_RUN = "PACK_BINDING_NOT_RUN"


def utc_now_iso() -> str:
    """Return the current UTC time in the protocol's ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_manifest_self_digest(manifest: dict[str, Any]) -> str:
    """Manifest self-digest: sha256 over JCS of the body without 'pack_digest'.

    This is the pack digest recursion rule from spec/decision-pack-spec.md §5.
    """
    body = dict(manifest)
    body.pop("pack_digest", None)
    return sha256_bytes(canonicalize_json(body))


@dataclass(frozen=True)
class PackCheckResult:
    """Outcome of one named verification check."""

    check_id: str
    status: str
    note: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"check_id": self.check_id, "status": self.status, "note": self.note}


@dataclass(frozen=True)
class SignatureEvaluation:
    """Three-way outcome of evaluating an optional DSSE signature.

    ``verification_attempted`` is False only when the envelope was
    structurally bound but no key material existed to attempt crypto
    verification (the UNVERIFIED case). Structural and binding failures and
    failed crypto verification all count as attempted.

    ``structural_failure`` is True only when the envelope itself is broken
    (malformed, wrong payload type, payload not bound to the manifest
    bytes). Only structural failures drag the pack verdict to PACK_INVALID;
    failed or impossible crypto verification is a trust-level failure and
    never downgrades member integrity.
    """

    state: PackSignatureState
    crypto_valid: bool
    is_trusted: bool
    trusted_key_id: str | None
    note: str
    verification_attempted: bool = True
    structural_failure: bool = False


@dataclass(frozen=True)
class _KeyCandidate:
    """A public key available for signature verification this run."""

    key: Ed25519PublicKey
    origin: str  # "trusted" or "embedded"
    key_id: str | None


def _embedded_key_candidates(envelope: dict[str, Any], notes: list[str]) -> list[_KeyCandidate]:
    """Extract Ed25519 public keys embedded as unauthenticated hints.

    Embedded keys never bootstrap trust: they only allow the signature math
    to be checked offline. Malformed hints are recorded as notes and skipped.
    """
    candidates: list[_KeyCandidate] = []
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list):
        return candidates
    for idx, entry in enumerate(sigs):
        if not isinstance(entry, dict):
            continue
        pem = entry.get(EMBEDDED_PUBLIC_KEY_HINT)
        if not isinstance(pem, str) or not pem:
            continue
        if len(pem) > MAX_EMBEDDED_KEY_LENGTH:
            notes.append(f"embedded key hint #{idx} exceeds maximum length")
            continue
        try:
            candidates.append(
                _KeyCandidate(
                    key=load_ed25519_public_key(pem.encode("utf-8")), origin="embedded", key_id=None
                )
            )
        except ValueError:
            notes.append(f"embedded key hint #{idx} is not a valid Ed25519 public key")
    return candidates


def _verify_sigs_against_candidates(
    envelope: dict[str, Any],
    pae_bytes: bytes,
    candidates: list[_KeyCandidate],
    notes: list[str],
) -> tuple[str | None, bool]:
    """Try every signature entry against every key candidate.

    Returns (trusted_key_id_or_None, verified_embedded). A signature that
    verifies against a trusted key wins; an embedded-key verification is
    reported separately and never implies trust.
    """
    sigs = envelope.get("signatures") or []
    verified_trusted: str | None = None
    verified_embedded = False
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        sig_b64 = entry.get("sig")
        if not isinstance(sig_b64, str) or not sig_b64:
            continue
        try:
            raw_sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
        except (ValueError, UnicodeEncodeError):
            notes.append("a signature entry contains invalid Base64")
            continue
        for candidate in candidates:
            try:
                candidate.key.verify(raw_sig, pae_bytes)
            except (InvalidSignature, ValueError):
                # ValueError covers malformed signature lengths; InvalidSignature
                # covers a wrong signature. Any other exception is a bug and
                # must surface rather than be swallowed as "not verified".
                continue
            if candidate.origin == "trusted" and verified_trusted is None:
                verified_trusted = candidate.key_id
            elif candidate.origin == "embedded":
                verified_embedded = True
    return verified_trusted, verified_embedded


def _invalid_structural(note: str) -> SignatureEvaluation:
    """Envelope itself is broken; drags the pack verdict to PACK_INVALID."""
    return SignatureEvaluation(
        state=PackSignatureState.SIGNATURE_INVALID,
        crypto_valid=False,
        is_trusted=False,
        trusted_key_id=None,
        note=note,
        verification_attempted=True,
        structural_failure=True,
    )


def _invalid_verification(note: str) -> SignatureEvaluation:
    """Signature present but not established valid; trust-level failure only."""
    return SignatureEvaluation(
        state=PackSignatureState.SIGNATURE_INVALID,
        crypto_valid=False,
        is_trusted=False,
        trusted_key_id=None,
        note=note,
        verification_attempted=True,
        structural_failure=False,
    )


def _evaluate_signature_state(
    envelope: dict[str, Any],
    expected_payload: bytes | None,
    trust_store: TrustStore | None,
) -> SignatureEvaluation:
    """Determine the honest three-way signature state for one envelope.

    ``expected_payload`` is the exact bytes the envelope payload must equal
    (the stored manifest bytes for packs). For receipts there is no external
    binding target, so ``None`` skips that check.
    """
    try:
        payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    except ValueError as exc:
        return _invalid_structural(f"DSSE envelope malformed: {exc}")

    if expected_payload is not None:
        if payload_type != MANIFEST_PAYLOAD_TYPE:
            return _invalid_structural(f"Unexpected DSSE payloadType: {payload_type}")
        if payload_bytes != expected_payload:
            return _invalid_structural("DSSE payload does not match the stored manifest bytes")

    notes: list[str] = []
    candidates: list[_KeyCandidate] = []
    if trust_store is not None:
        for trusted in trust_store.keys:
            candidates.append(
                _KeyCandidate(
                    key=load_ed25519_public_key(trusted.public_key_pem),
                    origin="trusted",
                    key_id=trusted.key_id,
                )
            )
    candidates.extend(_embedded_key_candidates(envelope, notes))

    if not candidates:
        return SignatureEvaluation(
            state=PackSignatureState.SIGNATURE_INVALID,
            crypto_valid=False,
            is_trusted=False,
            trusted_key_id=None,
            note=(
                "signature present but no caller trust roots and no embedded "
                "public key hint were available; validity could not be established"
                + (f" ({'; '.join(notes)})" if notes else "")
            ),
            verification_attempted=False,
        )

    pae_bytes = compute_pae(payload_type, payload_bytes)
    verified_trusted, verified_embedded = _verify_sigs_against_candidates(
        envelope, pae_bytes, candidates, notes
    )
    suffix = f" ({'; '.join(notes)})" if notes else ""

    if verified_trusted is not None:
        return SignatureEvaluation(
            state=PackSignatureState.SIGNATURE_VALID,
            crypto_valid=True,
            is_trusted=True,
            trusted_key_id=verified_trusted,
            note=f"Signature verified against caller-supplied trusted key '{verified_trusted}'",
        )
    if verified_embedded:
        return SignatureEvaluation(
            state=PackSignatureState.SIGNATURE_VALID,
            crypto_valid=True,
            is_trusted=False,
            trusted_key_id=None,
            note="Signature verified against the embedded public key hint "
            "(signer NOT caller-trusted)" + suffix,
        )
    return _invalid_verification("No signature verified against any available key" + suffix)


@dataclass(frozen=True)
class PackVerificationOutcome:
    """Full outcome of an offline pack verification run.

    ``checks`` is the complete, ordered check vector: exactly which checks
    passed, failed, were not run, or were not applicable. ``overall`` is
    PACK_VALID only when every integrity check passed and the signature check
    did not fail; signature state and signer trust are reported separately.
    """

    pack_path: str
    pack_present: bool
    overall: str
    checks: list[PackCheckResult]
    signature_state: str
    signature_crypto_valid: bool
    is_trusted_signer: bool
    trusted_signer_key_id: str | None
    signer_note: str
    pack_id: str
    case_id: str
    declared_pack_digest: str
    recomputed_pack_digest: str
    pack_digest_valid: bool
    member_results: list[MemberVerification]
    extra_files: list[str]
    structure_errors: list[str]

    def check_status(self, check_id: str) -> str:
        for check in self.checks:
            if check.check_id == check_id:
                return check.status
        raise KeyError(f"Unknown check id: {check_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_path": self.pack_path,
            "pack_present": self.pack_present,
            "overall": self.overall,
            "checks": [c.to_dict() for c in self.checks],
            "signature_state": self.signature_state,
            "signature_crypto_valid": self.signature_crypto_valid,
            "is_trusted_signer": self.is_trusted_signer,
            "trusted_signer_key_id": self.trusted_signer_key_id,
            "signer_note": self.signer_note,
            "pack_id": self.pack_id,
            "case_id": self.case_id,
            "declared_pack_digest": self.declared_pack_digest,
            "recomputed_pack_digest": self.recomputed_pack_digest,
            "pack_digest_valid": self.pack_digest_valid,
            "member_results": [m.to_dict() for m in self.member_results],
            "extra_files": list(self.extra_files),
            "structure_errors": list(self.structure_errors),
        }

    def format_human(self) -> str:
        lines: list[str] = [
            "=" * 70,
            "OEVP DECISION EVIDENCE PACK VERIFICATION REPORT",
            "=" * 70,
            f"Pack Path:            {self.pack_path}",
            f"Overall:              {self.overall}",
            "-" * 70,
            "Checks:",
        ]
        for check in self.checks:
            note = f" — {check.note}" if check.note else ""
            lines.append(f"  [{check.status:<15}] {check.check_id}{note}")
        lines.append("-" * 70)
        lines.append(f"Members ({len(self.member_results)}):")
        for m in self.member_results:
            digest_note = (
                f" (actual {m.actual_digest})" if m.actual_digest and m.status != "MATCH" else ""
            )
            lines.append(f"  [{m.status:<17}] {m.path}{digest_note}")
        if self.extra_files:
            lines.extend(["-" * 70, f"Unlisted Files ({len(self.extra_files)}):"])
            for f in self.extra_files:
                lines.append(f"  * {f}")
        if self.structure_errors:
            lines.extend(["-" * 70, f"Structure Errors ({len(self.structure_errors)}):"])
            for e in self.structure_errors:
                lines.append(f"  * {e}")
        lines.append("-" * 70)
        lines.append(f"Pack Digest:          {self.declared_pack_digest or '(unavailable)'}")
        lines.append(f"Signature State:      {self.signature_state}")
        if self.signature_state == PackSignatureState.SIGNATURE_NOT_PRESENT.value:
            lines.append("                      (unsigned pack — integrity does not require one)")
        else:
            lines.append(
                f"Signature Crypto:     "
                f"{'VALID' if self.signature_crypto_valid else 'NOT ESTABLISHED VALID'}"
            )
            lines.append(
                f"Signer Trusted:       {'YES' if self.is_trusted_signer else 'NO'}"
                + (
                    f" (key: {self.trusted_signer_key_id})"
                    if self.is_trusted_signer and self.trusted_signer_key_id
                    else ""
                )
            )
            if self.signer_note:
                lines.append(f"Signature Note:       {self.signer_note}")
        lines.extend(
            [
                "=" * 70,
                "NOTICE:",
                "Technical integrity verification only — not a legal, compliance, factual,",
                "or commercial conclusion. Pack validity does not re-execute rules and",
                "does not assert that any recorded decision was correct.",
                "=" * 70,
            ]
        )
        return "\n".join(lines)


def _verify_member(
    pack_dir: Path,
    member: PackMember,
) -> tuple[MemberVerification, dict[str, Any] | None]:
    """Verify one manifest member. Returns (result, parsed_json_or_None)."""
    file_path = pack_dir / member.path
    if not file_path.is_file():
        return (
            MemberVerification(
                path=member.path,
                status="MISSING",
                expected_digest=member.sha256,
                expected_size_bytes=member.size_bytes,
            ),
            None,
        )
    stored = file_path.read_bytes()

    if member.canonicalization == "raw":
        actual_digest = sha256_bytes(stored)
        status = "MATCH" if actual_digest == member.sha256 else "DIGEST_MISMATCH"
        return (
            MemberVerification(
                path=member.path,
                status=status,
                expected_digest=member.sha256,
                actual_digest=actual_digest,
                expected_size_bytes=member.size_bytes,
                actual_size_bytes=len(stored),
            ),
            None,
        )

    if member.canonicalization != "jcs-rfc8785":
        return (
            MemberVerification(
                path=member.path,
                status="UNREADABLE",
                expected_digest=member.sha256,
                expected_size_bytes=member.size_bytes,
                actual_size_bytes=len(stored),
            ),
            None,
        )

    try:
        parsed = safe_json_loads(stored)
    except ValueError:
        return (
            MemberVerification(
                path=member.path,
                status="UNREADABLE",
                expected_digest=member.sha256,
                expected_size_bytes=member.size_bytes,
                actual_size_bytes=len(stored),
            ),
            None,
        )

    canonical = canonicalize_json(parsed)
    actual_digest = sha256_bytes(canonical)
    if canonical != stored:
        status = "NOT_CANONICAL"
    elif actual_digest != member.sha256:
        status = "DIGEST_MISMATCH"
    else:
        status = "MATCH"
    return (
        MemberVerification(
            path=member.path,
            status=status,
            expected_digest=member.sha256,
            actual_digest=actual_digest,
            expected_size_bytes=member.size_bytes,
            actual_size_bytes=len(stored),
        ),
        parsed,
    )


def _timeline_ref_error(
    kind: str,
    ref_id: str,
    event_id: Any,
    fact_ids: set[str],
    run_ids: set[str],
    finding_ids: set[str],
    action_ids: set[str],
    snapshot_sources: set[str],
    member_paths: set[str],
) -> str:
    """Return an error message if a timeline reference does not resolve, else ''."""
    if kind == "artifact":
        if ref_id not in member_paths:
            return f"timeline event '{event_id}' references unknown artifact path '{ref_id}'"
    elif kind == "snapshot_source":
        if ref_id not in snapshot_sources:
            return f"timeline event '{event_id}' references unknown snapshot_source_id '{ref_id}'"
    elif kind == "fact":
        if ref_id not in fact_ids:
            return f"timeline event '{event_id}' references unknown fact id '{ref_id}'"
    elif kind == "rule_run":
        if ref_id not in run_ids:
            return f"timeline event '{event_id}' references unknown rule_run id '{ref_id}'"
    elif kind == "finding":
        if ref_id not in finding_ids:
            return f"timeline event '{event_id}' references unknown finding id '{ref_id}'"
    elif kind == "review_action" and ref_id not in action_ids:
        return f"timeline event '{event_id}' references unknown review_action id '{ref_id}'"
    return ""


def check_cross_references(docs: dict[str, dict[str, Any]], member_paths: set[str]) -> list[str]:
    """Validate internal referential integrity across pack members (technical only)."""
    errors: list[str] = []

    fact_rows = docs["facts"].get("facts", [])
    fact_ids = {str(f.get("fact_id")) for f in fact_rows}
    if len(fact_ids) != len(fact_rows):
        errors.append("facts.json contains duplicate fact_id values")

    run_rows = docs["rule_runs"].get("rule_runs", [])
    run_ids = {str(r.get("run_id")) for r in run_rows}
    if len(run_ids) != len(run_rows):
        errors.append("rule_runs.json contains duplicate run_id values")
    for run in run_rows:
        for fact_id in run.get("inputs", []):
            if fact_id not in fact_ids:
                errors.append(
                    f"rule run '{run.get('run_id')}' references unknown fact_id '{fact_id}'"
                )

    finding_rows = docs["findings"].get("findings", [])
    finding_ids = {str(f.get("finding_id")) for f in finding_rows}
    if len(finding_ids) != len(finding_rows):
        errors.append("findings.json contains duplicate finding_id values")
    for finding in finding_rows:
        if finding.get("rule_run_id") not in run_ids:
            errors.append(
                f"finding '{finding.get('finding_id')}' references unknown "
                f"rule_run_id '{finding.get('rule_run_id')}'"
            )
        for fact_id in finding.get("related_fact_ids", []):
            if fact_id not in fact_ids:
                errors.append(
                    f"finding '{finding.get('finding_id')}' references unknown fact_id '{fact_id}'"
                )

    action_rows = docs["review_actions"].get("review_actions", [])
    action_ids = {str(a.get("action_id")) for a in action_rows}
    if len(action_ids) != len(action_rows):
        errors.append("review_actions.json contains duplicate action_id values")
    for action in action_rows:
        for fid in action.get("references_finding_ids", []):
            if fid not in finding_ids:
                errors.append(
                    f"review action '{action.get('action_id')}' references unknown "
                    f"finding_id '{fid}'"
                )
        for rid in action.get("references_rule_run_ids", []):
            if rid not in run_ids:
                errors.append(
                    f"review action '{action.get('action_id')}' references unknown "
                    f"rule_run_id '{rid}'"
                )

    snapshot_sources = {
        str(s.get("source_id")) for s in docs["snapshot_context"].get("sources", [])
    }
    if len(snapshot_sources) != len(docs["snapshot_context"].get("sources", [])):
        errors.append("snapshot_context.json contains duplicate source_id values")
    for fact in fact_rows:
        sid = fact.get("snapshot_source_id")
        if sid is not None and sid not in snapshot_sources:
            errors.append(
                f"fact '{fact.get('fact_id')}' references unknown snapshot_source_id '{sid}'"
            )

    events = docs["timeline"].get("events", [])
    event_ids = {str(e.get("event_id")) for e in events}
    if len(event_ids) != len(events):
        errors.append("timeline.json contains duplicate event_id values")
    last_sequence = 0
    for event in events:
        seq = int(event.get("sequence", 0))
        if seq <= last_sequence:
            errors.append(
                f"timeline event '{event.get('event_id')}' sequence {seq} is not strictly "
                f"greater than the previous sequence {last_sequence}"
            )
        last_sequence = seq
        for ref in event.get("references", []):
            kind = str(ref.get("kind", ""))
            ref_id = str(ref.get("id", ""))
            ref_error = _timeline_ref_error(
                kind,
                ref_id,
                event.get("event_id", ""),
                fact_ids,
                run_ids,
                finding_ids,
                action_ids,
                snapshot_sources,
                member_paths,
            )
            if ref_error:
                errors.append(ref_error)

    return errors


def _validate_member_path(path: str, role: str) -> str | None:
    """Structural path rules for manifest members; error message or None."""
    if path in (MANIFEST_MEMBER_PATH, DSSE_ENVELOPE_MEMBER_PATH):
        return f"'{path}' must never be listed as a pack member"
    if path.startswith("/") or "\\" in path or ".." in path.split("/"):
        return f"Unsafe member path: {path!r}"
    if path.endswith("/"):
        return f"Member path must not end with '/': {path!r}"
    if role == "artifact":
        if not path.startswith("artifacts/"):
            return f"Artifact members must live under 'artifacts/': {path}"
    else:
        expected = CORE_MEMBER_ROLES.get(role)
        if expected is None:
            return f"Unknown member role: {role!r}"
        if path != expected:
            return f"Role '{role}' must use path '{expected}', got '{path}'"
    return None


def verify_pack_offline(
    pack_dir: str | Path,
    trust_store: TrustStore | None = None,
) -> PackVerificationOutcome:
    """Verify a decision evidence pack completely offline.

    Independent check vector, in fixed order: pack presence, manifest schema,
    canonical manifest encoding, pack digest, member coverage, snapshot
    membership (on-disk files exactly match manifest membership), member
    hashes, cross-member references, and the honest three-way signature state.

    ``trust_store`` is optional caller-supplied key material used only to
    verify the manifest signature; it never influences integrity checks.
    """
    pack_dir = Path(pack_dir)
    pack_path_str = str(pack_dir)

    checks: dict[str, PackCheckResult] = {}

    def record(check_id: str, status: str, note: str = "") -> None:
        checks[check_id] = PackCheckResult(check_id=check_id, status=status, note=note)

    def mark_remaining_not_run(note: str) -> None:
        for cid in PACK_CHECK_IDS:
            if cid not in checks:
                record(cid, CHECK_NOT_RUN, note)

    member_results: list[MemberVerification] = []
    extra_files: list[str] = []
    structure_errors: list[str] = []
    pack_id = ""
    case_id = ""
    declared_pack_digest = ""
    recomputed_pack_digest = ""

    manifest_file = pack_dir / MANIFEST_MEMBER_PATH
    envelope_file = pack_dir / DSSE_ENVELOPE_MEMBER_PATH

    if not manifest_file.is_file():
        record(CHECK_PACK_PRESENT, CHECK_FAIL, f"Missing {MANIFEST_MEMBER_PATH}")
        if envelope_file.is_file():
            signature = SignatureEvaluation(
                state=PackSignatureState.SIGNATURE_INVALID,
                crypto_valid=False,
                is_trusted=False,
                trusted_key_id=None,
                note="envelope present but manifest.json is missing; payload binding impossible",
                verification_attempted=False,
                structural_failure=True,
            )
        else:
            signature = SignatureEvaluation(
                state=PackSignatureState.SIGNATURE_NOT_PRESENT,
                crypto_valid=False,
                is_trusted=False,
                trusted_key_id=None,
                note="unsigned pack — no manifest.dsse.json present",
            )
        mark_remaining_not_run("manifest not present")
        record(
            CHECK_MANIFEST_SIGNATURE,
            _signature_check_status(signature),
            signature.note,
        )
        return _finish_outcome(
            pack_path_str,
            checks,
            member_results,
            extra_files,
            structure_errors,
            pack_id,
            case_id,
            declared_pack_digest,
            recomputed_pack_digest,
            signature,
        )

    try:
        manifest_data = safe_json_loads(manifest_file.read_bytes())
    except ValueError as exc:
        record(CHECK_PACK_PRESENT, CHECK_FAIL, f"manifest.json is not valid JSON: {exc}")
        mark_remaining_not_run("manifest unreadable")
        signature = SignatureEvaluation(
            state=PackSignatureState.SIGNATURE_NOT_PRESENT
            if not envelope_file.is_file()
            else PackSignatureState.SIGNATURE_INVALID,
            crypto_valid=False,
            is_trusted=False,
            trusted_key_id=None,
            note="manifest unreadable; signature payload cannot be bound",
            verification_attempted=not envelope_file.is_file(),
            structural_failure=envelope_file.is_file(),
        )
        record(CHECK_MANIFEST_SIGNATURE, _signature_check_status(signature), signature.note)
        return _finish_outcome(
            pack_path_str,
            checks,
            member_results,
            extra_files,
            structure_errors,
            pack_id,
            case_id,
            declared_pack_digest,
            recomputed_pack_digest,
            signature,
        )

    record(CHECK_PACK_PRESENT, CHECK_PASS)

    manifest: PackManifest | None = None
    try:
        validate_document(manifest_data, MANIFEST_SCHEMA_NAME)
        record(CHECK_MANIFEST_SCHEMA, CHECK_PASS)
    except ValueError as exc:
        record(CHECK_MANIFEST_SCHEMA, CHECK_FAIL, str(exc))

    try:
        manifest = PackManifest.from_dict(manifest_data)
        pack_id = manifest.pack_id
        case_id = manifest.case_id
    except (KeyError, TypeError, ValueError) as exc:
        record(CHECK_MANIFEST_SCHEMA, CHECK_FAIL, f"Manifest could not be loaded: {exc}")

    manifest_bytes = manifest_file.read_bytes()
    manifest_canonical = canonicalize_json(manifest_data) == manifest_bytes
    record(
        CHECK_MANIFEST_CANONICAL,
        CHECK_PASS if manifest_canonical else CHECK_FAIL,
        "" if manifest_canonical else "Manifest bytes are not canonical JCS encoding",
    )

    core_docs: dict[str, dict[str, Any]] = {}

    if manifest is not None:
        declared_pack_digest = manifest.pack_digest
        recomputed_pack_digest = compute_manifest_self_digest(manifest_data)
        digest_valid = declared_pack_digest == recomputed_pack_digest
        record(
            CHECK_PACK_DIGEST,
            CHECK_PASS if digest_valid else CHECK_FAIL,
            ""
            if digest_valid
            else f"declared {declared_pack_digest}, recomputed {recomputed_pack_digest}",
        )

        listed_paths = [m.path for m in manifest.members]
        order_stable = listed_paths == sorted(listed_paths) and len(set(listed_paths)) == len(
            listed_paths
        )
        coverage_notes: list[str] = []
        if not order_stable:
            coverage_notes.append("members are not in stable sorted path order (or duplicated)")
        for role, expected_path in CORE_MEMBER_ROLES.items():
            matching = [m for m in manifest.members if m.path == expected_path]
            if not matching:
                coverage_notes.append(
                    f"missing required core member '{expected_path}' (role '{role}')"
                )
            elif matching[0].role != role:
                coverage_notes.append(
                    f"core member '{expected_path}' has role '{matching[0].role}', expected '{role}'"
                )
        for member in manifest.members:
            path_error = _validate_member_path(member.path, member.role)
            if path_error:
                coverage_notes.append(path_error)
        record(
            CHECK_MEMBER_COVERAGE,
            CHECK_PASS if not coverage_notes else CHECK_FAIL,
            "; ".join(coverage_notes),
        )

        for member in manifest.members:
            result, parsed = _verify_member(pack_dir, member)
            member_results.append(result)
            if parsed is not None and member.path in CORE_MEMBER_ROLES.values():
                role_name = next(r for r, p in CORE_MEMBER_ROLES.items() if p == member.path)
                core_docs[role_name] = parsed
                if parsed.get("case_id") != manifest.case_id:
                    structure_errors.append(
                        f"Member '{member.path}' case_id does not match manifest case_id"
                    )

        hash_notes = [f"{m.path}: {m.status}" for m in member_results if m.status != "MATCH"]
        record(
            CHECK_MEMBER_HASHES,
            CHECK_PASS if not hash_notes else CHECK_FAIL,
            "; ".join(hash_notes[:8]),
        )

        if set(core_docs) == set(CORE_MEMBER_ROLES):
            ref_errors = check_cross_references(core_docs, set(listed_paths))
            structure_errors.extend(ref_errors)
            record(
                CHECK_CROSS_REFERENCES,
                CHECK_PASS if not ref_errors else CHECK_FAIL,
                "; ".join(ref_errors[:5]),
            )
        else:
            record(
                CHECK_CROSS_REFERENCES,
                CHECK_NOT_RUN,
                "one or more core members were missing or unreadable",
            )
    else:
        for cid in (
            CHECK_PACK_DIGEST,
            CHECK_MEMBER_COVERAGE,
            CHECK_MEMBER_HASHES,
            CHECK_CROSS_REFERENCES,
        ):
            record(cid, CHECK_NOT_RUN, "manifest could not be loaded")

    allowed = {MANIFEST_MEMBER_PATH, DSSE_ENVELOPE_MEMBER_PATH}
    if manifest is not None:
        allowed |= {m.path for m in manifest.members}
    for file_path in sorted(pack_dir.rglob("*")):
        if file_path.is_dir():
            continue
        rel = file_path.relative_to(pack_dir).as_posix()
        if rel not in allowed:
            extra_files.append(rel)

    if manifest is None:
        record(CHECK_SNAPSHOT_MEMBERSHIP, CHECK_NOT_RUN, "manifest could not be loaded")
    elif extra_files:
        record(
            CHECK_SNAPSHOT_MEMBERSHIP,
            CHECK_FAIL,
            f"pack contains {len(extra_files)} unlisted file(s): {', '.join(extra_files[:5])}",
        )
    else:
        missing_on_disk = [m.path for m in manifest.members if not (pack_dir / m.path).is_file()]
        if missing_on_disk:
            record(
                CHECK_SNAPSHOT_MEMBERSHIP,
                CHECK_FAIL,
                f"declared members absent from disk: {', '.join(missing_on_disk[:5])}",
            )
        else:
            record(CHECK_SNAPSHOT_MEMBERSHIP, CHECK_PASS)

    if not envelope_file.is_file():
        signature = SignatureEvaluation(
            state=PackSignatureState.SIGNATURE_NOT_PRESENT,
            crypto_valid=False,
            is_trusted=False,
            trusted_key_id=None,
            note="unsigned pack — no manifest.dsse.json present",
            verification_attempted=False,
        )
    else:
        try:
            envelope = safe_json_loads(envelope_file.read_bytes())
        except ValueError as exc:
            signature = _invalid_structural(f"manifest.dsse.json is not a valid JSON object: {exc}")
        else:
            if not isinstance(envelope, dict):
                signature = _invalid_structural("manifest.dsse.json is not a valid JSON object")
            else:
                signature = _evaluate_signature_state(envelope, manifest_bytes, trust_store)

    record(CHECK_MANIFEST_SIGNATURE, _signature_check_status(signature), signature.note)

    return _finish_outcome(
        pack_path_str,
        checks,
        member_results,
        extra_files,
        structure_errors,
        pack_id,
        case_id,
        declared_pack_digest,
        recomputed_pack_digest,
        signature,
    )


def _signature_check_status(signature: SignatureEvaluation) -> str:
    """Map the three-way signature state onto the check vocabulary.

    NOT_PRESENT → NOT_APPLICABLE (never fails an unsigned pack);
    VALID → PASS; INVALID → FAIL if verification was attempted and failed,
    UNVERIFIED if no key material existed to attempt it.
    """
    if signature.state == PackSignatureState.SIGNATURE_NOT_PRESENT:
        return CHECK_NOT_APPLICABLE
    if signature.state == PackSignatureState.SIGNATURE_VALID:
        return CHECK_PASS
    return CHECK_UNVERIFIED if not signature.verification_attempted else CHECK_FAIL


def _finish_outcome(
    pack_path: str,
    checks: dict[str, PackCheckResult],
    member_results: list[MemberVerification],
    extra_files: list[str],
    structure_errors: list[str],
    pack_id: str,
    case_id: str,
    declared_pack_digest: str,
    recomputed_pack_digest: str,
    signature: SignatureEvaluation,
) -> PackVerificationOutcome:
    ordered_checks = [checks[cid] for cid in PACK_CHECK_IDS]
    integrity_all_pass = all(checks[cid].status == CHECK_PASS for cid in INTEGRITY_CHECK_IDS)
    # A structurally broken signature envelope (or unbound payload) invalidates
    # the pack. A signature that merely fails crypto verification — or cannot
    # be verified for lack of keys — never downgrades member integrity; it is
    # reported via signature_state and the exit code instead.
    signature_structural_failure = (
        checks[CHECK_MANIFEST_SIGNATURE].status == CHECK_FAIL and signature.structural_failure
    )
    overall = (
        OVERALL_PACK_VALID
        if integrity_all_pass and not signature_structural_failure
        else OVERALL_PACK_INVALID
    )
    return PackVerificationOutcome(
        pack_path=pack_path,
        pack_present=checks[CHECK_PACK_PRESENT].status == CHECK_PASS,
        overall=overall,
        checks=ordered_checks,
        signature_state=signature.state.value,
        signature_crypto_valid=signature.crypto_valid,
        is_trusted_signer=signature.is_trusted,
        trusted_signer_key_id=signature.trusted_key_id,
        signer_note=signature.note,
        pack_id=pack_id,
        case_id=case_id,
        declared_pack_digest=declared_pack_digest,
        recomputed_pack_digest=recomputed_pack_digest,
        pack_digest_valid=bool(declared_pack_digest)
        and declared_pack_digest == recomputed_pack_digest,
        member_results=member_results,
        extra_files=extra_files,
        structure_errors=structure_errors,
    )


# ---------------------------------------------------------------------------
# Portable pack verification receipt
# ---------------------------------------------------------------------------


def build_pack_verification_receipt(
    outcome: PackVerificationOutcome,
    *,
    receipt_id: str | None = None,
    verified_at: str | None = None,
    verifier_version: str | None = None,
) -> dict[str, Any]:
    """Build the portable, self-digested pack verification receipt.

    The receipt records exactly which checks passed, failed, or were not run,
    plus the pack hash, the verifier identity/version, and the verification
    time. Its self-digest uses the same recursion rule as the pack manifest:
    sha256 over JCS of the body without 'receipt_digest'.
    """
    receipt: dict[str, Any] = {
        "protocol_version": PACK_RECEIPT_PROTOCOL_VERSION,
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "pack_id": outcome.pack_id,
        "case_id": outcome.case_id,
        "pack_digest": outcome.declared_pack_digest,
        "recomputed_pack_digest": outcome.recomputed_pack_digest,
        "pack_digest_valid": outcome.pack_digest_valid,
        "overall": outcome.overall,
        "signature_state": outcome.signature_state,
        "verified_at": verified_at or utc_now_iso(),
        "verifier": {"software": "oev", "version": verifier_version or __version__},
        "checks": [c.to_dict() for c in outcome.checks],
        "member_results": [m.to_dict() for m in outcome.member_results],
        "extra_files": list(outcome.extra_files),
        "structure_errors": list(outcome.structure_errors),
    }
    receipt["receipt_digest"] = sha256_bytes(canonicalize_json(receipt))
    validate_document(receipt, PACK_RECEIPT_SCHEMA_NAME)
    return receipt


def sign_pack_receipt(
    receipt: dict[str, Any],
    private_key_pem: bytes,
    key_id: str = "",
) -> dict[str, Any]:
    """Wrap a pack verification receipt in a DSSE v1 envelope (Ed25519).

    The payload is the exact canonical receipt bytes; the signer's public key
    is embedded as an unauthenticated hint so third parties can verify the
    signature math offline without trust roots. Trust always requires
    caller-supplied roots.
    """
    from oev.signing import load_ed25519_private_key

    payload_bytes = canonicalize_json(receipt)
    private_key = load_ed25519_private_key(private_key_pem)
    pae_bytes = compute_pae(PACK_RECEIPT_PAYLOAD_TYPE, payload_bytes)
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
        EMBEDDED_PUBLIC_KEY_HINT: public_pem,
    }
    if key_id:
        sig_entry["keyid"] = key_id
    return {
        "payloadType": PACK_RECEIPT_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [sig_entry],
    }


@dataclass(frozen=True)
class PackReceiptVerification:
    """Third-party offline verification of a pack verification receipt."""

    receipt_source: str
    is_dsse: bool
    schema_valid: bool
    declared_receipt_digest: str
    receipt_digest_valid: bool
    overall: str
    receipt: dict[str, Any] = field(default_factory=dict)
    signature_state: str = PackSignatureState.SIGNATURE_NOT_PRESENT.value
    signature_crypto_valid: bool = False
    is_trusted_signer: bool = False
    trusted_signer_key_id: str | None = None
    signer_note: str = ""
    pack_binding: str = ""
    pack_binding_note: str = ""
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_source": self.receipt_source,
            "is_dsse": self.is_dsse,
            "schema_valid": self.schema_valid,
            "declared_receipt_digest": self.declared_receipt_digest,
            "receipt_digest_valid": self.receipt_digest_valid,
            "overall": self.overall,
            "receipt": dict(self.receipt),
            "signature_state": self.signature_state,
            "signature_crypto_valid": self.signature_crypto_valid,
            "is_trusted_signer": self.is_trusted_signer,
            "trusted_signer_key_id": self.trusted_signer_key_id,
            "signer_note": self.signer_note,
            "pack_binding": self.pack_binding,
            "pack_binding_note": self.pack_binding_note,
            "reasons": list(self.reasons),
        }

    def format_human(self) -> str:
        lines: list[str] = [
            "=" * 70,
            "OEVP PACK VERIFICATION RECEIPT INSPECTION",
            "=" * 70,
            f"Receipt Source:       {self.receipt_source}",
            f"Overall:              {self.overall}",
            f"DSSE Envelope:        {'YES' if self.is_dsse else 'NO'}",
            (
                f"Receipt Self-Digest:  {self.declared_receipt_digest or '(none)'} "
                f"({'VALID' if self.receipt_digest_valid else 'INVALID'})"
            ),
            f"Signature State:      {self.signature_state}",
        ]
        if self.is_dsse:
            lines.append(
                f"Signature Crypto:     "
                f"{'VALID' if self.signature_crypto_valid else 'NOT ESTABLISHED VALID'}"
            )
            lines.append(f"Signer Trusted:       {'YES' if self.is_trusted_signer else 'NO'}")
            if self.signer_note:
                lines.append(f"Signature Note:       {self.signer_note}")
        if self.pack_binding:
            lines.append(f"Pack Binding:         {self.pack_binding}")
            if self.pack_binding_note:
                lines.append(f"Binding Note:         {self.pack_binding_note}")
        recorded_checks = self.receipt.get("checks", [])
        if recorded_checks:
            lines.append("-" * 70)
            lines.append(f"Recorded Checks ({len(recorded_checks)}):")
            for check in recorded_checks:
                note = f" — {check.get('note', '')}" if check.get("note") else ""
                lines.append(f"  [{check.get('status', ''):<15}] {check.get('check_id', '')}{note}")
        if self.reasons:
            lines.extend(["-" * 70, "Notes:"])
            for r in self.reasons:
                lines.append(f"  * {r}")
        lines.extend(
            [
                "=" * 70,
                "NOTICE:",
                "A receipt is a claim about what a verifier recorded — technical",
                "integrity only, never a factual, legal, or compliance conclusion.",
                "=" * 70,
            ]
        )
        return "\n".join(lines)


def verify_pack_receipt(
    source: str | Path | dict[str, Any],
    trust_store: TrustStore | None = None,
    pack_dir: str | Path | None = None,
) -> PackReceiptVerification:
    """Verify a pack verification receipt offline, as a third party would.

    Checks: schema validity, receipt self-digest, the receipt's own DSSE
    signature state (honest three-way), and — when ``pack_dir`` is supplied —
    that the receipt's recorded pack digest matches the manifest actually on
    disk (detects a receipt presented for different pack bytes).
    """
    if isinstance(source, (str, Path)):
        raw_bytes = Path(source).read_bytes()
        source_str = str(source)
        data = safe_json_loads(raw_bytes)
    elif isinstance(source, dict):
        source_str = "<inline receipt>"
        data = source
    else:
        raise TypeError(f"Expected path or dict for receipt, got {type(source).__name__}")

    if not isinstance(data, dict):
        return PackReceiptVerification(
            receipt_source=source_str,
            is_dsse=False,
            schema_valid=False,
            declared_receipt_digest="",
            receipt_digest_valid=False,
            overall=OVERALL_RECEIPT_INVALID,
            reasons=["Receipt is not a JSON object"],
        )

    is_dsse = "payload" in data and "signatures" in data and "payloadType" in data
    reasons: list[str] = []
    signature: SignatureEvaluation

    if is_dsse:
        try:
            payload_type, payload_bytes, _sigs = parse_dsse_envelope(data)
        except ValueError as exc:
            reasons.append(f"DSSE envelope malformed: {exc}")
            return PackReceiptVerification(
                receipt_source=source_str,
                is_dsse=True,
                schema_valid=False,
                declared_receipt_digest="",
                receipt_digest_valid=False,
                overall=OVERALL_RECEIPT_INVALID,
                reasons=reasons,
            )
        if payload_type != PACK_RECEIPT_PAYLOAD_TYPE:
            reasons.append(f"Unexpected DSSE payloadType: {payload_type}")
            return PackReceiptVerification(
                receipt_source=source_str,
                is_dsse=True,
                schema_valid=False,
                declared_receipt_digest="",
                receipt_digest_valid=False,
                overall=OVERALL_RECEIPT_INVALID,
                reasons=reasons,
            )
        try:
            candidate = safe_json_loads(payload_bytes)
        except ValueError as exc:
            reasons.append(f"DSSE payload is not valid JSON: {exc}")
            return PackReceiptVerification(
                receipt_source=source_str,
                is_dsse=True,
                schema_valid=False,
                declared_receipt_digest="",
                receipt_digest_valid=False,
                overall=OVERALL_RECEIPT_INVALID,
                reasons=reasons,
            )
        if not isinstance(candidate, dict):
            reasons.append("DSSE payload is not a JSON object")
            return PackReceiptVerification(
                receipt_source=source_str,
                is_dsse=True,
                schema_valid=False,
                declared_receipt_digest="",
                receipt_digest_valid=False,
                overall=OVERALL_RECEIPT_INVALID,
                reasons=reasons,
            )
        receipt_dict: dict[str, Any] = candidate
        signature = _evaluate_signature_state(data, None, trust_store)
    else:
        receipt_dict = data
        signature = SignatureEvaluation(
            state=PackSignatureState.SIGNATURE_NOT_PRESENT,
            crypto_valid=False,
            is_trusted=False,
            trusted_key_id=None,
            note="receipt is an unsigned JSON document",
            verification_attempted=False,
        )

    schema_valid = True
    try:
        validate_document(receipt_dict, PACK_RECEIPT_SCHEMA_NAME)
    except ValueError as exc:
        schema_valid = False
        reasons.append(f"Receipt schema validation failed: {exc}")

    declared_digest = str(receipt_dict.get("receipt_digest", ""))
    body = dict(receipt_dict)
    body.pop("receipt_digest", None)
    recomputed = sha256_bytes(canonicalize_json(body))
    digest_valid = bool(declared_digest) and declared_digest == recomputed
    if not digest_valid:
        reasons.append("Receipt self-digest does not match its contents")

    pack_binding = PACK_BINDING_NOT_RUN
    pack_binding_note = ""
    if pack_dir is not None:
        pack_path = Path(pack_dir)
        manifest_file = pack_path / MANIFEST_MEMBER_PATH
        if not manifest_file.is_file():
            pack_binding_note = "pack directory has no manifest.json; binding not checked"
        else:
            try:
                pack_manifest = safe_json_loads(manifest_file.read_bytes())
            except ValueError as exc:
                pack_binding_note = f"pack manifest unreadable: {exc}"
            else:
                if not isinstance(pack_manifest, dict):
                    pack_binding_note = "pack manifest unreadable: not a JSON object"
                else:
                    fresh_digest = compute_manifest_self_digest(pack_manifest)
                    recorded = str(receipt_dict.get("recomputed_pack_digest", ""))
                    if not recorded:
                        pack_binding_note = "receipt records no recomputed pack digest"
                    elif recorded == fresh_digest:
                        pack_binding = PACK_BINDING_MATCH
                    else:
                        pack_binding = PACK_BINDING_MISMATCH
                        pack_binding_note = (
                            f"receipt digest {recorded} does not match pack manifest {fresh_digest}"
                        )

    overall = (
        OVERALL_RECEIPT_VALID
        if schema_valid and digest_valid and pack_binding != PACK_BINDING_MISMATCH
        else OVERALL_RECEIPT_INVALID
    )
    if pack_binding == PACK_BINDING_MISMATCH:
        reasons.append("Receipt is bound to different pack bytes than the supplied pack")

    return PackReceiptVerification(
        receipt_source=source_str,
        is_dsse=is_dsse,
        schema_valid=schema_valid,
        declared_receipt_digest=declared_digest,
        receipt_digest_valid=digest_valid,
        overall=overall,
        receipt=receipt_dict,
        signature_state=signature.state.value,
        signature_crypto_valid=signature.crypto_valid,
        is_trusted_signer=signature.is_trusted,
        trusted_signer_key_id=signature.trusted_key_id,
        signer_note=signature.note,
        pack_binding=pack_binding,
        pack_binding_note=pack_binding_note,
        reasons=reasons,
    )
