# SPDX-License-Identifier: Apache-2.0

"""Data models and vocabularies for the OEVP Decision Evidence Pack (oev-decision-pack/0.2).

A Decision Evidence Pack records the evidence trail of a decision process in a
domain-neutral way: recorded facts, versioned rule runs (rules-as-data), findings,
review actions, a timeline, and the snapshot context the decision was made against.

INTEGRITY BOUNDARY (non-negotiable):
A decision pack proves technical integrity only — that its members are present,
byte-identical to their manifest digests, canonically encoded, and internally
consistent. It does NOT assert factual truth, commercial truth, legal validity,
compliance approval, or fraud detection, and it does NOT re-execute rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

DECISION_PACK_PROTOCOL_VERSION = "oev-decision-pack/0.2"

MANIFEST_MEMBER_PATH = "manifest.json"
DSSE_ENVELOPE_MEMBER_PATH = "manifest.dsse.json"

MANIFEST_PAYLOAD_TYPE = "application/vnd.oev.decision-pack-manifest+json"

CANONICALIZATION_JCS = "jcs-rfc8785"
CANONICALIZATION_RAW = "raw"

# The six mandatory decision members plus the case record, fixed paths, fixed roles.
CORE_MEMBER_ROLES: dict[str, str] = {
    "case": "case.json",
    "facts": "facts.json",
    "rule_runs": "rule_runs.json",
    "findings": "findings.json",
    "review_actions": "review_actions.json",
    "timeline": "timeline.json",
    "snapshot_context": "snapshot_context.json",
}

ROLE_TO_SCHEMA: dict[str, str] = {
    "case": "decision-pack-case.schema.json",
    "facts": "decision-pack-facts.schema.json",
    "rule_runs": "decision-pack-rule-runs.schema.json",
    "findings": "decision-pack-findings.schema.json",
    "review_actions": "decision-pack-review-actions.schema.json",
    "timeline": "decision-pack-timeline.schema.json",
    "snapshot_context": "decision-pack-snapshot-context.schema.json",
}

ARTIFACTS_DIR_PREFIX = "artifacts/"


class RuleRunOutcome(str, Enum):
    """Honest execution status of a recorded rule run.

    HASH_MISMATCH: an input referenced by digest did not match its recorded
        content at execution time; the run aborted fail-closed.
    UNVERIFIABLE: required input facts were missing or insufficient to evaluate
        the rule; the run did not reach a triggered/not-triggered conclusion.
    REVIEW_REQUIRED: the rule defers the decision to a human reviewer.
    """

    TRIGGERED = "TRIGGERED"
    NOT_TRIGGERED = "NOT_TRIGGERED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNVERIFIABLE = "UNVERIFIABLE"
    HASH_MISMATCH = "HASH_MISMATCH"


class FindingSeverity(str, Enum):
    """Coarse, domain-neutral severity label attached to a finding by the rule."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ReviewActionType(str, Enum):
    """Vocabulary of recorded review actions.

    Recording an action is evidence that it was performed by the named actor;
    it is never evidence that the action was correct.
    """

    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    ESCALATE = "ESCALATE"
    COMMENT = "COMMENT"


class MemberRole(str, Enum):
    """Role of a pack member covered by the manifest."""

    CASE = "case"
    FACTS = "facts"
    RULE_RUNS = "rule_runs"
    FINDINGS = "findings"
    REVIEW_ACTIONS = "review_actions"
    TIMELINE = "timeline"
    SNAPSHOT_CONTEXT = "snapshot_context"
    ARTIFACT = "artifact"


@dataclass(frozen=True)
class PackMember:
    """One manifest-covered pack member with its SHA-256 digest and size."""

    path: str
    role: str
    media_type: str
    canonicalization: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "media_type": self.media_type,
            "canonicalization": self.canonicalization,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PackMember:
        return cls(
            path=str(data["path"]),
            role=str(data["role"]),
            media_type=str(data["media_type"]),
            canonicalization=str(data["canonicalization"]),
            size_bytes=int(data["size_bytes"]),
            sha256=str(data["sha256"]),
        )


@dataclass(frozen=True)
class PackManifest:
    """SHA-256 manifest of a decision evidence pack.

    CRITICAL RECURSION RULE (mirrors the receipt self-digest rule):
    1. pack_unsigned_body = manifest dictionary WITHOUT 'pack_digest'
    2. pack_digest = sha256(JCS(pack_unsigned_body))
    3. The final serialized manifest includes the computed 'pack_digest'.
    4. Verifiers recompute by removing 'pack_digest', canonicalizing the
       remainder via JCS, and comparing against the declared value.
    """

    pack_id: str
    case_id: str
    created_at: str
    members: list[PackMember]
    protocol_version: str = DECISION_PACK_PROTOCOL_VERSION
    creator_software: str | None = None
    creator_version: str | None = None
    pack_digest: str = ""

    def to_dict(self, include_digest: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "pack_id": self.pack_id,
            "case_id": self.case_id,
            "created_at": self.created_at,
            "members": [m.to_dict() for m in self.members],
        }
        if self.creator_software is not None and self.creator_version is not None:
            d["creator"] = {
                "software": self.creator_software,
                "version": self.creator_version,
            }
        if include_digest and self.pack_digest:
            d["pack_digest"] = self.pack_digest
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PackManifest:
        creator = data.get("creator") or {}
        return cls(
            protocol_version=str(data.get("protocol_version", DECISION_PACK_PROTOCOL_VERSION)),
            pack_id=str(data["pack_id"]),
            case_id=str(data["case_id"]),
            created_at=str(data["created_at"]),
            members=[PackMember.from_dict(m) for m in data["members"]],
            creator_software=str(creator["software"]) if creator.get("software") else None,
            creator_version=str(creator["version"]) if creator.get("version") else None,
            pack_digest=str(data.get("pack_digest", "")),
        )


@dataclass(frozen=True)
class MemberVerification:
    """Per-member verification outcome."""

    path: str
    status: str  # MATCH, DIGEST_MISMATCH, NOT_CANONICAL, MISSING, UNREADABLE
    expected_digest: str
    actual_digest: str = ""
    expected_size_bytes: int = 0
    actual_size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "path": self.path,
            "status": self.status,
            "expected_digest": self.expected_digest,
        }
        if self.actual_digest:
            d["actual_digest"] = self.actual_digest
        d["expected_size_bytes"] = self.expected_size_bytes
        d["actual_size_bytes"] = self.actual_size_bytes
        return d


@dataclass(frozen=True)
class PackVerificationResult:
    """Outcome of technical verification of a decision evidence pack.

    overall is PACK_VALID or PACK_INVALID. ``signature_state`` is the honest
    three-way vocabulary SIGNATURE_NOT_PRESENT / SIGNATURE_VALID /
    SIGNATURE_INVALID (see oev.pack_verifier): an unsigned pack is never
    invalid because it is unsigned, and SIGNATURE_INVALID means the signature
    was present but not established valid. Signature trust is reported
    separately and never upgrades an invalid pack to valid.
    """

    pack_path: str
    overall: str
    manifest_schema_valid: bool
    manifest_canonical: bool
    pack_digest_valid: bool
    declared_pack_digest: str
    recomputed_pack_digest: str
    member_order_stable: bool
    member_results: list[MemberVerification]
    extra_files: list[str]
    structure_errors: list[str]
    is_signed: bool = False
    signature_crypto_valid: bool = False
    is_trusted_signer: bool = False
    trusted_signer_key_id: str | None = None
    signer_note: str = ""
    signature_state: str = "SIGNATURE_NOT_PRESENT"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "pack_path": self.pack_path,
            "overall": self.overall,
            "manifest_schema_valid": self.manifest_schema_valid,
            "manifest_canonical": self.manifest_canonical,
            "pack_digest_valid": self.pack_digest_valid,
            "declared_pack_digest": self.declared_pack_digest,
            "recomputed_pack_digest": self.recomputed_pack_digest,
            "member_order_stable": self.member_order_stable,
            "member_results": [m.to_dict() for m in self.member_results],
            "extra_files": list(self.extra_files),
            "structure_errors": list(self.structure_errors),
            "is_signed": self.is_signed,
            "signature_state": self.signature_state,
            "signature_crypto_valid": self.signature_crypto_valid,
            "is_trusted_signer": self.is_trusted_signer,
            "trusted_signer_key_id": self.trusted_signer_key_id,
            "signer_note": self.signer_note,
            "reasons": list(self.reasons),
        }
        return d

    def format_human(self) -> str:
        lines: list[str] = [
            "=" * 70,
            "OEVP DECISION EVIDENCE PACK VERIFICATION REPORT",
            "=" * 70,
            f"Pack Path:            {self.pack_path}",
            f"Overall:              {self.overall}",
            f"Manifest Schema:      {'VALID' if self.manifest_schema_valid else 'INVALID'}",
            f"Manifest Canonical:   {'YES' if self.manifest_canonical else 'NO'}",
            (
                f"Pack Digest:          {self.declared_pack_digest} "
                f"({'VALID' if self.pack_digest_valid else 'INVALID'})"
            ),
            f"Member Order Stable:  {'YES' if self.member_order_stable else 'NO'}",
            "-" * 70,
            f"Members ({len(self.member_results)}):",
        ]
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
        if self.is_signed:
            lines.extend(
                [
                    "DSSE Envelope:        PRESENT",
                    f"Signature State:      {self.signature_state}",
                    (
                        f"Signature Crypto:     "
                        f"{'VALID' if self.signature_crypto_valid else 'NOT ESTABLISHED VALID'}"
                    ),
                    f"Signer Trusted:       {'YES' if self.is_trusted_signer else 'NO'}"
                    + (
                        f" (key: {self.trusted_signer_key_id})"
                        if self.is_trusted_signer and self.trusted_signer_key_id
                        else ""
                    ),
                ]
            )
        else:
            lines.append("DSSE Envelope:        ABSENT (unsigned pack — SIGNATURE_NOT_PRESENT)")
        if self.reasons:
            lines.extend(["-" * 70, "Notes:"])
            for r in self.reasons:
                lines.append(f"  * {r}")
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
