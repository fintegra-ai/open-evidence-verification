# SPDX-License-Identifier: Apache-2.0

"""Data models and enums for the Open Evidence Verification Protocol (OEVP)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    """Granular check execution status.

    These distinctions must survive serialization. Do not add generic statuses
    like VERIFIED, SUCCESS, or UNKNOWN.

    Formal semantics (HEA design §7.5; full table in
    docs/PROTOCOL_SECURITY_REVIEW.md §C, taxonomy C1–C10):
    - PASS: the check executed and its rule evaluated true on the inputs.
    - FAIL: the check executed and its rule evaluated false. A FAIL is a
      *completed* execution with a negative outcome, never an execution
      failure; a proven FAIL execution is still a proven execution.
    - NOT_RUN: the check was scheduled but never started (e.g. execution
      interrupted first). No attestation may be produced for a NOT_RUN
      check; its HEA state is HEA_NOT_APPLICABLE, not UNPROVEN.
    - NOT_APPLICABLE: the check executed far enough to determine that its
      rule does not apply to this package (e.g. no signature present to
      verify). It is a completed evaluation, not a skipped one.
    - UNVERIFIED: the check executed but its outcome could not be
      established (e.g. no trust roots supplied to judge a signature).
      UNVERIFIED is an *indeterminate outcome*, not a missing execution.
    - UNSUPPORTED: the profile requires a capability this verifier build
      cannot perform (e.g. no adapter for the format). The check was not
      attempted because it cannot be attempted here.

    Merging (``aggregate_overall_result`` in receipts.py — the single
    normative merge): FAIL on a REQUIRED check dominates everything
    (TECHNICAL_CHECKS_FAILED). Otherwise any REQUIRED check in
    NOT_RUN / NOT_APPLICABLE / UNVERIFIED / UNSUPPORTED yields
    PROFILE_UNSATISFIED. A missing check in the receipt is treated as
    unsatisfied, never as PASS. OPTIONAL imperfections and material
    limitations downgrade PASSED to PARTIAL. The six statuses are never
    collapsed into one another: in particular FAIL, NOT_RUN,
    NOT_APPLICABLE, UNVERIFIED and UNSUPPORTED are never merged into a
    single "not passed" bucket — each keeps its own meaning, transition
    and overall-result contribution.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNVERIFIED = "UNVERIFIED"
    UNSUPPORTED = "UNSUPPORTED"


#: Human-readable meaning of each CheckStatus (single source of truth for
#: documentation and verifier output; the enum docstring above is normative).
CHECK_STATUS_MEANING: dict[str, str] = {
    "PASS": "Check executed; rule evaluated true on the given inputs.",
    "FAIL": "Check executed; rule evaluated false. A completed execution with a negative outcome.",
    "NOT_RUN": "Check scheduled but never started; no execution exists to attest.",
    "NOT_APPLICABLE": "Check evaluated far enough to determine its rule does not apply to this package.",
    "UNVERIFIED": "Check executed but its outcome could not be established (e.g. missing trust roots).",
    "UNSUPPORTED": "Check could not be attempted: this verifier build lacks the required capability.",
}

#: Which CheckStatus values count as "the check ran to a verdict" (a
#: verdict may be negative). NOT_RUN is the only status with no execution.
CHECK_STATUS_EXECUTED: frozenset[str] = frozenset(
    {"PASS", "FAIL", "NOT_APPLICABLE", "UNVERIFIED", "UNSUPPORTED"}
)


class HistoricalExecutionResult(str, Enum):
    """Historical-execution dimension of a verification (HEA design §7).

    Independent from reproducibility (MATCH/MISMATCH/CANNOT_REPRODUCE):
    the two dimensions are never merged into one score.
    """

    PROVEN = "HISTORICAL_EXECUTION_PROVEN"
    UNPROVEN = "HISTORICAL_EXECUTION_UNPROVEN"
    DISPROVEN = "HISTORICAL_EXECUTION_DISPROVEN"
    NOT_APPLICABLE = "HEA_NOT_APPLICABLE"


class HeaReason(str, Enum):
    """Normative reason codes for HISTORICAL_EXECUTION_UNPROVEN (§7.3).

    Every UNPROVEN verdict carries exactly one code; there is no silent UNPROVEN.
    """

    NO_ATTESTATION = "NO_ATTESTATION"
    NO_PREBINDING = "NO_PREBINDING"
    MALFORMED_ATTESTATION = "MALFORMED_ATTESTATION"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SIGNATURE_UNTRUSTED = "SIGNATURE_UNTRUSTED"
    WITNESS_UNAUTHORIZED = "WITNESS_UNAUTHORIZED"
    WITNESS_KEY_REVOKED = "WITNESS_KEY_REVOKED"
    WITNESS_KEY_EXPIRED = "WITNESS_KEY_EXPIRED"
    BUNDLE_DIGEST_MISMATCH = "BUNDLE_DIGEST_MISMATCH"
    PROFILE_DIGEST_MISMATCH = "PROFILE_DIGEST_MISMATCH"
    CODE_DIGEST_MISMATCH = "CODE_DIGEST_MISMATCH"
    LOG_ANCHOR_INVALID = "LOG_ANCHOR_INVALID"
    LOG_GAP = "LOG_GAP"
    MISSING_EXECUTION_STEP = "MISSING_EXECUTION_STEP"
    RESULT_CONFLICT = "RESULT_CONFLICT"
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    UNSUPPORTED_PROTOCOL_VERSION = "UNSUPPORTED_PROTOCOL_VERSION"


class OverallResult(str, Enum):
    """Terminal technical verdict for a verification execution.

    TECHNICAL_CHECKS_FAILED: at least one REQUIRED check returned FAIL.
    PROFILE_UNSATISFIED: no required check returned FAIL, but at least one REQUIRED check
        is NOT_RUN, NOT_APPLICABLE, UNVERIFIED, or UNSUPPORTED.
    EXECUTION_INCOMPLETE: verifier could not complete enough execution to evaluate
        required checks (e.g. fatal parser failure, resource exhaustion).
    TECHNICAL_CHECKS_PASSED: every REQUIRED check returned PASS and all executed OPTIONAL
        checks returned PASS or NOT_APPLICABLE with no material limitations.
    TECHNICAL_CHECKS_PARTIAL: every REQUIRED check returned PASS, but one or more OPTIONAL
        checks returned FAIL, NOT_RUN, UNVERIFIED, UNSUPPORTED, or material limitations exist.
    """

    TECHNICAL_CHECKS_PASSED = "TECHNICAL_CHECKS_PASSED"
    TECHNICAL_CHECKS_FAILED = "TECHNICAL_CHECKS_FAILED"
    TECHNICAL_CHECKS_PARTIAL = "TECHNICAL_CHECKS_PARTIAL"
    EXECUTION_INCOMPLETE = "EXECUTION_INCOMPLETE"
    PROFILE_UNSATISFIED = "PROFILE_UNSATISFIED"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single atomic verification check."""

    check_id: str
    category: str
    status: CheckStatus | str
    detail: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check_id": self.check_id,
            "category": self.category,
            "status": str(
                self.status.value if isinstance(self.status, CheckStatus) else self.status
            ),
        }
        if self.detail:
            d["detail"] = self.detail
        if self.duration_ms >= 0:
            d["duration_ms"] = self.duration_ms
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckResult:
        status_val = data["status"]
        return cls(
            check_id=str(data["check_id"]),
            category=str(data["category"]),
            status=CheckStatus(status_val)
            if status_val in CheckStatus._value2member_map_
            else str(status_val),
            detail=str(data.get("detail", "")),
            duration_ms=int(data.get("duration_ms", 0)),
        )


@dataclass(frozen=True)
class Limitation:
    """Explicit limitation on verification scope or coverage."""

    code: str
    description: str
    material: bool = True

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "description": self.description}
        if not self.material:
            d["material"] = False
        else:
            d["material"] = True
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Limitation:
        return cls(
            code=str(data["code"]),
            description=str(data["description"]),
            material=bool(data.get("material", True)),
        )


@dataclass(frozen=True)
class PackageReference:
    """Reference binding an evidence package by format and content digest."""

    digest: str
    format: str
    size_bytes: int | None = None
    declared_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"digest": self.digest, "format": self.format}
        if self.size_bytes is not None:
            d["size_bytes"] = self.size_bytes
        if self.declared_id is not None:
            d["declared_id"] = self.declared_id
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PackageReference:
        return cls(
            digest=str(data["digest"]),
            format=str(data["format"]),
            size_bytes=int(data["size_bytes"]) if data.get("size_bytes") is not None else None,
            declared_id=str(data["declared_id"]) if data.get("declared_id") is not None else None,
        )


@dataclass(frozen=True)
class ProfileReference:
    """Reference binding a verification profile by ID, version, and content digest."""

    profile_id: str
    profile_version: str
    profile_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_digest": self.profile_digest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProfileReference:
        return cls(
            profile_id=str(data["profile_id"]),
            profile_version=str(data["profile_version"]),
            profile_digest=str(data["profile_digest"]),
        )


@dataclass(frozen=True)
class VerifierIdentity:
    """Non-legal technical identity of the verifying software."""

    software: str
    version: str
    environment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"software": self.software, "version": self.version}
        if self.environment:
            d["environment"] = self.environment
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerifierIdentity:
        return cls(
            software=str(data["software"]),
            version=str(data["version"]),
            environment=str(data["environment"]) if data.get("environment") else None,
        )


@dataclass(frozen=True)
class TrustInput:
    """Identifier and content digest of a caller-supplied trust input."""

    trust_id: str
    type: str
    digest: str
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "trust_id": self.trust_id,
            "type": self.type,
            "digest": self.digest,
        }
        if self.note:
            d["note"] = self.note
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustInput:
        return cls(
            trust_id=str(data["trust_id"]),
            type=str(data["type"]),
            digest=str(data["digest"]),
            note=str(data["note"]) if data.get("note") else None,
        )


@dataclass(frozen=True)
class VerificationProfile:
    """Canonical verification ruleset defining required and optional checks."""

    profile_id: str
    profile_version: str
    target_format: str
    required_checks: list[str]
    protocol_version: str = "oev-profile/0.1"
    optional_checks: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "target_format": self.target_format,
            "required_checks": list(self.required_checks),
            "optional_checks": list(self.optional_checks),
            "parameters": dict(self.parameters),
        }
        if self.description:
            d["description"] = self.description
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationProfile:
        req = [str(c) for c in data.get("required_checks", [])]
        opt = [str(c) for c in data.get("optional_checks", [])]
        overlap = set(req).intersection(set(opt))
        if overlap:
            raise ValueError(
                f"Checks cannot be both required and optional in profile: {sorted(overlap)}"
            )
        return cls(
            protocol_version=str(data.get("protocol_version", "oev-profile/0.1")),
            profile_id=str(data["profile_id"]),
            profile_version=str(data["profile_version"]),
            target_format=str(data["target_format"]),
            required_checks=req,
            optional_checks=opt,
            parameters=dict(data.get("parameters", {})),
            description=str(data.get("description", "")),
        )


@dataclass(frozen=True)
class VerificationReceipt:
    """Portable technical verification receipt."""

    receipt_id: str
    recorded_verification_time: str
    package: PackageReference
    profile: ProfileReference
    verifier: VerifierIdentity
    trust_inputs: list[TrustInput]
    checks: list[CheckResult]
    limitations: list[Limitation]
    overall_result: OverallResult | str
    protocol_version: str = "oev-receipt/0.1"
    superseded_receipt: dict[str, str] | None = None
    receipt_digest: str = ""
    # HEA binding (oev-attestation/0.1, design §5.2 rule 2): per-check
    # attestation digests. Each entry is {"check_id": ..., "attestation_digest":
    # "sha256:<...>"} where attestation_digest is the JCS+SHA-256 digest of the
    # attestation payload. The field is part of the receipt digest, so it
    # cannot be added to a receipt after finalisation. Absence means "no
    # HEA attestation" (NO_ATTESTATION), never "receipt invalid".
    execution_attestations: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self, include_digest: bool = True) -> dict[str, Any]:
        res_val = (
            self.overall_result.value
            if isinstance(self.overall_result, OverallResult)
            else str(self.overall_result)
        )
        d: dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "protocol_version": self.protocol_version,
            "recorded_verification_time": self.recorded_verification_time,
            "package": self.package.to_dict(),
            "profile": self.profile.to_dict(),
            "verifier": self.verifier.to_dict(),
            "trust_inputs": [t.to_dict() for t in self.trust_inputs],
            "checks": [c.to_dict() for c in self.checks],
            "limitations": [l.to_dict() for l in self.limitations],
            "overall_result": res_val,
        }
        if self.superseded_receipt:
            d["superseded_receipt"] = dict(self.superseded_receipt)
        if self.execution_attestations:
            d["execution_attestations"] = [dict(a) for a in self.execution_attestations]
        if include_digest and self.receipt_digest:
            d["receipt_digest"] = self.receipt_digest
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationReceipt:
        res_val = data["overall_result"]
        overall = (
            OverallResult(res_val) if res_val in OverallResult._value2member_map_ else str(res_val)
        )
        checks = [CheckResult.from_dict(c) for c in data.get("checks", [])]
        seen_check_ids: set[str] = set()
        for c in checks:
            if c.check_id in seen_check_ids:
                raise ValueError(f"Duplicate check_id in checks: {c.check_id!r}")
            seen_check_ids.add(c.check_id)

        return cls(
            receipt_id=str(data["receipt_id"]),
            protocol_version=str(data.get("protocol_version", "oev-receipt/0.1")),
            recorded_verification_time=str(data["recorded_verification_time"]),
            package=PackageReference.from_dict(data["package"]),
            profile=ProfileReference.from_dict(data["profile"]),
            verifier=VerifierIdentity.from_dict(data["verifier"]),
            trust_inputs=[TrustInput.from_dict(t) for t in data.get("trust_inputs", [])],
            checks=checks,
            limitations=[Limitation.from_dict(l) for l in data.get("limitations", [])],
            overall_result=overall,
            superseded_receipt=dict(data["superseded_receipt"])
            if data.get("superseded_receipt")
            else None,
            receipt_digest=str(data.get("receipt_digest", "")),
            execution_attestations=[
                {"check_id": str(a["check_id"]), "attestation_digest": str(a["attestation_digest"])}
                for a in data.get("execution_attestations", [])
            ],
        )


@dataclass(frozen=True)
class ReverificationReport:
    """Report comparing an independent re-verification to a historical receipt."""

    receipt_digest: str
    package_digest_match: bool
    profile_digest_match: bool
    fresh_checks: list[CheckResult]
    check_differences: list[dict[str, Any]]
    reverification_result: str  # MATCH, MISMATCH, CANNOT_REPRODUCE
    protocol_version: str = "oev-reverification/0.1"
    notes: list[str] = field(default_factory=list)
    # HEA dimension (design §7.4): reported separately from reproducibility,
    # never merged into one score. Empty string means "not assessed".
    historical_execution: str = ""
    historical_execution_reason: str = ""
    historical_execution_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "receipt_digest": self.receipt_digest,
            "package_digest_match": self.package_digest_match,
            "profile_digest_match": self.profile_digest_match,
            "fresh_checks": [c.to_dict() for c in self.fresh_checks],
            "check_differences": list(self.check_differences),
            "reverification_result": self.reverification_result,
        }
        if self.notes:
            d["notes"] = list(self.notes)
        if self.historical_execution:
            d["historical_execution"] = self.historical_execution
        if self.historical_execution_reason:
            d["historical_execution_reason"] = self.historical_execution_reason
        if self.historical_execution_notes:
            d["historical_execution_notes"] = list(self.historical_execution_notes)
        return d
