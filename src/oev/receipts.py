# SPDX-License-Identifier: Apache-2.0

"""Verification Receipt construction, validation, digest computation, and overall aggregation.

CRITICAL RECURSION RULE:
A receipt must never hash itself including its own receipt_digest field.
1. receipt_unsigned_body = VerificationReceipt dictionary WITHOUT 'receipt_digest'
2. receipt_digest = sha256(JCS(receipt_unsigned_body))
3. The final serialized receipt includes the computed 'receipt_digest'.
4. Verification recomputes by removing 'receipt_digest' and hashing the canonical remaining body.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import canonicalize_json, safe_json_loads
from .hashing import sha256_bytes
from .models import CheckResult, CheckStatus, Limitation, OverallResult, VerificationReceipt
from .schemas import validate_document

RECEIPT_SCHEMA_NAME = "verification-receipt.schema.json"


def aggregate_overall_result(
    required_checks: list[str],
    optional_checks: list[str],
    checks: list[CheckResult],
    limitations: list[Limitation] | None = None,
    execution_interrupted: bool = False,
) -> OverallResult:
    """Deterministically aggregate atomic check results into a terminal OverallResult.

    Aggregation contract:
    - EXECUTION_INCOMPLETE: execution interrupted (e.g. fatal parser error, resource limit).
    - TECHNICAL_CHECKS_FAILED: at least one REQUIRED check returned FAIL.
    - PROFILE_UNSATISFIED: no required check returned FAIL, but at least one REQUIRED check
      is NOT_RUN, NOT_APPLICABLE, UNVERIFIED, or UNSUPPORTED.
    - TECHNICAL_CHECKS_PASSED: every REQUIRED check returned PASS, and all executed OPTIONAL
      checks returned PASS or NOT_APPLICABLE with no limitations.
    - TECHNICAL_CHECKS_PARTIAL: every REQUIRED check returned PASS, but one or more OPTIONAL
      checks returned FAIL, NOT_RUN, UNVERIFIED, UNSUPPORTED, or limitations exist.
    """
    if execution_interrupted:
        return OverallResult.EXECUTION_INCOMPLETE

    checks_by_id = {c.check_id: c for c in checks}

    # 1. Evaluate required checks
    required_fails: list[str] = []
    required_unsatisfied: list[str] = []

    for req_id in required_checks:
        check = checks_by_id.get(req_id)
        if check is None:
            required_unsatisfied.append(req_id)
            continue

        status = (
            check.status if isinstance(check.status, CheckStatus) else CheckStatus(check.status)
        )
        if status == CheckStatus.FAIL:
            required_fails.append(req_id)
        elif status in (
            CheckStatus.NOT_RUN,
            CheckStatus.NOT_APPLICABLE,
            CheckStatus.UNVERIFIED,
            CheckStatus.UNSUPPORTED,
        ):
            required_unsatisfied.append(req_id)
        elif status == CheckStatus.PASS:
            pass

    if required_fails:
        return OverallResult.TECHNICAL_CHECKS_FAILED

    if required_unsatisfied:
        return OverallResult.PROFILE_UNSATISFIED

    # 2. At this point, all required checks executed and passed.
    # Check optional checks and limitations
    optional_imperfect: list[str] = []
    for opt_id in optional_checks:
        check = checks_by_id.get(opt_id)
        if check is None:
            optional_imperfect.append(opt_id)
            continue
        status = (
            check.status if isinstance(check.status, CheckStatus) else CheckStatus(check.status)
        )
        if status not in (CheckStatus.PASS, CheckStatus.NOT_APPLICABLE):
            optional_imperfect.append(opt_id)

    material_limitations = [lim for lim in (limitations or []) if getattr(lim, "material", True)]
    has_material_limitations = bool(len(material_limitations) > 0)

    if optional_imperfect or has_material_limitations:
        return OverallResult.TECHNICAL_CHECKS_PARTIAL

    return OverallResult.TECHNICAL_CHECKS_PASSED


def compute_receipt_digest(receipt: dict[str, Any] | VerificationReceipt) -> str:
    """Compute deterministic SHA-256 digest over JCS-canonicalized receipt body WITHOUT receipt_digest."""
    d = (
        receipt.to_dict(include_digest=False)
        if isinstance(receipt, VerificationReceipt)
        else dict(receipt)
    )
    # Ensure receipt_digest is omitted from unsigned body
    d.pop("receipt_digest", None)
    canonical_bytes = canonicalize_json(d)
    return sha256_bytes(canonical_bytes)


def finalize_receipt(receipt: dict[str, Any] | VerificationReceipt) -> VerificationReceipt:
    """Compute and attach receipt_digest, validate against schema, and return VerificationReceipt."""
    d = (
        receipt.to_dict(include_digest=False)
        if isinstance(receipt, VerificationReceipt)
        else dict(receipt)
    )
    digest = compute_receipt_digest(d)
    d["receipt_digest"] = digest
    validate_document(d, RECEIPT_SCHEMA_NAME)
    return VerificationReceipt.from_dict(d)


def verify_receipt_digest(receipt: dict[str, Any] | VerificationReceipt) -> tuple[bool, str, str]:
    """Verify that a receipt's declared receipt_digest matches the recomputed digest.

    Returns (is_valid, declared_digest, recomputed_digest).
    """
    d = (
        receipt.to_dict(include_digest=True)
        if isinstance(receipt, VerificationReceipt)
        else dict(receipt)
    )
    declared = str(d.get("receipt_digest", ""))
    recomputed = compute_receipt_digest(d)
    return (declared == recomputed, declared, recomputed)


def load_receipt(source: str | Path | dict[str, Any]) -> VerificationReceipt:
    """Load and validate a VerificationReceipt from file path or dictionary."""
    if isinstance(source, (str, Path)):
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()
        data = safe_json_loads(content)
    elif isinstance(source, dict):
        data = source
    else:
        raise TypeError(f"Expected path or dict for receipt, got {type(source).__name__}")

    validate_document(data, RECEIPT_SCHEMA_NAME)
    return VerificationReceipt.from_dict(data)
