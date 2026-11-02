# SPDX-License-Identifier: Apache-2.0

"""Independent package re-verification comparing fresh execution against historic receipt."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oev.adapters import get_adapter_for_format, get_adapter_for_package
from oev.canonical import safe_json_loads
from oev.dsse import DEFAULT_PAYLOAD_TYPE, DsseError, parse_dsse_envelope
from oev.fileio import read_bounded_file
from oev.hashing import sha256_bytes
from oev.models import (
    ReverificationReport,
    TrustInput,
    VerificationProfile,
    VerificationReceipt,
)
from oev.profiles import compute_profile_digest, load_profile
from oev.receipts import aggregate_overall_result, load_receipt, verify_receipt_digest
from oev.schemas import validate_document

REVERIFICATION_SCHEMA_NAME = "reverification-report.schema.json"


def _extract_receipt(source: str | Path | dict[str, Any]) -> VerificationReceipt:
    """Load VerificationReceipt, unwrapping DSSE envelope if present."""
    if isinstance(source, (str, Path)):
        content = read_bounded_file(source)
        data = safe_json_loads(content)
    elif isinstance(source, dict):
        data = source
    else:
        raise TypeError(f"Expected path or dict, got {type(source).__name__}")

    if "payloadType" in data and "payload" in data and "signatures" in data:
        payload_type, payload_bytes, _ = parse_dsse_envelope(data)
        if payload_type != DEFAULT_PAYLOAD_TYPE:
            raise DsseError("Unexpected DSSE payloadType for an OEVP receipt")
        receipt_dict = safe_json_loads(payload_bytes.decode("utf-8"))
    else:
        receipt_dict = data

    return load_receipt(receipt_dict)


def reverify_package(
    package_bytes: bytes,
    receipt_source: str | Path | dict[str, Any],
    profile_source: str | Path | dict[str, Any] | VerificationProfile,
    package_trust_keys: list[dict[str, Any]] | None = None,
) -> ReverificationReport:
    """Independently re-verify package bytes against a historical verification receipt.

    Reverification order:
    1. Verify receipt self-digest.
    2. Check package digest match.
    3. Check profile content digest match.
    4. Re-execute adapter checks against package bytes.
    5. Diff fresh check statuses against historic receipt checks.
    """
    receipt = _extract_receipt(receipt_source)
    is_digest_valid, _declared_digest, _ = verify_receipt_digest(receipt)

    notes: list[str] = []
    if not is_digest_valid:
        # Fail closed: a receipt whose self-digest does not verify has been
        # altered since issuance, so every value recorded in it — including
        # the package and profile digests and the recorded check statuses —
        # is untrusted. Comparing fresh results against attacker-chosen
        # values could lend unearned credibility to a tampered receipt, so
        # re-verification terminates here (mirrors the terminal
        # RECEIPT_INVALID handling for pack verification receipts).
        notes.append("Historical receipt self-digest verification failed (tampered receipt)")
        report = ReverificationReport(
            protocol_version="oev-reverification/0.1",
            receipt_digest=receipt.receipt_digest,
            package_digest_match=False,
            profile_digest_match=False,
            fresh_checks=[],
            check_differences=[],
            reverification_result="MISMATCH",
            notes=notes,
        )
        validate_document(report.to_dict(), REVERIFICATION_SCHEMA_NAME)
        return report

    # 1. Package digest check
    actual_package_digest = sha256_bytes(package_bytes)
    package_digest_match = actual_package_digest == receipt.package.digest

    if not package_digest_match:
        notes.append(
            f"Package digest mismatch: receipt referenced {receipt.package.digest}, "
            f"actual package is {actual_package_digest}"
        )
        report = ReverificationReport(
            protocol_version="oev-reverification/0.1",
            receipt_digest=receipt.receipt_digest,
            package_digest_match=False,
            profile_digest_match=False,
            fresh_checks=[],
            check_differences=[],
            reverification_result="MISMATCH",
            notes=notes,
        )
        validate_document(report.to_dict(), REVERIFICATION_SCHEMA_NAME)
        return report

    # 2. Profile digest check
    profile = (
        profile_source
        if isinstance(profile_source, VerificationProfile)
        else load_profile(profile_source)
    )
    actual_profile_digest = compute_profile_digest(profile)
    profile_digest_match = actual_profile_digest == receipt.profile.profile_digest

    if not profile_digest_match:
        notes.append(
            f"Profile digest mismatch: receipt referenced {receipt.profile.profile_digest}, "
            f"provided profile evaluates to {actual_profile_digest} (PROFILE_DIGEST_MISMATCH)"
        )
        report = ReverificationReport(
            protocol_version="oev-reverification/0.1",
            receipt_digest=receipt.receipt_digest,
            package_digest_match=True,
            profile_digest_match=False,
            fresh_checks=[],
            check_differences=[],
            reverification_result="CANNOT_REPRODUCE",
            notes=notes,
        )
        validate_document(report.to_dict(), REVERIFICATION_SCHEMA_NAME)
        return report

    # 3. Re-execute checks
    adapter = get_adapter_for_package(package_bytes)
    if adapter is None:
        adapter = get_adapter_for_format(profile.target_format)

    if adapter is None:
        notes.append(f"No adapter available to evaluate format '{profile.target_format}'")
        report = ReverificationReport(
            protocol_version="oev-reverification/0.1",
            receipt_digest=receipt.receipt_digest,
            package_digest_match=True,
            profile_digest_match=True,
            fresh_checks=[],
            check_differences=[],
            reverification_result="CANNOT_REPRODUCE",
            notes=notes,
        )
        validate_document(report.to_dict(), REVERIFICATION_SCHEMA_NAME)
        return report

    trust_inputs = [
        TrustInput(
            trust_id=str(k["key_id"]),
            type="public_key",
            digest=sha256_bytes(
                k["public_key_pem"].encode()
                if isinstance(k["public_key_pem"], str)
                else bytes(k["public_key_pem"])
            ),
            note=k.get("note"),
        )
        for k in (package_trust_keys or [])
    ]

    fresh_checks = adapter.evaluate(
        package_bytes=package_bytes,
        profile=profile,
        trust_inputs=trust_inputs,
        package_trusted_keys_pem=package_trust_keys,
    )

    # 4. Compare check outcomes
    fresh_by_id = {c.check_id: c for c in fresh_checks}
    differences: list[dict[str, Any]] = []

    for hist in receipt.checks:
        fresh = fresh_by_id.get(hist.check_id)
        if fresh is None:
            differences.append(
                {
                    "check_id": hist.check_id,
                    "historical_status": str(
                        hist.status.value if hasattr(hist.status, "value") else hist.status
                    ),
                    "fresh_status": "NOT_EXECUTED",
                    "note": "Check was recorded in historical receipt but not evaluated in fresh run",
                }
            )
        else:
            hist_status = str(hist.status.value if hasattr(hist.status, "value") else hist.status)
            fresh_status = str(
                fresh.status.value if hasattr(fresh.status, "value") else fresh.status
            )
            if hist_status != fresh_status:
                differences.append(
                    {
                        "check_id": hist.check_id,
                        "historical_status": hist_status,
                        "fresh_status": fresh_status,
                        "note": f"Status difference detected for {hist.check_id}",
                    }
                )

    # 4b. Every profile check, required or optional, must be represented.
    hist_by_id = {c.check_id: c for c in receipt.checks}
    for req_id in dict.fromkeys(profile.required_checks + profile.optional_checks):
        if req_id not in hist_by_id:
            fresh_c = fresh_by_id.get(req_id)
            fresh_status_str = (
                str(fresh_c.status.value if hasattr(fresh_c.status, "value") else fresh_c.status)
                if fresh_c
                else "NOT_EXECUTED"
            )
            differences.append(
                {
                    "check_id": req_id,
                    "historical_status": "MISSING_FROM_RECEIPT",
                    "fresh_status": fresh_status_str,
                    "note": f"Profile check '{req_id}' was absent from the historical receipt",
                }
            )

    recorded_trust = sorted((k.trust_id, k.type, k.digest) for k in receipt.trust_inputs)
    supplied_trust = sorted((k.trust_id, k.type, k.digest) for k in trust_inputs)
    if recorded_trust != supplied_trust:
        differences.append(
            {
                "check_id": "trust_inputs",
                "historical_status": "RECORDED",
                "fresh_status": "CHANGED",
                "note": "Caller trust inputs differ from the content-bound historical inputs",
            }
        )
    fresh_overall = aggregate_overall_result(
        profile.required_checks, profile.optional_checks, fresh_checks, receipt.limitations
    )
    if fresh_overall != receipt.overall_result:
        differences.append(
            {
                "check_id": "overall_result",
                "historical_status": getattr(
                    receipt.overall_result, "value", receipt.overall_result
                ),
                "fresh_status": fresh_overall.value,
                "note": "Recorded overall result does not reproduce from fresh checks",
            }
        )

    reverification_result = "MATCH" if len(differences) == 0 else "MISMATCH"

    report = ReverificationReport(
        protocol_version="oev-reverification/0.1",
        receipt_digest=receipt.receipt_digest,
        package_digest_match=True,
        profile_digest_match=True,
        fresh_checks=fresh_checks,
        check_differences=differences,
        reverification_result=reverification_result,
        notes=notes,
    )

    validate_document(report.to_dict(), REVERIFICATION_SCHEMA_NAME)
    return report
