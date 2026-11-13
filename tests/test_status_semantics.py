# SPDX-License-Identifier: Apache-2.0

"""Formalised CheckStatus semantics and merge rules (HEA task §2).

The six statuses are never collapsed into one "not passed" bucket: each
keeps its own meaning, its own overall-result contribution, and its own
distinction between "profile incomplete" (a check the profile requires is
missing from the receipt) and "check failed" (a check ran and its rule
evaluated false).
"""

from __future__ import annotations

from pathlib import Path

from oev.models import (
    CHECK_STATUS_EXECUTED,
    CHECK_STATUS_MEANING,
    CheckResult,
    CheckStatus,
    Limitation,
    OverallResult,
)
from oev.receipts import aggregate_overall_result
from oev.reverify import reverify_package


def _checks(status_by_id: dict[str, CheckStatus]) -> list[CheckResult]:
    return [
        CheckResult(check_id=cid, category="test", status=status)
        for cid, status in status_by_id.items()
    ]


def test_status_meanings_cover_all_six_statuses() -> None:
    assert set(CHECK_STATUS_MEANING) == {s.value for s in CheckStatus}
    for status in CheckStatus:
        assert CHECK_STATUS_MEANING[status.value]


def test_only_not_run_has_no_execution() -> None:
    assert "NOT_RUN" not in CHECK_STATUS_EXECUTED
    assert CHECK_STATUS_EXECUTED == {"PASS", "FAIL", "NOT_APPLICABLE", "UNVERIFIED", "UNSUPPORTED"}


def test_required_fail_dominates() -> None:
    overall = aggregate_overall_result(
        ["c1", "c2"], [], _checks({"c1": CheckStatus.FAIL, "c2": CheckStatus.PASS}), []
    )
    assert overall == OverallResult.TECHNICAL_CHECKS_FAILED


def test_each_non_pass_required_status_yields_profile_unsatisfied() -> None:
    for status in (
        CheckStatus.NOT_RUN,
        CheckStatus.NOT_APPLICABLE,
        CheckStatus.UNVERIFIED,
        CheckStatus.UNSUPPORTED,
    ):
        overall = aggregate_overall_result(["c1"], [], _checks({"c1": status}), [])
        assert overall == OverallResult.PROFILE_UNSATISFIED, status


def test_missing_required_check_is_unsatisfied_never_pass() -> None:
    overall = aggregate_overall_result(["c1", "c2"], [], _checks({"c1": CheckStatus.PASS}), [])
    assert overall == OverallResult.PROFILE_UNSATISFIED


def test_optional_fail_downgrades_to_partial_not_failed() -> None:
    overall = aggregate_overall_result(
        ["c1"], ["c2"], _checks({"c1": CheckStatus.PASS, "c2": CheckStatus.FAIL}), []
    )
    assert overall == OverallResult.TECHNICAL_CHECKS_PARTIAL


def test_all_required_pass_with_no_limitations_is_passed() -> None:
    overall = aggregate_overall_result(["c1"], [], _checks({"c1": CheckStatus.PASS}), [])
    assert overall == OverallResult.TECHNICAL_CHECKS_PASSED


def test_material_limitation_downgrades_passed_to_partial() -> None:
    overall = aggregate_overall_result(
        ["c1"],
        [],
        _checks({"c1": CheckStatus.PASS}),
        [Limitation(code="X", description="x", material=True)],
    )
    assert overall == OverallResult.TECHNICAL_CHECKS_PARTIAL


def test_non_material_limitation_keeps_passed() -> None:
    overall = aggregate_overall_result(
        ["c1"],
        [],
        _checks({"c1": CheckStatus.PASS}),
        [Limitation(code="X", description="x", material=False)],
    )
    assert overall == OverallResult.TECHNICAL_CHECKS_PASSED


def test_interrupted_execution_is_incomplete() -> None:
    overall = aggregate_overall_result(
        ["c1"], [], _checks({"c1": CheckStatus.PASS}), [], execution_interrupted=True
    )
    assert overall == OverallResult.EXECUTION_INCOMPLETE


def test_missing_profile_check_vs_failed_check_are_distinct() -> None:
    # "Profile incomplete" (MISSING_FROM_RECEIPT in reverify) is not the
    # same as "check failed": the first means the receipt never recorded
    # the check, the second means the check ran and its rule was false.
    from oev.adapters.oept import is_oept_available

    if not is_oept_available():
        return
    import json

    from oev.models import (
        PackageReference,
        ProfileReference,
        TrustInput,
        VerificationProfile,
        VerificationReceipt,
        VerifierIdentity,
    )
    from oev.profiles import compute_profile_digest, load_profile
    from oev.receipts import finalize_receipt

    fixture = (
        Path(__file__).resolve().parents[1] / "conformance" / "fixtures" / "01-valid-oept-pass"
    )
    package_bytes = (fixture / "package.zip").read_bytes()
    trust_keys = json.loads((fixture / "package-trust-keys.json").read_text())
    profile = load_profile(fixture / "profile.json")
    # A profile that additionally requires a ghost check, with a receipt
    # built against THAT profile digest but never recording the ghost check.
    ghost_profile = VerificationProfile(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        target_format=profile.target_format,
        required_checks=[*profile.required_checks, "ghost_check_never_recorded"],
        optional_checks=profile.optional_checks,
        parameters=profile.parameters,
    )
    historic = json.loads((fixture / "receipt.dsse.json").read_bytes())
    import base64

    historic_receipt = json.loads(base64.b64decode(historic["payload"].encode()).decode())
    raw_receipt = VerificationReceipt(
        receipt_id=historic_receipt["receipt_id"],
        protocol_version="oev-receipt/0.1",
        recorded_verification_time=historic_receipt["recorded_verification_time"],
        package=PackageReference(
            digest=historic_receipt["package"]["digest"],
            format=historic_receipt["package"]["format"],
        ),
        profile=ProfileReference(
            profile_id=ghost_profile.profile_id,
            profile_version=ghost_profile.profile_version,
            profile_digest=compute_profile_digest(ghost_profile),
        ),
        verifier=VerifierIdentity(
            software=historic_receipt["verifier"]["software"],
            version=historic_receipt["verifier"]["version"],
        ),
        trust_inputs=[
            TrustInput(trust_id=t["trust_id"], type=t["type"], digest=t["digest"])
            for t in historic_receipt["trust_inputs"]
        ],
        checks=[CheckResult.from_dict(c) for c in historic_receipt["checks"]],
        limitations=[],
        overall_result=historic_receipt["overall_result"],
    )
    receipt = finalize_receipt(raw_receipt)
    report = reverify_package(
        package_bytes=package_bytes,
        receipt_source=receipt.to_dict(include_digest=True),
        profile_source=ghost_profile,
        package_trust_keys=trust_keys,
    )
    assert report.reverification_result == "MISMATCH"
    missing = [d for d in report.check_differences if d["check_id"] == "ghost_check_never_recorded"]
    assert missing and missing[0]["historical_status"] == "MISSING_FROM_RECEIPT"
    # ...while the recorded checks did not fail:
    failed = [d for d in report.check_differences if d.get("fresh_status") == "FAIL"]
    assert not failed
