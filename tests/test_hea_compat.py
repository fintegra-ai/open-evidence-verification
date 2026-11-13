# SPDX-License-Identifier: Apache-2.0

"""Backwards-compatibility tests: pre-HEA receipts stay valid (HEA design §10)."""

from __future__ import annotations

import json
from pathlib import Path

from oev.hea_verifier import verify_historical_execution
from oev.models import (
    CheckResult,
    CheckStatus,
    OverallResult,
    PackageReference,
    ProfileReference,
    TrustInput,
    VerificationReceipt,
    VerifierIdentity,
)
from oev.profiles import compute_profile_digest
from oev.receipts import finalize_receipt, verify_receipt_digest
from oev.reverify import reverify_package
from tests.hea_helpers import build_valid_hea, hea_inputs, make_profile


def _legacy_receipt() -> VerificationReceipt:
    profile = make_profile()
    raw = VerificationReceipt(
        receipt_id="00000000-0000-4000-8000-0000000000old",
        protocol_version="oev-receipt/0.1",
        recorded_verification_time="2026-01-01T12:00:00Z",
        package=PackageReference(digest="sha256:" + "1" * 64, format="oept-bundle/0.1"),
        profile=ProfileReference(
            profile_id=profile.profile_id,
            profile_version=profile.profile_version,
            profile_digest=compute_profile_digest(profile),
        ),
        verifier=VerifierIdentity(software="oev-test", version="0.2.3"),
        trust_inputs=[TrustInput(trust_id="k1", type="public_key", digest="sha256:" + "3" * 64)],
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(
                check_id="manifest_structure", category="structure", status=CheckStatus.PASS
            ),
        ],
        limitations=[],
        overall_result=OverallResult.TECHNICAL_CHECKS_PASSED,
    )
    return finalize_receipt(raw)


def test_legacy_receipt_has_no_hea_field_but_valid_digest() -> None:
    receipt = _legacy_receipt()
    assert receipt.execution_attestations == []
    assert "execution_attestations" not in receipt.to_dict(include_digest=True)
    ok, _declared, _recomputed = verify_receipt_digest(receipt)
    assert ok


def test_legacy_receipt_is_unproven_not_invalid(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt = _legacy_receipt()
    # Same package bytes as the bundle, so the digest steps pass; only the
    # attestation is missing.
    legacy = finalize_receipt(
        VerificationReceipt(
            receipt_id=receipt.receipt_id,
            protocol_version=receipt.protocol_version,
            recorded_verification_time=receipt.recorded_verification_time,
            package=PackageReference(
                digest=bundle["receipt"].package.digest, format="oept-bundle/0.1"
            ),
            profile=receipt.profile,
            verifier=receipt.verifier,
            trust_inputs=receipt.trust_inputs,
            checks=receipt.checks,
            limitations=receipt.limitations,
            overall_result=receipt.overall_result,
        )
    )
    result = verify_historical_execution(hea_inputs(bundle, receipt=legacy, attestations=[]))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "NO_ATTESTATION"
    # ...but the receipt's own overall result is untouched by HEA.
    assert legacy.overall_result == OverallResult.TECHNICAL_CHECKS_PASSED


def test_receipt_with_hea_field_validates_against_updated_schema(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    from oev.schemas import validate_document

    validate_document(
        bundle["receipt"].to_dict(include_digest=True), "verification-receipt.schema.json"
    )


def test_legacy_receipt_reverify_still_works(tmp_path: Path) -> None:
    # A pre-HEA receipt re-verifies exactly as before (MATCH), and the
    # reverify report simply carries no HEA dimension.
    from oev.adapters.oept import is_oept_available

    if not is_oept_available():
        return
    fixture = (
        Path(__file__).resolve().parents[1] / "conformance" / "fixtures" / "01-valid-oept-pass"
    )
    package_bytes = (fixture / "package.zip").read_bytes()
    trust_keys = json.loads((fixture / "package-trust-keys.json").read_text())
    report = reverify_package(
        package_bytes=package_bytes,
        receipt_source=fixture / "receipt.dsse.json",
        profile_source=fixture / "profile.json",
        package_trust_keys=trust_keys,
    )
    assert report.reverification_result == "MATCH"
    assert report.historical_execution == ""
    assert "historical_execution" not in report.to_dict()


def test_reverify_report_carries_hea_dimension_when_supplied(tmp_path: Path) -> None:
    from oev.adapters.oept import is_oept_available

    if not is_oept_available():
        return
    fixture = (
        Path(__file__).resolve().parents[1] / "conformance" / "fixtures" / "01-valid-oept-pass"
    )
    package_bytes = (fixture / "package.zip").read_bytes()
    trust_keys = json.loads((fixture / "package-trust-keys.json").read_text())
    report = reverify_package(
        package_bytes=package_bytes,
        receipt_source=fixture / "receipt.dsse.json",
        profile_source=fixture / "profile.json",
        package_trust_keys=trust_keys,
        hea_assessment={
            "historical_execution": "HISTORICAL_EXECUTION_UNPROVEN",
            "reason": "NO_ATTESTATION",
            "notes": ["pre-HEA receipt"],
        },
    )
    assert report.reverification_result == "MATCH"
    assert report.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert report.historical_execution_reason == "NO_ATTESTATION"
    assert report.historical_execution_notes == ["pre-HEA receipt"]
    assert report.to_dict()["historical_execution"] == "HISTORICAL_EXECUTION_UNPROVEN"


def test_superseded_receipt_keeps_hea_binding(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    old = bundle["receipt"]
    receipt_dict = old.to_dict(include_digest=False)
    receipt_dict["receipt_id"] = "00000000-0000-4000-8000-0000000000new"
    receipt_dict["superseded_receipt"] = {
        "receipt_id": old.receipt_id,
        "receipt_digest": old.receipt_digest,
    }
    new_receipt = finalize_receipt(receipt_dict)
    assert new_receipt.execution_attestations == old.execution_attestations
    result = verify_historical_execution(hea_inputs(bundle, receipt=new_receipt))
    # The new receipt binds the same attestations, but the attestations do
    # not carry the new receipt digest — and the old receipt digest they
    # would carry is absent (pre-receipt attestations). The receipt ->
    # attestation binding still holds, so the execution stays PROVEN.
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_new_receipt_digest_covers_execution_attestations(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    # Removing the binding changes the digest: the field is inside it.
    bound_digest = bundle["receipt"].receipt_digest
    del receipt_dict["execution_attestations"]
    stripped = finalize_receipt(receipt_dict)
    assert stripped.receipt_digest != bound_digest


def test_old_code_ignores_hea_field_gracefully(tmp_path: Path) -> None:
    # A reader that only knows the old fields (simulated by dropping the
    # field before from_dict) still loads the receipt.
    bundle = build_valid_hea(tmp_path)
    raw = bundle["receipt"].to_dict(include_digest=True)
    raw.pop("execution_attestations")
    loaded = VerificationReceipt.from_dict(raw)
    assert loaded.receipt_digest == bundle["receipt"].receipt_digest
    assert loaded.execution_attestations == []
