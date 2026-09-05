import pytest

from oev.canonical import (
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
    CanonicalizationError,
    canonicalize_json,
)
from oev.hashing import is_valid_digest
from oev.models import (
    CheckResult,
    CheckStatus,
    Limitation,
    OverallResult,
    PackageReference,
    ProfileReference,
    TrustInput,
    VerificationReceipt,
    VerifierIdentity,
)
from oev.profiles import compute_profile_digest, load_profile
from oev.receipts import (
    aggregate_overall_result,
    finalize_receipt,
    verify_receipt_digest,
)
from oev.schemas import SchemaValidationError, validate_document


def test_jcs_integer_boundary_safety():
    # Safe integers
    assert canonicalize_json({"safe": 0}) == b'{"safe":0}'
    assert canonicalize_json({"max": MAX_SAFE_INTEGER}) == f'{{"max":{MAX_SAFE_INTEGER}}}'.encode()
    assert canonicalize_json({"min": MIN_SAFE_INTEGER}) == f'{{"min":{MIN_SAFE_INTEGER}}}'.encode()
    assert (
        canonicalize_json({"bool_true": True, "bool_false": False})
        == b'{"bool_false":false,"bool_true":true}'
    )

    # Unsafe large integers must be rejected
    with pytest.raises(CanonicalizationError, match="outside safe JCS range"):
        canonicalize_json({"too_large": MAX_SAFE_INTEGER + 1})

    with pytest.raises(CanonicalizationError, match="outside safe JCS range"):
        canonicalize_json({"too_small": MIN_SAFE_INTEGER - 1})

    with pytest.raises(CanonicalizationError, match="outside safe JCS range"):
        canonicalize_json({"nested": [{"very_large": 2**64}]})


def test_profile_schema_and_hashing():
    profile_data = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "test-strict-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": ["archive_safety", "manifest_structure", "member_digests"],
        "optional_checks": ["application_signature"],
        "parameters": {"max_archive_size_bytes": 1048576},
        "description": "Test profile for unit verification",
    }
    # Validate against schema
    validate_document(profile_data, "verification-profile.schema.json")
    profile = load_profile(profile_data)
    assert profile.profile_id == "test-strict-profile"

    # Deterministic digest
    digest1 = compute_profile_digest(profile)
    digest2 = compute_profile_digest(profile_data)
    assert digest1 == digest2
    assert is_valid_digest(digest1)

    # Reordering keys does not change digest due to JCS
    reordered = {
        "description": "Test profile for unit verification",
        "parameters": {"max_archive_size_bytes": 1048576},
        "optional_checks": ["application_signature"],
        "required_checks": ["archive_safety", "manifest_structure", "member_digests"],
        "target_format": "oept-bundle/0.1",
        "profile_version": "0.1.0",
        "profile_id": "test-strict-profile",
        "protocol_version": "oev-profile/0.1",
    }
    assert compute_profile_digest(reordered) == digest1


def test_profile_schema_invalid():
    # Missing required field
    with pytest.raises(SchemaValidationError):
        validate_document({"profile_id": "bad"}, "verification-profile.schema.json")

    # Extra unknown property
    with pytest.raises(SchemaValidationError):
        validate_document(
            {
                "protocol_version": "oev-profile/0.1",
                "profile_id": "test",
                "profile_version": "0.1",
                "target_format": "fmt",
                "required_checks": ["c1"],
                "unknown_prop": 123,
            },
            "verification-profile.schema.json",
        )


def test_receipt_digest_recursion_rule():
    receipt = VerificationReceipt(
        receipt_id="00000000-0000-4000-8000-000000000001",
        protocol_version="oev-receipt/0.1",
        recorded_verification_time="2026-01-01T00:00:00Z",
        package=PackageReference(digest="sha256:" + "a" * 64, format="oept-bundle/0.1"),
        profile=ProfileReference(
            profile_id="p1", profile_version="0.1", profile_digest="sha256:" + "b" * 64
        ),
        verifier=VerifierIdentity(software="oev-test", version="0.1.0"),
        trust_inputs=[TrustInput(trust_id="k1", type="public_key", digest="sha256:" + "c" * 64)],
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.PASS),
        ],
        limitations=[],
        overall_result=OverallResult.TECHNICAL_CHECKS_PASSED,
    )

    finalized = finalize_receipt(receipt)
    assert finalized.receipt_digest.startswith("sha256:")
    is_valid, declared, recomputed = verify_receipt_digest(finalized)
    assert is_valid
    assert declared == recomputed

    # Mutating receipt_digest in the dictionary MUST NOT change recomputed digest
    d = finalized.to_dict()
    d["receipt_digest"] = "sha256:" + "f" * 64
    valid, _, recomputed_after = verify_receipt_digest(d)
    assert not valid
    assert recomputed_after == finalized.receipt_digest

    # Mutating an actual content field MUST change recomputed digest
    d_content_tampered = finalized.to_dict()
    d_content_tampered["checks"][0]["status"] = "FAIL"
    valid_tampered, _, recomputed_tampered = verify_receipt_digest(d_content_tampered)
    assert not valid_tampered
    assert recomputed_tampered != finalized.receipt_digest


def test_overall_result_aggregation_contract():
    req = ["archive_safety", "member_digests", "application_signature"]
    opt = ["rule_trace_integrity"]

    # 1. All required PASS, optional PASS -> TECHNICAL_CHECKS_PASSED
    res = aggregate_overall_result(
        required_checks=req,
        optional_checks=opt,
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.PASS),
            CheckResult(check_id="application_signature", category="sig", status=CheckStatus.PASS),
            CheckResult(check_id="rule_trace_integrity", category="trace", status=CheckStatus.PASS),
        ],
    )
    assert res == OverallResult.TECHNICAL_CHECKS_PASSED

    # 2. Required check FAIL -> TECHNICAL_CHECKS_FAILED
    res = aggregate_overall_result(
        required_checks=req,
        optional_checks=opt,
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.FAIL),
            CheckResult(check_id="application_signature", category="sig", status=CheckStatus.PASS),
        ],
    )
    assert res == OverallResult.TECHNICAL_CHECKS_FAILED

    # 3. Required check is UNVERIFIED (e.g. required signature on unsigned package) -> PROFILE_UNSATISFIED (NOT PARTIAL!)
    res = aggregate_overall_result(
        required_checks=req,
        optional_checks=opt,
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.PASS),
            CheckResult(
                check_id="application_signature", category="sig", status=CheckStatus.UNVERIFIED
            ),
        ],
    )
    assert res == OverallResult.PROFILE_UNSATISFIED

    # 4. Required check is NOT_RUN or UNSUPPORTED -> PROFILE_UNSATISFIED
    res = aggregate_overall_result(
        required_checks=req,
        optional_checks=opt,
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.PASS),
            CheckResult(
                check_id="application_signature", category="sig", status=CheckStatus.NOT_RUN
            ),
        ],
    )
    assert res == OverallResult.PROFILE_UNSATISFIED

    # 5. Required checks PASS, but optional check is FAIL -> TECHNICAL_CHECKS_PARTIAL
    res = aggregate_overall_result(
        required_checks=["archive_safety", "member_digests"],
        optional_checks=["rule_trace_integrity"],
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.PASS),
            CheckResult(check_id="rule_trace_integrity", category="trace", status=CheckStatus.FAIL),
        ],
    )
    assert res == OverallResult.TECHNICAL_CHECKS_PARTIAL

    # 6. Required checks PASS, optional checks PASS, but limitations exist -> TECHNICAL_CHECKS_PARTIAL
    res = aggregate_overall_result(
        required_checks=["archive_safety", "member_digests"],
        optional_checks=[],
        checks=[
            CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
            CheckResult(check_id="member_digests", category="integrity", status=CheckStatus.PASS),
        ],
        limitations=[
            Limitation(code="UNCHECKED_ZIP_COMMENT", description="ZIP comment was not analyzed")
        ],
    )
    assert res == OverallResult.TECHNICAL_CHECKS_PARTIAL

    # 7. Execution interrupted -> EXECUTION_INCOMPLETE
    res = aggregate_overall_result(
        required_checks=req,
        optional_checks=opt,
        checks=[],
        execution_interrupted=True,
    )
    assert res == OverallResult.EXECUTION_INCOMPLETE
