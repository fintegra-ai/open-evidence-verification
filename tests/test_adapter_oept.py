import json
from pathlib import Path

import pytest

from oev.adapters.oept import is_oept_available
from oev.engine import execute_verification
from oev.models import CheckStatus, OverallResult, VerificationProfile
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore, evaluate_receipt_trust

OEPT_FIXTURES = Path("/Users/investintech/Developer/open-evidence-provenance/conformance/fixtures")


@pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")
def test_oept_adapter_valid_signed_passes():
    bundle_path = OEPT_FIXTURES / "02-valid-signed" / "bundle.zip"
    trust_keys_path = OEPT_FIXTURES / "02-valid-signed" / "trust-keys.json"

    assert bundle_path.is_file()
    assert trust_keys_path.is_file()

    bundle_bytes = bundle_path.read_bytes()
    with open(trust_keys_path, "r", encoding="utf-8") as f:
        trust_keys = json.load(f)

    profile = VerificationProfile(
        protocol_version="oev-profile/0.1",
        profile_id="strict-oept",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=[
            "archive_safety",
            "manifest_structure",
            "member_digests",
            "application_signature",
        ],
    )

    verifier_priv, verifier_pub = generate_ed25519_keypair()

    receipt, envelope = execute_verification(
        package_bytes=bundle_bytes,
        profile=profile,
        package_trust_keys=trust_keys,
        private_key_pem=verifier_priv,
        signer_key_id="verifier-test",
    )

    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PASSED
    for check in receipt.checks:
        assert check.status == CheckStatus.PASS

    # Verify DSSE envelope
    assert envelope is not None
    verifier_trust_store = TrustStore.from_list(
        [{"key_id": "verifier-test", "public_key_pem": verifier_pub.decode("utf-8")}]
    )
    trust_eval = evaluate_receipt_trust(envelope, verifier_trust_store)
    assert trust_eval.is_trusted is True
    assert trust_eval.trusted_key_id == "verifier-test"


@pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")
def test_oept_adapter_unsigned_package_with_required_signature():
    """When a profile REQUIRES application_signature and the package is unsigned,
    the overall result MUST be PROFILE_UNSATISFIED (not PARTIAL, not PASSED).
    """
    bundle_path = OEPT_FIXTURES / "01-valid-unsigned" / "bundle.zip"
    bundle_bytes = bundle_path.read_bytes()

    profile = VerificationProfile(
        protocol_version="oev-profile/0.1",
        profile_id="requires-signature-profile",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=[
            "archive_safety",
            "manifest_structure",
            "member_digests",
            "application_signature",  # REQUIRED!
        ],
    )

    receipt, _ = execute_verification(
        package_bytes=bundle_bytes,
        profile=profile,
        package_trust_keys=None,
    )

    assert receipt.overall_result == OverallResult.PROFILE_UNSATISFIED
    # application_signature check status must be UNVERIFIED
    sig_check = next(c for c in receipt.checks if c.check_id == "application_signature")
    assert sig_check.status == CheckStatus.UNVERIFIED


@pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")
def test_oept_adapter_tampered_package():
    bundle_path = OEPT_FIXTURES / "03-tampered-artifact" / "bundle.zip"
    bundle_bytes = bundle_path.read_bytes()

    profile = VerificationProfile(
        protocol_version="oev-profile/0.1",
        profile_id="standard-profile",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=[
            "archive_safety",
            "manifest_structure",
            "member_digests",
        ],
    )

    receipt, _ = execute_verification(
        package_bytes=bundle_bytes,
        profile=profile,
    )

    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    digest_check = next(c for c in receipt.checks if c.check_id == "member_digests")
    assert digest_check.status == CheckStatus.FAIL
