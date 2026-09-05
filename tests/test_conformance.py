import json
from pathlib import Path

from oev.engine import execute_verification
from oev.inspect import inspect_receipt_file
from oev.models import CheckStatus, OverallResult
from oev.profiles import load_profile
from oev.reverify import reverify_package
from oev.trust import TrustStore

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "conformance" / "fixtures"


def test_conformance_fixture_01_valid_oept_pass():
    fix_dir = FIXTURES_DIR / "01-valid-oept-pass"
    package_bytes = (fix_dir / "package.zip").read_bytes()
    profile = load_profile(fix_dir / "profile.json")
    with open(fix_dir / "package-trust-keys.json") as f:
        pkg_keys = json.load(f)

    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    receipt, _ = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
        package_trust_keys=pkg_keys,
    )

    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_PASSED
    actual_overall = (
        receipt.overall_result.value
        if hasattr(receipt.overall_result, "value")
        else str(receipt.overall_result)
    )
    assert actual_overall == expected["overall_result"]

    # Verify each check matches expected PASS
    checks_by_id = {c.check_id: c.status for c in receipt.checks}
    for chk_id, exp_status in expected["checks"].items():
        actual_st = checks_by_id.get(chk_id)
        assert actual_st == CheckStatus(exp_status)

    # Inspect the pre-generated signed receipt in fixture
    trust_store = TrustStore.from_file(fix_dir / "verifier-trust-keys.json")
    inspection = inspect_receipt_file(
        fix_dir / "receipt.dsse.json", verifier_trust_store=trust_store
    )
    assert inspection.receipt_digest_valid is True
    assert inspection.is_trusted_signer is True
    assert inspection.crypto_valid is True
    assert inspection.trusted_signer_key_id == expected["trusted_verifier_key_id"]


def test_conformance_fixture_01_raw_crypto_independent_verification():
    """Anti-cheating test: verifies fixture 01 DSSE envelope and PAE using only raw stdlib and cryptography."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    fix_dir = FIXTURES_DIR / "01-valid-oept-pass"
    with open(fix_dir / "receipt.dsse.json", "rb") as f:
        env = json.loads(f.read())

    ptype = env["payloadType"]
    pbytes = base64.b64decode(env["payload"])
    pae = (
        b"DSSEv1 "
        + str(len(ptype.encode("utf-8"))).encode("ascii")
        + b" "
        + ptype.encode("utf-8")
        + b" "
        + str(len(pbytes)).encode("ascii")
        + b" "
        + pbytes
    )
    sig_bytes = base64.b64decode(env["signatures"][0]["sig"])

    with open(fix_dir / "verifier-trust-keys.json", "rb") as f:
        vkeys = json.loads(f.read())
    pem_bytes = vkeys[0]["public_key_pem"].encode("utf-8")
    pub = load_pem_public_key(pem_bytes)
    assert isinstance(pub, Ed25519PublicKey)
    pub.verify(sig_bytes, pae)


def test_conformance_fixture_02_tampered_package():
    fix_dir = FIXTURES_DIR / "02-tampered-package"
    package_bytes = (fix_dir / "package.zip").read_bytes()
    profile = load_profile(fix_dir / "profile.json")

    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    receipt, _ = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
    )

    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    actual_overall = (
        receipt.overall_result.value
        if hasattr(receipt.overall_result, "value")
        else str(receipt.overall_result)
    )
    assert actual_overall == expected["overall_result"]

    checks_by_id = {c.check_id: c.status for c in receipt.checks}
    for chk_id, exp_status in expected["checks"].items():
        actual_st = checks_by_id.get(chk_id)
        assert actual_st == CheckStatus(exp_status)


def test_conformance_fixture_03_required_signature_unsatisfied():
    fix_dir = FIXTURES_DIR / "03-required-signature-unsatisfied"
    package_bytes = (fix_dir / "package.zip").read_bytes()
    profile = load_profile(fix_dir / "profile.json")

    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    receipt, _ = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
    )

    assert receipt.overall_result == OverallResult.PROFILE_UNSATISFIED
    actual_overall = (
        receipt.overall_result.value
        if hasattr(receipt.overall_result, "value")
        else str(receipt.overall_result)
    )
    assert actual_overall == expected["overall_result"]

    checks_by_id = {c.check_id: c.status for c in receipt.checks}
    for chk_id, exp_status in expected["checks"].items():
        actual_st = checks_by_id.get(chk_id)
        assert actual_st == CheckStatus(exp_status)


def test_conformance_fixture_04_tampered_receipt():
    fix_dir = FIXTURES_DIR / "04-tampered-receipt"
    trust_store = TrustStore.from_file(fix_dir / "verifier-trust-keys.json")

    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    inspection = inspect_receipt_file(
        fix_dir / "receipt.dsse.json", verifier_trust_store=trust_store
    )
    assert inspection.is_trusted_signer is False
    assert inspection.crypto_valid is False
    assert inspection.receipt_digest_valid is False
    assert inspection.is_trusted_signer == expected["is_trusted_signer"]
    assert inspection.crypto_valid == expected["crypto_valid"]
    assert inspection.receipt_digest_valid == expected["receipt_digest_valid"]


def test_conformance_fixture_05_reverify_package_mismatch():
    fix_dir = FIXTURES_DIR / "05-reverify-package-mismatch"
    package_bytes = (fix_dir / "package.zip").read_bytes()
    profile = load_profile(fix_dir / "profile.json")

    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    report = reverify_package(
        package_bytes=package_bytes,
        receipt_source=fix_dir / "receipt.dsse.json",
        profile_source=profile,
    )

    assert report.package_digest_match is False
    assert report.reverification_result == "MISMATCH"
    assert report.package_digest_match == expected["package_digest_match"]
    assert report.reverification_result == expected["reverification_result"]
