# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

import pytest

from oev.adapters.oept import is_oept_available
from oev.engine import execute_verification
from oev.inspect import inspect_receipt_file
from oev.models import CheckStatus, OverallResult
from oev.pack_archive import PackArchiveError, extract_pack_archive
from oev.pack_verifier import (
    OVERALL_RECEIPT_VALID,
    verify_pack_offline,
    verify_pack_receipt,
)
from oev.profiles import load_profile
from oev.replay import PACK_HASH_CHANGED, REPLAY_OK, SNAPSHOT_LEAK, replay_snapshot
from oev.reverify import reverify_package
from oev.trust import TrustStore

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "conformance" / "fixtures"

# Fixtures 01-03 execute real package evaluation through the OEPT adapter.
requires_oept = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")


@requires_oept
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
    """Anti-cheating test: verifies fixture 01 DSSE envelope and PAE using only raw stdlib and cryptography.

    Does not require the OEPT adapter: it validates the committed receipt bytes directly.
    """
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


@requires_oept
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


@requires_oept
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


@requires_oept
def test_conformance_fixture_06_signature_invalid():
    """A corrupted signature must FAIL (TECHNICAL_CHECKS_FAILED), not merely be UNVERIFIED.

    This is the key distinction from fixture 03 (unsigned bundle): missing trust context
    yields UNVERIFIED/PROFILE_UNSATISFIED; a present-but-invalid signature yields
    FAIL/TECHNICAL_CHECKS_FAILED.
    """
    fix_dir = FIXTURES_DIR / "06-signature-invalid"
    package_bytes = (fix_dir / "package.zip").read_bytes()
    profile = load_profile(fix_dir / "profile.json")

    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    with open(fix_dir / "package-trust-keys.json") as f:
        pkg_keys = json.load(f)

    receipt, _ = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
        package_trust_keys=pkg_keys,
    )

    assert receipt.overall_result == OverallResult.TECHNICAL_CHECKS_FAILED
    checks_by_id = {c.check_id: c.status for c in receipt.checks}
    for chk_id, exp_status in expected["checks"].items():
        assert checks_by_id.get(chk_id) == CheckStatus(exp_status)


# ---------------------------------------------------------------------------
# Fixtures 07-14: decision pack surface (core-only, from demo-case-001)
# ---------------------------------------------------------------------------


def test_conformance_fixture_07_pack_replay_ok():
    fix_dir = FIXTURES_DIR / "07-pack-replay-ok"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    with open(fix_dir / "pin.json") as f:
        pin = json.load(f)

    result = replay_snapshot(fix_dir / "pack", expected_pack_digest=pin["pack_digest"])

    assert result.replay_status == REPLAY_OK == expected["replay_status"]
    assert result.eligible_fact_ids == expected["eligible_fact_ids"]
    assert all("fact-901" not in fid for fid in result.eligible_fact_ids)


def test_conformance_fixture_08_pack_replay_hash_changed():
    fix_dir = FIXTURES_DIR / "08-pack-replay-hash-changed"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    with open(fix_dir / "pin.json") as f:
        pin = json.load(f)
    assert expected["pinned_pack_digest"] == pin["pack_digest"]

    # The pack copy is internally self-consistent; only the out-of-band pin
    # anchors the original bytes, so replay must refuse.
    result = replay_snapshot(fix_dir / "pack", expected_pack_digest=pin["pack_digest"])

    assert result.replay_status == PACK_HASH_CHANGED == expected["replay_status"]
    assert result.pack_digest != pin["pack_digest"]


def test_conformance_fixture_09_pack_replay_snapshot_leak():
    fix_dir = FIXTURES_DIR / "09-pack-replay-snapshot-leak"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    # No pin: the pack itself verifies, but a recorded run consumed evidence
    # observed after the snapshot capture, so the replay refuses entirely.
    result = replay_snapshot(fix_dir / "pack")

    assert result.replay_status == SNAPSHOT_LEAK == expected["replay_status"]
    assert "fact-901" not in result.eligible_fact_ids
    excluded_ids = {fact.fact_id for fact in result.excluded_facts}
    assert expected["excluded_fact_id"] in excluded_ids


def test_conformance_fixture_10_pack_receipt_roundtrip():
    fix_dir = FIXTURES_DIR / "10-pack-receipt-roundtrip"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    receipt_path = fix_dir / "pack-verification-receipt.json"

    # Third party, receipt bytes only: schema, self-digest, signature state.
    result = verify_pack_receipt(receipt_path)
    assert result.overall == OVERALL_RECEIPT_VALID == expected["receipt_overall"]
    assert result.is_dsse == expected["is_dsse"]
    assert result.receipt_digest_valid == expected["receipt_digest_valid"]
    assert result.receipt["overall"] == expected["recorded_pack_overall"]
    assert result.receipt["signature_state"] == expected["recorded_signature_state"]
    assert result.receipt["receipt_id"] == expected["receipt_id"]
    assert result.receipt["verified_at"] == expected["verified_at"]

    # With the pack on disk, the recorded digest binds to the real manifest.
    bound = verify_pack_receipt(receipt_path, pack_dir=fix_dir / "pack")
    assert bound.pack_binding == expected["pack_binding"]


def test_conformance_fixture_11_pack_signature_not_present():
    fix_dir = FIXTURES_DIR / "11-pack-signature-not-present"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)

    outcome = verify_pack_offline(fix_dir / "pack")

    assert outcome.overall == expected["overall"]
    assert outcome.signature_state == expected["signature_state"]
    assert outcome.check_status("manifest_signature") == expected["manifest_signature_check"]


def test_conformance_fixture_12_pack_signature_invalid():
    fix_dir = FIXTURES_DIR / "12-pack-signature-invalid"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    trust_store = TrustStore.from_file(fix_dir / "verifier-keys.json")

    outcome = verify_pack_offline(fix_dir / "pack", trust_store=trust_store)

    assert outcome.overall == expected["overall"]
    assert outcome.signature_state == expected["signature_state"]
    assert outcome.signature_crypto_valid == expected["signature_crypto_valid"]
    assert outcome.check_status("manifest_signature") == expected["manifest_signature_check"]
    # Present-but-invalid is never confused with unsigned (fixture 11).
    assert outcome.signature_state != "SIGNATURE_NOT_PRESENT"


def test_conformance_fixture_13_archive_traversal_refused(tmp_path):
    fix_dir = FIXTURES_DIR / "13-archive-traversal-refused"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    out_dir = tmp_path / "extracted"

    with pytest.raises(PackArchiveError) as excinfo:
        extract_pack_archive(fix_dir / "hostile.zip", out_dir)

    assert expected["expected_error_contains"] in str(excinfo.value)
    # Validate-before-extract: nothing was written to the extraction root.
    assert not out_dir.exists()


def test_conformance_fixture_14_archive_duplicate_member_refused(tmp_path):
    fix_dir = FIXTURES_DIR / "14-archive-duplicate-member-refused"
    with open(fix_dir / "expected-result.json") as f:
        expected = json.load(f)
    out_dir = tmp_path / "extracted"

    with pytest.raises(PackArchiveError) as excinfo:
        extract_pack_archive(fix_dir / "hostile.zip", out_dir)

    assert expected["expected_error_contains"] in str(excinfo.value)
    assert not out_dir.exists()
