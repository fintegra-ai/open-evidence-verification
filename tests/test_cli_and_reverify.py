# SPDX-License-Identifier: Apache-2.0

import base64
import json
from pathlib import Path

import pytest

from oev.adapters.oept import is_oept_available
from oev.cli import main
from oev.engine import execute_verification
from oev.models import VerificationProfile
from oev.profiles import load_profile
from oev.receipts import compute_receipt_digest
from oev.reverify import reverify_package
from oev.signing import generate_ed25519_keypair, sign_receipt_dsse

# In-repo conformance fixtures carry byte-stable neutral OEPT bundles.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "conformance" / "fixtures"

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")


@pytest.fixture
def sample_profile_file(tmp_path: Path) -> Path:
    p_data = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "test-cli-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": [
            "archive_safety",
            "manifest_structure",
            "member_digests",
            "application_signature",
        ],
    }
    p_path = tmp_path / "profile.json"
    p_path.write_text(json.dumps(p_data), encoding="utf-8")
    return p_path


def test_cli_verify_inspect_and_reverify_roundtrip(
    tmp_path: Path, sample_profile_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle_path = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    trust_keys_path = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"
    receipt_out = tmp_path / "receipt.dsse.json"

    # Verifier keypair
    v_priv, v_pub = generate_ed25519_keypair()
    v_priv_file = tmp_path / "verifier.key"
    v_priv_file.write_bytes(v_priv)

    verifier_keys_file = tmp_path / "verifier_trust.json"
    verifier_keys_file.write_text(
        json.dumps([{"key_id": "auditor-01", "public_key_pem": v_pub.decode("utf-8")}]),
        encoding="utf-8",
    )

    # 1. oev verify
    ret = main(
        [
            "verify",
            str(bundle_path),
            "--profile",
            str(sample_profile_file),
            "--trust-keys",
            str(trust_keys_path),
            "--sign-receipt",
            str(v_priv_file),
            "--signer-key-id",
            "auditor-01",
            "--out",
            str(receipt_out),
        ]
    )
    assert ret == 0
    assert receipt_out.is_file()

    # 2. oev inspect-receipt
    ret_inspect = main(
        [
            "inspect-receipt",
            str(receipt_out),
            "--verifier-keys",
            str(verifier_keys_file),
        ]
    )
    assert ret_inspect == 0
    out_inspect = capsys.readouterr().out
    assert "Receipt inspection describes a verifier's recorded technical appraisal." in out_inspect
    assert (
        "Technical verification only — not a legal, compliance, or factual conclusion."
        in out_inspect
    )
    assert "Caller Trusted Signer:  YES" in out_inspect

    # 3. oev receipt verify
    ret_rcpt_verify = main(
        [
            "receipt",
            "verify",
            str(receipt_out),
            "--verifier-keys",
            str(verifier_keys_file),
        ]
    )
    assert ret_rcpt_verify == 0

    # 4. oev reverify (success match)
    ret_reverify = main(
        [
            "reverify",
            str(bundle_path),
            str(receipt_out),
            "--profile",
            str(sample_profile_file),
            "--trust-keys",
            str(trust_keys_path),
        ]
    )
    assert ret_reverify == 0
    out_reverify = capsys.readouterr().out
    assert "Re-verification Result:  MATCH" in out_reverify


def test_reverify_package_mismatch(tmp_path: Path, sample_profile_file: Path) -> None:
    bundle_a = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    bundle_b = FIXTURES_DIR / "03-required-signature-unsatisfied" / "package.zip"
    trust_keys = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"
    with open(trust_keys) as f:
        tk_data = json.load(f)

    profile = load_profile(sample_profile_file)
    receipt, _ = execute_verification(
        package_bytes=bundle_a.read_bytes(),
        profile=profile,
        package_trust_keys=tk_data,
    )

    # Re-verify with bundle_b (different package)
    report = reverify_package(
        package_bytes=bundle_b.read_bytes(),
        receipt_source=receipt.to_dict(),
        profile_source=profile,
        package_trust_keys=tk_data,
    )

    assert report.package_digest_match is False
    assert report.reverification_result == "MISMATCH"
    assert any("Package digest mismatch" in n for n in report.notes)


def test_reverify_profile_digest_substitution(tmp_path: Path, sample_profile_file: Path) -> None:
    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    trust_keys = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"
    with open(trust_keys) as f:
        tk_data = json.load(f)

    profile_orig = load_profile(sample_profile_file)
    receipt, _ = execute_verification(
        package_bytes=bundle.read_bytes(),
        profile=profile_orig,
        package_trust_keys=tk_data,
    )

    # Attacker tries to reverify using a modified profile (e.g. dropped check)
    profile_tampered = VerificationProfile(
        protocol_version="oev-profile/0.1",
        profile_id="test-cli-profile",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=["archive_safety"],  # Modified required checks
    )

    report = reverify_package(
        package_bytes=bundle.read_bytes(),
        receipt_source=receipt.to_dict(),
        profile_source=profile_tampered,
        package_trust_keys=tk_data,
    )

    assert report.package_digest_match is True
    assert report.profile_digest_match is False
    assert report.reverification_result == "CANNOT_REPRODUCE"
    assert any("Profile digest mismatch" in n for n in report.notes)


def test_reverify_tampered_receipt_fails_closed(tmp_path: Path, sample_profile_file: Path) -> None:
    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    trust_keys = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"
    with open(trust_keys) as f:
        tk_data = json.load(f)

    profile = load_profile(sample_profile_file)
    receipt, _ = execute_verification(
        package_bytes=bundle.read_bytes(),
        profile=profile,
        package_trust_keys=tk_data,
    )

    # Attacker edits a receipt field (valid receipt_id, plausible content)
    # without recomputing receipt_digest. Every other recorded value still
    # matches a fresh run, so only the self-digest check can expose this.
    receipt_dict = receipt.to_dict()
    tampered = dict(receipt_dict)
    tampered["receipt_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    report = reverify_package(
        package_bytes=bundle.read_bytes(),
        receipt_source=tampered,
        profile_source=profile,
        package_trust_keys=tk_data,
    )

    assert report.reverification_result == "MISMATCH"
    assert report.package_digest_match is False
    assert report.profile_digest_match is False
    assert report.fresh_checks == []
    assert any("self-digest verification failed" in n for n in report.notes)


def test_cli_reverify_tampered_receipt_exit_code(tmp_path: Path, sample_profile_file: Path) -> None:
    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    trust_keys = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"
    with open(trust_keys) as f:
        tk_data = json.load(f)

    profile = load_profile(sample_profile_file)
    receipt, _ = execute_verification(
        package_bytes=bundle.read_bytes(),
        profile=profile,
        package_trust_keys=tk_data,
    )

    receipt_dict = receipt.to_dict()
    tampered = dict(receipt_dict)
    tampered["receipt_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    receipt_file = tmp_path / "tampered-receipt.json"
    receipt_file.write_text(json.dumps(tampered), encoding="utf-8")

    ret = main(
        [
            "reverify",
            str(bundle),
            str(receipt_file),
            "--profile",
            str(sample_profile_file),
            "--trust-keys",
            str(trust_keys),
        ]
    )
    assert ret == 2


def test_cli_reverify_malformed_receipt_clean_error(
    tmp_path: Path, sample_profile_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    broken = tmp_path / "broken.json"
    broken.write_text('{"receipt_id": "x"}', encoding="utf-8")

    ret = main(
        [
            "reverify",
            str(bundle),
            str(broken),
            "--profile",
            str(sample_profile_file),
        ]
    )
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err
    assert "Traceback" not in captured.err


def test_reverify_self_consistent_forgery_matches_by_design(
    tmp_path: Path, sample_profile_file: Path
) -> None:
    """Documented boundary: re-verification proves reproducibility, not authenticity.

    An attacker who rewrites the payload, recomputes receipt_digest, and re-signs
    with their own key produces an internally consistent receipt. Detecting this
    requires receipt authenticity verification ('oev receipt verify' with
    caller-pinned verifier keys), not re-verification.
    """
    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    trust_keys = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"
    with open(trust_keys) as f:
        tk_data = json.load(f)

    profile = load_profile(sample_profile_file)
    _, envelope = execute_verification(
        package_bytes=bundle.read_bytes(),
        profile=profile,
        package_trust_keys=tk_data,
        private_key_pem=generate_ed25519_keypair()[0],
        signer_key_id="auditor-01",
    )
    assert envelope is not None

    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["receipt_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    payload["receipt_digest"] = compute_receipt_digest(payload)
    forged = sign_receipt_dsse(payload, generate_ed25519_keypair()[0], key_id="attacker-01")

    report = reverify_package(
        package_bytes=bundle.read_bytes(),
        receipt_source=forged,
        profile_source=profile,
        package_trust_keys=tk_data,
    )
    assert report.reverification_result == "MATCH"
