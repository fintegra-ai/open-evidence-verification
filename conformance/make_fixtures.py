"""Generate the five pre-application MVP conformance fixtures deterministically."""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

from oev.canonical import canonicalize_json
from oev.engine import execute_verification
from oev.models import VerificationProfile
from oev.signing import generate_ed25519_keypair

ROOT = Path(__file__).resolve().parent
FIXTURES_DIR = ROOT / "fixtures"
OEPT_DIR = Path("/Users/investintech/Developer/open-evidence-provenance/conformance/fixtures")


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # Deterministic verifier test keypair
    priv_pem, pub_pem = generate_ed25519_keypair()
    verifier_trust_keys = [
        {"key_id": "test-verifier-2026", "public_key_pem": pub_pem.decode("utf-8")}
    ]

    # Common strict profile (requires application signature)
    strict_profile = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "strict-conformance-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": [
            "archive_safety",
            "manifest_structure",
            "member_digests",
            "application_signature",
        ],
        "optional_checks": [],
        "parameters": {},
        "description": "Strict profile requiring safe archive, manifest, member digests, and application signature",
    }

    # -------------------------------------------------------------
    # FIXTURE 01: 01-valid-oept-pass
    # -------------------------------------------------------------
    f1_dir = FIXTURES_DIR / "01-valid-oept-pass"
    f1_dir.mkdir(exist_ok=True)
    bundle_01_src = OEPT_DIR / "02-valid-signed" / "bundle.zip"
    bundle_01_keys_src = OEPT_DIR / "02-valid-signed" / "trust-keys.json"

    shutil.copy(bundle_01_src, f1_dir / "package.zip")
    shutil.copy(bundle_01_keys_src, f1_dir / "package-trust-keys.json")
    (f1_dir / "profile.json").write_text(
        canonicalize_json(strict_profile).decode("utf-8"), encoding="utf-8"
    )
    (f1_dir / "verifier-trust-keys.json").write_text(
        canonicalize_json(verifier_trust_keys).decode("utf-8"), encoding="utf-8"
    )

    with open(f1_dir / "package-trust-keys.json") as f:
        pkg_keys = json.load(f)

    prof_obj = VerificationProfile.from_dict(strict_profile)
    _receipt_01, envelope_01 = execute_verification(
        package_bytes=(f1_dir / "package.zip").read_bytes(),
        profile=prof_obj,
        package_trust_keys=pkg_keys,
        private_key_pem=priv_pem,
        signer_key_id="test-verifier-2026",
    )
    (f1_dir / "receipt.dsse.json").write_text(
        canonicalize_json(envelope_01).decode("utf-8"), encoding="utf-8"
    )
    (f1_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "TECHNICAL_CHECKS_PASSED",
                "receipt_signature_trusted": True,
                "trusted_verifier_key_id": "test-verifier-2026",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "PASS",
                    "application_signature": "PASS",
                },
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 02: 02-tampered-package
    # -------------------------------------------------------------
    f2_dir = FIXTURES_DIR / "02-tampered-package"
    f2_dir.mkdir(exist_ok=True)
    bundle_02_src = OEPT_DIR / "03-tampered-artifact" / "bundle.zip"
    shutil.copy(bundle_02_src, f2_dir / "package.zip")

    profile_02 = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "integrity-check-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": [
            "archive_safety",
            "manifest_structure",
            "member_digests",
        ],
    }
    (f2_dir / "profile.json").write_text(
        canonicalize_json(profile_02).decode("utf-8"), encoding="utf-8"
    )
    (f2_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "TECHNICAL_CHECKS_FAILED",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "FAIL",
                },
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 03: 03-required-signature-unsatisfied
    # -------------------------------------------------------------
    f3_dir = FIXTURES_DIR / "03-required-signature-unsatisfied"
    f3_dir.mkdir(exist_ok=True)
    bundle_03_src = OEPT_DIR / "01-valid-unsigned" / "bundle.zip"
    shutil.copy(bundle_03_src, f3_dir / "package.zip")
    (f3_dir / "profile.json").write_text(
        canonicalize_json(strict_profile).decode("utf-8"), encoding="utf-8"
    )
    (f3_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "overall_result": "PROFILE_UNSATISFIED",
                "checks": {
                    "archive_safety": "PASS",
                    "manifest_structure": "PASS",
                    "member_digests": "PASS",
                    "application_signature": "UNVERIFIED",
                },
                "note": "Required check 'application_signature' was UNVERIFIED on unsigned package",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 04: 04-tampered-receipt
    # -------------------------------------------------------------
    f4_dir = FIXTURES_DIR / "04-tampered-receipt"
    f4_dir.mkdir(exist_ok=True)
    shutil.copy(f1_dir / "verifier-trust-keys.json", f4_dir / "verifier-trust-keys.json")

    # Take receipt 01 and mutate its inner payload
    envelope_data = json.loads((f1_dir / "receipt.dsse.json").read_text(encoding="utf-8"))
    payload_bytes = base64.b64decode(envelope_data["payload"])
    receipt_data = json.loads(payload_bytes.decode("utf-8"))
    # Tamper with the check result inside payload
    receipt_data["checks"][0]["status"] = "FAIL"
    tampered_payload_bytes = canonicalize_json(receipt_data)
    envelope_data["payload"] = base64.b64encode(tampered_payload_bytes).decode("ascii")

    (f4_dir / "receipt.dsse.json").write_text(
        canonicalize_json(envelope_data).decode("utf-8"), encoding="utf-8"
    )
    (f4_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "is_trusted_signer": False,
                "crypto_valid": False,
                "receipt_digest_valid": False,
                "note": "Tampered receipt payload must fail DSSE signature verification and self-digest check",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    # -------------------------------------------------------------
    # FIXTURE 05: 05-reverify-package-mismatch
    # -------------------------------------------------------------
    f5_dir = FIXTURES_DIR / "05-reverify-package-mismatch"
    f5_dir.mkdir(exist_ok=True)
    shutil.copy(f1_dir / "receipt.dsse.json", f5_dir / "receipt.dsse.json")
    shutil.copy(f1_dir / "profile.json", f5_dir / "profile.json")
    # Provide a different package (unsigned bundle instead of signed bundle)
    shutil.copy(bundle_03_src, f5_dir / "package.zip")
    (f5_dir / "expected-result.json").write_text(
        canonicalize_json(
            {
                "reverification_result": "MISMATCH",
                "package_digest_match": False,
                "note": "Package digest mismatch between historic receipt and fresh package bytes",
            }
        ).decode("utf-8"),
        encoding="utf-8",
    )

    print("All 5 conformance fixtures generated successfully.")


if __name__ == "__main__":
    main()
