# SPDX-License-Identifier: Apache-2.0

"""CLI must fail cleanly (no traceback) when the package adapter dependency is absent.

README promises: "If OEPT is not installed, the OEVP protocol core remains fully
functional." Verifying an OEPT-format bundle without the optional adapter dependency
must therefore produce a clean error message and exit code 1, not an unhandled
exception.
"""

import json
from pathlib import Path

import pytest

import oev.adapters.oept as oept_adapter_module
from oev.adapters.base import OptionalDependencyMissingError
from oev.cli import main

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "conformance" / "fixtures"


@pytest.fixture
def sample_profile_file(tmp_path: Path) -> Path:
    p_data = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "missing-adapter-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": ["archive_safety", "manifest_structure", "member_digests"],
    }
    p_path = tmp_path / "profile.json"
    p_path.write_text(json.dumps(p_data), encoding="utf-8")
    return p_path


def test_cli_verify_clean_error_when_adapter_dependency_missing(
    tmp_path: Path,
    sample_profile_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_require_oept() -> None:
        raise OptionalDependencyMissingError(
            "OEPT is not installed. Install with 'pip install oev[oept]'."
        )

    monkeypatch.setattr(oept_adapter_module, "_require_oept", fake_require_oept)

    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    ret = main(
        [
            "verify",
            str(bundle),
            "--profile",
            str(sample_profile_file),
            "--out",
            str(tmp_path / "receipt.json"),
        ]
    )

    captured = capsys.readouterr()
    assert ret == 1
    assert "Error: OEPT is not installed" in captured.err
    assert not (tmp_path / "receipt.json").exists()


def test_cli_reverify_clean_error_when_adapter_dependency_missing(
    tmp_path: Path,
    sample_profile_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from oev.canonical import canonicalize_json
    from oev.hashing import sha256_bytes
    from oev.models import (
        CheckResult,
        CheckStatus,
        OverallResult,
        PackageReference,
        ProfileReference,
        VerificationReceipt,
        VerifierIdentity,
    )
    from oev.profiles import compute_profile_digest, load_profile
    from oev.receipts import finalize_receipt

    profile = load_profile(sample_profile_file)
    bundle = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
    package_bytes = bundle.read_bytes()

    # Build a fully valid historical receipt without touching the adapter, so that
    # re-verification passes its digest checks and reaches adapter re-execution.
    receipt = finalize_receipt(
        VerificationReceipt(
            receipt_id="00000000-0000-4000-8000-000000000099",
            recorded_verification_time="2026-01-01T00:00:00Z",
            package=PackageReference(
                digest=sha256_bytes(package_bytes),
                format="oept-bundle/0.1",
                size_bytes=len(package_bytes),
            ),
            profile=ProfileReference(
                profile_id=profile.profile_id,
                profile_version=profile.profile_version,
                profile_digest=compute_profile_digest(profile),
            ),
            verifier=VerifierIdentity(software="oev-test", version="0.2.0"),
            trust_inputs=[],
            checks=[
                CheckResult(check_id=cid, category="test", status=CheckStatus.PASS)
                for cid in profile.required_checks
            ],
            limitations=[],
            overall_result=OverallResult.TECHNICAL_CHECKS_PASSED,
        )
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        canonicalize_json(receipt.to_dict(include_digest=True)).decode("utf-8"),
        encoding="utf-8",
    )

    def fake_require_oept() -> None:
        raise OptionalDependencyMissingError(
            "OEPT is not installed. Install with 'pip install oev[oept]'."
        )

    monkeypatch.setattr(oept_adapter_module, "_require_oept", fake_require_oept)

    ret = main(
        [
            "reverify",
            str(bundle),
            str(receipt_path),
            "--profile",
            str(sample_profile_file),
        ]
    )

    captured = capsys.readouterr()
    assert ret == 1
    assert "Error: OEPT is not installed" in captured.err
