# SPDX-License-Identifier: Apache-2.0

"""CLI end-to-end tests for `oev hea ...` (separate witness process)."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from oev.adapters.oept import is_oept_available
from oev.canonical import canonicalize_json
from oev.signing import generate_ed25519_keypair
from tests.hea_helpers import CLAIMED_TIME, write_trust_store_json

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "conformance" / "fixtures" / "01-valid-oept-pass"
SRC_DIR = REPO_ROOT / "src"


def _run_cli(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    import os

    env = dict(os.environ, PYTHONPATH=str(SRC_DIR))
    return subprocess.run(
        [sys.executable, "-m", "oev.cli", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
        check=False,
    )


def _make_keys(tmp_path: Path) -> dict[str, Path]:
    wit_priv, wit_pub = generate_ed25519_keypair()
    cp_priv, cp_pub = generate_ed25519_keypair()
    (tmp_path / "witness.key").write_bytes(wit_priv)
    (tmp_path / "checkpoint.key").write_bytes(cp_priv)
    write_trust_store_json(
        tmp_path / "witness-keys.json",
        [
            {
                "key_id": "wit-1",
                "public_key_pem": wit_pub.decode(),
                "role": "witness",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-12-31T23:59:59Z",
            }
        ],
    )
    write_trust_store_json(
        tmp_path / "checkpoint-keys.json",
        [
            {
                "key_id": "cp-1",
                "public_key_pem": cp_pub.decode(),
                "role": "checkpoint-signer",
                "not_after": "2027-12-31T23:59:59Z",
            }
        ],
    )
    return {
        "witness_key": tmp_path / "witness.key",
        "checkpoint_key": tmp_path / "checkpoint.key",
        "witness_keys": tmp_path / "witness-keys.json",
        "checkpoint_keys": tmp_path / "checkpoint-keys.json",
    }


def _attest(
    tmp_path: Path, keys: dict[str, Path], out_dir: Path
) -> subprocess.CompletedProcess[str]:
    return _run_cli(
        [
            "hea",
            "attest",
            str(FIXTURE_DIR / "package.zip"),
            "--profile",
            str(FIXTURE_DIR / "profile.json"),
            "--witness-key",
            str(keys["witness_key"]),
            "--witness-key-id",
            "wit-1",
            "--checkpoint-key",
            str(keys["checkpoint_key"]),
            "--checkpoint-key-id",
            "cp-1",
            "--out",
            str(out_dir),
            "--trust-keys",
            str(FIXTURE_DIR / "package-trust-keys.json"),
            "--json",
        ],
        cwd=tmp_path,
    )


def _verify(
    tmp_path: Path,
    keys: dict[str, Path],
    out_dir: Path,
    extra: list[str] | None = None,
    package: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    args = [
        "hea",
        "verify",
        str(package or (FIXTURE_DIR / "package.zip")),
        "--receipt",
        str(out_dir / "receipt.json"),
        "--profile",
        str(FIXTURE_DIR / "profile.json"),
        "--attestations",
        str(out_dir / "attestations"),
        "--log",
        str(out_dir / "execution-log.jsonl"),
        "--checkpoint",
        str(out_dir / "checkpoint.dsse.json"),
        "--witness-keys",
        str(keys["witness_keys"]),
        "--checkpoint-keys",
        str(keys["checkpoint_keys"]),
        "--json",
    ]
    if extra:
        args += extra
    return _run_cli(args, cwd=tmp_path)


def test_cli_attest_then_verify_is_proven(tmp_path: Path) -> None:
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    attest = _attest(tmp_path, keys, out_dir)
    assert attest.returncode == 0, attest.stderr
    summary = json.loads(attest.stdout)
    assert summary["overall_result"] == "TECHNICAL_CHECKS_PASSED"
    assert summary["execution_id"].startswith("exec_")
    assert (out_dir / "receipt.json").is_file()
    assert (out_dir / "execution-log.jsonl").is_file()
    assert (out_dir / "checkpoint.dsse.json").is_file()
    assert (out_dir / "commitment.dsse.json").is_file()
    assert (out_dir / "prebinding.json").is_file()
    assert len(list((out_dir / "attestations").glob("*.dsse.json"))) == 4

    verify = _verify(tmp_path, keys, out_dir)
    assert verify.returncode == 0, verify.stderr
    report = json.loads(verify.stdout)
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"
    assert report["time_not_proven"] is True


def test_cli_verify_with_reverify_reports_both_dimensions(tmp_path: Path) -> None:
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    assert _attest(tmp_path, keys, out_dir).returncode == 0
    verify = _verify(
        tmp_path,
        keys,
        out_dir,
        extra=[
            "--reverify",
            "--trust-keys",
            str(FIXTURE_DIR / "package-trust-keys.json"),
        ],
    )
    assert verify.returncode == 0, verify.stderr
    report = json.loads(verify.stdout)
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"
    assert report["reverification_result"] == "MATCH"


def test_cli_verify_tampered_receipt_fails_closed(tmp_path: Path) -> None:
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    assert _attest(tmp_path, keys, out_dir).returncode == 0
    receipt = json.loads((out_dir / "receipt.json").read_bytes())
    receipt["checks"][0]["status"] = "FAIL"
    (out_dir / "receipt.json").write_bytes(canonicalize_json(receipt))
    verify = _verify(tmp_path, keys, out_dir)
    assert verify.returncode == 1
    report = json.loads(verify.stdout)
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_UNPROVEN"
    assert report["reason"] == "RESULT_CONFLICT"


def test_cli_log_verify_valid_and_tampered(tmp_path: Path) -> None:
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    assert _attest(tmp_path, keys, out_dir).returncode == 0
    good = _run_cli(
        [
            "hea",
            "log",
            "verify",
            str(out_dir / "execution-log.jsonl"),
            "--checkpoint",
            str(out_dir / "checkpoint.dsse.json"),
            "--checkpoint-keys",
            str(keys["checkpoint_keys"]),
            "--json",
        ],
        cwd=tmp_path,
    )
    assert good.returncode == 0, good.stderr
    assert json.loads(good.stdout)["chain_valid"] is True

    lines = (out_dir / "execution-log.jsonl").read_bytes().splitlines()
    del lines[1]
    (out_dir / "execution-log.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    bad = _run_cli(
        [
            "hea",
            "log",
            "verify",
            str(out_dir / "execution-log.jsonl"),
            "--checkpoint",
            str(out_dir / "checkpoint.dsse.json"),
            "--checkpoint-keys",
            str(keys["checkpoint_keys"]),
            "--json",
        ],
        cwd=tmp_path,
    )
    assert bad.returncode == 1
    assert json.loads(bad.stdout)["chain_valid"] is False


def test_cli_revoke_makes_later_verification_fail(tmp_path: Path) -> None:
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    assert _attest(tmp_path, keys, out_dir).returncode == 0
    # The revocation authority is the witness key itself in this test setup.
    revoke = _run_cli(
        [
            "hea",
            "revoke",
            "--key-id",
            "wit-1",
            "--reason",
            "key-compromise",
            "--key",
            str(keys["witness_key"]),
            "--issuer-key-id",
            "wit-1",
            "--issued-at",
            CLAIMED_TIME,
            "--out",
            str(tmp_path / "revocation.dsse.json"),
        ],
        cwd=tmp_path,
    )
    assert revoke.returncode == 0, revoke.stderr
    assert (tmp_path / "revocation.dsse.json").is_file()
    verify = _verify(
        tmp_path,
        keys,
        out_dir,
        extra=[
            "--revocation-list",
            str(tmp_path / "revocation.dsse.json"),
            "--revocation-keys",
            str(keys["witness_keys"]),
        ],
    )
    assert verify.returncode == 1
    report = json.loads(verify.stdout)
    assert report["reason"] == "WITNESS_KEY_REVOKED"


def test_cli_disprove_for_never_executed_id(tmp_path: Path) -> None:
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    assert _attest(tmp_path, keys, out_dir).returncode == 0
    # Build a completeness statement with the checkpoint (log operator) key.

    from oev.execution_log import (
        LogCompleteness,
        parse_checkpoint_envelope,
        sign_completeness_dsse,
    )

    checkpoint = parse_checkpoint_envelope(
        json.loads((out_dir / "checkpoint.dsse.json").read_bytes())
    )
    statement = LogCompleteness(
        log_id="hea-log-001",
        through_seq=checkpoint.checkpoint_seq,
        checkpoint_digest=checkpoint.checkpoint_digest(),
        claimed_time=CLAIMED_TIME,
    )
    completeness = sign_completeness_dsse(
        statement, (tmp_path / "checkpoint.key").read_bytes(), "cp-1"
    )
    (tmp_path / "completeness.dsse.json").write_bytes(canonicalize_json(completeness))
    disprove = _run_cli(
        [
            "hea",
            "disprove",
            "--execution-id",
            "exec_" + "f" * 32,
            "--log",
            str(out_dir / "execution-log.jsonl"),
            "--checkpoint",
            str(out_dir / "checkpoint.dsse.json"),
            "--checkpoint-keys",
            str(keys["checkpoint_keys"]),
            "--completeness",
            str(tmp_path / "completeness.dsse.json"),
            "--completeness-keys",
            str(keys["checkpoint_keys"]),
            "--json",
        ],
        cwd=tmp_path,
    )
    assert disprove.returncode == 0, disprove.stderr
    assert json.loads(disprove.stdout)["historical_execution"] == "HISTORICAL_EXECUTION_DISPROVEN"


def test_cli_attest_refuses_committed_test_only_key(tmp_path: Path) -> None:
    # The OEPT committed test-only key must never serve as a witness key.
    test_key = (
        REPO_ROOT.parent
        / "oept"
        / "conformance"
        / "test-only-keys"
        / "conformance-test-only-signing.key"
    )
    if not test_key.is_file():
        pytest.skip("OEPT test-only key not present in this checkout")
    keys = _make_keys(tmp_path)
    out_dir = tmp_path / "hea-out"
    run = _run_cli(
        [
            "hea",
            "attest",
            str(FIXTURE_DIR / "package.zip"),
            "--profile",
            str(FIXTURE_DIR / "profile.json"),
            "--witness-key",
            str(test_key),
            "--witness-key-id",
            "test-only",
            "--checkpoint-key",
            str(keys["checkpoint_key"]),
            "--checkpoint-key-id",
            "cp-1",
            "--out",
            str(out_dir),
        ],
        cwd=tmp_path,
    )
    assert run.returncode == 1
    assert "test-only" in run.stderr


def test_cli_attest_on_hostile_bundle_proves_the_failure(tmp_path: Path) -> None:
    # A path-traversal bundle fails its checks; HEA attests the FAIL
    # execution (proven failure), it does not hide it or pass it.
    keys = _make_keys(tmp_path)
    hostile = tmp_path / "hostile.zip"
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"escape")
        zf.writestr("manifest.json", b"{}")
    hostile.write_bytes(buf.getvalue())
    out_dir = tmp_path / "hea-hostile"
    run = _run_cli(
        [
            "hea",
            "attest",
            str(hostile),
            "--profile",
            str(FIXTURE_DIR / "profile.json"),
            "--witness-key",
            str(keys["witness_key"]),
            "--witness-key-id",
            "wit-1",
            "--checkpoint-key",
            str(keys["checkpoint_key"]),
            "--checkpoint-key-id",
            "cp-1",
            "--out",
            str(out_dir),
            "--json",
        ],
        cwd=tmp_path,
    )
    # Attestation itself runs (the engine records FAILs); exit 2 = not PASSED.
    assert run.returncode == 2, run.stderr
    summary = json.loads(run.stdout)
    assert summary["overall_result"] != "TECHNICAL_CHECKS_PASSED"
    verify = _verify(tmp_path, keys, out_dir, package=hostile)
    # The failure execution is itself proven: HEA proves execution, not success.
    assert verify.returncode == 0, verify.stderr
    assert json.loads(verify.stdout)["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"
