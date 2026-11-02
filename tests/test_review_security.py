"""Regression coverage for pack containment, receipt types, and replay inputs."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from oev.canonical import canonicalize_json, safe_json_loads
from oev.decision_pack import build_pack, compute_pack_digest
from oev.dsse import DsseError
from oev.engine import execute_verification
from oev.fileio import read_bounded_file
from oev.inspect import inspect_receipt_data
from oev.models import VerificationProfile
from oev.pack_verifier import verify_pack_offline
from oev.receipts import compute_receipt_digest
from oev.reverify import reverify_package

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance/fixtures/01-valid-oept-pass"
NEGATIVE = ROOT / "conformance/review-regressions"


def copy_pack(tmp_path: Path) -> Path:
    out = tmp_path / "pack"
    shutil.copytree(ROOT / "examples/demo-case-001", out)
    return out


def rewrite_member(pack: Path, name: str, document: object) -> None:
    from oev.hashing import sha256_bytes

    body = canonicalize_json(document)
    (pack / name).write_bytes(body)
    manifest = json.loads((pack / "manifest.json").read_bytes())
    for member in manifest["members"]:
        if member["path"] == name:
            member["sha256"] = sha256_bytes(body)
            member["size_bytes"] = len(body)
    manifest["pack_digest"] = compute_pack_digest(manifest)
    (pack / "manifest.json").write_bytes(canonicalize_json(manifest))
    (pack / "manifest.dsse.json").unlink(missing_ok=True)


def test_symlink_artifact_refused_without_reading_target(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    victim = tmp_path / "outside.txt"
    victim.write_bytes(b"private sentinel")
    artifact = next((pack / "artifacts").rglob("*.txt"))
    artifact.unlink()
    artifact.symlink_to(victim)
    with patch.object(Path, "read_bytes", side_effect=AssertionError("must not read any payload")):
        result = verify_pack_offline(pack)
    assert result.overall == "PACK_INVALID"
    assert any("symlink" in note.lower() for note in result.structure_errors)


def test_manifest_traversal_never_reads_outside_root(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    manifest = json.loads((pack / "manifest.json").read_bytes())
    item = next(m for m in manifest["members"] if m["role"] == "artifact")
    item["path"] = json.loads((NEGATIVE / "manifest-traversal.json").read_text())["path"]
    manifest["pack_digest"] = compute_pack_digest(manifest)
    (pack / "manifest.json").write_bytes(canonicalize_json(manifest))
    original = read_bounded_file

    def guarded(path, *args):
        assert tmp_path / "outside.txt" != Path(path).resolve()
        return original(path, *args)

    with patch("oev.pack_verifier.read_bounded_file", side_effect=guarded):
        result = verify_pack_offline(pack)
    assert result.overall == "PACK_INVALID"


def test_self_consistent_schema_invalid_core_member_refused(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    data = json.loads((pack / "facts.json").read_bytes())
    data["facts"] = json.loads((NEGATIVE / "core-schema-invalid.json").read_text())["facts"]
    rewrite_member(pack, "facts.json", data)
    result = verify_pack_offline(pack)
    assert result.overall == "PACK_INVALID"
    assert any(m.path == "facts.json" and m.status == "UNREADABLE" for m in result.member_results)


def test_pack_with_noncanonical_number_returns_negative_result(tmp_path: Path) -> None:
    pack = copy_pack(tmp_path)
    data = json.loads((pack / "manifest.json").read_bytes())
    data["untrusted_number"] = 9007199254740992
    (pack / "manifest.json").write_text(json.dumps(data))
    assert verify_pack_offline(pack).overall == "PACK_INVALID"


def test_builder_refuses_artifact_source_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(ROOT / "examples/demo-case-001", source)
    victim = tmp_path / "outside.txt"
    victim.write_text("outside")
    (source / "artifacts/link.txt").symlink_to(victim)
    with pytest.raises(ValueError, match="Symlink"):
        build_pack(source, tmp_path / "built", "review")


def test_wrong_dsse_payload_type_cannot_be_inspected_or_reverified() -> None:
    envelope = json.loads((NEGATIVE / "receipt-wrong-type.dsse.json").read_bytes())
    with pytest.raises(DsseError, match="payloadType"):
        inspect_receipt_data(envelope)
    with pytest.raises(DsseError, match="payloadType"):
        reverify_package((FIXTURE / "package.zip").read_bytes(), envelope, FIXTURE / "profile.json")


def test_bounded_input_refused_before_read(tmp_path: Path) -> None:
    source = tmp_path / "big.json"
    source.write_bytes(b" " * 100)
    with (
        patch.object(Path, "open", side_effect=AssertionError("must reject before reading")),
        pytest.raises(ValueError, match="size limit"),
    ):
        read_bounded_file(source, limit=10)


def test_deep_json_returns_input_error() -> None:
    with pytest.raises(ValueError, match="nesting"):
        safe_json_loads("[" * 2000 + "0" + "]" * 2000)


def test_reverify_detects_rewritten_overall_optional_checks_and_trust_inputs() -> None:
    pytest.importorskip("oept")
    package = (FIXTURE / "package.zip").read_bytes()
    keys = json.loads((FIXTURE / "package-trust-keys.json").read_bytes())
    profile = VerificationProfile(
        protocol_version="oev-profile/0.1",
        profile_id="review",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=["archive_safety"],
        optional_checks=["member_digests"],
    )
    receipt, _ = execute_verification(package, profile, package_trust_keys=keys)
    mutations: list[tuple[Callable[[dict[str, Any]], None], str]] = [
        (lambda d: d.update(overall_result="TECHNICAL_CHECKS_FAILED"), "overall_result"),
        (
            lambda d: d.update(
                checks=[c for c in d["checks"] if c["check_id"] != "member_digests"]
            ),
            "member_digests",
        ),
        (lambda d: d.update(trust_inputs=[]), "trust_inputs"),
    ]
    for mutate, expected_id in mutations:
        data = receipt.to_dict()
        mutate(data)
        data["receipt_digest"] = compute_receipt_digest(data)
        report = reverify_package(package, data, profile, package_trust_keys=keys)
        assert report.reverification_result == "MISMATCH"
        assert any(d["check_id"] == expected_id for d in report.check_differences)


def test_malformed_package_cannot_pass_archive_only_profile() -> None:
    pytest.importorskip("oept")
    profile = VerificationProfile(
        protocol_version="oev-profile/0.1",
        profile_id="safety",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=["archive_safety"],
    )
    receipt, _ = execute_verification(b"not a zip", profile)
    assert receipt.overall_result != "TECHNICAL_CHECKS_PASSED"
    assert receipt.checks[0].status == "NOT_RUN"


def test_receipt_explicit_missing_pack_does_not_pass(tmp_path: Path) -> None:
    from oev.pack_verifier import build_pack_verification_receipt, verify_pack_receipt

    pack = copy_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack))
    result = verify_pack_receipt(receipt, pack_dir=tmp_path / "missing-pack")
    assert result.overall == "RECEIPT_INVALID"


def test_receipt_explicit_symlink_pack_does_not_pass(tmp_path: Path) -> None:
    from oev.pack_verifier import build_pack_verification_receipt, verify_pack_receipt

    pack = copy_pack(tmp_path)
    receipt = build_pack_verification_receipt(verify_pack_offline(pack))
    alias = tmp_path / "alias"
    alias.symlink_to(pack, target_is_directory=True)
    assert verify_pack_receipt(receipt, pack_dir=alias).overall == "RECEIPT_INVALID"


def test_json_depth_boundary_is_exact() -> None:
    assert safe_json_loads("[" * 128 + "0" + "]" * 128)
    with pytest.raises(ValueError, match="nesting"):
        safe_json_loads("[" * 129 + "0" + "]" * 129)
