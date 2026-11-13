# SPDX-License-Identifier: Apache-2.0

"""DISPROVEN end-to-end tests (round 4, worker D).

Covers the production DISPROVEN path built on B2 run artifacts:
the run emits a signed log-completeness statement and a signed
execution completeness statement (executed / NOT_RUN / skipped);
the verifier then answers, for an execution id that never started
and for a check that never ran:

* statement present + log + checkpoint consistent -> DISPROVEN;
* statement absent -> UNPROVEN (absence of evidence, never upgraded);
* statement forged / tampered / inconsistent with the log ->
  REJECTED (controlled rejection, distinct from UNPROVEN).

All data is synthetic; fixtures are the real conformance packages.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from oev.adapters.oept import is_oept_available
from oev.b2_completeness import (
    build_execution_completeness,
    sign_execution_completeness,
    verify_execution_completeness,
)
from oev.b2_disproven import (
    assess_b2_disproven,
    disprove_check_from_b2_run,
    verify_disproven_check,
)
from oev.b2_verify import verify_b2_execution
from oev.b2_witness import B2ReexecutingWitness, run_b2_witnessed_verification
from oev.canonical import canonicalize_json, safe_json_loads
from oev.dsse import parse_dsse_envelope
from oev.execution_log import LogCheckpoint, events_from_jsonl
from oev.hea_verifier import HeaVerificationInputs, verify_historical_execution
from oev.models import CheckResult, CheckStatus, VerificationReceipt
from oev.profiles import load_profile
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore
from tests.hea_helpers import build_valid_hea, hea_inputs

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_01 = REPO_ROOT / "conformance" / "fixtures" / "01-valid-oept-pass"
NOT_BEFORE = "2026-01-01T00:00:00Z"
NOT_AFTER = "2027-12-31T23:59:59Z"


def _key_entry(role: str, key_id: str, pub: bytes) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "key_id": key_id,
        "public_key_pem": pub.decode("utf-8"),
        "role": role,
    }
    if role == "witness":
        entry["not_before"] = NOT_BEFORE
        entry["not_after"] = NOT_AFTER
    if role == "checkpoint-signer":
        entry["not_after"] = NOT_AFTER
    return entry


def _make_b2(tmp_path: Path) -> dict[str, Any]:
    wit_priv, wit_pub = generate_ed25519_keypair()
    cp_priv, cp_pub = generate_ed25519_keypair()
    prod_priv, _prod_pub = generate_ed25519_keypair()
    witness = B2ReexecutingWitness(
        wit_priv,
        key_id="wit-b2-1",
        log_id="hea-b2-log-001",
        log_path=tmp_path / "witness-log.jsonl",
        checkpoint_private_key_pem=cp_priv,
        checkpoint_key_id="cp-b2-1",
    )
    return {
        "witness": witness,
        "wit_priv": wit_priv,
        "wit_pub": wit_pub,
        "cp_priv": cp_priv,
        "cp_pub": cp_pub,
        "prod_priv": prod_priv,
        "witness_store": TrustStore.from_list([_key_entry("witness", "wit-b2-1", wit_pub)]),
        "checkpoint_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
        # Log-operator store: the checkpoint-signer key signs both the
        # checkpoint and the completeness statements.
        "operator_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
    }


def _run_b2(ctx: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    trust_keys = json.loads((FIXTURE_01 / "package-trust-keys.json").read_text())
    out_dir = tmp_path / "b2-out"
    summary = run_b2_witnessed_verification(
        FIXTURE_01 / "package.zip",
        FIXTURE_01 / "profile.json",
        ctx["witness"],
        out_dir,
        package_trust_keys=trust_keys,
        receipt_signing_key_pem=ctx["prod_priv"],
        receipt_signer_key_id="prod-1",
        witness_public_pem=ctx["wit_pub"],
    )
    return {"summary": summary, "out_dir": out_dir}


def _profile_check_ids() -> list[str]:
    profile = load_profile(FIXTURE_01 / "profile.json")
    return list(dict.fromkeys(profile.required_checks + profile.optional_checks))


# ---------------------------------------------------------------------------
# The run emits both completeness artifacts, correctly bucketed
# ---------------------------------------------------------------------------


def test_b2_run_emits_signed_completeness_statements(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    out_dir = run["out_dir"]
    assert (out_dir / "log-completeness.dsse.json").is_file()
    assert (out_dir / "b2-completeness.dsse.json").is_file()
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    assert manifest["log_completeness"]["emitted"] is True
    assert manifest["execution_completeness"]["emitted"] is True
    statement = manifest["execution_completeness"]["statement"]
    assert statement is not None
    assert sorted(statement["executed"]) == sorted(run["summary"]["attested_checks"])
    assert statement["not_run"] == []
    assert statement["skipped"] == []
    assert statement["checkpoint_digest"].startswith("sha256:")
    assert statement["code_digest"] == manifest["code_digest"]
    # The code-digest document is bound to the same run.
    assert manifest["code_digest_document"]["code_digest"] == manifest["code_digest"]
    assert manifest["code_digest_document"]["policy_digest"] == statement["policy_digest"]


def test_execution_completeness_statement_verifies(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    out_dir = run["out_dir"]
    envelope = safe_json_loads((out_dir / "b2-completeness.dsse.json").read_bytes())
    checkpoint = safe_json_loads((out_dir / "checkpoint.dsse.json").read_bytes())
    checkpoint_digest = LogCheckpoint.from_dict(
        json.loads(parse_dsse_envelope(checkpoint)[1].decode("utf-8"))
    ).checkpoint_digest()
    statement, ok, note = verify_execution_completeness(
        envelope,
        ctx["operator_store"],
        expected_checkpoint_digest=checkpoint_digest,
        expected_execution_id=run["summary"]["execution_id"],
        profile_check_ids=_profile_check_ids(),
        attested_check_ids=run["summary"]["attested_checks"],
    )
    assert ok, note
    assert statement is not None
    assert statement.execution_id == run["summary"]["execution_id"]


def test_b2_verify_accepts_run_with_completeness(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    out_dir = run["out_dir"]
    # Rebuild HEA inputs the same way test_hea_b2 does.
    receipt_data = safe_json_loads((out_dir / "receipt.json").read_bytes())
    if isinstance(receipt_data, dict) and "payload" in receipt_data:
        _pt, payload_bytes, _sigs = parse_dsse_envelope(receipt_data)
        receipt_data = safe_json_loads(payload_bytes.decode("utf-8"))
    receipt = VerificationReceipt.from_dict(dict(receipt_data))
    profile = load_profile(FIXTURE_01 / "profile.json")
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    inputs = HeaVerificationInputs(
        package_bytes=(FIXTURE_01 / "package.zip").read_bytes(),
        receipt=receipt,
        profile=profile,
        attestations=[
            safe_json_loads(p.read_bytes())
            for p in sorted((out_dir / "attestations").glob("*.dsse.json"))
        ],
        commitment_envelope=safe_json_loads((out_dir / "commitment.dsse.json").read_bytes()),
        prebinding=safe_json_loads((out_dir / "prebinding.json").read_bytes()),
        log_events=events_from_jsonl((out_dir / "execution-log.jsonl").read_bytes()),
        checkpoint_envelope=safe_json_loads((out_dir / "checkpoint.dsse.json").read_bytes()),
        inclusion_proofs={
            str(k): [dict(s) for s in v]
            for k, v in dict(manifest.get("inclusion_proofs", {})).items()
        },
        witness_trust_store=ctx["witness_store"],
        checkpoint_trust_store=ctx["checkpoint_store"],
        expected_code_digest=str(manifest.get("code_digest") or ""),
    )
    completeness = safe_json_loads((out_dir / "b2-completeness.dsse.json").read_bytes())
    report = verify_b2_execution(
        inputs,
        execution_completeness_envelope=completeness,
        log_operator_trust_store=ctx["operator_store"],
        expected_code_digest_document=manifest["code_digest_document"],
    )
    assert report["b2_ok"] is True, report
    assert str(report["completeness_status"]).startswith("verified")


def test_b2_verify_rejects_tampered_completeness(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    out_dir = run["out_dir"]
    envelope = safe_json_loads((out_dir / "b2-completeness.dsse.json").read_bytes())
    # Tamper the statement payload (executed list) without re-signing.
    _pt, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    payload = safe_json_loads(payload_bytes.decode("utf-8"))
    payload["executed"] = payload["executed"][:-1]
    tampered = {
        **envelope,
        "payload": base64.b64encode(canonicalize_json(payload)).decode("ascii"),
    }
    receipt_data = safe_json_loads((out_dir / "receipt.json").read_bytes())
    if isinstance(receipt_data, dict) and "payload" in receipt_data:
        _pt2, payload_bytes2, _s2 = parse_dsse_envelope(receipt_data)
        receipt_data = safe_json_loads(payload_bytes2.decode("utf-8"))
    receipt = VerificationReceipt.from_dict(dict(receipt_data))
    profile = load_profile(FIXTURE_01 / "profile.json")
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    inputs = HeaVerificationInputs(
        package_bytes=(FIXTURE_01 / "package.zip").read_bytes(),
        receipt=receipt,
        profile=profile,
        attestations=[
            safe_json_loads(p.read_bytes())
            for p in sorted((out_dir / "attestations").glob("*.dsse.json"))
        ],
        commitment_envelope=safe_json_loads((out_dir / "commitment.dsse.json").read_bytes()),
        prebinding=safe_json_loads((out_dir / "prebinding.json").read_bytes()),
        log_events=events_from_jsonl((out_dir / "execution-log.jsonl").read_bytes()),
        checkpoint_envelope=safe_json_loads((out_dir / "checkpoint.dsse.json").read_bytes()),
        witness_trust_store=ctx["witness_store"],
        checkpoint_trust_store=ctx["checkpoint_store"],
        expected_code_digest=str(manifest.get("code_digest") or ""),
    )
    report = verify_b2_execution(
        inputs,
        execution_completeness_envelope=tampered,
        log_operator_trust_store=ctx["operator_store"],
    )
    assert report["b2_ok"] is False
    assert "COMPLETENESS_REJECTED" in str(report["b2_reason"])


# ---------------------------------------------------------------------------
# Execution-level DISPROVEN through the unchanged HEA verifier
# ---------------------------------------------------------------------------


def test_disproven_unknown_execution_id(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    result = assess_b2_disproven(
        run["out_dir"],
        "exec_" + "f" * 32,
        package_bytes=(FIXTURE_01 / "package.zip").read_bytes(),
        profile=load_profile(FIXTURE_01 / "profile.json"),
        witness_trust_store=ctx["witness_store"],
        checkpoint_trust_store=ctx["checkpoint_store"],
        log_operator_trust_store=ctx["operator_store"],
    )
    assert result["historical_execution"] == "HISTORICAL_EXECUTION_DISPROVEN", result


def test_disproven_real_execution_id_is_not_disproven(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    result = assess_b2_disproven(
        run["out_dir"],
        run["summary"]["execution_id"],
        package_bytes=(FIXTURE_01 / "package.zip").read_bytes(),
        profile=load_profile(FIXTURE_01 / "profile.json"),
        witness_trust_store=ctx["witness_store"],
        checkpoint_trust_store=ctx["checkpoint_store"],
        log_operator_trust_store=ctx["operator_store"],
    )
    assert result["historical_execution"] == "HISTORICAL_EXECUTION_UNPROVEN", result


def test_disproven_missing_completeness_is_unproven_not_disproven(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    out_dir = run["out_dir"]
    (out_dir / "log-completeness.dsse.json").unlink()
    result = assess_b2_disproven(
        out_dir,
        "exec_" + "f" * 32,
        package_bytes=(FIXTURE_01 / "package.zip").read_bytes(),
        profile=load_profile(FIXTURE_01 / "profile.json"),
        witness_trust_store=ctx["witness_store"],
        checkpoint_trust_store=ctx["checkpoint_store"],
        log_operator_trust_store=ctx["operator_store"],
    )
    assert result["historical_execution"] == "HISTORICAL_EXECUTION_UNPROVEN", result
    assert "completeness" in " ".join(result["notes"]).lower()


def test_disproven_forged_completeness_is_unproven(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    out_dir = run["out_dir"]
    envelope = safe_json_loads((out_dir / "log-completeness.dsse.json").read_bytes())
    _pt, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    payload = safe_json_loads(payload_bytes.decode("utf-8"))
    payload["through_seq"] = 9999
    forged = {
        **envelope,
        "payload": base64.b64encode(canonicalize_json(payload)).decode("ascii"),
    }
    (out_dir / "log-completeness.dsse.json").write_bytes(canonicalize_json(forged))
    result = assess_b2_disproven(
        out_dir,
        "exec_" + "f" * 32,
        package_bytes=(FIXTURE_01 / "package.zip").read_bytes(),
        profile=load_profile(FIXTURE_01 / "profile.json"),
        witness_trust_store=ctx["witness_store"],
        checkpoint_trust_store=ctx["checkpoint_store"],
        log_operator_trust_store=ctx["operator_store"],
    )
    assert result["historical_execution"] == "HISTORICAL_EXECUTION_UNPROVEN", result


# ---------------------------------------------------------------------------
# Per-check DISPROVEN: a check that never ran
# ---------------------------------------------------------------------------


def _build_not_run_bundle(tmp_path: Path) -> dict[str, Any]:
    """A valid HEA bundle whose receipt records one check as NOT_RUN."""
    checks = [
        CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
        CheckResult(
            check_id="manifest_structure", category="structure", status=CheckStatus.NOT_RUN
        ),
    ]
    return build_valid_hea(tmp_path, checks=checks)


def test_disproven_check_never_ran(tmp_path: Path) -> None:
    bundle = _build_not_run_bundle(tmp_path)
    profile_ids = ["archive_safety", "manifest_structure"]
    statement = build_execution_completeness(
        execution_id=bundle["execution_id"],
        checkpoint_digest=LogCheckpoint.from_dict(
            json.loads(parse_dsse_envelope(bundle["checkpoint_envelope"])[1].decode("utf-8"))
        ).checkpoint_digest(),
        code_digest=bundle["code_digest"],
        witness_key_id="wit-1",
        receipt_checks=[
            {"check_id": c.check_id, "status": str(c.status.value)} for c in bundle["checks"]
        ],
        profile_check_ids=profile_ids,
        claimed_time="2026-11-13T07:20:00Z",
    )
    envelope = sign_execution_completeness(statement, bundle["checkpoint_private"], "cp-1")
    outcome, note = verify_disproven_check(
        check_id="manifest_structure",
        execution_id=bundle["execution_id"],
        log_events=list(bundle["log_events"]),
        checkpoint_envelope=bundle["checkpoint_envelope"],
        checkpoint_trust_store=bundle["checkpoint_store"],
        execution_completeness_envelope=envelope,
        log_operator_trust_store=bundle["checkpoint_store"],
        profile_check_ids=profile_ids,
        expected_code_digest=bundle["code_digest"],
    )
    assert outcome == "DISPROVEN", note


def test_disproven_check_executed_is_rejected(tmp_path: Path) -> None:
    bundle = _build_not_run_bundle(tmp_path)
    profile_ids = ["archive_safety", "manifest_structure"]
    statement = build_execution_completeness(
        execution_id=bundle["execution_id"],
        checkpoint_digest=LogCheckpoint.from_dict(
            json.loads(parse_dsse_envelope(bundle["checkpoint_envelope"])[1].decode("utf-8"))
        ).checkpoint_digest(),
        code_digest=bundle["code_digest"],
        witness_key_id="wit-1",
        receipt_checks=[
            {"check_id": c.check_id, "status": str(c.status.value)} for c in bundle["checks"]
        ],
        profile_check_ids=profile_ids,
        claimed_time="2026-11-13T07:20:00Z",
    )
    envelope = sign_execution_completeness(statement, bundle["checkpoint_private"], "cp-1")
    # Claiming the EXECUTED check never ran must be rejected, not DISPROVEN.
    outcome, _note = verify_disproven_check(
        check_id="archive_safety",
        execution_id=bundle["execution_id"],
        log_events=list(bundle["log_events"]),
        checkpoint_envelope=bundle["checkpoint_envelope"],
        checkpoint_trust_store=bundle["checkpoint_store"],
        execution_completeness_envelope=envelope,
        log_operator_trust_store=bundle["checkpoint_store"],
        profile_check_ids=profile_ids,
        expected_code_digest=bundle["code_digest"],
    )
    assert outcome == "REJECTED"


def test_disproven_check_no_statement_is_unproven(tmp_path: Path) -> None:
    bundle = _build_not_run_bundle(tmp_path)
    outcome, _note = verify_disproven_check(
        check_id="manifest_structure",
        execution_id=bundle["execution_id"],
        log_events=list(bundle["log_events"]),
        checkpoint_envelope=bundle["checkpoint_envelope"],
        checkpoint_trust_store=bundle["checkpoint_store"],
        execution_completeness_envelope=None,
        log_operator_trust_store=bundle["checkpoint_store"],
        profile_check_ids=["archive_safety", "manifest_structure"],
    )
    assert outcome == "UNPROVEN"


def test_disproven_check_statement_contradicted_by_log_is_rejected(tmp_path: Path) -> None:
    bundle = _build_not_run_bundle(tmp_path)
    profile_ids = ["archive_safety", "manifest_structure"]
    # Forge a statement that lists the EXECUTED check as not_run and sign
    # it with the real operator key: the log contradiction must still reject it.
    statement = build_execution_completeness(
        execution_id=bundle["execution_id"],
        checkpoint_digest=LogCheckpoint.from_dict(
            json.loads(parse_dsse_envelope(bundle["checkpoint_envelope"])[1].decode("utf-8"))
        ).checkpoint_digest(),
        code_digest=bundle["code_digest"],
        witness_key_id="wit-1",
        receipt_checks=[
            {"check_id": "archive_safety", "status": "NOT_RUN"},
            {"check_id": "manifest_structure", "status": "NOT_RUN"},
        ],
        profile_check_ids=profile_ids,
        claimed_time="2026-11-13T07:20:00Z",
    )
    envelope = sign_execution_completeness(statement, bundle["checkpoint_private"], "cp-1")
    outcome, note = verify_disproven_check(
        check_id="archive_safety",
        execution_id=bundle["execution_id"],
        log_events=list(bundle["log_events"]),
        checkpoint_envelope=bundle["checkpoint_envelope"],
        checkpoint_trust_store=bundle["checkpoint_store"],
        execution_completeness_envelope=envelope,
        log_operator_trust_store=bundle["checkpoint_store"],
        profile_check_ids=profile_ids,
        expected_code_digest=bundle["code_digest"],
    )
    assert outcome == "REJECTED", note


def test_disproven_check_tampered_log_is_rejected(tmp_path: Path) -> None:
    bundle = _build_not_run_bundle(tmp_path)
    profile_ids = ["archive_safety", "manifest_structure"]
    statement = build_execution_completeness(
        execution_id=bundle["execution_id"],
        checkpoint_digest=LogCheckpoint.from_dict(
            json.loads(parse_dsse_envelope(bundle["checkpoint_envelope"])[1].decode("utf-8"))
        ).checkpoint_digest(),
        code_digest=bundle["code_digest"],
        witness_key_id="wit-1",
        receipt_checks=[
            {"check_id": c.check_id, "status": str(c.status.value)} for c in bundle["checks"]
        ],
        profile_check_ids=profile_ids,
        claimed_time="2026-11-13T07:20:00Z",
    )
    envelope = sign_execution_completeness(statement, bundle["checkpoint_private"], "cp-1")
    # Drop the CHECK_COMPLETED event: chain/Merkle no longer match the checkpoint.
    truncated = [e for e in bundle["log_events"] if e.event_type != "CHECK_COMPLETED"]
    outcome, _note = verify_disproven_check(
        check_id="manifest_structure",
        execution_id=bundle["execution_id"],
        log_events=truncated,
        checkpoint_envelope=bundle["checkpoint_envelope"],
        checkpoint_trust_store=bundle["checkpoint_store"],
        execution_completeness_envelope=envelope,
        log_operator_trust_store=bundle["checkpoint_store"],
        profile_check_ids=profile_ids,
        expected_code_digest=bundle["code_digest"],
    )
    assert outcome == "REJECTED"


def test_disproven_check_from_b2_run_wrapper(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    # Fixture 01 runs every check, so no check is DISPROVEN here — the
    # wrapper must say REJECTED for an executed check, not DISPROVEN.
    outcome, _note = disprove_check_from_b2_run(
        run["out_dir"],
        "member_digests",
        checkpoint_trust_store=ctx["checkpoint_store"],
        log_operator_trust_store=ctx["operator_store"],
        profile=load_profile(FIXTURE_01 / "profile.json"),
    )
    assert outcome == "REJECTED"


def test_disproven_genuine_execution_is_unproven_without_log(tmp_path: Path) -> None:
    """Without a log/checkpoint at all, a genuine-looking claim stays UNPROVEN."""
    bundle = _build_not_run_bundle(tmp_path)
    result = verify_historical_execution(
        hea_inputs(bundle, attestations=[], claimed_execution_id="exec_" + "0" * 32)
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "NO_ATTESTATION"
