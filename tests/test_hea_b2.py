# SPDX-License-Identifier: Apache-2.0

"""Model B2 tests: separate-machine, re-executing witness.

Covers the B2 run (in-process and separate-process witness), the
re-execution comparison that refuses a forged producer PASS, role
separation, code-digest agreement, authorisation, the B2 verify
wrapper (including its refusal to call a Model A bundle "B2"),
replay / omission / log-tamper / witness-compromise detection through
the unchanged HEA verifier, offline verification under a blocked
network, and TSA sidecar tokens (verified / absent / tampered).

The fixtures are the real conformance packages
(``01-valid-oept-pass``: all checks PASS;
``02-tampered-package``: ``member_digests`` FAILs), so the witness
re-execution runs the real engine on real bytes.
"""

from __future__ import annotations

import dataclasses
import json
import socket
from pathlib import Path
from typing import Any

import pytest

from oev import b2_witness as b2_mod
from oev.adapters.oept import is_oept_available
from oev.attestation import compute_attestation_digest, parse_attestation_envelope
from oev.b2_verify import verify_b2_execution
from oev.b2_witness import (
    B2ProcessWitness,
    B2ReexecutingWitness,
    build_b2_attestation_payload,
    check_role_separation,
    run_b2_witnessed_verification,
    to_verifier_authorization,
    validate_witness_authorization,
)
from oev.canonical import safe_json_loads
from oev.execution_log import events_from_jsonl
from oev.hea_verifier import HeaVerificationInputs, verify_historical_execution
from oev.models import CheckStatus, VerificationReceipt
from oev.profiles import load_profile
from oev.receipts import finalize_receipt
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore
from oev.tsa import MockTSA
from oev.witness import WitnessService
from tests.hea_helpers import CLAIMED_TIME, build_valid_hea

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_01 = REPO_ROOT / "conformance" / "fixtures" / "01-valid-oept-pass"
FIXTURE_02 = REPO_ROOT / "conformance" / "fixtures" / "02-tampered-package"
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


def _make_b2(tmp_path: Path, fixture: Path = FIXTURE_01) -> dict[str, Any]:
    """Build keys + a B2 witness (in-process) for a fixture."""
    wit_priv, wit_pub = generate_ed25519_keypair()
    cp_priv, cp_pub = generate_ed25519_keypair()
    prod_priv, prod_pub = generate_ed25519_keypair()
    auth = {
        "protocol_version": "oev-witness-authorization/0.1",
        "witness_key_id": "wit-b2-1",
        "witness_mode": "separate-machine",
        "profiles": ["strict-conformance-profile", "integrity-check-profile"],
        "bundle_formats": ["oept-bundle/0.1"],
        "not_after": NOT_AFTER,
    }
    witness = B2ReexecutingWitness(
        wit_priv,
        key_id="wit-b2-1",
        log_id="hea-b2-log-001",
        log_path=tmp_path / "witness-log.jsonl",
        checkpoint_private_key_pem=cp_priv,
        checkpoint_key_id="cp-b2-1",
        authorization=auth,
    )
    return {
        "witness": witness,
        "wit_priv": wit_priv,
        "wit_pub": wit_pub,
        "cp_priv": cp_priv,
        "cp_pub": cp_pub,
        "prod_priv": prod_priv,
        "prod_pub": prod_pub,
        "auth": auth,
        "witness_store": TrustStore.from_list([_key_entry("witness", "wit-b2-1", wit_pub)]),
        "checkpoint_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
        "fixture": fixture,
    }


def _run_b2(ctx: dict[str, Any], tmp_path: Path, **kwargs: Any) -> dict[str, Any]:
    fixture = ctx["fixture"]
    trust_keys: list[dict[str, Any]] | None = None
    trust_path = fixture / "package-trust-keys.json"
    if trust_path.is_file():
        trust_keys = json.loads(trust_path.read_text(encoding="utf-8"))
    out_dir = tmp_path / "b2-out"
    signing_key = kwargs.pop("receipt_signing_key_pem", ctx["prod_priv"])
    summary = run_b2_witnessed_verification(
        fixture / "package.zip",
        fixture / "profile.json",
        ctx["witness"],
        out_dir,
        package_trust_keys=trust_keys,
        receipt_signing_key_pem=signing_key,
        receipt_signer_key_id="prod-1",
        witness_public_pem=ctx["wit_pub"],
        producer_workdir=tmp_path / "producer",
        witness_workdir=tmp_path / "witness",
        **kwargs,
    )
    return {"summary": summary, "out_dir": out_dir, "trust_keys": trust_keys}


def _load_inputs(
    ctx: dict[str, Any], run: dict[str, Any], **overrides: Any
) -> HeaVerificationInputs:
    out_dir = run["out_dir"]
    fixture = ctx["fixture"]
    receipt_data = safe_json_loads((out_dir / "receipt.json").read_bytes())
    if isinstance(receipt_data, dict) and "payload" in receipt_data:
        from oev.dsse import parse_dsse_envelope

        _pt, payload_bytes, _sigs = parse_dsse_envelope(receipt_data)
        receipt_data = safe_json_loads(payload_bytes.decode("utf-8"))
    receipt = VerificationReceipt.from_dict(dict(receipt_data))
    profile = load_profile(fixture / "profile.json")
    attestations = [
        safe_json_loads(p.read_bytes())
        for p in sorted((out_dir / "attestations").glob("*.dsse.json"))
    ]
    manifest = safe_json_loads((out_dir / "b2-manifest.json").read_bytes())
    kwargs: dict[str, Any] = {
        "package_bytes": (fixture / "package.zip").read_bytes(),
        "receipt": receipt,
        "profile": profile,
        "attestations": attestations,
        "commitment_envelope": safe_json_loads((out_dir / "commitment.dsse.json").read_bytes()),
        "prebinding": safe_json_loads((out_dir / "prebinding.json").read_bytes()),
        "log_events": events_from_jsonl((out_dir / "execution-log.jsonl").read_bytes()),
        "checkpoint_envelope": safe_json_loads((out_dir / "checkpoint.dsse.json").read_bytes()),
        "inclusion_proofs": {
            str(k): [dict(s) for s in v]
            for k, v in dict(manifest.get("inclusion_proofs", {})).items()
        },
        "witness_trust_store": ctx["witness_store"],
        "checkpoint_trust_store": ctx["checkpoint_store"],
        "expected_code_digest": str(manifest.get("code_digest") or ""),
    }
    kwargs.update(overrides)
    return HeaVerificationInputs(**kwargs)


def _token_envelopes(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    token_dir = run["out_dir"] / "timestamp-tokens"
    if not token_dir.is_dir():
        return {}
    return {
        p.name[: -len(".dsse.json")]: safe_json_loads(p.read_bytes())
        for p in sorted(token_dir.glob("*.dsse.json"))
    }


def _tsa_store(tmp_path: Path) -> tuple[MockTSA, TrustStore]:
    priv, pub = generate_ed25519_keypair()
    tsa = MockTSA(priv, key_id="tsa-mock-1")
    store = TrustStore.from_list([{"key_id": "tsa-mock-1", "public_key_pem": pub.decode()}])
    return tsa, store


# -- happy path -----------------------------------------------------------------


def test_b2_valid_run_proven(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    summary = run["summary"]
    assert summary["witness_mode"] == "separate-machine"
    assert summary["attested_checks"] == [
        "application_signature",
        "archive_safety",
        "manifest_structure",
        "member_digests",
    ]
    assert summary["overall_result"] == "TECHNICAL_CHECKS_PASSED"
    assert summary["witness_code_digest"] == summary["producer_code_digest"]
    manifest = safe_json_loads((run["out_dir"] / "b2-manifest.json").read_bytes())
    assert manifest["isolation_claim"] == "prototype-process-venv-key-workdir-only"
    assert manifest["isolation"]["physical_or_administrative_independence"] is False
    assert manifest["timestamp_status"] == "UNVERIFIED"
    result = verify_historical_execution(_load_inputs(ctx, run))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert result.witness_mode == "separate-machine"
    assert result.reason == ""
    report = verify_b2_execution(_load_inputs(ctx, run))
    assert report["b2_ok"] is True
    assert report["timestamp_status"] == {
        check: "UNVERIFIED" for check in summary["attested_checks"]
    }
    assert report["time_proven"] is False


def test_b2_process_witness_proven(tmp_path: Path) -> None:
    import sys

    wit_priv, wit_pub = generate_ed25519_keypair()
    cp_priv, cp_pub = generate_ed25519_keypair()
    prod_priv, _prod_pub = generate_ed25519_keypair()
    (tmp_path / "wit.key").write_bytes(wit_priv)
    (tmp_path / "cp.key").write_bytes(cp_priv)
    trust_keys = json.loads((FIXTURE_01 / "package-trust-keys.json").read_text())
    out_dir = tmp_path / "b2-out"
    with B2ProcessWitness(
        tmp_path / "wit.key",
        key_id="wit-b2-1",
        log_path=tmp_path / "witness-log.jsonl",
        checkpoint_key_path=tmp_path / "cp.key",
        checkpoint_key_id="cp-b2-1",
        python=sys.executable,
    ) as witness:
        summary = run_b2_witnessed_verification(
            FIXTURE_01 / "package.zip",
            FIXTURE_01 / "profile.json",
            witness,
            out_dir,
            package_trust_keys=trust_keys,
            receipt_signing_key_pem=prod_priv,
            receipt_signer_key_id="prod-1",
            witness_public_pem=wit_pub,
        )
    assert summary["witness_mode"] == "separate-machine"
    assert len(summary["attested_checks"]) == 4
    ctx = {
        "fixture": FIXTURE_01,
        "witness_store": TrustStore.from_list([_key_entry("witness", "wit-b2-1", wit_pub)]),
        "checkpoint_store": TrustStore.from_list(
            [_key_entry("checkpoint-signer", "cp-b2-1", cp_pub)]
        ),
    }
    report = verify_b2_execution(_load_inputs(ctx, {"out_dir": out_dir}))
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"
    assert report["b2_ok"] is True


def test_b2_attests_fail_honestly(tmp_path: Path) -> None:
    """A FAIL is attested as FAIL: PROVEN execution, failed check — separate dimensions."""
    ctx = _make_b2(tmp_path, fixture=FIXTURE_02)
    run = _run_b2(ctx, tmp_path)
    assert run["summary"]["overall_result"] == "TECHNICAL_CHECKS_FAILED"
    assert run["summary"]["attested_checks"] == [
        "archive_safety",
        "manifest_structure",
        "member_digests",
    ]
    envelopes = [
        safe_json_loads(p.read_bytes())
        for p in sorted((run["out_dir"] / "attestations").glob("*.dsse.json"))
    ]
    payloads = {p["check_id"]: p for p in (parse_attestation_envelope(e) for e in envelopes)}
    assert payloads["member_digests"]["result"]["status"] == "FAIL"
    result = verify_historical_execution(_load_inputs(ctx, run))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert result.reason == ""


# -- re-execution comparison ------------------------------------------------------


def test_b2_refuses_forged_producer_pass(tmp_path: Path, monkeypatch: Any) -> None:
    """Producer forges PASS on the tampered package; witness re-runs and refuses."""
    ctx = _make_b2(tmp_path, fixture=FIXTURE_02)
    real_execute = b2_mod.execute_verification
    calls = {"n": 0}

    def _forged_first(*args: Any, **kwargs: Any) -> Any:
        receipt, envelope = real_execute(*args, **kwargs)
        calls["n"] += 1
        if calls["n"] == 1:
            forged_checks = [
                dataclasses.replace(c, status=CheckStatus.PASS, detail="forged PASS")
                if c.check_id == "member_digests"
                else c
                for c in receipt.checks
            ]
            forged = finalize_receipt(dataclasses.replace(receipt, checks=forged_checks))
            return forged, envelope
        return receipt, envelope

    monkeypatch.setattr(b2_mod, "execute_verification", _forged_first)
    with pytest.raises(ValueError, match="attestation refused"):
        _run_b2(ctx, tmp_path)
    assert calls["n"] == 2  # producer (forged) + witness (real re-execution)
    assert not list((tmp_path / "b2-out" / "attestations").glob("*.dsse.json"))


def test_b2_compare_results_ignores_duration_but_not_detail() -> None:
    witness = B2ReexecutingWitness.__new__(B2ReexecutingWitness)
    producer = [{"check_id": "a", "status": "PASS", "detail": "ok"}]
    observed = [{"check_id": "a", "status": "PASS", "detail": "ok"}]
    assert witness.compare_results(producer, observed) == []
    changed_detail = [{"check_id": "a", "status": "PASS", "detail": "different"}]
    assert witness.compare_results(producer, changed_detail) == ["a"]
    missing = [{"check_id": "b", "status": "PASS", "detail": "ok"}]
    assert witness.compare_results(producer, missing) == ["a"]


def test_b2_code_digest_mismatch_refused(tmp_path: Path, monkeypatch: Any) -> None:
    ctx = _make_b2(tmp_path)
    monkeypatch.setattr(ctx["witness"], "code_digest", lambda: "sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="Code digest mismatch"):
        _run_b2(ctx, tmp_path)


# -- role separation --------------------------------------------------------------


def test_b2_producer_key_must_differ_from_witness_key(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    with pytest.raises(ValueError, match="Role separation violated"):
        _run_b2(ctx, tmp_path, receipt_signing_key_pem=ctx["wit_priv"])
    with pytest.raises(ValueError, match="Role separation violated"):
        check_role_separation(ctx["wit_pub"], None, ctx["wit_pub"])


def test_b2_witness_key_must_differ_from_checkpoint_key(tmp_path: Path) -> None:
    wit_priv, _wit_pub = generate_ed25519_keypair()
    with pytest.raises(ValueError, match="Role separation violated"):
        B2ReexecutingWitness(
            wit_priv,
            key_id="wit-b2-1",
            log_path=tmp_path / "witness-log.jsonl",
            checkpoint_private_key_pem=wit_priv,
            checkpoint_key_id="cp-b2-1",
        )


def test_b2_authorization_schema() -> None:
    good = {
        "protocol_version": "oev-witness-authorization/0.1",
        "witness_key_id": "wit-b2-1",
        "witness_mode": "separate-machine",
        "profiles": ["strict-conformance-profile"],
        "bundle_formats": ["oept-bundle/0.1"],
    }
    assert validate_witness_authorization(good)["profiles"] == ["strict-conformance-profile"]
    assert to_verifier_authorization(good) == {
        "wit-b2-1": {"profiles": ["strict-conformance-profile"]}
    }
    with pytest.raises(ValueError):
        validate_witness_authorization(
            {**good, "protocol_version": "oev-witness-authorization/9.9"}
        )
    with pytest.raises(ValueError):
        validate_witness_authorization({**good, "profiles": []})
    with pytest.raises(ValueError):
        validate_witness_authorization({**good, "witness_mode": "local-process"})


def test_b2_unauthorised_profile_refused_at_run_and_verify(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    ctx["witness"].authorization = {
        "protocol_version": "oev-witness-authorization/0.1",
        "witness_key_id": "wit-b2-1",
        "witness_mode": "separate-machine",
        "profiles": ["some-other-profile"],
        "bundle_formats": ["oept-bundle/0.1"],
        "not_after": NOT_AFTER,
    }
    with pytest.raises(ValueError, match="not authorised for profile"):
        _run_b2(ctx, tmp_path)
    # And at verify time (authorisation document supplied to the wrapper):
    ctx2 = _make_b2(tmp_path)
    run = _run_b2(ctx2, tmp_path)
    other_auth = {
        "protocol_version": "oev-witness-authorization/0.1",
        "witness_key_id": "wit-b2-1",
        "witness_mode": "separate-machine",
        "profiles": ["some-other-profile"],
        "bundle_formats": ["oept-bundle/0.1"],
    }
    report = verify_b2_execution(_load_inputs(ctx2, run), witness_authorization=other_auth)
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_UNPROVEN"
    assert report["reason"] == "WITNESS_UNAUTHORIZED"


# -- verifier compatibility ---------------------------------------------------------


def test_b2_wrapper_rejects_model_a_bundle(tmp_path: Path) -> None:
    """A Model A bundle still verifies under HEA — but it is NOT a B2 proof."""
    bundle = build_valid_hea(tmp_path)
    from tests.hea_helpers import hea_inputs

    result = verify_historical_execution(hea_inputs(bundle))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert result.witness_mode == "local-process"
    report = verify_b2_execution(hea_inputs(bundle))
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"
    assert report["b2_ok"] is False
    assert "NOT_B2_WITNESS_MODE" in report["b2_reason"]


def test_model_a_commitment_still_says_local_process(tmp_path: Path) -> None:
    """Guard for the minimal witness.py change: Model A default is unchanged."""
    wit_priv, _wit_pub = generate_ed25519_keypair()
    cp_priv, _cp_pub = generate_ed25519_keypair()
    service = WitnessService(
        wit_priv,
        key_id="wit-1",
        log_path=tmp_path / "log.jsonl",
        checkpoint_private_key_pem=cp_priv,
        checkpoint_key_id="cp-1",
    )
    assert service.witness_mode == "local-process"
    bundle = build_valid_hea(tmp_path)
    assert bundle["prebinding"]["execution_context"]["witness_mode"] == "local-process"


def test_b2_replay_detected(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    other_bytes = (FIXTURE_02 / "package.zip").read_bytes()
    result = verify_historical_execution(_load_inputs(ctx, run, package_bytes=other_bytes))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "BUNDLE_DIGEST_MISMATCH"


def test_b2_attestation_omission_detected(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    inputs = _load_inputs(ctx, run)
    dropped = [
        a
        for a in inputs.attestations
        if parse_attestation_envelope(a)["check_id"] != "member_digests"
    ]
    assert len(dropped) == len(inputs.attestations) - 1
    result = verify_historical_execution(
        HeaVerificationInputs(**{**inputs.__dict__, "attestations": dropped})
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "NO_ATTESTATION"


def test_b2_log_tamper_detected(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    inputs = _load_inputs(ctx, run)
    truncated = [e for e in inputs.log_events if e.event_type != "CHECK_COMPLETED"] + [
        e for e in inputs.log_events if e.event_type == "CHECK_COMPLETED"
    ][:1]
    result = verify_historical_execution(
        HeaVerificationInputs(**{**inputs.__dict__, "log_events": truncated})
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason in ("LOG_ANCHOR_INVALID", "LOG_GAP", "MISSING_EXECUTION_STEP")


def test_b2_revoked_witness_key_detected(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)
    revoked_store = TrustStore.from_list(
        [{**_key_entry("witness", "wit-b2-1", ctx["wit_pub"]), "revoked": True}]
    )
    result = verify_historical_execution(_load_inputs(ctx, run, witness_trust_store=revoked_store))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "WITNESS_KEY_REVOKED"


def test_b2_offline_verify_with_blocked_network(tmp_path: Path, monkeypatch: Any) -> None:
    ctx = _make_b2(tmp_path)
    run = _run_b2(ctx, tmp_path)

    def _blocked(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("network call attempted during offline verification")

    monkeypatch.setattr(socket, "socket", _blocked)
    report = verify_b2_execution(_load_inputs(ctx, run))
    assert report["historical_execution"] == "HISTORICAL_EXECUTION_PROVEN"
    assert report["b2_ok"] is True


# -- TSA sidecars ---------------------------------------------------------------------


def test_b2_tsa_token_verified_but_time_not_proven(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    tsa, tsa_store = _tsa_store(tmp_path)
    run = _run_b2(ctx, tmp_path, tsa=tsa, tsa_gen_time="2026-11-13T10:00:00Z")
    assert "mock" in run["summary"]["timestamp_status"]
    tokens = _token_envelopes(run)
    assert set(tokens) == set(run["summary"]["attested_checks"])
    report = verify_b2_execution(
        _load_inputs(ctx, run),
        timestamp_token_envelopes=tokens,
        tsa_trust_store=tsa_store,
    )
    assert report["b2_ok"] is True
    assert all(s == "TSA_VERIFIED" for s in report["timestamp_status"].values())
    # Mock TSA: verified as a mock token, never as proven wall-clock time.
    assert report["time_proven"] is False
    # claimed_time (attestation) and tsa_gen_time (token) stay separate fields.
    envelopes = [
        safe_json_loads(p.read_bytes())
        for p in sorted((run["out_dir"] / "attestations").glob("*.dsse.json"))
    ]
    claimed = {parse_attestation_envelope(e)["claimed_time"] for e in envelopes}
    assert len(claimed) == 1
    from oev.tsa import parse_timestamp_token_envelope

    token_times = {parse_timestamp_token_envelope(e)["tsa_gen_time"] for e in tokens.values()}
    assert token_times == {"2026-11-13T10:00:00Z"}
    assert claimed != token_times  # different values, different fields, both reported


def test_b2_tsa_tampered_token_invalid(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    tsa, tsa_store = _tsa_store(tmp_path)
    run = _run_b2(ctx, tmp_path, tsa=tsa, tsa_gen_time="2026-11-13T10:00:00Z")
    tokens = _token_envelopes(run)
    # Swap two checks' tokens: each token's imprint no longer matches its attestation.
    checks = sorted(tokens)
    tokens[checks[0]], tokens[checks[1]] = tokens[checks[1]], tokens[checks[0]]
    report = verify_b2_execution(
        _load_inputs(ctx, run),
        timestamp_token_envelopes=tokens,
        tsa_trust_store=tsa_store,
    )
    assert report["b2_ok"] is True  # HEA verdict unaffected by a bad token ...
    assert report["timestamp_status"][checks[0]] == "TSA_INVALID"
    assert report["timestamp_status"][checks[1]] == "TSA_INVALID"
    assert report["time_proven"] is False


def test_b2_tsa_untrusted_key_invalid(tmp_path: Path) -> None:
    ctx = _make_b2(tmp_path)
    tsa, _unused_store = _tsa_store(tmp_path)
    run = _run_b2(ctx, tmp_path, tsa=tsa, tsa_gen_time="2026-11-13T10:00:00Z")
    _other_priv, other_pub = generate_ed25519_keypair()
    other_store = TrustStore.from_list(
        [{"key_id": "tsa-other-1", "public_key_pem": other_pub.decode()}]
    )
    report = verify_b2_execution(
        _load_inputs(ctx, run),
        timestamp_token_envelopes=_token_envelopes(run),
        tsa_trust_store=other_store,
    )
    assert all(s == "TSA_INVALID" for s in report["timestamp_status"].values())


def test_b2_attestation_payload_builder_uses_b2_mode_and_limits() -> None:
    payload = build_b2_attestation_payload(
        execution_id="exec_" + "a" * 32,
        commitment_digest="sha256:" + "b" * 64,
        bundle_digest="sha256:" + "c" * 64,
        profile_digest="sha256:" + "d" * 64,
        code_version={
            "engine": "oev 0.2.3",
            "adapter": "oept 0.1.3",
            "code_digest": "sha256:" + "e" * 64,
        },
        check_id="archive_safety",
        result_status="PASS",
        result_detail="ok",
        result_duration_ms=1,
        execution_status="COMPLETED",
        log_anchor={"log_id": "hea-b2-log-001", "leaf_index": 0, "leaf_hash": "sha256:" + "f" * 64},
        claimed_time=CLAIMED_TIME,
        witness_key_id="wit-b2-1",
    )
    assert payload["witness"]["witness_mode"] == "separate-machine"
    assert payload["witness"]["witness_software"] == "oev-witness-b2 0.1.0"
    codes = {lim["code"] for lim in payload["limitations"]}
    assert "WITNESS_SEPARATE_MACHINE_REEXECUTING" in codes
    assert "B2_PROTOTYPE_ISOLATION" in codes
    assert "NO_HARDWARE_ASSURANCE" in codes
    assert compute_attestation_digest(payload).startswith("sha256:")
