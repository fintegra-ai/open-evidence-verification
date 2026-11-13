# SPDX-License-Identifier: Apache-2.0

"""HEA conformance vector runner (v0.1 Model A).

Runs the vectors in ``conformance/vectors-hea/`` against the OEVP offline
HEA verifier and emits a machine-readable report. Each vector describes a
scenario; the runner builds a synthetic HEA bundle in-process (fresh keys
per run, via ``tests.hea_helpers``), applies the scenario's single
mutation, runs ``verify_historical_execution`` offline, and compares the
observed ``historical_execution`` + ``reason`` against ``expected.json``.

A vector passes only if every key/value pair in
``expected.json["asserts"]`` matches the observed result. Vectors marked
``"status": "planned"`` in the manifest are skipped and counted.

Usage::

    python conformance/run_hea_vectors.py run [--vector hea-03] [--json]
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS_DIR = REPO_ROOT / "conformance" / "vectors-hea"

sys.path.insert(0, str(REPO_ROOT / "src"))

_HEA_HELPERS_SPEC = importlib.util.spec_from_file_location(
    "hea_helpers", REPO_ROOT / "tests" / "hea_helpers.py"
)
assert _HEA_HELPERS_SPEC is not None and _HEA_HELPERS_SPEC.loader is not None
hea_helpers = importlib.util.module_from_spec(_HEA_HELPERS_SPEC)
_HEA_HELPERS_SPEC.loader.exec_module(hea_helpers)

from oev.attestation import parse_attestation_envelope, sign_attestation_dsse
from oev.execution_log import (
    GENESIS_PREV_HASH,
    LogCompleteness,
    LogEvent,
    build_checkpoint,
    parse_checkpoint_envelope,
    sign_checkpoint_dsse,
    sign_completeness_dsse,
)
from oev.hea_verifier import verify_historical_execution
from oev.models import CheckResult, CheckStatus
from oev.receipts import finalize_receipt
from oev.revocation import RevocationEntry, build_revocation_list, verify_revocation_list
from oev.signing import generate_ed25519_keypair, load_ed25519_private_key
from oev.trust import TrustStore

CLAIMED_TIME = hea_helpers.CLAIMED_TIME
OEPT_TEST_ONLY_KEY = (
    REPO_ROOT.parent
    / "oept"
    / "conformance"
    / "test-only-keys"
    / "conformance-test-only-signing.key"
)


def load_manifest(vectors_dir: Path = VECTORS_DIR) -> dict[str, Any]:
    return json.loads((vectors_dir / "manifest.json").read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def load_vector(
    vector_id: str, vectors_dir: Path = VECTORS_DIR
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = load_manifest(vectors_dir)
    entry = next(v for v in manifest["vectors"] if v["id"] == vector_id)
    vector_dir = vectors_dir / f"{vector_id}-{entry['scenario']}"
    input_doc = json.loads((vector_dir / "input.json").read_text(encoding="utf-8"))
    expected = json.loads((vector_dir / "expected.json").read_text(encoding="utf-8"))
    return input_doc, expected


def _resign_attestations(bundle: dict[str, Any], priv: bytes, key_id: str) -> list[dict[str, Any]]:
    resigned = []
    for envelope in bundle["attestation_envelopes"]:
        payload = parse_attestation_envelope(envelope)
        payload["witness"] = dict(payload["witness"])
        payload["witness"]["witness_key_id"] = key_id
        resigned.append(sign_attestation_dsse(payload, priv, key_id))
    return resigned


def _sign_attestation_raw(payload: dict[str, Any], priv: bytes, key_id: str) -> dict[str, Any]:
    """DSSE-sign an attestation payload with raw crypto (no blocklist).

    Used ONLY by the hea-11 vector to simulate an envelope produced
    outside this library (e.g. with openssl) using the committed
    test-only key: the library's own ``sign_attestation_dsse`` refuses
    that key, so the verifier-side blocklist is what must catch it.
    """
    import base64

    from oev.attestation import ATTESTATION_PAYLOAD_TYPE
    from oev.canonical import canonicalize_json
    from oev.dsse import build_dsse_envelope, compute_pae

    payload_bytes = canonicalize_json(payload)
    raw_sig = load_ed25519_private_key(priv).sign(
        compute_pae(ATTESTATION_PAYLOAD_TYPE, payload_bytes)
    )
    return build_dsse_envelope(
        payload_type=ATTESTATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[{"sig": base64.b64encode(raw_sig).decode("ascii"), "keyid": key_id}],
    )


def _public_pem(private_pem: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization

    public = load_ed25519_private_key(private_pem).public_key()
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _scenario_valid(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_no_attestations(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=[]))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_tampered_receipt(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    receipt = bundle["receipt"]
    flipped = [
        dataclasses.replace(c, status=CheckStatus.FAIL) if c.check_id == "archive_safety" else c
        for c in receipt.checks
    ]
    tampered = finalize_receipt(dataclasses.replace(receipt, checks=flipped))
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, receipt=tampered))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_unknown_witness_key(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    other_priv, _other_pub = generate_ed25519_keypair()
    resigned = _resign_attestations(bundle, other_priv, "other-1")
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=resigned))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_wrong_key_trusted_keyid(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    other_priv, _other_pub = generate_ed25519_keypair()
    resigned = _resign_attestations(bundle, other_priv, "wit-1")
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=resigned))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_missing_execution_started(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    events: list[LogEvent] = list(bundle["log_events"])
    # Rebuild a chain-valid log without the EXECUTION_STARTED event.
    rebuilt: list[LogEvent] = []
    prev = GENESIS_PREV_HASH
    for index, event in enumerate(events[1:]):
        rebuilt.append(dataclasses.replace(event, seq=index, prev_hash=prev))
        prev = rebuilt[-1].leaf_hash()
    checkpoint = build_checkpoint(rebuilt, "hea-log-001", CLAIMED_TIME)
    checkpoint_envelope = sign_checkpoint_dsse(checkpoint, bundle["checkpoint_private"], "cp-1")
    result = verify_historical_execution(
        hea_helpers.hea_inputs(bundle, log_events=rebuilt, checkpoint_envelope=checkpoint_envelope)
    )
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_tampered_log_event(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    events: list[LogEvent] = list(bundle["log_events"])
    events[1] = dataclasses.replace(events[1], claimed_time="2026-11-13T07:21:00Z")
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, log_events=events))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_checkpoint_signed_by_witness_key(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    events: list[LogEvent] = list(bundle["log_events"])
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    wrong = sign_checkpoint_dsse(checkpoint, bundle["witness_private"], "wit-1")
    # The witness key is trusted, but its role is "witness", not
    # "checkpoint-signer": role separation must reject it.
    result = verify_historical_execution(
        hea_helpers.hea_inputs(
            bundle,
            checkpoint_envelope=wrong,
            checkpoint_trust_store=bundle["witness_store"],
        )
    )
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_revoked_witness_key(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    rev_priv, _rev_pub, rev_entry = hea_helpers.make_keypair(role=None)
    rev_entry["key_id"] = "rev-1"
    envelope = build_revocation_list(
        [RevocationEntry(key_id="wit-1", reason="key-compromise", revoked_at_claimed=CLAIMED_TIME)],
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        private_key_pem=rev_priv,
    )
    revocation, _note = verify_revocation_list(envelope, TrustStore.from_list([rev_entry]))
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, revocation_list=revocation))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_expired_witness_key(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    entry = dict(bundle["witness_store"].keys[0].to_dict())
    entry["not_after"] = "2026-01-02T00:00:00Z"  # before CLAIMED_TIME
    expired_store = TrustStore.from_list([entry])
    result = verify_historical_execution(
        hea_helpers.hea_inputs(bundle, witness_trust_store=expired_store)
    )
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_test_only_key(workdir: Path) -> dict[str, str]:
    if not OEPT_TEST_ONLY_KEY.is_file():
        raise FileNotFoundError(f"OEPT test-only key not found: {OEPT_TEST_ONLY_KEY}")
    test_priv = OEPT_TEST_ONLY_KEY.read_bytes()
    test_pub = _public_pem(test_priv)
    bundle = hea_helpers.build_valid_hea(workdir)
    # Operator error the blocklist must survive: the test-only key is
    # (wrongly) present in the witness trust store as "test-1".
    test_entry = {
        "key_id": "test-1",
        "public_key_pem": test_pub.decode("utf-8"),
        "role": "witness",
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-12-31T23:59:59Z",
    }
    store_entries = [dict(k.to_dict()) for k in bundle["witness_store"].keys]
    store_entries.append(test_entry)
    store = TrustStore.from_list(store_entries)
    # Envelopes signed outside the library with the test-only key.
    resigned = []
    for envelope in bundle["attestation_envelopes"]:
        payload = parse_attestation_envelope(envelope)
        payload["witness"] = dict(payload["witness"])
        payload["witness"]["witness_key_id"] = "test-1"
        resigned.append(_sign_attestation_raw(payload, test_priv, "test-1"))
    result = verify_historical_execution(
        hea_helpers.hea_inputs(bundle, attestations=resigned, witness_trust_store=store)
    )
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_bundle_digest_mismatch(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    result = verify_historical_execution(
        hea_helpers.hea_inputs(bundle, package_bytes=b"different package bytes")
    )
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_profile_digest_mismatch(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    other_profile = hea_helpers.make_profile(
        required=["archive_safety", "manifest_structure", "extra_check"]
    )
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, profile=other_profile))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_partial_attestation_omission(workdir: Path) -> dict[str, str]:
    # H2: 1 of the 2 attestations is dropped; the log still holds every
    # CHECK_COMPLETED event, so only the coverage check can catch it.
    bundle = hea_helpers.build_valid_hea(workdir)
    kept = bundle["attestation_envelopes"][:1]
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=kept))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_extra_attestation(workdir: Path) -> dict[str, str]:
    # An attestation is supplied for a check the (re-finalised) receipt
    # no longer records: extra, not silently swallowed (RESULT_CONFLICT).
    bundle = hea_helpers.build_valid_hea(workdir)
    receipt_dict = bundle["receipt"].to_dict(include_digest=False)
    receipt_dict["checks"] = [
        c for c in receipt_dict["checks"] if c["check_id"] != "manifest_structure"
    ]
    receipt_dict["execution_attestations"] = [
        a for a in receipt_dict["execution_attestations"] if a["check_id"] != "manifest_structure"
    ]
    receipt = finalize_receipt(receipt_dict)
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, receipt=receipt))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_partial_attestation_omission_four_checks(workdir: Path) -> dict[str, str]:
    # H2 at 2/4: a four-check bundle with half its attestations dropped.
    four = ["check_a", "check_b", "check_c", "check_d"]
    checks = [CheckResult(check_id=c, category="safety", status=CheckStatus.PASS) for c in four]
    bundle = hea_helpers.build_valid_hea(
        workdir, checks=checks, profile=hea_helpers.make_profile(required=four)
    )
    kept = bundle["attestation_envelopes"][:2]
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=kept))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _four_check_bundle(workdir: Path) -> tuple[list[str], dict[str, Any]]:
    four = ["check_a", "check_b", "check_c", "check_d"]
    checks = [CheckResult(check_id=c, category="safety", status=CheckStatus.PASS) for c in four]
    bundle = hea_helpers.build_valid_hea(
        workdir, checks=checks, profile=hea_helpers.make_profile(required=four)
    )
    return four, bundle


def _scenario_partial_attestation_omission_three_of_four(workdir: Path) -> dict[str, str]:
    # H2 at 3/4 (round 3, P0): only one attestation survives; the other
    # three checks ran (log events exist) but are unattested.
    _four, bundle = _four_check_bundle(workdir)
    kept = bundle["attestation_envelopes"][:1]
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=kept))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_partial_attestation_omission_first_only(workdir: Path) -> dict[str, str]:
    # H2 at 1/4, first position (round 3, P0): the coverage check must
    # catch an omission wherever it sits, not only at the tail.
    _four, bundle = _four_check_bundle(workdir)
    kept = bundle["attestation_envelopes"][1:]
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle, attestations=kept))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_not_run_check_needs_no_attestation(workdir: Path) -> dict[str, str]:
    # Coverage exclusion (round 3, P0): a NOT_RUN check never ran, so no
    # attestation is expected for it; the bundle still verifies PROVEN.
    # Guards the H2 coverage check against overreach.
    checks = [
        CheckResult(check_id="check_a", category="safety", status=CheckStatus.PASS),
        CheckResult(check_id="check_b", category="safety", status=CheckStatus.PASS),
        CheckResult(check_id="check_c", category="safety", status=CheckStatus.PASS),
        CheckResult(check_id="check_d", category="safety", status=CheckStatus.NOT_RUN),
    ]
    bundle = hea_helpers.build_valid_hea(
        workdir,
        checks=checks,
        profile=hea_helpers.make_profile(required=["check_a", "check_b", "check_c", "check_d"]),
    )
    result = verify_historical_execution(hea_helpers.hea_inputs(bundle))
    return {"historical_execution": result.historical_execution, "reason": result.reason}


def _scenario_disprove_never_executed(workdir: Path) -> dict[str, str]:
    bundle = hea_helpers.build_valid_hea(workdir)
    checkpoint = parse_checkpoint_envelope(bundle["checkpoint_envelope"])
    statement = LogCompleteness(
        log_id="hea-log-001",
        through_seq=checkpoint.checkpoint_seq,
        checkpoint_digest=checkpoint.checkpoint_digest(),
        claimed_time=CLAIMED_TIME,
    )
    completeness = sign_completeness_dsse(statement, bundle["checkpoint_private"], "cp-1")
    result = verify_historical_execution(
        hea_helpers.hea_inputs(
            bundle,
            attestations=[],
            completeness_envelope=completeness,
            log_operator_trust_store=bundle["checkpoint_store"],
            claimed_execution_id="exec_" + "f" * 32,
        )
    )
    return {"historical_execution": result.historical_execution, "reason": result.reason}


SCENARIOS: dict[str, Any] = {
    "valid": _scenario_valid,
    "no-attestations": _scenario_no_attestations,
    "tampered-receipt": _scenario_tampered_receipt,
    "unknown-witness-key": _scenario_unknown_witness_key,
    "wrong-key-trusted-keyid": _scenario_wrong_key_trusted_keyid,
    "missing-execution-started": _scenario_missing_execution_started,
    "tampered-log-event": _scenario_tampered_log_event,
    "checkpoint-signed-by-witness-key": _scenario_checkpoint_signed_by_witness_key,
    "revoked-witness-key": _scenario_revoked_witness_key,
    "expired-witness-key": _scenario_expired_witness_key,
    "test-only-key": _scenario_test_only_key,
    "bundle-digest-mismatch": _scenario_bundle_digest_mismatch,
    "profile-digest-mismatch": _scenario_profile_digest_mismatch,
    "disprove-never-executed": _scenario_disprove_never_executed,
    "partial-attestation-omission": _scenario_partial_attestation_omission,
    "extra-attestation": _scenario_extra_attestation,
    "partial-attestation-omission-four-checks": _scenario_partial_attestation_omission_four_checks,
    "partial-attestation-omission-three-of-four": _scenario_partial_attestation_omission_three_of_four,
    "partial-attestation-omission-first-only": _scenario_partial_attestation_omission_first_only,
    "not-run-check-needs-no-attestation": _scenario_not_run_check_needs_no_attestation,
}


def compare(expected: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed comparison of expected asserts against the observed result."""
    asserts = expected.get("asserts", {})
    mismatches = {
        key: {"expected": value, "observed": observed.get(key)}
        for key, value in asserts.items()
        if observed.get(key) != value
    }
    return {"passed": not mismatches, "mismatches": mismatches}


def run_vector(vector_id: str, workdir: Path, vectors_dir: Path = VECTORS_DIR) -> dict[str, Any]:
    """Run one vector; returns its report entry (never raises for a mismatch)."""
    _input, expected = load_vector(vector_id, vectors_dir)
    scenario = _input["scenario"]
    builder = SCENARIOS.get(scenario)
    if builder is None:
        return {
            "vector_id": vector_id,
            "scenario": scenario,
            "passed": False,
            "error": f"no scenario builder for {scenario!r}",
        }
    try:
        vector_workdir = workdir / vector_id
        vector_workdir.mkdir(parents=True, exist_ok=True)
        observed = builder(vector_workdir)
    except Exception as exc:  # noqa: BLE001 -- runner error, not a vector failure
        return {
            "vector_id": vector_id,
            "scenario": scenario,
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    verdict = compare(expected, observed)
    return {
        "vector_id": vector_id,
        "scenario": scenario,
        "passed": verdict["passed"],
        "observed": observed,
        "expected": expected.get("asserts", {}),
        "mismatches": verdict["mismatches"],
    }


def run_all(vectors_dir: Path = VECTORS_DIR) -> dict[str, Any]:
    """Run every active vector; returns the full report dict."""
    manifest = load_manifest(vectors_dir)
    results: list[dict[str, Any]] = []
    skipped: list[str] = []
    with tempfile.TemporaryDirectory(prefix="hea-vectors-") as tmp:
        workdir = Path(tmp)
        for entry in manifest["vectors"]:
            if entry.get("status") != "active":
                skipped.append(entry["id"])
                continue
            results.append(run_vector(entry["id"], workdir, vectors_dir))
    passed = sum(1 for r in results if r["passed"])
    return {
        "vector_set": manifest["vector_set"],
        "version": manifest["version"],
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "skipped": skipped,
        "vectors": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the HEA conformance vectors.")
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--vector", help="run a single vector id (e.g. hea-03)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    if args.vector:
        with tempfile.TemporaryDirectory(prefix="hea-vectors-") as tmp:
            report = run_vector(args.vector, Path(tmp))
        results = [report]
        summary = {
            "vector_set": load_manifest()["vector_set"],
            "total": 1,
            "passed": 1 if report["passed"] else 0,
            "failed": 0 if report["passed"] else 1,
            "vectors": results,
        }
    else:
        summary = run_all()
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        for entry in summary["vectors"]:
            status = "PASS" if entry["passed"] else "FAIL"
            detail = entry.get("error") or (
                f"observed={entry.get('observed')} expected={entry.get('expected')}"
                if not entry["passed"]
                else f"observed={entry.get('observed')}"
            )
            print(f"{status} {entry['vector_id']} ({entry['scenario']}): {detail}")
        print(
            f"{summary['passed']}/{summary['total']} vectors passed"
            + (f", {len(summary.get('skipped', []))} skipped" if summary.get("skipped") else "")
        )
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
