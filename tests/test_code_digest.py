# SPDX-License-Identifier: Apache-2.0

"""Round-3 (P0) code-digest document tests (oev-code-digest/0.1).

The expected code is bound to a schema: code digest, policy digest,
pinned dependencies and environment identity. Mismatches fail closed
as UNPROVEN / CODE_DIGEST_MISMATCH; platform/OS differences are notes
only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from oev.code_digest import (
    build_code_digest_document,
    compare_code_digest_document,
    validate_code_digest_document,
)
from oev.execution import build_code_version
from oev.hea_verifier import verify_historical_execution
from tests.hea_helpers import build_valid_hea, hea_inputs


def _rebuild_with_code_version(tmp_path: Path, code_version: dict[str, Any]) -> dict[str, Any]:
    """Build a valid HEA bundle attested with the given code_version.

    Reuses the witness service: prebinding/commitment/attestations are
    rebuilt from scratch with the supplied code_version so every
    signature covers the enriched record.
    """
    from oev.attestation import compute_attestation_digest
    from oev.canonical import canonicalize_json
    from oev.execution import build_prebinding, compute_trust_inputs_digest
    from oev.execution_log import merkle_inclusion_proof
    from oev.hashing import sha256_bytes
    from oev.models import (
        CheckResult,
        CheckStatus,
        Limitation,
        OverallResult,
        PackageReference,
        ProfileReference,
        TrustInput,
        VerificationReceipt,
        VerifierIdentity,
    )
    from oev.receipts import finalize_receipt
    from oev.witness import WitnessService, build_attestation_payload
    from tests.hea_helpers import CLAIMED_TIME, make_keypair, make_package_bytes, make_profile

    profile = make_profile()
    package_bytes = make_package_bytes()
    checks = [
        CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
        CheckResult(check_id="manifest_structure", category="structure", status=CheckStatus.PASS),
    ]
    wit_priv, _wit_pub, wit_entry = make_keypair(role="witness")
    wit_entry["key_id"] = "wit-1"
    cp_priv, _cp_pub, cp_entry = make_keypair(role="checkpoint-signer")
    cp_entry["key_id"] = "cp-1"
    from oev.trust import TrustStore

    witness_store = TrustStore.from_list([dict(wit_entry)])
    checkpoint_store = TrustStore.from_list([dict(cp_entry)])
    log_path = tmp_path / "execution-log.jsonl"
    service = WitnessService(
        wit_priv,
        key_id="wit-1",
        log_id="hea-log-001",
        log_path=log_path,
        checkpoint_private_key_pem=cp_priv,
        checkpoint_key_id="cp-1",
    )
    bundle_digest = service.observe_bytes("package", package_bytes)
    profile_digest = service.observe_bytes("profile", canonicalize_json(profile.to_dict()))
    partial = build_prebinding(
        bundle_digest=bundle_digest,
        bundle_format=profile.target_format,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_digest=profile_digest,
        code_version=code_version,
        check_ids=[c.check_id for c in checks],
        input_digests={"package": bundle_digest, "profile": profile_digest},
        trust_inputs_digest=compute_trust_inputs_digest([]),
        witness_mode="local-process",
        witness_key_id="wit-1",
    )
    commitment_result = service.issue_commitment(partial, CLAIMED_TIME)
    execution_id = str(commitment_result["execution_id"])
    commitment_envelope = dict(commitment_result["commitment_envelope"])
    commitment_digest = str(commitment_result["commitment_digest"])
    prebinding = dict(commitment_result["prebinding"])
    service.start_execution(execution_id, commitment_digest, CLAIMED_TIME)
    anchors: dict[str, dict[str, Any]] = {}
    for check in checks:
        result_digest = sha256_bytes(canonicalize_json(check.to_dict()))
        completed = service.check_completed(
            execution_id, check.check_id, result_digest, CLAIMED_TIME
        )
        event = dict(completed["event"])
        anchors[check.check_id] = {
            "log_id": event["log_id"],
            "leaf_index": int(event["seq"]),
            "leaf_hash": str(completed["leaf_hash"]),
        }
    service.complete_execution(execution_id, "COMPLETED", CLAIMED_TIME)
    envelopes: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for check in checks:
        payload = build_attestation_payload(
            execution_id=execution_id,
            commitment_digest=commitment_digest,
            bundle_digest=bundle_digest,
            profile_digest=profile_digest,
            code_version=code_version,
            check_id=check.check_id,
            result_status="PASS",
            result_detail=check.detail,
            result_duration_ms=check.duration_ms,
            execution_status="COMPLETED",
            log_anchor=anchors[check.check_id],
            claimed_time=CLAIMED_TIME,
            witness_key_id="wit-1",
        )
        envelopes[check.check_id] = service.attest(payload)
        digests[check.check_id] = compute_attestation_digest(payload)
    checkpoint_envelope = dict(service.checkpoint(CLAIMED_TIME)["envelope"])
    events = service.events
    leaves = [e.leaf_hash() for e in events]
    proofs = {
        cid: merkle_inclusion_proof(leaves, int(a["leaf_index"])) for cid, a in anchors.items()
    }
    raw_receipt = VerificationReceipt(
        receipt_id="00000000-0000-4000-8000-0000000000hea",
        protocol_version="oev-receipt/0.1",
        recorded_verification_time=CLAIMED_TIME,
        package=PackageReference(digest=bundle_digest, format="oept-bundle/0.1"),
        profile=ProfileReference(
            profile_id=profile.profile_id,
            profile_version=profile.profile_version,
            profile_digest=profile_digest,
        ),
        verifier=VerifierIdentity(software="oev-test", version="0.2.3"),
        trust_inputs=[TrustInput(trust_id="k1", type="public_key", digest="sha256:" + "3" * 64)],
        checks=checks,
        limitations=[Limitation(code="TEST", description="synthetic test receipt", material=False)],
        overall_result=OverallResult.TECHNICAL_CHECKS_PASSED,
        execution_attestations=[
            {"check_id": cid, "attestation_digest": digest}
            for cid, digest in sorted(digests.items())
        ],
    )
    receipt = finalize_receipt(raw_receipt)
    return {
        "package_bytes": package_bytes,
        "profile": profile,
        "receipt": receipt,
        "checks": checks,
        "execution_id": execution_id,
        "prebinding": prebinding,
        "commitment_envelope": commitment_envelope,
        "commitment_digest": commitment_digest,
        "attestation_envelopes": [envelopes[cid] for cid in sorted(envelopes)],
        "attestation_envelopes_by_id": envelopes,
        "log_events": events,
        "log_jsonl": service.export_log_jsonl(),
        "checkpoint_envelope": checkpoint_envelope,
        "inclusion_proofs": proofs,
        "witness_store": witness_store,
        "checkpoint_store": checkpoint_store,
        "witness_private": wit_priv,
        "checkpoint_private": cp_priv,
        "code_digest": code_version["code_digest"],
        "service": service,
        "log_path": log_path,
    }


POLICY = "sha256:" + "a" * 64


def _doc(code_digest: str, **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "protocol_version": "oev-code-digest/0.1",
        "engine": "oev 0.2.3-test",
        "adapter": "oept 0.1.3-test",
        "code_digest": code_digest,
    }
    doc.update(extra)
    return doc


def test_build_code_digest_document_validates(tmp_path: Path) -> None:
    doc = build_code_digest_document("oev 0.2.3-test", "oept 0.1.3-test")
    validate_code_digest_document(doc)
    assert doc["code_digest"].startswith("sha256:")
    assert doc["environment"]["python_version"]
    assert doc["environment"]["venv_fingerprint"].startswith("sha256:")
    # Deterministic for the same install.
    again = build_code_digest_document("oev 0.2.3-test", "oept 0.1.3-test")
    assert again["code_digest"] == doc["code_digest"]
    assert again["environment"]["venv_fingerprint"] == doc["environment"]["venv_fingerprint"]


def test_build_code_version_enrichment(tmp_path: Path) -> None:
    plain = build_code_version("oev", "oept")
    assert set(plain) == {"engine", "adapter", "code_digest"}
    enriched = build_code_version(
        "oev",
        "oept",
        policy_digest=POLICY,
        dependencies=[{"name": "cryptography", "version": "1.0"}],
        include_environment=True,
    )
    assert enriched["policy_digest"] == POLICY
    assert enriched["dependencies"] == [{"name": "cryptography", "version": "1.0"}]
    assert enriched["environment"]["python_version"]


def test_matching_document_proves(tmp_path: Path) -> None:
    code_version = build_code_version(
        "oev 0.2.3-test", "oept 0.1.3-test", policy_digest=POLICY, include_environment=True
    )
    bundle = _rebuild_with_code_version(tmp_path, code_version)
    expected = _doc(bundle["code_digest"], policy_digest=POLICY)
    expected["environment"] = dict(code_version["environment"])
    result = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=expected))
    assert result.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_policy_digest_mismatch_fails(tmp_path: Path) -> None:
    code_version = build_code_version("oev 0.2.3-test", "oept 0.1.3-test", policy_digest=POLICY)
    bundle = _rebuild_with_code_version(tmp_path, code_version)
    expected = _doc(bundle["code_digest"], policy_digest="sha256:" + "b" * 64)
    result = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=expected))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "CODE_DIGEST_MISMATCH"


def test_missing_attested_policy_digest_fails_when_pinned(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)  # plain code_version, no policy_digest
    expected = _doc(bundle["code_digest"], policy_digest=POLICY)
    result = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=expected))
    assert result.reason == "CODE_DIGEST_MISMATCH"


def test_dependency_version_mismatch_fails(tmp_path: Path) -> None:
    code_version = build_code_version(
        "oev 0.2.3-test",
        "oept 0.1.3-test",
        dependencies=[{"name": "cryptography", "version": "44.0.0"}],
    )
    bundle = _rebuild_with_code_version(tmp_path, code_version)
    expected = _doc(
        bundle["code_digest"],
        dependencies=[{"name": "cryptography", "version": "43.0.0"}],
    )
    result = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=expected))
    assert result.reason == "CODE_DIGEST_MISMATCH"
    # Same pinned version passes.
    expected_ok = _doc(
        bundle["code_digest"],
        dependencies=[{"name": "cryptography", "version": "44.0.0"}],
    )
    ok = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=expected_ok))
    assert ok.historical_execution == "HISTORICAL_EXECUTION_PROVEN"


def test_python_version_mismatch_fails_but_os_mismatch_is_note(tmp_path: Path) -> None:
    code_version = build_code_version("oev 0.2.3-test", "oept 0.1.3-test", include_environment=True)
    bundle = _rebuild_with_code_version(tmp_path, code_version)
    env = dict(code_version["environment"])
    wrong_py = _doc(bundle["code_digest"], environment={**env, "python_version": "2.7.0"})
    result = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=wrong_py))
    assert result.reason == "CODE_DIGEST_MISMATCH"
    wrong_os = _doc(bundle["code_digest"], environment={**env, "os": "Windows"})
    noted = verify_historical_execution(hea_inputs(bundle, expected_code_digest_document=wrong_os))
    assert noted.historical_execution == "HISTORICAL_EXECUTION_PROVEN"
    assert any("os" in n for n in noted.notes)


def test_invalid_expected_document_is_mismatch_not_crash(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    result = verify_historical_execution(
        hea_inputs(
            bundle,
            expected_code_digest_document={"protocol_version": "oev-code-digest/9.9"},
        )
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "CODE_DIGEST_MISMATCH"


def test_compare_unit() -> None:
    attested = {
        "code_digest": "sha256:" + "c" * 64,
        "policy_digest": POLICY,
        "dependencies": [{"name": "cryptography", "version": "44.0.0"}],
        "environment": {"python_version": "3.12.3", "os": "Linux", "platform": "Linux-x86_64"},
    }
    mismatches, notes = compare_code_digest_document(_doc("sha256:" + "c" * 64), attested)
    assert mismatches == [] and notes == []
    mismatches, _ = compare_code_digest_document(
        _doc("sha256:" + "c" * 64, policy_digest="sha256:" + "d" * 64), attested
    )
    assert mismatches
    with pytest.raises(ValueError):
        compare_code_digest_document({"protocol_version": "bogus"}, attested)
