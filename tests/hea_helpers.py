# SPDX-License-Identifier: Apache-2.0

"""Shared builders for HEA tests: keys, witness service, valid HEA bundles.

A "valid HEA bundle" is a synthetic package + profile + receipt + witness
commitment + per-check attestations + hash-chained log + signed checkpoint
that the offline verifier accepts as HISTORICAL_EXECUTION_PROVEN. Tests
mutate one element at a time and assert the expected fail-closed reason.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from oev.attestation import compute_attestation_digest
from oev.canonical import canonicalize_json
from oev.execution import build_prebinding, compute_trust_inputs_digest
from oev.execution_log import merkle_inclusion_proof
from oev.hashing import sha256_bytes
from oev.hea_verifier import HeaVerificationInputs
from oev.models import (
    CheckResult,
    CheckStatus,
    Limitation,
    OverallResult,
    PackageReference,
    ProfileReference,
    TrustInput,
    VerificationProfile,
    VerificationReceipt,
    VerifierIdentity,
)
from oev.profiles import compute_profile_digest
from oev.receipts import finalize_receipt
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore
from oev.witness import WitnessService, build_attestation_payload

CLAIMED_TIME = "2026-11-13T07:20:00Z"
NOT_BEFORE = "2026-01-01T00:00:00Z"
NOT_AFTER = "2027-12-31T23:59:59Z"


def make_keypair(
    role: str | None = None, not_before: str = NOT_BEFORE
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Generate a fresh Ed25519 keypair and its trust-store dict."""
    priv, pub = generate_ed25519_keypair()
    entry: dict[str, Any] = {"public_key_pem": pub.decode("utf-8")}
    if role is not None:
        entry["role"] = role
    if role == "witness":
        entry["not_before"] = not_before
        entry["not_after"] = NOT_AFTER
    if role == "checkpoint-signer":
        entry["not_after"] = NOT_AFTER
    return priv, pub, entry


def make_profile(
    required: list[str] | None = None, optional: list[str] | None = None
) -> VerificationProfile:
    return VerificationProfile(
        profile_id="strict-conformance-profile",
        profile_version="0.1.0",
        target_format="oept-bundle/0.1",
        required_checks=required or ["archive_safety", "manifest_structure"],
        optional_checks=optional or [],
        parameters={},
    )


def make_package_bytes() -> bytes:
    return b"HEA test package bytes - deterministic fixture content"


def build_valid_hea(
    tmp_path: Path,
    checks: list[CheckResult] | None = None,
    overall: OverallResult = OverallResult.TECHNICAL_CHECKS_PASSED,
    profile: VerificationProfile | None = None,
    witness_role: str = "witness",
    claimed_time: str = CLAIMED_TIME,
    key_not_before: str = NOT_BEFORE,
) -> dict[str, Any]:
    """Build a complete valid HEA bundle (in-process witness).

    Returns a dict with every input the offline verifier needs, plus the
    witness service and key material for mutation tests.
    """
    profile = profile or make_profile()
    package_bytes = make_package_bytes()
    checks = checks or [
        CheckResult(check_id="archive_safety", category="safety", status=CheckStatus.PASS),
        CheckResult(check_id="manifest_structure", category="structure", status=CheckStatus.PASS),
    ]

    wit_priv, _wit_pub, wit_entry = make_keypair(role=witness_role, not_before=key_not_before)
    wit_entry["key_id"] = "wit-1"
    cp_priv, _cp_pub, cp_entry = make_keypair(role="checkpoint-signer")
    cp_entry["key_id"] = "cp-1"
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
    profile_dict = profile.to_dict()
    profile_bytes = canonicalize_json(profile_dict)
    profile_digest = service.observe_bytes("profile", profile_bytes)
    assert bundle_digest == sha256_bytes(package_bytes)
    assert profile_digest == compute_profile_digest(profile)
    code_version = {
        "engine": "oev 0.2.3-test",
        "adapter": "oept 0.1.3-test",
        "code_digest": service.code_digest(),
    }
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
    commitment_result = service.issue_commitment(partial, claimed_time)
    execution_id = str(commitment_result["execution_id"])
    commitment_envelope = dict(commitment_result["commitment_envelope"])
    commitment_digest = str(commitment_result["commitment_digest"])
    prebinding = dict(commitment_result["prebinding"])
    service.start_execution(execution_id, commitment_digest, claimed_time)

    anchors: dict[str, dict[str, Any]] = {}
    for check in checks:
        status = str(check.status.value if isinstance(check.status, CheckStatus) else check.status)
        if status == "NOT_RUN":
            continue
        result_digest = sha256_bytes(canonicalize_json(check.to_dict()))
        completed = service.check_completed(
            execution_id, check.check_id, result_digest, claimed_time
        )
        event = dict(completed["event"])
        anchors[check.check_id] = {
            "log_id": event["log_id"],
            "leaf_index": int(event["seq"]),
            "leaf_hash": str(completed["leaf_hash"]),
        }
    service.complete_execution(execution_id, "COMPLETED", claimed_time)

    envelopes: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for check in checks:
        status = str(check.status.value if isinstance(check.status, CheckStatus) else check.status)
        if status == "NOT_RUN":
            continue
        payload = build_attestation_payload(
            execution_id=execution_id,
            commitment_digest=commitment_digest,
            bundle_digest=bundle_digest,
            profile_digest=profile_digest,
            code_version=code_version,
            check_id=check.check_id,
            result_status=status,
            result_detail=check.detail,
            result_duration_ms=check.duration_ms,
            execution_status="COMPLETED",
            log_anchor=anchors[check.check_id],
            claimed_time=claimed_time,
            witness_key_id="wit-1",
        )
        envelopes[check.check_id] = service.attest(payload)
        digests[check.check_id] = compute_attestation_digest(payload)

    checkpoint_result = service.checkpoint(claimed_time)
    checkpoint_envelope = dict(checkpoint_result["envelope"])
    events = service.events
    leaves = [e.leaf_hash() for e in events]
    proofs = {
        check_id: merkle_inclusion_proof(leaves, int(anchor["leaf_index"]))
        for check_id, anchor in anchors.items()
    }

    raw_receipt = VerificationReceipt(
        receipt_id="00000000-0000-4000-8000-0000000000hea",
        protocol_version="oev-receipt/0.1",
        recorded_verification_time=claimed_time,
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
        overall_result=overall,
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
        "attestation_digests": digests,
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


def hea_inputs(bundle: dict[str, Any], **overrides: Any) -> HeaVerificationInputs:
    """Build HeaVerificationInputs from a bundle dict (overrides win)."""
    kwargs: dict[str, Any] = {
        "package_bytes": bundle["package_bytes"],
        "receipt": bundle["receipt"],
        "profile": bundle["profile"],
        "attestations": bundle["attestation_envelopes"],
        "commitment_envelope": bundle["commitment_envelope"],
        "prebinding": bundle["prebinding"],
        "log_events": bundle["log_events"],
        "checkpoint_envelope": bundle["checkpoint_envelope"],
        "inclusion_proofs": bundle["inclusion_proofs"],
        "witness_trust_store": bundle["witness_store"],
        "checkpoint_trust_store": bundle["checkpoint_store"],
        "expected_code_digest": bundle["code_digest"],
    }
    kwargs.update(overrides)
    return HeaVerificationInputs(**kwargs)


def write_trust_store_json(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path
