# SPDX-License-Identifier: Apache-2.0

"""Round-3 (P0) malformed-timestamp tests.

A malformed ``claimed_time`` / ``issued_at_claimed`` in a validly signed
attestation or commitment previously crashed ``verify_historical_execution``
with an uncaught ``ValueError`` (from ``key_state_at`` /
``parse_hea_timestamp``). It must now fail closed as a controlled
``HISTORICAL_EXECUTION_UNPROVEN`` verdict — ``MALFORMED_ATTESTATION``
for attestations, ``NO_PREBINDING`` for commitments — and the library
must refuse to *issue* such envelopes in the first place.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from oev.attestation import ATTESTATION_PAYLOAD_TYPE
from oev.canonical import canonicalize_json
from oev.dsse import build_dsse_envelope, compute_pae
from oev.execution import COMMITMENT_PAYLOAD_TYPE, ExecutionCommitment
from oev.hea_verifier import verify_historical_execution
from oev.signing import load_ed25519_private_key
from oev.witness import build_attestation_payload
from tests.hea_helpers import build_valid_hea, hea_inputs

MALFORMED_TIMESTAMPS = [
    "not-a-timestamp",
    "2026-11-13 07:20:00",  # space instead of T
    "2026-11-13T07:20:00",  # missing Z
    "2026-11-13T07:20:00+03:00",  # offset instead of Z
    "2026-02-30T00:00:00Z",  # impossible date
    "2026-11-13T07:20:00.123Z",  # fractional seconds
    "2026-11-13T07:20:00z",  # lowercase z
    "2026-13-45T99:99:99Z",  # out-of-range fields
    "",
]


def _raw_sign_attestation(payload: dict[str, Any], priv: bytes, key_id: str) -> dict[str, Any]:
    """DSSE-sign an attestation payload with raw crypto (no validation).

    Mirrors ``run_hea_vectors._sign_attestation_raw``: used ONLY to
    simulate an envelope produced outside this library. The verifier —
    not the signer — is what must catch the malformed timestamp.
    """
    payload_bytes = canonicalize_json(payload)
    raw_sig = load_ed25519_private_key(priv).sign(
        compute_pae(ATTESTATION_PAYLOAD_TYPE, payload_bytes)
    )
    return build_dsse_envelope(
        payload_type=ATTESTATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[{"sig": base64.b64encode(raw_sig).decode("ascii"), "keyid": key_id}],
    )


def _raw_sign_commitment(payload: dict[str, Any], priv: bytes, key_id: str) -> dict[str, Any]:
    payload_bytes = canonicalize_json(payload)
    raw_sig = load_ed25519_private_key(priv).sign(
        compute_pae(COMMITMENT_PAYLOAD_TYPE, payload_bytes)
    )
    return build_dsse_envelope(
        payload_type=COMMITMENT_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[{"sig": base64.b64encode(raw_sig).decode("ascii"), "keyid": key_id}],
    )


def _attestation_with_claimed_time(bundle: dict[str, Any], claimed_time: str) -> dict[str, Any]:
    from oev.attestation import parse_attestation_envelope

    orig = parse_attestation_envelope(bundle["attestation_envelopes_by_id"]["archive_safety"])
    payload = build_attestation_payload(
        execution_id=bundle["execution_id"],
        commitment_digest=bundle["commitment_digest"],
        bundle_digest=bundle["receipt"].package.digest,
        profile_digest=bundle["receipt"].profile.profile_digest,
        code_version=dict(orig["code_version"]),
        check_id="archive_safety",
        result_status="PASS",
        result_detail="",
        result_duration_ms=0,
        execution_status="COMPLETED",
        log_anchor=dict(orig["log_anchor"]),
        claimed_time=claimed_time,
        witness_key_id="wit-1",
    )
    return _raw_sign_attestation(payload, bundle["witness_private"], "wit-1")


@pytest.mark.parametrize("bad_time", MALFORMED_TIMESTAMPS)
def test_malformed_attestation_claimed_time_is_unproven_not_crash(
    tmp_path: Path, bad_time: str
) -> None:
    bundle = build_valid_hea(tmp_path)
    bad = _attestation_with_claimed_time(bundle, bad_time)
    result = verify_historical_execution(
        hea_inputs(
            bundle,
            attestations=[bad, bundle["attestation_envelopes_by_id"]["manifest_structure"]],
        )
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "MALFORMED_ATTESTATION"


def test_malformed_commitment_issued_at_is_unproven_not_crash(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    pre = dict(bundle["prebinding"])
    commitment = ExecutionCommitment(
        execution_id=bundle["execution_id"],
        nonce=str(pre["nonce"]),
        bundle_digest=str(pre["bundle_digest"]),
        profile_digest=str(pre["profile_digest"]),
        code_version=dict(pre["code_version"]),
        check_ids=[str(c) for c in pre["check_ids"]],
        input_digests={str(k): str(v) for k, v in dict(pre.get("input_digests", {})).items()},
        issued_at_claimed="garbage-time",
    )
    envelope = _raw_sign_commitment(commitment.to_dict(), bundle["witness_private"], "wit-1")
    result = verify_historical_execution(
        hea_inputs(bundle, commitment_envelope=envelope, prebinding=pre)
    )
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
    assert result.reason == "NO_PREBINDING"


def test_witness_refuses_to_issue_malformed_claimed_time(tmp_path: Path) -> None:
    """Issuance fails closed: the witness never signs a bad timestamp."""
    bundle = build_valid_hea(tmp_path)
    service = bundle["service"]
    with pytest.raises(ValueError):
        service.issue_commitment(dict(bundle["prebinding"]), "2026-02-30T00:00:00Z")
    with pytest.raises(ValueError):
        service.attest(
            build_attestation_payload(
                execution_id=bundle["execution_id"],
                commitment_digest=bundle["commitment_digest"],
                bundle_digest=bundle["receipt"].package.digest,
                profile_digest=bundle["receipt"].profile.profile_digest,
                code_version={
                    "engine": "oev",
                    "adapter": "oept",
                    "code_digest": bundle["code_digest"],
                },
                check_id="archive_safety",
                result_status="PASS",
                result_detail="",
                result_duration_ms=0,
                execution_status="COMPLETED",
                log_anchor={
                    "log_id": "hea-log-001",
                    "leaf_index": 1,
                    "leaf_hash": "sha256:" + "0" * 64,
                },
                claimed_time="tomorrow-ish",
                witness_key_id="wit-1",
            )
        )
