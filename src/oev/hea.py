# SPDX-License-Identifier: Apache-2.0

"""Witnessed verification runs (HEA design §1.3 flow + Ek A scenario).

``run_witnessed_verification`` drives the full pre-binding → execution →
attestation → checkpoint flow with a Model A witness (separate process):

1. The witness observes bundle/profile digests itself (reads the files)
   and reports its own code digest.
2. The witness issues a commitment with a fresh nonce; the Execution ID
   is derived from the pre-binding.
3. The producer executes the checks (``engine.execute_verification``).
4. Each executed check is logged (CHECK_COMPLETED) and attested
   individually by the witness; the log is checkpointed.
5. The receipt is finalised *with* ``execution_attestations[]`` binding
   the attestation digests, so the receipt digest covers them (§5.2).

Circularity note (§5.2): attestations are produced before the receipt
exists, so they carry no ``receipt_digest``; the receipt-to-attestation
binding in ``execution_attestations[]`` is the authoritative link, and
the offline verifier checks result equality plus digest equality
(``hea_verifier.py`` step 6).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from oev import __version__ as _oev_version
from oev.attestation import compute_attestation_digest
from oev.canonical import canonicalize_json
from oev.engine import execute_verification, utc_now_iso
from oev.execution import build_prebinding, compute_trust_inputs_digest
from oev.execution_log import events_from_jsonl, merkle_inclusion_proof
from oev.hashing import sha256_bytes
from oev.models import CHECK_STATUS_EXECUTED, CheckStatus, OverallResult
from oev.profiles import compute_profile_digest, load_profile
from oev.receipts import finalize_receipt
from oev.signing import sign_receipt_dsse
from oev.witness import LocalProcessWitness, WitnessService, build_attestation_payload

ENGINE_LABEL = f"oev {_oev_version}"


def run_witnessed_verification(
    package_path: str | Path,
    profile_path: str | Path,
    witness: WitnessService | LocalProcessWitness,
    out_dir: str | Path,
    package_trust_keys: list[dict[str, Any]] | None = None,
    receipt_signing_key_pem: bytes | None = None,
    receipt_signer_key_id: str = "",
    adapter_label: str = "oept 0.1.3",
) -> dict[str, Any]:
    """Run a witnessed verification and write HEA artifacts to ``out_dir``.

    Returns a summary dict (execution_id, receipt_digest, overall_result,
    per-check attestation digests, artifact paths). Raises ValueError on
    any digest disagreement between producer and witness observations.
    """
    package_path = Path(package_path)
    profile_path = Path(profile_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    attest_dir = out_dir / "attestations"
    attest_dir.mkdir(parents=True, exist_ok=True)

    package_bytes = package_path.read_bytes()
    if len(package_bytes) > 512 * 1024 * 1024:
        raise ValueError("Package exceeds the 512 MiB bound")
    profile = load_profile(profile_path)
    claimed_time = utc_now_iso()

    # 1. Witness observes digests itself; the producer cross-checks.
    witness_bundle_digest = witness.observe_file(package_path)
    witness_profile_digest = witness.observe_file(profile_path)
    local_bundle_digest = sha256_bytes(package_bytes)
    local_profile_digest = compute_profile_digest(profile)
    if witness_bundle_digest != local_bundle_digest:
        raise ValueError("Witness bundle digest disagrees with producer digest")
    if witness_profile_digest != local_profile_digest:
        raise ValueError("Witness profile digest disagrees with producer digest")
    code_digest = witness.code_digest()
    code_version = {"engine": ENGINE_LABEL, "adapter": adapter_label, "code_digest": code_digest}

    check_ids = list(dict.fromkeys(profile.required_checks + profile.optional_checks))
    trust_inputs_digest = compute_trust_inputs_digest(
        [
            {
                "trust_id": str(k.get("key_id", "")),
                "type": "public_key",
                "digest": sha256_bytes(
                    k["public_key_pem"].encode("utf-8")
                    if isinstance(k.get("public_key_pem"), str)
                    else bytes(k.get("public_key_pem", b""))
                ),
            }
            for k in (package_trust_keys or [])
        ]
    )
    partial_prebinding = build_prebinding(
        bundle_digest=witness_bundle_digest,
        bundle_format=profile.target_format,
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_digest=witness_profile_digest,
        code_version=code_version,
        check_ids=check_ids,
        input_digests={
            "package": witness_bundle_digest,
            "profile": witness_profile_digest,
        },
        trust_inputs_digest=trust_inputs_digest,
        nonce=None,  # witness-generated; any producer nonce is discarded
        witness_mode="local-process",
        witness_key_id=witness.key_id,
    )

    # 2. Commitment (witness fills the nonce, derives the Execution ID).
    commitment_result = witness.issue_commitment(partial_prebinding, claimed_time)
    execution_id = str(commitment_result["execution_id"])
    prebinding = dict(commitment_result["prebinding"])
    commitment_envelope = dict(commitment_result["commitment_envelope"])
    commitment_digest = str(commitment_result["commitment_digest"])

    # 3. Execution (producer).
    witness.start_execution(execution_id, commitment_digest, claimed_time)
    receipt, _receipt_envelope = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
        package_trust_keys=package_trust_keys,
    )
    execution_status = (
        "INTERRUPTED"
        if receipt.overall_result == OverallResult.EXECUTION_INCOMPLETE
        else "COMPLETED"
    )
    completion_status = (
        "FAILED" if receipt.overall_result == OverallResult.EXECUTION_INCOMPLETE else "COMPLETED"
    )

    # 4. Per-check log + attestation (NOT_RUN checks: no event, no attestation).
    attestation_envelopes: dict[str, dict[str, Any]] = {}
    attestation_digests: dict[str, str] = {}
    log_anchors: dict[str, dict[str, Any]] = {}
    for check in receipt.checks:
        status = str(check.status.value if isinstance(check.status, CheckStatus) else check.status)
        if status not in CHECK_STATUS_EXECUTED:
            continue
        result_digest = sha256_bytes(canonicalize_json(check.to_dict()))
        completed = witness.check_completed(
            execution_id, check.check_id, result_digest, claimed_time
        )
        event = dict(completed["event"])
        anchor = {
            "log_id": event["log_id"],
            "leaf_index": int(event["seq"]),
            "leaf_hash": str(completed["leaf_hash"]),
        }
        log_anchors[check.check_id] = anchor
        payload = build_attestation_payload(
            execution_id=execution_id,
            commitment_digest=commitment_digest,
            bundle_digest=witness_bundle_digest,
            profile_digest=witness_profile_digest,
            code_version=code_version,
            check_id=check.check_id,
            result_status=status,
            result_detail=check.detail,
            result_duration_ms=check.duration_ms,
            execution_status=execution_status,
            log_anchor=anchor,
            claimed_time=claimed_time,
            witness_key_id=witness.key_id,
        )
        envelope = witness.attest(payload)
        attestation_envelopes[check.check_id] = (
            dict(envelope["envelope"]) if "envelope" in envelope else dict(envelope)
        )
        attestation_digests[check.check_id] = compute_attestation_digest(payload)

    witness.complete_execution(execution_id, completion_status, claimed_time)

    # 5. Checkpoint + inclusion proofs.
    checkpoint_result = witness.checkpoint(claimed_time)
    checkpoint_envelope = dict(checkpoint_result["envelope"])
    checkpoint = dict(checkpoint_result["checkpoint"])
    log_bytes = (
        (out_dir / "execution-log.jsonl").read_bytes()
        if (out_dir / "execution-log.jsonl").is_file()
        else None
    )
    if log_bytes is None:
        # In-process witness keeps the log in memory; export it.
        if isinstance(witness, WitnessService):
            log_bytes = witness.export_log_jsonl()
        else:
            raise RuntimeError("Witness log file was not produced by the worker")
    log_events = events_from_jsonl(log_bytes)
    leaves = [e.leaf_hash() for e in log_events]
    inclusion_proofs = {
        check_id: merkle_inclusion_proof(leaves, int(anchor["leaf_index"]))
        for check_id, anchor in log_anchors.items()
    }

    # 6. Receipt finalised WITH the attestation binding (§5.2 rule 2).
    receipt_dict = receipt.to_dict(include_digest=False)
    receipt_dict["execution_attestations"] = [
        {"check_id": check_id, "attestation_digest": digest}
        for check_id, digest in sorted(attestation_digests.items())
    ]
    final_receipt = finalize_receipt(receipt_dict)
    receipt_envelope: dict[str, Any] | None = None
    if receipt_signing_key_pem is not None:
        receipt_envelope = sign_receipt_dsse(
            receipt=final_receipt,
            private_key_pem=receipt_signing_key_pem,
            key_id=receipt_signer_key_id,
        )

    # 7. Write artifacts.
    receipt_path = out_dir / "receipt.json"
    if receipt_envelope is not None:
        receipt_path.write_bytes(canonicalize_json(receipt_envelope))
    else:
        receipt_path.write_bytes(canonicalize_json(final_receipt.to_dict(include_digest=True)))
    for check_id, envelope in attestation_envelopes.items():
        (attest_dir / f"{check_id}.dsse.json").write_bytes(canonicalize_json(envelope))
    (out_dir / "execution-log.jsonl").write_bytes(log_bytes)
    (out_dir / "checkpoint.dsse.json").write_bytes(canonicalize_json(checkpoint_envelope))
    (out_dir / "commitment.dsse.json").write_bytes(canonicalize_json(commitment_envelope))
    (out_dir / "prebinding.json").write_bytes(canonicalize_json(prebinding))
    manifest = {
        "protocol_version": "oev-attestation/0.1",
        "execution_id": execution_id,
        "commitment_digest": commitment_digest,
        "receipt_digest": final_receipt.receipt_digest,
        "overall_result": str(
            final_receipt.overall_result.value
            if isinstance(final_receipt.overall_result, OverallResult)
            else final_receipt.overall_result
        ),
        "witness_mode": "local-process",
        "witness_key_id": witness.key_id,
        "code_digest": code_digest,
        "checkpoint": checkpoint,
        "inclusion_proofs": inclusion_proofs,
        "attestation_digests": attestation_digests,
        "notes": [
            "Time is NOT proven: claimed_time fields are self-asserted; ordering comes from log sequence only.",
            "Model A witness: separate process, same machine; no protection against machine compromise.",
        ],
    }
    (out_dir / "hea-manifest.json").write_bytes(canonicalize_json(manifest))

    return {
        "execution_id": execution_id,
        "commitment_digest": commitment_digest,
        "receipt_digest": final_receipt.receipt_digest,
        "overall_result": manifest["overall_result"],
        "witness_mode": "local-process",
        "witness_key_id": witness.key_id,
        "attested_checks": sorted(attestation_digests),
        "out_dir": str(out_dir),
        "receipt_path": str(receipt_path),
        "manifest_path": str(out_dir / "hea-manifest.json"),
    }
