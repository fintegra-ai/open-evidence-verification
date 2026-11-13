# SPDX-License-Identifier: Apache-2.0

"""Command-Line Interface (CLI) for Open Evidence Verification Protocol (OEVP)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from oev.adapters.base import OptionalDependencyMissingError
from oev.canonical import canonicalize_json, safe_json_loads
from oev.decision_pack import build_pack, sign_pack_manifest
from oev.engine import execute_verification, utc_now_iso
from oev.fileio import MAX_PACKAGE_BYTES, read_bounded_file
from oev.hea import run_witnessed_verification
from oev.hea_verifier import (
    HeaVerificationInputs,
    assess_disproven,
    verify_historical_execution,
)
from oev.inspect import inspect_receipt_file
from oev.models import OverallResult
from oev.pack_verifier import (
    build_pack_verification_receipt,
    sign_pack_receipt,
    verify_pack_offline,
    verify_pack_receipt,
)
from oev.profiles import load_profile
from oev.replay import ReplayError, replay_snapshot
from oev.reverify import _extract_receipt, reverify_package
from oev.trust import TrustStore
from oev.witness import LocalProcessWitness

NOTICE_FOOTER = "Technical verification only — not a legal, compliance, or factual conclusion."
INSPECTION_FOOTER = (
    "Receipt inspection describes a verifier's recorded technical appraisal.\n"
    "It does not independently verify the referenced package."
)


def cmd_verify(args: argparse.Namespace) -> int:
    package_path = Path(args.package)
    profile_path = Path(args.profile)

    if not package_path.is_file():
        sys.stderr.write(f"Error: package file not found: {package_path}\n")
        return 1
    if not profile_path.is_file():
        sys.stderr.write(f"Error: profile file not found: {profile_path}\n")
        return 1

    package_bytes = read_bounded_file(package_path, MAX_PACKAGE_BYTES)
    profile = load_profile(profile_path)

    package_trust_keys: list[dict[str, Any]] | None = None
    if args.trust_keys:
        tk_path = Path(args.trust_keys)
        if not tk_path.is_file():
            sys.stderr.write(f"Error: package trust keys file not found: {tk_path}\n")
            return 1
        package_trust_keys = safe_json_loads(read_bounded_file(tk_path))

    private_key_pem: bytes | None = None
    if args.sign_receipt:
        sk_path = Path(args.sign_receipt)
        if not sk_path.is_file():
            sys.stderr.write(f"Error: signing key file not found: {sk_path}\n")
            return 1
        private_key_pem = read_bounded_file(sk_path)

    try:
        receipt, envelope = execute_verification(
            package_bytes=package_bytes,
            profile=profile,
            package_trust_keys=package_trust_keys,
            private_key_pem=private_key_pem,
            signer_key_id=args.signer_key_id or "",
        )
    except OptionalDependencyMissingError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    out_obj = envelope if envelope is not None else receipt.to_dict(include_digest=True)
    out_json = canonicalize_json(out_obj).decode("utf-8")

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(out_json, encoding="utf-8")
        print(f"Receipt written to {out_path}")
    else:
        print(out_json)

    res_val = (
        receipt.overall_result.value
        if hasattr(receipt.overall_result, "value")
        else str(receipt.overall_result)
    )
    print(f"\nOverall Result: {res_val}")
    print(f"{NOTICE_FOOTER}")
    return 0 if res_val == OverallResult.TECHNICAL_CHECKS_PASSED.value else 2


def cmd_inspect_receipt(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        sys.stderr.write(f"Error: receipt file not found: {receipt_path}\n")
        return 1

    trust_store: TrustStore | None = None
    if args.verifier_keys:
        vk_path = Path(args.verifier_keys)
        if not vk_path.is_file():
            sys.stderr.write(f"Error: verifier keys file not found: {vk_path}\n")
            return 1
        trust_store = TrustStore.from_file(vk_path)

    result = inspect_receipt_file(receipt_path, verifier_trust_store=trust_store)

    if args.json:
        print(canonicalize_json(result.to_dict()).decode("utf-8"))
    else:
        print(result.format_human())

    return 0 if result.receipt_digest_valid else 1


def cmd_reverify(args: argparse.Namespace) -> int:
    package_path = Path(args.package)
    receipt_path = Path(args.receipt)
    profile_path = Path(args.profile)

    if not package_path.is_file():
        sys.stderr.write(f"Error: package file not found: {package_path}\n")
        return 1
    if not receipt_path.is_file():
        sys.stderr.write(f"Error: receipt file not found: {receipt_path}\n")
        return 1
    if not profile_path.is_file():
        sys.stderr.write(f"Error: profile file not found: {profile_path}\n")
        return 1

    package_bytes = read_bounded_file(package_path, MAX_PACKAGE_BYTES)
    profile = load_profile(profile_path)

    package_trust_keys: list[dict[str, Any]] | None = None
    if args.trust_keys:
        tk_path = Path(args.trust_keys)
        if not tk_path.is_file():
            sys.stderr.write(f"Error: package trust keys file not found: {tk_path}\n")
            return 1
        package_trust_keys = safe_json_loads(read_bounded_file(tk_path))

    try:
        report = reverify_package(
            package_bytes=package_bytes,
            receipt_source=receipt_path,
            profile_source=profile,
            package_trust_keys=package_trust_keys,
        )
    except OptionalDependencyMissingError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    if args.json:
        print(canonicalize_json(report.to_dict()).decode("utf-8"))
    else:
        print("=" * 70)
        print("OEVP PACKAGE RE-VERIFICATION REPORT")
        print("=" * 70)
        print(f"Receipt Self-Digest:     {report.receipt_digest}")
        print(f"Package Digest Match:    {'YES' if report.package_digest_match else 'NO'}")
        print(f"Profile Digest Match:    {'YES' if report.profile_digest_match else 'NO'}")
        print(f"Re-verification Result:  {report.reverification_result}")
        if report.check_differences:
            print("-" * 70)
            print(f"Check Differences ({len(report.check_differences)}):")
            for diff in report.check_differences:
                print(
                    f"  * {diff['check_id']}: Historical={diff['historical_status']}, Fresh={diff['fresh_status']}"
                )
        if report.notes:
            print("-" * 70)
            print("Notes:")
            for n in report.notes:
                print(f"  * {n}")
        print("=" * 70)
        print(f"{NOTICE_FOOTER}")
        print(
            "Re-verification establishes reproducibility, not receipt authenticity;\n"
            "verify the receipt signer separately with 'oev receipt verify'."
        )

    return 0 if report.reverification_result == "MATCH" else 2


def cmd_receipt_verify(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        sys.stderr.write(f"Error: receipt file not found: {receipt_path}\n")
        return 1

    if not args.verifier_keys:
        sys.stderr.write("Error: --verifier-keys is required to verify receipt signer trust\n")
        return 1

    vk_path = Path(args.verifier_keys)
    if not vk_path.is_file():
        sys.stderr.write(f"Error: verifier keys file not found: {vk_path}\n")
        return 1

    trust_store = TrustStore.from_file(vk_path)
    result = inspect_receipt_file(receipt_path, verifier_trust_store=trust_store)

    if args.json:
        out = {
            "receipt_id": result.receipt.receipt_id,
            "receipt_digest_valid": result.receipt_digest_valid,
            "is_dsse_signed": result.is_dsse_signed,
            "crypto_valid": result.crypto_valid,
            "is_trusted_signer": result.is_trusted_signer,
            "trusted_signer_key_id": result.trusted_signer_key_id,
        }
        print(canonicalize_json(out).decode("utf-8"))
    else:
        print("=" * 70)
        print("OEVP RECEIPT SIGNATURE VERIFICATION")
        print("=" * 70)
        print(f"Receipt ID:             {result.receipt.receipt_id}")
        print(
            f"Receipt Self-Digest:    {result.receipt.receipt_digest} ({'VALID' if result.receipt_digest_valid else 'INVALID'})"
        )
        print(f"DSSE Envelope Signed:   {'YES' if result.is_dsse_signed else 'NO'}")
        print(f"Signature Crypto Valid: {'YES' if result.crypto_valid else 'NO'}")
        print(f"Signer Trusted:         {'YES' if result.is_trusted_signer else 'NO'}")
        print(f"Trusted Key ID:         {result.trusted_signer_key_id or 'None'}")
        print("=" * 70)
        print(f"{NOTICE_FOOTER}")
        print(f"{INSPECTION_FOOTER}")

    if not result.receipt_digest_valid:
        return 1
    if not (result.is_dsse_signed and result.is_trusted_signer):
        return 2
    return 0


PACK_NOTICE_FOOTER = (
    "Technical integrity verification only — not a legal, compliance, factual, or\n"
    "commercial conclusion. Pack validity does not re-execute rules and does not\n"
    "assert that any recorded decision was correct."
)


def cmd_pack_build(args: argparse.Namespace) -> int:
    src_dir = Path(args.source)
    out_dir = Path(args.out)

    if not src_dir.is_dir():
        sys.stderr.write(f"Error: source directory not found: {src_dir}\n")
        return 1

    try:
        manifest = build_pack(
            src_dir=src_dir,
            out_dir=out_dir,
            pack_id=args.pack_id,
            created_at=args.created_at or None,
            creator_software=args.creator_software or None,
            creator_version=args.creator_version or None,
        )
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        sys.stderr.write(f"Error: pack build failed: {exc}\n")
        return 1

    print(f"Decision evidence pack written to {out_dir}")
    print(f"Pack ID:     {manifest.pack_id}")
    print(f"Case ID:     {manifest.case_id}")
    print(f"Members:     {len(manifest.members)}")
    print(f"Pack Digest: {manifest.pack_digest}")
    print(f"{PACK_NOTICE_FOOTER}")
    return 0


def cmd_pack_verify(args: argparse.Namespace) -> int:
    pack_dir = Path(args.pack)
    if not pack_dir.is_dir():
        sys.stderr.write(f"Error: pack directory not found: {pack_dir}\n")
        return 1

    trust_store: TrustStore | None = None
    if args.verifier_keys:
        vk_path = Path(args.verifier_keys)
        if not vk_path.is_file():
            sys.stderr.write(f"Error: verifier keys file not found: {vk_path}\n")
            return 1
        trust_store = TrustStore.from_file(vk_path)

    private_key_pem: bytes | None = None
    if args.sign_receipt:
        sk_path = Path(args.sign_receipt)
        if not sk_path.is_file():
            sys.stderr.write(f"Error: signing key file not found: {sk_path}\n")
            return 1
        private_key_pem = read_bounded_file(sk_path)

    outcome = verify_pack_offline(pack_dir, trust_store=trust_store)

    if args.out:
        try:
            receipt = build_pack_verification_receipt(outcome)
            envelope = (
                sign_pack_receipt(receipt, private_key_pem, key_id=args.signer_key_id or "")
                if private_key_pem is not None
                else None
            )
        except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
            sys.stderr.write(f"Error: receipt generation failed: {exc}\n")
            return 1
        out_obj = envelope if envelope is not None else receipt
        out_path = Path(args.out)
        out_path.write_bytes(canonicalize_json(out_obj))
        print(f"Pack verification receipt written to {out_path}")

    if args.json:
        print(canonicalize_json(outcome.to_dict()).decode("utf-8"))
    else:
        print(outcome.format_human())

    if outcome.overall != "PACK_VALID":
        return 1
    if trust_store is not None and not outcome.is_trusted_signer:
        # Trust roots were pinned by the caller: a missing, invalid, or
        # untrusted signature is a trust failure (exit 2), never silence.
        # The pack verdict itself stays PACK_VALID (an unsigned pack is
        # never invalid), and signature_state names the exact situation.
        return 2
    if outcome.signature_state == "SIGNATURE_INVALID":
        return 2
    return 0


def cmd_pack_receipt_verify(args: argparse.Namespace) -> int:
    receipt_path = Path(args.receipt)
    if not receipt_path.is_file():
        sys.stderr.write(f"Error: receipt file not found: {receipt_path}\n")
        return 1

    trust_store: TrustStore | None = None
    if args.verifier_keys:
        vk_path = Path(args.verifier_keys)
        if not vk_path.is_file():
            sys.stderr.write(f"Error: verifier keys file not found: {vk_path}\n")
            return 1
        trust_store = TrustStore.from_file(vk_path)

    pack_dir = Path(args.pack) if args.pack else None

    result = verify_pack_receipt(receipt_path, trust_store=trust_store, pack_dir=pack_dir)

    if args.json:
        print(canonicalize_json(result.to_dict()).decode("utf-8"))
    else:
        print(result.format_human())

    if result.overall != "RECEIPT_VALID":
        return 1
    if result.is_dsse and result.signature_state != "SIGNATURE_VALID":
        return 2
    if result.is_dsse and trust_store is not None and not result.is_trusted_signer:
        return 2
    return 0


def cmd_pack_sign(args: argparse.Namespace) -> int:
    pack_dir = Path(args.pack)
    if not pack_dir.is_dir():
        sys.stderr.write(f"Error: pack directory not found: {pack_dir}\n")
        return 1

    key_path = Path(args.key)
    if not key_path.is_file():
        sys.stderr.write(f"Error: signing key file not found: {key_path}\n")
        return 1

    try:
        envelope = sign_pack_manifest(
            pack_dir=pack_dir,
            private_key_pem=read_bounded_file(key_path),
            key_id=args.key_id or "",
            out_path=Path(args.out) if args.out else None,
        )
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        sys.stderr.write(f"Error: manifest signing failed: {exc}\n")
        return 1

    out_name = args.out if args.out else str(pack_dir / "manifest.dsse.json")
    print(f"Signed manifest envelope written to {out_name}")
    print(f"Signatures:  {len(envelope['signatures'])}")
    print(f"{PACK_NOTICE_FOOTER}")
    return 0


def cmd_pack_replay(args: argparse.Namespace) -> int:
    pack_dir = Path(args.pack)
    if not pack_dir.is_dir():
        sys.stderr.write(f"Error: pack directory not found: {pack_dir}\n")
        return 1

    trust_store: TrustStore | None = None
    if args.verifier_keys:
        vk_path = Path(args.verifier_keys)
        if not vk_path.is_file():
            sys.stderr.write(f"Error: verifier keys file not found: {vk_path}\n")
            return 1
        trust_store = TrustStore.from_file(vk_path)

    try:
        result = replay_snapshot(
            pack_dir,
            expected_pack_digest=args.expect_pack_digest or None,
            trust_store=trust_store,
        )
    except (ReplayError, ValueError) as exc:
        sys.stderr.write(f"Error: replay safety evaluation failed: {exc}\n")
        return 1

    if args.json:
        print(canonicalize_json(result.to_dict()).decode("utf-8"))
    else:
        print(result.format_human())

    if result.replay_status == "REPLAY_OK":
        return 0
    if result.replay_status == "PACK_INVALID":
        return 1
    return 2


def _load_json_file(path: Path) -> dict[str, Any]:
    data = safe_json_loads(read_bounded_file(path))
    if not isinstance(data, dict):
        raise TypeError(f"Expected a JSON object in {path}")
    return data


def _load_trust_store(path_str: str | None) -> TrustStore | None:
    if not path_str:
        return None
    store_path = Path(path_str)
    if not store_path.is_file():
        sys.stderr.write(f"Error: trust keys file not found: {store_path}\n")
        raise FileNotFoundError(str(store_path))
    return TrustStore.from_file(store_path)


def cmd_hea_attest(args: argparse.Namespace) -> int:
    package_path = Path(args.package)
    profile_path = Path(args.profile)
    out_dir = Path(args.out)
    for label, path in (("package", package_path), ("profile", profile_path)):
        if not path.is_file():
            sys.stderr.write(f"Error: {label} file not found: {path}\n")
            return 1
    witness_key_path = Path(args.witness_key)
    if not witness_key_path.is_file():
        sys.stderr.write(f"Error: witness key file not found: {witness_key_path}\n")
        return 1
    checkpoint_key_path = Path(args.checkpoint_key)
    if not checkpoint_key_path.is_file():
        sys.stderr.write(f"Error: checkpoint key file not found: {checkpoint_key_path}\n")
        return 1
    package_trust_keys: list[dict[str, Any]] | None = None
    if args.trust_keys:
        tk_path = Path(args.trust_keys)
        if not tk_path.is_file():
            sys.stderr.write(f"Error: package trust keys file not found: {tk_path}\n")
            return 1
        package_trust_keys = safe_json_loads(read_bounded_file(tk_path))
    receipt_signing_key: bytes | None = None
    if args.sign_receipt:
        sk_path = Path(args.sign_receipt)
        if not sk_path.is_file():
            sys.stderr.write(f"Error: receipt signing key file not found: {sk_path}\n")
            return 1
        receipt_signing_key = read_bounded_file(sk_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        with LocalProcessWitness(
            private_key_path=witness_key_path,
            key_id=args.witness_key_id,
            log_path=out_dir / "execution-log.jsonl",
            log_id=args.log_id or "hea-log-001",
            checkpoint_key_path=checkpoint_key_path,
            checkpoint_key_id=args.checkpoint_key_id,
        ) as witness:
            summary = run_witnessed_verification(
                package_path=package_path,
                profile_path=profile_path,
                witness=witness,
                out_dir=out_dir,
                package_trust_keys=package_trust_keys,
                receipt_signing_key_pem=receipt_signing_key,
                receipt_signer_key_id=args.signer_key_id or "",
                adapter_label=args.adapter_label or "oept 0.1.3",
            )
    except (ValueError, RuntimeError, TimeoutError) as exc:
        sys.stderr.write(f"Error: witnessed verification failed: {exc}\n")
        return 1

    if args.json:
        print(canonicalize_json(summary).decode("utf-8"))
    else:
        print("=" * 70)
        print("OEVP WITNESSED VERIFICATION (HEA Model A — local process witness)")
        print("=" * 70)
        print(f"Execution ID:    {summary['execution_id']}")
        print(f"Overall Result:  {summary['overall_result']}")
        print(f"Receipt Digest:  {summary['receipt_digest']}")
        print(f"Attested checks: {', '.join(summary['attested_checks'])}")
        print(f"Output dir:      {summary['out_dir']}")
        print("=" * 70)
        print("Time is NOT proven: claimed_time is self-asserted; ordering comes")
        print("from log sequence only. Model A witness: separate process, same")
        print("machine; no protection against machine compromise.")
        print(f"{NOTICE_FOOTER}")
    return 0 if summary["overall_result"] == OverallResult.TECHNICAL_CHECKS_PASSED.value else 2


def cmd_hea_verify(args: argparse.Namespace) -> int:
    package_path = Path(args.package)
    receipt_path = Path(args.receipt)
    profile_path = Path(args.profile)
    attest_dir = Path(args.attestations)
    log_path = Path(args.log)
    checkpoint_path = Path(args.checkpoint)
    for label, path in (
        ("package", package_path),
        ("receipt", receipt_path),
        ("profile", profile_path),
        ("log", log_path),
        ("checkpoint", checkpoint_path),
    ):
        if not path.is_file():
            sys.stderr.write(f"Error: {label} file not found: {path}\n")
            return 1
    if not attest_dir.is_dir():
        sys.stderr.write(f"Error: attestations directory not found: {attest_dir}\n")
        return 1

    try:
        witness_store = _load_trust_store(args.witness_keys)
        checkpoint_store = _load_trust_store(args.checkpoint_keys)
    except FileNotFoundError:
        return 1
    if witness_store is None or checkpoint_store is None:
        sys.stderr.write("Error: --witness-keys and --checkpoint-keys are required\n")
        return 1

    try:
        package_bytes = read_bounded_file(package_path, MAX_PACKAGE_BYTES)
        receipt = _extract_receipt(receipt_path)
        profile = load_profile(profile_path)
        attestations = [_load_json_file(p) for p in sorted(attest_dir.glob("*.dsse.json"))]
        from oev.execution_log import events_from_jsonl

        log_events = events_from_jsonl(read_bounded_file(log_path, MAX_PACKAGE_BYTES))
        checkpoint_envelope = _load_json_file(checkpoint_path)
        prebinding: dict[str, Any] | None = None
        commitment_envelope: dict[str, Any] | None = None
        inclusion_proofs: dict[str, list[dict[str, str]]] | None = None
        expected_code_digest: str | None = args.code_digest
        prebinding_path = attest_dir.parent / "prebinding.json"
        commitment_path = attest_dir.parent / "commitment.dsse.json"
        manifest_path = attest_dir.parent / "hea-manifest.json"
        if prebinding_path.is_file():
            prebinding = _load_json_file(prebinding_path)
        if commitment_path.is_file():
            commitment_envelope = _load_json_file(commitment_path)
        if manifest_path.is_file():
            manifest = _load_json_file(manifest_path)
            inclusion_proofs = {
                str(k): [dict(s) for s in v]
                for k, v in dict(manifest.get("inclusion_proofs", {})).items()
            }
            if expected_code_digest is None:
                expected_code_digest = str(manifest.get("code_digest") or "") or None
    except (ValueError, TypeError, KeyError, OSError) as exc:
        sys.stderr.write(f"Error: failed to load HEA inputs: {exc}\n")
        return 1

    revocation_list = None
    if args.revocation_list:
        from oev.revocation import verify_revocation_list

        try:
            authority_store = _load_trust_store(args.revocation_keys)
            envelope = _load_json_file(Path(args.revocation_list))
            revocation_list, note = verify_revocation_list(envelope, authority_store)
            if revocation_list is None:
                print(f"Note: revocation list not honoured: {note}")
        except (ValueError, FileNotFoundError) as exc:
            sys.stderr.write(f"Error: revocation list failed to load: {exc}\n")
            return 1

    reverification_result: str | None = None
    if args.reverify:
        package_trust_keys: list[dict[str, Any]] | None = None
        if args.trust_keys:
            package_trust_keys = safe_json_loads(read_bounded_file(Path(args.trust_keys)))
        try:
            report = reverify_package(
                package_bytes=package_bytes,
                receipt_source=receipt_path,
                profile_source=profile,
                package_trust_keys=package_trust_keys,
            )
            reverification_result = report.reverification_result
        except OptionalDependencyMissingError as exc:
            sys.stderr.write(f"Error: {exc}\n")
            return 1

    witness_authorization_document: dict[str, Any] | None = None
    if getattr(args, "witness_authorization", None):
        try:
            witness_authorization_document = _load_json_file(Path(args.witness_authorization))
        except (ValueError, TypeError, OSError) as exc:
            sys.stderr.write(f"Error: failed to load witness authorisation: {exc}\n")
            return 1
    expected_code_digest_document: dict[str, Any] | None = None
    if getattr(args, "code_digest_document", None):
        try:
            expected_code_digest_document = _load_json_file(Path(args.code_digest_document))
        except (ValueError, TypeError, OSError) as exc:
            sys.stderr.write(f"Error: failed to load code-digest document: {exc}\n")
            return 1

    result = verify_historical_execution(
        HeaVerificationInputs(
            package_bytes=package_bytes,
            receipt=receipt,
            profile=profile,
            attestations=attestations,
            commitment_envelope=commitment_envelope,
            prebinding=prebinding,
            log_events=log_events,
            checkpoint_envelope=checkpoint_envelope,
            inclusion_proofs=inclusion_proofs,
            witness_trust_store=witness_store,
            checkpoint_trust_store=checkpoint_store,
            revocation_list=revocation_list,
            expected_code_digest=expected_code_digest,
            witness_authorization_document=witness_authorization_document,
            require_witness_authorization=bool(
                getattr(args, "require_witness_authorization", False)
            ),
            expected_code_digest_document=expected_code_digest_document,
            reverification_result=reverification_result,
        )
    )

    if args.json:
        print(canonicalize_json(result.to_dict()).decode("utf-8"))
    else:
        print("=" * 70)
        print("OEVP HISTORICAL EXECUTION VERIFICATION (offline)")
        print("=" * 70)
        print(f"Historical execution: {result.historical_execution}")
        print(f"Reason:               {result.reason or '(none — proven)'}")
        print(f"Execution ID:         {result.execution_id}")
        print(f"Witness mode:         {result.witness_mode}")
        print(f"Receipt digest:       {result.receipt_digest}")
        if result.reverification_result is not None:
            print(f"Reproducibility:      {result.reverification_result} (separate dimension)")
        for entry in result.per_check:
            print(f"  - {entry['check_id']}: {entry['hea_result']}")
        if result.notes:
            print("Notes:")
            for note in result.notes:
                print(f"  * {note}")
        print("=" * 70)
        print(f"{NOTICE_FOOTER}")
    return 0 if result.historical_execution == "HISTORICAL_EXECUTION_PROVEN" else 1


def cmd_hea_log_verify(args: argparse.Namespace) -> int:
    log_path = Path(args.log)
    if not log_path.is_file():
        sys.stderr.write(f"Error: log file not found: {log_path}\n")
        return 1
    try:
        from oev.execution_log import (
            events_from_jsonl,
            merkle_root,
            verify_checkpoint_signature,
            verify_event_chain,
        )

        events = events_from_jsonl(read_bounded_file(log_path, MAX_PACKAGE_BYTES))
        chain_ok, chain_note = verify_event_chain(events)
        report: dict[str, Any] = {
            "event_count": len(events),
            "chain_valid": chain_ok,
            "chain_note": chain_note,
            "merkle_root": merkle_root([e.leaf_hash() for e in events]),
        }
        if args.checkpoint:
            checkpoint_path = Path(args.checkpoint)
            if not checkpoint_path.is_file():
                sys.stderr.write(f"Error: checkpoint file not found: {checkpoint_path}\n")
                return 1
            store = _load_trust_store(args.checkpoint_keys)
            checkpoint, reason = verify_checkpoint_signature(
                _load_json_file(checkpoint_path), store
            )
            report["checkpoint_valid"] = checkpoint is not None and reason == ""
            report["checkpoint_reason"] = reason
            if checkpoint is not None:
                report["checkpoint_leaf_count"] = checkpoint.leaf_count
                report["checkpoint_merkle_root"] = checkpoint.merkle_root
                report["merkle_root_matches_checkpoint"] = (
                    report["merkle_root"] == checkpoint.merkle_root
                    and len(events) == checkpoint.leaf_count
                )
    except (ValueError, TypeError, KeyError, OSError) as exc:
        sys.stderr.write(f"Error: log verification failed: {exc}\n")
        return 1
    if args.json:
        print(canonicalize_json(report).decode("utf-8"))
    else:
        print(f"Events: {report['event_count']}, chain valid: {report['chain_valid']}")
        if report["chain_note"]:
            print(f"Chain note: {report['chain_note']}")
        print(f"Merkle root: {report['merkle_root']}")
        if "checkpoint_valid" in report:
            print(f"Checkpoint valid: {report['checkpoint_valid']} ({report['checkpoint_reason']})")
            print(f"Root matches checkpoint: {report['merkle_root_matches_checkpoint']}")
    ok = bool(report["chain_valid"])
    if "checkpoint_valid" in report:
        ok = (
            ok
            and bool(report["checkpoint_valid"])
            and bool(report["merkle_root_matches_checkpoint"])
        )
    return 0 if ok else 1


def cmd_hea_revoke(args: argparse.Namespace) -> int:
    key_path = Path(args.key)
    if not key_path.is_file():
        sys.stderr.write(f"Error: signing key file not found: {key_path}\n")
        return 1
    from oev.revocation import RevocationEntry, build_revocation_list

    try:
        envelope = build_revocation_list(
            entries=[
                RevocationEntry(
                    key_id=args.key_id,
                    reason=args.reason,
                    revoked_at_claimed=args.issued_at or utc_now_iso(),
                )
            ],
            issuer_key_id=args.issuer_key_id,
            issued_at_claimed=args.issued_at or utc_now_iso(),
            private_key_pem=read_bounded_file(key_path),
        )
    except (ValueError, TypeError) as exc:
        sys.stderr.write(f"Error: revocation list build failed: {exc}\n")
        return 1
    out_path = Path(args.out)
    out_path.write_bytes(canonicalize_json(envelope))
    print(f"Revocation list written to {out_path} (revoked key: {args.key_id})")
    return 0


def cmd_hea_disprove(args: argparse.Namespace) -> int:
    log_path = Path(args.log)
    checkpoint_path = Path(args.checkpoint)
    completeness_path = Path(args.completeness)
    for label, path in (
        ("log", log_path),
        ("checkpoint", checkpoint_path),
        ("completeness", completeness_path),
    ):
        if not path.is_file():
            sys.stderr.write(f"Error: {label} file not found: {path}\n")
            return 1
    try:
        checkpoint_store = _load_trust_store(args.checkpoint_keys)
        operator_store = _load_trust_store(args.completeness_keys)
    except FileNotFoundError:
        return 1
    try:
        from oev.execution_log import events_from_jsonl

        events = events_from_jsonl(read_bounded_file(log_path, MAX_PACKAGE_BYTES))
        checkpoint_envelope = _load_json_file(checkpoint_path)
        completeness_envelope = _load_json_file(completeness_path)
    except (ValueError, TypeError, KeyError, OSError) as exc:
        sys.stderr.write(f"Error: failed to load DISPROVEN inputs: {exc}\n")
        return 1
    is_disproven, note = assess_disproven(
        events,
        checkpoint_envelope,
        completeness_envelope,
        args.execution_id,
        checkpoint_store,
        operator_store,
    )
    report = {
        "execution_id": args.execution_id,
        "historical_execution": (
            "HISTORICAL_EXECUTION_DISPROVEN" if is_disproven else "HISTORICAL_EXECUTION_UNPROVEN"
        ),
        "note": note,
    }
    if args.json:
        print(canonicalize_json(report).decode("utf-8"))
    else:
        print(f"Historical execution: {report['historical_execution']}")
        print(f"Note: {note}")
    return 0 if is_disproven else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oev",
        description="Open Evidence Verification Protocol (OEVP) CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. verify
    p_verify = subparsers.add_parser(
        "verify", help="Verify package against profile and emit receipt"
    )
    p_verify.add_argument("package", help="Path to evidence package")
    p_verify.add_argument("--profile", required=True, help="Path to verification profile JSON")
    p_verify.add_argument("--trust-keys", help="Path to package trust roots JSON")
    p_verify.add_argument("--sign-receipt", help="Path to Ed25519 private key PEM to sign receipt")
    p_verify.add_argument("--signer-key-id", help="Advisory key ID for DSSE envelope")
    p_verify.add_argument("--out", help="Output path for receipt JSON/DSSE")
    p_verify.set_defaults(func=cmd_verify)

    # 2. inspect-receipt
    p_inspect = subparsers.add_parser(
        "inspect-receipt", help="Offline inspect receipt without package"
    )
    p_inspect.add_argument("receipt", help="Path to receipt JSON or DSSE envelope")
    p_inspect.add_argument("--verifier-keys", help="Path to trusted verifier keys JSON")
    p_inspect.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_inspect.set_defaults(func=cmd_inspect_receipt)

    # 3. reverify
    p_reverify = subparsers.add_parser(
        "reverify", help="Independently re-verify package against historic receipt"
    )
    p_reverify.add_argument("package", help="Path to evidence package")
    p_reverify.add_argument("receipt", help="Path to historical receipt JSON or DSSE envelope")
    p_reverify.add_argument("--profile", required=True, help="Path to verification profile JSON")
    p_reverify.add_argument("--trust-keys", help="Path to package trust roots JSON")
    p_reverify.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_reverify.set_defaults(func=cmd_reverify)

    # 4. receipt
    p_receipt = subparsers.add_parser("receipt", help="Receipt operations")
    receipt_sub = p_receipt.add_subparsers(dest="receipt_subcommand", required=True)
    p_receipt_verify = receipt_sub.add_parser("verify", help="Verify receipt signature and trust")
    p_receipt_verify.add_argument("receipt", help="Path to receipt JSON or DSSE envelope")
    p_receipt_verify.add_argument(
        "--verifier-keys", required=True, help="Path to trusted verifier keys JSON"
    )
    p_receipt_verify.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_receipt_verify.set_defaults(func=cmd_receipt_verify)

    # 5. pack
    p_pack = subparsers.add_parser(
        "pack", help="Decision evidence pack operations (oev-decision-pack/0.2)"
    )
    pack_sub = p_pack.add_subparsers(dest="pack_subcommand", required=True)

    p_pack_build = pack_sub.add_parser(
        "build", help="Build a decision evidence pack from a source directory"
    )
    p_pack_build.add_argument("source", help="Directory containing core members and artifacts/")
    p_pack_build.add_argument("--out", required=True, help="Output pack directory")
    p_pack_build.add_argument("--pack-id", required=True, help="Identifier for the pack")
    p_pack_build.add_argument(
        "--created-at", help="ISO 8601 UTC creation time (defaults to current time)"
    )
    p_pack_build.add_argument("--creator-software", help="Creator software name for the manifest")
    p_pack_build.add_argument("--creator-version", help="Creator software version for the manifest")
    p_pack_build.set_defaults(func=cmd_pack_build)

    p_pack_verify = pack_sub.add_parser(
        "verify", help="Verify technical integrity of a decision evidence pack"
    )
    p_pack_verify.add_argument("pack", help="Path to the pack directory")
    p_pack_verify.add_argument("--verifier-keys", help="Path to trusted manifest signer keys JSON")
    p_pack_verify.add_argument(
        "--out", help="Write a portable pack verification receipt to this path"
    )
    p_pack_verify.add_argument(
        "--sign-receipt",
        help="Path to Ed25519 private key PEM to DSSE-sign the emitted receipt",
    )
    p_pack_verify.add_argument("--signer-key-id", help="Advisory key ID for the receipt envelope")
    p_pack_verify.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_pack_verify.set_defaults(func=cmd_pack_verify)

    p_pack_receipt = pack_sub.add_parser("receipt", help="Pack verification receipt operations")
    p_receipt_sub = p_pack_receipt.add_subparsers(dest="pack_receipt_subcommand", required=True)
    p_pack_receipt_verify = p_receipt_sub.add_parser(
        "verify",
        help="Offline third-party verification of a pack verification receipt",
    )
    p_pack_receipt_verify.add_argument(
        "receipt", help="Path to the receipt (canonical JSON or DSSE envelope)"
    )
    p_pack_receipt_verify.add_argument(
        "--verifier-keys", help="Path to trusted receipt-signer keys JSON"
    )
    p_pack_receipt_verify.add_argument(
        "--pack",
        help="Optional pack directory to re-bind the receipt against (digest comparison)",
    )
    p_pack_receipt_verify.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_pack_receipt_verify.set_defaults(func=cmd_pack_receipt_verify)

    p_pack_sign = pack_sub.add_parser(
        "sign", help="Sign the canonical manifest of a pack with DSSE v1 (Ed25519)"
    )
    p_pack_sign.add_argument("pack", help="Path to the pack directory")
    p_pack_sign.add_argument("--key", required=True, help="Path to Ed25519 private key PEM")
    p_pack_sign.add_argument("--key-id", help="Advisory key ID for DSSE envelope")
    p_pack_sign.add_argument(
        "--out", help="Output envelope path (defaults to <pack>/manifest.dsse.json)"
    )
    p_pack_sign.set_defaults(func=cmd_pack_sign)

    p_pack_replay = pack_sub.add_parser(
        "replay", help="Evaluate snapshot replay safety for a decision evidence pack"
    )
    p_pack_replay.add_argument("pack", help="Path to the pack directory")
    p_pack_replay.add_argument(
        "--expect-pack-digest",
        help="Pinned pack digest ('sha256:<hex>'); replay refuses if the pack hash changed",
    )
    p_pack_replay.add_argument("--verifier-keys", help="Path to trusted manifest signer keys JSON")
    p_pack_replay.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_pack_replay.set_defaults(func=cmd_pack_replay)

    # 6. hea — Historical Execution Attestation (Model A, local-process witness)
    p_hea = subparsers.add_parser(
        "hea", help="Historical Execution Attestation operations (oev-attestation/0.1)"
    )
    hea_sub = p_hea.add_subparsers(dest="hea_subcommand", required=True)

    p_hea_attest = hea_sub.add_parser(
        "attest", help="Run a witnessed verification (Model A witness, separate process)"
    )
    p_hea_attest.add_argument("package", help="Path to evidence package")
    p_hea_attest.add_argument("--profile", required=True, help="Path to verification profile JSON")
    p_hea_attest.add_argument(
        "--witness-key", required=True, help="Path to witness Ed25519 private key PEM"
    )
    p_hea_attest.add_argument("--witness-key-id", required=True, help="Witness key id")
    p_hea_attest.add_argument(
        "--checkpoint-key",
        required=True,
        help="Path to checkpoint-signer Ed25519 private key PEM (role-separated from the witness key)",
    )
    p_hea_attest.add_argument("--checkpoint-key-id", required=True, help="Checkpoint-signer key id")
    p_hea_attest.add_argument("--out", required=True, help="Output directory for HEA artifacts")
    p_hea_attest.add_argument("--trust-keys", help="Path to package trust roots JSON")
    p_hea_attest.add_argument(
        "--sign-receipt", help="Path to Ed25519 private key PEM to sign the receipt"
    )
    p_hea_attest.add_argument("--signer-key-id", help="Advisory key ID for the receipt envelope")
    p_hea_attest.add_argument("--log-id", help="Log identifier (default hea-log-001)")
    p_hea_attest.add_argument(
        "--adapter-label", help="Human-readable adapter label for code_version"
    )
    p_hea_attest.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_hea_attest.set_defaults(func=cmd_hea_attest)

    p_hea_verify = hea_sub.add_parser(
        "verify", help="Offline verification of a historical execution (no network)"
    )
    p_hea_verify.add_argument("package", help="Path to evidence package")
    p_hea_verify.add_argument(
        "--receipt", required=True, help="Path to receipt JSON or DSSE envelope"
    )
    p_hea_verify.add_argument("--profile", required=True, help="Path to verification profile JSON")
    p_hea_verify.add_argument(
        "--attestations", required=True, help="Directory with per-check attestation DSSE files"
    )
    p_hea_verify.add_argument("--log", required=True, help="Path to execution log JSONL")
    p_hea_verify.add_argument("--checkpoint", required=True, help="Path to checkpoint DSSE JSON")
    p_hea_verify.add_argument(
        "--witness-keys", required=True, help="Path to trusted witness keys JSON"
    )
    p_hea_verify.add_argument(
        "--checkpoint-keys", required=True, help="Path to trusted checkpoint keys JSON"
    )
    p_hea_verify.add_argument("--revocation-list", help="Path to signed revocation list DSSE JSON")
    p_hea_verify.add_argument(
        "--revocation-keys", help="Path to trusted revocation-authority keys JSON"
    )
    p_hea_verify.add_argument("--code-digest", help="Expected code digest ('sha256:<hex>')")
    p_hea_verify.add_argument(
        "--code-digest-document",
        help="Path to an oev-code-digest/0.1 JSON document: the attested "
        "code_version is compared against it field by field (code digest, "
        "policy digest, pinned dependencies, interpreter, venv fingerprint)",
    )
    p_hea_verify.add_argument(
        "--witness-authorization",
        help="Path to an oev-witness-authorization/0.1 JSON document: the "
        "witness key, profiles, checks and validity window are enforced",
    )
    p_hea_verify.add_argument(
        "--require-witness-authorization",
        action="store_true",
        help="Fail closed (WITNESS_UNAUTHORIZED) when no witness authorisation "
        "is supplied; without it, a missing authorisation is only noted",
    )
    p_hea_verify.add_argument(
        "--trust-keys", help="Path to package trust roots JSON (for --reverify)"
    )
    p_hea_verify.add_argument(
        "--reverify", action="store_true", help="Also run re-verification (separate dimension)"
    )
    p_hea_verify.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_hea_verify.set_defaults(func=cmd_hea_verify)

    p_hea_log = hea_sub.add_parser("log", help="Execution log operations")
    hea_log_sub = p_hea_log.add_subparsers(dest="hea_log_subcommand", required=True)
    p_hea_log_verify = hea_log_sub.add_parser(
        "verify", help="Verify a log hash-chain (and checkpoint, if given)"
    )
    p_hea_log_verify.add_argument("log", help="Path to execution log JSONL")
    p_hea_log_verify.add_argument("--checkpoint", help="Path to checkpoint DSSE JSON")
    p_hea_log_verify.add_argument("--checkpoint-keys", help="Path to trusted checkpoint keys JSON")
    p_hea_log_verify.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_hea_log_verify.set_defaults(func=cmd_hea_log_verify)

    p_hea_revoke = hea_sub.add_parser("revoke", help="Build a signed revocation list for one key")
    p_hea_revoke.add_argument("--key-id", required=True, help="Key id to revoke")
    p_hea_revoke.add_argument("--reason", required=True, help="Revocation reason")
    p_hea_revoke.add_argument("--key", required=True, help="Path to issuer Ed25519 private key PEM")
    p_hea_revoke.add_argument("--issuer-key-id", required=True, help="Issuer key id")
    p_hea_revoke.add_argument("--issued-at", help="Issued time (claimed, YYYY-MM-DDTHH:MM:SSZ)")
    p_hea_revoke.add_argument(
        "--out", required=True, help="Output path for the revocation list DSSE"
    )
    p_hea_revoke.set_defaults(func=cmd_hea_revoke)

    p_hea_disprove = hea_sub.add_parser(
        "disprove", help="Assess HISTORICAL_EXECUTION_DISPROVEN for an execution id"
    )
    p_hea_disprove.add_argument("--execution-id", required=True, help="Execution id to assess")
    p_hea_disprove.add_argument("--log", required=True, help="Path to execution log JSONL")
    p_hea_disprove.add_argument("--checkpoint", required=True, help="Path to checkpoint DSSE JSON")
    p_hea_disprove.add_argument(
        "--checkpoint-keys", required=True, help="Path to trusted checkpoint keys JSON"
    )
    p_hea_disprove.add_argument(
        "--completeness", required=True, help="Path to log completeness statement DSSE JSON"
    )
    p_hea_disprove.add_argument(
        "--completeness-keys", required=True, help="Path to trusted log-operator keys JSON"
    )
    p_hea_disprove.add_argument("--json", action="store_true", help="Emit raw JSON")
    p_hea_disprove.set_defaults(func=cmd_hea_disprove)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)  # type: ignore[no-any-return]
    except (ValueError, TypeError, KeyError, OSError, RecursionError) as exc:
        # Schema-invalid or otherwise unparseable JSON input (receipt, profile,
        # trust keys) must fail closed with a clean message, not a traceback.
        # SchemaValidationError and JSON decode errors are ValueError subclasses.
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
