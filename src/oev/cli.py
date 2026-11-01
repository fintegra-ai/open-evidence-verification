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
from oev.engine import execute_verification
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
from oev.reverify import reverify_package
from oev.trust import TrustStore

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

    package_bytes = package_path.read_bytes()
    profile = load_profile(profile_path)

    package_trust_keys: list[dict[str, Any]] | None = None
    if args.trust_keys:
        tk_path = Path(args.trust_keys)
        if not tk_path.is_file():
            sys.stderr.write(f"Error: package trust keys file not found: {tk_path}\n")
            return 1
        with open(tk_path, "r", encoding="utf-8") as f:
            package_trust_keys = safe_json_loads(f.read())

    private_key_pem: bytes | None = None
    if args.sign_receipt:
        sk_path = Path(args.sign_receipt)
        if not sk_path.is_file():
            sys.stderr.write(f"Error: signing key file not found: {sk_path}\n")
            return 1
        private_key_pem = sk_path.read_bytes()

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

    package_bytes = package_path.read_bytes()
    profile = load_profile(profile_path)

    package_trust_keys: list[dict[str, Any]] | None = None
    if args.trust_keys:
        tk_path = Path(args.trust_keys)
        if not tk_path.is_file():
            sys.stderr.write(f"Error: package trust keys file not found: {tk_path}\n")
            return 1
        with open(tk_path, "r", encoding="utf-8") as f:
            package_trust_keys = safe_json_loads(f.read())

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
    except ValueError as exc:
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
        private_key_pem = sk_path.read_bytes()

    outcome = verify_pack_offline(pack_dir, trust_store=trust_store)

    if args.out:
        try:
            receipt = build_pack_verification_receipt(outcome)
            envelope = (
                sign_pack_receipt(receipt, private_key_pem, key_id=args.signer_key_id or "")
                if private_key_pem is not None
                else None
            )
        except ValueError as exc:
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
            private_key_pem=key_path.read_bytes(),
            key_id=args.key_id or "",
            out_path=Path(args.out) if args.out else None,
        )
    except ValueError as exc:
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)  # type: ignore[no-any-return]
    except ValueError as exc:
        # Schema-invalid or otherwise unparseable JSON input (receipt, profile,
        # trust keys) must fail closed with a clean message, not a traceback.
        # SchemaValidationError and JSON decode errors are ValueError subclasses.
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
