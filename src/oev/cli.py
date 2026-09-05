"""Command-Line Interface (CLI) for Open Evidence Verification Protocol (OEVP)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from oev.canonical import canonicalize_json, safe_json_loads
from oev.engine import execute_verification
from oev.inspect import inspect_receipt_file
from oev.models import OverallResult
from oev.profiles import load_profile
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

    receipt, envelope = execute_verification(
        package_bytes=package_bytes,
        profile=profile,
        package_trust_keys=package_trust_keys,
        private_key_pem=private_key_pem,
        signer_key_id=args.signer_key_id or "",
    )

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

    report = reverify_package(
        package_bytes=package_bytes,
        receipt_source=receipt_path,
        profile_source=profile,
        package_trust_keys=package_trust_keys,
    )

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)  # type: ignore[no-any-return]


if __name__ == "__main__":
    sys.exit(main())
