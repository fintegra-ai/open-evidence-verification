# SPDX-License-Identifier: Apache-2.0

"""Verification engine orchestrating package evaluation, receipt generation, and DSSE signing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from oev import __version__
from oev.adapters import get_adapter_for_format, get_adapter_for_package
from oev.hashing import sha256_bytes
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
from oev.receipts import aggregate_overall_result, finalize_receipt
from oev.signing import sign_receipt_dsse

DEFAULT_VERIFIER_SOFTWARE = "oev"
# Receipts record the installed package version; kept in sync with oev.__version__.
DEFAULT_VERIFIER_VERSION = __version__


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def execute_verification(
    package_bytes: bytes,
    profile: VerificationProfile,
    package_trust_keys: list[dict[str, Any]] | None = None,
    verifier_identity: VerifierIdentity | None = None,
    private_key_pem: bytes | None = None,
    signer_key_id: str = "",
) -> tuple[VerificationReceipt, dict[str, Any] | None]:
    """Execute complete technical verification of package bytes against a profile.

    Returns a tuple of (finalized_receipt, dsse_envelope_or_None).
    """
    recorded_time = utc_now_iso()
    package_digest = sha256_bytes(package_bytes)
    profile_digest = compute_profile_digest(profile)

    verifier = verifier_identity or VerifierIdentity(
        software=DEFAULT_VERIFIER_SOFTWARE,
        version=DEFAULT_VERIFIER_VERSION,
    )

    profile_ref = ProfileReference(
        profile_id=profile.profile_id,
        profile_version=profile.profile_version,
        profile_digest=profile_digest,
    )

    # Convert package trust keys to TrustInput records
    trust_inputs: list[TrustInput] = []
    if package_trust_keys:
        for k in package_trust_keys:
            key_id = str(k["key_id"])
            pem = k["public_key_pem"]
            pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem)
            trust_inputs.append(
                TrustInput(
                    trust_id=key_id,
                    type="public_key",
                    digest=sha256_bytes(pem_bytes),
                    note=k.get("note"),
                )
            )

    limitations: list[Limitation] = []

    # Select adapter
    adapter = get_adapter_for_package(package_bytes)
    if adapter is None:
        adapter = get_adapter_for_format(profile.target_format)

    if adapter is None or (
        adapter.format_id != profile.target_format and not adapter.can_handle(package_bytes)
    ):
        # Package format unsupported or incompatible with requested profile
        pkg_ref = PackageReference(
            digest=package_digest,
            format=profile.target_format,
            size_bytes=len(package_bytes),
        )
        checks = [
            CheckResult(
                check_id=chk,
                category="adapter",
                status=CheckStatus.UNSUPPORTED,
                detail=f"No package adapter available to evaluate format '{profile.target_format}'",
            )
            for chk in profile.required_checks
        ]
        overall = OverallResult.PROFILE_UNSATISFIED
    else:
        pkg_ref = adapter.inspect_package(package_bytes)
        checks = adapter.evaluate(
            package_bytes=package_bytes,
            profile=profile,
            trust_inputs=trust_inputs,
            package_trusted_keys_pem=package_trust_keys,
        )
        overall = aggregate_overall_result(
            required_checks=profile.required_checks,
            optional_checks=profile.optional_checks,
            checks=checks,
            limitations=limitations,
        )

    raw_receipt = VerificationReceipt(
        receipt_id=str(uuid.uuid4()),
        protocol_version="oev-receipt/0.1",
        recorded_verification_time=recorded_time,
        package=pkg_ref,
        profile=profile_ref,
        verifier=verifier,
        trust_inputs=trust_inputs,
        checks=checks,
        limitations=limitations,
        overall_result=overall,
    )

    finalized = finalize_receipt(raw_receipt)

    envelope: dict[str, Any] | None = None
    if private_key_pem is not None:
        envelope = sign_receipt_dsse(
            receipt=finalized,
            private_key_pem=private_key_pem,
            key_id=signer_key_id,
        )

    return finalized, envelope
