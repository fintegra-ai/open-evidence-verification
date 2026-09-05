"""Offline Receipt Inspection decoupled from evidence package bytes.

INSPECTION INVARIANT:
Receipt inspection verifies receipt structure, content digest, and verifier signature.
It describes what a verifier claimed to have evaluated. It does NOT assert that the
referenced package is valid or intact (package bytes are not present during inspection).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oev.dsse import parse_dsse_envelope
from oev.models import VerificationReceipt
from oev.receipts import load_receipt, verify_receipt_digest
from oev.schemas import validate_document
from oev.trust import TrustStore, evaluate_receipt_trust

RECEIPT_SCHEMA_NAME = "verification-receipt.schema.json"


@dataclass(frozen=True)
class InspectionResult:
    """Outcome of offline receipt inspection."""

    receipt: VerificationReceipt
    is_dsse_signed: bool
    receipt_digest_valid: bool
    recomputed_digest: str
    crypto_valid: bool = False
    is_trusted_signer: bool = False
    trusted_signer_key_id: str | None = None
    envelope_key_id: str | None = None
    status_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt": self.receipt.to_dict(include_digest=True),
            "is_dsse_signed": self.is_dsse_signed,
            "receipt_digest_valid": self.receipt_digest_valid,
            "recomputed_digest": self.recomputed_digest,
            "crypto_valid": self.crypto_valid,
            "is_trusted_signer": self.is_trusted_signer,
            "trusted_signer_key_id": self.trusted_signer_key_id,
            "envelope_key_id": self.envelope_key_id,
            "status_summary": self.status_summary,
        }

    def format_human(self) -> str:
        lines: list[str] = [
            "=" * 70,
            "OEVP VERIFICATION RECEIPT INSPECTION REPORT",
            "=" * 70,
            f"Receipt ID:             {self.receipt.receipt_id}",
            f"Protocol Version:       {self.receipt.protocol_version}",
            f"Recorded Time (UTC):    {self.receipt.recorded_verification_time}",
            f"Verifier Software:      {self.receipt.verifier.software} {self.receipt.verifier.version}",
            f"Target Package Digest:  {self.receipt.package.digest}",
            f"Target Package Format:  {self.receipt.package.format}",
            f"Profile ID:             {self.receipt.profile.profile_id} (v{self.receipt.profile.profile_version})",
            f"Profile Content Digest: {self.receipt.profile.profile_digest}",
            f"Receipt Self-Digest:    {self.receipt.receipt_digest} ({'VALID' if self.receipt_digest_valid else 'INVALID'})",
            f"Recorded Overall:       {self.receipt.overall_result}",
            "-" * 70,
            f"DSSE Envelope Signed:   {'YES' if self.is_dsse_signed else 'NO'}",
        ]
        if self.is_dsse_signed:
            lines.extend([
                f"Signature Math Valid:   {'YES' if self.crypto_valid else 'NO'}",
                f"Caller Trusted Signer:  {'YES' if self.is_trusted_signer else 'NO'}",
                f"Trusted Signer Key ID:  {self.trusted_signer_key_id or 'None'}",
                f"Envelope Key ID Hint:   {self.envelope_key_id or 'None'}",
            ])

        lines.extend([
            "-" * 70,
            f"Check Vector ({len(self.receipt.checks)} checks):",
        ])
        for c in self.receipt.checks:
            lines.append(f"  [{c.status:<14}] {c.check_id:<25} ({c.category}) {c.detail}")

        if self.receipt.limitations:
            lines.extend(["-" * 70, "Recorded Limitations:"])
            for lim in self.receipt.limitations:
                lines.append(f"  * [{lim.code}] {lim.description}")

        lines.extend([
            "=" * 70,
            "NOTICE:",
            "Technical verification only — not a legal, compliance, or factual conclusion.",
            "Receipt inspection describes a verifier's recorded technical appraisal.",
            "It does not independently verify the referenced package.",
            "=" * 70,
        ])
        return "\n".join(lines)


def inspect_receipt_data(
    data: dict[str, Any],
    verifier_trust_store: TrustStore | None = None,
) -> InspectionResult:
    """Inspect receipt from parsed dictionary (raw receipt or DSSE envelope)."""
    is_dsse = False
    crypto_valid = False
    is_trusted = False
    trusted_key_id: str | None = None
    envelope_key_id: str | None = None

    if "payloadType" in data and "payload" in data and "signatures" in data:
        # DSSE Envelope
        is_dsse = True
        _, payload_bytes, signatures = parse_dsse_envelope(data)
        if signatures:
            envelope_key_id = signatures[0].get("keyid") or None

        receipt_dict = json.loads(payload_bytes.decode("utf-8"))

        if verifier_trust_store is not None:
            eval_result = evaluate_receipt_trust(data, verifier_trust_store)
            crypto_valid = eval_result.crypto_valid
            is_trusted = eval_result.is_trusted
            trusted_key_id = eval_result.trusted_key_id
    else:
        receipt_dict = data

    validate_document(receipt_dict, RECEIPT_SCHEMA_NAME)
    receipt = VerificationReceipt.from_dict(receipt_dict)

    digest_valid, declared_digest, recomputed_digest = verify_receipt_digest(receipt_dict)

    summary = (
        f"Overall: {receipt.overall_result} | "
        f"Self-Digest: {'VALID' if digest_valid else 'MISMATCH'} | "
        f"DSSE: {'SIGNED' if is_dsse else 'UNSIGNED'}"
    )
    if is_dsse:
        summary += f" | Trusted: {'YES' if is_trusted else 'NO'}"

    return InspectionResult(
        receipt=receipt,
        is_dsse_signed=is_dsse,
        receipt_digest_valid=digest_valid,
        recomputed_digest=recomputed_digest,
        crypto_valid=crypto_valid,
        is_trusted_signer=is_trusted,
        trusted_signer_key_id=trusted_key_id,
        envelope_key_id=envelope_key_id,
        status_summary=summary,
    )


def inspect_receipt_file(
    path: str | Path,
    verifier_trust_store: TrustStore | None = None,
) -> InspectionResult:
    """Load receipt file (JSON or DSSE) and run offline inspection."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return inspect_receipt_data(data, verifier_trust_store=verifier_trust_store)
