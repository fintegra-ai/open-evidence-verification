"""Optional reference package adapter for Open Evidence Provenance Toolkit (OEPT) bundles.

Implements support for the 'oept-bundle/0.1' archive specification.
This module is strictly optional. If 'oept' is not installed, importing and using other
parts of OEVP continues to function normally.
"""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from oev.adapters.base import OptionalDependencyMissingError, PackageAdapter
from oev.hashing import sha256_bytes
from oev.models import (
    CheckResult,
    CheckStatus,
    PackageReference,
    TrustInput,
    VerificationProfile,
)

OEPT_FORMAT_ID = "oept-bundle/0.1"
SUPPORTED_CHECKS = {
    "archive_safety",
    "manifest_structure",
    "member_digests",
    "application_signature",
}


def is_oept_available() -> bool:
    """Check if the oept library is installed and importable."""
    try:
        import oept  # noqa: F401
        return True
    except ImportError:
        return False


def _require_oept() -> Any:
    """Import and return the oept module, or raise OptionalDependencyMissingError."""
    try:
        import oept
        import oept.signing
        import oept.verify
        return oept
    except ImportError as exc:
        raise OptionalDependencyMissingError(
            "OEPT is not installed. Install with 'pip install open-evidence-provenance' "
            "or 'pip install oev[oept]' to evaluate oept-bundle/0.1 packages."
        ) from exc


class OEPTAdapter(PackageAdapter):
    """Adapter for validating and evaluating oept-bundle/0.1 archives."""

    @property
    def format_id(self) -> str:
        return OEPT_FORMAT_ID

    def can_handle(self, package_bytes: bytes) -> bool:
        """Check if package_bytes is a ZIP archive claiming oept-bundle/0.1 support."""
        if len(package_bytes) < 22:
            return False
        # Fast check for ZIP signature PK\x03\x04
        if not package_bytes.startswith(b"PK\x03\x04"):
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(package_bytes)) as zf:
                if "manifest.json" not in zf.namelist():
                    return False
                manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
                return manifest_data.get("bundle_spec_version") == OEPT_FORMAT_ID
        except Exception:
            return False

    def inspect_package(self, package_bytes: bytes) -> PackageReference:
        """Extract declared metadata without executing full verification."""
        digest = sha256_bytes(package_bytes)
        size_bytes = len(package_bytes)
        declared_id: str | None = None

        try:
            with zipfile.ZipFile(io.BytesIO(package_bytes)) as zf:
                if "manifest.json" in zf.namelist():
                    manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
                    declared_id = manifest_data.get("bundle_id")
        except Exception:
            pass

        return PackageReference(
            digest=digest,
            format=self.format_id,
            size_bytes=size_bytes,
            declared_id=declared_id,
        )

    def supported_checks(self) -> set[str]:
        return set(SUPPORTED_CHECKS)

    def evaluate(
        self,
        package_bytes: bytes,
        profile: VerificationProfile,
        trust_inputs: list[TrustInput],
        package_trusted_keys_pem: list[dict[str, Any]] | None = None,
    ) -> list[CheckResult]:
        """Execute atomic checks against the OEPT bundle using OEPT's offline verifier."""
        oept = _require_oept()

        # Convert caller-supplied package keys to OEPT TrustedKeys
        oept_keys = []
        if package_trusted_keys_pem:
            for k in package_trusted_keys_pem:
                key_id = str(k["key_id"])
                pem = k["public_key_pem"]
                pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else bytes(pem)
                oept_keys.append(oept.signing.TrustedKey(key_id=key_id, public_key_pem=pem_bytes))

        t0 = time.perf_counter()
        oept_result = oept.verify.verify_bundle_bytes(package_bytes, trusted_keys=oept_keys or None)
        duration_ms = max(0, int((time.perf_counter() - t0) * 1000))

        status_code = oept_result.status

        # Map OEPT verification outcomes to atomic OEVP checks
        results: list[CheckResult] = []
        all_requested = set(profile.required_checks) | set(profile.optional_checks)

        # 1. Archive Safety
        if "archive_safety" in all_requested:
            if status_code == "UNSAFE_ARCHIVE":
                safety_status = CheckStatus.FAIL
                detail = "; ".join(oept_result.notes) or "Unsafe archive structure detected"
            else:
                safety_status = CheckStatus.PASS
                detail = "Archive structure and member paths are safe"
            results.append(
                CheckResult(
                    check_id="archive_safety",
                    category="safety",
                    status=safety_status,
                    detail=detail,
                    duration_ms=duration_ms,
                )
            )

        # 2. Manifest Structure
        if "manifest_structure" in all_requested:
            if status_code == "UNSAFE_ARCHIVE":
                manifest_status = CheckStatus.NOT_RUN
                detail = "Archive safety check failed; manifest was not evaluated"
            elif status_code in ("MALFORMED_BUNDLE", "UNSUPPORTED_SPEC_VERSION"):
                manifest_status = CheckStatus.FAIL
                detail = "; ".join(oept_result.notes) or f"Manifest evaluation failed with {status_code}"
            else:
                manifest_status = CheckStatus.PASS
                detail = f"Manifest parsed successfully (spec: {oept_result.bundle_spec_version})"
            results.append(
                CheckResult(
                    check_id="manifest_structure",
                    category="structure",
                    status=manifest_status,
                    detail=detail,
                    duration_ms=duration_ms,
                )
            )

        # 3. Member Digests
        if "member_digests" in all_requested:
            if status_code in ("UNSAFE_ARCHIVE", "MALFORMED_BUNDLE", "UNSUPPORTED_SPEC_VERSION"):
                digest_status = CheckStatus.NOT_RUN
                detail = "Prior structural check failed; member digests were not evaluated"
            elif status_code in ("HASH_MISMATCH", "MISSING_FILE", "UNEXPECTED_FILE"):
                digest_status = CheckStatus.FAIL
                notes = list(oept_result.notes)
                if oept_result.mismatches:
                    notes.append(f"Mismatches: {len(oept_result.mismatches)}")
                detail = "; ".join(notes) or f"Member integrity check failed with {status_code}"
            else:
                digest_status = CheckStatus.PASS
                detail = "All declared member SHA-256 digests matched"
            results.append(
                CheckResult(
                    check_id="member_digests",
                    category="integrity",
                    status=digest_status,
                    detail=detail,
                    duration_ms=duration_ms,
                )
            )

        # 4. Application Signature
        if "application_signature" in all_requested:
            if status_code in (
                "UNSAFE_ARCHIVE",
                "MALFORMED_BUNDLE",
                "UNSUPPORTED_SPEC_VERSION",
                "HASH_MISMATCH",
                "MISSING_FILE",
                "UNEXPECTED_FILE",
            ):
                sig_status = CheckStatus.NOT_RUN
                detail = "Prior integrity or structural check failed; signature was not evaluated"
            elif status_code == "VALID_SIGNED":
                sig_status = CheckStatus.PASS
                detail = f"Valid Ed25519 signature verified against trusted key '{oept_result.trusted_key_id}'"
            elif status_code == "SIGNATURE_INVALID":
                sig_status = CheckStatus.FAIL
                detail = "Application signature is cryptographically invalid or does not match trusted key"
            elif status_code == "SIGNATURE_KEY_UNKNOWN":
                sig_status = CheckStatus.UNVERIFIED
                detail = "Signed bundle, but no matching caller trust root was supplied"
            elif status_code == "VALID_UNSIGNED":
                sig_status = CheckStatus.UNVERIFIED
                detail = "Package has no application signature (unsigned bundle)"
            else:
                sig_status = CheckStatus.UNVERIFIED
                detail = f"Signature status unverified ({status_code})"

            results.append(
                CheckResult(
                    check_id="application_signature",
                    category="signature",
                    status=sig_status,
                    detail=detail,
                    duration_ms=duration_ms,
                )
            )

        # 5. Unsupported checks
        for chk in all_requested:
            if chk not in SUPPORTED_CHECKS:
                results.append(
                    CheckResult(
                        check_id=chk,
                        category="unsupported",
                        status=CheckStatus.UNSUPPORTED,
                        detail=f"Check '{chk}' is not supported by OEPT adapter v0.1",
                    )
                )

        return results
