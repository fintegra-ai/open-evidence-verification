# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the OEVP domain check engines (``oev.domain``).

Status-semantics contract used by every domain engine (normative; also
documented in ``docs/DOMAIN_PROFILES.md`` and ``oevp/spec/profile-spec.md``
§5):

- PASS: the check ran and its rule evaluated true on the inputs.
- FAIL: the check ran and its rule evaluated false. A present-but-invalid
  input (wrong type, malformed date, value out of range) is a FAIL: the
  check executed and the claimed evidence does not satisfy the rule.
- NOT_RUN: the check never started because the evidence it must compute on
  is absent or unreadable (member missing, JSON unparseable). No verdict
  is fabricated from missing inputs.
- NOT_APPLICABLE: the check ran far enough to determine its rule does not
  apply to this bundle (declared subtype/kind makes the rule vacuous,
  e.g. a pro-forma invoice has no payment to match, a text dataset has no
  columns, a constant ``y_true`` makes R² undefined).
- UNVERIFIED: the check ran on present evidence but the *reference* needed
  to judge it is absent (e.g. no declared checksum, no reported metric).
  Missing evidence-to-check is NOT_RUN; missing reference-to-judge is
  UNVERIFIED. The two are never conflated.
- UNSUPPORTED: the bundle declares a domain profile version (or, for
  ``ds.checksum``, a hash algorithm) this engine build does not implement.

All inputs are synthetic / generated; no real personal or financial data
is ever read by these engines.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from oev.models import CheckResult, CheckStatus

#: Domain profile versions implemented by this engine build. A bundle
#: declaring any other version gets UNSUPPORTED for every domain check.
SUPPORTED_DOMAIN_PROFILE_VERSIONS: frozenset[str] = frozenset({"0.1.0"})

#: Default domain profile version assumed when a bundle predates
#: versioning and declares none. Documented assumption, not a silent
#: upgrade: the version check only fires on an explicitly declared
#: unsupported version.
DEFAULT_DOMAIN_PROFILE_VERSION = "0.1.0"


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of ``data`` (no ``sha256:`` prefix)."""
    return hashlib.sha256(data).hexdigest()


def load_json_member(
    members: dict[str, bytes], path: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Return ``(document, error)`` for a JSON bundle member.

    ``(None, "missing")`` when the member is absent, ``(None,
    "unparseable: ...")`` when it is not valid JSON or not a JSON object.
    """
    raw = members.get(path)
    if raw is None:
        return None, "missing"
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"unparseable: {exc}"
    if not isinstance(doc, dict):
        return None, "unparseable: top-level JSON value is not an object"
    return doc, None


def result(
    check_id: str,
    category: str,
    status: CheckStatus,
    detail: str,
    duration_ms: int = 0,
) -> CheckResult:
    """Build a CheckResult with the domain category convention."""
    return CheckResult(
        check_id=check_id,
        category=category,
        status=status,
        detail=detail,
        duration_ms=duration_ms,
    )


def declared_profile_version(doc: dict[str, Any] | None) -> str:
    """Profile version declared by a domain input document (or the default)."""
    if doc is None:
        return DEFAULT_DOMAIN_PROFILE_VERSION
    version = doc.get("profile_version")
    if version is None:
        return DEFAULT_DOMAIN_PROFILE_VERSION
    return str(version)


def version_supported(doc: dict[str, Any] | None) -> tuple[bool, str]:
    """Return ``(supported, declared_version)`` for a domain input document."""
    declared = declared_profile_version(doc)
    return declared in SUPPORTED_DOMAIN_PROFILE_VERSIONS, declared


def unsupported_results(
    check_ids: list[str],
    category: str,
    declared_version: str,
) -> list[CheckResult]:
    """One UNSUPPORTED result per requested check for an unsupported version."""
    return [
        result(
            check_id=cid,
            category=category,
            status=CheckStatus.UNSUPPORTED,
            detail=(
                f"Domain profile version {declared_version!r} is not supported "
                f"by this engine (supports: "
                f"{sorted(SUPPORTED_DOMAIN_PROFILE_VERSIONS)})"
            ),
        )
        for cid in check_ids
    ]


def is_int_value(value: Any) -> bool:
    """True for a genuine JSON integer (booleans are not integers here)."""
    return isinstance(value, int) and not isinstance(value, bool)
