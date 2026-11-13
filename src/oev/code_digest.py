# SPDX-License-Identifier: Apache-2.0

"""Code-digest documents (oev-code-digest/0.1).

Round 3 (P0): what ran is bound to an explicit JSON Schema instead of
a bare ``code_digest`` string. A code-digest document records:

- ``code_digest`` — SHA-256 over the running ``oev`` package sources +
  interpreter version (see ``execution.compute_code_digest``);
- ``policy_digest`` — digest of the verification profile / policy the
  code ran under, when the producer records one;
- ``dependencies`` — pinned third-party package versions (name +
  version, optional per-package digest);
- ``environment`` — interpreter version, platform/OS strings, and a
  venv/container fingerprint (SHA-256 over the installed distribution
  name→version map, or the container image digest).

Comparison rule (enforced by ``hea_verifier`` when the caller supplies
an expected document):
- ``code_digest`` and ``policy_digest`` (when the expected document pins
  one) must match exactly — otherwise ``CODE_DIGEST_MISMATCH``.
- Every dependency pinned in the expected document must be present in
  the attested ``code_version`` with the same version (and the same
  digest, when the expected document pins one) — otherwise mismatch.
- ``environment.python_version`` must match exactly when pinned.
- ``environment.venv_fingerprint`` must match exactly when both sides
  record one.
- ``platform`` / ``os`` mismatches are reported as notes only: the
  same code may legitimately run on another OS. They never fail the
  verdict on their own.

The attested side is the ``code_version`` dict carried by the
attestation and the commitment (``engine`` / ``adapter`` /
``code_digest`` plus the optional ``policy_digest`` / ``dependencies`` /
``environment`` fields, added to the attestation/commitment schemas in
round 3). A producer that records none of the optional fields can
only be checked on ``code_digest``; the verifier says so in its notes.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from typing import Any

from .canonical import canonicalize_json
from .execution import compute_code_digest
from .schemas import validate_document

CODE_DIGEST_PROTOCOL_VERSION = "oev-code-digest/0.1"
CODE_DIGEST_SCHEMA_NAME = "code-digest-0.1.schema.json"


def compute_venv_fingerprint() -> str:
    """SHA-256 over the sorted installed-distribution name→version map.

    Best-effort: if distribution metadata is unavailable, the
    fingerprint covers the interpreter version only, so it stays
    deterministic rather than failing. Two venvs with the same package
    set at the same versions produce the same fingerprint.
    """
    import importlib.metadata

    entries: dict[str, str] = {}
    try:
        for dist in importlib.metadata.distributions():
            name = (dist.metadata["Name"] or "").lower()
            if name:
                entries[name] = dist.version
    except (ImportError, OSError, ValueError):
        entries = {}
    record = {"python_version": sys.version.split()[0], "distributions": entries}
    return "sha256:" + hashlib.sha256(canonicalize_json(record)).hexdigest()


def build_environment_record() -> dict[str, Any]:
    """Environment identity for the running interpreter (record-only)."""
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "os": platform.system(),
        "venv_fingerprint": compute_venv_fingerprint(),
    }


def build_code_digest_document(
    engine: str,
    adapter: str,
    *,
    package_dir: str | None = None,
    policy_digest: str | None = None,
    dependencies: list[dict[str, Any]] | None = None,
    include_environment: bool = True,
) -> dict[str, Any]:
    """Build the expected/attested code-digest document for this install."""
    doc: dict[str, Any] = {
        "protocol_version": CODE_DIGEST_PROTOCOL_VERSION,
        "engine": engine,
        "adapter": adapter,
        "code_digest": compute_code_digest(package_dir),
    }
    if policy_digest is not None:
        doc["policy_digest"] = policy_digest
    if dependencies is not None:
        doc["dependencies"] = [dict(d) for d in dependencies]
    if include_environment:
        doc["environment"] = build_environment_record()
    validate_document(doc, CODE_DIGEST_SCHEMA_NAME)
    return doc


def validate_code_digest_document(doc: dict[str, Any]) -> None:
    """Validate a code-digest document against its schema. Raises ValueError."""
    if not isinstance(doc, dict):
        raise ValueError("Code-digest document must be a JSON object")  # noqa: TRY004 — callers catch ValueError for malformed documents.
    validate_document(doc, CODE_DIGEST_SCHEMA_NAME)
    if str(doc.get("protocol_version", "")) != CODE_DIGEST_PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported code-digest protocol version: {doc.get('protocol_version')!r}"
        )


def compare_code_digest_document(
    expected: dict[str, Any], attested_code_version: dict[str, Any]
) -> tuple[list[str], list[str]]:
    """Compare an expected document against an attested ``code_version``.

    Returns ``(mismatches, notes)``. Any mismatch fails verification
    with ``CODE_DIGEST_MISMATCH``; notes are informational only.
    Raises ``ValueError`` when the expected document itself is invalid.
    """
    validate_code_digest_document(expected)
    mismatches: list[str] = []
    notes: list[str] = []

    if str(attested_code_version.get("code_digest", "")) != str(expected["code_digest"]):
        mismatches.append(
            f"Attested code_digest {attested_code_version.get('code_digest')!r} "
            f"!= expected {expected['code_digest']!r}."
        )
    if "policy_digest" in expected:
        attested_policy = attested_code_version.get("policy_digest")
        if attested_policy is None:
            mismatches.append(
                "Attested code_version records no policy_digest, but the expected "
                "code-digest document pins one."
            )
        elif str(attested_policy) != str(expected["policy_digest"]):
            mismatches.append(
                f"Attested policy_digest {attested_policy!r} "
                f"!= expected {expected['policy_digest']!r}."
            )
    if "dependencies" in expected:
        attested_deps = {
            str(d.get("name")): d
            for d in attested_code_version.get("dependencies", [])
            if isinstance(d, dict)
        }
        for pinned in expected["dependencies"]:
            name = str(pinned["name"])
            found = attested_deps.get(name)
            if found is None:
                mismatches.append(
                    f"Attested code_version records no dependency {name!r}, but the "
                    "expected code-digest document pins it."
                )
                continue
            if str(found.get("version")) != str(pinned["version"]):
                mismatches.append(
                    f"Dependency {name!r} version {found.get('version')!r} "
                    f"!= expected {pinned['version']!r}."
                )
            if "digest" in pinned and str(found.get("digest", "")) != str(pinned["digest"]):
                mismatches.append(f"Dependency {name!r} digest differs from the expected pin.")
    expected_env = expected.get("environment")
    attested_env = attested_code_version.get("environment")
    if isinstance(expected_env, dict) and isinstance(attested_env, dict):
        if "python_version" in expected_env and str(attested_env.get("python_version", "")) != str(
            expected_env["python_version"]
        ):
            mismatches.append(
                f"Attested python_version {attested_env.get('python_version')!r} "
                f"!= expected {expected_env['python_version']!r}."
            )
        if (
            "venv_fingerprint" in expected_env
            and "venv_fingerprint" in attested_env
            and str(attested_env["venv_fingerprint"]) != str(expected_env["venv_fingerprint"])
        ):
            mismatches.append("Attested venv_fingerprint differs from the expected pin.")
        for key in ("platform", "os"):
            if key in expected_env and str(attested_env.get(key, "")) != str(expected_env[key]):
                notes.append(
                    f"Attested environment {key} {attested_env.get(key)!r} differs from "
                    f"expected {expected_env[key]!r} (recorded, not a verdict failure)."
                )
    elif isinstance(expected_env, dict):
        notes.append(
            "Attested code_version records no environment; the expected "
            "code-digest document's environment could not be compared."
        )
    return mismatches, notes
