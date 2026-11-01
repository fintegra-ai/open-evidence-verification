"""Seeded stdlib fuzz/property tests: receipt self-digest binding.

Properties under test, each failing closed:
- Any single schema-valid field or in-string byte change to an issued
  receipt, made WITHOUT recomputing receipt_digest, makes
  verify_receipt_digest report the digest as invalid.
- Re-verification of such a digest-stale receipt always returns MISMATCH
  with an empty fresh_checks list — no fresh result is ever compared
  against values from a tampered receipt.
- Recomputing the digest over the mutated body restores self-consistency,
  demonstrating the digest actually binds the mutated field.

Deterministic by construction: every random choice draws from a local
``random.Random`` instance with a fixed seed. No network, no new
dependencies, no wall-clock or timing assertions.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from oev.adapters.oept import is_oept_available
from oev.engine import execute_verification
from oev.profiles import load_profile
from oev.receipts import compute_receipt_digest, verify_receipt_digest
from oev.reverify import reverify_package

# In-repo conformance fixtures carry byte-stable neutral OEPT bundles.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "conformance" / "fixtures"
BUNDLE_PATH = FIXTURES_DIR / "01-valid-oept-pass" / "package.zip"
TRUST_KEYS_PATH = FIXTURES_DIR / "01-valid-oept-pass" / "package-trust-keys.json"

_FUZZ_SEED = 20261101
_FUZZ_ITERATIONS = 24

pytestmark = pytest.mark.skipif(not is_oept_available(), reason="OEPT not installed")


@pytest.fixture
def sample_profile_file(tmp_path: Path) -> Path:
    p_data = {
        "protocol_version": "oev-profile/0.1",
        "profile_id": "test-fuzz-profile",
        "profile_version": "0.1.0",
        "target_format": "oept-bundle/0.1",
        "required_checks": [
            "archive_safety",
            "manifest_structure",
            "member_digests",
            "application_signature",
        ],
    }
    p_path = tmp_path / "profile.json"
    p_path.write_text(json.dumps(p_data), encoding="utf-8")
    return p_path


@pytest.fixture
def issued_receipt(sample_profile_file: Path) -> dict[str, Any]:
    receipt, _envelope = execute_verification(
        package_bytes=BUNDLE_PATH.read_bytes(),
        profile=load_profile(sample_profile_file),
        package_trust_keys=json.loads(TRUST_KEYS_PATH.read_text(encoding="utf-8")),
    )
    return receipt.to_dict()


def _mutate_receipt_id(receipt: dict[str, Any], rng: random.Random) -> None:
    receipt["receipt_id"] = f"{rng.getrandbits(32):08x}-bbbb-cccc-dddd-{rng.getrandbits(48):012x}"


def _mutate_receipt_id_byte(receipt: dict[str, Any], rng: random.Random) -> None:
    receipt_id = receipt["receipt_id"]
    position = rng.randrange(len(receipt_id))
    # Guarantee an actual change: never replace a character with itself.
    replacements = [c for c in "0123456789abcdef" if c != receipt_id[position].lower()]
    receipt["receipt_id"] = (
        receipt_id[:position] + rng.choice(replacements) + receipt_id[position + 1 :]
    )


def _mutate_recorded_time(receipt: dict[str, Any], rng: random.Random) -> None:
    receipt["recorded_verification_time"] = (
        f"2026-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"
        f"T{rng.randrange(24):02d}:{rng.randrange(60):02d}:{rng.randrange(60):02d}Z"
    )


def _mutate_verifier_version(receipt: dict[str, Any], rng: random.Random) -> None:
    receipt["verifier"]["version"] = f"9.{rng.randrange(100)}.{rng.randrange(100)}"


def _mutate_check_detail(receipt: dict[str, Any], rng: random.Random) -> None:
    checks = receipt["checks"]
    check = checks[rng.randrange(len(checks))]
    check["detail"] = str(check["detail"]) + f" (fuzz annotation {rng.getrandbits(32):08x})"


def _mutate_check_duration(receipt: dict[str, Any], rng: random.Random) -> None:
    checks = receipt["checks"]
    check = checks[rng.randrange(len(checks))]
    check["duration_ms"] = rng.randrange(1, 100_000)


MUTATIONS: list[tuple[str, Callable[[dict[str, Any], random.Random], None]]] = [
    ("receipt_id", _mutate_receipt_id),
    ("receipt_id_byte", _mutate_receipt_id_byte),
    ("recorded_verification_time", _mutate_recorded_time),
    ("verifier.version", _mutate_verifier_version),
    ("checks[].detail", _mutate_check_detail),
    ("checks[].duration_ms", _mutate_check_duration),
]


def test_honest_receipt_self_verifies_and_reverifies_to_match(
    issued_receipt: dict[str, Any], sample_profile_file: Path
) -> None:
    is_valid, _declared, _recomputed = verify_receipt_digest(issued_receipt)
    assert is_valid is True
    report = reverify_package(
        package_bytes=BUNDLE_PATH.read_bytes(),
        receipt_source=issued_receipt,
        profile_source=load_profile(sample_profile_file),
        package_trust_keys=json.loads(TRUST_KEYS_PATH.read_text(encoding="utf-8")),
    )
    assert report.reverification_result == "MATCH"


def test_fuzzed_single_field_changes_never_match(
    issued_receipt: dict[str, Any], sample_profile_file: Path
) -> None:
    rng = random.Random(_FUZZ_SEED)
    package_bytes = BUNDLE_PATH.read_bytes()
    profile = load_profile(sample_profile_file)
    trust_keys = json.loads(TRUST_KEYS_PATH.read_text(encoding="utf-8"))

    for i in range(_FUZZ_ITERATIONS):
        mutated = json.loads(json.dumps(issued_receipt))
        # One or two independent single-field edits per iteration.
        for label, mutate in rng.sample(MUTATIONS, k=rng.randrange(1, 3)):
            mutate(mutated, rng)

        is_valid, _declared, _recomputed = verify_receipt_digest(mutated)
        assert is_valid is False, f"iteration {i}: digest accepted after {label} mutation"

        report = reverify_package(
            package_bytes=package_bytes,
            receipt_source=mutated,
            profile_source=profile,
            package_trust_keys=trust_keys,
        )
        assert report.reverification_result == "MISMATCH", (
            f"iteration {i}: tampered receipt ({label}) did not fail closed"
        )
        assert report.fresh_checks == [], f"iteration {i}: fresh checks ran against tampered data"
        assert report.package_digest_match is False

        # Complement: recomputing the digest over the mutated body restores
        # self-consistency, proving the digest binds the mutated field.
        mutated["receipt_digest"] = compute_receipt_digest(mutated)
        repaired_valid, _, _ = verify_receipt_digest(mutated)
        assert repaired_valid is True, f"iteration {i}: recomputed digest rejected mutated body"


def test_every_mutation_kind_is_exercised(issued_receipt: dict[str, Any]) -> None:
    rng = random.Random(_FUZZ_SEED + 1)
    for _label, mutate in MUTATIONS:
        mutated = json.loads(json.dumps(issued_receipt))
        mutate(mutated, rng)
        is_valid, _, _ = verify_receipt_digest(mutated)
        assert is_valid is False, f"mutation {_label} left the receipt self-consistent"
