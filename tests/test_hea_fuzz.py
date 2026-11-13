# SPDX-License-Identifier: Apache-2.0

"""Fuzz / hostile-input regression tests for HEA (seeded, deterministic).

No test here depends on unseeded randomness: every mutation loop uses a
fixed seed so failures reproduce.
"""

from __future__ import annotations

import base64
import json
import random
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from oev.canonical import CanonicalizationError, safe_json_loads
from oev.dsse import DsseError
from oev.execution_log import events_from_jsonl
from oev.hea_verifier import verify_historical_execution
from tests.hea_helpers import build_valid_hea, hea_inputs


def _mutate_bytes(data: bytes, rng: random.Random) -> bytes:
    mutated = bytearray(data)
    choice = rng.randrange(3)
    if choice == 0 and mutated:  # bit flip
        index = rng.randrange(len(mutated))
        mutated[index] ^= 1 << rng.randrange(8)
    elif choice == 1 and len(mutated) > 2:  # truncate
        mutated = mutated[: rng.randrange(1, len(mutated))]
    else:  # splice random bytes
        index = rng.randrange(len(mutated) + 1)
        mutated[index:index] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
    return bytes(mutated)


def test_mutated_attestation_envelopes_never_verify(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    rng = random.Random(20261113)
    from oev.canonical import canonicalize_json

    original = canonicalize_json(bundle["attestation_envelopes"][0])
    for _ in range(200):
        mutated = _mutate_bytes(original, rng)
        try:
            envelope = json.loads(mutated)
        except ValueError:
            continue  # not even JSON: rejected before verification
        if not isinstance(envelope, dict):
            continue
        result = verify_historical_execution(
            hea_inputs(bundle, attestations=[envelope, bundle["attestation_envelopes"][1]])
        )
        assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"


def test_mutated_log_lines_never_verify(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    rng = random.Random(20261113)
    original = bundle["log_jsonl"]
    for _ in range(100):
        mutated = _mutate_bytes(original, rng)
        try:
            events = events_from_jsonl(mutated)
        except (ValueError, TypeError):
            continue  # rejected at parse time
        result = verify_historical_execution(hea_inputs(bundle, log_events=events))
        assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"


def test_duplicate_json_keys_rejected_everywhere() -> None:
    duplicated = b'{"check_id": "c1", "check_id": "c2"}'
    with pytest.raises(ValueError, match="Duplicate"):
        safe_json_loads(duplicated)


def test_deeply_nested_json_rejected() -> None:
    depth = 200
    nested: object = {}
    for _ in range(depth):
        nested = {"a": nested}
    with pytest.raises(ValueError):
        safe_json_loads(json.dumps(nested).encode())


def test_huge_integer_rejected_by_canonicalization() -> None:
    with pytest.raises(CanonicalizationError):
        from oev.canonical import canonicalize_json as canon

        canon({"n": 2**60})


def test_oversized_json_rejected() -> None:
    huge = b'{"x": "' + b"a" * (11 * 1024 * 1024) + b'"}'
    with pytest.raises(ValueError, match="exceeds maximum"):
        safe_json_loads(huge)


def test_dsse_envelope_with_swapped_payload_type_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    envelope = dict(bundle["attestation_envelopes"][0])
    envelope["payloadType"] = "application/vnd.oev.verification-receipt+json"
    result = verify_historical_execution(hea_inputs(bundle, attestations=[envelope]))
    assert result.reason in ("MALFORMED_ATTESTATION", "SIGNATURE_INVALID", "SIGNATURE_UNTRUSTED")


def test_corrupted_dsse_signature_rejected(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    envelope = json.loads(json.dumps(bundle["attestation_envelopes"][0]))
    sig = envelope["signatures"][0]["sig"]
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 0xFF
    envelope["signatures"][0]["sig"] = base64.b64encode(bytes(raw)).decode()
    result = verify_historical_execution(hea_inputs(bundle, attestations=[envelope]))
    assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"


def test_path_traversal_bundle_never_passes(tmp_path: Path) -> None:
    pytest.importorskip("oept")
    from oept.verify import verify_bundle_bytes

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"escape")
        zf.writestr("manifest.json", b"{}")
    result = verify_bundle_bytes(buf.getvalue())
    assert result.status != "VALID"


def test_zip_bomb_member_over_limit_refused(tmp_path: Path) -> None:
    pytest.importorskip("oept")
    from oept.verify import verify_bundle_bytes

    # One member expanding past the 64 MiB single-member limit (zeros
    # compress to almost nothing on disk, ~70 MiB expanded).
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("evidence/big.bin", b"\x00" * (70 * 1024 * 1024))
        zf.writestr("facts.json", b"{}")
        zf.writestr("provenance.json", b"{}")
        zf.writestr(
            "manifest.json",
            json.dumps(
                {
                    "bundle_spec_version": "oept-bundle/0.1",
                    "bundle_id": "bomb",
                    "created_at": "2026-11-13T07:20:00Z",
                    "files": [],
                }
            ).encode(),
        )
    result = verify_bundle_bytes(buf.getvalue())
    assert result.status != "VALID"


def test_duplicate_member_paths_refused_by_oept_builder(tmp_path: Path) -> None:
    pytest.importorskip("oept")
    from oept.bundle import BundleBuilder
    from oept.errors import ValidationError

    builder = BundleBuilder(bundle_id="dup-test")
    builder.add_file("facts.json", b"{}")
    builder.add_file("provenance.json", b"{}")
    builder.add_evidence("a.bin", b"1")
    with pytest.raises(ValidationError, match="duplicate"):
        builder.add_file("facts.json", b"{}")


def test_random_json_documents_do_not_crash_verifier(tmp_path: Path) -> None:
    bundle = build_valid_hea(tmp_path)
    rng = random.Random(7)
    for _ in range(50):
        junk: object = rng.choice([[], {}, "x", 1, None, {"a": [1, {"b": None}]}])
        try:
            result = verify_historical_execution(hea_inputs(bundle, attestations=[junk]))
        except (ValueError, TypeError, DsseError, KeyError):
            continue
        assert result.historical_execution == "HISTORICAL_EXECUTION_UNPROVEN"
