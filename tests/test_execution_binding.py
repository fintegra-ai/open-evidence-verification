# SPDX-License-Identifier: Apache-2.0

"""Tests for pre-binding and Execution ID derivation (HEA design §1)."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from oev.execution import (
    COMMITMENT_PAYLOAD_TYPE,
    build_commitment_envelope,
    build_prebinding,
    compute_code_digest,
    compute_execution_id,
    compute_trust_inputs_digest,
    generate_nonce,
    is_valid_execution_id,
    parse_commitment_envelope,
)
from oev.signing import generate_ed25519_keypair

BUNDLE_DIGEST = "sha256:" + "a" * 64
PROFILE_DIGEST = "sha256:" + "b" * 64
CODE_DIGEST = "sha256:" + "c" * 64


def _prebinding(**overrides: object) -> dict[str, Any]:
    base = build_prebinding(
        bundle_digest=BUNDLE_DIGEST,
        bundle_format="oept-bundle/0.1",
        profile_id="strict-conformance-profile",
        profile_version="0.1.0",
        profile_digest=PROFILE_DIGEST,
        code_version={"engine": "oev 0.2.3", "adapter": "oept 0.1.3", "code_digest": CODE_DIGEST},
        check_ids=["archive_safety", "manifest_structure"],
        input_digests={"package": BUNDLE_DIGEST, "profile": PROFILE_DIGEST},
        trust_inputs_digest=compute_trust_inputs_digest([]),
        nonce="AAAAAAAAAAAAAAAAAAAAAA",
        witness_mode="local-process",
        witness_key_id="wit-1",
    )
    base.update(overrides)
    return base


def test_execution_id_is_deterministic_for_identical_prebinding() -> None:
    assert compute_execution_id(_prebinding()) == compute_execution_id(_prebinding())


def test_execution_id_is_insensitive_to_dict_key_order() -> None:
    first = _prebinding()
    reordered = {k: first[k] for k in reversed(list(first))}
    assert compute_execution_id(first) == compute_execution_id(reordered)


def test_execution_id_has_expected_form() -> None:
    execution_id = compute_execution_id(_prebinding())
    assert is_valid_execution_id(execution_id)
    assert execution_id.startswith("exec_")
    assert len(execution_id) == len("exec_") + 32


def test_nonce_changes_execution_id() -> None:
    assert compute_execution_id(_prebinding(nonce="AAAAAAAAAAAAAAAAAAAAAA")) != (
        compute_execution_id(_prebinding(nonce="BBBBBBBBBBBBBBBBBBBBBB"))
    )


def test_bundle_digest_change_changes_execution_id() -> None:
    assert compute_execution_id(_prebinding()) != compute_execution_id(
        _prebinding(bundle_digest="sha256:" + "d" * 64)
    )


def test_profile_digest_change_changes_execution_id() -> None:
    assert compute_execution_id(_prebinding()) != compute_execution_id(
        _prebinding(profile_digest="sha256:" + "d" * 64)
    )


def test_code_digest_change_changes_execution_id() -> None:
    changed = _prebinding()
    changed["code_version"] = {
        "engine": "oev 0.2.3",
        "adapter": "oept 0.1.3",
        "code_digest": "sha256:" + "d" * 64,
    }
    assert compute_execution_id(_prebinding()) != compute_execution_id(changed)


def test_check_ids_order_does_not_change_execution_id() -> None:
    # check_ids are sorted at build time, so listing order is not identity.
    # (Same explicit nonce on both sides: nonces are the identity salt.)
    first = build_prebinding(
        bundle_digest=BUNDLE_DIGEST,
        bundle_format="oept-bundle/0.1",
        profile_id="strict-conformance-profile",
        profile_version="0.1.0",
        profile_digest=PROFILE_DIGEST,
        code_version={"engine": "oev 0.2.3", "adapter": "oept 0.1.3", "code_digest": CODE_DIGEST},
        check_ids=["b_check", "a_check"],
        nonce="AAAAAAAAAAAAAAAAAAAAAA",
    )
    second = build_prebinding(
        bundle_digest=BUNDLE_DIGEST,
        bundle_format="oept-bundle/0.1",
        profile_id="strict-conformance-profile",
        profile_version="0.1.0",
        profile_digest=PROFILE_DIGEST,
        code_version={"engine": "oev 0.2.3", "adapter": "oept 0.1.3", "code_digest": CODE_DIGEST},
        check_ids=["a_check", "b_check"],
        nonce="AAAAAAAAAAAAAAAAAAAAAA",
    )
    assert compute_execution_id(first) == compute_execution_id(second)


def test_empty_check_ids_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        build_prebinding(
            bundle_digest=BUNDLE_DIGEST,
            bundle_format="oept-bundle/0.1",
            profile_id="p",
            profile_version="0.1",
            profile_digest=PROFILE_DIGEST,
            code_version={"engine": "e", "adapter": "a", "code_digest": CODE_DIGEST},
            check_ids=[],
        )


def test_duplicate_check_ids_rejected() -> None:
    with pytest.raises(ValueError, match="unique"):
        build_prebinding(
            bundle_digest=BUNDLE_DIGEST,
            bundle_format="oept-bundle/0.1",
            profile_id="p",
            profile_version="0.1",
            profile_digest=PROFILE_DIGEST,
            code_version={"engine": "e", "adapter": "a", "code_digest": CODE_DIGEST},
            check_ids=["c1", "c1"],
        )


def test_malformed_digest_rejected() -> None:
    with pytest.raises(ValueError, match="bundle_digest"):
        build_prebinding(
            bundle_digest="not-a-digest",
            bundle_format="oept-bundle/0.1",
            profile_id="p",
            profile_version="0.1",
            profile_digest=PROFILE_DIGEST,
            code_version={"engine": "e", "adapter": "a", "code_digest": CODE_DIGEST},
            check_ids=["c1"],
        )


def test_unknown_witness_mode_rejected() -> None:
    with pytest.raises(ValueError, match="witness_mode"):
        build_prebinding(
            bundle_digest=BUNDLE_DIGEST,
            bundle_format="oept-bundle/0.1",
            profile_id="p",
            profile_version="0.1",
            profile_digest=PROFILE_DIGEST,
            code_version={"engine": "e", "adapter": "a", "code_digest": CODE_DIGEST},
            check_ids=["c1"],
            witness_mode="quantum",
        )


def test_nonce_is_128_bit_base64url_and_unique() -> None:
    nonces = {generate_nonce() for _ in range(100)}
    assert len(nonces) == 100
    for nonce in nonces:
        raw = base64.urlsafe_b64decode(nonce + "=" * (-len(nonce) % 4))
        assert len(raw) == 16


def test_commitment_envelope_roundtrip() -> None:
    priv, _pub = generate_ed25519_keypair()
    prebinding = _prebinding()
    execution_id = compute_execution_id(prebinding)
    envelope = build_commitment_envelope(
        prebinding, execution_id, "2026-11-13T07:20:00Z", priv, "wit-1"
    )
    assert envelope["payloadType"] == COMMITMENT_PAYLOAD_TYPE
    commitment = parse_commitment_envelope(envelope)
    assert commitment.execution_id == execution_id
    assert commitment.nonce == prebinding["nonce"]
    assert commitment.bundle_digest == BUNDLE_DIGEST
    assert commitment.commitment_digest() == commitment.commitment_digest()


def test_commitment_with_wrong_payload_type_rejected() -> None:
    priv, _pub = generate_ed25519_keypair()
    prebinding = _prebinding()
    execution_id = compute_execution_id(prebinding)
    envelope = build_commitment_envelope(
        prebinding, execution_id, "2026-11-13T07:20:00Z", priv, "wit-1"
    )
    envelope["payloadType"] = "application/vnd.oev.verification-receipt+json"
    with pytest.raises(ValueError):
        parse_commitment_envelope(envelope)


def test_code_digest_is_deterministic_for_this_install() -> None:
    assert compute_code_digest() == compute_code_digest()


def test_trust_inputs_digest_is_order_insensitive() -> None:
    first = compute_trust_inputs_digest(
        [
            {"trust_id": "b", "type": "public_key", "digest": "sha256:" + "1" * 64},
            {"trust_id": "a", "type": "public_key", "digest": "sha256:" + "2" * 64},
        ]
    )
    second = compute_trust_inputs_digest(
        [
            {"trust_id": "a", "type": "public_key", "digest": "sha256:" + "2" * 64},
            {"trust_id": "b", "type": "public_key", "digest": "sha256:" + "1" * 64},
        ]
    )
    assert first == second


def test_unsupported_execution_protocol_version_rejected() -> None:
    prebinding = _prebinding(protocol_version="oev-execution/9.9")
    with pytest.raises(ValueError, match="Unsupported execution protocol version"):
        compute_execution_id(prebinding)
