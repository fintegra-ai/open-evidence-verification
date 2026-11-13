# SPDX-License-Identifier: Apache-2.0

"""Property-based tests for HEA (hypothesis)."""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from oev.attestation import compute_attestation_id
from oev.canonical import canonicalize_json
from oev.execution import build_prebinding, compute_execution_id, compute_trust_inputs_digest
from oev.execution_log import (
    GENESIS_PREV_HASH,
    LogEvent,
    merkle_inclusion_proof,
    merkle_root,
    verify_event_chain,
    verify_merkle_inclusion_proof,
)
from oev.hashing import sha256_bytes
from oev.revocation import RevocationEntry, RevocationList
from tests.hea_helpers import CLAIMED_TIME

hex_text = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
small_text = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=12)


@settings(max_examples=50)
@given(nonce_a=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=22, max_size=22))
def test_execution_id_changes_with_nonce(nonce_a: str) -> None:
    def _build(nonce: str) -> str:
        prebinding = build_prebinding(
            bundle_digest="sha256:" + "a" * 64,
            bundle_format="oept-bundle/0.1",
            profile_id="p",
            profile_version="0.1",
            profile_digest="sha256:" + "b" * 64,
            code_version={"engine": "e", "adapter": "a", "code_digest": "sha256:" + "c" * 64},
            check_ids=["c1"],
            nonce=nonce,
        )
        return compute_execution_id(prebinding)

    assert _build(nonce_a) != _build(nonce_a + "X" if len(nonce_a) < 22 else "Z" * 22)


@settings(max_examples=50)
@given(
    bundle_hex=hex_text,
    profile_hex=hex_text,
    check_ids=st.lists(small_text, min_size=1, max_size=5, unique=True),
)
def test_execution_id_is_deterministic(
    bundle_hex: str, profile_hex: str, check_ids: list[str]
) -> None:
    def _build() -> str:
        prebinding = build_prebinding(
            bundle_digest=f"sha256:{bundle_hex}",
            bundle_format="oept-bundle/0.1",
            profile_id="p",
            profile_version="0.1",
            profile_digest=f"sha256:{profile_hex}",
            code_version={"engine": "e", "adapter": "a", "code_digest": "sha256:" + "c" * 64},
            check_ids=check_ids,
            nonce="AAAAAAAAAAAAAAAAAAAAAA",
        )
        return compute_execution_id(prebinding)

    assert _build() == _build()


@settings(max_examples=30)
@given(n=st.integers(min_value=1, max_value=32))
def test_merkle_proof_verifies_for_every_leaf(n: int) -> None:
    leaves = ["sha256:" + f"{i:064x}" for i in range(n)]
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = merkle_inclusion_proof(leaves, index)
        assert verify_merkle_inclusion_proof(leaf, index, proof, root)


@settings(max_examples=30)
@given(n=st.integers(min_value=2, max_value=16))
def test_random_chain_verifies_and_single_tamper_breaks_it(n: int) -> None:
    events: list[LogEvent] = []
    prev = GENESIS_PREV_HASH
    for i in range(n):
        event = LogEvent(
            log_id="hea-log-001",
            seq=i,
            event_type="CHECK_COMPLETED",
            execution_id="exec_" + "a" * 32,
            check_id=f"c{i}",
            event_digest=sha256_bytes(canonicalize_json({"i": i})),
            prev_hash=prev,
            claimed_time=CLAIMED_TIME,
        )
        events.append(event)
        prev = event.leaf_hash()
    ok, _note = verify_event_chain(events)
    assert ok
    tampered = LogEvent(
        log_id=events[0].log_id,
        seq=events[0].seq,
        event_type=events[0].event_type,
        execution_id=events[0].execution_id,
        check_id=events[0].check_id,
        event_digest="sha256:" + "9" * 64,
        prev_hash=events[0].prev_hash,
        claimed_time=events[0].claimed_time,
    )
    ok, _note = verify_event_chain([tampered, *events[1:]])
    assert not ok


@settings(max_examples=50)
@given(
    execution_id=st.text(alphabet="0123456789abcdef", min_size=32, max_size=32),
    check_id=small_text,
)
def test_attestation_id_is_deterministic(execution_id: str, check_id: str) -> None:
    first = compute_attestation_id(f"exec_{execution_id}", check_id)
    second = compute_attestation_id(f"exec_{execution_id}", check_id)
    assert first == second
    assert first.startswith("att_") and len(first) == len("att_") + 16


@settings(max_examples=30)
@given(
    data=st.recursive(
        st.dictionaries(
            st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=6),
            st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1),
            max_size=4,
        ),
        lambda children: st.lists(children, max_size=3),
        max_leaves=6,
    )
)
def test_canonicalization_is_deterministic_for_json_like_data(data: object) -> None:
    assert canonicalize_json(data) == canonicalize_json(data)


@settings(max_examples=30)
@given(key_ids=st.lists(small_text, min_size=0, max_size=5, unique=True))
def test_revocation_membership_is_consistent(key_ids: list[str]) -> None:
    revocation = RevocationList(
        issuer_key_id="rev-1",
        issued_at_claimed=CLAIMED_TIME,
        entries=[
            RevocationEntry(key_id=k, reason="x", revoked_at_claimed=CLAIMED_TIME) for k in key_ids
        ],
    )
    for key_id in key_ids:
        assert revocation.is_revoked(key_id)
    assert not revocation.is_revoked("definitely-not-revoked")


@settings(max_examples=30)
@given(
    entries=st.lists(
        st.fixed_dictionaries(
            {
                "trust_id": small_text,
                "type": st.just("public_key"),
                "digest": hex_text.map(lambda h: f"sha256:{h}"),
            }
        ),
        min_size=0,
        max_size=5,
        unique_by=lambda e: e["trust_id"],
    )
)
def test_trust_inputs_digest_is_order_insensitive(entries: list[dict[str, str]]) -> None:
    first = compute_trust_inputs_digest(entries)
    second = compute_trust_inputs_digest(list(reversed(entries)))
    assert first == second
