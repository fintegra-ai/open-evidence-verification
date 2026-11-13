# SPDX-License-Identifier: Apache-2.0

"""Tests for the hash-chain / Merkle log and signed checkpoints (HEA design §4)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from oev.canonical import canonicalize_json
from oev.execution_log import (
    GENESIS_PREV_HASH,
    LogCheckpoint,
    LogCompleteness,
    LogEvent,
    build_checkpoint,
    events_from_jsonl,
    events_to_jsonl,
    merkle_inclusion_proof,
    merkle_root,
    parse_checkpoint_envelope,
    sign_checkpoint_dsse,
    sign_completeness_dsse,
    validate_log_event_dict,
    verify_checkpoint_signature,
    verify_completeness_signature,
    verify_event_chain,
    verify_merkle_inclusion_proof,
)
from oev.hashing import sha256_bytes
from oev.trust import TrustStore
from tests.hea_helpers import CLAIMED_TIME, make_keypair

EXECUTION_ID = "exec_" + "a" * 32


def _event(
    seq: int, prev_hash: str, event_type: str = "CHECK_COMPLETED", check_id: str | None = "c1"
) -> LogEvent:
    return LogEvent(
        log_id="hea-log-001",
        seq=seq,
        event_type=event_type,
        execution_id=EXECUTION_ID,
        check_id=check_id,
        event_digest=sha256_bytes(canonicalize_json({"seq": seq})),
        prev_hash=prev_hash,
        claimed_time=CLAIMED_TIME,
    )


def _chain(n: int) -> list[LogEvent]:
    events: list[LogEvent] = []
    prev = GENESIS_PREV_HASH
    for i in range(n):
        event = _event(i, prev, check_id=f"c{i}")
        events.append(event)
        prev = event.leaf_hash()
    return events


def test_empty_chain_is_valid() -> None:
    ok, note = verify_event_chain([])
    assert ok and note == ""


def test_valid_chain_verifies() -> None:
    ok, _note = verify_event_chain(_chain(5))
    assert ok


def test_genesis_prev_hash_is_zeroes() -> None:
    assert GENESIS_PREV_HASH == "sha256:" + "0" * 64
    assert _chain(1)[0].prev_hash == GENESIS_PREV_HASH


def test_prev_hash_tamper_breaks_chain() -> None:
    events = _chain(3)
    tampered = LogEvent(
        log_id=events[1].log_id,
        seq=events[1].seq,
        event_type=events[1].event_type,
        execution_id=events[1].execution_id,
        check_id=events[1].check_id,
        event_digest=events[1].event_digest,
        prev_hash="sha256:" + "1" * 64,
        claimed_time=events[1].claimed_time,
    )
    ok, note = verify_event_chain([events[0], tampered, events[2]])
    assert not ok
    assert "prev_hash" in note


def test_seq_gap_breaks_chain() -> None:
    events = _chain(3)
    del events[1]
    ok, note = verify_event_chain(events)
    assert not ok
    assert "seq gap" in note


def test_event_content_tamper_breaks_chain() -> None:
    events = _chain(3)
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
    ok, _note = verify_event_chain([tampered, events[1], events[2]])
    assert not ok


def test_leaf_hash_is_stable_and_content_bound() -> None:
    event = _chain(1)[0]
    assert event.leaf_hash() == event.leaf_hash()
    assert event.leaf_hash() == sha256_bytes(
        canonicalize_json(event.to_dict(include_leaf_hash=False))
    )


def test_merkle_root_single_leaf_is_the_leaf() -> None:
    leaves = ["sha256:" + "a" * 64]
    assert merkle_root(leaves) == leaves[0]


def test_merkle_root_empty_is_sha256_of_empty() -> None:
    assert merkle_root([]) == "sha256:" + hashlib.sha256(b"").hexdigest()


def test_merkle_root_two_leaves_is_pair_hash() -> None:
    left = bytes.fromhex("aa" * 32)
    right = bytes.fromhex("bb" * 32)
    expected = "sha256:" + hashlib.sha256(left + right).hexdigest()
    assert merkle_root(["sha256:" + "aa" * 32, "sha256:" + "bb" * 32]) == expected


def test_inclusion_proof_verifies_for_every_leaf() -> None:
    events = _chain(7)
    leaves = [e.leaf_hash() for e in events]
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = merkle_inclusion_proof(leaves, index)
        assert verify_merkle_inclusion_proof(leaf, index, proof, root)


def test_inclusion_proof_fails_for_wrong_leaf() -> None:
    events = _chain(4)
    leaves = [e.leaf_hash() for e in events]
    root = merkle_root(leaves)
    proof = merkle_inclusion_proof(leaves, 0)
    assert not verify_merkle_inclusion_proof("sha256:" + "0" * 64, 0, proof, root)


def test_inclusion_proof_fails_for_tampered_sibling() -> None:
    events = _chain(4)
    leaves = [e.leaf_hash() for e in events]
    root = merkle_root(leaves)
    proof = merkle_inclusion_proof(leaves, 0)
    proof[0] = {"side": proof[0]["side"], "hash": "sha256:" + "0" * 64}
    assert not verify_merkle_inclusion_proof(leaves[0], 0, proof, root)


def test_inclusion_proof_index_out_of_range_rejected() -> None:
    with pytest.raises(ValueError):
        merkle_inclusion_proof(["sha256:" + "a" * 64], 5)


def test_checkpoint_build_sign_verify_roundtrip() -> None:
    events = _chain(4)
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    assert checkpoint.leaf_count == 4
    assert checkpoint.checkpoint_seq == 4
    assert checkpoint.merkle_root == merkle_root([e.leaf_hash() for e in events])
    priv, _pub, entry = make_keypair(role="checkpoint-signer")
    entry["key_id"] = "cp-1"
    envelope = sign_checkpoint_dsse(checkpoint, priv, "cp-1")
    store = TrustStore.from_list([entry])
    parsed, reason = verify_checkpoint_signature(envelope, store)
    assert parsed is not None and reason == ""
    assert parsed.checkpoint_digest() == checkpoint.checkpoint_digest()


def test_checkpoint_signed_by_witness_key_rejected() -> None:
    events = _chain(2)
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    priv, _pub, entry = make_keypair(role="witness")
    entry["key_id"] = "wit-1"
    envelope = sign_checkpoint_dsse(checkpoint, priv, "wit-1")
    store = TrustStore.from_list([entry])
    _parsed, reason = verify_checkpoint_signature(envelope, store)
    assert reason == "SIGNATURE_UNTRUSTED"


def test_checkpoint_over_invalid_chain_refused() -> None:
    events = _chain(3)
    del events[1]
    with pytest.raises(ValueError, match="invalid event chain"):
        build_checkpoint(events, "hea-log-001", CLAIMED_TIME)


def test_checkpoint_wrong_payload_type_rejected() -> None:
    events = _chain(1)
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    priv, _pub, _entry = make_keypair(role="checkpoint-signer")
    envelope = sign_checkpoint_dsse(checkpoint, priv, "cp-1")
    envelope["payloadType"] = "application/vnd.oev.execution-attestation+json"
    with pytest.raises(ValueError):
        parse_checkpoint_envelope(envelope)


def test_log_jsonl_roundtrip() -> None:
    events = _chain(3)
    data = events_to_jsonl(events)
    parsed = events_from_jsonl(data)
    assert [e.to_dict() for e in parsed] == [e.to_dict() for e in events]


def test_log_jsonl_duplicate_key_rejected() -> None:
    line = b'{"seq": 0, "seq": 1, "log_id": "x"}'
    with pytest.raises(ValueError, match="Duplicate"):
        events_from_jsonl(line)


def test_log_jsonl_non_object_line_rejected() -> None:
    with pytest.raises(TypeError):
        events_from_jsonl(b"[1, 2, 3]\n")


def test_log_event_validation_rejects_bad_digest() -> None:
    event = _chain(1)[0]
    raw = event.to_dict()
    raw["event_digest"] = "not-a-digest"
    with pytest.raises(ValueError):
        validate_log_event_dict(raw)


def test_check_completed_without_check_id_rejected() -> None:
    event = _event(0, GENESIS_PREV_HASH, check_id=None)
    raw = event.to_dict()
    with pytest.raises(ValueError, match="check_id"):
        validate_log_event_dict(raw)


def test_unknown_event_type_rejected() -> None:
    event = _chain(1)[0]
    raw = event.to_dict()
    raw["event_type"] = "SOMETHING_ELSE"
    with pytest.raises(ValueError):
        validate_log_event_dict(raw)


def test_oversized_log_line_rejected(tmp_path: Path) -> None:
    huge = b'{"x": "' + b"a" * (11 * 1024 * 1024) + b'"}\n'
    with pytest.raises(ValueError, match="exceeds maximum"):
        events_from_jsonl(huge)


def test_completeness_statement_sign_verify() -> None:
    events = _chain(2)
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    statement = LogCompleteness(
        log_id="hea-log-001",
        through_seq=checkpoint.checkpoint_seq,
        checkpoint_digest=checkpoint.checkpoint_digest(),
        claimed_time=CLAIMED_TIME,
    )
    priv, _pub, entry = make_keypair(role="checkpoint-signer")
    entry["key_id"] = "cp-1"
    envelope = sign_completeness_dsse(statement, priv, "cp-1")
    store = TrustStore.from_list([entry])
    parsed, ok = verify_completeness_signature(envelope, store)
    assert ok and parsed is not None
    assert parsed.through_seq == 2


def test_completeness_statement_wrong_key_fails() -> None:
    events = _chain(2)
    checkpoint = build_checkpoint(events, "hea-log-001", CLAIMED_TIME)
    statement = LogCompleteness(
        log_id="hea-log-001",
        through_seq=checkpoint.checkpoint_seq,
        checkpoint_digest=checkpoint.checkpoint_digest(),
        claimed_time=CLAIMED_TIME,
    )
    priv, _pub, _entry = make_keypair(role="checkpoint-signer")
    envelope = sign_completeness_dsse(statement, priv, "cp-1")
    _other_priv, _other_pub, other_entry = make_keypair(role="checkpoint-signer")
    other_entry["key_id"] = "cp-2"
    store = TrustStore.from_list([other_entry])
    _parsed, ok = verify_completeness_signature(envelope, store)
    assert not ok


def test_checkpoint_type_roundtrip() -> None:
    checkpoint = LogCheckpoint(
        log_id="hea-log-001",
        checkpoint_seq=3,
        merkle_root="sha256:" + "a" * 64,
        leaf_count=3,
        prev_checkpoint_digest=GENESIS_PREV_HASH,
        claimed_time=CLAIMED_TIME,
    )
    assert LogCheckpoint.from_dict(checkpoint.to_dict()) == checkpoint
