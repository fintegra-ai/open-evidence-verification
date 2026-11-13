# SPDX-License-Identifier: Apache-2.0

"""Hash-chain / Merkle execution log with signed checkpoints (oev-execution-log/0.1).

HEA design §4. The log records execution events as JCS-canonical structures
linked by ``prev_hash``; leaf hashes feed a binary Merkle tree; a signed
checkpoint anchors a prefix of the log so verifiers can prune.

Event types: EXECUTION_STARTED, CHECK_COMPLETED, EXECUTION_COMPLETED,
EXECUTION_FAILED, CHECKPOINT. ``seq`` starts at 0, is gapless and monotone.
``prev_hash`` of the first event is ``"sha256:" + "0" * 64``.

What the log detects (design §4.5): deletion from the middle (seq gap or
Merkle mismatch), content tampering (leaf-hash chain breaks), reordering
(prev_hash chain breaks). What it does NOT detect: a complete rewrite
(fork) shown to a first-time verifier, or a log written by a dishonest
witness together with its operator. Both limits are reported, not hidden.

Resource bounds: a log is capped at ``MAX_LOG_EVENTS`` events and each
event payload at the JSON bound enforced by ``safe_json_loads``.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize_json, safe_json_loads
from .dsse import DsseError, build_dsse_envelope, compute_pae, parse_dsse_envelope
from .hashing import is_valid_digest, sha256_bytes
from .schemas import validate_document
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .trust import TrustStore

LOG_PROTOCOL_VERSION = "oev-execution-log/0.1"
CHECKPOINT_PROTOCOL_VERSION = "oev-log-checkpoint/0.1"
CHECKPOINT_PAYLOAD_TYPE = "application/vnd.oev.log-checkpoint+json"
COMPLETENESS_PAYLOAD_TYPE = "application/vnd.oev.log-completeness+json"
LOG_EVENT_SCHEMA_NAME = "execution-log-event-0.1.schema.json"
CHECKPOINT_SCHEMA_NAME = "log-checkpoint-0.1.schema.json"

MAX_LOG_EVENTS: int = 1_000_000
GENESIS_PREV_HASH = "sha256:" + "0" * 64

EVENT_TYPES: frozenset[str] = frozenset(
    {
        "EXECUTION_STARTED",
        "CHECK_COMPLETED",
        "EXECUTION_COMPLETED",
        "EXECUTION_FAILED",
        "CHECKPOINT",
    }
)


@dataclass(frozen=True)
class LogEvent:
    """One hash-chained log event (§4.2). ``leaf_hash`` is derived, not stored in the hash."""

    log_id: str
    seq: int
    event_type: str
    execution_id: str
    check_id: str | None
    event_digest: str
    prev_hash: str
    claimed_time: str
    protocol_version: str = LOG_PROTOCOL_VERSION

    def to_dict(self, include_leaf_hash: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "log_id": self.log_id,
            "seq": self.seq,
            "event_type": self.event_type,
            "execution_id": self.execution_id,
            "event_digest": self.event_digest,
            "prev_hash": self.prev_hash,
            "claimed_time": self.claimed_time,
        }
        if self.check_id is not None:
            d["check_id"] = self.check_id
        if include_leaf_hash:
            d["leaf_hash"] = self.leaf_hash()
        return d

    def leaf_hash(self) -> str:
        """``sha256:<hex>`` of the JCS-canonical event without ``leaf_hash``."""
        return sha256_bytes(canonicalize_json(self.to_dict(include_leaf_hash=False)))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogEvent:
        return cls(
            log_id=str(data["log_id"]),
            seq=int(data["seq"]),
            event_type=str(data["event_type"]),
            execution_id=str(data["execution_id"]),
            check_id=str(data["check_id"]) if data.get("check_id") else None,
            event_digest=str(data["event_digest"]),
            prev_hash=str(data["prev_hash"]),
            claimed_time=str(data["claimed_time"]),
            protocol_version=str(data.get("protocol_version", LOG_PROTOCOL_VERSION)),
        )


def validate_log_event_dict(data: dict[str, Any]) -> LogEvent:
    """Validate a raw event dict (schema + HEA rules) and return the event."""
    validate_document(data, LOG_EVENT_SCHEMA_NAME)
    event = LogEvent.from_dict(data)
    if event.protocol_version != LOG_PROTOCOL_VERSION:
        raise ValueError(f"Unsupported log protocol version: {event.protocol_version!r}")
    if event.event_type not in EVENT_TYPES:
        raise ValueError(f"Unknown log event_type: {event.event_type!r}")
    if event.seq < 0 or event.seq >= MAX_LOG_EVENTS:
        raise ValueError(f"Log event seq out of range: {event.seq}")
    if not is_valid_digest(event.event_digest):
        raise ValueError("Log event event_digest is malformed")
    if not is_valid_digest(event.prev_hash):
        raise ValueError("Log event prev_hash is malformed")
    declared_leaf = str(data.get("leaf_hash", ""))
    if declared_leaf and declared_leaf != event.leaf_hash():
        raise ValueError(f"Log event leaf_hash mismatch at seq {event.seq}")
    if event.event_type == "CHECK_COMPLETED" and not event.check_id:
        raise ValueError("CHECK_COMPLETED event requires check_id")
    return event


def verify_event_chain(events: list[LogEvent]) -> tuple[bool, str]:
    """Verify seq gaplessness, prev_hash linkage and leaf hashes.

    Returns ``(ok, note)``. ``note`` is empty on success.
    """
    if len(events) > MAX_LOG_EVENTS:
        return False, f"log exceeds {MAX_LOG_EVENTS} events"
    expected_prev = GENESIS_PREV_HASH
    for index, event in enumerate(events):
        if event.seq != index:
            return False, f"log seq gap at position {index}: found seq {event.seq}"
        if event.prev_hash != expected_prev:
            return False, f"log prev_hash mismatch at seq {event.seq}"
        expected_prev = event.leaf_hash()
    return True, ""


# ---------------------------------------------------------------------------
# Merkle tree (binary, SHA-256 over raw leaf-hash bytes, odd leaf promoted)
# ---------------------------------------------------------------------------


def merkle_root(leaf_hashes: list[str]) -> str:
    """Compute the Merkle root of ``sha256:<hex>`` leaf hashes.

    Empty list → SHA-256 of empty input (defined so checkpoints over an
    empty log still have a deterministic root). One leaf → the leaf itself.
    """
    if not leaf_hashes:
        return sha256_bytes(b"")
    level = [bytes.fromhex(h[len("sha256:") :]) for h in leaf_hashes]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return "sha256:" + level[0].hex()


def merkle_inclusion_proof(leaf_hashes: list[str], leaf_index: int) -> list[dict[str, str]]:
    """Inclusion proof for ``leaf_index``: ``[{side, hash}]`` steps to the root."""
    if leaf_index < 0 or leaf_index >= len(leaf_hashes):
        raise ValueError(f"leaf_index {leaf_index} out of range for {len(leaf_hashes)} leaves")
    proof: list[dict[str, str]] = []
    level = [bytes.fromhex(h[len("sha256:") :]) for h in leaf_hashes]
    index = leaf_index
    while len(level) > 1:
        if index % 2 == 0:
            if index + 1 < len(level):
                proof.append({"side": "right", "hash": "sha256:" + level[index + 1].hex()})
        else:
            proof.append({"side": "left", "hash": "sha256:" + level[index - 1].hex()})
        nxt: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
        index //= 2
    return proof


def verify_merkle_inclusion_proof(
    leaf_hash: str, leaf_index: int, proof: list[dict[str, str]], expected_root: str
) -> bool:
    """Verify a Merkle inclusion proof against an expected root."""
    if not is_valid_digest(leaf_hash) or not is_valid_digest(expected_root):
        return False
    current = bytes.fromhex(leaf_hash[len("sha256:") :])
    index = leaf_index
    for step in proof:
        sibling_hex = str(step.get("hash", ""))
        if not is_valid_digest(sibling_hex):
            return False
        sibling = bytes.fromhex(sibling_hex[len("sha256:") :])
        if step.get("side") == "right":
            current = hashlib.sha256(current + sibling).digest()
        elif step.get("side") == "left":
            current = hashlib.sha256(sibling + current).digest()
        else:
            return False
        index //= 2
    return "sha256:" + current.hex() == expected_root


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogCheckpoint:
    """A signed summary of a log prefix (§4.4).

    ``checkpoint_seq`` is the number of leaves covered (i.e. the next seq
    to be written), equal to ``leaf_count``.
    """

    log_id: str
    checkpoint_seq: int
    merkle_root: str
    leaf_count: int
    prev_checkpoint_digest: str
    claimed_time: str
    protocol_version: str = CHECKPOINT_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "log_id": self.log_id,
            "checkpoint_seq": self.checkpoint_seq,
            "merkle_root": self.merkle_root,
            "leaf_count": self.leaf_count,
            "prev_checkpoint_digest": self.prev_checkpoint_digest,
            "claimed_time": self.claimed_time,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogCheckpoint:
        if str(data.get("protocol_version", "")) != CHECKPOINT_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported checkpoint protocol version: {data.get('protocol_version')!r}"
            )
        return cls(
            log_id=str(data["log_id"]),
            checkpoint_seq=int(data["checkpoint_seq"]),
            merkle_root=str(data["merkle_root"]),
            leaf_count=int(data["leaf_count"]),
            prev_checkpoint_digest=str(data["prev_checkpoint_digest"]),
            claimed_time=str(data["claimed_time"]),
        )

    def checkpoint_digest(self) -> str:
        return sha256_bytes(canonicalize_json(self.to_dict()))


def build_checkpoint(
    events: list[LogEvent],
    log_id: str,
    claimed_time: str,
    prev_checkpoint_digest: str = GENESIS_PREV_HASH,
) -> LogCheckpoint:
    """Build the checkpoint covering all ``events`` (must be chain-valid)."""
    ok, note = verify_event_chain(events)
    if not ok:
        raise ValueError(f"Cannot checkpoint an invalid event chain: {note}")
    if events and any(e.log_id != log_id for e in events):
        raise ValueError("All checkpointed events must share the checkpoint log_id")
    leaves = [e.leaf_hash() for e in events]
    return LogCheckpoint(
        log_id=log_id,
        checkpoint_seq=len(events),
        merkle_root=merkle_root(leaves),
        leaf_count=len(events),
        prev_checkpoint_digest=prev_checkpoint_digest,
        claimed_time=claimed_time,
    )


def sign_checkpoint_dsse(
    checkpoint: LogCheckpoint, private_key_pem: bytes, key_id: str = ""
) -> dict[str, Any]:
    """Validate and DSSE-sign a checkpoint. Returns the envelope."""
    payload = checkpoint.to_dict()
    validate_document(payload, CHECKPOINT_SCHEMA_NAME)
    payload_bytes = canonicalize_json(payload)
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(CHECKPOINT_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
    if key_id:
        sig_entry["keyid"] = key_id
    return build_dsse_envelope(
        payload_type=CHECKPOINT_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def parse_checkpoint_envelope(envelope: dict[str, Any]) -> LogCheckpoint:
    """Parse a DSSE checkpoint envelope (no trust check)."""
    payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    if payload_type != CHECKPOINT_PAYLOAD_TYPE:
        raise DsseError(f"Unexpected DSSE payloadType for a log checkpoint: {payload_type!r}")
    data = safe_json_loads(payload_bytes.decode("utf-8"))
    if not isinstance(data, dict):
        raise DsseError("Checkpoint payload is not a JSON object")
    validate_document(data, CHECKPOINT_SCHEMA_NAME)
    return LogCheckpoint.from_dict(data)


def verify_checkpoint_signature(
    envelope: dict[str, Any], checkpoint_trust_store: TrustStore | None
) -> tuple[LogCheckpoint | None, str]:
    """Verify a checkpoint DSSE signature against caller checkpoint keys.

    Returns ``(checkpoint_or_None, reason)``; ``reason`` is ``""`` on success.
    A checkpoint key must carry role ``checkpoint-signer`` (or no role only
    when the store predates HEA roles — rejected here: checkpoint signing
    always requires the explicit role, mirroring the witness rule).
    """
    try:
        checkpoint = parse_checkpoint_envelope(envelope)
    except (DsseError, ValueError) as exc:
        return None, f"MALFORMED_ATTESTATION: {exc}"
    if checkpoint_trust_store is None or len(checkpoint_trust_store.keys) == 0:
        return checkpoint, "SIGNATURE_UNTRUSTED"
    _pt, payload_bytes, signatures = parse_dsse_envelope(envelope)
    pae = compute_pae(CHECKPOINT_PAYLOAD_TYPE, payload_bytes)
    for trusted_key in checkpoint_trust_store.keys:
        if trusted_key.role != "checkpoint-signer":
            continue
        if trusted_key.revoked:
            continue
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
        except ValueError:
            continue
        for sig_entry in signatures:
            try:
                public_key.verify(
                    base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                )
                return checkpoint, ""
            except (InvalidSignature, ValueError):
                continue
    return checkpoint, "SIGNATURE_UNTRUSTED"


# ---------------------------------------------------------------------------
# Log completeness statements (for DISPROVEN, design §7.2 condition 3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogCompleteness:
    """A log operator's signed statement that a log is complete through a seq.

    This is the third DISPROVEN condition: without it, absence of an
    EXECUTION_STARTED event may mean "deleted", not "never executed".
    """

    log_id: str
    through_seq: int
    checkpoint_digest: str
    claimed_time: str
    protocol_version: str = "oev-execution-log/0.1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "log_id": self.log_id,
            "through_seq": self.through_seq,
            "checkpoint_digest": self.checkpoint_digest,
            "claimed_time": self.claimed_time,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogCompleteness:
        return cls(
            log_id=str(data["log_id"]),
            through_seq=int(data["through_seq"]),
            checkpoint_digest=str(data["checkpoint_digest"]),
            claimed_time=str(data["claimed_time"]),
        )


def sign_completeness_dsse(
    statement: LogCompleteness, private_key_pem: bytes, key_id: str = ""
) -> dict[str, Any]:
    """DSSE-sign a log completeness statement. Returns the envelope."""
    payload_bytes = canonicalize_json(statement.to_dict())
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(COMPLETENESS_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
    if key_id:
        sig_entry["keyid"] = key_id
    return build_dsse_envelope(
        payload_type=COMPLETENESS_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_completeness_signature(
    envelope: dict[str, Any], trust_store: TrustStore | None
) -> tuple[LogCompleteness | None, bool]:
    """Verify a completeness statement against caller-supplied operator keys."""
    try:
        payload_type, payload_bytes, signatures = parse_dsse_envelope(envelope)
    except DsseError:
        return None, False
    if payload_type != COMPLETENESS_PAYLOAD_TYPE:
        return None, False
    try:
        data = safe_json_loads(payload_bytes.decode("utf-8"))
    except ValueError:
        return None, False
    if not isinstance(data, dict):
        return None, False
    try:
        statement = LogCompleteness.from_dict(data)
    except (ValueError, KeyError, TypeError):
        return None, False
    if trust_store is None or len(trust_store.keys) == 0:
        return statement, False
    pae = compute_pae(payload_type, payload_bytes)
    for trusted_key in trust_store.keys:
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
        except ValueError:
            continue
        for sig_entry in signatures:
            try:
                public_key.verify(
                    base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                )
                return statement, True
            except (InvalidSignature, ValueError):
                continue
    return statement, False


# ---------------------------------------------------------------------------
# JSONL log file helpers
# ---------------------------------------------------------------------------


def events_from_jsonl(data: bytes) -> list[LogEvent]:
    """Parse a JSONL log file (one event object per line, duplicate-key safe)."""
    text = data.decode("utf-8")
    events: list[LogEvent] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        raw = safe_json_loads(line.encode("utf-8"))
        if not isinstance(raw, dict):
            raise TypeError(f"Log line {line_no} is not a JSON object")
        events.append(validate_log_event_dict(raw))
    if len(events) > MAX_LOG_EVENTS:
        raise ValueError(f"log exceeds {MAX_LOG_EVENTS} events")
    return events


def events_to_jsonl(events: list[LogEvent]) -> bytes:
    """Serialise events to JSONL (canonical JSON per line)."""
    return b"\n".join(canonicalize_json(e.to_dict()) for e in events) + (b"\n" if events else b"")
