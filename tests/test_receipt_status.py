# SPDX-License-Identifier: Apache-2.0

"""Tests for signed receipt status / supersession checkpoints (V3-C13).

Covers: fresh CURRENT acceptance, stale detection, superseded detection
(snapshot + supersession link + chain), snapshot-age expiry
(STALE_SNAPSHOT), unsigned / wrong-signer snapshot rejection, the
fail-closed default policy (no status evidence -> REJECT), and the
two-dimensional outcome (MATCH + STALE / MATCH + SUPERSEDED reported
separately, never collapsed into one score).

Also executes the hea-21 / hea-22 conformance vectors in
``conformance/vectors-hea/`` (receipt-status vectors; they are NOT run
by ``conformance/run_hea_vectors.py``, which only dispatches HEA
scenarios — see ``receipt-status-vectors-README.md`` there).
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from oev.receipt_status import (
    DEFAULT_MAX_AGE_SECONDS,
    FreshnessAssessment,
    FreshnessPolicy,
    ReceiptStatusSnapshot,
    StatusEntry,
    assess_receipt_freshness,
    build_status_snapshot,
    combine_with_reverification,
    is_superseded_by_link,
    verify_status_snapshot,
)
from oev.schemas import validate_document
from oev.trust import TrustStore
from tests.hea_helpers import make_keypair

NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
SNAP_TIME = "2026-11-13T11:00:00Z"
OLD_SNAP_TIME = "2026-08-01T11:00:00Z"  # 104 days before NOW: past 90-day default
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def _status_authority(key_id: str = "status-1") -> tuple[bytes, dict]:
    priv, _pub, entry = make_keypair(role=None)
    entry["key_id"] = key_id
    return priv, entry


def _snapshot(
    entries: list[StatusEntry],
    priv: bytes,
    key_id: str = "status-1",
    snap_time: str = SNAP_TIME,
) -> dict:
    return build_status_snapshot(entries, key_id, snap_time, priv)


def _store(entry: dict) -> TrustStore:
    return TrustStore.from_list([entry])


# ---------------------------------------------------------------------------
# Build / verify roundtrip
# ---------------------------------------------------------------------------


def test_build_and_verify_roundtrip() -> None:
    priv, entry = _status_authority()
    env = _snapshot(
        [StatusEntry(receipt_digest=DIGEST_A, status="CURRENT", receipt_id="r-a")],
        priv,
    )
    snapshot, note = verify_status_snapshot(env, _store(entry))
    assert snapshot is not None
    assert snapshot.issuer_key_id == "status-1"
    assert snapshot.snapshot_time_claimed == SNAP_TIME
    assert snapshot.entry_for(DIGEST_A) is not None
    assert snapshot.entry_for(DIGEST_A).status == "CURRENT"
    assert snapshot.entry_for(DIGEST_B) is None
    assert "1 entries" in note


def test_snapshot_schema_validated() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="STALE")], priv)
    payload = json.loads(base64.b64decode(env["payload"].encode()))
    validate_document(payload, "receipt-status-0.1.schema.json")
    snapshot, _ = verify_status_snapshot(env, _store(entry))
    assert snapshot is not None


def test_duplicate_digest_entries_rejected() -> None:
    with pytest.raises(ValueError, match="Duplicate receipt_digest"):
        ReceiptStatusSnapshot.from_dict(
            {
                "protocol_version": "oev-receipt-status/0.1",
                "issuer_key_id": "status-1",
                "snapshot_time_claimed": SNAP_TIME,
                "entries": [
                    {"receipt_digest": DIGEST_A, "status": "CURRENT"},
                    {"receipt_digest": DIGEST_A, "status": "STALE"},
                ],
            }
        )


def test_entry_limit_and_bad_status_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown receipt status"):
        StatusEntry.from_dict({"receipt_digest": DIGEST_A, "status": "FRESH"})
    with pytest.raises(ValueError, match="Invalid receipt digest"):
        StatusEntry.from_dict({"receipt_digest": "not-a-digest", "status": "CURRENT"})


def test_unsupported_protocol_version_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported receipt-status protocol version"):
        ReceiptStatusSnapshot.from_dict(
            {
                "protocol_version": "oev-receipt-status/9.9",
                "issuer_key_id": "status-1",
                "snapshot_time_claimed": SNAP_TIME,
                "entries": [],
            }
        )


# ---------------------------------------------------------------------------
# Fresh CURRENT acceptance
# ---------------------------------------------------------------------------


def test_fresh_current_accepted_under_default_policy() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "CURRENT"
    assert a.decision == "ACCEPT"
    assert a.snapshot_age_seconds == 3600
    assert a.snapshot_time_claimed == SNAP_TIME
    assert a.status_evidence == "signed-snapshot"


def test_default_policy_is_fail_closed() -> None:
    pol = FreshnessPolicy()
    assert pol.require_current is True
    assert pol.max_age_seconds == DEFAULT_MAX_AGE_SECONDS == 90 * 24 * 3600
    assert pol.allow_stale_with_warning is False
    assert pol.allow_superseded is False


# ---------------------------------------------------------------------------
# Stale / superseded / revoked detection
# ---------------------------------------------------------------------------


def test_stale_entry_rejected_under_default_policy() -> None:
    priv, entry = _status_authority()
    env = _snapshot(
        [StatusEntry(receipt_digest=DIGEST_A, status="STALE", reason="re-issued")], priv
    )
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "STALE"
    assert a.decision == "REJECT"


def test_stale_accepted_with_warning_only_when_policy_allows() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="STALE")], priv)
    relaxed = FreshnessPolicy(require_current=False, allow_stale_with_warning=True)
    a = assess_receipt_freshness(
        DIGEST_A,
        snapshot_envelope=env,
        status_trust_store=_store(entry),
        policy=relaxed,
        now=NOW,
    )
    assert a.freshness == "STALE"
    assert a.decision == "ACCEPT_WITH_WARNING"
    # Same policy WITHOUT the stale allowance still rejects.
    strictish = FreshnessPolicy(require_current=False, allow_stale_with_warning=False)
    b = assess_receipt_freshness(
        DIGEST_A,
        snapshot_envelope=env,
        status_trust_store=_store(entry),
        policy=strictish,
        now=NOW,
    )
    assert b.decision == "REJECT"


def test_superseded_entry_rejected_and_chain_resolved() -> None:
    priv, entry = _status_authority()
    env = _snapshot(
        [
            StatusEntry(receipt_digest=DIGEST_A, status="SUPERSEDED", receipt_id="r-a"),
            StatusEntry(
                receipt_digest=DIGEST_B,
                status="CURRENT",
                receipt_id="r-b",
                supersedes={"receipt_id": "r-a", "receipt_digest": DIGEST_A},
            ),
        ],
        priv,
    )
    snapshot, _ = verify_status_snapshot(env, _store(entry))
    assert snapshot is not None
    assert snapshot.supersession_chain(DIGEST_A) == [DIGEST_A, DIGEST_B]
    assert snapshot.successor_of(DIGEST_A).receipt_digest == DIGEST_B
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "SUPERSEDED"
    assert a.decision == "REJECT"
    # The successor itself is CURRENT.
    b = assess_receipt_freshness(
        DIGEST_B, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert b.freshness == "CURRENT"
    assert b.decision == "ACCEPT"


def test_superseded_by_receipt_link_without_snapshot() -> None:
    # A newer receipt R-B carries superseded_receipt naming R-A: that is
    # positive evidence R-A is superseded even with no snapshot.
    newer = {
        "receipt_id": "r-b",
        "receipt_digest": DIGEST_B,
        "superseded_receipt": {"receipt_id": "r-a", "receipt_digest": DIGEST_A},
    }
    assert is_superseded_by_link(DIGEST_A, newer) is True
    assert is_superseded_by_link(DIGEST_B, newer) is False
    a = assess_receipt_freshness(DIGEST_A, newer_receipt=newer, now=NOW)
    assert a.freshness == "SUPERSEDED"
    assert a.decision == "REJECT"
    assert a.status_evidence == "supersession-link"


def test_link_vs_current_snapshot_resolved_fail_closed() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    newer = {"superseded_receipt": {"receipt_id": "r-a", "receipt_digest": DIGEST_A}}
    a = assess_receipt_freshness(
        DIGEST_A,
        snapshot_envelope=env,
        status_trust_store=_store(entry),
        newer_receipt=newer,
        now=NOW,
    )
    assert a.freshness == "SUPERSEDED"
    assert a.decision == "REJECT"


def test_revoked_entry_always_rejected() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="REVOKED")], priv)
    permissive = FreshnessPolicy(
        require_current=False, allow_stale_with_warning=True, allow_superseded=True
    )
    a = assess_receipt_freshness(
        DIGEST_A,
        snapshot_envelope=env,
        status_trust_store=_store(entry),
        policy=permissive,
        now=NOW,
    )
    assert a.freshness == "REVOKED"
    assert a.decision == "REJECT"


# ---------------------------------------------------------------------------
# Snapshot age: STALE_SNAPSHOT / UNKNOWN_FRESHNESS
# ---------------------------------------------------------------------------


def test_snapshot_age_expiry_yields_stale_snapshot_not_current() -> None:
    priv, entry = _status_authority()
    env = _snapshot(
        [StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")],
        priv,
        snap_time=OLD_SNAP_TIME,
    )
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "STALE_SNAPSHOT"
    assert a.decision == "REJECT"  # default require_current policy
    assert a.snapshot_age_seconds is not None and a.snapshot_age_seconds > 90 * 24 * 3600
    # A snapshot exactly at the boundary is still CURRENT.
    boundary_now = datetime(2026, 11, 13, 11, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=DEFAULT_MAX_AGE_SECONDS
    )
    env2 = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    b = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env2, status_trust_store=_store(entry), now=boundary_now
    )
    assert b.freshness == "CURRENT"
    assert b.decision == "ACCEPT"


def test_no_snapshot_is_unknown_freshness_and_fail_closed() -> None:
    a = assess_receipt_freshness(DIGEST_A, now=NOW)
    assert a.freshness == "UNKNOWN_FRESHNESS"
    assert a.decision == "REJECT"
    assert a.status_evidence == "none"
    assert a.snapshot_age_seconds is None
    # Only an explicit opt-out policy accepts unknown freshness.
    relaxed = FreshnessPolicy(require_current=False)
    b = assess_receipt_freshness(DIGEST_A, policy=relaxed, now=NOW)
    assert b.freshness == "UNKNOWN_FRESHNESS"
    assert b.decision == "ACCEPT_WITH_WARNING"


def test_snapshot_without_entry_is_unknown_not_current() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_B, status="CURRENT")], priv)
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "UNKNOWN_FRESHNESS"
    assert a.decision == "REJECT"


def test_future_snapshot_time_is_unknown_not_current() -> None:
    priv, entry = _status_authority()
    env = _snapshot(
        [StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")],
        priv,
        snap_time="2026-11-14T11:00:00Z",  # after NOW: claimed time untrusted
    )
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "UNKNOWN_FRESHNESS"
    assert a.decision == "REJECT"


# ---------------------------------------------------------------------------
# Unsigned / wrong-signer snapshots are rejected (not honoured)
# ---------------------------------------------------------------------------


def test_unsigned_snapshot_rejected() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    # Strip the signature: envelope with an empty signature is malformed.
    env_unsigned = dict(env)
    env_unsigned["signatures"] = []
    snapshot, _note = verify_status_snapshot(env_unsigned, _store(entry))
    assert snapshot is None
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env_unsigned, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "UNKNOWN_FRESHNESS"
    assert a.decision == "REJECT"


def test_wrong_signer_snapshot_not_honoured() -> None:
    _, entry = _status_authority()
    other_priv, _other_pub, other_entry = make_keypair(role=None)
    other_entry["key_id"] = "status-2"
    # Snapshot signed by status-2, trust store holds only status-1.
    env = _snapshot(
        [StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")],
        other_priv,
        key_id="status-2",
    )
    snapshot, note = verify_status_snapshot(env, _store(entry))
    assert snapshot is None
    assert "not trusted" in note
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert a.freshness == "UNKNOWN_FRESHNESS"
    assert a.decision == "REJECT"
    # With the right trust root it verifies.
    snapshot2, _ = verify_status_snapshot(env, _store(other_entry))
    assert snapshot2 is not None


def test_tampered_snapshot_entry_after_signing_fails() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    raw = bytearray(base64.b64decode(env["payload"].encode()))
    raw[-5] = ord("Z") if raw[-5] != ord("Z") else ord("Y")
    env["payload"] = base64.b64encode(bytes(raw)).decode()
    snapshot, _ = verify_status_snapshot(env, _store(entry))
    assert snapshot is None


def test_no_trust_store_is_unknown_not_current() -> None:
    priv, _entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    snapshot, note = verify_status_snapshot(env, None)
    assert snapshot is None
    assert "unknown" in note
    a = assess_receipt_freshness(DIGEST_A, snapshot_envelope=env, status_trust_store=None, now=NOW)
    assert a.freshness == "UNKNOWN_FRESHNESS"
    assert a.decision == "REJECT"


def test_same_key_as_receipt_signer_is_noted() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    a = assess_receipt_freshness(
        DIGEST_A,
        snapshot_envelope=env,
        status_trust_store=_store(entry),
        receipt_signer_key_id="status-1",
        now=NOW,
    )
    assert a.freshness == "CURRENT"
    assert any("same key" in n for n in a.notes)


# ---------------------------------------------------------------------------
# Two-dimensional outcome: reproducibility x freshness
# ---------------------------------------------------------------------------


def test_match_plus_stale_is_two_dimensional() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="STALE")], priv)
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    combined = combine_with_reverification("MATCH", a)
    assert combined["reverification_result"] == "MATCH"
    assert combined["freshness"] == "STALE"
    assert combined["freshness_decision"] == "REJECT"
    assert combined["overall_decision"] == "REJECT"
    # A mismatch still dominates even with a CURRENT snapshot.
    fresh_env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    fresh = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=fresh_env, status_trust_store=_store(entry), now=NOW
    )
    combined2 = combine_with_reverification("MISMATCH", fresh)
    assert combined2["reverification_result"] == "MISMATCH"
    assert combined2["freshness"] == "CURRENT"
    assert combined2["overall_decision"] == "REJECT"


def test_match_plus_superseded_is_two_dimensional() -> None:
    priv, entry = _status_authority()
    env = _snapshot(
        [
            StatusEntry(receipt_digest=DIGEST_A, status="SUPERSEDED"),
            StatusEntry(
                receipt_digest=DIGEST_B,
                status="CURRENT",
                supersedes={"receipt_id": "r-a", "receipt_digest": DIGEST_A},
            ),
        ],
        priv,
    )
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    combined = combine_with_reverification("MATCH", a)
    assert (combined["reverification_result"], combined["freshness"]) == ("MATCH", "SUPERSEDED")
    assert combined["overall_decision"] == "REJECT"


def test_match_plus_current_accepts() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    assert combine_with_reverification("MATCH", a)["overall_decision"] == "ACCEPT"


def test_combine_rejects_unknown_reverification_result() -> None:
    a = FreshnessAssessment(
        receipt_digest=DIGEST_A,
        freshness="CURRENT",
        decision="ACCEPT",
        policy=FreshnessPolicy().to_dict(),
    )
    with pytest.raises(ValueError, match="Unknown reverification_result"):
        combine_with_reverification("BOGUS", a)


def test_assessment_serializes() -> None:
    priv, entry = _status_authority()
    env = _snapshot([StatusEntry(receipt_digest=DIGEST_A, status="CURRENT")], priv)
    a = assess_receipt_freshness(
        DIGEST_A, snapshot_envelope=env, status_trust_store=_store(entry), now=NOW
    )
    d = a.to_dict()
    assert d["freshness"] == "CURRENT"
    assert d["snapshot_age_seconds"] == 3600
    assert json.dumps(d)  # JSON-serializable


# ---------------------------------------------------------------------------
# Conformance vectors hea-21 / hea-22 (receipt-status vectors)
# ---------------------------------------------------------------------------

VECTORS_DIR = Path(__file__).resolve().parents[1] / "conformance" / "vectors-hea"


def _run_vector(vector_dir: Path) -> None:
    data = json.loads((vector_dir / "input.json").read_text(encoding="utf-8"))
    expected = json.loads((vector_dir / "expected.json").read_text(encoding="utf-8"))
    # Fresh keys per run; the vector carries only digests/statuses, no secrets.
    priv, _pub, entry = make_keypair(role=None)
    entry["key_id"] = data["snapshot"]["issuer_key_id"]
    entries = [StatusEntry.from_dict(e) for e in data["snapshot"]["entries"]]
    env = build_status_snapshot(
        entries,
        data["snapshot"]["issuer_key_id"],
        data["snapshot"]["snapshot_time_claimed"],
        priv,
    )
    pol = FreshnessPolicy(**data["policy"])
    now = datetime.fromisoformat(data["now"].replace("Z", "+00:00"))
    a = assess_receipt_freshness(
        data["receipt_digest"],
        snapshot_envelope=env,
        status_trust_store=TrustStore.from_list([entry]),
        policy=pol,
        now=now,
    )
    combined = combine_with_reverification(data["reverification_result"], a)
    for key, value in expected["asserts"].items():
        assert combined[key] == value, f"{vector_dir.name}: {key}={combined[key]!r} != {value!r}"


def test_vector_hea21_stale_receipt() -> None:
    _run_vector(VECTORS_DIR / "hea-21-stale-receipt")


def test_vector_hea22_superseded_receipt() -> None:
    _run_vector(VECTORS_DIR / "hea-22-superseded-receipt")
