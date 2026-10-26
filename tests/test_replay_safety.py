# SPDX-License-Identifier: Apache-2.0

"""Tests for snapshot replay safety (oev.replay, oev-decision-pack/0.2).

Pins the two safety invariants:
- Evidence observed after a snapshot (or not bound to it) never enters the
  replay scope, and a recorded run that consumed post-snapshot evidence makes
  the whole replay refuse.
- Replay refuses when the pack hash changed after the replay pin, including
  self-consistent manifest rewrites that per-pack digest checks cannot catch.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from oev.canonical import canonicalize_json
from oev.decision_pack import build_pack, sign_pack_manifest, verify_pack
from oev.replay import (
    PACK_HASH_CHANGED,
    PACK_INVALID,
    REASON_AFTER_CAPTURE,
    REASON_NOT_BOUND,
    REPLAY_OK,
    SIGNATURE_UNTRUSTED,
    SNAPSHOT_INVALID,
    SNAPSHOT_LEAK,
    parse_iso_utc,
    pin_pack,
    replay_snapshot,
)
from oev.signing import generate_ed25519_keypair
from oev.trust import TrustStore
from tests.test_decision_pack import _build_tmp_pack, _write_source_dir

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples"
EXAMPLE_PACK_DIR = EXAMPLES_DIR / "demo-case-001"
EXAMPLE_KEYS = EXAMPLES_DIR / "demo-case-001.verifier-keys.json"


def _rewrite_member_and_manifest(pack_dir: Path, member_name: str, doc: object) -> None:
    """Rewrite one JSON member canonically and make the manifest self-consistent.

    This simulates the strongest attacker: member bytes change AND the
    manifest is rebuilt coherently (digest, size, pack_digest), so only an
    external pin or signature can catch it. The pack must be unsigned, since a
    stale DSSE envelope would no longer bind the rebuilt manifest.
    """

    body = canonicalize_json(doc)
    (pack_dir / member_name).write_bytes(body)
    manifest_path = pack_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    for member in manifest["members"]:
        if member["path"] == member_name:
            member["size_bytes"] = len(body)
            member["sha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
    unsigned = dict(manifest)
    declared = unsigned.pop("pack_digest")
    assert declared != ""  # sanity: the original manifest carried a digest
    manifest["pack_digest"] = "sha256:" + hashlib.sha256(canonicalize_json(unsigned)).hexdigest()
    manifest_path.write_bytes(canonicalize_json(manifest))


def _mutate_member_doc(pack_dir: Path, member_name: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((pack_dir / member_name).read_bytes())
    return doc


def test_parse_iso_utc_strict_format() -> None:
    assert parse_iso_utc("2026-10-01T08:00:00Z") is not None
    assert parse_iso_utc("2026-10-01T08:00:00+00:00") is None
    assert parse_iso_utc("2026-10-01 08:00:00") is None
    assert parse_iso_utc("not-a-time") is None
    assert parse_iso_utc(None) is None
    assert parse_iso_utc(20261001) is None


def test_example_pack_replays_cleanly_with_pin() -> None:
    pin = pin_pack(EXAMPLE_PACK_DIR)
    assert pin["pack_id"]
    assert pin["pack_digest"].startswith("sha256:")

    result = replay_snapshot(
        EXAMPLE_PACK_DIR,
        expected_pack_digest=pin["pack_digest"],
        trust_store=TrustStore.from_file(EXAMPLE_KEYS),
    )
    assert result.replay_status == REPLAY_OK
    assert result.snapshot_id == "snapshot-2026-10-01-001"
    assert result.captured_at == "2026-10-01T08:00:00Z"
    # Every demo fact is bound to a snapshot source and observed at or before
    # capture (fact-002 is observed exactly at capture time: still in scope).
    assert result.eligible_fact_ids == ["fact-001", "fact-002", "fact-003"]
    assert result.excluded_facts == []
    assert all(r.replayable for r in result.run_assessments)


def test_replay_refuses_when_pack_hash_changed(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    pin = pin_pack(pack_dir)

    # Strongest attack: coherent rewrite (member + manifest + pack_digest all
    # self-consistent). verify_pack alone returns PACK_VALID; the pin refuses.
    doc = _mutate_member_doc(pack_dir, "findings.json")
    doc["findings"][0]["severity"] = "CRITICAL"
    _rewrite_member_and_manifest(pack_dir, "findings.json", doc)

    assert verify_pack(pack_dir).overall == "PACK_VALID"

    result = replay_snapshot(pack_dir, expected_pack_digest=pin["pack_digest"])
    assert result.replay_status == PACK_HASH_CHANGED
    assert result.pack_digest != pin["pack_digest"]
    assert any("changed since the replay pin" in r for r in result.reasons)


def test_replay_refuses_when_pack_technically_invalid(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    pin = pin_pack(pack_dir)
    (pack_dir / "timeline.json").unlink()

    result = replay_snapshot(pack_dir, expected_pack_digest=pin["pack_digest"])
    assert result.replay_status == PACK_INVALID


def _bind_fixture_facts(src: Path) -> None:
    """Bind the base fixture's fact-001 to the snapshot source (in scope)."""

    facts = json.loads((src / "facts.json").read_bytes())
    facts["facts"][0]["snapshot_source_id"] = "source-001"
    (src / "facts.json").write_bytes(canonicalize_json(facts))


def test_post_snapshot_evidence_never_enters_replay_scope(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _write_source_dir(src)
    _bind_fixture_facts(src)
    facts = json.loads((src / "facts.json").read_bytes())
    # fact-001 (pre-snapshot, bound) is kept; add one post-snapshot bound fact
    # and one unbound fact, plus a run consuming the unbound one.
    facts["facts"].append(
        {
            "fact_id": "fact-late",
            "key": "sensor.later_reading",
            "value": "99.9",
            "value_type": "decimal_string",
            "source": "sensor-feed-A",
            "observed_at": "2026-01-02T00:00:00Z",  # after captured_at 2026-01-01T00:00:00Z
            "snapshot_source_id": "source-001",
        }
    )
    facts["facts"].append(
        {
            "fact_id": "fact-unbound",
            "key": "external.gossip",
            "value": True,
            "source": "outside",
            "observed_at": "2025-12-31T00:00:00Z",  # before capture, but unbound
        }
    )
    (src / "facts.json").write_bytes(canonicalize_json(facts))

    runs = json.loads((src / "rule_runs.json").read_bytes())
    runs["rule_runs"].append(
        {
            "run_id": "run-unbound",
            "rule": runs["rule_runs"][0]["rule"],
            "inputs": ["fact-unbound"],
            "outcome": "TRIGGERED",
            "executed_at": "2026-01-01T00:01:00Z",
            "executed_by": "synthetic-rules/0.1",
        }
    )
    (src / "rule_runs.json").write_bytes(canonicalize_json(runs))

    out = tmp_path / "pack"
    build_pack(src, out, pack_id="pack-scope", created_at="2026-01-01T00:10:00Z")

    result = replay_snapshot(out)
    assert result.replay_status == REPLAY_OK  # no leak: no run consumed fact-late
    assert result.eligible_fact_ids == ["fact-001"]
    excluded = {e.fact_id: e.reason for e in result.excluded_facts}
    assert excluded["fact-late"] == REASON_AFTER_CAPTURE
    assert excluded["fact-unbound"] == REASON_NOT_BOUND

    by_run = {r.run_id: r for r in result.run_assessments}
    assert by_run["run-001"].replayable is True
    assert by_run["run-unbound"].replayable is False
    assert any("out of snapshot scope" in reason for reason in by_run["run-unbound"].reasons)


def test_replay_refuses_on_post_snapshot_leak(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _write_source_dir(src)
    facts = json.loads((src / "facts.json").read_bytes())
    facts["facts"].append(
        {
            "fact_id": "fact-late",
            "key": "sensor.later_reading",
            "value": "99.9",
            "value_type": "decimal_string",
            "source": "sensor-feed-A",
            "observed_at": "2026-01-02T00:00:00Z",  # after captured_at
            "snapshot_source_id": "source-001",
        }
    )
    (src / "facts.json").write_bytes(canonicalize_json(facts))

    runs = json.loads((src / "rule_runs.json").read_bytes())
    runs["rule_runs"].append(
        {
            "run_id": "run-leaky",
            "rule": runs["rule_runs"][0]["rule"],
            "inputs": ["fact-001", "fact-late"],  # consumed post-snapshot evidence
            "outcome": "TRIGGERED",
            "executed_at": "2026-01-02T00:01:00Z",
            "executed_by": "synthetic-rules/0.1",
        }
    )
    (src / "rule_runs.json").write_bytes(canonicalize_json(runs))

    out = tmp_path / "pack"
    build_pack(src, out, pack_id="pack-leak", created_at="2026-01-01T00:10:00Z")

    # The pack itself is technically valid — the contradiction only surfaces
    # when the snapshot boundary is enforced.
    assert verify_pack(out).overall == "PACK_VALID"

    result = replay_snapshot(out)
    assert result.replay_status == SNAPSHOT_LEAK
    assert "fact-late" not in result.eligible_fact_ids
    leaky = next(r for r in result.run_assessments if r.run_id == "run-leaky")
    assert leaky.replayable is False
    assert any("observed after the snapshot" in reason for reason in leaky.reasons)
    assert any("contradicts the snapshot" in note for note in result.reasons)


def test_fact_observed_exactly_at_capture_is_eligible(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _write_source_dir(src)
    _bind_fixture_facts(src)
    # fact-001 is observed at 00:00:00Z, exactly the snapshot capture time.
    out = tmp_path / "pack"
    build_pack(src, out, pack_id="pack-boundary", created_at="2026-01-01T00:10:00Z")
    result = replay_snapshot(out)
    assert "fact-001" in result.eligible_fact_ids
    assert result.replay_status == REPLAY_OK


def test_replay_with_trust_roots_requires_trusted_signature(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    private_pem, public_pem = generate_ed25519_keypair()
    sign_pack_manifest(pack_dir, private_pem, key_id="replay-key")
    keys = tmp_path / "keys.json"
    keys.write_bytes(
        canonicalize_json([{"key_id": "replay-key", "public_key_pem": public_pem.decode()}])
    )
    trust = TrustStore.from_file(keys)

    assert replay_snapshot(pack_dir, trust_store=trust).replay_status == REPLAY_OK

    # Stripping the signature must block replay for a caller who pinned roots.
    (pack_dir / "manifest.dsse.json").unlink()
    result = replay_snapshot(pack_dir, trust_store=trust)
    assert result.replay_status == SIGNATURE_UNTRUSTED
    assert any("not signed by a trusted key" in r for r in result.reasons)

    # Without pinned roots an unsigned pack still replays (integrity only).
    assert replay_snapshot(pack_dir).replay_status == REPLAY_OK


def test_replay_refuses_on_unparseable_captured_at(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    doc = _mutate_member_doc(pack_dir, "snapshot_context.json")
    doc["captured_at"] = "2026-01-01T00:00:00+00:00"  # schema-shaped attack after rewrite
    _rewrite_member_and_manifest(pack_dir, "snapshot_context.json", doc)

    result = replay_snapshot(pack_dir)
    assert result.replay_status == SNAPSHOT_INVALID


def test_later_evidence_injected_into_pinned_pack_refuses_replay(tmp_path: Path) -> None:
    """The headline sabotage scenario: pin a pack, inject later evidence, replay."""

    pack_dir = _build_tmp_pack(tmp_path)
    pin = pin_pack(pack_dir)

    # An attacker (or an accident) adds evidence observed after the snapshot
    # and rewrites the run history to consume it, coherently re-signing nothing.
    facts = _mutate_member_doc(pack_dir, "facts.json")
    facts["facts"].append(
        {
            "fact_id": "fact-injected",
            "key": "sensor.injected_reading",
            "value": "120.0",
            "value_type": "decimal_string",
            "source": "sensor-feed-B",
            "observed_at": "2026-06-01T00:00:00Z",
            "snapshot_source_id": "source-001",
        }
    )
    _rewrite_member_and_manifest(pack_dir, "facts.json", facts)

    result = replay_snapshot(pack_dir, expected_pack_digest=pin["pack_digest"])
    assert result.replay_status == PACK_HASH_CHANGED


def test_pin_pack_refuses_invalid_pack(tmp_path: Path) -> None:
    pack_dir = _build_tmp_pack(tmp_path)
    (pack_dir / "facts.json").write_bytes(b"not json")
    with pytest.raises(ValueError, match="fails technical verification"):
        pin_pack(pack_dir)


def test_replay_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Pack directory not found"):
        replay_snapshot(tmp_path / "does-not-exist")


def test_replay_rejects_malformed_pin_digest(tmp_path: Path) -> None:
    import pytest

    pack_dir = _build_tmp_pack(tmp_path)
    with pytest.raises(ValueError, match="sha256"):
        replay_snapshot(pack_dir, expected_pack_digest="deadbeef")


def test_replay_works_on_copied_pack_directory(tmp_path: Path) -> None:
    """Replay must depend only on the pack contents, not on repo location."""

    clean = tmp_path / "clean-room"
    clean.mkdir()
    shutil.copytree(EXAMPLE_PACK_DIR, clean / "pack")
    shutil.copy2(EXAMPLE_KEYS, clean / "verifier-keys.json")

    pin = pin_pack(clean / "pack")
    result = replay_snapshot(
        clean / "pack",
        expected_pack_digest=pin["pack_digest"],
        trust_store=TrustStore.from_file(clean / "verifier-keys.json"),
    )
    assert result.replay_status == REPLAY_OK
