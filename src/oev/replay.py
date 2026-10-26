# SPDX-License-Identifier: Apache-2.0

"""Snapshot replay safety gate for decision evidence packs (oev-decision-pack/0.2).

Replay safety contract:
- Pin first: replay refuses to start against a pack whose recomputed pack digest
  differs from the caller-pinned digest, so a pack that changed after the pin
  (even a fully self-consistent rebuild of the manifest) can never be replayed
  under that pin.
- Snapshot isolation: the only facts eligible for a replay of a snapshot are
  facts bound to a source of that snapshot AND observed at or before the
  snapshot capture time. Evidence observed after the capture time — or not
  bound to the snapshot at all — is excluded from the replay scope and can
  never appear in the eligible fact set.
- Leak refusal: if a recorded rule run consumed evidence observed after the
  snapshot was captured, the recorded history contradicts the snapshot and the
  replay refuses (SNAPSHOT_LEAK) instead of silently re-scoping.

Integrity boundary: this module is a safety gate over recorded evidence. It
does not re-execute rules and does not assert factual truth, commercial truth,
legal validity, compliance approval, or fraud detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from oev.canonical import safe_json_loads
from oev.decision_models import (
    CORE_MEMBER_ROLES,
    MANIFEST_MEMBER_PATH,
)
from oev.decision_pack import verify_pack
from oev.trust import TrustStore

ISO_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

REPLAY_OK = "REPLAY_OK"
PACK_INVALID = "PACK_INVALID"
PACK_HASH_CHANGED = "PACK_HASH_CHANGED"
SIGNATURE_UNTRUSTED = "SIGNATURE_UNTRUSTED"
SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
SNAPSHOT_LEAK = "SNAPSHOT_LEAK"

REASON_NOT_BOUND = "not_bound_to_snapshot"
REASON_UNKNOWN_SOURCE = "unknown_snapshot_source"
REASON_AFTER_CAPTURE = "observed_after_snapshot"
REASON_UNPARSEABLE_TIME = "observed_at_unparseable"


class ReplayError(ValueError):
    """Raised when a replay request cannot be evaluated at all (bad input)."""


def parse_iso_utc(value: Any) -> datetime | None:
    """Parse a strict 'YYYY-MM-DDTHH:MM:SSZ' timestamp; return None if malformed."""
    if not isinstance(value, str):
        return None
    try:
        # strptime with an explicit literal format; the trailing Z pins UTC,
        # and the tzinfo makes that explicit to callers and checkers alike.
        return datetime.strptime(value, ISO_UTC_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass(frozen=True)
class ExcludedFact:
    """A fact kept out of the replay scope, with the reason it was excluded."""

    fact_id: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"fact_id": self.fact_id, "reason": self.reason}


@dataclass(frozen=True)
class ReplayRunAssessment:
    """Whether one recorded rule run may be replayed against the snapshot."""

    run_id: str
    replayable: bool
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "replayable": self.replayable,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class SnapshotReplayResult:
    """Outcome of a snapshot replay safety evaluation.

    replay_status is exactly one of:
    - REPLAY_OK: pack intact, pinned digest matched, snapshot coherent, and no
      recorded run consumed out-of-scope evidence. Per-run assessments may
      still mark individual runs not replayable for non-leak reasons.
    - PACK_INVALID: pack technical verification failed.
    - PACK_HASH_CHANGED: the recomputed pack digest differs from the pin.
    - SIGNATURE_UNTRUSTED: trust roots were supplied and the manifest is not
      signed by a trusted key (this covers a stripped or replaced signature).
    - SNAPSHOT_INVALID: the snapshot boundary could not be established.
    - SNAPSHOT_LEAK: a recorded run consumed evidence observed after the
      snapshot capture time.
    """

    pack_path: str
    replay_status: str
    pack_digest: str
    expected_pack_digest: str
    snapshot_id: str = ""
    captured_at: str = ""
    eligible_fact_ids: list[str] = field(default_factory=list)
    excluded_facts: list[ExcludedFact] = field(default_factory=list)
    run_assessments: list[ReplayRunAssessment] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_path": self.pack_path,
            "replay_status": self.replay_status,
            "pack_digest": self.pack_digest,
            "expected_pack_digest": self.expected_pack_digest,
            "snapshot_id": self.snapshot_id,
            "captured_at": self.captured_at,
            "eligible_fact_ids": list(self.eligible_fact_ids),
            "excluded_facts": [f.to_dict() for f in self.excluded_facts],
            "run_assessments": [r.to_dict() for r in self.run_assessments],
            "reasons": list(self.reasons),
        }

    def format_human(self) -> str:
        lines = [
            "=" * 70,
            "OEVP SNAPSHOT REPLAY SAFETY REPORT",
            "=" * 70,
            f"Pack Path:        {self.pack_path}",
            f"Replay Status:    {self.replay_status}",
            f"Pack Digest:      {self.pack_digest}",
        ]
        if self.expected_pack_digest:
            lines.append(f"Pinned Digest:    {self.expected_pack_digest}")
        if self.snapshot_id:
            lines.extend(
                [
                    f"Snapshot ID:      {self.snapshot_id}",
                    f"Captured At:      {self.captured_at}",
                    f"Eligible Facts:   {len(self.eligible_fact_ids)}",
                    f"Excluded Facts:   {len(self.excluded_facts)}",
                ]
            )
            for f in self.excluded_facts:
                lines.append(f"  * {f.fact_id}: {f.reason}")
        if self.run_assessments:
            lines.append("-" * 70)
            lines.append(f"Rule Runs ({len(self.run_assessments)}):")
            for r in self.run_assessments:
                status = "REPLAYABLE" if r.replayable else "NOT REPLAYABLE"
                lines.append(f"  [{status:<14}] {r.run_id}")
                for reason in r.reasons:
                    lines.append(f"      * {reason}")
        if self.reasons:
            lines.extend(["-" * 70, "Notes:"])
            for reason in self.reasons:
                lines.append(f"  * {reason}")
        lines.extend(
            [
                "=" * 70,
                "NOTICE:",
                "Replay safety evaluation only — scope pinning and evidence isolation.",
                "It does not re-execute rules and is not a legal, compliance, factual,",
                "or commercial conclusion.",
                "=" * 70,
            ]
        )
        return "\n".join(lines)


def _load_member(pack_dir: Path, role: str) -> dict[str, Any] | None:
    """Load one core member from a verified pack; None if unreadable."""
    path = pack_dir / CORE_MEMBER_ROLES[role]
    try:
        data = safe_json_loads(path.read_bytes())
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _refused(
    pack_dir: Path,
    status: str,
    pack_digest: str,
    expected_pack_digest: str,
    reasons: list[str],
) -> SnapshotReplayResult:
    return SnapshotReplayResult(
        pack_path=str(pack_dir),
        replay_status=status,
        pack_digest=pack_digest,
        expected_pack_digest=expected_pack_digest,
        reasons=reasons,
    )


def replay_snapshot(
    pack_dir: str | Path,
    expected_pack_digest: str | None = None,
    trust_store: TrustStore | None = None,
) -> SnapshotReplayResult:
    """Evaluate whether the snapshot of a pack may be safely replayed.

    The pack must first pass full technical verification. If
    ``expected_pack_digest`` is supplied it pins the pack: the recomputed pack
    digest must equal the pin or replay refuses (PACK_HASH_CHANGED) — this
    catches self-consistent manifest rewrites that digest checks alone cannot.
    If ``trust_store`` is supplied, the manifest must carry a signature from a
    trusted key (SIGNATURE_UNTRUSTED otherwise), so a stripped or replaced
    signature blocks replay for callers who pin trust roots.
    """

    pack_dir = Path(pack_dir)
    if not pack_dir.is_dir():
        raise ReplayError(f"Pack directory not found: {pack_dir}")
    if expected_pack_digest is not None and not expected_pack_digest.startswith("sha256:"):
        raise ReplayError("expected_pack_digest must use the 'sha256:<64 hex>' form")

    verification = verify_pack(pack_dir, trust_store=trust_store)
    declared_digest = verification.declared_pack_digest

    if verification.overall != "PACK_VALID":
        return _refused(
            pack_dir,
            PACK_INVALID,
            declared_digest,
            expected_pack_digest or "",
            ["Pack technical verification failed: " + "; ".join(verification.reasons)]
            if verification.reasons
            else ["Pack technical verification failed"],
        )

    if expected_pack_digest is not None and declared_digest != expected_pack_digest:
        return _refused(
            pack_dir,
            PACK_HASH_CHANGED,
            declared_digest,
            expected_pack_digest,
            [
                (
                    f"Pack hash changed since the replay pin: pinned {expected_pack_digest}, "
                    f"found {declared_digest}"
                )
            ],
        )

    if trust_store is not None and not verification.is_trusted_signer:
        return _refused(
            pack_dir,
            SIGNATURE_UNTRUSTED,
            declared_digest,
            expected_pack_digest or "",
            [
                (
                    "Trust roots were supplied but the manifest is not signed by a trusted key: "
                    + (verification.signer_note or "no trusted signature present")
                )
            ],
        )

    snapshot_doc = _load_member(pack_dir, "snapshot_context")
    facts_doc = _load_member(pack_dir, "facts")
    runs_doc = _load_member(pack_dir, "rule_runs")
    if snapshot_doc is None or facts_doc is None or runs_doc is None:
        return _refused(
            pack_dir,
            PACK_INVALID,
            declared_digest,
            expected_pack_digest or "",
            ["Core member could not be re-read after verification"],
        )

    captured_at_raw = snapshot_doc.get("captured_at")
    captured_at = parse_iso_utc(captured_at_raw)
    if captured_at is None:
        return _refused(
            pack_dir,
            SNAPSHOT_INVALID,
            declared_digest,
            expected_pack_digest or "",
            [f"Snapshot captured_at is not a strict UTC timestamp: {captured_at_raw!r}"],
        )

    snapshot_sources = {
        str(s.get("source_id")) for s in snapshot_doc.get("sources", []) if isinstance(s, dict)
    }

    eligible: list[str] = []
    excluded: list[ExcludedFact] = []
    fact_times: dict[str, datetime | None] = {}
    for fact in facts_doc.get("facts", []):
        fact_id = str(fact.get("fact_id"))
        source_id = fact.get("snapshot_source_id")
        if source_id is None:
            excluded.append(ExcludedFact(fact_id, REASON_NOT_BOUND))
            fact_times[fact_id] = None
            continue
        if str(source_id) not in snapshot_sources:
            excluded.append(ExcludedFact(fact_id, REASON_UNKNOWN_SOURCE))
            fact_times[fact_id] = None
            continue
        observed_at = parse_iso_utc(fact.get("observed_at"))
        if observed_at is None:
            excluded.append(ExcludedFact(fact_id, REASON_UNPARSEABLE_TIME))
            fact_times[fact_id] = None
        elif observed_at > captured_at:
            excluded.append(ExcludedFact(fact_id, REASON_AFTER_CAPTURE))
            fact_times[fact_id] = observed_at
        else:
            eligible.append(fact_id)
            fact_times[fact_id] = observed_at

    eligible_set = set(eligible)
    run_assessments: list[ReplayRunAssessment] = []
    leak = False
    leak_notes: list[str] = []
    for run in runs_doc.get("rule_runs", []):
        run_id = str(run.get("run_id"))
        run_reasons: list[str] = []
        run_leak = False
        for fact_id in run.get("inputs", []):
            fid = str(fact_id)
            if fid in eligible_set:
                continue
            exclusion = next((e for e in excluded if e.fact_id == fid), None)
            if exclusion is not None and exclusion.reason == REASON_AFTER_CAPTURE:
                run_leak = True
                run_reasons.append(
                    f"input fact '{fid}' was observed after the snapshot was captured"
                )
            elif exclusion is not None:
                run_reasons.append(
                    f"input fact '{fid}' is out of snapshot scope: {exclusion.reason}"
                )
            else:
                run_reasons.append(f"input fact '{fid}' does not exist")
        if run_leak:
            leak = True
            leak_notes.append(
                f"rule run '{run_id}' consumed post-snapshot evidence; the recorded "
                "history contradicts the snapshot boundary"
            )
        run_assessments.append(ReplayRunAssessment(run_id, not run_reasons, run_reasons))

    if leak:
        return SnapshotReplayResult(
            pack_path=str(pack_dir),
            replay_status=SNAPSHOT_LEAK,
            pack_digest=declared_digest,
            expected_pack_digest=expected_pack_digest or "",
            snapshot_id=str(snapshot_doc.get("snapshot_id", "")),
            captured_at=str(captured_at_raw),
            eligible_fact_ids=eligible,
            excluded_facts=excluded,
            run_assessments=run_assessments,
            reasons=leak_notes,
        )

    return SnapshotReplayResult(
        pack_path=str(pack_dir),
        replay_status=REPLAY_OK,
        pack_digest=declared_digest,
        expected_pack_digest=expected_pack_digest or "",
        snapshot_id=str(snapshot_doc.get("snapshot_id", "")),
        captured_at=str(captured_at_raw),
        eligible_fact_ids=eligible,
        excluded_facts=excluded,
        run_assessments=run_assessments,
    )


def pin_pack(pack_dir: str | Path) -> dict[str, str]:
    """Verify a pack and return the out-of-band replay pin record for it.

    The pin records the pack identity and digest so a later replay can refuse
    if the pack changed in between. It is deliberately minimal and contains no
    timestamps: the caller records when and where the pin was made.
    """

    pack_dir = Path(pack_dir)
    verification = verify_pack(pack_dir)
    if verification.overall != "PACK_VALID":
        raise ReplayError(
            "Refusing to pin a pack that fails technical verification: "
            + ("; ".join(verification.reasons) if verification.reasons else verification.overall)
        )
    manifest_path = pack_dir / MANIFEST_MEMBER_PATH
    manifest = safe_json_loads(manifest_path.read_bytes())
    if not isinstance(manifest, dict):
        raise ReplayError("Manifest is not a JSON object")
    return {
        "protocol_version": "oev-decision-pack/0.2",
        "pack_id": str(manifest.get("pack_id", "")),
        "case_id": str(manifest.get("case_id", "")),
        "pack_digest": verification.declared_pack_digest,
    }
