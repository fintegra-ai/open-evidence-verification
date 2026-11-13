# SPDX-License-Identifier: Apache-2.0

"""Signed receipt status / supersession checkpoints (oev-receipt-status/0.1).

V3-C13 (stale / superseded receipt) was measured in Tur 3 as detection
0.000: a stale or superseded receipt re-verifies as ``MATCH`` because
re-verification only checks reproducibility (does the receipt reproduce
from the package?), never currency (is this receipt still the current
one for this package?). This module adds currency as a *separate*
dimension, deliberately NOT merged into the reproducibility verdict:

- ``reverify_package`` still answers MATCH / MISMATCH / CANNOT_REPRODUCE.
- ``assess_receipt_freshness`` answers CURRENT / STALE / SUPERSEDED /
  REVOKED / UNKNOWN_FRESHNESS / STALE_SNAPSHOT.
- ``combine_with_reverification`` reports both dimensions side by side
  plus one relying-party decision. A technically reproducible receipt
  can therefore be ``MATCH + STALE`` or ``MATCH + SUPERSEDED`` — the
  two-dimensional outcome the taxonomy requires.

Design (follows the revocation-list pattern in ``oev.revocation``):

- A *status snapshot* is a DSSE-signed JSON document issued by a status
  signer. It lists, per receipt digest, a status (CURRENT / STALE /
  SUPERSEDED / REVOKED), the snapshot's claimed time, and — for a
  superseding receipt — a ``supersedes`` link to the receipt it replaces.
  The status-signer key is caller-supplied through a ``TrustStore`` and
  SHOULD be a different key from the receipt signer (the protocol does
  not force this; ``assess_receipt_freshness`` records it in its notes
  when the same key id signed both, so a relying party can see it).
- Freshness is a *relying-party policy*, not a protocol property: the
  caller defines ``FreshnessPolicy`` (``max_age_seconds``,
  ``require_current``, ``allow_stale_with_warning``,
  ``allow_superseded``). The protocol never imposes an age limit of its
  own. The DEFAULT policy is fail-closed (``require_current=True``):
  without current, trustworthy status evidence the receipt is REJECTED
  for security-policy uses, even though it re-verifies as MATCH.
- Snapshots are verifiable offline: the DSSE signature is checked
  against caller-supplied trust roots, no network is involved, and the
  snapshot carries its own claimed time so its age is always visible in
  the assessment.

Hard limits (honest, not fixable in this module):

- ``snapshot_time_claimed`` is a *claimed* time, exactly like every
  other claimed time in OEVP (V3-C17 backdating is still open). A
  backdated snapshot can fake freshness. The assessment therefore
  reports the snapshot time and its age against the *caller's* clock
  (``now`` parameter; the caller owns the clock), and a snapshot whose
  claimed time lies in the future of the caller clock is treated as
  UNKNOWN_FRESHNESS, never as CURRENT.
- An old snapshot cannot prove the current state: if the snapshot is
  older than the policy ``max_age_seconds``, a CURRENT entry yields
  STALE_SNAPSHOT, not CURRENT. Absence of a newer snapshot is not
  evidence that nothing changed.
- A supersession link inside a receipt (``superseded_receipt``: the
  newer receipt names the receipt it supersedes) is corroborating
  evidence only. It can mark a receipt SUPERSEDED when no snapshot
  entry exists, and it is resolved fail-closed against a snapshot
  entry (the more restrictive of the two wins), but it is never
  treated as an integrity statement about the superseded receipt
  (see ``oevp/spec/receipt-spec.md`` §2).
- A status signer that is compromised before its key is removed from
  the caller's trust store can sign false CURRENT snapshots. Status
  snapshots are only as trustworthy as the status-signer trust roots
  the caller supplies — the same trust-root assumption as receipts.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize_json, safe_json_loads
from .dsse import (
    DsseError,
    build_dsse_envelope,
    compute_pae,
    parse_dsse_envelope,
)
from .schemas import validate_document
from .signing import load_ed25519_private_key, load_ed25519_public_key
from .trust import TrustStore, parse_hea_timestamp

RECEIPT_STATUS_PROTOCOL_VERSION = "oev-receipt-status/0.1"
RECEIPT_STATUS_PAYLOAD_TYPE = "application/vnd.oev.receipt-status+json"
RECEIPT_STATUS_SCHEMA_NAME = "receipt-status-0.1.schema.json"

MAX_STATUS_ENTRIES: int = 1024

#: Default maximum snapshot age: 90 days. A CURRENT entry in a snapshot
#: older than this is STALE_SNAPSHOT, not CURRENT.
DEFAULT_MAX_AGE_SECONDS: int = 90 * 24 * 3600

#: Statuses a snapshot entry may carry for one receipt digest.
ENTRY_STATUSES: frozenset[str] = frozenset({"CURRENT", "STALE", "SUPERSEDED", "REVOKED"})

#: Freshness outcomes of an assessment (superset of ENTRY_STATUSES: the
#: last two describe the *evidence*, not the receipt).
FRESHNESS_VALUES: frozenset[str] = frozenset(
    {"CURRENT", "STALE", "SUPERSEDED", "REVOKED", "UNKNOWN_FRESHNESS", "STALE_SNAPSHOT"}
)

#: Digest form enforced for status entries ("sha256:<64 lowercase hex>").
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _check_digest(digest: str) -> str:
    if not _DIGEST_RE.match(digest):
        raise ValueError(f"Invalid receipt digest (expected 'sha256:<64 hex>'): {digest!r}")
    return digest


# ---------------------------------------------------------------------------
# Snapshot data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatusEntry:
    """One receipt's status inside a snapshot.

    ``supersedes`` is set on the entry of a receipt R when R replaces an
    older receipt: ``{"receipt_id": <old id>, "receipt_digest": <old
    digest>}``. The superseded receipt's own entry carries status
    SUPERSEDED. ``effective_at_claimed`` is the claimed time the status
    took effect (claimed, not trusted — see module docstring).
    """

    receipt_digest: str
    status: str
    receipt_id: str | None = None
    supersedes: dict[str, str] | None = None
    reason: str | None = None
    effective_at_claimed: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "receipt_digest": self.receipt_digest,
            "status": self.status,
        }
        if self.receipt_id is not None:
            d["receipt_id"] = self.receipt_id
        if self.supersedes is not None:
            d["supersedes"] = dict(self.supersedes)
        if self.reason is not None:
            d["reason"] = self.reason
        if self.effective_at_claimed is not None:
            d["effective_at_claimed"] = self.effective_at_claimed
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StatusEntry:
        digest = _check_digest(str(data["receipt_digest"]))
        status = str(data["status"])
        if status not in ENTRY_STATUSES:
            raise ValueError(f"Unknown receipt status: {status!r}")
        supersedes = data.get("supersedes")
        if supersedes is not None:
            supersedes = {
                "receipt_id": str(supersedes["receipt_id"]),
                "receipt_digest": _check_digest(str(supersedes["receipt_digest"])),
            }
        effective = data.get("effective_at_claimed")
        if effective is not None:
            parse_hea_timestamp(str(effective))
        return cls(
            receipt_digest=digest,
            status=status,
            receipt_id=str(data["receipt_id"]) if data.get("receipt_id") else None,
            supersedes=supersedes,
            reason=str(data["reason"]) if data.get("reason") else None,
            effective_at_claimed=str(effective) if effective is not None else None,
        )


@dataclass(frozen=True)
class ReceiptStatusSnapshot:
    """A signed, dated set of receipt statuses (oev-receipt-status/0.1)."""

    issuer_key_id: str
    snapshot_time_claimed: str
    entries: list[StatusEntry] = field(default_factory=list)
    protocol_version: str = RECEIPT_STATUS_PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "issuer_key_id": self.issuer_key_id,
            "snapshot_time_claimed": self.snapshot_time_claimed,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReceiptStatusSnapshot:
        if str(data.get("protocol_version", "")) != RECEIPT_STATUS_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported receipt-status protocol version: {data.get('protocol_version')!r}"
            )
        parse_hea_timestamp(str(data["snapshot_time_claimed"]))
        entries = [StatusEntry.from_dict(e) for e in data.get("entries", [])]
        if len(entries) > MAX_STATUS_ENTRIES:
            raise ValueError(f"Receipt-status snapshot exceeds {MAX_STATUS_ENTRIES} entries")
        seen: set[str] = set()
        for entry in entries:
            if entry.receipt_digest in seen:
                raise ValueError(
                    f"Duplicate receipt_digest in status snapshot: {entry.receipt_digest!r}"
                )
            seen.add(entry.receipt_digest)
        return cls(
            issuer_key_id=str(data["issuer_key_id"]),
            snapshot_time_claimed=str(data["snapshot_time_claimed"]),
            entries=entries,
        )

    def entry_for(self, receipt_digest: str) -> StatusEntry | None:
        """Return the snapshot entry for a receipt digest, if present."""
        for entry in self.entries:
            if entry.receipt_digest == receipt_digest:
                return entry
        return None

    def successor_of(self, receipt_digest: str) -> StatusEntry | None:
        """Return the entry whose ``supersedes`` link names this digest.

        That entry is the receipt that supersedes the given receipt, if
        the snapshot records the chain.
        """
        for entry in self.entries:
            if entry.supersedes is not None and (
                entry.supersedes.get("receipt_digest") == receipt_digest
            ):
                return entry
        return None

    def supersession_chain(self, receipt_digest: str) -> list[str]:
        """Follow ``supersedes`` links forward from a receipt digest.

        Returns ``[given_digest, successor_digest, ...]`` while the
        snapshot records successors. A chain of length 1 means the
        snapshot knows no successor for the receipt.
        """
        chain = [receipt_digest]
        seen = {receipt_digest}
        current = receipt_digest
        while True:
            nxt = self.successor_of(current)
            if nxt is None or nxt.receipt_digest in seen:
                break
            chain.append(nxt.receipt_digest)
            seen.add(nxt.receipt_digest)
            current = nxt.receipt_digest
        return chain


# ---------------------------------------------------------------------------
# Build / verify (DSSE, offline)
# ---------------------------------------------------------------------------


def build_status_snapshot(
    entries: list[StatusEntry],
    issuer_key_id: str,
    snapshot_time_claimed: str,
    private_key_pem: bytes,
) -> dict[str, Any]:
    """Build and DSSE-sign a receipt-status snapshot. Returns the envelope.

    The signer key is the *status-signer* key; it SHOULD differ from the
    receipt-signer key (separate trust roots), but this function does not
    enforce that — the caller owns key management.
    """
    snapshot = ReceiptStatusSnapshot(
        issuer_key_id=issuer_key_id,
        snapshot_time_claimed=snapshot_time_claimed,
        entries=list(entries),
    )
    payload = snapshot.to_dict()
    validate_document(payload, RECEIPT_STATUS_SCHEMA_NAME)
    payload_bytes = canonicalize_json(payload)
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(RECEIPT_STATUS_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {
        "sig": base64.b64encode(raw_sig).decode("ascii"),
        "keyid": issuer_key_id,
    }
    return build_dsse_envelope(
        payload_type=RECEIPT_STATUS_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


def verify_status_snapshot(
    envelope: dict[str, Any],
    status_trust_store: TrustStore | None,
) -> tuple[ReceiptStatusSnapshot | None, str]:
    """Verify a DSSE status snapshot against caller-supplied trust roots.

    Returns ``(snapshot_or_None, note)``. A ``None`` snapshot means the
    input was absent, malformed, or untrusted — the caller must treat
    freshness as UNKNOWN, never as CURRENT. Verification is offline:
    only the signature against the trust store is checked.
    """
    if envelope is None:
        return None, "no status snapshot supplied; freshness unknown"
    try:
        payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    except DsseError as exc:
        return None, f"status snapshot envelope malformed: {exc}"
    if payload_type != RECEIPT_STATUS_PAYLOAD_TYPE:
        return None, f"status snapshot has unexpected payloadType: {payload_type!r}"
    try:
        data = safe_json_loads(payload_bytes.decode("utf-8"))
    except ValueError as exc:
        return None, f"status snapshot payload is not valid JSON: {exc}"
    if not isinstance(data, dict):
        return None, "status snapshot payload is not a JSON object"
    try:
        validate_document(data, RECEIPT_STATUS_SCHEMA_NAME)
        snapshot = ReceiptStatusSnapshot.from_dict(data)
    except (ValueError, KeyError, TypeError) as exc:
        return None, f"status snapshot failed validation: {exc}"
    if status_trust_store is None or len(status_trust_store.keys) == 0:
        return None, "no status-signer trust roots supplied; freshness unknown"
    matched_key_id: str | None = None
    for trusted_key in status_trust_store.keys:
        try:
            public_key = load_ed25519_public_key(trusted_key.public_key_pem)
        except ValueError:
            continue
        pae = compute_pae(payload_type, payload_bytes)
        for sig_entry in _sigs:
            try:
                public_key.verify(
                    base64.b64decode(sig_entry["sig"].encode("ascii"), validate=True), pae
                )
                matched_key_id = trusted_key.key_id
                break
            except (InvalidSignature, ValueError):
                continue
        if matched_key_id is not None:
            break
    if matched_key_id is None:
        return None, "status snapshot signature is not trusted by caller"
    return snapshot, (
        f"status snapshot verified (issuer {snapshot.issuer_key_id}, "
        f"{len(snapshot.entries)} entries, snapshot_time "
        f"{snapshot.snapshot_time_claimed})"
    )


# ---------------------------------------------------------------------------
# Relying-party freshness policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FreshnessPolicy:
    """Relying-party freshness policy. The caller defines it; the
    protocol imposes nothing.

    - ``max_age_seconds``: a snapshot older than this cannot support a
      CURRENT claim (yields STALE_SNAPSHOT). ``None`` means "no age
      limit" — the caller then accepts arbitrarily old snapshots, which
      must be a deliberate decision, not a default.
    - ``require_current``: only a fresh CURRENT entry is acceptable.
      This is the fail-closed switch: when True, STALE, SUPERSEDED,
      REVOKED, UNKNOWN_FRESHNESS and STALE_SNAPSHOT are all REJECTED.
    - ``allow_stale_with_warning``: when ``require_current`` is False,
      a STALE entry is accepted with a warning instead of rejected.
      It has no effect while ``require_current`` is True.
    - ``allow_superseded``: when True, a SUPERSEDED receipt is
      accepted (the caller knowingly relies on an old receipt).
      Default False. REVOKED is never acceptable under any policy.

    DEFAULT POLICY (``FreshnessPolicy()``) is fail-closed:
    ``max_age_seconds=90 days, require_current=True``. Security-policy
    uses MUST use the default or a stricter policy; relaxing it
    (``require_current=False``) is an explicit caller decision that
    the assessment records in its notes.
    """

    max_age_seconds: int | None = DEFAULT_MAX_AGE_SECONDS
    require_current: bool = True
    allow_stale_with_warning: bool = False
    allow_superseded: bool = False

    def __post_init__(self) -> None:
        if self.max_age_seconds is not None and self.max_age_seconds < 0:
            raise ValueError("max_age_seconds must be >= 0 or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_age_seconds": self.max_age_seconds,
            "require_current": self.require_current,
            "allow_stale_with_warning": self.allow_stale_with_warning,
            "allow_superseded": self.allow_superseded,
        }


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FreshnessAssessment:
    """One receipt's freshness assessment — separate from reproducibility.

    ``freshness`` is one of CURRENT / STALE / SUPERSEDED / REVOKED /
    UNKNOWN_FRESHNESS / STALE_SNAPSHOT. ``decision`` is ACCEPT, REJECT,
    or ACCEPT_WITH_WARNING under the applied policy. ``snapshot_age_seconds``
    is None when no trustworthy snapshot was available; the snapshot's
    claimed time is always reported when one was verified, so the caller
    can see exactly how old the evidence is.
    """

    receipt_digest: str
    freshness: str
    decision: str
    snapshot_time_claimed: str | None = None
    snapshot_age_seconds: int | None = None
    status_evidence: str = "none"
    policy: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "receipt_digest": self.receipt_digest,
            "freshness": self.freshness,
            "decision": self.decision,
            "status_evidence": self.status_evidence,
            "policy": dict(self.policy),
            "notes": list(self.notes),
        }
        if self.snapshot_time_claimed is not None:
            d["snapshot_time_claimed"] = self.snapshot_time_claimed
        if self.snapshot_age_seconds is not None:
            d["snapshot_age_seconds"] = self.snapshot_age_seconds
        return d


def is_superseded_by_link(receipt_digest: str, newer_receipt: dict[str, Any] | None) -> bool:
    """True if a (newer) receipt's ``superseded_receipt`` link names this digest.

    Per ``oevp/spec/receipt-spec.md`` §2 the link identifies the prior
    receipt this receipt supersedes. The link is corroborating evidence
    only — it never proves the *newer* receipt itself is valid.
    """
    if not newer_receipt:
        return False
    link = newer_receipt.get("superseded_receipt")
    if not isinstance(link, dict):
        return False
    return str(link.get("receipt_digest", "")) == receipt_digest


def assess_receipt_freshness(
    receipt_digest: str,
    *,
    snapshot_envelope: dict[str, Any] | None = None,
    status_trust_store: TrustStore | None = None,
    policy: FreshnessPolicy | None = None,
    now: datetime | None = None,
    receipt_id: str | None = None,
    newer_receipt: dict[str, Any] | None = None,
    receipt_signer_key_id: str | None = None,
) -> FreshnessAssessment:
    """Assess one receipt's freshness under a caller-supplied policy.

    ``now`` is the *caller's* clock (default: current UTC time). The
    snapshot's claimed time is compared against it; a claimed time in
    the future of the caller clock yields UNKNOWN_FRESHNESS (claimed
    time is untrusted — V3-C17). ``newer_receipt`` is an optional
    receipt dict whose ``superseded_receipt`` link may name this
    receipt; it is resolved fail-closed against a snapshot entry (the
    more restrictive verdict wins).
    """
    pol = policy if policy is not None else FreshnessPolicy()
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    _check_digest(receipt_digest)
    policy_dict = pol.to_dict()

    def _decide(
        freshness: str,
        notes: list[str],
        evidence: str,
        snapshot_time: str | None = None,
        age: int | None = None,
    ) -> FreshnessAssessment:
        if freshness == "REVOKED":
            decision = "REJECT"
        elif freshness == "SUPERSEDED":
            decision = "ACCEPT" if pol.allow_superseded else "REJECT"
        elif freshness == "CURRENT":
            decision = "ACCEPT"
        elif freshness == "STALE":
            if pol.require_current:
                decision = "REJECT"
            elif pol.allow_stale_with_warning:
                decision = "ACCEPT_WITH_WARNING"
            else:
                decision = "REJECT"
        elif freshness == "STALE_SNAPSHOT":
            if pol.require_current:
                decision = "REJECT"
            else:
                decision = "ACCEPT_WITH_WARNING"
        else:  # UNKNOWN_FRESHNESS
            if pol.require_current:
                decision = "REJECT"
            else:
                decision = "ACCEPT_WITH_WARNING"
        return FreshnessAssessment(
            receipt_digest=receipt_digest,
            freshness=freshness,
            decision=decision,
            snapshot_time_claimed=snapshot_time,
            snapshot_age_seconds=age,
            status_evidence=evidence,
            policy=policy_dict,
            notes=notes,
        )

    # --- No snapshot at all: only a supersession link can speak. ---
    if snapshot_envelope is None:
        if is_superseded_by_link(receipt_digest, newer_receipt):
            return _decide(
                "SUPERSEDED",
                [
                    (
                        "supersession link in newer receipt names this receipt; "
                        "no status snapshot supplied"
                    )
                ],
                evidence="supersession-link",
            )
        note = (
            "no status snapshot supplied; freshness unknown — "
            "a receipt can re-verify as MATCH and still be stale"
        )
        if not pol.require_current:
            note += " (policy require_current=False: accepted with warning)"
        return _decide("UNKNOWN_FRESHNESS", [note], evidence="none")

    snapshot, verify_note = verify_status_snapshot(snapshot_envelope, status_trust_store)
    if snapshot is None:
        notes = [
            f"status snapshot not trustworthy: {verify_note}",
            "freshness unknown; fail-closed under require_current policy",
        ]
        return _decide("UNKNOWN_FRESHNESS", notes, evidence="untrusted-snapshot")

    notes = [verify_note]
    if receipt_signer_key_id is not None and snapshot.issuer_key_id == receipt_signer_key_id:
        notes.append(
            "status snapshot was signed with the same key id as the receipt "
            "signer; status-signer and receipt-signer keys SHOULD be distinct"
        )
    snap_time = parse_hea_timestamp(snapshot.snapshot_time_claimed)
    age_seconds = int((moment - snap_time).total_seconds())
    if age_seconds < 0:
        notes.append(
            "snapshot claimed time is in the future of the caller clock; "
            "claimed time is untrusted (V3-C17), freshness unknown"
        )
        return _decide(
            "UNKNOWN_FRESHNESS",
            notes,
            evidence="signed-snapshot",
            snapshot_time=snapshot.snapshot_time_claimed,
            age=age_seconds,
        )

    entry = snapshot.entry_for(receipt_digest)
    link_superseded = is_superseded_by_link(receipt_digest, newer_receipt)
    if entry is None:
        if link_superseded:
            notes.append(
                "no snapshot entry for this receipt, but a newer "
                "receipt's superseded_receipt link names it"
            )
            return _decide(
                "SUPERSEDED",
                notes,
                evidence="supersession-link",
                snapshot_time=snapshot.snapshot_time_claimed,
                age=age_seconds,
            )
        notes.append(
            f"snapshot verified but contains no entry for receipt {receipt_digest[:19]}...; "
            "absence from a snapshot is not evidence of currency"
        )
        return _decide(
            "UNKNOWN_FRESHNESS",
            notes,
            evidence="signed-snapshot",
            snapshot_time=snapshot.snapshot_time_claimed,
            age=age_seconds,
        )

    # Fail-closed resolution between snapshot entry and supersession link.
    effective = entry.status
    if link_superseded and effective == "CURRENT":
        notes.append(
            "snapshot entry says CURRENT but a newer receipt's "
            "superseded_receipt link names this receipt; resolved "
            "fail-closed to SUPERSEDED"
        )
        effective = "SUPERSEDED"
    if entry.receipt_id is not None and receipt_id is not None and entry.receipt_id != receipt_id:
        notes.append(
            "snapshot entry receipt_id does not match the presented "
            "receipt_id; digest match governs, id mismatch noted"
        )

    if effective == "REVOKED":
        notes.append(f"snapshot entry status REVOKED (reason: {entry.reason or 'unspecified'})")
        return _decide(
            "REVOKED",
            notes,
            evidence="signed-snapshot",
            snapshot_time=snapshot.snapshot_time_claimed,
            age=age_seconds,
        )
    if effective == "SUPERSEDED":
        chain = snapshot.supersession_chain(receipt_digest)
        notes.append(
            "snapshot entry status SUPERSEDED"
            + (f"; supersession chain length {len(chain)}" if len(chain) > 1 else "")
            + (f" (reason: {entry.reason})" if entry.reason else "")
        )
        return _decide(
            "SUPERSEDED",
            notes,
            evidence="signed-snapshot",
            snapshot_time=snapshot.snapshot_time_claimed,
            age=age_seconds,
        )
    if effective == "STALE":
        notes.append(
            "snapshot entry status STALE" + (f" (reason: {entry.reason})" if entry.reason else "")
        )
        return _decide(
            "STALE",
            notes,
            evidence="signed-snapshot",
            snapshot_time=snapshot.snapshot_time_claimed,
            age=age_seconds,
        )

    # CURRENT: only as good as the snapshot's age.
    if pol.max_age_seconds is not None and age_seconds > pol.max_age_seconds:
        notes.append(
            f"snapshot entry is CURRENT but the snapshot is {age_seconds}s old, "
            f"exceeding policy max_age_seconds={pol.max_age_seconds}; "
            "an old snapshot cannot prove the current state (STALE_SNAPSHOT)"
        )
        return _decide(
            "STALE_SNAPSHOT",
            notes,
            evidence="signed-snapshot",
            snapshot_time=snapshot.snapshot_time_claimed,
            age=age_seconds,
        )
    notes.append(
        f"snapshot entry CURRENT, snapshot age {age_seconds}s "
        f"(max_age_seconds={pol.max_age_seconds})"
    )
    return _decide(
        "CURRENT",
        notes,
        evidence="signed-snapshot",
        snapshot_time=snapshot.snapshot_time_claimed,
        age=age_seconds,
    )


def combine_with_reverification(
    reverification_result: str,
    assessment: FreshnessAssessment,
) -> dict[str, Any]:
    """Report reproducibility and freshness as separate dimensions.

    ``reverification_result`` is MATCH / MISMATCH / CANNOT_REPRODUCE
    (from ``reverify_package``); it is never overwritten by the
    freshness verdict. ``overall_decision`` is ACCEPT only when the
    receipt both reproduces (MATCH) and the freshness decision is
    ACCEPT; ACCEPT_WITH_WARNING propagates when reproducibility holds
    but freshness was only warning-accepted.
    """
    if reverification_result not in ("MATCH", "MISMATCH", "CANNOT_REPRODUCE"):
        raise ValueError(f"Unknown reverification_result: {reverification_result!r}")
    if reverification_result != "MATCH":
        overall = "REJECT"
    elif assessment.decision == "ACCEPT":
        overall = "ACCEPT"
    elif assessment.decision == "ACCEPT_WITH_WARNING":
        overall = "ACCEPT_WITH_WARNING"
    else:
        overall = "REJECT"
    return {
        "reverification_result": reverification_result,
        "freshness": assessment.freshness,
        "freshness_decision": assessment.decision,
        "overall_decision": overall,
        "receipt_digest": assessment.receipt_digest,
        "snapshot_time_claimed": assessment.snapshot_time_claimed,
        "snapshot_age_seconds": assessment.snapshot_age_seconds,
        "status_evidence": assessment.status_evidence,
        "policy": dict(assessment.policy),
        "freshness_notes": list(assessment.notes),
    }
