# SPDX-License-Identifier: Apache-2.0

"""Independent-evidence corroboration (V3-C18, staged consistent lie).

Tur 3 honest limit (``docs/PUBLICATION_READINESS_V3.md`` §2): the OEVP
domain engines only check *bundle-internal* relations. If the invoice,
the ERP record and the payment all agree on the same false amount, the
financial engine returns PASS — the execution is genuine, the claim is
false, and no bundle-internal check can see it. The same holds for a
dataset whose manifest checksum was recomputed over falsified data, and
for AI metrics recomputed over falsified predictions.

This module adds a second, independent dimension on top of the existing
engines *without changing them*: a **corroboration record** signed by a
trusted *external* source (an ERP system, a dataset registry, an
independent evaluation harness) in a different trust domain from the
producer/witness keys. The verifier reports two dimensions side by
side, never merged into one score:

- technical consistency — the existing domain engines' verdict;
- source trust — ``CORROBORATED`` / ``SOURCE_UNCORROBORATED`` /
  ``SOURCE_MISMATCH`` / ``SELF_CORROBORATION`` / ``SOURCE_REJECTED``.

Rules enforced here (all fail-closed, all with a reason code):

1. A corroboration record is a DSSE envelope (Ed25519, PAE) over the
   JCS-canonical JSON of the record. The record carries ``source_id``,
   ``source_key_id``, ``trust_root_id``, ``content_digest`` (SHA-256 of
   the JCS-canonical ``claims`` object) and the ``claims`` themselves,
   plus an optional ``issued_at`` and an optional ``timestamp_ref``.
2. Trust is caller-supplied, exactly as in ``oev.trust``: the caller
   passes ``trust_roots`` (``trust_root_id -> TrustStore``). A DSSE
   ``keyid`` is an unauthenticated hint only — the signature must verify
   cryptographically against a key *in the named trust root*.
3. Independence is a trust-domain separation, not a signature check: the
   key that verifies the signature must not be a producer or witness key
   (matched by key id *and* by public-key digest). A producer signing
   its own "external" corroboration yields ``SELF_CORROBORATION``.
4. A valid independent signature is not enough: the source's claims are
   compared against values recomputed from the bundle (ERP amount vs
   invoice amount, external checksum vs recomputed data checksum,
   external metrics vs metrics recomputed from the stored predictions).
   Disagreement is ``SOURCE_MISMATCH``.
5. No corroboration record at all is an explicit outcome,
   ``SOURCE_UNCORROBORATED`` — never a silent PASS.

What this does NOT do: it cannot prove that an external source is
honest, only that *this* record was signed by a key the caller trusts
under a root the caller named, that the key is independent of the
producer/witness domain, and that the attested values agree (or not)
with the bundle. A compromised external source, a source key stolen
pre-revocation, and a caller who puts the producer key in a "foreign"
trust root are all outside this layer — see
``docs/INDEPENDENT_EVIDENCE_MODEL.md``.
"""

from __future__ import annotations

import base64
import csv
import io
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from oev.canonical import canonicalize_json, safe_json_loads
from oev.domain import evaluate_domain_checks
from oev.domain.common import load_json_member, sha256_hex
from oev.dsse import build_dsse_envelope, compute_pae, parse_dsse_envelope
from oev.models import CheckResult, CheckStatus, VerificationProfile
from oev.schemas import SchemaValidationError, validate_document
from oev.signing import load_ed25519_private_key, verify_dsse_signature_with_key
from oev.trust import TrustedKey, TrustStore

#: Protocol version of a corroboration record.
CORROBORATION_PROTOCOL_VERSION = "oev-corroboration/0.1"

#: DSSE payload type for a corroboration record.
CORROBORATION_PAYLOAD_TYPE = "application/vnd.oev.corroboration+json"

#: JSON Schema file name for a corroboration record (identical copies in
#: ``oevp/schemas/`` and ``oevp/src/oev/schemas/``; see test_repo_consistency).
CORROBORATION_SCHEMA = "corroboration-0.1.schema.json"

#: ``content_digest`` form: ``sha256:<64 lowercase hex>``.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Strict ``YYYY-MM-DDTHH:MM:SSZ`` form (same as HEA claimed time).
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

#: Metric agreement tolerance, identical to the ai-eval engine
#: (``oev.domain.ai_eval``: 1e-9 absolute + 1e-6 relative).
DEFAULT_METRIC_ABS_TOL = 1e-9
DEFAULT_METRIC_REL_TOL = 1e-6


class SourceTrust(str, Enum):
    """Source-trust dimension of a verification (independent of technical).

    This is a *second* dimension, never merged with the technical
    verdict: a bundle can be technically consistent
    (``TECHNICAL_PASS``) and still ``SOURCE_UNCORROBORATED`` — that
    combination is exactly the staged-consistent-lie case (V3-C18).
    """

    CORROBORATED = "CORROBORATED"
    SOURCE_UNCORROBORATED = "SOURCE_UNCORROBORATED"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    SELF_CORROBORATION = "SELF_CORROBORATION"
    SOURCE_REJECTED = "SOURCE_REJECTED"


#: Controlled rejection / mismatch reason codes for corroboration.
REASON_OK = "OK"
REASON_NO_RECORD = "NO_RECORD"
REASON_MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"
REASON_MALFORMED_RECORD = "MALFORMED_RECORD"
REASON_SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
REASON_TRUST_ROOT_UNKNOWN = "TRUST_ROOT_UNKNOWN"
REASON_SIGNATURE_INVALID = "SIGNATURE_INVALID"
REASON_KEY_REVOKED = "KEY_REVOKED"
REASON_KEY_EXPIRED = "KEY_EXPIRED"
REASON_KEY_NOT_YET_VALID = "KEY_NOT_YET_VALID"
REASON_SELF_KEY = "SELF_KEY"
REASON_CONTENT_DIGEST_MISMATCH = "CONTENT_DIGEST_MISMATCH"
REASON_CLAIMS_DIGEST_MISMATCH = "CLAIMS_DIGEST_MISMATCH"


def claims_digest(claims: dict[str, Any]) -> str:
    """SHA-256 (``sha256:<hex>``) of the JCS-canonical ``claims`` object."""
    return "sha256:" + sha256_hex(canonicalize_json(claims))


@dataclass(frozen=True)
class CorroborationRecord:
    """A trusted external source's attestation about bundle content.

    ``content_digest`` is defined as :func:`claims_digest` of ``claims``:
    the digest binds exactly the attested values, nothing else. A source
    that attests an external artefact (e.g. an ERP row) puts the values
    it stands behind in ``claims``; the verifier recomputes the same
    values from the bundle and compares (see :func:`compare_claims`).
    """

    source_id: str
    source_key_id: str
    trust_root_id: str
    content_digest: str
    claims: dict[str, Any] = field(default_factory=dict)
    protocol_version: str = CORROBORATION_PROTOCOL_VERSION
    issued_at: str | None = None
    timestamp_ref: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "protocol_version": self.protocol_version,
            "source_id": self.source_id,
            "source_key_id": self.source_key_id,
            "trust_root_id": self.trust_root_id,
            "content_digest": self.content_digest,
            "claims": dict(self.claims),
        }
        if self.issued_at is not None:
            d["issued_at"] = self.issued_at
        if self.timestamp_ref is not None:
            d["timestamp_ref"] = dict(self.timestamp_ref)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CorroborationRecord:
        if not isinstance(data, dict):
            raise TypeError("Corroboration record must be a JSON object")
        protocol = data.get("protocol_version")
        if protocol != CORROBORATION_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported corroboration protocol version: {protocol!r} "
                f"(expected {CORROBORATION_PROTOCOL_VERSION!r})"
            )
        for fname in ("source_id", "source_key_id", "trust_root_id"):
            value = data.get(fname)
            if not isinstance(value, str) or not value:
                raise ValueError(f"Corroboration record field {fname!r} must be a non-empty string")
        digest = data.get("content_digest")
        if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
            raise ValueError(
                f"Corroboration record 'content_digest' must match sha256:<64 hex>, got {digest!r}"
            )
        claims = data.get("claims")
        if not isinstance(claims, dict):
            raise TypeError("Corroboration record 'claims' must be a JSON object")
        issued_at = data.get("issued_at")
        if issued_at is not None and (
            not isinstance(issued_at, str) or not _TIMESTAMP_RE.match(issued_at)
        ):
            raise ValueError(
                f"Corroboration record 'issued_at' must be YYYY-MM-DDTHH:MM:SSZ, got {issued_at!r}"
            )
        timestamp_ref = data.get("timestamp_ref")
        if timestamp_ref is not None and not isinstance(timestamp_ref, dict):
            raise ValueError("Corroboration record 'timestamp_ref' must be a JSON object")
        return cls(
            source_id=str(data["source_id"]),
            source_key_id=str(data["source_key_id"]),
            trust_root_id=str(data["trust_root_id"]),
            content_digest=str(digest),
            claims=dict(claims),
            protocol_version=str(protocol),
            issued_at=str(issued_at) if issued_at is not None else None,
            timestamp_ref=dict(timestamp_ref) if timestamp_ref is not None else None,
        )


def build_corroboration_record(
    source_id: str,
    source_key_id: str,
    trust_root_id: str,
    claims: dict[str, Any],
    issued_at: str | None = None,
    timestamp_ref: dict[str, Any] | None = None,
) -> CorroborationRecord:
    """Build a record whose ``content_digest`` is computed from ``claims``."""
    return CorroborationRecord(
        source_id=source_id,
        source_key_id=source_key_id,
        trust_root_id=trust_root_id,
        content_digest=claims_digest(claims),
        claims=dict(claims),
        issued_at=issued_at,
        timestamp_ref=dict(timestamp_ref) if timestamp_ref is not None else None,
    )


def sign_corroboration_dsse(
    record: CorroborationRecord,
    private_key_pem: bytes,
    key_id: str = "",
) -> dict[str, Any]:
    """DSSE-sign a corroboration record (Ed25519 over the DSSE PAE).

    The payload is the JCS-canonical JSON of the record. ``key_id`` is
    written into the envelope as an unauthenticated hint only; verifiers
    must never trust it (see :func:`verify_corroboration`).
    """
    payload_bytes = canonicalize_json(record.to_dict())
    private_key = load_ed25519_private_key(private_key_pem)
    raw_sig = private_key.sign(compute_pae(CORROBORATION_PAYLOAD_TYPE, payload_bytes))
    sig_entry: dict[str, str] = {"sig": base64.b64encode(raw_sig).decode("ascii")}
    if key_id:
        sig_entry["keyid"] = key_id
    return build_dsse_envelope(
        payload_type=CORROBORATION_PAYLOAD_TYPE,
        payload_bytes=payload_bytes,
        signatures=[sig_entry],
    )


@dataclass(frozen=True)
class CorroborationVerification:
    """Result of verifying one corroboration record."""

    outcome: SourceTrust
    reason: str
    detail: str
    source_id: str | None = None
    trust_root_id: str | None = None
    matched_key_id: str | None = None
    record: CorroborationRecord | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome.value,
            "reason": self.reason,
            "detail": self.detail,
        }
        if self.source_id is not None:
            d["source_id"] = self.source_id
        if self.trust_root_id is not None:
            d["trust_root_id"] = self.trust_root_id
        if self.matched_key_id is not None:
            d["matched_key_id"] = self.matched_key_id
        return d


def _rejected(reason: str, detail: str, **kw: Any) -> CorroborationVerification:
    return CorroborationVerification(
        outcome=SourceTrust.SOURCE_REJECTED, reason=reason, detail=detail, **kw
    )


def verify_corroboration(
    envelope: dict[str, Any] | None,
    trust_roots: dict[str, TrustStore] | None,
    producer_key_ids: set[str] | None = None,
    producer_key_digests: set[str] | None = None,
    expected_content_digest: str | None = None,
) -> CorroborationVerification:
    """Verify one corroboration record against caller-supplied trust roots.

    ``trust_roots`` maps ``trust_root_id`` to the ``TrustStore`` of source
    keys the caller trusts under that root. ``producer_key_ids`` /
    ``producer_key_digests`` describe the producer/witness trust domain:
    a source key that is also a producer/witness key is not independent,
    however valid its signature is. ``expected_content_digest``, when
    given, is the digest the caller expects the record to carry
    (``sha256:<hex>`` of the JCS-canonical claims the caller expects);
    a record carrying another digest attests different content and is a
    ``SOURCE_MISMATCH``, not a rejection.

    Every failure is a controlled, reasoned outcome — this function never
    raises for a bad record (only for programmer errors such as a wrong
    argument type).
    """
    producer_ids = set(producer_key_ids or ())
    producer_digests = set(producer_key_digests or ())
    if envelope is None:
        return CorroborationVerification(
            outcome=SourceTrust.SOURCE_UNCORROBORATED,
            reason=REASON_NO_RECORD,
            detail="No corroboration record supplied; source trust is explicitly uncorroborated, "
            "not a silent pass",
        )
    try:
        _payload_type, payload_bytes, _sigs = parse_dsse_envelope(envelope)
    except Exception as exc:  # noqa: BLE001 - malformed envelope is a verdict, not a crash
        return _rejected(REASON_MALFORMED_ENVELOPE, f"Corroboration envelope is malformed: {exc}")
    try:
        payload = safe_json_loads(payload_bytes)
    except Exception as exc:  # noqa: BLE001
        return _rejected(REASON_MALFORMED_RECORD, f"Corroboration payload is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        return _rejected(REASON_MALFORMED_RECORD, "Corroboration payload is not a JSON object")
    try:
        validate_document(payload, CORROBORATION_SCHEMA)
    except (SchemaValidationError, FileNotFoundError) as exc:
        return _rejected(
            REASON_SCHEMA_VIOLATION,
            f"Corroboration record violates {CORROBORATION_SCHEMA}: {exc}",
            source_id=payload.get("source_id")
            if isinstance(payload.get("source_id"), str)
            else None,
            trust_root_id=payload.get("trust_root_id")
            if isinstance(payload.get("trust_root_id"), str)
            else None,
        )
    try:
        record = CorroborationRecord.from_dict(payload)
    except ValueError as exc:
        return _rejected(REASON_MALFORMED_RECORD, f"Corroboration record is malformed: {exc}")
    # The digest must bind exactly the attested claims.
    if claims_digest(record.claims) != record.content_digest:
        return _rejected(
            REASON_CLAIMS_DIGEST_MISMATCH,
            "content_digest does not match the digest of the record's own claims "
            "(claims were altered after the digest was computed)",
            source_id=record.source_id,
            trust_root_id=record.trust_root_id,
            record=record,
        )
    roots = trust_roots or {}
    store = roots.get(record.trust_root_id)
    if store is None:
        return _rejected(
            REASON_TRUST_ROOT_UNKNOWN,
            f"Trust root {record.trust_root_id!r} is not supplied by the caller; "
            "the source cannot be trusted under an unknown root",
            source_id=record.source_id,
            trust_root_id=record.trust_root_id,
            record=record,
        )
    matched: TrustedKey | None = None
    for candidate in store.keys:
        try:
            if verify_dsse_signature_with_key(envelope, candidate.public_key_pem):
                matched = candidate
                break
        except Exception:  # noqa: BLE001,S112 - one bad key must not abort the search
            continue
    if matched is None:
        return _rejected(
            REASON_SIGNATURE_INVALID,
            "No key in trust root "
            f"{record.trust_root_id!r} verifies the record's signature "
            "(forged signature, wrong key, or key outside the root)",
            source_id=record.source_id,
            trust_root_id=record.trust_root_id,
            record=record,
        )
    # Independence: the verifying key must not belong to the
    # producer/witness domain — checked on the key that *actually*
    # verified, never on the unauthenticated keyid hint.
    if matched.key_id in producer_ids or matched.digest in producer_digests:
        return CorroborationVerification(
            outcome=SourceTrust.SELF_CORROBORATION,
            reason=REASON_SELF_KEY,
            detail=f"Source key {matched.key_id!r} belongs to the producer/witness trust "
            "domain; a producer corroborating its own evidence is not independent evidence",
            source_id=record.source_id,
            trust_root_id=record.trust_root_id,
            matched_key_id=matched.key_id,
            record=record,
        )
    if matched.revoked:
        return _rejected(
            REASON_KEY_REVOKED,
            f"Source key {matched.key_id!r} is revoked",
            source_id=record.source_id,
            trust_root_id=record.trust_root_id,
            matched_key_id=matched.key_id,
            record=record,
        )
    if record.issued_at is not None:
        try:
            state = matched.key_state_at(record.issued_at)
        except ValueError as exc:
            return _rejected(
                REASON_MALFORMED_RECORD,
                f"Corroboration record 'issued_at' is not a valid timestamp: {exc}",
                source_id=record.source_id,
                trust_root_id=record.trust_root_id,
                matched_key_id=matched.key_id,
                record=record,
            )
        if state == "expired":
            return _rejected(
                REASON_KEY_EXPIRED,
                f"Source key {matched.key_id!r} was expired at the record's issued_at "
                f"{record.issued_at}",
                source_id=record.source_id,
                trust_root_id=record.trust_root_id,
                matched_key_id=matched.key_id,
                record=record,
            )
        if state == "not_yet_valid":
            return _rejected(
                REASON_KEY_NOT_YET_VALID,
                f"Source key {matched.key_id!r} was not yet valid at the record's issued_at "
                f"{record.issued_at}",
                source_id=record.source_id,
                trust_root_id=record.trust_root_id,
                matched_key_id=matched.key_id,
                record=record,
            )
    if expected_content_digest is not None and record.content_digest != expected_content_digest:
        return CorroborationVerification(
            outcome=SourceTrust.SOURCE_MISMATCH,
            reason=REASON_CONTENT_DIGEST_MISMATCH,
            detail="Record is authentically signed by an independent trusted source, but its "
            f"content_digest {record.content_digest} differs from the expected digest "
            f"{expected_content_digest}: the source attests different content",
            source_id=record.source_id,
            trust_root_id=record.trust_root_id,
            matched_key_id=matched.key_id,
            record=record,
        )
    return CorroborationVerification(
        outcome=SourceTrust.CORROBORATED,
        reason=REASON_OK,
        detail=f"Record signed by independent trusted source key {matched.key_id!r} under "
        f"trust root {record.trust_root_id!r}; signature valid, digest binds the claims",
        source_id=record.source_id,
        trust_root_id=record.trust_root_id,
        matched_key_id=matched.key_id,
        record=record,
    )


# ---------------------------------------------------------------------------
# Claim comparison: source claims vs values recomputed from the bundle
# ---------------------------------------------------------------------------

#: profile parameter ``domain`` value -> comparison rule.
_PROFILE_DOMAINS: dict[str, str] = {
    "financial-evidence": "financial",
    "dataset-release": "dataset",
    "ai-model-eval": "ai_eval",
}


def profile_domain_name(profile: VerificationProfile) -> str | None:
    """Return ``financial`` / ``dataset`` / ``ai_eval`` for a domain profile."""
    domain_param = profile.parameters.get("domain")
    if isinstance(domain_param, str) and domain_param in _PROFILE_DOMAINS:
        return _PROFILE_DOMAINS[domain_param]
    for prefix, name in (
        ("financial-evidence", "financial"),
        ("dataset-release", "dataset"),
        ("ai-model-eval", "ai_eval"),
    ):
        if profile.profile_id.startswith(prefix):
            return name
    return None


def _metric_agrees(recomputed: float, claimed: Any, abs_tol: float, rel_tol: float) -> bool:
    if not isinstance(claimed, (int, float)) or isinstance(claimed, bool):
        return False
    return abs(recomputed - float(claimed)) <= abs_tol + rel_tol * abs(recomputed)


def _ai_recomputed(members: dict[str, bytes]) -> dict[str, float] | None:
    """Recompute MAE/RMSE/R² from the bundle's stored predictions (local math)."""
    raw = members.get("domain/ai-eval/predictions.csv")
    if raw is None:
        return None
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error):
        return None
    if not rows or [h.strip() for h in rows[0]] != ["y_true", "y_pred"]:
        return None
    pairs: list[tuple[float, float]] = []
    for row in rows[1:]:
        if len(row) != 2:
            return None
        try:
            y_true, y_pred = float(row[0]), float(row[1])
        except ValueError:
            return None
        if not (math.isfinite(y_true) and math.isfinite(y_pred)):
            return None
        pairs.append((y_true, y_pred))
    if not pairs:
        return None
    mae = sum(abs(t - p) for t, p in pairs) / len(pairs)
    rmse = math.sqrt(sum((t - p) ** 2 for t, p in pairs) / len(pairs))
    mean = sum(t for t, _ in pairs) / len(pairs)
    ss_tot = sum((t - mean) ** 2 for t, _ in pairs)
    out: dict[str, float] = {"mae": mae, "rmse": rmse}
    if ss_tot != 0.0:
        out["r2"] = 1.0 - sum((t - p) ** 2 for t, p in pairs) / ss_tot
    return out


def _dataset_facts(members: dict[str, bytes]) -> dict[str, Any] | None:
    """Recomputed dataset facts: data SHA-256, actual row count, ids."""
    raw = members.get("domain/dataset/data.csv")
    if raw is None:
        return None
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error):
        return None
    manifest, _ = load_json_member(members, "domain/dataset/manifest.json")
    facts: dict[str, Any] = {
        "sha256": sha256_hex(raw),
        "rows_actual": (len(rows) - 1) if rows else 0,
    }
    if manifest is not None:
        facts["dataset_id"] = manifest.get("dataset_id")
        facts["version"] = manifest.get("version")
        facts["rows_declared"] = manifest.get("rows_declared")
    return facts


def compare_claims(
    domain: str | None,
    members: dict[str, bytes],
    claims: dict[str, Any],
    profile: VerificationProfile | None = None,
) -> tuple[str, list[str], list[str]]:
    """Compare an independent source's claims against the bundle.

    Returns ``(comparison, mismatches, details)`` where ``comparison`` is
    ``"AGREE"``, ``"MISMATCH"`` or ``"NOT_COMPARED"``. Values are always
    recomputed from the bundle members here — never taken from a
    bundle-declared digest or a reported metric at face value, except
    where the comparison itself is "source value vs bundle-declared
    value" (financial amounts: the invoice *is* the bundle's claim, and
    the source is the independent check on it).

    Comparable claims per domain:

    - financial: ``amount_minor``, ``invoice_no``, ``seller_id``,
      ``buyer_id``, ``currency`` — compared against the invoice.
    - dataset: ``sha256`` (recomputed over ``data.csv``),
      ``rows_declared``/``rows_actual`` (recomputed row count),
      ``dataset_id``, ``version``.
    - ai_eval: ``mae``, ``rmse``, ``r2`` — compared against metrics
      recomputed from the stored predictions.
    """
    mismatches: list[str] = []
    details: list[str] = []
    if domain is None:
        return "NOT_COMPARED", [], ["No domain comparison rule for this profile"]
    if domain == "financial":
        invoice, _ = load_json_member(members, "domain/financial/invoice.json")
        if invoice is None:
            return "NOT_COMPARED", [], ["invoice.json absent/unreadable; nothing to compare"]
        compared = 0
        for key in ("amount_minor", "invoice_no", "seller_id", "buyer_id", "currency"):
            if key not in claims:
                continue
            compared += 1
            if claims[key] != invoice.get(key):
                mismatches.append(
                    f"{key}: source {claims[key]!r} != bundle invoice {invoice.get(key)!r}"
                )
        if compared == 0:
            return "NOT_COMPARED", [], ["Source claims carry no financial field to compare"]
        details.append(f"Compared {compared} financial field(s) against the invoice")
    elif domain == "dataset":
        facts = _dataset_facts(members)
        if facts is None:
            return "NOT_COMPARED", [], ["data.csv absent/unreadable; nothing to compare"]
        compared = 0
        if "sha256" in claims:
            compared += 1
            claimed = str(claims["sha256"]).lower()
            if claimed != facts["sha256"]:
                mismatches.append(
                    f"sha256: source {claimed} != recomputed data.csv {facts['sha256']}"
                )
        if "rows_declared" in claims:
            compared += 1
            if claims["rows_declared"] != facts["rows_actual"]:
                mismatches.append(
                    f"rows: source declares {claims['rows_declared']!r} rows, "
                    f"data.csv actually has {facts['rows_actual']}"
                )
        for key in ("dataset_id", "version"):
            if key in claims:
                compared += 1
                if claims[key] != facts.get(key):
                    mismatches.append(
                        f"{key}: source {claims[key]!r} != bundle manifest {facts.get(key)!r}"
                    )
        if compared == 0:
            return "NOT_COMPARED", [], ["Source claims carry no dataset field to compare"]
        details.append(f"Compared {compared} dataset field(s) against recomputed facts")
    elif domain == "ai_eval":
        recomputed = _ai_recomputed(members)
        if recomputed is None:
            return "NOT_COMPARED", [], ["predictions.csv absent/unreadable; nothing to compare"]
        abs_tol = DEFAULT_METRIC_ABS_TOL
        rel_tol = DEFAULT_METRIC_REL_TOL
        if profile is not None:
            raw_abs = profile.parameters.get("metric_abs_tol")
            raw_rel = profile.parameters.get("metric_rel_tol")
            if isinstance(raw_abs, (int, float)) and not isinstance(raw_abs, bool):
                abs_tol = float(raw_abs)
            if isinstance(raw_rel, (int, float)) and not isinstance(raw_rel, bool):
                rel_tol = float(raw_rel)
        compared = 0
        for metric in ("mae", "rmse", "r2"):
            if metric not in claims or metric not in recomputed:
                continue
            compared += 1
            if not _metric_agrees(recomputed[metric], claims[metric], abs_tol, rel_tol):
                mismatches.append(
                    f"{metric}: source {claims[metric]!r} != recomputed "
                    f"{recomputed[metric]:.6f} (tol {abs_tol} abs + {rel_tol} rel)"
                )
        if compared == 0:
            return "NOT_COMPARED", [], ["Source claims carry no metric to compare"]
        details.append(f"Compared {compared} metric(s) against recomputed values")
    else:
        return "NOT_COMPARED", [], [f"No domain comparison rule for domain {domain!r}"]
    if mismatches:
        return "MISMATCH", mismatches, details
    return "AGREE", [], details


# ---------------------------------------------------------------------------
# Two-dimensional profile evaluation (thin wrapper over the domain engines)
# ---------------------------------------------------------------------------


def technical_summary(results: list[CheckResult], profile: VerificationProfile) -> str:
    """Summarise the technical dimension over the domain checks returned.

    ``TECHNICAL_PASS``: every returned check PASS. ``TECHNICAL_FAIL``:
    at least one FAIL. ``TECHNICAL_INCOMPLETE``: no FAIL, but at least
    one NOT_RUN / NOT_APPLICABLE / UNVERIFIED / UNSUPPORTED. Only the
    domain checks the engines returned are counted; mechanical checks
    (archive safety, digests, signatures) are out of scope here.
    """
    if not results:
        return "TECHNICAL_INCOMPLETE"
    statuses = [
        (r.status.value if isinstance(r.status, CheckStatus) else str(r.status)) for r in results
    ]
    if any(s == "FAIL" for s in statuses):
        return "TECHNICAL_FAIL"
    if all(s == "PASS" for s in statuses):
        return "TECHNICAL_PASS"
    return "TECHNICAL_INCOMPLETE"


@dataclass
class CorroboratedProfileResult:
    """Two-dimensional result: technical consistency + source trust.

    The two dimensions are reported separately and never merged: a
    staged consistent lie is ``TECHNICAL_PASS`` +
    ``SOURCE_UNCORROBORATED`` (or ``SOURCE_MISMATCH`` when a trusted
    independent source disagrees). ``verifications`` holds the
    per-record verdicts so an aggregate never hides a conflicting
    record.
    """

    profile_id: str
    domain: str | None
    technical: list[CheckResult]
    technical_summary: str
    source_trust: SourceTrust
    comparison: str
    mismatches: list[str]
    comparison_details: list[str]
    verifications: list[CorroborationVerification]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "domain": self.domain,
            "technical_summary": self.technical_summary,
            "technical_checks": [c.to_dict() for c in self.technical],
            "source_trust": self.source_trust.value,
            "comparison": self.comparison,
            "mismatches": list(self.mismatches),
            "comparison_details": list(self.comparison_details),
            "verifications": [v.to_dict() for v in self.verifications],
            "detail": self.detail,
        }


def evaluate_profile_with_corroboration(
    members: dict[str, bytes],
    profile: VerificationProfile,
    envelopes: list[dict[str, Any]] | None = None,
    trust_roots: dict[str, TrustStore] | None = None,
    producer_key_ids: set[str] | None = None,
    producer_key_digests: set[str] | None = None,
) -> CorroboratedProfileResult:
    """Evaluate a domain profile in two dimensions (wrapper, no engine change).

    The technical dimension is exactly :func:`oev.domain.evaluate_domain_checks`
    over ``members`` — this function adds no check and changes no engine
    behaviour. The source dimension verifies each supplied corroboration
    envelope and compares the best verified independent record's claims
    against values recomputed from the bundle.

    Aggregate priority (documented, per-record verdicts always kept):
    a verified independent record whose claims AGREE corroborates;
    otherwise a verified independent record whose claims MISMATCH wins
    over a self-corroboration attempt, which wins over a rejected
    record; with no record at all the outcome is explicitly
    ``SOURCE_UNCORROBORATED``.
    """
    technical = evaluate_domain_checks(members, profile)
    summary = technical_summary(technical, profile)
    domain = profile_domain_name(profile)
    records = envelopes or []
    verifications = [
        verify_corroboration(
            env,
            trust_roots,
            producer_key_ids=producer_key_ids,
            producer_key_digests=producer_key_digests,
        )
        for env in records
    ]
    if not records:
        return CorroboratedProfileResult(
            profile_id=profile.profile_id,
            domain=domain,
            technical=technical,
            technical_summary=summary,
            source_trust=SourceTrust.SOURCE_UNCORROBORATED,
            comparison="NOT_COMPARED",
            mismatches=[],
            comparison_details=["No corroboration record supplied"],
            verifications=[],
            detail="Technical dimension: " + summary + ". Source dimension: "
            "SOURCE_UNCORROBORATED — no independent source record was supplied, "
            "so the bundle's claims are uncorroborated (not silently passed).",
        )
    comparison = "NOT_COMPARED"
    mismatches: list[str] = []
    comparison_details: list[str] = []
    corroborated = [v for v in verifications if v.outcome == SourceTrust.CORROBORATED]
    for verification in corroborated:
        assert verification.record is not None
        comp, mism, det = compare_claims(domain, members, verification.record.claims, profile)
        if comp == "AGREE":
            return CorroboratedProfileResult(
                profile_id=profile.profile_id,
                domain=domain,
                technical=technical,
                technical_summary=summary,
                source_trust=SourceTrust.CORROBORATED,
                comparison="AGREE",
                mismatches=[],
                comparison_details=det,
                verifications=verifications,
                detail="Technical dimension: " + summary + ". Source dimension: CORROBORATED — "
                f"independent source {verification.source_id!r} verified and its claims "
                "agree with values recomputed from the bundle.",
            )
        if comp == "MISMATCH":
            comparison, mismatches, comparison_details = comp, mism, det
    if comparison == "MISMATCH":
        return CorroboratedProfileResult(
            profile_id=profile.profile_id,
            domain=domain,
            technical=technical,
            technical_summary=summary,
            source_trust=SourceTrust.SOURCE_MISMATCH,
            comparison="MISMATCH",
            mismatches=mismatches,
            comparison_details=comparison_details,
            verifications=verifications,
            detail="Technical dimension: " + summary + ". Source dimension: SOURCE_MISMATCH — "
            "an independent trusted source attests values that disagree with the bundle: "
            + "; ".join(mismatches),
        )
    if any(v.outcome == SourceTrust.SELF_CORROBORATION for v in verifications):
        return CorroboratedProfileResult(
            profile_id=profile.profile_id,
            domain=domain,
            technical=technical,
            technical_summary=summary,
            source_trust=SourceTrust.SELF_CORROBORATION,
            comparison="NOT_COMPARED",
            mismatches=[],
            comparison_details=["Self-corroboration is not compared: it is not independent"],
            verifications=verifications,
            detail="Technical dimension: " + summary + ". Source dimension: SELF_CORROBORATION "
            "— the only supplied record(s) were signed with a producer/witness key.",
        )
    if any(v.outcome == SourceTrust.SOURCE_REJECTED for v in verifications):
        reasons = "; ".join(
            f"{v.source_id or '?'}: {v.reason}"
            for v in verifications
            if v.outcome == SourceTrust.SOURCE_REJECTED
        )
        return CorroboratedProfileResult(
            profile_id=profile.profile_id,
            domain=domain,
            technical=technical,
            technical_summary=summary,
            source_trust=SourceTrust.SOURCE_REJECTED,
            comparison="NOT_COMPARED",
            mismatches=[],
            comparison_details=["Rejected record(s) are not compared"],
            verifications=verifications,
            detail="Technical dimension: "
            + summary
            + ". Source dimension: SOURCE_REJECTED — "
            + reasons,
        )
    # Verified independent record(s) exist but carry no comparable claim.
    return CorroboratedProfileResult(
        profile_id=profile.profile_id,
        domain=domain,
        technical=technical,
        technical_summary=summary,
        source_trust=SourceTrust.CORROBORATED,
        comparison="NOT_COMPARED",
        mismatches=[],
        comparison_details=[
            (
                "Verified record(s) carry no claim comparable to this profile; "
                "only the record's authenticity (not its content) is corroborated"
            )
        ],
        verifications=verifications,
        detail="Technical dimension: " + summary + ". Source dimension: CORROBORATED "
        "(record authentic) but NOT_COMPARED — no claim in the record compares against "
        "this profile's bundle values.",
    )


__all__ = [
    "CORROBORATION_PAYLOAD_TYPE",
    "CORROBORATION_PROTOCOL_VERSION",
    "CORROBORATION_SCHEMA",
    "REASON_CLAIMS_DIGEST_MISMATCH",
    "REASON_CONTENT_DIGEST_MISMATCH",
    "REASON_KEY_EXPIRED",
    "REASON_KEY_NOT_YET_VALID",
    "REASON_KEY_REVOKED",
    "REASON_MALFORMED_ENVELOPE",
    "REASON_MALFORMED_RECORD",
    "REASON_NO_RECORD",
    "REASON_OK",
    "REASON_SCHEMA_VIOLATION",
    "REASON_SELF_KEY",
    "REASON_SIGNATURE_INVALID",
    "REASON_TRUST_ROOT_UNKNOWN",
    "CorroboratedProfileResult",
    "CorroborationRecord",
    "CorroborationVerification",
    "SourceTrust",
    "build_corroboration_record",
    "claims_digest",
    "compare_claims",
    "evaluate_profile_with_corroboration",
    "profile_domain_name",
    "sign_corroboration_dsse",
    "technical_summary",
    "verify_corroboration",
]
