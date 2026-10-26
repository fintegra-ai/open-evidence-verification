# OEVP Decision Evidence Pack Specification (`oev-decision-pack/0.2`)

Status: Pre-1.0 Draft (0.2.0 — unreleased)  
Protocol Version: `oev-decision-pack/0.2`

---

## 1. Purpose & Scope

A **Decision Evidence Pack** is a portable, self-contained directory that records the evidence
trail of a decision process in a **domain-neutral** way: what facts were recorded, which
versioned rules were executed against them and with what honest outcomes, what findings were
raised, what review actions humans or systems performed, in what order events happened, and
against which snapshot of source context the decision was made.

The pack complements the OEVP Verification Receipt (`oev-receipt/0.1`): a receipt records what a
verifier checked about *package bytes*; a decision pack records how a *decision process* was
documented, so that a third party can later verify its technical integrity offline.

**Integrity boundary (non-negotiable).** Verification of a decision pack asserts **technical
integrity only**: that members are present, byte-identical to their manifest digests, canonically
encoded, and internally consistent. It does NOT assert factual truth, commercial truth, legal
validity, compliance approval, or fraud detection. It does NOT re-execute recorded rules. It
does NOT evaluate whether any recorded review action was correct. Recording that a human
performed an action is evidence that the action occurred — never evidence that it was right.

---

## 2. Pack Layout

A decision evidence pack is a directory containing exactly:

| Path | Role | Required | Content |
| :--- | :--- | :--- | :--- |
| `manifest.json` | — | Yes | SHA-256 manifest covering every member (see §5) |
| `case.json` | `case` | Yes | Case identity and lifecycle record |
| `facts.json` | `facts` | Yes | Recorded input facts with source attribution |
| `rule_runs.json` | `rule_runs` | Yes | Executions of versioned rules-as-data over facts |
| `findings.json` | `findings` | Yes | Findings derived from rule runs |
| `review_actions.json` | `review_actions` | Yes | Human/system review actions |
| `timeline.json` | `timeline` | Yes | Ordered event log |
| `snapshot_context.json` | `snapshot_context` | Yes | Content-addressed snapshot of the source context |
| `artifacts/…` | `artifact` | No | Opaque artifact files referenced by digest |
| `manifest.dsse.json` | — | Optional | DSSE v1 envelope signing the exact manifest bytes |

The seven required core members (fixed paths, fixed roles) are the case record plus the six
decision members (facts, rule runs, findings, review actions, timeline, snapshot context).

Every member document MUST conform to its JSON Schema (Draft 2020-12) in `schemas/`:
`decision-pack-case.schema.json`, `decision-pack-facts.schema.json`,
`decision-pack-rule-runs.schema.json`, `decision-pack-findings.schema.json`,
`decision-pack-review-actions.schema.json`, `decision-pack-timeline.schema.json`,
`decision-pack-snapshot-context.schema.json`, and `decision-pack-manifest.schema.json`.

A verifier MUST reject any file in the pack directory that is not a listed member, the manifest,
or a recognized `manifest.dsse.json` envelope.

---

## 3. Deterministic Canonical Encoding

Everything that is hashed or signed MUST be deterministic:

1. **JSON members** (`*.json` except `manifest.dsse.json`) are stored as RFC 8785 (JCS)
   canonicalized UTF-8 bytes with **no trailing newline**. A verifier MUST re-canonicalize each
   parsed member and reject the pack if the stored bytes differ (`NOT_CANONICAL`).
2. **Artifact members** are hashed over their raw stored bytes (`canonicalization: "raw"`);
   their internal format is out of scope.
3. All digests use the explicit prefix form `sha256:<64 lowercase hex characters>`.
4. All timestamps are ISO 8601 UTC in the exact form `YYYY-MM-DDTHH:MM:SSZ`.
5. Integers MUST remain within the IEEE 754 safe domain `[-(2^53 - 1), 2^53 - 1]`; values that
   require exact decimal representation (amounts, measurements, ratios) MUST be encoded as
   strings (see `value_type: "decimal_string"` in the example).
6. Rule definitions are content-addressed: each `rule.rule_digest` is
   `sha256:` + hex(SHA-256(JCS(rule definition object without `rule_digest`))), pinning the
   exact rule-as-data that produced the recorded outcome.

---

## 4. Member Semantics (Honest Vocabularies)

### 4.1 Facts
A fact is a **recorded observation** attributed to a `source` and `observed_at` time, optionally
bound to a snapshot source by `snapshot_source_id`. A fact is not asserted to be true; it is
asserted to have been recorded.

### 4.2 Rule Runs — outcome vocabulary
Rule runs record what actually happened during execution. Generic success/failure booleans are
prohibited. Each run MUST record exactly one outcome:

| Outcome | Definition |
| :--- | :--- |
| **`TRIGGERED`** | The rule evaluated and its condition matched, producing outputs. |
| **`NOT_TRIGGERED`** | The rule evaluated and its condition did not match. |
| **`REVIEW_REQUIRED`** | The rule defers the decision to a human reviewer by design. |
| **`UNVERIFIABLE`** | Required inputs were missing or insufficient; the run did not reach a triggered/not-triggered conclusion. |
| **`HASH_MISMATCH`** | An input referenced by digest did not match its recorded content at execution time; the run aborted fail-closed. |

Each run records the consuming fact ids in `inputs[]`, the executing identity in `executed_by`,
and the execution time. OEVP v0.2 records rule definitions and outcomes; it does not prescribe a
condition language and does not re-execute conditions.

### 4.3 Findings — severity vocabulary
A finding references the `rule_run_id` that produced it and carries one severity label:
`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. A finding is a recorded output of a rule
execution; it is not an asserted fact.

### 4.4 Review Actions — action vocabulary
`APPROVE`, `REJECT`, `REQUEST_CHANGES`, `ESCALATE`, `COMMENT` — performed by an identified
`actor` (opaque id; `actor_type: "human"` or otherwise) at `performed_at`, optionally
referencing findings or rule runs. The pack records the action as performed; it never certifies
the action's correctness or the actor's judgment.

### 4.5 Timeline
Events carry a monotonically strictly increasing `sequence` (per pack), an `event_type`
(lowercase dotted token, e.g. `case.opened`), an occurrence time, and optional references to
facts, rule runs, findings, review actions, artifacts, or snapshot sources. Verifiers MUST
reject duplicate ids, non-increasing sequences, and references that do not resolve within the
pack.

### 4.6 Snapshot Context
The snapshot binds the decision to the source state it was made against: a `snapshot_id`, the
capture time, and content-addressed `sources[]` (each with `source_id`, `kind`, and `sha256`
digest of the captured source content). Facts may reference snapshot sources; the replay safety
rules in §8 pin any later replay to the exact snapshot.

---

## 5. Manifest & Pack Digest

The manifest is the integrity anchor of the pack.

1. `members[]` covers **every** pack member: core JSON documents, artifacts, and any future
   member type. Each entry records `path`, `role`, `media_type`, `canonicalization`,
   `size_bytes`, and `sha256` over the exact stored bytes.
2. `members[]` MUST be in **stable order**: lexicographically sorted by `path` byte-wise.
   Duplicate paths are prohibited.
3. The seven core members MUST be present with their exact fixed paths and roles (§2). Artifact
   members MUST live under `artifacts/`.
4. `manifest.json` and `manifest.dsse.json` are never listed as members.

**Pack digest recursion rule** (mirrors the receipt self-digest rule):

1. Let `manifest_unsigned_body` be the manifest object **omitting** the `pack_digest` key.
2. Canonicalize it with RFC 8785 (JCS).
3. `pack_digest = "sha256:" + hex(SHA-256(JCS(manifest_unsigned_body)))`.
4. Verifiers recompute by removing `pack_digest`, canonicalizing the remainder, and comparing
   against the declared value.

---

## 6. DSSE Manifest Binding (Optional)

The manifest MAY be signed with DSSE v1 (Ed25519, matching the receipt binding in
`dsse-binding.md`):

- `payloadType`: `application/vnd.oev.decision-pack-manifest+json`
- `payload`: the **exact canonical bytes of `manifest.json`** (Base64), not a re-serialization.
- The envelope is stored as `manifest.dsse.json` inside the pack directory. It is not a pack
  member and is not covered by the manifest (a manifest cannot cover its own signature).

Verifiers MUST reject an envelope whose payload does not equal the stored manifest bytes.
The signature entry MAY additionally embed the signer's public key as an
unauthenticated hint (`public_key_pem`), so any third party can verify the signature
math offline without trust roots; embedded keys NEVER bootstrap trust.
As with receipts, the DSSE `keyid` is an unauthenticated hint; a signer is trusted only if its
public key matches a caller-supplied trust root. An unsigned pack or an untrusted signer does
not by itself invalidate pack integrity — trust evaluation is reported separately.

---

## 7. Verification Procedure

`oev pack verify <dir>` performs, in order:

1. Manifest schema validation and canonical-storage check of the manifest bytes.
2. Manifest self-digest (`pack_digest`) recomputation.
3. Stable-order and duplicate-path check of `members[]`.
4. Core member presence with correct fixed paths and roles.
5. Per-member checks: existence, size, SHA-256 digest, and canonical encoding (JSON members).
6. Unlisted-file detection (strict directory walk).
7. Cross-member referential integrity: fact/run/finding/action id uniqueness, run inputs →
   facts, findings → rule runs and facts, review actions → findings/runs, timeline sequence
   monotonicity and reference resolution, facts → snapshot sources, and `case_id` consistency
   across all members and the manifest.
8. If present: DSSE envelope payload binding and caller-supplied trust evaluation.

The overall result is `PACK_VALID` or `PACK_INVALID`. Signature trust is reported separately
and never upgrades an invalid pack to valid.

**Exit codes**: `0` valid (and trusted where trust roots were supplied); `1` invalid; `2` valid
pack whose signature fails trust — including the case where the caller supplied trust roots and
the pack carries **no** signature at all (a stripped signature must be a visible trust failure,
never silent success).

### 7.1 Portable pack verification receipt (`oev-pack-receipt/0.1`)

Any `oev pack verify` run MAY emit a **pack verification receipt** (`--out`), a portable,
self-digested JSON document that records what the verifier checked — so a third party can
inspect the claim later, offline, even if the verifier is gone. The receipt asserts technical
integrity only; it is never a factual, legal, or compliance conclusion.

1. **Content.** The receipt MUST record: the protocol version (`oev-pack-receipt/0.1`), a
   `receipt_id` (UUID), the `pack_id` and `case_id`, the manifest's declared pack digest and the
   verifier's recomputed pack digest (both possibly empty when the manifest was unreadable) with
   an explicit `pack_digest_valid` flag, the overall verdict (`PACK_VALID` / `PACK_INVALID`), the
   honest three-way `signature_state` of the pack at verification time (§6), the verification
   time (`verified_at`, exact `YYYY-MM-DDTHH:MM:SSZ` form), the verifier identity
   (`verifier.software`, `verifier.version`), the **complete ordered check vector** — every check
   with one exact status `PASS`, `FAIL`, `NOT_RUN`, `NOT_APPLICABLE`, or `UNVERIFIED` and a note —
   the per-member results, any unlisted files, and all structure errors. A check that was not
   performed MUST be recorded as `NOT_RUN` (or `NOT_APPLICABLE`/`UNVERIFIED` where the check
   vocabulary defines it), never silently omitted.
2. **Self-digest.** `receipt_digest` uses the same recursion rule as the pack manifest (§5):
   `"sha256:" + hex(SHA-256(JCS(receipt body without the receipt_digest key)))`. Third parties
   recompute by removing `receipt_digest`, canonicalizing the remainder, and comparing.
3. **Schema.** Receipts MUST conform to `pack-verification-receipt.schema.json` (Draft 2020-12),
   which pins the check ids, the status vocabulary, and the three-way `signature_state` enum.
4. **Optional DSSE signature.** The receipt MAY be signed (`oev pack verify --sign-receipt`)
   with DSSE v1 / Ed25519: `payloadType`
   `application/vnd.oev.pack-verification-receipt+json`, `payload` the exact canonical receipt
   bytes. The signer's public key MAY be embedded in the signature entry as an unauthenticated
   hint (as with packs and receipts, `keyid` and embedded keys never bootstrap trust).
5. **Third-party offline verification** (`oev pack receipt verify`): the receipt is verified
   without the pack by (a) schema validation, (b) self-digest recomputation, and (c) the honest
   three-way signature state of its envelope. When the pack directory is available, the verifier
   additionally re-computes the pack digest of the on-disk manifest and reports an explicit pack
   binding: `PACK_BINDING_MATCH`, `PACK_BINDING_MISMATCH` (the receipt describes different pack
   bytes — invalid), or `PACK_BINDING_NOT_RUN`. Overall result is `RECEIPT_VALID` or
   `RECEIPT_INVALID`.
6. **Honesty of receipts of failed verifications.** A receipt recording a failed verification is
   itself an intact, verifiable record of that failure: `RECEIPT_VALID` means "this receipt is
   intact and says what its verifier recorded" — it never implies `PACK_VALID`, and it never
   upgrades the pack it describes.
7. **Exit codes** (`oev pack receipt verify`): `0` receipt valid (and signature
   valid/trusted where applicable); `1` receipt invalid; `2` receipt valid but its envelope
   signature is not established valid or its signer is not trusted.

---

## 8. Snapshot Replay Safety

v0.2 does **not** re-execute rules. What v0.2 does provide is the *safety gate* that any later
replay must pass (`oev pack replay`, `oev.replay.replay_snapshot`). The gate enforces four rules,
in order:

1. **Integrity first.** The pack must verify as `PACK_VALID` (§7) before any replay evaluation.
   A technically invalid pack is never replayed (`PACK_INVALID`).
2. **Pin before replay.** Replay callers SHOULD pin the pack out-of-band: record
   `pin_pack()`'s `{pack_id, case_id, pack_digest}` when the pack is accepted, and pass
   `expected_pack_digest` on every later replay. If the pack's recomputed digest differs from
   the pin, replay MUST refuse (`PACK_HASH_CHANGED`) — even when the manifest was rewritten
   fully self-consistently (member digests and `pack_digest` all agree), because only the
   external pin anchors "the pack I originally accepted".
3. **Snapshot isolation.** The replay scope of a snapshot contains exactly the facts that are
   (a) bound to a source of that snapshot via `snapshot_source_id`, and (b) observed at or
   before `captured_at`. Evidence observed after the capture time, evidence not bound to the
   snapshot, and evidence bound to unknown sources MUST be excluded from the replay scope and
   reported with the exclusion reason. A fact whose `observed_at` equals `captured_at` is in
   scope (the boundary is inclusive). A fact whose `observed_at` cannot be parsed as a strict
   UTC timestamp is excluded (fail closed: unprovable is out of scope).
4. **Leak refusal.** If a recorded rule run consumed a fact that was observed after the
   snapshot was captured, the recorded history contradicts the snapshot boundary. Replay MUST
   refuse the entire evaluation (`SNAPSHOT_LEAK`) rather than silently re-scoping the run.

**Trust gate.** If the caller supplies verifier trust roots, replay additionally requires the
manifest to carry a signature from a trusted key (`SIGNATURE_UNTRUSTED` otherwise). This makes
both signature stripping and signature replacement block replay for callers who pin trust roots.
Without pinned roots, replay proceeds on integrity alone — an unsigned pack is replayable, which
is a property of integrity, not an endorsement.

**Status vocabulary** (exactly one): `REPLAY_OK`, `PACK_INVALID`, `PACK_HASH_CHANGED`,
`SIGNATURE_UNTRUSTED`, `SNAPSHOT_INVALID` (the snapshot boundary itself is unusable, e.g. an
unparseable `captured_at`), `SNAPSHOT_LEAK`.

**CLI exit codes** (`oev pack replay`): `0` `REPLAY_OK`; `1` input error or `PACK_INVALID`;
`2` every other refusal.

Replay safety is still technical integrity only: it says *which evidence a replay may consume
and which pack bytes it may consume them from*. It does not assert that the snapshot was honest,
that the facts are true, or that any recorded outcome was correct.

---

## 9. Pack Archive (ZIP) Transport Safety

A pack is a directory format; a ZIP file is only a transport envelope for it. Because an
archive is untrusted input the moment it changes hands, extraction MUST fail closed:

1. **Validate everything before extracting anything.** No file may be written until every
   entry has passed validation; a rejected archive must leave the target directory untouched.
2. **Reject path traversal.** Entry names that are absolute, contain `..` or `.` path
   segments, backslashes, or drive letters MUST be rejected (zip-slip).
3. **Reject duplicate members.** Two entries claiming the same name MUST be rejected: a
   duplicate is either corruption or an attempt to shadow a file with different content.
4. **Reject encrypted entries and enforce bounds.** Per-entry and total uncompressed size
   limits MUST be enforced against the declared entry sizes before extraction (decompression
   bomb), and encrypted entries are out of scope.
5. **Re-verify after extraction.** Extraction safety and pack integrity are independent:
   always run §7 verification (`oev pack verify`) on the extracted directory.

`oev.pack_archive.create_pack_archive` writes a deterministic archive (sorted entries, fixed
metadata) so transport bytes are reproducible; `extract_pack_archive` / `inspect_pack_archive`
implement the rules above.

---

## 10. Explicit Non-Goals

The decision pack format explicitly does NOT provide:

- **Factual or commercial truth** of recorded facts, findings, or decisions.
- **Legal validity or compliance approval** — a valid pack is not a legal or regulatory conclusion.
- **Fraud detection** — pack verification detects byte tampering, not deception.
- **Rule re-execution** — v0.2 records rules-as-data and outcomes, plus the replay *safety
  gate* of §8; actually re-evaluating rule conditions remains future work.
- **Trusted timestamps** — all recorded times are unauthenticated clock readings; snapshot
  `captured_at` bounds the replay scope but proves nothing about when evidence really arrived.
- **Non-equivocation** — two contradictory packs can both be internally valid; transparency
  services (e.g. RFC 9943) are required to detect equivocation.
