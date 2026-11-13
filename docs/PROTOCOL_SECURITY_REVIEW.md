# Protocol Security Review — Historical Execution Attestation v0.1

Status: Pre-1.0 Draft, 2026-11-13. Scope: the HEA v0.1 Model A
implementation in `oevp/` (and the `execution_binding` pointer in
`oept/`). This is the document that defines the **C1–C10 attack
taxonomy** (it does not exist in code — code uses attack-scenario
names — to avoid colliding with the benchmark vocabulary).

Companions: `docs/THREAT_MODEL.md` (HEA threat model),
`spec/execution-attestation-spec.md`,
`spec/execution-log-spec.md`, design doc
`docs/HISTORICAL_EXECUTION_ATTESTATION.md` (§6–§9).

## 1. C1–C10 attack taxonomy (normative for this review)

| ID | Attack class | What the attacker does |
| --- | --- | --- |
| C1 | **Replay / substitution** | Re-presents a genuine attestation/receipt against a different package, profile, or execution |
| C2 | **Forged PASS** | Writes PASS (and a receipt) for a check that never ran, without any witness attestation |
| C3 | **Receipt tampering** | Flips a check result in the receipt after attestation (with or without recomputing the receipt digest) |
| C4 | **Nonexistent execution claim** | Claims an execution that never happened and demands it be treated as disproven/false |
| C5 | **Log manipulation** | Deletes, reorders, alters or withholds log events; forges a checkpoint |
| C6 | **Freshness / supersession abuse** | Presents a stale or superseded receipt/attestation as current |
| C7 | **Witness compromise & role confusion** | Steals or misuses a witness key; uses a receipt key to attest, or a witness key to checkpoint |
| C8 | **Time forgery (backdating)** | Writes a false `claimed_time` (past or future) into commitments, attestations, or log events |
| C9 | **Signature violation** | Invalid signature, untrusted signing key, or use of the committed test-only key |
| C10 | **Fake execution / misreported result** | Runs different code than claimed, or reports a result the log does not support |

## 2. Threat model ↔ provable properties

| Attack | Detected in v0.1? | Mechanism (verifier step) | Evidence |
| --- | --- | --- | --- |
| C1 replay/substitution | **Yes** | Attestation binds `bundle_digest` + `profile_digest` + `code_digest` + `nonce` + `execution_id`; any substitution breaks the recomputed Execution ID or a digest check (steps 2–3) | hea-12, hea-13 |
| C2 forged PASS (no attestation) | **Yes, as UNPROVEN** | No attestation exists → `NO_ATTESTATION` (step 0). Note: this does not prove the PASS is false — only that its execution is unproven | hea-02 |
| C3 receipt tampering | **Yes** | Receipt self-digest fails (fail-closed in reverify) and attestation `result_status` ≠ receipt status → `RESULT_CONFLICT` (step 6) | hea-03 |
| C4 nonexistent execution | **Only as DISPROVEN, narrowly** | All three §7.2 conditions (complete signed log + no `EXECUTION_STARTED` + signed completeness statement) → `DISPROVEN`; otherwise `UNPROVEN` (step 0) | hea-14 |
| C5 log manipulation | **Yes, after checkpoint** | Hash chain (`LOG_GAP`/`LOG_ANCHOR_INVALID`), Merkle root vs signed checkpoint, inclusion proofs, `MISSING_EXECUTION_STEP` for a missing start (step 5) | hea-06, hea-07 |
| C6 freshness/supersession | **Partially — see §4** | Supersession is visible through `superseded_receipt` chaining and profile-digest mismatch; *staleness itself* is not detectable offline | — |
| C7 witness compromise | **Partially — see §5** | Role separation (witness ≠ checkpoint-signer ≠ receipt-signer), key expiry, retroactive revocation; a stolen witness key is undetectable until revoked. Since round 3 the witness-authorisation document is schema-bound (`oev-witness-authorization/0.1`); with `--require-witness-authorization` a missing/invalid/non-matching document fails closed as `WITNESS_UNAUTHORIZED` (step 4) | hea-08, hea-09, hea-10, `tests/test_witness_authorization.py` (10 tests) |
| C8 time forgery | **No (forgery) — but malformed time is rejected, see §5** | `claimed_time` is self-asserted; only log `seq` ordering is proven. Backdating is **not prevented** in v0.1. A *malformed* timestamp (non-UTC shape, impossible date) is a controlled rejection (`MALFORMED_ATTESTATION`, UNPROVEN) since round 3 — never an uncaught exception | `tests/test_hea_timestamps.py` (11 tests), malformed-timestamp fixture |
| C9 signature violation | **Yes** | `SIGNATURE_INVALID` (trusted key, bad crypto), `SIGNATURE_UNTRUSTED` (unknown key), test-key blocklist (skipped even when in the store) (step 4) | hea-04, hea-05, hea-11 |
| C10 fake execution / misreported result | **Yes, when the log disagrees** | `code_digest` binding catches different code; since round 3 a caller-supplied code-digest document (`oev-code-digest/0.1`) additionally pins `policy_digest`, dependency versions and the environment record — any mismatch is `CODE_DIGEST_MISMATCH` (step 3b). Attestation result vs log `event_digest` vs receipt result must all agree (steps 3, 5, 6). A same-machine staged execution is **not** detectable in Model A | hea-03 (result side), `tests/test_code_digest.py` (9 tests) |

Conformance vectors hea-01..hea-20 (`conformance/vectors-hea/`,
runner `conformance/run_hea_vectors.py`) cover every row marked
"Yes" above; rows marked "Partially"/"No" are covered by the explicit
limits in §5, not by a passing vector.

## 3. CheckStatus semantics (formalised in v0.1)

`CheckStatus` (`src/oev/models.py`) names the **outcome of a check**;
HEA names the **evidence for the execution**. They are independent
dimensions (§7.5 of the design doc).

| Status | Meaning | Merge rule |
| --- | --- | --- |
| `PASS` | The check ran and its condition held | Counts toward `TECHNICAL_CHECKS_PASSED` |
| `FAIL` | The check ran and its condition did not hold | A proven FAIL is a proven execution — HEA proves execution, not success |
| `NOT_RUN` | The check was skipped before running (dependency failed, execution interrupted) | Never attested; HEA state `HEA_NOT_APPLICABLE`. Never counted as a success |
| `NOT_APPLICABLE` | The check does not apply to this package/profile | Never attested; `HEA_NOT_APPLICABLE` |
| `UNVERIFIED` | The check ran but its outcome could not be established (e.g. missing trust context) | Attested as `UNVERIFIED` (the run happened; the outcome is unknown) |
| `UNSUPPORTED` | The verifier cannot perform this check in this environment | Attested as `UNSUPPORTED` (the run happened; the capability is absent) |

Two distinctions the old code blurred, now enforced:

- **Missing profile check vs failed check.** A profile-required check
  absent from the receipt is `MISSING_FROM_RECEIPT` (reverify step
  4b) — a structural gap, not a FAIL. A check present with status
  `FAIL` is a completed, failed check. They are different findings
  with different remedies.
- **Missing profile vs failed check (input side).** A missing or
  unreadable profile file is an input error (`CANNOT_REPRODUCE`),
  not a check failure. A profile that loads but whose digest differs
  from the receipt's is `PROFILE_DIGEST_MISMATCH` (HEA) /
  `CANNOT_REPRODUCE` (reverify).

## 4. C6 — freshness / supersession, offline limits

HEA v0.1 is offline and has no clock it trusts, so freshness has a
hard limit:

- **What is detectable:** a receipt that supersedes another
  (`superseded_receipt`) is linked explicitly; a receipt presented
  against a *different* (newer) profile fails with
  `PROFILE_DIGEST_MISMATCH`; a receipt whose inputs changed fails
  re-verification (`MISMATCH`).
- **What is NOT detectable:** that a receipt is *old*. An attested
  execution from last year verifies as PROVEN today, forever, unless
  its witness key is revoked or expires. There is no "receipt is stale
  after N days" rule in v0.1, and no offline way to know whether a
  newer receipt for the same package exists.
- **Consequence for consumers:** freshness is a *policy* decision for
  the relying party (e.g. "accept receipts attested within the last
  90 days, by claimed_time — knowing claimed_time is unproven"), not
  a protocol property. Do not present PROVEN as "current".

## 5. Explicitly unprovable claims (v0.1)

These are not limitations of the implementation; they are properties
the protocol **cannot** establish in Model A. Any claim to the
contrary is a misrepresentation.

1. **Backdating is not prevented (C8).** No TSA, no trusted clock.
   `claimed_time` is self-asserted everywhere (commitment,
   attestation, log, checkpoint, revocation list). Log `seq` proves
   order only.
2. **Same-machine staging is not detectable (C10, Model A).** The
   witness observes digests and files the producer provides on the
   same machine. A producer that fabricates those inputs defeats
   observation. Remote/TEE witnesses (Model B/C) are future work.
3. **Witness honesty is assumed, not proven (C7).** A compromised
   witness key can sign false commitments and attestations until the
   compromise is noticed and the key revoked. Revocation is
   retroactive *once distributed*; distribution is out-of-band.
4. **Non-equivocation is not provided.** A malicious witness can show
   different attestations to different verifiers. No transparency log
   exists in v0.1.
5. **Completeness without operator cooperation is not provable (C4/C5).**
   A log that never checkpoints, or a log whose operator will not sign
   a completeness statement, can hide deletions. Absence from such a
   log is UNPROVEN, never DISPROVEN.
6. **Code identity is partial (C10) — unless the caller pins more.** The
   in-attestation code digest covers the `oev` package + Python
   version, not third-party dependencies. Since round 3 a verifier
   may supply a code-digest document (`oev-code-digest/0.1`) that
   pins `policy_digest`, dependency name→version pairs and the
   environment record; any mismatch is `CODE_DIGEST_MISMATCH`.
   Without the document, dependency versions are unchecked.
7. **Revocation freshness is not provable offline.** A verifier with
   an old revocation list accepts a key revoked after the list was
   issued. Absence of a list is reported as "unknown", never as
   "not revoked".
8. **Factual truth, legal validity, and compliance are out of scope.**
   HEA proves an execution happened as attested; it says nothing
   about whether the evidence, the profile, or the check itself is
   correct, lawful, or sufficient.
9. **Witness authorisation is schema-bound but opt-in by default
   (C7).** The document format is specified
   (`oev-witness-authorization/0.1`); the default verifier behaviour
   is unchanged (a missing document is a note, not a failure), and
   the document itself is not signed in v0.1. Only
   `--require-witness-authorization` enforces it fail-closed.

## 6. C9 vs C10 split (why they are separate classes)

C9 and C10 are often conflated ("the attestation is fake"); they are
different failures with different remedies:

- **C9 — signature violation.** The *signature* is wrong: bad crypto
  (`SIGNATURE_INVALID`), unknown key (`SIGNATURE_UNTRUSTED`), wrong
  role (`WITNESS_UNAUTHORIZED`), or a blocklisted test key
  (hea-11, surfacing as `SIGNATURE_INVALID`). Remedy: fix the key
  material / trust store. The execution itself may have been real.
- **C10 — fake execution / misreported result.** The *signatures* are
  fine but the *content* lies: different code than claimed
  (`CODE_DIGEST_MISMATCH`), a result the log does not support
  (`RESULT_CONFLICT`, `MISSING_EXECUTION_STEP`), or a staged
  same-machine execution (undetectable in Model A). Remedy: re-run
  under an honest witness; no key rotation fixes a staged run.

A single bad attestation can be both C9 and C10, but the verifier
reports the first failure in step order (signature checks, step 4,
precede content checks, steps 5–6).

## 7. Deviations from the design doc (implemented v0.1)

| # | Design doc | Implemented | Rationale |
| --- | --- | --- | --- |
| D1 | §6 step 2 names `RECEIPT_INVALID` | Receipt self-digest failure maps to `RESULT_CONFLICT` | `RECEIPT_INVALID` is not in the §7.3 code list; a re-finalised tampered receipt is a result conflict, and the code list is normative |
| D2 | §5.2 names `attestation_id` after the execution only | `att_` + first 16 hex of `SHA-256(execution_id + ":" + check_id)` | Per-check attestations must stay distinct |
| D3 | Code digest scope unspecified (§5, Ek B Q1) | All `.py` files under the installed `oev` package + Python version; third-party deps excluded | Reproducible, minimal, honest scope; deps are out of scope in v0.1 |
| D4 | Revocation timing unspecified | Revocation is **retroactive**: a listed key's attestations are rejected regardless of claimed time | Claimed time is untrusted, so a time-bounded revocation would be meaningless |
| D5 | §7.3 has no `ATTESTATION_UNTRUSTED` code | Unknown signers are `SIGNATURE_UNTRUSTED`; trusted-but-wrong keys are `SIGNATURE_INVALID` | The §7.3 list is normative and has no attestation-specific untrusted code; the two codes cover the cases |
| D6 | §7.2 DISPROVEN conditions | Implemented as specified; default is always `UNPROVEN` | — |
| D7 | Commitment carries the pre-binding | `hea attest` also writes `prebinding.json`; the verifier recomputes the Execution ID from it | The commitment digest alone lacks `trust_inputs_digest` / `execution_context` |
| D8 | Float handling unspecified | Finite floats are accepted on both sides per RFC 8785 §3.2.2.3 (ECMAScript `Number::toString`); non-finite values are rejected; lone surrogates are rejected per §3.2.2.2; duplicate JSON members and invalid UTF-8 are rejected with structured errors | Round 3 decision (2026-11-13): the RFC is the normative spec both sides claim; OEVP + Node already accepted finite floats and agreed, OEPT was the outlier. Three-way differential 403/403 |
| D9 | Pin-less replay returned `REPLAY_OK` + note | Pin-less replay is REFUSED by default (`PINLESS_REPLAY_REFUSED`, exit 2) unless the caller explicitly opts in (`--allow-pinless-replay` / `allow_pinless=True`) | Round 3 decision (2026-11-13): the measured 0/60 case showed a silent `REPLAY_OK` is not a proof; fail-closed by default, explicit opt-in for self-consistency-only checks |
| D10 | Timestamp shape unspecified beyond schema | `claimed_time` / `issued_at_claimed` / `revoked_at_claimed` must match `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$` in the schemas AND be semantically valid (real calendar date, hour < 24); malformed values are `MALFORMED_ATTESTATION`, never an uncaught exception | Round 3 fix (2026-11-13): a validly signed attestation with a garbage `claimed_time` crashed the verifier with an uncaught `ValueError` |

## 8. Security-relevant implementation notes

- **Bounds everywhere:** attestations ≤ 1024; log events ≤ 1,000,000;
  log files ≤ 10 MiB; revocation entries ≤ 1024; attestation detail
  ≤ 1024 chars; DSSE signatures ≤ 32 (inherited). Oversized inputs
  fail closed, never truncated silently.
- **Canonicalisation:** all digests and signatures are over RFC 8785
  (JCS) canonical JSON. Duplicate JSON keys are rejected at parse
  time (see `tests/test_hea_fuzz.py`). Since round 3 (2026-11-13):
  finite floats are accepted per RFC 8785 §3.2.2.3, lone surrogates
  are rejected per §3.2.2.2, invalid UTF-8 is rejected with a plain
  structured `ValueError` (never a bare codec error), and the three
  implementations (Node, OEVP, OEPT) agree 403/403 on the
  differential corpus (`docs/JCS_MISMATCH_LIST.md`).
- **Replay gate (round 3):** an unanchored replay is refused by
  default (`PINLESS_REPLAY_REFUSED`); the explicit opt-in
  (`--allow-pinless-replay`) restores the old self-consistency-only
  `REPLAY_OK`, which still carries the no-anchor note. See
  `docs/THREAT_MODEL.md` §8.
- **Path traversal / ZIP bombs:** the HEA flow verifies the package
  through the existing OEPT adapter first; hostile archives fail
  their checks and the *failure* is what gets attested (a proven
  failure, not a hidden one — see `tests/test_hea_cli.py`).
- **Verifier independence:** `src/oev/hea_verifier.py` imports only
  protocol-core modules (`execution`, `attestation`,
  `execution_log`, `revocation`, `canonical`, `dsse`, `hashing`,
  `models`, `receipts`, `trust`, `profiles`, `schemas`). It never
  imports the engine, adapters, replay, CLI, or witness code, so a
  verifier built from it cannot be confused by producer code
  (`tests/test_hea_verifier_independence.py` enforces this
  mechanically, including a clean-directory run).
- **Key handling:** the separate-process witness
  (`LocalProcessWitness` + `witness_worker.py`) keeps the witness
  private key inside the worker process; it is never passed to the
  orchestrator. The checkpoint key is a *different* key by
  construction (`WitnessService.checkpoint()` refuses the witness
  key).
- **Test-only key:** the committed OEPT conformance test-only key is
  refused as a witness key at three layers: `WitnessService`
  construction, `sign_attestation_dsse`, and verifier-side blocklist
  skip. Its public-key digest is
  `sha256:7b62577c0ed2710b0d171aa4bdb96834ccacdd91e73ab115f73b38130369656b`.

## 9. Residual risks (accepted for v0.1)

| Risk | Severity | Mitigation / next step |
| --- | --- | --- |
| Backdating (C8) | High for time-sensitive reliance | TSA support in v0.2; until then, never rely on `claimed_time` |
| Same-machine staging (C10) | High for adversarial producers | Remote witness (Model B) in a later version |
| Witness key theft before revocation (C7) | Medium | Short key lifetimes (`not_after` mandatory), revocation lists, rotation |
| Stale revocation lists (C7) | Medium | Fresh lists per verification; distribution is operator responsibility |
| No non-equivocation (C5/C7) | Medium | Transparency log / gossip in a later version |
| Dependency-blind code digest (C10) | Low | Partially addressed in round 3: a caller-supplied code-digest document (`oev-code-digest/0.1`) pins dependency versions + environment; the in-attestation digest itself is still dependency-blind, and the document is opt-in |

## 10. Verification of this review

- Unit / integration / property / fuzz tests: `tests/test_hea_*.py`,
  `tests/test_attestation.py`, `tests/test_execution_*.py`,
  `tests/test_revocation.py`, `tests/test_status_semantics.py`
  (583 OEVP tests passing, round 3 re-run 2026-11-13,
  `/tmp/venv-r2-clean/bin/python -m pytest -q`; OEPT 145 passed).
- Conformance vectors hea-01..hea-20: 20/20 pass
  (`python conformance/run_hea_vectors.py run`).
- OEPT `execution_binding`: 27 tests
  (`tests/test_execution_binding.py` in `oept/`).
- Benchmarks (measured, not estimated): see §11.

## 11. Benchmarks (measured 2026-11-13)

Measured on this machine (Linux x86_64, Python 3.12.3, 1.5 shared
vCPUs, `/tmp/hea_bench.py`, median of 5 runs unless noted):

| Measurement | Result |
| --- | --- |
| (a) 1000-event log checkpoint verification (chain + checkpoint signature + Merkle root recomputation) | **58.04 ms** |
| (b1) Single Merkle inclusion-proof verification in a 10000-leaf tree (median of 20) | **0.027 ms** |
| (b2) All 10000 inclusion proofs verified (median of 3) | **293.77 ms** |
| (c1) Plain `reverify` of conformance fixture 01 | **3.22 ms** |
| (c2) HEA offline verification of a 2-check bundle | **4.83 ms** |
| (c) Ratio HEA verify / plain reverify | **1.50×** (different inputs — synthetic 2-check bundle vs fixture 01 — so indicative only, not a controlled overhead measurement) |

Interpretation: HEA verification is dominated by signature checks and
canonical JSON hashing, not by Merkle proofs (a single proof is ~30 µs).
Log verification scales linearly with event count (~58 µs/event at
1000 events, dominated by per-event leaf-hash recomputation). These are
single-machine numbers on shared vCPUs; treat them as order-of-magnitude
guidance, not SLAs.
