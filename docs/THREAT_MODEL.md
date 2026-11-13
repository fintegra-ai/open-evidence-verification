# HEA Threat Model (v0.1, Model A)

Status: Pre-1.0 Draft. Scope: Historical Execution Attestation as
implemented in `src/oev/execution.py`, `src/oev/attestation.py`,
`src/oev/execution_log.py`, `src/oev/revocation.py`,
`src/oev/hea_verifier.py`, `src/oev/witness.py` (+
`src/oev/witness_worker.py`), and `src/oev/hea.py`. The base OEVP
threat model (`spec/threat-model.md`) still applies to receipts,
re-verification and packs; this document covers only what HEA adds.

## 1. What HEA is for

A receipt says *what* a verifier observed. HEA answers a different
question: **did the claimed historical execution really happen, under
the claimed inputs, observed by the claimed witness?** It does this by
binding bundle + profile + code + nonce into an Execution ID, having a
witness commit to those inputs before execution, attesting each check
result as it happens, anchoring results in a hash-chained log under a
signed checkpoint, and binding attestations into the receipt digest.

## 2. Trust boundaries (non-negotiable)

- **Attested execution != true claim.** A proven FAIL is still a
  FAIL; a proven PASS proves the check ran and passed under the
  attested code — not that the underlying evidence is true.
- **Witness signature != witness honesty.** A signature proves key
  possession at signing time, not that the witness observed a real
  execution.
- **Local witness != independent witness.** In Model A the witness is
  a separate process on the **same machine** as the producer. It
  protects against a producer that lies in its own output files; it
  does **not** protect against machine compromise, a malicious
  producer that stages the witness's inputs, or a compromised witness
  process. Every Model A attestation carries the `WITNESS_LOCAL_ONLY`
  limitation saying exactly this.
- **Claimed time != proven time.** `claimed_time` is self-asserted.
  Ordering comes from log `seq` only. Backdating is **not prevented**
  in v0.1 (see §5).
- **Malformed time != crash.** Since round 3 (2026-11-13) a
  `claimed_time` (or commitment `issued_at_claimed`) that is not a
  strict UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`, semantically valid
  calendar date/time) is a controlled rejection, never an uncaught
  exception: the attestation/commitment verifies as
  `HISTORICAL_EXECUTION_UNPROVEN / MALFORMED_ATTESTATION`. This
  rejects *malformed* time; it does not prevent *forged* time (C8) —
  a well-formed false time still verifies.
- **NOT_RUN != PASS, and NOT_RUN has no attestation.** A check that
  never ran cannot have its execution proven; its HEA state is
  `HEA_NOT_APPLICABLE`.
- **UNPROVEN != invalid.** A receipt without attestations (pre-HEA, or
  attestations lost) is still a valid receipt; only its historical
  execution is unproven. Never treat UNPROVEN as a failed check.
- **PROVEN execution + MISMATCH re-verification is possible.** The two
  dimensions are independent (§7.4 of the design doc): history can be
  proven while today's re-run disagrees (code/profile/inputs moved),
  and vice versa. Never collapse them into one score.

## 3. Adversary capabilities

The attacker is assumed to be able to:

1. Generate arbitrary packages, profiles, receipts and DSSE envelopes.
2. Generate arbitrary Ed25519 keypairs and sign anything with them.
3. Intercept, replay, reorder, truncate or alter any artifact in
   transit or at rest (receipts, attestations, logs, checkpoints).
4. Run the producer on a machine they control (Model A: same machine
   as the witness).
5. Present stale receipts as current, and superseded receipts as live.
6. Attempt denial-of-service through oversized inputs (zip bombs,
   huge logs, thousands of attestations, deep JSON nesting).

The attacker is assumed **not** to be able to:

- Forge an Ed25519 signature under a key they do not hold.
- Find a SHA-256 preimage or second preimage (including the
  fixed-point a self-binding bundle would need — see §6).
- Break RFC 8785 canonicalisation.

## 4. Assets and what protects them

| Asset | Protected by | Not protected against |
| --- | --- | --- |
| Execution inputs (bundle/profile/code/nonce) | Pre-binding + Execution ID + witness commitment | A witness that signs a false commitment (key compromise, §5) |
| Per-check results | Per-check attestations + receipt `execution_attestations[]` (inside receipt digest) | A witness that attests results it did not observe |
| Execution ordering | Hash-chained log (`seq`, `prev_hash`, `leaf_hash`) | Withholding events before the first checkpoint (needs a completeness statement to detect) |
| Log integrity after checkpoint | Merkle root + signed checkpoint | A log operator that never checkpoints, or checkpoints a false log (operator is trusted for completeness) |
| Witness key | Role separation, expiry, revocation (retroactive), test-key blocklist | Key theft before revocation is noticed; revocation is only as fast as the list reaches verifiers |
| Receipt binding | Receipt self-digest + attestation digest cross-check | An attacker holding the receipt-signing key (can re-sign a forged receipt; attestations still disagree) |

## 5. Explicit limits of Model A (v0.1)

1. **Backdating is not prevented.** There is no trusted timestamp
   authority in v0.1. `claimed_time` is self-asserted by the witness;
   a witness (or producer) can write any time. Log `seq` proves order,
   not wall-clock time. A verifier MUST surface `TIME_NOT_PROVEN` and
   MUST NOT treat `claimed_time` as evidence of when something
   happened.
2. **Same-machine witness.** The witness observes digests the
   producer hands it and output files the producer writes. A producer
   that stages fake inputs on the same machine defeats observation.
   This is the documented Model A limitation, not a bug.
3. **No non-equivocation.** A malicious witness can sign two
   different commitments/attestations for the same execution id (or
   the same inputs with different nonces) and present different ones
   to different verifiers. v0.1 has no transparency log or gossip to
   detect equivocation.
4. **Code digest covers the `oev` package + Python version only —
   unless the caller pins more.** The in-attestation `code_digest`
   still covers `oev` sources + Python version; third-party
   dependencies are excluded from it. Since round 3 (2026-11-13) a
   verifier may additionally supply a code-digest document
   (`oev-code-digest/0.1`, `schemas/code-digest-0.1.schema.json`):
   `code_digest` + `policy_digest` + pinned dependency
   name→version pairs (+ optional digests) + environment record
   (Python version, OS, platform, venv fingerprint). Any mismatch
   between the document and the attested `code_version` record fails
   closed with `CODE_DIGEST_MISMATCH` (step 3b); a platform/OS
   difference is a note only, not a failure. The whole attested
   `code_version` record must also agree across all attestations of
   one execution. Without the document, dependency versions are
   unchecked — the document is the mechanism, and it is opt-in.
5. **Revocation is distribution-bound.** A revocation list only helps
   verifiers that have received it. There is no live revocation
   lookup in the offline verifier; absence of a list is reported as
   "revocation status unknown" (fail-explicit, not fail-open).
6. **DISPROVEN is narrow.** It needs a complete signed log *and* a
   signed completeness statement from the log operator. Without the
   operator's cooperation, a missing execution is UNPROVEN, never
   DISPROVEN.
7. **Witness authorisation is schema-bound since round 3
   (2026-11-13), but opt-in by default.**
   `oev-witness-authorization/0.1`
   (`schemas/witness-authorization-0.1.schema.json`) binds witness
   identity (`witness_key_id`, `issuer_key_id`), the profiles and
   checks the key may attest (`authorized_profiles`,
   `authorized_checks`), a validity window
   (`valid_from_claimed`/`valid_until_claimed`) and revocation. An
   empty `authorized_profiles` authorises NO profile (fail-closed);
   `authorized_checks` absent means no restriction, present-empty
   means none. Default v0.1 behaviour is preserved: a missing
   document is a note, not a failure. `--require-witness-authorization`
   fails closed: a missing, invalid, or non-matching document is
   `WITNESS_UNAUTHORIZED`. The document itself is not signed in v0.1
   (its binding to the witness key is by `witness_key_id` only).
8. **Canonicalisation is agreed three ways since round 3
   (2026-11-13).** Finite floats are accepted on all sides per RFC
   8785 §3.2.2.3 (ECMAScript `Number::toString`; non-finite values
   are rejected); lone surrogates are rejected on all sides per
   RFC 8785 §3.2.2.2; duplicate JSON members and invalid UTF-8 are
   rejected with structured errors, never codec internals or
   uncaught exceptions. Measured: three-way differential
   (Node vs OEVP vs OEPT) 403/403 agreement, including float,
   int-boundary (2**53), duplicate-key, surrogate, unicode and
   malformed-JSON cases (`docs/JCS_MISMATCH_LIST.md`).

## 6. The self-binding impossibility (OEPT side)

A bundle's manifest MAY carry an optional `execution_binding`
(`execution_id` + `commitment_digest`) pointing at the HEA execution
that attested it. A bundle **cannot** bind its own execution: the
Execution ID is derived from the bundle digest, and adding the binding
changes the manifest and therefore the digest — a SHA-256 fixed point
no producer can construct. The field is therefore always a pointer to
the execution of the bundle as built **without** the binding. OEPT
checks only the field's format; content verification happens on the
OEVP side against the bundle as presented. A verifier that wants to
match a manifest binding must recompute the digest of the unbound
bundle.

## 7. Out of scope (explicit non-goals)

- Proving factual truth of evidence, legal validity, or regulatory
  compliance.
- Real-time revocation, trusted timestamping, transparency logs,
  remote/TEE witnesses (Model B/C — future work).
- Protecting the producer's machine from its owner.
- Any claim about executions that predate HEA (no attestations exist
  for them by construction).

## 8. Replay without an anchor is unprotected (pin-less replay)

Measured: with a replay pin, a substituted pack is refused 60/60
(`PACK_HASH_CHANGED`); without a pin, 0/60 — a different, individually
valid pack replays as `REPLAY_OK` (benchmarks/RESULTS.md §6).

Why no in-pack mechanism can fix this: `pack_digest` is a self-digest
(SHA-256 over the JCS manifest without `pack_digest`). Any self-consistent
pack verifies against itself, and snapshot isolation / leak checks are
intra-pack coherence checks that a coherent substitute pack also passes.
Distinguishing "the pack I accepted" from "a different valid pack"
requires an external reference. The two anchors are:

- the out-of-band pin (`pin_pack()` → `expected_pack_digest`), or
- caller-supplied trust roots (a substitute pack is unsigned or signed by
  an untrusted key → `SIGNATURE_UNTRUSTED`).

A pack verification receipt (`oev-pack-receipt/0.1`) does not add a third
anchor: an unsigned receipt for a substitute pack is as forgeable as the
pack itself, and a receipt signed by a trusted verifier key is the same
trust class as the trust-store anchor. No receipt parameter was therefore
added to the replay API (decision 2026-11-13, Görev C — document honestly,
do not add a mechanism that cannot change the measured 0/60).

Consequences:

- **Since round 3 (2026-11-13) a pin-less replay is REFUSED by
  default, not `REPLAY_OK`.** `replay_snapshot()` returns
  `PINLESS_REPLAY_REFUSED` (and `oev pack replay` / the Node CLI
  exit 2) when no pin and no trust roots were supplied and the
  caller did not explicitly opt in. The opt-in is
  `--allow-pinless-replay` (CLI) / `allow_pinless=True` (API) /
  `allowPinless` (Node), and an opt-in `REPLAY_OK` still carries
  the no-anchor note in `reasons`. The opt-in exists for callers
  that only need a self-consistency / snapshot-coherence check
  (the measured 0/60 case); a security-critical caller must never
  pass it, and must supply a pin or trust roots on every replay.
- `REPLAY_OK` without a pin or trust roots means "self-consistent and
  snapshot-coherent" only. It is labelled as such in the result itself
  (`reasons` carries the no-anchor note; `oev pack replay` prints it under
  Notes).
- Callers that need replay protection MUST supply a pin on every replay,
  or trust roots. Never present a pin-less `REPLAY_OK` as proof that the
  expected pack was replayed.

## 9. Model B2 threat model (v0.2, 2026-11-13 — prototype)

Implementation: `src/oev/b2_witness.py` (`B2ReexecutingWitness`,
`B2ProcessWitness`, `run_b2_witnessed_verification`),
`src/oev/b2_worker.py`, `src/oev/b2_verify.py`, `src/oev/tsa.py`.
Measured outcomes: `benchmarks/HEA_B2_COMPARISON.md` (scenarios S1–S6,
real code). This section is the B2 counterpart of §5 (Model A limits);
it does not replace §2–§8.

### 9.1 What changes vs Model A

- **Producer forgery is now checked by re-execution, not by
  observation.** The B2 witness receives the bundle/profile bytes,
  computes their digests itself, re-runs the checks, and attests only
  on agreement (status + detail). A producer that forges a PASS on a
  failing package is refused before any attestation is signed (S1).
- **Code identity is compared, not just recorded.** Witness and
  producer code digests must agree or the run stops. The digest scope
  is unchanged from v0.1 (`oev` sources + Python version,
  third-party dependencies excluded — §5.4 still applies).
- **Role separation is code-enforced.** Witness, checkpoint-signer and
  producer receipt-signer keys must be three different keys (public-key
  digests compared); a witness authorisation document
  (`oev-witness-authorization/0.1`) bounds which profiles/formats a
  witness key may attest. Using one key for two roles raises.
- **The verifier is unchanged.** B2 attestations verify through the
  same `hea_verifier`; `verify_b2_execution` adds only the
  `separate-machine` mode check, the authorisation input, and the
  (optional) TSA-token status. Model A bundles still verify (PROVEN)
  but are reported as "not B2".

### 9.2 New trust boundaries (non-negotiable)

- **Re-execution != code correctness.** If producer and witness run
  the same buggy code, a wrong result is "confirmed" by agreement
  (common-mode failure). B2 proves the checks ran as the attested code
  defines them, not that the code is right (§0.2 still applies).
- **Witness signature != witness honesty (still).** A compromised B2
  witness (stolen key, dishonest operator) can attest without
  re-executing — it can call `attest()` directly, bypassing the
  comparison in `run_b2_witnessed_verification`. Measured (S4):
  pre-revocation the forged attestation verifies as PROVEN in both
  models; post-revocation both report `WITNESS_KEY_REVOKED`. B2 moves
  trust from the producer's machine to the witness's machine; it does
  not eliminate trust.
- **Prototype isolation != physical independence.** In this prototype
  the two sides are separate processes, venvs, keys, workdirs and
  logs — but they install the same local source tree, the byte
  handoff is a local call (no mTLS / signed channel), and a
  host-level attacker defeats the prototype. The manifest records
  `isolation_claim: "prototype-process-venv-key-workdir-only"` and
  every attestation carries `B2_PROTOTYPE_ISOLATION`. Never cite the
  prototype as separate-host evidence.
- **B2 receives the bundle bytes.** For confidential packages B2 is an
  exposure channel (design §9.5): do not use B2 for them; Model A or
  B1 is the honest choice there.
- **No hardware assurance.** B2 is not a TEE (Model C): no protection
  against a host that subverts the witness process itself.
- **Mock TSA time != proven time.** The timestamp token is signed by
  a local mock TSA (`tsa_policy: "mock-tsa/0.1"`); `time_proven` is
  always `False` for mock tokens. A missing token is `UNVERIFIED`
  (time not proven), a broken token is `TSA_INVALID` — neither changes
  the HEA verdict. No real TSA is contacted; full CMS TimeStampToken
  verification is not implemented.

### 9.3 Adversary capabilities added for B2

The §3 attacker additionally can:

7. Control the producer machine/venv entirely (forge receipts, stage
   files, run arbitrary producer code) — B2 detects this (S6) as long
   as the witness side is uncompromised *within the prototype scope*.
8. Present a B2 attestation for a different package, drop an
   attestation, or tamper with the log — detected exactly as in
   Model A (S5/S2/S3: `BUNDLE_DIGEST_MISMATCH` / `NO_ATTESTATION` /
   `LOG_GAP`).
9. Hold the witness key (compromised witness) — **not detected**
   pre-revocation (S4); detected only after the revocation list
   reaches verifiers (`WITNESS_KEY_REVOKED`).

The attacker is still assumed not to be able to forge Ed25519
signatures under keys they do not hold, or find SHA-256 preimages.

### 9.4 Explicit limits of Model B2 (v0.2)

1. **Witness compromise defeats B2** (see §9.2). Mitigations are
   organisational (key custody, witness diversity, rotation, audit),
   not in this code.
2. **Common-mode code faults are confirmed, not caught.**
3. **Prototype isolation only** (see §9.2). A production deployment
   needs independently managed witness hosts, an authenticated
   channel, and independent key custody — none of which this
   prototype demonstrates.
4. **No trusted wall-clock time.** The mock TSA is a format + signing
   exercise, not a time authority. Backdating is still not prevented.
5. **No non-equivocation beyond Model A.** A malicious witness can
   still sign two different attestations for one execution; no
   transparency log / gossip exists in v0.2.
6. **Code digest excludes third-party dependencies** (§5.4 unchanged).
7. **Witness authorisation is caller-supplied.** A verifier that does
   not pass the authorisation document does not enforce it; the
   document itself is not signed in v0.2 (its binding to the witness
   key is by `witness_key_id` only).
