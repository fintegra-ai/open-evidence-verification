# Changelog

All notable changes to the Open Evidence Verification Protocol (OEVP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

- Historical Execution Attestation (HEA) v0.1 Model A: pre-binding with
  Execution ID (JCS + SHA-256), witness-signed execution commitments,
  per-check Ed25519/DSSE attestations with mandatory limitations,
  hash-chained execution log with Merkle inclusion proofs and signed
  checkpoints, signed revocation lists, offline verification
  (`HISTORICAL_EXECUTION_PROVEN / UNPROVEN / DISPROVEN` + `HeaReason`
  codes), and the `oev hea attest|verify|log verify|revoke|disprove`
  CLI. Re-verification (`MATCH / MISMATCH / CANNOT_REPRODUCE`) and
  historical execution are reported as two separate dimensions, never
  collapsed into one score.
- HEA conformance vectors hea-01..hea-14
  (`conformance/vectors-hea/`, 14/14 pass).
- `TrustedKey` gains validity window, revocation flag, role, and
  successor fields; witness keys must carry an expiry and a role.
- `CheckStatus` semantics formalised (see
  `docs/PROTOCOL_SECURITY_REVIEW.md` §3); missing-profile-check vs
  failed-check are distinct findings.
- OEPT: optional `execution_binding` manifest field (format-checked
  only; a bundle cannot bind its own execution — see
  `spec/OEPT-1.0-draft.md` §2 rule 7).

### Security

- Committed OEPT conformance test-only key is refused as a witness key
  at three layers (witness construction, attestation signing,
  verifier-side blocklist).
- HEA verifier imports only protocol-core modules (no engine, adapter,
  replay, CLI, or witness code); enforced by
  `tests/test_hea_verifier_independence.py`.

### Planned for 0.3.0 — DRAFT (not released; version fields still 0.2.3)

> Draft entry prepared 2026-11-13 (worker E, round 3 P4; version number
> revised 2026-11-13, round 4 P5). The version bump itself is a separate,
> Enes-gated step — see `docs/BRANCH_AND_COMMIT_PLAN_V4.md` (commit
> OEVP-12). Do not publish from this entry alone.
>
> **Why 0.3.0, not 0.2.4 (round-3 draft):** the pin-less replay refusal
> documented below under "Changed" is a backwards-incompatible behaviour
> change (callers relying on unpinned `REPLAY_OK` now get
> `PINLESS_REPLAY_REFUSED`). This project versions pre-1.0 `0.x.y` with
> breaking changes landing in minor releases (see OEPT `CHANGELOG.md`:
> "breaking changes may land in minor releases until 1.0"), so the next
> OEVP release is a **minor** bump. Everything else in this entry is
> additive (new opt-in layers) or fixes. OEPT stays 0.1.4 (patch:
> additive + fixes only).

#### Added (round 4, Tur 4)

- Receipt freshness layer (`oev.receipt_status`, schema
  `oev-receipt-status/0.1`): signed status snapshots (CURRENT / STALE /
  SUPERSEDED / REVOKED) + relying-party `FreshnessPolicy` (default
  fail-closed: 90 days, `require_current=True`). Plain re-verification
  is unchanged — a stale/superseded receipt still re-verifies `MATCH`;
  the freshness dimension is reported separately and `overall_decision`
  is REJECT unless the receipt is fresh CURRENT. Snapshot-less receipts
  (including all pre-Tur-4 receipts) assess `UNKNOWN_FRESHNESS` /
  REJECT under the default policy.
- Real RFC 3161 TSA layer (`oev.tsa_real`): `TimeStampReq` DER +
  `TimeStampToken` verification against live TSAs (freetsa.org,
  DigiCert, Sectigo — measured end-to-end), `claimed_time` vs `genTime`
  check (a consistent backdate/future date with a real token is now
  caught), mock tokens never prove time (`time_proven=False`),
  `time_proven` / `execution_proven` reported separately. OCSP/CRL
  revocation checking is NOT implemented (open gap).
- Independent-evidence corroboration (`oev.corroboration`, schema
  `oev-corroboration/0.1`): `SOURCE_MISMATCH` when a trusted
  independent source disagrees with the bundle's claim (staged
  consistent lie caught), `SOURCE_UNCORROBORATED` when no source
  exists (openly uncorroborated, not a detection),
  `SOURCE_REJECTED` on forged/unknown sources, `SELF_CORROBORATION`
  when the producer/witness poses as an external source.
- Model B2 hardening (still a prototype: same host, separate trust
  domains — no physical/administrative independence): localhost mTLS
  channel (TLS 1.3, separate keystores), signed witness authorisation
  (`oev.b2_signed_auth`), signed completeness statements
  (`oev.b2_completeness`) and a `DISPROVEN` completeness path
  (`oev.b2_disproven`): unknown execution id → `DISPROVEN`, real id →
  `UNPROVEN`. Compromised-witness detection pre-revocation is still
  impossible (S4, both models).
- Cross-version interop measured (round 4 P5): PyPI OEPT 0.1.3 / OEVP
  0.2.3 verify/re-verify bundles and receipts produced by this tree
  (`VALID_SIGNED` / `MATCH`) and vice versa.

#### Fixed (round 4, Tur 4)

- mypy: 7 errors in the round-4 B2 files (`b2_keystore.py`,
  `b2_mtls.py`) fixed by type narrowing (rotation-record `None` guard,
  RSA-only test-CA key check, `getpeercert()` `None` guards, one
  removed unused `type: ignore`). `mypy src/oev` is clean again
  (50 files).
- Bandit B310: `request_timestamp` now refuses non-HTTP(S) TSA URLs
  (`file:` etc.) before `urlopen`; the audited call site carries a
  `nosec B310` with the justification. Bandit: 0 Medium / 0 High
  (18 Low, all false-positive class: enum-string B105, asserts,
  fixed-argv subprocess).

#### Added

- H2 attestation-omission coverage expanded: HEA vectors hea-18 (omit 3
  of 4), hea-19 (omit first only), hea-20 (NOT_RUN needs no attestation);
  HEA vectors now 20/20.
- JCS convergence with the independent Node.js verifier and OEPT:
  finite floats accepted on all sides per RFC 8785 §3.2.2.3 (non-finite
  rejected), lone surrogates rejected on all sides per §3.2.2.2,
  duplicate JSON members rejected everywhere (including the OEPT
  trust-keys loader gap), invalid UTF-8 rejected with structured errors.
  Three-way differential 403/403, full differential 610/610, zero open
  divergences (`docs/JCS_MISMATCH_LIST.md`).
- Witness authorisation + code-digest schemas (`oev-witness-authorization/0.1`,
  `oev-code-digest/0.1`): `code_version` carries optional `policy_digest`,
  `dependencies[]`, `environment{}`; verifier Step 3b compares a supplied
  code-digest document (`CODE_DIGEST_MISMATCH`), Step 4 enforces
  authorisation fail-closed under `--require-witness-authorization`
  (`WITNESS_UNAUTHORIZED`). Defaults unchanged (missing document is a note).
- Model B2 prototype (v0.2 work, separate-machine re-executing witness):
  the witness receives bundle + profile bytes itself, re-executes the
  checks and compares per-check results with the producer's claims
  (`src/oev/b2_witness.py`, `b2_verify.py`, `b2_worker.py`); mock TSA
  (RFC 3161 `TimeStampReq` format + offline mock timestamp tokens,
  `src/oev/tsa.py`) — no network use, no real TSA.
- Domain profile engines (real computation, adapter-level): financial
  evidence (`fin.*`, 7 required + 1 optional), dataset release (`ds.*`,
  5 + 1), AI model evaluation (`ai.*`, 5 + 1) in `src/oev/domain/`,
  dispatched by the OEPT adapter; the three profiles are registered as
  **draft** (#6–8) pending a governance decision on adapter-level engines.

#### Fixed

- Unsigned-K4 int-range gap: the `|n| ≤ 2**53−1` check now runs on the
  unsigned path too (reference + Node verifiers); K4 probe 11/11.
- Malformed `claimed_time` in a validly signed attestation crashed the
  verifier (`ValueError`); timestamps are now validated semantically and a
  malformed time is a controlled rejection
  (`HISTORICAL_EXECUTION_UNPROVEN / MALFORMED_ATTESTATION`). Backdating
  (a well-formed false time) is still not prevented — TSA is v0.2 work.

#### Changed

- Pin-less replay is now refused by default: `replay_snapshot` returns
  `PINLESS_REPLAY_REFUSED` (CLI exit 2) when no pin and no trust roots
  were supplied and the caller did not explicitly opt in
  (`--allow-pinless-replay` / `allow_pinless=True`); an opt-in `REPLAY_OK`
  still carries the explicit no-anchor note. Measured behaviour unchanged:
  with a pin 60/60 `PACK_HASH_CHANGED`, without a pin 0/60 under the old
  default. Spec updated: `spec/threat-model.md`,
  `spec/decision-pack-spec.md` §8.

## [0.2.3] — 2026-11-02

### Fixed

- Archive extraction rejects case/Unicode filename aliases before any writes.
- Offline pack verification refuses symlinks, escaping manifest paths, oversized
  files and excessive entries before reading payloads. Core member schemas are
  checked even when an attacker recomputes every manifest hash.
- Receipt inspection/re-verification enforce the OEVP DSSE payload type.
- Re-verification detects omitted optional checks, changed trust inputs and
  inconsistent overall results, even when the receipt self-digest is recomputed.
- Bounded input readers reject oversized/non-regular files before loading them;
  JSON nesting is bounded to 128 containers and malformed input fails cleanly.
- A malformed package cannot pass an archive-safety-only profile.
- Remove a duplicate registry entry and guard registry uniqueness/schema validity.

## [0.2.2] — 2026-11-02


### Fixed

- Validate and stage every archive member before extraction; reject path aliases,
  file/directory collisions, symlink entries, and existing destination files.
  Permanent hostile archive vectors cover late CRC failures and path collisions.
- Release verification removes an unsupported `oev verify --json` option and
  uses an explicit unsigned-integrity profile, and runs for relevant source
  changes as well as releases/manual dispatch.
- Correct published package status and distinguish project-internal language
  implementations from independent external implementers in the evidence dossier.


### Changed

- Distribution name changed from `oev` to `open-evidence-verification` (PyPI name taken by an unrelated project). Import package `oev` and CLI `oev` are unchanged; install with `pip install open-evidence-verification[oept]` for the OEPT adapter.



### Added

- Language-independent conformance vector set (`conformance/vectors/`,
  version 0.1.0, 12 active vectors covering fixtures 01–12) with a runner
  (`conformance/run_vectors.py`) that also drives external verifiers through
  a documented stdin/stdout-JSON contract and emits machine-readable
  reports. Fixture 13/14 (pack-archive extraction) vectors are drafted and
  marked planned until the extraction CLI contract exists.
- Normative protocol draft `spec/OEVP-1.0-draft.md` (RFC 2119, MUST→test
  traceability, versioning policy, non-guarantees), `GOVERNANCE.md`, and
  BOUNDARY.md §5 Faz-A+ disposition decisions.
- Fuzz minimizer `conformance/minimize_fuzz.py`: greedily minimizes a
  crashing archive at member level against any verifier command, verifies
  the failure persists, and emits a vector DRAFT (captured failure
  signature) for the fuzz-finding issue process.
- Conformance runner C+ evidence packs: `--evidence-pack` writes each run
  as an OEPT bundle (run report and vector-set manifest as digest-bound
  members) that `oev verify` accepts with `TECHNICAL_CHECKS_PASSED`.

## [0.2.1] - 2026-11-01

### Fixed

- **Re-verification of a tampered receipt no longer reports `MATCH`.** When the
  historical receipt's self-digest does not verify, `oev reverify` now fails
  closed with `MISMATCH` (CLI exit code 2) instead of recording the failure in
  `notes` and continuing — previously a receipt with an edited field (e.g. a
  replaced `receipt_id`) and a stale `receipt_digest` could still produce
  `MATCH` with exit code 0 if all other checks happened to agree.
- CLI: schema-invalid or unparseable JSON inputs (e.g. a malformed receipt or
  profile) now fail with a clean `Error: ...` message and exit code 1 instead
  of an unhandled traceback.

### Changed

- The optional `oept` extra now depends on the `oept` distribution (OEPT's
  actual PyPI/dist name), not the non-existent `open-evidence-provenance` name.
- `oev reverify` human output and the README now state explicitly that
  re-verification establishes reproducibility, not receipt authenticity;
  `oev receipt verify` with caller-pinned verifier keys remains the
  authenticity check.

### Added

- CI: a dedicated OEPT integration job that installs OEPT from the sibling
  repository and asserts the adapter is importable, so the previously
  auto-skipped adapter/CLI/conformance tests execute on every run.

## [0.2.0] - 2026-10-26

### Added

- **Decision Evidence Pack** (`oev-decision-pack/0.2`): a portable, integrity-checked
  directory format for the evidence trail of a decision process — case record, facts,
  versioned rule runs (rules-as-data), findings, review actions, timeline, snapshot
  context, and artifacts. Includes pack build, DSSE v1 manifest signing, and offline
  integrity verification (`oev pack build|sign|verify`), a normative specification
  (`spec/decision-pack-spec.md`), and a fully synthetic, domain-neutral example pack
  (`examples/demo-case-001`, regenerable via `examples/make_example.py`).
- **Portable pack verification receipt** (`oev-pack-receipt/0.1`,
  `spec/decision-pack-spec.md` §7.1): `oev pack verify --out` emits a self-digested receipt
  recording exactly which checks passed, failed, or were not run (the complete ordered check
  vector), plus the declared and recomputed pack digest, the verifier identity/version, the
  verification time, per-member results, and structure errors. The receipt can be DSSE-signed
  (`--sign-receipt`) and is verifiable offline by a third party (`oev pack receipt verify`),
  optionally bound against the pack on disk (`PACK_BINDING_MATCH` / `PACK_BINDING_MISMATCH`).
  A receipt of an invalid pack is itself a valid record of that failure and never upgrades
  the pack it describes. Schema: `pack-verification-receipt.schema.json`.
- JSON schemas (Draft 2020-12) for the pack: `decision-pack-case`, `decision-pack-facts`,
  `decision-pack-rule-runs`, `decision-pack-findings`, `decision-pack-review-actions`,
  `decision-pack-timeline`, `decision-pack-snapshot-context`, and
  `decision-pack-manifest`.
- Conformance fixture `06-signature-invalid`: a corrupt application signature must
  yield `FAIL` / `TECHNICAL_CHECKS_FAILED`, pinning the distinction from the
  `UNVERIFIED` / `PROFILE_UNSATISFIED` outcome of an unsigned bundle (`03`).
- Conformance fixtures `07`–`14` for the decision pack surface, derived deterministically
  from the neutral `demo-case-001` example and runnable on the OEVP core alone (no OEPT):
  replay OK on a pinned valid pack, `PACK_HASH_CHANGED` refusal of a self-consistent
  rewrite, `SNAPSHOT_LEAK` refusal after late evidence injection, a third-party
  pack-receipt round-trip (`RECEIPT_VALID` offline plus `PACK_BINDING_MATCH`), honest
  `SIGNATURE_NOT_PRESENT` vs `SIGNATURE_INVALID` reporting, and archive refusals of
  ZIP-slip traversal and duplicate member entries.
- **Snapshot replay safety gate** (`oev.replay`, `oev pack replay`): replay of a pack's
  snapshot now fails closed. Replay requires full pack verification first, refuses when the
  pack hash changed since an out-of-band replay pin (`pin_pack`, `PACK_HASH_CHANGED` — this
  catches fully self-consistent manifest rewrites that per-pack digests cannot), refuses when
  caller-pinned trust roots are not satisfied by the manifest signature
  (`SIGNATURE_UNTRUSTED`, covering stripping and replacement), and refuses when a recorded
  rule run consumed evidence observed after the snapshot was captured (`SNAPSHOT_LEAK`).
  The replay scope is computed by snapshot isolation: only facts bound to a snapshot source
  and observed at or before `captured_at` are eligible; later or unbound evidence is excluded
  with an explicit reason and can never enter a replay of that snapshot.
- **Safe ZIP transport for packs** (`oev.pack_archive`): deterministic pack archive creation
  and a validate-before-extract unpacker that rejects path-traversal entries (zip-slip),
  duplicate member names, encrypted entries, and decompression bombs (per-entry and total
  size bounds) — a hostile archive leaves the target directory untouched.
- **Sabotage test suite** (`tests/test_sabotage.py`): 33 adversarial cases across byte flips
  (members, artifacts, manifest, DSSE payload and signature bytes), ZIP traversal entries,
  duplicate members (archive and manifest), signature stripping, signature replacement
  (including keyid spoofing and envelopes over rewritten manifests), manifest tampering
  (digest flips and self-consistent rebuilds), and replay with later evidence injected.
- **Verifier-independence tests** (`tests/test_verifier_independence.py`): the offline
  verifier's import closure is proven protocol-only (static AST and runtime `sys.modules`
  checks; no application or store code), and the CLI verifier is exercised in a subprocess
  against a pack copied to a clean directory containing no application code.
- GitHub Actions CI running ruff, mypy (strict), and pytest on Python 3.10–3.13
  (matching `requires-python`).
- Schema-parity conformance guard: `schemas/` and the wheel-shipped `src/oev/schemas/`
  copies must stay byte-identical.
- `conformance/README.md` documenting the fixture corpus, expected results, and
  regeneration procedure.

### Changed

- `oev pack verify` exit code `2` now also covers the case where the caller supplied
  verifier trust roots but the pack carries no trusted manifest signature: a stripped
  signature is a visible trust failure, never silent success (previously an unsigned pack
  exited `0` even with keys supplied).
- README rewritten to pro standard: what OEVP is and is not, trust boundaries in plain
  language, and a quickstart where every command runs against the committed conformance
  fixtures.
- SECURITY.md expanded with report scope, supported versions, coordinated disclosure,
  and an explicit "what verification does not protect against" section.
- CONTRIBUTING.md and CODE_OF_CONDUCT.md completed (OEPT availability, quality gates,
  full covenant structure).
- Threat model (`spec/threat-model.md`) extended to the 0.2 decision pack surface: pack
  member tampering, self-consistent manifest rewrites, signature stripping/replacement,
  hostile pack archives, and snapshot replay leaks, with rule re-execution recorded as
  an explicit non-goal.
- Example pack `demo-case-001` regenerated so the committed bytes match the current
  generator exactly: the DSSE envelope now embeds the signer's public key as an
  unauthenticated hint (members, manifest, and pack digest are unchanged).
- Receipts record the installed `oev` package version as the verifier identity version
  (previously a hardcoded literal).
- CLI exits with a clean error message (exit 1) instead of a traceback when the
  optional OEPT adapter is missing.
- Test suite no longer references paths outside the repository: OEPT-dependent tests use
  the committed in-repo fixtures and skip with an explicit reason when OEPT is absent.

### Removed

- Dead code: `sha256_stream`/`sha256_file` (unused stream hashing helpers),
  `get_available_adapters` (unused adapter registry accessor), `archive_info`
  (unused archive summary helper), and the never-raised `PackVerifierError`.

## [0.1.0] - Unreleased (draft)

### Added

- Initial pre-application MVP for the Open Evidence Verification Protocol.
- JSON schemas: `verification-profile.schema.json`, `verification-receipt.schema.json`, `reverification-report.schema.json` (Draft 2020-12).
- Deterministic RFC 8785 (JCS) canonicalization with integer range boundary enforcement `[-(2^53 - 1), 2^53 - 1]`.
- Granular `CheckResult` model with 6 exact states: `PASS`, `FAIL`, `NOT_RUN`, `NOT_APPLICABLE`, `UNVERIFIED`, `UNSUPPORTED`.
- Deterministic overall result aggregation with 5 exact states: `TECHNICAL_CHECKS_PASSED`, `TECHNICAL_CHECKS_FAILED`, `TECHNICAL_CHECKS_PARTIAL`, `EXECUTION_INCOMPLETE`, `PROFILE_UNSATISFIED`.
- Canonical receipt digest with strict self-digest recursion avoidance rule.
- DSSE v1 specification envelope implementation with PAE and Ed25519 signing.
- Caller-supplied verifier trust roots preventing self-trust and key-hint impersonation.
- Pluggable `PackageAdapter` protocol with optional reference `OEPTAdapter`.
- Receipt inspection engine decoupled from package bytes.
- Package re-verification engine comparing fresh evaluations against historical receipts.
- Minimal CLI (`oev verify`, `oev inspect-receipt`, `oev reverify`, `oev receipt verify`).
- Five primary MVP conformance fixtures.
- Strict duplicate-key JSON rejection, input bounds, and profile check uniqueness hardening.
