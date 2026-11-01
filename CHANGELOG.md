# Changelog

All notable changes to the Open Evidence Verification Protocol (OEVP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

- Distribution name changed from `oev` to `open-evidence-verification` (PyPI name taken by an unrelated project). Import package `oev` and CLI `oev` are unchanged; install with `pip install open-evidence-verification[oept]` for the OEPT adapter.

## [Unreleased]

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
