# OEVP Conformance Kit

This directory holds the conformance fixture corpus for the Open Evidence Verification
Protocol: fourteen small, committed scenarios that exercise the verification engine,
receipt inspection, re-verification, the decision pack surface (offline verifier,
portable receipt, replay gate, archive transport) against known inputs with known
expected results.

The fixtures are executed automatically by `tests/test_conformance.py`; running
`pytest` (see the [top-level README](../README.md#running-the-tests)) is the conformance
run.

## Fixtures

Fixtures 01–06 exercise the *package* verification engine (OEPT bundles). Fixtures
07–14 exercise the *decision pack* surface and are derived deterministically from the
committed neutral example pack [`examples/demo-case-001`](../examples/demo-case-001).

| Fixture | Inputs | Expected outcome |
| :--- | :--- | :--- |
| [`01-valid-oept-pass`](fixtures/01-valid-oept-pass/) | Valid signed OEPT bundle, strict profile, package trust keys, verifier trust keys, pre-generated signed receipt | `TECHNICAL_CHECKS_PASSED`; all four checks `PASS`; DSSE signature validates against `verifier-trust-keys.json` |
| [`02-tampered-package`](fixtures/02-tampered-package/) | OEPT bundle with one tampered member, integrity-only profile | `TECHNICAL_CHECKS_FAILED`; `member_digests` is `FAIL` |
| [`03-required-signature-unsatisfied`](fixtures/03-required-signature-unsatisfied/) | Valid *unsigned* bundle, strict profile requiring `application_signature` | `PROFILE_UNSATISFIED`; `application_signature` is `UNVERIFIED` (never counted as passed) |
| [`04-tampered-receipt`](fixtures/04-tampered-receipt/) | Receipt from fixture 01 with a check status flipped inside the DSSE payload, plus the original verifier trust keys | Signature and receipt self-digest both fail; `is_trusted_signer`, `crypto_valid`, `receipt_digest_valid` all `false` |
| [`05-reverify-package-mismatch`](fixtures/05-reverify-package-mismatch/) | Receipt from fixture 01 presented with a different package | `MISMATCH` with `package_digest_match: false` |
| [`06-signature-invalid`](fixtures/06-signature-invalid/) | Bundle whose application signature is corrupt, with trust keys matching the key the bundle claims | `TECHNICAL_CHECKS_FAILED`; `application_signature` is `FAIL` (a present-but-invalid signature is a cryptographic failure, not missing trust context) |
| [`07-pack-replay-ok`](fixtures/07-pack-replay-ok/) | demo-case-001 pack plus its out-of-band replay pin (`pin.json`) | `REPLAY_OK`; only snapshot-bound facts observed at or before `captured_at` are eligible (`fact-001`, `fact-002`, `fact-003`) |
| [`08-pack-replay-hash-changed`](fixtures/08-pack-replay-hash-changed/) | demo-case-001 copy with a self-consistently rewritten manifest, plus the pin of the *original* bytes | `PACK_HASH_CHANGED`; the pin anchors the original pack bytes even when the rewrite is internally coherent |
| [`09-pack-replay-snapshot-leak`](fixtures/09-pack-replay-snapshot-leak/) | demo-case-001 copy with an injected fact observed after `captured_at` and a recorded rule run consuming it | `SNAPSHOT_LEAK`; `fact-901` is excluded from the replay scope and the recorded history contradiction refuses the entire replay |
| [`10-pack-receipt-roundtrip`](fixtures/10-pack-receipt-roundtrip/) | demo-case-001 pack, its verifier keys, and a deterministic pack verification receipt (`oev-pack-receipt/0.1`) | `RECEIPT_VALID` from the receipt bytes alone (self-digest valid, recorded `PACK_VALID` / `SIGNATURE_VALID`); with the pack on disk the binding is `PACK_BINDING_MATCH` |
| [`11-pack-signature-not-present`](fixtures/11-pack-signature-not-present/) | demo-case-001 copy with `manifest.dsse.json` removed | `PACK_VALID` with `SIGNATURE_NOT_PRESENT` and `manifest_signature` `NOT_APPLICABLE` — unsigned is never invalid |
| [`12-pack-signature-invalid`](fixtures/12-pack-signature-invalid/) | demo-case-001 copy with corrupted signature bytes, plus the matching verifier keys | `PACK_VALID` (member integrity intact) with `SIGNATURE_INVALID`, crypto not valid, `manifest_signature` `FAIL` — present-but-invalid is never reported as valid |
| [`13-archive-traversal-refused`](fixtures/13-archive-traversal-refused/) | Hostile ZIP containing a `../` traversal entry | `extract_pack_archive` raises with "traverses outside the root"; the extraction target is never created (validate-before-extract) |
| [`14-archive-duplicate-member-refused`](fixtures/14-archive-duplicate-member-refused/) | Hostile ZIP containing the same entry name twice with different content | `extract_pack_archive` raises with "duplicate entry name"; the extraction target is never created |

Each fixture directory contains the input artifacts (package, profile, receipt, trust
keys, pack, pin, archive as applicable) and an `expected-result.json` describing the
assertions that `tests/test_conformance.py` makes against the real outputs.

## What the fixtures demonstrate

- A required check that cannot complete (`UNVERIFIED`) yields `PROFILE_UNSATISFIED`,
  never a passing verdict — skipped is not passed.
- A check that executed and failed (`FAIL`) yields `TECHNICAL_CHECKS_FAILED`. Fixture 03
  (unsigned, no trust context) and fixture 06 (corrupt signature) together pin down the
  distinction between `UNVERIFIED` and `FAIL`.
- Tampering with package bytes, with a check status inside a receipt, or substituting a
  different package/profile is detected by digest binding and DSSE signatures.
- Receipt inspection (fixtures 01 and 04) needs only the receipt bytes and the
  caller-supplied verifier trust keys — no package, no OEPT install.
- Pack fixtures 07–09 pin the replay gate: pin-then-replay anchors the exact accepted
  bytes (catching self-consistent rewrites), and a recorded run that consumed evidence
  observed after the snapshot capture refuses the whole replay.
- Pack fixtures 10–12 pin the honest three-way signature vocabulary and the portable
  receipt: `SIGNATURE_NOT_PRESENT` (fixture 11) and `SIGNATURE_INVALID` (fixture 12) are
  distinct states, an unsigned pack is never invalid because of the missing signature,
  and a third party can verify a receipt offline with or without the pack.
- Pack fixtures 13–14 pin archive fail-closed behavior: a hostile archive is rejected
  before any file is written.

Fixtures 01, 02, 03, and 06 execute real OEPT bundle evaluation and are skipped
automatically when the optional OEPT adapter is not installed; fixtures 04, 05, and
07–14 run on the OEVP core alone.

## Regenerating fixtures

The committed fixtures are generated deterministically by
[`make_fixtures.py`](make_fixtures.py). Fixtures 07–14 are regenerated from the
committed `examples/demo-case-001` bytes and need only a working OEVP core install
(`pip install -e .`):

```bash
python conformance/make_fixtures.py   # generates 07-14; adds 01-06 when OEPT is available
```

Fixtures 01–06 additionally require the OEPT package and its conformance fixtures
(OEPT is a sibling project, not yet published to PyPI; point `OEPT_FIXTURES_DIR` at its
checkout):

```bash
OEPT_FIXTURES_DIR=/path/to/open-evidence-provenance/conformance/fixtures \
    python conformance/make_fixtures.py
```

The default `OEPT_FIXTURES_DIR` assumes the OEPT checkout sits next to this repository.

> Notes: regeneration of 01–06 creates a fresh verifier signing key, so the regenerated
> fixture receipts are signed by a new throwaway key (matched by the regenerated
> `verifier-trust-keys.json`). Fixtures are regenerated as a set; do not mix files
> across generation runs. The receipt in fixture 10 embeds the installed `oev` package
> version as the verifier identity, so regenerate 07–14 after a version bump.
