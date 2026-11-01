# OEVP-1.0 (draft) — Open Evidence Verification Protocol

Status: **draft** — normative restatement of shipped `oev-profile/0.1`,
`oev-receipt/0.1`, `oev-reverification/0.1`, and `oev-decision-pack/0.2`
behavior, extracted from code as Faz B of the NLnet plan v2. On release this
file becomes `OEVP-1.0`. The key words MUST, MUST NOT, SHOULD, MAY follow
RFC 2119. Code license: Apache-2.0; this document: CC-BY-4.0 (see
GOVERNANCE.md).

## 1. Scope

OEVP defines: verification profiles, verification receipts (optionally DSSE
signed), receipt authenticity verification, package re-verification, and
decision evidence packs with a snapshot replay safety gate. Bundle formats
are OEPT-1.0's subject.

## 2. Canonicalization and digests

1. Canonical JSON MUST be RFC 8785 (JCS) with the same fail-closed integer
   range as OEPT-1.0 (§3). [tests: `test_canonical_and_schemas.py`]
2. The receipt self-digest MUST be computed over the canonicalized receipt
   body WITHOUT the `receipt_digest` field. [tests:
   `test_dsse_and_trust.py`, `test_fuzz_receipt_digest.py`]
3. Any change to the receipt body without recomputing the digest MUST make
   `verify_receipt_digest` fail, and re-verification of such a receipt MUST
   return `MISMATCH` with an empty fresh-check list. [tests:
   `test_fuzz_receipt_digest.py::test_fuzzed_single_field_changes_never_match`,
   `test_reverify_tampered_receipt_fails_closed`]

## 3. Profiles

A profile MUST conform to `verification-profile.schema.json`. The canonical
profile digest MUST be bound into receipts; re-verification against a
profile whose digest differs MUST abort with `PROFILE_DIGEST_MISMATCH`
(result `CANNOT_REPRODUCE`). [test: `test_reverify_profile_digest_substitution`]

## 4. Receipts and authenticity

1. Receipts MUST conform to `verification-receipt.schema.json`.
2. A receipt MAY be a DSSE v1 envelope; signatures MUST be Ed25519 over the
   PAE encoding. [tests: `test_dsse_and_trust.py`]
3. Receipt authenticity is established ONLY by `oev receipt verify` against
   caller-pinned verifier keys. Embedded or self-referenced keys MUST NOT
   confer trust. [tests: `test_verifier_independence.py`, `test_sabotage.py`]
4. Re-verification establishes **reproducibility, not authenticity**: a
   receipt that is internally consistent (self-digest recomputed and
   re-signed by an attacker) MUST still re-verify to `MATCH`; this is a
   documented boundary, not a defect. [test:
   `test_reverify_self_consistent_forgery_matches_by_design`]

## 5. Re-verification

A conforming re-verifier MUST: (1) verify the receipt self-digest first and,
on failure, return `MISMATCH` with empty fresh checks and compare nothing
against the receipt; (2) bind the package digest; (3) bind the profile
digest; (4) re-execute profile checks; (5) diff fresh statuses against the
recorded ones. [tests: `test_reverify_tampered_receipt_fails_closed`,
`test_reverify_package_mismatch` (fixture 05), `test_independence.py`]

## 6. Decision evidence packs and replay safety

1. A pack MUST contain a canonical manifest with per-member SHA-256 digests;
   verification is integrity-only. A pack verdict MUST NOT depend on rule
   outcomes. [tests: `test_decision_pack.py`]
2. Replay safety MUST evaluate snapshot eligibility by digest binding and
   captured-at scoping only. A replay evaluator MUST NOT re-execute any
   rule; rule re-execution is out of scope for OEVP-1.0. [tests:
   `test_replay_safety.py`]
3. Pack manifests MAY be DSSE signed; with caller-pinned keys, a missing,
   invalid, or untrusted signature MUST exit 2 (never silence). [tests:
   `test_pack_receipt.py`]

## 7. CLI surface and exit codes (normative)

| Command | 0 | 1 | 2 |
| :--- | :--- | :--- | :--- |
| `oev verify` | `TECHNICAL_CHECKS_PASSED` | missing input / clean error | any other overall result |
| `oev inspect-receipt` | digest valid | digest invalid | — |
| `oev reverify` | `MATCH` | missing input / clean error | `MISMATCH` / `CANNOT_REPRODUCE` |
| `oev receipt verify` | trusted signer | digest invalid | signed but untrusted/invalid |
| `oev pack verify` | `PACK_VALID` (+ trusted signature) | pack invalid | untrusted/invalid signature |
| `oev pack replay` | `REPLAY_OK` | `PACK_INVALID` | blocked / hash changed |
| `oev pack receipt verify` | `RECEIPT_VALID` | receipt invalid | signature problems |

Malformed or schema-invalid JSON input MUST produce a single-line
`Error: ...` on stderr with exit code 1 — never a traceback. [tests:
`test_cli_and_reverify.py`, `test_cli_missing_adapter.py`]

## 8. Error taxonomy

Verification checks: `PASS`, `FAIL`, `NOT_RUN`, `NOT_APPLICABLE`,
`UNVERIFIED`, `UNSUPPORTED`. Overall results: `TECHNICAL_CHECKS_PASSED`,
`TECHNICAL_CHECKS_FAILED`, `TECHNICAL_CHECKS_PARTIAL`,
`EXECUTION_INCOMPLETE`, `PROFILE_UNSATISFIED`. Re-verification: `MATCH`,
`MISMATCH`, `CANNOT_REPRODUCE`. Replay: `REPLAY_OK`, `PACK_INVALID`, or a
blocked status. The INDETERMINATE family of Faz B is covered by
`NOT_RUN`/`EXECUTION_INCOMPLETE`; a dedicated cross-cutting
`INDETERMINATE` status is a 1.0 review item, not silently new behavior.

## 9. Versioning policy

| Artifact version | New verifier behavior |
| :--- | :--- |
| known `protocol_version` | accept |
| unknown `protocol_version` | reject with a clean error, exit 1 |
| old version after deprecation | warn in release notes, reject in next major |

## 10. What this specification does NOT guarantee

- The truthfulness of recorded check outcomes; a receipt binds what its
  verifier observed, not what is true.
- Receipt authenticity without caller-pinned verifier keys (§4.3).
- Rule correctness or re-execution (§6.2).
- Any legal, compliance, or factual conclusion.

## 11. Conformance

Conformance is defined by the OEVP conformance vector set
(`conformance/vectors/`, set version in `manifest.json`) executed via
`conformance/run_vectors.py`. A conformance claim MUST reference a passing
machine-readable report for a named vector-set version. Claims are governed
by GOVERNANCE.md. [test: `test_conformance_vectors.py`]
