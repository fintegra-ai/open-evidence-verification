# Second technical review — 2026-11-02

Scope: the existing OEPT/OEVP alpha, its published artifacts, offline trust
boundaries, packaging, registry, and documentation. New domain adapters,
external pilots and the post-funding direction remain future work.

## Findings closed in source

1. Pack member path checks now stop unsafe reads: traversal, symlink roots,
   symlink ancestors/members, non-regular files, and bound violations are
   refused. Source collection and output construction apply containment too.
2. A self-consistent manifest no longer bypasses core-member JSON Schemas.
   Malformed/noncanonical numbers and deep JSON return negative outcomes or
   input errors rather than crashing the public verifier.
3. Receipt inspection and package re-verification reject non-OEVP DSSE
   payload types. Signature math remains separate from caller trust.
4. Re-verification compares optional-check presence, trust-input hashes and
   the aggregated overall result, as well as package/profile digests and
   individual statuses. Recomputed self-digests do not conceal those changes.
5. An explicit receipt-to-pack binding fails if the supplied pack is missing
   or unsafe, instead of accepting an unexecuted binding expectation.
6. Oversized JSON/package files are refused before loading them into memory.
   JSON nesting is capped at 128 container levels.
7. A malformed package cannot pass an archive-safety-only profile.
8. OEPT builders enforce the required evidence member; CLI output labels
   digest checks NOT EVALUATED after structural failure. Symlink directory
   roots and source entries are refused.
9. Remove the duplicate Profile 0 registry entry. Six unique profiles remain:
   one registered, five draft. A guard validates uniqueness and profile schema.
10. Archive extraction also rejects portable case/Unicode filename collisions
    before writing, including aliases of file/directory ancestors.
11. Dependency metadata/integration pins use the published OEPT 0.1.2 safety
    baseline. Contributor instructions and published-release records are updated.

Permanent negative inputs: `conformance/review-regressions/`; regression
coverage: `tests/test_review_security.py` and OEPT's
`tests/test_review_consistency.py`. The existing replay timestamp attack is
now rejected by core schema validation before replay-specific checks run.
Its expected terminal classification changes from SNAPSHOT_INVALID to
PACK_INVALID; the attack remains refused.

## Evidence and limits

- Source suites on Python 3.12: OEPT 101 tests, OEVP 176 with the adapter.
- Ruff lint/format and strict mypy pass in both source checkouts.
- The active OEVP 0.1.0 vector set remains 12 active / 2 planned; the new
  negative inputs are additional regression coverage, not an inflated parity claim.
- OEPT 0.1.2 and OEVP 0.2.2 are published and their four artifact hashes
  independently matched the reviewed files.
- Project-scoped credentials persist in macOS Keychain. The account owner
  confirmed old account-wide token revocation on 2026-11-02. No credential
  values belong in this repository.
- OEPT 0.1.3 / OEVP 0.2.3 are follow-up source candidates. Final wheel/sdist,
  installed-artifact, dependency-audit, and conformance evidence is delivered
  in the owner-side review artifact directory, separate from credentials.
- This is an internal engineering review, not an independent security audit
  or a guarantee that no vulnerabilities remain. It does not claim safety
  against a privileged process concurrently changing local files.

## Remaining external / administrative gates

A second human maintainer, actual external implementations/pilots, and the
human-written NLnet application are not fabricated or marked complete.
Private deployment rotation records are independent of PyPI credential
rotation and remain owner-side obligations.

Both repositories' reviewed source branches await main integration. The
GitHub connector cannot create PRs (HTTP 403), and the browser is signed out.
A prior attempt at direct main integration with [skip ci] was rejected by
automatic approval review; it has not been retried through a workaround.
The owner must explicitly authorize that exact integration or restore PR
creation access. Local checks are batched to avoid unnecessary Actions runs.
