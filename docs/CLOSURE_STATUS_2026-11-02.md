# Technical closure review — 2026-11-02

Scope: `fintegra-ai/open-evidence-provenance` and
`fintegra-ai/open-evidence-verification`. This review freezes the existing
alpha scope; new domain adapters and the post-funding direction remain future
work. It is not an independent security audit or an NLnet eligibility decision.

## Verified technical work

| Deliverable | Result / evidence |
| --- | --- |
| OEPT source suite | 96 passed, Python 3.12; lint, format, strict mypy passed |
| OEVP source suite with OEPT | 159 passed, Python 3.12; lint, format, strict mypy passed |
| OEPT conformance | 15/15, including five new permanent negative ZIP/manifest vectors |
| OEVP conformance 0.1.0 | 12 active pass, 0 failed, 2 planned; planned is not passed |
| Project-internal TypeScript parity | 12/12 against the same OEVP vector set; external implementers remain 0 |
| Open-repository full-history secret scans | gitleaks 8.30.1: 0 findings in both repos with the committed configs |
| Distribution checks | Prepared OEPT 0.1.2 and OEVP 0.2.2 wheel + sdist built; all four pass `twine check` |
| Installed artifact check | Both wheels imported from clean `site-packages`; `pip check` passes; installed OEPT corpus 15/15 |
| Installed OEVP evidence loop | Built-wheel runner emits an OEPT evidence bundle; `oev verify` returns `TECHNICAL_CHECKS_PASSED` using `profiles/release-integrity/profile.json` |
| Baseline remote CI | [OEPT](https://github.com/fintegra-ai/open-evidence-provenance/actions/runs/41319073281), [OEVP](https://github.com/fintegra-ai/open-evidence-verification/actions/runs/41352833271): successful before these changes |

Source changes harden malformed manifest handling, required member checks,
encrypted/corrupt ZIP handling, byte-API size limits, and builder drive paths.
OEVP extraction stages every payload before destination writes and refuses
existing files, aliases, symlink entries, and file/directory collisions.
Permanent negative vectors accompany the fixes. The release-verification
workflow now uses supported CLI arguments and an explicit integrity profile
for unsigned CI evidence, and runs on relevant source changes.

The integrity profile does not authenticate a publisher. Existing signed
profiles retain their signature requirements.

## Publication and account handoff

Confirmed existing PyPI publications:
[`oept 0.1.1`](https://pypi.org/project/oept/0.1.1/),
[`open-evidence-verification 0.2.1`](https://pypi.org/project/open-evidence-verification/0.2.1/),
[`oev-conformance-vectors 0.1.0`](https://pypi.org/project/oev-conformance-vectors/0.1.0/).
The new 0.1.2 / 0.2.2 artifacts are prepared locally, **not published**.
GitHub review/CI for these changes must be checked separately from baseline CI.

PyPI token rotation is **PENDING verification**, not an application blocker:

1. Account owner creates separate project-scoped tokens for `oept` and
   `open-evidence-verification` in PyPI's account UI.
2. Upload each project's new distributions with its own scoped credential;
   confirm successful publication in PyPI's release listing.
3. Only after both uploads succeed, revoke the old account-wide credential.

No credential value belongs in a repository, log, command argument, chat,
or this report. This review accessed the PyPI login page; it did not have an
authenticated account session, create tokens, upload distributions, or revoke
the old token. A failed or missing upload cannot count as rotation completed.

## Human / external gates that remain open

- Second human maintainer and access transfer: required by project governance
  before funding intake. An AI agent is not a second human maintainer.
- Human-written application prose: evidence appendix is corrected, but does
  not constitute an application or submission.
- External implementers and named public pilots: 0 recorded. Internal Python/
  TypeScript parity is an engineering result, not independent adoption.
- Profiles 1–5: draft, pending domain adapters/vectors; not promoted by this review.
- Private deployment key rotation: previous owner-facing records remain open
  until the deployment owner confirms rotation. Open-side clean scans cannot
  prove rotation of a private environment. No private system was changed here.
- Independent security audit and post-funding scope remain future work.

These statuses are project evidence and governance gates; they are not
presented as official NLnet rules. No deadline or filing-cycle recommendation
is inferred from stale notes.

## Superseding publication / account update

The earlier prepared/unpublished statuses above are historical. OEPT 0.1.2
and OEVP 0.2.2 were published and all four artifact hashes independently
verified on 2026-11-02. The account owner confirmed revocation of the old
account-wide token after the project-scoped uploads. Project credentials
persist in macOS Keychain, with no token values stored in this repository.
See SECOND_REVIEW_2026-11-02.md for the subsequent source review.
