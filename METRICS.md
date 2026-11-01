# METRICS.md — Honest Measurement (Faz J)

Program-level metrics for the OEPT / OEVP commons effort. Rule (Faz J):
every number traces to a linked source, no estimates or inflation, declines
are recorded like declines. This page starts the ledger at the Faz A
baseline (2026-11-01) and is the seed for the public metrics page (Kapı J).

| Metric | Current | Source / evidence |
| :--- | :--- | :--- |
| Implementers passing the conformance corpus | 2 — Python reference + TypeScript verifier (12/12 parity); the vector set ships standalone on PyPI | `conformance/` fixtures 01–14, this repo; sibling OEPT corpus 10/10 via `oept conformance` |
| External implementers (independent of this project) | 0 | none recorded |
| Registered profiles | 1 registered (Profile 0) + 5 draft — promotion requires domain adapters/vectors (funded-work) | profiles/registry.json |
| External merged contributions | 0 | GitHub PRs to `fintegra-ai/*` are project-internal so far |
| Public pilot packages | 0 | none published |
| Failed interop attempts (recorded) | 0 — interop table is live and accepts external submissions | docs/interop-table.md |
| PyPI releases | `open-evidence-verification 0.2.1`, `oept 0.1.1`, `oev-conformance-vectors 0.1.0` | pypi.org JSON API, 2026-11-01 |
| npm releases | **1** — `oept-verifier-ts 0.1.0` (published 2026-11-01, maintainer fintegraai) | registry.npmjs.org/oept-verifier-ts |
| Profiles total | 6 — 1 registered (Profile 0) + 5 draft (domain adapters/vectors are funded-work) | profiles/registry.json |
| Interop table | published with 2 entries (both project-internal; external submissions open) | docs/interop-table.md |
| Standalone vector package | **PUBLISHED** — `oev-conformance-vectors 0.1.0` on PyPI (2026-11-01, twine-clean, 12/12 builtin acceptance against the PyPI-published reference). **Kapı C: 4/4 — fully closed** | pypi.org/project/oev-conformance-vectors/0.1.0/ |
| NLnet dossier | nlnet/evidence-dossier.md — linked evidence + funded-work split (application prose is human-written by rule). **Timing reality 2026-11-02: no application prose yet, no external implementer/pilot — the reviewer-recommended path is the NEXT cycle unless the human completes the prose and rotation confirmation** | this repo |
| Closed-side security incident | **OPEN — purge executed, rotation NOT yet confirmed.** 2026-11-01: gateway.key purged from ALL pushed refs (filter-repo, 368 commits rewritten; fresh-clone gitleaks 0 private-key findings; local residuals zeroed after tag/branch/reflog cleanup). The key remains COMPROMISED-by-history until the owner confirms rotation of every environment that ever used it. Residuals: hidden GitHub PR refs (refs/pull/1,2 — git cannot rewrite), 12 synthetic-candidate findings, archived worktrees content-scanned (see below) | EU_Demo docs/runbooks/SECURITY_ROTATION.md purge record |
| Faz D slices 1-3 | TS verifier passes 12/12 OEVP vectors with identical results — parity criterion of Kapı D met; repo public at github.com/fintegra-ai/open-evidence-verifier-ts; **published to npm as oept-verifier-ts 0.1.0** | repo + registry.npmjs.org/oept-verifier-ts; acceptance via `run_vectors.py` external mode, exit 0 |
| Downloads / stars | not tracked yet (secondary metric; added only with a link) | — |

## Known negative facts (recorded, not hidden)

- The PyPI name `oev` is held by an unrelated project; this project
  publishes as `open-evidence-verification` (distribution rename
  ef86547, import/CLI unchanged).
- The 13 "git-less" EvidenceOS copies turned out to be git WORKTREES of
  EU_Demo (shared object store). They were archived on 2026-11-01 to
  `~/Developer/evidenceos-worktrees-archived-20261101/` (2.1 GB, every byte
  preserved, incl. uncommitted changes) and are content-scannable —
  scan results recorded below. Disposition (archive vs delete per
  directory) still pending owner decision.
- Archived-worktree CONTENT scans (2026-11-02, gitleaks 8.30.1, --no-git,
  redacted): 12 worktrees carry the shared synthetic set (6×
  generic-api-key, 2× curl-auth-header, 1× jwt); Muse_WO1 adds **2 NEW
  private-key findings in uncommitted content**; QUAL_Gemini +1
  generic-api-key. `gateway.key` file itself is absent from every archived
  tree (0 matches). Muse_WO1's two keys: rotation/disposition is an owner
  decision (content recoverable from the archive).
- The 3 stash patches exported during reconciliation contained **132
  findings incl. 3 private-key occurrences** — the patch files were
  DELETED on 2026-11-02 (content remains recoverable from the pre-purge
  bundle); a README in the archive documents the recovery path.
- Closed-side history scans (2026-11-01, gitleaks 8.30.1, redacted):
  `EvidenceOS_Finance_EU_Demo` 13 findings (incl. `private-key` on
  `deployment/certs/gateway.key`), `EvidenceOS_Islamic_Finance_Saudi`
  1 finding. Rotation / purge decisions are pending and belong to the
  closed side; open repositories are clean.

## Update discipline

Metrics move only when the linked evidence moves. A phase gate counts as
passed only with the artifacts its gate names — never with intent, plans,
or private claims.

## Program artifacts added 2026-11-01 (Faz B/C/I baseline)

- `spec/OEVP-1.0-draft.md` (this repo) and `spec/OEPT-1.0-draft.md`
  (sibling): normative RFC 2119 drafts with MUST→test traceability, error
  taxonomy, versioning policy, and explicit non-guarantees.
- `conformance/vectors/` (12 active + 2 planned) and
  `conformance/run_vectors.py`: language-independent vector set v0.1.0 with
  a machine-readable report; the Python reference verifier passes 12/12
  active vectors (`test_conformance_vectors.py`). C+ evidence-pack
  production implemented: `--evidence-pack` emits every run as an OEPT
  bundle (report + vector-set manifest as bound members) that `oev verify`
  accepts with `TECHNICAL_CHECKS_PASSED`. Auto-minimize of fuzz
  findings implemented (`conformance/minimize_fuzz.py` emits vector
  drafts). The vector set now also ships standalone:
  `oev-conformance-vectors 0.1.0` on PyPI.
- `GOVERNANCE.md`: decisions adopted — DCO over CLA, CC-BY-4.0 for
  spec/docs, conformance-brand rule, no funding intake before a second
  maintainer, access-transfer checklist.
- `BOUNDARY.md` §5: dispositions for the 18 scanned closed-side copies
  (canonical = EU_Demo; 12 git-less copies = archive candidates; nothing
  deleted) and the rotation decision for `deployment/certs/gateway.key`.
