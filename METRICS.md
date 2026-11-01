# METRICS.md — Honest Measurement (Faz J)

Program-level metrics for the OEPT / OEVP commons effort. Rule (Faz J):
every number traces to a linked source, no estimates or inflation, declines
are recorded like declines. This page starts the ledger at the Faz A
baseline (2026-11-01) and is the seed for the public metrics page (Kapı J).

| Metric | Current | Source / evidence |
| :--- | :--- | :--- |
| Implementers passing the conformance corpus | 1 (Python reference verifier; the vector set is not yet a standalone package) | `conformance/` fixtures 01–14, this repo; sibling OEPT corpus 10/10 via `oept conformance` |
| External implementers (independent of this project) | 0 | none recorded |
| Registered profiles | 0 (the finance demo profile is a demo, not a registered profile) | profile registry does not exist yet (Faz F) |
| External merged contributions | 0 | GitHub PRs to `fintegra-ai/*` are project-internal so far |
| Public pilot packages | 0 | none published |
| Failed interop attempts (recorded) | 0 | interop table does not exist yet (Faz G) |
| PyPI releases | `open-evidence-verification 0.2.1`, `oept 0.1.1` | pypi.org JSON API, 2026-11-01 |
| npm releases | 0 | TypeScript verifier does not exist yet (Faz D) |
| Downloads / stars | not tracked yet (secondary metric; added only with a link) | — |

## Known negative facts (recorded, not hidden)

- The PyPI name `oev` is held by an unrelated project; this project
  publishes as `open-evidence-verification` (distribution rename
  ef86547, import/CLI unchanged).
- 12 local EvidenceOS working copies are plain directories without git
  history; they cannot be history-scanned and await the
  canonical / archive / delete decision table (Faz A+).
- Closed-side history scans (2026-11-01, gitleaks 8.30.1, redacted):
  `EvidenceOS_Finance_EU_Demo` 13 findings (incl. `private-key` on
  `deployment/certs/gateway.key`), `EvidenceOS_Islamic_Finance_Saudi`
  1 finding. Rotation / purge decisions are pending and belong to the
  closed side; open repositories are clean.

## Update discipline

Metrics move only when the linked evidence moves. A phase gate counts as
passed only with the artifacts its gate names — never with intent, plans,
or private claims.
