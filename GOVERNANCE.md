# GOVERNANCE.md

Status: adopted 2026-11-01 (Faz I of the NLnet plan v2; decisions below were
made under the project owner's explicit delegation, "kararlara sen karar
ver"). Amendments follow §2.

## 1. Roles

- **Maintainers**: today one (project owner). Target before any NLnet award:
  two maintainers with independent access (§5).
- **Contributors**: anyone submitting a PR under the DCO (§4).
- **The project owner** acts as decision-maker of last resort until a
  second maintainer exists; after that, decisions are consensus of
  maintainers, escalating to a simple majority vote.

## 2. Decision and spec-change process

1. Code changes: normal PR review. One maintainer approval is sufficient
   today; two when a second maintainer exists.
2. Spec changes (files under `spec/`, schemas, vector-set semantics): a PR
   MUST state the user-visible impact; after the first external
   contributor, spec PRs stay open for a 7-day comment window before merge.
3. Breaking changes to `spec_version`/`protocol_version` handling MUST be
   announced in the CHANGELOG one release ahead (see OEVP-1.0 §9).
4. This document changes only with a PR referencing the Faz/phase it
   affects.

## 3. Conformance and brand rule

- The phrases "OEVP-conformant", "OEPT-conformant", or any translation MAY
  be used ONLY by implementations with a passing machine-readable report
  against a named vector-set version, published (or linkable) in the
  interop table. Failed interop attempts MUST be recorded in the same table
  — hiding failures is prohibited (plan §Yapılmayacaklar).
- The conformance vector set version is the compatibility contract: the
  report names the version, the claim names the same version.

## 4. Licensing

- **Code**: Apache-2.0 (unchanged, both repositories).
- **Specifications, schemas-as-documentation, and docs**: CC-BY-4.0.
  The JSON Schema files remain dual-viewed: as code artifacts they ship
  under Apache-2.0; quoting their prose in derivative specs is CC-BY-4.0
  with attribution.
- **Contributions**: DCO 1.1 (`Signed-off-by`), no CLA. This keeps the
  barrier low for public-sector and academic contributors.

## 5. Bus factor and access transfer (checklist — human-executed steps)

| Asset | Current | Required state before NLnet award |
| :--- | :--- | :--- |
| GitHub repositories | under `fintegra-ai` org ✓ | second admin added |
| PyPI `open-evidence-verification`, `oept` | single-owner publishing | add a second Owner or use Trusted Publishing from the org with two maintainers enabled |
| npm (future, Faz D) | n/a | publish via CI (Trusted Publishing), no personal tokens |
| Domain (if any) | n/a | registrar account shared or org-owned |
| Decision records | GOVERNANCE.md + METRICS.md | kept in-repo, never private |

The transfer MUST be executed by the human owner; the plan prohibits
pretending this is done.

## 6. Funding transparency

Decision (2026-11-01): **no funding intake is opened** (no Open Collective,
no Sponsors) until a second maintainer exists. This enforces the plan's
anti-single-person principle: money follows the commons, not a person.
When opened, income and spend are tracked publicly and linked from
METRICS.md.

## 7. Personal data and closed code

Closed-side repositories, customer data, and finance artifacts are out of
scope for governance here; the boundary is BOUNDARY.md and its CI guards.
Governance decisions MUST NOT move closed code into open repositories.
