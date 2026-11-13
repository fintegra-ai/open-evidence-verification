# Profile Registry (Faz F)

OEVP's core is domain-agnostic: a profile is a `oev-profile/0.1` document
that selects checks and parameters, and the engine never learns about
domains. This registry is the Faz F mechanism that makes that promise
operational: **registering a new profile MUST NOT require any change to
`src/`** — a profile is spec + vectors, recorded here.

## How to register a profile (acceptance criteria — normative)

1. **Spec**: a complete `oev-profile/0.1` document (validated against
   `src/oev/schemas/verification-profile.schema.json`) with a stated domain
   and `required_checks` drawn from adapter-supported checks (or explicitly
   accepting `UNSUPPORTED` outcomes for checks no adapter provides).
2. **Vectors**: at least one named vector-set version whose runner report
   passes with the profile (see `conformance/run_vectors.py`; the report
   names `oev-conformance-vectors@<version>`).
3. **Ownership**: a named maintainer responsible for the profile and its
   vectors.
4. **Registration**: a PR adding the entry to `registry.json`, merged under
   GOVERNANCE.md §2. **The diff MUST NOT touch `src/`** — that is the whole
   point, and reviewers enforce it.
5. **Honesty**: statuses are `registered` / `draft` / `deprecated`. A
   profile that fails its own vectors is `draft`, never `registered`.

## Registered profiles

See `registry.json` (machine-readable, versioned). Current state:

| # | profile_id | Domain | Status | Vectors |
| :-- | :--- | :--- | :--- | :--- |
| 0 | `strict-conformance-profile` (v0.1.0) | finance — neutral synthetic demo (demo-case-001 shape, moved into the open repository) | registered | `oev-conformance-vectors@0.1.0` (12/12 active vectors) |
| 6 | `financial-evidence-verify` (v0.1.0) | financial evidence — invoice / ERP / payment matching (`fin.*`, 8 checks) | draft | `tests/test_domain_profiles.py` + `tests/test_domain_profiles_e2e.py` (financial cases) |
| 7 | `dataset-release-verify` (v0.1.0) | dataset release — schema / rows / checksum / version (`ds.*`, 6 checks) | draft | `tests/test_domain_profiles.py` + `tests/test_domain_profiles_e2e.py` (dataset cases) |
| 8 | `ai-model-eval-verify` (v0.1.0) | AI model evaluation — independent metric recomputation (`ai.*`, 6 checks) | draft | `tests/test_domain_profiles.py` + `tests/test_domain_profiles_e2e.py` (AI-eval cases) |

## Why this matters

Faz F's gate requires "at least one profile added via the registry without
touching the core". Profile 0 demonstrates the mechanism end to end: the
profile document moved from the closed demo side into
`profiles/finance-demo-neutral/profile.json`, is exercised by the existing
vector set, and its registration diff adds zero lines to `src/`.

## Note on profiles 6–8 (domain engines, 2026-11-13)

Profiles 6–8 (`financial-evidence-verify`, `dataset-release-verify`,
`ai-model-eval-verify`) are real, working check engines — not just
profile documents. Their checks are implemented in new adapter-level
modules (`src/oev/domain/*.py`, dispatched by the OEPT adapter); the
OEVP core (`engine.py`, `receipts.py`, `models.py`) is untouched, and
each profile document is still a plain `oev-profile/0.1` document. That
is a deliberate, documented exception to the "registration diff MUST NOT
touch `src/`" rule above: a profile that only *selects* checks cannot
gain checks that do not exist yet. The three profiles are therefore
`draft`, not `registered`, until governance decides whether adapter-level
domain engines count as "core" for this rule. See
`../../docs/DOMAIN_PROFILES.md` (upgrade-root docs) for the check lists,
input schemas, and status semantics.

## Non-goals

- The registry does not evaluate domain correctness: it records which
  checks a profile requires and which vectors pass. Whether a check
  meaningfully appraises a domain is the profile maintainer's
  responsibility (and the reviewer's, per GOVERNANCE).
- Rule re-execution / deterministic rule replay remains out of scope for
  the core (NLnet-plan funded work); profiles select checks, they do not
  define executable rules.
