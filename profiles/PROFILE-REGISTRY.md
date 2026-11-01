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

## Why this matters

Faz F's gate requires "at least one profile added via the registry without
touching the core". Profile 0 demonstrates the mechanism end to end: the
profile document moved from the closed demo side into
`profiles/finance-demo-neutral/profile.json`, is exercised by the existing
vector set, and its registration diff adds zero lines to `src/`.

## Non-goals

- The registry does not evaluate domain correctness: it records which
  checks a profile requires and which vectors pass. Whether a check
  meaningfully appraises a domain is the profile maintainer's
  responsibility (and the reviewer's, per GOVERNANCE).
- Rule re-execution / deterministic rule replay remains out of scope for
  the core (NLnet-plan funded work); profiles select checks, they do not
  define executable rules.
