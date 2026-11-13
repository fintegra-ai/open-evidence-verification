# OEVP Verification Profile Specification (`oev-profile/0.1`)

Status: Pre-1.0 Draft  
Protocol Version: `oev-profile/0.1`

---

## 1. Purpose & Scope

A **Verification Profile** is an immutable, machine-readable declaration specifying what technical checks must be executed against an evidence package.

Profiles eliminate ambiguity in evidence evaluation: instead of a verifier executing an arbitrary set of proprietary checks, it executes an explicit, content-addressed profile.

---

## 2. Normative Profile Schema

Every verification profile MUST conform to `verification-profile.schema.json` (JSON Schema Draft 2020-12).

```json
{
  "protocol_version": "oev-profile/0.1",
  "profile_id": "strict-oept",
  "profile_version": "0.1.0",
  "target_format": "oept-bundle/0.1",
  "description": "Requires safe archive structure, manifest schema validation, member digest checks, and Ed25519 signature.",
  "required_checks": [
    "archive_safety",
    "manifest_structure",
    "member_digests",
    "application_signature"
  ],
  "optional_checks": [],
  "parameters": {
    "max_archive_size_bytes": 536870912,
    "max_entry_count": 10000
  }
}
```

---

## 3. Profile Content Hashing & Immutability

Named policies without cryptographic identity are vulnerable to silent modification and downgrade attacks.

1. A verification profile document is canonicalized using RFC 8785 (JSON Canonicalization Scheme - JCS).
2. The `profile_digest` is computed as:
   $$\text{profile\_digest} = \text{"sha256:"} + \text{hex}(\text{SHA-256}(\text{JCS}(\text{profile\_document})))$$
3. Every Verification Receipt referencing a profile MUST include the exact `profile_digest`.
4. Re-verifiers receiving a profile with a matching `profile_id` but different `profile_digest` MUST abort before evaluation with `PROFILE_DIGEST_MISMATCH` (`CANNOT_REPRODUCE`).

---

## 4. Check Semantics

- **`required_checks`**: Atomic checks that MUST execute and return `PASS` for the package to achieve `TECHNICAL_CHECKS_PASSED`.
- **`optional_checks`**: Atomic checks that are informational or advisory. If an optional check fails or is unverified, the overall result degrades to `TECHNICAL_CHECKS_PARTIAL`.
- **`parameters`**: Key-value map providing runtime limits and constraints (e.g. maximum archive size, allowed hash algorithms).

---

## 5. Domain profiles (`fin.*` / `ds.*` / `ai.*`)

The three domain profiles registered in `profiles/registry.json`
(#6–8) select real, computing checks implemented by the adapter-level
domain engines in `src/oev/domain/` (dispatched by the OEPT adapter
when a profile requests a domain check id). The OEVP core is untouched:
profiles still only *select* checks; the engines live one layer down,
next to the format adapter. Full check lists, input schemas, status
semantics and limits: `../../docs/DOMAIN_PROFILES.md`.

### 5.1 Check-id namespacing

Domain checks are namespaced by prefix so the dispatcher can route
them without the core learning about domains:

| Prefix | Domain | Engine | Checks |
| :--- | :--- | :--- | :--- |
| `fin.` | financial evidence | `src/oev/domain/financial.py` | 7 required + 1 optional |
| `ds.` | dataset release | `src/oev/domain/dataset.py` | 5 required + 1 optional |
| `ai.` | AI model evaluation | `src/oev/domain/ai_eval.py` | 5 required + 1 optional |

A requested check id with a domain prefix that no engine implements
returns `UNSUPPORTED`, never silence. A profile may combine the four
mechanical checks (`archive_safety`, `manifest_structure`,
`member_digests`, `application_signature`) with domain checks; the
mechanical checks run first, and a bundle that fails structural
verification reports its domain checks as `NOT_RUN`.

### 5.2 Status semantics for domain checks

The six statuses of §4 keep the meanings of `models.CheckStatus`,
with two domain-level precisions that the engines enforce and the
tests pin down:

- **Missing evidence-to-check → `NOT_RUN`; missing reference-to-judge
  → `UNVERIFIED`.** A check whose input member is absent or unreadable
  never starts and never fabricates a verdict (`NOT_RUN`). A check that
  ran on present evidence but has no declared reference to judge it
  against (no declared checksum, no reported metric, no reference
  digest) is `UNVERIFIED`. Both yield `PROFILE_UNSATISFIED` when the
  check is required, but they are distinct receipt statuses and are
  never merged into one bucket.
- **Missing *required* evidence is a `FAIL` at the completeness level.**
  `fin.evidence_completeness` FAILs when a required member is absent —
  the bundle claims a complete evidence set and that claim is false —
  while the dependent computation checks report `NOT_RUN`. A missing
  *optional* member makes its (optional) check `NOT_RUN`: the profile
  defines that check as skippable, and a skipped check is not a failed
  check.
- **`NOT_APPLICABLE` is a property of the bundle's declared kind.**
  A pro-forma invoice has no payment to match; a text dataset has no
  columns; a constant `y_true` makes R² undefined; generated-on-the-fly
  evaluation inputs have no stored file to hash. In each case the
  check ran far enough to determine its rule does not apply.
- **`UNSUPPORTED` is a capability statement.** A bundle declaring a
  domain profile version this engine build does not implement
  (supported: `0.1.0`) gets `UNSUPPORTED` for every domain check — no
  computation is run under unknown semantics. Likewise
  `ds.checksum` with a checksum algorithm other than `sha256` is
  `UNSUPPORTED` for that check alone.

### 5.3 Verifier-side policy parameters

Thresholds that decide pass/fail are verifier policy, taken from the
*profile document's* `parameters` — never from the bundle under
verification. A producer-declared threshold in a bundle manifest is
used only when the profile declares none, and then only as a fallback
to the documented default. Concretely: `ds.missing_value_rate` uses
profile `missing_threshold` (default `0.05`); `ai.*` metric agreement
uses profile `metric_abs_tol` (`1e-9`) + `metric_rel_tol` (`1e-6`);
`ai.calibration` uses profile `calibration_max_error` (`0.10`).
Amounts are always compared exactly in integer minor units; no
floating-point money comparison exists anywhere in the engines.

### 5.4 What the engines do NOT do

- They do not judge domain *truth* (whether an invoice is genuine, a
  dataset is representative, a model is good) — only the stated,
  checkable relations between the bundle's own members.
- They do not re-execute rules, fetch external data, or contact any
  network service. All inputs come from the bundle's members.
- They never read real personal or financial data: every input in the
  test fixtures and vectors is synthetic / generated.
