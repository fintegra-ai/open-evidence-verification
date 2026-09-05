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
