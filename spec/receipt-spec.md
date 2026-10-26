# OEVP Verification Receipt Specification (`oev-receipt/0.1`)

Status: Pre-1.0 Draft  
Protocol Version: `oev-receipt/0.1`

---

## 1. Purpose & Scope

The Open Evidence Verification Protocol defines a portable, self-contained, cryptographically signable artifact called a **Verification Receipt**.

A Verification Receipt records the technical appraisal performed by an identified verifier over a specific evidence package under a deterministic verification profile at a recorded time.

It is designed to survive the permanent decommissioning of the originator, verifier, and underlying cloud infrastructure. Holding only the receipt (and the verifier's public key), an auditor can inspect the claims made by the verifier. Holding both the receipt and the original package bytes, an auditor can independently re-verify the evaluation.

---

## 2. Normative Receipt Schema

Every receipt MUST conform to `verification-receipt.schema.json` (JSON Schema Draft 2020-12).

```json
{
  "receipt_id": "00000000-0000-4000-8000-000000000001",
  "protocol_version": "oev-receipt/0.1",
  "recorded_verification_time": "2026-09-05T12:00:00Z",
  "package": {
    "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "format": "oept-bundle/0.1",
    "size_bytes": 1024,
    "declared_id": "bundle-2026-001"
  },
  "profile": {
    "profile_id": "strict-oept",
    "profile_version": "0.1.0",
    "profile_digest": "sha256:4a5b6c..."
  },
  "verifier": {
    "software": "oev",
    "version": "0.1.0",
    "environment": "linux-x86_64"
  },
  "trust_inputs": [
    {
      "trust_id": "corp-root-2026",
      "type": "public_key",
      "digest": "sha256:7b6257..."
    }
  ],
  "checks": [
    {
      "check_id": "archive_safety",
      "category": "safety",
      "status": "PASS",
      "detail": "Archive structure and member paths are safe",
      "duration_ms": 4
    }
  ],
  "limitations": [],
  "overall_result": "TECHNICAL_CHECKS_PASSED",
  "receipt_digest": "sha256:9f8e7d..."
}
```

### Optional: re-issuance reference

A receipt MAY additionally carry an optional `superseded_receipt` object with exactly two
members, `receipt_id` and `receipt_digest`, identifying a prior receipt that this receipt
supersedes (e.g. after a re-verification triggered re-issuance). The field is not set by
the reference engine today; verifiers must not treat its presence as an integrity
statement about the superseded receipt.

---

## 3. Normative Receipt Digest Recursion Rule

To prevent circular hashing dependencies, the receipt self-digest is defined strictly as follows:

1. Let `receipt_unsigned_body` be the Verification Receipt JSON object **omitting** the `receipt_digest` key.
2. Canonicalize `receipt_unsigned_body` using RFC 8785 (JSON Canonicalization Scheme - JCS).
3. Compute SHA-256 over the canonical UTF-8 bytes:
   $$\text{receipt\_digest} = \text{"sha256:"} + \text{hex}(\text{SHA-256}(\text{JCS}(\text{receipt\_unsigned\_body})))$$
4. The final serialized receipt includes the computed `receipt_digest` key.
5. Verifiers recomputing the digest MUST remove `receipt_digest` from the parsed object, canonicalize the remainder via JCS, and assert equality against the declared value.

---

## 4. Check Status Vocabulary

Verifiers MUST NOT emit generic boolean statuses (such as `verified: true`). Each check in `checks[]` MUST report one of six exact states:

| Status | Definition |
| :--- | :--- |
| **`PASS`** | The check executed and all evaluated criteria passed. |
| **`FAIL`** | The check executed and one or more evaluated criteria failed. |
| **`NOT_RUN`** | The check was defined in the profile but was not executed (e.g. skipped due to prior structural failure). |
| **`NOT_APPLICABLE`** | The check does not apply to this package format. |
| **`UNVERIFIED`** | Insufficient trust or external context was supplied to reach a conclusion (e.g. unsigned bundle). |
| **`UNSUPPORTED`** | The verifier software engine lacks implementation for this check. |

---

## 5. Overall Result Aggregation Contract

The `overall_result` is deterministically aggregated from the check vector:

1. **`EXECUTION_INCOMPLETE`**: Verifier execution was interrupted by an unhandled error, fatal parser failure, or resource boundary.
2. **`TECHNICAL_CHECKS_FAILED`**: At least one `REQUIRED` check executed and returned `FAIL`.
3. **`PROFILE_UNSATISFIED`**: No required check returned `FAIL`, but at least one `REQUIRED` check returned `NOT_RUN`, `NOT_APPLICABLE`, `UNVERIFIED`, or `UNSUPPORTED`.
   - *Example:* A profile requires `application_signature`. An unsigned package returns `UNVERIFIED` for that check. The overall verdict is `PROFILE_UNSATISFIED` (never `PARTIAL` or `PASSED`).
4. **`TECHNICAL_CHECKS_PASSED`**: Every `REQUIRED` check returned `PASS`, and all executed `OPTIONAL` checks returned `PASS` or `NOT_APPLICABLE`, with zero material limitations.
5. **`TECHNICAL_CHECKS_PARTIAL`**: Every `REQUIRED` check returned `PASS`, but one or more `OPTIONAL` checks returned `FAIL`, `NOT_RUN`, `UNVERIFIED`, or `UNSUPPORTED`, or explicit limitations were recorded.

---

## 6. Time Semantics

The field `recorded_verification_time` is an ISO 8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`) generated from the verifier's system clock.

**Explicit Invariant:** This is an unauthenticated operational timestamp. It is NOT an RFC 3161 trusted timestamp, NOT a cryptographic proof of time, and NOT an eIDAS time assertion.

---

## 7. Storage & Independence Guarantees

A receipt MUST NOT mandate live network endpoints, cloud URLs, or proprietary IDs. All cryptographic cross-references use lowercase hex SHA-256 strings prefixed with `sha256:`. An auditor holding only the receipt file can inspect and evaluate it completely offline.
