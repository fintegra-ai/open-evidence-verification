# HEA conformance vectors (hea-01..hea-14)

Outcome-based conformance vectors for Historical Execution Attestation
(v0.1 Model A). Each vector is a scenario description plus the expected
offline-verifier outcome (`historical_execution` + `reason`); the runner
builds a synthetic HEA bundle in-process (fresh keys per run) and applies
the scenario's single mutation, so no secret key material is committed.

Run them:

```sh
python conformance/run_hea_vectors.py run          # 14/14 expected
python conformance/run_hea_vectors.py run --vector hea-03
pytest tests/test_hea_vectors.py -q
```

| Vector | Scenario | Expected |
| --- | --- | --- |
| hea-01 | valid | HISTORICAL_EXECUTION_PROVEN |
| hea-02 | no-attestations | UNPROVEN / NO_ATTESTATION |
| hea-03 | tampered-receipt | UNPROVEN / RESULT_CONFLICT |
| hea-04 | unknown-witness-key | UNPROVEN / SIGNATURE_UNTRUSTED |
| hea-05 | wrong-key-trusted-keyid | UNPROVEN / SIGNATURE_INVALID |
| hea-06 | missing-execution-started | UNPROVEN / MISSING_EXECUTION_STEP |
| hea-07 | tampered-log-event | UNPROVEN / LOG_ANCHOR_INVALID |
| hea-08 | checkpoint-signed-by-witness-key | UNPROVEN / LOG_ANCHOR_INVALID |
| hea-09 | revoked-witness-key | UNPROVEN / WITNESS_KEY_REVOKED |
| hea-10 | expired-witness-key | UNPROVEN / WITNESS_KEY_EXPIRED |
| hea-11 | test-only-key | UNPROVEN / SIGNATURE_INVALID |
| hea-12 | bundle-digest-mismatch | UNPROVEN / BUNDLE_DIGEST_MISMATCH |
| hea-13 | profile-digest-mismatch | UNPROVEN / PROFILE_DIGEST_MISMATCH |
| hea-14 | disprove-never-executed | HISTORICAL_EXECUTION_DISPROVEN |

Notes:

- There is no `ATTESTATION_UNTRUSTED` reason code in the verifier: an
  unknown signer surfaces as `SIGNATURE_UNTRUSTED`, a trusted-but-wrong
  key as `SIGNATURE_INVALID` (§7.3 code list, `oev.models.HeaReason`).
- hea-11 exercises the verifier-side test-key blocklist: the committed
  OEPT test-only key signs envelopes produced outside the library (the
  library itself refuses that key) and is wrongly present in the witness
  trust store. The blocklist skips it during verification, so the hinted
  keyid is trusted-but-unverifiable → `SIGNATURE_INVALID`.
- hea-06 has its own code, `MISSING_EXECUTION_STEP`, distinct from a
  broken chain (`LOG_ANCHOR_INVALID`).
