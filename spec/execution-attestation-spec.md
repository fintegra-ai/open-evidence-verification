# Execution Attestation Specification (oev-attestation/0.1, oev-execution/0.1)

Status: Pre-1.0 Draft — HEA v0.1 Model A (local software witness,
separate process). Normative companion to
`docs/HISTORICAL_EXECUTION_ATTESTATION.md` (design) and the implementation
in `src/oev/execution.py`, `src/oev/attestation.py`, `src/oev/witness.py`.

## 1. Pre-binding and Execution ID

Before any check runs, the producer and the witness agree on a
**pre-binding** — the complete set of inputs the execution will be bound
to:

| Field | Meaning |
| --- | --- |
| `bundle_digest` | `sha256:` digest of the package bytes as presented |
| `bundle_format` | Package format string (e.g. `oept-bundle/0.1`) |
| `profile_id`, `profile_version`, `profile_digest` | The verification profile and its digest |
| `code_version` | `{engine, adapter, code_digest}` — see §4 |
| `check_ids` | Every check the profile requires (required + optional) |
| `input_digests` | `{package, profile}` digests (extendable) |
| `trust_inputs_digest` | Digest over the sorted trust inputs (§1.1) |
| `nonce` | 128-bit fresh nonce, base64url, witness-generated |
| `witness_mode` | `local-process` in v0.1 |
| `witness_key_id` | Key id of the witness key that will sign the commitment |

The **Execution ID** is `exec_` + the first 32 hex chars of
`SHA-256(JCS(pre-binding))`, where JCS is RFC 8785 canonical JSON. The
nonce makes every execution ID unique even for identical inputs; the
witness MUST generate a fresh nonce per execution (never accept a
producer-supplied nonce for the commitment).

### 1.1 Trust-inputs digest

`compute_trust_inputs_digest` canonicalises the trust inputs sorted by
`trust_id` (then `type`, then `digest`) and hashes the result. Order of
presentation does not change the digest. Duplicate `trust_id` values make
the input ambiguous and MUST NOT be relied on.

## 2. Execution commitment (oev-execution/0.1)

The witness signs the pre-binding (+ execution ID) as a DSSE v1 envelope
with payload type `application/vnd.oev.execution-commitment+json`.
The commitment is issued **before** execution starts and binds the
witness to the exact inputs. An attestation that names an execution ID
with no verifiable commitment is rejected (`NO_PREBINDING`).

The commitment envelope carries the pre-binding in full: the commitment
digest alone is not sufficient for verification, because the verifier
must recompute the Execution ID from the pre-binding fields.

## 3. Attestation (oev-attestation/0.1)

One attestation per executed check. The payload (DSSE v1, payload type
`application/vnd.oev.execution-attestation+json`):

| Field | Rule |
| --- | --- |
| `attestation_id` | `att_` + first 16 hex of `SHA-256(execution_id + ":" + check_id)` — deterministic and per-check distinct (design §5.2 names the id after the execution only; the check fold is a v0.1 deviation, see §7) |
| `execution_id` | From §1 |
| `commitment_digest` | Digest of the commitment envelope |
| `bundle_digest`, `profile_digest`, `code_version` | Must equal the commitment's values |
| `check_id`, `result_status`, `result_detail`, `result_duration_ms` | The check's observed outcome |
| `execution_status` | `COMPLETED` / `INTERRUPTED` |
| `log_anchor` | `{log_id, leaf_index, leaf_hash}` — the CHECK_COMPLETED event (§4 of the log spec) |
| `claimed_time` | Self-asserted timestamp; **time is not proven** |
| `witness_key_id` | Signing witness key |
| `limitations` | **Mandatory, non-empty** list of limitation objects (`{code, description, material}`); Model A always includes `WITNESS_LOCAL_ONLY` and `TIME_NOT_PROVEN` |
| `protocol_version` | `oev-attestation/0.1` |

Rules:

- `result_detail` is at most 1024 chars.
- `NOT_RUN` is never attested as a completed result: a check that did
  not run has no execution to prove; its HEA state is
  `HEA_NOT_APPLICABLE`, not `UNPROVEN`. The only `NOT_RUN` attestation
  allowed is one whose `execution_status` is `INTERRUPTED` (the run was
  cut short, and the check genuinely never ran) — a `NOT_RUN` result
  with `COMPLETED` execution is rejected as malformed.
- Attestations are produced **before** the receipt exists, so they carry
  no `receipt_digest`. The receipt binds attestations the other way:
  `receipt.execution_attestations[]` lists `{check_id,
  attestation_digest}` and is inside the receipt digest (§5.2
  circularity resolution). The verifier checks result equality AND
  digest equality in both directions.

## 4. Code digest

`code_digest` = `sha256:` over the canonical list of
`{path, sha256}` for every `.py` file under the installed `oev`
package (sorted by path), plus the Python version string
(`sys.version`). Third-party dependencies are **excluded** in v0.1:
the digest proves which OEVP code ran, not which libraries it ran
against. This scope is a deliberate v0.1 limit, recorded in
`docs/PROTOCOL_SECURITY_REVIEW.md`.

## 5. Signature evaluation (§3.4)

The verifier evaluates an attestation signature in this order:

1. DSSE envelope structure + payload type + schema + canonical form.
2. The signing key is looked up in the caller-supplied witness trust
   store. A key whose public-key digest is in the blocklist
   (`KNOWN_TEST_KEY_DIGESTS`, currently the committed OEPT
   conformance test-only key) is skipped even if the operator put it in
   the store — it can never authenticate an attestation.
3. Cryptographic verification (Ed25519 over the DSSE PAE).
4. If no trusted key verifies the signature: `SIGNATURE_INVALID` when
   the envelope names a caller-trusted key (keyid hint or payload
   `witness_key_id`), otherwise `SIGNATURE_UNTRUSTED`. There is no
   `ATTESTATION_UNTRUSTED` code; those two codes cover the cases.
5. Revocation (list or store `revoked` flag) → `WITNESS_KEY_REVOKED`.
6. Role must be `witness` (roleless keys sign receipts only, never
   attestations) → else `WITNESS_UNAUTHORIZED`.
7. Witness keys MUST carry `not_after`; a missing expiry is treated as
   `WITNESS_KEY_EXPIRED`. Expiry at `claimed_time` →
   `WITNESS_KEY_EXPIRED`; not-yet-valid → `WITNESS_UNAUTHORIZED`.
8. The verifying key's id must equal the payload's `witness_key_id`.

Revocation is **retroactive** for verification: a listed key's
attestations are rejected regardless of claimed time, because claimed
time is untrusted.

## 6. Verification order (offline, §6)

The offline verifier (`src/oev/hea_verifier.py`) runs the steps in
order and stops at the first failure:

0. Attestation presence (none → `NO_ATTESTATION`, unless the §7.2
   DISPROVEN conditions hold).
1. Attestation schema / canonical form / size bounds.
2. Bundle digest and profile digest against the attested values.
3. Pre-binding recomputation (Execution ID) + commitment signature.
4. Witness signatures (§5).
5. Log binding: signed checkpoint → hash chain → leaf count → Merkle
   root → EXECUTION_STARTED presence → per-check inclusion proofs.
6. Attestation ↔ receipt binding (results equal, digests equal both
   ways).
7. Code digest agreement.

`HISTORICAL_EXECUTION_UNPROVEN` always carries exactly one
`HeaReason` code (§7.3 of the design doc; `oev.models.HeaReason`).
There is no silent UNPROVEN.

## 7. Deviations from the design doc (recorded)

- **Attestation id folds in `check_id`.** The design names the id
  after the execution only; v0.1 uses
  `SHA-256(execution_id + ":" + check_id)` so per-check attestations
  stay distinct.
- **Receipt self-digest failure maps to `RESULT_CONFLICT`.** Design
  §6 step 2 names `RECEIPT_INVALID`, which is not in the §7.3 code
  list; a receipt whose self-digest fails (after re-finalisation) is
  reported as `RESULT_CONFLICT`.
- **Code digest scope** is the installed `oev` package + Python
  version only (§4).
- **No `ATTESTATION_UNTRUSTED` code.** Unknown signers are
  `SIGNATURE_UNTRUSTED`; trusted-but-wrong keys are
  `SIGNATURE_INVALID`.

## 8. What attestation proves — and does not prove

Proves: *this witness key* signed *this result* for *this check* of
*this execution* (bound to bundle/profile/code/nonce), and the result
is anchored in a hash-chained log under a signed checkpoint.

Does **not** prove: that the claimed time is true (backdating is not
prevented in v0.1); that the producer's machine was honest (Model A
witness runs on the same machine); that the check outcome is factually
correct (a proven FAIL is still a FAIL); that the execution happened
at all if the witness key itself is compromised. See
`docs/PROTOCOL_SECURITY_REVIEW.md` for the full unprovable list.
