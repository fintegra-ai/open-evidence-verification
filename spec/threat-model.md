# OEVP Threat Model & Security Boundaries (v0.1)

Status: Pre-1.0 Draft  
Scope: Verification Profile evaluation, Verification Receipt generation, DSSE envelope verification, offline inspection, and package re-verification.

---

## 1. Trust Invariants (Non-Negotiable)

The protocol preserves the following critical trust boundaries strictly:

- **bundle integrity != factual truth**: Byte immutability does not prove the underlying claims are true.
- **signature valid != source truth**: Valid Ed25519 cryptography proves key possession, not honesty.
- **signature valid != legal validity**: Application signatures are not qualified electronic signatures or eIDAS seals.
- **receipt != audit opinion**: A technical receipt records check statuses; it is not a commercial or legal audit opinion.
- **verification result != commercial correctness**: Correct digests do not indicate commercial validity.
- **trusted public key != trustworthy claim**: Trusting a key for signature verification does not endorse the payload's accuracy.
- **provenance assertion != cryptographic membership proof**: Recorded provenance traces are subject to the verifier's profile.
- **verification policy != regulatory approval**: Executing a verification profile does not confer statutory compliance.
- **NOT_RUN != PASS**: Skipped checks are never counted as successes.
- **UNVERIFIED != FAILED**: Missing trust context is distinct from cryptographic failure.
- **UNKNOWN != INVALID**: Unrecognized metadata does not automatically corrupt valid checks.

---

## 2. Adversary Capabilities

The attacker is assumed to have the ability to:
1. Generate arbitrary evidence packages with malformed, tampered, or hostile internal archives.
2. Intercept and alter receipts, envelopes, and packages in transit or at rest.
3. Generate arbitrary Ed25519 keypairs and sign forged receipts.
4. Substitute verification profiles with weakened or downgraded rulesets.
5. Present historical receipts for modified or substituted packages.
6. Attempt denial-of-service through archive expansion (zip bombs) or large numbers.

---

## 3. Threats Addressed & Mitigations

| Threat | Attack Vector | Protocol Mitigation |
| :--- | :--- | :--- |
| **Receipt Tampering** | Attacker modifies a check status (e.g. `FAIL` to `PASS`) or package digest in an issued receipt. | Mitigated by DSSE signature envelope over `PAE(payloadType, canonical_payload)`. Any 1-bit change breaks the signature. Additionally, the receipt self-digest (`receipt_digest`) detects tampering in unsigned receipts. |
| **Verifier Signer Substitution** | Attacker signs a fraudulent receipt using their own key and claims the verifier's identity. | Mitigated by caller-supplied verifier trust roots (`--verifier-keys`). The verifier is trusted only if its public key matches a caller trust root. |
| **Self-Trusted Embedded Keys** | Attacker embeds a public key in the package or receipt and expects the verifier to trust it. | Strictly prohibited. Embedded keys are treated as unauthenticated labels. Trust roots MUST be supplied explicitly by the caller. |
| **Profile Downgrade / Substitution** | Attacker substitutes a strict profile with an empty profile under the same `profile_id`. | Mitigated by binding the canonical `profile_digest` (SHA-256) inside the receipt. Re-verification detects any profile modification and aborts with `PROFILE_DIGEST_MISMATCH`. |
| **Stale Receipt Replay** | Attacker presents a passing receipt issued for Package A as proof for Package B. | Mitigated by binding `package.digest` (SHA-256) inside the receipt. Re-verification recomputes the package digest and aborts on mismatch. |
| **Malicious Archive / Expansion** | Attacker submits zip bombs, path traversals (`../`), or symlink attacks. | Delegated to package adapters (e.g. OEPT's streaming verification) with strict entry-count, total uncompressed size, and path sanitization limits prior to content reading. |
| **Confidentiality / Data Leakage** | Confidential payload data leaked to third-party auditors inspecting receipts. | Receipts record digests, check IDs, execution times, and limitation codes only. No raw evidence bytes or PII are copied into receipts. |
| **JCS Number Precision Attacks** | Attacker injects large integers outside standard IEEE 754 precision to cause parser divergence. | OEVP strictly validates that all integers fall within $[-(2^{53} - 1), 2^{53} - 1]$ prior to canonicalization, rejecting unsafe values. |

---

## 4. Explicit Non-Goals

The protocol explicitly does NOT provide:
- **Factual truth of evidence**: Opaque bytes are verified for integrity, not real-world factuality.
- **Legal certification**: Receipts are technical artifacts, not legal or regulatory certifications.
- **Non-equivocation**: Standalone OEVP does not prevent a signer from issuing two contradictory packages.
- **Trusted timestamp authority**: `recorded_verification_time` is an unauthenticated verifier clock reading, not an RFC 3161 timestamp.
- **Malware detection**: Evidence packages are not scanned for malicious payloads.
- **Content execution**: Verifiers NEVER execute code or binaries contained within evidence packages.

---

## 5. Relationship to SCITT (RFC 9943)

- **IETF RFC 9943** (*An Architecture for Trustworthy and Transparent Digital Supply Chains*) standardizes Transparency Services and transparent statement receipts.
- **OEVP does not replace SCITT**:
  - A **SCITT receipt** is proof that a signed statement was registered in an append-only transparency service ledger with a Merkle tree inclusion proof.
  - An **OEVP receipt** is a portable record of granular technical verification checks performed over a package under a specific profile.
- **Future Anchoring**: An OEVP verification receipt may be formatted and submitted as an input statement registered within a SCITT transparency service to achieve non-equivocation.
