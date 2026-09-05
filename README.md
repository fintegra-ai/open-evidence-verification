# Open Evidence Verification Protocol (OEVP)

Small, dependency-light open protocol and reference implementation for **evidence verification and portable receipts**:
enable organizations to evaluate digital evidence packages offline against deterministic verification profiles,
bind caller-supplied trust roots, and produce portable, cryptographically signed receipts that third parties can
later inspect or independently re-verify — without trusting the originator's application or requiring any live server.

```
PACKAGE + VERIFICATION PROFILE + CALLER TRUST INPUTS
                     ↓
         TECHNICAL VERIFICATION
                     ↓
             PORTABLE RECEIPT
                     ↓
          OPTIONAL DSSE SIGNATURE
                     ↓
        OFFLINE RECEIPT INSPECTION
                     ↓
          INDEPENDENT RE-VERIFICATION
```

## 1. The Problem

Digital evidence systems frequently create vendor lock-in: an originator exports evidence in a proprietary
bundle and directs recipients to verify it via a hosted verification portal or SaaS API. If the originator's
service goes offline, the tenant is deleted, or the company dissolves, counterparties, auditors, and regulators
cannot independently determine:
- What package was evaluated?
- Which exact byte digest was verified?
- Which verification policy or profile was executed?
- Which specific technical checks passed, failed, or were never run?
- What cryptographic trust roots were supplied?
- Whether the verification receipt itself was tampered with?

## 2. What OEVP Does

OEVP defines a vendor-neutral protocol for technical evidence appraisal:
1. **Verification Profile**: A deterministic, content-addressed JSON declaration of required and optional checks.
2. **Technical Evaluation**: Execution of checks via pluggable package adapters (e.g. OEPT bundles).
3. **Portable Verification Receipt**: A self-contained JSON record capturing the exact check vector (`PASS`, `FAIL`,
   `NOT_RUN`, `NOT_APPLICABLE`, `UNVERIFIED`, `UNSUPPORTED`), trust input hashes, limitations, and aggregated status.
4. **DSSE Signature**: Optional signing of canonical receipt bytes using the Dead Simple Signing Envelope (DSSE v1).
5. **Offline Inspection**: Third-party evaluation of receipt validity and verifier identity without needing original package bytes.
6. **Package Re-verification**: Independent re-execution of profile checks against package bytes to detect deviations.

## 3. Receipt vs. Package

- An **Evidence Package** contains the underlying opaque evidence files, internal manifests, and claims (e.g. an OEPT ZIP archive).
- A **Verification Receipt** is a distinct, lightweight metadata document recording what a specific verifier evaluated at a given time.
- A receipt does NOT embed the package bytes or sensitive evidence payloads; it binds the package by its canonical SHA-256 digest (`sha256:<64 hex>`).

## 4. Inspection vs. Re-verification

OEVP strictly separates two operational procedures:
- **Receipt Inspection (`oev inspect-receipt`)**: Operates on receipt bytes alone. It verifies receipt schema validity,
  recomputes the receipt self-digest, evaluates the DSSE signature against caller-supplied verifier keys, and parses the
  recorded check results. It proves what a verifier *claimed* it did, but does NOT assert that the referenced package is valid.
- **Package Re-verification (`oev reverify`)**: Operates on both the original package bytes and the receipt. It confirms
  package digest equality, loads the exact verification profile (asserting profile content digest equality), re-runs all
  applicable checks, diffs fresh check results against the historical receipt, and reports whether the appraisal is reproducible.

## 5. Verification Profile

Verification policies must be reproducible:
- A profile declares `required_checks`, `optional_checks`, and evaluation `parameters`.
- Profiles are canonicalized using RFC 8785 (JSON Canonicalization Scheme - JCS) and referenced by content digest (`profile_digest`).
- A receipt citing a named profile without its content digest is rejected. Profile digest mismatches abort re-verification.

## 6. Caller-Supplied Trust Roots

Trust is strictly external to packages and receipts:
- Keys or metadata embedded within an evidence package or DSSE envelope are unauthenticated hints.
- Verification trust is established ONLY when a public key is explicitly supplied by the caller (`--trust-keys` for packages,
  `--verifier-keys` for receipts).
- OEVP never automatically trusts self-asserted or embedded keys.

## 7. DSSE Relationship

- DSSE is the **Dead Simple Signing Envelope specification (DSSE v1)** maintained within the Secure Systems Lab and in-toto ecosystem.
- OEVP uses DSSE v1 as its normative signing envelope for receipts (`application/vnd.oev.verification-receipt+json`).
- DSSE security signs exact payload bytes through Pre-Authentication Encoding (`PAE`).
- OEVP uses RFC 8785 (JCS) before DSSE wrapping to achieve deterministic receipt bytes and content addressing; DSSE itself authenticates the exact bytes passed to it.
- DSSE `keyid` is strictly an unauthenticated hint; a signer is trusted only if its public key matches a caller-supplied trust root.

## 8. OEPT Relationship

- **OEPT (Open Evidence Provenance Toolkit)** is a separate open-source project providing reference evidence bundle construction,
  internal manifest generation, member SHA-256 integrity checks, and offline bundle verification (`oept-bundle/0.1`).
- **OEVP** operates above OEPT. OEVP does not build bundles or define ZIP archive formats. It provides the vendor-neutral
  appraisal, profile, receipt, and re-verification protocol.
- OEPT is integrated via an optional adapter (`oev.adapters.oept`). If OEPT is not installed, the OEVP protocol core remains fully functional.

## 9. SCITT Relationship

- SCITT is standardized in **IETF RFC 9943** (*An Architecture for Trustworthy and Transparent Digital Supply Chains*).
- SCITT defines an architecture and receipts for registering signed statements in a Transparency Service.
- An **OEVP receipt** describes application-level technical verification checks performed over a package.
- An **OEVP receipt does not replace a SCITT receipt**. In future architectures, an OEVP receipt may be submitted as an artifact registered within a SCITT transparency service.

## 10. Non-Equivocation Boundary

- Standalone OEVP **does not claim non-equivocation**.
- An originator can create two contradictory evidence packages and sign both; each may receive an individually valid technical receipt.
- Detecting equivocation requires external transparency mechanisms, multi-party exchange registries, or transparency logs (e.g. RFC 9943).

## 11. Quickstart

### Installation

```bash
# Install core protocol
pip install .

# Or install with OEPT reference adapter
pip install ".[oept]"
```

### CLI Usage

```bash
# 1. Verify a package against a verification profile and emit a signed receipt
oev verify bundle.zip \
    --profile strict-profile.json \
    --trust-keys package-trust-keys.json \
    --sign-receipt verifier-private.pem \
    --signer-key-id verifier-2026 \
    --out receipt.dsse.json

# 2. Inspect a receipt offline (package bytes NOT required)
oev inspect-receipt receipt.dsse.json --verifier-keys verifier-trust-keys.json

# 3. Verify receipt cryptographic signature and trust
oev receipt verify receipt.dsse.json --verifier-keys verifier-trust-keys.json

# 4. Independently re-verify package against the historic receipt
oev reverify bundle.zip receipt.dsse.json \
    --profile strict-profile.json \
    --trust-keys package-trust-keys.json
```

## 12. Roadmap (Grant-Scope Work)

The following capabilities are deliberately reserved for subsequent grant work:
- Generic ZIP and directory package adapters.
- BagIt and RO-Crate package adapters.
- in-toto Statement attestation exporter (`https://in-toto.io/attestation/`).
- IETF RFC 9943 (SCITT) transparent statement exporter.
- Sigstore Rekor transparency log integration study.
- Full 12+ scenario conformance suite and automated archive fuzzing.
- Multi-party receipt diffing and consensus visualization.

## 13. License

Apache-2.0. See [LICENSE](LICENSE).
