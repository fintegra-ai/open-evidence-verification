# Open Evidence Verification Protocol (OEVP)

OEVP is a small, dependency-light open protocol and reference implementation for
**technical evidence verification with portable receipts**. It lets a verifier evaluate a
digital evidence package offline against a deterministic, content-addressed verification
profile, bind caller-supplied trust roots, and produce a portable, optionally signed
receipt that third parties can inspect or independently re-verify later — without the
originator's application, without a hosted portal, and without any live server.

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

| | |
| :--- | :--- |
| Package | [`oev`](pyproject.toml) — Python ≥ 3.10, Apache-2.0 |
| Protocol drafts | [`spec/`](spec/) — `oev-profile/0.1`, `oev-receipt/0.1`, `oev-reverification/0.1` |
| Conformance kit | [`conformance/`](conformance/README.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changes | [CHANGELOG.md](CHANGELOG.md) |

## Why OEVP exists

Digital evidence systems frequently create vendor lock-in: an originator exports evidence
in a proprietary bundle and directs recipients to verify it via a hosted verification
portal or SaaS API. If the originator's service goes offline, the tenant is deleted, or
the company dissolves, counterparties, auditors, and regulators cannot independently
determine:

- What package was evaluated, and which exact byte digest was verified?
- Which verification policy was executed, and could it have been swapped for a weaker one?
- Which specific technical checks passed, failed, or were never run?
- What cryptographic trust roots were supplied?
- Whether the verification receipt itself was tampered with after issuance?

OEVP addresses these questions with two self-contained artifacts: a **verification
receipt** (what a verifier claims it did) and a **re-verification procedure** (checking
those claims against the package bytes yourself).

## What OEVP is — and what it is not

OEVP defines a vendor-neutral protocol for **technical** evidence appraisal:

1. **Verification Profile** — a deterministic, content-addressed JSON declaration of
   required and optional checks ([spec/profile-spec.md](spec/profile-spec.md)).
2. **Technical Evaluation** — execution of checks via pluggable package adapters
   (e.g. [OEPT](#relationship-to-oept) bundles).
3. **Portable Verification Receipt** — a self-contained JSON record capturing the exact
   check vector (`PASS`, `FAIL`, `NOT_RUN`, `NOT_APPLICABLE`, `UNVERIFIED`,
   `UNSUPPORTED`), trust input hashes, limitations, and aggregated status
   ([spec/receipt-spec.md](spec/receipt-spec.md)).
4. **DSSE Signature** — optional signing of canonical receipt bytes using the Dead Simple
   Signing Envelope v1 ([spec/dsse-binding.md](spec/dsse-binding.md)).
5. **Offline Inspection** — third-party evaluation of receipt validity and verifier
   identity without needing the original package bytes.
6. **Package Re-verification** — independent re-execution of profile checks against
   package bytes to detect deviations from the recorded appraisal.

Since 0.2.0, OEVP also defines a **Decision Evidence Pack** format
(`oev-decision-pack/0.2`) for packaging the evidence trail of a decision process; see
[Decision evidence packs](#decision-evidence-packs-oev-decision-pack02).

Equally important, OEVP is **not**:

- **Not a statement of truth.** A valid receipt proves that an identified verifier ran
  the declared checks against specific package bytes. It says nothing about whether the
  underlying content is factually, commercially, or legally true.
- **Not a legal or compliance instrument.** Receipts and signatures are not qualified
  electronic signatures, eIDAS seals, regulatory approvals, or audit opinions.
- **Not fraud detection.** OEVP detects byte tampering, profile substitution, and stale
  receipts. It does not judge intent or detect deceptive-but-intact content.
- **Not a transparency log.** Standalone OEVP does not provide non-equivocation; see
  [Non-equivocation boundary](#non-equivocation-boundary).
- **Not a malware scanner.** Evidence packages are never executed and are not scanned
  for malicious payloads; archive-safety checks are structural only.

## Trust boundaries in plain language

These are the rules the implementation enforces; each is covered by tests in
`tests/`:

- **Trust is caller-supplied.** Verification trust is established *only* when you
  explicitly supply public keys (`--trust-keys` for packages, `--verifier-keys` for
  receipts). Keys embedded inside a package or envelope are unauthenticated hints and
  are never automatically trusted.
- **A valid signature proves key possession, not honesty.** A DSSE signature that
  verifies cryptographically is still untrusted unless the signing key matches one of
  *your* supplied trust roots.
- **A receipt is a claim, not a conclusion.** Inspection proves what a verifier
  *recorded*; only re-verification against the package bytes checks whether the claim
  reproduces.
- **Skipped is not passed.** `NOT_RUN` and `UNVERIFIED` check states never count as
  successes; a required check that cannot complete fails the overall result.
- **Profiles are pinned by content.** Receipts embed the SHA-256 digest of the
  canonicalized profile. Re-verification aborts with `PROFILE_DIGEST_MISMATCH` if a
  profile with the same ID but different content is supplied.
- **Receipts are bound to one package.** Receipts embed the package's SHA-256 digest;
  presenting a passing receipt for different package bytes is detected as a mismatch.
- **Timestamps are unauthenticated.** `recorded_verification_time` comes from the
  verifier's clock. It is not an RFC 3161 trusted timestamp.

## Install

Python ≥ 3.10 (see `requires-python` in [pyproject.toml](pyproject.toml)).

```bash
# Core protocol (receipt generation, DSSE signing, inspection, re-verification plumbing)
pip install .

# Development install with test/lint/type tooling
pip install -e ".[dev]"
```

> **Optional OEPT adapter:** `pip install ".[oept]"` enables evaluation of OEPT bundles.
> The OEPT package ([Open Evidence Provenance Toolkit](#relationship-to-oept)) is a
> sibling project that is **not yet published to PyPI**; until it is, install OEPT from
> its own repository. Without it, the OEVP core still runs everything except
> OEPT-specific package checks — including all receipt inspection commands below.

## Quickstart

Every command below was executed against the committed conformance fixture
[`01-valid-oept-pass`](conformance/fixtures/01-valid-oept-pass/). Exit codes: `0` on the
positive outcome, `2` when the verdict is negative (e.g. mismatch), `1` on input errors.

### 1. Inspect a receipt offline — no package bytes, no optional extras

This works with a core-only install because receipt inspection never touches the
package:

```bash
oev inspect-receipt conformance/fixtures/01-valid-oept-pass/receipt.dsse.json \
    --verifier-keys conformance/fixtures/01-valid-oept-pass/verifier-trust-keys.json
```

You get the recorded check vector, the verifier identity, the receipt self-digest, and
the signer trust decision:

```
OEVP VERIFICATION RECEIPT INSPECTION REPORT
======================================================================
Receipt ID:             465d3382-1102-4f4e-b7ad-fe8ef24aac0c
...
Receipt Self-Digest:    sha256:5ab487cf... (VALID)
DSSE Envelope Signed:   YES
Signature Math Valid:   YES
Caller Trusted Signer:  YES
Trusted Signer Key ID:  test-verifier-2026
----------------------------------------------------------------------
Check Vector (4 checks):
  [CheckStatus.PASS] archive_safety        (safety) ...
  [CheckStatus.PASS] manifest_structure    (structure) ...
  [CheckStatus.PASS] member_digests        (integrity) ...
  [CheckStatus.PASS] application_signature (signature) ...
```

To check only the cryptographic facts (signature + trust + digest), use the narrow
command:

```bash
oev receipt verify conformance/fixtures/01-valid-oept-pass/receipt.dsse.json \
    --verifier-keys conformance/fixtures/01-valid-oept-pass/verifier-trust-keys.json
```

### 2. Verify a package and emit a signed receipt

This requires the optional OEPT adapter (the sample package is an `oept-bundle/0.1`
archive). First generate an Ed25519 keypair — any PKCS#8/SPKI PEM generator works:

```bash
openssl genpkey -algorithm ed25519 -out verifier-private.pem
openssl pkey -in verifier-private.pem -pubout -out verifier-public.pem
```

Save your public key as a verifier trust file — anyone inspecting your receipts will
pass this file to `--verifier-keys` to trust your signatures:

```json
[
  {
    "key_id": "my-verifier-2026",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
  }
]
```

```bash
cat > my-verifier-keys.json <<'EOF'
<paste the JSON above with your full public PEM>
EOF
```

Then run the verification loop (package trust keys come from the fixture; receipt trust
keys are yours):

```bash
F=conformance/fixtures/01-valid-oept-pass

# Verify the sample package; sign the receipt with your key
oev verify $F/package.zip \
    --profile $F/profile.json \
    --trust-keys $F/package-trust-keys.json \
    --sign-receipt verifier-private.pem \
    --signer-key-id my-verifier-2026 \
    --out my-receipt.dsse.json
# → Overall Result: TECHNICAL_CHECKS_PASSED

# Inspect your receipt offline
oev receipt verify my-receipt.dsse.json --verifier-keys my-verifier-keys.json

# Independently re-verify the package against your receipt
oev reverify $F/package.zip my-receipt.dsse.json \
    --profile $F/profile.json \
    --trust-keys $F/package-trust-keys.json
# → Re-verification Result: MATCH
```

Try tampering with the sample: flip a byte inside `package.zip` (or re-run `reverify`
with the package from
[`03-required-signature-unsatisfied`](conformance/fixtures/03-required-signature-unsatisfied/))
and the re-verification reports `MISMATCH` with a package digest mismatch note. Swap in
a weakened profile under the same `profile_id` and it aborts with
`CANNOT_REPRODUCE` / `PROFILE_DIGEST_MISMATCH`.

## Decision evidence packs (`oev-decision-pack/0.2`)

New in 0.2.0, alongside package verification, OEVP can package the evidence trail of a
**decision process** into a portable, integrity-checked directory: a case record,
recorded facts, versioned rule runs (rules-as-data: recorded inputs, digests, and
outcomes — not re-executed code), findings, review actions, a timeline, the snapshot
context the decision was made against, and arbitrary artifacts under `artifacts/`.

A pack is built from a source directory, its manifest is optionally DSSE-signed, and any
third party can verify technical integrity offline:

```bash
# Build: canonicalizes every JSON member (RFC 8785), hashes members, writes manifest.json
oev pack build ./my-case-source --out ./my-pack --pack-id pack-2026-001

# Sign the canonical manifest bytes with DSSE v1 / Ed25519 (writes manifest.dsse.json)
oev pack sign ./my-pack --key verifier-private.pem --key-id my-verifier-2026

# Offline integrity verification (manifest schema, canonical encoding, pack digest,
# member digests, cross-member references, and manifest signature trust)
oev pack verify ./my-pack --verifier-keys my-verifier-keys.json
# → Overall: PACK_VALID · Signature Crypto: VALID · Signer Trusted: YES

# Emit a portable pack verification receipt (add --sign-receipt <key.pem> to DSSE-sign it)
oev pack verify ./my-pack --verifier-keys my-verifier-keys.json --out pack-receipt.json

# Third-party offline verification of that receipt — receipt alone, or bound to the pack
oev pack receipt verify pack-receipt.json --verifier-keys my-verifier-keys.json
oev pack receipt verify pack-receipt.json --pack ./my-pack

# Snapshot replay safety: pin the pack when accepted, replay later against the pin
oev pack replay ./my-pack --expect-pack-digest sha256:<64 hex> --verifier-keys my-verifier-keys.json
```

Each JSON member must conform to its schema in
[`schemas/`](schemas/) (`decision-pack-case`, `decision-pack-facts`,
`decision-pack-rule-runs`, `decision-pack-findings`, `decision-pack-review-actions`,
`decision-pack-timeline`, `decision-pack-snapshot-context`); the manifest records each
member's SHA-256 digest and `pack_digest` is a self-digest over the canonical manifest
body, using the same recursion rule as receipts.

**Pack exit codes** (`pack verify`, `pack receipt verify`, `pack replay`):

- `0` — positive outcome: `PACK_VALID` / `RECEIPT_VALID` / `REPLAY_OK`, and trusted where
  trust roots were supplied.
- `1` — negative technical verdict (`PACK_INVALID` / `RECEIPT_INVALID`) or an input error
  (missing pack, malformed receipt).
- `2` — the artifact itself is intact but a pinned trust expectation fails: a manifest
  signature that is `SIGNATURE_INVALID` or not from a trusted key, a replay refusal
  (`PACK_HASH_CHANGED`, `SIGNATURE_UNTRUSTED`, `SNAPSHOT_INVALID`, `SNAPSHOT_LEAK`), or a
  receipt whose envelope signature is not established valid. An unsigned pack is never
  exit-`1`-invalid because of the missing signature alone — it is reported as
  `SIGNATURE_NOT_PRESENT`, and it becomes a trust failure (`2`) only when the caller
  pinned trust roots.

**Archive transport** is a library API (`oev.pack_archive`): `create_pack_archive` writes
a deterministic ZIP of a pack; `extract_pack_archive` validates every entry
*before* writing anything and refuses path-traversal names (zip-slip), duplicate member
names, encrypted entries, and decompression bombs. Always re-run `oev pack verify` on an
extracted pack (see [spec/decision-pack-spec.md §9](spec/decision-pack-spec.md)).

**Integrity boundary:** pack verification asserts technical integrity only — that
members are present, byte-identical to their manifest digests, canonically encoded, and
internally consistent. It never asserts factual, commercial, or legal truth, never
asserts compliance approval or fraud detection, and never re-executes recorded rules.
See [spec/decision-pack-spec.md](spec/decision-pack-spec.md) for the normative format
specification, and [examples/demo-case-001](examples/demo-case-001) for a fully
synthetic, domain-neutral example pack (regenerate with `python examples/make_example.py`).

## Running the tests

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src tests
pytest
```

Tests that exercise OEPT bundle fixtures are skipped automatically when the optional
OEPT adapter is not installed (see [CONTRIBUTING.md](CONTRIBUTING.md) for enabling the
full conformance run).

## Documentation

- [spec/profile-spec.md](spec/profile-spec.md) — verification profile format, content
  hashing, check semantics (`oev-profile/0.1`).
- [spec/receipt-spec.md](spec/receipt-spec.md) — receipt schema, check status vocabulary,
  aggregation contract, time semantics (`oev-receipt/0.1`).
- [spec/dsse-binding.md](spec/dsse-binding.md) — DSSE v1 envelope binding, PAE, trust
  evaluation.
- [spec/decision-pack-spec.md](spec/decision-pack-spec.md) — decision evidence pack
  layout, canonical encoding, manifest rules, honest vocabularies, and verification
  procedure (`oev-decision-pack/0.2`).
- [spec/threat-model.md](spec/threat-model.md) — trust invariants, adversary model,
  threats and mitigations, explicit non-goals.
- [conformance/README.md](conformance/README.md) — the fixture corpus and expected
  results.
- [SECURITY.md](SECURITY.md) — vulnerability reporting, scope, and the limits of
  verification.

## Design notes

### Receipt vs. package

- An **evidence package** contains the underlying opaque evidence files, internal
  manifests, and claims (e.g. an OEPT ZIP archive).
- A **verification receipt** is a distinct, lightweight metadata document recording what
  a specific verifier evaluated at a given time.
- A receipt does **not** embed the package bytes or sensitive evidence payloads; it
  binds the package by its canonical SHA-256 digest (`sha256:<64 hex>`).

### Inspection vs. re-verification

OEVP strictly separates two operational procedures:

- **Receipt Inspection (`oev inspect-receipt`)** operates on receipt bytes alone. It
  verifies receipt schema validity, recomputes the receipt self-digest, evaluates the
  DSSE signature against caller-supplied verifier keys, and parses the recorded check
  results. It proves what a verifier *claimed* it did, but does **not** assert that the
  referenced package is valid.
- **Package Re-verification (`oev reverify`)** operates on both the original package
  bytes and the receipt. It confirms package digest equality, loads the exact
  verification profile (asserting profile content digest equality), re-runs all
  applicable checks, diffs fresh check results against the historical receipt, and
  reports whether the appraisal is reproducible.

Re-verification establishes that the recorded appraisal is **reproducible** for the
supplied package and profile. It does **not** establish who issued the receipt: an
attacker who rewrites the payload, recomputes the self-digest, and re-signs with
their own key produces an internally consistent receipt. Receipt authenticity is a
separate check — `oev receipt verify` against caller-pinned verifier keys.

### Relationship to OEPT

**OEPT (Open Evidence Provenance Toolkit)** is a separate, sibling open-source project
providing reference evidence bundle construction, internal manifest generation, member
SHA-256 integrity checks, and offline bundle verification (`oept-bundle/0.1`). OEVP
operates above OEPT: it does not build bundles or define ZIP archive formats. OEPT is
integrated via an optional adapter (`oev.adapters.oept`); if OEPT is not installed, the
OEVP protocol core remains fully functional.

### DSSE relationship

- DSSE is the **Dead Simple Signing Envelope** specification (DSSE v1), maintained in the
  Secure Systems Lab / in-toto ecosystem ([DSSE on GitHub](https://github.com/secure-systems-lab/dsse)).
- OEVP uses DSSE v1 as its normative signing envelope for receipts
  (`application/vnd.oev.verification-receipt+json`).
- DSSE authenticates exact payload bytes through Pre-Authentication Encoding (PAE).
  OEVP applies RFC 8785 (JCS) canonicalization before DSSE wrapping for deterministic
  receipt bytes and content addressing.
- The DSSE `keyid` is an unauthenticated hint; a signer is trusted only if its public
  key matches a caller-supplied trust root.

### SCITT relationship

SCITT is standardized in IETF [RFC 9943](https://www.rfc-editor.org/info/rfc9943)
(*An Architecture for Trustworthy and Transparent Digital Supply Chains*), which defines
registering signed statements in a Transparency Service. An OEVP receipt records
application-level technical checks over a package; it does **not** replace a SCITT
receipt. In future architectures, an OEVP receipt may be submitted as an artifact
registered within a SCITT transparency service.

### Non-equivocation boundary

Standalone OEVP does **not** claim non-equivocation. An originator can create two
contradictory evidence packages and sign both; each may receive an individually valid
technical receipt. Detecting equivocation requires external transparency mechanisms,
multi-party exchange registries, or transparency logs (e.g. RFC 9943).

## Roadmap

Deliberately reserved for later work (see [CHANGELOG.md](CHANGELOG.md) for what has
landed):

- Generic ZIP and directory package adapters.
- BagIt and RO-Crate package adapters.
- in-toto Statement attestation exporter ([in-toto.io/attestation](https://in-toto.io/attestation/)).
- RFC 9943 (SCITT) transparent statement exporter.
- Sigstore Rekor transparency log integration study.
- Extended conformance suite and automated archive fuzzing.
- Multi-party receipt diffing and consensus visualization.

## License

Apache-2.0. See [LICENSE](LICENSE).
