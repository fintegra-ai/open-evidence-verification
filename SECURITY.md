# Security Policy

This document describes how to report security vulnerabilities in the Open Evidence
Verification Protocol (OEVP), what is in scope, and — just as important — what OEVP
verification does **not** protect against. The detailed adversary model, threats, and
mitigations live in [spec/threat-model.md](spec/threat-model.md).

## Reporting a vulnerability

If you discover a potential security vulnerability in the OEVP implementation or
specification, please report it privately:

- Use GitHub's **Private vulnerability reporting** feature (Security tab →
  "Report a vulnerability") on this repository.

Do **not** open a public GitHub issue for security-sensitive reports.

Please include:

- A description of the issue.
- Steps to reproduce or a proof of concept.
- Affected components (e.g. DSSE parsing, canonicalization, profile evaluation,
  receipt/re-verification engines, decision pack verification, the CLI).
- The potential impact.

We follow coordinated vulnerability disclosure: reports are acknowledged, investigated,
and fixed before any public disclosure. Please give us a reasonable window to release a
fix before publishing details.

## Scope

**In scope:**

- The `oev` Python package (`src/oev/`): canonicalization, hashing, DSSE signing and
  parsing, trust evaluation, verification engine, receipt inspection, package
  re-verification, decision pack build/verify, and the `oev` CLI.
- The JSON schemas under `schemas/`.
- The specification documents under `spec/` (protocol-level weaknesses).

**Out of scope:**

- Vulnerabilities in third-party dependencies — please report those upstream
  (`cryptography`, `jcs`, `jsonschema`).
- The optional OEPT adapter's target format and the OEPT project itself — report those
  to the OEPT project.
- Issues that require the attacker to already control the caller's trust roots, the
  verifier's private signing key, or the machine running the verifier.
- Denial of service through unlimited local resources is mitigated with explicit input
  bounds; reports of resource exhaustion that requires privileged local access are out
  of scope.

## Supported versions

OEVP is pre-1.0 software with draft specifications (`oev-profile/0.1`,
`oev-receipt/0.1`, `oev-reverification/0.1`, `oev-decision-pack/0.2`). Only the latest
published release receives security fixes. The specifications may still change in
breaking ways between 0.x releases.

## What verification does not protect against

OEVP receipts and decision packs are **technical integrity** artifacts. Even a fully
valid, correctly signed, successfully re-verified result does not protect you against:

- **False content.** Byte-immutability is not truth: a package can be perfectly intact
  and still contain false, misleading, or incomplete claims.
- **Dishonest or compromised verifiers.** A valid signature proves key possession. If
  the holder of a trusted key lies about what they checked, OEVP cannot tell you.
- **Misplaced trust.** Trusting the wrong public key (e.g. a key supplied by the
  originator itself) makes every downstream "trusted" conclusion vacuous. Trust roots
  are the caller's responsibility.
- **Non-equivocation gaps.** A signer can issue two contradictory packages or receipts;
  standalone OEVP will verify both. Detecting this requires a transparency service or
  shared registry (e.g. RFC 9943).
- **Stale appraisals.** A receipt says nothing about changes made after verification
  time. Re-verification against current bytes is how you check.
- **Legal, compliance, or commercial conclusions.** Receipts are not qualified
  electronic signatures, eIDAS seals, regulatory approvals, audit opinions, or evidence
  of any legal fact.
- **Malware.** Evidence packages are not scanned for malicious content, and verifiers
  never execute package contents.

## Trust invariants (short form)

1. **Receipt integrity ≠ factual truth.** A valid receipt proves that an identified
   verifier performed the declared technical checks against specific package bytes —
   nothing more.
2. **Signature valid ≠ trusted signer.** Cryptographic validity proves key possession;
   trust requires the key to match a caller-supplied trust root.
3. **No self-trust.** Keys or hints embedded in packages or envelopes are never
   automatically trusted.
4. **No non-equivocation.** See above; transparency mechanisms are required.
5. **Deterministic re-verification.** Re-verification recomputes supported checks
   independently and detects profile or package substitution.
