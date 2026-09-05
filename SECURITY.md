# Security Policy

## Reporting Security Vulnerabilities

If you discover a potential security vulnerability in the Open Evidence Verification Protocol (OEVP)
implementation or specification, please report it responsibly.

Do not open a public GitHub issue for security-sensitive reports. Until a dedicated security address
is established, report vulnerabilities privately through the repository's private security advisory
mechanism.

Please include:
- A description of the issue.
- Steps to reproduce or a proof of concept.
- Affected components (e.g., DSSE parsing, canonicalization, profile evaluation, trust models).
- The potential impact.

## Threat Model and Trust Invariants

The Open Evidence Verification Protocol operates under strict trust boundaries:

1. **Receipt Integrity != Factual Truth**: A valid receipt proves that an identified verifier performed
   the declared technical checks against specific package bytes. It does NOT assert that the underlying
   content is factually, legally, or commercially true.
2. **Signature Valid != Trusted Signer**: A DSSE signature with a valid cryptographic signature proves key
   possession, but is untrusted unless the public key is explicitly accepted by the caller's trust store.
3. **No Self-Trust**: Public keys or hints embedded within packages or receipts are unauthenticated labels
   and are NEVER automatically trusted.
4. **No Non-Equivocation**: Standalone OEVP does not provide non-equivocation. An entity may sign multiple
   conflicting packages. Non-equivocation requires external transparency mechanisms (e.g. SCITT RFC 9943).
5. **Deterministic Re-verification**: Package re-verification recomputes supported technical checks
   independently and detects profile or digest substitution.
