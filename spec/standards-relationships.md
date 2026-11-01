# Relationship to Adjacent Standards (Faz F)

Status: informational mapping, 2026-11-01. Normative references live in the
OEVP-1.0 / OEPT-1.0 drafts. This document exists so implementers do not have
to rediscover how OEVP/OEPT relate to the ecosystems they already use, and
so the NLnet application can point at a single honest page.

## The one-line positioning

OEPT binds **content** to digests and signatures in portable bundles; OEVP
records **what a verifier appraised and what it concluded** in portable,
re-verifiable receipts. Neither asserts truth, legality, or identity beyond
caller-pinned keys.

| Standard | What it solves | Relationship to OEVP/OEPT |
| :--- | :--- | :--- |
| **in-toto** | Signed software supply-chain layouts and attestations about steps | Closest conceptual sibling. An OEVP receipt is akin to an in-toto link/attestation: a signed statement that specific checks ran over specific materials. A future bridge can wrap an OEVP receipt as an in-toto statement subject; conversely an in-toto layout can be one profile's `required_checks`. |
| **SLSA** | Build-integrity levels (provenance about HOW an artifact was built) | Complementary scope: SLSA speaks about build provenance; OEVP speaks about appraisal of evidence. The Faz F "software release" profile (Profile 1) is the planned bridge: SLSA provenance documents can be pack members, and their verification can be a profile check. |
| **C2PA** | Media provenance (signed manifests bound into media files) | Same architectural pattern (content credentials), different domain. The media-verification profile (Profile 5) plans to accept a C2PA manifest as evidence and record its validation as a check; C2PA's trust model (certificate lists) stays theirs — OEVP adds caller-pinned verification of what was validated. |
| **W3C Verifiable Credentials** | Portable, signed, selective-disclosure claims about subjects | A pack verification receipt could be represented as a VC for ecosystems that require VC shape; OEVP's own formats remain the source of truth. Mapping receipt fields → `credentialSubject` is mechanical; the tamper-evidence story (DSSE, self-digest) carries over. |
| **RO-Crate** | Research data packaging with rich metadata | OEPT bundles play a similar role for appraisal-oriented evidence. A research-data profile (Profile 3) can treat an RO-Crate as a member of an OEPT bundle and verify its checksum file, giving research outputs the same replay-safety story. |
| **SCITT** | Supply-chain integrity transparency ledger (receipts for signed statements) | SCITT answers "who registered what, when, in an append-only ledger"; OEVP answers "what did an offline verifier conclude and can I re-verify it". A SCITT registration of an OEVP receipt is a natural future extension point (the receipt is already a signed, canonical statement). |

## Deliberate differences (why OEVP/OEPT exist alongside them)

1. **Offline-first, no ledger required.** Verification needs no network, no
   registry, no timestamp authority; the only trust inputs are the package,
   the profile, and caller-pinned keys.
2. **Appraisal semantics, not just provenance.** Receipts record check
   statuses (PASS/FAIL/UNVERIFIED/…) against a profile — in-toto/SLSA
   attestations record that steps ran, not whether the outcome satisfies a
   stated appraisal contract.
3. **Re-verification as a first-class operation.** `oev reverify` compares a
   fresh run to a historical receipt; no adjacent standard has this as a
   protocol operation (and its boundary is honesty-preserving: it proves
   reproducibility, never receipt authenticity).
4. **Fail-closed honesty.** Non-guarantees are part of the spec (content
   truth, signer honesty, time correctness are explicitly out).

## Bridge policy

Bridges are profiles or adapters, never core changes (Faz F rule). Each
bridge MUST ship with its own vectors, and a bridge that cannot reproduce
the referenced standard's guarantees says so in its profile description
rather than implying interop that does not exist.
