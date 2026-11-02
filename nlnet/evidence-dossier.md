# NLnet Application — Linked Evidence Dossier (Faz H)

> **This file is NOT the application text.** Per the plan's own rule
> ("NLnet metnini AI ile yazmak yok"), the application prose is written by
> the human applicant. This dossier is the linked-evidence appendix Faz H
> requires: every claim the application will make, with its link, prepared
> 2026-11-01.

## 1. Existing, linked (what the application can already point at)

| Claim | Link / evidence |
| :--- | :--- |
| Normative specs, code-independent (RFC 2119 drafts) | open-evidence-verification `spec/OEVP-1.0-draft.md`; open-evidence-provenance `spec/OEPT-1.0-draft.md` |
| Conformance: language-independent vectors + runner | OEVP `conformance/vectors/` (v0.1.0) + `conformance/run_vectors.py`; standalone package [`oev-conformance-vectors` 0.1.0](https://pypi.org/project/oev-conformance-vectors/0.1.0/) (published) |
| Conformance: reference passes everything | Baseline OEVP suite 153 passed (2026-11-01); current rerun in `docs/CLOSURE_STATUS_2026-11-02.md`; OEPT corpus 15/15; runner exit 0 (12 active vectors) |
| **Second implementation** (project-internal, not external adoption) | `fintegra-ai/open-evidence-verifier-ts` — **12/12 vector parity** with the Python reference, stdlib-only, ambiguity log A-001 |
| Public PyPI packages | `open-evidence-verification 0.2.3`, `oept 0.1.3` (pypi.org) |
| Threat model | both repos, `spec/threat-model.md` |
| Security process | OEPT `SECURITY.md`; gitleaks full-history CI in both repos (checksum-pinned) |
| Governance | `GOVERNANCE.md` (DCO, CC-BY-4.0 spec license, conformance-brand rule, no-funding-before-second-maintainer) |
| Boundary | `BOUNDARY.md` both repos; import-guard test; org-hosted repos (`fintegra-ai`) |
| Honest metrics | `METRICS.md` — every number linked; negative facts recorded |
| Profile architecture kickoff | `profiles/registry.json` + `PROFILE-REGISTRY.md`; Profile 0 registered with zero core changes |

## 2. Funded-work split (already existing vs. milestones)

**Already existing (not funded):** everything in §1 — specs, reference
implementations, conformance machinery, second implementation parity,
governance, boundary/security tooling, PyPI releases.

**Funded-work candidates (separate, milestone-able):**
1. Profile expansion 1–5 (software-release/SLSA, AI evaluation, research/
   RO-Crate, public-procurement, media/C2PA) — spec + vectors each.
2. Deterministic rule replay engine (today the core deliberately does NOT
   re-execute rules; replay is digest/pinning only).
3. Browser verifier release (same core as the TS verifier; slice planned in
   `spec/faz-d-ts-verifier-plan.md`) (npm 0.1.0 already published; browser delivery remains future work).
4. Rust third implementation (plan D+ second priority).
5. Independent security audit + closure of findings (separate budget line).
6. Public docs site + external-pilot onboarding (interop table already exists).

## 3. Remaining owner / external steps

- PyPI credential rotation: complete. Separate project tokens were used for
  the verified 0.1.2 / 0.2.2 uploads; the account owner confirmed revocation of
  the old account-wide token on 2026-11-02. Credentials persist in macOS Keychain;
  no credential values are included in this dossier.
- Second maintainer: required by this project's GOVERNANCE before funding
  intake; do not count an automated agent as a second human maintainer.
- External implementers / pilots: 0 recorded; do not invent participants.
- Human-written application prose remains the applicant's task.
- Profiles 1–5 stay draft until adapters and domain vectors exist.

Vector publication and npm publication are complete and no longer pending.
See `docs/CLOSURE_STATUS_2026-11-02.md` for the technical freeze and remaining
steps. These are project gates, not asserted NLnet eligibility rules.
