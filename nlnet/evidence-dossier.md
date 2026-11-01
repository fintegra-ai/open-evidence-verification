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
| Conformance: language-independent vectors + runner | OEVP `conformance/vectors/` (v0.1.0) + `conformance/run_vectors.py`; standalone package `oev-conformance-vectors` 0.1.0 (local, publication pending owner push) |
| Conformance: reference passes everything | OEVP suite 153 passed; OEPT corpus 10/10; runner exit 0 (12 active vectors) |
| **Second implementer** (the NLnet requirement most projects fail) | `fintegra-ai/open-evidence-verifier-ts` — **12/12 vector parity** with the Python reference, stdlib-only, ambiguity log A-001 |
| Public PyPI packages | `open-evidence-verification 0.2.1`, `oept 0.1.1` (pypi.org) |
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
   `spec/faz-d-ts-verifier-plan.md`) + npm publication.
4. Rust third implementation (plan D+ second priority).
5. Independent security audit + closure of findings (separate budget line).
6. Interop table + public docs site + external-pilot onboarding.

## 3. Pending owner decisions (gating the filing)

- Kapı C 4/4 final step: publish `oev-conformance-vectors` to PyPI (package
  built, twine-clean; push is the owner's action).
- TS verifier: npm name + publication (repo is now public at
  github.com/fintegra-ai/open-evidence-verifier-ts).
- Profiles 1–5 registration pace.
- Second maintainer (GOVERNANCE requires it before accepting funds).
- Pilots: 1–3 nameable external projects (cannot be invented).
