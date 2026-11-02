# Interop Table (Faz G)

Who verified what, against which vector-set version, with linked evidence.
**Failed attempts are recorded exactly like successes** — hiding them is
prohibited by the plan and by GOVERNANCE.md §3. To add an entry, see
"Submission" below.

| Implementer | Language | Vector set | Result | Evidence | Date |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Python reference (open-evidence-verification) | Python | oev-conformance-vectors@0.1.0 | 12/12 active vectors pass | `run_vectors.py` report (runner exit 0); CI integration job executes the runner regression test every push | 2026-11-01 |
| TypeScript (fintegra-ai/open-evidence-verifier-ts) | TypeScript/Node | oev-conformance-vectors@0.1.0 | 12/12 active vectors pass, identical results | `run_vectors.py` external mode report; acceptance recorded in METRICS.md | 2026-11-01 |

## Submission

1. Run your verifier against the vector set you downloaded
   (`oev-conformance-vectors` package, or `conformance/vectors/` in this
   repository), using the external-verifier contract documented in
   `conformance/run_vectors.py`.
2. Open a PR (or issue) with: implementer name/link, language, vector-set
   version, the machine-readable report JSON (pass or FAIL — failures are
   welcome entries), and one paragraph on scope.
3. A maintainer verifies the report against the same vector set and merges.
   Failures stay visible; they are data, not shame.

## Package status

- PyPI: `open-evidence-verification 0.2.1` (reference verifier), `oept 0.1.1`
  (bundle format), [`oev-conformance-vectors 0.1.0`](https://pypi.org/project/oev-conformance-vectors/0.1.0/)
  (published vector set; verified 2026-11-02).
- npm: `oept-verifier-ts 0.1.0` (TS verifier, published 2026-11-01).

Both implementations above are maintained by this project. Two languages do
not establish an independent external implementer; the external count is 0.
