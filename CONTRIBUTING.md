# Contributing to OEVP

Thank you for contributing to the Open Evidence Verification Protocol.

## Principles

1. **Clean Codebase**: All contributions must be original work licensed under Apache-2.0.
2. **Minimal Dependencies**: Runtime dependencies must remain strictly minimal (Python stdlib, `cryptography`, `jcs`, `jsonschema`).
3. **Core Independence**: The protocol core (`src/oev` excluding `oev/adapters/oept.py`) must have zero imports or runtime dependencies on OEPT, EvidenceOS, or any financial software.
4. **Deterministic Security**: All canonicalization, hashing, signature verification, and overall result aggregations must be fully deterministic and accompanied by tests.
5. **Honest Boundaries**: Documentation and error messages must never claim factual truth, legal validity, compliance approval, or fraud detection. Verification is technical appraisal only (see [SECURITY.md](SECURITY.md)).
6. **No Release Tags Pre-Review**: Pre-1.0 development proceeds under provisional specifications (`oev-profile/0.1`, `oev-receipt/0.1`, `oev-reverification/0.1`, `oev-decision-pack/0.2`).

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Python ≥ 3.10 is supported (CI runs 3.10–3.13; see
[.github/workflows/ci.yml](.github/workflows/ci.yml)).

### Optional OEPT adapter

The reference adapter for OEPT bundles is optional. The OEPT package (Open Evidence
Provenance Toolkit) is a sibling project not yet published to PyPI; to run the
OEPT-dependent tests and the full conformance suite locally, install OEPT from its own
checkout:

```bash
pip install -e /path/to/open-evidence-provenance
```

Tests that require the adapter are skipped automatically (with an explicit reason) when
OEPT is not installed; everything else — the whole protocol core, receipt inspection,
and decision pack tooling — runs without it.

## Quality gates

Every pull request must pass (CI enforces the same checks on Python 3.10–3.13):

```bash
ruff check .
ruff format --check .
mypy src tests
pytest
```

## Conformance fixtures

The committed fixtures under [`conformance/fixtures`](conformance/fixtures) are the
protocol's conformance corpus; [conformance/README.md](conformance/README.md) documents
each scenario and how to regenerate them
(`OEPT_FIXTURES_DIR=... python conformance/make_fixtures.py`).

When changing verification behavior, keep the corpus consistent: fixtures and their
`expected-result.json` files must reflect actual engine output, and every example in the
[README](README.md) must run and verify against the code in this repository.

## Pull requests

- Keep changes focused; one logical change per PR.
- Update [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]` for user-visible changes.
- Update the spec documents under `spec/` in the same PR when protocol-level behavior
  changes.
