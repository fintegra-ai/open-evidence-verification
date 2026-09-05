# Contributing to OEVP

Thank you for contributing to the Open Evidence Verification Protocol.

## Principles

1. **Clean Codebase**: All contributions must be original work licensed under Apache-2.0.
2. **Minimal Dependencies**: Runtime dependencies must remain strictly minimal (Python stdlib, `cryptography`, `jcs`, `jsonschema`).
3. **Core Independence**: The protocol core (`src/oev` excluding `oev/adapters/oept.py`) must have zero imports or runtime dependencies on OEPT, EvidenceOS, or any financial software.
4. **Deterministic Security**: All canonicalization, hashing, signature verification, and overall result aggregations must be fully deterministic and accompanied by tests.
5. **No Release Tags Pre-Review**: Pre-1.0 development proceeds under provisional specifications (`oev-profile/0.1`, `oev-receipt/0.1`, `oev-reverification/0.1`).

## Development Workflow

1. Setup environment:
   ```bash
   python3.12 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Run quality checks:
   ```bash
   ruff check .
   ruff format --check .
   mypy src tests
   pytest
   ```
