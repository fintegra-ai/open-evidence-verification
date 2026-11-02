# Archive extraction regression vectors

`archive-regressions/expected.json` names permanent hostile ZIP vectors added
on 2026-11-02: a late CRC failure, an empty path segment, and a file/directory
collision, plus portable case/Unicode aliases. Every case must raise `PackArchiveError` without creating the
extraction destination. Run `pytest tests/test_archive_closure.py`.
Regenerate byte-stably with `python conformance/make_archive_regressions.py`.

These transport safety vectors are separate from the OEVP 0.1.0 receipt
vector set; they do not change its 12 active / 2 planned compatibility contract.
