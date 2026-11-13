# Receipt-status conformance vectors (hea-21, hea-22)

V3-C13 freshness / supersession vectors. Unlike hea-01..hea-20, these do
NOT test the HEA verifier — they test `oev.receipt_status`
(`assess_receipt_freshness` + `combine_with_reverification`), i.e. the
reproducibility × freshness two-dimensional outcome.

They are therefore NOT listed in `manifest.json` and NOT run by
`conformance/run_hea_vectors.py` (that runner only dispatches HEA
scenarios; adding these ids to the manifest would break it). They are
executed by `tests/test_receipt_status.py`
(`test_vector_hea21_stale_receipt`, `test_vector_hea22_superseded_receipt`),
which rebuilds the signed snapshot in-process with fresh keys per run
(the vectors carry only digests/statuses, no secret key material).

| Vector | Scenario | Expected combined outcome |
| --- | --- | --- |
| hea-21 | stale-receipt | MATCH + STALE → overall REJECT |
| hea-22 | superseded-receipt | MATCH + SUPERSEDED → overall REJECT |
