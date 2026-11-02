# Second review negative vectors

Permanent synthetic negative inputs for the 2026-11-02 second review.
`receipt-wrong-type.dsse.json` must raise DsseError during inspection and
re-verification. `manifest-traversal.json` mutates an artifact manifest entry;
verification must return PACK_INVALID without reading outside the pack.
`core-schema-invalid.json` mutates facts.json and rehashes its manifest; the
self-consistent pack must still be invalid because the member schema fails.

`tests/test_review_security.py` executes these inputs and covers symlinks,
bounded input reads, deep JSON, optional-check omission, trust-input changes,
and rewritten overall results. These vectors do not change the active OEVP
0.1.0 vector-set compatibility contract (12 active / 2 planned).
