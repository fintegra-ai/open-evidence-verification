# Examples

Fully synthetic, domain-neutral example artifacts for OEVP. Nothing here is derived
from real data, and nothing here demonstrates a finance workflow, finance rule pack,
or customer data.

## `demo-case-001` — decision evidence pack

A complete [decision evidence pack](../spec/decision-pack-spec.md)
(`oev-decision-pack/0.2`) for a fictional pump-station maintenance review:

- `case.json`, `facts.json`, `rule_runs.json`, `findings.json`, `review_actions.json`,
  `timeline.json`, `snapshot_context.json` — the seven core members.
- `artifacts/` — two small synthetic artifacts covered by the manifest as raw bytes.
- `manifest.json` — SHA-256 manifest of every member in stable sorted path order.
- `manifest.dsse.json` — DSSE v1 (Ed25519) envelope binding the exact manifest bytes.

The rule runs intentionally showcase the honest outcome vocabulary: one `TRIGGERED`,
one `NOT_TRIGGERED`, one `REVIEW_REQUIRED`, and one `UNVERIFIABLE` run (a required
fact was absent from the snapshot). No outcome in this pack — or in any pack — asserts
that a decision was correct; pack verification is a technical-integrity check only.

Verify it offline:

```bash
oev pack verify examples/demo-case-001 \
    --verifier-keys examples/demo-case-001.verifier-keys.json
```

Regenerate it (the pack bytes are deterministic; only the demo signing keypair — and
therefore the DSSE envelope — changes per run):

```bash
python examples/make_example.py
```

The demo signing key's public half is committed in
`demo-case-001.verifier-keys.json`. No private keys are committed; each regeneration
mints a fresh throwaway demo keypair.
