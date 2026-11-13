# Execution Log Specification (oev-execution-log/0.1, oev-log-checkpoint/0.1)

Status: Pre-1.0 Draft — HEA v0.1 Model A. Normative companion to
`docs/HISTORICAL_EXECUTION_ATTESTATION.md` (design §4) and the
implementation in `src/oev/execution_log.py`.

## 1. Log events (oev-execution-log/0.1)

One append-only JSONL log per witness (`log_id`, e.g. `hea-log-001`).
Each line is one canonical-JSON event:

| Field | Rule |
| --- | --- |
| `protocol_version` | `oev-execution-log/0.1` |
| `log_id` | The log this event belongs to |
| `seq` | 0-based, gapless, strictly increasing |
| `event_type` | `EXECUTION_STARTED` \| `CHECK_COMPLETED` \| `EXECUTION_COMPLETED` \| `CHECKPOINT` |
| `execution_id` | The execution this event belongs to |
| `check_id` | Present (and required) for `CHECK_COMPLETED`, absent otherwise |
| `event_digest` | `sha256:` digest of the event's payload (check result digest for `CHECK_COMPLETED`) |
| `prev_hash` | `leaf_hash` of the previous event; `sha256:` + 64 zeroes for seq 0 (genesis) |
| `claimed_time` | Self-asserted timestamp; ordering comes from `seq`, not from time |
| `leaf_hash` | Derived, not stored in the hash: `SHA-256(JCS(event without leaf_hash))` |

Rules:

- `seq` gaps are a distinct failure (`LOG_GAP`); a broken
  `prev_hash` link is `LOG_ANCHOR_INVALID`.
- `event_digest` and `prev_hash` must be well-formed `sha256:` digests.
- A declared `leaf_hash` that does not match the recomputed value is
  rejected.
- At most 1,000,000 events per log (`MAX_LOG_EVENTS`); a log file over
  10 MiB is refused by the JSONL reader.
- An execution's log MUST contain exactly one `EXECUTION_STARTED`
  event for its `execution_id`, followed by one `CHECK_COMPLETED` per
  executed check, followed by `EXECUTION_COMPLETED`. A rebuilt chain
  without `EXECUTION_STARTED` fails with the distinct code
  `MISSING_EXECUTION_STEP` (not `LOG_ANCHOR_INVALID`).

## 2. Hash chain

The chain is verified by `verify_event_chain`: seq starts at 0 and is
gapless; every event's `prev_hash` equals the previous event's
`leaf_hash`; every event's declared `leaf_hash` (when present) matches
its recomputed value. The chain proves *ordering and completeness of
what was recorded* — it does not prove that nothing was withheld
before the first checkpoint (see §5).

## 3. Merkle tree

Leaves are the events' `leaf_hash` values in seq order. The tree is a
binary SHA-256 tree; an odd leaf at any level is promoted unchanged to
the next level (no duplication). `merkle_root` is the root digest;
`merkle_inclusion_proof` returns the sibling path for a leaf index;
`verify_merkle_inclusion_proof` recomputes the root from leaf +
proof. A proof that does not reproduce the checkpoint's root fails
with `LOG_ANCHOR_INVALID`.

## 4. Checkpoint (oev-log-checkpoint/0.1)

A checkpoint (`LogCheckpoint`) covers a prefix of the log:

| Field | Meaning |
| --- | --- |
| `log_id` | The log covered |
| `checkpoint_seq` | Number of events covered (= next seq) |
| `merkle_root` | Merkle root over the covered leaves |
| `leaf_count` | Same as `checkpoint_seq` for a prefix checkpoint |
| `prev_checkpoint_digest` | Digest of the previous checkpoint (genesis = zeroes) |
| `claimed_time` | Self-asserted |

The checkpoint is signed as a DSSE v1 envelope (payload type
`application/vnd.oev.log-checkpoint+json`) by a key whose role is
**`checkpoint-signer`**. A checkpoint signed with the witness key (or
any non-`checkpoint-signer` key) is rejected — role separation is
enforced at verification, not only at issuance (`WitnessService.checkpoint()`
refuses to sign with the witness key, and the verifier re-checks the
role). A log without a signed checkpoint can never be PROVEN:
verification fails closed with `LOG_ANCHOR_INVALID`.

## 5. Completeness and DISPROVEN (oev-log-checkpoint/0.1)

A completeness statement (`LogCompleteness`: `log_id`,
`through_seq`, `checkpoint_digest`, `claimed_time`) is signed by the
log operator (checkpoint-signer key) and asserts that the log is
complete through `through_seq` — i.e. nothing was withheld or deleted
before that point.

`DISPROVEN` for a claimed `execution_id` requires **all three**
conditions together (design §7.2):

1. A complete, signed log covers the claimed interval (chain valid,
   checkpoint valid, completeness statement valid and covering it).
2. No `EXECUTION_STARTED` event for that `execution_id` exists in
   the log.
3. The signed completeness statement covers the interval.

If any condition fails, the result is `UNPROVEN` — never `DISPROVEN`.
The default is always `UNPROVEN`; `DISPROVEN` is the exception. In
particular, absence from an *incomplete* log proves nothing: the
events may simply have been deleted.

## 6. What the log proves — and does not prove

Proves: the recorded events happened in the recorded order under the
witness's observation, the log was not altered after the checkpoint
was signed, and each attested check has a leaf in the checkpointed
tree.

Does **not** prove: that events were recorded promptly (a log can be
written late and backdated — `claimed_time` is self-asserted); that
the log is complete without a signed completeness statement; that the
witness observed the *real* execution rather than a staged one on the
same machine (Model A limit); anything about events before the first
checkpoint.
