# Golden test vectors

JSON files here are loaded by **both** `circuits/` (Go) and `packages/*` (TS) tests, so the two implementations can't drift.

Each file holds an array of cases: `{ "name": ..., "input": {...}, "expected": {...} }`. Byte strings are lowercase hex without `0x`.

Planned files:
- `frame-tx.json`: encodings and sighashes
- `state.json`: leaf hashes and roots
- `withdrawals.json`: leaves and roots, cross-checked against the RDK's `withdrawalsTree`
- `batch.json`: full batch transitions (pre-state, txs, post-state, public inputs)
