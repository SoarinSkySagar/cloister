# @cloister/sequencer

HTTP API and batch loop for one rollup. It verifies signed frame txs (ML-DSA-87, nonce, expiry, fee floor), queues them, then every interval (or when 4 are queued) it seals the bundle to the members, proves with the Go circuit, posts, submits with the ML-DSA-87 anchor, and pays withdrawals on L1. See design.md §A5.

```bash
pnpm sequencer --id cloister-dev-2 [--port 8787] [--interval 30] [--min-fee 0.01] [--relayer 1] [--proof-log]
export CLOISTER_SEQUENCER_URL=http://127.0.0.1:8787     # for the wallet
```

| Endpoint | |
|---|---|
| `POST /tx {tx: hex}` | Validate and queue a signed frame tx. Returns its id (the sighash), or 400 with the reason |
| `GET /tx/<id>` | queued, included (batch, account, applied actions) or rejected |
| `POST /account` | A signed query (`signAccountQuery`). Returns only the caller's own account, since the rollup is private |
| `POST /proof {query, tx}` | The inclusion proof ([spec/inclusion.md](../../spec/inclusion.md)) of a tx. A signed query: only its sender or a listed party gets it |
| `GET /status` | Batch count, queue length and last error. No balances |
| `POST /batch` | Run a batch now |

It listens on 127.0.0.1 only. The rollup state lives in `circuits/setup/<id>/state.json` and the ML-DSA keys of accounts in `keys.json` (both gitignored, members-only data). If a queued tx's fee can't be paid at batch time, the tx is rejected and the batch is retried without it.

**Multi-party and time-locked txs.** A tx may name up to 3 co-signing parties and a `not_before` batch. The sequencer checks every party's signature and that each party is an account. A tx whose `not_before` has not been reached stays queued and does not trigger a batch. After each batch the prover's inclusion proofs are kept in `circuits/setup/<id>/proofs/<batch>.json` (members-only data, gitignored).

**Restart and crash behaviour** (tested live on `cloister-dev-2`, batch 10, and offline: `pnpm --filter @cloister/sequencer test`):

- Accepted txs are saved to `mempool.json`. After a restart they are re-queued and re-validated against the current state; stale ones (for example a nonce that moved on) are dropped and logged.
- A tx whose payer cannot cover the fee is rejected at batch time (`fee: insufficient balance`) and the batch is retried with the rest.
- If a crash lands between `submitBatch` and the local state update, the chain is one batch ahead. On startup the sequencer adopts the prover's `next-state.json` for that batch only if its root equals the chain's batch root, and relearns the keys that batch registered from the saved bundle. Any other mismatch (chain two or more ahead, root differs) is refused with an error: it never guesses at state.
- A crash between posting the data and `submitBatch` needs nothing: the next batch posts again.

Tested on `cloister-dev-2` batches 3 and 4 (PROOF.md): txs sent through the API by the wallet, including refusals (fee below the minimum, duplicate, wrong nonce).
