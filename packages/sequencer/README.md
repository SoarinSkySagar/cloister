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
| `GET /status` | Batch count, queue length and last error. No balances |
| `POST /batch` | Run a batch now |

It listens on 127.0.0.1 only. The rollup state lives in `circuits/setup/<id>/state.json` and the ML-DSA keys of accounts in `keys.json` (both gitignored, members-only data). If a queued tx's fee can't be paid at batch time, the tx is rejected and the batch is retried without it.

Tested on `cloister-dev-2` batches 3 and 4 (PROOF.md): txs sent through the API by the wallet, including refusals (fee below the minimum, duplicate, wrong nonce).
