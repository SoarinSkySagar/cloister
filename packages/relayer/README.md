# @cloister/relayer

The public door to a rollup. Users have no L1 QOR, so they hand their signed frame tx to the relayer. It checks it cheaply (hex, size, structure for this rollup, fee floor, per-client rate limit) and forwards it to the sequencer. It is paid in-rollup: each tx's fee is credited to the relayer's rollup account at batch time. See design.md §A3.

```bash
pnpm relayer --id cloister-dev-2 [--port 8788] [--upstream http://127.0.0.1:8787] [--min-fee 0.01] [--rate 30]
```

| Endpoint | |
|---|---|
| `POST /tx {tx: hex}` | Validate and forward. Returns `{id}` or 400 with the reason |
| `POST /account` | A signed account query, passed through to the sequencer (which checks the signature), so users need only the relayer's URL |
| `GET /tx/<id>` | The sequencer's status for that tx |
| `GET /info` | Fee floor and counters |

On a dedicated rollup only the sequencer may post, so the relayer forwards over HTTP. On a based rollup it could post the sealed envelope itself (untested on chain). It does not check ML-DSA signatures: the sequencer does, and every member watchtower re-checks. Tests: `pnpm --filter @cloister/relayer test`.
