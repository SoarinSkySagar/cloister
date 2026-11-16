# Go/no-go spike (17–18 Nov)

Checklist: [design.md §A7](../../design.md). Record every transaction hash in [PROOF.md](../../PROOF.md).

| Step | Script | Needs keys? | Status |
|---|---|---|---|
| Network, params, id availability | `pnpm spike:network` | No | ✅ |
| VK + sample proof (both encodings) | `cd circuits && go run ./cmd/export -out build` | No | ✅ |
| Register ML-DSA + ML-KEM keys | todo | Yes (`.env`) | — |
| Create `cloister-dev-1` (dedicated, private, spike VK). **Try the compressed VK first, then raw** | todo | Yes | — |
| Members, seal → post → open | todo | Yes | — |
| Batch with proof + anchor | todo | Yes | — |
| Receipt build/verify | todo | Yes | — |
| Withdrawal | todo | Yes | — |
| Stop `cloister-dev-1` and check the refund | todo | Yes | — |
| Simulate private + based create (don't broadcast) | todo | Yes | — |

Before any transaction: copy `.env.example` to `.env` and fill in **testnet-only** keys. A human approves the first `create-rollup` after a dry run.
