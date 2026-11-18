# @cloister/receipts

Verify settlement receipts against live QoreChain state. A receipt is only a claim: `verifySettlementReceipt` re-reads the rollup, the batch, the ML-DSA-87 anchor and the signing key from the chain, so a fabricated or altered receipt cannot pass.

**CLI**

```bash
pnpm --filter @cloister/receipts cli verify --all                   # every file in receipts/
pnpm --filter @cloister/receipts cli verify path/to/receipt.json
pnpm --filter @cloister/receipts cli build --id cloister-dev-2 --batch 3
```

Exit code 1 if any receipt is invalid.

**Verifier page**

```bash
pnpm --filter @cloister/receipts start        # http://127.0.0.1:8791
```

Paste or drop a receipt, pick one of the published receipts, or enter a rollup and batch to build and verify one. Verification runs in the browser. The testnet REST/RPC send no CORS headers, so the small server proxies read-only chain GETs (`/qorechain/*`, `/cosmos/*`, and `/status` on the RPC; nothing else, no POST). It binds to 127.0.0.1; a public deployment would put it behind a reverse proxy.

What a valid receipt proves: the batch's state root was settled on QoreChain and anchored with a post-quantum signature from the rollup creator's key. It does not prove the transactions inside were correct; the Groth16 proof that settled the batch does.

Tested: the CLI verifies all published receipts, and refuses a receipt with a changed state root or batch index and malformed input. `pnpm --filter @cloister/receipts test` runs the offline checks (parsing, the proxy allow-list).
