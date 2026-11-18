# @cloister/watchtower

A member node that checks every batch independently of the sequencer (design.md §A6). It fetches the sealed bundle from the L1 tx that posted it, opens it with its ML-KEM key and verifies:

| Check | |
|---|---|
| link | `sha256(envelope)` equals the batch's `data_hash` on chain |
| index / count | the bundle names this batch and holds `tx_count` txs |
| structure | every frame tx is well formed for this rollup |
| signature | every ML-DSA-87 signature verifies (the circuit does not prove these) |

Batches 0 and 1 of `cloister-dev-2` predate the bundle format and are reported as `legacy` (link only).

```bash
pnpm watchtower --id cloister-dev-2 [--sign] [--json report.json] [--explorer /abs/path/packages/explorer/data.json]
```

`--sign` writes a signed **verdict** per batch (spec/verdict.md) to `receipts/<rollup>-<batch>.verdicts.json`, one entry per member watchtower. The receipts page and CLI verify each verdict against the chain and show "checked by N member watchtower(s)" next to the settlement receipt.

Exit code 1 if any check fails. Not built yet: re-executing the batch against the state root, the inclusion check against a based inbox, liveness alerts and the VK-swap alarm. Tests: `pnpm --filter @cloister/watchtower test` (includes negative cases: wrong hash, wrong index/count, wrong signer, non-member key).
