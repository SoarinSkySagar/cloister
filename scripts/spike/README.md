# Go/no-go spike (17–18 Nov)

Checklist: [design.md §A7](../../design.md). Record every transaction hash in [PROOF.md](../../PROOF.md).

| Step | Command | Needs keys? | Status |
|---|---|---|---|
| Network, params, id availability | `pnpm spike:network` | No | ✅ |
| VK + sample proof (keys persist in `circuits/setup/spike/`) | `cd circuits && go run ./cmd/export -out build` | No | ✅ |
| Generate watchtower/relayer mnemonics + member ML-KEM seeds into `.env` | `pnpm spike:keygen` | No | ✅ |
| Balances and key status per role | `pnpm spike:status` | Read-only | ✅ |
| Fund a role with test QOR (hybrid-signed send) | `pnpm spike:fund -- --to watchtower --amount 50 --send` | Yes | ✅ |
| Register ML-DSA-87 (with PoP) + ML-KEM-1024 keys for operator and watchtower | `pnpm spike:register-keys -- --send` | Yes | ✅ |
| Simulate `cloister-dev-1` creation (raw vs compressed VK, dedicated vs based) | `pnpm spike:create-dev` | Yes | ✅ all accepted |
| Create `cloister-dev-1` (**locks 10,000 QOR**; human approves) | `pnpm spike:create-dev -- --send --encoding raw` | Yes | ✅ |
| Members, seal → post → open | `pnpm spike:members-post -- --send` | Yes | ✅ |
| Batch with proof + anchor (simulates both encodings + a tampered control first) | `pnpm spike:batch -- [--withdraw-to relayer --withdraw-qor 1] --send --encoding raw` | Yes | ✅ batches 0, 1 |
| Receipt build/verify | `pnpm spike:receipt -- --batch 0` | Read-only | ✅ valid |
| Withdrawal | (in `spike:batch --withdraw-to`) | Yes | ✅ 1 QOR paid |
| Stop `cloister-dev-1` and check the refund | `pnpm spike:stop-dev -- --send` | Yes | ✅ +10,898.93 QOR |

Before any transaction: copy `.env.example` to `.env` and fill in **testnet-only** keys. A human approves the first `create-rollup` after a dry run.

## Circuit v1 on chain (cloister-dev-2)

| Command | What | Status |
|---|---|---|
| `pnpm spike:ledger config --id cloister-dev-2` | Genesis config: treasury = operator key holding the expected escrow | ✅ |
| `pnpm spike:ledger setup --id cloister-dev-2` | Groth16 setup (3.5 min, 1.3 GB pk, gitignored) | ✅ |
| `pnpm spike:create-dev --id cloister-dev-2 --vk-dir setup/cloister-dev-2 --send --encoding raw` | Create the rollup with the v1 VK | ✅ |
| `pnpm spike:ledger batch --id cloister-dev-2 --step onboard --send` | Batch 0: treasury funds account 2, sponsored register_key | ✅ finalized |
| `pnpm spike:ledger batch --id cloister-dev-2 --step withdraw --send` | Batch 1: atomic withdraw+transfer, relayer withdraws its fees; both paid on L1 | ✅ finalized |
| `pnpm --filter @cloister/spike gen-vectors` | Regenerate `spec/vectors/withdrawals.json` from the RDK | ✅ |
