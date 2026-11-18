# @cloister/wallet

User CLI for Cloister frame transactions: ML-DSA-87 keys (the same key as the user's L1 account), building, signing (sender and sponsor), inspecting, and sealing to the rollup's members with ML-KEM-1024. Format: [spec/frame-tx.md](../../spec/frame-tx.md).

```bash
pnpm --silent wallet new alice                                   # testnet mnemonic into .env (never printed)
pnpm --silent wallet whoami --as alice --id cloister-dev-2
pnpm --silent wallet build --as alice --id cloister-dev-2 --register --sponsor 0 --fee 0.01 --out a.hex
pnpm --silent wallet sign --as alice --in a.hex                  # sender
pnpm --silent wallet sign --as operator --in a.hex               # sponsor (pays the fee)
pnpm --silent wallet inspect --in a.hex
pnpm --silent wallet send --in a.hex --id cloister-dev-2 --envelope a.env   # sealed, for the relayer
```

- `build` options: `--to <idx|name> --amount <x> [--asset qor|usd]`, `--withdraw <qor> [--recipient qor1…]`, `--register`, `--sponsor <idx|name>`, `--fee <qor>`, `--atomic`, `--expiry <batches>`.
- A dedicated rollup (every `cloister-dev-N`) only accepts posts from its sequencer. `send` then writes the sealed envelope for the relayer, or posts with `--via operator` (dev only). On a based rollup the relayer posts it.
- Until the sequencer serves member queries, balances and nonces come from the operator's state view (`circuits/setup/<rollup>/state.json`, or `--state`).

Tested on `cloister-dev-2` batch 2 (PROOF.md). `alice`, who has no QOR on L1, was onboarded with the treasury sponsoring her fee.
