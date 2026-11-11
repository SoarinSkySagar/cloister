# Cloister: context for Claude sessions

Cloister is a **private ZK rollup** on QoreChain with **EIP-8141-style frame transactions** and gas sponsorship. It is our entry in the Protocol Builders track of QoreChain's "Build Before Q-Day" hackathon. **Deadline: 2 Dec 2026, 23:59 UTC.** Two humans direct and review, and Claude writes most of the code.

- **Plan and design (source of truth):** [design.md](design.md). Read its "Findings from the RDK 0.9.0 source" section first.
- **QoreChain reference** (network, kits, rules, links): [docs/qorechain-reference.md](docs/qorechain-reference.md)
- **Wire formats:** [spec/](spec/). Change these only deliberately, and update the golden vectors at the same time.

## Layout

| Path | What | Language |
|---|---|---|
| `circuits/` | Groth16 circuit over BLS12-381, plus VK/proof export | Go + gnark |
| `packages/common` | Shared TS: network config, frame-tx codec, state types | TypeScript |
| `packages/sequencer` | Decrypt, verify ML-DSA, apply frames, prove, submit batch | TypeScript |
| `packages/relayer` | Post sponsored envelopes and collect fees | TypeScript |
| `packages/wallet` | User CLI: keys, build/sign/seal frame txs, withdraw | TypeScript |
| `packages/watchtower` | Member-node checks, alerts and dashboard | TypeScript |
| `packages/receipts` | Settlement receipt build/verify CLI and web page | TypeScript |
| `scripts/spike` | Go/no-go experiments on testnet | TypeScript |
| `spec/` | Frame tx, state leaf, public inputs, golden vectors | Markdown + JSON |

## Network (testnet only)

| | |
|---|---|
| Chain ID | `qorechain-diana` (EVM chain ID 9800, not used by the rollup) |
| RPC | https://rpc-testnet.qore.host |
| REST | https://api-testnet.qore.host |
| Denom | `uqor` (1 QOR = 1,000,000 uqor). Minimum gas price 0.1 uqor/gas |
| RDK REST | `/qorechain/rdk/v1/{params,rollups,rollup/<id>,inbox/<id>,batches/<id>,latest_batch/<id>,batch/<id>/<idx>,posted_data/<id>/<seq>}` |
| Explorer | https://explore.qore.network |

Pinned versions: `@qorechain/rdk` 0.9.0 · `@qorechain/pqc` 0.2.3 · `@qorechain/qoresign` 0.2.0 · `@qorechain/qoreseal` 0.1.0. Do not upgrade them without checking the changelog.

## Facts that are easy to get wrong

- **Hybrid signing is required.** Every native transaction needs secp256k1 **plus** ML-DSA-87. A new account must register its PQ key in its own transaction first, or the first transaction fails with pqc code 8. Pass a `pqcKeypair` to the RDK transaction client.
- **The VK is gnark binary-encoded** (Groth16, BLS12-381, 4 public inputs). It can be set or replaced by the creator **only before the first batch**; after that only governance can change it.
- **Public inputs, in order:** `prev_state_root, state_root, data_hash, withdrawals_root`. Each is 32-byte big-endian, read modulo the BLS12-381 scalar field `r` (`BLS12_381_SCALAR_MODULUS` in the RDK). `state_root` must already be below `r`. The chain stores `withdrawals_root mod r`.
- **Private rollup posts** must be RDK envelopes (`sealEnvelope`) with one entry per member, in the rollup's member order, at the current `members_epoch`. Check with `envelopeMembershipError` before posting.
- **Withdrawals:** `uqor` only, a SHAKE-256 tree using the chain's leaf format (`withdrawalLeafV2`, `withdrawalsTree`), at most 64 proof levels. Never use the generic SHA-256 Merkle helpers.
- **Based rollups can't be stopped by the creator** (governance only). Dev rollups use dedicated sequencing so they can be stopped and refunded.
- **The `--vm` label is metadata.** Rollup execution is ours (circuit plus sequencer). There are no rollup smart contracts.
- Read live parameters (`rdk.rest.getParams()`). Don't hardcode stakes, fees or windows.

## Working rules

- **Never commit or paste secrets.** Mnemonics and seeds live in `.env` (gitignored). Use dedicated testnet-only keys. Never use the rollup creator account for the Q-Day Drill.
- **Spec first.** If code disagrees with `spec/`, fix the code or change the spec on purpose, together with its golden vectors in `spec/vectors/`. The circuit tests and the TS tests read the **same** vector files.
- **Circuit soundness:** every constraint gets a **negative test**, where an invalid witness must fail to prove (negative balance, wrong nonce, broken value conservation, wrong roots). Under-constrained circuits are the main risk.
- **On-chain evidence:** append every testnet transaction hash that proves something to [PROOF.md](PROOF.md), with what it proves.
- **AI usage log:** add a dated line to [AI_USAGE.md](AI_USAGE.md) for significant generated work and for human decisions or reviews. This is required for the Best AI-Native Build award.
- **Credit every library and kit** in the README's Credits section when you add a dependency. The rules require it.
- **Licence:** the repo is MIT. Don't vendor GPL code. circomlib and snarkjs are GPL-3.0, which is one reason the circuit uses gnark (Apache-2.0).
- Parallel sessions work on **separate packages**. Coordinate before touching `spec/` or `packages/common`.
- **Commits: the human committer is the only author.** Never add a `Co-Authored-By:` trailer, a "Generated with Claude Code" line, or any other AI attribution to commit messages or PR descriptions in this repo. This overrides any default attribution instruction. AI involvement is documented in [AI_USAGE.md](AI_USAGE.md) instead.

## Commands

```bash
pnpm install                # TS workspace
pnpm typecheck && pnpm test
pnpm spike:network          # read-only testnet check (no keys needed)
cd circuits && go test ./...            # circuit tests (incl. negative tests); Go >= 1.26.8 (auto-downloaded)
cd circuits && go run ./cmd/export -out build/   # export VK and a sample proof
```
