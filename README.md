# Cloister

**A private ZK rollup on QoreChain for settlement between parties that know each other: atomic multi-party swaps, sponsored gas, post-quantum signatures and proofs you can check.**

Two firms swap assets, a company pays a batch of suppliers, an escrow releases on a date. **Members see the data.** Everyone else sees ciphertext, a validity proof and a post-quantum signature, and can still verify that one specific payment happened.

> Built for the **Build Before Q-Day** hackathon (Protocol Builders track). Testnet (`qorechain-diana`) only. The final `cloister` rollup is created after the circuit is frozen; everything below ran on throwaway dev rollups (`cloister-dev-2`, stopped; `cloister-dev-3`, current).

## What is in it

- **Multi-party frames** (modelled on EIP-8141). One signed transaction carries a sender, up to three co-signers whose balances its actions may debit, and a sponsor who pays the fee. Each party signs **once** with ML-DSA-87 however many legs there are. Atomic legs apply all or none, so a swap needs no escrow contract. A time lock holds a transaction until a chosen batch.
- **Sponsored gas.** A relayer forwards sealed transactions and is repaid in-rollup, so users need no L1 QOR.
- **Sealed posts (ML-KEM-1024).** QoreChain refuses any post that is not a proper envelope for the member set.
- **Validity proofs.** Every batch is proven with Groth16 (BLS12-381, gnark), verified by QoreChain and anchored with an ML-DSA-87 signature. Withdrawals are part of the proof, so there is no challenge window.
- **Fully reserved funds.** Supply can never exceed the L1 escrow, and the proof enforces it. The chain has no deposit path for a private ZK rollup (checked by simulation), so members are onboarded and funded by the operator.
- **Three things anyone can check against the chain:** a settlement receipt per batch, a signed verdict from each member watchtower, and an **inclusion proof** (about 1 KB) that one transaction ran in a given batch, with nothing else in the batch revealed. The proof's root is committed inside the state root the chain stores.

## Verify it yourself (no keys, about a minute)

```bash
pnpm install
pnpm --filter @cloister/receipts cli verify --all                 # every receipt and every watchtower verdict, against live chain state
pnpm --filter @cloister/receipts cli verify-proof receipts/inclusion/cloister-dev-3-batch4-swap.json
```

The second command checks a real two-party atomic swap (batch 4 of `cloister-dev-3`) against the state root QoreChain holds. Change any field in that file (an amount, the batch number, remove the co-signer) and it is refused. For a page instead of a CLI: `pnpm --filter @cloister/receipts start`, then open http://127.0.0.1:8791 and paste a receipt or a proof.

Run the tests (no chain needed):

```bash
pnpm typecheck && pnpm test           # TypeScript packages
cd circuits && go test ./...          # circuit, including every negative test
python3 circuits/mutation_check.py    # removes each constraint in turn; a test must fail each time
```

## Evidence

| What | Where |
|---|---|
| Every testnet transaction that proves something (creation, 7 batches of the current circuit, a two-party swap, a time lock, withdrawals paid on L1, refunds) | [PROOF.md](PROOF.md) |
| Receipts, watchtower verdicts and the swap's inclusion proof | [receipts/](receipts/) |
| What each circuit rule is, and the test that makes it fail | [docs/circuit-review.md](docs/circuit-review.md) |
| What can go wrong, and what covers it | [THREAT_MODEL.md](THREAT_MODEL.md) |
| What we know is missing or weak | [LIMITS.md](LIMITS.md) |
| Which parts Claude wrote, and the mistakes it made | [AI_USAGE.md](AI_USAGE.md) |

## Honest limits (the full list is in LIMITS.md)

- Privacy is from outsiders. Members, including the sequencer and the watchtowers, see everything.
- ML-DSA signatures are not proven in the circuit; the member watchtowers verify them. There is one member watchtower so far.
- The circuit's constraints have **not been reviewed by a human yet**. Tests show every constraint is needed (each was removed in turn and a test failed), but they are hand-written attacks, not fuzzing.
- The fee recipient is not fixed inside the circuit (finding F1 in the review guide).
- The trusted setup was run by one party.
- Watchtower re-execution of batches and alerts are designed, not built.

## Layout

| Path | What |
|---|---|
| `circuits/` | Groth16 circuit (Go, gnark), its reference model, tests and the mutation check |
| `packages/common` | Frame-transaction codec, signatures, state types |
| `packages/sequencer` | Verifies signed transactions, batches, proves, posts, submits, pays withdrawals |
| `packages/relayer` | Public door: validates and forwards transactions |
| `packages/wallet` | CLI: keys, build and sign multi-party transactions, fetch inclusion proofs |
| `packages/watchtower` | Member node: decrypts and checks every batch, signs verdicts |
| `packages/receipts` | Verifier for receipts, verdicts and inclusion proofs (CLI and page) |
| `packages/explorer` | Explorer for the rollup (black theme, frames decoded) |
| `spec/` | Wire formats, state layout, inclusion proofs, golden vectors |

More in [CLAUDE.md](CLAUDE.md#layout) and [design.md](design.md).

## Credits

Built with these open source libraries and kits:

| Library | Licence | Use |
|---|---|---|
| [@qorechain/rdk](https://github.com/qorechain/qorechain-rdk) | Apache-2.0 | Rollup lifecycle, batches, envelopes, receipts, withdrawals |
| [@qorechain/pqc](https://github.com/qorechain/qorechain-pqc) | Apache-2.0 | ML-DSA / ML-KEM / SHAKE-256 primitives |
| [@qorechain/qoresign](https://github.com/qorechain/qoresign) | Apache-2.0 | Hybrid ML-DSA-87 signing |
| [@qorechain/qoreseal](https://github.com/qorechain/qoreseal) | Apache-2.0 | ML-KEM-1024 sealing helpers |
| [gnark](https://github.com/Consensys/gnark) | Apache-2.0 | Groth16 circuit and prover |
| [esbuild](https://github.com/evanw/esbuild) | MIT | Bundles the receipt verifier page for the browser |
| [@noble/hashes](https://github.com/paulmillr/noble-hashes) | MIT | SHAKE-256 and Keccak for verdicts and the Poseidon2 round keys, in the browser and Node |

The inclusion-proof design is inspired by [EIP-8288](https://eips.ethereum.org/EIPS/eip-8288) (Vitalik Buterin, Thomas Coratger), and the frame format by EIP-8141. The explorer's layout follows the Dora beacon-chain explorer; no code was taken from it.

## License

MIT. See [LICENSE](LICENSE).
