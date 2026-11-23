# Cloister

**A private ZK rollup on QoreChain for settlement between parties that know each other: atomic multi-party swaps, sponsored gas, post-quantum signatures and proofs you can check.**

Two firms swap assets, a company pays a batch of suppliers, an escrow releases on a date. **Members see the data.** Everyone else sees ciphertext, a validity proof and a post-quantum signature, and can still verify that one specific payment happened.

> Built for the **Build Before Q-Day** hackathon (Protocol Builders track). Testnet (`qorechain-diana`) only. The final `cloister` rollup is created after the circuit is frozen; everything below ran on throwaway dev rollups (`cloister-dev-2` and `-3`, stopped; `cloister-dev-5`, current, runs circuit v3).

## What is in it

- **Multi-party frames** (modelled on EIP-8141). One signed transaction carries a sender, up to three co-signers whose balances its actions may debit, and a sponsor who pays the fee. Each party signs **once** with ML-DSA-87 however many legs there are. Atomic legs apply all or none, so a swap needs no escrow contract. A time lock holds a transaction until a chosen batch.
- **Sponsored gas.** A relayer forwards sealed transactions and is repaid in-rollup, so users need no L1 QOR.
- **Sealed posts (ML-KEM-1024).** QoreChain refuses any post that is not a proper envelope for the member set.
- **Validity proofs.** Every batch is proven with Groth16 (BLS12-381, gnark), verified by QoreChain and anchored with an ML-DSA-87 signature. Withdrawals are part of the proof, so there is no challenge window.
- **Fully reserved funds.** Supply can never exceed the L1 escrow, and the proof enforces it. The chain has no deposit path for a private ZK rollup (checked by simulation), so members are onboarded and funded by the operator.
- **Checked skips and a signed-terms digest** (circuit v3, built and tested locally; it goes on chain with `cloister-dev-5`). A sequencer can no longer skip a valid action and keep the fee: the circuit makes every skip prove that some action of its atomic group could not apply. Every record also carries a digest of what the signers wrote, so the holder of a signed transaction can check that a proof is for *their* transaction and which actions applied (`check-tx`).
- **Three things anyone can check against the chain:** a settlement receipt per batch, a signed verdict from each member watchtower, and an **inclusion proof** (about 1 KB) that one transaction ran in a given batch, with nothing else in the batch revealed. The proof's root is committed inside the state root the chain stores.

## Verify it yourself (no keys, about a minute)

```bash
pnpm install
pnpm --filter @cloister/receipts cli verify --all                 # every receipt and every watchtower verdict, against live chain state
pnpm --filter @cloister/receipts cli verify-proof receipts/inclusion/cloister-dev-5-batch4-skipped-swap.json
pnpm --filter @cloister/receipts cli check-tx receipts/inclusion/cloister-dev-5-batch4-skipped-swap.json receipts/inclusion/cloister-dev-5-batch4-skipped-swap.tx.hex
```

The second command checks a real two-party atomic swap that **could not apply** (batch 4 of `cloister-dev-5`: one leg was unaffordable, so both were skipped and the fee still charged, which the circuit allows only because it proves a leg fails) against the state root QoreChain holds. The third checks that the proof is for the transaction that was signed, and says which actions applied; give it another transaction and it is refused. The older proof of an applied swap on `cloister-dev-3` still verifies too (`receipts/inclusion/cloister-dev-3-batch4-swap.json`, a version 1 proof). Change any field in that file (an amount, the batch number, remove the co-signer) and it is refused. For a page instead of a CLI: `pnpm --filter @cloister/receipts start`, then open http://127.0.0.1:8791 and paste a receipt or a proof.

Run the tests (no chain needed):

```bash
pnpm typecheck && pnpm test           # TypeScript packages
cd circuits && go test ./...          # circuit, including every negative test
python3 circuits/mutation_check.py    # removes each constraint in turn; a test must fail each time
```

## Build your own ZK rollup on QoreChain

As far as we know this is the only custom-circuit ZK rollup settled by `x/rdk`, so the guide is part of the submission: [docs/zk-rollup-on-qorechain.md](docs/zk-rollup-on-qorechain.md) (what the chain accepts, the verifying key, posting, gas, withdrawals, costs, and which directories to fork). How fast a withdrawal really is: [docs/finality.md](docs/finality.md) (final in the submitting block, 17 s from post to money on L1, no challenge window).

## Evidence

| What | Where |
|---|---|
| Every testnet transaction that proves something (creations, 8 batches of circuit v3, a two-party swap, a skipped swap, a time lock, a withdrawal paid on L1, refunds) | [PROOF.md](PROOF.md) |
| Receipts, watchtower verdicts and the swap's inclusion proof | [receipts/](receipts/) |
| What each circuit rule is, and the test that makes it fail | [docs/circuit-review.md](docs/circuit-review.md) |
| What can go wrong, and what covers it | [THREAT_MODEL.md](THREAT_MODEL.md) |
| What we know is missing or weak | [LIMITS.md](LIMITS.md) |
| Which parts Claude wrote, and the mistakes it made | [AI_USAGE.md](AI_USAGE.md) |

## Honest limits (the full list is in LIMITS.md)

- Privacy is from outsiders. Members, including the sequencer and the watchtowers, see everything.
- ML-DSA signatures are not proven in the circuit; the member watchtowers verify them. There is one member watchtower so far.
- The circuit's constraints have **not been reviewed by a human yet**. Tests show every constraint is needed (each was removed in turn and a test failed), and a randomised test compares the builder, a reference interpreter and the circuit, but the generator is ours.
- The dev rollups' trusted setup was run by one party. A multi-party ceremony tool exists and has been rehearsed ([docs/ceremony.md](docs/ceremony.md)), not run for a real key.
- The proof system (Groth16 over BLS12-381) is not post-quantum, and the circuit does not verify the ML-DSA signatures. [docs/pq-auth.md](docs/pq-auth.md) measures why ML-DSA cannot be verified in this circuit and prototypes a hash-based signature that can.
- Watchtower re-execution (`--replay`) is built and tested against the builder, not yet run against a live rollup. Alerts are designed, not built.

## Layout

| Path | What |
|---|---|
| `circuits/` | Groth16 circuit (Go, gnark), its reference model, tests and the mutation check; `ceremony/` multi-party setup; `hbs/` hash-based signature prototype |
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
