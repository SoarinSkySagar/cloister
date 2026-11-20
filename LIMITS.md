# Known limits

Kept current as we build. Threat references are to [THREAT_MODEL.md](THREAT_MODEL.md); circuit findings (F1 to F8) are in [docs/circuit-review.md](docs/circuit-review.md).

**Scope**
- Testnet only (`qorechain-diana`). Nothing here has handled value.
- The final `cloister` rollup is not created yet. Development runs on throwaway `cloister-dev-N` rollups, which are stopped for a refund. `cloister-dev-2` ran circuit v1 and is stopped; `cloister-dev-3` runs circuit v2.
- The v2 circuit's constraints have not had a human review. Run `go test ./...`, `python3 circuits/mutation_check.py` and read the review guide.
- Every circuit constraint is shown necessary by a test (37 of 37 mutations caught), but the tests are hand-written attacks; there is no fuzzing yet.

**What is not proven in the circuit** (checked by watchtowers instead; detected, not prevented)
- ML-DSA signatures of the sender, every co-signer and the sponsor (T2, T3).
- That a transaction's recorded time window is the one it signed (T7).
- That a skipped action had to be skipped (T6), and ordering or censorship (T8).

**Trust**
- One sequencer, which is also the rollup creator (T8). On a dedicated rollup only the sequencer may post, so the relayer forwards over HTTP; relayer posting on a based rollup is untested on chain.
- Members see all data. Privacy is from outsiders, not from the sequencer or the watchtowers.
- One member watchtower exists today. Verdicts add accountability, not certainty, and there is no staking or slashing (T18).
- The trusted setup is single-party (T20).
- Balances are backed by the creator's escrow; the treasury key is a trusted role (T15).

**Circuit shape**
- 4 transactions per batch, 3 actions per transaction, up to 3 co-signers, 4 withdrawals per batch, 65,535 accounts.
- Withdrawal recipients must be 42-character `qor1` addresses; only QOR can be withdrawn. USD is a rollup-internal asset.
- Setting up the circuit for a `cloister-dev-N` id (two Keccak blocks per withdrawal leaf) took about 4.5 minutes and **13.2 GB of RAM** at its peak on a 15 GB machine (it fits with little to spare; close other programs). The 8-byte `cloister` id needs one block per leaf and less.
- A different shape means a new circuit, a new verifying key and, once a rollup has settled a batch, a new rollup.

**Operations**
- The sequencer keeps state in local files (`state.json`, `keys.json`, `mempool.json`, `proofs/`); it recovers if a crash leaves the chain one batch ahead, but a crash mid-proof is untested.
- Batches are built one at a time; there is no parallel proving.
- The watchtower does not re-execute batches against the state root, does not check inclusion against a based inbox, and raises no alerts (VK-update alarm, liveness). Those are designed, not built.
- Settlement receipts anchor a batch's root with the creator's ML-DSA-87 signature; they say nothing about the transactions inside. Inclusion proofs and verdicts cover that, with the limits above.
- Inclusion proofs disclose a whole record to whoever holds them.
- The explorer and receipts page are local tools bound to 127.0.0.1; a public deployment needs a reverse proxy.

**Cannot be done in this system**
- ML-DSA verification inside the circuit (far beyond our constraint budget). EIP-8288-style aggregation of post-quantum signatures would need a prover and verifier the chain does not offer; our watchtower verdict is the stand-in and is structured so an aggregate proof could replace it.
