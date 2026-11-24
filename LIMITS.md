# Known limits

Kept current as we build. Threat references are to [THREAT_MODEL.md](THREAT_MODEL.md); circuit findings (F1 to F8; F2 fixed and F3, F6 narrowed in circuit v3) are in [docs/circuit-review.md](docs/circuit-review.md).

**Scope**
- Testnet only (`qorechain-diana`). Nothing here has handled value.
- The final `cloister` rollup is not created yet. Development runs on throwaway `cloister-dev-N` rollups, which are stopped for a refund. `cloister-dev-2` ran circuit v1 and is stopped; `cloister-dev-3` ran circuit v2 and is stopped. Circuit v3 (checked skips, transaction digest, new-account rule) runs on `cloister-dev-5` (8 batches verified by QoreChain on 23 Nov); `cloister-dev-3` is stopped and refunded.
- The circuit's constraints have not had a human review. Run `go test ./...`, `python3 circuits/mutation_check.py` and read the review guide.
- Every circuit constraint is shown necessary by a test (70 of 70 mutations caught). Tests are hand-written attacks plus a randomised differential test with a generator I wrote; neither is an audit.

**What is not proven in the circuit** (checked by watchtowers instead; detected, not prevented)
- ML-DSA signatures of the sender, every co-signer and the sponsor (T2, T3).
- That the terms in a record (window, co-signers, payer, actions) are the ones the signers wrote (T3, T7). Circuit v3 commits them in a digest anyone holding the signed transaction can check, and the watchtower can re-execute whole batches (`--replay`); the circuit still does not verify the signature that would make a lie impossible. `docs/pq-auth.md` measures why ML-DSA cannot be verified in this circuit (about 60 million constraints) and prototypes the feasible alternative (`circuits/hbs`, about 0.22 million constraints per signature; not wired in).
- Ordering, inclusion and censorship by choice of transaction (T8).

**Trust**
- One sequencer, which is also the rollup creator (T8); the chain gives a dedicated rollup no second submitter, and what a based ZK rollup allows is unverified (`docs/decentralisation.md`). On a dedicated rollup only the sequencer may post, so the relayer forwards over HTTP; relayer posting on a based rollup is untested on chain.
- Members see all data. Privacy is from outsiders, not from the sequencer or the watchtowers; hiding data from members needs recursion or threshold proving that the settlement proof system does not support (`docs/private-state.md`). Use one rollup per counterparty group for "A must not see B".
- One member watchtower exists today. Verdicts add accountability, not certainty, and there is no staking or slashing (T18).
- The trusted setup of dev rollups is single-party (T20). A multi-party ceremony tool exists (`docs/ceremony.md`) and has been rehearsed, not run for a real key.
- Balances are backed by the creator's escrow; the treasury key is a trusted role (T15).

**Circuit shape**
- 4 transactions per batch, 3 actions per transaction, up to 3 co-signers, 4 withdrawals per batch, 65,535 accounts.
- Withdrawal recipients must be 42-character `qor1` addresses; only QOR can be withdrawn. USD is a rollup-internal asset.
- Setting up the circuit for a `cloister-dev-N` id (two Keccak blocks per withdrawal leaf) took about 4.5 minutes and **13.2 GB of RAM** at its peak on a 15 GB machine for circuit v2 (it fits with little to spare; close other programs); circuit v3 measured 3 min 54 s and 12.4 GB (2,272,862 constraints). The 8-byte `cloister` id needs one block per leaf and less.
- A different shape means a new circuit, a new verifying key and, once a rollup has settled a batch, a new rollup.

**Operations**
- The sequencer keeps state in local files (`state.json`, `keys.json`, `mempool.json`, `proofs/`), written atomically (a kill-the-writer test never finds a half-written file). It recovers if a crash leaves the chain one batch ahead. A crash mid-proof leaves no partial state (the prover's outputs are written atomically and nothing is read before the prover exits successfully); a crash after the data was posted and before the batch was submitted leaves an orphan post, and what the chain does with it is untested.
- Batches are built one at a time; there is no parallel proving.
- The watchtower re-executes batches against the state root only with `--replay`, on circuit v3 rollups, and has matched every batch of `cloister-dev-5` (8 of 8). `--alerts` raises stall, continuity, membership-epoch, watchtower-disagreement and verification-key alerts, tested on fixtures; the key alert reads the chain's `rdk_verification_key_set` event, verified live for a creation but never for a change. It does not check inclusion against a based inbox.
- Settlement receipts anchor a batch's root with the creator's ML-DSA-87 signature; they say nothing about the transactions inside. Inclusion proofs and verdicts cover that, with the limits above.
- Inclusion proofs disclose a whole record to whoever holds them.
- The explorer and receipts page are local tools bound to 127.0.0.1; a public deployment needs a reverse proxy.

**Cannot be done in this system**
- ML-DSA verification inside the circuit (about 60 million constraints per signature by our estimate; `docs/pq-auth.md`). EIP-8288-style aggregation of post-quantum signatures would need a prover and verifier the chain does not offer; our watchtower verdict is the stand-in and is structured so an aggregate proof could replace it.
- Chain-enforced forced inclusion. A dedicated rollup lets only the sequencer post; a based rollup lets anyone post (untested for us) but, as far as the documentation says, the chain cannot force the sequencer to execute what is posted, and the circuit cannot link ciphertext to plaintext. What we have is detection: `--replay` re-execution compares the chain's root with the execution of the posted bundle.
