# One sequencer, and what the chain lets us do about it

Cloister has one sequencer today: the rollup creator's account posts the data, proves the batch and submits it (`packages/sequencer`). It chooses which transactions go in and in what order, it sees every transaction, and if it stops, the rollup stops. This note says what we can improve, what the chain makes impossible, and what is a question for the chain's team. Facts about the chain are from `docs/qorechain-reference.md` and the RDK 0.9.0 typings; anything marked **unverified** has not been tried on a live rollup.

## What the sequencer can and cannot do, now

| Power | Status | Covered by |
|---|---|---|
| Execute something other than what it posted | closed in the detection sense | watchtower `--replay`: the chain's root must equal the execution of the sealed bundle |
| Skip a valid action and keep the fee | closed in the circuit (v3) | rows S1 to S10 |
| Forge a signature (debit an account nobody authorised) | **open** | member watchtowers' `signature` check; the digest makes it provable afterwards; `docs/pq-auth.md` for the in-circuit route |
| Choose which transactions to include, and their order | **open** | detection only: a member that sees a valid signed transaction never executed can say so (`--replay` checks the executed set against the sealed bundle, and the bundle against what members know was sent) |
| Stop | **open** | nothing: no other account may take over |
| Read everything | **open, by design** | members see all data (THREAT_MODEL, `docs/private-state.md`) |

## What a dedicated rollup allows

Only the creator posts data and submits batches. There is no way to add a second submitter, so **no failover and no rotation**. A threshold or multi-signature creator account would help only if QoreChain supports one for rollup creators, which we have not found in the docs: **unverified**. What we can do is keep the sequencer's whole state reproducible, so that a replacement operator can be set up by anyone who is a member:

- `watchtower --replay` already rebuilds the state from genesis from the sealed bundles alone, with no sequencer files. The same code (`packages/watchtower/src/replay.ts`) is the start of a standby sequencer: replay to the chain head, then prove the next batch.
- But a standby cannot submit unless it controls the creator account, so today this is **disaster recovery with the creator's key, not decentralisation**. The sequencer's crash safety (atomic state files, `recover()`) is what makes restarting from its own files safe (`packages/sequencer/src/atomic.ts`).

## What a based rollup might allow (unverified)

Under `--sequencing based` the chain defines the batch by an **inbox range**: users post sealed transactions to the L1 inbox, the chain checks the batch's `data_hash` against the range it consumes, and a batch starts where the previous one ended (error 46 otherwise). If a ZK based rollup lets any bonded account submit, then:

- **The L1 inbox is the mempool and orders the transactions.** No sequencer chooses. Anyone can post (sealing to the member keys needs only public keys), so a transaction cannot be refused at the door: that is forced inclusion at the data layer.
- **Any member can prove the next batch.** The batch is a deterministic function of the state and the range, so members run the same prover (`ledger simulate` already shows the execution is deterministic). Liveness no longer depends on one operator.
- **What it does not give.** The chain cannot force a submitter to execute a posted transaction (the circuit cannot link ciphertext to plaintext); a submitter that drops one is caught by `--replay`, and accountability is social or governance, not a slashing proof. And the rule for which posted transactions are *invalid* (bad signature, wrong nonce, expired) would have to be written down as a deterministic filter that every member applies identically, because those checks are off-circuit.

What we do not know, and need a based dev rollup (stake) to find out:

1. Whether a ZK based rollup accepts batches from any bonded submitter, or only from its creator. (The docs describe the 1,000 QOR submitter bond for `qledger-v1` rollups only.)
2. Whether a private (`encapsulated`) rollup can be created as `based`. The 17 Nov simulation said creation is accepted; nothing was settled.
3. Whether the relayer's posting path works on a based rollup (untested on chain, `packages/relayer/README.md`).
4. Whether the chain demands that a batch consume the whole inbox up to its head, or only up to the `inbox_end` the submitter names.

Based rollups cannot be stopped by their creator (governance only), so the stake is locked for good: do this on a throwaway rollup before the final one.

## What we built for this, and what remains

| | State |
|---|---|
| Deterministic, key-free re-execution of a batch from sealed data | built, tested (`replay.ts`, `ledger simulate`) |
| Crash-safe sequencer state, so a restart never reads a half-written file | built, tested with a kill-the-writer test (`atomic.test.ts`) |
| Alerts for stalls, a batch that does not continue the last, membership changes and watchtowers that disagree | built, tested on fixtures (`alerts.ts`) |
| A deterministic filter for posted transactions (what a based batch must include) | **not written** |
| A standby sequencer that takes over | **not written**, and not possible on a dedicated rollup |
| Anything on a based rollup | **untested** |
