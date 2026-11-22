# How fast is a withdrawal? Measured on cloister-dev-5

**Claim:** in a ZK rollup a batch is final in the block that accepts its proof, so a withdrawal needs no challenge window and no liquidity pool in front of it. This note shows what that looked like on the testnet, and what was not measured.

## What the chain says

`cloister-dev-5` (settlement `snark`, circuit v3), eight batches, 22 Nov 2026. For every batch we read back from the chain (`rdk batch/<id>/<n>`) `finalizedAt` equals `submittedAt` on the batches checked (0, 3, 4, 5 and 7): **finality in the same block as the submission**. The chain parameter `defaultChallengeWindow` is 3,600 s, which is what an optimistic rollup on this chain waits before a withdrawal can be executed without a third party fronting it; our rollup's own `challengeWindowSec` is 0.

## The timings (chain time, from the transactions' own heights and timestamps)

| Batch | Post → submit (blocks) | Post → submit (s) | Post gas | Submit gas | Post size |
|---|---|---|---|---|---|
| 0 | 6 | 9 | 829,650 | 801,788 | 19,831 B |
| 1 | 6 | 8 | 829,650 | 814,316 | 19,831 B |
| 2 | 7 | 10 | 583,860 | 814,478 | 11,639 B |
| 3 | 6 | 9 | 829,692 | 814,562 | 19,831 B |
| 4 | 6 | 9 | 829,650 | 814,568 | 19,831 B |
| 5 (a withdrawal) | 7 | 10 | 583,860 | 826,962 | 11,639 B |
| 6 | 15 | 22 | 583,863 | 815,156 | 11,639 B |
| 7 | 7 | 10 | 583,920 | 814,571 | 11,639 B |

The submit gas is the Groth16 verification plus the anchor: about 0.81 million gas whatever the batch holds.

**The withdrawal (batch 5):** data posted 18:59:38, batch submitted and finalized 18:59:48, the 0.5 QOR withdrawal paid on L1 at 18:59:55 (gas 206,207). That is **10 s from post to final and 17 s from post to money on L1**.

## What is not in these numbers

- **Proving time.** The prover runs *before* the post, on the sequencer's machine. On the development laptop (12 threads) two real proofs plus a build ran in 46 seconds (`scripts/spike/src/multiparty-local.ts`); a batch's proof is well under a minute, but we did not time it separately on the live run.
- **Waiting for a batch.** A transaction waits for the sequencer's next batch (we ran with a 25 s interval, so up to about that). A user's total wait is that, plus proving, plus the 10 s above. We did not measure it end to end.
- **One run, eight batches, a testnet with a fast chain.** Block times were about 1.4 s in this run, not the 500 ms the rollup record shows.

## The comparison

An optimistic rollup's withdrawal is safe only after its challenge window (3,600 s default here, seven days elsewhere), so projects such as Wicketgate build an instant-exit product on top: staked watchers sign, a pool pays at once and is repaid after the window. That is a good answer to a window that exists. A validity-proof rollup has no window to cover: the proof is the finality. The price is the work of building and proving a circuit, which is what most of this repository is.

The two are not opposites: both rest on someone checking a batch. In ours it is a proof the chain verifies; in theirs it is stake behind watchers' signatures.
