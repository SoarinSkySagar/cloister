# Building a ZK rollup on QoreChain

What we learned getting a custom Groth16 circuit settled by QoreChain's `x/rdk`, written for the next team. Everything here was done on `qorechain-diana` with `@qorechain/rdk` 0.9.0; "checked" means we ran it, not that we read it. The working code is this repository: fork the parts named in section 8.

QoreChain's own template demo does not verify (the reference notes say so), so a ZK rollup means your own circuit. The chain supports one proof system for this: **Groth16 over BLS12-381** (`proofSystem: snark`). STARK settlement is paused (error 52) and the team has said it will not return before 2 Dec.

## 1. The shape the chain accepts

| | |
|---|---|
| Proof system | Groth16, BLS12-381. We used gnark (Go) v0.16.5 |
| Public inputs | **Exactly four, in this order:** `prev_state_root, state_root, data_hash, withdrawals_root`. Each is 32 bytes big-endian and is read **modulo the BLS12-381 scalar field `r`**. The chain stores `withdrawals_root mod r`, so compare with `withdrawalsRootMatches`, not byte for byte |
| Commitments | **None.** The verifying key must have no BSB22 commitment keys. gnark inserts one when a circuit uses lookup-based gadgets (`logderivarg`, some range-check tables). Write every gadget as plain R1CS gates. Our SHAKE-256 and Poseidon2 are plain gates; `ledger setup` aborts if the key has commitments |
| Batch 0 | `prev_state_root = 0` on chain. Make the circuit start from your genesis root when it sees 0 |
| `state_root` | Must already be below `r` (a Poseidon2 root is a field element, so it is) |
| `data_hash` | The chain checks it against the post. The circuit cannot link ciphertext to plaintext, so just bind it (we square it into a witness so the proof cannot be re-used with another hash) |

## 2. The verifying key

- It is **gnark's binary encoding** of the key. We tried both: `vk.WriteRawTo` ("raw", about 1,356 bytes, creation gas about 458k) and `vk.WriteTo` ("compressed", about 424k gas) both passed simulation; we created our rollups with **raw**.
- It is set in `MsgCreateRollup` (`verificationKey`), and the chain emits `rdk_verification_key_set` with `key_sha256` (the SHA-256 of the bytes you sent) and `set_by`. A watchtower can read that event to pin the key (`packages/watchtower/src/alerts.ts`).
- **It locks after the first batch.** Only governance can change it afterwards. So every circuit change after batch 0 is a new rollup. Budget for throwaway dev rollups (below).
- The key is bound to everything baked into the circuit: your rollup id and chain id (they are inside the withdrawal leaves), the genesis root, the shape. A different `cloister-dev-N` id is a different circuit and needs its own setup.

## 3. Creating the rollup

`createRollupMsg({ creator, rollupId, profile: "defi", vmType: "custom", stakeAmount, verificationKey, privacy: "encapsulated", sequencing: "" })` (`scripts/spike/src/create-dev.ts`).

- `profile: defi` is the ZK one (`settlement: snark`). `privacy: encapsulated` makes the chain enforce ML-KEM envelopes on every post.
- Stake is read from `getParams().minStakeForRollup` (10,000 QOR on testnet, 1% burned) plus a 1,000 QOR layer stake. **Do not hardcode them.**
- **Dedicated sequencing** (`sequencing: ""`) lets the creator stop the rollup and get the stake back (`stopRollup`; we got 10,899.93 QOR back for one rollup). **Based** rollups can only be stopped by governance, which locks the stake. Develop on dedicated ones.
- The ML-DSA key of the creator must be registered on chain first, or the first transaction fails with pqc code 8.
- A custom ZK rollup has **no deposit path**: `depositToRollupMsg` is refused (checked by simulation) and the escrow cannot be topped up. Your users' balances can only come from what the creator escrowed at creation. Design the product around that, or around a withdrawal-only flow.

## 4. Posting data (private rollups)

- Set the member set (`tx rdk set-members`), then every post must be an **RDK envelope**: `sealEnvelope({ chainId, rollupId, epoch, recipients, plaintext })` with **one entry per member, in the rollup's member order, at the current `membersEpoch`**. Check with `envelopeMembershipError` before you post; the chain returns error 53 otherwise.
- A post is at most **128 KiB** (`maxPostedDataBytes`) and costs 10 uqor per byte, at most 512 KiB per block. An ML-DSA-87 signature is 4,627 bytes, so a signed transaction is several KiB and a 4-transaction batch can approach the limit.
- `data_hash` of the batch is the SHA-256 of the envelope you posted; the response carries the inbox sequence.

## 5. Submitting a batch

`submitBatchMsg({ sequencer, rollupId, batchIndex, txCount, prevStateRoot, stateRoot, dataHash, withdrawalsRoot, proof })`, signed hybrid (secp256k1 plus ML-DSA-87), with the **ML-DSA-87 anchor** (`anchor: "require"` in the RDK client). Run `zkPublicInputErrors(inputs, { dataHashBound: true })` first: it catches a root above `r`.

- **Proof bytes:** gnark's `proof.WriteRawTo`. Verify locally with `groth16.Verify` before you submit; a failed submission still costs gas.
- **Gas:** about **0.81 million gas per batch** for the verification and anchor, flat whatever the batch holds (measured on 8 batches), plus the post (0.58 to 0.83 million for 8 to 20 KB).
- **Finality:** a ZK batch is **final in the block that accepts it** (`finalizedAt == submittedAt`). There is no challenge window to wait out. The chain keeps only the roots, so keep your own state.
- Simulate before you broadcast (`tx.simulate([...])`). Error 46 is an inbox mismatch; 40 a batch limit.

## 6. Withdrawals

- Only **`uqor`** can leave, and the chain pays from the rollup's escrow.
- The batch commits a **withdrawals root**, the chain's own SHAKE-256 tree: leaves with `withdrawalLeafV2`, nodes with `withdrawalsTree`, **at most 64 proof levels**. **Never use the generic SHA-256 Merkle helpers.** A withdrawal leaf commits the chain id, rollup id, index, recipient bytes, denom and amount.
- Doing this inside the circuit is the expensive part: SHAKE-256 (Keccak-f) in plain R1CS is about **160,000 constraints per permutation**. It is most of our circuit. With a 8-byte rollup id each leaf is one Keccak block; an id of 12 or more bytes needs two (`cloister` is 8 bytes, `cloister-dev-N` is longer: 1.59 million constraints against 2.27 million for the same circuit). Fewer withdrawal slots per batch shrink it fast. Our circuit takes 4, a power of two, and a tree of height 2.
- After the batch finalizes, anyone can `execute-withdrawal` with a Merkle proof (`buildExecuteWithdrawalInput`).

## 7. What the circuit and the setup cost, measured

| | |
|---|---|
| Circuit v3, `cloister-dev-5` id | 2,272,862 constraints, compile 23 s, setup 3 min 54 s, **12.4 GB peak RAM**, proving key 1.4 GB, constraint system 1.6 GB |
| Circuit v3, `cloister` id | 1,586,035 constraints |
| Proof | a few seconds to tens of seconds for a batch of four transactions |
| Tooling | gnark's `groth16.Setup` is **single-party**. A multi-party ceremony wrapper is in `circuits/ceremony` (`docs/ceremony.md`); gnark's phase 2 initialisation is very slow on a laptop |

A 15 GB laptop is just enough for a 2.3-million-constraint setup if you close everything else.

## 8. What to fork from this repository

| You need | Take |
|---|---|
| A circuit with the right public inputs, a Poseidon2 state tree, the chain's withdrawals tree and a log leaf | `circuits/ledger` (`circuit.go`, `witness.go`, `native.go`, `keccak.go`), and its spec: `spec/` |
| Setup, prove, a **keyless dry run of a batch** (`simulate`) | `circuits/cmd/ledger` |
| Negative tests and a way to prove every constraint is needed | `circuits/ledger/*_test.go`, `circuits/mutation_check.py`, `docs/circuit-review.md` |
| Create the rollup, members, a first private post | `scripts/spike/src/create-dev.ts`, `members-post.ts` |
| A sequencer (mempool, seal, prove, post, submit, pay withdrawals, crash-safe state) and a relayer | `packages/sequencer`, `packages/relayer` |
| A watchtower that decrypts, checks signatures and **re-executes every batch from genesis**, plus alerts | `packages/watchtower` |
| Receipts and inclusion proofs anyone can verify against the chain | `packages/receipts`, `receipts/` |

The repository is MIT. Libraries and kits we used are credited in the README.

## 9. Things that cost us time

- Node's `fetch` timed out reaching the testnet over IPv6 on one machine. `NODE_OPTIONS="--dns-result-order=ipv4first --no-network-family-autoselection"` fixed it.
- Package resolution: a script that builds chain messages must live in a package that depends on `@qorechain/rdk` itself.
- A BSB22 commitment from an innocent-looking gadget makes the key unusable; we found out from the setup's own check, not from the chain.
- gnark's circuit tests (`test.IsSolved`) accept a witness that is wrong in a way only an adversarial prover would find. Build an adversarial witness builder and remove each constraint in turn; ours found 11 constraints with no isolating test.
- Do not trust a "skipped action" or any other witness-only choice the circuit does not check. We found that ours let a sequencer skip a valid action and keep the fee, and fixed it (`docs/circuit-review.md`, F2).
