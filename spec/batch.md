# Batch circuit and batch input (draft v3: skips must be justified, transaction digest, new-account rule)

Implemented in [`circuits/ledger`](../circuits/ledger). The sequencer (TypeScript) decrypts the posts and verifies ML-DSA signatures, then hands the Go prover a **batch input** as JSON. The prover executes it, builds the witness and proves.

## Shape (v2)

| | Value | Why |
|---|---|---|
| State tree depth | 16 | 65,535 accounts: the last leaf is the reserved log leaf ([state.md](state.md)) |
| Tx slots per batch | 4 | Padded with inactive slots; a power of two (the transaction root is a Merkle tree) |
| Moves per tx | 4 | Move 0 is the fee (payer → relayer), moves 1–3 are actions |
| Parties per tx | 3 | Co-signers whose accounts an action may debit ([frame-tx.md](frame-tx.md)) |
| Relayer | one account | A constant of the circuit (`relayer` in `config.json`): every fee is paid to it |
| Withdrawal slots | 4 | Withdrawals tree depth 2 |

Measured on 18 Nov for circuit v1 (3 moves, no parties, no log): **1,460,727 R1CS constraints for `cloister` (8-byte id), 4 public inputs, no commitment extension. Proving takes 5.4 s and setup takes 2 min, with 9.4 GB peak RAM (during setup).** Keccak (the withdrawals root) is about 75% of the constraints. With `cloister-dev-2` (two-block leaves) it is 2,147,554 constraints, a 9 s proof and a 3.5 min setup. The proving key is 1.3 GB and the VK is 1,356 bytes raw.

Circuit v2 adds about 2% to the v1 shape (1,489,877 constraints under the same 3-move test config) for the party rules, the time window, the in-circuit transaction records and the log leaf; the fourth move per tx adds more. Its full Groth16 round trip (compile, setup, prove, verify) passes with exactly four public inputs and no commitment key.

Circuit v3 (checked skips, digest, new-account rule) for `cloister-dev-5`: **2,272,862 constraints** (26,730 more than the circuit with the fee-recipient fix), compile 23 s, setup 3 min 54 s, **12.4 GB peak RSS**; four public inputs, no commitment key. Two batches (onboarding and funding; a two-party swap and a time lock) were proved with real Groth16 proofs and verified locally by `scripts/spike/src/multiparty-local.ts` on 22 Nov; they have not been verified by QoreChain.

**On chain (18 Nov):** `cloister-dev-2` settled two circuit v1 batches (onboarding, then two withdrawals), and both withdrawals were paid on L1. See PROOF.md.

A config also fixes `chain_id`, `rollup_id` (both baked into the withdrawal leaves) and the genesis accounts. Every dev rollup therefore gets its own setup and VK. Rollup ids of up to 11 bytes keep each withdrawal leaf to one Keccak block (`cloister` = 8). `cloister-dev-N` needs two blocks, which is slower but correct.

## Batch input

```json
{ "txs": [ {
    "sender": 5, "payer": 0, "relayer": 1, "fee_asset": 0, "fee": 10,
    "parties": [6], "expiry": 99, "not_before": 3, "max_fee": 10,
    "actions": [
      { "kind": "transfer", "to": 6, "asset": 0, "amount": 100, "atomic": true },
      { "kind": "transfer", "from": 6, "to": 5, "asset": 1, "amount": 7, "atomic": true },
      { "kind": "withdraw", "from": 6, "recipient": "qor1…(42 chars)", "amount": 200, "atomic": true },
      { "kind": "register_key", "pk_commit": "<hex, < r>" } ] } ] }
```

`max_fee` (optional, default the fee) is the fee ceiling the payer signed: the fee charged may not exceed it. `new_account: true` marks a transaction signed as `NEW_ACCOUNT`: `sender` is then the index the sequencer assigned, which must be an empty account, and the transaction must register a key. `parties` (optional) are the co-signers; an action's `from` (optional, default the sender) must be the sender or a party; `expiry` (optional, default none) is the last batch index the tx is valid in and `not_before` (optional) the first.

`ledger simulate -dir <setup> -batch batch.json -data <32-byte hex> -out <dir>` executes a batch exactly as `prove` does, checks that the witness satisfies the circuit and writes the same `result.json` and `next-state.json`, with no proving key and no proof (it starts from the genesis state if there is no `state.json`). The watchtower's re-execution and the local end-to-end scripts use it.

## Execution rules (the native builder; the circuit enforces what it applied)

1. A tx whose fee the payer cannot cover is **not included**; the sequencer drops it. Otherwise the sender's nonce increments and the fee moves, even if every action fails.
2. Actions apply in order. A run of consecutive `atomic` actions applies all-or-nothing. A failing non-atomic action is skipped, and the reason is reported for the watchtower. **The circuit checks the skip**: a skipped action is witnessed with its planned terms and a `skip` bit, and the circuit requires that some action of its group could not apply (below).
3. A tx is **not included** (the sequencer drops it and retries the batch) if its `relayer` is not the config's (`relayer:`), its window excludes this batch (`window:`), an action debits an account that is neither the sender nor a party (`auth:`), its parties are not distinct valid accounts (`parties`), its fee is above its `max_fee` (`fee:`), a new account's index is not empty (`a new account`), or it contains terms no valid signer writes (`invalid:`: an unknown asset, a withdrawal in USD or to a malformed address, an empty key).
4. An action **fails**, and is skipped, on exactly these grounds, which the circuit can check: insufficient balance, a credit that would take the receiver past 2^64 - 1, full withdrawal slots, or `register_key` on an account that already has a key. Judged on the balances after the earlier actions of its atomic group.

## What the circuit enforces

- Every leaf read is proven against the current root, and every write produces the next root. Batch 0 starts from the genesis root.
- Each move is at most one of transfer, withdraw or register_key, and all its flags are boolean. Inactive tx slots contain only no-ops.
- **A skipped action must be one that could not apply** (circuit v3, finding F2). Each action carries a `skip` bit and an atomic bit; an atomic group is skipped or applied as a whole; a skipped group must contain an action that fails on one of the four grounds above, evaluated on the balances the group's earlier actions would have left (the circuit tracks those as a tentative balance per move). Only a real action can be skipped, and the fee never is. A sequencer can no longer skip a valid action and keep the fee.
- **The record carries a digest of what was signed** ([inclusion.md](inclusion.md), "Transaction digest"), computed from the planned values of every move (before any skip), the window, the co-signers, the payer, the signed max fee, and the signed sender (the real index, or `NEW_ACCOUNT`). A transaction signed as a new account runs on an empty leaf and registers a key. The fee charged is at most the signed max fee.
- **Every fee is paid to the configured relayer account.** The fee move's recipient is not a witness the prover can choose.
- An applied action debits the **sender or an active party** of its tx; `register_key` is sender-only. The fee move can only be a transfer. Party slots are booleans and are part of the tx record.
- Every included tx satisfies `not_before <= n <= expiry`, where `n` is the batch counter in the log leaf; both bounds are range-checked to 64 bits.
- No account update may touch the reserved log leaf. After all txs, the circuit replaces the log leaf with `{tx_root, n + 1}`, where `tx_root` is the Merkle root of the batch's tx records, computed from the executed moves ([inclusion.md](inclusion.md)).
- Amounts and every written balance are in `[0, 2^64)`. That rules out negative balances and inflation. A credit always equals its debit, so value is conserved per asset.
- Only QOR can be withdrawn. The k-th withdraw of the batch fills withdrawal slot k with the same amount it debited. There are at most 4 withdrawals.
- `withdrawals_root` is the chain's own SHAKE-256 tree over those slots (0 when there are none), reduced mod r.
- A key can only be set on an account with no key, and never to 0.
- `data_hash` is bound but not interpreted: the chain checks it against the post.

Every rule above has a negative test in `circuits/ledger/ledger_test.go`, `multiparty_test.go`, `adversary_test.go` and `skip_test.go`, and each constraint was removed in turn to confirm a test fails without it (`circuits/mutation_check.py`). `fuzz_test.go` also runs random batches through the builder, an independent reference interpreter and the circuit. Some constraints are canonicality or defence in depth (the 64-bit range of `expiry` and `not_before`, the log leaf's shape, boolean party flags): their tests use witnesses that are consistent in every other respect, so only that constraint can reject them.

## Not enforced by the circuit (the watchtower's job)

- ML-DSA signatures by the sender, the parties or the sponsor
- that a tx's recorded window is the window it signed: the circuit enforces the window **in the record** and commits the signed terms in the record's digest. The transaction's holder, or a member watchtower, recomputes the digest and compares it (the `window` check; `check-tx`; and, with `--replay`, re-execution of the whole batch)
- that the executed txs are exactly those in the sealed posts covered by `data_hash`
- withdrawal recipients: they come from the signed tx, and the circuit only fixes them into the leaf
