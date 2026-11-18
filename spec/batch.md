# Batch circuit and batch input (draft v1)

Implemented in [`circuits/ledger`](../circuits/ledger). The sequencer (TypeScript) decrypts the posts and verifies ML-DSA signatures, then hands the Go prover a **batch input** as JSON. The prover executes it, builds the witness and proves.

## Shape (v1)

| | Value | Why |
|---|---|---|
| State tree depth | 16 | 65,536 accounts |
| Tx slots per batch | 4 | Padded with inactive slots |
| Moves per tx | 3 | Move 0 is the fee (payer → relayer), moves 1–2 are actions |
| Withdrawal slots | 4 | Withdrawals tree depth 2 |

Measured on 18 Nov: **1,460,727 R1CS constraints for `cloister` (8-byte id), 4 public inputs, no commitment extension. Proving takes 5.4 s and setup takes 2 min, with 9.4 GB peak RAM (during setup).** Keccak (the withdrawals root) is about 75% of the constraints. With `cloister-dev-2` (two-block leaves) it is 2,147,554 constraints, a 9 s proof and a 3.5 min setup. The proving key is 1.3 GB and the VK is 1,356 bytes raw.

**On chain (18 Nov):** `cloister-dev-2` settled two circuit v1 batches (onboarding, then two withdrawals), and both withdrawals were paid on L1. See PROOF.md.

A config also fixes `chain_id`, `rollup_id` (both baked into the withdrawal leaves) and the genesis accounts. Every dev rollup therefore gets its own setup and VK. Rollup ids of up to 11 bytes keep each withdrawal leaf to one Keccak block (`cloister` = 8). `cloister-dev-N` needs two blocks, which is slower but correct.

## Batch input

```json
{ "txs": [ {
    "sender": 5, "payer": 0, "relayer": 1, "fee_asset": 0, "fee": 10,
    "actions": [
      { "kind": "transfer", "to": 6, "asset": 0, "amount": 100, "atomic": true },
      { "kind": "withdraw", "recipient": "qor1…(42 chars)", "amount": 200, "atomic": true },
      { "kind": "register_key", "pk_commit": "<hex, < r>" } ] } ] }
```

## Execution rules (the native builder; the circuit enforces what it applied)

1. A tx whose fee the payer cannot cover is **not included**; the sequencer drops it. Otherwise the sender's nonce increments and the fee moves, even if every action fails.
2. Actions apply in order. A run of consecutive `atomic` actions applies all-or-nothing. A failing non-atomic action is skipped (it becomes a no-op), and the reason is reported for the watchtower.
3. An action fails on: insufficient balance, a non-QOR withdrawal, a recipient that isn't a 42-character `qor1` address, full withdrawal slots, `register_key` on an account that already has a key, or an empty key.

## What the circuit enforces

- Every leaf read is proven against the current root, and every write produces the next root. Batch 0 starts from the genesis root.
- Each move is at most one of transfer, withdraw or register_key, and all its flags are boolean. Inactive tx slots contain only no-ops.
- Action moves debit the **sender**. The fee move can only be a transfer.
- Amounts and every written balance are in `[0, 2^64)`. That rules out negative balances and inflation. A credit always equals its debit, so value is conserved per asset.
- Only QOR can be withdrawn. The k-th withdraw of the batch fills withdrawal slot k with the same amount it debited. There are at most 4 withdrawals.
- `withdrawals_root` is the chain's own SHAKE-256 tree over those slots (0 when there are none), reduced mod r.
- A key can only be set on an account with no key, and never to 0.
- `data_hash` is bound but not interpreted: the chain checks it against the post.

Every rule above has a negative test in `circuits/ledger/ledger_test.go`.

## Not enforced by the circuit (the watchtower's job)

- ML-DSA signatures by the sender or sponsor
- that the executed txs are exactly those in the sealed posts covered by `data_hash`
- withdrawal recipients: they come from the signed tx, and the circuit only fixes them into the leaf
