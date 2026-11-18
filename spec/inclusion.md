# Transaction inclusion proofs (draft v0)

A user can prove that **their transaction was executed in batch N** without revealing any other transaction in that batch and without access to the sealed data. The proof is checked against the batch's `state_root`, which QoreChain stores and anchors with the ML-DSA-87 signature (the settlement receipt). Design: [design.md §A6b](../design.md), motivated by [EIP-8288](https://eips.ethereum.org/EIPS/eip-8288)'s dependency hash, but a Merkle tree so each item has its own short proof.

The chain stores exactly four public inputs, so the commitment lives **inside `state_root`**: the circuit computes a Merkle root over the batch's transaction records and writes it, with the batch counter, into a reserved leaf of the state tree.

## Constants

| | |
|---|---|
| `LOG_INDEX` | `2^depth - 1` (65,535 for depth 16). **Reserved**: no account may live here, and no account update may touch it |
| `TX_TAG` | `1` |
| `P` | parties per transaction (`MAX_PARTIES`), 3 |
| `M` | moves per transaction: move 0 is the fee, moves 1.. are actions (4 in the current circuit) |
| Move codes | `0` none, `1` transfer, `2` withdraw, `3` register_key |
| `H` | Poseidon2, as in [state.md](state.md): `Compress(l, r)` for nodes, Merkle-Damgard with zero IV for vectors |

## Move record

Each of a transaction's `M` moves becomes six field elements, computed from the same witness values the circuit executes. An unapplied move is all zeros.

```
val = IsTransfer + IsWithdraw ; any = val + IsRegister
code = IsTransfer + 2·IsWithdraw + 3·IsRegister
asset  = Asset  · val
amount = Amount · val
from   = From.Index · any          (for register_key: the account getting the key)
to     = To.Index · IsTransfer
aux    = PkCommit · IsRegister + recipient_commit · IsWithdraw
```

`recipient_commit` (withdrawals only) binds the L1 recipient: `Compress(pack(r[0..21]), pack(r[21..42]))`, where `r` is the 42-byte `qor1…` address and `pack` reads 21 bytes as a big-endian integer (below 2^168).

## Transaction record

```
rec_fields = [ TX_TAG, sender_index, nonce_before, expiry_batch, not_before_batch,
               party_0, …, party_{P-1},          (each is account_index + 1, or 0 for an unused slot)
               move_0, …, move_{M-1} ]           (8 + 6M elements, plus P-3 if P ≠ 3)
record     = Active ? MD(rec_fields) : 0
```

`nonce_before` is the sender's nonce before this transaction. `Active` is 0 for an unused slot, which holds only no-ops. A skipped action (for example `insufficient balance`) is a no-op move, so a record shows **what actually applied**, not just what was submitted. The party slots list the accounts that co-signed, so the proof shows who authorised the debits. A transaction whose fee could not be paid is not in the batch at all.

## Transaction root, batch counter and log leaf

```
tx_root  = Merkle root over the T records (T = 4, a power of two), node = Compress(left, right), no padding
log_leaf = Account{ pk_commit: tx_root, qor: 0, usd: 0, nonce: n + 1, orders: 0 }   at LOG_INDEX
```

`n` is the batch index: the circuit reads it as the `nonce` of the log leaf before the batch (0 at genesis, where the leaf is empty) and writes `n + 1`. The log leaf is **replaced** by every batch, so batch `n`'s `state_root` commits batch `n`'s `tx_root` and the number `n` itself. A proof for an older batch is checked against that batch's own anchored root.

## Circuit rules added

1. Every state update (sender, move `From`, move `To`) has an index different from `LOG_INDEX`. Without this a prover could move value into or overwrite the log leaf.
2. After all transactions, the log leaf is read from the tree and replaced with `{tx_root, n + 1}`.
3. `tx_root` is computed from the executed moves, parties and window as above; it is not a free witness.
4. Every active transaction satisfies `not_before_batch <= n <= expiry_batch`, with all three values range-checked to 64 bits.
5. An applied move with `any = 1` debits an account that is the sender or an active party. `register_key` is sender-only.
6. `LOG_INDEX` is also excluded from account assignment by the sequencer (`nextFreeIndex` stops below it) and from the genesis accounts.

## Proof format

```json
{
  "version": 1,
  "chainId": "qorechain-diana", "rollupId": "…", "batchIndex": 3,
  "record": {
    "sender": 3, "nonceBefore": "1", "expiryBatch": "53", "notBeforeBatch": "0",
    "parties": [5],
    "moves": [ { "code": 1, "asset": 0, "amount": "10000", "from": 0, "to": 1, "aux": "00…00" } ] },
  "txIndex": 0,
  "txPath":  ["<32-byte hex>", …],     // siblings inside the tx tree, leaf level first (log2 T of them)
  "logPath": ["<32-byte hex>", …]      // siblings of the log leaf in the state tree, leaf level first (depth of them)
}
```

Field elements are 32-byte big-endian hex and must be canonical (below `r`). `parties` lists account indexes of the active party slots, in slot order.

## Verifying

1. Reject any non-canonical element, unknown version, wrong path lengths, `txIndex` out of range, or a record with the wrong shape (`M` moves; an unapplied move must be all zeros; a transfer has `aux = 0`; a withdraw or register has `to = 0`; at most `P` parties).
2. `leaf = MD(rec_fields)`; climb `txPath` using the bits of `txIndex` to get `tx_root`.
3. `log = leaf hash of Account{pk_commit: tx_root, 0, 0, batchIndex + 1, 0}`; climb `logPath` using the bits of `LOG_INDEX` to get `state_root'`.
4. Accept only if `state_root'` equals the `state_root` the **chain** holds for that batch, read from the chain (never from the proof). The receipt for the batch shows that root is anchored with ML-DSA-87. Because `batchIndex` is inside the log leaf, a proof cannot be moved to another batch number.
5. Optionally, given the signed transaction, recompute `record` from it with its assigned indexes and applied flags and compare.

## What it proves, and what it does not

- **Proves:** the batch's validity proof executed exactly this record, in this slot, as batch `n`, with these applied flags and these listed co-signers, against a state the chain accepted. Proof size is `log2 T + depth` hashes (about 1 KB).
- **Does not prove** that any ML-DSA signature, the sender's or a party's, was valid. The circuit has never proven signatures; the member watchtowers check them (see [verdict.md](verdict.md)).
- **Discloses** the record to whoever receives the proof: sender, nonce, window, co-signers, fee payer, fee, and the actions. Nothing else in the batch. Selective disclosure of single fields would need each record to be a tree of fields; not done.

Implementations other than Go (the TypeScript and browser verifiers) need Poseidon2 over BLS12-381 with gnark-crypto's default parameters (width 2). They must reproduce every value in the golden vector below before they are trusted.

Golden vector: [vectors/inclusion.json](vectors/inclusion.json), generated by the Go reference (`circuits/ledger/inclusion.go`).
