# Transaction inclusion proofs (draft v1, circuit v3)

> Circuit v3 (`cloister-dev-5` onwards) adds the transaction **digest** to every record and makes a skipped action prove it could not apply. Proofs of circuit v2 (for example `receipts/inclusion/cloister-dev-3-batch4-swap.json`) are **version 1**: they have no digest and are still checked by the same code.

A user can prove that **their transaction was executed in batch N** without revealing any other transaction in that batch and without access to the sealed data. The proof is checked against the batch's `state_root`, which QoreChain stores and anchors with the ML-DSA-87 signature (the settlement receipt). Design: [design.md §A6b](../design.md), motivated by [EIP-8288](https://eips.ethereum.org/EIPS/eip-8288)'s dependency hash, but a Merkle tree so each item has its own short proof.

The chain stores exactly four public inputs, so the commitment lives **inside `state_root`**: the circuit computes a Merkle root over the batch's transaction records and writes it, with the batch counter, into a reserved leaf of the state tree.

## Constants

| | |
|---|---|
| `LOG_INDEX` | `2^depth - 1` (65,535 for depth 16). **Reserved**: no account may live here, and no account update may touch it |
| `TX_TAG` | `1` |
| `DIGEST_TAG` | `2` |
| `NEW_ACCOUNT_SENDER` | `0xffffffff`: the sender index a signed transaction carries when it creates its own account |
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
rec_fields = [ TX_TAG, digest, sender_index, nonce_before, expiry_batch, not_before_batch,
               party_0, …, party_{P-1},          (each is account_index + 1, or 0 for an unused slot)
               move_0, …, move_{M-1} ]           (9 + 6M elements, plus P-3 if P ≠ 3)
record     = Active ? MD(rec_fields) : 0
```

`digest` is defined below. `nonce_before` is the sender's nonce before this transaction. `Active` is 0 for an unused slot, which holds only no-ops. A skipped action is a zero move, so the record shows **what actually applied**; the digest still commits to what was **written**, and the circuit requires every skip to be justified (below). The party slots list the accounts that co-signed, so the proof shows who authorised the debits. A transaction whose fee could not be paid is not in the batch at all.

## Transaction digest

The digest is a field element that commits to everything the transaction's signers wrote. The circuit computes it from the same witness it executes (the *planned* move values, before any skip), so a record cannot show other terms than the digest says.

```
domain = SHAKE-256/32( "cloister/domain/v1" ‖ u32 len(chain_id) ‖ chain_id ‖ u32 len(rollup_id) ‖ rollup_id ) read mod r      (a circuit constant)

digest = MD( DIGEST_TAG, domain, signed_sender, nonce, expiry, not_before, payer, fee_asset, max_fee,
             party_0 .. party_{P-1},                                   (account_index + 1, or 0 for an unused slot)
             then for each of the M-1 action slots:  code, asset, amount, from, to, aux, atomic )
```

- `signed_sender` is the sender index the signers committed to: the executing sender's index, or `NEW_ACCOUNT_SENDER` when the transaction creates its own account (the record's `sender` then shows the index the sequencer assigned).
- `nonce` is the signed nonce, equal to `nonce_before` of the record. `expiry` and `not_before` are the values the circuit uses; a transaction without an expiry carries `2^53-1` through the prover input (`expiry_batch` beyond that cannot be reached).
- `payer` is the fee payer's index (the fee move's debited account, also when there is no fee). `fee_asset` is 0 when there is no fee. `max_fee` is the fee ceiling the payer signed; the fee charged is that value.
- An action's `code, asset, amount, from, to, aux` are normalised exactly as in a move record (fields that do not apply to the kind are zero; `aux` is the key commitment of a `register_key` or the recipient commitment of a withdrawal). Unused slots are all zero. `atomic` is the action's atomic flag.
- The digest is **not** the signing hash. The signers sign `sighash` ([frame-tx.md](frame-tx.md)); the digest is a second, circuit-friendly commitment to the same content. Whoever holds the signed transaction recomputes the digest with `receipts` `txDigest` (`check-tx` on the CLI) and compares it with the record's. If it matches, the record is that transaction.

Golden vectors: [vectors/digest.json](vectors/digest.json).

## Transaction root, batch counter and log leaf

```
tx_root  = Merkle root over the T records (T = 4, a power of two), node = Compress(left, right), no padding
log_leaf = Account{ pk_commit: tx_root, qor: 0, usd: 0, nonce: n + 1, orders: 0 }   at LOG_INDEX
```

`n` is the batch index: the circuit reads it as the `nonce` of the log leaf before the batch (0 at genesis, where the leaf is empty) and writes `n + 1`. The log leaf is **replaced** by every batch, so batch `n`'s `state_root` commits batch `n`'s `tx_root` and the number `n` itself. A proof for an older batch is checked against that batch's own anchored root.

## Circuit rules added (circuit v2: 1 to 6; circuit v3: 7 to 11)

1. Every state update (sender, move `From`, move `To`) has an index different from `LOG_INDEX`. Without this a prover could move value into or overwrite the log leaf.
2. After all transactions, the log leaf is read from the tree and replaced with `{tx_root, n + 1}`.
3. `tx_root` is computed from the executed moves, parties and window as above; it is not a free witness.
4. Every active transaction satisfies `not_before_batch <= n <= expiry_batch`, with all three values range-checked to 64 bits.
5. An applied move with `any = 1` debits an account that is the sender or an active party. `register_key` is sender-only.
6. `LOG_INDEX` is also excluded from account assignment by the sequencer (`nextFreeIndex` stops below it) and from the genesis accounts.
7. **A skipped action must be one that could not apply.** Every action carries a `skip` bit. Atomic groups (consecutive actions with the atomic flag) are skipped or applied as a whole, and a skipped group must contain an action that fails, judged on the balances the group's earlier actions would have left: a debit above the payer's balance, a credit that takes the receiver past 2^64 - 1, a withdrawal when the batch's slots are full, or a key registration on an account that already has one. Only a real action can be skipped; the fee never is. A sequencer can therefore no longer skip a valid action and keep the fee.
8. **The record carries the digest** and the circuit computes it from the executed witness, so the window, the co-signers, the payer, the max fee and every action's terms (including skipped ones) are bound to what the signers wrote.
9. **New accounts.** `signed_sender` is the executing sender or `NEW_ACCOUNT_SENDER`. A transaction signed as a new account must register a key and runs on an empty leaf (no key, balance, nonce or orders), so a registering user cannot be handed an account that already holds funds.
10. The fee charged is at most the signed `max_fee`.
11. A withdrawal's planned recipient commitment equals the commitment of the withdrawal slot it fills; aux is zero for a transfer. Withdrawals in USD, a malformed recipient, an unknown asset and an empty key are refused outright (the circuit cannot be given them, skipped or not).

## Proof format

```json
{
  "version": 2,
  "chainId": "qorechain-diana", "rollupId": "…", "batchIndex": 3,
  "record": {
    "digest": "<32-byte hex>",
    "sender": 3, "nonceBefore": "1", "expiryBatch": "53", "notBeforeBatch": "0",
    "parties": [5],
    "moves": [ { "code": 1, "asset": 0, "amount": "10000", "from": 0, "to": 1, "aux": "00…00" } ] },
  "txIndex": 0,
  "txPath":  ["<32-byte hex>", …],     // siblings inside the tx tree, leaf level first (log2 T of them)
  "logPath": ["<32-byte hex>", …]      // siblings of the log leaf in the state tree, leaf level first (depth of them)
}
```

Version 1 (circuit v2) proofs have no `digest` and hash `5 + P + 6M` record elements. Field elements are 32-byte big-endian hex and must be canonical (below `r`). `parties` lists account indexes of the active party slots, in slot order.

## Verifying

1. Reject any non-canonical element, unknown version (a version 1 record has no digest; a version 2 record has one), wrong path lengths, `txIndex` out of range, or a record with the wrong shape (`M` moves; an unapplied move must be all zeros; a transfer has `aux = 0`; a withdraw or register has `to = 0`; at most `P` parties).
2. `leaf = MD(rec_fields)`; climb `txPath` using the bits of `txIndex` to get `tx_root`.
3. `log = leaf hash of Account{pk_commit: tx_root, 0, 0, batchIndex + 1, 0}`; climb `logPath` using the bits of `LOG_INDEX` to get `state_root'`.
4. Accept only if `state_root'` equals the `state_root` the **chain** holds for that batch, read from the chain (never from the proof). The receipt for the batch shows that root is anchored with ML-DSA-87. Because `batchIndex` is inside the log leaf, a proof cannot be moved to another batch number.
5. Given the signed transaction, recompute its digest (with the assigned sender index for a new account) and compare it with `record.digest`; also compare `sender`, `nonceBefore` and the parties. Then read the record's moves against the transaction's actions: a zero move at an action's slot means it did not apply, and rule 7 says it could not have.

## What it proves, and what it does not

- **Proves:** the batch's validity proof executed exactly this record, in this slot, as batch `n`, with these applied flags and these listed co-signers, against a state the chain accepted. With the digest it also proves that the terms executed (or provably not applicable) are those of the transaction whose digest matches. Proof size is `log2 T + depth` hashes (about 1 KB).
- **Does not prove** that any ML-DSA signature, the sender's or a party's, was valid. The digest makes that check public: anyone holding the signed transaction can verify the signatures over `sighash` and the digest against the record. Proving the signatures inside the circuit is a separate piece of work. The circuit has never proven signatures; the member watchtowers check them (see [verdict.md](verdict.md)).
- **Discloses** the record to whoever receives the proof: sender, nonce, window, co-signers, fee payer, fee, and the actions. Nothing else in the batch. Selective disclosure of single fields would need each record to be a tree of fields; not done.

Implementations other than Go (the TypeScript and browser verifiers) need Poseidon2 over BLS12-381 with gnark-crypto's default parameters (width 2). They must reproduce every value in the golden vector below before they are trusted.

Golden vector: [vectors/inclusion.json](vectors/inclusion.json), generated by the Go reference (`circuits/ledger/inclusion.go`).
