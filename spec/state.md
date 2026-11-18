# State (draft v0)

## Account leaf

```
leaf(i) = H( pk_commit, bal_QOR, bal_USD, nonce, orders_root )
pk_commit = SHAKE-256/32(ML-DSA-87 public key) reduced mod r   (computed outside the circuit; opaque inside it)
orders_root = 0 in Part A (reserved for Part B's dark pool)
empty leaf = 0
```

- **Tree:** sparse binary Merkle tree, **depth 16** (65,536 accounts), indexed by the account index. Node = `H(left, right)`.
- **`H` (decided 18 Nov): Poseidon2** over the BLS12-381 scalar field, gnark-crypto default parameters (width 2).
  - Node: `node = Compress(left, right)` (one permutation; gnark-crypto `poseidon2.Compressor.CompressField`).
  - Leaf: Merkle-Damgard over the five fields with zero IV: `h = 0; for f in (pk_commit, bal_QOR, bal_USD, nonce, orders_root): h = Compress(h, f)`.
  - **Empty leaf = 0** (an account whose five fields are all 0). Empty subtree roots: `e0 = 0`, `e(i+1) = Compress(e(i), e(i))`.
- **Field:** every value is an element of `F_r` (BLS12-381 scalar field). The state root is therefore always below `r`, as the chain requires.
- **Balances:** `u64`, enforced in the circuit with 64-bit range checks.

## Assets

| id | Asset | Withdrawable to L1 |
|---|---|---|
| 0 | QOR (uqor units) | ✅ via the withdrawals tree |
| 1 | USD (rollup-internal synthetic, 6 decimals) | ❌ (Part B trading asset) |

## Genesis and funding

`defi` rollups have no deposit message (only qledger-v1 does). Instead:
- **Account 0 is the treasury.** At genesis it holds the whole QOR supply (equal to the rollup's escrow after the creation burn) and the whole USD supply. Its `pk_commit` is the operator's key.
- The genesis accounts are part of the circuit config, so the **genesis root is a circuit constant**. Batch 0 has `prev_state_root = 0` on chain, and the circuit then starts from the genesis root.
- Onboarding credit is an ordinary signed transfer from the treasury. The circuit conserves value, so total rollup QOR never exceeds the escrow. Trusting the operator to hand out treasury funds fairly is recorded in THREAT_MODEL.md.
