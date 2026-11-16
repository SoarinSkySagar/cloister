# State (draft v0)

## Account leaf

```
leaf(i) = H( pk_commit, bal_QOR, bal_USD, nonce, orders_root )
pk_commit = SHAKE-256/32(ML-DSA-87 public key) reduced mod r   (computed outside the circuit; opaque inside it)
orders_root = 0 in Part A (reserved for Part B's dark pool)
empty leaf = 0
```

- **Tree:** sparse binary Merkle tree, **depth 16** (65,536 accounts), indexed by the account index. Node = `H(left, right)`.
- **`H`:** a ZK-friendly hash over the BLS12-381 scalar field, from gnark's standard library. **OPEN:** MiMC vs Poseidon2, chosen by BLS12-381 support in gnark and by constraint count. Fix it in the spike and record the choice here.
- **Field:** every value is an element of `F_r` (BLS12-381 scalar field). The state root is therefore always below `r`, as the chain requires.
- **Balances:** `u64`, enforced in the circuit with 64-bit range checks.

## Assets

| id | Asset | Withdrawable to L1 |
|---|---|---|
| 0 | QOR (uqor units) | ✅ via the withdrawals tree |
| 1 | USD (rollup-internal synthetic, 6 decimals) | ❌ (Part B trading asset) |

## Funding

**OPEN:** `defi` rollups appear to have no deposit message (only qledger-v1 does), so the spike will confirm. Until then, accounts are credited at onboarding from the creator's escrow (a trusted operator action, recorded in THREAT_MODEL.md).
