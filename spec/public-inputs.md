# Groth16 public inputs (draft v0)

The chain verifies each batch's proof against the rollup's stored VK (gnark binary encoding, Groth16 over BLS12-381) with **exactly four public inputs, in this order**:

| # | Input | Derivation |
|---|---|---|
| 0 | `prev_state_root` | State root before the batch (0 for the genesis state). Must be below `r` (except on the first batch) |
| 1 | `state_root` | State root after applying the batch. **Must be below `r`** (always true for our field-element roots) |
| 2 | `data_hash` | Under based sequencing, the inbox range commitment that the chain sets and checks. Under dedicated sequencing, our commitment to the batch's posts. **OPEN:** fix the dedicated-mode definition in the spike |
| 3 | `withdrawals_root` | Root of the chain's SHAKE-256 withdrawals tree (`withdrawalLeafV2`) over this batch's withdrawals. The chain stores and compares it **mod r** |

The chain sends each input as 32-byte big-endian, reduced modulo `r` (`BLS12_381_SCALAR_MODULUS` in `@qorechain/rdk`).

**What the circuit can't bind** (the watchtower covers these):
- the link between ciphertext envelopes (`data_hash`) and the plaintext transactions the circuit executes
- ML-DSA signatures

**OPEN (spike):**
- ~~VK encoding~~ **Answered 17 Nov (simulation):** the chain accepts both raw (`WriteRawTo`) and compressed (`WriteTo`) gnark encodings at creation. We use **raw**.
- What byte layout does `submitBatch.proof` take?
- Is the withdrawals root built in the circuit (SHAKE-256 as Keccak in gnark) or outside it (fallback)? Decide by 25 Nov.
