# Frame transaction (draft v0)

Modelled on EIP-8141 (frames, VERIFY approvals, a sponsor as payer, an atomic flag, and a signature hash with the signatures removed). The rollup is a fixed-function ZK circuit, not an EVM, so frame `kind`s are a closed set. **This format is not EIP-8141-compatible**, and we don't claim it is.

## Encoding

All integers are big-endian. `lp(x)` = `u32 length ‖ x`.

```
FrameTx :=
  u8   version            = 1
  lp   chain_id           ("qorechain-diana")
  lp   rollup_id          ("cloister" / "cloister-dev-N")
  u32  sender             account index (see state.md)
  u64  nonce
  u64  expiry_batch       tx is a no-op if included in a batch with index > expiry_batch
  u8   fee_asset          0 = QOR, 1 = USD
  u64  max_fee
  u8   frame_count        1..=8
  Frame[frame_count]
  u8   sig_count          1..=2
  Sig[sig_count]

Frame :=
  u8   mode               1 VERIFY_SENDER · 2 VERIFY_PAYER · 3 ACTION
  u8   flags              bit 2 (0x04) = atomic
  u8   kind               ACTION kinds below; 0 for VERIFY frames
  lp   params

Sig :=
  u8   scheme             1 = ML-DSA-87
  u32  signer             account index
  lp   signature          4627 bytes for ML-DSA-87
```

**VERIFY frame params:**
- VERIFY_SENDER: empty.
- VERIFY_PAYER: `u32 payer` (account index).

## ACTION kinds

| kind | Name | Params | v1 |
|---|---|---|---|
| 0x01 | transfer | `u32 to ‖ u8 asset ‖ u64 amount` | ✅ |
| 0x02 | withdraw | `lp(l1_recipient as ASCII bech32 "qor1…") ‖ u64 amount` (asset is always QOR) | ✅ |
| 0x03 | register_key | `lp(ML-DSA-87 public key, 2592 bytes)` | ✅ |
| 0x10 | place_order | reserved (Part B) | — |
| 0x11 | cancel_order | reserved (Part B) | — |

## Signature hash

```
sighash = SHAKE-256/32( "cloister/frametx/v1" ‖ enc_unsigned(tx) )
```
`enc_unsigned(tx)` is the encoding above, except each `Sig.signature` is replaced by its `u32` length only, with no bytes. The sender and the sponsor sign the **same** `sighash` with ML-DSA-87 (`@qorechain/qoresign` `pqSign` / `pqVerify`).

## Validity rules (checked by the sequencer and re-checked by the watchtower)

1. `version == 1`, and `chain_id` / `rollup_id` match the rollup.
2. Exactly one VERIFY_SENDER frame, and at most one VERIFY_PAYER frame. Every VERIFY frame comes before the ACTION frames.
3. There's a valid ML-DSA-87 signature by `sender`, and by `payer` if a VERIFY_PAYER frame is present. Keys are taken from the account's registered key.
4. `nonce == account.nonce` of the sender. The nonce increments once per included tx, even if every action fails.
5. Payer = the VERIFY_PAYER account if present, otherwise the sender. The fee charged is `min(max_fee, fee_schedule(tx))` in `fee_asset`, debited from the payer and credited to the **relayer account** (the rollup account mapped to the L1 poster of the envelope).
6. ACTION frames apply in order. Consecutive frames with the atomic flag apply all-or-nothing. A non-atomic failing frame is skipped.

**OPEN:**
- `fee_schedule` (flat per-tx vs per-byte)
- relayer L1-address → account mapping (registered by a `register_key` frame plus a binding message)
- how a fresh account gets its index (proposed: `register_key` with `sender = 0xFFFFFFFF`, and the sequencer assigns the next free index)
