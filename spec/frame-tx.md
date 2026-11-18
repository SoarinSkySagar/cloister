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

**Decided (18 Nov), implemented in `packages/common/src/frametx.ts`:**
- **Fee:** flat. The fee charged is exactly `max_fee`, which the user chooses. The relayer refuses txs below its minimum. (Rule 5's `min(max_fee, fee_schedule)` therefore simplifies to `max_fee`.)
- **Relayer account:** fixed in the rollup's config (account 1 on `cloister-dev-2`). It receives every fee.
- **New accounts:** `sender = 0xFFFFFFFF`, `nonce = 0`, and the first action is `register_key`. The sender signature is checked against the key in that frame. The sequencer assigns the lowest index above every index in use, in bundle order, so watchtowers can recompute it.
- **Keys:** a Cloister account uses its owner's L1 ML-DSA-87 key (one mnemonic for both layers), so `pk_commit` is derivable from the chain's PQC registry.
- **Circuit v1 limits:** at most 2 ACTION frames, withdraw recipients are 42-character `qor1` addresses, and `expiry_batch` is checked by the sequencer.
- Signature slots are zero-filled to 4627 bytes before signing, so the sighash is known before anyone signs and sender and sponsor sign the same bytes.

## Batch bundle (the sealed post)

A batch's `data_hash` binds a single post. That post is the ML-KEM envelope of a bundle of the **signed** frame txs, in execution order:

```
Bundle := "cloister/bundle/v1" ‖ u64 batch_index ‖ u8 count ‖ lp(FrameTx)[count]
```

Every member (the watchtower) can open it, re-verify every ML-DSA signature and re-execute the batch. On a dedicated rollup only the sequencer may post, so wallets hand their signed tx to the relayer or sequencer. On a based rollup the relayer posts it.

Golden vectors: [`vectors/frame-tx.json`](vectors/frame-tx.json) (encodings and sighashes, deterministic keys).
