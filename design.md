# Cloister: Private ZK Rollup with Frame Transactions

Track: Protocol Builders (QoreChain Build Before Q-Day). Deadline: **2 Dec 2026, 23:59 UTC**. Revised 16 Nov.
**Rollup ID: `cloister`** (free on testnet as of 16 Nov; permanent once created). Team: 2 people, with Claude building and the team directing and reviewing.
Companion reference: [docs/qorechain-reference.md](docs/qorechain-reference.md)

**Pitch:** *Cloister is a members-only private sidechain on QoreChain that settles with ZK proofs.*
- Transactions are **frame transactions modelled on EIP-8141**, with ML-DSA-87 signatures natively.
- **Gas sponsorship:** a relayer posts sealed transactions, so users need no L1 QOR, and the L1 never learns who transacted.
- Contents are encrypted with ML-KEM-1024 and enforced by the chain.
- Each batch is signed with ML-DSA-87, finalized by a Groth16 proof and comes with a portable settlement receipt.
- A watchtower guards what validity proofs can't cover.

**Build strategy:** ship the **core rollup** (Part A) first. It meets every track requirement on its own. Add the **DeFi dark pool** (Part B) only if the 26 Nov go/no-go passes.

## Findings from the RDK 0.9.0 source (16 Nov): these override older text below

1. **The VK format is gnark.** `SetVerificationKeyInput.verificationKey` is a "Groth16 BLS12-381 verifying key, gnark binary encoding, four public inputs". **The circuit is written in gnark (Go, Apache-2.0)**, not circom. That also avoids GPL-3.0 code, since circomlib and snarkjs are GPL-3.0 and the repo is MIT.
2. **The VK locks after the first batch.** The creator can set or replace it (`setVerificationKey`) **only before batch 0**. After that, `updateVerificationKeyMsg` is **governance-only** (error 39 `verification_key_locked`). There is no "trivial circuit first, upgrade later" path on one rollup.
3. **Private rollups must be ZK with a Groth16 key** (error 48 hint), so the key is registered at creation (`CreateRollupInput.verificationKey`).
4. **Based rollups can only be paused or stopped by governance.** A dedicated-sequencer rollup can be stopped by its creator, which refunds the stake minus the 1% burn (as long as it holds no deposits and its latest batch isn't pending).
5. **The RDK has the chain's envelope format built in:** `sealEnvelope` / `openEnvelope` / `envelopeMembershipError` / `kemKeypairFromSeed` / `registerKemKeyMsg`. Each envelope needs one entry per member, in the rollup's member order, at the current membership epoch. **Use these for posts**, not raw QoreSeal envelopes.
6. Batch posting uses `postRollupDataMsg`, and the response carries the inbox sequence. `RdkTxClient.submitBatch` produces the `anchorSignature` itself when it signs hybrid.

### Resulting rollup strategy

| Rollup | Settings | Purpose | Lifetime |
|---|---|---|---|
| `cloister-dev-N` | `defi`, zk, private, **dedicated** sequencing | Every test cycle with the current circuit | Stop after each circuit change (refund ≈ 99%, ~100 QOR burned each time), then create the next N |
| **`cloister`** | `defi`, zk, private, based if allowed (otherwise dedicated) | The submitted rollup | Created **once**, with the **frozen final circuit** (Part A, or Part A+B), ideally by 28 Nov |

Budget: 15,000 QOR covers one live rollup at a time (10,000 stake + 1,000 layer) plus about 30 dev-cycle burns.

Because of finding 2:
- **Part B must be in the final circuit** before `cloister` is created. It can't be added later.
- The watchtower's "VK swap" alarm watches **governance** VK updates.

---

# PART A: Core: private ZK rollup with frame transactions

## A1. Requirement coverage

| Requirement | How it's met |
|---|---|
| ML-DSA-signed batches | Every batch carries the creator's ML-DSA-87 `anchor_signature` (anchored in `x/multilayer`). Every user frame tx is ML-DSA-87 signed |
| Withdrawal | `withdraw` frame → SHAKE-256 withdrawals tree committed in the proof → `execute-withdrawal` on L1 |
| Verified settlement receipt | `buildSettlementReceipt` per batch, published, plus a public receipt-verifier page/CLI |
| Watchtower | Member node: proof re-verification, decrypt and re-execute, inclusion check, VK-swap alarm, data availability, liveness |
| ML-KEM data protection | `--privacy encapsulated`. The chain accepts only ML-KEM-1024 envelopes to members |
| Threat model | THREAT_MODEL.md (§A8) |

## A2. Architecture

```
 User wallet                Relayer (sponsor-paid)          QoreChain testnet (qorechain-diana)
 ┌───────────────┐ sealed   ┌──────────────────┐ post-private-data ┌──────────────────────────────┐
 │ build FrameTx │─envelope─▶│ posts envelope,  │──────────────────▶│ x/rdk rollup (defi · zk ·     │
 │ ML-DSA-87 sign│ (ML-KEM  │ pays L1 post fee │                   │  snark · encapsulated)        │
 │ seal (QoreSeal│ to member│ reimbursed in-   │                   │  inbox · members · vk         │
 └───────────────┘  set)    │ rollup by sponsor│                   │  batches · escrow · withdraw  │
        ▲                   └──────────────────┘                   ├──────────────────────────────┤
        │ receipts                                     submit-batch│ x/multilayer anchors (ML-DSA) │
        │                   ┌──────────────────────────┐ +anchor sig│ x/pqc ML-DSA + ML-KEM registry│
        │                   │ Sequencer/Prover (creator,│───────────▶└──────────────────────────────┘
        │                   │ member): decrypt, verify  │                     ▲
        │                   │ sigs, apply frames, build │                     │ REST/RPC reads
        │                   │ wd tree, Groth16 proof    │                     │
        │                   └──────────────────────────┘  ┌──────────────────┴─────────┐
        └──────────────────────────────────────────────────│ Watchtower (member)        │
                         Receipt verifier (public web/CLI) │ + alerts + dashboard       │
                                                           └────────────────────────────┘
 Member set (≤32): sequencer + 1–2 watchtowers. Users are NOT members, so they can't read each other's transactions.
```

| # | Component | Stack | Owner |
|---|---|---|---|
| 1 | Circuit | **gnark** (Go) Groth16 over BLS12-381. The chain wants gnark-encoded VKs | A |
| 2 | Sequencer/prover | TypeScript, `@qorechain/rdk` 0.9.0, `@qorechain/qoreseal` | B |
| 3 | Relayer | TypeScript service. Posts envelopes and earns sponsor fees | B |
| 4 | Wallet/CLI | TypeScript: QoreSign (ML-DSA-87) and QoreSeal | D |
| 5 | Watchtower and dashboard | TypeScript, extending RDK `watchBatches` | C |
| 6 | Receipt verifier | Web page plus CLI using `verifySettlementReceipt` | C |
| 7 | Docs and video | README, THREAT_MODEL, PROOF, LIMITS, AI_USAGE | D |

## A3. Frame transaction format (modelled on EIP-8141)

We take EIP-8141's ideas: an ordered list of frames, VERIFY frames that approve execution or payment, a sponsor as payer, an atomic batch flag, and a signature hash with the signatures removed. We implement them as a **fixed set of frame types**, because the rollup is a ZK circuit, not an EVM. We are **not** claiming EIP-8141 compatibility (it is a draft, type `0x06`).

```
FrameTx {
  version:        u8        = 1
  chain_id:       string    = "qorechain-diana"
  rollup_id:      string
  sender:         AccountId                      // field element, see A4
  nonce:          u64
  expiry_batch:   u64                            // reject if batch_index > expiry_batch
  fee:            { max_fee: u64, asset: QOR|USD }
  frames:         [Frame; 1..=8]
  signatures:     [ { scheme: ML_DSA_87, signer: AccountId, sig: bytes(4627) } ]
}
Frame { mode: u8, flags: u8, kind: u8, params: bytes }
```

| mode | Name | 8141 analogue | Meaning |
|---|---|---|---|
| 1 | VERIFY_SENDER | VERIFY + APPROVE(EXECUTION) | Sender's signature authorizes the action frames |
| 2 | VERIFY_PAYER | VERIFY + APPROVE(PAYMENT) | A sponsor's signature agrees to pay up to `max_fee` |
| 3 | ACTION | SENDER | Executes as `sender` |

`flags` bit 2 = **atomic**: consecutive atomic frames all apply or none do.

| ACTION `kind` | v1 | Params |
|---|---|---|
| 0x01 transfer | ✅ | `to, asset, amount` |
| 0x02 withdraw | ✅ | `l1_recipient (qor1…), amount` (QOR only) |
| 0x03 register_key | ✅ | ML-DSA-87 public key (binds the account, see A4) |
| 0x10 place_order | reserved for Part B | `side, amount, limit_price, batch_window` |
| 0x11 cancel_order | reserved for Part B | `order_id` |

**Signature hash:**
`SHAKE-256/32( "cloister/frametx/v1" ‖ enc_unsigned(tx) )`. See [spec/frame-tx.md](spec/frame-tx.md); `chain_id` and `rollup_id` are inside the encoding

This binds the chain and rollup (no replay across contexts), and the sender and sponsor sign the same bytes.

**Payer rules:**
- No VERIFY_PAYER frame means the sender pays.
- Otherwise the sponsor pays, and `fee ≤ max_fee` is debited from the sponsor's balance and credited to the **relayer** that posted the envelope (identified by the L1 poster address in the inbox, mapped to a rollup account).

**Size:** about 10 KB with two ML-DSA signatures, so about 0.1 QOR to post at 10 uqor/byte (the post limit is 128 KiB).

## A4. State and circuit

**Account leaf (two assets from day one):**
```
leaf = Poseidon(pk_commit, bal_QOR, bal_USD, nonce, orders_root)   // orders_root = 0 in Part A
pk_commit = SHAKE-256(ML-DSA-87 pubkey) reduced mod r              // computed outside the circuit and treated as opaque inside it
```
- State is a Poseidon sparse Merkle tree of depth 16, so the root is always below r.
- `bal_USD` is a rollup-internal synthetic asset in Part A. It is unused until Part B, but already in the tree, so Part B needs no state migration.

**Circuit public inputs** (the chain's order): `prev_state_root, state_root, data_hash, withdrawals_root`.

**Fixed batch shape** (padded with no-op slots): for example **4 tx slots × up to 3 actions**. Tune this after benchmarking.

**Each tx slot proves:**
- the sender leaf exists, the nonce matches, and the nonce increments
- each action applies, with no negative balance, and value is conserved per asset
- the fee is debited from the payer (the sender or the sponsor leaf) and credited to the relayer leaf
- `withdraw` appends a leaf to the batch's withdrawals list

**Withdrawals root:** the chain's SHAKE-256 tree (v2 leaf binds the chain id; layout from the RDK's `withdrawalLeafV2`), with at most 4 withdrawals per batch (depth 2). **Decided 18 Nov: computed in the circuit** (circuit v1, `circuits/ledger`), so the fallback is not needed.
- **Fallback (decide by 25 Nov):** compute it outside the circuit and record that trust assumption in LIMITS.md.

**`data_hash`:** under based sequencing the chain sets and checks it as the inbox range commitment (over the ciphertexts). The circuit can't link ciphertext to plaintext, because that would mean proving AES-GCM inside the circuit. The **watchtower** enforces that link (A6).

**Not proven in the circuit (stated in the threat model):** ML-DSA signatures. The sequencer verifies them, and every member watchtower re-verifies them after decrypting.

**Deposits:** the docs only describe `MsgDepositToRollup` for qledger-v1.
- If `defi` rollups have no deposit path (check in the spike), v1 credits accounts at onboarding from the creator's escrow, which the threat model records as trusted.
- Withdrawals are paid from escrow (stake minus the 1% burn).

## A5. Settlement flow per batch

1. The sequencer takes inbox entries up to a cutoff (`inbox_end`), decrypts them and verifies the ML-DSA signatures. Invalid transactions become no-ops, and the reason is logged for the watchtower.
2. Apply the frames, build the withdrawals tree and generate the Groth16 proof.
3. `submit-batch` with `inbox_end` and `anchor_signature` (creator ML-DSA-87). The chain verifies the Groth16 proof, finalizes the batch and anchors it in `x/multilayer`.
4. `buildSettlementReceipt` and publish it (repo `receipts/`, plus the dashboard).
5. Users `execute-withdrawal` with their SHAKE proof and are paid from escrow.

## A6. Watchtower

| Check | Why |
|---|---|
| **Inclusion:** decrypt every envelope in `[inbox_start, inbox_end)` and confirm each valid tx was applied, in order | The circuit can't prove this, so the watchtower closes the censorship and reordering gap |
| **Signatures:** re-verify every ML-DSA sender and sponsor signature | Closes the circuit's auth gap |
| **Re-execute:** recompute `state_root` and `withdrawals_root` | Independent check of the operator |
| **Proof:** re-verify Groth16 against the stored VK | Doesn't trust the operator's claim |
| **VK-swap alarm:** watch governance `MsgUpdateVerificationKey` proposals and the rollup's stored VK | A new VK means new rules (only governance can change it after batch 0). Members can exit first |
| **Membership:** watch `set-members` and epoch changes | Detects reader-set changes |
| **Data availability:** every envelope in range opens for members | Detects withholding or garbage |
| **Liveness:** alert if the inbox head grows unbatched for more than N blocks | Detects stalls |
| **Receipt:** run `verifySettlementReceipt` on every batch | Settlement is verifiably anchored |

