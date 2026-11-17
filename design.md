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

**Withdrawals root:** the chain's SHAKE-256 tree (v2 leaf binds the chain id; layout from the RDK's `withdrawalLeafV2`), with at most 4 withdrawals per batch (depth 2).
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

**Alerts:** console, a webhook (Discord/Telegram), and dashboard badges.

## A7. Days 1–2 spike: go or no-go (17–18 Nov)

Record every transaction hash in PROOF.md.

- [x] VK format: **gnark binary encoding** (from the RDK source)
- [x] VK and proof encoding: gnark raw and compressed are both accepted for VKs and proofs; we use raw
- [x] Registered ML-DSA (hybrid, with PoP) and **ML-KEM** keys for the sequencer and watchtower (17 Nov, see PROOF.md)
- [x] Created `cloister-dev-1` (17 Nov): `defi`, private, dedicated, spike gnark VK (raw); layer `cloister-dev-1` registered, escrow 9,900 QOR
- [x] Members [operator, watchtower] set; 3,536-byte envelope posted; chain SHA-256 matches; both members open it, a non-member key is refused
- [x] **Batches 0 and 1 verified on chain** (Groth16/BLS12-381, gnark raw or compressed proof both accepted; a tampered statement is refused), `data_hash` = SHA-256 of the sealed post, ML-DSA-87 anchor, finalized immediately
- [x] Settlement receipt for batch 0: `valid: true`, all six checks pass (`receipts/cloister-dev-1-0.json`)
- [x] Batch 1 committed a 1 QOR withdrawal (v2 SHAKE-256 tree in the proof); `executeWithdrawal` paid the relayer from escrow
- [x] Stopped `cloister-dev-1`: net +10,898.93 QOR refunded (escrow + layer stake, minus the fee), layer decommissioned; receipts still verify after the stop. **The dev-cycle strategy works**
- [x] **Simulated 17 Nov:** `defi` + private + `based` creation is **accepted**, so the final `cloister` rollup can be based
- [ ] Check whether any deposit path exists for `defi` rollups (`depositToRollupMsg` is documented for qledger-v1 only)

**Result (17 Nov UTC): GO.** Every item passed on chain, including stop-and-refund.

**No-go (end of 18 Nov):** if the Groth16 batch or the withdrawal fails, switch to an optimistic `qledger-v1` rollup with frame transactions inside posted data. Receipts become the headline.

## A8. Threat model outline

- **Assets:** balances, transaction contents, sender/sponsor identity, escrow, withdrawal rights
- **Actors:** malicious sequencer, malicious relayer, malicious sponsor, outside observer, quantum adversary, compromised classical key
- **Threats and mitigations:**
  - Q-Day key compromise (ML-DSA everywhere)
  - forged transactions (watchtower signature re-check)
  - sequencer censorship or reordering (inclusion watchtower, based inbox)
  - relayer dropping transactions (users can post themselves under based sequencing)
  - a sponsor drained by spam (the `max_fee` cap and signing each tx)
  - fee replay (nonce, expiry and chain/rollup binding in the signature hash)
  - VK swap (alarm)
  - data withholding
  - escrow-backed balances
  - metadata leakage (sizes, timing and withdrawals are public; the relayer hides the poster identity)
  - removed members keeping old data
  - trusted setup (our own BLS12-381 powers of tau)
  - single sequencer
- **Outsiders vs members:** the rollup acts like a validium to outsiders (they can check validity but can't rebuild state) and gives full data availability to members.

## A9. Schedule

| Dates | Milestone |
|---|---|
| **16–17 Nov** | Register both team members (all four steps). Create the `cloister` repo (Apache-2.0, GitHub App) and the project page. Q-Day Drill signup before **17 Nov 23:59 UTC**, using a fresh account |
| 17–18 Nov | Spike (A7) and go/no-go |
| 19–23 Nov | Circuit v1: 2-asset ledger, transfer, fees. Sequencer/prover loop. Wallet CLI |
| 23–25 Nov | Frame transactions end to end: sponsor frame, relayer, reimbursement |
| 24–26 Nov | Withdrawals (in the circuit or fallback), receipts, verifier page |
| **26 Nov** | **Part B go/no-go** (§B6) |
| 27 Nov | Workshop 4, protocol clinic (16:30 UTC). Ask the open questions |
| 27–29 Nov | Watchtower and dashboard (+ Part B if go). **Freeze the circuit and create the final `cloister` rollup by 28 Nov**, then run the full demo flow on it |
| 30 Nov–1 Dec | THREAT_MODEL, LIMITS, PROOF, README (credit every kit), AI_USAGE, ≤3-min video |
| 2 Dec | Buffer, final testnet run, **submit before 23:59 UTC** |

## A10. Demo video (≤3 min, Part A)

1. A user with **zero L1 QOR** sends a sponsored, sealed frame transaction. The L1 explorer shows only the relayer and ciphertext.
2. The batch is proven and finalized immediately. The ML-DSA anchor is shown on the explorer.
3. The settlement receipt is verified live, with every check green.
4. A withdrawal is executed and the funds arrive on L1.
5. Watchtower: the operator drops a transaction and the inclusion alarm fires. A forged signature is flagged.
6. Threat model in 15 seconds.

---

# PART B: Extension: DeFi dark pool (only if 26 Nov passes)

**Goal:** a private batch auction on the same rollup. Orders stay sealed from the public, the L1 mempool and other traders until settlement, and every fill in a batch clears at one uniform price, which removes most of the gain from front-running.

## B1. What changes vs Part A

| Area | Change |
|---|---|
| Frames | Enable `place_order` (0x10) and `cancel_order` (0x11). Same format, sponsorship and relayer |
| State | Use `orders_root` in the account leaf (a per-account open-orders tree) and lock balances while orders are open |
| Circuit | New clearing logic. **It must be in the final circuit before `cloister` is created**, because the VK locks after batch 0 |
| Assets | QOR vs `USD` (rollup-internal). Only QOR is withdrawable on L1 |
| Watchtower | Adds a clearing re-check and an order-inclusion check |

**State compatibility:** the leaf already has `bal_USD` and `orders_root`, so the upgrade keeps the existing state root. No migration.

## B2. Order and auction rules

- **Order:** `{order_id, side: BUY|SELL, amount, limit_price, batch_window}`. Funds are locked at placement.
- **Batch window:** an auction closes at a fixed inbox checkpoint (every 64 entries, or every N blocks). Orders after the cutoff roll into the next window.
- **Clearing:** take the crossing orders and choose a single price `p*` within the overlap that maximizes matched volume, with a deterministic tie-break such as the midpoint. Fill pro-rata on the constrained side. Unfilled amounts stay open or are refunded, depending on the order flag.
- **Fees:** a protocol fee in the received asset, plus the relayer fee through the sponsor frame as before.

## B3. What the clearing circuit proves

1. Every fill satisfies its limit: buyers pay ≤ their limit and sellers receive ≥ theirs, both at `p*`.
2. All fills in the batch use the same `p*`.
3. Each asset is conserved across all accounts, plus fees.
4. Pro-rata allocation is correct, and no fill exceeds an order's size.
5. Locked funds are released or consumed correctly, and `orders_root` is updated.
6. Volume is maximal: no crossing order pair is left unmatched at `p*`.

Price math uses fixed-point integers, with explicit rounding toward the protocol.

**Batch shape:** for example 8 order slots per batch. Benchmark the constraint count early.

## B4. Who sees what

| Party | Order contents before settlement? |
|---|---|
| Public / L1 mempool / other traders | ❌ ciphertext only (users are not members) |
| Sequencer (matcher) | ✅ (trust assumption, see B5) |
| Watchtowers | ✅ (auditors) |
| After settlement | Net balance changes and withdrawals are public. Orders stay sealed |

## B5. Additions to the threat model

- **Sequencer front-running:**
  - Mitigations: uniform price, fixed cutoffs, a based inbox (orders the sequencer posts are timestamped and attributed on L1), and the watchtower checking for orders posted after it has seen others.
  - Residual: the sequencer still sees order flow.
  - Future work: threshold decryption, or a committee of several sequencers.
- **Withholding orders to move `p*`:** the inclusion watchtower catches it.
- **Spoof orders:** funds lock at placement, and the fee is paid even if the order is cancelled.
- **Price manipulation in thin markets:** a minimum batch volume, and clearing only when both sides are present.
- **The second asset is synthetic:** the production path is fUSD bridged through an EVM escrow (described, not built).

## B6. Go/no-go (26 Nov)

Start Part B only if **all** of these are working on testnet:
- a sponsored frame tx posted by the relayer
- proven and finalized batches with ML-DSA anchors
- a paid withdrawal
- a verified receipt
- the watchtower inclusion check and signature check

Otherwise, polish Part A and put B1–B5 in the README as the design for the next phase.

## B7. Effort and demo

- **Effort:** about 5–8 person-days (clearing circuit, order lifecycle, watchtower additions).
- **Demo addition (about 30 s):**
  1. Two sealed orders are posted, and outsiders see ciphertext only.
  2. The batch clears at one price.
  3. The watchtower re-checks the clearing price and every fill independently.

---

# PART C: Logistics

## C1. Funding: ✅ done (15,000 test QOR on hand)

Budget: 10,000 stake (100 burned) + 1,000 layer + about 100–300 in fees ≈ 3,700 QOR left for withdrawal liquidity and the relayer. **That is enough for only one rollup.** Create `cloister` once, after a dry run (`--generate-only` + simulate, or `qorollup --dry-run`), and keep the Q-Day Drill account separate from the creator account.

## C2. Team roles

| Team size | Roles |
|---|---|
| 4 | **A** circuit · **B** sequencer, prover and relayer · **C** watchtower and receipt verifier · **D** wallet, docs and video |
| 3 | A · B · C, with docs and video shared |
| 2 | A takes A+B · C takes C+D, and Part B is unlikely |

## C3. Open questions for the organisers

1. What VK format does the chain accept? Is there a reference Groth16 circuit with the 4 canonical inputs?
2. Has a ZK batch settled on testnet since v3.2.7/v3.2.8?
3. Can `--privacy encapsulated` be combined with `--sequencing based`?
4. Is there a deposit path for `defi` rollups?
5. What is the exact byte layout of the v2 withdrawal leaf? (Or read the RDK's `withdrawalLeafV2`.)
6. What is the Protocol Builders judging rubric?
