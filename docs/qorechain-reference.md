# QoreChain "Build Before Q-Day": Protocol Builders Track Reference

Compiled 16 Nov 2026 from build.qorechain.io, docs.qorechain.io and github.com/qorechain.
The organiser says rules, prizes and dates can change until the event ends, so re-check /prizes and /rules before you submit.

---

## 1. The track at a glance

| Item | Value |
|---|---|
| Goal | Build a **rollup or sidechain** with settlement verification, monitoring and confidential data |
| Example projects | Gaming rollup, DeFi rollup, private sidechain, watchtower |
| **Required features** | (1) ML-DSA-signed batches · (2) withdrawal · (3) verified settlement receipt · (4) watchtower · (5) ML-KEM data protection · (6) threat model |
| Prizes | 1st **$3,000** · 2nd **$1,500** (total $4,500, the largest single prize in the event), paid in stablecoin |
| Team size | **2 to 4. Solo entries are not allowed** |
| Judging | Automatic and manual checks, then jury scoring against a category rubric. **The rubric's criteria and weighting are not published.** Finalists may get a change request with 48 h to respond |
| Competition (16 Nov) | **1 project** of 57 is in Protocol Builders: *Wicketgate* ("instant rollup exits with staked watchers", /p/wicketgate) |

You can also win special awards on top of the category prize (see §3).

## 2. Eligibility and submission

**Every team member must:**
- Be 18 or older
- Register individually at build.qorechain.io/register with all four steps done: sign in with GitHub; fill in details (level, solo/team, 18+, accept Terms); connect X; connect the **QoreX wallet on Testnet**. Registration sends a small proof transaction if your PQ key isn't registered yet, which needs about 0.1 test QOR.
- Have one account only. Multiple accounts per person lead to removal.

**Team formation:** invite teammates by GitHub username from My space (/me). They accept from their own My space. "Find a team" mode is also available.

**Submission must include:**
- A public GitHub repo with a **MIT or Apache-2.0** LICENSE file
- A README that **credits every open source library, QoreChain kit and template** you used
- A video of up to **3 minutes** showing it working
- The testnet address(es) used (`qor1…`)
- The kits and network features the code actually uses (declared on the project form)
- Optional: 16:9 cover image (≥1200×675, JPG/PNG/WebP, ≤5 MB). The rules list a "featured image", but /start calls it optional and auto-generates one.
- Install the **QoreChain Build GitHub App** on the repo so commits appear in the live feed
- The project must be **built during the event** (from 4 Nov). Copied projects are disqualified.
- After the deadline the project becomes read-only, except for jury change requests.

**One category per project**, but you can build more than one project.

## 3. Timeline (UTC)

| Date | Event |
|---|---|
| 4 Nov – 2 Dec 23:59 | Building period. **Submission deadline is 2 Dec 23:59** |
| 17 Nov 23:59 | Q-Day Drill registration closes |
| **17 Nov 15:00** | Workshop 2: PQ dApps and AI agents (luma.com/2m9pgcp2) |
| 18 Nov | Q-Day Drill (bot attacks with your leaked ECDSA key) |
| 19 Nov | Drill transaction hash deadline |
| 20 Nov 16:30 | Workshop 3: Encrypted apps, cross-VM (luma.com/tzxebs2b) |
| **27 Nov 16:30** | **Workshop 4: Protocol building and submission clinic** (luma.com/rli48c3m), the one most relevant to this track |
| 3–5 Dec | Automatic and eligibility checks |
| 6–15 Dec | Jury scoring, and People's Choice vote on mainnet |
| 16 Dec | Winners announced at the live demo show |
| 17–22 Dec | Stablecoin payouts (payment details may be requested; sanctioned jurisdictions are blocked) |
| From Jan 2027 | Follow-on grants paid in QOR against milestones (no terms published) |

**Special awards you can stack:**
- **Q-Day Survivor** (5 × $200): register a fresh testnet account with an ML-DSA-87 key, its ECDSA private key, and up to 5 contract addresses on your project page **before 17 Nov 23:59**. Then make one normal tx during the drill on 18 Nov. Never use a key that matters, because it is published afterwards. Your threat model is used as the tiebreaker.
- **Best AI-Native Build** ($500): tick the AI-native box and add `AI_USAGE.md` (workflow, generated work, human contribution).
- **Quantum Campus** ($500): every member is a verified student.
- **People's Choice** ($500/$300/$200): mainnet vote, 3 votes per wallet.
- **Regional** (5 × $200) and **Top-Quality** (7 × $250, score ≥70/100) go only to projects that win no other prize.

## 4. Network and endpoints

| | Testnet (build here) | Mainnet |
|---|---|---|
| Chain ID | `qorechain-diana` | `qorechain-vladi` |
| EVM chain ID | 9800 | 9801 (`0x2649`) |
| Chain version | **v3.2.8** (has the RDK v3.2.8 features) | v3.2.7 |
| CometBFT RPC | https://rpc-testnet.qore.host | https://rpc.qore.host |
| REST / LCD | https://api-testnet.qore.host | https://api.qore.host |
| EVM JSON-RPC | https://evm-testnet.qore.host | – |
| Rollup challenge window (default) | **3,600 s** | 604,800 s |
| Max rollups / sidechain layers | 200 / 64 | 100 / 10 |

- Token: QOR. The base denom is `uqor`, with 1 QOR = 10^6 uqor. The fee floor is **0.1 uqor/gas** (for example, 600k gas needs a 60,000uqor fee).
- Explorer: https://explore.qore.network · Dashboard: https://dashboard.qorechain.io
- **Faucet:** https://dashboard.qorechain.io/faucet gives **100 QOR per 24 h** per account and address (sign-in required), plus 1,000 fUSD, 0.5 fETH and 0.02 fBTC.
- Node manifests (binary, genesis, peers, statesync): https://download.qore.host/testnet/latest.json and /mainnet/latest.json
- Node ports: RPC 26657, P2P 26656, REST 1317, gRPC 9090, EVM 8545/8546 (ws), SVM read-only 8899, Prometheus 26660
- Running your own node: use the **release archive only**. A binary built from public source refuses to join either network. Ship the whole `lib/` folder (`libqorepqc.so`, `libqoresvm.so`, `libwasmvm*.so`). Testnet has no snapshot, so use statesync. Hardware for a pruned RPC node is 4 cores, 16 GB RAM, 500 GB+ NVMe. Keep the clock NTP-synced (the node halts at more than 60 s drift).

### ⚠️ Funding blocker: read this first

| Cost | Amount |
|---|---|
| Rollup stake (`min_stake_for_rollup`) | **10,000 QOR** (1% = 100 QOR burned, the rest escrowed and refunded on stop) |
| Layer registration in `x/multilayer` (needed for anchors and receipts) | **1,000 QOR** |
| Submitter bond (`qledger-v1` rollups) | **1,000 QOR** |
| Challenge bond (`nft`/`custom` presets) | 1,000 QOR |

That totals about **12,000–13,000 test QOR**. The faucet gives 100 QOR per day per person, so a 4-person team over the remaining ~16 days gets about 6,400. **There is no documented hackathon allowance.** Ask in Discord (discord.gg/qorechain) or at team@qorechain.io today for a builder top-up. The other options are a sidechain or paychain layer (1,000 or 100 QOR stake) or a sovereign design.

## 5. Architecture you're building on

- QoreChain is a Cosmos SDK v0.53 L1 with three VMs (EVM, CosmWasm, SVM) and cross-VM calls. Consensus is the QoreChain Consensus Engine, tuned by the PRISM reinforcement-learning layer.
- **PQC from genesis:** ML-DSA-87 (Dilithium-5) signatures and ML-KEM-1024 KEM, both NIST Level 5. SHAKE-256 is the default app hash. Hybrid secp256k1 + ML-DSA-87 signatures are **Required** on the native lane (since v3.1.71). **A classical-only tx is refused.**
- Sizes: ML-DSA-87 pk 2,592 B, sk 4,896 B, sig 4,627 B. ML-KEM-1024 pk 1,568 B, ct 1,568 B, shared secret 32 B.
- Hybrid tx extension: `/qorechain.pqc.v1.PQCHybridSignature`. Sign bytes v2 are `"qorechain-pqc-hybrid-v2" ‖ BE64(len chainID) ‖ chainID ‖ BE32(len B0) ‖ B0 ‖ BE32(len authInfo) ‖ authInfo`.
- Key messages are `MsgRegisterPQCKey(V2)`, `MsgRotatePQCKey`, `MsgMigratePQCKey` and `MsgRegisterKEMKey` (ML-KEM registry, queried at `/qorechain/pqc/v1/kem/{address}`). An optional proof of possession is supported.
- The EVM lane can't carry ML-DSA signatures, so it needs an **EVM authorisation window** (`MsgOpenEVMWindow`, scoped with `--native-only` or `--allowed-targets`).

### Modules that matter for this track

**`x/rdk` (rollups).** Each rollup has a `rollup-id` matching `^[a-z0-9][a-z0-9._-]{2,63}$`, a stake, and a status of `pending`, `active`, `paused` or `stopped`.

| Settlement | Proof | Sequencer | Status |
|---|---|---|---|
| **optimistic** | `fraud` | dedicated/shared | ✅ **Use this.** Proven end to end on testnet on 12 Nov |
| zk | `snark` (Groth16/BLS12-381) | dedicated/shared | Untried live. Needs your own circuit (the template demo can't verify) |
| based | none | based | Via `--sequencing based` on v3.2.8 |
| sovereign | none | self | Roots posted for transparency only |

STARK is **paused** (error 52). Celestia DA is not implemented. Presets: `defi` (zk, EVM), `gaming` (based), `nft` (optimistic), `enterprise` (based, EVM), `custom` (optimistic, EVM).

**v3.2.8 testnet features (RDK 0.9.0):**
- **`qledger-v1` optimistic rollups:** a chain-native account ledger (sparse Merkle tree, SHA-256, ML-DSA-44 account keys). The chain **re-executes batches for fraud proofs**, so it's a real fraud-proof system you don't have to build.
- **Data posting:** `MsgPostRollupData`, ≤128 KiB per post, 10 uqor/byte. It feeds an inbox accumulator.
- **Deposits:** `MsgDepositToRollup` (L1→L2 for qledger-v1).
- **Private rollups:** `--privacy encapsulated`. Accepts only AES-256-GCM envelopes with the key wrapped by **ML-KEM-1024** to up to 32 registered members (`MsgSetRollupMembers`, with an epoch per membership change). Supported on `defi` rollups. **This covers the "ML-KEM data protection" requirement.**
- Submitter bond: an upheld fraud slashes it, with half burned and half paid to the challenger.

**`x/multilayer` (sidechains, paychains, anchors).**
- Sidechain: 3–10 validators, 1,000 QOR stake. Paychain: 500 ms blocks, 100 QOR.
- **`MsgAnchorState`** carries layer_id, layer_height, state_root, validator_set_hash, `pqc_aggregate_signature` (ML-DSA-87 by the layer creator), tx count and compressed proof.
- Anchor interval is 100–1,000 blocks. The anchor challenge period is 24 h (`MsgChallengeAnchor`).
- A rollup batch submitted with `anchor_signature` is anchored here in the same tx. **Without a layer there is no anchor and no settlement receipt.**
- REST: `/qorechain/multilayer/v1/{layers,anchor/{id},anchors/{id},params}`
- Registration message names aren't documented. Read `qorechaind tx multilayer --help` or the qorechain-core source.

## 6. How each requirement maps to the tooling

| Requirement | How to satisfy it | Key APIs / commands |
|---|---|---|
| **ML-DSA-signed batches** | Submit batches with an `anchor_signature`: ML-DSA-87 by the rollup creator over the v2 anchor sign bytes. Every tx is also hybrid-signed | `qorechaind query rdk anchor-sign-bytes <layer> <idx> <root> --chain-id … --tx-count n`; RDK `anchorSignBytesForBatch`; TS client sends `anchor_signature` automatically when hybrid-signing as creator (Python/Go/Rust/Java don't) |
| **Withdrawal** | Commit a `withdrawals_root` (SHAKE-256 tree, v2 leaves bind the chain id) per batch. After finalization anyone can call `MsgExecuteWithdrawal` | `withdrawalsTree`, `assembleWithdrawalProof` (RDK ≥0.7.0; older SHA-256 helpers **never verify**); `qorollup withdraw --file w.json --dry-run`; `tx rdk execute-withdrawal <rollup> <batch> <idx> <recipient> uqor <amt> --proof …`. qledger-v1 pays from the deposit pool |
| **Verified settlement receipt** | Build a portable receipt from the on-chain anchor and verify it against **live chain state** (key read from chain, chain-id bound). A signature-only check reports `valid:false` | `buildSettlementReceipt(rdk, id, idx)`, `verifySettlementReceipt(r, {client})` → `rollupLayerBinding, batchStateRoot, anchorOnChain, creatorAuthority, pqcSignature, chainBinding`; `qorollup receipt <id> <idx> --out r.json`, `qorollup receipt verify` |
| **Watchtower** | Watch batches, validate state roots, auto-challenge fraud, warn before windows close | `watchBatches(rdk, id, {validate, onInvalid, onDeadline})`, `transitionRootValidator`, `fraudProofForBatch`, `tx.challengeBatch`; `qorollup watchtower <id> --canonical` (TypeScript only) |
| **ML-KEM data protection** | Either a private rollup (`--privacy encapsulated`, on-chain enforced envelopes) or QoreSeal envelopes / epoch keys for a private sidechain, with commitments anchored via the RDK | `tx rdk set-members`, `post-private-data`, `decrypt-private-data`; `@qorechain/qoreseal` `seal()/open()`, `MsgRegisterKEMKey` |
| **Threat model** | A written document (THREAT_MODEL.md). Also the Q-Day Drill tiebreaker | Cover: Q-Day key compromise, malicious sequencer, invalid roots, withdrawal double-spend, watchtower liveness, DA withholding, key loss, metadata leakage (QoreSeal hides **payload only**), chain-id replay, trusted-operator assumptions |

### Reference end-to-end flow (proven on testnet, 12 Nov, RDK 0.9.0 TS)

0. Register the PQC key. This is required first, otherwise the first tx fails with pqc code 8.
1. Create an `nft` rollup with `qledger-v1`, based sequencing and a 10,000 QOR stake.
2. Bond the submitter (1,000 QOR).
3. Deposit (3 QOR + 1 QOR).
4. Post a signed transfer and a withdrawal.
5. Submit a 4-entry batch.
6. Fraud test: a wrong-root batch is challenged with a 4,136-byte proof. It is rejected, the bond is half-slashed and the inbox rolls back.
7. The good batch finalizes after 3,600 s.
8. Withdraw 0.3 QOR.

CLI equivalents:
```bash
qorechaind tx rdk create-rollup my-rollup nft 10000000000 --execution-vm qledger-v1 --sequencing based --from k --chain-id qorechain-diana
qorechaind tx rdk bond-submitter my-rollup 1000000000 --from k --chain-id qorechain-diana
qorechaind tx rdk deposit my-rollup <64-hex-account> 1000000 --from k --chain-id qorechain-diana
qorechaind tx rdk submit-batch my-rollup 0 <root> --prev-state-root <hex> --tx-count 4 --inbox-end 4 --data-hash <range_hash> --withdrawals-root <hex> --from k --chain-id qorechain-diana
qorechaind tx rdk challenge-batch my-rollup 1 --proof <hex> --from k --chain-id qorechain-diana
qorechaind tx rdk execute-withdrawal my-rollup 0 <idx> <qor1…> uqor <amt> --proof <s1>,<s2> --from k --chain-id qorechain-diana
# Classical CLI txs: --generate-only > tx.json, then
qorechaind tx pqc cosign tx.json --from k --pqc-key mypqc --chain-id qorechain-diana
```
REST: `https://api-testnet.qore.host/qorechain/rdk/v1/{params,rollups,rollup/<id>,inbox/<id>,posted_data/<id>/<seq>,submitter_bond/<id>/<addr>,batches/<id>,latest_batch/<id>,batch/<id>/<idx>}`

### Caveats in the docs that you need to plan around
- As of the docs, **no layer or anchor existed on either network**, so the receipt path has never been verified against a real anchor. You may be the first. Budget time for debugging.
- **Untested combination:** private (`encapsulated`) rollups are `defi`, which means ZK with a Groth16 VK. qledger-v1 fraud proofs are `nft`/`custom`. You may need **two rollups** (or a QoreSeal-based private data layer on the optimistic rollup) to cover both optimistic + watchtower and ML-KEM.
- The `--vm` label is metadata only. Your rollup execution runs off-chain unless you use qledger-v1.
- Batches finalize strictly in index order, and one stuck batch blocks later withdrawals.
- A rollup with deposits can't be stopped (error 54), so the stake stays locked.
- Pin **RDK 0.9.0**. Older non-TS clients can't send valid txs.
- Watchtower and multi-VM helpers are **TypeScript only**, so TS is the natural language for this track.
- Error codes: 40 batch/block limit · 46 inbox mismatch · 49 bond required · 51 proof doesn't show fraud · 52 STARK paused · 53 bad envelope · 54 has deposits.

## 7. Kits and packages

| Kit | Install | Use |
|---|---|---|
| **RDK 0.9.0** (TS) | `npm i @qorechain/rdk` | Rollup config, lifecycle, batches, receipts, watchtower, withdrawals |
| RDK CLI | `npm i -g @qorechain/rdk-cli` → `qorollup` | keygen, doctor, create, status, watch, withdraw, faucet, advise, receipt, watchtower |
| Rollup scaffold | `npx create-qorechain-rollup my-rollup --template nft-rollup --network testnet --yes` | Templates: defi, gaming, nft, enterprise, custom, multivm |
| RDK other languages | `pip install qorechain-rdk` · `cargo add qorechain-rdk` · `go get github.com/qorechain/qorechain-rdk/packages/go@v0.9.0` · `io.github.qorechain:qorechain-rdk:0.9.0` | Mirrored surface (no watchtower) |
| qorechain-pqc 0.2.3 | `npm i @qorechain/pqc` (also py/rust/go/java) | ML-DSA, ML-KEM, SHAKE-256, hybrid sign-bytes |
| QoreSeal 0.1.0 | Build TS from `packages/ts` (not on npm yet); `cargo add qorechain-qoreseal`; `pip install qorechain-qoreseal` | ML-KEM-1024 envelopes, multi-recipient, epoch keys for private sidechains |
| QoreSign 0.2.0 | `npm i @qorechain/qoresign` | Hybrid key derivation, signing, SIWQ, signing envelopes |
| SDK 0.14.0 | `npm i @qorechain/sdk` | General chain client, `buildHybridTx` |
| PQ light client (research) | `npm i @qorechain/pq-light-client` | ML-DSA checkpoint verifier (simulated only) |
| MCP server / CLI | `npx -y @qorechain/mcp`, `npm i -g @qorechain/qore-cli` | Read-only chain and docs access for AI assistants |
| QoreScan | `npx @qorechain/qorescan scan --network testnet --out cbom.json` | Crypto inventory (CBOM) |

There is **no watchtower kit or sidechain kit** beyond the RDK, and the build-before-qday example repo has **no rollup example**. Original work in these areas stands out.

## 8. Docs and links

- Event: https://build.qorechain.io (/start, /prizes#protocol_builders, /rules, /kits, /projects, /me, /feed)
- Docs: https://docs.qorechain.io. For this track:
  - /rollups/overview, /rollups/deploying-a-rollup, /rollups/settlement-receipts, /rollups/watchtower, /rollups/zk-stark-withdrawals, /rollups/rdk-v328, /rollups/data-availability, /rollups/preset-profiles, /rollups/multi-vm
  - /architecture/rollup-development-kit, /architecture/multilayer-architecture, /architecture/post-quantum-security, /architecture/prism-consensus-engine
  - /developer-guide/running-a-node, /dashboard/faucet, /build-before-qday, /sdk/quickstart, /developer-tools/mcp
- RDK API docs: https://qorechain.github.io/qorechain-rdk
- Whitepapers (https://www.qorechain.io/whitepaper):
  - Technical v4.1 (348 pp): https://www.qorechain.io/whitepaper/QoreChain_Whitepaper_v4.1.pdf
  - Tokenomics v2.2: https://www.qorechain.io/whitepaper/QCTokenomics_v2.2.pdf
  - Community v2.1: https://www.qorechain.io/whitepaper/QC_Community_Whitepaper_v2.1.pdf
- GitHub: https://github.com/qorechain. Key repos: qorechain-rdk, qorechain-core (Go chain source, useful for multilayer messages), qoreseal, qoresign, qorechain-pqc, qorechain-sdk, qorechain-pq-light-client, QORel, build-before-qday, qorechain-docs
- QoreX wallet: https://qorechain.io/qorex
- Community: Discord https://discord.gg/qorechain · Telegram https://t.me/QorechainCommunity · X https://x.com/QoreChain (#BuildBeforeQDay) · team@qorechain.io

## 9. Open questions to ask organisers (Discord / Workshop 4)
1. Can Protocol Builders teams get enough test QOR for the 10k rollup stake, 1k layer and 1k bond?
2. What is the published judging rubric for Protocol Builders?
3. What is the exact multilayer layer-registration message, and is anchoring a rollup batch known to work on testnet?
4. Does the "verified settlement receipt" requirement accept a sidechain `MsgAnchorState` anchor instead of an RDK rollup anchor?
5. Is a private `defi` rollup required for ML-KEM, or is QoreSeal over an optimistic rollup acceptable?
