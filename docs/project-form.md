# Project form: build.qorechain.io/projects/new

Copy-paste values for the project page. Fields and limits were read from the live form on 16 Nov 2026. **Update "How it's made", kits, features and addresses as the build progresses.** The jury reads the final version, and kits and features are checked against the repo and the chain.

To create the project you need: **name, tagline, category, description and plan**. Everything else can be added before **2 Dec 23:59 UTC**.

---

## The project

**Name** (required, max 60)
```
Cloister
```

**Tagline** (required, max 120; this one is 119)
```
Private ZK rollup for consortium settlement: atomic multi-party swaps, sponsored gas, post-quantum, provable inclusion.
```

**Category** (required): `Protocol Builders`

**Description** (max 5000)
```
Cloister is a private rollup for settlement between parties that know each other: two firms swapping assets, a company paying a batch of suppliers, an escrow that releases on a date. Members see the data. Everyone else sees only ciphertext, a validity proof and a post-quantum signature, and can still check that one specific payment happened.

How it works
- Transactions are frames, modelled on EIP-8141. One signed transaction can carry several parties: the sender, co-signers whose balances its actions may debit, and a sponsor who pays the fee. Each party signs once with ML-DSA-87, however many legs there are. Atomic legs all apply or none does, so a swap needs no escrow contract and no counterparty risk. A time lock holds a transaction until a chosen batch.
- Posts are sealed with ML-KEM-1024 to the member set. QoreChain refuses any post that is not a proper envelope for those members.
- Every batch is proven with Groth16 over BLS12-381, verified by QoreChain, signed with the creator's ML-DSA-87 key and anchored. Withdrawals are part of the proof, so there is no challenge window to wait out.
- Funds are fully reserved. The rollup's supply can never exceed the L1 escrow, and the proof enforces it. The chain has no deposit path for a private ZK rollup, so members are onboarded and funded by the operator and can withdraw to L1 at any time.

What you can check without trusting us
- A settlement receipt per batch, verified against live chain state in a public page and CLI.
- An inclusion proof: about 1 KB that shows one transaction ran in a given batch, committed inside the state root the chain stores. It reveals that transaction and nothing else in the batch. It is inspired by EIP-8288's dependency hash, but built as a Merkle tree so each transaction has its own proof.
- A signed verdict from each member watchtower: what it decrypted and checked, verified against the chain.

Evidence: PROOF.md lists every transaction hash. On a dev rollup, QoreChain verified seven batches of the current circuit, including a two-party atomic swap, a time-locked transaction and an inclusion proof that matches the chain's state root. Altered copies of the proof are refused.

What it does not do (THREAT_MODEL.md and LIMITS.md say more): privacy is from outsiders, not from members. ML-DSA signatures are checked by the watchtowers, not proven in the circuit. There is one member watchtower so far, the trusted setup is single-party, and the circuit is awaiting human review. The final rollup is created after the circuit is frozen.

How we cover the Protocol Builders requirements
- ML-DSA-signed batches: every batch carries an ML-DSA-87 anchor, and every transaction is signed with ML-DSA-87
- Withdrawal: a SHAKE-256 withdrawals tree bound into the proof, paid out with execute-withdrawal
- Verified settlement receipt: one per batch, checked against chain state, with a public verifier
- Watchtower: a member node that checks the hash link, every party's signature and every signed time window, and signs a verdict. Batch re-execution and alerts are planned
- ML-KEM data protection: ML-KEM-1024 envelopes enforced by the chain in private mode
- Threat model: THREAT_MODEL.md in the repo
```

**How it's made** (max 5000). Starting plan; rewrite it as the project lands.
```
What we're using
- The circuit is gnark (Go), Groth16 over BLS12-381. QoreChain stores the verifying key in gnark's format and checks four public inputs: prev_state_root, state_root, data_hash and withdrawals_root.
- The sequencer, relayer, wallet, watchtower, receipt verifier and explorer are TypeScript on @qorechain/rdk 0.9.0, with @qorechain/qoresign for ML-DSA-87, @qorechain/pqc and the RDK's envelope helpers for ML-KEM-1024.
- Everything runs on the qorechain-diana testnet. The rollup uses the defi profile with zk settlement and private mode.

State and transactions
- Accounts live in a Poseidon2 sparse Merkle tree. The circuit runs four transactions per batch, up to three actions and three co-signers each.
- The wire formats are written in spec/ with golden vectors that the Go circuit and the TypeScript code both test against.
- Because QoreChain fixes four public inputs, the proof can't carry extra fields. So the circuit commits each batch's transaction records, the batch counter and the time window inside a reserved leaf of the state tree instead.

What was hard
- The verifying key locks after a rollup's first batch, so we test on throwaway dev rollups that we stop for a refund, and create the real rollup after the circuit is final.
- The circuit can't verify ML-DSA, so the watchtowers do. THREAT_MODEL.md states that limit.
- Mutation testing (removing each constraint to see if a test fails) showed that 11 older constraints had tests that passed for the wrong reason: our honest builder stores balances as 64-bit numbers, so it couldn't build the wrapped-around values a malicious prover would. We wrote an adversarial witness builder that replays the circuit's arithmetic with every check off, and now all 37 constraints are shown necessary, each by an attack it stops.
- The chain refuses deposits into a private ZK rollup (checked by simulation), so funding is operator-onboarded.

We build this AI-natively. The two of us decide and review, and Claude Code writes most of the code. AI_USAGE.md logs it, including the mistakes it made and we caught.
```

**Cover image** (optional): 16:9, at least 1200×675, up to 5 MB, JPG/PNG/WebP. Skip it for now; one is generated from the name.

---

## Links and addresses

| Field | Value | When |
|---|---|---|
| Public GitHub repository | `https://github.com/SoarinSkySagar/cloister` | Now (push first; the repo must be public with an MIT/Apache licence. Already MIT) |
| Video (≤3 min, **required by the deadline**) | YouTube/Vimeo/Loom link | 30 Nov–1 Dec |
| Demo | Receipt verifier or watchtower dashboard URL | When deployed |
| Testnet addresses (up to 5 `qor1…`, one per line) | Creator/sequencer · relayer · watchtower · a sponsor · a user | After the spike creates them |

---

## Kits and SDKs: tick only what the repo actually uses

They check your dependency files and mark matches as **verified**. Today's `package.json` has:

| Kit | Variant | Tick now? |
|---|---|---|
| RDK | TypeScript | ✅ |
| qorechain-pqc | TypeScript | ✅ |
| QoreSign | TypeScript | ✅ |
| QoreSeal | TypeScript | ✅ (installed; tick only if it's still used at submission) |
| RDK | TypeScript (CLI) | Only if we use `qorollup` in scripts |
| MCP + qore CLI | TypeScript (Node.js server) | Only if we add it to the workflow |
| QoreScan | CLI (npm wrapper) | Only if we publish a CBOM for the threat model |

## Network features: tick only what our testnet addresses actually do

They read the chain for your addresses and mark matches as **verified**.

| Feature | Tick? |
|---|---|
| Hybrid ML-DSA-87 transactions | ✅ (every native tx) |
| PQC key registration with proof of possession | ✅ if we register with PoP (planned) |
| QoreSeal and the encryption key registry | ✅ (ML-KEM-1024 key registration for members) |
| RDK rollup | ✅ |
| MCP server or qore CLI | Only if used |
| EVM window, Solidity PQC checks, smart accounts, AMM, fUSD/fETH/fBTC, IBC, Cross-VM, Sidechain/paychain, light node, Sign In With QoreChain, Asset Kit | ❌ not part of Cloister |

---

## Special awards

| Option | Choose |
|---|---|
| **AI-Native** | ✅ Tick it. `AI_USAGE.md` is already in the repo |
| **Quantum Campus** | Only if **both** members are enrolled students (proof is requested from jury-picked candidates) |
| **Regional** | Pick the country your team represents. You may be asked for proof of residence. It only pays out if the project wins no other prize, but there's no downside |

**Q-Day Drill:** it isn't on this form. After creating the project, register the drill account on the project page **before 17 Nov 23:59 UTC**. Use a fresh testnet account, never the creator.
