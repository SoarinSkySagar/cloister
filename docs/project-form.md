# Project form: build.qorechain.io/projects/new

Copy-paste values for the project page. Fields and limits were read from the live form on 16 Nov 2026. **Update "How it's made", kits, features and addresses as the build progresses.** The jury reads the final version, and kits and features are checked against the repo and the chain.

To create the project you need: **name, tagline, category, description and plan**. Everything else can be added before **2 Dec 23:59 UTC**.

---

## The project

**Name** (required, max 60)
```
Cloister
```

**Tagline** (required, max 120; this one is 111)
```
Members-only private ZK rollup on QoreChain: sealed frame transactions, sponsored gas, post-quantum settlement.
```

**Category** (required): `Protocol Builders`

**Description** (max 5000)
```
Cloister is a private rollup on QoreChain. Think of it as a members-only sidechain that settles every batch with a zero-knowledge proof.

You sign a transaction with ML-DSA-87 and seal it with ML-KEM-1024 to the rollup's members, which are the sequencer and a couple of independent watchtowers. QoreChain checks that every post is a proper envelope for those members, so everyone else (the public, the L1 mempool, other users) only ever sees ciphertext.

We borrowed the shape of our transactions from EIP-8141 frame transactions. Each one has a verify frame for the sender, an optional verify frame for a sponsor, and then the actions themselves: transfer, withdraw or register a key. Actions can be marked atomic so they all go through or none do. If a sponsor signs, they pay the fee, and a relayer posts the sealed transaction and gets paid back inside the rollup. So you can use Cloister without holding any QOR on L1, and L1 never sees who sent what.

Every batch is proven with Groth16 over BLS12-381, signed with the creator's ML-DSA-87 key and anchored on QoreChain. Each batch also gets a settlement receipt that anyone can check against live chain state. Withdrawals are part of the proof, so once a batch is final you can claim your QOR on L1 right away. No challenge window to wait out.

A proof can't catch everything, so we also run a watchtower. It decrypts every post as a member, checks every signature, makes sure nothing was dropped or reordered, re-runs the batch, re-checks the proof, and raises an alert if data goes missing, batches stall or the verification key changes.

How we cover the Protocol Builders requirements:
- ML-DSA-signed batches: every batch carries an ML-DSA-87 anchor signature, and every user transaction is ML-DSA-87 signed
- Withdrawal: a SHAKE-256 withdrawals tree bound into the proof, paid out with execute-withdrawal
- Verified settlement receipt: one per batch, checked against chain state, with a public verifier
- Watchtower: a member node doing the checks above
- ML-KEM data protection: ML-KEM-1024 envelopes enforced by the chain in private rollup mode
- Threat model: THREAT_MODEL.md in the repo

If we have time, we'll add a private batch auction (a dark pool) on top, so orders stay sealed until they settle.
```

**How it's made** (max 5000). Starting plan; rewrite it as the project lands.
```
This is our plan right now. We'll keep updating it as things land.

What we're using
- The circuit is written in gnark (Go), Groth16 over BLS12-381. QoreChain stores the rollup's verifying key in gnark's format and checks four public inputs: prev_state_root, state_root, data_hash and withdrawals_root.
- The sequencer, relayer, wallet CLI, watchtower and receipt verifier are TypeScript on @qorechain/rdk 0.9.0, plus @qorechain/qoresign for ML-DSA-87, @qorechain/pqc, and the RDK's envelope helpers for ML-KEM-1024.
- Everything runs on the qorechain-diana testnet. The rollup uses the defi profile with zk settlement and private mode (--privacy encapsulated).

State and transactions
- Accounts live in a sparse Merkle tree with a ZK-friendly hash. Each account holds two assets from the start, so adding the dark pool later doesn't mean migrating state.
- The transaction format and signature hash are written down in spec/, and the Go circuit and the TypeScript code test against the same vector files so they can't drift apart.

What's been hard so far
- The verification key locks after a rollup's first batch. So we test on throwaway dev rollups that we stop and get refunded, and we'll create the real rollup once the circuit is final.
- The circuit can't check ML-DSA signatures, and it can't prove that the encrypted posts match the transactions it runs. The watchtower covers both, and we're upfront about it in THREAT_MODEL.md.
- Fitting the chain's SHAKE-256 withdrawals tree into a BLS12-381 circuit.

We're building this AI-natively. The two of us make the decisions and review everything, and Claude Code writes most of the code. AI_USAGE.md has the details.
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
