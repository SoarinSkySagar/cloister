# Hiding data from the members

Cloister's privacy today: **outsiders** see ciphertext, a validity proof and a post-quantum signature, and members see everything. The sequencer and every watchtower decrypt every transaction. The question: can the members be kept from seeing balances and transfers?

**Short answer: not with this proof system, and not cheaply with any other we can use on QoreChain.** This note says why, what each way out would cost, and what we do instead.

## Why the sequencer has to see the data

A Groth16 prover needs the *witness*: every balance read, every amount, every account. Whoever runs the prover sees it. QoreChain settles one Groth16 proof per batch, so one party proves the whole batch and sees it all. The watchtowers see it too because re-executing a batch needs the same data (`--replay`).

## The ways out

| Approach | What it hides | Why it is not available to us |
|---|---|---|
| **Each user proves their own transaction** (client-side proving), the sequencer only aggregates | Balances and amounts from the sequencer | The sequencer would aggregate N Groth16 proofs into one the chain accepts: that is recursion over BLS12-381, not supported by the settlement verifier and far beyond our constraint budget (one in-circuit pairing check is millions of constraints, per proof) |
| **Secret-shared state, threshold proving** (members jointly prove without any one seeing the witness) | Balances from any single member | A multi-party Groth16 prover over a 2.3-million-constraint circuit with secret-shared witnesses: research-grade, not an off-the-shelf tool |
| **Homomorphic encryption of balances** (Zether-style) | Balances from everyone but the owner | Needs lattice-based additively homomorphic encryption with range proofs for post-quantum security; the in-circuit cost is far beyond the signature-verification cost measured in `docs/pq-auth.md` |
| **A trusted execution environment** (SGX-style) | Data from the operator's host | Hardware trust, not post-quantum, and not what this hackathon's security story is about |
| **Separate rollups per counterparty group** | Each group's data from the other groups | **Available now** and cheap: members of one rollup see only that rollup. It costs a stake per rollup (10,000 QOR on testnet) |
| **Need-to-know watchtowers**: only the sequencer sees all, a watchtower is a member only while auditing | Data from watchtowers in between | Possible, but a member's key opens past data forever (THREAT_MODEL T19); membership epochs protect only future posts |

## What we do

- The product is a **consortium settlement rollup**: the counterparties are the members and they see each other's settled transactions. The README says so in its first paragraph, and outsiders are the adversary the design defends against.
- A user's balance and proofs are shown only to the accounts that need them: the sequencer's `/account` and `/proof` answer a signed query from the account itself, and an inclusion proof discloses one record (THREAT_MODEL T16). That limits what a member learns *through the service*, not through the data they can decrypt.
- Per-group rollups remain the honest answer for "A must not see B".

## What would change this

QoreChain accepting a recursion-friendly proof (a STARK settlement mode with real rollup statements, which the chain team says returns "in a later release"), or a client-side proving scheme whose aggregate is cheap to verify. Neither exists today.
