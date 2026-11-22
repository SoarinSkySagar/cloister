# Proving signatures inside the circuit

**The gap.** The circuit proves every state change is a valid move, but not that anyone *authorised* it. ML-DSA-87 signatures (sender, co-signers, sponsor) are checked by the sequencer and re-checked by the member watchtowers (THREAT_MODEL T2, T3). A sequencer that forges a transaction, and has no honest watchtower watching, can move any listed account's funds, and the proof still verifies. This is a trust gap even without a quantum computer.

**The question.** Can the circuit verify the signatures itself? This note answers with numbers, shows what we built, and says what is and is not wired in. Nothing here is on a live rollup.

## 1. ML-DSA-87 inside Groth16: not feasible

ML-DSA-87 is the signature QoreChain uses. Verifying one signature needs (FIPS 204, parameters k = 8, l = 7):

| Part | Work | Keccak permutations |
|---|---|---|
| Hash the public key (2,592 bytes) | SHAKE-256 | about 20 |
| Expand the 8 x 7 matrix A from its seed | 56 polynomials of 256 coefficients by SHAKE-128 rejection sampling, at least 5 blocks each, 6 to be safe against rejection | about 336 |
| The message hash, the challenge hash over `w1` (1,024 bytes), the challenge polynomial | SHAKE-256 | about 12 |
| 24 NTTs of size 256 modulo q = 8,380,417, the matrix-vector product, hints and the norm check | arithmetic | none |

The Keccak count is about **370 permutations per signature**. Our own circuit measures a permutation at roughly 160,000 R1CS constraints (the withdrawals root: 7 to 11 permutations are about 1.1 to 1.8 million of the 1.46 to 2.15 million constraints in `spec/batch.md`). That is **about 60 million constraints for the hashing alone, plus about 3 million for the arithmetic**, per signature. The whole ledger circuit today is 2.25 million constraints and needs 13.2 GB to set up. At 60 million the setup would need hundreds of gigabytes, and a batch holds up to 4 transactions with up to 5 signers each.

This figure is derived from measured gadget costs, not from building an ML-DSA verifier. It is not close enough to the limit for the estimate's error to matter: a factor of 5 either way leaves it infeasible.

QoreChain only accepts a Groth16 proof with four public inputs, so a cheaper proof system (PLONK with lookup-based Keccak, or a STARK with a native Keccak table) is not an option for the settlement proof today (STARK settlement is paused by the chain, see LIMITS.md).

## 2. What is feasible: a hash-based signature the circuit can verify

`circuits/hbs` is a prototype of a signature designed for the circuit: **Winternitz one-time signatures** (w = 16) under a **Merkle tree** (XMSS-style), with **Poseidon2** as the hash. Poseidon2 is what the ledger already uses for its state tree, and costs a few hundred constraints, not 160,000.

| | |
|---|---|
| Verifier cost in the circuit | **216,713 constraints** per signature at tree height 2, **218,233** at height 10 (1,024 signatures per key). Measured: `go test ./circuits/hbs -run ConstraintCount -v` |
| Signature size | 67 field elements plus a path of `height` elements: about 2.5 KB at height 10 (67 + 10 elements of 32 bytes) |
| Assumption | Poseidon2 as a collision-, preimage- and second-preimage-resistant hash. No pairing, no lattice: **sound against a quantum adversary** |
| Public key | the Merkle root, one field element, which fits the account leaf's existing `pk_commit` |

How it fits the ledger:

- **The statefulness problem is already solved by the nonce.** A one-time key must never sign two messages. An account's nonce rises by exactly one per included transaction, inside the circuit. The key used for a transaction is the leaf whose index is the nonce, so the circuit itself guarantees no leaf is reused. (Wallet side: never sign two different transactions with one nonce; a re-sign must be the same digest.)
- **The message is the transaction digest** (`spec/inclusion.md`), a field element the circuit already computes. That is why circuit v3 introduced the digest.
- **Hardness of forgery** is the Winternitz argument, tested: raising any single message digit lowers the checksum, so hashing a signature forward cannot produce a signature on another message (`TestChecksumBlocksForgeryByHashingForward`, `TestChecksumBlocksRaisingASingleDigit`). The circuit rejects a tampered message, key, chain element, checksum chain, leaf index and path element (`TestCircuitRefusesEveryAlteration`), and agrees with the native verifier (`TestCircuitAgreesWithNative`).

### What it would cost to wire in

At about 0.22 million constraints per signature, verifying only each transaction's **sender** in a 4-transaction batch adds about 0.9 million constraints; verifying every co-signer too (up to 4 signers per transaction) adds up to 3.5 million, and the sponsor's signature on each sponsored transaction another 0.9 million. Today's circuit is 2.25 million, and **about 1.8 million of that is the SHAKE-256 withdrawals tree**. Options, none free:

1. **Fewer withdrawal slots** (W = 1 or 2 instead of 4): the tree shrinks, the signatures fit. Fewer withdrawals per batch.
2. **Sender signatures only in the circuit** and co-signers checked by the watchtower: closes forged *senders* (the largest gap) and leaves the co-signer gap.
3. **A second proof system for signatures later**, a hash-based STARK, which makes both the Keccak-heavy withdrawals tree and the signatures cheap and also removes the quantum weakness of the proof itself. This is the real destination; the chain does not accept it yet.

Wiring needs: a circuit change (a key kind, the signature witness per signer, the leaf index tied to the nonce), a TypeScript signer in the wallet (Poseidon2 already exists in `packages/receipts`), key storage and a "key is used up" policy at 2^height transactions, and a new setup. It is a well-defined piece of work, not done.

## 3. What remains true either way

- The proof system (Groth16 over BLS12-381) is not post-quantum. A quantum attacker forges proofs regardless of how signatures are verified. Hash-based in-circuit signatures close the *authorisation* gap; the STARK route closes the *proof* gap.
- ML-DSA-87 stays the L1 signature. A rollup account would hold both: the ML-DSA key (watchtowers, L1) and the hash-based key (the circuit).
- Until something here is wired in, the signature check is the sequencer's and the member watchtowers', as the threat model says.
