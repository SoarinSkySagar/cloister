# Cloister threat model

Written 19 Nov 2026 against circuit v2 (`circuits/ledger`), the sequencer, relayer, wallet, watchtower and receipts tools in this repository. Each claim names the test or on-chain evidence behind it; where there is none, it says so. The circuit's constraints have **not yet had a human review** (see [docs/circuit-review.md](docs/circuit-review.md)). Known limits are collected in [LIMITS.md](LIMITS.md).

## 1. System and trust boundaries

| Component | Role | Trusted for |
|---|---|---|
| **QoreChain (L1)** | Verifies the Groth16 proof, stores batches and the verifying key, enforces that private posts are envelopes for the member set, pays withdrawals from escrow, anchors each batch with the creator's ML-DSA-87 signature | Correct verification; honest governance (only governance can change the key after batch 0) |
| **Sequencer / prover** (rollup creator, a member) | Decrypts posts, checks signatures, orders and executes transactions, proves batches, posts and submits them | Ordering and inclusion; honest signature checking (not proven by the circuit) |
| **Relayer** | Public door: validates, rate-limits and forwards signed transactions; paid in-rollup from fees | Availability only; it never holds keys and sees only ciphertext once sealed |
| **Member watchtowers** | Decrypt every batch, re-check structure, hash link, every ML-DSA signature and every signed time window, sign a verdict | At least one honest member |
| **Users** | Sign frame transactions (sender, co-signers, sponsor) with ML-DSA-87 | Their own keys |
| **Verifier (anyone)** | Checks receipts, verdicts and inclusion proofs against live chain state | Nothing: every check re-reads the chain |

Privacy model: **members see everything; outsiders see ciphertext, roots and proofs.** To outsiders Cloister behaves like a validium: they can verify each state transition was valid but cannot rebuild the state. This is a consortium model, not privacy from the sequencer.

## 2. Assets

Balances · transaction contents · who paid and who co-signed · escrow and withdrawal rights · the verifying key · key material (sender, party, sponsor, member ML-KEM keys).

## 3. Adversaries

Malicious sequencer · malicious relayer · malicious sponsor · malicious co-signer / counterparty · outside observer · colluding members · quantum adversary (Q-Day) and holders of leaked classical keys · governance (key change).

## 4. What the circuit proves, and what it does not

**Proven on chain** (a Groth16 proof QoreChain verified; v2 first verified 19 Nov, see PROOF.md): every state change is a valid move on the committed tree; balances stay in `[0, 2^64)`; value is conserved per asset except withdrawals; only QOR leaves, and each withdrawal leaf the chain pays is backed by a debit of the same amount; nonces move once per included tx; a key is only set on a key-less account; **an applied action debits only the sender or a listed co-signer**; **every included tx is inside its time window** against an in-state batch counter; **the batch's transaction records, with co-signers and window, are committed in `state_root`**. Circuit v3 (22 Nov; **verified by QoreChain on `cloister-dev-5`, batches 0 to 7, 23 Nov**) adds: **a skipped action must be one that could not apply** (insufficient balance, a credit past 2^64, full withdrawal slots, a key already set; judged on the group's tentative balances); **each record carries a digest of what the signers wrote** (planned actions including skipped ones, window, co-signers, payer, max fee, signed sender, chain and rollup); **the fee is at most the signed max fee**; **a new account must be an empty leaf and register a key**.

**Not proven** (checked off-circuit, so detected rather than prevented): ML-DSA signatures of the sender, co-signers and sponsor (this is the gap that lets a forged party list or window stand, as far as the circuit goes; the digest makes the lie detectable by anyone holding the signed transaction); that executed transactions are those in the sealed post (the watchtower's `--replay` re-execution checks this); ordering and censorship.

## 5. Threats and mitigations

