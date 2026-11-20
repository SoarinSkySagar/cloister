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

**Proven on chain** (a Groth16 proof QoreChain verified; v2 first verified 19 Nov, see PROOF.md): every state change is a valid move on the committed tree; balances stay in `[0, 2^64)`; value is conserved per asset except withdrawals; only QOR leaves, and each withdrawal leaf the chain pays is backed by a debit of the same amount; nonces move once per included tx; a key is only set on a key-less account; **an applied action debits only the sender or a listed co-signer**; **every included tx is inside its time window** against an in-state batch counter; **the batch's transaction records, with co-signers and window, are committed in `state_root`**.

**Not proven** (checked off-circuit, so detected rather than prevented): ML-DSA signatures of the sender, co-signers and sponsor; that executed transactions are those in the sealed post; that a recorded window equals the signed one; that a skipped action had to be skipped; ordering and censorship.

## 5. Threats and mitigations

| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | **Q-Day**: a classical key is broken | Rollup transactions are ML-DSA-87 only; every L1 transaction is hybrid (secp256k1 + ML-DSA-87); data sealed with ML-KEM-1024 | Hash-based or classical parts of the L1 are QoreChain's |
| T2 | **Forged transaction** (the circuit does not verify ML-DSA) | Sequencer checks every signature; every member watchtower re-checks them after decrypting (`signature` check) and signs a verdict | Detected, not prevented on chain. Single honest-member assumption |
| T3 | **Forged co-signer**: a sequencer lists an account as a party without its signature and debits it | Watchtower verifies **every** party signature; the party list is committed in the record, so an inclusion proof shows who was named; a party only loses what the signed actions say | A malicious sequencer with no honest watchtower can debit any listed account. Same trust as T2, with more accounts exposed per tx |
| T4 | **Co-signer griefing**: a party signs a transaction that debits it unexpectedly | The signature covers the whole transaction, every leg and amount; atomic legs apply all-or-nothing; only the sender's nonce moves, so the tx runs at most once | A party who signs a bad deal has signed it |
| T5 | **Fee redirected** to an account the sequencer controls | The relayer account is a constant of the circuit and every fee must pay it (negative test, mutation-checked); the record also shows the recipient | — (fixed 20 Nov, finding F1) |
| T6 | **Censorship of an action**: sequencer skips a valid action and still charges the fee | The record shows skipped actions; the user can prove it with an inclusion proof | Detectable by the user, not rejected by the circuit (F2). Watchtower re-execution not built |
| T7 | **Wider window than signed**: sequencer claims `not_before = 0` for a tx that signed 100 | Watchtower `window` check against the signed tx (tested); the user can compare their signed tx with their inclusion proof | Accountability, not prevention (F3) |
| T8 | **Sequencer censors or reorders** | Member watchtower; based inbox if the final rollup is based; users can prove what was included | Single sequencer. Dedicated rollups let only the sequencer post |
| T9 | **Relayer drops or snoops** | Relayer sees only a transaction a user chose to send it; it cannot sign; refuses malformed, oversized, under-fee and rate-limited txs | A dropping relayer is an availability problem; use another or post via the sequencer |
| T10 | **Sponsor drained** by spam | `max_fee` is signed; the fee is flat; the relayer enforces a fee floor and a rate limit; the sponsor signs every tx it pays for | A sponsor pays for txs that fail their actions (the fee is still charged); cap exposure with `max_fee` |
| T11 | **Replay** | Nonce increments once per included tx; expiry and `not_before` in the signed tx; chain id and rollup id are in the signature hash | — |
| T12 | **Time-lock bypass** | Circuit enforces `not_before <= n <= expiry` against the batch counter (negative tests, boundary tests); the sequencer holds an early tx | The record's window is a witness (T7) |
| T13 | **Verifying-key change** | The key locks after batch 0; only governance can change it; the committed key is in `circuits/setup/<id>` | Governance trust. Watchtower alarm for key updates: **not built** |
| T14 | **Data withholding** | Watchtower opens every envelope in range; members only | Members only |
| T15 | **Escrow-backed balances** (no deposit path on `defi` rollups) | Account 0 holds the escrow at genesis; value is conserved, so total QOR never exceeds the escrow | Operator-credited onboarding: trust the treasury key (F5) |
| T16 | **Disclosure through proofs** | An inclusion proof reveals one record (sender, co-signers, window, fee payer, actions) and nothing else in the batch; the sequencer only serves it to accounts the record names (sender, co-signers, fee payer) via a signed query | Whoever receives a proof sees that record. Single-field disclosure is not supported |
| T17 | **Metadata leakage** | Contents are sealed; the relayer hides who posted | Sizes, timing, member list, batch roots and withdrawals are public on L1 |
| T18 | **Colluding members sign a false verdict** | A verdict is an off-chain signature by a current member whose key is read from the chain; a false `pass` is attributable | Accountability, not certainty; at least one honest member is assumed. No staking or slashing |
| T19 | **Removed member keeps old data** | New membership epoch on every change | Past data stays readable to them |
| T20 | **Trusted setup** | We ran the setup ourselves | **Single-party setup**: the holder of the toxic waste could forge proofs. Testnet only |
| T21 | **Reserved-leaf abuse**: moving value into or overwriting the log leaf | Circuit forbids any account update at the reserved index; checked old-leaf shape (negative tests, each constraint mutation-tested) | — |
| T22 | **Proof moved to another batch** | The batch number is inside the log leaf the proof hashes to (negative test) | — |

## 6. Review status

- Every circuit rule has a negative test, and each of the 37 constraints was removed in turn to confirm a test fails without it (`circuits/mutation_check.py`: **37 of 37 caught**). The older v1 rules did not pass this at first (11 were not isolated); an adversarial witness builder (`circuits/ledger/adversary_test.go`, field arithmetic with every check off) was written to test them properly, and two of those rules (key overwrite, inactive tx) now have tests that demonstrate the attack they prevent. One unreachable v2 constraint was removed.
- A full Groth16 round trip passes (compile, setup, prove, verify; four public inputs, no commitment key), and the v2 circuit's proofs were verified by QoreChain on `cloister-dev-3` (batches 0 to 6).
- Not yet done: a human review of the constraints, fuzzing (random batches through the honest builder, the adversarial builder and the circuit), and an independent look at the Poseidon2 leaf construction (finding F4).
