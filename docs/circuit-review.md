# Circuit review guide (circuit v2)

For the human reviewer (CLAUDE.md requires one before the verifying key is frozen). The circuit is `circuits/ledger/circuit.go` (about 410 lines); the Go reference it is tested against is `native.go`, `witness.go` and `inclusion.go`. Everything below was written by Claude, so treat the claims as things to **check**, not facts. Where a claim was tested, the test is named.

## 0. How to review

```bash
cd circuits
go test ./...                              # all tests, including every negative test (about 15 s)
python3 mutation_check.py                  # removes one constraint at a time; a test must fail each time
CLOISTER_GROTH16=1 go test ./ledger -run Groth16 -v   # compile, setup, prove, verify; about 3 min, several GB
```

Read in this order: the package comment in `circuit.go`, `spec/batch.md`, `spec/state.md`, `spec/inclusion.md`, then `Define` (`circuit.go` from line 211). Then read the tests of any constraint you doubt: a constraint is only as good as the test that fails without it.

## 1. What the circuit claims, and what it does not

**Public statement** (four inputs, as QoreChain requires): `prev_state_root, state_root, data_hash, withdrawals_root`. The proof says: *starting from `prev_state_root` (or the genesis root for batch 0), executing these moves under the rules below gives `state_root`, and `withdrawals_root` is the SHAKE-256 tree over the withdrawals those moves debited.*

**Not proven here** (stated in THREAT_MODEL and LIMITS, checked by the member watchtowers):

| Not proven | Who checks |
|---|---|
| Any ML-DSA signature (sender, party, sponsor) | sequencer, then every member watchtower (`signature` check) |
| That the executed txs are the ones in the sealed post (`data_hash` is only bound, not interpreted) | watchtower (`link`, `count`), the chain checks the hash |
| That the recorded time window is the window the user signed | watchtower (`window` check); also visible in an inclusion proof |
| That a skipped action *had* to be skipped (the circuit accepts a no-op for any action) | not checked yet (needs the watchtower's re-execution, not built) |
| That the tx nonce in the signed tx equals the account nonce | sequencer; the circuit only increments |
| Ordering, inclusion and censorship | watchtower inclusion check (not built); based inbox |
| That the fee goes to the configured relayer (see finding F1) | visible in the record; not enforced |

## 2. The constraints, with the test that makes each one fail

Line numbers are for `circuit.go` at this commit. "Mutation" means the constraint was deleted and the named test failed (`mutation_check.py`). Section 2a records how that was established and what was found along the way.

### Ledger rules (v1, unchanged in meaning)

| # | Constraint | Line | Negative test |
|---|---|---|---|
| L1 | Every leaf read is proven against the running root; every write yields the next root (`applyAt`) | 175–186 | `TestRejectForgedOldLeaf`, `TestRejectWrongStateRoot`, `TestRejectWrongPrevRoot` |
| L2 | Batch 0 starts from the genesis constant when `prev_state_root = 0` | 218 | `TestRejectBatch0NotFromGenesis` |
| L3 | A move is at most one of transfer / withdraw / register; flags are boolean; the tx `Active` flag is boolean | 269–275 | `TestRejectNonBooleanTxActiveFlag`, `TestRejectNonBooleanMoveKindFlag`, `TestRejectNonBooleanAssetFlag`, `TestRejectAMoveWithTwoKinds` (adversarial witnesses; mutation: all caught) |
| L4 | An inactive tx contains only no-ops | 273 | `TestRejectActionsInAnInactiveTxWithAConsistentWitness` (mutation: caught; the earlier test was not isolated) |
| L5 | The fee move (move 0) can only be a transfer | 274–277 | `TestRejectAFeeMoveThatWithdraws`, `TestRejectAFeeMoveThatRegistersAKey` (adversarial witnesses; mutation: both caught) |
| L6 | Only QOR can leave the rollup | 286 | `TestRejectUsdWithdrawal` (mutation: caught) |
| L7 | Amounts and every written balance are in `[0, 2^64)`: no negative balance, no inflation | 288, 297–299, 311–312 | `TestRejectANegativeAmount` (a transfer of `-5` would steal from the receiver), `TestRejectOverdraftWithAConsistentWitness` (qor and usd), `TestRejectCreditOverflow` (qor and usd); mutation: all caught |
| L8 | A key can only be registered on an account with no key, and never as 0 | 294–295 | `TestRejectKeyOverwriteWithAConsistentWitness`, `TestRejectEmptyKey` (mutation: both caught; the earlier overwrite test was not isolated: a prover could have set the key to `new - old` and replaced someone's key) |
| L9 | The k-th withdraw of the batch fills slot k with the amount it debited; at most W withdrawals | 318–322, 353 | `TestRejectTamperedAmount` (the slot filling). "At most W": `TestRejectMoreWithdrawalsThanSlots` (mutation: caught) |
| L10 | `withdrawals_root` is the chain's own SHAKE-256 v2 tree over those slots | 355–402 | `TestWithdrawalVectorsMatchRDK`, `TestRejectWrongWithdrawalsRoot`, `TestRejectChangedRecipient` |
| L11 | `data_hash` squared is a witness, so the proof cannot be re-used with another hash by malleability | 221 | `TestRejectWrongDataHashSquare` |

### Multi-party frames (new)

| # | Constraint | Line | Negative test / mutation |
|---|---|---|---|
| P1 | An applied action debits the sender or an *active* party of its tx | 277–283 | `TestRejectActionFromOtherAccount`, `TestRejectPartyLegWithPartySlotDisabled`, `TestRejectPartyLegByDifferentAccount` |
| P2 | `register_key` is sender-only | 284 | `TestRejectRegisterKeyOnAPartyAccount` |
| P3 | Party flags are boolean | 256 | `TestRejectNonBooleanPartyFlag` (consistent root, so only this constraint can reject it) |
| P4 | The party list is part of the committed record | 262–264 | `TestRejectUnlistedPartyAddedLater`; mutation: caught by every valid-batch test |

### Time window and batch counter (new)

| # | Constraint | Line | Negative test / mutation |
|---|---|---|---|
| W1 | `not_before <= n` for every active tx | 251 | `TestWindowBoundaries` (checks 6 boundary cases both in the builder and in the circuit) |
| W2 | `n <= expiry` for every active tx | 252 | `TestWindowBoundaries` |
| W3 | `expiry` and `not_before` are `< 2^64` | 249–250 | `TestRejectWindowBoundsOver64Bits`, `TestRejectNotBeforeThatWrapsTheField` (witness consistent in every other respect) |
| W4 | `n` is the counter held in the log leaf and increases by exactly one per batch | 232, 345 | `TestBatchCounterAndInclusionProofs`, `TestRejectForgedBatchCounter`; mutation: caught |

### Log leaf and inclusion records (new)

| # | Constraint | Line | Negative test / mutation |
|---|---|---|---|
| G1 | No account update (sender, `From`, `To`) may touch `LOG_INDEX` | 184 | `TestRejectMoveIntoTheLogLeaf`, `TestRejectSenderIsTheLogLeaf` (mutation: caught) |
| G2 | The log update is at `LOG_INDEX` (a fixed constant) | 341 | `TestRejectLogUpdateAtAnotherIndex` (mutation: caught) |
| G3 | The old log leaf has only `pk_commit` and `nonce` set | 342–344 | `TestRejectOldLogLeafThatIsNotLogShaped` (3 cases, mutation: each caught) |
| G4 | `tx_root` is computed in-circuit from the executed moves, parties and window; it is not a free witness | 239–340 | every valid-batch test (the root would mismatch); `TestRejectChangedWindowAfterTheFact` |
| G5 | The withdrawal recipient is bound in the record (`recipient_commit`) | 239–242, 322–327 | `TestEveryWithdrawalCount`, mutation: caught |
| G6 | An inactive slot's record is 0 | 329 | mutation: caught |
| G7 | `tx slots` is a power of two; genesis accounts avoid `LOG_INDEX`; parties in `1..8` | `Config.Validate` | `TestRejectGenesisAtTheReservedIndex` |

One constraint was **removed** because no test could reach it: the 64-bit range of the batch counter `n` (it starts at 0 and only the circuit raises it).

### 2a. Mutation results (20 Nov, all 36 mutations: 36 caught)

`python3 circuits/mutation_check.py` removes one constraint at a time and requires a test to fail. **All 36 are caught**, each by a test whose witness is consistent in every other respect, so only that rule can reject it.

It did not start that way. On 19 Nov, 11 inherited v1 constraints were **not** caught, and two older rules (key overwrite, inactive tx) were found to have tests that passed for the wrong reason. The cause: the Go builder keeps balances as `uint64`, so it cannot build a witness in which a balance wraps around the field, and a witness that is inconsistent anywhere is rejected by the root check before it reaches the rule under test. The fix is `circuits/ledger/adversary_test.go`: an **adversarial witness builder** that replays the circuit's own formulas in field arithmetic over an arbitrary-field-element tree with every check off, which is what a malicious prover would run. Its own correctness is tested by comparison: it produces the same state root as the honest builder for the same batch and the circuit accepts it.

What the tests demonstrate, in attack terms:

| Without this rule | The prover could |
|---|---|
| amount `< 2^64` | send a negative amount (`r - 5`): the sender gains 5 and the receiver loses 5 |
| debited balance stays in range | overdraw an account; its balance wraps to a huge field value |
| credited balance stays in range | push a receiver past `2^64` |
| move flags boolean | use flags `2` and `-1` (sum 1) to credit more than was debited; use asset `2` |
| a move has at most one kind | make one move both a transfer and a withdrawal |
| fee move cannot withdraw | debit the payer with no withdrawal paid: funds vanish |
| fee move cannot register | set a key on any key-less account, not just the sender's |
| at most W withdrawals | debit a withdrawal that no leaf pays |
| key never overwritten | set the move's key to `new - old`, so `old + move = new` replaces someone's key |
| inactive tx has no actions | apply actions without bumping the nonce: a free, replayable action |
| `Active` boolean | scale the nonce bump and the record by 2 |

Some of these constraints are canonicality or defence in depth rather than soundness-critical on their own (the 64-bit range of `expiry`/`not_before`, the old log leaf's shape, boolean party flags); their tests still reject only what that one rule rejects.

## 3. Where I would look hardest (my own suspicions, in order)

**F1. The fee recipient is not fixed in the circuit.** `Move.To` of the fee move is a free witness. A malicious sequencer can send every fee to an account it controls instead of the configured relayer. It is visible in the tx record (an inclusion proof shows `to` of move 0), but the circuit does not stop it. A fix is cheap: make the relayer index a `Config` constant and assert `fee.To.Index == relayer` when the fee move is applied. This changes the circuit, so it must be decided before the freeze. *Recommendation: fix it.*

**F2. Skipped actions are unconstrained.** The circuit lets any action be a no-op. The sequencer can skip a valid action and still take the fee (partial censorship). The record shows it (`applied` is visible as an all-zero move) and an inclusion proof makes it provable to the user, but nothing rejects it. Closing it in-circuit is hard (it needs the "would have applied" condition as a constraint: roughly a balance comparison per move); the practical answer is the watchtower's re-execution, which is not built.

**F3. The window is only as honest as the record.** The circuit proves the record's window contains the batch, but the record's window is a witness. A sequencer can claim `not_before = 0` for a tx that signed `not_before = 100`. The watchtower's `window` check compares against the signed tx; so can the user, with an inclusion proof. This is accountability, not prevention.

**F4. Hash collisions between record leaves and account leaves.** Both are Merkle-Damgard over Poseidon2 with a zero IV and no length padding. A record leaf (32 field elements, first one the tag 1) and an account leaf (5 elements) live in different trees, and the log leaf is the only account-shaped leaf derived from a record-tree root. I believe cross-use is infeasible (it needs a Poseidon2 compression collision), but I have not seen a proof, and Poseidon2's parameters are gnark-crypto's defaults. A reviewer who knows the construction should check this.

**F5. Genesis and treasury trust.** The genesis root is a circuit constant and holds the whole supply in account 0. Onboarding credit is an ordinary transfer, so the treasury's key is a trusted role (THREAT_MODEL). Conservation guarantees total QOR never exceeds the escrow, not that the operator is fair.

**F6. Parties are authorized by a list the sequencer supplies.** The circuit checks `From ∈ {sender, active parties}`. It cannot check that those parties *signed*. A sequencer that forges a party signature (or never checks it) can debit any account by listing it. This is the same trust gap as the sender's signature, now with more accounts exposed per tx. The watchtower's `signature` check covers every party; until a second honest member runs, it is one party's word. *Worth a second watchtower in the demo.*

**F7. Single-party trusted setup.** The Groth16 setup was run by one party (us). Anyone who kept the toxic waste could forge proofs. Testnet only; stated in LIMITS.

**F8. Range checks on witness-supplied indexes.** `ToBinary(u.Index, depth)` bounds every account index to `depth` bits, so an index cannot wrap the field. Party and sender indexes are also bound this way where they are used in a move; an *unused* active party slot may hold any field element (it only appears in the record). I believe that is harmless (the record is just a commitment), but check it.

## 4. What the tests do not cover

- The Go builder and the circuit share my understanding of the rules. The tests check that they agree, not that the rules are the right ones.
- No fuzzing. The adversarial builder gives hand-written attacks (one per rule); a random-batch test comparing the honest builder, the adversarial builder and the circuit would find combinations I did not think of.
- Groth16 soundness itself, and gnark's Poseidon2 and BLS12-381 code, are assumed.
- The on-chain verifier is QoreChain's. We tested that it accepts our proofs (cloister-dev-2, circuit v1) but have not independently audited it. The v2 circuit has **not yet been verified on chain**.
