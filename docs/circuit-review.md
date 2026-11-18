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

Line numbers are for `circuit.go` at this commit. "Mutation" means the constraint was deleted and the named test failed (`mutation_check.py`). **Read section 2a before trusting a row**: eleven v1 rules below are marked *not isolated*: their tests do reject a bad witness, but also without the rule, so the test does not show the rule is needed.

### Ledger rules (v1, unchanged in meaning)

| # | Constraint | Line | Negative test |
|---|---|---|---|
| L1 | Every leaf read is proven against the running root; every write yields the next root (`applyAt`) | 175–186 | `TestRejectForgedOldLeaf`, `TestRejectWrongStateRoot`, `TestRejectWrongPrevRoot` |
| L2 | Batch 0 starts from the genesis constant when `prev_state_root = 0` | 218 | `TestRejectBatch0NotFromGenesis` |
| L3 | A move is at most one of transfer / withdraw / register; flags are boolean; the tx `Active` flag is boolean | 269–275 | `TestRejectTwoKindsInOneMove`, `TestRejectNonBooleanFlag`. **Not isolated** (three mutations not caught) |
| L4 | An inactive tx contains only no-ops | 273 | `TestRejectActionsInAnInactiveTxWithAConsistentWitness` (mutation: caught; the earlier test was not isolated) |
| L5 | The fee move (move 0) can only be a transfer | 274–277 | `TestRejectWithdrawInFeeMove`. **Not isolated** (both mutations not caught) |
| L6 | Only QOR can leave the rollup | 286 | `TestRejectUsdWithdrawal` (mutation: caught) |
| L7 | Amounts and every written balance are in `[0, 2^64)`: no negative balance, no inflation | 288, 297–299, 311–312 | `TestRejectOverdraft`, `TestRejectFeeOverdraft`, `TestRejectAmountOver64Bits`. **Not isolated** (five mutations not caught) |
| L8 | A key can only be registered on an account with no key, and never as 0 | 294–295 | `TestRejectKeyOverwriteWithAConsistentWitness`, `TestRejectEmptyKey` (mutation: both caught; the earlier overwrite test was not isolated: a prover could have set the key to `new - old` and replaced someone's key) |
| L9 | The k-th withdraw of the batch fills slot k with the amount it debited; at most W withdrawals | 318–322, 353 | `TestRejectTamperedAmount` (the slot filling). "At most W": `TestRejectTooManyWithdrawals`, **not isolated** |
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

### 2a. Mutation results (19 Nov, all 36 mutations)

`python3 circuits/mutation_check.py` removes one constraint at a time. **25 are caught; 11 are not**, all inherited from circuit v1:

`tx Active is boolean` · `move kind flags are boolean` · `a move has at most one kind` · `fee move cannot withdraw` · `fee move cannot register a key` · `amount is below 2^64` · `debited balance stays non-negative` (qor, usd) · `credited balance cannot overflow` (qor, usd) · `at most W withdrawals`.

**Why:** the Go builder keeps balances and nonces as `uint64`. A real violation of these rules needs the circuit's field arithmetic to *wrap* (a negative balance becomes `r - x`), so a witness consistent in every other respect needs state the builder cannot represent. The existing tests do reject their witnesses, but because the builder's state no longer matches the circuit's, not because of the named rule. Two older tests had the same flaw (key overwrite, inactive tx) and were fixed on 19 Nov with witnesses built to be consistent; these eleven are not fixed yet.

**What this means for you:** the eleven rules are still in the circuit and read as correct, but I have **not shown they are needed**. Please read them line by line. The fix is an adversarial witness builder that does field arithmetic with no checks (what a malicious prover would run); it is the next piece of work.

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

- Eleven v1 constraints have tests that do not isolate them (section 2a).
- The Go builder and the circuit share my understanding of the rules. The tests check that they agree, not that the rules are the right ones.
- `circuits/ledger` has no fuzzing. A random-batch test comparing the builder against the circuit (accept, reject, same state root) would be a useful addition.
- Groth16 soundness itself, and gnark's Poseidon2 and BLS12-381 code, are assumed.
- The on-chain verifier is QoreChain's. We tested that it accepts our proofs (cloister-dev-2, circuit v1) but have not independently audited it. The v2 circuit has **not yet been verified on chain**.
