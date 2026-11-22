# Circuit review guide (circuit v3)

For the human reviewer (CLAUDE.md requires one before the verifying key is frozen). The circuit is `circuits/ledger/circuit.go` (about 620 lines); the Go reference it is tested against is `native.go`, `witness.go` and `inclusion.go`. Circuit v3 (22 Nov) adds checked skips, the transaction digest and the new-account rule (sections 2b and 3). Everything below was written by Claude, so treat the claims as things to **check**, not facts. Where a claim was tested, the test is named.

## 0. How to review

```bash
cd circuits
go test ./...                              # all tests, including every negative test and the fuzz test (about 1 min)
FUZZ_BATCHES=500 go test ./ledger -run Fuzz -count=1 -timeout 0   # random batches vs a reference interpreter and the circuit
python3 mutation_check.py                  # removes one constraint at a time; a test must fail each time
CLOISTER_GROTH16=1 go test ./ledger -run Groth16 -v   # compile, setup, prove, verify; about 3 min, several GB
```

Read in this order: the package comment in `circuit.go`, `spec/batch.md`, `spec/state.md`, `spec/inclusion.md`, then `Define` (search for `func (c *Circuit) Define`). Line numbers are not given below because they go stale; each rule names the code to search for. Then read the tests of any constraint you doubt: a constraint is only as good as the test that fails without it.

## 1. What the circuit claims, and what it does not

**Public statement** (four inputs, as QoreChain requires): `prev_state_root, state_root, data_hash, withdrawals_root`. The proof says: *starting from `prev_state_root` (or the genesis root for batch 0), executing these moves under the rules below gives `state_root`, and `withdrawals_root` is the SHAKE-256 tree over the withdrawals those moves debited.*

**Not proven here** (stated in THREAT_MODEL and LIMITS, checked by the member watchtowers):

| Not proven | Who checks |
|---|---|
| Any ML-DSA signature (sender, party, sponsor) | sequencer, then every member watchtower (`signature` check) |
| That the executed txs are the ones in the sealed post (`data_hash` is only bound, not interpreted) | watchtower (`link`, `count`), the chain checks the hash |
| That the record's terms (window, co-signers, payer, max fee, every action) are what the signers wrote | the record carries a digest of them (rows D1 to D4); the holder of the signed tx, or a member watchtower, recomputes it: `check-tx`, the `window` check, and `--replay` re-execution |
| (Closed in v3) That a skipped action had to be skipped | the circuit, rows S1 to S10 |
| That the tx nonce in the signed tx equals the account nonce | sequencer; the circuit only increments |
| Ordering, inclusion and censorship | watchtower `--replay` re-execution (a dropped, substituted or reordered tx changes the root); based inbox |

## 2. The constraints, with the test that makes each one fail

Line numbers are for `circuit.go` at this commit. "Mutation" means the constraint was deleted and the named test failed (`mutation_check.py`). Section 2a records how that was established and what was found along the way.

### Ledger rules (v1, unchanged in meaning)

| # | Constraint | Search for | Negative test |
|---|---|---|---|
| L1 | Every leaf read is proven against the running root; every write yields the next root (`applyAt`) | `func (x ctx) applyAt` | `TestRejectForgedOldLeaf`, `TestRejectWrongStateRoot`, `TestRejectWrongPrevRoot` |
| L2 | Batch 0 starts from the genesis constant when `prev_state_root = 0` | `api.IsZero(c.PrevStateRoot)` | `TestRejectBatch0NotFromGenesis` |
| L3 | A move is at most one of transfer / withdraw / register; flags are boolean; the tx `Active` flag is boolean | `AssertIsBoolean(any)`, the flag loop | `TestRejectNonBooleanTxActiveFlag`, `TestRejectNonBooleanMoveKindFlag`, `TestRejectNonBooleanAssetFlag`, `TestRejectAMoveWithTwoKinds` (adversarial witnesses; mutation: all caught) |
| L4 | An inactive tx contains only no-ops | `any, api.Sub(1, tx.Active)` | `TestRejectActionsInAnInactiveTxWithAConsistentWitness` (mutation: caught; the earlier test was not isolated) |
| L5 | The fee move (move 0) can only be a transfer | `if m == 0` (fee move) | `TestRejectAFeeMoveThatWithdraws`, `TestRejectAFeeMoveThatRegistersAKey` (adversarial witnesses; mutation: both caught) |
| L6 | Only QOR can leave the rollup | `mv.IsWithdraw, mv.Asset` | `TestRejectUsdWithdrawal` (mutation: caught) |
| L7 | Amounts and every written balance are in `[0, 2^64)`: no negative balance, no inflation | `x.u64(mv.Amount)`, `x.u64(nf.…)`, `x.u64(nt.…)` | `TestRejectANegativeAmount` (a transfer of `-5` would steal from the receiver), `TestRejectOverdraftWithAConsistentWitness` (qor and usd), `TestRejectCreditOverflow` (qor and usd); mutation: all caught |
| L8 | A key can only be registered on an account with no key, and never as 0 | `eR, f.Pk`, `api.IsZero(mv.PkCommit)` | `TestRejectKeyOverwriteWithAConsistentWitness`, `TestRejectEmptyKey` (mutation: both caught; the earlier overwrite test was not isolated: a prover could have set the key to `new - old` and replaced someone's key) |
| L9 | The k-th withdraw of the batch fills slot k with the amount it debited; at most W withdrawals | `slotAmt[k]`, `prod` | `TestRejectTamperedAmount` (the slot filling). "At most W": `TestRejectMoreWithdrawalsThanSlots` (mutation: caught) |
| L10 | `withdrawals_root` is the chain's own SHAKE-256 v2 tree over those slots | `withdrawalLeafV2` section | `TestWithdrawalVectorsMatchRDK`, `TestRejectWrongWithdrawalsRoot`, `TestRejectChangedRecipient` |
| L11 | `data_hash` squared is a witness, so the proof cannot be re-used with another hash by malleability | `DataHashSq` | `TestRejectWrongDataHashSquare` |

### Multi-party frames (new)

| # | Constraint | Search for | Negative test / mutation |
|---|---|---|---|
| P1 | An applied action debits the sender or an *active* party of its tx | `notAuth` | `TestRejectActionFromOtherAccount`, `TestRejectPartyLegWithPartySlotDisabled`, `TestRejectPartyLegByDifferentAccount` |
| P2 | `register_key` is sender-only | `mv.IsRegister, api.Sub(mv.From.Index, tx.Sender.Index)` | `TestRejectRegisterKeyOnAPartyAccount` |
| P3 | Party flags are boolean | `AssertIsBoolean(tx.PartyActive[i])` | `TestRejectNonBooleanPartyFlag` (consistent root, so only this constraint can reject it) |
| P4 | The party list is part of the committed record | `partyFields` | `TestRejectUnlistedPartyAddedLater`; mutation: caught by every valid-batch test |

### Fee recipient (new, 20 Nov)

| # | Constraint | Search for | Negative test / mutation |
|---|---|---|---|
| R1 | The fee move's recipient is the config's relayer account (a circuit constant) | `api.Sub(mv.To.Index, relayer)` | `TestRejectAFeeThatDoesNotPayTheRelayer` (control: a fee to the relayer is accepted), `TestCheckedBuilderAndConfigRefuseAnotherRelayer`; mutation: caught |

### Time window and batch counter (new)

| # | Constraint | Search for | Negative test / mutation |
|---|---|---|---|
| W1 | `not_before <= n` for every active tx | `api.Sub(n, tx.NotBefore)` | `TestWindowBoundaries` (checks 6 boundary cases both in the builder and in the circuit) |
| W2 | `n <= expiry` for every active tx | `api.Sub(tx.Expiry, n)` | `TestWindowBoundaries` |
| W3 | `expiry` and `not_before` are `< 2^64` | `x.u64(tx.Expiry)`, `x.u64(tx.NotBefore)` | `TestRejectWindowBoundsOver64Bits`, `TestRejectNotBeforeThatWrapsTheField` (witness consistent in every other respect) |
| W4 | `n` is the counter held in the log leaf and increases by exactly one per batch | `n := c.Log.Old.Nonce`, `api.Add(n, 1)` | `TestBatchCounterAndInclusionProofs`, `TestRejectForgedBatchCounter`; mutation: caught |

### Log leaf and inclusion records (new)

| # | Constraint | Search for | Negative test / mutation |
|---|---|---|---|
| G1 | No account update (sender, `From`, `To`) may touch `LOG_INDEX` | `AssertIsDifferent(u.Index, x.logIndex)` | `TestRejectMoveIntoTheLogLeaf`, `TestRejectSenderIsTheLogLeaf` (mutation: caught) |
| G2 | The log update is at `LOG_INDEX` (a fixed constant) | `c.Log.Index, x.logIndex` | `TestRejectLogUpdateAtAnotherIndex` (mutation: caught) |
| G3 | The old log leaf has only `pk_commit` and `nonce` set | `c.Log.Old.Qor` etc. | `TestRejectOldLogLeafThatIsNotLogShaped` (3 cases, mutation: each caught) |
| G4 | `tx_root` is computed in-circuit from the executed moves, parties and window; it is not a free witness | `recFields`, `recMoves` | every valid-batch test (the root would mismatch); `TestRejectChangedWindowAfterTheFact` |
| G5 | The withdrawal recipient is bound in the record (`recipient_commit`) | `rcommit`, `rcSel` | `TestEveryWithdrawalCount`, mutation: caught |
| G6 | An inactive slot's record is 0 | `api.Mul(tx.Active, x.md(recFields))` | mutation: caught |
| G7 | `tx slots` is a power of two; genesis accounts avoid `LOG_INDEX`; parties in `1..8` | `Config.Validate` | `TestRejectGenesisAtTheReservedIndex` |

One constraint was **removed** because no test could reach it: the 64-bit range of the batch counter `n` (it starts at 0 and only the circuit raises it).

### 2b. Checked skips, the digest and new accounts (circuit v3, 22 Nov)

A move now carries its **planned** terms (what the signers wrote) and a `Skip` bit; its effect on the tree is the planned move times `1 - Skip`. Search `fail[a]` and `skips` in `Define`. A skipped action must be one that could not apply, judged on the balances the action's atomic group would have left.

| # | Constraint | Search for | Negative test / mutation |
|---|---|---|---|
| S1 | `Skip` is a bit | `AssertIsBoolean(mv.Skip)` | `TestRejectNonBooleanSkipAndAtomicFlags` (skip = 2 on an overdraft: live = -1 turns the debit into a credit; every balance in range) |
| S2 | `Atomic` is a bit | `AssertIsBoolean(mv.Atomic)` | same test (atomic = 2 changes only the digest) |
| S3 | An empty slot has no atomic flag. (A skipped empty slot is refused by S6: an empty slot never fails. There was a separate "only a real action can be skipped" constraint; mutation checking showed it redundant and it was removed.) | `mv.Atomic, api.Sub(1, any)` | `TestOnlyARealActionCanBeSkippedOrFlaggedAtomic` |
| S4 | The fee always applies and has no atomic flag | `api.AssertIsEqual(mv.Skip, 0)` in the `m == 0` branch | same test (skipping or flagging the fee move) |
| S5 | An atomic group is skipped or applied as a whole | `link[a]` | `TestSkipOfAnAtomicGroupIsJustifiedByAnyLeg` (one leg applied, one skipped) |
| S6 | **A skip must be justified**: some action of the group fails | `skips[a], none` | `TestRejectSkippingAnActionThatWouldHaveApplied`, `...AValidWithdrawalOrKeyRegistration`, `TestSkipOnlyHoldsInsideItsOwnGroup` |
| S7 | The four grounds of failure: insufficient balance, credit overflow, full withdrawal slots, key already set | `insufficient`, `overflow`, `full`, `keyExists` | `TestSkipIsAcceptedWhenTheActionCouldNotApply`, `TestSkipJustifiedByCreditOverflow` (boundary at 2^64 - 1), `...ByFullWithdrawalSlots`, `...ByAKeyAlreadyOnTheAccount`; each ground has a mutation |
| S8 | The failing action is judged on the tentative balances after the earlier actions of its group, and only of its own group | `balFrom`, `balTo`, `wTent`, `keyHit`, `conn` | `TestSkipUsesTheBalanceAfterEarlierLegsOfTheGroup`, `TestSkipCountsCreditsFromEarlierLegs`, `TestSkipTentativeStateOfTheReceiver`, `TestSkipJustifiedByAKeyRegisteredEarlierInTheGroup`, `TestSkipTentativeStateIgnoresUnlinkedMoves`; one mutation per term |
| S9 | The tentative balance is per asset, and a transfer to the account it debits nets to zero | `same := api.IsZero(...)`, `api.IsZero(api.Sub(mv.From.Index, mv.To.Index))` | the USD case of `TestSkipUsesTheBalanceAfterEarlierLegsOfTheGroup`; the self-transfer case of `TestSkipTentativeStateOfTheReceiver` |
| S10 | The 68-bit comparison windows hold (balances are below 2^64 and a group has at most 8 moves) | `ToBinary(... , 68)` | `Config.Validate` bounds `Moves`; the boundary tests above |
| D1 | The record carries the digest, computed in the circuit from the planned moves, window, co-signers, payer, fee asset, max fee, signed sender and the chain/rollup domain | `digest := x.md(dfields)` | `TestHonestRecordDigestIsTheDigestOfTheSignedTx`, `TestUsdFeeIsInTheDigestAndTheCircuitAgrees`, `TestDigestGoldenVector`, `scripts/spike/src/digest-local.ts` (Go and TypeScript agree); one mutation per field |
| D2 | A withdrawal's planned recipient commitment is the slot's, and a transfer has no aux | `eW, api.Sub(mv.PkCommit, rcSel)`, `mv.PkCommit, api.Sub(1, ...)` | `TestRejectAWithdrawalWhoseRecipientCommitmentIsNotTheSlots`, `TestRejectAuxOnATransfer` |
| D3 | The fee charged is at most the signed max fee | `api.Sub(tx.MaxFee, feeAmt)` | `TestMaxFee` |
| D4 | The signed sender is the executing sender or the new-account sentinel | `tx.SignedSender, tx.Sender.Index` | `TestNewAccountRules` |
| N1 | A new account's leaf is empty (no key, balance, nonce or orders) | `api.Mul(isNew, f)` | `TestNewAccountRules` (a registering user handed an account that already holds funds) |
| N2 | A new-account transaction registers a key | `api.IsZero(regCount)` | `TestNewAccountRules` |

Terms no valid signer writes are refused outright, not skipped: an unknown asset, a withdrawal in USD or to a malformed address, an empty key (`TestCheckedBuilderRefusesTermsTheCircuitCannotSkip`).

### 2c. Randomised check

`TestFuzzHonestBatchesAgreeWithTheReferenceAndTheCircuit` runs random batches (multi-party, atomic groups, overdrafts, a receiver 3 below the 2^64 limit, full withdrawal slots, keys already set) through the honest builder, a reference interpreter written from the spec in the test file (no shared code with the builder), and the circuit. They must agree on which actions applied, every balance, conservation of value, the withdrawals, every record's digest and every inclusion proof. Then each applied last action of a plain transaction is re-run through the adversarial builder with only its skip bit set; the circuit must refuse all of them.

### 2a. Mutation results (20 Nov, 37 mutations: 37 caught; extended 22 Nov to 70, see 2d)

`python3 circuits/mutation_check.py` removes one constraint at a time and requires a test to fail. **All 37 are caught**, each by a test whose witness is consistent in every other respect, so only that rule can reject it.

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

### 2d. Mutation results, circuit v3 (22 Nov)

**70 mutations, 70 caught** (`python3 circuits/mutation_check.py`, final run on the circuit as committed to this review). It did not start that way: the first full run of v3 (71 mutations) caught 55 and missed 16. What the misses were, because a reviewer should know how far to trust the rest:

- **4 were test-isolation regressions I caused.** The digest added a record field, which shifted the field indexes in the `consistentTweak` helper, so the window-range, party-flag and key-overwrite tests were rejecting for the wrong reason (a root mismatch). Fixed: the helper now recomputes the digest as the circuit would (`consistentTweakMany`), and the overwrite-keys builder path gives the digest the aux the circuit sees.
- **6 were tests that rejected for another reason** once the digest existed (skip = 2 left the receiver negative; a stray aux, a wrong recipient commitment and a wrong signed sender each changed the digest; a "funded new account" test used an account that already had a key). Each now isolates its rule, with a control the circuit accepts.
- **3 were mutation patterns that did not compile** (an unused variable), so they proved nothing. Fixed the patterns.
- **1 constraint was redundant** ("only a real action can be skipped": an empty slot never fails, so the justification already refuses it) and was removed.
- **2 needed new tests** (a fee in USD, which the digest commits to; moves outside an atomic group, which must not count towards the tentative balances).

## 3. Where I would look hardest (my own suspicions, in order)

**F1. Fixed (20 Nov).** The fee recipient used to be a free witness, so a malicious sequencer could send every fee to an account it controls. The relayer index is now a `Config` constant (`relayer` in `config.json`) and the circuit asserts the fee move pays it (row R1). The new setup is `cloister-dev-4`. Kept here because it was found by review of my own design, and because a reviewer should still check that the constant cannot be changed after the verifying key is fixed (it is baked into the circuit).

**F2. Skipped actions were unconstrained. Fixed in circuit v3 (22 Nov).** The circuit used to accept a no-op for any action, so a sequencer could skip a valid action and keep the fee. Now a skip needs a justification (rows S1 to S10): some action of its atomic group must fail on one of four grounds, judged on the tentative balances. Check by reading `fail[a]` and the tentative-state loop: is the list of four grounds complete (compare `witness.go` `check`), and are the 68-bit windows safe (S10)? Residual: a sequencer can still *choose which transaction to include* (inclusion and ordering are not in the circuit), and an action it skips with a false planned term is caught by the digest, not the circuit.

**F3. The window is only as honest as the record. Narrowed in v3 (22 Nov).** The window in the record is still a witness, so a sequencer can claim `not_before = 0` for a tx that signed `not_before = 100`. But the window is now an input to the record's **digest**, so the lie changes the digest: the holder of the signed tx finds it with `check-tx`, a watchtower with `--replay` (the root differs), and anyone with the signature can verify `sighash` against the digest. Still detection, not prevention: preventing it needs the signature verified in the circuit (`docs/pq-auth.md`).

**F4. Hash collisions between record leaves, digests and account leaves. Analysed (22 Nov), not proven.** All of them are Merkle-Damgard over Poseidon2 with a zero IV and no length padding (`md`). My reasoning, which a reviewer should challenge:

- *Leaf/node confusion* is excluded by the fixed depth: every path is climbed for exactly `depth` levels from a leaf at level 0, so an internal node cannot be presented as a leaf (it would reach a root at the wrong height). The tx tree has fixed depth 2 the same way.
- *Cross-structure collisions.* Two different inputs of different lengths hashing to the same value would need `Compress(h_{n-1}, f_n) = Compress(a_4, orders)` for chains of different length, which needs either a `Compress` collision or an internal-state cycle. The first elements differ by design (`TX_TAG = 1`, `DIGEST_TAG = 2`; an account leaf starts with a key commitment), but an account can choose its key commitment freely, so I do not rely on that as separation, only on collision resistance.
- *Without length padding,* `MD(m)` is the internal state of `MD(m || x)`, so the hash of a prefix is available to an attacker who sees a long hash. Nothing here treats a hash as a secret or a MAC, and each structure has a fixed length (account: 5, record: `6 + P + 6M`, digest: `9 + P + 7(M-1)`), so no verifier accepts two lengths for one structure.
- What this does not cover: Poseidon2's own security (gnark-crypto's default parameters for width 2) and whether `Compress(l, r) = r + perm(l, r)[1]` (feed-forward) is a good compression function. Both are the library's.
A second, cheap defence would be a distinct constant domain tag on account leaves; not done, because it changes every vector and gives only defence in depth.

**F5. Genesis and treasury trust.** The genesis root is a circuit constant and holds the whole supply in account 0. Onboarding credit is an ordinary transfer, so the treasury's key is a trusted role (THREAT_MODEL). Conservation guarantees total QOR never exceeds the escrow, not that the operator is fair.

**F6. Parties are authorized by a list the sequencer supplies. Narrowed in v3 (22 Nov), not closed.** The circuit checks `From ∈ {sender, active parties}`. It cannot check that those parties *signed*. In v3 the party list is part of the digest, so a forged list is detectable from the record alone by anyone holding the transaction (`check-tx`), and `--replay` re-execution of the sealed bundle exposes a list the bundle does not contain. Closing it needs the signature verified in the circuit: `docs/pq-auth.md` measures that (ML-DSA is not feasible; a hash-based signature at about 0.22 million constraints each is, and is prototyped in `circuits/hbs`, not wired in). Until then it is the watchtowers' word, and one watchtower is one party's word. *Worth a second watchtower in the demo.*

**F7. Single-party trusted setup.** The Groth16 setup was run by one party (us). Anyone who kept the toxic waste could forge proofs. Testnet only; stated in LIMITS.

**F8. Range checks on witness-supplied indexes.** `ToBinary(u.Index, depth)` bounds every account index to `depth` bits, so an index cannot wrap the field. Party and sender indexes are also bound this way where they are used in a move; an *unused* active party slot may hold any field element (it only appears in the record). I believe that is harmless (the record is just a commitment), but check it.

## 4. What the tests do not cover

- The Go builder and the circuit share my understanding of the rules. The tests check that they agree, not that the rules are the right ones.
- Fuzzing exists (section 2c) but is modest: 40 random batches by default, 500 or more on request, with a generator I wrote. It found nothing in the runs recorded in AI_USAGE.md, which is evidence about my generator as much as about the circuit.
- Groth16 soundness itself, and gnark's Poseidon2 and BLS12-381 code, are assumed.
- The on-chain verifier is QoreChain's. We tested that it accepts our proofs (cloister-dev-2 for circuit v1, cloister-dev-3 for circuit v2) but have not independently audited it. Circuit v3 has **not yet been verified on chain**: it needs a new setup and a new rollup (`cloister-dev-5`).
