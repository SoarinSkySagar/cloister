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

