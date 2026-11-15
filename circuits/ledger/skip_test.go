package ledger

// Tests for circuit v3: a skipped action must be one that could not apply (finding F2), and the record carries a
// digest of what the signers wrote, built from the same witness the circuit executes (findings F3 and F6).
//
// Skip tests use the adversarial builder (adversary_test.go) so the witness is consistent in every respect except
// the rule under test. Each "reject" test has a control that the circuit accepts, so the rejection is the rule's.

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func skipped(m advMove) advMove { m.skip = fe(1); return m }
func atomic(m advMove) advMove  { m.atomic = fe(1); return m }

func withdrawMove(from uint32, amount uint64) advMove {
	return advMove{withdraw: fe(1), amount: fe(amount), from: from, to: from}
}

// ---- F2: a skip must be justified ----

func TestSkipIsAcceptedWhenTheActionCouldNotApply(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// alice has 1,000,000 QOR: sending 2,000,000 fails, so skipping it is honest
	w := advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, bob, fe(0), fe(2_000_000)))))
	mustSolve(t, cfg, w, "skipping an overdraft")
}

func TestRejectSkippingAnActionThatWouldHaveApplied(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), transferMove(alice, bob, fe(0), fe(5)))), "control: the transfer applied")
	_, rt = advSetup(t, cfg)
	w := advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, bob, fe(0), fe(5)))))
	mustFail(t, cfg, w, "a sequencer skipping a valid transfer but charging the fee (censorship)")
}

func TestRejectSkippingAValidWithdrawalOrKeyRegistration(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	w := advBuild(t, cfg, rt, advBatch{txs: oneTx(cfg, alice, noopMove(alice), skipped(withdrawMove(alice, 10))).txs, recipients: map[int]string{0: l1Addr}})
	mustFail(t, cfg, w, "skipping a valid withdrawal")
	_, rt = advSetup(t, cfg)
	reg := advMove{register: fe(1), pk: fe(55), from: alice, to: alice}
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(reg))), "skipping a key registration on a keyless account")
}

func TestSkipOfAnAtomicGroupIsJustifiedByAnyLeg(t *testing.T) {
	cfg := testConfig()
	good := atomic(transferMove(alice, bob, fe(0), fe(10)))
	bad := atomic(transferMove(alice, bob, fe(0), fe(9_000_000)))

	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(good), skipped(bad))),
		"a group is skipped because its second leg cannot apply")
	_, rt = advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(bad), skipped(good))),
		"a group is skipped because its first leg cannot apply")

	_, rt = advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), good, skipped(bad))),
		"one leg of an atomic group applied while the other was skipped")
	_, rt = advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(good), bad)),
		"the other leg skipped and this one applied (it would overdraw, and the groups disagree)")

	_, rt = advSetup(t, cfg)
	other := atomic(transferMove(alice, bob, fe(0), fe(20)))
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(good), skipped(other))),
		"a whole atomic group skipped though every leg could apply")
}

func TestSkipOnlyHoldsInsideItsOwnGroup(t *testing.T) {
	cfg := testConfig()
	good := transferMove(alice, bob, fe(0), fe(10)) // not atomic: its own group
	bad := transferMove(alice, bob, fe(0), fe(9_000_000))
	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), good, skipped(bad))), "the valid action applied, the overdraft skipped")
	_, rt = advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(good), bad)),
		"a failing neighbour does not justify skipping a valid non-atomic action")
}

// The failing leg is judged on the balance after the legs before it in its group.
func TestSkipUsesTheBalanceAfterEarlierLegsOfTheGroup(t *testing.T) {
	cfg := testConfig()
	all := atomic(transferMove(alice, bob, fe(0), fe(1_000_000))) // alice's whole QOR balance
	one := atomic(transferMove(alice, bob, fe(0), fe(1)))
	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(all), skipped(one))),
		"the second leg fails only because the first would have emptied the account")

	// the same two legs with a smaller first leg both apply, so skipping them is refused
	small := atomic(transferMove(alice, bob, fe(0), fe(999_999)))
	_, rt = advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(small), skipped(one))), "both legs fit; skipping is refused")

	// a different asset is a different balance: a QOR leg does not drain the USD balance
	usd := atomic(transferMove(alice, bob, fe(1), fe(500)))
	_, rt = advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(all), skipped(usd))), "a USD leg is unaffected by a QOR leg")
}

// A credit in an earlier leg can fund a later one.
func TestSkipCountsCreditsFromEarlierLegs(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// bob pays alice 1,000,000 then alice pays 2,000,000: with the credit she holds 2,000,000 and can pay, so skipping is refused
	w := advBuild(t, cfg, rt, advBatch{txs: []advTx{{
		active: fe(1), sender: alice, expiry: maxU64Fe,
		partyActive: []fr.Element{fe(1), {}, {}}, party: []uint32{bob, 0, 0},
		moves: []advMove{noopMove(treas),
			skipped(atomic(transferMove(bob, alice, fe(0), fe(1_000_000)))),
			skipped(atomic(transferMove(alice, bob, fe(0), fe(2_000_000))))},
	}}})
	mustFail(t, cfg, w, "the credit from the first leg makes the second leg payable")
	_, rt = advSetup(t, cfg)
	w = advBuild(t, cfg, rt, advBatch{txs: []advTx{{
		active: fe(1), sender: alice, expiry: maxU64Fe,
		partyActive: []fr.Element{fe(1), {}, {}}, party: []uint32{bob, 0, 0},
		moves: []advMove{noopMove(treas),
			skipped(atomic(transferMove(bob, alice, fe(0), fe(1_000_000)))),
			skipped(atomic(transferMove(alice, bob, fe(0), fe(2_000_001))))},
	}}})
	mustSolve(t, cfg, w, "2,000,001 is one more than alice would hold, so the second leg fails and the group is skipped")
}

func TestSkipJustifiedByCreditOverflow(t *testing.T) {
	cfg := testConfig()
	prep := func(bobQor uint64) *rawTree {
		tree := fundedTree(t, cfg)
		b := tree.Get(bob)
		b.Qor = bobQor
		tree.Set(bob, b)
		return newRawTree(tree)
	}
	mustSolve(t, cfg, advBuild(t, cfg, prep(math.MaxUint64), oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, bob, fe(0), fe(2))))),
		"the receiver is at the 2^64 limit, so the credit cannot apply")
	mustFail(t, cfg, advBuild(t, cfg, prep(100), oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, bob, fe(0), fe(2))))),
		"the receiver has room: skipping is refused")
	// exactly at the limit still fits
	mustFail(t, cfg, advBuild(t, cfg, prep(math.MaxUint64-2), oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, bob, fe(0), fe(2))))),
		"the credit lands exactly on 2^64-1: skipping is refused")
	mustSolve(t, cfg, advBuild(t, cfg, prep(math.MaxUint64-1), oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, bob, fe(0), fe(2))))),
		"one past the limit: the skip is justified")
}

func TestSkipJustifiedByFullWithdrawalSlots(t *testing.T) {
	cfg := testConfig()
	cfg.Withdrawals = 1
	run := func(first, second advMove) *Circuit {
		_, rt := advSetup(t, cfg)
		return advBuild(t, cfg, rt, advBatch{txs: oneTx(cfg, alice, noopMove(alice), first, second).txs, recipients: map[int]string{0: l1Addr}})
	}
	mustSolve(t, cfg, run(withdrawMove(alice, 10), skipped(withdrawMove(alice, 20))), "the only slot is taken, the second withdrawal is skipped")
	mustFail(t, cfg, run(skipped(withdrawMove(alice, 10)), withdrawMove(alice, 20)), "the slot was free for the first withdrawal: skipping it is refused")
	// two atomic withdrawals with one slot cannot both fit: the group is skipped
	mustSolve(t, cfg, run(skipped(atomic(withdrawMove(alice, 10))), skipped(atomic(withdrawMove(alice, 20)))), "an atomic pair needs two slots and there is one")
	cfg.Withdrawals = 2
	mustFail(t, cfg, run(skipped(atomic(withdrawMove(alice, 10))), skipped(atomic(withdrawMove(alice, 20)))), "with two slots the pair fits: skipping is refused")
}

func TestSkipJustifiedByAKeyAlreadyOnTheAccount(t *testing.T) {
	cfg := testConfig()
	reg := advMove{register: fe(1), pk: fe(55), from: alice, to: alice}
	withKey := func() *rawTree {
		tree := fundedTree(t, cfg)
		a := tree.Get(alice)
		a.Pk = felt(777)
		tree.Set(alice, a)
		return newRawTree(tree)
	}
	mustSolve(t, cfg, advBuild(t, cfg, withKey(), oneTx(cfg, alice, noopMove(alice), skipped(reg))), "the account already has a key")
	_, rt := advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(reg))), "the account has no key: skipping is refused")
}

func TestOnlyARealActionCanBeSkippedOrFlaggedAtomic(t *testing.T) {
	cfg := testConfig()
	for name, m := range map[string]advMove{
		"skipping an empty slot":          skipped(noopMove(alice)),
		"an atomic flag on an empty slot": atomic(noopMove(alice)),
	} {
		_, rt := advSetup(t, cfg)
		mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), m)), name)
	}
	_, rt := advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, skipped(transferMove(alice, relay, fe(0), fe(10))))), "skipping the fee move (the fee always applies)")
	_, rt = advSetup(t, cfg)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, atomic(transferMove(alice, relay, fe(0), fe(10))))), "an atomic flag on the fee move")
}

func TestRejectNonBooleanSkipAndAtomicFlags(t *testing.T) {
	cfg := testConfig()
	// skip = 2 on an overdraft (which could be skipped): live = -1 turns the debit into a credit of the same size, and every
	// balance stays in range, so only "skip is a bit" can reject it
	over := transferMove(alice, alice, fe(0), fe(2_000_000)) // a transfer to the account it debits: live = -1 nets to zero, so no balance leaves its range
	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(over))), "control: skip = 1")
	_, rt = advSetup(t, cfg)
	two := over
	two.skip = fe(2)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), two)), "a skip flag of 2")

	// atomic = 2 on a lone action changes only what the digest commits to, so only "atomic is a bit" can reject it
	one := transferMove(alice, bob, fe(0), fe(5))
	_, rt = advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), atomic(one))), "control: atomic = 1")
	_, rt = advSetup(t, cfg)
	two = one
	two.atomic = fe(2)
	mustFail(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), two)), "an atomic flag of 2")
}

// The tentative balances of the justification count what earlier legs of the group would have done to every account involved.
func TestSkipTentativeStateOfTheReceiver(t *testing.T) {
	cfg := testConfig()
	prep := func(bobQor, aliceQor uint64) *rawTree {
		tree := fundedTree(t, cfg)
		b := tree.Get(bob)
		b.Qor = bobQor
		tree.Set(bob, b)
		a := tree.Get(alice)
		a.Qor = aliceQor
		tree.Set(alice, a)
		return newRawTree(tree)
	}
	// an earlier credit to bob makes a later credit overflow
	mustSolve(t, cfg, advBuild(t, cfg, prep(math.MaxUint64-5, 1_000_000), oneTx(cfg, alice, noopMove(alice),
		skipped(atomic(transferMove(alice, bob, fe(0), fe(3)))), skipped(atomic(transferMove(alice, bob, fe(0), fe(3)))))),
		"two credits of 3 to a receiver with room for 5: the second overflows only because of the first")
	mustFail(t, cfg, advBuild(t, cfg, prep(math.MaxUint64-6, 1_000_000), oneTx(cfg, alice, noopMove(alice),
		skipped(atomic(transferMove(alice, bob, fe(0), fe(3)))), skipped(atomic(transferMove(alice, bob, fe(0), fe(3)))))),
		"room for 6: both credits fit, skipping is refused")

	// an earlier debit of the receiver makes room for a later credit: bob pays alice 5, then alice pays bob 3
	pair := func(rt *rawTree, bobPays uint64) *Circuit {
		return advBuild(t, cfg, rt, advBatch{txs: []advTx{{
			active: fe(1), sender: alice, expiry: maxU64Fe,
			partyActive: []fr.Element{fe(1), {}, {}}, party: []uint32{bob, 0, 0},
			moves: []advMove{noopMove(treas),
				skipped(atomic(transferMove(bob, alice, fe(0), fe(bobPays)))),
				skipped(atomic(transferMove(alice, bob, fe(0), fe(3))))},
		}}})
	}
	mustFail(t, cfg, pair(prep(math.MaxUint64, 1_000_000), 5), "bob's own debit leaves room for the credit: both legs apply, skipping is refused")
	mustSolve(t, cfg, pair(prep(math.MaxUint64, 1_000_000), 1), "bob pays only 1, so the credit of 3 still overflows: the skip is justified")

	// a transfer to the account it debits nets to zero, so it cannot overflow
	mustFail(t, cfg, advBuild(t, cfg, prep(0, math.MaxUint64), oneTx(cfg, alice, noopMove(alice), skipped(transferMove(alice, alice, fe(0), fe(1))))),
		"a self-transfer of 1 from a full account applies: skipping is refused")
}

func TestSkipJustifiedByAKeyRegisteredEarlierInTheGroup(t *testing.T) {
	cfg := testConfig()
	first := atomic(advMove{register: fe(1), pk: fe(55), from: alice, to: alice})
	second := atomic(advMove{register: fe(1), pk: fe(66), from: alice, to: alice})
	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), skipped(first), skipped(second))),
		"the second registration fails because the first would have set a key")
}

// A withdrawal's recipient commitment is part of what was signed and must be the slot's. The record and digest are made
// consistent with the tampered value (record move 1 aux = field 20, digest action 0 aux = element 17), so only that rule can reject it.
func TestRejectAWithdrawalWhoseRecipientCommitmentIsNotTheSlots(t *testing.T) {
	cfg := testConfig()
	batch := Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{{Kind: "withdraw", Recipient: l1Addr, Amount: 10}}}}}
	w, _, _ := build(t, cfg, batch, Options{})
	mustSolve(t, cfg, w, "control")
	tree := fundedTree(t, cfg)
	w, res, err := solveBuilt(t, cfg, tree, batch, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.Txs[0].Moves[1].PkCommit = 12345
	other := big.NewInt(12345)
	consistentTweakMany(t, cfg, tree, res, w, 0, map[int]*big.Int{20: other}, map[int]*big.Int{17: other})
	mustFail(t, cfg, w, "the planned recipient differs from the one the withdrawal leaf pays")
}

func TestRejectAuxOnATransfer(t *testing.T) {
	cfg := testConfig()
	batch := Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 10}}}}}
	w, _, _ := build(t, cfg, batch, Options{})
	mustSolve(t, cfg, w, "control")
	tree := fundedTree(t, cfg)
	w, res, err := solveBuilt(t, cfg, tree, batch, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.Txs[0].Moves[1].PkCommit = 1
	// the record's aux for a transfer is masked to 0, so only the digest (element 17) sees the stray value
	consistentTweakMany(t, cfg, tree, res, w, 0, nil, map[int]*big.Int{17: big.NewInt(1)})
	mustFail(t, cfg, w, "stray data in a transfer's aux slot")
}

// ---- F3/F6: the record binds what was signed ----

func TestHonestRecordDigestIsTheDigestOfTheSignedTx(t *testing.T) {
	cfg := testConfig()
	tx := TxIn{Sender: alice, Payer: treas, Relayer: relay, Fee: 10, FeeAsset: 0, Parties: []uint32{bob}, NotBefore: 0,
		Actions: []ActionIn{
			{Kind: "transfer", From: u32p(alice), To: bob, Asset: 1, Amount: 100, Atomic: true},
			{Kind: "transfer", From: u32p(bob), To: alice, Asset: 0, Amount: 9_000_000_000, Atomic: true}, // bob cannot: the pair is skipped
		}}
	w, res, _ := build(t, cfg, Batch{Txs: []TxIn{tx}}, Options{})
	mustSolve(t, cfg, w, "a swap skipped because one leg cannot apply")
	if res.Txs[0].Applied[0] || res.Txs[0].Applied[1] {
		t.Fatalf("setup: the pair should be skipped: %+v", res.Txs[0])
	}
	var zero fr.Element
	dom := DomainConst(cfg.ChainID, cfg.RollupID)
	acts := []PlannedMove{
		{MoveRecord: NewMoveRecord(MoveTransfer, 1, 100, alice, bob, zero, zero), Atomic: true},
		{MoveRecord: NewMoveRecord(MoveTransfer, 0, 9_000_000_000, bob, alice, zero, zero), Atomic: true},
	}
	want := TxDigest(dom, alice, res.Records[0].NonceBefore, math.MaxUint64, 0, treas, 0, 10, []uint32{bob}, cfg.Parties, acts, cfg.Moves-1)
	if !want.Equal(&res.Records[0].Digest) {
		t.Fatal("the record's digest is not the digest of the signed transaction")
	}
	// what the user sees: the skipped legs are zero moves, yet the digest still commits to their terms
	for k := 1; k < 3; k++ {
		if res.Records[0].Moves[k] != (MoveRecord{}) {
			t.Fatalf("a skipped move must appear as a zero move, got %+v", res.Records[0].Moves[k])
		}
	}
	dropped := TxDigest(dom, alice, res.Records[0].NonceBefore, math.MaxUint64, 0, treas, 0, 10, []uint32{bob}, cfg.Parties, nil, cfg.Moves-1)
	if dropped.Equal(&res.Records[0].Digest) {
		t.Fatal("the digest must differ from that of a transaction without the skipped legs")
	}
}

func u32p(v uint32) *uint32 { return &v }

func TestNewAccountRules(t *testing.T) {
	cfg := testConfig()
	const fresh = 20
	reg := TxIn{Sender: fresh, Payer: treas, Relayer: relay, NewAccount: true, Fee: 5, Actions: []ActionIn{{Kind: "register_key", PkCommit: "99"}}}
	w, res, _ := build(t, cfg, Batch{Txs: []TxIn{reg}}, Options{})
	mustSolve(t, cfg, w, "a new account registers its key")
	var zero fr.Element
	pk, _ := parseFr("99")
	want := TxDigest(DomainConst(cfg.ChainID, cfg.RollupID), NewAccountSender, 0, math.MaxUint64, 0, treas, 0, 5, nil, cfg.Parties,
		[]PlannedMove{{MoveRecord: NewMoveRecord(MoveRegister, 0, 0, fresh, 0, pk, zero)}}, cfg.Moves-1)
	if !want.Equal(&res.Records[0].Digest) || res.Records[0].Sender != fresh {
		t.Fatal("a new account's digest carries the sentinel; its record carries the assigned index")
	}

	// the signed sender is neither the sender nor the sentinel. The digest and record are made consistent with it (digest element 2),
	// so only the "signed sender" rule can reject it.
	tree := fundedTree(t, cfg)
	w, res, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{reg}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.Txs[0].SignedSender = 21
	consistentTweakMany(t, cfg, tree, res, w, 0, nil, map[int]*big.Int{2: big.NewInt(21)})
	mustFail(t, cfg, w, "a signed sender that is neither the executing sender nor the new-account sentinel")

	// a registration handed an account that already holds funds and has no key: carol (1,000,000 QOR). The control
	// registers on carol as an ordinary (not new) account, which is allowed; signed as a new account it must be refused.
	asNew := TxIn{Sender: carol, Payer: treas, Relayer: relay, NewAccount: true, Fee: 5, Actions: []ActionIn{{Kind: "register_key", PkCommit: "99"}}}
	asOld := asNew
	asOld.NewAccount = false
	if _, _, err := Build(cfg, fundedTree(t, cfg), false, Batch{Txs: []TxIn{asNew}}, Options{}); err == nil {
		t.Fatal("the checked builder gave a new account to an index that holds funds")
	}
	w, _, err = Build(cfg, fundedTree(t, cfg), false, Batch{Txs: []TxIn{asOld}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.SetDataHash([32]byte{1})
	mustSolve(t, cfg, w, "control: a key registered on a funded, key-less account that is not signed as new")
	w, _, err = Build(cfg, fundedTree(t, cfg), false, Batch{Txs: []TxIn{asNew}}, Options{Unchecked: true})
	if err != nil {
		t.Fatal(err)
	}
	w.SetDataHash([32]byte{1})
	mustFail(t, cfg, w, "the sequencer assigns a registering user an account that already holds funds")

	// a new-account transaction that registers nothing
	idle := TxIn{Sender: fresh, Payer: treas, Relayer: relay, NewAccount: true, Fee: 5, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 0}}}
	w, _, _ = build(t, cfg, Batch{Txs: []TxIn{idle}}, Options{Unchecked: true})
	mustFail(t, cfg, w, "a new-account transaction without a key registration burns an index")
}

// A fee in USD: the digest commits to the fee asset.
func TestUsdFeeIsInTheDigestAndTheCircuitAgrees(t *testing.T) {
	cfg := testConfig()
	tx := TxIn{Sender: alice, Payer: alice, Relayer: relay, Fee: 7, FeeAsset: 1, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}
	w, res, _ := build(t, cfg, Batch{Txs: []TxIn{tx}}, Options{})
	mustSolve(t, cfg, w, "a fee paid in USD")
	var zero fr.Element
	want := TxDigest(DomainConst(cfg.ChainID, cfg.RollupID), alice, res.Records[0].NonceBefore, math.MaxUint64, 0, alice, 1, 7, nil, cfg.Parties,
		[]PlannedMove{{MoveRecord: NewMoveRecord(MoveTransfer, 0, 1, alice, bob, zero, zero)}}, cfg.Moves-1)
	if !want.Equal(&res.Records[0].Digest) {
		t.Fatal("the digest does not carry the fee asset")
	}
	tx.FeeAsset = 0
	_, res2, _ := build(t, cfg, Batch{Txs: []TxIn{tx}}, Options{})
	if res2.Records[0].Digest.Equal(&res.Records[0].Digest) {
		t.Fatal("a fee in QOR and a fee in USD share a digest")
	}
}

// A move that is not in the same atomic group does not count towards the tentative balances of a skipped one.
func TestSkipTentativeStateIgnoresUnlinkedMoves(t *testing.T) {
	cfg := testConfig()
	prep := func() *rawTree {
		tree := fundedTree(t, cfg)
		b := tree.Get(bob)
		b.Qor = math.MaxUint64 // the first transfer cannot land
		tree.Set(bob, b)
		return newRawTree(tree)
	}
	first := transferMove(alice, bob, fe(0), fe(1_000_000))  // all of alice's QOR, but bob is full: skipped (overflow)
	second := transferMove(alice, carol, fe(0), fe(500_000)) // not atomic with the first: alice still has the funds, so it applies
	mustSolve(t, cfg, advBuild(t, cfg, prep(), oneTx(cfg, alice, noopMove(alice), skipped(first), second)), "control: the second transfer applies")
	mustFail(t, cfg, advBuild(t, cfg, prep(), oneTx(cfg, alice, noopMove(alice), skipped(first), skipped(second))),
		"skipping the second transfer on the strength of a first one it is not grouped with")
}

func mustTree(t *testing.T, cfg Config) *Tree { return fundedTree(t, cfg) }

func TestMaxFee(t *testing.T) {
	cfg := testConfig()
	max := uint64(5)
	tx := TxIn{Sender: alice, Payer: alice, Relayer: relay, Fee: 10, MaxFee: &max, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}
	if _, _, err := Build(cfg, mustTree(t, cfg), false, Batch{Txs: []TxIn{tx}}, Options{}); err == nil {
		t.Fatal("the checked builder charged more than the signed max fee")
	}
	w, _, _ := build(t, cfg, Batch{Txs: []TxIn{tx}}, Options{Unchecked: true})
	mustFail(t, cfg, w, "a fee above the max fee the payer signed")
	tx.Fee = 5
	w, _, _ = build(t, cfg, Batch{Txs: []TxIn{tx}}, Options{})
	mustSolve(t, cfg, w, "a fee equal to the max fee")
}

func TestCheckedBuilderRefusesTermsTheCircuitCannotSkip(t *testing.T) {
	cfg := testConfig()
	for name, a := range map[string]ActionIn{
		"a USD withdrawal":                {Kind: "withdraw", Recipient: l1Addr, Asset: 1, Amount: 1},
		"a withdrawal to a short address": {Kind: "withdraw", Recipient: "qor1short", Amount: 1},
		"an empty key":                    {Kind: "register_key", PkCommit: "00"},
		"an unknown asset":                {Kind: "transfer", To: bob, Asset: 2, Amount: 1},
	} {
		_, _, err := Build(cfg, mustTree(t, cfg), false, Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{a}}}}, Options{})
		if err == nil {
			t.Errorf("%s: the checked builder accepted it", name)
		}
	}
}

// The justification compares balances in a 68-bit window; more than 8 moves per tx would let a tentative balance leave it.
func TestConfigRefusesMoreThanEightMoves(t *testing.T) {
	cfg := testConfig()
	cfg.Moves = 8
	if err := cfg.Validate(); err != nil {
		t.Fatalf("8 moves must be accepted: %v", err)
	}
	cfg.Moves = 9
	if cfg.Validate() == nil {
		t.Fatal("9 moves were accepted")
	}
}
