package ledger

// An adversarial witness builder: what a malicious prover would run. It executes the circuit's OWN formulas
// (circuit.go, spec/batch.md) in field arithmetic with every check turned off, on a tree whose leaves are
// arbitrary field elements (the honest Tree keeps balances as uint64, so it cannot represent a wrapped balance).
// Each witness is consistent in every respect except the one rule a test targets, so only that rule can reject
// it. circuits/mutation_check.py removes each rule in turn and confirms the matching test then fails.

import (
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
)

// ---- a tree of arbitrary field-element leaves ----

type rawTree struct {
	depth  int
	leaves map[uint32][5]fr.Element
	nodes  []map[uint32]fr.Element
	empty  []fr.Element
}

func rawHash(f [5]fr.Element) fr.Element {
	var h fr.Element
	allZero := true
	for _, e := range f {
		if !e.IsZero() {
			allZero = false
		}
	}
	if allZero {
		return h
	}
	for _, e := range f {
		h = Compress(h, e)
	}
	return h
}

func newRawTree(t *Tree) *rawTree {
	r := &rawTree{depth: t.depth, leaves: map[uint32][5]fr.Element{}}
	r.nodes = make([]map[uint32]fr.Element, r.depth+1)
	r.empty = make([]fr.Element, r.depth+1)
	for l := 0; l <= r.depth; l++ {
		r.nodes[l] = map[uint32]fr.Element{}
		if l > 0 {
			r.empty[l] = Compress(r.empty[l-1], r.empty[l-1])
		}
	}
	for idx, a := range t.accounts {
		r.set(idx, a.fields())
	}
	return r
}

func (r *rawTree) node(l int, i uint32) fr.Element {
	if v, ok := r.nodes[l][i]; ok {
		return v
	}
	return r.empty[l]
}

func (r *rawTree) get(idx uint32) [5]fr.Element { return r.leaves[idx] }

func (r *rawTree) set(idx uint32, f [5]fr.Element) {
	r.leaves[idx] = f
	r.nodes[0][idx] = rawHash(f)
	for l := 1; l <= r.depth; l++ {
		idx >>= 1
		r.nodes[l][idx] = Compress(r.node(l-1, 2*idx), r.node(l-1, 2*idx+1))
	}
}

func (r *rawTree) path(idx uint32) []fr.Element {
	out := make([]fr.Element, r.depth)
	for l := 0; l < r.depth; l++ {
		out[l] = r.node(l, idx^1)
		idx >>= 1
	}
	return out
}

func (r *rawTree) root() fr.Element { return r.node(r.depth, 0) }

// ---- field helpers (fr.Element methods mutate their receiver) ----

func fe(n uint64) fr.Element         { var e fr.Element; e.SetUint64(n); return e }
func feNeg(n uint64) fr.Element      { e := fe(n); e.Neg(&e); return e } // -n mod r
func add(a, b fr.Element) fr.Element { var r fr.Element; r.Add(&a, &b); return r }
func sub(a, b fr.Element) fr.Element { var r fr.Element; r.Sub(&a, &b); return r }
func mul(a, b fr.Element) fr.Element { var r fr.Element; r.Mul(&a, &b); return r }
func isZeroFe(a fr.Element) fr.Element {
	if a.IsZero() {
		return fe(1)
	}
	return fe(0)
}
func bigOf(e fr.Element) *big.Int { return e.BigInt(new(big.Int)) }

func rawLeafW(f [5]fr.Element) Leaf {
	return Leaf{bigOf(f[0]), bigOf(f[1]), bigOf(f[2]), bigOf(f[3]), bigOf(f[4])}
}

// ---- the adversary's batch description: every value is a free field element ----

type advMove struct {
	transfer, withdraw, register, asset, amount, pk fr.Element
	atomic, skip                                    fr.Element // the action's atomic flag; 1 = the move did not apply
	from, to                                        uint32
}

type advTx struct {
	active            fr.Element
	sender            uint32
	expiry, notBefore fr.Element
	partyActive       []fr.Element
	party             []uint32
	moves             []advMove // len = cfg.Moves; move 0 is the fee move

	// what the signers committed to; the zero values mean "the sender" and "the fee itself"
	signedSender    fr.Element
	hasSignedSender bool
	maxFee          fr.Element
	hasMaxFee       bool
}

type advBatch struct {
	txs        []advTx        // the remaining slots are unused no-ops
	recipients map[int]string // withdrawal slot -> 42-byte recipient
}

func noopMove(idx uint32) advMove { return advMove{from: idx, to: idx} }

// advBuild runs b through the circuit's formulas on rt (which it mutates) and returns the full witness.
func advBuild(t *testing.T, cfg Config, rt *rawTree, b advBatch) *Circuit {
	t.Helper()
	w, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	W := cfg.Withdrawals
	logIdx := LogIndex(cfg.Depth)
	prev := rt.root()

	update := func(idx uint32, next func([5]fr.Element) [5]fr.Element) Update {
		old := rt.get(idx)
		path := rt.path(idx)
		u := Update{Index: idx, Old: rawLeafW(old), Path: make([]frontend.Variable, len(path))}
		for i, p := range path {
			u.Path[i] = bigOf(p)
		}
		rt.set(idx, next(old))
		return u
	}

	n := rt.get(logIdx)[3] // the batch counter
	rcommit := make([]fr.Element, W)
	for k := 0; k < W; k++ {
		if s, ok := b.recipients[k]; ok {
			rcommit[k], _ = RecipientCommit(s)
		} else {
			rcommit[k] = Compress(fr.Element{}, fr.Element{}) // all-zero recipient bytes
		}
	}

	var wCount fr.Element
	slotAmt := make([]fr.Element, W)
	var wlist []Withdrawal
	recLeaves := make([]fr.Element, cfg.Txs)

	for i := 0; i < cfg.Txs; i++ {
		var tx advTx
		if i < len(b.txs) {
			tx = b.txs[i]
		}
		if tx.moves == nil {
			tx.moves = make([]advMove, cfg.Moves)
			for m := range tx.moves {
				tx.moves[m] = noopMove(tx.sender)
			}
		}
		if tx.partyActive == nil {
			tx.partyActive = make([]fr.Element, cfg.Parties)
			tx.party = make([]uint32, cfg.Parties)
		}
		wt := &w.Txs[i]
		wt.Active, wt.Expiry, wt.NotBefore = bigOf(tx.active), bigOf(tx.expiry), bigOf(tx.notBefore)
		for k := range tx.party {
			wt.PartyActive[k], wt.Party[k] = bigOf(tx.partyActive[k]), uint64(tx.party[k])
		}
		signedSender := fe(uint64(tx.sender))
		if tx.hasSignedSender {
			signedSender = tx.signedSender
		}
		maxFee := mul(tx.moves[0].amount, tx.moves[0].transfer)
		if tx.hasMaxFee {
			maxFee = tx.maxFee
		}
		wt.SignedSender, wt.MaxFee = bigOf(signedSender), bigOf(maxFee)

		senderOld := rt.get(tx.sender)
		wt.Sender = update(tx.sender, func(f [5]fr.Element) [5]fr.Element { f[3] = add(f[3], tx.active); return f })

		partyFields := make([]fr.Element, len(tx.party))
		for k := range tx.party {
			partyFields[k] = mul(tx.partyActive[k], add(fe(uint64(tx.party[k])), fe(1)))
		}
		var recMoves, digestActs []fr.Element

		for m, mv := range tx.moves {
			live := sub(fe(1), mv.skip)
			eT, eW, eR := mul(mv.transfer, live), mul(mv.withdraw, live), mul(mv.register, live)
			val := add(eT, eW)
			effAny := add(val, eR)

			// the withdrawal slot this move would fill, and the recipient commitment it must carry
			var rcSel fr.Element
			if m > 0 {
				for k := 0; k < W; k++ {
					hit := mul(eW, isZeroFe(sub(wCount, fe(uint64(k)))))
					slotAmt[k] = add(slotAmt[k], mul(hit, mv.amount))
					rcSel = add(rcSel, mul(hit, rcommit[k]))
				}
				if eW.Equal(ptr(fe(1))) && len(wlist) < W {
					wlist = append(wlist, Withdrawal{Recipient: b.recipients[len(wlist)], Amount: mv.amount.Uint64()})
				}
				wCount = add(wCount, eW)
			}
			aux := add(mv.pk, mul(eW, rcSel)) // a withdrawal's aux is its recipient commitment

			debit := mul(val, mv.amount)
			dUsd := mul(debit, mv.asset)
			dQor := sub(debit, dUsd)
			wt.Moves[m].IsTransfer, wt.Moves[m].IsWithdraw, wt.Moves[m].IsRegister = bigOf(mv.transfer), bigOf(mv.withdraw), bigOf(mv.register)
			wt.Moves[m].Asset, wt.Moves[m].Amount, wt.Moves[m].PkCommit = bigOf(mv.asset), bigOf(mv.amount), bigOf(aux)
			wt.Moves[m].Atomic, wt.Moves[m].Skip = bigOf(mv.atomic), bigOf(mv.skip)
			wt.Moves[m].From = update(mv.from, func(f [5]fr.Element) [5]fr.Element {
				return [5]fr.Element{add(f[0], mul(eR, aux)), sub(f[1], dQor), sub(f[2], dUsd), f[3], f[4]}
			})
			credit := mul(eT, mv.amount)
			cUsd := mul(credit, mv.asset)
			cQor := sub(credit, cUsd)
			wt.Moves[m].To = update(mv.to, func(f [5]fr.Element) [5]fr.Element {
				return [5]fr.Element{f[0], add(f[1], cQor), add(f[2], cUsd), f[3], f[4]}
			})

			// what applied (the record) and what was written (the digest)
			code := add(add(eT, mul(fe(2), eW)), mul(fe(3), eR))
			recMoves = append(recMoves, code, mul(mv.asset, val), mul(mv.amount, val), mul(fe(uint64(mv.from)), effAny), mul(fe(uint64(mv.to)), eT), mul(aux, add(eR, eW)))
			if m > 0 {
				pVal := add(mv.transfer, mv.withdraw)
				pAny := add(pVal, mv.register)
				pCode := add(add(mv.transfer, mul(fe(2), mv.withdraw)), mul(fe(3), mv.register))
				digestActs = append(digestActs, pCode, mul(mv.asset, pVal), mul(mv.amount, pVal), mul(fe(uint64(mv.from)), pAny), mul(fe(uint64(mv.to)), mv.transfer), aux, mv.atomic)
			}
		}
		feeAsset := mul(tx.moves[0].asset, tx.moves[0].transfer)
		dfields := []fr.Element{fe(DigestTag), DomainConst(cfg.ChainID, cfg.RollupID), signedSender, senderOld[3], tx.expiry, tx.notBefore, fe(uint64(tx.moves[0].from)), feeAsset, maxFee}
		dfields = append(dfields, partyFields...)
		dfields = append(dfields, digestActs...)
		var digest fr.Element
		for _, f := range dfields {
			digest = Compress(digest, f)
		}
		fields := []fr.Element{fe(TxRecordTag), digest, fe(uint64(tx.sender)), senderOld[3], tx.expiry, tx.notBefore}
		fields = append(fields, partyFields...)
		fields = append(fields, recMoves...)
		var h fr.Element
		for _, f := range fields {
			h = Compress(h, f)
		}
		recLeaves[i] = mul(tx.active, h)
	}

	txRoot := TxRoot(recLeaves)
	w.Log = update(logIdx, func([5]fr.Element) [5]fr.Element { return [5]fr.Element{txRoot, {}, {}, add(n, fe(1)), {}} })

	w.PrevStateRoot = bigOf(prev)
	w.StateRoot = bigOf(rt.root())
	w.SetDataHash([32]byte{9})
	// the withdrawals root the circuit expects: the tree over the filled slots when 1..W were made, else 0
	wc := uint64(math.MaxUint32)
	if wCount.IsUint64() {
		wc = wCount.Uint64()
	}
	var root [32]byte
	if wc >= 1 && wc <= uint64(W) {
		root = WithdrawalsRoot(cfg.ChainID, cfg.RollupID, wlist)
	}
	w.WithdrawalsRoot = ModR(root)
	for k := range w.Recipients {
		for j := range w.Recipients[k] {
			w.Recipients[k][j] = 0
		}
		if s, ok := b.recipients[k]; ok {
			for j := 0; j < RecipientLen && j < len(s); j++ {
				w.Recipients[k][j] = int(s[j])
			}
		}
	}
	return w
}

func ptr(e fr.Element) *fr.Element { return &e }

// ---- tests ----

var maxU64Fe = fe(math.MaxUint64)

// oneTx is a single active tx from sender: the given moves (fee move first), the rest no-ops. The no-ops sit on
// the treasury (account 0), never on the sender or the parties: a no-op re-checks the balance of the account it
// touches, so a no-op on an account a test has just corrupted would reject the witness for a second reason.
func oneTx(cfg Config, sender uint32, moves ...advMove) advBatch {
	all := make([]advMove, cfg.Moves)
	for m := range all {
		all[m] = noopMove(treas)
		if m < len(moves) {
			all[m] = moves[m]
		}
	}
	return advBatch{txs: []advTx{{active: fe(1), sender: sender, expiry: maxU64Fe, moves: all}}}
}

func transferMove(from, to uint32, asset, amount fr.Element) advMove {
	return advMove{transfer: fe(1), asset: asset, amount: amount, from: from, to: to}
}

// state after batch 0: alice 1,000,000 QOR and 500 USD, bob 1,000,000 QOR and 900 USD, carol 1,000,000 QOR, no keys.
func advSetup(t *testing.T, cfg Config) (*Tree, *rawTree) {
	t.Helper()
	tree := fundedTree(t, cfg)
	return tree, newRawTree(tree)
}

func mustSolve(t *testing.T, cfg Config, w *Circuit, what string) {
	t.Helper()
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("%s: the adversarial builder's own witness must satisfy the circuit: %v", what, err)
	}
}

// The builder is only useful if it agrees with the honest one: same state root, and the circuit accepts it.
func TestAdversarialBuilderAgreesWithTheHonestBuilder(t *testing.T) {
	cfg := testConfig()
	tree, rt := advSetup(t, cfg)
	honest := tree.Clone()
	_, res, err := Build(cfg, honest, false, Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Fee: 1,
		Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 5}}}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w := advBuild(t, cfg, rt, oneTx(cfg, alice,
		transferMove(alice, relay, fe(0), fe(1)), // the fee
		transferMove(alice, bob, fe(0), fe(5))))
	mustSolve(t, cfg, w, "honest transfer")
	got := rt.root()
	if !got.Equal(&res.NewRoot) {
		t.Fatalf("the adversarial builder's root %s differs from the honest builder's %s", HexElem(got), HexElem(res.NewRoot))
	}
}

func TestAdversarialBuilderAcceptsAnHonestWithdrawal(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	w := advBuild(t, cfg, rt, advBatch{
		txs: oneTx(cfg, alice,
			transferMove(alice, relay, fe(0), fe(1)),
			advMove{withdraw: fe(1), amount: fe(10), from: alice, to: alice}).txs,
		recipients: map[int]string{0: l1Addr},
	})
	mustSolve(t, cfg, w, "honest withdrawal")
}

func TestRejectNonBooleanTxActiveFlag(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	b := oneTx(cfg, alice) // only no-ops, so no other rule is touched
	b.txs[0].active = fe(2)
	b.txs[0].expiry = fe(1000) // 2·(expiry-n) must stay below 2^64, or the window check would reject it first
	w := advBuild(t, cfg, rt, b)
	mustFail(t, cfg, w, "a tx Active flag of 2 (nonce would move by 2, record scaled by 2)")
}

func TestRejectNonBooleanMoveKindFlag(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// transfer = 2 and register = -1 sum to 1, so "at most one kind" holds; only the per-flag boolean rule can reject it
	w := advBuild(t, cfg, rt, oneTx(cfg, alice,
		noopMove(treas),
		advMove{transfer: fe(2), register: feNeg(1), pk: fe(7), amount: fe(10), from: alice, to: bob}))
	mustFail(t, cfg, w, "kind flags 2 and -1 that sum to 1")
}

func TestRejectNonBooleanAssetFlag(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	w := advBuild(t, cfg, rt, oneTx(cfg, alice,
		noopMove(treas),
		advMove{transfer: fe(1), asset: fe(2), amount: fe(5), from: alice, to: bob}))
	mustFail(t, cfg, w, "asset 2 (neither QOR nor USD)")
}

func TestRejectAMoveWithTwoKinds(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// transfer and withdraw at once: each flag is boolean, only the sum is not
	w := advBuild(t, cfg, rt, advBatch{
		txs: oneTx(cfg, alice,
			noopMove(treas),
			advMove{transfer: fe(1), withdraw: fe(1), amount: fe(10), from: alice, to: bob}).txs,
		recipients: map[int]string{0: l1Addr},
	})
	mustFail(t, cfg, w, "one move that is both a transfer and a withdrawal")
}

func TestRejectAFeeMoveThatWithdraws(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// the fee move debits the payer but fills no withdrawal slot: the funds would simply vanish
	w := advBuild(t, cfg, rt, oneTx(cfg, alice, advMove{withdraw: fe(1), amount: fe(7), from: alice, to: alice}))
	mustFail(t, cfg, w, "a fee move used as a withdrawal")
}

func TestRejectAFeeMoveThatRegistersAKey(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// the fee move is not tied to the sender, so it could set a key on any key-less account (here an empty leaf)
	const victim = 40000
	w := advBuild(t, cfg, rt, oneTx(cfg, alice, advMove{register: fe(1), pk: fe(9), from: victim, to: victim}))
	mustFail(t, cfg, w, "a fee move used to register a key on someone else's account")
}

func TestRejectANegativeAmount(t *testing.T) {
	cfg := testConfig()
	_, rt := advSetup(t, cfg)
	// amount = -5 (r-5): "alice sends bob -5" makes alice richer and bob poorer, with every balance still in range
	w := advBuild(t, cfg, rt, oneTx(cfg, alice,
		noopMove(treas),
		transferMove(alice, bob, fe(0), feNeg(5))))
	mustFail(t, cfg, w, "a transfer of a negative amount (theft from the receiver)")
}

func TestRejectOverdraftWithAConsistentWitness(t *testing.T) {
	for name, tc := range map[string]struct {
		asset  fr.Element
		amount uint64
	}{
		"qor": {fe(0), 2_000_000}, // alice has 1,000,000 QOR
		"usd": {fe(1), 600},       // alice has 500 USD
	} {
		cfg := testConfig()
		_, rt := advSetup(t, cfg)
		w := advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), transferMove(alice, bob, tc.asset, fe(tc.amount))))
		mustFail(t, cfg, w, "a balance that goes negative and wraps around the field ("+name+")")
	}
}

func TestRejectCreditOverflow(t *testing.T) {
	for name, asset := range map[string]fr.Element{"qor": fe(0), "usd": fe(1)} {
		cfg := testConfig()
		tree := fundedTree(t, cfg)
		b := tree.Get(bob)
		if name == "qor" {
			b.Qor = math.MaxUint64
		} else {
			b.Usd = math.MaxUint64
		}
		tree.Set(bob, b)
		rt := newRawTree(tree)
		w := advBuild(t, cfg, rt, oneTx(cfg, alice, noopMove(alice), transferMove(alice, bob, asset, fe(2))))
		mustFail(t, cfg, w, "a credit that pushes the receiver's balance past 2^64 ("+name+")")
	}
}

func TestRejectMoreWithdrawalsThanSlots(t *testing.T) {
	cfg := testConfig()
	cfg.Withdrawals = 1
	_, rt := advSetup(t, cfg)
	// two withdrawals into one slot: the second debits alice but no withdrawal leaf is ever paid
	w := advBuild(t, cfg, rt, advBatch{
		txs: oneTx(cfg, alice,
			noopMove(treas),
			advMove{withdraw: fe(1), amount: fe(10), from: alice, to: alice},
			advMove{withdraw: fe(1), amount: fe(20), from: alice, to: alice}).txs,
		recipients: map[int]string{0: l1Addr},
	})
	mustFail(t, cfg, w, "two withdrawals with one withdrawal slot")
}

func TestRejectAFeeThatDoesNotPayTheRelayer(t *testing.T) {
	cfg := testConfig()
	// control: the same fee paid to the configured relayer is accepted
	_, rt := advSetup(t, cfg)
	mustSolve(t, cfg, advBuild(t, cfg, rt, oneTx(cfg, alice, transferMove(alice, relay, fe(0), fe(10)))), "a fee paid to the relayer")
	// a sequencer pointing the fee at an account it controls
	_, rt = advSetup(t, cfg)
	w := advBuild(t, cfg, rt, oneTx(cfg, alice, transferMove(alice, carol, fe(0), fe(10))))
	mustFail(t, cfg, w, "a fee paid to an account other than the configured relayer")
}

func TestCheckedBuilderAndConfigRefuseAnotherRelayer(t *testing.T) {
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	tx := TxIn{Sender: alice, Payer: alice, Relayer: carol, Fee: 1, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}
	if _, _, err := Build(cfg, tree, false, Batch{Txs: []TxIn{tx}}, Options{}); err == nil {
		t.Fatal("the checked builder accepted a tx whose relayer is not the configured one")
	}
	bad := testConfig()
	bad.Relayer = LogIndex(bad.Depth)
	if bad.Validate() == nil {
		t.Fatal("the reserved log leaf was accepted as the relayer account")
	}
}
