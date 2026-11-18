package ledger

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	carol  = 7
	dave   = 8
	farFut = uint64(1) << 40
)

func u32(v uint32) *uint32  { return &v }
func u64p(v uint64) *uint64 { return &v }

// fundedConfig gives alice, bob and carol balances through the shared batch1/batch2 helpers' tree.
func fundedTree(t *testing.T, cfg Config) *Tree {
	t.Helper()
	tree, err := GenesisTree(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// batch 0: treasury funds alice, bob and carol, and registers their keys
	b0 := Batch{Txs: []TxIn{
		{Sender: treas, Payer: treas, Relayer: relay, Actions: []ActionIn{
			{Kind: "transfer", To: alice, Asset: 0, Amount: 1_000_000, Atomic: true},
			{Kind: "transfer", To: alice, Asset: 1, Amount: 500, Atomic: true},
		}},
		{Sender: treas, Payer: treas, Relayer: relay, Actions: []ActionIn{
			{Kind: "transfer", To: bob, Asset: 0, Amount: 1_000_000, Atomic: true},
			{Kind: "transfer", To: bob, Asset: 1, Amount: 900, Atomic: true},
		}},
		{Sender: treas, Payer: treas, Relayer: relay, Actions: []ActionIn{
			{Kind: "transfer", To: carol, Asset: 0, Amount: 1_000_000},
		}},
	}}
	if _, _, err := Build(cfg, tree, true, b0, Options{}); err != nil {
		t.Fatal(err)
	}
	return tree
}

func solveBuilt(t *testing.T, cfg Config, tree *Tree, b Batch, opts Options) (*Circuit, *Result, error) {
	t.Helper()
	w, res, err := Build(cfg, tree, false, b, opts)
	if err != nil {
		return nil, nil, err
	}
	w.SetDataHash([32]byte{7})
	return w, res, nil
}

// alice swaps 300 USD for bob's 400 QOR in one atomic tx. Bob is a party: his debit needs no tx of his own.
var swap = TxIn{Sender: alice, Payer: treas, Relayer: relay, Fee: 10, Parties: []uint32{bob}, Actions: []ActionIn{
	{Kind: "transfer", From: u32(alice), To: bob, Asset: 1, Amount: 300, Atomic: true},
	{Kind: "transfer", From: u32(bob), To: alice, Asset: 0, Amount: 400, Atomic: true},
}}

func TestTwoPartyAtomicSwap(t *testing.T) {
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	w, res, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{swap}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("valid two-party swap rejected: %v", err)
	}
	if !res.Txs[0].Applied[0] || !res.Txs[0].Applied[1] {
		t.Fatalf("swap not applied: %+v", res.Txs[0])
	}
	a, b := tree.Get(alice), tree.Get(bob)
	if a.Usd != 200 || a.Qor != 1_000_400 || b.Usd != 1_200 || b.Qor != 999_600 {
		t.Fatalf("alice %+v bob %+v", a, b)
	}
	if a.Nonce != 1 || b.Nonce != 0 {
		t.Fatalf("only the sender's nonce moves: alice %d bob %d", a.Nonce, b.Nonce)
	}
	if got := res.Records[0].Parties; len(got) != 1 || got[0] != bob {
		t.Fatalf("record parties %v", got)
	}
}

func TestSwapIsAllOrNothing(t *testing.T) {
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	broke := swap
	broke.Actions = []ActionIn{
		{Kind: "transfer", From: u32(alice), To: bob, Asset: 1, Amount: 300, Atomic: true},
		{Kind: "transfer", From: u32(bob), To: alice, Asset: 0, Amount: 5_000_000, Atomic: true}, // bob cannot pay
	}
	w, res, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{broke}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := solves(t, cfg, w); err != nil {
		t.Fatal(err)
	}
	if res.Txs[0].Applied[0] || res.Txs[0].Applied[1] {
		t.Fatalf("a leg applied although the other failed: %+v", res.Txs[0])
	}
	if a := tree.Get(alice); a.Usd != 500 || a.Qor != 1_000_000 {
		t.Fatalf("alice lost value %+v", a)
	}
	// the fee is still charged and the nonce still moves
	if tree.Get(alice).Nonce != 1 {
		t.Fatal("nonce must move even when every action fails")
	}
	// the record shows what applied: no legs
	for _, m := range res.Records[0].Moves[1:] {
		if m.Code != MoveNone {
			t.Fatalf("record shows a skipped leg: %+v", m)
		}
	}
}

func TestPartyCanWithdrawAndThreeActionsFit(t *testing.T) {
	cfg := testConfig()
	cfg.Moves = 4 // fee + 3 actions
	tree := fundedTree(t, cfg)
	tx := TxIn{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, Parties: []uint32{bob, carol}, Actions: []ActionIn{
		{Kind: "transfer", From: u32(carol), To: alice, Asset: 0, Amount: 11, Atomic: true},
		{Kind: "withdraw", From: u32(bob), Recipient: l1Addr, Amount: 22, Atomic: true},
		{Kind: "transfer", From: u32(alice), To: carol, Asset: 1, Amount: 33, Atomic: true},
	}}
	w, res, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{tx}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("three-party, three-action tx rejected: %v", err)
	}
	if len(res.Withdrawals) != 1 || res.Withdrawals[0].Amount != 22 {
		t.Fatalf("withdrawals %+v", res.Withdrawals)
	}
	if got := tree.Get(bob).Qor; got != 1_000_000-22 {
		t.Fatalf("the party's balance funded the withdrawal: %d", got)
	}
}

func TestCheckedBuilderRefusesBadAuthAndParties(t *testing.T) {
	cfg := testConfig()
	cases := map[string]TxIn{
		"debit of a non-party": {Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
			{Kind: "transfer", From: u32(bob), To: alice, Amount: 1}}},
		"register_key for someone else": {Sender: alice, Payer: alice, Relayer: relay, Parties: []uint32{bob}, Actions: []ActionIn{
			{Kind: "register_key", From: u32(bob), PkCommit: "99"}}},
		"party equals sender":    {Sender: alice, Payer: alice, Relayer: relay, Parties: []uint32{alice}, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}},
		"duplicate party":        {Sender: alice, Payer: alice, Relayer: relay, Parties: []uint32{bob, bob}, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}},
		"too many parties":       {Sender: alice, Payer: alice, Relayer: relay, Parties: []uint32{1, 2, 3, 4}, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}},
		"party is the log leaf":  {Sender: alice, Payer: alice, Relayer: relay, Parties: []uint32{LogIndex(16)}, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}},
		"credit to the log leaf": {Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{{Kind: "transfer", To: LogIndex(16), Amount: 1}}},
	}
	for name, tx := range cases {
		tree := fundedTree(t, cfg)
		if _, _, err := Build(cfg, tree, false, Batch{Txs: []TxIn{tx}}, Options{}); err == nil {
			t.Errorf("%s: accepted by the checked builder", name)
		}
	}
}

// ---- negative tests: the circuit must reject these witnesses on its own ----

func swapWitness(t *testing.T) (Config, *Circuit) {
	t.Helper()
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{swap}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, w
}

func TestRejectPartyLegWithPartySlotDisabled(t *testing.T) {
	cfg, w := swapWitness(t)
	w.Txs[0].PartyActive[0] = 0 // bob's leg is applied but bob is no longer a listed party
	mustFail(t, cfg, w, "debit of an account whose party slot is inactive")
}

func TestRejectPartyLegByDifferentAccount(t *testing.T) {
	cfg, w := swapWitness(t)
	w.Txs[0].Party[0] = carol // the slot now names carol, but bob is debited
	mustFail(t, cfg, w, "debit of an account other than the listed party")
}

func TestRejectUnlistedPartyAddedLater(t *testing.T) {
	// a party the sequencer did not commit to cannot be slipped in: the record (and so the tx root) changes
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	tx := swap
	w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{tx}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.Txs[0].PartyActive[1], w.Txs[0].Party[1] = 1, carol
	mustFail(t, cfg, w, "extra party changes the committed tx root")
}

func TestRejectRegisterKeyOnAPartyAccount(t *testing.T) {
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	tree.Set(dave, Account{Qor: 5}) // an account without a key
	tx := TxIn{Sender: alice, Payer: alice, Relayer: relay, Parties: []uint32{dave}, Actions: []ActionIn{
		{Kind: "register_key", From: u32(dave), PkCommit: "99"}}}
	w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{tx}}, Options{Unchecked: true})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, cfg, w, "register_key on a party's account")
}

func TestWindowBoundaries(t *testing.T) {
	cfg := testConfig()
	// the fixture's next batch is batch 1
	for name, tc := range map[string]struct {
		notBefore uint64
		expiry    *uint64
		ok        bool
	}{
		"exactly at not_before":     {1, nil, true},
		"exactly at expiry":         {0, u64p(1), true},
		"both bounds on this batch": {1, u64p(1), true},
		"one batch too early":       {2, nil, false},
		"expired one batch ago":     {0, u64p(0), false},
		"far future":                {farFut, nil, false},
	} {
		tree := fundedTree(t, cfg)
		tx := TxIn{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, NotBefore: tc.notBefore, Expiry: tc.expiry,
			Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}
		_, _, err := Build(cfg, tree, false, Batch{Txs: []TxIn{tx}}, Options{})
		if tc.ok != (err == nil) {
			t.Errorf("%s: checked builder err=%v, want ok=%v", name, err, tc.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "window") {
			t.Errorf("%s: refusal should name the window: %v", name, err)
		}
		// an unchecked witness outside the window must be rejected by the circuit itself
		tree = fundedTree(t, cfg)
		w, _, e2 := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{tx}}, Options{Unchecked: true})
		if e2 != nil {
			t.Fatal(e2)
		}
		got := solves(t, cfg, w)
		if tc.ok && got != nil {
			t.Errorf("%s: valid window rejected: %v", name, got)
		}
		if !tc.ok && got == nil {
			t.Errorf("%s: circuit accepted a tx outside its window", name)
		}
	}
}

// consistentTweak changes one field of tx slot's record in the witness and recomputes the batch's
// state root to match, so the circuit is asked only about the tweaked value (not a root mismatch).
func consistentTweak(t *testing.T, cfg Config, tree *Tree, res *Result, w *Circuit, slot, field int, val *big.Int) {
	t.Helper()
	fields := res.Records[slot].Fields(cfg.Parties)
	fields[field].SetBigInt(val)
	var h fr.Element
	for _, f := range fields {
		h = Compress(h, f)
	}
	leaves := make([]fr.Element, cfg.Txs)
	for i, r := range res.Records {
		leaves[i] = RecordLeaf(r, cfg.Parties)
	}
	leaves[slot] = h
	log := LogIndex(cfg.Depth)
	root := climb(LogAccount(TxRoot(leaves), res.BatchIndex).LeafHash(), log, tree.Path(log))
	w.StateRoot = root.BigInt(new(big.Int))
}

func plainWitness(t *testing.T) (Config, *Tree, *Result, *Circuit) {
	t.Helper()
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	w, res, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Fee: 1,
		Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("baseline witness must be valid: %v", err)
	}
	return cfg, tree, res, w
}

// Field indexes in a record: 0 tag, 1 sender, 2 nonce_before, 3 expiry, 4 not_before, 5.. parties.
func TestRejectWindowBoundsOver64Bits(t *testing.T) {
	// n is 1 here. expiry = 2^64 leaves expiry - n below 2^64, so only the range check on expiry rejects it.
	cfg, tree, res, w := plainWitness(t)
	big64 := new(big.Int).Lsh(big.NewInt(1), 64)
	w.Txs[0].Expiry = big64
	consistentTweak(t, cfg, tree, res, w, 0, 3, big64)
	mustFail(t, cfg, w, "expiry of exactly 2^64 (only the range check can reject it)")
}

func TestRejectNotBeforeThatWrapsTheField(t *testing.T) {
	// not_before = r-1 makes n - not_before equal n+1 in the field: the lock would be bypassed without the range check.
	cfg, tree, res, w := plainWitness(t)
	wrap := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	w.Txs[0].NotBefore = wrap
	consistentTweak(t, cfg, tree, res, w, 0, 4, wrap)
	mustFail(t, cfg, w, "not_before that wraps around the field")
}

func TestRejectNonBooleanPartyFlag(t *testing.T) {
	// the record would carry 2·(party+1): a non-canonical record. The root is made consistent, so only the boolean check rejects it.
	cfg, tree, res, w := plainWitness(t)
	w.Txs[0].PartyActive[0], w.Txs[0].Party[0] = 2, 9
	consistentTweak(t, cfg, tree, res, w, 0, 5, big.NewInt(2*(9+1)))
	mustFail(t, cfg, w, "non-boolean party flag")
}

func TestRejectLogUpdateAtAnotherIndex(t *testing.T) {
	// a consistent witness in which the "log" is an ordinary account's leaf (empty, so its shape fits)
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	at := uint32(40000)
	w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Fee: 1,
		Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}}}, Options{Unchecked: true, LogAt: &at})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, cfg, w, "the batch counter and tx root written to an ordinary leaf")
}

func TestRejectOldLogLeafThatIsNotLogShaped(t *testing.T) {
	// the state somehow holds a log leaf with a balance or orders: the circuit refuses to build on it
	for name, bad := range map[string]Account{
		"qor":    {Pk: felt(5), Qor: 1, Nonce: 1},
		"usd":    {Pk: felt(5), Usd: 1, Nonce: 1},
		"orders": {Pk: felt(5), Nonce: 1, Orders: felt(3)},
	} {
		cfg := testConfig()
		tree := fundedTree(t, cfg)
		tree.Set(LogIndex(16), bad)
		w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Fee: 1,
			Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 1}}}}}, Options{Unchecked: true})
		if err != nil {
			t.Fatal(err)
		}
		mustFail(t, cfg, w, "old log leaf with "+name)
	}
}

func TestRejectChangedWindowAfterTheFact(t *testing.T) {
	// the window is part of the record: changing it without changing the root fails
	cfg, w := swapWitness(t)
	w.Txs[0].Expiry = uint64(12345)
	mustFail(t, cfg, w, "window changed against the committed tx root")
	cfg, w = swapWitness(t)
	w.Txs[0].NotBefore = uint64(1)
	mustFail(t, cfg, w, "not_before changed against the committed tx root")
}

func TestRejectMoveIntoTheLogLeaf(t *testing.T) {
	cfg := testConfig()
	log := LogIndex(16)
	for name, mk := range map[string]func() TxIn{
		"credit": func() TxIn {
			return TxIn{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, Actions: []ActionIn{{Kind: "transfer", To: log, Amount: 5}}}
		},
		"debit": func() TxIn {
			return TxIn{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, Parties: []uint32{log}, Actions: []ActionIn{{Kind: "transfer", From: u32(log), To: alice, Amount: 0}}}
		},
	} {
		tree := fundedTree(t, cfg)
		w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{mk()}}, Options{Unchecked: true})
		if err != nil {
			t.Fatal(err)
		}
		mustFail(t, cfg, w, "move touching the reserved log leaf ("+name+")")
	}
}

func TestRejectSenderIsTheLogLeaf(t *testing.T) {
	cfg := testConfig()
	tree := fundedTree(t, cfg)
	tx := TxIn{Sender: LogIndex(16), Payer: alice, Relayer: relay, Fee: 1, Actions: []ActionIn{{Kind: "transfer", To: bob, Amount: 0}}}
	w, _, err := solveBuilt(t, cfg, tree, Batch{Txs: []TxIn{tx}}, Options{Unchecked: true})
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, cfg, w, "the log leaf as a tx sender (nonce bump)")
}

func TestRejectForgedBatchCounter(t *testing.T) {
	cfg, w := swapWitness(t)
	w.Log.Old.Nonce = uint64(5) // claim a later batch to widen every window
	mustFail(t, cfg, w, "forged old log leaf (batch counter)")
	cfg, w = swapWitness(t)
	w.Log.Old.Pk = big.NewInt(1234)
	mustFail(t, cfg, w, "forged old tx root")
	cfg, w = swapWitness(t)
	w.Log.Old.Qor = uint64(1)
	mustFail(t, cfg, w, "non-log shaped old leaf")
	cfg, w = swapWitness(t)
	w.Log.Index = uint64(LogIndex(16)) - 1
	mustFail(t, cfg, w, "log update at another index")
}

func TestRejectGenesisAtTheReservedIndex(t *testing.T) {
	cfg := testConfig()
	cfg.Genesis = append(cfg.Genesis, GenesisAccount{Index: LogIndex(16), Pk: "03", Qor: 1})
	if cfg.Validate() == nil {
		t.Fatal("a genesis account at the reserved index was accepted")
	}
	if _, err := GenesisTree(cfg); err == nil {
		t.Fatal("GenesisTree accepted the reserved index")
	}
	bad := testConfig()
	bad.Txs = 3
	if bad.Validate() == nil {
		t.Fatal("a non power-of-two tx slot count was accepted")
	}
	bad = testConfig()
	bad.Parties = 0
	if bad.Validate() == nil {
		t.Fatal("zero party slots accepted")
	}
}

func TestBatchCounterAndInclusionProofs(t *testing.T) {
	cfg := testConfig()
	tree, _ := GenesisTree(cfg)
	_, r0, err := Build(cfg, tree, true, batch1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r0.BatchIndex != 0 || tree.Get(LogIndex(16)).Nonce != 1 {
		t.Fatalf("after batch 0: index %d counter %d", r0.BatchIndex, tree.Get(LogIndex(16)).Nonce)
	}
	w, r1, err := Build(cfg, tree, false, batch2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.SetDataHash([32]byte{1})
	if err := solves(t, cfg, w); err != nil {
		t.Fatal(err)
	}
	if r1.BatchIndex != 1 || tree.Get(LogIndex(16)).Nonce != 2 {
		t.Fatalf("after batch 1: index %d counter %d", r1.BatchIndex, tree.Get(LogIndex(16)).Nonce)
	}
	if len(r1.Proofs) != 3 {
		t.Fatalf("want a proof per included tx, got %d", len(r1.Proofs))
	}
	root := r1.NewRoot
	for _, p := range r1.Proofs {
		got, err := p.StateRoot(cfg.Depth, cfg.Txs, cfg.Parties)
		if err != nil || !got.Equal(&root) {
			t.Fatalf("tx %d: proof does not reach the batch's state root (%v)", p.TxIndex, err)
		}
		moved := p
		moved.BatchIndex++ // the same proof claimed for another batch number
		if got, _ := moved.StateRoot(cfg.Depth, cfg.Txs, cfg.Parties); got.Equal(&root) {
			t.Fatal("a proof can be moved to another batch number")
		}
	}
}

func TestPrevBatchProofsStillVerifyAgainstTheirOwnRoot(t *testing.T) {
	cfg := testConfig()
	tree, _ := GenesisTree(cfg)
	_, r0, err := Build(cfg, tree, true, batch1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Build(cfg, tree, false, batch2, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range r0.Proofs {
		got, err := p.StateRoot(cfg.Depth, cfg.Txs, cfg.Parties)
		if err != nil || !got.Equal(&r0.NewRoot) {
			t.Fatalf("an old batch's proof must verify against that batch's own root (%v)", err)
		}
	}
}
