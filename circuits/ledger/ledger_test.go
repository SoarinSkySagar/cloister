package ledger

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

const (
	alice  = 5
	bob    = 6
	relay  = 1
	treas  = 0
	l1Addr = "qor12jmzemjntpkfr4ler3rdwpemrv3qg7pzxkpxkm"
)

func testConfig() Config {
	return Config{
		Depth: 16, Txs: 4, Moves: 3, Withdrawals: 4, Parties: 3, Relayer: relay,
		ChainID: "qorechain-diana", RollupID: "cloister",
		Genesis: []GenesisAccount{
			{Index: treas, Pk: "01", Qor: 1_000_000_000_000, Usd: 1_000_000_000_000},
			{Index: relay, Pk: "02"},
		},
	}
}

// batch1 funds alice from the treasury (genesis -> state 1).
var batch1 = Batch{Txs: []TxIn{
	{Sender: treas, Payer: treas, Relayer: relay, Actions: []ActionIn{
		{Kind: "transfer", To: alice, Asset: 0, Amount: 1_000_000},
		{Kind: "transfer", To: alice, Asset: 1, Amount: 500_000},
	}},
	// sponsored onboarding: the treasury pays alice's fee
	{Sender: alice, Payer: treas, Relayer: relay, Fee: 10, Actions: []ActionIn{
		{Kind: "register_key", PkCommit: "55"},
	}},
}}

// batch2 exercises sponsorship, an atomic pair, withdrawals and a skipped action.
var batch2 = Batch{Txs: []TxIn{
	{Sender: alice, Payer: treas, Relayer: relay, Fee: 10, Actions: []ActionIn{
		{Kind: "transfer", To: bob, Amount: 100, Atomic: true},
		{Kind: "withdraw", Recipient: l1Addr, Amount: 200, Atomic: true},
	}},
	{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, Actions: []ActionIn{
		{Kind: "withdraw", Recipient: l1Addr, Amount: 50},
		{Kind: "transfer", To: bob, Amount: 1 << 40}, // insufficient: skipped
	}},
	{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
		{Kind: "transfer", To: bob, Asset: 1, Amount: 7},
		{Kind: "withdraw", Recipient: l1Addr, Amount: 1},
	}},
}}

func field() *big.Int { return ecc.BLS12_381.ScalarField() }

func build(t *testing.T, cfg Config, b Batch, opts Options) (*Circuit, *Result, *Tree) {
	t.Helper()
	tree, err := GenesisTree(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Build(cfg, tree, true, batch1, Options{}); err != nil {
		t.Fatal(err)
	}
	w, res, err := Build(cfg, tree, false, b, opts)
	if err != nil {
		t.Fatal(err)
	}
	w.SetDataHash([32]byte{0xde, 0xad})
	return w, res, tree
}

func solves(t *testing.T, cfg Config, w *Circuit) error {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return test.IsSolved(c, w, field())
}

func mustFail(t *testing.T, cfg Config, w *Circuit, what string) {
	t.Helper()
	err := solves(t, cfg, w)
	if err == nil {
		t.Fatalf("invalid witness accepted: %s", what)
	}
	t.Logf("%s: %s", what, firstLine(err.Error()))
}

func TestGenesisBatch(t *testing.T) {
	cfg := testConfig()
	tree, _ := GenesisTree(cfg)
	w, res, err := Build(cfg, tree, true, batch1, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.SetDataHash([32]byte{1})
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("valid genesis batch rejected: %v", err)
	}
	a := tree.Get(alice)
	if a.Qor != 1_000_000-10 && a.Qor != 1_000_000 {
		t.Fatalf("alice qor %d", a.Qor)
	}
	if a.Nonce != 1 || a.Pk.IsZero() || len(res.Withdrawals) != 0 {
		t.Fatalf("alice %+v, withdrawals %d", a, len(res.Withdrawals))
	}
}

func TestValidBatch(t *testing.T) {
	cfg := testConfig()
	w, res, tree := build(t, cfg, batch2, Options{})
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
	if len(res.Withdrawals) != 3 {
		t.Fatalf("withdrawals %d", len(res.Withdrawals))
	}
	if !res.Txs[0].Applied[0] || !res.Txs[0].Applied[1] || res.Txs[1].Applied[1] || len(res.Txs[1].Skipped) != 1 {
		t.Fatalf("results %+v", res.Txs)
	}
	a, b := tree.Get(alice), tree.Get(bob)
	if a.Qor != 1_000_000-100-200-1-50-1 || a.Usd != 500_000-7 || a.Nonce != 4 || b.Qor != 100 || b.Usd != 7 {
		t.Fatalf("alice %+v bob %+v", a, b)
	}
	// conservation: total QOR = genesis - withdrawn
	var total, out uint64
	for _, acc := range tree.accounts {
		total += acc.Qor
	}
	for _, x := range res.Withdrawals {
		out += x.Amount
	}
	if total+out != 1_000_000_000_000 {
		t.Fatalf("QOR not conserved: %d + %d", total, out)
	}
}

func TestEveryWithdrawalCount(t *testing.T) {
	cfg := testConfig()
	for n := 0; n <= 4; n++ {
		var b Batch
		for i := 0; i < n; i++ {
			b.Txs = append(b.Txs, TxIn{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
				{Kind: "withdraw", Recipient: l1Addr, Amount: uint64(10 + i)},
			}})
		}
		w, res, _ := build(t, cfg, b, Options{})
		if len(res.Withdrawals) != n {
			t.Fatalf("n=%d: got %d", n, len(res.Withdrawals))
		}
		if err := solves(t, cfg, w); err != nil {
			t.Fatalf("n=%d rejected: %v", n, err)
		}
	}
}

func TestDevRollupIDTwoBlockLeaves(t *testing.T) {
	cfg := testConfig()
	cfg.RollupID = "cloister-dev-2"
	w, _, _ := build(t, cfg, batch2, Options{})
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("rejected: %v", err)
	}
}

// ---- negative tests: one per rule ----

func TestRejectWrongStateRoot(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.StateRoot = new(big.Int).Add(w.StateRoot.(*big.Int), big.NewInt(1))
	mustFail(t, cfg, w, "wrong state_root")
}

func TestRejectWrongPrevRoot(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.PrevStateRoot = new(big.Int).Add(w.PrevStateRoot.(*big.Int), big.NewInt(1))
	mustFail(t, cfg, w, "wrong prev_state_root")
}

func TestRejectWrongWithdrawalsRoot(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.WithdrawalsRoot = new(big.Int).Add(w.WithdrawalsRoot.(*big.Int), big.NewInt(1))
	mustFail(t, cfg, w, "wrong withdrawals_root")
}

func TestRejectChangedRecipient(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Recipients[0][10] = int('z')
	mustFail(t, cfg, w, "recipient changed after the root was computed")
}

func TestRejectWrongDataHashSquare(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.DataHashSq = 3
	mustFail(t, cfg, w, "data_hash binding")
}

func TestRejectOverdraft(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: bob, Payer: bob, Relayer: relay, Actions: []ActionIn{
		{Kind: "transfer", To: alice, Amount: 1},
	}}}}
	w, _, _ := build(t, cfg, b, Options{Unchecked: true})
	mustFail(t, cfg, w, "negative balance")
}

func TestRejectFeeOverdraft(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: bob, Payer: bob, Relayer: relay, Fee: 5}}}
	w, _, _ := build(t, cfg, b, Options{Unchecked: true})
	mustFail(t, cfg, w, "fee payer goes negative")
}

func TestRejectUsdWithdrawal(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
		{Kind: "withdraw", Asset: 1, Recipient: l1Addr, Amount: 5},
	}}}}
	w, _, _ := build(t, cfg, b, Options{Unchecked: true})
	mustFail(t, cfg, w, "USD withdrawal")
}

func TestRejectKeyOverwrite(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
		{Kind: "register_key", PkCommit: "66"},
	}}}}
	w, _, _ := build(t, cfg, b, Options{Unchecked: true})
	mustFail(t, cfg, w, "overwriting a registered key")
}

func TestRejectEmptyKey(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: bob, Payer: treas, Relayer: relay, Actions: []ActionIn{
		{Kind: "register_key", PkCommit: "00"},
	}}}}
	w, _, _ := build(t, cfg, b, Options{Unchecked: true})
	mustFail(t, cfg, w, "registering an empty key")
}

func TestRejectActionFromOtherAccount(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: bob, Payer: treas, Relayer: relay, Actions: []ActionIn{
		{Kind: "transfer", To: bob, Amount: 1},
	}}}}
	// the checked builder refuses this tx (see TestCheckedBuilderRefusesNonPartyDebit); an unchecked witness must fail in the circuit
	w, _, _ := build(t, cfg, b, Options{Unchecked: true, FromOverride: map[[2]int]uint32{{0, 0}: alice}})
	mustFail(t, cfg, w, "action debiting an account other than the sender or a party")
}

func TestRejectTooManyWithdrawals(t *testing.T) {
	cfg := testConfig()
	var b Batch
	for i := 0; i < 3; i++ {
		b.Txs = append(b.Txs, TxIn{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
			{Kind: "withdraw", Recipient: l1Addr, Amount: 1},
			{Kind: "withdraw", Recipient: l1Addr, Amount: 1},
		}})
	}
	w, res, _ := build(t, cfg, b, Options{Unchecked: true})
	if len(res.Withdrawals) != 6 {
		t.Fatalf("setup: %d withdrawals", len(res.Withdrawals))
	}
	mustFail(t, cfg, w, "more withdrawals than slots")
}

func TestCheckedBuilderSkipsFifthWithdrawal(t *testing.T) {
	cfg := testConfig()
	var b Batch
	for i := 0; i < 3; i++ {
		b.Txs = append(b.Txs, TxIn{Sender: alice, Payer: alice, Relayer: relay, Actions: []ActionIn{
			{Kind: "withdraw", Recipient: l1Addr, Amount: 1},
			{Kind: "withdraw", Recipient: l1Addr, Amount: 1},
		}})
	}
	w, res, _ := build(t, cfg, b, Options{})
	if len(res.Withdrawals) != 4 || !strings.Contains(strings.Join(res.Txs[2].Skipped, ";"), "slots are full") {
		t.Fatalf("got %d withdrawals, %+v", len(res.Withdrawals), res.Txs[2])
	}
	if err := solves(t, cfg, w); err != nil {
		t.Fatal(err)
	}
}

func TestRejectTamperedAmount(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Moves[1].Amount = 101 // the tree was updated with 100
	mustFail(t, cfg, w, "amount differs from the state change")
}

func TestRejectForgedOldLeaf(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Moves[1].From.Old.Qor = uint64(1 << 50) // claim a bigger balance
	mustFail(t, cfg, w, "old leaf not in the tree")
}

func TestRejectNonceNotIncremented(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Active = 0 // keeps the actions but would skip the nonce bump
	mustFail(t, cfg, w, "actions in an inactive tx / nonce not bumped")
}

func TestRejectWithdrawInFeeMove(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Moves[0].IsTransfer = 0
	w.Txs[0].Moves[0].IsWithdraw = 1
	mustFail(t, cfg, w, "fee move used as a withdrawal")
}

func TestRejectTwoKindsInOneMove(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Moves[1].IsWithdraw = 1 // already a transfer
	mustFail(t, cfg, w, "move with two kinds")
}

func TestRejectNonBooleanFlag(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Moves[1].IsTransfer = 2
	mustFail(t, cfg, w, "non-boolean kind flag")
}

func TestRejectAmountOver64Bits(t *testing.T) {
	cfg := testConfig()
	w, _, _ := build(t, cfg, batch2, Options{})
	w.Txs[0].Moves[1].Amount = new(big.Int).Lsh(big.NewInt(1), 64)
	mustFail(t, cfg, w, "amount over 64 bits")
}

func TestRejectBatch0NotFromGenesis(t *testing.T) {
	cfg := testConfig()
	tree, _ := GenesisTree(cfg)
	tree.Set(9, Account{Qor: 1_000_000}) // minted out of thin air
	w, _, err := Build(cfg, tree, true, batch1, Options{Unchecked: true})
	if err != nil {
		t.Fatal(err)
	}
	w.SetDataHash([32]byte{1})
	mustFail(t, cfg, w, "batch 0 starting from a non-genesis state")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// The next two tests exist because mutation checking showed the older tests rejected their witnesses for another
// reason (a root that no longer matched), not by the rule they were named after. These witnesses are consistent in
// every other respect, so only the rule under test can reject them.

func TestRejectKeyOverwriteWithAConsistentWitness(t *testing.T) {
	cfg := testConfig()
	// alice already has a key after batch1; replacing it must be impossible, even with a witness that sums to the new key
	b := Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, Actions: []ActionIn{
		{Kind: "register_key", PkCommit: "77"}}}}}
	w, _, tree := build(t, cfg, b, Options{Unchecked: true, OverwriteKeys: true})
	if got := tree.Get(alice).Pk; got.IsZero() {
		t.Fatal("test setup: alice should end up with a key")
	}
	mustFail(t, cfg, w, "replacing an existing key with a witness that sums to the new key")
}

func TestRejectActionsInAnInactiveTxWithAConsistentWitness(t *testing.T) {
	cfg := testConfig()
	b := Batch{Txs: []TxIn{{Sender: alice, Payer: alice, Relayer: relay, Fee: 1, Actions: []ActionIn{
		{Kind: "transfer", To: bob, Amount: 5}}}}}
	// control: the same tx, active, is valid
	w, _, _ := build(t, cfg, b, Options{Unchecked: true})
	if err := solves(t, cfg, w); err != nil {
		t.Fatalf("control witness must be valid: %v", err)
	}
	// free action: inactive (no nonce bump) but the transfer still applies
	w, _, tree := build(t, cfg, b, Options{Unchecked: true, FreeActions: map[int]bool{0: true}})
	if tree.Get(bob).Qor != 5+1 && tree.Get(bob).Qor != 5 {
		t.Fatalf("test setup: the transfer should have applied, bob has %d", tree.Get(bob).Qor)
	}
	mustFail(t, cfg, w, "an inactive tx that still applies actions (a replayable free action)")
}
