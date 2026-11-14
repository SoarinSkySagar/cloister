package ledger

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	inclusionVectors = "../../spec/vectors/inclusion.json"
	testParties      = 3
)

func felt(n uint64) fr.Element { var e fr.Element; e.SetUint64(n); return e }

// A fixed scenario: tx 0 is a sponsored transfer, tx 1 a two-party swap plus a self-paid fee, slots 2 and 3 are unused.
func sample(t *testing.T) (records []*TxRecord, tree *Tree, rc fr.Element) {
	t.Helper()
	const recipient = "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu"
	var err error
	rc, err = RecipientCommit(recipient)
	if err != nil {
		t.Fatal(err)
	}
	var zero fr.Element
	dom := DomainConst("qorechain-diana", "cloister-dev-3")
	d0 := TxDigest(dom, 3, 1, 53, 0, 0, 0, 10_000, nil, testParties, []PlannedMove{
		{MoveRecord: NewMoveRecord(MoveTransfer, 0, 1_000_000, 3, 2, zero, zero)}}, 3)
	d1 := TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, []PlannedMove{
		{MoveRecord: NewMoveRecord(MoveTransfer, 1, 5, 2, 3, zero, zero), Atomic: true},
		{MoveRecord: NewMoveRecord(MoveWithdraw, 0, 500_000, 3, 0, zero, rc), Atomic: true}}, 3)
	records = []*TxRecord{
		{Digest: d0, Sender: 3, NonceBefore: 1, Expiry: 53, NotBefore: 0, Moves: []MoveRecord{
			NewMoveRecord(MoveTransfer, 0, 10_000, 0, 1, zero, zero),    // fee: payer 0 -> relayer 1
			NewMoveRecord(MoveTransfer, 0, 1_000_000, 3, 2, zero, zero), // 1 QOR to account 2
			NewMoveRecord(MoveNone, 0, 0, 0, 0, zero, zero),
			NewMoveRecord(MoveNone, 0, 0, 0, 0, zero, zero),
		}},
		{Digest: d1, Sender: 2, NonceBefore: 4, Expiry: 99, NotBefore: 7, Parties: []uint32{3}, Moves: []MoveRecord{
			NewMoveRecord(MoveTransfer, 0, 10_000, 2, 1, zero, zero), // fee: self-paid
			NewMoveRecord(MoveTransfer, 1, 5, 2, 3, zero, zero),      // 2 pays 3 five USD
			NewMoveRecord(MoveWithdraw, 0, 500_000, 3, 0, zero, rc),  // 3 (the party) withdraws 0.5 QOR to L1
			NewMoveRecord(MoveNone, 0, 0, 0, 0, zero, zero),
		}},
		nil, nil,
	}
	tree = NewTree(16)
	for i := uint32(0); i < 4; i++ {
		tree.Set(i, Account{Pk: Compress(felt(uint64(i)+100), felt(7)), Qor: 1_000_000_000 + uint64(i), Usd: 5, Nonce: uint64(i)})
	}
	return
}

func leavesOf(rs []*TxRecord) []fr.Element {
	out := make([]fr.Element, len(rs))
	for i, r := range rs {
		out[i] = RecordLeaf(r, testParties)
	}
	return out
}

const batchNo = 8 // the batch the sample is "in"

func TestInclusionRoundTrip(t *testing.T) {
	rs, tree, _ := sample(t)
	leaves := leavesOf(rs)
	tree.Set(LogIndex(16), LogAccount(TxRoot(leaves), batchNo))
	root := tree.Root()
	for i := 0; i < 2; i++ {
		p := InclusionProof{BatchIndex: batchNo, Record: *rs[i], TxIndex: i, TxPath: TxPath(leaves, i), LogPath: tree.Path(LogIndex(16))}
		got, err := p.StateRoot(16, 4, testParties)
		if err != nil || !got.Equal(&root) {
			t.Fatalf("slot %d: %v root %s want %s", i, err, HexElem(got), HexElem(root))
		}
	}
}

// Negative cases: every way to alter a proof must change the root it commits to (or be refused).
func TestInclusionProofsRefuseTampering(t *testing.T) {
	rs, tree, _ := sample(t)
	leaves := leavesOf(rs)
	tree.Set(LogIndex(16), LogAccount(TxRoot(leaves), batchNo))
	root := tree.Root()
	good := InclusionProof{BatchIndex: batchNo, Record: *rs[1], TxIndex: 1, TxPath: TxPath(leaves, 1), LogPath: tree.Path(LogIndex(16))}
	clone := func() InclusionProof {
		c := good
		c.Record.Moves = append([]MoveRecord(nil), good.Record.Moves...)
		c.Record.Parties = append([]uint32(nil), good.Record.Parties...)
		c.TxPath = append([]fr.Element(nil), good.TxPath...)
		c.LogPath = append([]fr.Element(nil), good.LogPath...)
		return c
	}
	mut := map[string]func(*InclusionProof){
		"amount":         func(p *InclusionProof) { p.Record.Moves[1].Amount++ },
		"recipient/aux":  func(p *InclusionProof) { p.Record.Moves[2].Aux = felt(1) },
		"sender":         func(p *InclusionProof) { p.Record.Sender++ },
		"digest":         func(p *InclusionProof) { p.Record.Digest = felt(1) },
		"nonce":          func(p *InclusionProof) { p.Record.NonceBefore++ },
		"expiry":         func(p *InclusionProof) { p.Record.Expiry++ },
		"not before":     func(p *InclusionProof) { p.Record.NotBefore++ },
		"add a party":    func(p *InclusionProof) { p.Record.Parties = append(p.Record.Parties, 9) },
		"drop the party": func(p *InclusionProof) { p.Record.Parties = nil },
		"other party":    func(p *InclusionProof) { p.Record.Parties[0] = 4 },
		"code":           func(p *InclusionProof) { p.Record.Moves[1].Code = MoveWithdraw },
		"drop a move":    func(p *InclusionProof) { p.Record.Moves = p.Record.Moves[:3] },
		"slot":           func(p *InclusionProof) { p.TxIndex = 0 },
		"batch number":   func(p *InclusionProof) { p.BatchIndex++ },
		"tx path":        func(p *InclusionProof) { p.TxPath[0] = felt(9) },
		"log path":       func(p *InclusionProof) { p.LogPath[5] = felt(9) },
	}
	for name, f := range mut {
		p := clone()
		f(&p)
		got, err := p.StateRoot(16, 4, testParties)
		if err == nil && got.Equal(&root) {
			t.Errorf("%s: tampered proof still reaches the state root", name)
		}
	}
	short := clone()
	short.LogPath = short.LogPath[:15]
	if _, err := short.StateRoot(16, 4, testParties); err == nil {
		t.Error("short log path accepted")
	}
	oob := clone()
	oob.TxIndex = 4
	if _, err := oob.StateRoot(16, 4, testParties); err == nil {
		t.Error("tx index out of range accepted")
	}
	many := clone()
	many.Record.Parties = []uint32{1, 2, 3, 4}
	if _, err := many.StateRoot(16, 4, testParties); err == nil {
		t.Error("more parties than slots accepted")
	}
	if _, err := RecipientCommit("qor1short"); err == nil {
		t.Error("short recipient accepted")
	}
}

func TestLogLeafIsReplacedNotAccumulated(t *testing.T) {
	rs, tree, _ := sample(t)
	a := tree.Clone()
	a.Set(LogIndex(16), LogAccount(TxRoot(leavesOf(rs)), batchNo))
	rs[0].Moves[1].Amount++
	b := tree.Clone()
	b.Set(LogIndex(16), LogAccount(TxRoot(leavesOf(rs)), batchNo))
	ra, rb := a.Root(), b.Root()
	if ra.Equal(&rb) {
		t.Fatal("different batches must commit different roots")
	}
}

type inclusionVector struct {
	Name  string `json:"name"`
	Depth int    `json:"depth"`
	Input struct {
		Recipient  string        `json:"recipient"`
		PartySlots int           `json:"party_slots"`
		BatchIndex uint64        `json:"batch_index"`
		Records    []*RecordJSON `json:"records"`
		Accounts   []accountJSON `json:"accounts"`
	} `json:"input"`
	Expected struct {
		LogIndex        uint32      `json:"log_index"`
		RecipientCommit string      `json:"recipient_commit"`
		RecordHashes    []string    `json:"record_hashes"`
		TxRoot          string      `json:"tx_root"`
		LogLeaf         string      `json:"log_leaf"`
		StateRootBefore string      `json:"state_root_before_log"`
		StateRoot       string      `json:"state_root"`
		Proofs          []ProofJSON `json:"proofs"`
	} `json:"expected"`
}

type accountJSON struct {
	Index uint32 `json:"index"`
	Pk    string `json:"pk_commit"`
	Qor   uint64 `json:"qor,string"`
	Usd   uint64 `json:"usd,string"`
	Nonce uint64 `json:"nonce,string"`
}

// Golden vector (spec/vectors/inclusion.json). UPDATE_VECTORS=1 rewrites it; otherwise the file must match.
func TestInclusionGoldenVector(t *testing.T) {
	rs, tree, rc := sample(t)
	leaves := leavesOf(rs)
	var v inclusionVector
	v.Name = "sponsored transfer, then a two-party tx where the party withdraws; two unused slots"
	v.Depth = 16
	v.Input.Recipient = "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu"
	v.Input.PartySlots = testParties
	v.Input.BatchIndex = batchNo
	for _, r := range rs {
		if r == nil {
			v.Input.Records = append(v.Input.Records, nil)
			continue
		}
		j := r.JSON()
		v.Input.Records = append(v.Input.Records, &j)
	}
	for i := uint32(0); i < 4; i++ {
		a := tree.Get(i)
		v.Input.Accounts = append(v.Input.Accounts, accountJSON{i, HexElem(a.Pk), a.Qor, a.Usd, a.Nonce})
	}
	before := tree.Root()
	txRoot := TxRoot(leaves)
	tree.Set(LogIndex(16), LogAccount(txRoot, batchNo))
	v.Expected.LogIndex = LogIndex(16)
	v.Expected.RecipientCommit = HexElem(rc)
	v.Expected.RecordHashes = hexes(leaves)
	v.Expected.TxRoot = HexElem(txRoot)
	v.Expected.LogLeaf = HexElem(LogAccount(txRoot, batchNo).LeafHash())
	v.Expected.StateRootBefore = HexElem(before)
	v.Expected.StateRoot = HexElem(tree.Root())
	for i := 0; i < 2; i++ {
		p := InclusionProof{BatchIndex: batchNo, Record: *rs[i], TxIndex: i, TxPath: TxPath(leaves, i), LogPath: tree.Path(LogIndex(16))}
		v.Expected.Proofs = append(v.Expected.Proofs, p.JSON("qorechain-diana", "cloister-dev-3"))
	}
	got, err := json.MarshalIndent([]inclusionVector{v}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_VECTORS") != "" {
		if err := os.WriteFile(inclusionVectors, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(inclusionVectors)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_VECTORS=1 to create it)", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("spec/vectors/inclusion.json differs from the Go reference (UPDATE_VECTORS=1 to regenerate on purpose)")
	}
}

// ---- digest vectors (spec/vectors/digest.json): what a user recomputes from the transaction they signed ----

const digestVectors = "../../spec/vectors/digest.json"

type digestAction struct {
	Code   uint8  `json:"code"`
	Asset  uint8  `json:"asset"`
	Amount string `json:"amount"`
	From   uint32 `json:"from"`
	To     uint32 `json:"to"`
	Aux    string `json:"aux"`
	Atomic bool   `json:"atomic"`
}

type digestCase struct {
	Name         string         `json:"name"`
	ChainID      string         `json:"chain_id"`
	RollupID     string         `json:"rollup_id"`
	SignedSender uint32         `json:"signed_sender"`
	Nonce        string         `json:"nonce"`
	Expiry       string         `json:"expiry"`
	NotBefore    string         `json:"not_before"`
	Payer        uint32         `json:"payer"`
	FeeAsset     uint8          `json:"fee_asset"`
	MaxFee       string         `json:"max_fee"`
	Parties      []uint32       `json:"parties"`
	PartySlots   int            `json:"party_slots"`
	ActionSlots  int            `json:"action_slots"`
	Actions      []digestAction `json:"actions"`
	Domain       string         `json:"domain"`
	Digest       string         `json:"digest"`
}

func TestDigestGoldenVector(t *testing.T) {
	const recipient = "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu"
	rc, _ := RecipientCommit(recipient)
	var zero fr.Element
	mk := func(name string, signed uint32, nonce, expiry, notBefore uint64, payer uint32, feeAsset uint8, maxFee uint64, parties []uint32, acts []PlannedMove) digestCase {
		c := digestCase{Name: name, ChainID: "qorechain-diana", RollupID: "cloister-dev-3", SignedSender: signed, Nonce: u(nonce), Expiry: u(expiry), NotBefore: u(notBefore),
			Payer: payer, FeeAsset: feeAsset, MaxFee: u(maxFee), Parties: append([]uint32{}, parties...), PartySlots: testParties, ActionSlots: 3, Actions: []digestAction{}}
		for _, a := range acts {
			c.Actions = append(c.Actions, digestAction{a.Code, a.Asset, u(a.Amount), a.From, a.To, HexElem(a.Aux), a.Atomic})
		}
		dom := DomainConst(c.ChainID, c.RollupID)
		c.Domain = HexElem(dom)
		c.Digest = HexElem(TxDigest(dom, signed, nonce, expiry, notBefore, payer, feeAsset, maxFee, parties, testParties, acts, 3))
		return c
	}
	pm := func(m MoveRecord, atomic bool) PlannedMove { return PlannedMove{MoveRecord: m, Atomic: atomic} }
	cases := []digestCase{
		mk("a sponsored transfer", 3, 1, 53, 0, 0, 0, 10_000, nil,
			[]PlannedMove{pm(NewMoveRecord(MoveTransfer, 0, 1_000_000, 3, 2, zero, zero), false)}),
		mk("a two-party atomic swap with a withdrawal, time-locked", 2, 4, 99, 7, 2, 0, 10_000, []uint32{3},
			[]PlannedMove{pm(NewMoveRecord(MoveTransfer, 1, 5, 2, 3, zero, zero), true), pm(NewMoveRecord(MoveWithdraw, 0, 500_000, 3, 0, zero, rc), true)}),
		mk("a new account registering its key, no expiry", NewAccountSender, 0, math.MaxUint64, 0, 0, 0, 10_000, nil,
			[]PlannedMove{pm(NewMoveRecord(MoveRegister, 0, 0, 7, 0, felt(12345), zero), false)}),
		mk("no fee, no actions", 5, 0, math.MaxUint64, 0, 5, 0, 0, nil, nil),
	}
	got, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_VECTORS") != "" {
		if err := os.WriteFile(digestVectors, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(digestVectors)
	if err != nil {
		t.Fatalf("%v (run with UPDATE_VECTORS=1 to create it)", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("spec/vectors/digest.json differs from the Go reference (UPDATE_VECTORS=1 to regenerate on purpose)")
	}
	// every field of the transaction is bound: change any one and the digest changes
	base := cases[1]
	dom := DomainConst(base.ChainID, base.RollupID)
	acts := []PlannedMove{pm(NewMoveRecord(MoveTransfer, 1, 5, 2, 3, zero, zero), true), pm(NewMoveRecord(MoveWithdraw, 0, 500_000, 3, 0, zero, rc), true)}
	d0 := TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, acts, 3)
	variants := map[string]fr.Element{
		"signed sender":  TxDigest(dom, 9, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"nonce":          TxDigest(dom, 2, 5, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"expiry":         TxDigest(dom, 2, 4, 100, 7, 2, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"not before":     TxDigest(dom, 2, 4, 99, 0, 2, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"payer":          TxDigest(dom, 2, 4, 99, 7, 3, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"fee asset":      TxDigest(dom, 2, 4, 99, 7, 2, 1, 10_000, []uint32{3}, testParties, acts, 3),
		"max fee":        TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_001, []uint32{3}, testParties, acts, 3),
		"party":          TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{4}, testParties, acts, 3),
		"no party":       TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, nil, testParties, acts, 3),
		"another chain":  TxDigest(DomainConst("other", base.RollupID), 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"another rollup": TxDigest(DomainConst(base.ChainID, "other"), 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, acts, 3),
		"drop an action": TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, acts[:1], 3),
		"atomic flag":    TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, []PlannedMove{pm(acts[0].MoveRecord, false), acts[1]}, 3),
		"amount":         TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, []PlannedMove{pm(NewMoveRecord(MoveTransfer, 1, 6, 2, 3, zero, zero), true), acts[1]}, 3),
		"recipient":      TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, []PlannedMove{acts[0], pm(NewMoveRecord(MoveWithdraw, 0, 500_000, 3, 0, zero, felt(1)), true)}, 3),
		"reorder":        TxDigest(dom, 2, 4, 99, 7, 2, 0, 10_000, []uint32{3}, testParties, []PlannedMove{acts[1], acts[0]}, 3),
	}
	for name, d := range variants {
		if d.Equal(&d0) {
			t.Errorf("changing the %s does not change the digest", name)
		}
	}
}
