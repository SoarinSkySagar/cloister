package ledger

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const inclusionVectors = "../../spec/vectors/inclusion.json"

func felt(n uint64) fr.Element { var e fr.Element; e.SetUint64(n); return e }

// A fixed scenario: tx 0 is a sponsored transfer, tx 1 a self-paid withdrawal, slots 2 and 3 are unused.
func sample(t *testing.T) (records []*TxRecord, tree *Tree, rc fr.Element) {
	t.Helper()
	const recipient = "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu"
	var err error
	rc, err = RecipientCommit(recipient)
	if err != nil {
		t.Fatal(err)
	}
	var zero fr.Element
	records = []*TxRecord{
		{Sender: 3, NonceBefore: 1, Moves: []MoveRecord{
			NewMoveRecord(MoveTransfer, 0, 10_000, 0, 1, zero, zero),    // fee: payer 0 -> relayer 1
			NewMoveRecord(MoveTransfer, 0, 1_000_000, 3, 2, zero, zero), // 1 QOR to account 2
			NewMoveRecord(MoveNone, 0, 0, 0, 0, zero, zero),
		}},
		{Sender: 2, NonceBefore: 4, Moves: []MoveRecord{
			NewMoveRecord(MoveTransfer, 0, 10_000, 2, 1, zero, zero), // fee: self-paid
			NewMoveRecord(MoveWithdraw, 0, 500_000, 2, 0, zero, rc),  // 0.5 QOR to L1
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
		out[i] = RecordLeaf(r)
	}
	return out
}

func TestInclusionRoundTrip(t *testing.T) {
	rs, tree, _ := sample(t)
	leaves := leavesOf(rs)
	txRoot := TxRoot(leaves)
	tree.Set(LogIndex(16), LogAccount(txRoot))
	root := tree.Root()
	for i := 0; i < 2; i++ {
		p := InclusionProof{Record: *rs[i], TxIndex: i, TxPath: TxPath(leaves, i), LogPath: tree.Path(LogIndex(16))}
		got, err := p.StateRoot(16, 4)
		if err != nil || !got.Equal(&root) {
			t.Fatalf("slot %d: %v root %s want %s", i, err, HexElem(got), HexElem(root))
		}
	}
}

// Negative cases: every way to alter a proof must change the root it commits to (or be refused).
func TestInclusionProofsRefuseTampering(t *testing.T) {
	rs, tree, _ := sample(t)
	leaves := leavesOf(rs)
	tree.Set(LogIndex(16), LogAccount(TxRoot(leaves)))
	root := tree.Root()
	good := InclusionProof{Record: *rs[0], TxIndex: 0, TxPath: TxPath(leaves, 0), LogPath: tree.Path(LogIndex(16))}
	clone := func() InclusionProof {
		c := good
		c.Record.Moves = append([]MoveRecord(nil), good.Record.Moves...)
		c.TxPath = append([]fr.Element(nil), good.TxPath...)
		c.LogPath = append([]fr.Element(nil), good.LogPath...)
		return c
	}
	mut := map[string]func(*InclusionProof){
		"amount":        func(p *InclusionProof) { p.Record.Moves[1].Amount++ },
		"recipient/aux": func(p *InclusionProof) { p.Record.Moves[1].Aux = felt(1) },
		"sender":        func(p *InclusionProof) { p.Record.Sender++ },
		"nonce":         func(p *InclusionProof) { p.Record.NonceBefore++ },
		"code":          func(p *InclusionProof) { p.Record.Moves[1].Code = MoveWithdraw },
		"drop a move":   func(p *InclusionProof) { p.Record.Moves = p.Record.Moves[:2] },
		"slot":          func(p *InclusionProof) { p.TxIndex = 1 },
		"tx path":       func(p *InclusionProof) { p.TxPath[0] = felt(9) },
		"log path":      func(p *InclusionProof) { p.LogPath[5] = felt(9) },
	}
	for name, f := range mut {
		p := clone()
		f(&p)
		got, err := p.StateRoot(16, 4)
		if err == nil && got.Equal(&root) {
			t.Errorf("%s: tampered proof still reaches the state root", name)
		}
	}
	short := clone()
	short.LogPath = short.LogPath[:15]
	if _, err := short.StateRoot(16, 4); err == nil {
		t.Error("short log path accepted")
	}
	oob := clone()
	oob.TxIndex = 4
	if _, err := oob.StateRoot(16, 4); err == nil {
		t.Error("tx index out of range accepted")
	}
	if _, err := RecipientCommit("qor1short"); err == nil {
		t.Error("short recipient accepted")
	}
}

func TestLogLeafIsReplacedNotAccumulated(t *testing.T) {
	rs, tree, _ := sample(t)
	a := tree.Clone()
	a.Set(LogIndex(16), LogAccount(TxRoot(leavesOf(rs))))
	rs[0].Moves[1].Amount++
	b := tree.Clone()
	b.Set(LogIndex(16), LogAccount(TxRoot(leavesOf(rs))))
	ra, rb := a.Root(), b.Root()
	if ra.Equal(&rb) {
		t.Fatal("different batches must commit different roots")
	}
}

type inclusionVector struct {
	Name  string `json:"name"`
	Depth int    `json:"depth"`
	Input struct {
		Recipient string        `json:"recipient"`
		Records   []*recordJSON `json:"records"`
		Accounts  []accountJSON `json:"accounts"`
	} `json:"input"`
	Expected struct {
		LogIndex        uint32      `json:"log_index"`
		RecipientCommit string      `json:"recipient_commit"`
		RecordHashes    []string    `json:"record_hashes"`
		TxRoot          string      `json:"tx_root"`
		LogLeaf         string      `json:"log_leaf"`
		StateRootBefore string      `json:"state_root_before_log"`
		StateRoot       string      `json:"state_root"`
		Proofs          []proofJSON `json:"proofs"`
	} `json:"expected"`
}
type accountJSON struct {
	Index uint32 `json:"index"`
	Pk    string `json:"pk_commit"`
	Qor   uint64 `json:"qor,string"`
	Usd   uint64 `json:"usd,string"`
	Nonce uint64 `json:"nonce,string"`
}
type moveJSON struct {
	Code   uint8  `json:"code"`
	Asset  uint8  `json:"asset"`
	Amount string `json:"amount"`
	From   uint32 `json:"from"`
	To     uint32 `json:"to"`
	Aux    string `json:"aux"`
}
type recordJSON struct {
	Sender      uint32     `json:"sender"`
	NonceBefore string     `json:"nonceBefore"`
	Moves       []moveJSON `json:"moves"`
}
type proofJSON struct {
	TxIndex int        `json:"txIndex"`
	Record  recordJSON `json:"record"`
	TxPath  []string   `json:"txPath"`
	LogPath []string   `json:"logPath"`
}

func toRecordJSON(r TxRecord) recordJSON {
	out := recordJSON{Sender: r.Sender, NonceBefore: itoa(r.NonceBefore)}
	for _, m := range r.Moves {
		out.Moves = append(out.Moves, moveJSON{m.Code, m.Asset, itoa(m.Amount), m.From, m.To, HexElem(m.Aux)})
	}
	return out
}
func itoa(n uint64) string { b, _ := json.Marshal(n); return string(b) }
func hexes(es []fr.Element) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = HexElem(e)
	}
	return out
}

// Golden vector (spec/vectors/inclusion.json). UPDATE_VECTORS=1 rewrites it; otherwise the file must match.
func TestInclusionGoldenVector(t *testing.T) {
	rs, tree, rc := sample(t)
	leaves := leavesOf(rs)
	var v inclusionVector
	v.Name = "sponsored transfer and self-paid withdrawal, two unused slots"
	v.Depth = 16
	v.Input.Recipient = "qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu"
	for _, r := range rs {
		if r == nil {
			v.Input.Records = append(v.Input.Records, nil)
			continue
		}
		j := toRecordJSON(*r)
		v.Input.Records = append(v.Input.Records, &j)
	}
	for i := uint32(0); i < 4; i++ {
		a := tree.Get(i)
		v.Input.Accounts = append(v.Input.Accounts, accountJSON{i, HexElem(a.Pk), a.Qor, a.Usd, a.Nonce})
	}
	before := tree.Root()
	txRoot := TxRoot(leaves)
	tree.Set(LogIndex(16), LogAccount(txRoot))
	v.Expected.LogIndex = LogIndex(16)
	v.Expected.RecipientCommit = HexElem(rc)
	v.Expected.RecordHashes = hexes(leaves)
	v.Expected.TxRoot = HexElem(txRoot)
	v.Expected.LogLeaf = HexElem(LogAccount(txRoot).LeafHash())
	v.Expected.StateRootBefore = HexElem(before)
	v.Expected.StateRoot = HexElem(tree.Root())
	for i := 0; i < 2; i++ {
		v.Expected.Proofs = append(v.Expected.Proofs, proofJSON{i, toRecordJSON(*rs[i]), hexes(TxPath(leaves, i)), hexes(tree.Path(LogIndex(16)))})
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
