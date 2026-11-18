package ledger

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Transaction inclusion proofs (spec/inclusion.md). This is the native
// reference: the circuit must compute exactly these values.

const (
	TxRecordTag = 1

	MoveNone     = 0
	MoveTransfer = 1
	MoveWithdraw = 2
	MoveRegister = 3
)

// LogIndex is the reserved leaf that holds the latest batch's transaction root.
func LogIndex(depth int) uint32 { return uint32(1)<<depth - 1 }

// MoveRecord is one move as the circuit executed it. An unapplied move is all zeros.
type MoveRecord struct {
	Code   uint8      `json:"code"`
	Asset  uint8      `json:"asset"`
	Amount uint64     `json:"amount,string"`
	From   uint32     `json:"from"`
	To     uint32     `json:"to"`
	Aux    fr.Element `json:"-"` // pk_commit (register) or recipient commitment (withdraw)
}

// NewMoveRecord normalises a move exactly as the circuit does: fields that do
// not apply to the move's kind are zero.
func NewMoveRecord(code uint8, asset uint8, amount uint64, from, to uint32, pk, recipientCommit fr.Element) MoveRecord {
	m := MoveRecord{Code: code}
	switch code {
	case MoveNone:
	case MoveTransfer:
		m.Asset, m.Amount, m.From, m.To = asset, amount, from, to
	case MoveWithdraw:
		m.Asset, m.Amount, m.From, m.Aux = asset, amount, from, recipientCommit
	case MoveRegister:
		m.From, m.Aux = from, pk
	default:
		panic(fmt.Sprintf("bad move code %d", code))
	}
	return m
}

// TxRecord is one executed transaction slot.
type TxRecord struct {
	Sender      uint32
	NonceBefore uint64
	Moves       []MoveRecord
}

// Fields are the 3+6M field elements hashed into the record (spec/inclusion.md).
func (r TxRecord) Fields() []fr.Element {
	out := make([]fr.Element, 0, 3+6*len(r.Moves))
	var tag, sender, nonce fr.Element // separate variables: never alias one element across arguments
	tag.SetUint64(TxRecordTag)
	sender.SetUint64(uint64(r.Sender))
	nonce.SetUint64(r.NonceBefore)
	out = append(out, tag, sender, nonce)
	for _, m := range r.Moves {
		var f [6]fr.Element
		f[0].SetUint64(uint64(m.Code))
		f[1].SetUint64(uint64(m.Asset))
		f[2].SetUint64(m.Amount)
		f[3].SetUint64(uint64(m.From))
		f[4].SetUint64(uint64(m.To))
		f[5] = m.Aux
		out = append(out, f[:]...)
	}
	return out
}

// Hash is the Merkle-Damgard Poseidon2 hash (zero IV) of the fields.
func (r TxRecord) Hash() fr.Element {
	var h fr.Element
	for _, f := range r.Fields() {
		h = Compress(h, f)
	}
	return h
}

// RecordLeaf is the tx-tree leaf of a slot: 0 for an inactive slot.
func RecordLeaf(r *TxRecord) fr.Element {
	if r == nil {
		return fr.Element{}
	}
	return r.Hash()
}

// RecipientCommit binds a 42-byte qor1 address: Compress(pack(r[0..21]), pack(r[21..42])).
func RecipientCommit(recipient string) (fr.Element, error) {
	if len(recipient) != RecipientLen {
		return fr.Element{}, fmt.Errorf("recipient must be %d bytes, got %d", RecipientLen, len(recipient))
	}
	pack := func(b []byte) fr.Element {
		var e fr.Element
		e.SetBigInt(new(big.Int).SetBytes(b))
		return e
	}
	return Compress(pack([]byte(recipient[:21])), pack([]byte(recipient[21:]))), nil
}

// TxRoot is the Merkle root over the slot leaves (a power of two).
func TxRoot(leaves []fr.Element) fr.Element {
	n := len(leaves)
	if n == 0 || n&(n-1) != 0 {
		panic("tx slots must be a power of two")
	}
	level := append([]fr.Element(nil), leaves...)
	for len(level) > 1 {
		next := make([]fr.Element, len(level)/2)
		for i := range next {
			next[i] = Compress(level[2*i], level[2*i+1])
		}
		level = next
	}
	return level[0]
}

// TxPath returns the siblings of slot i, leaf level first.
func TxPath(leaves []fr.Element, i int) []fr.Element {
	level := append([]fr.Element(nil), leaves...)
	var out []fr.Element
	for len(level) > 1 {
		out = append(out, level[i^1])
		next := make([]fr.Element, len(level)/2)
		for j := range next {
			next[j] = Compress(level[2*j], level[2*j+1])
		}
		level, i = next, i/2
	}
	return out
}

// LogAccount is the log leaf for a transaction root.
func LogAccount(txRoot fr.Element) Account { return Account{Pk: txRoot} }

// InclusionProof is what a user holds (spec/inclusion.md, "Proof format").
type InclusionProof struct {
	Record  TxRecord
	TxIndex int
	TxPath  []fr.Element
	LogPath []fr.Element
}

func climb(leaf fr.Element, index uint32, path []fr.Element) fr.Element {
	cur := leaf
	for _, sib := range path {
		if index&1 == 0 {
			cur = Compress(cur, sib)
		} else {
			cur = Compress(sib, cur)
		}
		index >>= 1
	}
	return cur
}

// StateRoot recomputes the state root the proof commits to; the caller must
// compare it with the root the chain holds for the batch.
func (p InclusionProof) StateRoot(depth, txSlots int) (fr.Element, error) {
	if p.TxIndex < 0 || p.TxIndex >= txSlots {
		return fr.Element{}, fmt.Errorf("tx index %d out of range", p.TxIndex)
	}
	want := 0
	for n := txSlots; n > 1; n >>= 1 {
		want++
	}
	if len(p.TxPath) != want {
		return fr.Element{}, fmt.Errorf("tx path has %d siblings, want %d", len(p.TxPath), want)
	}
	if len(p.LogPath) != depth {
		return fr.Element{}, fmt.Errorf("log path has %d siblings, want %d", len(p.LogPath), depth)
	}
	txRoot := climb(p.Record.Hash(), uint32(p.TxIndex), p.TxPath)
	return climb(LogAccount(txRoot).LeafHash(), LogIndex(depth), p.LogPath), nil
}

// HexElem is the 32-byte big-endian hex of a field element (vectors, proofs).
func HexElem(e fr.Element) string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}
