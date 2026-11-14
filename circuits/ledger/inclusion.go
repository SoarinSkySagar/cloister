package ledger

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"golang.org/x/crypto/sha3"
)

// Transaction inclusion proofs (spec/inclusion.md). This is the native
// reference: the circuit must compute exactly these values.

const (
	TxRecordTag = 1
	// DigestTag starts every transaction digest (spec/inclusion.md, "Transaction digest").
	DigestTag = 2
	// NewAccountSender is the sender index a signed transaction carries when it
	// creates its own account (the sequencer assigns the real index afterwards).
	NewAccountSender = 0xffffffff

	MoveNone     = 0
	MoveTransfer = 1
	MoveWithdraw = 2
	MoveRegister = 3

	// ProofVersion is the inclusion proof JSON version: 2 carries the transaction digest (circuit v3); 1 is circuit v2.
	ProofVersion = 2
)

// LogIndex is the reserved leaf that holds the latest batch's transaction root
// and the batch counter.
func LogIndex(depth int) uint32 { return uint32(1)<<depth - 1 }

// MoveRecord is one move as the circuit executed it. An unapplied move is all zeros.
type MoveRecord struct {
	Code   uint8
	Asset  uint8
	Amount uint64
	From   uint32
	To     uint32
	Aux    fr.Element // pk_commit (register) or recipient commitment (withdraw)
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

// PlannedMove is one signed action as the sender wrote it, whether or not it
// applied. Fields that do not apply to the action's kind are zero, exactly as
// in MoveRecord.
type PlannedMove struct {
	MoveRecord
	Atomic bool
}

// DomainConst binds a digest to one chain and one rollup: SHAKE-256/32 of
// "cloister/domain/v1" || len(chain) || chain || len(rollup) || rollup, read mod r.
func DomainConst(chainID, rollupID string) fr.Element {
	h := sha3.NewShake256()
	h.Write([]byte("cloister/domain/v1"))
	for _, s := range []string{chainID, rollupID} {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s))))
		h.Write([]byte(s))
	}
	var out [32]byte
	h.Read(out[:])
	var e fr.Element
	e.SetBigInt(new(big.Int).SetBytes(out[:]))
	return e
}

// TxDigest is the field-element digest of everything a transaction's signers
// committed to, computed by the circuit from the same witness it executes and
// stored in the record. A user recomputes it from the transaction they signed
// and compares: a record whose digest differs is not their transaction.
//
//	MD( DIGEST_TAG, domain, signed_sender, nonce, expiry, not_before, payer, fee_asset, max_fee,
//	    party_0 .. party_{P-1}, then for each action slot: code, asset, amount, from, to, aux, atomic )
func TxDigest(domain fr.Element, signedSender uint32, nonce, expiry, notBefore uint64, payer uint32, feeAsset uint8, maxFee uint64,
	parties []uint32, partySlots int, actions []PlannedMove, actionSlots int) fr.Element {
	return mdFields(DigestFields(domain, signedSender, nonce, expiry, notBefore, payer, feeAsset, maxFee, parties, partySlots, actions, actionSlots))
}

func mdFields(fields []fr.Element) fr.Element {
	var h fr.Element
	for _, f := range fields {
		h = Compress(h, f)
	}
	return h
}

// DigestFields are the elements TxDigest hashes, in order (the circuit hashes the same vector; tests tweak one element).
func DigestFields(domain fr.Element, signedSender uint32, nonce, expiry, notBefore uint64, payer uint32, feeAsset uint8, maxFee uint64,
	parties []uint32, partySlots int, actions []PlannedMove, actionSlots int) []fr.Element {
	if len(parties) > partySlots || len(actions) > actionSlots {
		panic("more parties or actions than slots")
	}
	n := func(v uint64) fr.Element { var e fr.Element; e.SetUint64(v); return e }
	fields := []fr.Element{n(DigestTag), domain, n(uint64(signedSender)), n(nonce), n(expiry), n(notBefore), n(uint64(payer)), n(uint64(feeAsset)), n(maxFee)}
	for i := 0; i < partySlots; i++ {
		var p fr.Element
		if i < len(parties) {
			p.SetUint64(uint64(parties[i]) + 1)
		}
		fields = append(fields, p)
	}
	for i := 0; i < actionSlots; i++ {
		var a PlannedMove
		if i < len(actions) {
			a = actions[i]
		}
		atomic := uint64(0)
		if a.Atomic {
			atomic = 1
		}
		fields = append(fields, n(uint64(a.Code)), n(uint64(a.Asset)), n(a.Amount), n(uint64(a.From)), n(uint64(a.To)), a.Aux, n(atomic))
	}
	return fields
}

// TxRecord is one executed transaction slot.
type TxRecord struct {
	Digest      fr.Element // TxDigest of the signed transaction
	Sender      uint32
	NonceBefore uint64
	Expiry      uint64
	NotBefore   uint64
	Parties     []uint32 // active co-signers in slot order
	Moves       []MoveRecord
}

// Fields are the 6 + partySlots + 6M field elements hashed into the record.
func (r TxRecord) Fields(partySlots int) []fr.Element {
	if len(r.Parties) > partySlots {
		panic("more parties than slots")
	}
	out := make([]fr.Element, 0, 6+partySlots+6*len(r.Moves))
	var tag, sender, nonce, expiry, notBefore fr.Element // separate variables: never alias one element across arguments
	tag.SetUint64(TxRecordTag)
	sender.SetUint64(uint64(r.Sender))
	nonce.SetUint64(r.NonceBefore)
	expiry.SetUint64(r.Expiry)
	notBefore.SetUint64(r.NotBefore)
	out = append(out, tag, r.Digest, sender, nonce, expiry, notBefore)
	for i := 0; i < partySlots; i++ {
		var p fr.Element
		if i < len(r.Parties) {
			p.SetUint64(uint64(r.Parties[i]) + 1)
		}
		out = append(out, p)
	}
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
func (r TxRecord) Hash(partySlots int) fr.Element {
	var h fr.Element
	for _, f := range r.Fields(partySlots) {
		h = Compress(h, f)
	}
	return h
}

// RecordLeaf is the tx-tree leaf of a slot: 0 for an inactive slot.
func RecordLeaf(r *TxRecord, partySlots int) fr.Element {
	if r == nil {
		return fr.Element{}
	}
	return r.Hash(partySlots)
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

// LogAccount is the log leaf after batch batchIndex: the tx root and the counter n+1.
func LogAccount(txRoot fr.Element, batchIndex uint64) Account {
	return Account{Pk: txRoot, Nonce: batchIndex + 1}
}

// InclusionProof is what a user holds (spec/inclusion.md, "Proof format").
type InclusionProof struct {
	BatchIndex uint64
	Record     TxRecord
	TxIndex    int
	TxPath     []fr.Element
	LogPath    []fr.Element
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
func (p InclusionProof) StateRoot(depth, txSlots, partySlots int) (fr.Element, error) {
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
	if len(p.Record.Parties) > partySlots {
		return fr.Element{}, fmt.Errorf("record lists %d parties, the circuit has %d slots", len(p.Record.Parties), partySlots)
	}
	txRoot := climb(p.Record.Hash(partySlots), uint32(p.TxIndex), p.TxPath)
	return climb(LogAccount(txRoot, p.BatchIndex).LeafHash(), LogIndex(depth), p.LogPath), nil
}

// HexElem is the 32-byte big-endian hex of a field element (vectors, proofs).
func HexElem(e fr.Element) string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}

// ---- JSON form (spec/inclusion.md "Proof format"), shared by the prover output and the vectors ----

type MoveJSON struct {
	Code   uint8  `json:"code"`
	Asset  uint8  `json:"asset"`
	Amount string `json:"amount"`
	From   uint32 `json:"from"`
	To     uint32 `json:"to"`
	Aux    string `json:"aux"`
}

type RecordJSON struct {
	Digest         string     `json:"digest"`
	Sender         uint32     `json:"sender"`
	NonceBefore    string     `json:"nonceBefore"`
	ExpiryBatch    string     `json:"expiryBatch"`
	NotBeforeBatch string     `json:"notBeforeBatch"`
	Parties        []uint32   `json:"parties"`
	Moves          []MoveJSON `json:"moves"`
}

type ProofJSON struct {
	Version    int        `json:"version"`
	ChainID    string     `json:"chainId"`
	RollupID   string     `json:"rollupId"`
	BatchIndex uint64     `json:"batchIndex"`
	Record     RecordJSON `json:"record"`
	TxIndex    int        `json:"txIndex"`
	TxPath     []string   `json:"txPath"`
	LogPath    []string   `json:"logPath"`
}

func u(n uint64) string { return strconv.FormatUint(n, 10) }

func (r TxRecord) JSON() RecordJSON {
	out := RecordJSON{Digest: HexElem(r.Digest), Sender: r.Sender, NonceBefore: u(r.NonceBefore), ExpiryBatch: u(r.Expiry), NotBeforeBatch: u(r.NotBefore), Parties: append([]uint32{}, r.Parties...)}
	for _, m := range r.Moves {
		out.Moves = append(out.Moves, MoveJSON{m.Code, m.Asset, u(m.Amount), m.From, m.To, HexElem(m.Aux)})
	}
	return out
}

func hexes(es []fr.Element) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = HexElem(e)
	}
	return out
}

func (p InclusionProof) JSON(chainID, rollupID string) ProofJSON {
	return ProofJSON{ProofVersion, chainID, rollupID, p.BatchIndex, p.Record.JSON(), p.TxIndex, hexes(p.TxPath), hexes(p.LogPath)}
}
