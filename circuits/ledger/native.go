package ledger

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	"golang.org/x/crypto/sha3"
)

// Native (out-of-circuit) model of the ledger. It is the reference the
// circuit is tested against, and it builds the circuit witness.

var compressor = poseidon2.NewCompressor(poseidon2.NewDefaultPermutation())

// Compress is the 2-to-1 Poseidon2 compression used for tree nodes.
func Compress(l, r fr.Element) fr.Element {
	var out fr.Element
	compressor.CompressField(&out, &l, &r)
	return out
}

// Account is one leaf of the state tree (spec/state.md).
type Account struct {
	Pk     fr.Element // SHAKE-256/32(ML-DSA-87 public key) mod r; 0 = no key yet
	Qor    uint64
	Usd    uint64
	Nonce  uint64
	Orders fr.Element // Part B; always 0 in Part A
}

func (a Account) fields() [5]fr.Element {
	var f [5]fr.Element
	f[0] = a.Pk
	f[1].SetUint64(a.Qor)
	f[2].SetUint64(a.Usd)
	f[3].SetUint64(a.Nonce)
	f[4] = a.Orders
	return f
}

func (a Account) IsEmpty() bool {
	return a.Pk.IsZero() && a.Qor == 0 && a.Usd == 0 && a.Nonce == 0 && a.Orders.IsZero()
}

// LeafHash is 0 for an empty account, else the Merkle-Damgard Poseidon2 hash
// (zero IV) of the five fields.
func (a Account) LeafHash() fr.Element {
	var h fr.Element
	if a.IsEmpty() {
		return h
	}
	for _, f := range a.fields() {
		h = Compress(h, f)
	}
	return h
}

// Tree is a sparse binary Poseidon2 Merkle tree of the given depth over
// account leaves.
type Tree struct {
	depth    int
	accounts map[uint32]Account
	nodes    []map[uint32]fr.Element // nodes[level][index]; level 0 = leaves
	empty    []fr.Element            // empty subtree root per level
}

func NewTree(depth int) *Tree {
	t := &Tree{depth: depth, accounts: map[uint32]Account{}}
	t.nodes = make([]map[uint32]fr.Element, depth+1)
	t.empty = make([]fr.Element, depth+1)
	for l := 0; l <= depth; l++ {
		t.nodes[l] = map[uint32]fr.Element{}
		if l > 0 {
			t.empty[l] = Compress(t.empty[l-1], t.empty[l-1])
		}
	}
	return t
}

func (t *Tree) node(level int, idx uint32) fr.Element {
	if v, ok := t.nodes[level][idx]; ok {
		return v
	}
	return t.empty[level]
}

func (t *Tree) Get(idx uint32) Account { return t.accounts[idx] }

func (t *Tree) Set(idx uint32, a Account) {
	if uint64(idx) >= 1<<t.depth {
		panic(fmt.Sprintf("account index %d out of range", idx))
	}
	if a.IsEmpty() {
		delete(t.accounts, idx)
	} else {
		t.accounts[idx] = a
	}
	h := a.LeafHash()
	t.nodes[0][idx] = h
	for l := 1; l <= t.depth; l++ {
		idx >>= 1
		t.nodes[l][idx] = Compress(t.node(l-1, 2*idx), t.node(l-1, 2*idx+1))
	}
}

func (t *Tree) Root() fr.Element { return t.node(t.depth, 0) }

// Path returns the sibling of each level, leaf level first.
func (t *Tree) Path(idx uint32) []fr.Element {
	out := make([]fr.Element, t.depth)
	for l := 0; l < t.depth; l++ {
		out[l] = t.node(l, idx^1)
		idx >>= 1
	}
	return out
}

func (t *Tree) Clone() *Tree {
	c := &Tree{depth: t.depth, accounts: map[uint32]Account{}, empty: t.empty}
	for k, v := range t.accounts {
		c.accounts[k] = v
	}
	c.nodes = make([]map[uint32]fr.Element, len(t.nodes))
	for l, m := range t.nodes {
		c.nodes[l] = make(map[uint32]fr.Element, len(m))
		for k, v := range m {
			c.nodes[l][k] = v
		}
	}
	return c
}

// ---- withdrawals (must match @qorechain/rdk withdrawalLeafV2 / withdrawalsTree) ----

const (
	withdrawalDomain = "qorechain-rdk-withdrawal/v2"
	withdrawalDenom  = "uqor"
	// RecipientLen is the length of a qor1 bech32 address of a 20-byte account,
	// the only recipient form the circuit supports.
	RecipientLen = 42
)

func shake32(parts ...[]byte) [32]byte {
	h := sha3.NewShake256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Read(out[:])
	return out
}

func lp(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// withdrawalPrefix is everything in a v2 leaf before the u64 withdrawal index.
func withdrawalPrefix(chainID, rollupID string) []byte {
	var m []byte
	m = append(m, lp([]byte(withdrawalDomain))...)
	m = append(m, lp([]byte(chainID))...)
	m = append(m, lp([]byte(rollupID))...)
	return m
}

// WithdrawalLeafMessage is the SHAKE-256 input of a v2 withdrawal leaf.
func WithdrawalLeafMessage(chainID, rollupID string, index uint64, recipient string, amount uint64) []byte {
	m := withdrawalPrefix(chainID, rollupID)
	m = binary.BigEndian.AppendUint64(m, index)
	m = append(m, lp([]byte(recipient))...)
	m = append(m, lp([]byte(withdrawalDenom))...)
	m = binary.BigEndian.AppendUint64(m, amount)
	return m
}

type Withdrawal struct {
	Recipient string `json:"recipient"`
	Amount    uint64 `json:"amount"`
}

// WithdrawalsRoot is the chain's tree root (no leaf re-hashing, odd node
// duplicated), and 32 zero bytes for no withdrawals.
func WithdrawalsRoot(chainID, rollupID string, ws []Withdrawal) [32]byte {
	if len(ws) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(ws))
	for i, w := range ws {
		level[i] = shake32(WithdrawalLeafMessage(chainID, rollupID, uint64(i), w.Recipient, w.Amount))
	}
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			r := level[i]
			if i+1 < len(level) {
				r = level[i+1]
			}
			next = append(next, shake32(level[i][:], r[:]))
		}
		level = next
	}
	return level[0]
}

// ModR reduces a 32-byte big-endian value mod r, as the chain does.
func ModR(b [32]byte) *big.Int {
	v := new(big.Int).SetBytes(b[:])
	return v.Mod(v, fr.Modulus())
}
