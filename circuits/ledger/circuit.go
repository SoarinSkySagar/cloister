// Package ledger is Cloister's batch circuit (Part A): a two-asset account
// ledger in a Poseidon2 sparse Merkle tree, frame-transaction moves (fee,
// transfer, withdraw, register_key), and the chain's SHAKE-256 withdrawals
// root computed inside the proof.
//
// What the circuit guarantees: every state change is a valid move on the
// committed tree, no balance goes negative or over 64 bits, value is
// conserved per asset except for withdrawals, nonces increment once per
// included tx, a key can only be set on an account without one, and every
// withdrawal leaf the chain will pay is backed by a debit of the same amount.
// What it does not prove (the watchtower does): ML-DSA signatures, and that
// the transactions are the ones in the sealed posts (data_hash).
package ledger

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// Config fixes the circuit's shape and its constants. A change to any field
// is a new circuit (new VK).
type Config struct {
	Depth       int              `json:"depth"`       // state tree depth
	Txs         int              `json:"txs"`         // tx slots per batch
	Moves       int              `json:"moves"`       // moves per tx: 1 fee move + (Moves-1) actions
	Withdrawals int              `json:"withdrawals"` // withdrawal slots per batch: 1, 2 or 4
	ChainID     string           `json:"chain_id"`
	RollupID    string           `json:"rollup_id"`
	Genesis     []GenesisAccount `json:"genesis"`
}

type GenesisAccount struct {
	Index uint32 `json:"index"`
	Pk    string `json:"pk_commit"` // hex, mod r
	Qor   uint64 `json:"qor"`
	Usd   uint64 `json:"usd"`
}

func (c Config) Validate() error {
	if c.Depth < 1 || c.Depth > 32 || c.Txs < 1 || c.Moves < 2 {
		return fmt.Errorf("bad shape %d/%d/%d", c.Depth, c.Txs, c.Moves)
	}
	if c.Withdrawals != 1 && c.Withdrawals != 2 && c.Withdrawals != 4 {
		return fmt.Errorf("withdrawals must be 1, 2 or 4")
	}
	if c.ChainID == "" || c.RollupID == "" {
		return fmt.Errorf("chain and rollup ids are required")
	}
	return nil
}

// ---- witness layout ----

type Leaf struct{ Pk, Qor, Usd, Nonce, Orders frontend.Variable }

// Update is one read-modify-write of a leaf. The new leaf is computed by the
// circuit from Old and the move, never taken from the witness.
type Update struct {
	Index frontend.Variable
	Old   Leaf
	Path  []frontend.Variable
}

type Move struct {
	IsTransfer, IsWithdraw, IsRegister frontend.Variable
	Asset                              frontend.Variable // 0 QOR, 1 USD
	Amount                             frontend.Variable
	PkCommit                           frontend.Variable
	From, To                           Update
}

type Tx struct {
	Active frontend.Variable
	Sender Update // nonce increment
	Moves  []Move
}

type Circuit struct {
	PrevStateRoot   frontend.Variable `gnark:",public"`
	StateRoot       frontend.Variable `gnark:",public"`
	DataHash        frontend.Variable `gnark:",public"`
	WithdrawalsRoot frontend.Variable `gnark:",public"`

	DataHashSq frontend.Variable
	Txs        []Tx
	Recipients [][RecipientLen]frontend.Variable // one per withdrawal slot, ASCII bytes

	cfg     Config
	genesis *big.Int
}

// New returns an empty circuit of the config's shape (for compile and as a
// witness template).
func New(cfg Config) (*Circuit, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	g, err := GenesisTree(cfg)
	if err != nil {
		return nil, err
	}
	root := g.Root()
	c := &Circuit{cfg: cfg, genesis: root.BigInt(new(big.Int))}
	upd := func() Update { return Update{Path: make([]frontend.Variable, cfg.Depth)} }
	c.Txs = make([]Tx, cfg.Txs)
	for i := range c.Txs {
		c.Txs[i] = Tx{Sender: upd(), Moves: make([]Move, cfg.Moves)}
		for m := range c.Txs[i].Moves {
			c.Txs[i].Moves[m] = Move{From: upd(), To: upd()}
		}
	}
	c.Recipients = make([][RecipientLen]frontend.Variable, cfg.Withdrawals)
	return c, nil
}

type ctx struct {
	api  frontend.API
	bits bitAPI
	p2   *poseidon2.Permutation
}

func (x ctx) leafHash(l Leaf) frontend.Variable {
	api := x.api
	var h frontend.Variable = 0
	for _, f := range []frontend.Variable{l.Pk, l.Qor, l.Usd, l.Nonce, l.Orders} {
		h = x.p2.Compress(h, f)
	}
	empty := api.Mul(api.IsZero(l.Pk), api.IsZero(l.Qor), api.IsZero(l.Usd), api.IsZero(l.Nonce), api.IsZero(l.Orders))
	return api.Mul(api.Sub(1, empty), h)
}

func (x ctx) rootOf(leaf frontend.Variable, idxBits []frontend.Variable, path []frontend.Variable) frontend.Variable {
	cur := leaf
	for l, sib := range path {
		left := x.api.Select(idxBits[l], sib, cur)
		right := x.api.Select(idxBits[l], cur, sib)
		cur = x.p2.Compress(left, right)
	}
	return cur
}

// apply checks u.Old against root and returns the root with newLeaf written.
func (x ctx) apply(root frontend.Variable, u Update, newLeaf Leaf, depth int) frontend.Variable {
	idx := x.api.ToBinary(u.Index, depth)
	x.api.AssertIsEqual(x.rootOf(x.leafHash(u.Old), idx, u.Path), root)
	return x.rootOf(x.leafHash(newLeaf), idx, u.Path)
}

func (x ctx) u64(v frontend.Variable) { x.api.ToBinary(v, 64) }

func (c *Circuit) Define(api frontend.API) error {
	p2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	x := ctx{api: api, bits: bitAPI{api}, p2: p2}
	cfg := c.cfg
	W := cfg.Withdrawals

	// Batch 0 has prev_state_root = 0 on chain; it starts from the genesis state.
	root := api.Select(api.IsZero(c.PrevStateRoot), c.genesis, c.PrevStateRoot)
	// data_hash is checked by the chain; this keeps it in the constraint system
	// so the proof is not malleable in it.
	api.AssertIsEqual(api.Mul(c.DataHash, c.DataHash), c.DataHashSq)

	var wCount frontend.Variable = 0
	slotAmt := make([]frontend.Variable, W)
	for k := range slotAmt {
		slotAmt[k] = 0
	}

	for _, tx := range c.Txs {
		api.AssertIsBoolean(tx.Active)
		s := tx.Sender.Old
		root = x.apply(root, tx.Sender, Leaf{s.Pk, s.Qor, s.Usd, api.Add(s.Nonce, tx.Active), s.Orders}, cfg.Depth)

		for m, mv := range tx.Moves {
			for _, b := range []frontend.Variable{mv.IsTransfer, mv.IsWithdraw, mv.IsRegister, mv.Asset} {
				api.AssertIsBoolean(b)
			}
			any := api.Add(mv.IsTransfer, mv.IsWithdraw, mv.IsRegister)
			api.AssertIsBoolean(any)                                  // at most one kind
			api.AssertIsEqual(api.Mul(any, api.Sub(1, tx.Active)), 0) // inactive tx: no-ops only
			if m == 0 {
				// the fee move is a payer -> relayer transfer or nothing
				api.AssertIsEqual(mv.IsWithdraw, 0)
				api.AssertIsEqual(mv.IsRegister, 0)
			} else {
				// actions act on the sender's account
				api.AssertIsEqual(api.Mul(any, api.Sub(mv.From.Index, tx.Sender.Index)), 0)
			}
			api.AssertIsEqual(api.Mul(mv.IsWithdraw, mv.Asset), 0) // only QOR leaves the rollup
			x.u64(mv.Amount)

			// debit (transfer, withdraw) and key registration on From
			debit := api.Mul(api.Add(mv.IsTransfer, mv.IsWithdraw), mv.Amount)
			dUsd := api.Mul(debit, mv.Asset)
			dQor := api.Sub(debit, dUsd)
			f := mv.From.Old
			api.AssertIsEqual(api.Mul(mv.IsRegister, f.Pk), 0)                    // never overwrite a key
			api.AssertIsEqual(api.Mul(mv.IsRegister, api.IsZero(mv.PkCommit)), 0) // and never set an empty one
			nf := Leaf{api.Add(f.Pk, api.Mul(mv.IsRegister, mv.PkCommit)), api.Sub(f.Qor, dQor), api.Sub(f.Usd, dUsd), f.Nonce, f.Orders}
			x.u64(nf.Qor) // no negative balance
			x.u64(nf.Usd)
			root = x.apply(root, mv.From, nf, cfg.Depth)

			// credit (transfer) on To
			credit := api.Mul(mv.IsTransfer, mv.Amount)
			cUsd := api.Mul(credit, mv.Asset)
			cQor := api.Sub(credit, cUsd)
			t := mv.To.Old
			nt := Leaf{t.Pk, api.Add(t.Qor, cQor), api.Add(t.Usd, cUsd), t.Nonce, t.Orders}
			x.u64(nt.Qor)
			x.u64(nt.Usd)
			root = x.apply(root, mv.To, nt, cfg.Depth)

			// withdraw: the k-th withdraw of the batch fills slot k
			if m > 0 {
				for k := 0; k < W; k++ {
					hit := api.Mul(mv.IsWithdraw, api.IsZero(api.Sub(wCount, k)))
					slotAmt[k] = api.Add(slotAmt[k], api.Mul(hit, mv.Amount))
				}
				wCount = api.Add(wCount, mv.IsWithdraw)
			}
		}
	}
	api.AssertIsEqual(root, c.StateRoot)

	// at most W withdrawals: n in {0..W}
	var prod frontend.Variable = 1
	for k := 0; k <= W; k++ {
		prod = api.Mul(prod, api.Sub(wCount, k))
	}
	api.AssertIsEqual(prod, 0)
	eq := make([]frontend.Variable, W+1)
	for k := range eq {
		eq[k] = api.IsZero(api.Sub(wCount, k))
	}

	// withdrawal leaves, exactly @qorechain/rdk withdrawalLeafV2
	leaves := make([][32][8]frontend.Variable, W)
	prefix := withdrawalPrefix(cfg.ChainID, cfg.RollupID)
	for k := 0; k < W; k++ {
		msg := constBytes(binary.BigEndian.AppendUint64(append([]byte{}, prefix...), uint64(k)))
		msg = append(msg, constBytes(binary.BigEndian.AppendUint32(nil, RecipientLen))...)
		for _, ch := range c.Recipients[k] {
			var b [8]frontend.Variable
			copy(b[:], api.ToBinary(ch, 8))
			msg = append(msg, b)
		}
		msg = append(msg, constBytes(lp([]byte(withdrawalDenom)))...)
		amt := api.ToBinary(slotAmt[k], 64)
		for j := 0; j < 8; j++ { // u64 big-endian
			var b [8]frontend.Variable
			copy(b[:], amt[(7-j)*8:(8-j)*8])
			msg = append(msg, b)
		}
		leaves[k] = x.bits.shake256x32(msg)
	}
	node := func(l, r [32][8]frontend.Variable) [32][8]frontend.Variable {
		msg := make([][8]frontend.Variable, 0, 64)
		msg = append(msg, l[:]...)
		msg = append(msg, r[:]...)
		return x.bits.shake256x32(msg)
	}

	// root by count: 0 -> 0; 1 -> l0; 2 -> H(l0,l1); 3 -> H(a, H(l2,l2)); 4 -> H(a, H(l2,l3))
	wroot := api.Mul(eq[1], x.bits.packBE(leaves[0]))
	if W >= 2 {
		a := node(leaves[0], leaves[1])
		wroot = api.Add(wroot, api.Mul(eq[2], x.bits.packBE(a)))
		if W == 4 {
			var r3 [32][8]frontend.Variable
			for i := range r3 {
				for j := range r3[i] {
					r3[i][j] = api.Select(eq[3], leaves[2][i][j], leaves[3][i][j])
				}
			}
			top := node(a, node(leaves[2], r3))
			wroot = api.Add(wroot, api.Mul(api.Add(eq[3], eq[4]), x.bits.packBE(top)))
		}
	}
	api.AssertIsEqual(wroot, c.WithdrawalsRoot)
	return nil
}
