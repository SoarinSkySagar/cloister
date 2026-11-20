// Package ledger is Cloister's batch circuit (Part A): a two-asset account
// ledger in a Poseidon2 sparse Merkle tree, frame-transaction moves (fee,
// transfer, withdraw, register_key), and the chain's SHAKE-256 withdrawals
// root computed inside the proof.
//
// What the circuit guarantees: every state change is a valid move on the
// committed tree, no balance goes negative or over 64 bits, value is
// conserved per asset except for withdrawals, nonces increment once per
// included tx, a key can only be set on an account without one, every
// withdrawal leaf the chain will pay is backed by a debit of the same amount,
// an applied action debits only the sender or a listed co-signing party, every
// included tx is inside its time window (checked against an in-state batch
// counter), every fee is paid to the configured relayer account, and the
// batch's transaction records are committed in the state root (spec/inclusion.md).
// What it does not prove (the watchtower does): ML-DSA signatures of the
// sender and the parties, and that the transactions are the ones in the sealed
// posts (data_hash).
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
	Parties     int              `json:"parties"`     // co-signer slots per tx (spec/frame-tx.md, multi-party)
	Relayer     uint32           `json:"relayer"`     // the account every fee is paid to: a circuit constant
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
	if c.Txs&(c.Txs-1) != 0 {
		return fmt.Errorf("tx slots must be a power of two (the transaction root is a Merkle tree)")
	}
	if c.Parties < 1 || c.Parties > 8 {
		return fmt.Errorf("parties must be 1..8")
	}
	for _, g := range c.Genesis {
		if g.Index >= LogIndex(c.Depth) {
			return fmt.Errorf("genesis account %d: the last leaf is reserved for the log", g.Index)
		}
	}
	if c.Relayer >= LogIndex(c.Depth) {
		return fmt.Errorf("the relayer account %d is not a valid account (the last leaf is reserved for the log)", c.Relayer)
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

	// Time window (batch indexes) and co-signers. Party slots are listed in
	// the tx record; an active party may be debited by this tx's actions.
	Expiry, NotBefore frontend.Variable
	PartyActive       []frontend.Variable
	Party             []frontend.Variable
}

type Circuit struct {
	PrevStateRoot   frontend.Variable `gnark:",public"`
	StateRoot       frontend.Variable `gnark:",public"`
	DataHash        frontend.Variable `gnark:",public"`
	WithdrawalsRoot frontend.Variable `gnark:",public"`

	DataHashSq frontend.Variable
	Txs        []Tx
	// Log is the reserved leaf at LogIndex: the previous batch's tx root and
	// the batch counter, replaced by this batch's.
	Log        Update
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
	c.Log = upd()
	c.Txs = make([]Tx, cfg.Txs)
	for i := range c.Txs {
		c.Txs[i] = Tx{Sender: upd(), Moves: make([]Move, cfg.Moves),
			PartyActive: make([]frontend.Variable, cfg.Parties), Party: make([]frontend.Variable, cfg.Parties)}
		for m := range c.Txs[i].Moves {
			c.Txs[i].Moves[m] = Move{From: upd(), To: upd()}
		}
	}
	c.Recipients = make([][RecipientLen]frontend.Variable, cfg.Withdrawals)
	return c, nil
}

type ctx struct {
	api      frontend.API
	bits     bitAPI
	p2       *poseidon2.Permutation
	logIndex *big.Int
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

// applyAt checks u.Old against root and returns the root with newLeaf written.
func (x ctx) applyAt(root frontend.Variable, u Update, newLeaf Leaf, depth int) frontend.Variable {
	idx := x.api.ToBinary(u.Index, depth)
	x.api.AssertIsEqual(x.rootOf(x.leafHash(u.Old), idx, u.Path), root)
	return x.rootOf(x.leafHash(newLeaf), idx, u.Path)
}

// apply is an account update. It may never touch the reserved log leaf.
func (x ctx) apply(root frontend.Variable, u Update, newLeaf Leaf, depth int) frontend.Variable {
	x.api.AssertIsDifferent(u.Index, x.logIndex)
	return x.applyAt(root, u, newLeaf, depth)
}

// md is the Merkle-Damgard Poseidon2 hash with a zero IV.
func (x ctx) md(fields []frontend.Variable) frontend.Variable {
	var h frontend.Variable = 0
	for _, f := range fields {
		h = x.p2.Compress(h, f)
	}
	return h
}

// pack21 reads 21 bytes as a big-endian integer.
func (x ctx) pack21(bytes []frontend.Variable) frontend.Variable {
	var acc frontend.Variable = 0
	for i, b := range bytes {
		acc = x.api.Add(acc, x.api.Mul(b, new(big.Int).Lsh(big.NewInt(1), uint(8*(len(bytes)-1-i)))))
	}
	return acc
}

func (x ctx) u64(v frontend.Variable) { x.api.ToBinary(v, 64) }

func (c *Circuit) Define(api frontend.API) error {
	p2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	x := ctx{api: api, bits: bitAPI{api}, p2: p2, logIndex: new(big.Int).SetUint64(uint64(LogIndex(c.cfg.Depth)))}
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

	// every fee is paid to this account (cfg.Relayer), so a sequencer cannot redirect fees
	relayer := new(big.Int).SetUint64(uint64(cfg.Relayer))

	// The batch index n is the counter in the log leaf (checked against the
	// root below, after the accounts have been updated; no account update can
	// touch that leaf).
	// n starts at 0 and only this circuit raises it, one per batch, so it stays below 2^64.
	n := c.Log.Old.Nonce

	// Recipient commitments, one per withdrawal slot: the record of a
	// withdrawal binds the L1 recipient (spec/inclusion.md).
	rcommit := make([]frontend.Variable, W)
	for k := 0; k < W; k++ {
		rcommit[k] = x.p2.Compress(x.pack21(c.Recipients[k][:21]), x.pack21(c.Recipients[k][21:]))
	}

	recLeaves := make([]frontend.Variable, 0, len(c.Txs))
	for _, tx := range c.Txs {
		api.AssertIsBoolean(tx.Active)
		s := tx.Sender.Old
		root = x.apply(root, tx.Sender, Leaf{s.Pk, s.Qor, s.Usd, api.Add(s.Nonce, tx.Active), s.Orders}, cfg.Depth)

		// time window: not_before <= n <= expiry for every included tx
		x.u64(tx.Expiry)
		x.u64(tx.NotBefore)
		x.u64(api.Mul(tx.Active, api.Sub(n, tx.NotBefore)))
		x.u64(api.Mul(tx.Active, api.Sub(tx.Expiry, n)))

		// co-signers: booleans, and the set an action may debit besides the sender
		for i := range tx.Party {
			api.AssertIsBoolean(tx.PartyActive[i])
		}

		recFields := []frontend.Variable{TxRecordTag, tx.Sender.Index, s.Nonce, tx.Expiry, tx.NotBefore}
		for i := range tx.Party {
			recFields = append(recFields, api.Mul(tx.PartyActive[i], api.Add(tx.Party[i], 1)))
		}

		for m, mv := range tx.Moves {
			for _, b := range []frontend.Variable{mv.IsTransfer, mv.IsWithdraw, mv.IsRegister, mv.Asset} {
				api.AssertIsBoolean(b)
			}
			any := api.Add(mv.IsTransfer, mv.IsWithdraw, mv.IsRegister)
			api.AssertIsBoolean(any)                                  // at most one kind
			api.AssertIsEqual(api.Mul(any, api.Sub(1, tx.Active)), 0) // inactive tx: no-ops only
			if m == 0 {
				// the fee move is a payer -> relayer transfer or nothing, and the recipient is the configured relayer
				api.AssertIsEqual(mv.IsWithdraw, 0)
				api.AssertIsEqual(mv.IsRegister, 0)
				api.AssertIsEqual(api.Mul(mv.IsTransfer, api.Sub(mv.To.Index, relayer)), 0)
			} else {
				// an applied action debits the sender or an active co-signing party
				notAuth := api.Sub(1, api.IsZero(api.Sub(mv.From.Index, tx.Sender.Index)))
				for i := range tx.Party {
					match := api.Mul(tx.PartyActive[i], api.IsZero(api.Sub(mv.From.Index, tx.Party[i])))
					notAuth = api.Mul(notAuth, api.Sub(1, match))
				}
				api.AssertIsEqual(api.Mul(any, notAuth), 0)
				// a key is registered on the sender's own account only
				api.AssertIsEqual(api.Mul(mv.IsRegister, api.Sub(mv.From.Index, tx.Sender.Index)), 0)
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
			var rcSel frontend.Variable = 0
			if m > 0 {
				for k := 0; k < W; k++ {
					hit := api.Mul(mv.IsWithdraw, api.IsZero(api.Sub(wCount, k)))
					slotAmt[k] = api.Add(slotAmt[k], api.Mul(hit, mv.Amount))
					rcSel = api.Add(rcSel, api.Mul(hit, rcommit[k]))
				}
				wCount = api.Add(wCount, mv.IsWithdraw)
			}

			// the move's part of the tx record (spec/inclusion.md)
			val := api.Add(mv.IsTransfer, mv.IsWithdraw)
			code := api.Add(mv.IsTransfer, api.Mul(2, mv.IsWithdraw), api.Mul(3, mv.IsRegister))
			aux := api.Add(api.Mul(mv.PkCommit, mv.IsRegister), api.Mul(rcSel, mv.IsWithdraw))
			recFields = append(recFields, code, api.Mul(mv.Asset, val), api.Mul(mv.Amount, val),
				api.Mul(mv.From.Index, any), api.Mul(mv.To.Index, mv.IsTransfer), aux)
		}
		recLeaves = append(recLeaves, api.Mul(tx.Active, x.md(recFields)))
	}

	// tx root, then the log leaf: replace {previous tx root, n} by {this tx root, n+1}
	level := recLeaves
	for len(level) > 1 {
		next := make([]frontend.Variable, len(level)/2)
		for i := range next {
			next[i] = x.p2.Compress(level[2*i], level[2*i+1])
		}
		level = next
	}
	api.AssertIsEqual(c.Log.Index, x.logIndex)
	api.AssertIsEqual(c.Log.Old.Qor, 0)
	api.AssertIsEqual(c.Log.Old.Usd, 0)
	api.AssertIsEqual(c.Log.Old.Orders, 0)
	root = x.applyAt(root, c.Log, Leaf{Pk: level[0], Qor: 0, Usd: 0, Nonce: api.Add(n, 1), Orders: 0}, cfg.Depth)
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
