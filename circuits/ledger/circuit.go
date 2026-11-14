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
	if c.Depth < 1 || c.Depth > 31 || c.Txs < 1 || c.Moves < 2 {
		return fmt.Errorf("bad shape %d/%d/%d", c.Depth, c.Txs, c.Moves)
	}
	if c.Moves > 8 {
		// the skip justification compares balances in a 68-bit window; with at most 7 earlier moves in a group
		// (8 moves = the fee and 7 actions) the tentative balances stay inside it (docs/circuit-review.md, S10)
		return fmt.Errorf("at most 8 moves per tx (the fee and 7 actions), got %d", c.Moves)
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

// Move is one signed action (or the fee) as the sender wrote it. Its kind flags,
// asset, amount, accounts and aux are the PLANNED values; the digest commits to
// them. Skip says the move did not apply; the circuit then requires proof that it
// could not have (see the justification below). The effect on the tree is the
// planned move times (1 - Skip).
type Move struct {
	IsTransfer, IsWithdraw, IsRegister frontend.Variable
	Asset                              frontend.Variable // 0 QOR, 1 USD
	Amount                             frontend.Variable
	PkCommit                           frontend.Variable // aux: the key (register) or the recipient commitment (withdraw)
	Atomic                             frontend.Variable // the action's atomic flag (consecutive atomic actions stand or fall together)
	Skip                               frontend.Variable // 1: the move did not apply
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

	// SignedSender is the sender index the signers committed to: Sender.Index, or
	// NewAccountSender when the transaction creates its own account. MaxFee is the
	// fee ceiling the signers committed to.
	SignedSender, MaxFee frontend.Variable
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
	domain  *big.Int
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
	dom := DomainConst(cfg.ChainID, cfg.RollupID)
	c := &Circuit{cfg: cfg, genesis: root.BigInt(new(big.Int)), domain: dom.BigInt(new(big.Int))}
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
	newAccount := new(big.Int).SetUint64(NewAccountSender)

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
		partyFields := make([]frontend.Variable, len(tx.Party))
		for i := range tx.Party {
			partyFields[i] = api.Mul(tx.PartyActive[i], api.Add(tx.Party[i], 1))
		}

		// The sender index the signers committed to: the real one, or the new-account
		// sentinel. A new account must be a fresh, empty leaf, so the sequencer cannot
		// hand a registering user an account that already holds funds, and the tx must
		// actually register a key.
		isNew := api.IsZero(api.Sub(tx.SignedSender, newAccount))
		api.AssertIsEqual(api.Mul(api.Sub(tx.SignedSender, tx.Sender.Index), api.Sub(tx.SignedSender, newAccount)), 0)
		for _, f := range []frontend.Variable{s.Pk, s.Qor, s.Usd, s.Nonce, s.Orders} {
			api.AssertIsEqual(api.Mul(isNew, f), 0)
		}
		feeAmt := api.Mul(tx.Moves[0].Amount, tx.Moves[0].IsTransfer)
		x.u64(api.Mul(tx.Active, api.Sub(tx.MaxFee, feeAmt)))

		A := len(tx.Moves) - 1 // action slots
		type planned struct{ isT, isW, isR, any, from, to, asset, amount, atomic frontend.Variable }
		acts := make([]planned, A)
		fail := make([]frontend.Variable, A)
		skips := make([]frontend.Variable, A)

		recMoves := make([]frontend.Variable, 0, 6*len(tx.Moves))
		digestActs := make([]frontend.Variable, 0, 7*A)
		var regCount frontend.Variable = 0

		for m, mv := range tx.Moves {
			for _, b := range []frontend.Variable{mv.IsTransfer, mv.IsWithdraw, mv.IsRegister, mv.Asset} {
				api.AssertIsBoolean(b)
			}
			api.AssertIsBoolean(mv.Atomic)
			api.AssertIsBoolean(mv.Skip)
			any := api.Add(mv.IsTransfer, mv.IsWithdraw, mv.IsRegister)
			api.AssertIsBoolean(any)                                  // at most one kind
			api.AssertIsEqual(api.Mul(any, api.Sub(1, tx.Active)), 0) // inactive tx: no-ops only
			// (a skip of an empty slot is refused by the justification below: an empty slot never fails)
			api.AssertIsEqual(api.Mul(mv.Atomic, api.Sub(1, any)), 0)                                     // an empty slot carries no flag
			api.AssertIsEqual(api.Mul(mv.PkCommit, api.Sub(1, api.Add(mv.IsRegister, mv.IsWithdraw))), 0) // aux belongs to register and withdraw
			if m == 0 {
				// the fee move is a payer -> relayer transfer or nothing, it always applies, and the recipient is the configured relayer
				api.AssertIsEqual(mv.IsWithdraw, 0)
				api.AssertIsEqual(mv.IsRegister, 0)
				api.AssertIsEqual(mv.Skip, 0)
				api.AssertIsEqual(mv.Atomic, 0)
				api.AssertIsEqual(api.Mul(mv.IsTransfer, api.Sub(mv.To.Index, relayer)), 0)
			} else {
				// an action debits the sender or an active co-signing party
				notAuth := api.Sub(1, api.IsZero(api.Sub(mv.From.Index, tx.Sender.Index)))
				for i := range tx.Party {
					match := api.Mul(tx.PartyActive[i], api.IsZero(api.Sub(mv.From.Index, tx.Party[i])))
					notAuth = api.Mul(notAuth, api.Sub(1, match))
				}
				api.AssertIsEqual(api.Mul(any, notAuth), 0)
				// a key is registered on the sender's own account only, and never an empty one
				api.AssertIsEqual(api.Mul(mv.IsRegister, api.Sub(mv.From.Index, tx.Sender.Index)), 0)
				api.AssertIsEqual(api.Mul(mv.IsRegister, api.IsZero(mv.PkCommit)), 0)
				regCount = api.Add(regCount, mv.IsRegister)
			}
			api.AssertIsEqual(api.Mul(mv.IsWithdraw, mv.Asset), 0) // only QOR leaves the rollup
			x.u64(mv.Amount)

			f := mv.From.Old
			t := mv.To.Old

			// ---- what the signers wrote (planned) ----
			pVal := api.Add(mv.IsTransfer, mv.IsWithdraw)
			pCode := api.Add(mv.IsTransfer, api.Mul(2, mv.IsWithdraw), api.Mul(3, mv.IsRegister))
			pAsset, pAmount := api.Mul(mv.Asset, pVal), api.Mul(mv.Amount, pVal)
			pFrom, pTo := api.Mul(mv.From.Index, any), api.Mul(mv.To.Index, mv.IsTransfer)
			if m == 0 {
				pFrom = mv.From.Index // the payer, also when there is no fee
			} else {
				digestActs = append(digestActs, pCode, pAsset, pAmount, pFrom, pTo, mv.PkCommit, mv.Atomic)
			}

			// ---- may this move be skipped? ----
			// A skipped move must be one that could not apply. fail is computed as if every
			// earlier move of the same atomic group had applied, from the leaves the tree holds
			// when this move is reached (nothing before it in a skipped group changed them).
			if m > 0 {
				a := m - 1
				acts[a] = planned{mv.IsTransfer, mv.IsWithdraw, mv.IsRegister, any, mv.From.Index, mv.To.Index, mv.Asset, mv.Amount, mv.Atomic}
				skips[a] = mv.Skip
				balOf := func(l Leaf, asset frontend.Variable) frontend.Variable {
					return api.Add(l.Qor, api.Mul(asset, api.Sub(l.Usd, l.Qor)))
				}
				balFrom := balOf(f, mv.Asset)
				balTo := balOf(t, mv.Asset)
				wTent := wCount
				var keyHit frontend.Variable = 0
				var conn frontend.Variable = 1
				for i := a - 1; i >= 0; i-- {
					p := acts[i]
					conn = api.Mul(conn, api.Mul(p.atomic, acts[i+1].atomic)) // linked to the move after it
					same := api.IsZero(api.Sub(p.asset, mv.Asset))
					debit := api.Mul(conn, same, api.Add(p.isT, p.isW), p.amount)
					credit := api.Mul(conn, same, p.isT, p.amount)
					balFrom = api.Sub(balFrom, api.Mul(debit, api.IsZero(api.Sub(p.from, mv.From.Index))))
					balFrom = api.Add(balFrom, api.Mul(credit, api.IsZero(api.Sub(p.to, mv.From.Index))))
					balTo = api.Sub(balTo, api.Mul(debit, api.IsZero(api.Sub(p.from, mv.To.Index))))
					balTo = api.Add(balTo, api.Mul(credit, api.IsZero(api.Sub(p.to, mv.To.Index))))
					wTent = api.Add(wTent, api.Mul(conn, p.isW))
					keyHit = api.Add(keyHit, api.Mul(conn, p.isR, api.IsZero(api.Sub(p.from, mv.From.Index))))
				}
				// this move's own debit, for a transfer to the account it debits
				balTo = api.Sub(balTo, api.Mul(mv.IsTransfer, mv.Amount, api.IsZero(api.Sub(mv.From.Index, mv.To.Index))))

				// insufficient: amount > balance (68-bit window, bit 67 set iff balance >= amount)
				ok := api.ToBinary(api.Add(api.Sub(balFrom, mv.Amount), new(big.Int).Lsh(big.NewInt(1), 67)), 68)[67]
				insufficient := api.Sub(1, ok)
				// overflow: balance(to) + amount > 2^64 - 1
				top := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 67), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1)))
				okTo := api.ToBinary(api.Sub(top, api.Add(balTo, mv.Amount)), 68)[67]
				overflow := api.Sub(1, okTo)
				// the batch's withdrawal slots are full
				var full frontend.Variable = 0
				for k := W; k < W+len(tx.Moves); k++ {
					full = api.Add(full, api.IsZero(api.Sub(wTent, k)))
				}
				keyExists := api.Sub(1, api.Mul(api.IsZero(f.Pk), api.IsZero(keyHit)))

				nf := func(v frontend.Variable) frontend.Variable { return api.Sub(1, v) }
				fail[a] = api.Sub(1, api.Mul(
					nf(api.Mul(pVal, insufficient)), nf(api.Mul(mv.IsTransfer, overflow)),
					nf(api.Mul(mv.IsWithdraw, full)), nf(api.Mul(mv.IsRegister, keyExists))))
			}

			// ---- what happened (effective = planned unless skipped) ----
			live := api.Sub(1, mv.Skip)
			eT, eW, eR := api.Mul(mv.IsTransfer, live), api.Mul(mv.IsWithdraw, live), api.Mul(mv.IsRegister, live)

			// debit (transfer, withdraw) and key registration on From
			debit := api.Mul(api.Add(eT, eW), mv.Amount)
			dUsd := api.Mul(debit, mv.Asset)
			dQor := api.Sub(debit, dUsd)
			api.AssertIsEqual(api.Mul(eR, f.Pk), 0) // never overwrite a key
			nf := Leaf{api.Add(f.Pk, api.Mul(eR, mv.PkCommit)), api.Sub(f.Qor, dQor), api.Sub(f.Usd, dUsd), f.Nonce, f.Orders}
			x.u64(nf.Qor) // no negative balance
			x.u64(nf.Usd)
			root = x.apply(root, mv.From, nf, cfg.Depth)

			// credit (transfer) on To
			credit := api.Mul(eT, mv.Amount)
			cUsd := api.Mul(credit, mv.Asset)
			cQor := api.Sub(credit, cUsd)
			nt := Leaf{t.Pk, api.Add(t.Qor, cQor), api.Add(t.Usd, cUsd), t.Nonce, t.Orders}
			x.u64(nt.Qor)
			x.u64(nt.Usd)
			root = x.apply(root, mv.To, nt, cfg.Depth)

			// withdraw: the k-th effective withdraw of the batch fills slot k; its planned recipient commitment must be that slot's
			var rcSel frontend.Variable = 0
			if m > 0 {
				for k := 0; k < W; k++ {
					hit := api.Mul(eW, api.IsZero(api.Sub(wCount, k)))
					slotAmt[k] = api.Add(slotAmt[k], api.Mul(hit, mv.Amount))
					rcSel = api.Add(rcSel, api.Mul(hit, rcommit[k]))
				}
				wCount = api.Add(wCount, eW)
				api.AssertIsEqual(api.Mul(eW, api.Sub(mv.PkCommit, rcSel)), 0)
			}

			// the move's part of the tx record (spec/inclusion.md): what applied, zeros if skipped
			val := api.Add(eT, eW)
			code := api.Add(eT, api.Mul(2, eW), api.Mul(3, eR))
			effAny := api.Add(val, eR)
			aux := api.Mul(mv.PkCommit, api.Add(eR, eW))
			recMoves = append(recMoves, code, api.Mul(mv.Asset, val), api.Mul(mv.Amount, val),
				api.Mul(mv.From.Index, effAny), api.Mul(mv.To.Index, eT), aux)
		}

		// A new account's transaction registers a key.
		api.AssertIsEqual(api.Mul(isNew, api.IsZero(regCount)), 0)

		// Skips: atomic groups stand or fall together, and a skipped move must belong to a group in which some move could not apply.
		link := make([]frontend.Variable, A)
		for a := 0; a+1 < A; a++ {
			link[a] = api.Mul(acts[a].atomic, acts[a+1].atomic)
			api.AssertIsEqual(api.Mul(link[a], api.Sub(skips[a], skips[a+1])), 0)
		}
		for a := 0; a < A; a++ {
			var none frontend.Variable = 1 // no move of a's group fails
			for j := 0; j < A; j++ {
				var cn frontend.Variable = 1
				lo, hi := a, j
				if lo > hi {
					lo, hi = hi, lo
				}
				for k := lo; k < hi; k++ {
					cn = api.Mul(cn, link[k])
				}
				none = api.Mul(none, api.Sub(1, api.Mul(cn, fail[j])))
			}
			api.AssertIsEqual(api.Mul(skips[a], none), 0)
		}

		// The digest of what was signed: from the planned values, so a record cannot show other terms than the signers wrote.
		feeAsset := api.Mul(tx.Moves[0].Asset, tx.Moves[0].IsTransfer)
		dfields := []frontend.Variable{DigestTag, c.domain, tx.SignedSender, s.Nonce, tx.Expiry, tx.NotBefore, tx.Moves[0].From.Index, feeAsset, tx.MaxFee}
		dfields = append(dfields, partyFields...)
		dfields = append(dfields, digestActs...)
		digest := x.md(dfields)

		recFields := []frontend.Variable{TxRecordTag, digest, tx.Sender.Index, s.Nonce, tx.Expiry, tx.NotBefore}
		recFields = append(recFields, partyFields...)
		recFields = append(recFields, recMoves...)
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
