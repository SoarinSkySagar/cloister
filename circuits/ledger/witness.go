package ledger

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
)

// Batch input (spec/batch.md). The sequencer has already decrypted the posts
// and verified the ML-DSA signatures; here we only execute.
type Batch struct {
	Txs []TxIn `json:"txs"`
}

type TxIn struct {
	Sender   uint32     `json:"sender"`
	Payer    uint32     `json:"payer"`   // == sender when there is no VERIFY_PAYER frame
	Relayer  uint32     `json:"relayer"` // fee recipient
	FeeAsset uint8      `json:"fee_asset"`
	Fee      uint64     `json:"fee"`
	Actions  []ActionIn `json:"actions"`
	// Parties are the VERIFY_PARTY accounts: actions may debit them besides the sender.
	Parties []uint32 `json:"parties,omitempty"`
	// Expiry is the last batch index the tx is valid in (nil: no expiry);
	// NotBefore the first (GUARD frame).
	Expiry    *uint64 `json:"expiry,omitempty"`
	NotBefore uint64  `json:"not_before,omitempty"`
}

type ActionIn struct {
	Kind      string  `json:"kind"`           // transfer | withdraw | register_key
	From      *uint32 `json:"from,omitempty"` // account to debit (transfer_from / withdraw_from); nil = the sender
	Atomic    bool    `json:"atomic,omitempty"`
	To        uint32  `json:"to,omitempty"`
	Asset     uint8   `json:"asset,omitempty"`
	Amount    uint64  `json:"amount,omitempty"`
	Recipient string  `json:"recipient,omitempty"`
	PkCommit  string  `json:"pk_commit,omitempty"` // hex, < r
}

// TxResult says what happened to each tx and action.
type TxResult struct {
	Included bool     `json:"included"`
	Reason   string   `json:"reason,omitempty"`
	Applied  []bool   `json:"applied"`
	Skipped  []string `json:"skipped,omitempty"`
}

type Result struct {
	PrevRoot        fr.Element
	NewRoot         fr.Element
	Withdrawals     []Withdrawal
	WithdrawalsRoot [32]byte
	Txs             []TxResult
	// Inclusion (spec/inclusion.md): the batch index the circuit counted, one
	// record per tx slot (nil = unused), their Merkle root, and a proof per
	// included tx.
	BatchIndex uint64
	Records    []*TxRecord
	TxRoot     fr.Element
	Proofs     []InclusionProof
}

// Options are for tests only: Unchecked applies every move as given, with no
// balance, key or slot checks, to produce invalid witnesses the circuit must
// reject.
type Options struct {
	Unchecked bool
	// FromOverride makes an action debit this account instead of the sender.
	FromOverride map[[2]int]uint32
	// LogAt (with Unchecked) keeps the log leaf at another index, so a test can
	// build an otherwise consistent witness that only the circuit's
	// "log update is at LOG_INDEX" rule rejects.
	LogAt *uint32
	// OverwriteKeys (with Unchecked) builds a register_key onto an account that
	// already has a key as a *consistent* witness: the move carries new-old, so the
	// circuit's "old + new" arithmetic lands on the replaced key. Only the
	// "never overwrite a key" rule can reject it.
	OverwriteKeys bool
	// FreeActions (with Unchecked) marks tx slots that are inactive (no nonce
	// bump, record 0) yet still apply their moves: a free, replayable action.
	// Only the "inactive tx has only no-ops" rule can reject it.
	FreeActions map[int]bool
}

func GenesisTree(cfg Config) (*Tree, error) {
	t := NewTree(cfg.Depth)
	for _, g := range cfg.Genesis {
		if g.Index >= LogIndex(cfg.Depth) {
			return nil, fmt.Errorf("genesis %d: the last leaf is reserved for the log", g.Index)
		}
		pk, err := parseFr(g.Pk)
		if err != nil {
			return nil, fmt.Errorf("genesis %d: %w", g.Index, err)
		}
		t.Set(g.Index, Account{Pk: pk, Qor: g.Qor, Usd: g.Usd})
	}
	return t, nil
}

func parseFr(h string) (fr.Element, error) {
	var e fr.Element
	h = strings.TrimPrefix(h, "0x")
	if h == "" {
		return e, nil
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return e, err
	}
	v := new(big.Int).SetBytes(b)
	if v.Cmp(fr.Modulus()) >= 0 {
		return e, fmt.Errorf("value is not below r")
	}
	e.SetBigInt(v)
	return e, nil
}

func bi(e fr.Element) *big.Int { return e.BigInt(new(big.Int)) }

func leafW(a Account) Leaf {
	return Leaf{bi(a.Pk), a.Qor, a.Usd, a.Nonce, bi(a.Orders)}
}

type builder struct {
	cfg   Config
	t     *Tree
	w     *Circuit
	opts  Options
	withd []Withdrawal
}

// update records u's old leaf and path at the current state, then writes next.
func (b *builder) update(idx uint32, next func(Account) Account) Update {
	old := b.t.Get(idx)
	path := b.t.Path(idx)
	u := Update{Index: idx, Old: leafW(old), Path: make([]frontend.Variable, len(path))}
	for i, p := range path {
		u.Path[i] = bi(p)
	}
	b.t.Set(idx, next(old))
	return u
}

// updateLog records the log leaf's old value and path (after every account
// update) and writes the new one.
func (b *builder) updateLog(idx uint32, next Account) Update {
	return b.update(idx, func(Account) Account { return next })
}

func (b *builder) noop(idx uint32) Move {
	same := func(a Account) Account { return a }
	return Move{IsTransfer: 0, IsWithdraw: 0, IsRegister: 0, Asset: 0, Amount: 0, PkCommit: 0,
		From: b.update(idx, same), To: b.update(idx, same)}
}

func bal(a Account, asset uint8) uint64 {
	if asset == 1 {
		return a.Usd
	}
	return a.Qor
}

func addBal(a Account, asset uint8, d uint64, sub bool) Account {
	p := &a.Qor
	if asset == 1 {
		p = &a.Usd
	}
	if sub {
		*p -= d
	} else {
		*p += d
	}
	return a
}

// move is one resolved move.
type move struct {
	kind     int // 0 noop, 1 transfer, 2 withdraw, 3 register
	from, to uint32
	asset    uint8
	amount   uint64
	pk       fr.Element
	recip    string
}

// record is the move's tx-record form (spec/inclusion.md); an unapplied move is all zeros.
func (mv move) record(applied bool) MoveRecord {
	if !applied || mv.kind == 0 {
		return MoveRecord{}
	}
	var rc fr.Element
	if mv.kind == 2 {
		rc, _ = RecipientCommit(mv.recip)
	}
	return NewMoveRecord(uint8(mv.kind), mv.asset, mv.amount, mv.from, mv.to, mv.pk, rc)
}

// check reports why mv cannot apply on top of accounts in ov (an overlay of
// the tree), or "" and the overlay updated.
func (b *builder) check(mv move, ov map[uint32]Account, wcount *int) string {
	get := func(i uint32) Account {
		if a, ok := ov[i]; ok {
			return a
		}
		return b.t.Get(i)
	}
	if uint64(mv.from) >= 1<<b.cfg.Depth || uint64(mv.to) >= 1<<b.cfg.Depth {
		return "account index out of range"
	}
	f := get(mv.from)
	switch mv.kind {
	case 1, 2:
		if mv.asset > 1 {
			return "unknown asset"
		}
		if mv.kind == 2 {
			if mv.asset != 0 {
				return "only QOR can be withdrawn"
			}
			if len(mv.recip) != RecipientLen || !strings.HasPrefix(mv.recip, "qor1") {
				return "recipient must be a 42-character qor1 address"
			}
			if *wcount >= b.cfg.Withdrawals {
				return "batch withdrawal slots are full"
			}
		}
		if bal(f, mv.asset) < mv.amount {
			return "insufficient balance"
		}
		ov[mv.from] = addBal(f, mv.asset, mv.amount, true)
		if mv.kind == 1 {
			t := get(mv.to)
			if bal(t, mv.asset) > ^uint64(0)-mv.amount {
				return "balance overflow"
			}
			ov[mv.to] = addBal(t, mv.asset, mv.amount, false)
		} else {
			*wcount++
		}
	case 3:
		if !f.Pk.IsZero() {
			return "account already has a key"
		}
		if mv.pk.IsZero() {
			return "empty key"
		}
		f.Pk = mv.pk
		ov[mv.from] = f
	}
	return ""
}

func (b *builder) apply(mv move) Move {
	if mv.kind == 0 {
		return b.noop(mv.from)
	}
	out := Move{IsTransfer: 0, IsWithdraw: 0, IsRegister: 0, Asset: int(mv.asset), Amount: mv.amount, PkCommit: 0}
	switch mv.kind {
	case 1:
		out.IsTransfer = 1
	case 2:
		out.IsWithdraw = 1
		b.withd = append(b.withd, Withdrawal{Recipient: mv.recip, Amount: mv.amount})
	case 3:
		out.IsRegister = 1
		out.PkCommit = bi(mv.pk)
		out.Amount = 0
		if old := b.t.Get(mv.from); b.opts.OverwriteKeys && !old.Pk.IsZero() {
			var delta fr.Element
			delta.Sub(&mv.pk, &old.Pk)
			out.PkCommit = bi(delta)
		}
	}
	out.From = b.update(mv.from, func(a Account) Account {
		switch mv.kind {
		case 1, 2:
			return addBal(a, mv.asset, mv.amount, true)
		case 3:
			a.Pk = mv.pk
		}
		return a
	})
	to := mv.from
	if mv.kind == 1 {
		to = mv.to
	}
	out.To = b.update(to, func(a Account) Account {
		if mv.kind == 1 {
			return addBal(a, mv.asset, mv.amount, false)
		}
		return a
	})
	return out
}

// Build executes batch on t (which it mutates) and returns the full circuit
// assignment. prevIsGenesis marks batch 0, whose prev_state_root input is 0.
func Build(cfg Config, t *Tree, prevIsGenesis bool, batch Batch, opts Options) (*Circuit, *Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	if len(batch.Txs) > cfg.Txs {
		return nil, nil, fmt.Errorf("batch has %d txs, the circuit takes %d", len(batch.Txs), cfg.Txs)
	}
	w, err := New(cfg)
	if err != nil {
		return nil, nil, err
	}
	b := &builder{cfg: cfg, t: t, w: w, opts: opts}
	if prevIsGenesis && !opts.Unchecked {
		g, _ := GenesisTree(cfg)
		if g.Root() != t.Root() {
			return nil, nil, fmt.Errorf("batch 0 must start from the genesis state")
		}
	}
	res := &Result{PrevRoot: t.Root()}
	logIdx := LogIndex(cfg.Depth)
	if opts.Unchecked && opts.LogAt != nil {
		logIdx = *opts.LogAt
	}
	res.BatchIndex = t.Get(logIdx).Nonce // the circuit reads the batch counter from the log leaf
	res.Records = make([]*TxRecord, cfg.Txs)

	for i := range w.Txs {
		w.Txs[i].Expiry, w.Txs[i].NotBefore = 0, 0
		for k := range w.Txs[i].Party {
			w.Txs[i].PartyActive[k], w.Txs[i].Party[k] = 0, 0
		}
		if i >= len(batch.Txs) {
			w.Txs[i].Active = 0
			w.Txs[i].Sender = b.update(0, func(a Account) Account { return a })
			for m := range w.Txs[i].Moves {
				w.Txs[i].Moves[m] = b.noop(0)
			}
			continue
		}
		tx := batch.Txs[i]
		expiry := uint64(math.MaxUint64)
		if tx.Expiry != nil {
			expiry = *tx.Expiry
		}
		rec := &TxRecord{Sender: tx.Sender, Expiry: expiry, NotBefore: tx.NotBefore, Parties: append([]uint32{}, tx.Parties...)}
		if !opts.Unchecked {
			if len(tx.Parties) > cfg.Parties {
				return nil, nil, fmt.Errorf("tx %d: %d parties, the circuit takes %d", i, len(tx.Parties), cfg.Parties)
			}
			seen := map[uint32]bool{tx.Sender: true}
			for _, p := range tx.Parties {
				if seen[p] || uint64(p) >= uint64(logIdx) {
					return nil, nil, fmt.Errorf("tx %d: parties must be distinct, differ from the sender and be valid accounts", i)
				}
				seen[p] = true
			}
			if res.BatchIndex < tx.NotBefore {
				return nil, nil, fmt.Errorf("tx %d: window: not valid before batch %d (this is batch %d)", i, tx.NotBefore, res.BatchIndex)
			}
			if res.BatchIndex > expiry {
				return nil, nil, fmt.Errorf("tx %d: window: expired at batch %d (this is batch %d)", i, expiry, res.BatchIndex)
			}
			if uint64(tx.Sender) >= uint64(logIdx) || uint64(tx.Payer) >= uint64(logIdx) || uint64(tx.Relayer) >= uint64(logIdx) {
				return nil, nil, fmt.Errorf("tx %d: account index is reserved or out of range", i)
			}
		}
		w.Txs[i].Expiry, w.Txs[i].NotBefore = expiry, tx.NotBefore
		for k, p := range tx.Parties {
			if k < len(w.Txs[i].Party) {
				w.Txs[i].PartyActive[k], w.Txs[i].Party[k] = 1, p
			}
		}
		sender := tx.Sender
		auth := map[uint32]bool{sender: true}
		for _, p := range tx.Parties {
			auth[p] = true
		}
		tr := TxResult{Applied: make([]bool, len(tx.Actions))}
		if len(tx.Actions) > cfg.Moves-1 {
			return nil, nil, fmt.Errorf("tx %d has %d actions, max %d", i, len(tx.Actions), cfg.Moves-1)
		}
		fee := move{kind: 1, from: tx.Payer, to: tx.Relayer, asset: tx.FeeAsset, amount: tx.Fee}
		if tx.Fee == 0 {
			fee = move{kind: 0, from: tx.Payer}
		}
		wc := len(b.withd)
		if !opts.Unchecked {
			if uint64(tx.Sender) >= 1<<cfg.Depth {
				return nil, nil, fmt.Errorf("tx %d: sender out of range", i)
			}
			if why := b.check(fee, map[uint32]Account{}, &wc); why != "" {
				// a tx whose fee cannot be paid is not included at all
				return nil, nil, fmt.Errorf("tx %d: fee: %s", i, why)
			}
		}
		free := opts.Unchecked && opts.FreeActions[i]
		w.Txs[i].Active = 1
		rec.NonceBefore = b.t.Get(tx.Sender).Nonce
		if free {
			w.Txs[i].Active = 0
			w.Txs[i].Sender = b.update(tx.Sender, func(a Account) Account { return a })
		} else {
			w.Txs[i].Sender = b.update(tx.Sender, func(a Account) Account { a.Nonce++; return a })
		}
		w.Txs[i].Moves[0] = b.apply(fee)
		rec.Moves = make([]MoveRecord, cfg.Moves)
		rec.Moves[0] = fee.record(true)

		// resolve actions; consecutive atomic actions stand or fall together
		moves := make([]move, len(tx.Actions))
		for j, a := range tx.Actions {
			mv := move{from: tx.Sender, to: a.To, asset: a.Asset, amount: a.Amount, recip: a.Recipient}
			if a.From != nil {
				mv.from = *a.From
			}
			if o, ok := opts.FromOverride[[2]int{i, j}]; ok {
				mv.from = o
			}
			switch a.Kind {
			case "transfer":
				mv.kind = 1
			case "withdraw":
				mv.kind = 2
			case "register_key":
				mv.kind = 3
				pk, err := parseFr(a.PkCommit)
				if err != nil {
					return nil, nil, fmt.Errorf("tx %d action %d: pk_commit: %w", i, j, err)
				}
				mv.pk = pk
			default:
				return nil, nil, fmt.Errorf("tx %d action %d: unknown kind %q", i, j, a.Kind)
			}
			if !opts.Unchecked {
				// the debited account must be the sender or a party; a key is registered on the sender only
				if !auth[mv.from] || (mv.kind == 3 && mv.from != tx.Sender) {
					return nil, nil, fmt.Errorf("tx %d action %d: auth: account %d is not the sender or a party of this tx", i, j, mv.from)
				}
				if uint64(mv.to) >= uint64(logIdx) {
					return nil, nil, fmt.Errorf("tx %d action %d: account index is reserved or out of range", i, j)
				}
			}
			moves[j] = mv
		}
		for j := 0; j < len(moves); {
			end := j + 1
			if tx.Actions[j].Atomic {
				for end < len(moves) && tx.Actions[end].Atomic {
					end++
				}
			}
			ok := true
			if !opts.Unchecked {
				ov := map[uint32]Account{}
				wc := len(b.withd)
				for k := j; k < end; k++ {
					if why := b.check(moves[k], ov, &wc); why != "" {
						ok = false
						tr.Skipped = append(tr.Skipped, fmt.Sprintf("action %d: %s", k, why))
						break
					}
				}
			}
			for k := j; k < end; k++ {
				if ok {
					oldPk := b.t.Get(moves[k].from).Pk
					w.Txs[i].Moves[1+k] = b.apply(moves[k])
					tr.Applied[k] = true
					rec.Moves[1+k] = moves[k].record(true)
					if opts.Unchecked && opts.OverwriteKeys && moves[k].kind == 3 && !oldPk.IsZero() {
						rec.Moves[1+k].Aux.Sub(&moves[k].pk, &oldPk) // the record carries what the circuit saw: new - old
					}
				} else {
					w.Txs[i].Moves[1+k] = b.noop(tx.Sender)
				}
			}
			j = end
		}
		for m := 1 + len(moves); m < cfg.Moves; m++ {
			w.Txs[i].Moves[m] = b.noop(tx.Sender)
		}
		tr.Included = true
		res.Txs = append(res.Txs, tr)
		if !free {
			res.Records[i] = rec
		}
	}

	// Inclusion: commit the tx records and the batch counter in the log leaf (spec/inclusion.md).
	leaves := make([]fr.Element, cfg.Txs)
	for i, r := range res.Records {
		leaves[i] = RecordLeaf(r, cfg.Parties)
	}
	res.TxRoot = TxRoot(leaves)
	w.Log = b.updateLog(logIdx, LogAccount(res.TxRoot, res.BatchIndex))
	for i, r := range res.Records {
		if r != nil {
			res.Proofs = append(res.Proofs, InclusionProof{
				BatchIndex: res.BatchIndex, Record: *r, TxIndex: i, TxPath: TxPath(leaves, i), LogPath: t.Path(logIdx),
			})
		}
	}

	res.NewRoot = t.Root()
	res.Withdrawals = b.withd
	res.WithdrawalsRoot = WithdrawalsRoot(cfg.ChainID, cfg.RollupID, b.withd)
	if prevIsGenesis {
		w.PrevStateRoot = 0
	} else {
		w.PrevStateRoot = bi(res.PrevRoot)
	}
	w.StateRoot = bi(res.NewRoot)
	w.WithdrawalsRoot = ModR(res.WithdrawalsRoot)
	for k := range w.Recipients {
		for j := range w.Recipients[k] {
			w.Recipients[k][j] = 0
		}
		if k < len(b.withd) {
			for j := 0; j < RecipientLen && j < len(b.withd[k].Recipient); j++ {
				w.Recipients[k][j] = int(b.withd[k].Recipient[j])
			}
		}
	}
	return w, res, nil
}

// SetDataHash sets the data_hash public input (32-byte big-endian, reduced mod r).
func (c *Circuit) SetDataHash(h [32]byte) {
	v := ModR(h)
	c.DataHash = v
	sq := new(big.Int).Mul(v, v)
	c.DataHashSq = sq.Mod(sq, fr.Modulus())
}
