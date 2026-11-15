package ledger

// Randomised differential testing of circuit v3. Random batches (multi-party, atomic groups, overdrafts, receivers at the
// 2^64 limit, full withdrawal slots, keys already set) go through:
//
//   1. the honest builder (Build, checked mode),
//   2. a reference interpreter written here from the spec, sharing no code with the builder, and
//   3. the circuit itself (every honest witness must satisfy it).
//
// They must agree on which actions applied, on every final balance, on conservation, on the withdrawals, on the
// transaction digests, and on every inclusion proof. Then each applied single action is re-run through the
// ADVERSARIAL builder with its skip bit set and nothing else changed: the circuit must refuse every one (finding F2).
//
//	go test ./ledger -run Fuzz -count=1                 (40 batches, about a minute)
//	FUZZ_BATCHES=500 FUZZ_SEED=7 go test ./ledger -run Fuzz -count=1 -timeout 0

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func fuzzConfig() Config {
	return Config{
		Depth: 16, Txs: 4, Moves: 4, Withdrawals: 2, Parties: 2, Relayer: relay,
		ChainID: "qorechain-diana", RollupID: "cloister-fuzz",
		Genesis: []GenesisAccount{
			{Index: treas, Pk: "01", Qor: 1_000_000_000_000, Usd: 1_000_000_000_000}, {Index: relay, Pk: "02"},
			{Index: 2, Pk: "a2", Qor: 1000, Usd: 50}, {Index: 3, Pk: "a3", Qor: 10, Usd: 700},
			{Index: 4}, // an empty account with no key
			{Index: 5, Pk: "a5", Qor: math.MaxUint64 - 3, Usd: math.MaxUint64 - 3}, // next to the limit
		},
	}
}

// ---- the reference interpreter ----

type refAccount struct {
	key       bool
	qor, usd  uint64
	nonce     uint64
	everKeyed bool
}

type refState struct {
	acc       map[uint32]*refAccount
	withdrawn *big.Int // sums can exceed 2^64: accounts here hold up to 2^64-1 each
	slots     int
	maxSlots  int
}

func (s *refState) get(i uint32) *refAccount {
	if a, ok := s.acc[i]; ok {
		return a
	}
	a := &refAccount{}
	s.acc[i] = a
	return a
}

func (s *refState) clone() *refState {
	c := &refState{acc: map[uint32]*refAccount{}, withdrawn: new(big.Int).Set(s.withdrawn), slots: s.slots, maxSlots: s.maxSlots}
	for k, v := range s.acc {
		x := *v
		c.acc[k] = &x
	}
	return c
}

func (a *refAccount) bal(asset uint8) *uint64 {
	if asset == 1 {
		return &a.usd
	}
	return &a.qor
}

// leg applies one action to s, or says why it cannot.
func (s *refState) leg(sender uint32, a ActionIn) string {
	from := sender
	if a.From != nil {
		from = *a.From
	}
	f := s.get(from)
	switch a.Kind {
	case "transfer":
		fb := f.bal(a.Asset)
		if *fb < a.Amount {
			return "insufficient"
		}
		*fb -= a.Amount
		tb := s.get(a.To).bal(a.Asset)
		if *tb > math.MaxUint64-a.Amount {
			return "overflow"
		}
		*tb += a.Amount
	case "withdraw":
		if s.slots >= s.maxSlots {
			return "slots"
		}
		if f.qor < a.Amount {
			return "insufficient"
		}
		f.qor -= a.Amount
		s.slots++
		s.withdrawn.Add(s.withdrawn, new(big.Int).SetUint64(a.Amount))
	case "register_key":
		if f.key {
			return "key"
		}
		f.key = true
	}
	return ""
}

// run executes the batch; it returns the applied flags per tx, or an error naming a tx whose fee cannot be paid.
func (s *refState) run(cfg Config, batch Batch) ([][]bool, error) {
	var out [][]bool
	for i, tx := range batch.Txs {
		fee := s.get(tx.Payer).bal(tx.FeeAsset)
		if tx.Fee > 0 {
			if *fee < tx.Fee {
				return nil, fmt.Errorf("tx %d: fee", i)
			}
			*fee -= tx.Fee
			rb := s.get(cfg.Relayer).bal(tx.FeeAsset)
			if *rb > math.MaxUint64-tx.Fee {
				return nil, fmt.Errorf("tx %d: fee: the relayer would overflow", i) // the builder refuses this as a fee failure too
			}
			*rb += tx.Fee
		}
		s.get(tx.Sender).nonce++
		applied := make([]bool, len(tx.Actions))
		for j := 0; j < len(tx.Actions); {
			end := j + 1
			if tx.Actions[j].Atomic {
				for end < len(tx.Actions) && tx.Actions[end].Atomic {
					end++
				}
			}
			trial := s.clone()
			ok := true
			for k := j; k < end; k++ {
				if why := trial.leg(tx.Sender, tx.Actions[k]); why != "" {
					ok = false
					break
				}
			}
			if ok {
				*s = *trial
				for k := j; k < end; k++ {
					applied[k] = true
				}
			}
			j = end
		}
		out = append(out, applied)
	}
	return out, nil
}

// ---- the generator ----

type gen struct{ r *rand.Rand }

func (g gen) pick(xs ...uint64) uint64 { return xs[g.r.Intn(len(xs))] }

func (g gen) amount(have uint64) uint64 {
	switch g.r.Intn(10) {
	case 0:
		return 0
	case 1, 2, 3:
		return 1 + uint64(g.r.Intn(20))
	case 4:
		return have
	case 5:
		return have + 1
	case 6:
		return math.MaxUint64 - uint64(g.r.Intn(4))
	case 7, 8:
		return have / 2
	}
	return uint64(g.r.Intn(2000))
}

func (g gen) batch(tree *Tree) Batch {
	users := []uint32{2, 3, 4, 5}
	var b Batch
	for t := 0; t < 1+g.r.Intn(4); t++ {
		sender := users[g.r.Intn(len(users))]
		tx := TxIn{Sender: sender, Payer: sender, Relayer: relay}
		if g.r.Intn(10) < 7 {
			tx.Payer = treas // the treasury can pay in either asset; a user often cannot
		}
		if g.r.Intn(3) > 0 {
			tx.Fee = uint64(g.r.Intn(30))
			if tx.Payer == treas {
				tx.FeeAsset = uint8(g.r.Intn(2))
			}
		}
		auth := []uint32{sender}
		for _, u := range users {
			if u != sender && len(tx.Parties) < 2 && g.r.Intn(2) == 0 {
				tx.Parties = append(tx.Parties, u)
				auth = append(auth, u)
			}
		}
		for a := 0; a < 1+g.r.Intn(3); a++ {
			from := auth[g.r.Intn(len(auth))]
			act := ActionIn{Atomic: g.r.Intn(4) == 0, From: &from}
			acct := tree.Get(from)
			switch g.r.Intn(5) {
			case 0, 1, 2:
				act.Kind = "transfer"
				act.To = uint32(g.r.Intn(8))
				act.Asset = uint8(g.r.Intn(2))
				if act.Asset == 1 {
					act.Amount = g.amount(acct.Usd)
				} else {
					act.Amount = g.amount(acct.Qor)
				}
			case 3:
				act.Kind = "withdraw"
				act.Recipient = l1Addr
				act.Amount = g.amount(acct.Qor)
			default:
				act.Kind = "register_key"
				act.PkCommit = fmt.Sprintf("%08x", 1+g.r.Intn(1<<20))
				act.From = &sender // sender-only
				act.To = 0
			}
			tx.Actions = append(tx.Actions, act)
		}
		b.Txs = append(b.Txs, tx)
	}
	return b
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// ---- the test ----

func TestFuzzHonestBatchesAgreeWithTheReferenceAndTheCircuit(t *testing.T) {
	cfg := fuzzConfig()
	seed := int64(envInt("FUZZ_SEED", 1))
	batches := envInt("FUZZ_BATCHES", 40)
	skippedSeen, appliedSeen, adversarial, refused, ran := 0, 0, 0, 0, 0
	only := envInt("FUZZ_ONLY", -1) // replay one batch of a failing run
	for it := 0; it < batches; it++ {
		if only >= 0 && it != only {
			continue
		}
		ran++
		g := gen{rand.New(rand.NewSource(seed*1_000_003 + int64(it)))}
		tree, err := GenesisTree(cfg)
		if err != nil {
			t.Fatal(err)
		}
		tag := fmt.Sprintf("seed %d batch %d", seed, it)

		// reference state from the same genesis
		ref := &refState{acc: map[uint32]*refAccount{}, withdrawn: new(big.Int), maxSlots: cfg.Withdrawals}
		for _, ga := range cfg.Genesis {
			*ref.get(ga.Index) = refAccount{key: ga.Pk != "", qor: ga.Qor, usd: ga.Usd}
		}
		supplyQor, supplyUsd := new(big.Int), new(big.Int)
		for _, a := range ref.acc {
			supplyQor.Add(supplyQor, new(big.Int).SetUint64(a.qor))
			supplyUsd.Add(supplyUsd, new(big.Int).SetUint64(a.usd))
		}

		b := g.batch(tree)
		before := tree.Clone()
		w, res, err := Build(cfg, tree, true, b, Options{})
		wantApplied, refErr := ref.run(cfg, b)
		if err != nil {
			if refErr == nil {
				t.Fatalf("%s: the builder refused a batch the reference accepts: %v\nbatch: %+v", tag, err, b)
			}
			if !strings.Contains(err.Error(), "fee") {
				t.Fatalf("%s: the builder refused for an unexpected reason: %v", tag, err)
			}
			refused++
			continue
		}
		if refErr != nil {
			t.Fatalf("%s: the reference refuses (%v) a batch the builder accepted\nbatch: %+v", tag, refErr, b)
		}
		w.SetDataHash([32]byte{byte(it)})
		if err := solves(t, cfg, w); err != nil {
			t.Fatalf("%s: the circuit rejects an honest witness: %v\nbatch: %+v", tag, err, b)
		}

		// 1. applied flags and balances
		for i := range b.Txs {
			for j := range b.Txs[i].Actions {
				if res.Txs[i].Applied[j] != wantApplied[i][j] {
					t.Fatalf("%s: tx %d action %d: builder applied=%v, reference applied=%v (%v)\nbatch: %+v", tag, i, j, res.Txs[i].Applied[j], wantApplied[i][j], res.Txs[i].Skipped, b)
				}
				if wantApplied[i][j] {
					appliedSeen++
				} else {
					skippedSeen++
				}
			}
		}
		gotQor, gotUsd := new(big.Int), new(big.Int)
		for idx := uint32(0); idx < 8; idx++ {
			a, r := tree.Get(idx), ref.get(idx)
			if a.Qor != r.qor || a.Usd != r.usd || a.Nonce != r.nonce || (!a.Pk.IsZero()) != r.key {
				t.Fatalf("%s: account %d differs: builder qor=%d usd=%d nonce=%d key=%v, reference %+v\nbatch: %+v", tag, idx, a.Qor, a.Usd, a.Nonce, !a.Pk.IsZero(), *r, b)
			}
			gotQor.Add(gotQor, new(big.Int).SetUint64(a.Qor))
			gotUsd.Add(gotUsd, new(big.Int).SetUint64(a.Usd))
		}
		// 2. conservation: QOR only leaves through withdrawals, USD never leaves
		if new(big.Int).Add(gotQor, ref.withdrawn).Cmp(supplyQor) != 0 || gotUsd.Cmp(supplyUsd) != 0 {
			t.Fatalf("%s: value was created or destroyed (qor %v+%v vs %v, usd %v vs %v)\nbatch: %+v", tag, gotQor, ref.withdrawn, supplyQor, gotUsd, supplyUsd, b)
		}
		wsum := new(big.Int)
		for _, wd := range res.Withdrawals {
			wsum.Add(wsum, new(big.Int).SetUint64(wd.Amount))
		}
		if wsum.Cmp(ref.withdrawn) != 0 || len(res.Withdrawals) != ref.slots {
			t.Fatalf("%s: withdrawals differ: builder %v in %d, reference %v in %d", tag, wsum, len(res.Withdrawals), ref.withdrawn, ref.slots)
		}

		// 3. every record's digest is the digest of its transaction, and every inclusion proof reaches the state root
		dom := DomainConst(cfg.ChainID, cfg.RollupID)
		for i, tx := range b.Txs {
			var planned []PlannedMove
			for _, a := range tx.Actions {
				mv := move{from: tx.Sender, to: a.To, asset: a.Asset, amount: a.Amount, recip: a.Recipient}
				if a.From != nil {
					mv.from = *a.From
				}
				switch a.Kind {
				case "transfer":
					mv.kind = 1
				case "withdraw":
					mv.kind = 2
				case "register_key":
					mv.kind = 3
					mv.pk, _ = parseFr(a.PkCommit)
				}
				planned = append(planned, mv.planned(a.Atomic))
			}
			feeAsset := uint8(0)
			if tx.Fee > 0 {
				feeAsset = tx.FeeAsset
			}
			want := TxDigest(dom, tx.Sender, res.Records[i].NonceBefore, math.MaxUint64, 0, tx.Payer, feeAsset, tx.Fee, tx.Parties, cfg.Parties, planned, cfg.Moves-1)
			if !want.Equal(&res.Records[i].Digest) {
				t.Fatalf("%s: tx %d: the record's digest is not the digest of its transaction", tag, i)
			}
			// a skipped action is a zero move; an applied one is not
			for j := range tx.Actions {
				isZero := res.Records[i].Moves[1+j] == (MoveRecord{})
				if isZero == res.Txs[i].Applied[j] {
					t.Fatalf("%s: tx %d action %d: applied=%v but the record's move is zero=%v", tag, i, j, res.Txs[i].Applied[j], isZero)
				}
			}
		}
		for _, p := range res.Proofs {
			root, err := p.StateRoot(cfg.Depth, cfg.Txs, cfg.Parties)
			if err != nil || !root.Equal(&res.NewRoot) {
				t.Fatalf("%s: an inclusion proof does not reach the state root (%v)", tag, err)
			}
		}

		// 4. F2: skip every applied single action (one at a time) in an otherwise consistent adversarial witness; the circuit must refuse
		adversarial += fuzzSkipApplied(t, cfg, before, b, res, tag)
	}
	t.Logf("%d batches (%d refused for an unpayable fee): %d actions applied, %d skipped, %d skip-an-applied-action attacks refused", ran, refused, appliedSeen, skippedSeen, adversarial)
	if skippedSeen == 0 || appliedSeen == 0 {
		t.Fatal("the generator never produced both applied and skipped actions: it is not exercising the circuit")
	}
}

// fuzzSkipApplied takes batches whose every tx is a plain single-sender tx and, for one applied non-atomic action at
// a time, builds the witness in which that action is skipped and everything else is as the honest run left it.
func fuzzSkipApplied(t *testing.T, cfg Config, before *Tree, b Batch, res *Result, tag string) int {
	t.Helper()
	count := 0
	for i, tx := range b.Txs {
		if len(tx.Parties) > 0 {
			continue
		}
		for j, a := range tx.Actions {
			// only the last action: later actions could depend on it, and a different rule would then reject the witness
			if a.Atomic || !res.Txs[i].Applied[j] || j != len(tx.Actions)-1 {
				continue
			}
			// replay the batch in the adversarial builder up to and including tx i, with action j skipped
			rt := newRawTree(before)
			var advs []advTx
			ok := true
			for ti := 0; ti <= i; ti++ {
				at, good := toAdvTx(cfg, b.Txs[ti], res.Txs[ti].Applied)
				if !good {
					ok = false
					break
				}
				if ti == i {
					at.moves[1+j].skip = fe(1)
				}
				advs = append(advs, at)
			}
			if !ok {
				continue
			}
			recips := map[int]string{}
			for k := 0; k < cfg.Withdrawals; k++ {
				recips[k] = l1Addr
			}
			w := advBuild(t, cfg, rt, advBatch{txs: advs, recipients: recips})
			if err := solves(t, cfg, w); err == nil {
				t.Fatalf("%s: tx %d action %d: the circuit accepted a skip of an action that applied\nbatch: %+v", tag, i, j, b)
			}
			count++
		}
	}
	return count
}

// toAdvTx maps a plain single-sender tx (no parties) to the adversarial builder's form, with the honest skips.
func toAdvTx(cfg Config, tx TxIn, applied []bool) (advTx, bool) {
	if len(tx.Parties) > 0 {
		return advTx{}, false
	}
	at := advTx{active: fe(1), sender: tx.Sender, expiry: fe(math.MaxUint64)}
	at.moves = make([]advMove, cfg.Moves)
	for m := range at.moves {
		at.moves[m] = noopMove(treas)
	}
	if tx.Fee > 0 {
		at.moves[0] = transferMove(tx.Payer, cfg.Relayer, fe(uint64(tx.FeeAsset)), fe(tx.Fee))
	} else {
		at.moves[0] = noopMove(tx.Payer)
	}
	at.partyActive = make([]fr.Element, cfg.Parties)
	at.party = make([]uint32, cfg.Parties)
	for j, a := range tx.Actions {
		from := tx.Sender
		if a.From != nil {
			from = *a.From
		}
		var mv advMove
		switch a.Kind {
		case "transfer":
			mv = transferMove(from, a.To, fe(uint64(a.Asset)), fe(a.Amount))
		case "withdraw":
			mv = advMove{withdraw: fe(1), amount: fe(a.Amount), from: from, to: from}
		case "register_key":
			pk, _ := parseFr(a.PkCommit)
			mv = advMove{register: fe(1), pk: pk, from: from, to: from}
		}
		if a.Atomic {
			mv.atomic = fe(1)
		}
		if !applied[j] {
			mv.skip = fe(1)
		}
		at.moves[1+j] = mv
	}
	return at, true
}
