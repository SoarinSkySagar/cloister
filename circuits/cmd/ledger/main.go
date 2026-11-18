// ledger runs circuit v1 (circuits/ledger) for one rollup.
//
//	ledger setup -dir setup/<rollup>            reads config.json, writes ccs.bin, pk.bin, vk.raw.bin,
//	                                            vk.compressed.bin and the genesis state.json
//	ledger prove -dir setup/<rollup> -batch b.json -data <hex> -out <dir>
//	                                            executes the batch on state.json, proves, verifies
//	                                            locally, writes proof.{raw,compressed}.bin, result.json
//	                                            and next-state.json (state.json is not touched)
//
// The setup is single-party: testnet only.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/soarinskysagar/cloister/circuits/ledger"
)

type rawWriter interface {
	WriteRawTo(io.Writer) (int64, error)
}

// State is the persisted rollup state between batches.
type State struct {
	Batches int    `json:"batches"` // batches already settled; 0 = genesis (also the batch counter in the log leaf)
	Root    string `json:"root"`
	// TxRoot is the latest batch's transaction root, held in the reserved log
	// leaf (spec/state.md). The log leaf is not an account and is not listed below.
	TxRoot   string         `json:"tx_root,omitempty"`
	Accounts []StateAccount `json:"accounts"`
}

type StateAccount struct {
	Index uint32 `json:"index"`
	Pk    string `json:"pk_commit"`
	Qor   uint64 `json:"qor"`
	Usd   uint64 `json:"usd"`
	Nonce uint64 `json:"nonce"`
}

func hex32(e fr.Element) string { b := e.Bytes(); return hex.EncodeToString(b[:]) }

func toState(t *ledger.Tree, batches int, depth int) State {
	s := State{Batches: batches, Root: hex32(t.Root())}
	logIdx := ledger.LogIndex(depth)
	if batches > 0 {
		s.TxRoot = hex32(t.Get(logIdx).Pk)
	}
	for i := uint32(0); uint64(i) < 1<<depth; i++ {
		a := t.Get(i)
		if a.IsEmpty() || i == logIdx {
			continue
		}
		s.Accounts = append(s.Accounts, StateAccount{i, hex32(a.Pk), a.Qor, a.Usd, a.Nonce})
	}
	return s
}

func fromState(s State, depth int) *ledger.Tree {
	t := ledger.NewTree(depth)
	for _, a := range s.Accounts {
		pk, ok := new(big.Int).SetString(a.Pk, 16)
		if !ok {
			log.Fatalf("bad pk_commit for account %d", a.Index)
		}
		var e fr.Element
		e.SetBigInt(pk)
		if a.Index >= ledger.LogIndex(depth) {
			log.Fatalf("state.json lists account %d: the last leaf is reserved for the log", a.Index)
		}
		t.Set(a.Index, ledger.Account{Pk: e, Qor: a.Qor, Usd: a.Usd, Nonce: a.Nonce})
	}
	if s.Batches > 0 {
		root, ok := new(big.Int).SetString(s.TxRoot, 16)
		if !ok {
			log.Fatal("state.json has batches but no tx_root")
		}
		var e fr.Element
		e.SetBigInt(root)
		t.Set(ledger.LogIndex(depth), ledger.LogAccount(e, uint64(s.Batches-1)))
	}
	if got := hex32(t.Root()); got != s.Root {
		log.Fatalf("state.json root %s does not match its accounts (%s)", s.Root, got)
	}
	return t
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		log.Fatalf("%s: %v", path, err)
	}
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
}

func writeFile(path string, f func(io.Writer) (int64, error)) {
	out, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	if _, err := f(out); err != nil {
		log.Fatal(err)
	}
}

func readFile(path string, r io.ReaderFrom) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := r.ReadFrom(f); err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
}

func loadConfig(dir string) ledger.Config {
	var cfg ledger.Config
	readJSON(filepath.Join(dir, "config.json"), &cfg)
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	return cfg
}

func setup(dir string) {
	cfg := loadConfig(dir)
	c, err := ledger.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("compiled: %d constraints (%v)", ccs.GetNbConstraints(), time.Since(t0))
	t0 = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("setup done (%v)", time.Since(t0))
	if k := vk.(*groth16bls.VerifyingKey); vk.NbPublicWitness() != 4 || len(k.CommitmentKeys) != 0 {
		log.Fatalf("unexpected vk shape: %d public, %d commitments", vk.NbPublicWitness(), len(k.CommitmentKeys))
	}
	writeFile(filepath.Join(dir, "ccs.bin"), ccs.WriteTo)
	writeFile(filepath.Join(dir, "pk.bin"), pk.(rawWriter).WriteRawTo)
	writeFile(filepath.Join(dir, "vk.raw.bin"), vk.(rawWriter).WriteRawTo)
	writeFile(filepath.Join(dir, "vk.compressed.bin"), vk.WriteTo)
	g, _ := ledger.GenesisTree(cfg)
	writeJSON(filepath.Join(dir, "state.json"), toState(g, 0, cfg.Depth))
	fmt.Printf("setup ok: %s (genesis root %s)\n", dir, hex32(g.Root()))
}

type Result struct {
	BatchIndex      int                 `json:"batch_index"`
	PrevStateRoot   string              `json:"prev_state_root"` // public input (0 for batch 0)
	StateRoot       string              `json:"state_root"`
	DataHash        string              `json:"data_hash"`         // as given (32 bytes)
	WithdrawalsRoot string              `json:"withdrawals_root"`  // full 32 bytes, "" if none
	WithdrawalsModR string              `json:"withdrawals_mod_r"` // public input
	Withdrawals     []ledger.Withdrawal `json:"withdrawals"`
	Txs             []ledger.TxResult   `json:"txs"`
	TxCount         int                 `json:"tx_count"`
	// Inclusion proofs (spec/inclusion.md): the committed transaction root and one
	// proof per included tx, in batch order, each checkable against state_root.
	TxRoot    string             `json:"tx_root"`
	Inclusion []ledger.ProofJSON `json:"inclusion"`
}

func inclusionJSON(cfg ledger.Config, res *ledger.Result) []ledger.ProofJSON {
	out := make([]ledger.ProofJSON, 0, len(res.Proofs))
	for _, p := range res.Proofs {
		out = append(out, p.JSON(cfg.ChainID, cfg.RollupID))
	}
	return out
}

func prove(dir, batchPath, dataHex, out string) {
	cfg := loadConfig(dir)
	var st State
	readJSON(filepath.Join(dir, "state.json"), &st)
	tree := fromState(st, cfg.Depth)
	var batch ledger.Batch
	readJSON(batchPath, &batch)

	db, err := hex.DecodeString(strings.TrimPrefix(dataHex, "0x"))
	if err != nil || len(db) != 32 {
		log.Fatal("-data must be 32 bytes of hex")
	}
	var data [32]byte
	copy(data[:], db)

	w, res, err := ledger.Build(cfg, tree, st.Batches == 0, batch, ledger.Options{})
	if err != nil {
		log.Fatalf("execute: %v", err)
	}
	w.SetDataHash(data)

	r := ecc.BLS12_381.ScalarField()
	ccs := groth16.NewCS(ecc.BLS12_381)
	readFile(filepath.Join(dir, "ccs.bin"), ccs)
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	f, err := os.Open(filepath.Join(dir, "pk.bin"))
	if err != nil {
		log.Fatal(err)
	}
	if _, err := pk.UnsafeReadFrom(f); err != nil {
		log.Fatal(err)
	}
	f.Close()
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	readFile(filepath.Join(dir, "vk.raw.bin"), vk)

	full, err := frontend.NewWitness(w, r)
	if err != nil {
		log.Fatal(err)
	}
	t0 := time.Now()
	proof, err := groth16.Prove(ccs.(constraint.ConstraintSystem), pk, full)
	if err != nil {
		log.Fatalf("prove: %v", err)
	}
	pub, _ := full.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		log.Fatalf("local verify failed: %v", err)
	}
	log.Printf("proved and verified locally (%v)", time.Since(t0))

	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatal(err)
	}
	writeFile(filepath.Join(out, "proof.raw.bin"), proof.(rawWriter).WriteRawTo)
	writeFile(filepath.Join(out, "proof.compressed.bin"), proof.WriteTo)

	prev := "00"
	if st.Batches > 0 {
		prev = hex32(res.PrevRoot)
	}
	wr, wm := "", ""
	if len(res.Withdrawals) > 0 {
		wr = hex.EncodeToString(res.WithdrawalsRoot[:])
		wm = fmt.Sprintf("%064x", ledger.ModR(res.WithdrawalsRoot))
	}
	writeJSON(filepath.Join(out, "result.json"), Result{
		BatchIndex: st.Batches, PrevStateRoot: fmt.Sprintf("%064s", prev), StateRoot: hex32(res.NewRoot),
		DataHash: hex.EncodeToString(data[:]), WithdrawalsRoot: wr, WithdrawalsModR: wm,
		Withdrawals: res.Withdrawals, Txs: res.Txs, TxCount: len(batch.Txs),
		TxRoot: hex32(res.TxRoot), Inclusion: inclusionJSON(cfg, res),
	})
	writeJSON(filepath.Join(out, "next-state.json"), toState(tree, st.Batches+1, cfg.Depth))
	fmt.Printf("proof ok: %s (state_root %s, %d withdrawals)\n", out, hex32(res.NewRoot), len(res.Withdrawals))
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: ledger setup|prove ...")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "", "setup directory (holds config.json)")
	batch := fs.String("batch", "", "batch input JSON")
	data := fs.String("data", "", "data_hash, 32-byte hex")
	out := fs.String("out", "", "output directory")
	fs.Parse(os.Args[2:])
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	switch os.Args[1] {
	case "setup":
		setup(*dir)
	case "prove":
		if *batch == "" || *data == "" || *out == "" {
			log.Fatal("prove needs -batch, -data and -out")
		}
		prove(*dir, *batch, *data, *out)
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}
