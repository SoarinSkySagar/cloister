package ledger

import (
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Full Groth16 round trip (slow, several GB of RAM). Run with
// CLOISTER_GROTH16=1 go test ./ledger -run Groth16 -v
func TestGroth16EndToEnd(t *testing.T) {
	if os.Getenv("CLOISTER_GROTH16") == "" {
		t.Skip("set CLOISTER_GROTH16=1")
	}
	cfg := testConfig()
	c, _ := New(cfg)
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("compile: %d constraints, %d public, %v", ccs.GetNbConstraints(), ccs.GetNbPublicVariables(), time.Since(t0))
	if ccs.GetNbPublicVariables() != 5 { // the constant 1 + four inputs
		t.Fatalf("public variables %d", ccs.GetNbPublicVariables())
	}
	t0 = time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("setup: %v", time.Since(t0))
	if n := vk.NbPublicWitness(); n != 4 {
		t.Fatalf("vk public witness %d", n)
	}
	// no BSB22 commitment: the chain gets a plain four-input Groth16 statement
	if k := vk.(*groth16bls.VerifyingKey); len(k.CommitmentKeys) != 0 || len(k.PublicAndCommitmentCommitted) != 0 {
		t.Fatalf("vk has %d commitment keys", len(k.CommitmentKeys))
	}
	w, _, _ := build(t, cfg, batch2, Options{})
	full, err := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	t0 = time.Now()
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prove: %v", time.Since(t0))
	pub, _ := full.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
}
