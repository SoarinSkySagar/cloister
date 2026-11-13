package ledger

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// shakeCircuit checks the in-circuit SHAKE-256/32 of a 138-byte message
// (two blocks, like a cloister-dev-N withdrawal leaf) against a public digest.
type shakeCircuit struct {
	Msg    [138]frontend.Variable
	Digest frontend.Variable `gnark:",public"`
}

func (c *shakeCircuit) Define(api frontend.API) error {
	b := bitAPI{api}
	msg := make([][8]frontend.Variable, len(c.Msg))
	for i, v := range c.Msg {
		bits := api.ToBinary(v, 8)
		copy(msg[i][:], bits)
	}
	api.AssertIsEqual(b.packBE(b.shake256x32(msg)), c.Digest)
	return nil
}

func TestShakeMatchesNative(t *testing.T) {
	m := WithdrawalLeafMessage("qorechain-diana", "cloister-dev-2", 0, "qor12jmzemjntpkfr4ler3rdwpemrv3qg7pzxkpxkm", 1_000_000)
	if len(m) != 138 {
		t.Fatalf("message is %d bytes", len(m))
	}
	var w shakeCircuit
	for i, v := range m {
		w.Msg[i] = v
	}
	w.Digest = ModR(shake32(m))
	if err := test.IsSolved(&shakeCircuit{}, &w, ecc.BLS12_381.ScalarField()); err != nil {
		t.Fatalf("valid digest rejected: %v", err)
	}
	// Negative: one flipped bit in the digest must fail.
	w.Digest = new(big.Int).Xor(ModR(shake32(m)), big.NewInt(1))
	if test.IsSolved(&shakeCircuit{}, &w, ecc.BLS12_381.ScalarField()) == nil {
		t.Fatal("wrong digest accepted")
	}
}
