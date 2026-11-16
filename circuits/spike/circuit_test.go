package spike

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func sq(x int64) *big.Int { return new(big.Int).Mul(big.NewInt(x), big.NewInt(x)) }

func valid() *Circuit {
	return &Circuit{
		PrevStateRoot: 7, StateRoot: 8, DataHash: 11, WithdrawalsRoot: 13,
		DataHashSq: sq(11), WithdrawalsRootSq: sq(13),
	}
}

func TestSpikeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.GROTH16)}

	assert.ProverSucceeded(&Circuit{}, valid(), opts...)

	// Negative tests: every constraint must reject a bad witness.
	bad := valid()
	bad.StateRoot = 9 // wrong transition
	assert.ProverFailed(&Circuit{}, bad, opts...)

	bad = valid()
	bad.DataHashSq = sq(12) // data_hash binding broken
	assert.ProverFailed(&Circuit{}, bad, opts...)

	bad = valid()
	bad.WithdrawalsRootSq = sq(14) // withdrawals_root binding broken
	assert.ProverFailed(&Circuit{}, bad, opts...)
}
