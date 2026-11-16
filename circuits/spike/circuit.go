// Package spike holds the trivial go/no-go circuit: it has the exact public
// interface the chain verifies (four inputs, in order) but a toy transition
// rule, state_root = prev_state_root + 1. It exists only to prove the
// VK/proof encoding and the settlement path on a cloister-dev-N rollup.
package spike

import "github.com/consensys/gnark/frontend"

// Circuit's public inputs follow the chain's order (spec/public-inputs.md):
// prev_state_root, state_root, data_hash, withdrawals_root.
type Circuit struct {
	PrevStateRoot   frontend.Variable `gnark:",public"`
	StateRoot       frontend.Variable `gnark:",public"`
	DataHash        frontend.Variable `gnark:",public"`
	WithdrawalsRoot frontend.Variable `gnark:",public"`

	// Private witnesses that bind DataHash and WithdrawalsRoot into the
	// constraint system, so neither public input is left unconstrained.
	DataHashSq        frontend.Variable
	WithdrawalsRootSq frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.StateRoot, api.Add(c.PrevStateRoot, 1))
	api.AssertIsEqual(c.DataHashSq, api.Mul(c.DataHash, c.DataHash))
	api.AssertIsEqual(c.WithdrawalsRootSq, api.Mul(c.WithdrawalsRoot, c.WithdrawalsRoot))
	return nil
}
