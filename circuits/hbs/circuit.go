package hbs

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// VerifyCircuit is the in-circuit verifier: the same computation as Verify, with the message and leaf index as inputs.
// Root is the account's key commitment; Leaf is the account's nonce.
type VerifyCircuit struct {
	Root, Msg, Leaf frontend.Variable
	Chain           [Chains]frontend.Variable
	Path            []frontend.Variable

	Height int `gnark:"-"`
}

func NewVerifyCircuit(height int) *VerifyCircuit {
	return &VerifyCircuit{Height: height, Path: make([]frontend.Variable, height)}
}

func tweakVar(api frontend.API, use uint64, leaf frontend.Variable, chain, step uint64) frontend.Variable {
	// use<<48 | leaf<<16 | chain<<8 | step  (the leaf is below 2^32)
	k := new(big.Int).SetUint64(use<<48 | chain<<8 | step)
	return api.Add(k, api.Mul(leaf, 1<<16))
}

func (c *VerifyCircuit) Define(api frontend.API) error {
	p2, err := poseidon2.NewPoseidon2(api)
	if err != nil {
		return err
	}
	api.ToBinary(c.Leaf, c.Height) // the leaf is a valid index: Height bits

	// message digits: 256 bits big-endian, four per digit; the field element has 255 bits, so the top bit is zero
	bits := api.ToBinary(c.Msg, 255) // little-endian
	var digits [Chains]frontend.Variable
	for i := 0; i < MsgDigits; i++ {
		// digit i covers big-endian bits 4i..4i+3 of a 256-bit number: little-endian bits 255-4i .. 252-4i
		var v frontend.Variable = 0
		for b := 0; b < 4; b++ {
			pos := 255 - (4*i + b) // little-endian position of the b-th most significant bit of the digit
			var bit frontend.Variable = 0
			if pos <= 254 {
				bit = bits[pos]
			}
			v = api.Add(api.Mul(v, 2), bit)
		}
		digits[i] = v
	}
	// checksum: sum of (15 - digit), as 3 base-16 digits
	var cs frontend.Variable = 0
	for i := 0; i < MsgDigits; i++ {
		cs = api.Add(cs, api.Sub(W-1, digits[i]))
	}
	csBits := api.ToBinary(cs, 4*CsDigits)
	for j := 0; j < CsDigits; j++ {
		var v frontend.Variable = 0
		for b := 3; b >= 0; b-- {
			v = api.Add(api.Mul(v, 2), csBits[4*(CsDigits-1-j)+b])
		}
		digits[MsgDigits+j] = v
	}

	// each chain: apply the chain function (W-1-digit) times, as a fixed 15 steps with a per-step select
	var pk frontend.Variable = 0
	for ch := 0; ch < Chains; ch++ {
		cur := c.Chain[ch]
		d := digits[ch]
		// step s (0-based, absolute) is applied when digit <= s, i.e. s in [digit, 14]
		// ge[s] = 1 iff digit <= s: running sum of IsZero(digit - k) for k = 0..s
		var ge frontend.Variable = 0
		for s := 0; s < W-1; s++ {
			ge = api.Add(ge, api.IsZero(api.Sub(d, s)))
			next := p2.Compress(cur, tweakVar(api, useChain, c.Leaf, uint64(ch), uint64(s)))
			cur = api.Select(ge, next, cur)
		}
		pk = p2.Compress(pk, p2.Compress(cur, tweakVar(api, usePk, c.Leaf, uint64(ch), 0)))
	}

	// Merkle path to the root; the leaf's bits say which side the sibling is on
	idx := api.ToBinary(c.Leaf, c.Height)
	cur := pk
	for l, sib := range c.Path {
		left := api.Select(idx[l], sib, cur)
		right := api.Select(idx[l], cur, sib)
		cur = p2.Compress(left, right)
	}
	api.AssertIsEqual(cur, c.Root)
	return nil
}
