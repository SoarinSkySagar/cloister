// Package hbs is a prototype of in-circuit post-quantum authentication: a hash-based signature (Winternitz one-time
// signatures under a Merkle tree, XMSS-style) built on Poseidon2, with a verifier that is cheap enough to live inside a
// Groth16 circuit, which ML-DSA-87 is not (docs/pq-auth.md measures both).
//
// Why this shape fits the ledger:
//
//   - The account leaf already holds a 32-byte key commitment (`pk_commit`). Here it is the root of a Merkle tree of
//     one-time keys.
//   - Hash-based schemes are stateful: a one-time key must never sign two messages. The ledger already has the right
//     counter: an account's nonce rises by exactly one per included transaction, in the circuit. The key used for a
//     transaction is the leaf numbered by the nonce, so the circuit itself enforces that no leaf is used twice.
//   - The message is the transaction digest (spec/inclusion.md), a field element the circuit already computes.
//
// Security rests on Poseidon2 being a good hash (collision-, preimage- and second-preimage-resistant), not on any
// pairing or lattice assumption, so these signatures stay sound against a quantum adversary. (The Groth16 proof that carries
// them does not: that is the separate STARK question.) The tweak (leaf, chain, step) in every hash call separates all
// hash invocations, as in WOTS+/XMSS.
//
// This is a prototype: parameters are fixed (w = 16), no external audit, and the wallet side (key storage, state) is
// not written. Do not register these keys on a live rollup.
package hbs

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/soarinskysagar/cloister/circuits/ledger"
)

const (
	W         = 16 // Winternitz parameter: 4 bits per digit
	MsgDigits = 64 // 256 bits of message
	CsDigits  = 3  // checksum: at most 64*15 = 960 < 16^3
	Chains    = MsgDigits + CsDigits
)

// Tweak is the address of one hash call: (leaf, chain, step), mixed into the hash so no two calls share an input
// structure. It is a plain field element: leaf·2^16 + chain·2^8 + step, plus a domain constant that separates the
// uses (chain step, public-key compression, secret derivation).
func tweak(use, leaf, chain, step uint64) fr.Element {
	var e fr.Element
	e.SetUint64(use<<48 | leaf<<16 | chain<<8 | step)
	return e
}

const (
	useChain  = 1
	usePk     = 2
	useSecret = 3
)

func hashStep(x fr.Element, tw fr.Element) fr.Element { return ledger.Compress(x, tw) }

// Digits splits a field element (as 32 big-endian bytes, mod r already applied by the caller) into the 67
// Winternitz digits: 64 message digits, then the checksum.
func Digits(msg fr.Element) [Chains]int {
	b := msg.Bytes() // big-endian, 32 bytes
	var d [Chains]int
	for i := 0; i < 32; i++ {
		d[2*i] = int(b[i] >> 4)
		d[2*i+1] = int(b[i] & 15)
	}
	cs := 0
	for i := 0; i < MsgDigits; i++ {
		cs += W - 1 - d[i]
	}
	for j := CsDigits - 1; j >= 0; j-- {
		d[MsgDigits+j] = cs & 15
		cs >>= 4
	}
	return d
}

// PrivateKey is a seed and the tree height: it can sign 2^Height messages, one per leaf.
type PrivateKey struct {
	Seed   fr.Element
	Height int
}

func (k PrivateKey) secret(leaf uint64, chain int) fr.Element {
	return hashStep(hashStep(k.Seed, tweak(useSecret, leaf, uint64(chain), 0)), tweak(useSecret, leaf, uint64(chain), 1))
}

// chainEnd applies the chain function from step `from` for `n` steps.
func chainEnd(x fr.Element, leaf uint64, chain, from, n int) fr.Element {
	for s := from; s < from+n; s++ {
		x = hashStep(x, tweak(useChain, leaf, uint64(chain), uint64(s)))
	}
	return x
}

// leafPk compresses a leaf's chain ends into one field element (the Merkle leaf).
func leafPk(ends [Chains]fr.Element, leaf uint64) fr.Element {
	var h fr.Element
	for i, e := range ends {
		h = ledger.Compress(h, ledger.Compress(e, tweak(usePk, leaf, uint64(i), 0)))
	}
	return h
}

func (k PrivateKey) leaf(leaf uint64) fr.Element {
	var ends [Chains]fr.Element
	for c := 0; c < Chains; c++ {
		ends[c] = chainEnd(k.secret(leaf, c), leaf, c, 0, W-1)
	}
	return leafPk(ends, leaf)
}

// Tree builds every level of the Merkle tree of leaf public keys (level 0 = leaves). Key generation costs 2^Height
// leaves of 67·15 hash calls each: keep Height small in tests.
func (k PrivateKey) Tree() [][]fr.Element {
	n := 1 << k.Height
	level := make([]fr.Element, n)
	for i := range level {
		level[i] = k.leaf(uint64(i))
	}
	levels := [][]fr.Element{level}
	for len(level) > 1 {
		next := make([]fr.Element, len(level)/2)
		for i := range next {
			next[i] = ledger.Compress(level[2*i], level[2*i+1])
		}
		levels = append(levels, next)
		level = next
	}
	return levels
}

// PublicKey is the tree root: what an account stores as its key commitment.
func PublicKey(tree [][]fr.Element) fr.Element { return tree[len(tree)-1][0] }

// Signature authenticates one message under one leaf.
type Signature struct {
	Leaf  uint64
	Chain [Chains]fr.Element // the signature element of each chain
	Path  []fr.Element       // Merkle siblings, leaf level first
}

// Sign signs msg with leaf `leaf`. The caller must never sign two different messages with one leaf: in the ledger the
// leaf is the account nonce, which the circuit raises once per included transaction.
func (k PrivateKey) Sign(tree [][]fr.Element, leaf uint64, msg fr.Element) (Signature, error) {
	if leaf >= 1<<k.Height {
		return Signature{}, fmt.Errorf("leaf %d is beyond the tree (2^%d leaves): the key is used up", leaf, k.Height)
	}
	s := Signature{Leaf: leaf}
	d := Digits(msg)
	for c := 0; c < Chains; c++ {
		s.Chain[c] = chainEnd(k.secret(leaf, c), leaf, c, 0, d[c])
	}
	idx := leaf
	for l := 0; l < k.Height; l++ {
		s.Path = append(s.Path, tree[l][idx^1])
		idx >>= 1
	}
	return s, nil
}

// Verify checks sig on msg against the public key (tree root) of a tree of the given height.
func Verify(root fr.Element, height int, msg fr.Element, sig Signature) bool {
	if len(sig.Path) != height || sig.Leaf >= 1<<height {
		return false
	}
	d := Digits(msg)
	var ends [Chains]fr.Element
	for c := 0; c < Chains; c++ {
		ends[c] = chainEnd(sig.Chain[c], sig.Leaf, c, d[c], W-1-d[c])
	}
	cur := leafPk(ends, sig.Leaf)
	idx := sig.Leaf
	for _, sib := range sig.Path {
		if idx&1 == 0 {
			cur = ledger.Compress(cur, sib)
		} else {
			cur = ledger.Compress(sib, cur)
		}
		idx >>= 1
	}
	return cur.Equal(&root)
}
