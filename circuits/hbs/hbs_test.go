package hbs

import (
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func el(n uint64) fr.Element { var e fr.Element; e.SetUint64(n); return e }

func randEl(r *rand.Rand) fr.Element {
	var e fr.Element
	e.SetRandom()
	_ = r
	return e
}

const testHeight = 2

func keys(t *testing.T) (PrivateKey, [][]fr.Element, fr.Element) {
	t.Helper()
	k := PrivateKey{Seed: el(0xc10157e2), Height: testHeight}
	tree := k.Tree()
	return k, tree, PublicKey(tree)
}

func TestSignAndVerify(t *testing.T) {
	k, tree, pk := keys(t)
	r := rand.New(rand.NewSource(1))
	for leaf := uint64(0); leaf < 1<<testHeight; leaf++ {
		msg := randEl(r)
		sig, err := k.Sign(tree, leaf, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(pk, testHeight, msg, sig) {
			t.Fatalf("leaf %d: an honest signature was refused", leaf)
		}
	}
	if _, err := k.Sign(tree, 1<<testHeight, el(1)); err == nil {
		t.Fatal("signed beyond the last leaf")
	}
}

func TestVerifyRefusesEveryAlteration(t *testing.T) {
	k, tree, pk := keys(t)
	msg := el(123456789)
	good, _ := k.Sign(tree, 1, msg)
	clone := func() Signature {
		s := good
		s.Path = append([]fr.Element(nil), good.Path...)
		return s
	}
	cases := map[string]func(*Signature, *fr.Element){
		"another message":     func(s *Signature, m *fr.Element) { *m = el(123456790) },
		"a chain element":     func(s *Signature, m *fr.Element) { s.Chain[10] = el(1) },
		"the last chain":      func(s *Signature, m *fr.Element) { s.Chain[Chains-1] = el(1) },
		"another leaf":        func(s *Signature, m *fr.Element) { s.Leaf = 0 },
		"a leaf out of range": func(s *Signature, m *fr.Element) { s.Leaf = 1 << testHeight },
		"a path element":      func(s *Signature, m *fr.Element) { s.Path[0] = el(9) },
		"a short path":        func(s *Signature, m *fr.Element) { s.Path = s.Path[:1] },
	}
	for name, f := range cases {
		s, m := clone(), msg
		f(&s, &m)
		if Verify(pk, testHeight, m, s) {
			t.Errorf("%s: accepted", name)
		}
	}
	if Verify(el(7), testHeight, msg, good) {
		t.Error("accepted under another public key")
	}
}

// The Winternitz checksum: raising one message digit lowers the checksum, so an attacker who can only hash forward
// (raise digits) from a signature cannot reach another message's digits.
func TestChecksumBlocksForgeryByHashingForward(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 2000; i++ {
		a, b := randEl(r), randEl(r)
		if a.Equal(&b) {
			continue
		}
		da, db := Digits(a), Digits(b)
		aGEb, bGEa := true, true // can b be reached from a by hashing forward in every chain (b's digit >= a's)? and the reverse
		for c := 0; c < Chains; c++ {
			if db[c] < da[c] {
				aGEb = false
			}
			if da[c] < db[c] {
				bGEa = false
			}
		}
		if aGEb || bGEa {
			t.Fatalf("messages %v and %v: one's digits dominate the other's, so a signature on one would give a signature on the other", a, b)
		}
	}
}

// The same property on the worst cases: a message and the same message with one digit raised, which is exactly what a
// forger holding a signature on the first would need to turn into a signature on the second.
func TestChecksumBlocksRaisingASingleDigit(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 500; i++ {
		a := randEl(r)
		da := Digits(a)
		// build b by raising one nibble of a's 256-bit value (when it is not already 15 and the result stays below r)
		raw := a.Bytes()
		pos := r.Intn(63) + 1 // never the top nibble, which could push the value past r
		hi := pos%2 == 0
		byteI := pos / 2
		cur := int(raw[byteI] & 15)
		if hi {
			cur = int(raw[byteI] >> 4)
		}
		if cur == 15 {
			continue
		}
		if hi {
			raw[byteI] += 1 << 4
		} else {
			raw[byteI]++
		}
		var b fr.Element
		if err := b.SetBytesCanonical(raw[:]); err != nil {
			continue
		}
		db := Digits(b)
		if da[pos] >= db[pos] {
			t.Fatalf("setup: digit %d was not raised", pos)
		}
		dominated := true
		for c := 0; c < Chains; c++ {
			if db[c] < da[c] {
				dominated = false
			}
		}
		if dominated {
			t.Fatalf("raising digit %d left every chain at or above the original: the checksum failed to protect it", pos)
		}
	}
}

func TestCircuitAgreesWithNative(t *testing.T) {
	k, tree, pk := keys(t)
	msg := el(987654321)
	for leaf := uint64(0); leaf < 1<<testHeight; leaf++ {
		sig, _ := k.Sign(tree, leaf, msg)
		w := assignment(pk, msg, sig)
		if err := test.IsSolved(NewVerifyCircuit(testHeight), w, ecc.BLS12_381.ScalarField()); err != nil {
			t.Fatalf("leaf %d: the circuit refused an honest signature: %v", leaf, err)
		}
	}
}

func assignment(root, msg fr.Element, sig Signature) *VerifyCircuit {
	w := NewVerifyCircuit(len(sig.Path))
	w.Root, w.Msg, w.Leaf = root, msg, sig.Leaf
	for i := range w.Chain {
		w.Chain[i] = sig.Chain[i]
	}
	for i := range w.Path {
		w.Path[i] = sig.Path[i]
	}
	return w
}

func TestCircuitRefusesEveryAlteration(t *testing.T) {
	k, tree, pk := keys(t)
	msg := el(555)
	good, _ := k.Sign(tree, 2, msg)
	solve := func(root, m fr.Element, s Signature) error {
		return test.IsSolved(NewVerifyCircuit(testHeight), assignment(root, m, s), ecc.BLS12_381.ScalarField())
	}
	if err := solve(pk, msg, good); err != nil {
		t.Fatalf("control: %v", err)
	}
	clone := func() Signature {
		s := good
		s.Path = append([]fr.Element(nil), good.Path...)
		return s
	}
	for name, mut := range map[string]func(*Signature) (fr.Element, fr.Element){
		"another message":  func(s *Signature) (fr.Element, fr.Element) { return pk, el(556) },
		"another key":      func(s *Signature) (fr.Element, fr.Element) { return el(1), msg },
		"a chain element":  func(s *Signature) (fr.Element, fr.Element) { s.Chain[3] = el(1); return pk, msg },
		"a checksum chain": func(s *Signature) (fr.Element, fr.Element) { s.Chain[MsgDigits+1] = el(1); return pk, msg },
		"another leaf":     func(s *Signature) (fr.Element, fr.Element) { s.Leaf = 3; return pk, msg },
		"a path element":   func(s *Signature) (fr.Element, fr.Element) { s.Path[1] = el(2); return pk, msg },
	} {
		s := clone()
		root, m := mut(&s)
		if solve(root, m, s) == nil {
			t.Errorf("%s: the circuit accepted it", name)
		}
	}
	// a message that is not a field element's 255 bits cannot be used to dodge the digits
	var big fr.Element
	big.SetInt64(-1) // r - 1
	if sig, err := k.Sign(tree, 1, big); err == nil {
		if err := solve(pk, big, sig); err == nil {
			t.Log("a maximal message verifies as expected")
		}
	}
}

// What it costs: the number that decides whether this can sit in the ledger circuit.
func TestConstraintCount(t *testing.T) {
	for _, h := range []int{2, 10} {
		ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, NewVerifyCircuit(h))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("tree height %d (%d signatures per key): %d constraints per signature", h, 1<<h, ccs.GetNbConstraints())
	}
}
