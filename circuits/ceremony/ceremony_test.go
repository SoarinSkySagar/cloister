package ceremony

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	mpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	"github.com/consensys/gnark/frontend"
)

// A small circuit with a public input, so the whole protocol runs in seconds. The protocol code does not depend on
// the circuit; the real ledger circuit goes through the same functions (cmd/ledger ceremony-*).
type toy struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (c *toy) Define(api frontend.API) error {
	api.AssertIsEqual(api.Add(api.Mul(c.X, c.X, c.X), c.X, 5), c.Y)
	return nil
}

type run struct {
	dir  string
	n    uint64
	r    interface{ GetNbConstraints() int }
	srs  *mpc.SrsCommons
	p1   []string // Phase 1 contribution files
	p2   []string
	init string
}

func contribute1(t *testing.T, dir, in, out string) {
	t.Helper()
	p, err := ReadPhase1(in)
	if err != nil {
		t.Fatal(err)
	}
	p.Contribute()
	if err := WritePhase1(out, p); err != nil {
		t.Fatal(err)
	}
}

func contribute2(t *testing.T, in, out string) {
	t.Helper()
	p, err := ReadPhase2(in)
	if err != nil {
		t.Fatal(err)
	}
	p.Contribute()
	if err := WritePhase2(out, p); err != nil {
		t.Fatal(err)
	}
}

func TestCeremonyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	r, err := Compile(&toy{})
	if err != nil {
		t.Fatal(err)
	}
	n := DomainSize(r)
	beacon, _ := Beacon("00112233445566778899aabbccddeeff00112233")

	// Phase 1: the coordinator publishes the starting point, three people contribute in turn
	p0, err := Phase1Init(n)
	if err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(dir, "p1_0000.bin")
	if err := WritePhase1(start, p0); err != nil {
		t.Fatal(err)
	}
	var p1files []string
	prev := start
	for i := 1; i <= 3; i++ {
		out := filepath.Join(dir, "p1_000"+string(rune('0'+i))+".bin")
		contribute1(t, dir, prev, out)
		p1files = append(p1files, out)
		prev = out
	}
	load1 := func(files ...string) []*mpc.Phase1 {
		var out []*mpc.Phase1
		for _, f := range files {
			p, err := ReadPhase1(f)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, p)
		}
		return out
	}
	srs, err := Phase1Seal(n, beacon, load1(p1files...)...)
	if err != nil {
		t.Fatalf("an honest Phase 1 chain was refused: %v", err)
	}

	// Phase 2: two people contribute
	q0, err := Phase2Init(r, srs)
	if err != nil {
		t.Fatal(err)
	}
	q0file := filepath.Join(dir, "p2_0000.bin")
	if err := WritePhase2(q0file, q0); err != nil {
		t.Fatal(err)
	}
	q1, q2 := filepath.Join(dir, "p2_0001.bin"), filepath.Join(dir, "p2_0002.bin")
	contribute2(t, q0file, q1)
	contribute2(t, q1, q2)
	load2 := func(files ...string) []*mpc.Phase2 {
		var out []*mpc.Phase2
		for _, f := range files {
			p, err := ReadPhase2(f)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, p)
		}
		return out
	}
	pk, vk, err := Phase2Finalize(r, srs, beacon, load2(q1, q2)...)
	if err != nil {
		t.Fatalf("an honest Phase 2 chain was refused: %v", err)
	}

	// the keys prove and verify
	w, _ := frontend.NewWitness(&toy{X: 3, Y: 35}, ecc.BLS12_381.ScalarField())
	proof, err := groth16.Prove(r, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("a proof under the ceremony's keys does not verify: %v", err)
	}
	bad, _ := frontend.NewWitness(&toy{X: 3, Y: 36}, ecc.BLS12_381.ScalarField())
	badPub, _ := bad.Public()
	if err := groth16.Verify(proof, vk, badPub); err == nil {
		t.Fatal("a proof verified for a different public input")
	}

	// anyone can re-derive the keys from the same files and the same beacon, and gets the same verifying key
	_, vk2, err := Phase2Finalize(r, srs, beacon, load2(q1, q2)...)
	if err != nil {
		t.Fatal(err)
	}
	var a, b bytes.Buffer
	vk.WriteTo(&a)
	vk2.WriteTo(&b)
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("the same contributions and beacon gave a different verifying key")
	}
	// another beacon gives another key
	other, _ := Beacon("ffeeddccbbaa99887766554433221100ffeeddcc")
	_, vk3, err := Phase2Finalize(r, srs, other, load2(q1, q2)...)
	if err != nil {
		t.Fatal(err)
	}
	var c bytes.Buffer
	vk3.WriteTo(&c)
	if bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Fatal("the beacon does not affect the key")
	}

	// ---- chains that must be refused ----
	t.Run("phase 1: a contributor who starts over from the identity instead of the previous contribution", func(t *testing.T) {
		restart := filepath.Join(dir, "p1_restart.bin")
		contribute1(t, dir, start, restart) // does not build on contribution 1
		if _, err := Phase1Seal(n, beacon, load1(p1files[0], restart)...); err == nil {
			t.Fatal("a restart was accepted: it would drop the first contributor's randomness")
		}
	})
	t.Run("phase 1: a skipped contribution", func(t *testing.T) {
		if _, err := Phase1Seal(n, beacon, load1(p1files[0], p1files[2])...); err == nil {
			t.Fatal("a skipped contribution was accepted")
		}
	})
	t.Run("phase 1: a repeated contribution", func(t *testing.T) {
		if _, err := Phase1Seal(n, beacon, load1(p1files[0], p1files[0])...); err == nil {
			t.Fatal("a repeated contribution was accepted")
		}
	})
	t.Run("phase 1: contributions out of order", func(t *testing.T) {
		if _, err := Phase1Seal(n, beacon, load1(p1files[1], p1files[0])...); err == nil {
			t.Fatal("reordered contributions were accepted")
		}
	})
	t.Run("phase 1: a corrupted file", func(t *testing.T) {
		p := load1(p1files[0])[0]
		var buf bytes.Buffer
		p.WriteTo(&buf)
		raw := buf.Bytes()
		raw[len(raw)/2] ^= 0xff
		f := filepath.Join(dir, "p1_corrupt.bin")
		if err := writeBytes(f, raw); err != nil {
			t.Fatal(err)
		}
		q, err := ReadPhase1(f)
		if err == nil {
			if _, err = Phase1Seal(n, beacon, q); err == nil {
				t.Fatal("a corrupted contribution was accepted")
			}
		}
	})
	t.Run("phase 1: the wrong domain size", func(t *testing.T) {
		if _, err := Phase1Seal(n*2, beacon, load1(p1files[0])...); err == nil {
			t.Fatal("contributions for another domain size were accepted")
		}
	})
	t.Run("phase 2: a skipped contribution", func(t *testing.T) {
		if _, _, err := Phase2Finalize(r, srs, beacon, load2(q2)...); err == nil {
			t.Fatal("a chain that starts at the second contribution was accepted")
		}
	})
	t.Run("phase 2: a repeated or reordered contribution", func(t *testing.T) {
		if _, _, err := Phase2Finalize(r, srs, beacon, load2(q1, q1)...); err == nil {
			t.Fatal("a repeated contribution was accepted")
		}
		if _, _, err := Phase2Finalize(r, srs, beacon, load2(q2, q1)...); err == nil {
			t.Fatal("reordered contributions were accepted")
		}
	})
	t.Run("phase 2: contributions made for other universal parameters", func(t *testing.T) {
		// another Phase 1 run yields different parameters: Phase 2 files made on top of the first run do not verify against them
		p, _ := Phase1Init(n)
		other := filepath.Join(dir, "other1.bin")
		WritePhase1(other, p)
		contribute1(t, dir, other, other+".1")
		srs2, err := Phase1Seal(n, beacon, load1(other+".1")...)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Phase2Finalize(r, srs2, beacon, load2(q1, q2)...); err == nil {
			t.Fatal("Phase 2 contributions were accepted against universal parameters they were not built on")
		}
	})
	t.Run("a short beacon is refused", func(t *testing.T) {
		if _, err := Beacon("abcd"); err == nil {
			t.Fatal("a 2-byte beacon was accepted")
		}
	})
	if h1, err := FileHash(q1); err != nil || len(h1) != 64 {
		t.Fatalf("file hash: %q %v", h1, err)
	}
}

func writeBytes(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644)
}
