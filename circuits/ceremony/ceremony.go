// Package ceremony runs a multi-party trusted setup for Cloister's Groth16 circuit, so that no single person's
// secret can forge a proof: the setup is sound as long as ONE contributor destroyed their randomness.
//
// It wraps gnark's MPC setup (Phase 1 "powers of tau", universal for a domain size; Phase 2, specific to the
// circuit) with file handling, a transcript of hashes, and verification. See docs/ceremony.md for the procedure.
//
// What the code guarantees (tests: ceremony_test.go): every contribution carries a proof of knowledge of the secret it
// added and is checked against the previous one; a chain that skips, repeats, reorders or restarts is refused; the
// final keys are a deterministic function of the contributions and a public beacon, so anyone re-derives and compares
// them; the keys produce proofs that the verifying key accepts.
package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	mpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	cs "github.com/consensys/gnark/constraint/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Compile builds the R1CS of a circuit over BLS12-381.
func Compile(c frontend.Circuit) (*cs.R1CS, error) {
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return nil, err
	}
	r, ok := ccs.(*cs.R1CS)
	if !ok {
		return nil, fmt.Errorf("unexpected constraint system type %T", ccs)
	}
	return r, nil
}

// DomainSize is the smallest power of two that holds the circuit's constraints: the size N of the Phase 1 parameters.
func DomainSize(r *cs.R1CS) uint64 { return ecc.NextPowerOfTwo(uint64(r.GetNbConstraints())) }

// ---- Phase 1 ----

func Phase1Init(n uint64) (*mpc.Phase1, error) {
	if n == 0 || n&(n-1) != 0 {
		return nil, fmt.Errorf("the domain size must be a power of two, got %d", n)
	}
	return mpc.NewPhase1(n), nil
}

// Phase1Seal verifies a chain of Phase 1 contributions (first to last, the identity start is recomputed) and applies
// the public beacon, returning the universal parameters. The beacon must be unpredictable before the last contribution.
func Phase1Seal(n uint64, beacon []byte, contributions ...*mpc.Phase1) (*mpc.SrsCommons, error) {
	if len(contributions) == 0 {
		return nil, fmt.Errorf("no contributions")
	}
	srs, err := mpc.VerifyPhase1(n, beacon, contributions...)
	if err != nil {
		return nil, err
	}
	return &srs, nil
}

// ---- Phase 2 ----

// Phase2Init derives the circuit-specific starting point from the universal parameters (no secrets: anyone can
// recompute it and compare).
func Phase2Init(r *cs.R1CS, srs *mpc.SrsCommons) (p *mpc.Phase2, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()
	p = new(mpc.Phase2)
	p.Initialize(r, srs)
	return p, nil
}

// Phase2Finalize verifies the chain of Phase 2 contributions against the circuit and the universal parameters, applies
// the beacon and returns the keys.
func Phase2Finalize(r *cs.R1CS, srs *mpc.SrsCommons, beacon []byte, contributions ...*mpc.Phase2) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	if len(contributions) == 0 {
		return nil, nil, fmt.Errorf("no contributions")
	}
	return mpc.VerifyPhase2(r, srs, beacon, contributions...)
}

// ---- files ----

type fileObject interface {
	io.WriterTo
	io.ReaderFrom
}

func writeObject(path string, o io.WriterTo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := o.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readObject(path string, o io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = o.ReadFrom(f)
	return err
}

func WritePhase1(path string, p *mpc.Phase1) error  { return writeObject(path, p) }
func WritePhase2(path string, p *mpc.Phase2) error  { return writeObject(path, p) }
func WriteSrs(path string, s *mpc.SrsCommons) error { return writeObject(path, s) }

func ReadPhase1(path string) (*mpc.Phase1, error) {
	p := new(mpc.Phase1)
	return p, readObject(path, p)
}

func ReadPhase2(path string) (*mpc.Phase2, error) {
	p := new(mpc.Phase2)
	return p, readObject(path, p)
}

func ReadSrs(path string) (*mpc.SrsCommons, error) {
	s := new(mpc.SrsCommons)
	return s, readObject(path, s)
}

// FileHash is the SHA-256 of a file, hex. Each contributor publishes the hash of the file they produced; the transcript
// is the list of those hashes, and anyone can check the files they downloaded against it.
func FileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Beacon decodes a hex beacon value (for example a Bitcoin block hash or a drand round's randomness, chosen and
// announced before the last contribution is closed, and fetched after it).
func Beacon(h string) ([]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 16 {
		return nil, fmt.Errorf("the beacon must be at least 16 bytes of hex")
	}
	return b, nil
}
