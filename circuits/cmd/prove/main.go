// prove builds a Groth16 proof for the spike circuit from the four public
// inputs (32-byte big-endian hex, already reduced mod r, as the RDK's
// zkPublicInputs returns them), using the persistent keys in -setup, verifies
// it locally, and writes the proof in both gnark encodings to -out.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/soarinskysagar/cloister/circuits/spike"
)

type rawWriter interface {
	WriteRawTo(io.Writer) (int64, error)
}

func scalar(name, h string) *big.Int {
	b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	if err != nil || len(b) != 32 {
		log.Fatalf("-%s must be 32 bytes of hex", name)
	}
	v := new(big.Int).SetBytes(b)
	if v.Cmp(ecc.BLS12_381.ScalarField()) >= 0 {
		log.Fatalf("-%s is not reduced mod r", name)
	}
	return v
}

func read(path string, r io.ReaderFrom) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := r.ReadFrom(f); err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
}

func write(path string, f func(io.Writer) (int64, error)) {
	out, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	if _, err := f(out); err != nil {
		log.Fatal(err)
	}
}

func main() {
	setup := flag.String("setup", "setup/spike", "persistent key directory")
	out := flag.String("out", "build/batch", "output directory")
	prev := flag.String("prev", "", "prev_state_root (hex)")
	state := flag.String("state", "", "state_root (hex)")
	data := flag.String("data", "", "data_hash (hex)")
	wd := flag.String("wd", "", "withdrawals_root (hex)")
	flag.Parse()

	r := ecc.BLS12_381.ScalarField()
	p, s, d, w := scalar("prev", *prev), scalar("state", *state), scalar("data", *data), scalar("wd", *wd)
	sq := func(x *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(x, x), r) }

	ccs, err := frontend.Compile(r, r1cs.NewBuilder, &spike.Circuit{})
	if err != nil {
		log.Fatal(err)
	}
	pk, vk := groth16.NewProvingKey(ecc.BLS12_381), groth16.NewVerifyingKey(ecc.BLS12_381)
	read(filepath.Join(*setup, "pk.bin"), pk.(io.ReaderFrom))
	read(filepath.Join(*setup, "vk.bin"), vk.(io.ReaderFrom))

	full, err := frontend.NewWitness(&spike.Circuit{
		PrevStateRoot: p, StateRoot: s, DataHash: d, WithdrawalsRoot: w,
		DataHashSq: sq(d), WithdrawalsRootSq: sq(w),
	}, r)
	if err != nil {
		log.Fatal(err)
	}
	pub, _ := full.Public()
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		log.Fatalf("prove: %v", err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		log.Fatalf("local verify failed: %v", err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	write(filepath.Join(*out, "proof.raw.bin"), proof.(rawWriter).WriteRawTo)
	write(filepath.Join(*out, "proof.compressed.bin"), proof.WriteTo)
	fmt.Println("proof ok:", *out)
}
