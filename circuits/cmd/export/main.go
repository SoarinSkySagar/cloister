// export compiles the spike circuit over BLS12-381, runs a (single-party,
// testnet-only) Groth16 setup, and writes the verifying key and one sample
// proof in BOTH gnark encodings, because the spike must find out which one the
// chain accepts (spec/public-inputs.md, OPEN).
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/soarinskysagar/cloister/circuits/spike"
)

type rawWriter interface {
	WriteRawTo(io.Writer) (int64, error)
}

func write(path string, f func(io.Writer) (int64, error)) {
	out, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	n, err := f(out)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  %-28s %6d bytes\n", filepath.Base(path), n)
}

func main() {
	dir := flag.String("out", "build", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}

	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &spike.Circuit{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("constraints: %d, public inputs: %d\n", ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1)

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	sq := func(x int64) *big.Int { return new(big.Int).Mul(big.NewInt(x), big.NewInt(x)) }
	full, err := frontend.NewWitness(&spike.Circuit{
		PrevStateRoot: 0, StateRoot: 1, DataHash: 0, WithdrawalsRoot: 0,
		DataHashSq: sq(0), WithdrawalsRootSq: sq(0),
	}, ecc.BLS12_381.ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	pub, err := full.Public()
	if err != nil {
		log.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		log.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		log.Fatalf("local verify failed: %v", err)
	}
	fmt.Println("local verify: ok")

	write(filepath.Join(*dir, "vk.compressed.bin"), vk.WriteTo)
	write(filepath.Join(*dir, "vk.raw.bin"), vk.(rawWriter).WriteRawTo)
	write(filepath.Join(*dir, "proof.compressed.bin"), proof.WriteTo)
	write(filepath.Join(*dir, "proof.raw.bin"), proof.(rawWriter).WriteRawTo)
	write(filepath.Join(*dir, "public.bin"), pub.WriteTo)
	fmt.Println("sample statement: prev_state_root=0 state_root=1 data_hash=0 withdrawals_root=0")
}
