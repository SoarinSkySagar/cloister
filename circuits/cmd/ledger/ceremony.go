package main

// The multi-party setup (docs/ceremony.md), as subcommands of the ledger tool:
//
//	ledger ceremony phase1-init     -log2 22 -out p1_0000.bin
//	ledger ceremony contribute      -phase 1|2 -in <previous> -out <mine>      prints the sha256 of the file made
//	ledger ceremony phase1-seal     -log2 22 -beacon <hex> -out srs.bin  p1_0001.bin p1_0002.bin ...
//	ledger ceremony phase2-init     -dir setup/<id> -srs srs.bin -out p2_0000.bin
//	ledger ceremony phase2-finalize -dir setup/<id> -srs srs.bin -beacon <hex>  p2_0001.bin p2_0002.bin ...
//	ledger ceremony hash            <file> ...
//
// Phase 1 is universal for a domain size (2^22 holds the current circuit's 2.2M constraints) and is reused across
// circuits. Phase 2 is specific to the circuit in <dir>/config.json. `phase2-finalize` writes the same files as
// `ledger setup` (ccs.bin, pk.bin, vk.raw.bin, vk.compressed.bin, state.json), so everything downstream is unchanged.

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"
	mpc "github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"

	"github.com/soarinskysagar/cloister/circuits/ceremony"
	"github.com/soarinskysagar/cloister/circuits/ledger"
)

func ceremonyMain(args []string) {
	if len(args) == 0 {
		log.Fatal("usage: ledger ceremony phase1-init|contribute|phase1-seal|phase2-init|phase2-finalize|hash ...")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("ceremony "+sub, flag.ExitOnError)
	log2 := fs.Uint("log2", 0, "Phase 1 domain size as a power of two (22 for the current circuit)")
	phase := fs.Int("phase", 0, "1 or 2")
	in := fs.String("in", "", "the previous contribution")
	out := fs.String("out", "", "output file")
	dir := fs.String("dir", "", "setup directory (holds config.json)")
	srsPath := fs.String("srs", "", "universal parameters from phase1-seal")
	beaconHex := fs.String("beacon", "", "public randomness, hex, announced before the last contribution closes and read after it")
	fs.Parse(rest)
	files := fs.Args()
	must := func(err error) {
		if err != nil {
			log.Fatal(err)
		}
	}
	timed := func(what string) func() {
		t0 := time.Now()
		return func() { log.Printf("%s (%v)", what, time.Since(t0).Round(time.Second)) }
	}

	switch sub {
	case "phase1-init":
		if *log2 == 0 || *log2 > 28 || *out == "" {
			log.Fatal("phase1-init needs -log2 (1..28) and -out")
		}
		p, err := ceremony.Phase1Init(uint64(1) << *log2)
		must(err)
		must(ceremony.WritePhase1(*out, p))
		h, _ := ceremony.FileHash(*out)
		fmt.Printf("%s  sha256 %s\n", *out, h)

	case "contribute":
		if (*phase != 1 && *phase != 2) || *in == "" || *out == "" {
			log.Fatal("contribute needs -phase 1|2, -in and -out")
		}
		done := timed("contributed")
		if *phase == 1 {
			p, err := ceremony.ReadPhase1(*in)
			must(err)
			p.Contribute()
			must(ceremony.WritePhase1(*out, p))
		} else {
			p, err := ceremony.ReadPhase2(*in)
			must(err)
			p.Contribute()
			must(ceremony.WritePhase2(*out, p))
		}
		done()
		h, _ := ceremony.FileHash(*out)
		fmt.Printf("%s  sha256 %s\nPublish this hash, then destroy the randomness: close the program, and wipe or power off the machine you used.\n", *out, h)

	case "phase1-seal":
		if *log2 == 0 || *out == "" || *beaconHex == "" || len(files) == 0 {
			log.Fatal("phase1-seal needs -log2, -beacon, -out and the contribution files in order")
		}
		beacon, err := ceremony.Beacon(*beaconHex)
		must(err)
		var cs []*mpc.Phase1
		for _, f := range files {
			p, err := ceremony.ReadPhase1(f)
			must(err)
			cs = append(cs, p)
		}
		done := timed("verified every contribution and sealed")
		srs, err := ceremony.Phase1Seal(uint64(1)<<*log2, beacon, cs...)
		must(err)
		done()
		must(ceremony.WriteSrs(*out, srs))
		h, _ := ceremony.FileHash(*out)
		fmt.Printf("%d phase 1 contributions verified. %s  sha256 %s\n", len(files), *out, h)

	case "phase2-init", "phase2-finalize":
		if *dir == "" || *srsPath == "" {
			log.Fatal(sub + " needs -dir and -srs")
		}
		cfg := loadConfig(*dir)
		c, err := ledger.New(cfg)
		must(err)
		done := timed("compiled the circuit")
		r, err := ceremony.Compile(c)
		must(err)
		done()
		log.Printf("%d constraints, domain size %d", r.GetNbConstraints(), ceremony.DomainSize(r))
		srs, err := ceremony.ReadSrs(*srsPath)
		must(err)
		if sub == "phase2-init" {
			if *out == "" {
				log.Fatal("phase2-init needs -out")
			}
			done = timed("derived the phase 2 starting point")
			p, err := ceremony.Phase2Init(r, srs)
			must(err)
			done()
			must(ceremony.WritePhase2(*out, p))
			h, _ := ceremony.FileHash(*out)
			fmt.Printf("%s  sha256 %s\n", *out, h)
			return
		}
		if *beaconHex == "" || len(files) == 0 {
			log.Fatal("phase2-finalize needs -beacon and the contribution files in order")
		}
		beacon, err := ceremony.Beacon(*beaconHex)
		must(err)
		var cs []*mpc.Phase2
		for _, f := range files {
			p, err := ceremony.ReadPhase2(f)
			must(err)
			cs = append(cs, p)
		}
		done = timed("verified every contribution and derived the keys")
		pk, vk, err := ceremony.Phase2Finalize(r, srs, beacon, cs...)
		must(err)
		done()
		if k := vk.(*groth16bls.VerifyingKey); vk.NbPublicWitness() != 4 || len(k.CommitmentKeys) != 0 {
			log.Fatalf("unexpected vk shape: %d public, %d commitments", vk.NbPublicWitness(), len(k.CommitmentKeys))
		}
		writeFile(filepath.Join(*dir, "ccs.bin"), r.WriteTo)
		writeFile(filepath.Join(*dir, "pk.bin"), pk.(rawWriter).WriteRawTo)
		writeFile(filepath.Join(*dir, "vk.raw.bin"), vk.(rawWriter).WriteRawTo)
		writeFile(filepath.Join(*dir, "vk.compressed.bin"), vk.WriteTo)
		g, _ := ledger.GenesisTree(cfg)
		writeJSON(filepath.Join(*dir, "state.json"), toState(g, 0, cfg.Depth))
		h, _ := ceremony.FileHash(filepath.Join(*dir, "vk.compressed.bin"))
		fmt.Printf("%d phase 2 contributions verified. keys written to %s\nverifying key (vk.compressed.bin) sha256 %s\n", len(files), *dir, h)

	case "hash":
		for _, f := range files {
			h, err := ceremony.FileHash(f)
			must(err)
			fmt.Printf("%s  %s\n", h, f)
		}

	default:
		log.Fatalf("unknown ceremony command %q", sub)
	}
}
