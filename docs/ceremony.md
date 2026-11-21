# Trusted setup ceremony

Groth16 needs a one-time setup. Whoever ran it holds "toxic waste": a secret that lets them forge a proof for any false batch, and settle fake state on QoreChain. Every dev rollup so far used a **single-party setup** (`ledger setup`, run by one person on one laptop). That is fine for throwaway rollups and not for the final one.

A multi-party ceremony removes the single point of trust: the setup is sound as long as **at least one** contributor really destroyed their randomness. Everyone else can be dishonest, or compromised, or colluding, and the key is still safe.

Tooling: `circuits/ceremony` (library, tested) and `ledger ceremony …` (commands), a wrapper around gnark's MPC setup (Groth16 phase 1 "powers of tau" and phase 2, the protocol of [eprint 2017/1050](https://eprint.iacr.org/2017/1050) by Bowe, Gabizon and Miers, also used for the Zcash Sapling ceremony). We wrote file handling, a hash transcript, the chain-skipping/reordering checks and the rehearsal; the cryptography is gnark's and has not been audited by us.

## What the ceremony protects, and what it does not

| | |
|---|---|
| Protects | Forged proofs from a leaked or malicious setup secret |
| Does not protect | A forged proof by a quantum computer. Groth16 over BLS12-381 is not post-quantum, with or without a ceremony (see LIMITS.md) |
| Does not protect | Any bug in the circuit. A ceremony makes a wrong circuit's key trustworthy, not the circuit correct |
| Needs | At least one honest, careful contributor, and a public random beacon the contributors could not predict |

## Roles

- **Coordinator** (anyone; holds no secret): publishes the starting files and collects contributions in order. The coordinator cannot weaken the setup, and anyone can re-derive every step.
- **Contributors** (two humans of this team at minimum; the more independent people, the better): each adds randomness once.
- **Verifiers** (anyone): recompute the chain from the published files and compare the final verifying key with the one on chain.

## Phase 1: universal parameters (once for a domain size, reusable for every circuit up to it)

The final rollup `cloister` (the 8-byte id needs one Keccak block per withdrawal leaf) has **1,586,035 constraints, so the domain size is 2^21** (the dev rollups' 2.27 million need 2^22). Phase 1 for 2^21 is reusable for any circuit up to that size.

```bash
cd circuits
# coordinator
go run ./cmd/ledger ceremony phase1-init -log2 21 -out p1_0000.bin
# contributor 1 (then contributor 2, ... each on the previous file)
go run ./cmd/ledger ceremony contribute -phase 1 -in p1_0000.bin -out p1_0001.bin     # prints a sha256: publish it
# after the last contribution closes, fetch the beacon (below), then anyone can verify the chain and seal:
go run ./cmd/ledger ceremony phase1-seal -log2 21 -beacon <hex> -out srs.bin p1_0001.bin p1_0002.bin ...
```

## Phase 2: this circuit

```bash
go run ./cmd/ledger ceremony phase2-init -dir setup/cloister -srs srs.bin -out p2_0000.bin    # coordinator; no secrets
go run ./cmd/ledger ceremony contribute -phase 2 -in p2_0000.bin -out p2_0001.bin             # each contributor, in turn
go run ./cmd/ledger ceremony phase2-finalize -dir setup/cloister -srs srs.bin -beacon <hex> p2_0001.bin p2_0002.bin ...
```

`phase2-finalize` writes `pk.bin`, `ccs.bin`, `vk.raw.bin`, `vk.compressed.bin` and `state.json`, the same files `ledger setup` writes, so the sequencer and the rollup creation script are unchanged. It refuses a chain that skips, repeats, reorders or restarts a contribution, a corrupted file, a file made for other universal parameters, and a beacon shorter than 16 bytes (tests: `circuits/ceremony/ceremony_test.go`).

## The beacon

A contributor who goes last could grind their randomness to influence the key; the **beacon** removes that. It is public randomness nobody could predict before the last contribution closed, mixed in as a final contribution that anyone can reproduce.

1. Before the first contribution, announce the beacon source and the exact moment: for example **the hash of the first Bitcoin block mined after a stated UTC time**, or a named round of a public randomness service. Write the rule in the transcript.
2. Close the last contribution. Only then fetch the value and publish it.
3. Everyone uses the same hex value in `phase1-seal` and `phase2-finalize`. Use a different beacon (a different block) for phase 2 than for phase 1.

## What a contributor does

1. Take the previous file from the coordinator and check its sha256 against the transcript.
2. On a machine you trust (a fresh boot of a live USB without network is best; a normal laptop is acceptable for a testnet rollup): run `contribute`. It draws its randomness from the operating system's CSPRNG and exits.
3. Publish the sha256 it prints, together with your name and the time, then send the file on.
4. **Destroy the randomness.** The randomness lives only in the process memory of that one command: close the terminal, then power the machine off. Do not run `contribute` twice on one input and keep a "better" result; that is how a contribution is leaked.

The security argument is only as strong as step 4 for at least one person.

## Verifying (anyone, no secrets)

```bash
go run ./cmd/ledger ceremony hash p1_*.bin p2_*.bin srs.bin          # compare with the transcript
go run ./cmd/ledger ceremony phase1-seal -log2 21 -beacon <hex> -out /tmp/srs.bin p1_0001.bin ...
go run ./cmd/ledger ceremony phase2-finalize -dir /tmp/setup -srs /tmp/srs.bin -beacon <hex> p2_0001.bin ...
sha256sum /tmp/setup/vk.compressed.bin       # must equal the verifying key of the rollup on chain (REST /qorechain/rdk/v1/rollup/<id>)
```

Verification re-checks every contribution's proof of knowledge against the previous file, so a contribution that did not add randomness, or that replaced the chain, fails.

## Measured cost (22 Nov, 12-thread 15 GB laptop; read this before planning a ceremony)

The tooling is correct on a toy circuit (second-long tests), but **the rehearsal on a real ledger circuit did not finish here**:

| Step (rehearsal circuit: 1 tx slot, 1 withdrawal slot, domain 2^19) | Observed |
|---|---|
| Phase 1, two contributions and the seal | about 25 minutes in total, while another test run shared the CPU |
| Phase 2 start (`phase2-init`, no secrets) | **still running after 40 minutes at 2.5 GB, stopped by me** |

gnark's phase 2 initialisation multiplies a curve point for every circuit term with a non-trivial coefficient, in both groups, and the ledger circuit has millions of them. The final circuit (1.59 million constraints, domain 2^21) is 4 times larger on phase 1 than the rehearsal's 2^19, and more on phase 2, so on this laptop the real ceremony is a matter of **many hours for the coordinator's `phase2-init` and `phase2-finalize`**, which hold no secrets and can run on a rented many-core machine, and an unmeasured time for each contributor's `contribute -phase 2`. Plan it as an overnight job and measure one contribution on the real circuit before inviting anyone. A smaller circuit (fewer withdrawal slots, whose SHAKE-256 tree is most of the constraints) would shorten all of it.

## Rehearsal

`circuits/ceremony/rehearsal.sh` runs the whole flow on a small ledger circuit (two contributors per phase, the beacon, the keys, then a real proof under them and a refused chain). It has **not completed** on this machine (see above). The unit tests run the same functions on a toy circuit in a second and cover the refusal cases; the end-to-end path through the real circuit, including `phase2-finalize` writing the files the sequencer reads, is untested.

## Transcript (to be filled during the real ceremony)

| Phase | # | Contributor | Time (UTC) | sha256 of the file they produced |
|---|---|---|---|---|
| | | | | |

Beacon rule: _not yet announced_. Final verifying key sha256: _not yet produced_.
