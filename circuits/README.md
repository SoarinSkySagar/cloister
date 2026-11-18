# circuits

Groth16 over **BLS12-381** with [gnark](https://github.com/Consensys/gnark) (Apache-2.0). The chain stores the rollup's verifying key in **gnark binary encoding** and checks each batch against **four public inputs**: `prev_state_root, state_root, data_hash, withdrawals_root` (see [../spec/public-inputs.md](../spec/public-inputs.md)).

| Path | What |
|---|---|
| `spike/` | Trivial go/no-go circuit: correct public interface, toy rule `state_root = prev_state_root + 1` |
| `ledger/` | **Circuit v1**: account tree, frame-tx moves, in-circuit withdrawals root. See [../spec/batch.md](../spec/batch.md) |
| `cmd/export` | Compile, run setup (single-party, **testnet only**), prove a sample and write the VK and proof in both gnark encodings |

```bash
go test ./...                   # includes negative tests (bad witnesses must fail)
CLOISTER_GROTH16=1 go test ./ledger -run Groth16 -v   # full setup+prove, ~2.5 min, ~9.4 GB RAM
go run ./cmd/export -out build  # build/ is gitignored
```

Toolchain: gnark v0.16.5 needs Go ≥ 1.26.8. `go` downloads it automatically via the `go` line in go.mod.

**Rule:** every constraint has a negative test. A circuit that accepts a bad witness is the most serious bug this project can have.
