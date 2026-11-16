# Cloister specs

These files define the formats shared by the circuit (Go), the sequencer, the wallet and the watchtower (TypeScript). **They are the source of truth.**

| File | Defines |
|---|---|
| [frame-tx.md](frame-tx.md) | Frame transaction structure, canonical encoding, signature hash |
| [state.md](state.md) | Account leaf, state tree, assets |
| [public-inputs.md](public-inputs.md) | The 4 Groth16 public inputs and how each is derived |
| [vectors/](vectors/) | Golden test vectors that **both** the Go and TS tests load |

Status: **draft v0**. Items marked **OPEN** must be settled before the circuit is frozen (target: 25 Nov).
