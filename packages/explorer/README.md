# @cloister/explorer

A block explorer for the rollup itself: overview, batches (roots, proof, watchtower checks), frame transactions (every frame decoded), accounts, withdrawals. The layout follows the Dora beacon-chain explorer (overview cards, latest tables, key/value detail pages) in a black theme. No code is taken from Dora (we believe it is GPL-licensed; not re-checked); this is plain HTML/CSS/JS with no dependencies.

```bash
pnpm watchtower --id cloister-dev-2 --explorer $PWD/packages/explorer/data.json
pnpm explorer          # http://127.0.0.1:8790
```

`data.json` is the watchtower's decrypted view, so it contains every transaction and balance. It is gitignored. For now the explorer shows everything; whether the final rollup is private is still open (design.md).
