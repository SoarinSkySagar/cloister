# AI usage

Cloister is built AI-natively: the two team members direct, decide and review, and Claude (Claude Code, Opus) writes most of the code and docs.

## Workflow
- Planning and research: Claude researched QoreChain docs, kits, the live testnet and the competing project, and drafted design.md. The team made the product decisions.
- Build: parallel Claude Code sessions, one per package, guided by CLAUDE.md and the `spec/` files.
- Review: humans review every circuit constraint (negative tests) and every on-chain step (PROOF.md).

## Log
| Date | Who | What |
|---|---|---|
| 2026-11-16 | Claude | Researched the track, QoreChain docs and testnet; competitor analysis (Wicketgate, from public repo and chain data) |
| 2026-11-16 | Team | Chose a private ZK rollup over a sidechain or an optimistic rollup; added frame transactions and sponsorship; Part B dark pool as a gated stretch goal; named it Cloister |
| 2026-11-16 | Claude | Read the RDK 0.9.0 source: VK is gnark-encoded and locks after the first batch, so the circuit moves to gnark with a dev-rollup cycle strategy |
| 2026-11-16 | Claude | Scaffolded the repo: CLAUDE.md, specs, docs, workspace, gnark spike circuit, network check |
