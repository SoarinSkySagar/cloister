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
| 2026-11-16 | Team + Claude | Cover image via the impeccable skill: team set the audience (jury, voters, future users) and the brand rules, and chose the "Redacted Record" direction on impeccable's decision page. Claude built brand/cover.html and rendered it with Playwright; an independent reviewer subagent ran two correction rounds (fixed a "member copy" story error, stamp material, margins) |
| 2026-11-18 | Claude | Ran the go/no-go spike on testnet: keys, cloister-dev-1, sealed post, two proven batches, a verified settlement receipt and a withdrawal. Team approved each spend (funding, rollup creation). Result: GO |
| 2026-11-18 | Claude | Circuit v1 (`circuits/ledger`, gnark): Poseidon2 account tree, fee/transfer/withdraw/register_key moves with sponsorship and atomic groups, and the chain's SHAKE-256 withdrawals root computed inside the proof (hand-written bit-level Keccak, no lookups). Has 20 negative tests, each confirmed to fail on its target rule, and RDK-generated golden vectors for the withdrawals root. Team asked for it after the spike; human review of the constraints is pending |
| 2026-11-18 | Claude | Ran circuit v1 on testnet. Built the `cmd/ledger` setup/prove command and the `spike:ledger` driver. The team approved creating cloister-dev-2, which then settled 2 sealed batches (sponsored onboarding, then 2 withdrawals paid on L1) with valid receipts |
| 2026-11-18 | Claude | Frame-tx codec (`packages/common/src/frametx.ts`): encoding, sighash, ML-DSA-87 signing, validation, batch bundle and golden vectors. Wallet CLI (`packages/wallet`) with new, whoami, build, sign, inspect and send. Closed the frame-tx spec's open items (flat fee, relayer account in config, new-account index rule). On cloister-dev-2, batch 2 carried wallet-built txs: a sponsored onboarding of a user with no L1 funds, a payment and a withdrawal |
| 2026-11-18 | Claude | Sequencer service (`packages/sequencer`): HTTP API, mempool checks, automatic seal/prove/post/submit/withdraw loop. Signed account queries so a private rollup shows each user only their own balance (`packages/common/src/query.ts`). The wallet now talks to the sequencer. On cloister-dev-2, batches 3 and 4 came from txs sent through the API; refusals checked; receipts valid |
- 2026-11-18: Claude wrote the relayer service (validate, rate limit, forward to sequencer; 3 tests), the watchtower v1 (fetch and open sealed bundles from L1, check link/index/count/structure/ML-DSA signatures; 5 tests incl. negatives; passes on cloister-dev-2 batches 0-4) and a Dora-style black-theme explorer (static page fed by the watchtower, frame txs decoded). Human decision: explorer shows everything for now, privacy decided later.
