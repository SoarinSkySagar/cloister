# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Delegated. The user said "I don't care how". Brand and marketing assets (like the cover) are built as static HTML/CSS pages and rendered to images. App surfaces (receipt verifier, watchtower dashboard) aren't decided yet.

## Users

- **Hackathon jury:** technical judges of QoreChain's "Build Before Q-Day" Protocol Builders track. They score against the track requirements (ML-DSA-signed batches, withdrawal, verified settlement receipt, watchtower, ML-KEM data protection, threat model).
- **Community voters:** people browsing build.qorechain.io/projects and voting in People's Choice on mainnet (6–15 Dec 2026).
- **Future users (confirmed as a lasting audience):** groups that want to transact privately with each other on QoreChain without exposing contents on L1, plus sponsors and relayers who pay gas for them. Cloister should keep its identity after the hackathon.

## Product Purpose

Cloister is a members-only private ZK rollup on QoreChain. Users sign frame transactions with ML-DSA-87 and seal them with ML-KEM-1024 to the member set. The chain enforces that only valid envelopes to members are posted. Batches settle with Groth16 proofs, are anchored with ML-DSA-87 signatures, and each comes with a verifiable settlement receipt. Withdrawals are paid on L1 as soon as a batch is final. Success for now means a complete, honest, working testnet entry that wins the Protocol Builders track.

## Positioning

The only rollup on QoreChain combining chain-enforced post-quantum encryption (private mode), validity-proof settlement, EIP-8141-style frame transactions with gas sponsorship, and independently verifiable settlement receipts. The nearest competitor (Wicketgate) is an optimistic rollup without receipts and without chain-enforced privacy.

## Operating Context

- QoreChain testnet `qorechain-diana`. Hackathon deadline 2 Dec 2026, 23:59 UTC.
- Project page on build.qorechain.io: name, tagline, cover (16:9, ≥1200×675, ≤5 MB), ≤3-minute video, public MIT-licensed repo.
- Two-person team. Claude Code writes most of the code, and the humans direct and review.

## Capabilities and Constraints

- **Terms:** frame transaction, sponsor, relayer, member set, envelope, batch, settlement receipt, watchtower, anchor.
- **Built and verified so far:** repo scaffold, specs, gnark spike circuit with negative tests, read-only testnet check. **Nothing is on chain yet.** Don't claim live features before PROOF.md has them.
- The dark pool (private batch auction) is a stretch goal and must be described as such.
- The circuit doesn't verify ML-DSA signatures or link ciphertext to plaintext. The watchtower covers those gaps (documented in THREAT_MODEL.md).

## Brand Commitments

- Name: **Cloister** (rollup ID `cloister`). No existing logo, colours or fonts. The first visual identity is still to be created.
- QoreChain may be named **as plain text** ("on QoreChain"). Never use the QoreChain logo or imitate its branding.

## Evidence on Hand

- design.md (plan), spec/, THREAT_MODEL.md, PROOF.md (empty so far), the circuits/ spike.
- **None yet:** users, testimonials, benchmarks, mainnet deployment or audits. Don't fabricate any of these.

## Product Principles

1. **Honest claims:** say only what's built or clearly marked as planned. Name the limits openly.
2. **Privacy by construction:** contents are sealed to members, and the public sees only what settlement requires.
3. **Post-quantum everywhere:** ML-DSA-87 signatures and ML-KEM-1024 encryption, not as an add-on.
4. **Verifiable by anyone:** receipts and watchtower checks let outsiders trust settlement without trusting the operator.
