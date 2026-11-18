# Cloister

**A private ZK rollup on QoreChain: members-only, post-quantum, settled with proofs.**

Cloister is a private rollup (a members-only sidechain) on [QoreChain](https://qorechain.io):

- **Frame transactions modelled on EIP-8141:** VERIFY frames for the sender and the sponsor, ACTION frames, and an atomic flag. Every transaction is signed with ML-DSA-87.
- **Gas sponsorship:** a relayer posts sealed transactions and is reimbursed inside the rollup. Users need no L1 QOR, and the L1 never learns who transacted.
- **ML-KEM-1024 privacy enforced by the chain:** transactions are posted as envelopes that only the member set (sequencer and watchtowers) can open.
- **ZK settlement:** each batch is proven with Groth16 (BLS12-381, gnark), signed with ML-DSA-87, anchored on QoreChain and paired with a verifiable settlement receipt.
- **Watchtower:** checks what the proof can't: inclusion, signatures, data availability, liveness and VK changes.

> Status: under construction for the **Build Before Q-Day** hackathon (Protocol Builders track). Testnet (`qorechain-diana`) only.

## Documents

- [design.md](design.md): architecture and build plan
- [spec/](spec/): wire formats (frame transactions, state, public inputs)
- [THREAT_MODEL.md](THREAT_MODEL.md) · [LIMITS.md](LIMITS.md) · [PROOF.md](PROOF.md) (testnet evidence) · [AI_USAGE.md](AI_USAGE.md)

## Layout

See [CLAUDE.md](CLAUDE.md#layout).

## Credits

Built with these open source libraries and kits:

| Library | Licence | Use |
|---|---|---|
| [@qorechain/rdk](https://github.com/qorechain/qorechain-rdk) | Apache-2.0 | Rollup lifecycle, batches, envelopes, receipts, withdrawals |
| [@qorechain/pqc](https://github.com/qorechain/qorechain-pqc) | Apache-2.0 | ML-DSA / ML-KEM / SHAKE-256 primitives |
| [@qorechain/qoresign](https://github.com/qorechain/qoresign) | Apache-2.0 | Hybrid ML-DSA-87 signing |
| [@qorechain/qoreseal](https://github.com/qorechain/qoreseal) | Apache-2.0 | ML-KEM-1024 sealing helpers |
| [gnark](https://github.com/Consensys/gnark) | Apache-2.0 | Groth16 circuit and prover |
| [esbuild](https://github.com/evanw/esbuild) | MIT | Bundles the receipt verifier page for the browser |

## License

MIT. See [LICENSE](LICENSE).
