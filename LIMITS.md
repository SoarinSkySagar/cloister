# Known limits

> Kept current as we build. Each item links to the threat model where relevant.

- Testnet only (`qorechain-diana`).
- ML-DSA signatures are verified outside the circuit (THREAT_MODEL T2).
- Single sequencer, which is also the rollup creator (T3).
- Balances are backed by the creator's escrow until a deposit path exists (T9).
- The trusted setup is single-party (T12).
