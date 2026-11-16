# Cloister threat model

> Draft skeleton. It gets filled in as components land. See design.md §A8 and §B5.

## 1. System and trust boundaries
- **L1 (QoreChain):** verifies Groth16 proofs, stores batches and the VK, enforces envelope structure, pays withdrawals from escrow, and anchors ML-DSA-87 signatures.
- **Sequencer/prover (rollup creator, member):** decrypts, orders and executes transactions, and proves batches.
- **Relayer:** posts sealed envelopes and is reimbursed by sponsors.
- **Watchtowers (members):** independently decrypt, re-execute and alert.
- **Users (not members):** sign frame transactions and seal them to the member set.

## 2. Assets
Balances · transaction contents · sender/sponsor identity · escrow · withdrawal rights

## 3. Adversaries
Malicious sequencer · malicious relayer · malicious sponsor · outside observer · quantum adversary (Q-Day) · holder of a leaked classical key

## 4. Threats and mitigations
| # | Threat | Mitigation | Residual |
|---|---|---|---|
| T1 | Q-Day: a classical key is broken | Hybrid L1 transactions (ML-DSA-87 required); ML-DSA-87-only frame transactions | — |
| T2 | Forged transactions (circuit doesn't verify ML-DSA) | Sequencer checks, plus every watchtower re-verifies and alerts | Detected, not prevented on chain |
| T3 | Sequencer censors or reorders | Inclusion watchtower; based inbox (if available) | Single sequencer |
| T4 | Relayer drops transactions | Users can post themselves (based mode) | Dedicated mode depends on the sequencer |
| T5 | Sponsor drained by spam | `max_fee` cap, and the sponsor signs every tx | — |
| T6 | Replay | Nonce, expiry, and chain and rollup id in the sighash | — |
| T7 | VK change | VK locks after batch 0; governance-only updates; watchtower alarm | Governance trust |
| T8 | Data withholding | Watchtower opens every envelope in range | Members only |
| T9 | Escrow-backed balances (no deposit path) | Recorded; operator-credited onboarding | Trusted operator |
| T10 | Metadata leakage | Relayer hides posters; contents sealed | Sizes, timing, member list and withdrawals are public |
| T11 | Removed member keeps old data | New epoch on every membership change | Past data stays readable to them |
| T12 | Trusted setup | Our own setup ceremony; transcript published | Single-party setup (hackathon) |

## 5. Outsiders vs members
To outsiders Cloister behaves like a **validium**: they can verify that each state transition was valid but can't rebuild the state. Members get full data availability.
