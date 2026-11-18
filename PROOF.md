# On-chain evidence (testnet `qorechain-diana`)

Every transaction that proves a feature works goes here, newest last.

| Date (UTC) | What it proves | Tx hash / query | Notes |
|---|---|---|---|
| 2026-11-17 | operator registered ML-KEM-1024 key | `83F87FDEED9E367E97B84661FE368B5F963A2778CA8CBCA10D0BE256F2D591E3` | testnet |
| 2026-11-17 | watchtower registered ML-KEM-1024 key (after ML-DSA-87 key + PoP) | `B71AD27D67D30BB605E9DD044517184AD8F6F805E7C64BD74980DB87FF6E5728` | testnet |
| 2026-11-17 | Operator funded the watchtower with 50 test QOR (hybrid-signed MsgSend) | `5ACD6076F158F034A9402A01ACE3F882AAB85D4A929ED51730481FE11DB56FAD` | testnet |
| 2026-11-17 | Simulation: create defi + zk + private rollup accepted with the gnark VK in **both** raw (gas ≈347k) and compressed (≈313k) encodings, and with **based** sequencing | simulation only, no tx | testnet |
| 2026-11-17 | Created cloister-dev-1 (defi, zk, private, dedicated) with the spike gnark VK (raw encoding); layer cloister-dev-1 | `CC21FF52A6CD5EFF30153B56A16B2350A6DF9A51800ED16B48151593B8FE08C2` | testnet |
| 2026-11-17 | cloister-dev-1: member set [operator, watchtower] (ML-KEM-1024 keys from the chain registry) | `85AF5DD5E90BE19799AD68A5111957042C17E9DF5126935E52B7F5B20E46D464` | testnet |
| 2026-11-17 | cloister-dev-1: posted a 3536-byte ML-KEM-1024 envelope to the members (inbox seq 1); chain SHA-256 matches | `2AD586916E015D7193C8FE6B54A701D0587CB63DA54DF49C8AA86351E4C276F1` | testnet |
| 2026-11-17 | cloister-dev-1 batch 0: Groth16 (BLS12-381, gnark raw) proof verified on chain, data_hash = SHA-256 of sealed post #1, ML-DSA-87 anchor; status finalized | `41ACE69B5376469344EC40CF7D0C46E61550A18AB1557D70275019FC9D461394` | testnet |
| 2026-11-17 | Settlement receipt for cloister-dev-1 batch 0 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-1-0.json | testnet |
| 2026-11-17 | cloister-dev-1 batch 1: Groth16 (BLS12-381, gnark raw) proof verified on chain, data_hash = SHA-256 of sealed post #1, ML-DSA-87 anchor; status finalized | `3D1910379635A36015B3F1CE1C66F68C58423F115C8A3FFCE74E76721967DDCC` | testnet |
| 2026-11-17 | cloister-dev-1 batch 1: withdrawal of 1 QOR to the relayer paid on L1 (SHAKE-256 v2 withdrawals tree bound in the Groth16 proof) | `0BE31B5EF2AE70F498ABFBC5804A26BA2C999B818C03B365239FC013AF82E00D` | testnet |
| 2026-11-17 | Stopped cloister-dev-1: status stopped; creator refunded net 10898.934059 QOR (escrow 9899 QOR + layer stake, after fee) | `F6B7F2349D6CD5BE6A1E5610D66E106C24F4F53F69C8D1A2C6A12D6141EB82AE` | testnet |
| 2026-11-17 | After the stop, batch 0's settlement receipt still verifies against chain state (valid, all six checks): receipts outlive the rollup | receipts/cloister-dev-1-0.json | testnet |
| 2026-11-18 | Created cloister-dev-2 (defi, zk, private, dedicated) with the circuit v1 VK (setup/cloister-dev-2), raw encoding; layer cloister-dev-2 | `CA8AE0D671CA9276EC488A29F33DC422AC190CE1B5DBDE3D2B73A94B21D1708C` | testnet |
| 2026-11-18 | cloister-dev-2: member set [operator, watchtower] | `7A26DB8CF34279FFEFED77F86133C0F5D3EB2BD9FF1C19B8EAA13C3F8CC527BF` | testnet |
| 2026-11-18 | cloister-dev-2 batch 0: sealed batch input posted (3856-byte ML-KEM-1024 envelope, members only) | `704EC0B90DCDA8071008ED4FE26017E40440BAD9D9B9328D81E917F23608317D` | testnet |
| 2026-11-18 | cloister-dev-2 batch 0 (onboard): **circuit v1** Groth16 proof verified on chain (Poseidon2 account tree, 2 frame txs, 0 withdrawal(s) with the SHAKE-256 root computed in-circuit); status finalized | `53172CBD9B6D6A94E2DE36688918DDF60E58033CF7F05F8B6AA62349CA0EDA51` | testnet |
| 2026-11-18 | cloister-dev-2 batch 1: sealed batch input posted (3911-byte ML-KEM-1024 envelope, members only) | `82831458565D171764F7B049E593F1FFF86298DB48ECE0A7FF56185960D31271` | testnet |
| 2026-11-18 | cloister-dev-2 batch 1 (withdraw): **circuit v1** Groth16 proof verified on chain (Poseidon2 account tree, 2 frame txs, 2 withdrawal(s) with the SHAKE-256 root computed in-circuit); status finalized | `92428072C8E983EAEA64CEF965E38CE4CC0007B1F3ED1280ED73F4CAD64D107E` | testnet |
| 2026-11-18 | cloister-dev-2 batch 1: withdrawal #0 of 5 QOR paid on L1 from a leaf proven inside circuit v1 | `D9DE78C09D5DBC31F2C69C5885825B652034DAAD25DAF3FD7A68E82CA280FCEC` | testnet |
| 2026-11-18 | cloister-dev-2 batch 1: withdrawal #1 of 1.02 QOR paid on L1 from a leaf proven inside circuit v1 | `9AA724CBAE8174DDD181F0DB4C0CB5DC2BBE8DC7C3CFEB311672A460571A6E42` | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 0 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-0.json | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 1 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-1.json | testnet |
| 2026-11-18 | cloister-dev-2 batch 2: sealed batch input posted (20237-byte ML-KEM-1024 envelope, members only) | `C0A1AD090CC42375F4DECBF197AA201AFEF27E5010605A5B90E1100E30EFA00B` | testnet |
| 2026-11-18 | cloister-dev-2 batch 2 (frame txs): **circuit v1** Groth16 proof verified on chain (Poseidon2 account tree, 2 frame txs, 1 withdrawal(s) with the SHAKE-256 root computed in-circuit); status finalized | `DB88318D506743C07F5CCC81900E47BCA61334945AA7F53752B6CC38F9EE325D` | testnet |
| 2026-11-18 | cloister-dev-2 batch 2: withdrawal #0 of 1 QOR paid on L1 from a leaf proven inside circuit v1 | `809371B5EA98D935C3E75A67022824E65CD39434DDDCE612F127C44B7B7657CC` | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 2 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-2.json | testnet |
| 2026-11-18 | cloister-dev-2 batch 3: sealed bundle of 1 signed frame tx(s) posted (8271 B, members only) | `CC050EAC798E047EE1B77E9DD5455969F1D61A67C43DB44F6CFFF74CF711EDE6` | testnet |
| 2026-11-18 | cloister-dev-2 batch 3: sequencer service, 1 frame tx(s), 1 withdrawal(s), circuit v1 proof verified on chain; status finalized | `5E75EBCBCE906D2E4C795726398D3691AB0A3F1C0B260B539E266A037EF1C203` | testnet |
| 2026-11-18 | cloister-dev-2 batch 3: withdrawal #0 of 0.5 QOR to qor1plfn9jpxnavtxsrwe0sg6cls5z9amy8p3tg9nu paid on L1 | `C7D83AF32A9991D746CF058A6E8E88582311993125D447D352AD44CBEF1CFA83` | testnet |
| 2026-11-18 | cloister-dev-2 batch 4: sealed bundle of 1 signed frame tx(s) posted (8210 B, members only) | `6D2E3260BEB4D35811D8015141D01CE85FC83EC4A7FA25B4A5CC4C7F55F99282` | testnet |
| 2026-11-18 | cloister-dev-2 batch 4: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `70414F431AE2398DEC968712787FBBFBC6EC4715A6D3C7ADCA6AFB1B0577DA82` | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 3 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-3.json | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 4 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-4.json | testnet |
