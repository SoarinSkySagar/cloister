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
| 2026-11-18 | cloister-dev-2 batch 5: sealed bundle of 1 signed frame tx(s) posted (15440 B, members only) | `0C82D3C83042191C9B4F6D4EDCBB676F6909AA7A2D32DFABD8D9D3421CB33ABC` | testnet |
| 2026-11-18 | cloister-dev-2 batch 5: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `B559503DC36DDE0EDEBB094A8BD2C3EBB37CB0726DECABC324C0EFF3C134AAAA` | testnet |
| 2026-11-18 | cloister-dev-2 batch 6: sealed bundle of 1 signed frame tx(s) posted (12857 B, members only) | `B8AF618149D1EF935DBE20D32BA30AF7450E02248BC3F11C1CE8F0D0FF4D709C` | testnet |
| 2026-11-18 | cloister-dev-2 batch 6: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `EC5CF11F22BE2B914160CA5E82E4AA944758402FEF8593435BB4A7091B717625` | testnet |
| 2026-11-18 | cloister-dev-2 batch 7: sealed bundle of 1 signed frame tx(s) posted (15440 B, members only) | `2438DF5D8D4863D5302394DA2BCA81B676CEE4B664360811E8CB23AC39976244` | testnet |
| 2026-11-18 | cloister-dev-2 batch 7: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `816FB044BC916B602FFBF33E089977211788A9C3EA4AF128B947196A71F7ADD0` | testnet |
| 2026-11-18 | cloister-dev-2 batch 8: sealed bundle of 2 signed frame tx(s) posted (20176 B, members only) | `F65CD42A4AE964FAC096EB26CA02B04F4E7A4AEB65C5A6EC8195E919A3CBD6B8` | testnet |
| 2026-11-18 | cloister-dev-2 batch 8: sequencer service, 2 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `6E85898828E246ACB6F2377174538C6972ED8133B49A05F8A3A504452AF62197` | testnet |
| 2026-11-18 | cloister-dev-2 batch 9: sealed bundle of 1 signed frame tx(s) posted (12857 B, members only) | `B89B6013BF47C15057050B4EDA8300566CD57F5E9E540527DD05D74B522874F8` | testnet |
| 2026-11-18 | cloister-dev-2 batch 9: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `6C89423A506CF4AC84F6AADE5E24E2B42660B3D0080DAB33FCA0BF1499FA973F` | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 5 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-5.json | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 6 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-6.json | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 7 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-7.json | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 8 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-8.json | testnet |
| 2026-11-18 | Settlement receipt for cloister-dev-2 batch 9 verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/cloister-dev-2-9.json | testnet |
| 2026-11-18 | cloister-dev-2 batch 10: sealed bundle of 1 signed frame tx(s) posted (12857 B, members only) | `85425DD7BC29918C1C1C897F039B42221E38895EEBEDA49C15118C5CAFF8DC22` | testnet |
| 2026-11-18 | cloister-dev-2 batch 10: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v1 proof verified on chain; status finalized | `509A5CFEC12176277429F70C39B6B8F41F7A179F6B910871BC370AC850B209EF` | testnet |
| 2026-11-18 | Stopped cloister-dev-2: status stopped; creator refunded net 10892.414134 QOR (escrow 9892.48 QOR + layer stake, after fee) | `8DC0367ADEF68469C891198BCE71CAF4CC68D73E54C5EAC55ABD47F7A3B32B00` | testnet |
| 2026-11-18 | Created cloister-dev-3 (defi, zk, private, dedicated) with the circuit v2 VK (setup/cloister-dev-3), raw encoding; layer cloister-dev-3 | `6B0F523D403D0A648536BA4EEEF975AC692217328916D2A5A06897D1E45940DF` | testnet |
| 2026-11-18 | cloister-dev-3: member set [operator, watchtower] (ML-KEM-1024 keys from the chain registry) | `051DC7D9187D26946BB16A4DE05BCFE265207894650711CF7B485C4433725867` | testnet |
| 2026-11-18 | cloister-dev-3: posted a 3536-byte ML-KEM-1024 envelope to the members (inbox seq 1); chain SHA-256 matches | `A9802AF970DA07CDA4F3BB445741DB8208210E9DF53E36E3455EC29B0B3F12F0` | testnet |
| 2026-11-18 | cloister-dev-3 batch 0: sealed bundle of 1 signed frame tx(s) posted (15440 B, members only) | `7769854A75F2385A054F28DAAD801CD5ADF9891637BA0C68F86F8139A774C0E8` | testnet |
| 2026-11-18 | cloister-dev-3 batch 0: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `304FDC51E3F6710FD12D0DA43C455FC2A50B46633CDF0CE9C78CF122D68C9EC1` | testnet |
| 2026-11-18 | cloister-dev-3 batch 1: sealed bundle of 1 signed frame tx(s) posted (15440 B, members only) | `34055E71A551EF84D3C0DFD683AFC52EDC104548801CEC6555685875B9E48303` | testnet |
| 2026-11-18 | cloister-dev-3 batch 1: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `5C8B3B5AFC49C960CECCF575095814851A7B036BE6511D6B59F6424A478FA894` | testnet |
| 2026-11-18 | cloister-dev-3 batch 2: sealed bundle of 1 signed frame tx(s) posted (8234 B, members only) | `57FF978798EB3F59749A7B10715D639BCA845ECB2FD0FDA530325452823BC4D4` | testnet |
| 2026-11-18 | cloister-dev-3 batch 2: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `042C5A529647B9DA403B8BFF8F4C366E356664761FB73B6F06191C62278CCBC7` | testnet |
| 2026-11-18 | cloister-dev-3 batch 3: sealed bundle of 1 signed frame tx(s) posted (8234 B, members only) | `B0AEF43B11D9ED4ED8458467C6D923AA64D835E9C5412E018F2DB4D02F2CA607` | testnet |
| 2026-11-18 | cloister-dev-3 batch 3: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `5F21CA24D0D2A05D510138301840C940B7580A8A31E97A3033ED76F79CB0C4AC` | testnet |
| 2026-11-18 | cloister-dev-3 batch 4: sealed bundle of 1 signed frame tx(s) posted (17532 B, members only) | `8C11B10A463DE965CA29FFB3748500D999DBECA38D0D1BCCEE41D6D8F77C079F` | testnet |
| 2026-11-18 | cloister-dev-3 batch 4: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `2EEAEC4586FDB6C1EB65D2A1449F6E51428BE38C1560E938696532027C7BD415` | testnet |
| 2026-11-18 | cloister-dev-3 batch 5: sealed bundle of 1 signed frame tx(s) posted (8210 B, members only) | `C7E20CF5D2F552510444E174476C2ACC7EC5A23E916E455235C5332E1E033E16` | testnet |
| 2026-11-18 | cloister-dev-3 batch 5: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `130771013FB043B895F1CC3B0D1076ACEBEF279D8E9CEE10F102061E314AD644` | testnet |
| 2026-11-18 | cloister-dev-3 batch 6: sealed bundle of 1 signed frame tx(s) posted (8225 B, members only) | `7610A75AD36DEDA2E4CBA5B0C33304194C0BCA8D7F091DEDBB5753C455712043` | testnet |
| 2026-11-18 | cloister-dev-3 batch 6: sequencer service, 1 frame tx(s), 0 withdrawal(s), circuit v2 proof verified on chain; status finalized | `91016DFCB6793D3E43D14DDA0E22A38F454DD4EC178CB94DD2B04DF27EA44CCE` | testnet |
| 2026-11-19 | cloister-dev-3 batches 0-3 (circuit v2): onboarding of alice (#2) and carol (#3) sponsored by the treasury, then funding; each batch's Groth16 proof verified on chain. First on-chain verification of circuit v2 (2,246,124 constraints, 4 public inputs) | see the batch lines above | testnet |
| 2026-11-19 | cloister-dev-3 batch 4: **two-party atomic swap** (sender alice, co-signer carol, sponsor treasury): 300 USD alice -> carol and 20 QOR carol -> alice in one tx, one signature per party. Both legs applied; alice 700 USD / 122 QOR and carol 400 USD after batch 6 | `2EEAEC4586FDB6C1EB65D2A1449F6E51428BE38C1560E938696532027C7BD415` | testnet |
| 2026-11-19 | cloister-dev-3: **inclusion proof** of that swap (receipts/inclusion/cloister-dev-3-batch4-swap.json, 18 hashes) verifies against the state root QoreChain holds for batch 4 (`pnpm --filter @cloister/receipts cli verify-proof`). A copy with the amount changed, a copy claimed for batch 3 and a copy without the co-signer are all refused | receipts/inclusion/cloister-dev-3-batch4-swap.json | testnet |
| 2026-11-19 | cloister-dev-3: **time lock**: a treasury tx with GUARD not_before = 6 was accepted at batch 4, stayed queued through batch 5, and was included in batch 6, the first batch it was valid in | `91016DFCB6793D3E43D14DDA0E22A38F454DD4EC178CB94DD2B04DF27EA44CCE` | testnet |
| 2026-11-19 | cloister-dev-3: the member watchtower signed verdicts for batches 0-6 (all checks incl. both signatures of the swap and the signed-window check pass) and 7 settlement receipts verify | receipts/cloister-dev-3-*.verdicts.json | testnet |
