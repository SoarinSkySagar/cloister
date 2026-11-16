/**
 * Read-only testnet check: no keys, no transactions.
 * Prints the live rdk parameters Cloister depends on, the chain tip, existing
 * rollups, and whether our rollup ids are still free.
 */
import { FINAL_ROLLUP_ID, devRollupId, testnetClient } from "@cloister/common";

const QOR = 1_000_000n;
const toQor = (uqor: string | undefined) => (uqor === undefined ? "n/a" : `${BigInt(uqor) / QOR} QOR`);

const rdk = testnetClient();
console.log(`network   ${rdk.network.chainId}`);
console.log(`rest      ${rdk.network.endpoints.rest}`);

const tip = await rdk.getChainTip();
console.log(`tip       height ${tip.height} @ ${new Date(tip.timeSecs * 1000).toISOString()}`);

const p = await rdk.rest.getParams();
console.log("\nrdk params");
console.log(`  min stake for rollup     ${toQor(p.minStakeForRollup)}`);
console.log(`  creation burn rate       ${p.rollupCreationBurnRate}`);
console.log(`  max rollups              ${p.maxRollups}`);
console.log(`  max batches per block    ${p.maxBatchesPerBlock}`);
console.log(`  max posted data bytes    ${p.maxPostedDataBytes ?? "n/a"}`);
console.log(`  posted data fee / byte   ${p.postedDataFeePerByte ?? "n/a"} uqor`);
console.log(`  posted data retention    ${p.postedDataRetentionBlocks ?? "n/a"} blocks`);

const rollups = await rdk.rest.listRollups();
console.log(`\nrollups on testnet: ${rollups.length}`);
for (const r of rollups) {
  console.log(`  ${r.rollupId.padEnd(28)} ${r.profile.padEnd(8)} ${r.settlementMode.padEnd(11)} ${(r.proofSystem ?? "").padEnd(6)} ${r.status}`);
}

const taken = new Set(rollups.map((r) => r.rollupId));
console.log("\nour ids");
for (const id of [FINAL_ROLLUP_ID, devRollupId(1)]) {
  console.log(`  ${id.padEnd(16)} ${taken.has(id) ? "TAKEN" : "free"}`);
}
