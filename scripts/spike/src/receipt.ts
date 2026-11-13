/**
 * Build the settlement receipt for a batch from its on-chain ML-DSA-87 anchor,
 * then verify it against live chain state (the key is read from the chain,
 * never from the receipt). Writes receipts/<rollup>-<batch>.json.
 *   pnpm spike:receipt -- [--id cloister-dev-1] [--batch 0]
 */
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildSettlementReceipt, verifySettlementReceipt } from "@qorechain/rdk";
import { REPO_ROOT, devRollupId, testnetClient } from "@cloister/common";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const rollupId = flag("--id") ?? devRollupId(1);
const batchIndex = Number(flag("--batch") ?? 0);

const rdk = testnetClient();
const receipt = await buildSettlementReceipt(rdk, rollupId, batchIndex);
const result = await verifySettlementReceipt(receipt, { client: rdk });

const dir = join(REPO_ROOT, "receipts");
mkdirSync(dir, { recursive: true });
const file = join(dir, `${rollupId}-${batchIndex}.json`);
writeFileSync(file, JSON.stringify(receipt, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");

console.log(`receipt ${rollupId} batch ${batchIndex} -> ${file}`);
console.log(`valid: ${result.valid}  mode: ${(result as { mode?: string }).mode ?? "?"}`);
const checks = (result as { checks?: Record<string, unknown> }).checks ?? {};
for (const [name, value] of Object.entries(checks)) console.log(`  ${name.padEnd(22)} ${JSON.stringify(value)}`);
if (!result.valid) {
  console.log(JSON.stringify(result, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2).slice(0, 1500));
  process.exit(1);
}
appendFileSync(
  join(REPO_ROOT, "PROOF.md"),
  `| ${new Date().toISOString().slice(0, 10)} | Settlement receipt for ${rollupId} batch ${batchIndex} verified against live chain state (ML-DSA-87 anchor, key read from chain): valid | receipts/${rollupId}-${batchIndex}.json | testnet |\n`,
);
