/**
 * Create a cloister-dev-N rollup: defi profile, zk (Groth16) settlement,
 * private (--privacy encapsulated), DEDICATED sequencing (so the creator can
 * stop it and get the stake back), with the spike circuit's verifying key.
 *
 * Default is a dry run that SIMULATES:
 *   1. creation with the raw gnark VK encoding,
 *   2. creation with the compressed gnark VK encoding,
 *   3. the same with sequencing "based" (only to learn whether the final
 *      `cloister` rollup can be private + based; never broadcast here).
 * The simulations spend nothing and tell us which VK encoding the chain takes.
 *
 * Broadcast:  --send --encoding raw|compressed   [--id cloister-dev-2]
 * --vk-dir <dir under circuits/>: take the VK from there (default build/, the
 * spike circuit); circuit v1 uses setup/<rollup-id>.
 */
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createRollupMsg } from "@qorechain/rdk";
import {
  REPO_ROOT, addressFor, devRollupId, formatQor, isValidRollupId, pqcAccount, testnetClient, txClientFor,
} from "@cloister/common";

const args = process.argv.slice(2);
const flag = (name: string) => {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
};
const SEND = args.includes("--send");
const rollupId = flag("--id") ?? devRollupId(1);
const encodingArg = flag("--encoding");

if (!isValidRollupId(rollupId) || !rollupId.startsWith("cloister-dev-")) {
  throw new Error(`refusing id "${rollupId}": this script only creates cloister-dev-N rollups`);
}

const vkDirArg = flag("--vk-dir");
const buildDir = join(REPO_ROOT, "circuits", vkDirArg ?? "build");
const circuitLabel = vkDirArg ? `circuit v1 VK (${vkDirArg})` : "spike gnark VK";
const vkFiles = { raw: join(buildDir, "vk.raw.bin"), compressed: join(buildDir, "vk.compressed.bin") } as const;
for (const path of Object.values(vkFiles)) {
  if (!existsSync(path)) throw new Error(`missing ${path}: run \`cd circuits && go run ./cmd/export -out build\` first`);
}
const vk = { raw: readFileSync(vkFiles.raw), compressed: readFileSync(vkFiles.compressed) };

const rdk = testnetClient();
const creator = await addressFor("operator");
if (!creator) throw new Error("QORE_MNEMONIC is not set in .env");
if (!(await pqcAccount(rdk, creator)).registered) {
  throw new Error("operator has no ML-DSA-87 key on chain yet: run `pnpm spike:register-keys --send` first");
}

const params = await rdk.rest.getParams();
const stake = BigInt(params.minStakeForRollup);
const balance = BigInt(await rdk.rest.getBalance(creator, "uqor"));
const existing = await rdk.rest.getRollup(rollupId).catch(() => undefined);
if (existing) throw new Error(`${rollupId} already exists (status ${existing.status})`);

console.log(`creator   ${creator} (${formatQor(balance)})`);
console.log(`rollup    ${rollupId}  defi · zk/snark · private · dedicated · vmType custom`);
console.log(`stake     ${formatQor(stake)} (burn ${params.rollupCreationBurnRate}), plus a 1,000 QOR layer stake if the chain registers a layer`);

const { tx } = await txClientFor(rdk, "operator");
const msg = (verificationKey: Uint8Array, sequencing: "" | "based") =>
  createRollupMsg({
    creator, rollupId, profile: "defi", vmType: "custom", stakeAmount: stake.toString(),
    verificationKey, privacy: "encapsulated", sequencing,
  });

async function simulate(label: string, m: ReturnType<typeof msg>): Promise<boolean> {
  try {
    const gas = await tx.simulate([m]);
    console.log(`  ok    ${label.padEnd(34)} gas ≈ ${gas}`);
    return true;
  } catch (e) {
    const text = e instanceof Error ? e.message : String(e);
    console.log(`  FAIL  ${label.padEnd(34)} ${text.replace(/\s+/g, " ").slice(0, 220)}`);
    return false;
  }
}

console.log("\nsimulations (nothing is broadcast):");
const rawOk = await simulate("raw VK, dedicated", msg(vk.raw, ""));
const compressedOk = await simulate("compressed VK, dedicated", msg(vk.compressed, ""));
const best = rawOk ? "raw" : compressedOk ? "compressed" : undefined;
if (best) await simulate(`${best} VK, based (final-rollup check)`, msg(vk[best], "based"));

if (!SEND) {
  console.log(`\ndry run only. ${best ? `To create it: --send --encoding ${best}` : "No encoding passed simulation; do not broadcast."}`);
  process.exit(0);
}

const encoding = encodingArg === "raw" || encodingArg === "compressed" ? encodingArg : undefined;
if (!encoding) throw new Error("--send needs --encoding raw|compressed (use the one that passed simulation)");
if (balance < stake + 1_100n * 1_000_000n) throw new Error(`balance too low for stake + layer + fees: ${formatQor(balance)}`);

const res = await tx.createRollup({
  rollupId, profile: "defi", vmType: "custom", stakeAmount: stake.toString(),
  verificationKey: vk[encoding], privacy: "encapsulated", sequencing: "",
});
if (res.code !== 0) throw new Error(`createRollup failed (code ${res.code}): ${res.rawLog ?? ""}`);
const created = await rdk.rest.getRollup(rollupId);
console.log(`\ncreated ${rollupId}: ${res.transactionHash}`);
console.log(`status ${created.status}, layer ${created.layerId || "(none)"}, escrow ${formatQor(created.escrowBalance)} (${created.escrowBalance} uqor)`);
appendFileSync(
  join(REPO_ROOT, "PROOF.md"),
  `| ${new Date().toISOString().slice(0, 10)} | Created ${rollupId} (defi, zk, private, dedicated) with the ${circuitLabel}, ${encoding} encoding; layer ${created.layerId || "none"} | \`${res.transactionHash}\` | testnet |\n`,
);
