/**
 * Stop a cloister-dev-N rollup (dedicated sequencing, so the creator can) and
 * check the refund: escrow (stake minus the creation burn, minus payouts) plus
 * the layer stake should return to the creator.
 * Dry run by default; --send to stop.  Never touches the final `cloister`.
 */
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { stopRollupError } from "@qorechain/rdk";
import { REPO_ROOT, addressFor, devRollupId, formatQor, testnetClient, txClientFor } from "@cloister/common";

const args = process.argv.slice(2);
const i = args.indexOf("--id");
const rollupId = i === -1 ? devRollupId(1) : args[i + 1]!;
const SEND = args.includes("--send");
if (!/^cloister-dev-\d+$/.test(rollupId)) throw new Error("only cloister-dev-N rollups can be stopped here");

const rdk = testnetClient();
const creator = (await addressFor("operator"))!;
const rollup = await rdk.rest.getRollup(rollupId);
if (rollup.creator !== creator) throw new Error(`${rollupId} was not created by the operator`);
if (rollup.status === "stopped") throw new Error(`${rollupId} is already stopped`);
if (rollup.sequencing === "based") throw new Error("based rollups can only be stopped by governance");

const latest = await rdk.rest.getLatestBatch(rollupId).catch(() => undefined);
const blocked = stopRollupError(latest?.status);
if (blocked) throw new Error(`cannot stop: ${blocked}`);
if (BigInt(rollup.depositPool || "0") > 0n) throw new Error("rollup holds deposits and cannot be stopped");

const before = BigInt(await rdk.rest.getBalance(creator, "uqor"));
const escrow = BigInt(rollup.escrowBalance);
console.log(`${rollupId}: status ${rollup.status}, latest batch ${latest ? `${latest.batchIndex} (${latest.status})` : "none"}`);
console.log(`escrow ${formatQor(escrow)}, layer ${rollup.layerId || "none"}; creator balance ${formatQor(before)}`);
console.log(`expected refund ≈ ${formatQor(escrow)} escrow${rollup.layerId ? " + 1000 QOR layer stake" : ""} (minus the tx fee)`);
if (!SEND) { console.log("dry run: pass --send to stop"); process.exit(0); }

const { tx } = await txClientFor(rdk, "operator");
const res = await tx.stopRollup({ rollupId, currentStatus: rollup.status as never });
if (res.code !== 0) throw new Error(`stopRollup failed (code ${res.code}): ${res.rawLog ?? ""}`);

const after = BigInt(await rdk.rest.getBalance(creator, "uqor"));
const stopped = await rdk.rest.getRollup(rollupId);
const refunded = after - before;
console.log(`stopped: ${res.transactionHash}`);
console.log(`status ${stopped.status}, escrow ${formatQor(stopped.escrowBalance)}`);
console.log(`creator balance ${formatQor(before)} -> ${formatQor(after)} (net +${formatQor(refunded)}, after fee)`);
appendFileSync(
  join(REPO_ROOT, "PROOF.md"),
  `| ${new Date().toISOString().slice(0, 10)} | Stopped ${rollupId}: status ${stopped.status}; creator refunded net ${formatQor(refunded)} (escrow ${formatQor(escrow)}${rollup.layerId ? " + layer stake" : ""}, after fee) | \`${res.transactionHash}\` | testnet |\n`,
);
