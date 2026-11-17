/**
 * Prove and submit a batch on a cloister-dev-N rollup with the spike circuit
 * (rule: state_root = prev_state_root + 1).
 *
 * data_hash: SHA-256 of the latest posted envelope (the chain checks a retained
 * post with exactly that hash exists; the circuit sees it reduced mod r).
 * withdrawals_root: empty (0) for this batch.
 *
 * Default: prove, then SIMULATE submitBatch with the raw and compressed gnark
 * proof encodings (the chain's verifier runs, nothing is broadcast).
 * --send --encoding raw|compressed: broadcast with the creator's ML-DSA-87
 * anchor signature (anchor: "require"), so a settlement receipt is possible.
 * NOTE: the rollup's verifying key locks after its first batch.
 */
import { appendFileSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { buildExecuteWithdrawalInput, isRestNotFound, submitBatchMsg, withdrawalsTree, zkPublicInputErrors, zkPublicInputs } from "@qorechain/rdk";
import { CHAIN_ID, QOR, REPO_ROOT, addressFor, devRollupId, formatQor, testnetClient, txClientFor, type Role } from "@cloister/common";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const SEND = args.includes("--send");
const rollupId = flag("--id") ?? devRollupId(1);
if (!rollupId.startsWith("cloister-dev-")) throw new Error("only cloister-dev-N rollups");

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const be32 = (n: bigint) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");

const rdk = testnetClient();
const sequencer = await addressFor("operator");
if (!sequencer) throw new Error("QORE_MNEMONIC missing");

// Next batch index and previous state root.
let batchIndex = 0;
let prev = 0n;
try {
  const latest = await rdk.rest.getLatestBatch(rollupId);
  batchIndex = latest.batchIndex + 1;
  prev = BigInt("0x" + (latest.stateRoot || "0"));
} catch (e) {
  if (!isRestNotFound(e)) throw e;
}
const state = prev + 1n;

const inbox = await rdk.rest.getInbox(rollupId);
if (inbox.headSequence === 0) throw new Error("no posted data yet: run spike:members-post --send first");
const posted = await rdk.rest.getPostedData(rollupId, inbox.headSequence);
const dataHash = Buffer.from(posted.dataHash, "hex");

// Optional withdrawal committed in this batch: --withdraw-to relayer --withdraw-qor 1
const withdrawTo = flag("--withdraw-to") as Role | undefined;
const withdrawQor = Number(flag("--withdraw-qor") ?? 0);
let tree: ReturnType<typeof withdrawalsTree> | undefined;
let withdrawal: { recipient: string; denom: string; amount: string } | undefined;
if (withdrawTo) {
  if (!Number.isInteger(withdrawQor) || withdrawQor < 1 || withdrawQor > 10) throw new Error("--withdraw-qor must be 1..10");
  const recipient = await addressFor(withdrawTo);
  if (!recipient) throw new Error(`${withdrawTo} mnemonic missing`);
  withdrawal = { recipient, denom: "uqor", amount: (BigInt(withdrawQor) * QOR).toString() };
  tree = withdrawalsTree([withdrawal], { rollupId, version: "v2", chainId: CHAIN_ID });
}

const inputs = {
  prevStateRoot: batchIndex === 0 ? undefined : be32(prev),
  stateRoot: be32(state),
  dataHash,
  withdrawalsRoot: tree?.root,
};
const errs = zkPublicInputErrors(inputs, { dataHashBound: true });
if (errs.length) throw new Error(`public inputs not canonical: ${errs.join("; ")}`);
const [pi0, pi1, pi2, pi3] = zkPublicInputs(inputs) as [Uint8Array, Uint8Array, Uint8Array, Uint8Array];

console.log(`${rollupId} batch ${batchIndex}: prev=${prev} state=${state}`);
console.log(`  data_hash = sha256(post #${inbox.headSequence}) ${posted.dataHash.slice(0, 16)}… (circuit input reduced mod r)`);
if (withdrawal && tree) console.log(`  withdrawal #0: ${formatQor(withdrawal.amount)} -> ${withdrawTo} ${withdrawal.recipient}, withdrawals_root ${hex(tree.root).slice(0, 16)}…`);

const outDir = join(REPO_ROOT, "circuits", "build", `${rollupId}-b${batchIndex}`);
execFileSync("go", ["run", "./cmd/prove", "-out", outDir, "-prev", hex(pi0), "-state", hex(pi1), "-data", hex(pi2), "-wd", hex(pi3)], {
  cwd: join(REPO_ROOT, "circuits"), stdio: ["ignore", "inherit", "inherit"],
});
const proofs = {
  raw: readFileSync(join(outDir, "proof.raw.bin")),
  compressed: readFileSync(join(outDir, "proof.compressed.bin")),
};

const { tx } = await txClientFor(rdk, "operator");
const base = { sequencer, rollupId, batchIndex, stateRoot: inputs.stateRoot, prevStateRoot: inputs.prevStateRoot, txCount: 1, dataHash, withdrawalsRoot: tree?.root };

console.log("\nsimulations (the chain's Groth16 verifier runs; nothing is broadcast):");
const results: Record<string, boolean> = {};
for (const [enc, proof] of Object.entries(proofs)) {
  try {
    const gas = await tx.simulate([submitBatchMsg({ ...base, proof })]);
    console.log(`  ok    ${enc.padEnd(10)} proof (${proof.length} B)  gas ≈ ${gas}`);
    results[enc] = true;
  } catch (e) {
    console.log(`  FAIL  ${enc.padEnd(10)} proof (${proof.length} B)  ${(e instanceof Error ? e.message : String(e)).replace(/\s+/g, " ").slice(0, 200)}`);
    results[enc] = false;
  }
}

// Negative control: a valid proof against a different statement must be refused,
// otherwise the simulations above prove nothing.
try {
  await tx.simulate([submitBatchMsg({ ...base, stateRoot: be32(state + 1n), proof: proofs.raw })]);
  console.log("  WARN  tampered state_root was ACCEPTED: the verifier is not running in simulation");
} catch (e) {
  console.log(`  ok    tampered state_root refused: ${(e instanceof Error ? e.message : String(e)).replace(/\s+/g, " ").slice(0, 120)}`);
}

if (!SEND) {
  const ok = Object.keys(results).filter((k) => results[k]);
  console.log(`\ndry run only. ${ok.length ? `To submit: --send --encoding ${ok[0]}  (locks the VK of ${rollupId})` : "No encoding verified; do not broadcast."}`);
  process.exit(0);
}
const enc = flag("--encoding");
if (enc !== "raw" && enc !== "compressed") throw new Error("--send needs --encoding raw|compressed");

const res = await tx.submitBatch({ rollupId, batchIndex, stateRoot: base.stateRoot, prevStateRoot: base.prevStateRoot, txCount: 1, dataHash, withdrawalsRoot: tree?.root, proof: proofs[enc] }, { anchor: "require" });
if (res.code !== 0) throw new Error(`submitBatch failed (code ${res.code}): ${res.rawLog ?? ""}`);
const batch = await rdk.rest.getBatch(rollupId, batchIndex);
console.log(`\nsubmitted batch ${batchIndex}: ${res.transactionHash}`);
console.log(`status ${batch.status}, state_root ${batch.stateRoot.slice(0, 16)}…`);
appendFileSync(
  join(REPO_ROOT, "PROOF.md"),
  `| ${new Date().toISOString().slice(0, 10)} | ${rollupId} batch ${batchIndex}: Groth16 (BLS12-381, gnark ${enc}) proof verified on chain, data_hash = SHA-256 of sealed post #${inbox.headSequence}, ML-DSA-87 anchor; status ${batch.status} | \`${res.transactionHash}\` | testnet |\n`,
);

if (withdrawal && tree && withdrawTo) {
  if (batch.status !== "finalized") throw new Error(`batch ${batchIndex} is ${batch.status}, not finalized: cannot withdraw yet`);
  const before = BigInt(await rdk.rest.getBalance(withdrawal.recipient, "uqor"));
  const input = buildExecuteWithdrawalInput({
    submitter: sequencer, rollupId, batchIndex, ...withdrawal, withdrawal: tree.proof(0),
  });
  const w = await tx.executeWithdrawal(input);
  if (w.code !== 0) throw new Error(`executeWithdrawal failed (code ${w.code}): ${w.rawLog ?? ""}`);
  const after = BigInt(await rdk.rest.getBalance(withdrawal.recipient, "uqor"));
  const escrow = (await rdk.rest.getRollup(rollupId)).escrowBalance;
  console.log(`withdrawal executed: ${w.transactionHash}`);
  console.log(`  ${withdrawTo} balance ${formatQor(before)} -> ${formatQor(after)}; rollup escrow now ${formatQor(escrow)}`);
  if (after - before !== BigInt(withdrawal.amount)) throw new Error("recipient balance did not increase by the withdrawal amount");
  appendFileSync(
    join(REPO_ROOT, "PROOF.md"),
    `| ${new Date().toISOString().slice(0, 10)} | ${rollupId} batch ${batchIndex}: withdrawal of ${formatQor(withdrawal.amount)} to the ${withdrawTo} paid on L1 (SHAKE-256 v2 withdrawals tree bound in the Groth16 proof) | \`${w.transactionHash}\` | testnet |\n`,
  );
}
