/**
 * Circuit v1 on a cloister-dev-N rollup.
 *
 *   ledger config --id cloister-dev-2      write circuits/setup/<id>/config.json (genesis: treasury = operator
 *                                          key holding the expected escrow, relayer = account 1)
 *   ledger setup  --id cloister-dev-2      Groth16 setup (go run ./cmd/ledger setup), ~2.5 min, ~9.4 GB RAM
 *   ledger batch  --id cloister-dev-2 --step onboard|withdraw [--send]
 *       seal the batch input to the members (ML-KEM-1024 envelope), prove it locally with data_hash =
 *       SHA-256(envelope); with --send: set members if needed, post the envelope, simulate submitBatch
 *       (raw + compressed + a tampered control), submit with the ML-DSA-87 anchor, advance the state,
 *       and execute the batch's withdrawals on L1.
 *
 * Accounts: 0 treasury (operator key), 1 relayer, 2 watchtower (onboarded in batch 0).
 */
import { appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import {
  BLS12_381_SCALAR_MODULUS, buildExecuteWithdrawalInput, envelopeMembershipError, resolvePqcKeypair, sealEnvelope,
  submitBatchMsg, withdrawalsTree, zkPublicInputErrors,
} from "@qorechain/rdk";
import {
  CHAIN_ID, REPO_ROOT, addressFor, formatQor, loadEnv, mnemonicFor, testnetClient, txClientFor, type Role,
} from "@cloister/common";

const [cmd, ...args] = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const SEND = args.includes("--send");
const rollupId = flag("--id") ?? "";
if (!/^cloister-dev-\d+$/.test(rollupId)) throw new Error("--id cloister-dev-N is required");

const circuits = join(REPO_ROOT, "circuits");
const setupRel = join("setup", rollupId);
const setupDir = join(circuits, setupRel);
const rdk = testnetClient();
const env = loadEnv();
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const be32 = (h: string) => Buffer.from(h.padStart(64, "0"), "hex");
const proofLine = (what: string, ref: string) =>
  appendFileSync(join(REPO_ROOT, "PROOF.md"), `| ${new Date().toISOString().slice(0, 10)} | ${what} | ${ref} | testnet |\n`);

/** pk_commit = SHAKE-256/32(ML-DSA-87 public key) mod r (spec/state.md). */
async function pkCommit(role: Role): Promise<string> {
  const address = (await addressFor(role, env))!;
  const { keypair } = await resolvePqcKeypair(rdk, address, mnemonicFor(role, env)!);
  const h = createHash("shake256", { outputLength: 32 }).update(keypair.publicKey).digest("hex");
  return (BigInt("0x" + h) % BLS12_381_SCALAR_MODULUS).toString(16).padStart(64, "0");
}

if (cmd === "config") {
  const params = await rdk.rest.getParams();
  const stake = BigInt(params.minStakeForRollup);
  const burnRate = Number(params.rollupCreationBurnRate);
  const burn = (stake * BigInt(Math.round(burnRate * 1e6))) / 1_000_000n;
  const escrow = stake - burn;
  const config = {
    depth: 16, txs: 4, moves: 3, withdrawals: 4, chain_id: CHAIN_ID, rollup_id: rollupId,
    genesis: [
      { index: 0, pk_commit: await pkCommit("operator"), qor: Number(escrow), usd: 1_000_000_000_000 },
      { index: 1, pk_commit: await pkCommit("relayer"), qor: 0, usd: 0 },
    ],
  };
  mkdirSync(setupDir, { recursive: true });
  writeFileSync(join(setupDir, "config.json"), JSON.stringify(config, null, 2) + "\n");
  console.log(`wrote ${join(setupRel, "config.json")}: treasury ${formatQor(escrow)} (stake ${formatQor(stake)} minus ${burnRate} burn), 1,000,000 USD`);
  process.exit(0);
}

if (cmd === "setup") {
  execFileSync("go", ["run", "./cmd/ledger", "setup", "-dir", setupRel], { cwd: circuits, stdio: "inherit" });
  process.exit(0);
}

if (cmd !== "batch") throw new Error("usage: ledger config|setup|batch --id cloister-dev-N");

// ---- batch ----
const step = flag("--step");
const [watchtower, relayer] = [(await addressFor("watchtower", env))!, (await addressFor("relayer", env))!];
let batch: object;
if (step === "onboard") {
  batch = { txs: [
    { sender: 0, payer: 0, relayer: 1, fee_asset: 0, fee: 0, actions: [
      { kind: "transfer", to: 2, asset: 0, amount: 50_000_000 },
      { kind: "transfer", to: 2, asset: 1, amount: 1_000_000_000 },
    ] },
    // sponsored onboarding: the treasury pays the new account's fee
    { sender: 2, payer: 0, relayer: 1, fee_asset: 0, fee: 10_000, actions: [
      { kind: "register_key", pk_commit: await pkCommit("watchtower") },
    ] },
  ] };
} else if (step === "withdraw") {
  batch = { txs: [
    { sender: 2, payer: 0, relayer: 1, fee_asset: 0, fee: 10_000, actions: [
      { kind: "withdraw", recipient: watchtower, amount: 5_000_000, atomic: true },
      { kind: "transfer", to: 1, asset: 0, amount: 1_000_000, atomic: true },
    ] },
    // the relayer withdraws everything it earned (fees + payment) to L1
    { sender: 1, payer: 1, relayer: 1, fee_asset: 0, fee: 0, actions: [
      { kind: "withdraw", recipient: relayer, amount: 1_020_000 },
    ] },
  ] };
} else throw new Error("--step onboard|withdraw");

const state = JSON.parse(readFileSync(join(setupDir, "state.json"), "utf8")) as { batches: number; root: string };
let rollup = await rdk.rest.getRollup(rollupId).catch((e) => {
  if (SEND) throw e;
  console.log(`(dry run: ${rollupId} does not exist yet)`);
  return { members: [] as string[], membersEpoch: 0 } as unknown as Awaited<ReturnType<typeof rdk.rest.getRollup>>;
});
const latest = await rdk.rest.getLatestBatch(rollupId).catch(() => undefined);
const batchIndex = latest ? latest.batchIndex + 1 : 0;
if (batchIndex !== state.batches) throw new Error(`chain is at batch ${batchIndex}, local state at ${state.batches}`);
if (latest && latest.stateRoot.toLowerCase().padStart(64, "0") !== state.root) {
  throw new Error(`chain state_root ${latest.stateRoot} != local ${state.root}`);
}

// Members: the operator and the watchtower can open every post.
const { tx } = await txClientFor(rdk, "operator");
const memberAddrs = [(await addressFor("operator", env))!, watchtower];
if (rollup.members.join() !== memberAddrs.join() && (SEND || rollup.members.length)) {
  if (!SEND) { console.log("members not set yet (needs --send)"); }
  else {
    const res = await tx.setRollupMembers({ rollupId, members: memberAddrs });
    if (res.code !== 0) throw new Error(`setRollupMembers failed: ${res.rawLog}`);
    proofLine(`${rollupId}: member set [operator, watchtower]`, `\`${res.transactionHash}\``);
    rollup = await rdk.rest.getRollup(rollupId);
  }
}

// Seal the batch input itself: the post IS the batch's transactions, readable by members only.
const plaintext = new TextEncoder().encode(JSON.stringify({ kind: "cloister-batch/v1", batch_index: batchIndex, ...batch }));
const recipients = await Promise.all(rollup.members.map(async (member) => {
  const kem = await rdk.rest.getKemKey(member);
  if (!kem) throw new Error(`${member} has no ML-KEM key`);
  return { member, encapsulationKey: kem.publicKey };
}));
let sha = "";
let envelope: Uint8Array | undefined;
if (recipients.length) {
  envelope = sealEnvelope({ chainId: CHAIN_ID, rollupId, epoch: rollup.membersEpoch, recipients, plaintext });
  const err = envelopeMembershipError(envelope, { membersEpoch: rollup.membersEpoch, members: recipients });
  if (err) throw new Error(`envelope refused: ${err}`);
  sha = createHash("sha256").update(envelope).digest("hex");
  console.log(`sealed batch ${batchIndex} (${step}): ${plaintext.length} B plaintext -> ${envelope.length} B envelope, sha256 ${sha.slice(0, 16)}…`);
} else {
  sha = createHash("sha256").update(plaintext).digest("hex"); // dry run before members exist
  console.log("(dry run: no members yet, proving against the plaintext hash)");
}

const outRel = join("build", `${rollupId}-b${batchIndex}`);
const out = join(circuits, outRel);
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "batch.json"), JSON.stringify(batch, null, 2));
execFileSync("go", ["run", "./cmd/ledger", "prove", "-dir", setupRel, "-batch", join(outRel, "batch.json"), "-data", sha, "-out", outRel],
  { cwd: circuits, stdio: ["ignore", "inherit", "inherit"] });
const result = JSON.parse(readFileSync(join(out, "result.json"), "utf8")) as {
  state_root: string; withdrawals_root: string; withdrawals: { recipient: string; amount: number }[];
  txs: { applied: boolean[]; skipped?: string[] }[]; tx_count: number;
};
result.txs.forEach((t, i) => console.log(`  tx ${i}: applied ${JSON.stringify(t.applied)}${t.skipped ? ` skipped ${t.skipped.join("; ")}` : ""}`));

// The chain's own withdrawals tree must give the same root as the circuit.
const withdrawals = (result.withdrawals ?? []).map((w) => ({ recipient: w.recipient, denom: "uqor", amount: String(w.amount) }));
const tree = withdrawals.length ? withdrawalsTree(withdrawals, { rollupId, version: "v2", chainId: CHAIN_ID }) : undefined;
if ((tree ? hex(tree.root) : "") !== result.withdrawals_root) throw new Error("RDK withdrawals root differs from the circuit's");

const inputs = {
  prevStateRoot: batchIndex === 0 ? undefined : be32(state.root),
  stateRoot: be32(result.state_root), dataHash: Buffer.from(sha, "hex"), withdrawalsRoot: tree?.root,
};
const errs = zkPublicInputErrors(inputs, { dataHashBound: true });
if (errs.length) throw new Error(`public inputs: ${errs.join("; ")}`);
console.log(`batch ${batchIndex}: state_root ${result.state_root.slice(0, 16)}…, ${withdrawals.length} withdrawal(s)`);
if (!SEND) { console.log("dry run: proof built and verified locally. --send posts and submits."); process.exit(0); }
if (!envelope) throw new Error("members are not set; rerun");

// Post the sealed batch.
const post = await tx.postRollupData({ rollupId, data: envelope });
if (post.code !== 0) throw new Error(`post failed: ${post.rawLog}`);
const inbox = await rdk.rest.getInbox(rollupId);
const posted = await rdk.rest.getPostedData(rollupId, inbox.headSequence);
if (posted.dataHash.toLowerCase() !== sha) throw new Error("chain post hash differs from the envelope");
console.log(`posted: ${post.transactionHash} (seq ${inbox.headSequence})`);
proofLine(`${rollupId} batch ${batchIndex}: sealed batch input posted (${envelope.length}-byte ML-KEM-1024 envelope, members only)`, `\`${post.transactionHash}\``);

const proofs = { raw: readFileSync(join(out, "proof.raw.bin")), compressed: readFileSync(join(out, "proof.compressed.bin")) };
const base = { sequencer: memberAddrs[0]!, rollupId, batchIndex, txCount: result.tx_count, ...inputs };
for (const [enc, proof] of Object.entries(proofs)) {
  const gas = await tx.simulate([submitBatchMsg({ ...base, proof })]);
  console.log(`  simulate ${enc}: ok, gas ≈ ${gas}`);
}
try {
  const bad = Buffer.from(inputs.stateRoot); bad[31] = bad[31]! ^ 1;
  await tx.simulate([submitBatchMsg({ ...base, stateRoot: bad, proof: proofs.raw })]);
  throw new Error("tampered state_root accepted");
} catch (e) {
  if (e instanceof Error && e.message === "tampered state_root accepted") throw e;
  console.log("  simulate tampered state_root: refused (as expected)");
}

const res = await tx.submitBatch({ rollupId, batchIndex, txCount: result.tx_count, ...inputs, proof: proofs.raw }, { anchor: "require" });
if (res.code !== 0) throw new Error(`submitBatch failed (code ${res.code}): ${res.rawLog}`);
const settled = await rdk.rest.getBatch(rollupId, batchIndex);
console.log(`submitted batch ${batchIndex}: ${res.transactionHash}, status ${settled.status}`);
copyFileSync(join(out, "next-state.json"), join(setupDir, "state.json"));
proofLine(
  `${rollupId} batch ${batchIndex} (${step}): **circuit v1** Groth16 proof verified on chain (Poseidon2 account tree, ${result.tx_count} frame txs, ${withdrawals.length} withdrawal(s) with the SHAKE-256 root computed in-circuit); status ${settled.status}`,
  `\`${res.transactionHash}\``,
);

if (tree) {
  if (settled.status !== "finalized") throw new Error("batch not finalized: cannot withdraw yet");
  for (let i = 0; i < withdrawals.length; i++) {
    const w = withdrawals[i]!;
    const before = BigInt(await rdk.rest.getBalance(w.recipient, "uqor"));
    const x = await tx.executeWithdrawal(buildExecuteWithdrawalInput({
      submitter: memberAddrs[0]!, rollupId, batchIndex, ...w, withdrawal: tree.proof(i),
    }));
    if (x.code !== 0) throw new Error(`executeWithdrawal ${i} failed: ${x.rawLog}`);
    const after = BigInt(await rdk.rest.getBalance(w.recipient, "uqor"));
    if (after - before !== BigInt(w.amount)) throw new Error(`withdrawal ${i}: balance moved by ${after - before}`);
    console.log(`  withdrawal ${i}: ${formatQor(w.amount)} -> ${w.recipient} paid (${x.transactionHash})`);
    proofLine(`${rollupId} batch ${batchIndex}: withdrawal #${i} of ${formatQor(w.amount)} paid on L1 from a leaf proven inside circuit v1`, `\`${x.transactionHash}\``);
  }
}
if (!existsSync(join(setupDir, "state.json"))) throw new Error("state not saved");
