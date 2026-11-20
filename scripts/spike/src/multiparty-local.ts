/**
 * Local end-to-end check of circuit v2 (no chain): real frame txs through the TypeScript codec, the Go prover with
 * a real Groth16 proof, and the TypeScript inclusion verifier.
 *
 *   pnpm --filter @cloister/spike exec tsx src/multiparty-local.ts [setup-dir]    (default circuits/setup/cloister-dev-4)
 *
 * Needs a v2 setup (`go run ./cmd/ledger setup -dir setup/cloister-dev-4` in circuits/, several GB of RAM).
 * Batch 0 onboards alice and bob and funds them; batch 1 runs a two-party atomic swap and a time-locked tx.
 * Every inclusion proof must reach the batch's state_root, and a tx outside its window must be refused.
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import {
  ASSET, NEW_ACCOUNT, REPO_ROOT, buildFrameTx, nextFreeIndex, signFrameTx, signatureErrors, structuralErrors, toLedgerTx,
  type BuildArgs, type FrameTx,
} from "@cloister/common";
import { proofStateRoot, toHex, type InclusionProof } from "../../../packages/receipts/src/inclusion.ts";

const setup = resolve(process.argv[2] ?? join(REPO_ROOT, "circuits", "setup", "cloister-dev-4"));
const config = JSON.parse(readFileSync(join(setup, "config.json"), "utf8")) as { rollup_id: string; chain_id: string };
const ids = { chainId: config.chain_id, rollupId: config.rollup_id };
const key = (n: number) => pqKeyFromSeed(new Uint8Array(32).fill(n));
const alice = key(11), bob = key(12);
const T = 0, RELAY = 1; // treasury and relayer: genesis accounts (their signatures are not the point here)

const must = (cond: unknown, msg: string) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } console.log(`  ok  ${msg}`); };

function signed(args: BuildArgs, secrets: Map<number, Uint8Array>): FrameTx {
  let tx = buildFrameTx(args);
  const errs = structuralErrors(tx, ids);
  if (errs.length) throw new Error(`structure: ${errs.join("; ")}`);
  for (const s of tx.sigs) if (secrets.has(s.signer)) tx = signFrameTx(tx, s.signer, secrets.get(s.signer)!);
  return tx;
}

/** Run the Go prover on `state` (a state.json) and return its result. Uses symlinks so the 3 GB setup is not copied. */
function prove(stateJson: string, batch: unknown, label: string): { ok: true; out: string; result: any } | { ok: false; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "mp-"));
  for (const f of ["config.json", "ccs.bin", "pk.bin", "vk.raw.bin"]) symlinkSync(join(setup, f), join(dir, f));
  copyFileSync(stateJson, join(dir, "state.json"));
  const batchPath = join(dir, "batch.json");
  writeFileSync(batchPath, JSON.stringify(batch));
  const out = join(dir, "out");
  try {
    execFileSync("go", ["run", "./cmd/ledger", "prove", "-dir", dir, "-batch", batchPath, "-data", "ab".repeat(32), "-out", out],
      { cwd: join(REPO_ROOT, "circuits"), stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 << 20 });
  } catch (e) {
    return { ok: false, stderr: String((e as { stderr?: Buffer }).stderr ?? e) };
  }
  console.log(`  proved ${label}`);
  return { ok: true, out, result: JSON.parse(readFileSync(join(out, "result.json"), "utf8")) };
}

if (!existsSync(join(setup, "pk.bin"))) throw new Error(`no setup in ${setup}: run the ledger setup first`);

// ---- batch 0: onboard alice and bob (sponsored by the treasury), then fund them ----
console.log("batch 0: onboarding and funding");
const used = [T, RELAY];
const b0: FrameTx[] = [
  signed({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: T,
    actions: [{ kind: "register_key", publicKey: alice.publicKey, atomic: false }] }, new Map([[NEW_ACCOUNT, alice.secretKey]])),
  signed({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: T,
    actions: [{ kind: "register_key", publicKey: bob.publicKey, atomic: false }] }, new Map([[NEW_ACCOUNT, bob.secretKey]])),
  signed({ ...ids, sender: T, nonce: 0n, expiryBatch: 50n, actions: [
    { kind: "transfer", to: 2, asset: ASSET.QOR, amount: 100_000_000n, atomic: false },
    { kind: "transfer", to: 3, asset: ASSET.QOR, amount: 50_000_000n, atomic: false }] }, new Map()),
  signed({ ...ids, sender: T, nonce: 1n, expiryBatch: 50n, actions: [
    { kind: "transfer", to: 2, asset: ASSET.USD, amount: 1_000_000n, atomic: false }] }, new Map()),
];
const assign = b0.map((tx) => (tx.sender === NEW_ACCOUNT ? (() => { const i = nextFreeIndex(used); used.push(i); return i; })() : undefined));
must(assign[0] === 2 && assign[1] === 3, "new accounts get indexes 2 and 3 in bundle order");
const r0 = prove(join(setup, "state.json"), { txs: b0.map((tx, i) => toLedgerTx(tx, { relayer: RELAY, senderIndex: assign[i] })) }, "batch 0");
if (!r0.ok) { console.error(r0.stderr); process.exit(1); }
must(r0.result.batch_index === 0 && r0.result.tx_count === 4, "batch 0 settled 4 txs");
must(r0.result.inclusion.length === 4, "one inclusion proof per included tx");
for (const p of r0.result.inclusion as InclusionProof[]) must(toHex(proofStateRoot(p)) === r0.result.state_root, `batch 0 slot ${p.txIndex}: the TypeScript verifier reaches the prover's state root`);

// ---- batch 1: a two-party atomic swap, sponsored, plus a time-locked tx ----
console.log("batch 1: two-party swap and a time lock");
const swap = signed({ ...ids, sender: 2, nonce: 1n, expiryBatch: 50n, maxFee: 10_000n, payer: T, parties: [3], actions: [
  { kind: "transfer_from", from: 2, to: 3, asset: ASSET.USD, amount: 300_000n, atomic: true },
  { kind: "transfer_from", from: 3, to: 2, asset: ASSET.QOR, amount: 400_000n, atomic: true }] },
  new Map([[2, alice.secretKey], [3, bob.secretKey]]));
const keys = new Map([[2, alice.publicKey], [3, bob.publicKey]]);
const sigErrs = signatureErrors(swap, (i) => keys.get(i)).filter((e) => !e.includes("account 0"));
must(sigErrs.length === 0, "alice and bob both signed the swap (the treasury's sponsor slot is left unsigned here)");
const locked = signed({ ...ids, sender: T, nonce: 2n, expiryBatch: 50n, notBefore: 1n, actions: [
  { kind: "transfer", to: 3, asset: ASSET.QOR, amount: 1_000_000n, atomic: false }] }, new Map());
const r1 = prove(join(r0.out, "next-state.json"), { txs: [swap, locked].map((tx) => toLedgerTx(tx, { relayer: RELAY })) }, "batch 1");
if (!r1.ok) { console.error(r1.stderr); process.exit(1); }
must(r1.result.batch_index === 1, "batch 1 is counted as batch 1 (the counter lives in the state)");
must(r1.result.txs[0].applied[0] && r1.result.txs[0].applied[1], "both legs of the swap applied");
const next = JSON.parse(readFileSync(join(r1.out, "next-state.json"), "utf8")) as { accounts: { index: number; qor: number; usd: number; nonce: number }[] };
const acct = (i: number) => next.accounts.find((a) => a.index === i)!;
must(acct(2).usd === 700_000 && acct(3).usd === 300_000, "alice paid 0.3 USD to bob");
must(acct(3).qor === 50_000_000 + 1_000_000 - 400_000 && acct(2).qor === 100_000_000 + 400_000, "bob paid alice 0.4 QOR; the treasury sent bob 1 QOR");
must(acct(3).nonce === 1 && acct(2).nonce === 2, "only the sender's nonce moved for the swap (bob's registration was nonce 0 -> 1)");
const proofs1 = r1.result.inclusion as InclusionProof[];
for (const p of proofs1) must(toHex(proofStateRoot(p)) === r1.result.state_root, `batch 1 slot ${p.txIndex}: proof reaches the state root`);
must(proofs1[0]!.record.parties.length === 1 && proofs1[0]!.record.parties[0] === 3, "the swap's proof shows bob as co-signer");
must(proofs1[0]!.batchIndex === 1, "the proof names batch 1");
for (const p of r0.result.inclusion as InclusionProof[]) must(toHex(proofStateRoot(p)) === r0.result.state_root && toHex(proofStateRoot(p)) !== r1.result.state_root, `a batch 0 proof still verifies against batch 0's own root`);
const moved = { ...proofs1[0]!, batchIndex: 0 };
must(toHex(proofStateRoot(moved)) !== r1.result.state_root, "a proof cannot be claimed for another batch number");

// ---- refusals from the real prover ----
console.log("refusals");
const early = signed({ ...ids, sender: T, nonce: 2n, expiryBatch: 50n, notBefore: 5n, actions: [
  { kind: "transfer", to: 3, asset: ASSET.QOR, amount: 1n, atomic: false }] }, new Map());
const bad = prove(join(r0.out, "next-state.json"), { txs: [toLedgerTx(early, { relayer: RELAY })] }, "x");
must(!bad.ok && /tx 0: window: not valid before batch 5/.test(bad.stderr), "a tx before its not_before is refused by the prover");
const stranger = signed({ ...ids, sender: 2, nonce: 1n, expiryBatch: 50n, actions: [
  { kind: "transfer", to: 2, asset: ASSET.QOR, amount: 1n, atomic: false }] }, new Map());
const hacked = toLedgerTx(stranger, { relayer: RELAY });
hacked.actions[0] = { kind: "transfer", from: 3, to: 2, asset: 0, amount: 1 }; // debit bob, who is not a party
const bad2 = prove(join(r0.out, "next-state.json"), { txs: [hacked] }, "y");
must(!bad2.ok && /auth: account 3 is not the sender or a party/.test(bad2.stderr), "a debit of a non-party is refused by the prover");

console.log("\nall checks passed");
mkdirSync(join(tmpdir(), "mp-done"), { recursive: true });
