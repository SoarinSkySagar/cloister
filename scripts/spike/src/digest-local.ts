/**
 * Keyless end-to-end check of circuit v3's transaction digest and skip rule: real frame txs through the
 * TypeScript codec, the Go builder and circuit (`ledger simulate`: the witness must satisfy the circuit, no proof),
 * and the TypeScript digest and inclusion verifier. Needs only a setup directory's config.json.
 *
 *   pnpm --filter @cloister/spike exec tsx src/digest-local.ts [setup-dir]    (default circuits/setup/cloister-dev-5)
 *
 * Batch 0 onboards alice and bob and funds them. Batch 1 holds a swap whose second leg cannot apply (so both legs are
 * skipped and the fee is still charged) and an ordinary transfer. Each included tx's proof must carry the digest the
 * user computes from the transaction they signed, and must show the skipped legs as zero moves.
 */
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { ASSET, NEW_ACCOUNT, REPO_ROOT, buildFrameTx, nextFreeIndex, signFrameTx, structuralErrors, toLedgerTx, type BuildArgs, type FrameTx } from "@cloister/common";
import { txDigest } from "../../../packages/receipts/src/digest.ts";
import { proofStateRoot, toHex, type InclusionProof } from "../../../packages/receipts/src/inclusion.ts";

const setup = resolve(process.argv[2] ?? join(REPO_ROOT, "circuits", "setup", "cloister-dev-5"));
const config = JSON.parse(readFileSync(join(setup, "config.json"), "utf8")) as { rollup_id: string; chain_id: string };
const ids = { chainId: config.chain_id, rollupId: config.rollup_id };
const key = (n: number) => pqKeyFromSeed(new Uint8Array(32).fill(n));
const alice = key(11), bob = key(12);
const T = 0, RELAY = 1;
const must = (cond: unknown, msg: string) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } console.log(`  ok  ${msg}`); };

function signed(args: BuildArgs, secrets: Map<number, Uint8Array>): FrameTx {
  let tx = buildFrameTx(args);
  const errs = structuralErrors(tx, ids);
  if (errs.length) throw new Error(`structure: ${errs.join("; ")}`);
  for (const s of tx.sigs) if (secrets.has(s.signer)) tx = signFrameTx(tx, s.signer, secrets.get(s.signer)!);
  return tx;
}

const dir = mkdtempSync(join(tmpdir(), "digest-"));
copyFileSync(join(setup, "config.json"), join(dir, "config.json"));
function simulate(batch: unknown): any {
  const bp = join(dir, "batch.json"), out = join(dir, "out");
  writeFileSync(bp, JSON.stringify(batch));
  try {
    execFileSync("go", ["run", "./cmd/ledger", "simulate", "-dir", dir, "-batch", bp, "-data", "ab".repeat(32), "-out", out],
      { cwd: join(REPO_ROOT, "circuits"), stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 << 20 });
  } catch (e) { console.error(String((e as { stderr?: Buffer }).stderr ?? e)); process.exit(1); }
  copyFileSync(join(out, "next-state.json"), join(dir, "state.json"));
  return JSON.parse(readFileSync(join(out, "result.json"), "utf8"));
}

console.log("batch 0: onboarding and funding");
const used = [T, RELAY];
const b0: FrameTx[] = [
  signed({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: T, actions: [{ kind: "register_key", publicKey: alice.publicKey, atomic: false }] }, new Map([[NEW_ACCOUNT, alice.secretKey]])),
  signed({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: T, actions: [{ kind: "register_key", publicKey: bob.publicKey, atomic: false }] }, new Map([[NEW_ACCOUNT, bob.secretKey]])),
  signed({ ...ids, sender: T, nonce: 0n, expiryBatch: 50n, actions: [
    { kind: "transfer", to: 2, asset: ASSET.QOR, amount: 100_000_000n, atomic: false },
    { kind: "transfer", to: 3, asset: ASSET.QOR, amount: 50_000_000n, atomic: false }] }, new Map()),
  signed({ ...ids, sender: T, nonce: 1n, expiryBatch: 50n, actions: [{ kind: "transfer", to: 2, asset: ASSET.USD, amount: 1_000_000n, atomic: false }] }, new Map()),
];
const assign = b0.map((tx) => (tx.sender === NEW_ACCOUNT ? (() => { const i = nextFreeIndex(used); used.push(i); return i; })() : undefined));
const ledger0 = b0.map((tx, i) => toLedgerTx(tx, { relayer: RELAY, senderIndex: assign[i] }));
const r0 = simulate({ txs: ledger0 });
must(r0.tx_count === 4, "batch 0 settled 4 txs and the witness satisfies the circuit");
r0.inclusion.forEach((p: InclusionProof, k: number) => {
  must(p.version === 2 && p.record.digest !== undefined, `proof ${k}: a version 2 record carries a digest`);
  must(toHex(proofStateRoot(p)) === r0.state_root, `proof ${k}: reaches batch 0's state root`);
  must(toHex(txDigest(ids.chainId, ids.rollupId, b0[k]!.nonce, ledger0[k]!)) === p.record.digest, `proof ${k}: the digest is the digest of the signed transaction`);
});
must(ledger0[0]!.new_account === true && r0.inclusion[0].record.sender === 2, "a new account's digest carries the sentinel; its record shows the assigned index 2");

console.log("batch 1: a swap that cannot apply, and a transfer");
const swap = signed({ ...ids, sender: 2, nonce: 1n, expiryBatch: 50n, maxFee: 10_000n, payer: T, parties: [3], actions: [
  { kind: "transfer_from", from: 2, to: 3, asset: ASSET.USD, amount: 300_000n, atomic: true },
  { kind: "transfer_from", from: 3, to: 2, asset: ASSET.QOR, amount: 90_000_000_000n, atomic: true }] }, // bob has 50 QOR
  new Map([[2, alice.secretKey], [3, bob.secretKey]]));
const plain = signed({ ...ids, sender: 3, nonce: 1n, expiryBatch: 50n, maxFee: 5_000n, payer: 3, actions: [
  { kind: "transfer", to: 2, asset: ASSET.QOR, amount: 1_000_000n, atomic: false }] }, new Map([[3, bob.secretKey]]));
const b1 = [swap, plain], ledger1 = b1.map((tx) => toLedgerTx(tx, { relayer: RELAY }));
const r1 = simulate({ txs: ledger1 });
must(r1.txs[0].applied.every((a: boolean) => !a), "both legs of the swap were skipped (bob cannot fund his leg), and the circuit accepted that");
must(r1.txs[1].applied[0] === true, "the plain transfer applied");
const p1 = r1.inclusion as InclusionProof[];
p1.forEach((p, k) => {
  must(toHex(proofStateRoot(p)) === r1.state_root, `proof ${k}: reaches batch 1's state root`);
  must(toHex(txDigest(ids.chainId, ids.rollupId, b1[k]!.nonce, ledger1[k]!)) === p.record.digest, `proof ${k}: the digest is the digest of the signed transaction`);
});
must(p1[0]!.record.moves.slice(1).every((m) => m.code === 0), "the skipped legs are zero moves in the record");
must(p1[0]!.record.moves[0]!.code === 1 && p1[0]!.record.moves[0]!.amount === "10000", "the fee was still charged");

// a user holding a different transaction (one cent more in the first leg) does not match the record
const other = structuredClone(ledger1[0]!);
(other.actions[0] as { amount: number }).amount += 1;
must(toHex(txDigest(ids.chainId, ids.rollupId, swap.nonce, other)) !== p1[0]!.record.digest, "a transaction that differs in any amount does not match the record's digest");
// the skipped legs are bound too: dropping them from the user's copy does not match either
const dropped = structuredClone(ledger1[0]!); dropped.actions = [];
must(toHex(txDigest(ids.chainId, ids.rollupId, swap.nonce, dropped)) !== p1[0]!.record.digest, "a transaction without the skipped legs does not match the record's digest");
console.log("\nall checks passed");
