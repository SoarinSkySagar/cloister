/**
 *   pnpm watchtower --id cloister-dev-2 [--sign] [--explorer path] [--json path] [--from n]
 *   (older usage) pnpm --filter @cloister/watchtower start --id cloister-dev-2 [--state path/to/state.json] [--from 0] [--json out.json]
 * Checks every finalized batch of the rollup as a member (role "watchtower"). Exit 1 if any check fails.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  REPO_ROOT, pkCommit, addressFor, identity, allIdentities, decodeBundle, kemKeypairFor, loadEnv, testnetClient,
} from "@cloister/common";
import { openEnvelope } from "@qorechain/rdk";
import { normRoot, signVerdict, sortChecks, type Verdict } from "@cloister/receipts/verdict";
import { actionsOf, payerOf, sighash, type FrameTx } from "@cloister/common";
import { checkBatch, keyResolver, type BatchView } from "./check.ts";
import { postedBytes } from "./l1.ts";

const args = process.argv.slice(2);
const flag = (n: string) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
const rollupId = flag("--id") ?? "";
if (!/^cloister(-dev-\d+)?$/.test(rollupId)) throw new Error("--id cloister or cloister-dev-N is required");
const statePath = flag("--state") ?? join(REPO_ROOT, "circuits", "setup", rollupId, "state.json");

const rdk = testnetClient();
const env = loadEnv();
const member = (await addressFor("watchtower", env))!;
const kem = kemKeypairFor("watchtower", env);
if (!member || !kem) throw new Error("watchtower mnemonic / ML-KEM seed missing in .env");
const signer = args.includes("--sign") ? await identity(rdk, "watchtower", env) : undefined;
if (signer && signer.address !== member) throw new Error("watchtower identity differs from the member address");
const verdictFile = (i: number) => join(REPO_ROOT, "receipts", `${rollupId}-${i}.verdicts.json`);
/** Sign this batch's findings and merge the verdict into receipts/<rollup>-<batch>.verdicts.json (one entry per watchtower). */
function publishVerdict(i: number, bv: BatchView, findings: { check: string; ok: boolean }[]) {
  const legacy = findings.some((x) => x.check === "legacy");
  const v = signVerdict({
    version: 1, chainId: "qorechain-diana", rollupId, batchIndex: i, stateRoot: normRoot(bv.state_root), dataHash: normRoot(bv.data_hash),
    watchtower: member, result: findings.every((x) => x.ok) ? "pass" : "fail", scope: legacy ? "link-only" : "bundle",
    checks: sortChecks(findings.map((x) => ({ name: x.check, ok: x.ok }))), signedAt: Math.floor(Date.now() / 1000),
  }, signer!.secretKey);
  let all: Verdict[] = [];
  try { all = JSON.parse(readFileSync(verdictFile(i), "utf8")) as Verdict[]; } catch { /* first verdict for this batch */ }
  all = [...all.filter((x) => x.watchtower !== member), v].sort((a, b) => (a.watchtower < b.watchtower ? -1 : 1));
  writeFileSync(verdictFile(i), JSON.stringify(all, null, 2) + "\n");
}
const state = JSON.parse(readFileSync(statePath, "utf8")) as { batches: number; accounts: { index: number; pk_commit: string }[] };
const known = (await allIdentities(rdk, env)).map((i) => i.publicKey);

const inbox = await rdk.rest.getInbox(rollupId);
const posted = [];
for (let s = 1; s <= Number(inbox.headSequence); s++) posted.push(await rdk.rest.getPostedData(rollupId, s));

// Pass 1: decrypt everything to learn the keys of registered accounts.
const envelopes = new Map<string, Uint8Array>();
const allTxs = [];
for (const p of posted) {
  const bytes = await postedBytes(Number(p.height), Number(p.size), p.dataHash.toLowerCase());
  envelopes.set(p.dataHash.toLowerCase(), bytes);
  try {
    const plain = openEnvelope({ envelope: bytes, chainId: "qorechain-diana", rollupId, member, decapsulationKey: kem.secretKey });
    if (new TextDecoder().decode(plain.subarray(0, 18)) === "cloister/bundle/v1") allTxs.push(...decodeBundle(plain).txs);
  } catch { /* not for us, reported below */ }
}
const keyOf = keyResolver(known, state.accounts, allTxs);

const report: unknown[] = [];
const explorer: { batches: unknown[] } = { batches: [] };
const hexOf = (u: Uint8Array) => Buffer.from(u).toString("hex");
const txView = (t: FrameTx) => ({
  id: hexOf(sighash(t)), sender: t.sender === 0xffffffff ? "new" : t.sender, nonce: String(t.nonce), expiry_batch: String(t.expiryBatch),
  fee_asset: t.feeAsset, max_fee: String(t.maxFee), payer: payerOf(t),
  frames: t.frames.map((f) => ({ mode: ["", "VERIFY_SENDER", "VERIFY_PAYER", "ACTION"][f.mode], flags: f.flags, kind: f.kind, params: hexOf(f.params) })),
  actions: actionsOf(t).map((a) => a.kind === "register_key" ? { ...a, publicKey: undefined, pk_commit: pkCommit(a.publicKey) } : { ...a, amount: String((a as { amount: bigint }).amount) }),
  signers: t.sigs.map((x) => x.signer),
});
let bad = 0;
for (let i = Number(flag("--from") ?? 0); i < state.batches; i++) {
  const raw = await (await fetch(`https://api-testnet.qore.host/qorechain/rdk/v1/batch/${rollupId}/${i}`)).json() as { batch: BatchView };
  const bv = raw.batch;
  const env_ = envelopes.get(bv.data_hash.toLowerCase());
  if (!env_) { console.log(`batch ${i}: no posted data matches data_hash (${bv.status}), skipped (spike batch?)`); report.push({ batch: i, skipped: true }); continue; }
  const { findings, txs } = checkBatch({ rollupId, batch: bv, envelope: env_, member, decapsulationKey: kem.secretKey, keyOf });
  const ok = findings.every((x) => x.ok);
  if (!ok) bad++;
  console.log(`batch ${i} [${bv.status}] ${ok ? "OK" : "FAIL"}  ` + findings.map((x) => `${x.ok ? "✓" : "✗"}${x.check}`).join(" "));
  for (const x of findings.filter((y) => !y.ok)) console.log(`    ${x.check}: ${x.detail}`);
  if (signer) publishVerdict(i, bv, findings);
  report.push({ batch: i, status: bv.status, ok, findings });
  explorer.batches.push({ ...bv, findings, ok, txs: txs.map(txView) });
}
const names = new Map((await allIdentities(rdk, env)).map((x) => [x.pkCommit, x.name]));
const ex = flag("--explorer");
if (ex) {
  const full = JSON.parse(readFileSync(statePath, "utf8")) as { root: string; accounts: Record<string, unknown>[] };
  const rollup = (await rdk.rest.getRollup(rollupId)) as unknown as Record<string, unknown>;
  writeFileSync(ex, JSON.stringify({
    rollup_id: rollupId, generated_at: new Date().toISOString(), state_root: full.root, rollup,
    accounts: full.accounts.map((a) => ({ ...a, name: names.get(a.pk_commit as string) ?? null })),
    batches: explorer.batches,
  }, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 1));
  console.log(`explorer data -> ${ex}`);
}
const out = flag("--json");
if (out) writeFileSync(out, JSON.stringify({ rollup_id: rollupId, checked_at: new Date().toISOString(), batches: report }, null, 2));
console.log(bad ? `${bad} batch(es) failed` : "all checked batches pass");
if (signer) console.log(`verdicts signed by ${member} -> receipts/${rollupId}-<batch>.verdicts.json`);
process.exit(bad ? 1 : 0);
