import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { ASSET, NEW_ACCOUNT, buildFrameTx, encodeBundle, pkCommit, sighash, signFrameTx } from "@cloister/common";
import { Sequencer, feeFailure, txFailure, type InclusionProofJSON } from "../src/batcher.ts";

const ID = "cloister-dev-9";
const key = (n: number) => pqKeyFromSeed(new Uint8Array(32).fill(n));
const alice = key(1), op = key(2), carol = key(4);
const ROOT = "ab".repeat(32);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** A throwaway layout: <tmp>/circuits/setup/<id> (+ <tmp>/circuits/build) so recover() finds its files. */
function sandbox(state: object, latest?: { batchIndex: number; stateRoot: string }) {
  const root = mkdtempSync(join(tmpdir(), "seq-"));
  const dir = join(root, "circuits", "setup", ID);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "state.json"), JSON.stringify(state));
  const rdk = { rest: { getLatestBatch: async () => { if (!latest) throw new Error("404"); return latest; } } } as never;
  const seq = new Sequencer({ rollupId: ID, relayerIndex: 1, minFee: 10_000n, maxTxs: 4, proofLog: false, setupDir: dir }, rdk, {} as never, "qor1op");
  return { root, dir, seq };
}
const acct = (index: number, pk: Uint8Array, nonce = 0) => ({ index, pk_commit: pkCommit(pk), qor: 1_000_000_000, usd: 0, nonce });
const register = (who: typeof alice, sponsor = 0) => signFrameTx(signFrameTx(buildFrameTx({
  chainId: "qorechain-diana", rollupId: ID, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 99n, maxFee: 10_000n, payer: sponsor,
  actions: [{ kind: "register_key", publicKey: who.publicKey, atomic: false }] }), NEW_ACCOUNT, who.secretKey), sponsor, op.secretKey);
const transfer = (nonce: bigint) => signFrameTx(buildFrameTx({
  chainId: "qorechain-diana", rollupId: ID, sender: 5, nonce, expiryBatch: 99n, maxFee: 10_000n,
  actions: [{ kind: "transfer", to: 6, asset: ASSET.QOR, amount: 1n, atomic: false }] }), 5, alice.secretKey);

test("feeFailure reads the prover's message", () => {
  assert.deepEqual(feeFailure("exit 1\ntx 2: fee: payer 4 cannot pay 10000\n"), { index: 2, reason: "fee: payer 4 cannot pay 10000" });
  assert.equal(feeFailure("some other failure"), undefined);
});

// Regression: actionsOf() builds new objects on every call, and the key of a newly registered
// account was once looked up with indexOf(identity) -> -1, so it was never stored.
test("record(): the key of a newly registered account is stored, and a failed registration stores nothing", () => {
  const { seq } = sandbox({ batches: 3, root: ROOT, accounts: [acct(0, op.publicKey)] });
  const t = register(alice);
  seq.record([{ id: hex(sighash(t)), tx: t }], [4], [{ applied: [true] }], 3, "TX1");
  assert.deepEqual(seq.keystore.get(4), alice.publicKey);
  assert.equal(seq.statuses.get(hex(sighash(t)))?.status, "included");

  const t2 = register(carol);
  seq.record([{ id: hex(sighash(t2)), tx: t2 }], [5], [{ applied: [false], skipped: ["action 0: key already set"] }], 4, "TX2");
  assert.equal(seq.keystore.get(5), undefined);
});

test("restart: queued txs survive and are re-validated against the current state", () => {
  const state = { batches: 3, root: ROOT, accounts: [acct(0, op.publicKey), acct(5, alice.publicKey, 1), acct(6, carol.publicKey)] };
  const a = sandbox(state);
  a.seq.keystore.set(5, alice.publicKey); a.seq.keystore.set(0, op.publicKey);
  a.seq.submit(transfer(1n));
  a.seq.submit(transfer(2n));
  assert.equal(a.seq.queueLength(), 2);

  // Between the crash and the restart, account 5's nonce moved on to 2: the first tx is stale.
  writeFileSync(join(a.dir, "state.json"), JSON.stringify({ ...state, accounts: [state.accounts[0], acct(5, alice.publicKey, 2), state.accounts[2]] }));
  const b = new Sequencer({ rollupId: ID, relayerIndex: 1, minFee: 10_000n, maxTxs: 4, proofLog: false, setupDir: a.dir }, { rest: {} } as never, {} as never, "qor1op");
  const r = b.restore();
  assert.equal(r.requeued, 1);
  assert.equal(r.dropped.length, 1);
  assert.match(r.dropped[0]!, /nonce 1, expected 2/);
  assert.equal(b.queueLength(), 1);
});

function crashSandbox(chain: { batchIndex: number; stateRoot: string }, nextRoot = chain.stateRoot) {
  const sb = sandbox({ batches: 5, root: "cd".repeat(32), accounts: [acct(0, op.publicKey)] }, chain);
  const build = join(sb.root, "circuits", "build", `${ID}-b5`);
  mkdirSync(build, { recursive: true });
  writeFileSync(join(build, "next-state.json"), JSON.stringify({ batches: 6, root: nextRoot, accounts: [acct(0, op.publicKey), acct(4, alice.publicKey)] }));
  writeFileSync(join(build, "bundle.bin"), encodeBundle(5, [register(alice)]));
  return sb;
}

test("recover(): chain one batch ahead -> adopt the prover's next-state and relearn the registered key", async () => {
  const { seq, dir } = crashSandbox({ batchIndex: 5, stateRoot: ROOT }, ROOT);
  const msg = await seq.recover();
  assert.match(msg!, /adopted batch 5/);
  const s = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
  assert.equal(s.batches, 6);
  assert.deepEqual(seq.keystore.get(4), alice.publicKey);
});

test("recover(): refuses a next-state that does not match the chain's root", async () => {
  const { seq, dir } = crashSandbox({ batchIndex: 5, stateRoot: ROOT }, "ee".repeat(32));
  await assert.rejects(() => seq.recover(), /cannot recover/);
  assert.equal(JSON.parse(readFileSync(join(dir, "state.json"), "utf8")).batches, 5);
});

test("recover(): refuses when the chain is two or more batches ahead, does nothing when in sync", async () => {
  await assert.rejects(() => crashSandbox({ batchIndex: 6, stateRoot: ROOT }).seq.recover(), /cannot recover/);
  const sync = sandbox({ batches: 5, root: ROOT, accounts: [] }, { batchIndex: 4, stateRoot: ROOT });
  assert.equal(await sync.seq.recover(), undefined);
});

test("txFailure reads every refusal the prover reports, with or without an action index", () => {
  assert.deepEqual(txFailure("tx 1: window: not valid before batch 9 (this is batch 3)"), { index: 1, reason: "window: not valid before batch 9 (this is batch 3)" });
  assert.deepEqual(txFailure("execute: tx 0 action 2: auth: account 7 is not the sender or a party of this tx"), { index: 0, reason: "auth: account 7 is not the sender or a party of this tx" });
  assert.deepEqual(txFailure("tx 3: parties must be distinct, differ from the sender and be valid accounts"), { index: 3, reason: "parties must be distinct, differ from the sender and be valid accounts" });
  assert.equal(txFailure("tx 0: something unrelated"), undefined);
});

const bob = key(5);
const swapTx = (parties: number[], notBefore = 0n) => signFrameTx(signFrameTx(signFrameTx(buildFrameTx({
  chainId: "qorechain-diana", rollupId: ID, sender: 5, nonce: 0n, expiryBatch: 99n, maxFee: 10_000n, payer: 0, parties, notBefore,
  actions: [{ kind: "transfer_from", from: 5, to: 6, asset: ASSET.QOR, amount: 1n, atomic: false }] }), 5, alice.secretKey), 0, op.secretKey), 6, bob.secretKey);

test("a tx naming a party that is not an account is refused, and a known party is accepted", () => {
  const { seq } = sandbox({ batches: 3, root: ROOT, accounts: [acct(0, op.publicKey), acct(5, alice.publicKey), acct(6, bob.publicKey)] });
  seq.keystore.set(5, alice.publicKey); seq.keystore.set(0, op.publicKey); seq.keystore.set(6, bob.publicKey);
  assert.equal(typeof seq.submit(swapTx([6])), "string");
  const ghost = signFrameTx(signFrameTx(buildFrameTx({
    chainId: "qorechain-diana", rollupId: ID, sender: 5, nonce: 1n, expiryBatch: 99n, maxFee: 10_000n, parties: [9],
    actions: [{ kind: "transfer_from", from: 9, to: 6, asset: ASSET.QOR, amount: 1n, atomic: false }] }), 5, alice.secretKey), 9, bob.secretKey);
  assert.throws(() => seq.submit(ghost), /party #9 does not exist|no key for account 9/);
});

test("a time-locked tx waits in the queue and does not trigger a batch before its batch", async () => {
  const { seq } = sandbox({ batches: 3, root: ROOT, accounts: [acct(0, op.publicKey), acct(5, alice.publicKey), acct(6, bob.publicKey)] });
  seq.keystore.set(5, alice.publicKey); seq.keystore.set(0, op.publicKey); seq.keystore.set(6, bob.publicKey);
  seq.submit(swapTx([6], 5n)); // next batch is 3: not before 5
  assert.equal(seq.queueLength(), 1);
  assert.equal(await seq.runBatch(), undefined, "nothing is due, so no batch runs");
  assert.equal(seq.queueLength(), 1, "the tx stays queued");
});

const proofOf = (sender: number, parties: number[], payer = sender): InclusionProofJSON => ({
  version: 1, chainId: "qorechain-diana", rollupId: ID, batchIndex: 3, record: { sender, parties, moves: [{ from: payer }] }, txIndex: 0, txPath: [], logPath: [],
});

test("an inclusion proof is shown only to the accounts its record names", () => {
  const { seq } = sandbox({ batches: 4, root: ROOT, accounts: [acct(0, op.publicKey), acct(5, alice.publicKey), acct(6, bob.publicKey), acct(7, carol.publicKey)] });
  const id = "ab".repeat(32);
  seq.saveProofs(3, [id], [proofOf(5, [6], 0)]); // sponsored by account 0
  const who = (k: typeof alice) => seq.proofFor(id, pkCommit(k.publicKey));
  assert.equal((who(alice) as InclusionProofJSON).batchIndex, 3, "the sender");
  assert.equal((who(bob) as InclusionProofJSON).batchIndex, 3, "a listed party");
  assert.equal((who(op) as InclusionProofJSON).batchIndex, 3, "the sponsor who paid the fee");
  assert.deepEqual(who(carol), { error: "this tx does not name your account" });
  assert.deepEqual(who(key(9)), { error: "no account for this key" });
  assert.deepEqual(seq.proofFor("00".repeat(32), pkCommit(alice.publicKey)), { error: "no proof for that tx" });
  assert.deepEqual(seq.proofFor("not-an-id", pkCommit(alice.publicKey)), { error: "bad tx id" });
  assert.throws(() => seq.saveProofs(3, [id, id], [proofOf(5, [])]), /1 inclusion proofs for 2 txs/);
});
