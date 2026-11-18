import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { ASSET, NEW_ACCOUNT, REPO_ROOT, buildFrameTx, signFrameTx, type FrameTx } from "@cloister/common";
import { Replayer, reexecutionFinding, type ReplayOutcome } from "../src/replay.ts";

// One setup directory (just a config.json) and one built binary shared by the tests: replay needs `go`, no keys, no chain.
let dir: string, bin: string, setup: string;
const ids = { chainId: "qorechain-diana", rollupId: "cloister-replay" };
const config = { depth: 16, txs: 4, moves: 4, withdrawals: 4, parties: 3, relayer: 1, chain_id: ids.chainId, rollup_id: ids.rollupId,
  genesis: [{ index: 0, pk_commit: "01", qor: 9_900_000_000, usd: 1_000_000_000_000 }, { index: 1, pk_commit: "02" }] };

before(() => {
  dir = mkdtempSync(join(tmpdir(), "replay-test-"));
  setup = join(dir, "setup");
  mkdirSync(setup);
  writeFileSync(join(setup, "config.json"), JSON.stringify(config));
  bin = join(dir, "ledger");
  execFileSync("go", ["build", "-o", bin, "./cmd/ledger"], { cwd: join(REPO_ROOT, "circuits"), stdio: "pipe" });
});
after(() => rmSync(dir, { recursive: true, force: true }));

const key = (n: number) => pqKeyFromSeed(new Uint8Array(32).fill(n));
const alice = key(11), bob = key(12);
const sign = (tx: FrameTx, who: [number, Uint8Array][]) => who.reduce((t, [i, sk]) => signFrameTx(t, i, sk), tx);

const batch0 = (): FrameTx[] => [
  sign(buildFrameTx({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: 0, actions: [{ kind: "register_key", publicKey: alice.publicKey, atomic: false }] }), [[NEW_ACCOUNT, alice.secretKey]]),
  sign(buildFrameTx({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: 0, actions: [{ kind: "register_key", publicKey: bob.publicKey, atomic: false }] }), [[NEW_ACCOUNT, bob.secretKey]]),
  buildFrameTx({ ...ids, sender: 0, nonce: 0n, expiryBatch: 50n, actions: [
    { kind: "transfer", to: 2, asset: ASSET.QOR, amount: 100_000_000n, atomic: false }, { kind: "transfer", to: 3, asset: ASSET.QOR, amount: 50_000_000n, atomic: false }] }),
  buildFrameTx({ ...ids, sender: 0, nonce: 1n, expiryBatch: 50n, actions: [{ kind: "transfer", to: 2, asset: ASSET.USD, amount: 1_000_000n, atomic: false }] }),
];
const batch1 = (): FrameTx[] => [
  sign(buildFrameTx({ ...ids, sender: 2, nonce: 1n, expiryBatch: 50n, maxFee: 10_000n, payer: 0, parties: [3], actions: [
    { kind: "transfer_from", from: 2, to: 3, asset: ASSET.USD, amount: 300_000n, atomic: true },
    { kind: "transfer_from", from: 3, to: 2, asset: ASSET.QOR, amount: 400_000n, atomic: true }] }), [[2, alice.secretKey], [3, bob.secretKey]]),
  buildFrameTx({ ...ids, sender: 0, nonce: 2n, expiryBatch: 50n, actions: [{ kind: "transfer", to: 3, asset: ASSET.QOR, amount: 1_000_000n, atomic: false }] }),
];
const DH = "ab".repeat(32);
const replayAll = (b0: FrameTx[], b1: FrameTx[]) => {
  const r = new Replayer(setup, { binary: bin });
  const o0 = r.replay(0, b0, DH);
  if (o0.refused) throw new Error("batch 0 refused: " + o0.refused);
  const o1 = r.replay(1, b1, DH);
  return { r, o0, o1 };
};

test("replay is deterministic and reproduces the batch roots, applied flags and accounts", () => {
  const a = replayAll(batch0(), batch1()), b = replayAll(batch0(), batch1());
  assert.equal(a.o0.refused, undefined);
  assert.equal(a.o1.stateRoot, b.o1.stateRoot);
  assert.notEqual(a.o0.stateRoot, a.o1.stateRoot);
  assert.deepEqual(a.o1.applied, [[true, true], [true]]);
  const acct = (i: number) => a.r.accounts().find((x) => x.index === i)!;
  assert.equal(acct(2).usd, 1_000_000 - 300_000);
  assert.equal(acct(3).usd, 300_000);
  assert.equal(a.r.batch, 2);
});

test("a batch the chain accepted but the bundle does not produce is caught", () => {
  const honest = replayAll(batch0(), batch1()).o1;
  const chain = { state_root: honest.stateRoot, tx_count: "2" };
  assert.equal(reexecutionFinding(honest, chain).ok, true);

  const variants: Record<string, (b: FrameTx[]) => FrameTx[]> = {
    "a transaction left out": (b) => b.slice(1),
    "the order changed": (b) => [b[1]!, b[0]!],
    "an extra transaction": (b) => [...b, buildFrameTx({ ...ids, sender: 0, nonce: 3n, expiryBatch: 50n, actions: [{ kind: "transfer", to: 2, asset: ASSET.QOR, amount: 1n, atomic: false }] })],
    "a different amount": (b) => [b[0]!, buildFrameTx({ ...ids, sender: 0, nonce: 2n, expiryBatch: 50n, actions: [{ kind: "transfer", to: 3, asset: ASSET.QOR, amount: 1_000_001n, atomic: false }] })],
    "a different window": (b) => [b[0]!, buildFrameTx({ ...ids, sender: 0, nonce: 2n, expiryBatch: 49n, actions: [{ kind: "transfer", to: 3, asset: ASSET.QOR, amount: 1_000_000n, atomic: false }] })],
  };
  for (const [name, f] of Object.entries(variants)) {
    const o = replayAll(batch0(), f(batch1())).o1;
    assert.equal(reexecutionFinding(o, chain).ok, false, `${name}: the replay must differ from the chain's root`);
  }
});

test("a bundle the builder refuses is reported, and later batches cannot be replayed", () => {
  const r = new Replayer(setup, { binary: bin });
  const poor = [buildFrameTx({ ...ids, sender: 1, nonce: 0n, expiryBatch: 50n, maxFee: 5n, payer: 1, actions: [{ kind: "transfer", to: 0, asset: ASSET.QOR, amount: 1n, atomic: false }] })]; // the relayer holds nothing
  const o = r.replay(0, poor, DH);
  assert.match(o.refused ?? "", /fee/);
  assert.equal(reexecutionFinding(o, { state_root: "00".repeat(32), tx_count: "1" }).ok, false);
  assert.equal(r.batch, 0, "a refused batch does not advance the replay");
  assert.throws(() => r.replay(1, [], DH), /in order/);
});

test("the finding names a skipped action, and shows a mismatch clearly", () => {
  const o: ReplayOutcome = { stateRoot: "aa".repeat(32), txRoot: "", withdrawalsRoot: "", applied: [[false]], skipped: [["action 0: insufficient balance"]] };
  const ok = reexecutionFinding(o, { state_root: "0x" + "AA".repeat(32), tx_count: "1" });
  assert.equal(ok.ok, true);
  assert.match(ok.detail, /1 skipped action/);
  const bad = reexecutionFinding(o, { state_root: "bb".repeat(32), tx_count: "1" });
  assert.equal(bad.ok, false);
  assert.match(bad.detail, /not the execution of the sealed bundle/);
});
