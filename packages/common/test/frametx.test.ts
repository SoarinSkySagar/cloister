import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import {
  ASSET, NEW_ACCOUNT, REPO_ROOT, buildFrameTx, decodeFrameTx, encodeFrameTx, encodeUnsigned, pkCommit, sighash,
  signFrameTx, signatureErrors, structuralErrors, toLedgerTx, type BuildArgs, type FrameTx,
} from "../src/index.ts";

const ids = { chainId: "qorechain-diana", rollupId: "cloister" };
const key = (n: number) => pqKeyFromSeed(new Uint8Array(32).fill(n));
const alice = key(1), sponsor = key(2), mallory = key(3);
const keys = new Map([[5, alice.publicKey], [0, sponsor.publicKey]]);
const L1 = "qor12jmzemjntpkfr4ler3rdwpemrv3qg7pzxkpxkm";

const cases: Record<string, BuildArgs> = {
  "self-paid transfer": { ...ids, sender: 5, nonce: 3n, expiryBatch: 100n, maxFee: 10n, actions: [
    { kind: "transfer", to: 6, asset: ASSET.QOR, amount: 1_000n, atomic: false }] },
  "sponsored atomic withdraw+transfer": { ...ids, sender: 5, nonce: 4n, expiryBatch: 100n, maxFee: 10_000n, payer: 0, actions: [
    { kind: "withdraw", recipient: L1, amount: 5_000_000n, atomic: true },
    { kind: "transfer", to: 1, asset: ASSET.USD, amount: 7n, atomic: true }] },
  "new account, sponsored onboarding": { ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 100n, maxFee: 10_000n, payer: 0, actions: [
    { kind: "register_key", publicKey: alice.publicKey, atomic: false }] },
};

function signAll(tx: FrameTx): FrameTx {
  let t = signFrameTx(tx, tx.sender, alice.secretKey);
  if (t.sigs.length > 1) t = signFrameTx(t, t.sigs[1]!.signer, sponsor.secretKey);
  return t;
}

test("encode/decode round trip and sighash ignores signatures", () => {
  for (const [name, args] of Object.entries(cases)) {
    const unsigned = buildFrameTx(args);
    const signed = signAll(unsigned);
    const back = decodeFrameTx(encodeFrameTx(signed));
    assert.deepEqual(encodeFrameTx(back), encodeFrameTx(signed), name);
    assert.deepEqual(sighash(unsigned), sighash(signed), `${name}: sighash must not depend on signature bytes`);
    assert.deepEqual(structuralErrors(back, ids), [], name);
    assert.deepEqual(signatureErrors(back, (i) => keys.get(i)), [], name);
  }
});

test("sighash commits to every field", () => {
  const base = buildFrameTx(cases["sponsored atomic withdraw+transfer"]!);
  const h = Buffer.from(sighash(base)).toString("hex");
  const variants: FrameTx[] = [
    { ...base, nonce: base.nonce + 1n },
    { ...base, maxFee: base.maxFee + 1n },
    { ...base, expiryBatch: 99n },
    { ...base, rollupId: "cloister-dev-2" },
    { ...base, sigs: base.sigs.slice(0, 1) },
    buildFrameTx({ ...cases["sponsored atomic withdraw+transfer"]!, payer: 1 }),
    buildFrameTx({ ...cases["sponsored atomic withdraw+transfer"]!, actions: [
      { kind: "withdraw", recipient: L1, amount: 5_000_001n, atomic: true },
      { kind: "transfer", to: 1, asset: ASSET.USD, amount: 7n, atomic: true }] }),
  ];
  for (const v of variants) assert.notEqual(Buffer.from(sighash(v)).toString("hex"), h);
});

test("signatures: tampering, wrong key and missing sponsor are refused", () => {
  const signed = signAll(buildFrameTx(cases["sponsored atomic withdraw+transfer"]!));
  const tampered = { ...signed, maxFee: signed.maxFee + 1n };
  assert.equal(signatureErrors(tampered, (i) => keys.get(i)).length, 2);
  const byMallory = signFrameTx(buildFrameTx(cases["self-paid transfer"]!), 5, mallory.secretKey);
  assert.deepEqual(signatureErrors(byMallory, (i) => keys.get(i)), ["bad signature by account 5"]);
  const senderOnly = signFrameTx(buildFrameTx(cases["sponsored atomic withdraw+transfer"]!), 5, alice.secretKey);
  assert.deepEqual(signatureErrors(senderOnly, (i) => keys.get(i)), ["bad signature by account 0"]);
});

test("structural rules", () => {
  const ok = buildFrameTx(cases["sponsored atomic withdraw+transfer"]!);
  const errs = (t: FrameTx) => structuralErrors(t, ids);
  assert.ok(errs({ ...ok, chainId: "x" }).includes("chain_id mismatch"));
  assert.ok(errs({ ...ok, frames: ok.frames.slice(1) }).some((e) => e.includes("VERIFY_SENDER")));
  assert.ok(errs({ ...ok, frames: [ok.frames[2]!, ...ok.frames.slice(0, 2), ok.frames[3]!] }).some((e) => e.includes("before ACTION")));
  assert.ok(errs({ ...ok, sigs: ok.sigs.slice(0, 1) }).some((e) => e.startsWith("signatures must be")));
  assert.ok(errs({ ...ok, sigs: [...ok.sigs].reverse() }).some((e) => e.startsWith("signatures must be")));
  const three = buildFrameTx({ ...cases["self-paid transfer"]!, actions: Array(3).fill(cases["self-paid transfer"]!.actions[0]) });
  assert.ok(errs(three).some((e) => e.includes("at most 2 actions")));
  const badRecipient = buildFrameTx({ ...cases["self-paid transfer"]!, actions: [{ kind: "withdraw", recipient: "qor1short", amount: 1n, atomic: false }] });
  assert.ok(errs(badRecipient).some((e) => e.includes("42-character")));
  const newNoKey = buildFrameTx({ ...cases["self-paid transfer"]!, sender: NEW_ACCOUNT, nonce: 0n });
  assert.ok(errs(newNoKey).some((e) => e.includes("register_key")));
  assert.throws(() => decodeFrameTx(new Uint8Array([...encodeFrameTx(ok), 0])), /trailing/);
  assert.throws(() => decodeFrameTx(encodeFrameTx(ok).slice(0, 40)), /truncated/);
});

test("new account: verified with the key it registers; prover input gets the assigned index", () => {
  const tx = signAll(buildFrameTx(cases["new account, sponsored onboarding"]!));
  assert.deepEqual(signatureErrors(tx, (i) => keys.get(i)), []);
  const t = toLedgerTx(tx, { relayer: 1, senderIndex: 9 });
  assert.equal(t.sender, 9);
  assert.equal(t.payer, 0);
  assert.deepEqual(t.actions, [{ kind: "register_key", pk_commit: pkCommit(alice.publicKey), atomic: undefined }]);
});

// Golden vectors (spec/vectors/frame-tx.json). UPDATE_VECTORS=1 rewrites them.
test("golden vectors", () => {
  const file = join(REPO_ROOT, "spec", "vectors", "frame-tx.json");
  const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
  const got = Object.entries(cases).map(([name, args]) => {
    const unsigned = buildFrameTx(args);
    const signed = signAll(unsigned);
    return {
      name,
      input: { ...args, nonce: String(args.nonce), expiryBatch: String(args.expiryBatch), maxFee: String(args.maxFee ?? 0n),
        actions: args.actions.map((a) => a.kind === "register_key" ? { ...a, publicKey: "ML-DSA-87 key from seed 0x01*32" }
          : { ...a, amount: String(a.amount) }),
        signers: "sender: pqKeyFromSeed(0x01*32), sponsor: pqKeyFromSeed(0x02*32)" },
      expected: {
        enc_unsigned: Buffer.from(encodeUnsigned(unsigned)).toString("hex"),
        sighash: Buffer.from(sighash(unsigned)).toString("hex"),
        signed_sha256: sha(encodeFrameTx(signed)),
        signed_length: encodeFrameTx(signed).length,
      },
    };
  });
  if (process.env.UPDATE_VECTORS || !existsSync(file)) writeFileSync(file, JSON.stringify(got, null, 2) + "\n");
  assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), got);
});

test("bundle round trip", async () => {
  const { encodeBundle, decodeBundle, nextFreeIndex } = await import("../src/index.ts");
  const txs = Object.values(cases).map((a) => signAll(buildFrameTx(a)));
  const back = decodeBundle(encodeBundle(7, txs));
  assert.equal(back.batchIndex, 7);
  assert.deepEqual(back.txs.map(encodeFrameTx), txs.map(encodeFrameTx));
  assert.throws(() => decodeBundle(new TextEncoder().encode("nope")), /bundle|truncated/);
  assert.equal(nextFreeIndex([0, 1, 2]), 3);
  assert.equal(nextFreeIndex([]), 0);
});
