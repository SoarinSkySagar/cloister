import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import {
  ASSET, MAX_ACTIONS, NEW_ACCOUNT, REPO_ROOT, buildFrameTx, decodeFrameTx, encodeFrameTx, encodeUnsigned, nextFreeIndex, notBeforeOf,
  partiesOf, pkCommit, sighash, signFrameTx, signatureErrors, signersOf, structuralErrors, toLedgerTx, type BuildArgs, type FrameTx,
} from "../src/index.ts";

const ids = { chainId: "qorechain-diana", rollupId: "cloister" };
const key = (n: number) => pqKeyFromSeed(new Uint8Array(32).fill(n));
const alice = key(1), sponsor = key(2), mallory = key(3), bob = key(4), carol = key(5);
const keys = new Map([[5, alice.publicKey], [0, sponsor.publicKey], [6, bob.publicKey], [7, carol.publicKey]]);
const secrets = new Map<number, Uint8Array>([[5, alice.secretKey], [NEW_ACCOUNT, alice.secretKey], [0, sponsor.secretKey], [6, bob.secretKey], [7, carol.secretKey]]);
const L1 = "qor12jmzemjntpkfr4ler3rdwpemrv3qg7pzxkpxkm";

const cases: Record<string, BuildArgs> = {
  "self-paid transfer": { ...ids, sender: 5, nonce: 3n, expiryBatch: 100n, maxFee: 10n, actions: [
    { kind: "transfer", to: 6, asset: ASSET.QOR, amount: 1_000n, atomic: false }] },
  "sponsored atomic withdraw+transfer": { ...ids, sender: 5, nonce: 4n, expiryBatch: 100n, maxFee: 10_000n, payer: 0, actions: [
    { kind: "withdraw", recipient: L1, amount: 5_000_000n, atomic: true },
    { kind: "transfer", to: 1, asset: ASSET.USD, amount: 7n, atomic: true }] },
  "new account, sponsored onboarding": { ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 100n, maxFee: 10_000n, payer: 0, actions: [
    { kind: "register_key", publicKey: alice.publicKey, atomic: false }] },
  "two-party atomic swap, sponsored": { ...ids, sender: 5, nonce: 7n, expiryBatch: 100n, maxFee: 10_000n, payer: 0, parties: [6], actions: [
    { kind: "transfer_from", from: 5, to: 6, asset: ASSET.USD, amount: 300n, atomic: true },
    { kind: "transfer_from", from: 6, to: 5, asset: ASSET.QOR, amount: 400n, atomic: true }] },
  "three parties, a party withdraws, time-locked": { ...ids, sender: 5, nonce: 8n, expiryBatch: 200n, maxFee: 10_000n, parties: [6, 7], notBefore: 50n, actions: [
    { kind: "transfer_from", from: 7, to: 5, asset: ASSET.QOR, amount: 11n, atomic: true },
    { kind: "withdraw_from", from: 6, recipient: L1, amount: 22n, atomic: true },
    { kind: "transfer", to: 7, asset: ASSET.USD, amount: 33n, atomic: true }] },
};

function signAll(tx: FrameTx): FrameTx {
  let t = tx;
  for (const s of tx.sigs) t = signFrameTx(t, s.signer, secrets.get(s.signer)!);
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
  assert.ok(errs({ ...ok, frames: [ok.frames[2]!, ...ok.frames.slice(0, 2), ok.frames[3]!] }).some((e) => e.includes("ordered")));
  assert.ok(errs({ ...ok, sigs: ok.sigs.slice(0, 1) }).some((e) => e.startsWith("signatures must be")));
  assert.ok(errs({ ...ok, sigs: [...ok.sigs].reverse() }).some((e) => e.startsWith("signatures must be")));
  const ok3 = buildFrameTx({ ...cases["self-paid transfer"]!, actions: Array(MAX_ACTIONS).fill(cases["self-paid transfer"]!.actions[0]) });
  assert.deepEqual(errs(ok3), []);
  const four = buildFrameTx({ ...cases["self-paid transfer"]!, actions: Array(MAX_ACTIONS + 1).fill(cases["self-paid transfer"]!.actions[0]) });
  assert.ok(errs(four).some((e) => e.includes(`at most ${MAX_ACTIONS} actions`)));
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
  // the circuit needs to know the signed sender was the sentinel, and the fee ceiling the payer signed
  assert.equal(t.new_account, true);
  assert.equal(t.max_fee, t.fee);
  assert.equal(toLedgerTx(signAll(swap()), { relayer: 1 }).new_account, undefined);
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
        notBefore: args.notBefore === undefined ? undefined : String(args.notBefore),
        actions: args.actions.map((a) => a.kind === "register_key" ? { ...a, publicKey: "ML-DSA-87 key from seed 0x01*32" }
          : { ...a, amount: String(a.amount) }),
        signers: "sender: pqKeyFromSeed(0x01*32), sponsor: pqKeyFromSeed(0x02*32), party 6: pqKeyFromSeed(0x04*32), party 7: pqKeyFromSeed(0x05*32)" },
      expected: {
        enc_unsigned: Buffer.from(encodeUnsigned(unsigned)).toString("hex"),
        sighash: Buffer.from(sighash(unsigned)).toString("hex"),
        signed_sha256: sha(encodeFrameTx(signed)),
        signed_length: encodeFrameTx(signed).length,
      },
    };
  });
  if (process.env.UPDATE_VECTORS || !existsSync(file)) writeFileSync(file, JSON.stringify(got, null, 2) + "\n");
  assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), JSON.parse(JSON.stringify(got)));
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

test("account queries: only a fresh signature by the key itself passes", async () => {
  const { signAccountQuery, verifyAccountQuery } = await import("../src/index.ts");
  const q = signAccountQuery("cloister", alice.publicKey, alice.secretKey, 1_000_000);
  assert.deepEqual(verifyAccountQuery(q, "cloister", 1_000_000), { pkCommit: pkCommit(alice.publicKey) });
  assert.ok("error" in verifyAccountQuery(q, "cloister-dev-2", 1_000_000));
  assert.ok("error" in verifyAccountQuery(q, "cloister", 1_000_000 + 10 * 60_000));
  const forged = { ...signAccountQuery("cloister", alice.publicKey, mallory.secretKey, 1_000_000) };
  assert.ok("error" in verifyAccountQuery(forged, "cloister", 1_000_000));
  assert.ok("error" in verifyAccountQuery({ ...q, ts: q.ts + 1 }, "cloister", 1_000_000));
});

// ---- multi-party frames (spec/frame-tx.md) ----

const swap = () => buildFrameTx(cases["two-party atomic swap, sponsored"]!);
const errs = (t: FrameTx) => structuralErrors(t, ids);
const withFrames = (t: FrameTx, f: (fr: FrameTx["frames"]) => FrameTx["frames"]) => ({ ...t, frames: f(t.frames) });

test("multi-party: parties, guard and signer order", () => {
  const t = swap();
  assert.deepEqual(partiesOf(t), [6]);
  assert.deepEqual(signersOf(t), [5, 6, 0], "sender, parties in frame order, then the sponsor");
  assert.deepEqual(t.sigs.map((s) => s.signer), [5, 6, 0]);
  const locked = buildFrameTx(cases["three parties, a party withdraws, time-locked"]!);
  assert.equal(notBeforeOf(locked), 50n);
  assert.deepEqual(signersOf(locked), [5, 6, 7], "a self-paid tx needs no extra payer signature");
  assert.equal(notBeforeOf(t), 0n);
  const back = decodeFrameTx(encodeFrameTx(signAll(locked)));
  assert.deepEqual(errs(back), []);
  assert.deepEqual(signatureErrors(back, (i) => keys.get(i)), []);
});

test("multi-party: a payer who is also a party signs once", () => {
  const t = buildFrameTx({ ...cases["two-party atomic swap, sponsored"]!, payer: 6 });
  assert.deepEqual(signersOf(t), [5, 6]);
  assert.deepEqual(errs(t), []);
});

test("multi-party: every signature must verify, and each signer is checked", () => {
  const signed = signAll(swap());
  assert.deepEqual(signatureErrors(signed, (i) => keys.get(i)), []);
  const byMallory = signFrameTx(swap(), 5, secrets.get(5)!);
  const missingBob = signFrameTx(byMallory, 0, secrets.get(0)!); // bob's slot left empty
  assert.deepEqual(signatureErrors(missingBob, (i) => keys.get(i)), ["bad signature by account 6"]);
  const forgedParty = signFrameTx(signFrameTx(signFrameTx(swap(), 5, secrets.get(5)!), 6, mallory.secretKey), 0, secrets.get(0)!);
  assert.deepEqual(signatureErrors(forgedParty, (i) => keys.get(i)), ["bad signature by account 6"]);
  // the sighash covers the parties and every leg: changing either invalidates the signatures
  const retargeted = { ...signed, frames: signed.frames.map((f) => (f.kind === 0x04 && f.params[3] === 5 ? { ...f, params: Uint8Array.from([...f.params.slice(0, 7), 9, ...f.params.slice(8)]) } : f)) };
  assert.notDeepEqual(sighash(retargeted), sighash(signed));
  assert.ok(signatureErrors(retargeted, (i) => keys.get(i)).length > 0);
});

test("multi-party: structural refusals", () => {
  const t = swap();
  // signatures: missing, wrong order
  assert.ok(errs({ ...t, sigs: t.sigs.slice(0, 2) }).some((e) => e.startsWith("signatures must be")));
  assert.ok(errs({ ...t, sigs: [t.sigs[1]!, t.sigs[0]!, t.sigs[2]!] }).some((e) => e.startsWith("signatures must be")));
  // a leg debiting an account that is neither the sender nor a party
  const stranger = buildFrameTx({ ...cases["two-party atomic swap, sponsored"]!, actions: [
    { kind: "transfer_from", from: 7, to: 5, asset: ASSET.QOR, amount: 1n, atomic: false }] });
  assert.ok(errs(stranger).some((e) => e.includes("neither the sender nor a party")));
  // parties: sender as a party, duplicates, too many, invalid index
  const bad = (parties: number[]) => errs(buildFrameTx({ ...cases["two-party atomic swap, sponsored"]!, parties }));
  assert.ok(bad([5]).some((e) => e.includes("cannot be the sender")));
  assert.ok(bad([6, 6]).some((e) => e.includes("distinct")));
  assert.ok(bad([6, 7, 8, 9]).some((e) => e.includes("at most 3 VERIFY_PARTY")));
  assert.ok(bad([65535]).some((e) => e.includes("not a valid account index")));
  // frame order and counts
  assert.ok(errs(withFrames(t, (f) => [f[1]!, f[0]!, ...f.slice(2)])).some((e) => e.includes("ordered")));
  assert.ok(errs(withFrames(t, (f) => [f[0]!, f[0]!, ...f.slice(1)])).some((e) => e.includes("exactly one VERIFY_SENDER")));
  assert.ok(errs(withFrames(t, (f) => [f[0]!, ...f.slice(1, 3), f[2]!, ...f.slice(3)])).some((e) => e.includes("at most one VERIFY_PAYER")));
  const two = buildFrameTx({ ...cases["three parties, a party withdraws, time-locked"]! });
  const guard = two.frames.find((f) => f.mode === 5)!;
  assert.ok(errs(withFrames(two, (f) => [...f.slice(0, 3), guard, ...f.slice(3)])).some((e) => e.includes("at most one GUARD")));
  assert.ok(errs(withFrames(two, (f) => f.map((x) => (x.mode === 5 ? { ...x, params: new Uint8Array(4) } : x)))).some((e) => e.includes("GUARD params")));
  // a new account cannot bring parties or *_from legs, and register_key stays sender-only (no register_from kind exists)
  const newAcct = buildFrameTx({ ...cases["new account, sponsored onboarding"]!, parties: [6] });
  assert.ok(errs(newAcct).some((e) => e.includes("no parties")));
  const newFrom = buildFrameTx({ ...cases["new account, sponsored onboarding"]!, actions: [
    { kind: "register_key", publicKey: alice.publicKey, atomic: false },
    { kind: "transfer_from", from: 0, to: 1, asset: 0, amount: 1n, atomic: false }] });
  assert.ok(errs(newFrom).some((e) => e.includes("cannot use transfer_from")));
});

test("multi-party: prover input carries parties, window and each leg's debited account", () => {
  const t = signAll(swap());
  const l = toLedgerTx(t, { relayer: 1 });
  assert.deepEqual(l.parties, [6]);
  assert.equal(l.expiry, 100);
  assert.equal(l.not_before, undefined);
  assert.deepEqual(l.actions.map((a) => (a.kind === "register_key" ? -1 : a.from)), [5, 6]);
  const locked = toLedgerTx(signAll(buildFrameTx(cases["three parties, a party withdraws, time-locked"]!)), { relayer: 1 });
  assert.equal(locked.not_before, 50);
  assert.deepEqual(locked.actions.map((a) => (a.kind === "register_key" ? -1 : a.from)), [7, 6, undefined]);
  // an "unbounded" window is capped, never lost to float rounding
  const forever = toLedgerTx(buildFrameTx({ ...cases["self-paid transfer"]!, expiryBatch: (1n << 64n) - 1n }), { relayer: 1 });
  assert.equal(forever.expiry, Number.MAX_SAFE_INTEGER);
});

test("account indexes never reach the reserved log leaf", () => {
  assert.equal(nextFreeIndex([0, 1, 2]), 3);
  assert.throws(() => nextFreeIndex([0, 65534]), /no free account index/);
  assert.equal(nextFreeIndex([0, 65535]), 1, "the reserved leaf is not an account");
  const noLog = buildFrameTx({ ...cases["self-paid transfer"]!, actions: [{ kind: "transfer", to: 65535, asset: 0, amount: 1n, atomic: false }] });
  assert.ok(errs(noLog).some((e) => e.includes("invalid account index")));
});

test("padded bundles: sizes fall in buckets, decode like unpadded ones, and padding cannot carry data", async () => {
  const { encodeBundle, decodeBundle, padBucket, BUNDLE_PAD_MAX } = await import("../src/index.ts");
  const all = Object.values(cases).map((a) => signAll(buildFrameTx(a)));
  const sizes = new Set<number>();
  for (const k of [0, 1, 2, all.length]) {
    const padded = encodeBundle(3, all.slice(0, k), { pad: true });
    sizes.add(padded.length);
    assert.equal(padded.length, padBucket(padded.length), "a padded bundle is exactly one bucket long");
    const back = decodeBundle(padded);
    assert.equal(back.batchIndex, 3);
    assert.deepEqual(back.txs.map(encodeFrameTx), all.slice(0, k).map(encodeFrameTx));
  }
  // two bundles of one transaction that differ in length by a few bytes (here: a longer rollup id) fall in the same bucket
  const base = cases["self-paid transfer"]!;
  const t1 = signAll(buildFrameTx({ ...base })), t2 = signAll(buildFrameTx({ ...base, rollupId: base.rollupId + "-x" }));
  assert.notEqual(encodeBundle(3, [t1]).length, encodeBundle(3, [t2]).length, "setup: the unpadded sizes differ");
  const a = encodeBundle(3, [t1], { pad: true }), b = encodeBundle(3, [t2], { pad: true });
  assert.equal(a.length, b.length, "the padded sizes are equal");
  assert.ok(encodeBundle(3, [t1]).length < a.length, "unpadded is shorter, so padding really hides the size");
  // fixed size: nothing at all is revealed by the length
  const f0 = encodeBundle(3, [], { fixed: BUNDLE_PAD_MAX }), f3 = encodeBundle(3, all, { fixed: BUNDLE_PAD_MAX });
  assert.equal(f0.length, BUNDLE_PAD_MAX);
  assert.equal(f3.length, BUNDLE_PAD_MAX);
  assert.equal(decodeBundle(f3).txs.length, all.length);
  assert.throws(() => encodeBundle(3, all, { fixed: 100 }), /does not fit/);
  // a bundle that was never padded still decodes (every batch of the dev rollups so far)
  assert.equal(decodeBundle(encodeBundle(5, all.slice(0, 1))).txs.length, 1);
  // padding must be zero: a non-zero byte could carry a covert message
  const dirty = encodeBundle(3, all.slice(0, 1), { pad: true });
  dirty[dirty.length - 1] = 1;
  assert.throws(() => decodeBundle(dirty), /padding must be zero/);
  // a padding length that does not match what follows is refused
  const lying = encodeBundle(3, all.slice(0, 1), { pad: true });
  const at = encodeBundle(3, all.slice(0, 1)).length;
  new DataView(lying.buffer).setUint32(at, 10);
  assert.throws(() => decodeBundle(lying), /trailing bytes/);
  assert.ok(padBucket(1) === 4096 && padBucket(4097) === 8192 && BUNDLE_PAD_MAX === 131072);
  assert.ok(sizes.size >= 1);
});
