import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { signVerdict, sortChecks, verdictMessage, verdictShapeErrors, verifyVerdict, type Unsigned, type Verdict } from "../src/verdict.ts";

const wt = pqKeyFromSeed(new Uint8Array(32).fill(7));
const other = pqKeyFromSeed(new Uint8Array(32).fill(8));
const ADDR = "qor1lyu0fnsxvxvwmhwnmuvrln9st4z70dap5mzkad";
const ROOT = "0cd96a4ecbbedde114e42533ffa2f1d394da5685e5a5f5bc38ce2d20091d4919";
const DATA = "42a7495eddf6a383154037c50d0429962e2ea56625e43bb851e69328a16c1255";
const base: Unsigned = {
  version: 1, chainId: "qorechain-diana", rollupId: "cloister-dev-2", batchIndex: 3, stateRoot: ROOT, dataHash: DATA,
  watchtower: ADDR, result: "pass", scope: "bundle", signedAt: 1_795_000_000,
  checks: sortChecks(["link", "decrypt", "index", "count", "structure", "signature"].map((name) => ({ name, ok: true }))),
};
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** A fake chain: the rollup's members, one batch, and the PQC registry. */
const chain = (over: { members?: string[]; stateRoot?: string; dataHash?: string; key?: Uint8Array; chainId?: string } = {}) => ({
  network: { chainId: over.chainId ?? "qorechain-diana" },
  rest: {
    getRollup: async () => ({ members: over.members ?? [ADDR, "qor16qg03qnndz6zzgz02ezda5agyrjwcyh4m3eh77"] }),
    getBatch: async () => ({ stateRoot: over.stateRoot ?? ROOT, dataHash: over.dataHash ?? DATA }),
    getPqcAccount: async () => ({ publicKey: hex(over.key ?? wt.publicKey) }),
  },
}) as never;

test("golden vector: the signed message is fixed", () => {
  const file = join(import.meta.dirname, "..", "..", "..", "spec", "vectors", "verdict.json");
  const got = [{ name: "all checks pass, bundle", input: base, expected: { message: hex(verdictMessage(base)) } },
    { name: "failed signature check", input: { ...base, result: "fail", checks: base.checks.map((c) => (c.name === "signature" ? { ...c, ok: false } : c)) },
      expected: { message: hex(verdictMessage({ ...base, result: "fail", checks: base.checks.map((c) => (c.name === "signature" ? { ...c, ok: false } : c)) })) } },
    { name: "link-only legacy batch", input: { ...base, batchIndex: 0, scope: "link-only", checks: sortChecks([{ name: "legacy", ok: true }, { name: "link", ok: true }]) },
      expected: { message: hex(verdictMessage({ ...base, batchIndex: 0, scope: "link-only", checks: sortChecks([{ name: "legacy", ok: true }, { name: "link", ok: true }]) })) } }];
  if (process.env.UPDATE_VECTORS || !existsSync(file)) writeFileSync(file, JSON.stringify(got, null, 2) + "\n");
  assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), JSON.parse(JSON.stringify(got)));
});

test("an honest verdict verifies against the chain", async () => {
  const v = signVerdict(base, wt.secretKey);
  assert.deepEqual(await verifyVerdict(v, chain()), { valid: true, result: "pass", problems: [] });
});

test("a signed 'fail' verdict is valid: it is a warning, never hidden", async () => {
  const failing = { ...base, result: "fail" as const, checks: base.checks.map((c) => (c.name === "signature" ? { ...c, ok: false } : c)) };
  const r = await verifyVerdict(signVerdict(failing, wt.secretKey), chain());
  assert.equal(r.valid, true);
  assert.equal(r.result, "fail");
});

test("changing any signed field after signing breaks the signature", async () => {
  const v = signVerdict(base, wt.secretKey);
  const variants: Partial<Verdict>[] = [
    { signedAt: v.signedAt + 1 }, { scope: "link-only" }, { result: "fail" }, { watchtower: "qor16qg03qnndz6zzgz02ezda5agyrjwcyh4m3eh77" },
    { checks: v.checks.map((c) => (c.name === "link" ? { ...c, ok: false } : c)) },
  ];
  for (const x of variants) {
    const t = { ...v, ...x } as Verdict;
    const r = await verifyVerdict(t, chain({ members: [t.watchtower, ADDR] }));
    assert.equal(r.valid, false, JSON.stringify(x));
  }
});

test("a verdict for other roots, batch, rollup or chain is refused", async () => {
  const v = signVerdict(base, wt.secretKey);
  assert.deepEqual((await verifyVerdict(v, chain({ stateRoot: "ee".repeat(32) }))).problems, ["state root differs from the chain's"]);
  assert.deepEqual((await verifyVerdict(v, chain({ dataHash: "ee".repeat(32) }))).problems, ["data hash differs from the chain's"]);
  assert.ok((await verifyVerdict(v, chain({ chainId: "qorechain-other" }))).problems[0]!.includes("chain qorechain-diana"));
});

test("a signer that is not a member is refused, even with a valid signature", async () => {
  const v = signVerdict(base, wt.secretKey);
  const r = await verifyVerdict(v, chain({ members: ["qor16qg03qnndz6zzgz02ezda5agyrjwcyh4m3eh77"] }));
  assert.deepEqual(r.problems, ["signer is not a current member of the rollup"]);
});

test("the key comes from the chain: a verdict signed by another key is refused", async () => {
  const v = signVerdict(base, other.secretKey);
  assert.deepEqual((await verifyVerdict(v, chain())).problems, ["bad signature"]);
});

test("shape rules: newline injection, unsorted or duplicate checks, pass with a failing check, bad roots", () => {
  const bad = (over: Partial<Unsigned>) => verdictShapeErrors({ ...base, ...over });
  assert.ok(bad({ watchtower: `${ADDR}\nresult=pass` }).length);
  assert.ok(bad({ checks: [{ name: "link", ok: true }, { name: "count", ok: true }] }).some((e) => e.includes("sorted")));
  assert.ok(bad({ checks: [{ name: "link", ok: true }, { name: "link", ok: true }] }).some((e) => e.includes("sorted")));
  assert.ok(bad({ checks: [{ name: "Link", ok: true }] }).some((e) => e.includes("[a-z]+")));
  assert.ok(bad({ checks: [{ name: "link", ok: false }] }).some((e) => e.includes("pass with a failing check")));
  assert.ok(bad({ stateRoot: "ABC" }).length && bad({ dataHash: DATA.toUpperCase() }).length);
  assert.ok(bad({ batchIndex: -1 }).length && bad({ version: 2 as 1 }).length && bad({ result: "maybe" as "pass" }).length);
  assert.deepEqual(bad({}), []);
  assert.throws(() => verdictMessage({ ...base, scope: "x" as "bundle" }), /invalid verdict/);
});
