import { test } from "node:test";
import assert from "node:assert/strict";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { ASSET, buildFrameTx, frameTxToHex, signFrameTx } from "@cloister/common";
import { Relayer } from "../src/relayer.ts";

const alice = pqKeyFromSeed(new Uint8Array(32).fill(1));
const cfg = { chainId: "qorechain-diana", rollupId: "cloister", upstream: "http://seq", minFee: 10_000n, maxTxBytes: 32_000, ratePerMinute: 3 };
const mk = (maxFee: bigint, rollupId = "cloister") => frameTxToHex(signFrameTx(buildFrameTx({
  chainId: "qorechain-diana", rollupId, sender: 5, nonce: 1n, expiryBatch: 100n, maxFee,
  actions: [{ kind: "transfer", to: 6, asset: ASSET.QOR, amount: 1n, atomic: false }] }), 5, alice.secretKey));
const upstream = (ok = true): typeof fetch => (async () => ({ ok, status: ok ? 200 : 400, json: async () => (ok ? { id: "abc" } : { error: "nonce" }) })) as never;
const why = async (p: Promise<unknown>) => { try { await p; return ""; } catch (e) { return (e as Error).message; } };

test("valid tx is forwarded", async () => {
  const r = new Relayer(cfg, upstream());
  assert.deepEqual(await r.relay(mk(10_000n)), { id: "abc" });
  assert.equal(r.stats.forwarded, 1);
});
test("refusals: fee floor, wrong rollup, garbage, sequencer error", async () => {
  const r = new Relayer({ ...cfg, ratePerMinute: 99 }, upstream());
  assert.match(await why(r.relay(mk(9_999n))), /^fee/);
  assert.match(await why(r.relay(mk(10_000n, "cloister-dev-2"))), /^structure/);
  assert.match(await why(r.relay("zz")), /^malformed/);
  assert.match(await why(r.relay("00ff")), /^malformed/);
  assert.match(await why(new Relayer({ ...cfg, maxTxBytes: 10 }, upstream()).relay(mk(10_000n))), /^too large/);
  assert.match(await why(new Relayer(cfg, upstream(false)).relay(mk(10_000n))), /^sequencer: nonce/);
  assert.equal(r.stats.forwarded, 0);
});
test("rate limit is per client and resets after a minute", async () => {
  const r = new Relayer(cfg, upstream());
  for (let i = 0; i < 3; i++) await r.relay(mk(10_000n), "a", 1000);
  assert.match(await why(r.relay(mk(10_000n), "a", 1001)), /^rate limit/);
  await r.relay(mk(10_000n), "b", 1001);
  await r.relay(mk(10_000n), "a", 62_000);
});
