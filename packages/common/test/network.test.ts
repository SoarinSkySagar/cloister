import { test } from "node:test";
import assert from "node:assert/strict";
import { CHAIN_ID, FINAL_ROLLUP_ID, devRollupId, isValidRollupId, testnetClient } from "../src/index.ts";

test("rollup ids are valid for the chain", () => {
  assert.ok(isValidRollupId(FINAL_ROLLUP_ID));
  assert.ok(isValidRollupId(devRollupId(1)));
  assert.ok(isValidRollupId(devRollupId(42)));
  assert.ok(!isValidRollupId("Cloister"));
  assert.ok(!isValidRollupId("cl"));
  assert.throws(() => devRollupId(0));
});

test("testnet client resolves qorechain-diana", () => {
  assert.equal(testnetClient().network.chainId, CHAIN_ID);
});
