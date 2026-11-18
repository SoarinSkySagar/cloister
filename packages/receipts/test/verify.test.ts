import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseReceipt } from "../src/verify.ts";
import { allowedChainPath, allowedRpcPath } from "../src/proxy.ts";

const real = readFileSync(join(import.meta.dirname, "..", "..", "..", "receipts", "cloister-dev-2-9.json"), "utf8");

test("a published receipt parses", () => {
  const p = parseReceipt(real);
  assert.ok("receipt" in p && p.receipt.batchIndex === 9);
});
test("junk is refused before any chain call", () => {
  for (const bad of ["", "nope", "[]", "null", "{}", '{"rollupId":"x"}']) assert.ok("error" in parseReceipt(bad), bad);
});
test("a receipt with a missing field or unknown version is refused", () => {
  const r = JSON.parse(real);
  const { pqcSignature, ...noSig } = r;
  void pqcSignature;
  assert.ok("error" in parseReceipt(JSON.stringify(noSig)));
  assert.ok("error" in parseReceipt(JSON.stringify({ ...r, version: 99 })));
  assert.ok("error" in parseReceipt(JSON.stringify({ ...r, algorithm: "ML-DSA-44" })));
});
test("proxy allow-list: read-only chain paths only", () => {
  assert.ok(allowedChainPath("/qorechain/rdk/v1/batch/cloister-dev-2/3"));
  assert.ok(allowedChainPath("/cosmos/bank/v1beta1/balances/qor1abc"));
  for (const bad of ["/", "/auth/x", "/qorechain/../etc", "/qorechain/%2e%2e/x", "//qorechain/x", "/qorechain/a b", "/admin"]) assert.ok(!allowedChainPath(bad), bad);
  assert.ok(allowedRpcPath("/status"));
  assert.ok(!allowedRpcPath("/broadcast_tx_sync") && !allowedRpcPath("/status/x"));
});
