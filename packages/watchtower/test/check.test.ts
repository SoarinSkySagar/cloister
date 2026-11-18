import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { kemKeypairFromSeed, sealEnvelope } from "@qorechain/rdk";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { ASSET, buildFrameTx, encodeBundle, signFrameTx } from "@cloister/common";
import { checkBatch } from "../src/check.ts";

const alice = pqKeyFromSeed(new Uint8Array(32).fill(1));
const mallory = pqKeyFromSeed(new Uint8Array(32).fill(3));
const kem = kemKeypairFromSeed(randomBytes(64));
const member = "qor1lyu0fnsxvxvwmhwnmuvrln9st4z70dap5mzkad";
const mk = (signer: typeof alice) => signFrameTx(buildFrameTx({ chainId: "qorechain-diana", rollupId: "cloister-dev-2", sender: 5, nonce: 1n,
  expiryBatch: 9n, maxFee: 10_000n, actions: [{ kind: "transfer", to: 6, asset: ASSET.QOR, amount: 1n, atomic: false }] }), 5, signer.secretKey);
const seal = (txs: ReturnType<typeof mk>[]) => sealEnvelope({ chainId: "qorechain-diana", rollupId: "cloister-dev-2", epoch: 1,
  recipients: [{ member, encapsulationKey: kem.publicKey }], plaintext: encodeBundle(7, txs) });
const run = (envelope: Uint8Array, over: Record<string, string> = {}) => checkBatch({
  rollupId: "cloister-dev-2", member, decapsulationKey: kem.secretKey, envelope, keyOf: (i) => (i === 5 ? alice.publicKey : undefined),
  batch: { batch_index: "7", tx_count: "1", status: "finalized", data_hash: createHash("sha256").update(envelope).digest("hex"), ...over },
}).findings.filter((f) => !f.ok).map((f) => f.check);

test("honest batch passes", () => assert.deepEqual(run(seal([mk(alice)])), []));
test("wrong data_hash fails link", () => assert.deepEqual(run(seal([mk(alice)]), { data_hash: "00".repeat(32) }), ["link"]));
test("wrong batch index and count fail", () => assert.deepEqual(run(seal([mk(alice)]), { batch_index: "8", tx_count: "2" }), ["index", "count"]));
test("a tx signed by the wrong key fails signature", () => assert.deepEqual(run(seal([mk(mallory)])), ["signature"]));
test("a non-member key cannot decrypt", () => {
  const e = seal([mk(alice)]);
  const r = checkBatch({ rollupId: "cloister-dev-2", member, envelope: e, decapsulationKey: kemKeypairFromSeed(randomBytes(64)).secretKey,
    keyOf: () => undefined, batch: { batch_index: "7", tx_count: "1", status: "finalized", data_hash: createHash("sha256").update(e).digest("hex") } });
  assert.ok(r.findings.some((f) => f.check === "decrypt" && !f.ok));
});
