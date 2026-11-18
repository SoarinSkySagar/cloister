import { test } from "node:test";
import assert from "node:assert/strict";
import { ASSET, NEW_ACCOUNT, buildFrameTx, toLedgerTx, type FrameTx } from "@cloister/common";
import { pqKeyFromSeed } from "@qorechain/qoresign";
import { checkTxAgainstProof } from "../src/checktx.ts";
import { txDigest } from "../src/digest.ts";
import { toHex, type InclusionProof } from "../src/inclusion.ts";

const ids = { chainId: "qorechain-diana", rollupId: "cloister-dev-5" };
const swap = (over: Partial<Parameters<typeof buildFrameTx>[0]> = {}): FrameTx => buildFrameTx({ ...ids, sender: 2, nonce: 4n, expiryBatch: 99n, maxFee: 10_000n, payer: 0, parties: [3], notBefore: 7n,
  actions: [{ kind: "transfer_from", from: 2, to: 3, asset: ASSET.USD, amount: 5n, atomic: true }, { kind: "transfer_from", from: 3, to: 2, asset: ASSET.QOR, amount: 9n, atomic: true }], ...over });

/** The record the circuit would write for `tx` (sender index `index`), with these action moves applied or not. */
function proofFor(tx: FrameTx, index: number, applied: boolean[]): InclusionProof {
  const l = toLedgerTx(tx, { relayer: 1, senderIndex: tx.sender === NEW_ACCOUNT ? index : undefined });
  const zero = { code: 0, asset: 0, amount: "0", from: 0, to: 0, aux: "0".repeat(64) };
  const moves = [{ code: 1, asset: 0, amount: String(l.fee), from: l.payer, to: 1, aux: "0".repeat(64) },
    ...l.actions.map((a, k) => (applied[k] && a.kind === "transfer" ? { code: 1, asset: a.asset, amount: String(a.amount), from: a.from ?? l.sender, to: a.to, aux: "0".repeat(64) } : zero))];
  while (moves.length < 4) moves.push(zero);
  return { version: 2, chainId: ids.chainId, rollupId: ids.rollupId, batchIndex: 3, txIndex: 0, txPath: ["00".repeat(32), "00".repeat(32)], logPath: Array(16).fill("00".repeat(32)),
    record: { digest: toHex(txDigest(ids.chainId, ids.rollupId, tx.nonce, l)), sender: l.sender, nonceBefore: String(tx.nonce), expiryBatch: String(l.expiry), notBeforeBatch: String(l.not_before ?? 0), parties: l.parties ?? [], moves } };
}

test("a record made from the transaction matches it, and the applied flags are read from the moves", () => {
  const tx = swap();
  const c = checkTxAgainstProof(proofFor(tx, 2, [true, true]), tx);
  assert.deepEqual(c.problems, []);
  assert.deepEqual(c.applied, [true, true]);
  assert.deepEqual(checkTxAgainstProof(proofFor(tx, 2, [false, false]), tx).applied, [false, false]);
});

test("a record that differs from the transaction in any signed term is refused", () => {
  const tx = swap();
  const p = proofFor(tx, 2, [true, true]);
  for (const [name, other] of Object.entries({
    "a different amount": swap({ actions: [{ kind: "transfer_from", from: 2, to: 3, asset: ASSET.USD, amount: 6n, atomic: true }, { kind: "transfer_from", from: 3, to: 2, asset: ASSET.QOR, amount: 9n, atomic: true }] }),
    "a dropped leg": swap({ actions: [{ kind: "transfer_from", from: 2, to: 3, asset: ASSET.USD, amount: 5n, atomic: true }] }),
    "a different window": swap({ expiryBatch: 100n }),
    "a different time lock": swap({ notBefore: 0n }),
    "a different max fee": swap({ maxFee: 20_000n }),
    "a different payer": swap({ payer: 2 }),
    "a different co-signer": swap({ parties: [4], actions: [{ kind: "transfer_from", from: 2, to: 4, asset: ASSET.USD, amount: 5n, atomic: true }, { kind: "transfer_from", from: 4, to: 2, asset: ASSET.QOR, amount: 9n, atomic: true }] }),
    "another rollup": swap({ rollupId: "cloister-dev-6" }),
    "another nonce": swap({ nonce: 5n }),
  })) {
    assert.notDeepEqual(checkTxAgainstProof(p, other).problems, [], name);
  }
});

test("a new account's transaction is matched with the index the record shows", () => {
  const k = pqKeyFromSeed(new Uint8Array(32).fill(7));
  const tx = buildFrameTx({ ...ids, sender: NEW_ACCOUNT, nonce: 0n, expiryBatch: 50n, maxFee: 10_000n, payer: 0, actions: [{ kind: "register_key", publicKey: k.publicKey, atomic: false }] });
  const p = proofFor(tx, 9, [false]);
  assert.deepEqual(checkTxAgainstProof(p, tx).problems, []);
  p.record.sender = 10; // the digest does not carry the index of a registering account, but the register action's `from` does
  assert.notDeepEqual(checkTxAgainstProof(p, tx).problems, []);
});

test("a version 1 proof cannot be tied to a transaction", () => {
  const tx = swap();
  const p = proofFor(tx, 2, [true, true]);
  const old = { ...p, version: 1 as const, record: { ...p.record, digest: undefined } };
  assert.match(checkTxAgainstProof(old, tx).problems[0]!, /version 1/);
});
