import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { checkShape, logLeaf, proofStateRoot, recipientCommit, recordFields, toHex, verifyInclusion, type InclusionProof } from "../src/inclusion.ts";
import { compress, md, P } from "../src/poseidon2.ts";

const [vec] = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "spec", "vectors", "inclusion.json"), "utf8")) as any[];
const exp = vec.expected;
const proofs = exp.proofs as InclusionProof[];
const clone = <T,>(x: T): T => JSON.parse(JSON.stringify(x));

test("Poseidon2 reproduces the Go reference: records, tx root, log leaf, state root and recipient commitment", () => {
  assert.equal(toHex(recipientCommit(vec.input.recipient)), exp.recipient_commit);
  const leaves: bigint[] = vec.input.records.map((r: any, i: number) => (r ? md(recordFields(r)) : 0n));
  assert.deepEqual(leaves.map(toHex), exp.record_hashes);
  const root = compress(compress(leaves[0]!, leaves[1]!), compress(leaves[2]!, leaves[3]!));
  assert.equal(toHex(root), exp.tx_root);
  assert.equal(toHex(logLeaf(root, vec.input.batch_index)), exp.log_leaf);
});

test("every proof in the vector reaches the state root the Go reference computed", () => {
  assert.equal(proofs.length, 2);
  for (const p of proofs) assert.equal(toHex(proofStateRoot(p)), exp.state_root);
});

/** A fake chain holding one batch. */
const chain = (stateRoot: string, over: { chainId?: string; fail?: boolean } = {}) => ({
  network: { chainId: over.chainId ?? "qorechain-diana" },
  rest: { getBatch: async () => { if (over.fail) throw new Error("fetch failed"); return { stateRoot }; } },
}) as never;

test("a proof verifies against the chain's root, and the chain's root is what decides", async () => {
  const p = proofs[0]!;
  assert.deepEqual(await verifyInclusion(p, chain(exp.state_root)), { valid: true, proofRoot: exp.state_root, chainRoot: exp.state_root, problems: [] });
  // the chain may return a root without leading zeros
  const short = exp.state_root.replace(/^0+/, "");
  assert.equal((await verifyInclusion(p, chain(short))).valid, true);
  const wrong = await verifyInclusion(p, chain("ab".repeat(32)));
  assert.equal(wrong.valid, false);
  assert.match(wrong.problems[0]!, /does not reach the state root/);
  assert.match((await verifyInclusion(p, chain(exp.state_root, { chainId: "other" }))).problems[0]!, /proof is for chain/);
});

test("a chain that cannot be read is unverifiable, not invalid", async () => {
  const r = await verifyInclusion(proofs[0]!, chain(exp.state_root, { fail: true }));
  assert.equal(r.valid, false);
  assert.equal(r.unverifiable, true);
});

test("changing any part of a proof changes the root it reaches", () => {
  const good = proofs[1]!; // the two-party tx where the party withdraws
  const mut: Record<string, (p: InclusionProof) => void> = {
    "sender": (p) => { p.record.sender++; },
    "digest": (p) => { p.record.digest = "00".repeat(31) + "01"; },
    "nonce": (p) => { p.record.nonceBefore = "5"; },
    "expiry": (p) => { p.record.expiryBatch = "100"; },
    "not before": (p) => { p.record.notBeforeBatch = "0"; },
    "party": (p) => { p.record.parties = [4]; },
    "drop the party": (p) => { p.record.parties = []; },
    "add a party": (p) => { p.record.parties = [3, 9]; },
    "amount": (p) => { p.record.moves[1]!.amount = "6"; },
    "debited account": (p) => { p.record.moves[1]!.from = 3; },
    "credited account": (p) => { p.record.moves[1]!.to = 0; },
    "asset": (p) => { p.record.moves[1]!.asset = 0; },
    "recipient commitment": (p) => { p.record.moves[2]!.aux = toHex(recipientCommit("qor1" + "x".repeat(38))); },
    "slot": (p) => { p.txIndex = 0; },
    "batch number": (p) => { p.batchIndex++; },
    "tx path": (p) => { p.txPath[0] = "00".repeat(31) + "09"; },
    "log path": (p) => { p.logPath[3] = "00".repeat(31) + "09"; },
  };
  for (const [name, f] of Object.entries(mut)) {
    const p = clone(good);
    f(p);
    let root: string | undefined;
    try { root = toHex(proofStateRoot(p)); } catch { root = undefined; /* refused by the shape rules, also fine */ }
    assert.notEqual(root, exp.state_root, name);
  }
});

test("shape rules refuse malformed proofs before any hashing", () => {
  const bad = (f: (p: InclusionProof) => void) => { const p = clone(proofs[0]!); f(p); assert.throws(() => checkShape(p)); };
  bad((p) => { p.version = 3 as 1; });
  bad((p) => { p.version = 1; }); // a version 1 record has no digest
  bad((p) => { delete p.record.digest; }); // a version 2 record carries it
  bad((p) => { p.record.digest = "ff".repeat(32); }); // not canonical
  bad((p) => { p.txIndex = 4; });
  bad((p) => { p.txIndex = -1; });
  bad((p) => { p.txPath.pop(); });
  bad((p) => { p.logPath.push("00".repeat(32)); });
  bad((p) => { p.record.moves.pop(); });
  bad((p) => { p.record.parties = [1, 2, 3, 4]; });
  bad((p) => { p.record.parties = [p.record.sender]; });
  bad((p) => { p.record.parties = [6, 6]; });
  bad((p) => { p.record.moves[3]!.amount = "1"; }); // an unapplied move must be all zeros
  bad((p) => { p.record.moves[1]!.aux = "00".repeat(31) + "01"; }); // a transfer has aux 0
  bad((p) => { p.record.moves[0]!.code = 9; });
  assert.throws(() => proofStateRoot({ ...clone(proofs[0]!), txPath: ["ff".repeat(32), "00".repeat(32)] }), /not canonical/);
  assert.throws(() => proofStateRoot({ ...clone(proofs[0]!), txPath: ["AB".repeat(32), "00".repeat(32)] }), /lower-case hex/);
  const huge = clone(proofs[0]!); huge.record.nonceBefore = (1n << 64n).toString();
  assert.throws(() => proofStateRoot(huge), /not a u64/);
  assert.ok(P > 0n);
});
