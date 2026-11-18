import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateAlerts, type AlertInput, type BatchLite } from "../src/alerts.ts";

const R = (n: number) => n.toString(16).padStart(64, "0");
const chain = (n: number, at = 100): BatchLite[] => Array.from({ length: n }, (_, i) => ({ batchIndex: i, stateRoot: R(i + 1), prevStateRoot: i === 0 ? "0" : R(i), submittedAt: at + 10 * i }));
const base = (over: Partial<AlertInput> = {}): AlertInput => ({ height: 200, rollup: { hasVerificationKey: true, membersEpoch: 1, sequencing: "" }, batches: chain(3), vkEvents: [{ height: 90, sha256: "ab".repeat(32) }], pinnedVkSha256: "ab".repeat(32), ...over });
const codes = (a: AlertInput) => evaluateAlerts(a).map((x) => `${x.level}:${x.code}`);

test("a healthy rollup raises nothing", () => assert.deepEqual(codes(base()), []));

test("verification key: replaced after the first batch, different from the committed one, missing, or unreadable", () => {
  assert.deepEqual(codes(base({ vkEvents: [{ height: 90, sha256: "ab".repeat(32) }, { height: 150, sha256: "ab".repeat(32) }] })), ["critical:vk"]);
  assert.deepEqual(codes(base({ vkEvents: [{ height: 90, sha256: "cd".repeat(32) }] })), ["critical:vk"]);
  assert.deepEqual(codes(base({ vkEvents: [{ height: 90, sha256: "ab".repeat(32), setBy: "governance" }] })), ["critical:vk"], "set by governance, even before the first batch");
  assert.deepEqual(codes(base({ vkEvents: [{ height: 90, sha256: "ab".repeat(32), setBy: "creator" }] })), []);
  assert.deepEqual(codes(base({ rollup: { hasVerificationKey: false, membersEpoch: 1, sequencing: "" } })), ["critical:vk"]);
  assert.deepEqual(codes(base({ vkEvents: undefined })), ["info:vk"], "not being able to read the events is never reported as 'unchanged'");
  assert.deepEqual(codes(base({ vkEvents: [] })), ["warning:vk"]);
  assert.deepEqual(codes(base({ rollup: { membersEpoch: 1, sequencing: "" } })), ["critical:vk"], "a node that does not serve the field means no key");
});

test("a batch that does not continue the previous one, or a gap, is critical", () => {
  const b = chain(3);
  b[2]!.prevStateRoot = R(99);
  assert.deepEqual(codes(base({ batches: b })), ["critical:continuity"]);
  assert.deepEqual(codes(base({ batches: [chain(3)[0]!, chain(3)[2]!] })), ["critical:continuity"]);
  assert.deepEqual(codes(base({ batches: [...chain(3)].reverse() })), [], "order of arrival does not matter");
});

test("stalls: no batch for a long time; posts the sequencer has not consumed on a based rollup", () => {
  assert.deepEqual(codes(base({ height: 1000 })), ["warning:stall"]);
  assert.deepEqual(codes(base({ height: 1000, stallBlocks: 5000 })), []);
  assert.deepEqual(codes(base({ rollup: { hasVerificationKey: true, membersEpoch: 1, sequencing: "based" }, inbox: { headSequence: 9, consumedSequence: 6 } })), ["info:stall"]);
  assert.deepEqual(codes(base({ inbox: { headSequence: 9, consumedSequence: 6 } })), [], "a dedicated rollup has no based inbox to consume");
});

test("a changed membership epoch is a warning, the first run is not", () => {
  assert.deepEqual(codes(base({ knownEpoch: 1 })), []);
  assert.deepEqual(codes(base({ knownEpoch: 0 })), ["warning:epoch"]);
});

test("watchtowers that disagree about a batch are critical", () => {
  const v = (w: string, result: "pass" | "fail", root = R(2)) => ({ watchtower: w, batchIndex: 1, result, stateRoot: root });
  assert.deepEqual(codes(base({ verdicts: [v("qor1aaaaaaaaaaaaaaaa", "pass"), v("qor1bbbbbbbbbbbbbbbb", "pass")] })), []);
  assert.deepEqual(codes(base({ verdicts: [v("qor1aaaaaaaaaaaaaaaa", "pass"), v("qor1bbbbbbbbbbbbbbbb", "fail")] })), ["critical:disagreement"]);
  assert.deepEqual(codes(base({ verdicts: [v("qor1aaaaaaaaaaaaaaaa", "pass"), v("qor1bbbbbbbbbbbbbbbb", "pass", R(7))] })), ["critical:disagreement"]);
  assert.deepEqual(codes(base({ verdicts: [v("qor1aaaaaaaaaaaaaaaa", "pass")] })), [], "one watchtower cannot disagree with itself");
});
