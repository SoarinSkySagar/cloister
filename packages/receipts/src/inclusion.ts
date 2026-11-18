/**
 * Transaction inclusion proofs (spec/inclusion.md): verification in TypeScript, shared by the CLI and the
 * browser page. The proof is only a claim until its state root is compared with the one the chain holds.
 */
import type { RdkClient } from "@qorechain/rdk";
import { compress, md, P } from "./poseidon2.ts";

export interface InclusionShape { depth: number; txSlots: number; partySlots: number; moves: number }
/** The circuit shape of the current rollups (circuits/ledger Config). */
export const DEFAULT_SHAPE: InclusionShape = { depth: 16, txSlots: 4, partySlots: 3, moves: 4 };

export interface MoveJSON { code: number; asset: number; amount: string; from: number; to: number; aux: string }
export interface RecordJSON {
  sender: number; nonceBefore: string; expiryBatch: string; notBeforeBatch: string; parties: number[]; moves: MoveJSON[];
}
export interface InclusionProof {
  version: 1; chainId: string; rollupId: string; batchIndex: number; record: RecordJSON;
  txIndex: number; txPath: string[]; logPath: string[];
}

const TX_TAG = 1n;
const CODES = { none: 0, transfer: 1, withdraw: 2, register: 3 };
const U64 = (1n << 64n) - 1n;

const feHex = (s: string) => {
  if (!/^[0-9a-f]{64}$/.test(s)) throw new Error("field element must be 64 lower-case hex");
  const v = BigInt("0x" + s);
  if (v >= P) throw new Error("field element is not canonical (not below r)");
  return v;
};
export const toHex = (v: bigint) => v.toString(16).padStart(64, "0");
const u64 = (s: string, what: string) => {
  if (!/^\d+$/.test(s)) throw new Error(`${what} must be a decimal string`);
  const v = BigInt(s);
  if (v > U64) throw new Error(`${what} is not a u64`);
  return v;
};
const idx = (n: number, what: string) => {
  if (!Number.isInteger(n) || n < 0 || n >= 2 ** 32) throw new Error(`${what} must be a u32`);
  return BigInt(n);
};

/** Structural checks (spec "Verifying" step 1). Throws with the reason. */
export function checkShape(p: InclusionProof, shape: InclusionShape = DEFAULT_SHAPE): void {
  if (p.version !== 1) throw new Error("unsupported proof version");
  if (!Number.isInteger(p.batchIndex) || p.batchIndex < 0) throw new Error("bad batchIndex");
  if (!Number.isInteger(p.txIndex) || p.txIndex < 0 || p.txIndex >= shape.txSlots) throw new Error("txIndex out of range");
  const txDepth = Math.log2(shape.txSlots);
  if (p.txPath.length !== txDepth) throw new Error(`txPath must have ${txDepth} siblings`);
  if (p.logPath.length !== shape.depth) throw new Error(`logPath must have ${shape.depth} siblings`);
  const r = p.record;
  if (r.parties.length > shape.partySlots) throw new Error(`at most ${shape.partySlots} parties`);
  if (r.moves.length !== shape.moves) throw new Error(`a record has exactly ${shape.moves} moves`);
  const seen = new Set<number>();
  for (const q of r.parties) { if (seen.has(q) || q === r.sender) throw new Error("parties must be distinct and not the sender"); seen.add(q); }
  r.moves.forEach((m, i) => {
    feHex(m.aux);
    u64(m.amount, `move ${i} amount`);
    const zeroAux = /^0{64}$/.test(m.aux);
    if (m.code === CODES.none) {
      if (m.asset || m.amount !== "0" || m.from || m.to || !zeroAux) throw new Error(`move ${i}: an unapplied move must be all zeros`);
    } else if (m.code === CODES.transfer) {
      if (!zeroAux) throw new Error(`move ${i}: a transfer has aux 0`);
    } else if (m.code === CODES.withdraw) {
      if (m.to !== 0 || m.asset !== 0) throw new Error(`move ${i}: a withdraw is QOR and has to = 0`);
    } else if (m.code === CODES.register) {
      if (m.to !== 0 || m.asset !== 0 || m.amount !== "0") throw new Error(`move ${i}: register_key has no asset, amount or to`);
    } else throw new Error(`move ${i}: unknown code ${m.code}`);
    if (m.code === CODES.none || m.code === CODES.transfer) return;
    if (m.asset !== 0 && m.asset !== 1) throw new Error(`move ${i}: unknown asset`);
  });
  for (const m of r.moves) if (m.code !== CODES.none && m.asset > 1) throw new Error("unknown asset");
}

/** The 5 + P + 6M field elements of a record (spec "Transaction record"). */
export function recordFields(r: RecordJSON, shape: InclusionShape = DEFAULT_SHAPE): bigint[] {
  const out = [TX_TAG, idx(r.sender, "sender"), u64(r.nonceBefore, "nonceBefore"), u64(r.expiryBatch, "expiryBatch"), u64(r.notBeforeBatch, "notBeforeBatch")];
  for (let i = 0; i < shape.partySlots; i++) out.push(i < r.parties.length ? idx(r.parties[i]!, "party") + 1n : 0n);
  for (const m of r.moves) out.push(BigInt(m.code), BigInt(m.asset), u64(m.amount, "amount"), idx(m.from, "from"), idx(m.to, "to"), feHex(m.aux));
  return out;
}

/** The account-leaf hash of the log leaf after batch n: {pk: tx_root, qor 0, usd 0, nonce n+1, orders 0}. */
export function logLeaf(txRoot: bigint, batchIndex: number): bigint {
  return md([txRoot, 0n, 0n, BigInt(batchIndex) + 1n, 0n]);
}

function climb(leaf: bigint, index: number, path: bigint[]): bigint {
  let cur = leaf;
  for (const sib of path) {
    cur = (index & 1) === 0 ? compress(cur, sib) : compress(sib, cur);
    index = Math.floor(index / 2);
  }
  return cur;
}

/** The state root the proof commits to. Compare it with the chain's root for the batch. */
export function proofStateRoot(p: InclusionProof, shape: InclusionShape = DEFAULT_SHAPE): bigint {
  checkShape(p, shape);
  const txRoot = climb(md(recordFields(p.record, shape)), p.txIndex, p.txPath.map(feHex));
  return climb(logLeaf(txRoot, p.batchIndex), 2 ** shape.depth - 1, p.logPath.map(feHex));
}

export interface InclusionVerdict {
  valid: boolean;
  /** The chain could not be read; the proof is neither accepted nor shown to be wrong. */
  unverifiable?: boolean;
  proofRoot?: string;
  chainRoot?: string;
  problems: string[];
}

const norm = (s: string) => s.toLowerCase().replace(/^0x/, "").padStart(64, "0");

async function retry<T>(fn: () => Promise<T>, tries = 3): Promise<T> {
  let last: unknown;
  for (let i = 0; i < tries; i++) {
    try { return await fn(); } catch (e) { last = e; if (i < tries - 1) await new Promise((r) => setTimeout(r, 400 * (i + 1))); }
  }
  throw last;
}

/** Accept a proof only if its root equals the state root the chain holds for that batch (read from the chain, never the proof). */
export async function verifyInclusion(p: InclusionProof, client: RdkClient, shape: InclusionShape = DEFAULT_SHAPE): Promise<InclusionVerdict> {
  let root: bigint;
  try { root = proofStateRoot(p, shape); } catch (e) { return { valid: false, problems: [(e as Error).message] }; }
  if (client.network.chainId !== p.chainId) return { valid: false, proofRoot: toHex(root), problems: [`proof is for chain ${p.chainId}, not ${client.network.chainId}`] };
  let batch;
  try { batch = await retry(() => client.rest.getBatch(p.rollupId, p.batchIndex)); }
  catch (e) { return { valid: false, unverifiable: true, proofRoot: toHex(root), problems: [`could not read the chain: ${(e as Error).message}`] }; }
  const chainRoot = norm(batch.stateRoot);
  return chainRoot === toHex(root)
    ? { valid: true, proofRoot: toHex(root), chainRoot, problems: [] }
    : { valid: false, proofRoot: toHex(root), chainRoot, problems: ["the proof does not reach the state root the chain holds for this batch"] };
}

export function parseInclusion(text: string): { proof: InclusionProof } | { error: string } {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return { error: "not valid JSON" }; }
  if (!j || typeof j !== "object") return { error: "not an inclusion proof" };
  const p = j as InclusionProof;
  if (typeof p.rollupId !== "string" || !p.record || !Array.isArray(p.txPath) || !Array.isArray(p.logPath)) return { error: "not an inclusion proof" };
  return { proof: p };
}

/** Binds the 42-byte qor1 address of a withdrawal: Compress(pack(r[0..21]), pack(r[21..42])). */
export function recipientCommit(recipient: string): bigint {
  const b = new TextEncoder().encode(recipient);
  if (b.length !== 42) throw new Error("recipient must be 42 bytes");
  const pack = (x: Uint8Array) => x.reduce((n, v) => (n << 8n) | BigInt(v), 0n);
  return compress(pack(b.slice(0, 21)), pack(b.slice(21)));
}
