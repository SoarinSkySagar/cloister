/**
 * Frame transaction codec (spec/frame-tx.md): encoding, decoding, the
 * signature hash, ML-DSA-87 signing and verification, structural validation,
 * and the mapping to the prover's batch input (spec/batch.md).
 */
import { createHash } from "node:crypto";
import { pqSign, pqVerify } from "@qorechain/qoresign";
import { BLS12_381_SCALAR_MODULUS } from "@qorechain/rdk";

export const FRAME_TX_VERSION = 1;
export const SIGHASH_DOMAIN = "cloister/frametx/v1";
export const MODE = { VERIFY_SENDER: 1, VERIFY_PAYER: 2, ACTION: 3, VERIFY_PARTY: 4, GUARD: 5 } as const;
export const KIND = { transfer: 0x01, withdraw: 0x02, register_key: 0x03, transfer_from: 0x04, withdraw_from: 0x05 } as const;
export const FLAG_ATOMIC = 0x04;
export const SCHEME_ML_DSA_87 = 1;
export const ML_DSA_87_SIG_LEN = 4627;
export const ML_DSA_87_PK_LEN = 2592;
/** `sender` of a tx that creates its account; the sequencer assigns the index. */
export const NEW_ACCOUNT = 0xffffffff;
/** Circuit: 1 fee move + 3 actions (circuits/ledger, spec/batch.md). */
export const MAX_ACTIONS = 3;
/** Co-signers per tx (spec/frame-tx.md, multi-party). */
export const MAX_PARTIES = 3;
/** Account indexes are below this: the last leaf of the depth-16 state tree is the reserved log leaf (spec/state.md). */
export const ACCOUNT_LIMIT = 65535;
export const RECIPIENT_LEN = 42;
export const ASSET = { QOR: 0, USD: 1 } as const;

export interface Frame { mode: number; flags: number; kind: number; params: Uint8Array }
export interface Sig { scheme: number; signer: number; signature: Uint8Array }
export interface FrameTx {
  version: number;
  chainId: string;
  rollupId: string;
  sender: number;
  nonce: bigint;
  expiryBatch: bigint;
  feeAsset: number;
  maxFee: bigint;
  frames: Frame[];
  sigs: Sig[];
}

export type Action =
  | { kind: "transfer"; to: number; asset: number; amount: bigint; atomic: boolean }
  | { kind: "withdraw"; recipient: string; amount: bigint; atomic: boolean }
  | { kind: "register_key"; publicKey: Uint8Array; atomic: boolean }
  /** Like transfer / withdraw, but debits `from`, which must be the sender or a VERIFY_PARTY account. */
  | { kind: "transfer_from"; from: number; to: number; asset: number; amount: bigint; atomic: boolean }
  | { kind: "withdraw_from"; from: number; recipient: string; amount: bigint; atomic: boolean };

// ---- byte helpers ----

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

class Writer {
  private parts: Uint8Array[] = [];
  u8(v: number) { this.parts.push(Uint8Array.of(v & 0xff)); return this; }
  u32(v: number) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0); this.parts.push(b); return this; }
  u64(v: bigint) {
    if (v < 0n || v >= 1n << 64n) throw new Error(`u64 out of range: ${v}`);
    const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, v); this.parts.push(b); return this;
  }
  raw(b: Uint8Array) { this.parts.push(b); return this; }
  lp(b: Uint8Array) { return this.u32(b.length).raw(b); }
  bytes(): Uint8Array {
    const out = new Uint8Array(this.parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of this.parts) { out.set(p, o); o += p.length; }
    return out;
  }
}

class Reader {
  private o = 0;
  constructor(private b: Uint8Array) {}
  private need(n: number) { if (this.o + n > this.b.length) throw new Error("frame tx: truncated"); }
  u8() { this.need(1); return this.b[this.o++]!; }
  u32() { this.need(4); const v = new DataView(this.b.buffer, this.b.byteOffset + this.o, 4).getUint32(0); this.o += 4; return v; }
  u64() { this.need(8); const v = new DataView(this.b.buffer, this.b.byteOffset + this.o, 8).getBigUint64(0); this.o += 8; return v; }
  raw(n: number) { this.need(n); const v = this.b.slice(this.o, this.o + n); this.o += n; return v; }
  lp(max: number) { const n = this.u32(); if (n > max) throw new Error(`frame tx: field of ${n} bytes exceeds ${max}`); return this.raw(n); }
  done() { if (this.o !== this.b.length) throw new Error("frame tx: trailing bytes"); }
  get atEnd() { return this.o === this.b.length; }
}

// ---- encoding ----

function encodeBody(w: Writer, tx: FrameTx) {
  w.u8(tx.version).lp(te.encode(tx.chainId)).lp(te.encode(tx.rollupId)).u32(tx.sender).u64(tx.nonce).u64(tx.expiryBatch)
    .u8(tx.feeAsset).u64(tx.maxFee).u8(tx.frames.length);
  for (const f of tx.frames) w.u8(f.mode).u8(f.flags).u8(f.kind).lp(f.params);
  w.u8(tx.sigs.length);
}

export function encodeFrameTx(tx: FrameTx): Uint8Array {
  const w = new Writer();
  encodeBody(w, tx);
  for (const s of tx.sigs) w.u8(s.scheme).u32(s.signer).lp(s.signature);
  return w.bytes();
}

/** The encoding with each signature replaced by its u32 length only. */
export function encodeUnsigned(tx: FrameTx): Uint8Array {
  const w = new Writer();
  encodeBody(w, tx);
  for (const s of tx.sigs) w.u8(s.scheme).u32(s.signer).u32(s.signature.length);
  return w.bytes();
}

export function sighash(tx: FrameTx): Uint8Array {
  return createHash("shake256", { outputLength: 32 }).update(SIGHASH_DOMAIN).update(encodeUnsigned(tx)).digest();
}

export function decodeFrameTx(bytes: Uint8Array): FrameTx {
  const r = new Reader(bytes);
  const version = r.u8();
  if (version !== FRAME_TX_VERSION) throw new Error(`frame tx: version ${version}`);
  const chainId = td.decode(r.lp(64));
  const rollupId = td.decode(r.lp(64));
  const sender = r.u32();
  const nonce = r.u64();
  const expiryBatch = r.u64();
  const feeAsset = r.u8();
  const maxFee = r.u64();
  const nf = r.u8();
  if (nf < 1 || nf > 12) throw new Error(`frame tx: ${nf} frames`);
  const frames: Frame[] = [];
  for (let i = 0; i < nf; i++) frames.push({ mode: r.u8(), flags: r.u8(), kind: r.u8(), params: r.lp(4096) });
  const ns = r.u8();
  if (ns < 1 || ns > 5) throw new Error(`frame tx: ${ns} signatures`);
  const sigs: Sig[] = [];
  for (let i = 0; i < ns; i++) sigs.push({ scheme: r.u8(), signer: r.u32(), signature: r.lp(ML_DSA_87_SIG_LEN) });
  r.done();
  return { version, chainId, rollupId, sender, nonce, expiryBatch, feeAsset, maxFee, frames, sigs };
}

// ---- frames ----

export const verifySenderFrame = (): Frame => ({ mode: MODE.VERIFY_SENDER, flags: 0, kind: 0, params: new Uint8Array() });
export const verifyPayerFrame = (payer: number): Frame =>
  ({ mode: MODE.VERIFY_PAYER, flags: 0, kind: 0, params: new Writer().u32(payer).bytes() });

export const verifyPartyFrame = (party: number): Frame =>
  ({ mode: MODE.VERIFY_PARTY, flags: 0, kind: 0, params: new Writer().u32(party).bytes() });
export const guardFrame = (notBeforeBatch: bigint): Frame =>
  ({ mode: MODE.GUARD, flags: 0, kind: 0, params: new Writer().u64(notBeforeBatch).bytes() });

export function actionFrame(a: Action): Frame {
  const flags = a.atomic ? FLAG_ATOMIC : 0;
  switch (a.kind) {
    case "transfer":
      return { mode: MODE.ACTION, flags, kind: KIND.transfer, params: new Writer().u32(a.to).u8(a.asset).u64(a.amount).bytes() };
    case "withdraw":
      return { mode: MODE.ACTION, flags, kind: KIND.withdraw, params: new Writer().lp(te.encode(a.recipient)).u64(a.amount).bytes() };
    case "register_key":
      return { mode: MODE.ACTION, flags, kind: KIND.register_key, params: new Writer().lp(a.publicKey).bytes() };
    case "transfer_from":
      return { mode: MODE.ACTION, flags, kind: KIND.transfer_from, params: new Writer().u32(a.from).u32(a.to).u8(a.asset).u64(a.amount).bytes() };
    case "withdraw_from":
      return { mode: MODE.ACTION, flags, kind: KIND.withdraw_from, params: new Writer().u32(a.from).lp(te.encode(a.recipient)).u64(a.amount).bytes() };
  }
}

export function parseAction(f: Frame): Action {
  if (f.mode !== MODE.ACTION) throw new Error("not an ACTION frame");
  const atomic = (f.flags & FLAG_ATOMIC) !== 0;
  const r = new Reader(f.params);
  let a: Action;
  switch (f.kind) {
    case KIND.transfer: a = { kind: "transfer", to: r.u32(), asset: r.u8(), amount: r.u64(), atomic }; break;
    case KIND.withdraw: a = { kind: "withdraw", recipient: td.decode(r.lp(128)), amount: r.u64(), atomic }; break;
    case KIND.register_key: a = { kind: "register_key", publicKey: r.lp(ML_DSA_87_PK_LEN), atomic }; break;
    case KIND.transfer_from: a = { kind: "transfer_from", from: r.u32(), to: r.u32(), asset: r.u8(), amount: r.u64(), atomic }; break;
    case KIND.withdraw_from: a = { kind: "withdraw_from", from: r.u32(), recipient: td.decode(r.lp(128)), amount: r.u64(), atomic }; break;
    default: throw new Error(`unknown action kind 0x${f.kind.toString(16)}`);
  }
  r.done();
  return a;
}

export function payerOf(tx: FrameTx): number {
  const f = tx.frames.find((x) => x.mode === MODE.VERIFY_PAYER);
  return f ? new Reader(f.params).u32() : tx.sender;
}

/** The VERIFY_PARTY accounts, in frame order. */
export const partiesOf = (tx: FrameTx): number[] =>
  tx.frames.filter((f) => f.mode === MODE.VERIFY_PARTY).map((f) => new Reader(f.params).u32());

/** The GUARD frame's not_before_batch (0 when absent). */
export function notBeforeOf(tx: FrameTx): bigint {
  const g = tx.frames.find((f) => f.mode === MODE.GUARD);
  return g ? new Reader(g.params).u64() : 0n;
}

/** The account an action debits. */
export const fromOf = (a: Action, sender: number): number =>
  a.kind === "transfer_from" || a.kind === "withdraw_from" ? a.from : sender;

/**
 * The accounts that must sign, in signature order: the sender, the parties in frame order, then the
 * payer unless it is already one of them.
 */
export function signersOf(tx: FrameTx): number[] {
  const out = [tx.sender, ...partiesOf(tx)];
  const payer = payerOf(tx);
  if (!out.includes(payer)) out.push(payer);
  return out;
}

export const actionsOf = (tx: FrameTx): Action[] => tx.frames.filter((f) => f.mode === MODE.ACTION).map(parseAction);

/** The ML-DSA-87 key a new account registers (its first action must be register_key). */
export function newAccountKey(tx: FrameTx): Uint8Array | undefined {
  if (tx.sender !== NEW_ACCOUNT) return undefined;
  const first = actionsOf(tx)[0];
  return first?.kind === "register_key" ? first.publicKey : undefined;
}

// ---- building ----

export interface BuildArgs {
  chainId: string;
  rollupId: string;
  sender: number;
  nonce: bigint;
  expiryBatch: bigint;
  feeAsset?: number;
  maxFee?: bigint;
  payer?: number; // sponsor; omit for self-paid
  parties?: number[]; // co-signers: actions may debit them (transfer_from / withdraw_from)
  notBefore?: bigint; // GUARD: not valid before this batch index
  actions: Action[];
}

