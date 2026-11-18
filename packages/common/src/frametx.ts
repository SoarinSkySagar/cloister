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
export const MODE = { VERIFY_SENDER: 1, VERIFY_PAYER: 2, ACTION: 3 } as const;
export const KIND = { transfer: 0x01, withdraw: 0x02, register_key: 0x03 } as const;
export const FLAG_ATOMIC = 0x04;
export const SCHEME_ML_DSA_87 = 1;
export const ML_DSA_87_SIG_LEN = 4627;
export const ML_DSA_87_PK_LEN = 2592;
/** `sender` of a tx that creates its account; the sequencer assigns the index. */
export const NEW_ACCOUNT = 0xffffffff;
/** Circuit v1: 1 fee move + 2 actions (circuits/ledger, spec/batch.md). */
export const MAX_ACTIONS = 2;
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
  | { kind: "register_key"; publicKey: Uint8Array; atomic: boolean };

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
  if (nf < 1 || nf > 8) throw new Error(`frame tx: ${nf} frames`);
  const frames: Frame[] = [];
  for (let i = 0; i < nf; i++) frames.push({ mode: r.u8(), flags: r.u8(), kind: r.u8(), params: r.lp(4096) });
  const ns = r.u8();
  if (ns < 1 || ns > 2) throw new Error(`frame tx: ${ns} signatures`);
  const sigs: Sig[] = [];
  for (let i = 0; i < ns; i++) sigs.push({ scheme: r.u8(), signer: r.u32(), signature: r.lp(ML_DSA_87_SIG_LEN) });
  r.done();
  return { version, chainId, rollupId, sender, nonce, expiryBatch, feeAsset, maxFee, frames, sigs };
}

// ---- frames ----

export const verifySenderFrame = (): Frame => ({ mode: MODE.VERIFY_SENDER, flags: 0, kind: 0, params: new Uint8Array() });
export const verifyPayerFrame = (payer: number): Frame =>
  ({ mode: MODE.VERIFY_PAYER, flags: 0, kind: 0, params: new Writer().u32(payer).bytes() });

export function actionFrame(a: Action): Frame {
  const flags = a.atomic ? FLAG_ATOMIC : 0;
  switch (a.kind) {
    case "transfer":
      return { mode: MODE.ACTION, flags, kind: KIND.transfer, params: new Writer().u32(a.to).u8(a.asset).u64(a.amount).bytes() };
    case "withdraw":
      return { mode: MODE.ACTION, flags, kind: KIND.withdraw, params: new Writer().lp(te.encode(a.recipient)).u64(a.amount).bytes() };
    case "register_key":
      return { mode: MODE.ACTION, flags, kind: KIND.register_key, params: new Writer().lp(a.publicKey).bytes() };
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
    default: throw new Error(`unknown action kind 0x${f.kind.toString(16)}`);
  }
  r.done();
  return a;
}

export function payerOf(tx: FrameTx): number {
  const f = tx.frames.find((x) => x.mode === MODE.VERIFY_PAYER);
  return f ? new Reader(f.params).u32() : tx.sender;
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
  actions: Action[];
}

/** An unsigned tx with zeroed signature slots of the final length, so the sighash is fixed. */
export function buildFrameTx(a: BuildArgs): FrameTx {
  const sponsored = a.payer !== undefined && a.payer !== a.sender;
  const frames = [verifySenderFrame(), ...(sponsored ? [verifyPayerFrame(a.payer!)] : []), ...a.actions.map(actionFrame)];
  const slot = (signer: number): Sig => ({ scheme: SCHEME_ML_DSA_87, signer, signature: new Uint8Array(ML_DSA_87_SIG_LEN) });
  return {
    version: FRAME_TX_VERSION, chainId: a.chainId, rollupId: a.rollupId, sender: a.sender, nonce: a.nonce,
    expiryBatch: a.expiryBatch, feeAsset: a.feeAsset ?? ASSET.QOR, maxFee: a.maxFee ?? 0n, frames,
    sigs: [slot(a.sender), ...(sponsored ? [slot(a.payer!)] : [])],
  };
}

/** Fill the signature slot of `signer` (the sender, or the sponsor). Deterministic ML-DSA-87. */
export function signFrameTx(tx: FrameTx, signer: number, secretKey: Uint8Array): FrameTx {
  const i = tx.sigs.findIndex((s) => s.signer === signer);
  if (i < 0) throw new Error(`no signature slot for account ${signer}`);
  const sig = pqSign(secretKey, sighash(tx));
  if (sig.length !== ML_DSA_87_SIG_LEN) throw new Error("unexpected ML-DSA-87 signature length");
  const sigs = tx.sigs.map((s, k) => (k === i ? { ...s, signature: sig } : s));
  return { ...tx, sigs };
}

// ---- validation (spec/frame-tx.md, rules 1-3) ----

export function structuralErrors(tx: FrameTx, expect: { chainId: string; rollupId: string }): string[] {
  const e: string[] = [];
  if (tx.version !== FRAME_TX_VERSION) e.push("version");
  if (tx.chainId !== expect.chainId) e.push("chain_id mismatch");
  if (tx.rollupId !== expect.rollupId) e.push("rollup_id mismatch");
  if (tx.feeAsset > 1) e.push("unknown fee asset");
  const modes = tx.frames.map((f) => f.mode);
  if (modes.filter((m) => m === MODE.VERIFY_SENDER).length !== 1) e.push("need exactly one VERIFY_SENDER frame");
  if (modes.filter((m) => m === MODE.VERIFY_PAYER).length > 1) e.push("at most one VERIFY_PAYER frame");
  const firstAction = modes.indexOf(MODE.ACTION);
  if (firstAction < 0) e.push("no ACTION frame");
  else if (modes.slice(firstAction).some((m) => m !== MODE.ACTION)) e.push("VERIFY frames must come before ACTION frames");
  if (modes.some((m) => m < 1 || m > 3)) e.push("unknown frame mode");
  for (const f of tx.frames) {
    if (f.mode !== MODE.ACTION && (f.kind !== 0 || f.flags !== 0)) e.push("VERIFY frames carry no kind or flags");
    if (f.mode === MODE.VERIFY_SENDER && f.params.length !== 0) e.push("VERIFY_SENDER has params");
    if (f.mode === MODE.VERIFY_PAYER && f.params.length !== 4) e.push("VERIFY_PAYER params must be a u32");
    if (f.mode === MODE.ACTION && (f.flags & ~FLAG_ATOMIC) !== 0) e.push("unknown frame flags");
  }
  let actions: Action[] = [];
  try { actions = actionsOf(tx); } catch (err) { e.push(`bad action: ${(err as Error).message}`); }
  if (actions.length > MAX_ACTIONS) e.push(`at most ${MAX_ACTIONS} actions in circuit v1`);
  for (const a of actions) {
    if (a.kind === "transfer" && a.asset > 1) e.push("unknown asset");
    if (a.kind === "withdraw" && (a.recipient.length !== RECIPIENT_LEN || !a.recipient.startsWith("qor1"))) {
      e.push("withdraw recipient must be a 42-character qor1 address");
    }
    if (a.kind === "register_key" && a.publicKey.length !== ML_DSA_87_PK_LEN) e.push("register_key needs a 2592-byte ML-DSA-87 key");
  }
  if (tx.sender === NEW_ACCOUNT) {
    if (actions[0]?.kind !== "register_key") e.push("a new account's first action must be register_key");
    if (tx.nonce !== 0n) e.push("a new account's nonce is 0");
  }
  const payer = (() => { try { return payerOf(tx); } catch { return tx.sender; } })();
  const want = payer === tx.sender ? [tx.sender] : [tx.sender, payer];
  const got = tx.sigs.map((s) => s.signer);
  if (got.length !== want.length || want.some((w, i) => got[i] !== w)) e.push(`signatures must be by [${want.join(", ")}] in that order`);
  for (const s of tx.sigs) {
    if (s.scheme !== SCHEME_ML_DSA_87) e.push("unknown signature scheme");
    if (s.signature.length !== ML_DSA_87_SIG_LEN) e.push("signature length");
  }
  return e;
}

/**
 * Rule 3: every signature verifies under the signer's key. `keyOf` returns the
 * registered ML-DSA-87 public key of an account index. A new account's key is
 * the one in its register_key frame.
 */
export function signatureErrors(tx: FrameTx, keyOf: (index: number) => Uint8Array | undefined): string[] {
  const e: string[] = [];
  const h = sighash(tx);
  for (const s of tx.sigs) {
    const pk = s.signer === NEW_ACCOUNT ? newAccountKey(tx) : keyOf(s.signer);
    if (!pk) { e.push(`no key for account ${s.signer}`); continue; }
    if (!pqVerify(pk, h, s.signature)) e.push(`bad signature by account ${s.signer}`);
  }
  return e;
}

/** pk_commit = SHAKE-256/32(ML-DSA-87 public key) mod r, as hex (spec/state.md). */
export function pkCommit(publicKey: Uint8Array): string {
  const h = createHash("shake256", { outputLength: 32 }).update(publicKey).digest("hex");
  return (BigInt("0x" + h) % BLS12_381_SCALAR_MODULUS).toString(16).padStart(64, "0");
}

// ---- to the prover's batch input ----

export interface LedgerTxIn {
  sender: number; payer: number; relayer: number; fee_asset: number; fee: number;
  actions: Array<
    | { kind: "transfer"; to: number; asset: number; amount: number; atomic?: boolean }
    | { kind: "withdraw"; recipient: string; amount: number; atomic?: boolean }
    | { kind: "register_key"; pk_commit: string; atomic?: boolean }
  >;
}

const num = (v: bigint) => { if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("amount too large for JSON"); return Number(v); };

/**
 * Map a validated, signature-checked tx to the prover input. The fee charged is
 * `max_fee` (flat, chosen by the user and accepted by the relayer). A new
 * account's sender index is assigned by the sequencer.
 */
export function toLedgerTx(tx: FrameTx, opts: { relayer: number; senderIndex?: number }): LedgerTxIn {
  const sender = tx.sender === NEW_ACCOUNT ? opts.senderIndex : tx.sender;
  if (sender === undefined) throw new Error("new account needs an assigned index");
  const payer = payerOf(tx) === NEW_ACCOUNT ? sender : payerOf(tx);
  return {
    sender, payer, relayer: opts.relayer, fee_asset: tx.feeAsset, fee: num(tx.maxFee),
    actions: actionsOf(tx).map((a) => {
      const atomic = a.atomic || undefined;
      switch (a.kind) {
        case "transfer": return { kind: "transfer", to: a.to, asset: a.asset, amount: num(a.amount), atomic };
        case "withdraw": return { kind: "withdraw", recipient: a.recipient, amount: num(a.amount), atomic };
        case "register_key": return { kind: "register_key", pk_commit: pkCommit(a.publicKey), atomic };
      }
    }),
  };
}

// ---- JSON (for files the wallet passes around) ----

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
export const frameTxToHex = (tx: FrameTx) => hex(encodeFrameTx(tx));
export const frameTxFromHex = (s: string) => decodeFrameTx(unhex(s.trim()));

// ---- batch bundle (the sealed post a batch's data_hash binds; spec/frame-tx.md) ----

export const BUNDLE_MAGIC = "cloister/bundle/v1";

/** magic ‖ u64 batch_index ‖ u8 count ‖ lp(frame tx)… */
export function encodeBundle(batchIndex: number, txs: FrameTx[]): Uint8Array {
  if (txs.length > 255) throw new Error("too many txs");
  const w = new Writer().raw(te.encode(BUNDLE_MAGIC)).u64(BigInt(batchIndex)).u8(txs.length);
  for (const t of txs) w.lp(encodeFrameTx(t));
  return w.bytes();
}

export function decodeBundle(bytes: Uint8Array): { batchIndex: number; txs: FrameTx[] } {
  const r = new Reader(bytes);
  if (td.decode(r.raw(BUNDLE_MAGIC.length)) !== BUNDLE_MAGIC) throw new Error("not a cloister bundle");
  const batchIndex = Number(r.u64());
  const n = r.u8();
  const txs: FrameTx[] = [];
  for (let i = 0; i < n; i++) txs.push(decodeFrameTx(r.lp(1 << 16)));
  r.done();
  return { batchIndex, txs };
}

/** Sequencer rule: a new account gets the lowest index above every account in use. */
export function nextFreeIndex(used: Iterable<number>): number {
  let max = -1;
  for (const i of used) max = Math.max(max, i);
  return max + 1;
}
