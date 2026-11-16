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

/** An unsigned tx with zeroed signature slots of the final length, so the sighash is fixed. */
export function buildFrameTx(a: BuildArgs): FrameTx {
  const sponsored = a.payer !== undefined && a.payer !== a.sender;
  const parties = a.parties ?? [];
  // canonical order: sender, parties, payer, guard, actions (one encoding per meaning)
  const frames = [
    verifySenderFrame(), ...parties.map(verifyPartyFrame), ...(sponsored ? [verifyPayerFrame(a.payer!)] : []),
    ...(a.notBefore ? [guardFrame(a.notBefore)] : []), ...a.actions.map(actionFrame),
  ];
  const slot = (signer: number): Sig => ({ scheme: SCHEME_ML_DSA_87, signer, signature: new Uint8Array(ML_DSA_87_SIG_LEN) });
  const tx: FrameTx = {
    version: FRAME_TX_VERSION, chainId: a.chainId, rollupId: a.rollupId, sender: a.sender, nonce: a.nonce,
    expiryBatch: a.expiryBatch, feeAsset: a.feeAsset ?? ASSET.QOR, maxFee: a.maxFee ?? 0n, frames, sigs: [],
  };
  return { ...tx, sigs: signersOf(tx).map(slot) };
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

const RANK: Record<number, number> = {
  [MODE.VERIFY_SENDER]: 0, [MODE.VERIFY_PARTY]: 1, [MODE.VERIFY_PAYER]: 2, [MODE.GUARD]: 3, [MODE.ACTION]: 4,
};

export function structuralErrors(tx: FrameTx, expect: { chainId: string; rollupId: string }): string[] {
  const e: string[] = [];
  if (tx.version !== FRAME_TX_VERSION) e.push("version");
  if (tx.chainId !== expect.chainId) e.push("chain_id mismatch");
  if (tx.rollupId !== expect.rollupId) e.push("rollup_id mismatch");
  if (tx.feeAsset > 1) e.push("unknown fee asset");
  const modes = tx.frames.map((f) => f.mode);
  const count = (m: number) => modes.filter((x) => x === m).length;
  if (modes.some((m) => !(m in RANK))) e.push("unknown frame mode");
  if (count(MODE.VERIFY_SENDER) !== 1) e.push("need exactly one VERIFY_SENDER frame");
  if (count(MODE.VERIFY_PAYER) > 1) e.push("at most one VERIFY_PAYER frame");
  if (count(MODE.VERIFY_PARTY) > MAX_PARTIES) e.push(`at most ${MAX_PARTIES} VERIFY_PARTY frames`);
  if (count(MODE.GUARD) > 1) e.push("at most one GUARD frame");
  if (count(MODE.ACTION) < 1) e.push("no ACTION frame");
  // one canonical order: sender, parties, payer, guard, actions
  const ranks = modes.map((m) => RANK[m] ?? 99);
  if (ranks.some((r, i) => i > 0 && r < ranks[i - 1]!)) e.push("frames must be ordered: sender, parties, payer, guard, actions");
  for (const f of tx.frames) {
    if (f.mode !== MODE.ACTION && (f.kind !== 0 || f.flags !== 0)) e.push("VERIFY and GUARD frames carry no kind or flags");
    if (f.mode === MODE.VERIFY_SENDER && f.params.length !== 0) e.push("VERIFY_SENDER has params");
    if (f.mode === MODE.VERIFY_PAYER && f.params.length !== 4) e.push("VERIFY_PAYER params must be a u32");
    if (f.mode === MODE.VERIFY_PARTY && f.params.length !== 4) e.push("VERIFY_PARTY params must be a u32");
    if (f.mode === MODE.GUARD && f.params.length !== 8) e.push("GUARD params must be a u64");
    if (f.mode === MODE.ACTION && (f.flags & ~FLAG_ATOMIC) !== 0) e.push("unknown frame flags");
  }
  let actions: Action[] = [];
  try { actions = actionsOf(tx); } catch (err) { e.push(`bad action: ${(err as Error).message}`); }
  if (actions.length > MAX_ACTIONS) e.push(`at most ${MAX_ACTIONS} actions`);

  // parties: distinct, not the sender, valid accounts
  let parties: number[] = [];
  try { parties = partiesOf(tx); } catch { /* reported above */ }
  if (new Set(parties).size !== parties.length) e.push("parties must be distinct");
  if (parties.includes(tx.sender)) e.push("a party cannot be the sender");
  if (parties.some((p) => p >= ACCOUNT_LIMIT)) e.push("party is not a valid account index");
  if (tx.sender !== NEW_ACCOUNT && tx.sender >= ACCOUNT_LIMIT) e.push("sender is not a valid account index");

  const payer = (() => { try { return payerOf(tx); } catch { return tx.sender; } })();
  if (payer !== NEW_ACCOUNT && payer >= ACCOUNT_LIMIT) e.push("payer is not a valid account index");
  const authorised = new Set([tx.sender, ...parties]);
  for (const a of actions) {
    if ((a.kind === "transfer" || a.kind === "transfer_from") && a.asset > 1) e.push("unknown asset");
    if ((a.kind === "transfer" || a.kind === "transfer_from") && a.to >= ACCOUNT_LIMIT) e.push("transfer to an invalid account index");
    if ((a.kind === "withdraw" || a.kind === "withdraw_from") && (a.recipient.length !== RECIPIENT_LEN || !a.recipient.startsWith("qor1"))) {
      e.push("withdraw recipient must be a 42-character qor1 address");
    }
    if (a.kind === "register_key" && a.publicKey.length !== ML_DSA_87_PK_LEN) e.push("register_key needs a 2592-byte ML-DSA-87 key");
    if ((a.kind === "transfer_from" || a.kind === "withdraw_from") && !authorised.has(a.from)) {
      e.push(`${a.kind} debits account ${a.from}, which is neither the sender nor a party`);
    }
  }
  if (tx.sender === NEW_ACCOUNT) {
    if (actions[0]?.kind !== "register_key") e.push("a new account's first action must be register_key");
    if (tx.nonce !== 0n) e.push("a new account's nonce is 0");
    if (parties.length) e.push("a new account's tx has no parties");
    if (actions.some((a) => a.kind === "transfer_from" || a.kind === "withdraw_from")) e.push("a new account's tx cannot use transfer_from or withdraw_from");
  }

  const want = (() => { try { return signersOf(tx); } catch { return [tx.sender]; } })();
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
  /** VERIFY_PARTY accounts. */
  parties?: number[];
  /** Last batch index the tx is valid in, and the first (GUARD); capped at 2^53-1 (see toLedgerTx). */
  expiry?: number; not_before?: number;
  /** The fee ceiling the payer signed (the fee charged is the signed max fee) and whether the signed sender was NEW_ACCOUNT. */
  max_fee?: number; new_account?: boolean;
  actions: Array<
    | { kind: "transfer"; from?: number; to: number; asset: number; amount: number; atomic?: boolean }
    | { kind: "withdraw"; from?: number; recipient: string; amount: number; atomic?: boolean }
    | { kind: "register_key"; pk_commit: string; atomic?: boolean }
  >;
}

const num = (v: bigint) => { if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("amount too large for JSON"); return Number(v); };
/** Batch indexes beyond 2^53-1 cannot be reached, so a larger bound means "never" (not_before) or "no expiry". */
const capBatch = (v: bigint) => Number(v > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : v);

/**
 * Map a validated, signature-checked tx to the prover input. The fee charged is
 * `max_fee` (flat, chosen by the user and accepted by the relayer). A new
 * account's sender index is assigned by the sequencer.
 */
export function toLedgerTx(tx: FrameTx, opts: { relayer: number; senderIndex?: number }): LedgerTxIn {
  const sender = tx.sender === NEW_ACCOUNT ? opts.senderIndex : tx.sender;
  if (sender === undefined) throw new Error("new account needs an assigned index");
  const payer = payerOf(tx) === NEW_ACCOUNT ? sender : payerOf(tx);
  const parties = partiesOf(tx);
  const notBefore = notBeforeOf(tx);
  return {
    sender, payer, relayer: opts.relayer, fee_asset: tx.feeAsset, fee: num(tx.maxFee), max_fee: num(tx.maxFee),
    ...(tx.sender === NEW_ACCOUNT ? { new_account: true } : {}),
    ...(parties.length ? { parties } : {}),
    expiry: capBatch(tx.expiryBatch), ...(notBefore ? { not_before: capBatch(notBefore) } : {}),
    actions: actionsOf(tx).map((a) => {
      const atomic = a.atomic || undefined;
      switch (a.kind) {
        case "transfer": return { kind: "transfer", to: a.to, asset: a.asset, amount: num(a.amount), atomic };
        case "withdraw": return { kind: "withdraw", recipient: a.recipient, amount: num(a.amount), atomic };
        case "transfer_from": return { kind: "transfer", from: a.from, to: a.to, asset: a.asset, amount: num(a.amount), atomic };
        case "withdraw_from": return { kind: "withdraw", from: a.from, recipient: a.recipient, amount: num(a.amount), atomic };
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

/** Padded bundle sizes: 4 KiB, doubling (a post is at most 128 KiB). */
export const BUNDLE_PAD_MIN = 4096;
export const BUNDLE_PAD_MAX = 128 * 1024;

/** The smallest bucket that holds `n` bytes: 4096, 8192, 16384, … */
export function padBucket(n: number): number {
  let b = BUNDLE_PAD_MIN;
  while (b < n) b *= 2;
  return b;
}

/**
 * magic ‖ u64 batch_index ‖ u8 count ‖ lp(frame tx)… [‖ u32 pad_len ‖ pad_len zero bytes]
 *
 * With `pad: true` the plaintext is padded with zeros to the next bucket size (4 KiB, 8 KiB, 16 KiB, …), so the size
 * of the sealed post says only which bucket a batch fell into. A signed transaction is several KiB (an ML-DSA-87
 * signature is 4,627 bytes), so buckets still tell one transaction from three; `fixed: BUNDLE_PAD_MAX` hides the count
 * entirely (spec/frame-tx.md, "Bundle"). Bundles without the pad trailer (every batch of the dev rollups so far) still decode.
 */
export function encodeBundle(batchIndex: number, txs: FrameTx[], opts: { pad?: boolean; fixed?: number } = {}): Uint8Array {
  if (txs.length > 255) throw new Error("too many txs");
  const w = new Writer().raw(te.encode(BUNDLE_MAGIC)).u64(BigInt(batchIndex)).u8(txs.length);
  for (const t of txs) w.lp(encodeFrameTx(t));
  const body = w.bytes();
  if (!opts.pad && !opts.fixed) return body;
  // `fixed`: every bundle is exactly this long, so the size says nothing at all (it costs the same post fee every batch)
  const target = opts.fixed ?? padBucket(body.length + 4);
  if (target < body.length + 4) throw new Error(`bundle of ${body.length} bytes does not fit the fixed size ${target}`);
  if (target > BUNDLE_PAD_MAX) throw new Error(`bundle of ${body.length} bytes does not fit a ${BUNDLE_PAD_MAX}-byte post once padded`);
  const out = new Uint8Array(target);
  out.set(body, 0);
  new DataView(out.buffer).setUint32(body.length, target - body.length - 4);
  return out;
}

export function decodeBundle(bytes: Uint8Array): { batchIndex: number; txs: FrameTx[] } {
  const r = new Reader(bytes);
  if (td.decode(r.raw(BUNDLE_MAGIC.length)) !== BUNDLE_MAGIC) throw new Error("not a cloister bundle");
  const batchIndex = Number(r.u64());
  const n = r.u8();
  const txs: FrameTx[] = [];
  for (let i = 0; i < n; i++) txs.push(decodeFrameTx(r.lp(1 << 16)));
  if (!r.atEnd) {
    // the padding trailer: a length and that many zero bytes, nothing else (a non-zero byte could carry a covert message)
    const len = r.u32();
    const pad = r.raw(len);
    if (pad.some((x) => x !== 0)) throw new Error("bundle padding must be zero");
  }
  r.done();
  return { batchIndex, txs };
}

/**
 * Sequencer rule: a new account gets the lowest index above every account in use. The last leaf of the
 * tree is the reserved log leaf, so the rollup is full at ACCOUNT_LIMIT accounts.
 */
export function nextFreeIndex(used: Iterable<number>): number {
  let max = -1;
  for (const i of used) if (i < ACCOUNT_LIMIT) max = Math.max(max, i);
  if (max + 1 >= ACCOUNT_LIMIT) throw new Error("the rollup has no free account index");
  return max + 1;
}
