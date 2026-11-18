/**
 * The transaction digest (spec/inclusion.md, "Transaction digest"): a field element committing to everything a
 * transaction's signers wrote. The circuit computes it from the same witness it executes and stores it in the
 * record, so a user can recompute it from the transaction they signed and compare. A record whose digest differs
 * is not their transaction; a record whose digest matches shows exactly what was done with it, including which
 * actions did not apply (those appear as zero moves).
 */
import { shake256 } from "@noble/hashes/sha3";
import { md, P } from "./poseidon2.ts";
import { DEFAULT_SHAPE, recipientCommit, type InclusionShape } from "./inclusion.ts";

export const DIGEST_TAG = 2n;
/** The sender index a signed transaction carries when it creates its own account. */
export const NEW_ACCOUNT_SENDER = 0xffffffff;
const MAX_U64 = (1n << 64n) - 1n;
const te = new TextEncoder();

/** SHAKE-256/32("cloister/domain/v1" ‖ u32 len ‖ chain ‖ u32 len ‖ rollup) read mod r. */
export function domainConst(chainId: string, rollupId: string): bigint {
  const part = (s: string) => { const b = te.encode(s); const l = new Uint8Array(4); new DataView(l.buffer).setUint32(0, b.length); return [l, b]; };
  const chunks = [te.encode("cloister/domain/v1"), ...part(chainId), ...part(rollupId)];
  const msg = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) { msg.set(c, o); o += c.length; }
  const out = shake256(msg, { dkLen: 32 });
  return BigInt("0x" + Buffer.from(out).toString("hex")) % P;
}

/** One action in the form the digest commits to: fields that do not apply to the kind are zero. */
export interface PlannedAction { code: number; asset: number; amount: bigint; from: number; to: number; aux: bigint; atomic: boolean }

/** The digest of already-normalised terms (what the golden vectors list). */
export function digestOfTerms(t: {
  chainId: string; rollupId: string; signedSender: number; nonce: bigint; expiry: bigint; notBefore: bigint; payer: number;
  feeAsset: number; maxFee: bigint; parties: number[]; actions: PlannedAction[];
}, shape: InclusionShape = DEFAULT_SHAPE): bigint {
  const actionSlots = shape.moves - 1;
  if (t.parties.length > shape.partySlots || t.actions.length > actionSlots) throw new Error("more parties or actions than the circuit has slots");
  const f: bigint[] = [DIGEST_TAG, domainConst(t.chainId, t.rollupId), BigInt(t.signedSender), t.nonce, t.expiry, t.notBefore, BigInt(t.payer), BigInt(t.feeAsset), t.maxFee];
  for (let i = 0; i < shape.partySlots; i++) f.push(i < t.parties.length ? BigInt(t.parties[i]!) + 1n : 0n);
  for (let i = 0; i < actionSlots; i++) {
    const a = t.actions[i];
    f.push(...(a ? [BigInt(a.code), BigInt(a.asset), a.amount, BigInt(a.from), BigInt(a.to), a.aux, a.atomic ? 1n : 0n] : [0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  }
  return md(f);
}

/** The prover's view of a transaction (@cloister/common `LedgerTxIn`, `toLedgerTx`). */
export interface DigestTx {
  sender: number; payer: number; fee_asset: number; fee: number; max_fee?: number; new_account?: boolean;
  parties?: number[]; expiry?: number; not_before?: number;
  actions: Array<{ kind: "transfer" | "withdraw" | "register_key"; from?: number; to?: number; asset?: number; amount?: number; recipient?: string; pk_commit?: string; atomic?: boolean }>;
}

/**
 * The digest of a transaction as the prover received it. `nonce` is the signed nonce. For a new account `sender` is the
 * index the sequencer assigned (the record shows it); the digest itself carries the sentinel for the sender.
 */
export function txDigest(chainId: string, rollupId: string, nonce: bigint, tx: DigestTx, shape: InclusionShape = DEFAULT_SHAPE): bigint {
  const fee = BigInt(tx.fee);
  const actions: PlannedAction[] = tx.actions.map((a) => {
    const from = a.from ?? tx.sender;
    const atomic = !!a.atomic;
    switch (a.kind) {
      case "transfer": return { code: 1, asset: a.asset ?? 0, amount: BigInt(a.amount ?? 0), from, to: a.to ?? 0, aux: 0n, atomic };
      case "withdraw": return { code: 2, asset: a.asset ?? 0, amount: BigInt(a.amount ?? 0), from, to: 0, aux: recipientCommit(a.recipient ?? ""), atomic };
      case "register_key": return { code: 3, asset: 0, amount: 0n, from, to: 0, aux: BigInt("0x" + (a.pk_commit || "0")), atomic };
    }
  });
  return digestOfTerms({
    chainId, rollupId, signedSender: tx.new_account ? NEW_ACCOUNT_SENDER : tx.sender, nonce,
    expiry: tx.expiry === undefined ? MAX_U64 : BigInt(tx.expiry), notBefore: BigInt(tx.not_before ?? 0),
    payer: tx.payer, feeAsset: fee > 0n ? tx.fee_asset : 0, maxFee: BigInt(tx.max_fee ?? tx.fee), parties: tx.parties ?? [], actions,
  }, shape);
}

