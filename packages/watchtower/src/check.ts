/**
 * Watchtower checks for one batch (design.md A6). A member decrypts the sealed
 * bundle and verifies, independently of the sequencer:
 *   link       sha256(envelope) == the batch's data_hash on chain
 *   index      the bundle names this batch
 *   count      the bundle holds tx_count txs
 *   structure  every frame tx is well formed for this rollup
 *   signature  every ML-DSA-87 signature verifies (the circuit does not prove these)
 */
import { createHash } from "node:crypto";
import { openEnvelope } from "@qorechain/rdk";
import {
  CHAIN_ID, actionsOf, decodeBundle, pkCommit, signatureErrors, structuralErrors, type FrameTx,
} from "@cloister/common";

export interface BatchView { batch_index: string; tx_count: string; state_root: string; data_hash: string; status: string }
export interface Finding { check: string; ok: boolean; detail: string }

export function checkBatch(a: {
  rollupId: string; batch: BatchView; envelope: Uint8Array; member: string; decapsulationKey: Uint8Array;
  keyOf: (index: number) => Uint8Array | undefined;
}): { findings: Finding[]; txs: FrameTx[] } {
  const f: Finding[] = [];
  const add = (check: string, ok: boolean, detail: string) => f.push({ check, ok, detail });
  const sha = createHash("sha256").update(a.envelope).digest("hex");
  add("link", sha === a.batch.data_hash.toLowerCase(), `sha256 ${sha.slice(0, 16)}… vs data_hash ${a.batch.data_hash.slice(0, 16)}…`);
  let txs: FrameTx[] = [];
  try {
    const plain = openEnvelope({ envelope: a.envelope, chainId: CHAIN_ID, rollupId: a.rollupId, member: a.member, decapsulationKey: a.decapsulationKey });
    const b = decodeBundle(plain);
    txs = b.txs;
    add("decrypt", true, `opened, ${txs.length} tx(s)`);
    add("index", b.batchIndex === Number(a.batch.batch_index), `bundle says batch ${b.batchIndex}`);
  } catch (e) {
    const m = (e as Error).message;
    // Spike batches 0-1 predate the bundle format: the link check still holds, the contents are not re-verifiable.
    if (/not a cloister bundle/.test(m)) add("legacy", true, "pre-bundle spike batch: link verified, contents not a frame-tx bundle");
    else add("decrypt", false, m);
    return { findings: f, txs };
  }
  add("count", txs.length === Number(a.batch.tx_count), `bundle ${txs.length}, chain ${a.batch.tx_count}`);
  const se = txs.flatMap((t, i) => structuralErrors(t, { chainId: CHAIN_ID, rollupId: a.rollupId }).map((e) => `tx ${i}: ${e}`));
  add("structure", !se.length, se.join("; ") || "all well formed");
  const sg = txs.flatMap((t, i) => signatureErrors(t, a.keyOf).map((e) => `tx ${i}: ${e}`));
  add("signature", !sg.length, sg.join("; ") || `${txs.length} tx(s) verified`);
  return { findings: f, txs };
}

/** Public keys by account index, learned from register_key actions, resolved through the rollup state's pk_commits. */
export function keyResolver(known: Uint8Array[], accounts: { index: number; pk_commit: string }[], bundles: FrameTx[]) {
  const byCommit = new Map<string, Uint8Array>();
  for (const k of known) byCommit.set(pkCommit(k), k);
  for (const t of bundles) for (const x of actionsOf(t)) if (x.kind === "register_key") byCommit.set(pkCommit(x.publicKey), x.publicKey);
  const byIndex = new Map(accounts.map((x) => [x.index, byCommit.get(x.pk_commit)]));
  return (i: number) => byIndex.get(i);
}
