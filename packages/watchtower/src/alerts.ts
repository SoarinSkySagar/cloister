/**
 * Alerts (design.md A6): what a member watchtower raises besides a failed batch check. Pure functions over data the
 * watchtower already fetches, so they are tested without a chain.
 *
 *   vk            a verification key was (re)set after the first batch, or is not the one committed in the repo, or is missing
 *   stall         no batch for too long, or posts waiting in the inbox that no batch consumed (based rollups)
 *   continuity    a batch whose prev_state_root is not the previous batch's state_root
 *   epoch         the membership epoch changed (members were added or removed)
 *   disagreement  two member watchtowers signed different results for the same batch
 *
 * The chain's REST view of a rollup says only whether a verification key exists (`hasVerificationKey`), never which one,
 * so `vk` needs the key-setting events as input (`VkEvent`). `fetchVkEvents` reads them from the transaction search
 * (tested against the live chain for a creation; a change by governance has not been observed). A missing event list is
 * "unknown", never "unchanged".
 */
export interface Alert { level: "critical" | "warning" | "info"; code: "vk" | "stall" | "continuity" | "epoch" | "disagreement"; detail: string }

export interface VkEvent { height: number; sha256: string; txHash?: string; setBy?: string }
export interface BatchLite { batchIndex: number; stateRoot: string; prevStateRoot: string; submittedAt: number; inboxEnd?: number }
export interface VerdictLite { watchtower: string; batchIndex: number; result: "pass" | "fail"; stateRoot: string }

const norm = (s: string) => s.toLowerCase().replace(/^0x/, "").replace(/^0+/, "");

export interface AlertInput {
  /** The chain's current block height. */
  height: number;
  rollup: { hasVerificationKey?: boolean; membersEpoch: number; sequencing: string };
  batches: BatchLite[];
  inbox?: { headSequence: number; consumedSequence: number };
  /** Key-setting events in order; undefined = could not be read. */
  vkEvents?: VkEvent[];
  /** sha256 of the verifying key as submitted: circuits/setup/<id>/vk.raw.bin, as hex. */
  pinnedVkSha256?: string;
  /** The epoch the watchtower saw last time (undefined: first run). */
  knownEpoch?: number;
  verdicts?: VerdictLite[];
  /** Blocks without a batch that count as a stall, and without a consumed inbox post. */
  stallBlocks?: number;
}

export function evaluateAlerts(a: AlertInput): Alert[] {
  const out: Alert[] = [];
  const stall = a.stallBlocks ?? 600;
  const batches = [...a.batches].sort((x, y) => x.batchIndex - y.batchIndex);

  // vk
  if (a.rollup.hasVerificationKey === false || a.rollup.hasVerificationKey === undefined) {
    out.push({ level: "critical", code: "vk", detail: "the rollup has no verification key registered: every zk batch is refused" });
  }
  if (a.vkEvents === undefined) {
    out.push({ level: "info", code: "vk", detail: "the key-setting transactions could not be read, so a key change cannot be ruled out" });
  } else {
    const first = batches[0];
    for (const e of a.vkEvents) {
      if (e.setBy && e.setBy !== "creator") {
        out.push({ level: "critical", code: "vk", detail: `the verification key was set by ${e.setBy} at height ${e.height}${e.txHash ? `: tx ${e.txHash}` : ""}` });
      }
      if (first && e.height > first.submittedAt) {
        out.push({ level: "critical", code: "vk", detail: `the verification key was set at height ${e.height}, after the first batch (height ${first.submittedAt})${e.txHash ? `: tx ${e.txHash}` : ""}: only governance can do that` });
      }
      if (a.pinnedVkSha256 && norm(e.sha256) !== norm(a.pinnedVkSha256)) {
        out.push({ level: "critical", code: "vk", detail: `the key set at height ${e.height} has sha256 ${e.sha256.slice(0, 16)}…, not the committed ${a.pinnedVkSha256.slice(0, 16)}…` });
      }
    }
    if (a.pinnedVkSha256 && a.vkEvents.length === 0) out.push({ level: "warning", code: "vk", detail: "no key-setting transaction was found for this rollup, so the committed key could not be compared" });
  }

  // continuity
  for (let i = 1; i < batches.length; i++) {
    if (batches[i]!.batchIndex !== batches[i - 1]!.batchIndex + 1) {
      out.push({ level: "critical", code: "continuity", detail: `batches ${batches[i - 1]!.batchIndex} and ${batches[i]!.batchIndex} are not consecutive` });
    } else if (norm(batches[i]!.prevStateRoot) !== norm(batches[i - 1]!.stateRoot)) {
      out.push({ level: "critical", code: "continuity", detail: `batch ${batches[i]!.batchIndex} starts from ${batches[i]!.prevStateRoot.slice(0, 16)}…, not from batch ${batches[i - 1]!.batchIndex}'s root` });
    }
  }

  // stall
  const last = batches[batches.length - 1];
  if (last && a.height - last.submittedAt > stall) {
    out.push({ level: "warning", code: "stall", detail: `no batch for ${a.height - last.submittedAt} blocks (last at ${last.submittedAt}, now ${a.height})` });
  }
  if (a.inbox && a.rollup.sequencing === "based" && a.inbox.headSequence > a.inbox.consumedSequence) {
    out.push({ level: "info", code: "stall", detail: `${a.inbox.headSequence - a.inbox.consumedSequence} post(s) wait in the inbox, consumed up to ${a.inbox.consumedSequence} of ${a.inbox.headSequence}` });
  }

  // epoch
  if (a.knownEpoch !== undefined && a.rollup.membersEpoch !== a.knownEpoch) {
    out.push({ level: "warning", code: "epoch", detail: `the membership epoch changed from ${a.knownEpoch} to ${a.rollup.membersEpoch}: members were added or removed` });
  }

  // disagreement between watchtowers
  const byBatch = new Map<number, VerdictLite[]>();
  for (const v of a.verdicts ?? []) byBatch.set(v.batchIndex, [...(byBatch.get(v.batchIndex) ?? []), v]);
  for (const [i, vs] of [...byBatch].sort((x, y) => x[0] - y[0])) {
    const results = new Set(vs.map((v) => v.result));
    const roots = new Set(vs.map((v) => norm(v.stateRoot)));
    if (results.size > 1) {
      out.push({ level: "critical", code: "disagreement", detail: `batch ${i}: ${vs.map((v) => `${v.watchtower.slice(0, 12)}… says ${v.result}`).join(", ")}` });
    }
    if (roots.size > 1) {
      out.push({ level: "critical", code: "disagreement", detail: `batch ${i}: the watchtowers signed different state roots` });
    }
  }
  return out;
}

/**
 * Key-setting events of a rollup, from the chain's transaction search: every transaction that sets a verification key
 * emits `rdk_verification_key_set` with the rollup id, who set it (`creator` or governance) and `key_sha256`, the SHA-256
 * of the key as submitted (the raw gnark encoding for our rollups: `vk.raw.bin`). Checked against the live chain on
 * 23 Nov for cloister-dev-5's creation (one event, hash equal to `sha256sum vk.raw.bin`). A key change by governance
 * has not been observed, so that path is tested only on fixtures.
 */
export async function fetchVkEvents(api: string, rollupId: string): Promise<VkEvent[] | undefined> {
  try {
    const out: VkEvent[] = [];
    for (let page = 1; ; page++) {
      const q = new URLSearchParams({ query: `rdk_verification_key_set.rollup_id='${rollupId}'`, order_by: "ORDER_BY_ASC", page: String(page), limit: "50" });
      const r = await fetch(`${api}/cosmos/tx/v1beta1/txs?${q}`);
      if (!r.ok) return undefined;
      const body = (await r.json()) as { tx_responses?: { height: string; txhash: string; events?: { type: string; attributes: { key: string; value: string }[] }[] }[] };
      const rows = body.tx_responses ?? [];
      for (const t of rows) {
        for (const e of t.events ?? []) {
          if (e.type !== "rdk_verification_key_set") continue;
          const at = Object.fromEntries(e.attributes.map((x) => [x.key, x.value]));
          if (at.rollup_id !== rollupId) continue;
          if (!at.key_sha256) return undefined; // an event shape this code does not know: do not pretend to have read it
          out.push({ height: Number(t.height), sha256: at.key_sha256, txHash: t.txhash, setBy: at.set_by });
        }
      }
      if (rows.length < 50) return out;
    }
  } catch {
    return undefined;
  }
}
