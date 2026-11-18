/**
 * Receipt verification, shared by the CLI and the web page (no Node imports).
 * A receipt is only a claim: verifySettlementReceipt re-reads the rollup, the
 * batch, the anchor and the signing key from the chain, so a fabricated or
 * altered receipt cannot pass.
 */
import { verifyVerdict, type Verdict, type VerdictResult } from "./verdict.ts";
import { receiptSchemaError, verifySettlementReceipt, type RdkClient, type SettlementReceipt } from "@qorechain/rdk";

export interface ReceiptVerdict {
  valid: boolean;
  mode: string;
  checks: { name: string; ok: boolean; detail: string }[];
  error?: string;
}

const show = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x)));

/** Parse untrusted text into a receipt, or say why it is not one. */
export function parseReceipt(text: string): { receipt: SettlementReceipt } | { error: string } {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return { error: "not valid JSON" }; }
  if (!j || typeof j !== "object") return { error: "not a receipt object" };
  const r = j as SettlementReceipt;
  for (const k of ["rollupId", "stateRoot", "pqcSignature", "creator"] as const) {
    if (typeof r[k] !== "string") return { error: `missing field ${k}` };
  }
  if (!Number.isInteger(r.batchIndex)) return { error: "missing field batchIndex" };
  const bad = receiptSchemaError(r);
  return bad ? { error: bad } : { receipt: r };
}

export async function verifyReceipt(receipt: SettlementReceipt, client: RdkClient): Promise<ReceiptVerdict> {
  try {
    const res = (await verifySettlementReceipt(receipt, { client })) as { valid: boolean; mode?: string; checks?: Record<string, unknown>; reason?: string; error?: string };
    const checks = Object.entries(res.checks ?? {}).map(([name, v]) => {
      const ok = v === true || (typeof v === "object" && v !== null && (v as { ok?: boolean; status?: string }).ok === true) || (typeof v === "object" && v !== null && (v as { status?: string }).status === "pass");
      return { name, ok, detail: show(v) };
    });
    return { valid: !!res.valid, mode: res.mode ?? "?", checks, error: res.valid ? undefined : res.reason ?? res.error };
  } catch (e) {
    return { valid: false, mode: "error", checks: [], error: (e as Error).message };
  }
}

export interface CoSignature { verdict: Verdict; check: VerdictResult }

/** Verify the member watchtower verdicts published for a receipt's batch. A verdict for another batch is refused, not ignored. */
export async function checkVerdicts(receipt: SettlementReceipt, verdicts: Verdict[], client: RdkClient): Promise<CoSignature[]> {
  return Promise.all(verdicts.map(async (verdict) => {
    if (verdict.rollupId !== receipt.rollupId || verdict.batchIndex !== receipt.batchIndex) {
      return { verdict, check: { valid: false, problems: [`verdict is for ${verdict.rollupId} batch ${verdict.batchIndex}, not this receipt`] } };
    }
    return { verdict, check: await verifyVerdict(verdict, client) };
  }));
}

/** One line for humans: how many member watchtowers vouch for the batch. */
export function summarize(co: CoSignature[]): string {
  const ok = co.filter((c) => c.check.valid && c.check.result === "pass").length;
  const failed = co.filter((c) => c.check.valid && c.check.result === "fail").length;
  const unv = co.filter((c) => c.check.unverifiable).length;
  const bad = co.filter((c) => !c.check.valid && !c.check.unverifiable).length;
  if (!co.length) return "no member watchtower verdict published";
  return [`checked by ${ok} member watchtower(s)`, failed ? `${failed} reported a FAILED check` : "", bad ? `${bad} verdict(s) INVALID` : "", unv ? `${unv} could not be verified (chain unreachable)` : ""].filter(Boolean).join("; ");
}
