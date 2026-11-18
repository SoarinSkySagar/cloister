/**
 * Watchtower verdicts (spec/verdict.md). No Node imports: the CLI, the browser page
 * and the watchtower all use this file.
 */
import { shake256 } from "@noble/hashes/sha3";
import { pqSign, pqVerify } from "@qorechain/qoresign";
import type { RdkClient } from "@qorechain/rdk";

export const VERDICT_DOMAIN = "cloister/verdict/v1";
export interface Check { name: string; ok: boolean }
export interface Verdict {
  version: 1;
  chainId: string;
  rollupId: string;
  batchIndex: number;
  stateRoot: string;
  dataHash: string;
  watchtower: string;
  result: "pass" | "fail";
  scope: "bundle" | "link-only";
  checks: Check[];
  signedAt: number;
  signature: string;
}
export type Unsigned = Omit<Verdict, "signature">;

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));
/** Chain roots may come back without leading zeros or in upper case. */
export const normRoot = (s: string) => s.toLowerCase().replace(/^0x/, "").padStart(64, "0");

/** Structural problems that make a verdict unacceptable before any signature or chain check. */
export function verdictShapeErrors(v: Unsigned): string[] {
  const e: string[] = [];
  const noNl = (k: string, s: unknown) => { if (typeof s !== "string" || /[\n\r]/.test(s)) e.push(`${k} must be a single-line string`); };
  if (v.version !== 1) e.push("unsupported version");
  for (const [k, s] of [["chainId", v.chainId], ["rollupId", v.rollupId], ["watchtower", v.watchtower], ["result", v.result], ["scope", v.scope]] as const) noNl(k, s);
  if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(v.rollupId ?? "")) e.push("bad rollupId");
  if (!Number.isInteger(v.batchIndex) || v.batchIndex < 0) e.push("bad batchIndex");
  if (!/^[0-9a-f]{64}$/.test(v.stateRoot ?? "")) e.push("stateRoot must be 64 lower-case hex");
  if (!/^[0-9a-f]{64}$/.test(v.dataHash ?? "")) e.push("dataHash must be 64 lower-case hex");
  if (v.result !== "pass" && v.result !== "fail") e.push("result must be pass or fail");
  if (v.scope !== "bundle" && v.scope !== "link-only") e.push("scope must be bundle or link-only");
  if (!Number.isInteger(v.signedAt)) e.push("bad signedAt");
  if (!Array.isArray(v.checks) || !v.checks.length) e.push("checks required");
  else {
    const names = v.checks.map((c) => c?.name);
    if (names.some((n) => typeof n !== "string" || !/^[a-z]+$/.test(n))) e.push("check names must match [a-z]+");
    else if (names.some((n, i) => i > 0 && !(names[i - 1]! < n))) e.push("checks must be sorted by name, without duplicates");
    if (v.checks.some((c) => typeof c.ok !== "boolean")) e.push("check results must be boolean");
    if (v.result === "pass" && v.checks.some((c) => !c.ok)) e.push("result pass with a failing check");
  }
  return e;
}

export function verdictMessage(v: Unsigned): Uint8Array {
  const errs = verdictShapeErrors(v);
  if (errs.length) throw new Error(`invalid verdict: ${errs.join("; ")}`);
  const text = [
    VERDICT_DOMAIN, v.chainId, v.rollupId, String(v.batchIndex), v.stateRoot, v.dataHash, v.watchtower, v.result, v.scope,
    v.checks.map((c) => `${c.name}=${c.ok ? 1 : 0}`).join(","), String(v.signedAt),
  ].join("\n");
  return shake256(enc.encode(text), { dkLen: 32 });
}

export function signVerdict(u: Unsigned, secretKey: Uint8Array): Verdict {
  return { ...u, signature: hex(pqSign(secretKey, verdictMessage(u))) };
}

/** Sort checks by name (the signed message requires it). */
export const sortChecks = (c: Check[]) => [...c].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

export interface VerdictResult {
  valid: boolean;
  /** Present when the signature, key, membership and chain binding all hold. */
  result?: "pass" | "fail";
  problems: string[];
}

/** Accept a verdict only per spec/verdict.md: key from the chain, signer a member, roots as the chain holds them. */
export async function verifyVerdict(v: Verdict, client: RdkClient): Promise<VerdictResult> {
  const problems: string[] = [];
  const shape = verdictShapeErrors(v);
  if (shape.length) return { valid: false, problems: shape };
  try {
    const [rollup, batch, account] = await Promise.all([
      client.rest.getRollup(v.rollupId), client.rest.getBatch(v.rollupId, v.batchIndex), client.rest.getPqcAccount(v.watchtower),
    ]);
    if (client.network.chainId !== v.chainId) problems.push(`verdict is for chain ${v.chainId}, not ${client.network.chainId}`);
    if (!rollup.members.includes(v.watchtower)) problems.push("signer is not a current member of the rollup");
    if (normRoot(batch.stateRoot) !== v.stateRoot) problems.push("state root differs from the chain's");
    if (normRoot(batch.dataHash) !== v.dataHash) problems.push("data hash differs from the chain's");
    const pk = unhex(account.publicKey.replace(/^0x/, ""));
    if (!pk.length) problems.push("signer has no ML-DSA key on chain");
    else if (!pqVerify(pk, verdictMessage(v), unhex(v.signature))) problems.push("bad signature");
  } catch (e) {
    problems.push(`chain lookup failed: ${(e as Error).message}`);
  }
  return problems.length ? { valid: false, problems } : { valid: true, result: v.result, problems };
}

export function parseVerdicts(text: string): { verdicts: Verdict[] } | { error: string } {
  let j: unknown;
  try { j = JSON.parse(text); } catch { return { error: "not valid JSON" }; }
  const arr = Array.isArray(j) ? j : [j];
  if (!arr.length || arr.some((x) => !x || typeof x !== "object" || typeof (x as Verdict).signature !== "string")) return { error: "not a verdict (list)" };
  return { verdicts: arr as Verdict[] };
}
