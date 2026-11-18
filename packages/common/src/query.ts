/**
 * Authenticated account queries. Balances on a private rollup are only shown
 * to the account's owner: the request carries the owner's ML-DSA-87 public key
 * and a signature over a fresh timestamp, bound to the rollup and the endpoint.
 */
import { createHash } from "node:crypto";
import { pqSign, pqVerify } from "@qorechain/qoresign";
import { pkCommit } from "./frametx.ts";

export const QUERY_DOMAIN = "cloister/query/v1";
export const QUERY_MAX_SKEW_MS = 120_000;

export interface AccountQuery { rollup_id: string; public_key: string; ts: number; signature: string }

const message = (rollupId: string, publicKey: Uint8Array, ts: number) =>
  createHash("shake256", { outputLength: 32 })
    .update(`${QUERY_DOMAIN}|${rollupId}|${ts}|`).update(publicKey).digest();

export function signAccountQuery(rollupId: string, publicKey: Uint8Array, secretKey: Uint8Array, now = Date.now()): AccountQuery {
  return {
    rollup_id: rollupId, public_key: Buffer.from(publicKey).toString("hex"), ts: now,
    signature: Buffer.from(pqSign(secretKey, message(rollupId, publicKey, now))).toString("hex"),
  };
}

/** The pk_commit of a valid, fresh query for this rollup, or an error string. */
export function verifyAccountQuery(q: AccountQuery, rollupId: string, now = Date.now()): { pkCommit: string } | { error: string } {
  if (q.rollup_id !== rollupId) return { error: "wrong rollup" };
  if (!Number.isInteger(q.ts) || Math.abs(now - q.ts) > QUERY_MAX_SKEW_MS) return { error: "stale or future timestamp" };
  const pk = new Uint8Array(Buffer.from(q.public_key ?? "", "hex"));
  const sig = new Uint8Array(Buffer.from(q.signature ?? "", "hex"));
  if (!pqVerify(pk, message(rollupId, pk, q.ts), sig)) return { error: "bad signature" };
  return { pkCommit: pkCommit(pk) };
}
