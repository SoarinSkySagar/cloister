import { createRdkClient, type RdkClient } from "@qorechain/rdk";

/** Cloister runs on QoreChain testnet only. */
export const CHAIN_ID = "qorechain-diana" as const;

/** Final rollup id. Dev cycles use `cloister-dev-N` (see design.md). */
export const FINAL_ROLLUP_ID = "cloister" as const;

/** Rollup and layer ids must match this (x/rdk, x/multilayer since v3.2.2). */
export const ROLLUP_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{2,63}$/;

export function isValidRollupId(id: string): boolean {
  return ROLLUP_ID_PATTERN.test(id);
}

/** Dev rollup id for cycle `n` (n >= 1). */
export function devRollupId(n: number): string {
  if (!Number.isInteger(n) || n < 1) throw new Error(`dev cycle must be a positive integer, got ${n}`);
  return `cloister-dev-${n}`;
}

/** Testnet RDK client. Read-only until a signer is attached. */
export function testnetClient(): RdkClient {
  const client = createRdkClient({ network: "testnet" });
  if (client.network.chainId !== CHAIN_ID) {
    throw new Error(`expected ${CHAIN_ID}, RDK resolved ${client.network.chainId}`);
  }
  return client;
}
