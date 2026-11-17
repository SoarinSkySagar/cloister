import { resolvePqcKeypair, signerFromEnv, type RdkClient, type RdkTxClient } from "@qorechain/rdk";
import { addressFor, mnemonicFor, type Role } from "./accounts.ts";
import { loadEnv } from "./env.ts";

export const QOR = 1_000_000n;
export const GAS_PRICE = "0.15uqor"; // floor is 0.1 uqor/gas

export function formatQor(uqor: bigint | string): string {
  const v = BigInt(uqor);
  const whole = v / QOR;
  const frac = (v % QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${whole}${frac ? "." + frac : ""} QOR`;
}

export interface PqcAccountView {
  registered: boolean;
  algorithm?: string;
  keyType?: string;
  possessionProven?: boolean;
}

/** The account's registered post-quantum key, from GET /qorechain/pqc/v1/account/{address}. */
export async function pqcAccount(rdk: RdkClient, address: string): Promise<PqcAccountView> {
  const res = await fetch(`${rdk.network.endpoints.rest}/qorechain/pqc/v1/account/${address}`);
  if (res.status === 404) return { registered: false };
  if (!res.ok) throw new Error(`pqc account query failed: HTTP ${res.status}`);
  const body = (await res.json()) as Record<string, any>;
  const acct = (body.account ?? body) as Record<string, any>;
  const hasKey = Boolean(acct.public_key ?? acct.publicKey ?? acct.pqc_public_key);
  return {
    registered: hasKey,
    algorithm: acct.algorithm_id !== undefined ? String(acct.algorithm_id) : acct.algorithm,
    keyType: acct.key_type ?? acct.keyType,
    possessionProven: acct.possession_proven ?? acct.possessionProven,
  };
}

/**
 * A hybrid-signing (secp256k1 + ML-DSA-87) tx client for a role. If the role's
 * PQ key is not on chain yet, the client registers it (MsgRegisterPQCKeyV2 with
 * proof of possession) in its own transaction before the first real one.
 */
export async function txClientFor(
  rdk: RdkClient,
  role: Role,
): Promise<{ tx: RdkTxClient; address: string; pqcAlreadyRegistered: boolean }> {
  const env = loadEnv();
  const mnemonic = mnemonicFor(role, env);
  const address = await addressFor(role, env);
  if (!mnemonic || !address) throw new Error(`${role}: mnemonic not set in .env`);
  const signer = await signerFromEnv({ QORE_MNEMONIC: mnemonic });
  if (!signer) throw new Error(`${role}: could not build a signer`);
  const pqc = await resolvePqcKeypair(rdk, address, mnemonic);
  const tx = await rdk.connectTx(signer, {
    pqcKeypair: pqc.keypair,
    includePqcPublicKey: pqc.includePqcPublicKey,
    gasPrice: GAS_PRICE,
  });
  return { tx, address, pqcAlreadyRegistered: pqc.registered };
}
