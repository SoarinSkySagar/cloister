import { kemKeypairFromSeed, kemKeyFingerprint, signerFromEnv } from "@qorechain/rdk";
import { loadEnv } from "./env.ts";

/** Who holds which key. The operator is the rollup creator and sequencer. */
export type Role = "operator" | "watchtower" | "relayer";
export const ROLES: readonly Role[] = ["operator", "watchtower", "relayer"];

/** Env var holding each role's (testnet-only) mnemonic. */
export const MNEMONIC_ENV: Record<Role, string> = {
  operator: "QORE_MNEMONIC",
  watchtower: "WATCHTOWER_MNEMONIC",
  relayer: "RELAYER_MNEMONIC",
};

/** Rollup members hold an ML-KEM-1024 seed (64 bytes, d||z) to open envelopes. */
export const KEM_SEED_ENV: Partial<Record<Role, string>> = {
  operator: "CLOISTER_KEM_SEED_HEX",
  watchtower: "WATCHTOWER_KEM_SEED_HEX",
};

export function mnemonicFor(role: Role, env = loadEnv()): string | undefined {
  const v = env[MNEMONIC_ENV[role]]?.trim();
  return v ? v : undefined;
}

/** The role's qor1 address, or undefined if its mnemonic is not configured. */
export async function addressFor(role: Role, env = loadEnv()): Promise<string | undefined> {
  const mnemonic = mnemonicFor(role, env);
  if (!mnemonic) return undefined;
  const signer = await signerFromEnv({ QORE_MNEMONIC: mnemonic });
  const [account] = (await signer?.getAccounts()) ?? [];
  return account?.address;
}

/** The role's ML-KEM-1024 keypair, or undefined if it is not a member or has no seed. */
export function kemKeypairFor(role: Role, env = loadEnv()): { publicKey: Uint8Array; secretKey: Uint8Array } | undefined {
  const name = KEM_SEED_ENV[role];
  const seed = name ? env[name]?.trim() : undefined;
  return seed ? kemKeypairFromSeed(seed) : undefined;
}

/** Short, non-secret identifier for an encapsulation key (for logs). */
export function kemFingerprintHex(publicKey: Uint8Array): string {
  return Buffer.from(kemKeyFingerprint(publicKey)).toString("hex").slice(0, 16);
}
