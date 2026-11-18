/**
 * Named identities (the three roles plus wallet users) and their keys.
 * A Cloister account uses the same ML-DSA-87 key as its owner's L1 account,
 * so one mnemonic signs on both layers and pk_commit is derivable from the
 * chain's PQC registry.
 */
import { resolvePqcKeypair, signerFromEnv, type RdkClient } from "@qorechain/rdk";
import { MNEMONIC_ENV, ROLES, type Role } from "./accounts.ts";
import { loadEnv } from "./env.ts";
import { pkCommit } from "./frametx.ts";

export const USER_ENV_PREFIX = "CLOISTER_USER_";
export const userEnvName = (name: string) => `${USER_ENV_PREFIX}${name.toUpperCase()}_MNEMONIC`;

export interface Identity {
  name: string;
  address: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  pkCommit: string;
}

export function isValidUserName(name: string) {
  return /^[a-z][a-z0-9]{1,15}$/.test(name) && !(ROLES as readonly string[]).includes(name);
}

export function mnemonicForName(name: string, env = loadEnv()): string | undefined {
  const key = (ROLES as readonly string[]).includes(name) ? MNEMONIC_ENV[name as Role] : userEnvName(name);
  return env[key]?.trim() || undefined;
}

/** All names with a mnemonic configured in .env. */
export function knownNames(env = loadEnv()): string[] {
  const users = Object.keys(env)
    .filter((k) => k.startsWith(USER_ENV_PREFIX) && k.endsWith("_MNEMONIC") && env[k])
    .map((k) => k.slice(USER_ENV_PREFIX.length, -"_MNEMONIC".length).toLowerCase());
  return [...ROLES.filter((r) => mnemonicForName(r, env)), ...users];
}

export async function identity(rdk: RdkClient, name: string, env = loadEnv()): Promise<Identity> {
  const mnemonic = mnemonicForName(name, env);
  if (!mnemonic) throw new Error(`no mnemonic for "${name}" in .env`);
  const signer = await signerFromEnv({ QORE_MNEMONIC: mnemonic });
  const [account] = (await signer?.getAccounts()) ?? [];
  if (!account) throw new Error(`could not derive an address for "${name}"`);
  const { keypair } = await resolvePqcKeypair(rdk, account.address, mnemonic);
  return { name, address: account.address, publicKey: keypair.publicKey, secretKey: keypair.secretKey, pkCommit: pkCommit(keypair.publicKey) };
}

export async function allIdentities(rdk: RdkClient, env = loadEnv()): Promise<Identity[]> {
  return Promise.all(knownNames(env).map((n) => identity(rdk, n, env)));
}

// ---- rollup state view ----

export interface StateAccount { index: number; pk_commit: string; qor: number; usd: number; nonce: number }
export interface RollupState { batches: number; root: string; accounts: StateAccount[] }

export const findByCommit = (s: RollupState, commit: string) => s.accounts.find((a) => a.pk_commit === commit);
