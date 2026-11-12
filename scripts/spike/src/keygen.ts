/**
 * Fill the repo .env with fresh TESTNET-ONLY keys for the roles we generate:
 * watchtower and relayer mnemonics, and ML-KEM-1024 seeds for the two rollup
 * members (operator and watchtower). Never overwrites an existing value and
 * never prints a secret: only addresses and key fingerprints.
 *
 * QORE_MNEMONIC (the funded operator account) is never generated here; the
 * human adds it.
 */
import { randomBytes } from "node:crypto";
import { generateMnemonic } from "@qorechain/rdk";
import {
  ENV_PATH, ROLES, addressFor, ensureEnvFile, fillEnvValues, kemFingerprintHex, kemKeypairFor, loadEnv, readEnvFile,
} from "@cloister/common";

const created = ensureEnvFile();
const current = readEnvFile();
const missing = (key: string) => !current[key]?.trim();

const fresh: Record<string, string> = {};
if (missing("WATCHTOWER_MNEMONIC")) fresh.WATCHTOWER_MNEMONIC = generateMnemonic();
if (missing("RELAYER_MNEMONIC")) fresh.RELAYER_MNEMONIC = generateMnemonic();
if (missing("CLOISTER_KEM_SEED_HEX")) fresh.CLOISTER_KEM_SEED_HEX = randomBytes(64).toString("hex");
if (missing("WATCHTOWER_KEM_SEED_HEX")) fresh.WATCHTOWER_KEM_SEED_HEX = randomBytes(64).toString("hex");

const filled = Object.keys(fresh).length ? fillEnvValues(fresh) : [];
console.log(`${created ? "created" : "updated"} ${ENV_PATH} (mode 600)`);
console.log(`generated: ${filled.length ? filled.join(", ") : "nothing (all set)"}`);

const env = loadEnv();
console.log("\nrole        address                                       ML-KEM key");
for (const role of ROLES) {
  const address = (await addressFor(role, env)) ?? "(not set: add QORE_MNEMONIC to .env)";
  const kem = kemKeypairFor(role, env);
  console.log(`${role.padEnd(11)} ${address.padEnd(45)} ${kem ? kemFingerprintHex(kem.publicKey) : "-"}`);
}
