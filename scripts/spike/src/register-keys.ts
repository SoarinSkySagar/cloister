/**
 * Register the rollup members' keys on testnet:
 *   - ML-DSA-87 (hybrid) with proof of possession: sent automatically by the
 *     tx client as its own transaction if the account has no key yet;
 *   - ML-KEM-1024 encapsulation key in the chain's KEM registry.
 *
 * Members are the operator (sequencer) and the watchtower.
 * Dry run by default; pass --send to broadcast. Appends tx hashes to PROOF.md.
 */
import { appendFileSync } from "node:fs";
import { join } from "node:path";
import {
  REPO_ROOT, addressFor, formatQor, kemKeypairFor, loadEnv, testnetClient, txClientFor, type Role,
} from "@cloister/common";

const SEND = process.argv.includes("--send");
const MEMBERS: Role[] = ["operator", "watchtower"];
const MIN_BALANCE_UQOR = 1_000_000n; // 1 QOR covers both registrations with room to spare

const rdk = testnetClient();
const env = loadEnv();

function proof(what: string, hash: string) {
  const line = `| ${new Date().toISOString().slice(0, 10)} | ${what} | \`${hash}\` | testnet |\n`;
  appendFileSync(join(REPO_ROOT, "PROOF.md"), line);
}

for (const role of MEMBERS) {
  const address = await addressFor(role, env);
  const kem = kemKeypairFor(role, env);
  if (!address || !kem) {
    console.log(`${role}: skipped (mnemonic or KEM seed missing in .env)`);
    continue;
  }
  const balance = BigInt(await rdk.rest.getBalance(address, "uqor"));
  const onChainKem = await rdk.rest.getKemKey(address);
  const kemHex = Buffer.from(kem.publicKey).toString("hex");

  console.log(`\n${role} ${address} (${formatQor(balance)})`);
  if (onChainKem?.publicKey === kemHex) {
    console.log("  ML-KEM key already registered. Nothing to do.");
    continue;
  }
  if (onChainKem) {
    console.log("  ML-KEM key on chain differs from the .env seed. Refusing to replace it automatically.");
    continue;
  }
  if (balance < MIN_BALANCE_UQOR) {
    console.log(`  needs at least ${formatQor(MIN_BALANCE_UQOR)} for fees: fund it from the faucet or the operator first.`);
    continue;
  }

  const { tx, pqcAlreadyRegistered } = await txClientFor(rdk, role);
  console.log(`  ML-DSA-87 key: ${pqcAlreadyRegistered ? "already registered" : "will be registered first (with proof of possession)"}`);
  console.log("  ML-KEM-1024 key: will be registered");
  if (!SEND) {
    console.log("  dry run: nothing sent (pass --send to broadcast)");
    continue;
  }
  const res = await tx.registerKemKey({ publicKey: kem.publicKey });
  if (res.code !== 0) throw new Error(`${role}: registerKemKey failed (code ${res.code}): ${res.rawLog ?? ""}`);
  console.log(`  registered: ${res.transactionHash}`);
  proof(`${role} registered ML-KEM-1024 key${pqcAlreadyRegistered ? "" : " (after ML-DSA-87 key + PoP)"}`, res.transactionHash);
}
