/** Read-only: each role's address, QOR balance, post-quantum key and ML-KEM key status. */
import { ROLES, addressFor, formatQor, kemFingerprintHex, kemKeypairFor, loadEnv, pqcAccount, testnetClient } from "@cloister/common";

const rdk = testnetClient();
const env = loadEnv();

console.log("role        address                                       balance        ML-DSA key            ML-KEM key");
for (const role of ROLES) {
  const address = await addressFor(role, env);
  if (!address) {
    console.log(`${role.padEnd(11)} (not set)`);
    continue;
  }
  const balance = formatQor(await rdk.rest.getBalance(address, "uqor"));
  const pq = await pqcAccount(rdk, address);
  const pqText = pq.registered ? `registered${pq.possessionProven ? " +PoP" : ""}` : "not registered";

  const local = kemKeypairFor(role, env);
  let kemText = "-";
  if (local) {
    const onChain = await rdk.rest.getKemKey(address);
    const localHex = Buffer.from(local.publicKey).toString("hex");
    kemText = !onChain ? "not registered" : onChain.publicKey === localHex ? "registered (match)" : "registered (MISMATCH)";
    kemText += ` ${kemFingerprintHex(local.publicKey)}`;
  }
  console.log(`${role.padEnd(11)} ${address.padEnd(45)} ${balance.padEnd(14)} ${pqText.padEnd(21)} ${kemText}`);
}
